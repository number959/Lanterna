//go:build windows

package sign

import (
	"context"
	"encoding/hex"
	"errors"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"lanterna/internal/scan"
)

// Funzioni di wintrust.dll che x/sys non dichiara. Microsoft: le funzioni
// CryptCAT* e WTHelper* «have no associated import library», quindi si
// caricano a richiesta (e se mancano la firma si dichiara non verificabile).
// WinVerifyTrust si chiama con una Proc propria e non con
// windows.WinVerifyTrustEx: serve GetLastError per distinguere «nessuna
// firma» da «firma illeggibile» (esempio Microsoft «Verifying the Signature
// of a PE File»), e il ritorno è un LONG da leggere sui 32 bit bassi.
var (
	wintrust                        = windows.NewLazySystemDLL("wintrust.dll")
	procWinVerifyTrust              = wintrust.NewProc("WinVerifyTrust")
	procProvDataFromStateData       = wintrust.NewProc("WTHelperProvDataFromStateData")
	procGetProvSignerFromChain      = wintrust.NewProc("WTHelperGetProvSignerFromChain")
	procCATAdminAcquireContext2     = wintrust.NewProc("CryptCATAdminAcquireContext2")
	procCATAdminCalcHashFromHandle  = wintrust.NewProc("CryptCATAdminCalcHashFromFileHandle2")
	procCATAdminEnumCatalogFromHash = wintrust.NewProc("CryptCATAdminEnumCatalogFromHash")
	procCATCatalogInfoFromContext   = wintrust.NewProc("CryptCATCatalogInfoFromContext")
	procCATAdminReleaseCatalogCtx   = wintrust.NewProc("CryptCATAdminReleaseCatalogContext")
	procCATAdminReleaseContext      = wintrust.NewProc("CryptCATAdminReleaseContext")
)

// driverActionVerify è DRIVER_ACTION_VERIFY (softpub.h), il sottosistema dei
// cataloghi di sistema per CryptCATAdminAcquireContext2.
var driverActionVerify = windows.GUID{Data1: 0xf750e6c3, Data2: 0x38ee, Data3: 0x11d1, Data4: [8]byte{0x85, 0xe5, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee}}

// microsoftRootApplicationFlag è
// MICROSOFT_ROOT_CERT_CHAIN_POLICY_CHECK_APPLICATION_ROOT_FLAG (wincrypt.h):
// controlla la radice «Microsoft Root Certificate Authority 2011» invece
// delle altre radici Microsoft.
const microsoftRootApplicationFlag = 0x00020000

// wintrustCatalogInfo è WINTRUST_CATALOG_INFO (wintrust.h) nella forma
// completa da Windows 8, con hCatAdmin, obbligatorio per le impronte SHA256
// («can be zero only for a SHA1 file hash»). Scostamenti amd64/arm64 → 386:
// cbStruct 0, dwCatalogVersion 4, pcwszCatalogFilePath 8, pcwszMemberTag
// 16→12, pcwszMemberFilePath 24→16, hMemberFile 32→20, pbCalculatedFileHash
// 40→24, cbCalculatedFileHash 48→28, pcCatalogContext 56→32, hCatAdmin
// 64→36; dimensione 72→40 (calcolati con clang sugli header mingw-w64).
type wintrustCatalogInfo struct {
	Size                   uint32
	CatalogVersion         uint32
	CatalogFilePath        *uint16
	MemberTag              *uint16
	MemberFilePath         *uint16
	MemberFile             windows.Handle
	CalculatedFileHash     *byte
	CalculatedFileHashSize uint32
	CatalogContext         uintptr
	CatAdmin               windows.Handle
}

// catalogInfo è CATALOG_INFO (mscat.h, pack 8): cbStruct e il percorso del
// catalogo in MAX_PATH caratteri; 524 byte su ogni architettura.
type catalogInfo struct {
	Size        uint32
	CatalogFile [windows.MAX_PATH]uint16
}

// cryptProviderSgnr è CRYPT_PROVIDER_SGNR (wintrust.h), letto e mai
// scritto: cbStruct 0, sftVerifyAsOf 4, csCertChain 12, pasCertChain 16,
// dwSignerType 24→20, psSigner 32→24, dwError 40→28, csCounterSigners
// 44→32, pasCounterSigners 48→36, pChainContext 56→40; dimensione 64→44.
// La memoria è di Windows e vale fino a WTD_STATEACTION_CLOSE.
type cryptProviderSgnr struct {
	Size               uint32
	VerifyAsOf         windows.Filetime
	CertChainCount     uint32
	CertChain          unsafe.Pointer // CRYPT_PROVIDER_CERT[]: pCert a ptrSize
	SignerType         uint32
	Signer             unsafe.Pointer
	Error              uint32
	CounterSignerCount uint32
	CounterSigners     unsafe.Pointer
	ChainContext       *windows.CertChainContext
}

const ptrSize = unsafe.Sizeof(uintptr(0))

// Le dimensioni e gli scostamenti devono coincidere con quelli degli header
// per ogni architettura: un errore qui ferma la compilazione (e go vet con
// GOARCH=amd64, arm64 e 386).
var (
	_ [unsafe.Sizeof(wintrustCatalogInfo{}) - (40 + 8*(ptrSize-4))]struct{}
	_ [(40 + 8*(ptrSize-4)) - unsafe.Sizeof(wintrustCatalogInfo{})]struct{}
	_ [unsafe.Offsetof(wintrustCatalogInfo{}.CatAdmin) - (36 + 7*(ptrSize-4))]struct{}
	_ [(36 + 7*(ptrSize-4)) - unsafe.Offsetof(wintrustCatalogInfo{}.CatAdmin)]struct{}
	_ [unsafe.Sizeof(catalogInfo{}) - 524]struct{}
	_ [524 - unsafe.Sizeof(catalogInfo{})]struct{}
	_ [unsafe.Sizeof(cryptProviderSgnr{}) - (44 + 5*(ptrSize-4))]struct{}
	_ [(44 + 5*(ptrSize-4)) - unsafe.Sizeof(cryptProviderSgnr{})]struct{}
	_ [unsafe.Offsetof(cryptProviderSgnr{}.ChainContext) - (40 + 4*(ptrSize-4))]struct{}
	_ [(40 + 4*(ptrSize-4)) - unsafe.Offsetof(cryptProviderSgnr{}.ChainContext)]struct{}
	_ [unsafe.Sizeof(windows.WinTrustData{}) - (52 + 9*(ptrSize-4))]struct{}
	_ [(52 + 9*(ptrSize-4)) - unsafe.Sizeof(windows.WinTrustData{})]struct{}
)

// outcome è l'esito di una chiamata a WinVerifyTrust.
type outcome struct {
	code, lastErr uint32
	signer        string
	msRoot        bool
}

func (o outcome) signature(catalog bool) *scan.FileSignature {
	st := statusOf(o.code)
	return &scan.FileSignature{
		Status:    st,
		Signer:    o.signer,
		Catalog:   catalog,
		Microsoft: st == "valid" && o.msRoot && microsoftSigner(o.signer),
		Code:      codeHex(o.code),
	}
}

func errnoOf(err error) uint32 {
	var e syscall.Errno
	if errors.As(err, &e) {
		return uint32(e)
	}
	return 0
}

// verify verifica la firma Authenticode del file (percorso già passato da
// nativePath): prima la firma incorporata, poi, se il file non ne ha, i
// cataloghi di Windows. Nessun accesso alla rete: WTD_REVOKE_NONE e
// WTD_CACHE_ONLY_URL_RETRIEVAL, quindi la revoca non si controlla online.
func verify(ctx context.Context, path string) *scan.FileSignature {
	if wintrust.Load() != nil || procWinVerifyTrust.Find() != nil {
		return &scan.FileSignature{Status: "unknown"}
	}
	p16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return &scan.FileSignature{Status: "unreadable"}
	}
	h, err := windows.CreateFile(p16, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return &scan.FileSignature{Status: "unreadable", Code: codeHex(hresultWin32(errnoOf(err)))}
	}
	defer windows.CloseHandle(h)

	fi := &windows.WinTrustFileInfo{FilePath: p16, File: h}
	fi.Size = uint32(unsafe.Sizeof(*fi))
	emb := trust(windows.WTD_CHOICE_FILE, unsafe.Pointer(fi))
	runtime.KeepAlive(fi)
	if !noSignature(emb.code) {
		return emb.signature(false)
	}
	if ctx.Err() != nil {
		// Niente tempo per i cataloghi: non si sa ancora se è firmato, e
		// la firma resta non verificata.
		return nil
	}
	sig, found, fail := verifyCatalog(h, p16)
	runtime.KeepAlive(p16)
	switch {
	case found:
		return sig
	case fail != 0:
		// Cataloghi non consultabili (per esempio il servizio Servizi di
		// crittografia fermo): firma non verificabile, mai «non firmato».
		return &scan.FileSignature{Status: "unknown", Code: codeHex(fail)}
	}
	return unsignedSignature(emb.code, emb.lastErr, path)
}

// trust chiama WinVerifyTrust con WINTRUST_ACTION_GENERIC_VERIFY_V2 sul file
// o sul membro di catalogo indicato, legge il firmatario prima di chiudere e
// chiude sempre (WTD_STATEACTION_CLOSE, obbligatorio dopo ogni VERIFY).
func trust(choice uint32, info unsafe.Pointer) outcome {
	wd := &windows.WinTrustData{
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     choice,
		FileOrCatalogOrBlobOrSgnrOrCert: info,
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		ProvFlags:                       windows.WTD_CACHE_ONLY_URL_RETRIEVAL,
		UIContext:                       windows.WTD_UICONTEXT_EXECUTE,
	}
	wd.Size = uint32(unsafe.Sizeof(*wd))
	// hwnd = INVALID_HANDLE_VALUE: «There is no interactive user».
	r, _, e := procWinVerifyTrust.Call(uintptr(windows.InvalidHandle), uintptr(unsafe.Pointer(&windows.WINTRUST_ACTION_GENERIC_VERIFY_V2)), uintptr(unsafe.Pointer(wd)))
	o := outcome{code: uint32(r), lastErr: errnoOf(e)}
	if wd.StateData != 0 && !noSignature(o.code) {
		o.signer, o.msRoot = signerOf(wd.StateData)
	}
	wd.StateAction = windows.WTD_STATEACTION_CLOSE
	procWinVerifyTrust.Call(uintptr(windows.InvalidHandle), uintptr(unsafe.Pointer(&windows.WINTRUST_ACTION_GENERIC_VERIFY_V2)), uintptr(unsafe.Pointer(wd)))
	runtime.KeepAlive(wd)
	return o
}

// signerOf legge il nome semplice del certificato del firmatario e se la sua
// catena arriva a una radice Microsoft, dai dati del fornitore ancora aperti.
func signerOf(state windows.Handle) (name string, msRoot bool) {
	if procProvDataFromStateData.Find() != nil || procGetProvSignerFromChain.Find() != nil {
		return "", false
	}
	pd, _, _ := procProvDataFromStateData.Call(uintptr(state))
	if pd == 0 {
		return "", false
	}
	// Primo firmatario, non un controfirmatario.
	r, _, _ := procGetProvSignerFromChain.Call(pd, 0, 0, 0)
	if r == 0 {
		return "", false
	}
	sg := *(**cryptProviderSgnr)(unsafe.Pointer(&r))
	var chain *windows.CertChainContext
	if sg.Size >= uint32(unsafe.Sizeof(cryptProviderSgnr{})) {
		chain = sg.ChainContext
	}
	var cert *windows.CertContext
	// CERT_SIMPLE_CHAIN: «rgpElement[0] is the end certificate chain element».
	if chain != nil && chain.ChainCount > 0 && chain.Chains != nil {
		if simple := *chain.Chains; simple != nil && simple.NumElements > 0 && simple.Elements != nil {
			if el := *simple.Elements; el != nil {
				cert = el.CertContext
			}
		}
	}
	// Riserva: il primo certificato della catena del firmatario (pCert @ptrSize).
	if cert == nil && sg.CertChainCount > 0 && sg.CertChain != nil {
		cert = *(**windows.CertContext)(unsafe.Add(sg.CertChain, ptrSize))
	}
	if cert != nil {
		name = certName(cert)
	}
	if chain != nil {
		msRoot = microsoftRoot(chain)
	}
	return name, msRoot
}

func certName(cert *windows.CertContext) string {
	n := windows.CertGetNameString(cert, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil, nil, 0)
	if n <= 1 || n > 4096 {
		return ""
	}
	buf := make([]uint16, n)
	windows.CertGetNameString(cert, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil, &buf[0], n)
	return cleanText(windows.UTF16ToString(buf))
}

// microsoftRoot dice se l'ultimo elemento della prima catena semplice è una
// radice Microsoft (CERT_CHAIN_POLICY_MICROSOFT_ROOT): prima le radici
// predefinite, poi «Microsoft Root Certificate Authority 2011». La funzione
// non verifica altro: vale solo insieme all'esito di WinVerifyTrust.
func microsoftRoot(chain *windows.CertChainContext) bool {
	for _, flags := range []uint32{0, microsoftRootApplicationFlag} {
		para := &windows.CertChainPolicyPara{Flags: flags}
		para.Size = uint32(unsafe.Sizeof(*para))
		st := &windows.CertChainPolicyStatus{}
		st.Size = uint32(unsafe.Sizeof(*st))
		if windows.CertVerifyCertificateChainPolicy(windows.CERT_CHAIN_POLICY_MICROSOFT_ROOT, chain, para, st) == nil && st.Error == 0 {
			return true
		}
	}
	return false
}

// cats sono i contesti dei cataloghi tenuti aperti tra un file e l'altro
// (catPool): aprirne uno per file costava gran parte del tempo della prima
// verifica dell'avvio automatico.
var cats = newCatPool(acquireCat, releaseCat)

// acquireCat apre un contesto dei cataloghi di sistema (DRIVER_ACTION_VERIFY)
// per l'algoritmo d'impronta indicato.
func acquireCat(alg string) (uintptr, uint32) {
	alg16, err := windows.UTF16PtrFromString(alg)
	if err != nil {
		return 0, trustEProviderUnknown
	}
	var cat windows.Handle
	r, _, e := procCATAdminAcquireContext2.Call(uintptr(unsafe.Pointer(&cat)), uintptr(unsafe.Pointer(&driverActionVerify)), uintptr(unsafe.Pointer(alg16)), 0, 0)
	if uint32(r) == 0 || cat == 0 {
		return 0, hresultWin32(errnoOf(e))
	}
	return uintptr(cat), 0
}

func releaseCat(h uintptr) { procCATAdminReleaseContext.Call(h, 0) }

// verifyCatalog cerca il file nei cataloghi di Windows, prima con l'impronta
// SHA256 e poi con SHA1 (AcquireContext2 sceglie da sé l'algoritmo, e il
// predefinito può cambiare: si passa il nome esplicito). found: il file è in
// un catalogo e sig è l'esito della verifica; fail: i cataloghi non si sono
// potuti consultare con nessun algoritmo. I contesti vengono da cats: uno
// per goroutine alla volta, e dopo un errore si chiude.
func verifyCatalog(h windows.Handle, p16 *uint16) (sig *scan.FileSignature, found bool, fail uint32) {
	for _, p := range []*windows.LazyProc{procCATAdminAcquireContext2, procCATAdminCalcHashFromHandle, procCATAdminEnumCatalogFromHash, procCATCatalogInfoFromContext, procCATAdminReleaseCatalogCtx, procCATAdminReleaseContext} {
		if p.Find() != nil {
			return nil, false, trustEProviderUnknown
		}
	}
	searched := false
	for _, alg := range []string{"SHA256", "SHA1"} {
		c, f := cats.get(alg)
		if c == nil {
			fail = f
			continue
		}
		s, ok, f := catalogWith(windows.Handle(c.h), h, p16)
		cats.put(c, f == 0)
		if ok {
			return s, true, 0
		}
		if f != 0 {
			fail = f
			continue
		}
		searched = true
	}
	if searched {
		return nil, false, 0
	}
	if fail == 0 {
		fail = trustEProviderUnknown
	}
	return nil, false, fail
}

// catalogWith calcola l'impronta del file con il contesto cat, cerca un
// catalogo che la contiene e verifica il file come membro di quel catalogo.
func catalogWith(cat, h windows.Handle, p16 *uint16) (*scan.FileSignature, bool, uint32) {
	// L'impronta si calcola dall'inizio del file, già letto da WinVerifyTrust.
	if _, err := windows.Seek(h, 0, 0); err != nil {
		return nil, false, hresultWin32(errnoOf(err))
	}
	hash := make([]byte, 64)
	cb := uint32(len(hash))
	r, _, e := procCATAdminCalcHashFromHandle.Call(uintptr(cat), uintptr(h), uintptr(unsafe.Pointer(&cb)), uintptr(unsafe.Pointer(&hash[0])), 0)
	if uint32(r) == 0 {
		if errnoOf(e) != uint32(windows.ERROR_INSUFFICIENT_BUFFER) || cb <= uint32(len(hash)) || cb > 1024 {
			return nil, false, hresultWin32(errnoOf(e))
		}
		hash = make([]byte, cb)
		r, _, e = procCATAdminCalcHashFromHandle.Call(uintptr(cat), uintptr(h), uintptr(unsafe.Pointer(&cb)), uintptr(unsafe.Pointer(&hash[0])), 0)
		if uint32(r) == 0 {
			return nil, false, hresultWin32(errnoOf(e))
		}
	}
	if cb == 0 || cb > uint32(len(hash)) {
		return nil, false, trustEProviderUnknown
	}
	hash = hash[:cb]
	info, _, _ := procCATAdminEnumCatalogFromHash.Call(uintptr(cat), uintptr(unsafe.Pointer(&hash[0])), uintptr(cb), 0, 0)
	if info == 0 {
		return nil, false, 0 // nessun catalogo con questa impronta
	}
	defer procCATAdminReleaseCatalogCtx.Call(uintptr(cat), info, 0)
	ci := &catalogInfo{}
	ci.Size = uint32(unsafe.Sizeof(*ci))
	if r, _, e := procCATCatalogInfoFromContext.Call(info, uintptr(unsafe.Pointer(ci)), 0); uint32(r) == 0 {
		return &scan.FileSignature{Status: "unknown", Catalog: true, Code: codeHex(hresultWin32(errnoOf(e)))}, true, 0
	}
	// Il membro del catalogo si chiama con l'impronta in esadecimale maiuscolo.
	tag16, _ := windows.UTF16PtrFromString(strings.ToUpper(hex.EncodeToString(hash)))
	wci := &wintrustCatalogInfo{
		CatalogFilePath:        &ci.CatalogFile[0],
		MemberTag:              tag16,
		MemberFilePath:         p16,
		MemberFile:             h,
		CalculatedFileHash:     &hash[0],
		CalculatedFileHashSize: cb,
		CatAdmin:               cat,
	}
	wci.Size = uint32(unsafe.Sizeof(*wci))
	o := trust(windows.WTD_CHOICE_CATALOG, unsafe.Pointer(wci))
	runtime.KeepAlive(wci)
	runtime.KeepAlive(ci)
	return o.signature(true), true, 0
}

// driveTypeOf restituisce il tipo dell'unità con la radice indicata ("E:\")
// con GetDriveType; 0 se non si legge.
func driveTypeOf(root string) uint32 {
	p, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return 0
	}
	return windows.GetDriveType(p)
}

// Reindirizzamento di System32 per i processi a 32 bit su Windows a 64 bit.
var (
	redirectOnce sync.Once
	redirectDir  string // %windir% se serve passare da Sysnative
)

// nativePath restituisce il percorso da aprire per leggere davvero il file
// indicato: in un processo a 32 bit su Windows a 64 bit System32 diventa
// Sysnative, negli altri casi il percorso resta com'è (un programma a 64 bit
// non può usare Sysnative).
func nativePath(p string) string {
	if runtime.GOARCH != "386" && runtime.GOARCH != "arm" {
		return p
	}
	redirectOnce.Do(func() {
		var wow bool
		if windows.IsWow64Process(windows.CurrentProcess(), &wow) == nil && wow {
			redirectDir, _ = windows.GetSystemWindowsDirectory()
		}
	})
	if redirectDir == "" {
		return p
	}
	return sysnative(p, redirectDir)
}

// versionInfo legge CompanyName, FileDescription e FileVersion dalle
// informazioni di versione (VERSIONINFO) nella lingua indicata dalla tabella
// \VarFileInfo\Translation, con ripiego su 040904B0; la versione, se manca il
// testo, dalla parte fissa (VS_FIXEDFILEINFO). Testi ripuliti e accorciati.
func versionInfo(path string) (company, description, version string) {
	size, err := windows.GetFileVersionInfoSize(path, nil)
	if err != nil || size == 0 || size > 16<<20 {
		return "", "", ""
	}
	buf := make([]uint64, (size+7)/8) // allineato a 8
	block := unsafe.Pointer(&buf[0])
	if windows.GetFileVersionInfo(path, 0, size, block) != nil {
		return "", "", ""
	}
	limit := uintptr(len(buf) * 8)
	// query restituisce i byte del valore, solo se stanno dentro il blocco.
	query := func(sub string, unit uint32) []byte {
		var p unsafe.Pointer
		var n uint32
		if windows.VerQueryValue(block, sub, unsafe.Pointer(&p), &n) != nil || p == nil || n == 0 {
			return nil
		}
		off := uintptr(p) - uintptr(block)
		bytes := uintptr(n) * uintptr(unit)
		if uintptr(p) < uintptr(block) || off > limit || bytes > limit-off {
			return nil
		}
		return unsafe.Slice((*byte)(p), bytes)
	}
	text := func(sub string) string {
		// Per i testi la lunghezza è in caratteri UTF-16.
		b := query(sub, 2)
		if len(b) < 2 {
			return ""
		}
		u := unsafe.Slice((*uint16)(unsafe.Pointer(&b[0])), len(b)/2)
		return cleanText(windows.UTF16ToString(u))
	}
	for _, k := range translations(query(`\VarFileInfo\Translation`, 1)) {
		base := `\StringFileInfo\` + k + `\`
		c, d, v := text(base+"CompanyName"), text(base+"FileDescription"), text(base+"FileVersion")
		if c != "" || d != "" || v != "" {
			company, description, version = c, d, v
			break
		}
	}
	if version == "" {
		version = fixedVersion(query(`\`, 1))
	}
	runtime.KeepAlive(buf)
	return company, description, version
}
