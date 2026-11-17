package sign

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"unicode"

	"lanterna/internal/scan"
)

// Codici restituiti da WinVerifyTrust e da CryptoAPI (winerror.h, gli stessi
// valori di golang.org/x/sys/windows/zerrors_windows.go). Sono LONG: si
// confrontano sui 32 bit bassi.
const (
	trustENoSignature        = 0x800B0100
	trustEProviderUnknown    = 0x800B0001
	trustESubjectFormUnknown = 0x800B0003
	trustESubjectNotTrusted  = 0x800B0004
	trustEBadDigest          = 0x80096010
	trustEExplicitDistrust   = 0x800B0111
	trustETimeStamp          = 0x80096005
	trustECertSignature      = 0x80096004
	trustENoSignerCert       = 0x80096002
	trustEMalformedSignature = 0x80096011
	certEExpired             = 0x800B0101
	certEUntrustedRoot       = 0x800B0109
	certEChaining            = 0x800B010A
	certERevoked             = 0x800B010C
	certEUntrustedTestRoot   = 0x800B010D
	certERevocationFailure   = 0x800B010E
	certEWrongUsage          = 0x800B0110
	certEUntrustedCA         = 0x800B0112
	cryptEFileError          = 0x80092003
	cryptERevoked            = 0x80092010
	cryptENoRevocationCheck  = 0x80092012
	cryptERevocationOffline  = 0x80092013
	cryptESecuritySettings   = 0x80092026
)

// Errori Win32 di apertura del file, anche nella forma HRESULT_FROM_WIN32.
var fileErrors = map[uint32]bool{
	2:  true, // ERROR_FILE_NOT_FOUND
	3:  true, // ERROR_PATH_NOT_FOUND
	5:  true, // ERROR_ACCESS_DENIED
	32: true, // ERROR_SHARING_VIOLATION
	33: true, // ERROR_LOCK_VIOLATION
}

// hresultWin32 è HRESULT_FROM_WIN32: lo stesso codice che WinVerifyTrust
// restituirebbe per un errore di sistema.
func hresultWin32(e uint32) uint32 {
	if e == 0 || e&0x80000000 != 0 {
		return e
	}
	return 0x80070000 | e&0xFFFF
}

func isFileError(code uint32) bool {
	if code == cryptEFileError {
		return true
	}
	if code&0xFFFF0000 == 0x80070000 {
		code &= 0xFFFF
	}
	return fileErrors[code]
}

// noSignature dice se WinVerifyTrust non ha trovato una firma nel file: è il
// caso in cui si cerca nel catalogo di Windows.
func noSignature(code uint32) bool {
	return code == trustENoSignature || code == trustESubjectFormUnknown || code == trustEProviderUnknown
}

// unsignedStatus decide, quando il file non ha una firma propria e nessun
// catalogo lo contiene, tra «non firmato» e gli altri casi. L'esempio
// Microsoft («Verifying the Signature of a PE File») legge GetLastError: tra
// NOSIGNATURE, SUBJECT_FORM_UNKNOWN e PROVIDER_UNKNOWN il file non è firmato,
// altrimenti la firma non è valida o il file non si è aperto. Un
// GetLastError a zero non dice nulla di diverso: resta «non firmato».
func unsignedStatus(lastErr uint32) string {
	switch {
	case lastErr == 0 || noSignature(lastErr):
		return "unsigned"
	case isFileError(lastErr):
		return "unreadable"
	}
	return "invalid"
}

// packagedApp dice se il file sta nella cartella delle app dello Store
// (pacchetti MSIX): %ProgramFiles%\WindowsApps, oppure <unità>:\WindowsApps
// e <unità>:\Program Files\WindowsApps per le app spostate su un'altra
// unità. Lì la firma è nel pacchetto (AppxSignature.p7x), che Polaris non
// verifica, e un eseguibile senza firma propria non è per questo «non
// firmato». Quelle cartelle sono scrivibili solo dal sistema; una qualsiasi
// altra cartella chiamata WindowsApps (nei Download, sul Desktop, in
// ProgramData, gli alias di esecuzione in %LOCALAPPDATA%\Microsoft) o una
// condivisione di rete non conta: basterebbe il nome per non dirsi «non
// firmato». Sull'unità di Windows vale solo %ProgramFiles%\WindowsApps
// (%ProgramW6432% per Polaris a 32 bit): alla radice di C:\ ogni utente può
// creare una cartella (C:\WindowsApps), e lì Windows non mette le app.
func packagedApp(path string) bool {
	p := strings.TrimPrefix(winClean(path), `\\?\`)
	pfs := []string{os.Getenv("ProgramW6432"), os.Getenv("ProgramFiles")}
	if pfs[0] == "" && pfs[1] == "" {
		pfs[0] = `C:\Program Files`
	}
	for _, pf := range pfs {
		if pf = winClean(pf); pf != "" && strings.HasPrefix(p, pf+`\windowsapps\`) {
			return true
		}
	}
	if len(p) < 4 || p[1] != ':' || p[2] != '\\' || p[0] < 'a' || p[0] > 'z' || p[:2] == systemDrive() {
		return false
	}
	return strings.HasPrefix(p[3:], `windowsapps\`) || strings.HasPrefix(p[3:], `program files\windowsapps\`)
}

// systemDrive è l'unità di Windows in minuscolo («c:»), da %SystemDrive% o
// da %SystemRoot%.
func systemDrive() string {
	for _, v := range []string{os.Getenv("SystemDrive"), os.Getenv("SystemRoot")} {
		if v = winClean(v); len(v) >= 2 && v[1] == ':' && v[0] >= 'a' && v[0] <= 'z' {
			return v[:2]
		}
	}
	return "c:"
}

// unsignedSignature è l'esito di un file senza firma propria e che nessun
// catalogo contiene. Lo stato viene da GetLastError (unsignedStatus) e il
// codice esportato è quello che lo spiega: per una firma non valida o un
// file non leggibile è GetLastError, non il ritorno «nessuna firma»
// (0x800B0100) che lo contraddirebbe.
func unsignedSignature(code, lastErr uint32, path string) *scan.FileSignature {
	st := unsignedStatus(lastErr)
	switch {
	case st == "unsigned" && packagedApp(path):
		// App dello Store: la firma del pacchetto non si verifica qui.
		st = "unknown"
	case st != "unsigned":
		code = hresultWin32(lastErr)
	}
	return &scan.FileSignature{Status: st, Code: codeHex(code)}
}

// transient dice se l'esito della verifica può cambiare senza che cambi il
// file: file non apribile (in uso, accesso negato) o cataloghi di Windows
// non consultabili (servizio Servizi di crittografia occupato o fermo). Non
// lo è l'app dello Store (0x800B0100), il cui esito resta lo stesso.
func transient(s *scan.FileSignature) bool {
	return s != nil && (s.Status == "unreadable" || (s.Status == "unknown" && s.Code != codeHex(trustENoSignature)))
}

// statusOf traduce il codice di WinVerifyTrust in FileSignature.Status. Il
// caso «nessuna firma» lo decide unsignedStatus, dopo il catalogo.
func statusOf(code uint32) string {
	switch code {
	case 0:
		return "valid"
	case trustENoSignature, trustESubjectFormUnknown, trustEProviderUnknown:
		return "unsigned"
	case trustEBadDigest:
		return "tampered"
	case certERevoked, cryptERevoked:
		return "revoked"
	case trustEExplicitDistrust:
		return "distrusted"
	case certEExpired:
		return "expired"
	case certEUntrustedRoot, certEChaining, certEUntrustedCA, certEUntrustedTestRoot:
		return "untrustedRoot"
	case certEWrongUsage:
		return "wrongUsage"
	case cryptESecuritySettings:
		return "policy"
	case trustETimeStamp, trustECertSignature, trustENoSignerCert, trustEMalformedSignature, trustESubjectNotTrusted:
		return "invalid"
	case certERevocationFailure, cryptERevocationOffline, cryptENoRevocationCheck:
		// Con WTD_REVOKE_NONE non dovrebbero comparire: la firma è valida e
		// la revoca non è stata controllata (il codice resta in Code).
		return "valid"
	}
	if isFileError(code) {
		return "unreadable"
	}
	return "unknown"
}

// codeHex scrive il codice come in Microsoft Learn ("0x800B0100"); vuoto se 0.
func codeHex(code uint32) string {
	if code == 0 {
		return ""
	}
	return fmt.Sprintf("0x%08X", code)
}

// microsoftSigners sono i nomi semplici dei certificati con cui Microsoft
// firma i propri componenti. Altri nomi con «Microsoft», come «Microsoft
// Windows Hardware Compatibility Publisher» (driver di altri produttori
// certificati WHQL o per attestazione) o «Microsoft Windows Third Party
// Component», restano fuori: il file è di chi l'ha scritto. È la scelta
// prudente: un componente Microsoft con un nome diverso risulta «non
// Microsoft», mai il contrario.
var microsoftSigners = map[string]bool{
	"Microsoft Windows":           true,
	"Microsoft Windows Publisher": true,
	"Microsoft Corporation":       true,
}

// microsoftSigner dice se il firmatario è uno di quelli di Microsoft per i
// propri componenti; da solo non basta, serve anche la catena verso la
// radice Microsoft (CERT_CHAIN_POLICY_MICROSOFT_ROOT).
func microsoftSigner(name string) bool { return microsoftSigners[name] }

// sysnative riscrive %windir%\System32\... in %windir%\Sysnative\...: un
// processo a 32 bit su Windows a 64 bit vedrebbe al posto di System32 la
// cartella SysWOW64 e verificherebbe il file sbagliato. Microsoft (File
// System Redirector): i programmi a 64 bit non possono usare Sysnative,
// quindi chi chiama lo fa solo se serve.
func sysnative(path, windir string) string {
	windir = strings.TrimRight(windir, `\/`)
	if windir == "" {
		return path
	}
	prefix := windir + `\System32`
	if len(path) < len(prefix) || !strings.EqualFold(path[:len(prefix)], prefix) {
		return path
	}
	rest := path[len(prefix):]
	if rest != "" && rest[0] != '\\' && rest[0] != '/' {
		return path // C:\Windows\System32x\...
	}
	return path[:len(windir)] + `\Sysnative` + rest
}

// translations sono le chiavi \StringFileInfo\<lingua><code page> da provare,
// nell'ordine: quelle della tabella \VarFileInfo\Translation (coppie di WORD
// lingua e code page), poi 040904B0 (inglese, Unicode) e 040904E4 (inglese,
// Windows-1252), il ripiego più comune.
func translations(table []byte) []string {
	var out []string
	seen := map[string]bool{}
	add := func(k string) {
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	for i := 0; i+4 <= len(table) && i < 64; i += 4 {
		lang := binary.LittleEndian.Uint16(table[i:])
		cp := binary.LittleEndian.Uint16(table[i+2:])
		add(fmt.Sprintf("%04X%04X", lang, cp))
	}
	add("040904B0")
	add("040904E4")
	return out
}

// maxText è la lunghezza massima, in caratteri, dei testi delle informazioni
// di versione.
const maxText = 120

// cleanText ripulisce un testo scritto da chi ha prodotto il file: niente
// caratteri di controllo né di formato (che potrebbero rovesciare la lettura,
// come U+202E), spazi ridotti, al massimo maxText caratteri.
func cleanText(s string) string {
	var b strings.Builder
	space := false
	for _, r := range s {
		switch {
		case r == 0 || r == unicode.ReplacementChar || unicode.Is(unicode.Cf, r):
			continue
		case unicode.IsSpace(r) || unicode.IsControl(r):
			space = true
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(r)
	}
	out := []rune(b.String())
	if len(out) > maxText {
		return strings.TrimRight(string(out[:maxText-1]), " ") + "…"
	}
	return string(out)
}

// fixedVersion legge la versione del file da VS_FIXEDFILEINFO (verrsrc.h:
// dwSignature 0xFEEF04BD @0, dwFileVersionMS @8, dwFileVersionLS @12), il
// ripiego quando manca il testo FileVersion.
func fixedVersion(b []byte) string {
	if len(b) < 16 || binary.LittleEndian.Uint32(b) != 0xFEEF04BD {
		return ""
	}
	ms, ls := binary.LittleEndian.Uint32(b[8:]), binary.LittleEndian.Uint32(b[12:])
	if ms == 0 && ls == 0 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", ms>>16, ms&0xFFFF, ls>>16, ls&0xFFFF)
}
