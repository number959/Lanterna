//go:build windows

package pcinfo

import (
	"os"

	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"lanterna/internal/scan"
)

var (
	netapi32                    = windows.NewLazySystemDLL("netapi32.dll")
	procNetLocalGroupGetMembers = netapi32.NewProc("NetLocalGroupGetMembers")
	user32                      = windows.NewLazySystemDLL("user32.dll")
	procSystemParametersInfoW   = user32.NewProc("SystemParametersInfoW")
)

// userInfo20 è USER_INFO_20 (lmaccess.h): nome, nome completo, commento,
// flag e RID. Dei campi si usano solo flag e RID; i testi restano in
// memoria e non escono dall'agente.
type userInfo20 struct {
	Name     *uint16
	FullName *uint16
	Comment  *uint16
	Flags    uint32
	UserID   uint32
}

// localGroupMembersInfo2 è LOCALGROUP_MEMBERS_INFO_2: SID, tipo e
// "DOMINIO\nome" (usato solo per distinguere gli account locali).
type localGroupMembersInfo2 struct {
	SID           *windows.SID
	SIDUsage      uint32
	DomainAndName *uint16
}

const (
	filterNormalAccount = 0x0002
	maxPreferredLength  = 0xFFFFFFFF
	nerrSuccess         = 0
	errorMoreData       = 234
)

// localUsers legge gli account locali (NetUserEnum, livello 20).
func localUsers() ([]rawUser, bool) {
	var out []rawUser
	var resume uint32
	for {
		var buf *byte
		var read, total uint32
		err := windows.NetUserEnum(nil, 20, filterNormalAccount, &buf, maxPreferredLength, &read, &total, &resume)
		if buf != nil {
			entries := unsafe.Slice((*userInfo20)(unsafe.Pointer(buf)), read)
			for _, e := range entries {
				out = append(out, rawUser{RID: int(e.UserID), Flags: e.Flags})
			}
			windows.NetApiBufferFree(buf)
		}
		if err == nil {
			return out, true
		}
		if err != windows.Errno(errorMoreData) {
			return out, len(out) > 0
		}
	}
}

// ridOf restituisce l'ultimo sotto-identificativo di un SID.
func ridOf(sid *windows.SID) int {
	if sid == nil || sid.SubAuthorityCount() == 0 {
		return 0
	}
	return int(sid.SubAuthority(uint32(sid.SubAuthorityCount()) - 1))
}

// adminMembers legge i membri del gruppo Administrators: i RID degli
// account locali e il numero degli altri (dominio, Microsoft Entra).
func adminMembers(computer string) (map[int]bool, int, bool) {
	sid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, 0, false
	}
	group, _, _, err := sid.LookupAccount("")
	if err != nil || group == "" {
		return nil, 0, false
	}
	g, err := windows.UTF16PtrFromString(group)
	if err != nil {
		return nil, 0, false
	}
	local := map[int]bool{}
	other := 0
	var resume uintptr
	for {
		var buf *byte
		var read, total uint32
		r, _, _ := procNetLocalGroupGetMembers.Call(0, uintptr(unsafe.Pointer(g)), 2, uintptr(unsafe.Pointer(&buf)), maxPreferredLength,
			uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&resume)))
		if buf != nil {
			for _, m := range unsafe.Slice((*localGroupMembersInfo2)(unsafe.Pointer(buf)), read) {
				domain, _, _ := strings.Cut(windows.UTF16PtrToString(m.DomainAndName), `\`)
				if strings.EqualFold(domain, computer) && m.SIDUsage == 1 { // SidTypeUser
					local[ridOf(m.SID)] = true
				} else {
					other++
				}
			}
			windows.NetApiBufferFree(buf)
		}
		if r == nerrSuccess {
			return local, other, true
		}
		if r != errorMoreData {
			return local, other, false
		}
	}
}

// currentLocalRID è il RID dell'account che usa Polaris, se è un account
// locale (0 se di dominio o Microsoft Entra).
func currentLocalRID(computer string) int {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return 0
	}
	_, domain, _, err := u.User.Sid.LookupAccount("")
	if err != nil || !strings.EqualFold(domain, computer) {
		return 0
	}
	return ridOf(u.User.Sid)
}

// readAccounts legge gli account locali e il gruppo Administrators.
func readAccounts() *scan.AccountsInfo {
	users, ok := localUsers()
	if !ok {
		return nil
	}
	computer, _ := windows.ComputerName()
	admins, other, adminsRead := adminMembers(computer)
	return AccountsFrom(users, admins, other, currentLocalRID(computer), adminsRead)
}

func regDword(root registry.Key, path, name string) (uint64, bool) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return 0, false
	}
	defer k.Close()
	return dword(k, name)
}

func regString(root registry.Key, path, name string) (string, bool) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return "", false
	}
	defer k.Close()
	s, _, err := k.GetStringValue(name)
	return s, err == nil
}

// regExists dice se un valore esiste, senza leggerne il contenuto né la
// lunghezza (che per una password ne rivelerebbe la lunghezza).
func regExists(root registry.Key, path, name string) bool {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetValue(name, nil)
	return err == nil || err == registry.ErrShortBuffer
}

func spiBool(action uint32) (bool, bool) {
	var v uint32
	r, _, _ := procSystemParametersInfoW.Call(uintptr(action), 0, uintptr(unsafe.Pointer(&v)), 0)
	return v != 0, r != 0
}

func spiInt(action uint32) (int, bool) {
	var v int32
	r, _, _ := procSystemParametersInfoW.Call(uintptr(action), 0, uintptr(unsafe.Pointer(&v)), 0)
	return int(v), r != 0
}

const (
	winlogonKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
	policiesSys = `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
	tsKey       = `SYSTEM\CurrentControlSet\Control\Terminal Server`
	tsPolicy    = `SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`
	rdpTcpKey   = `SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`
)

// readAccess legge accesso automatico, Desktop remoto, Controllo
// dell'account utente e blocco dello schermo, senza mai leggere nomi o
// password.
func readAccess() *scan.AccessInfo {
	a := &scan.AccessInfo{}
	auto, _ := regString(registry.LOCAL_MACHINE, winlogonKey, "AutoAdminLogon")
	a.Autologon = &scan.AutologonInfo{Enabled: strings.TrimSpace(auto) == "1"}
	if a.Autologon.Enabled {
		a.Autologon.PasswordInRegistry = regExists(registry.LOCAL_MACHINE, winlogonKey, "DefaultPassword")
	}

	rdp := &scan.RdpInfo{}
	deny, ok := regDword(registry.LOCAL_MACHINE, tsKey, "fDenyTSConnections")
	if pdeny, pok := regDword(registry.LOCAL_MACHINE, tsPolicy, "fDenyTSConnections"); pok {
		deny, ok, rdp.ByPolicy = pdeny, true, true
	}
	if ok {
		rdp.Enabled = deny == 0
		nla, nok := regDword(registry.LOCAL_MACHINE, rdpTcpKey, "UserAuthentication")
		if pnla, pok := regDword(registry.LOCAL_MACHINE, tsPolicy, "UserAuthentication"); pok {
			nla, nok = pnla, true
		}
		rdp.NLA = !nok || nla == 1
		if port, pok := regDword(registry.LOCAL_MACHINE, rdpTcpKey, "PortNumber"); pok && port > 0 && port < 65536 {
			rdp.Port = int(port)
		}
		a.RDP = rdp
	}

	uac := &scan.UacInfo{Enabled: true, ConsentAdmin: 5, SecureDesktop: true}
	if v, ok := regDword(registry.LOCAL_MACHINE, policiesSys, "EnableLUA"); ok {
		uac.Enabled = v != 0
	}
	if v, ok := regDword(registry.LOCAL_MACHINE, policiesSys, "ConsentPromptBehaviorAdmin"); ok {
		uac.ConsentAdmin = int(v)
	}
	if v, ok := regDword(registry.LOCAL_MACHINE, policiesSys, "PromptOnSecureDesktop"); ok {
		uac.SecureDesktop = v != 0
	}
	a.UAC = uac

	lock := &scan.LockInfo{}
	if v, ok := regDword(registry.LOCAL_MACHINE, policiesSys, "InactivityTimeoutSecs"); ok {
		lock.InactivitySec = int(v)
	}
	// SPI_GETSCREENSAVEACTIVE, SPI_GETSCREENSAVETIMEOUT, SPI_GETSCREENSAVESECURE.
	lock.SaverActive, _ = spiBool(0x0010)
	lock.SaverSec, _ = spiInt(0x000E)
	lock.SaverSecure, _ = spiBool(0x0076)
	a.Lock = lock
	return a
}

// preventDeviceEncryption legge PreventDeviceEncryption; nil se il valore non c'è.
func preventDeviceEncryption() *bool {
	v, ok := regDword(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\BitLocker`, "PreventDeviceEncryption")
	if !ok {
		return nil
	}
	b := v == 1
	return &b
}

// restoreDisabledByPolicy dice se i criteri spengono Ripristino configurazione di sistema.
func restoreDisabledByPolicy() bool {
	v, ok := regDword(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore`, "DisableSR")
	return ok && v == 1
}

// oneDriveFolders elenca le cartelle Desktop, Documenti e Immagini che stanno
// dentro la cartella di OneDrive (spostate con il backup delle cartelle di
// OneDrive). Solo i nomi delle cartelle, mai i percorsi.
func oneDriveFolders() []string {
	var roots []string
	for _, k := range []string{"OneDrive", "OneDriveConsumer", "OneDriveCommercial"} {
		if v := strings.TrimRight(os.Getenv(k), `\`); v != "" {
			roots = append(roots, strings.ToLower(v)+`\`)
		}
	}
	if len(roots) == 0 {
		return nil
	}
	var out []string
	for _, f := range []struct {
		id   *windows.KNOWNFOLDERID
		name string
	}{{windows.FOLDERID_Desktop, "desktop"}, {windows.FOLDERID_Documents, "documents"}, {windows.FOLDERID_Pictures, "pictures"}} {
		p, err := windows.KnownFolderPath(f.id, 0)
		if err != nil {
			continue
		}
		lp := strings.ToLower(p) + `\`
		for _, r := range roots {
			if strings.HasPrefix(lp, r) {
				out = append(out, f.name)
				break
			}
		}
	}
	return out
}
