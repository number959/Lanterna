package pcinfo

import (
	"sort"
	"strings"
	"time"

	"lanterna/internal/scan"
)

// Sicurezza dell'accesso e dei dati: cifratura dei volumi, punti di
// ripristino e backup, account locali, accesso automatico, Desktop remoto,
// Controllo dell'account utente, blocco dello schermo, stampanti. Qui le
// traduzioni dei valori di Windows, provate su qualunque piattaforma; le
// letture stanno in access_windows.go, printing_windows.go e HealthScript.

// AccountKind riconosce gli account predefiniti dal RID (identificativo
// relativo): 500 Administrator integrato, 501 Guest, 503 DefaultAccount, 504
// WDAGUtilityAccount.
func AccountKind(rid int) string {
	switch rid {
	case 500:
		return "builtin-admin"
	case 501:
		return "guest"
	case 503:
		return "default"
	case 504:
		return "wdag"
	}
	return "user"
}

// Bit di usri_flags (lmaccess.h, gli stessi di userAccountControl).
const (
	ufAccountDisable   = 0x0002
	ufLockout          = 0x0010
	ufPasswdNotReqd    = 0x0020
	ufDontExpirePasswd = 0x10000
)

// rawUser è un account locale come lo legge l'agente: il nome non esce mai.
type rawUser struct {
	RID   int
	Flags uint32
}

// AccountsFrom prepara l'elenco degli account locali senza nomi. admins sono
// i RID degli account locali nel gruppo Administrators, other i membri di
// dominio o di Microsoft Entra; current è il RID dell'account che usa Polaris
// (0 se non è un account locale).
func AccountsFrom(users []rawUser, admins map[int]bool, other, current int, adminsRead bool) *scan.AccountsInfo {
	a := &scan.AccountsInfo{Local: []scan.LocalAccount{}}
	enabledAdmins := 0
	for _, u := range users {
		acc := scan.LocalAccount{
			RID:                  u.RID,
			Kind:                 AccountKind(u.RID),
			Enabled:              u.Flags&ufAccountDisable == 0,
			Admin:                admins[u.RID],
			Current:              current != 0 && u.RID == current,
			PasswordNotRequired:  u.Flags&ufPasswdNotReqd != 0,
			PasswordNeverExpires: u.Flags&ufDontExpirePasswd != 0,
			LockedOut:            u.Flags&ufLockout != 0,
		}
		if acc.Admin && acc.Enabled {
			enabledAdmins++
		}
		a.Local = append(a.Local, acc)
	}
	sort.Slice(a.Local, func(i, j int) bool { return a.Local[i].RID < a.Local[j].RID })
	if adminsRead {
		a.Admins = &scan.AdminGroup{Members: len(admins) + other, LocalEnabled: enabledAdmins, Other: other}
		if current != 0 {
			is := admins[current]
			a.CurrentIsAdmin = &is
		}
	}
	return a
}

// Bit di PRINTER_STATUS (winspool.h) e nome dello stato in Polaris.
var printerStatusBits = []struct {
	bit  uint32
	name string
}{
	{0x1, "paused"}, {0x2, "error"}, {0x4, "pending-deletion"}, {0x8, "paper-jam"}, {0x10, "paper-out"},
	{0x40, "paper-problem"}, {0x80, "offline"}, {0x800, "output-bin-full"}, {0x1000, "not-available"},
	{0x20000, "toner-low"}, {0x40000, "no-toner"}, {0x100000, "user-intervention"}, {0x200000, "out-of-memory"},
	{0x400000, "door-open"}, {0x800000, "server-unknown"}, {0x1000000, "power-save"},
}

// PrinterFlags decodifica i bit di stato di una stampante.
func PrinterFlags(status uint32) []string {
	var out []string
	for _, b := range printerStatusBits {
		if status&b.bit != 0 {
			out = append(out, b.name)
		}
	}
	return out
}

// PrinterKind classifica una stampante dalla porta e dal driver: virtuali
// (PDF, XPS, OneNote, fax), di rete TCP/IP o WSD, USB, altro.
func PrinterKind(port, driver string) string {
	p, d := strings.ToLower(strings.TrimSpace(port)), strings.ToLower(driver)
	switch {
	case p == "portprompt:" || p == "nul:" || p == "file:" || strings.HasPrefix(p, "xpsport") || strings.HasPrefix(p, "shrfax") || strings.Contains(p, "onenote") ||
		strings.Contains(d, "print to pdf") || strings.Contains(d, "xps document writer") || strings.Contains(d, "onenote") || strings.Contains(d, "fax"):
		return "virtual"
	case strings.HasPrefix(p, "wsd"):
		return "wsd"
	case strings.HasPrefix(p, "usb"), strings.HasPrefix(p, "dot4"):
		return "usb"
	case strings.HasPrefix(p, "ip_"), strings.HasPrefix(p, "http"), strings.Count(p, ".") == 3, strings.Contains(p, ":9100"):
		return "tcp"
	}
	return "other"
}

// PrinterPort toglie dal nome della porta i percorsi: una porta locale può
// scrivere su un file (anche nella cartella dell'utente) o puntare a una
// condivisione; resta solo il tipo.
func PrinterPort(port string) string {
	p := strings.TrimSpace(port)
	switch {
	case strings.HasPrefix(p, `\\`):
		return "condivisione di rete"
	case strings.ContainsAny(p, `\/`):
		return "file"
	}
	return p
}

// Stati di un lavoro di stampa (JOB_STATUS_*, winspool.h).
const (
	jobPaused   = 0x1
	jobError    = 0x2
	jobPrinting = 0x10
	jobOffline  = 0x20
	jobBlocked  = 0x200
	// StuckJobMin: un lavoro in coda da più minuti di così è fermo (scelta di Polaris).
	StuckJobMin = 15
)

// JobState riassume un lavoro in coda: in errore e fermo da troppo tempo.
func JobState(status uint32, submitted, now time.Time) (failed, stuck bool, ageMin int) {
	failed = status&(jobError|jobOffline|jobBlocked) != 0
	if !submitted.IsZero() && now.After(submitted) {
		ageMin = int(now.Sub(submitted) / time.Minute)
	}
	stuck = status&jobPrinting == 0 && ageMin >= StuckJobMin
	return
}

// Traduzioni dei valori di Win32_EncryptableVolume.

// ConversionName traduce GetConversionStatus.
func ConversionName(v int) string {
	switch v {
	case 0:
		return "decrypted"
	case 1:
		return "encrypted"
	case 2:
		return "encrypting"
	case 3:
		return "decrypting"
	case 4:
		return "encrypt-paused"
	case 5:
		return "decrypt-paused"
	}
	return "unknown"
}

// ProtectionName traduce GetProtectionStatus.
func ProtectionName(v int) string {
	switch v {
	case 0:
		return "off"
	case 1:
		return "on"
	}
	return "unknown"
}

// MethodName traduce GetEncryptionMethod.
func MethodName(v int64) string {
	switch v {
	case 0:
		return "none"
	case 1:
		return "aes128-diffuser"
	case 2:
		return "aes256-diffuser"
	case 3:
		return "aes128"
	case 4:
		return "aes256"
	case 5:
		return "hardware"
	case 6:
		return "xts-aes128"
	case 7:
		return "xts-aes256"
	}
	return "unknown"
}

// ProtectorName traduce il tipo di una protezione della chiave.
func ProtectorName(v int) string {
	switch v {
	case 1:
		return "tpm"
	case 2:
		return "startup-key"
	case 3:
		return "recovery-password"
	case 4:
		return "tpm-pin"
	case 5:
		return "tpm-startup-key"
	case 6:
		return "tpm-pin-startup-key"
	case 7:
		return "public-key"
	case 8:
		return "password"
	case 9:
		return "tpm-certificate"
	}
	return "other"
}

// VolumeKindName traduce VolumeType.
func VolumeKindName(v int) string {
	switch v {
	case 0:
		return "os"
	case 1:
		return "fixed"
	case 2:
		return "removable"
	}
	return "unknown"
}

// RestoreTypeName traduce RestorePointType.
func RestoreTypeName(v int) string {
	switch v {
	case 0:
		return "app-install"
	case 1:
		return "app-uninstall"
	case 10:
		return "driver-install"
	case 12:
		return "settings"
	case 13:
		return "cancelled"
	case 17:
		return "windows-update"
	}
	return "other"
}

// CimErrorState traduce l'errore di una lettura CIM: denied (serve
// l'amministratore), absent (spazio dei nomi o classe assenti), error.
func CimErrorState(msg string) string {
	m := strings.ToUpper(strings.TrimSpace(msg))
	switch {
	case m == "ACCESSDENIED" || m == "0X80041003" || m == "0X80070005":
		return "denied"
	case m == "INVALIDNAMESPACE" || m == "INVALIDCLASS" || m == "NOTFOUND" || m == "0X8004100E" || m == "0X80041010":
		return "absent"
	}
	return "error"
}

// Eventi di Microsoft-Windows-Backup (Backup e ripristino di Windows 7): 4 è
// un backup riuscito; gli altri elencati sono backup non riusciti o annullati.
func backupFailed(id int) bool {
	switch {
	case id == 5, id == 8, id == 9, id >= 17 && id <= 22, id == 49, id == 50, id == 52, id >= 517 && id <= 564:
		return true
	}
	return false
}

// psEncVolume, psRestore e psBackupEvent rispecchiano le sezioni di HealthScript.
type psEncVolume struct {
	Letter  string `json:"letter"`
	Type    int    `json:"type"`
	Conv    int    `json:"conv"`
	Pct     int    `json:"pct"`
	Flags   int    `json:"flags"`
	Prot    int    `json:"prot"`
	Method  int64  `json:"method"`
	Lock    int    `json:"lock"`
	KP      []int  `json:"kp"`
	KPOk    bool   `json:"kpOk"`
	RID     string `json:"rid"`
	Suspend *int   `json:"suspend"`
}

type psRestore struct {
	T    string `json:"t"`
	Type int    `json:"type"`
}

type psBackupEvent struct {
	ID int    `json:"id"`
	T  string `json:"t"`
}

// EncryptionFrom prepara lo stato della cifratura.
func EncryptionFrom(vols []psEncVolume, errMsg string, read bool) *scan.EncryptionInfo {
	e := &scan.EncryptionInfo{Read: "ok"}
	if !read {
		e.Read = CimErrorState(errMsg)
		return e
	}
	for _, v := range vols {
		letter := strings.ToUpper(strings.TrimSpace(v.Letter))
		if len(letter) == 1 {
			letter += ":"
		}
		if len(letter) != 2 || letter[1] != ':' {
			continue
		}
		ev := scan.EncVolume{Letter: letter, Kind: VolumeKindName(v.Type), Conversion: ConversionName(v.Conv), UsedSpaceOnly: v.Flags&1 != 0,
			Protection: ProtectionName(v.Prot), Locked: v.Lock == 1, Method: MethodName(v.Method), SuspendCount: v.Suspend}
		if v.Pct >= 0 && v.Pct <= 100 {
			p := v.Pct
			ev.Percent = &p
		}
		if v.KPOk {
			ev.Protectors = []string{}
			for _, k := range v.KP {
				ev.Protectors = append(ev.Protectors, ProtectorName(k))
			}
		}
		if rid := strings.ToUpper(v.RID); len(rid) == 8 && strings.Trim(rid, "0123456789ABCDEF") == "" {
			ev.RecoveryKeyID = rid
		}
		e.Volumes = append(e.Volumes, ev)
	}
	sort.SliceStable(e.Volumes, func(i, j int) bool { return e.Volumes[i].Letter < e.Volumes[j].Letter })
	return e
}

// RestoreFrom prepara i punti di ripristino (senza le descrizioni).
func RestoreFrom(list []psRestore, errMsg string, read, server bool) *scan.RestorePoints {
	r := &scan.RestorePoints{Read: "ok"}
	switch {
	case server:
		r.Read = "unsupported"
		return r
	case !read:
		r.Read = CimErrorState(errMsg)
		if r.Read == "absent" {
			r.Read = "unsupported"
		}
		return r
	}
	var newest, oldest time.Time
	for _, p := range list {
		t, err := time.Parse(time.RFC3339Nano, p.T)
		if err != nil {
			continue
		}
		r.Count++
		if t.After(newest) {
			newest, r.NewestType = t, RestoreTypeName(p.Type)
		}
		if oldest.IsZero() || t.Before(oldest) {
			oldest = t
		}
	}
	r.Newest, r.Oldest = isoOf(newest), isoOf(oldest)
	return r
}

// ImageBackupFrom riassume gli eventi di Backup e ripristino di Windows.
func ImageBackupFrom(events []psBackupEvent, errMsg string, read bool, days int) *scan.ImageBackupInfo {
	b := &scan.ImageBackupInfo{Read: "ok", Days: days}
	if !read {
		b.Read = CimErrorState(errMsg)
		if b.Read == "absent" {
			b.Read = "error"
		}
		return b
	}
	var ok, ko time.Time
	for _, e := range events {
		t, err := time.Parse(time.RFC3339Nano, e.T)
		if err != nil {
			continue
		}
		switch {
		case e.ID == 4:
			if t.After(ok) {
				ok = t
			}
		case backupFailed(e.ID):
			b.Failures++
			if t.After(ko) {
				ko, b.FailureID = t, e.ID
			}
		}
	}
	b.LastSuccess, b.LastFailure = isoOf(ok), isoOf(ko)
	return b
}

// BackupDays è la finestra in cui si cercano gli esiti di Backup e ripristino.
const BackupDays = 90

// mergeProtection unisce a pc cifratura, punti di ripristino e backup letti
// da HealthScript.
func mergeProtection(pc *scan.PcData, h *healthOut) {
	server := pc.OS != nil && pc.OS.Server
	var bl []psEncVolume
	if h.BL != nil {
		bl = *h.BL
	}
	pc.Encryption = EncryptionFrom(bl, h.Errors["bl"], h.BL != nil)
	var rp []psRestore
	if h.RP != nil {
		rp = *h.RP
	}
	var wb []psBackupEvent
	if h.WB != nil {
		wb = *h.WB
	}
	pc.Backup = &scan.BackupInfo{
		RestorePoints: RestoreFrom(rp, h.Errors["rp"], h.RP != nil, server),
		ImageBackup:   ImageBackupFrom(wb, h.Errors["wb"], h.WB != nil, BackupDays),
	}
}
