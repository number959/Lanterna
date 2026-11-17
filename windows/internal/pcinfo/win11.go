package pcinfo

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"lanterna/internal/scan"
)

// Dati per la scheda tecnica e i requisiti di Windows 11 aggiunti con la
// 0.14.0: RAM installata, TPM, Secure Boot attivabile, verdetto di Windows
// Update, chipset, schermi e modello del driver video. Le letture native
// stanno in win11_windows.go, display_windows.go e wddm_windows.go; qui la
// parte indipendente dal sistema, provata ovunque.

// hw014PS completa lo script PowerShell della scheda tecnica:
//   - schermi da root\wmi: dimensioni dichiarate in cm
//     (WmiMonitorBasicDisplayParams, solo gli schermi attivi) e tipo di
//     collegamento (WmiMonitorConnectionParams.VideoOutputTechnology);
//     InstanceName serve solo ad abbinarli, non esce dall'agente;
//   - Secure Boot attivabile: Confirm-SecureBootUEFI risponde $true o $false
//     (acceso o spento) solo se il firmware lo supporta, «non supportato»
//     (PlatformNotSupportedException) altrimenti; senza amministratore
//     rifiuta l'accesso e il valore resta sconosciuto.
const hw014PS = `try{$cp=@{};try{Get-CimInstance -Namespace root/wmi -ClassName WmiMonitorConnectionParams -OperationTimeoutSec 10|ForEach-Object{$cp["$($_.InstanceName)"]=[long]$_.VideoOutputTechnology}}catch{};` +
	`$r.mon=@(Get-CimInstance -Namespace root/wmi -ClassName WmiMonitorBasicDisplayParams -OperationTimeoutSec 10|Where-Object{$_.Active}|ForEach-Object{@{id="$($_.InstanceName)";w=[int]$_.MaxHorizontalImageSize;h=[int]$_.MaxVerticalImageSize;vot=$cp["$($_.InstanceName)"]}})}catch{$e.mon="$_"};` +
	`try{$v=Confirm-SecureBootUEFI;if($v -is [bool]){$r.sbCapable=$true}}catch{if($_.Exception -is [System.PlatformNotSupportedException] -or "$($_.FullyQualifiedErrorId)" -like 'SecureBootNotSupported*'){$r.sbCapable=$false}else{$e.sbCapable="$_"}};`

// Tbsi_GetDeviceInfo (tbs.h): TBS_SUCCESS, TBS_E_TPM_NOT_FOUND e i valori
// di TPM_DEVICE_INFO.tpmVersion.
const (
	tbsSuccess     = 0
	tbsTPMNotFound = 0x8028400F
	tpmVersion12   = 1
	tpmVersion20   = 2
)

// tpmVersionOf interpreta l'esito di Tbsi_GetDeviceInfo: "2.0", "1.2", ""
// se Windows non vede alcun TPM, nil se non si è potuto verificare (servizio
// TBS fermo o versione sconosciuta).
func tpmVersionOf(code, version uint32) *string {
	var v string
	switch {
	case code == tbsTPMNotFound:
		v = ""
	case code != tbsSuccess:
		return nil
	case version == tpmVersion20:
		v = "2.0"
	case version == tpmVersion12:
		v = "1.2"
	default:
		return nil
	}
	return &v
}

// appraiserKeyRe riconosce le sottochiavi del verdetto di Windows Update con
// il nome in codice della versione di Windows 11 davanti (CO21H2, NI22H2,
// GE24H2): quelle senza prefisso (21H2, 22H2) riguardano gli aggiornamenti
// di Windows 10.
var appraiserKeyRe = regexp.MustCompile(`^([A-Za-z]{2,4})(\d{2})H([12])$`)

// latestAppraiserKey sceglie tra le sottochiavi quella della versione di
// Windows 11 più recente; "" se non ce n'è.
func latestAppraiserKey(names []string) (key, target string) {
	best := -1
	for _, n := range names {
		m := appraiserKeyRe.FindStringSubmatch(strings.TrimSpace(n))
		if m == nil {
			continue
		}
		yy, _ := strconv.Atoi(m[2])
		h, _ := strconv.Atoi(m[3])
		if rank := yy*10 + h; rank > best {
			best, key, target = rank, n, m[2]+"H"+m[3]
		}
	}
	return key, target
}

var reasonRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,39}$`)

// AppraiserOf costruisce il verdetto dai valori UpgEx (Red, Orange, Yellow,
// Green, come li documenta Configuration Manager: Orange vuol dire app o
// driver da aggiornare dopo l'aggiornamento, non un blocco) e RedReason
// (motivi separati da spazi, "None" se nessuno) della chiave; at è l'ora
// dell'ultima scrittura della chiave. nil se la chiave non dice nulla.
func AppraiserOf(target, upgEx, redReason string, at time.Time) *scan.Win11Appraiser {
	a := &scan.Win11Appraiser{Target: target}
	switch v := strings.ToLower(strings.TrimSpace(upgEx)); v {
	case "green", "yellow", "orange", "red":
		a.Verdict = v
	}
	seen := map[string]bool{}
	for _, r := range strings.FieldsFunc(redReason, func(c rune) bool { return c == ' ' || c == ',' || c == ';' || c == '|' || c == '\t' }) {
		if strings.EqualFold(r, "none") || !reasonRe.MatchString(r) || seen[strings.ToLower(r)] || len(a.Reasons) == 12 {
			continue
		}
		seen[strings.ToLower(r)] = true
		a.Reasons = append(a.Reasons, r)
	}
	if a.Verdict == "" && len(a.Reasons) == 0 {
		return nil
	}
	if !at.IsZero() && at.Year() > 2000 {
		a.At = at.UTC().Format(time.RFC3339)
	}
	return a
}

// hwExtra sono le letture native aggiunte con la 0.14.0.
type hwExtra struct {
	InstalledMB int64
	TPM         *string
	Appraiser   *scan.Win11Appraiser
	Displays    []rawDisplay
	Wddm        []wddmAdapter
}

// applyHardwareExtra completa i dati del computer: ok è falso se le letture
// native non sono finite in tempo; ps è l'uscita dello script (nil se non
// letta); devRaw i dispositivi grezzi (devOK se letti).
func applyHardwareExtra(pc *scan.PcData, x hwExtra, ok bool, ps *psOut, devRaw []rawDevice, devOK, elevated bool) {
	if !ok {
		pc.Notes = append(pc.Notes, "TPM, schermi, modello del driver video e RAM installata non sono stati letti: Windows non ha risposto in tempo.")
	}
	// La RAM dichiarata dal firmware non può essere meno di quella che vede
	// Windows: in quel caso le tabelle SMBIOS sono sbagliate e il valore non si usa.
	if pc.Memory != nil && x.InstalledMB > 0 && x.InstalledMB >= pc.Memory.TotalMB {
		pc.Memory.InstalledMB = x.InstalledMB
	}
	w := &scan.Win11Data{TpmVersion: x.TPM, Appraiser: x.Appraiser}
	if ps != nil {
		w.SecureBootCapable = ps.SBCapable
	}
	if ok || ps != nil {
		pc.Win11 = w
	}
	if pc.Hardware == nil {
		pc.Hardware = &scan.Hardware{}
	}
	hw := pc.Hardware
	if devOK {
		hw.Chipset = ChipsetOf(devRaw)
	}
	var mon []psMonitor
	if ps != nil && ps.Mon != nil {
		mon = *ps.Mon
	}
	hw.Displays = BuildDisplays(x.Displays, mon, pc.GPUs)
	AssignWddm(pc.GPUs, x.Wddm)
	if ps != nil && ps.SBCapable == nil && !elevated && hw.Firmware == "uefi" && hw.SecureBoot != nil && !*hw.SecureBoot {
		pc.Notes = append(pc.Notes, "Se Secure Boot, oggi spento, si possa attivare lo dice Windows solo avviando Polaris come amministratore.")
	}
}
