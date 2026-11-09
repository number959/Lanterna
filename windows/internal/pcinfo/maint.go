package pcinfo

import (
	"regexp"
	"sort"
	"strings"
	"time"

	"lanterna/internal/scan"
	"lanterna/internal/winevt"
)

// Manutenzione di Windows: esito di Diagnostica memoria, cronologia di
// Windows Update, controlli del file system. Qui la parte indipendente dal
// sistema; le letture stanno in maint_windows.go e in HealthScript.

// MemDiagDays è la finestra in cui si cerca l'esito di Diagnostica memoria:
// un test si fa di rado, un anno basta a trovare l'ultimo.
const MemDiagDays = 365

// Fonti dei registri usate qui.
const (
	MemDiagResults  = "Microsoft-Windows-MemoryDiagnostics-Results"
	MemDiagSchedule = "Microsoft-Windows-MemoryDiagnostics-Schedule"
)

// FsProviders sono le fonti del registro Applicazione con i controlli del
// file system: Wininit (all'avvio, evento 1001) e Chkdsk (lanciato a mano).
var FsProviders = []string{"Wininit", "Chkdsk"}

// MemDiagFrom ricava gli esiti dei test della memoria, dal più recente. Gli
// identificativi degli eventi non sono documentati da Microsoft: l'esito con
// errori si riconosce dal livello Errore o dai codici 1102 e 1202.
func MemDiagFrom(events []winevt.Event, days int) *scan.MemDiagInfo {
	m := &scan.MemDiagInfo{Days: days, Results: []scan.MemDiagResult{}}
	var sched time.Time
	for _, e := range events {
		switch {
		case strings.EqualFold(e.Provider, MemDiagResults):
			if len(m.Results) < 10 {
				m.Results = append(m.Results, scan.MemDiagResult{Time: isoOf(e.Time), ID: e.ID, Errors: e.Level == 2 || e.Level == 1 || e.ID == 1102 || e.ID == 1202})
			}
		case strings.EqualFold(e.Provider, MemDiagSchedule):
			if e.Time.After(sched) {
				sched = e.Time
			}
		}
	}
	sort.SliceStable(m.Results, func(i, j int) bool { return m.Results[i].Time > m.Results[j].Time })
	m.LastScheduled = isoOf(sched)
	return m
}

var driveLetter = regexp.MustCompile(`\b([A-Za-z]):`)

// FsChecksFrom ricava i controlli del file system: solo ora, fonte, codice e
// lettera dell'unità (il resoconto di chkdsk può contenere nomi di file e di
// cartelle dell'utente e non viene conservato).
func FsChecksFrom(events []winevt.Event) []scan.FsCheck {
	out := []scan.FsCheck{}
	for _, e := range events {
		src := ""
		switch {
		case strings.EqualFold(e.Provider, "Wininit") && e.ID == 1001:
			src = "wininit"
		case strings.EqualFold(e.Provider, "Chkdsk"):
			src = "chkdsk"
		default:
			continue
		}
		c := scan.FsCheck{Time: isoOf(e.Time), Source: src, ID: e.ID}
		if len(e.Data) > 0 {
			head := e.Data[0]
			if r := []rune(head); len(r) > 300 {
				head = string(r[:300])
			}
			if m := driveLetter.FindStringSubmatch(head); m != nil {
				c.Drive = strings.ToUpper(m[1]) + ":"
			}
		}
		out = append(out, c)
		if len(out) >= 50 {
			break
		}
	}
	return out
}

var kbRe = regexp.MustCompile(`(?i)\bKB(\d{6,8})\b`)
var featureTitle = regexp.MustCompile(`(?i)feature update|aggiornamento delle funzionalit|windows 1[01], version`)
var driverTitle = regexp.MustCompile(`^[^-]+ - [^-]+ - `)

// definitionKBs sono gli aggiornamenti di Microsoft Defender (firme e
// piattaforma): arrivano più volte al giorno e hanno una voce a parte.
var definitionKBs = map[string]bool{"KB2267602": true, "KB4052623": true, "KB915597": true, "KB2461484": true}

// otherKBs e otherTitle: lo Strumento di rimozione malware (KB890830), che
// si installa ogni mese anche quando gli aggiornamenti cumulativi di Windows
// falliscono, e gli aggiornamenti di altri prodotti (.NET, Office...). Non
// sono aggiornamenti di qualità di Windows: altrimenti "ultimo aggiornamento
// installato" risulterebbe recente anche con Windows Update guasto.
var otherKBs = map[string]bool{"KB890830": true}
var otherTitle = regexp.MustCompile(`(?i)\.net|\boffice\b|microsoft 365|visual c\+\+|silverlight|sql server|malicious software removal|rimozione (di )?(malware|software dannoso)`)

// UpdateKind classifica una voce della cronologia (euristica di Polaris sui
// titoli di Windows Update e sul codice di errore).
func UpdateKind(title, kb, hresult string) string {
	switch {
	case definitionKBs[strings.ToUpper(kb)]:
		return "definition"
	case otherKBs[strings.ToUpper(kb)], otherTitle.MatchString(title):
		return "other"
	case strings.HasPrefix(strings.ToUpper(hresult), "0XC19"), featureTitle.MatchString(title):
		return "feature"
	case driverTitle.MatchString(title):
		return "driver"
	case kb != "":
		return "quality"
	}
	return "other"
}

var updateResult = map[int]string{0: "notStarted", 1: "inProgress", 2: "succeeded", 3: "succeededWithErrors", 4: "failed", 5: "aborted"}

// psUpdate rispecchia una voce della cronologia letta da HealthScript.
type psUpdate struct {
	Title string `json:"title"`
	Date  string `json:"date"`
	Op    int    `json:"op"`
	RC    int    `json:"rc"`
	HR    string `json:"hr"`
	ID    string `json:"id"`
}

// UpdateHistoryFrom prepara la cronologia di Windows Update, dalla più recente.
func UpdateHistoryFrom(list []psUpdate) []scan.UpdateEntry {
	out := []scan.UpdateEntry{}
	for _, u := range list {
		title := strings.Join(strings.Fields(u.Title), " ")
		if r := []rune(title); len(r) > 160 {
			title = string(r[:160]) + "…"
		}
		kb := ""
		if m := kbRe.FindStringSubmatch(title); m != nil {
			kb = "KB" + m[1]
		}
		hr := strings.ToUpper(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(u.HR), "0x"), "0X"))
		if hr == "00000000" || hr == "" {
			hr = ""
		} else {
			hr = "0x" + hr
		}
		e := scan.UpdateEntry{Title: title, KB: kb, Kind: UpdateKind(title, kb, hr), Result: updateResult[u.RC], HResult: hr, Date: u.Date, UpdateID: strings.ToLower(strings.Trim(u.ID, "{} "))}
		if e.Result == "" {
			e.Result = "notStarted"
		}
		switch u.Op {
		case 1:
			e.Operation = "install"
		case 2:
			e.Operation = "uninstall"
		default:
			e.Operation = "other"
		}
		if t, err := time.Parse(time.RFC3339Nano, u.Date); err == nil {
			e.Date = isoOf(t)
		}
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Date > out[j].Date })
	return out
}

// VolumeHealth traduce MSFT_Volume.HealthStatus (0 sano, 1 da analizzare,
// 2 serve una correzione rapida, 3 serve la riparazione completa).
func VolumeHealth(v int) string {
	switch v {
	case 0:
		return "healthy"
	case 1:
		return "scan"
	case 2:
		return "spotfix"
	case 3:
		return "repair"
	}
	return ""
}

// FsDetail tiene il dettaglio di un evento del file system solo se è la
// lettera di un'unità: gli altri campi possono contenere nomi di file.
func FsDetail(d string) string {
	d = strings.TrimSpace(d)
	if len(d) == 2 && d[1] == ':' && ((d[0] >= 'A' && d[0] <= 'Z') || (d[0] >= 'a' && d[0] <= 'z')) {
		return strings.ToUpper(d)
	}
	return ""
}

// mergeMaint unisce a pc i dati di manutenzione letti da HealthScript.
func mergeMaint(pc *scan.PcData, h *healthOut) {
	if pc.Updates == nil {
		pc.Updates = &scan.UpdateInfo{}
	}
	u := pc.Updates
	if h.WU != nil {
		u.History = UpdateHistoryFrom(*h.WU)
	} else if code := h.Errors["wu"]; code != "" {
		u.HistoryError = code
	}
	if h.WURes != nil {
		u.LastSuccess, u.LastSearch = h.WURes.Install, h.WURes.Search
	}
	if h.WUReboot != nil && *h.WUReboot {
		has := false
		for _, r := range u.RebootReasons {
			if r == "Windows Update" {
				has = true
			}
		}
		if !has {
			u.RebootReasons = append(u.RebootReasons, "Windows Update")
		}
		u.PendingReboot = true
	}
	for _, v := range h.Vols {
		letter := strings.ToUpper(strings.TrimSpace(v.Letter))
		if len(letter) == 1 {
			letter += ":"
		}
		for i := range pc.Volumes {
			if strings.EqualFold(pc.Volumes[i].Letter, letter) {
				pc.Volumes[i].Health = VolumeHealth(v.Health)
			}
		}
	}
}
