package pcinfo

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"lanterna/internal/scan"
	"lanterna/internal/winevt"
)

// Avvio, programmi che si chiudono da soli e affidabilità. Gli eventi si
// leggono con le API native del registro eventi (winevt), l'indice di
// stabilità con HealthScript (WMI); qui la parte indipendente dal sistema.

// Finestre di lettura: 90 giorni per gli avvii (sono pochi eventi), gli
// stessi 30 giorni del registro di sistema per i programmi.
const (
	BootDays = 90
	AppDays  = EventsDays
)

// Canali e interrogazioni del registro eventi.
const (
	BootChannel = "Microsoft-Windows-Diagnostics-Performance/Operational"
	AppChannel  = "Application"
)

// BootIDs sono gli eventi di Diagnostics-Performance letti: 100 avvio, 101-110
// componenti lenti all'avvio, 200 spegnimento, 201-203 componenti lenti allo
// spegnimento.
var BootIDs = []int{100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 200, 201, 202, 203}

// AppProviders e AppIDs: arresti (1000), blocchi (1002) e rapporti di
// Segnalazione errori (1001) nel registro Applicazione.
var (
	AppProviders = []string{"Application Error", "Application Hang", "Windows Error Reporting"}
	AppIDs       = []int{1000, 1001, 1002}
)

var slowKind = map[int][2]string{
	101: {"boot", "app"}, 102: {"boot", "driver"}, 103: {"boot", "service"}, 104: {"boot", "core"},
	105: {"boot", "prefetch"}, 106: {"boot", "prefetch"}, 107: {"boot", "policy"}, 108: {"boot", "policy"},
	109: {"boot", "device"}, 110: {"boot", "session"},
	201: {"shutdown", "app"}, 202: {"shutdown", "device"}, 203: {"shutdown", "service"},
}

func msOf(v string) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

func truthy(v string) bool {
	v = strings.TrimSpace(v)
	return strings.EqualFold(v, "true") || v == "1"
}

func isoOf(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// eventTime preferisce l'ora scritta nell'evento (inizio dell'avvio) a
// quella di registrazione.
func eventTime(e winevt.Event, field string) string {
	if v := e.Get(field, -1); v != "" {
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil && t.Year() > 2000 {
			return isoOf(t)
		}
	}
	return isoOf(e.Time)
}

// ChannelState traduce l'errore di lettura di un registro.
func ChannelState(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, winevt.ErrDenied):
		return "denied"
	case errors.Is(err, winevt.ErrNoChannel):
		return "missing"
	}
	return "error"
}

// BootFrom riassume gli eventi di Diagnostics-Performance, dal più recente.
func BootFrom(events []winevt.Event, days int) *scan.BootPerf {
	b := &scan.BootPerf{Days: days, Channel: "ok", Boots: []scan.BootRecord{}}
	slow := map[string]*scan.BootSlow{}
	var order []string
	for _, e := range events {
		if !strings.EqualFold(e.Provider, "Microsoft-Windows-Diagnostics-Performance") {
			continue
		}
		switch {
		case e.ID == 100:
			r := scan.BootRecord{
				Time:        eventTime(e, "BootStartTime"),
				TotalMs:     msOf(e.Get("BootTime", -1)),
				MainPathMs:  msOf(e.Get("MainPathBootTime", -1)),
				PostBootMs:  msOf(e.Get("BootPostBootTime", -1)),
				Degraded:    truthy(e.Get("BootIsDegradation", -1)),
				AfterUpdate: truthy(e.Get("BootIsRebootAfterInstall", -1)),
			}
			if n, err := strconv.Atoi(e.Get("BootNumStartupApps", -1)); err == nil && n > 0 {
				r.StartupApps = n
			}
			if r.TotalMs > 0 && len(b.Boots) < 30 {
				b.Boots = append(b.Boots, r)
			}
		case e.ID == 200:
			r := scan.ShutdownRecord{Time: eventTime(e, "ShutdownStartTime"), TotalMs: msOf(e.Get("ShutdownTime", -1)), Degraded: truthy(e.Get("ShutdownIsDegradation", -1))}
			if r.TotalMs > 0 && len(b.Shutdowns) < 10 {
				b.Shutdowns = append(b.Shutdowns, r)
			}
		default:
			k, ok := slowKind[e.ID]
			if !ok {
				continue
			}
			name := baseName(e.Get("Name", -1))
			if name == "" {
				continue
			}
			key := fmt.Sprint(e.ID, "|", strings.ToLower(name))
			s := slow[key]
			if s == nil {
				// Il primo evento è il più recente: i suoi tempi sono quelli mostrati.
				s = &scan.BootSlow{Phase: k[0], Kind: k[1], Name: name, Friendly: trimDetail(e.Get("FriendlyName", -1)), Version: trimDetail(e.Get("Version", -1)),
					TotalMs: msOf(e.Get("TotalTime", -1)), DegradationMs: msOf(e.Get("DegradationTime", -1)), Last: isoOf(e.Time)}
				slow[key] = s
				order = append(order, key)
			}
			s.Count++
		}
	}
	for _, k := range order {
		b.Slow = append(b.Slow, *slow[k])
	}
	sort.SliceStable(b.Slow, func(i, j int) bool {
		if b.Slow[i].Count != b.Slow[j].Count {
			return b.Slow[i].Count > b.Slow[j].Count
		}
		return b.Slow[i].DegradationMs > b.Slow[j].DegradationMs
	})
	if len(b.Slow) > 50 {
		b.Slow = b.Slow[:50]
	}
	return b
}

var hexCode = regexp.MustCompile(`^(?:0[xX])?([0-9a-fA-F]{1,8})$`)

// ExceptionCode normalizza un codice di eccezione ("c0000005" → "0xc0000005").
func ExceptionCode(v string) string {
	m := hexCode.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return ""
	}
	return "0x" + strings.ToLower(fmt.Sprintf("%08s", m[1]))
}

func under(path, root string) bool {
	if path == "" || root == "" {
		return false
	}
	p, r := strings.ToLower(strings.TrimSpace(path)), strings.ToLower(strings.TrimRight(root, `\`))+`\`
	return strings.HasPrefix(p, r)
}

func topCounts(m map[string]int, n int) []scan.NameCount {
	out := make([]scan.NameCount, 0, len(m))
	for k, v := range m {
		out = append(out, scan.NameCount{Name: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// AppsFrom riassume arresti e blocchi dei programmi, dal più recente. Dei
// percorsi tiene solo se l'eseguibile sta nella cartella di un utente
// (usersRoot, di solito C:\Users) o di Windows (winDir).
func AppsFrom(events []winevt.Event, days int, usersRoot, winDir string) *scan.AppFailures {
	d := &scan.AppFailures{Days: days, Channel: "ok", Apps: []scan.AppFailure{}}
	type agg struct {
		f         scan.AppFailure
		mods, exc map[string]int
	}
	apps := map[string]*agg{}
	reports := map[string]*scan.WerReport{}
	var rorder []string
	get := func(app string, t time.Time) *agg {
		k := strings.ToLower(app)
		a := apps[k]
		if a == nil {
			a = &agg{f: scan.AppFailure{App: app, Last: isoOf(t)}, mods: map[string]int{}, exc: map[string]int{}}
			apps[k] = a
		}
		return a
	}
	flags := func(a *agg, path, pkg string) {
		if strings.TrimSpace(pkg) != "" {
			a.f.Store = true
		}
		if under(path, usersRoot) {
			a.f.UserFolder = true
		}
		if under(path, winDir) {
			a.f.System = true
		}
	}
	for _, e := range events {
		p := strings.ToLower(e.Provider)
		switch {
		case e.ID == 1000 && p == "application error":
			app := baseName(e.Get("AppName", 0))
			if app == "" {
				continue
			}
			a := get(app, e.Time)
			a.f.Crashes++
			d.Crashes++
			if a.f.Version == "" {
				a.f.Version = trimDetail(e.Get("AppVersion", 1))
			}
			if m := baseName(e.Get("ModuleName", 3)); m != "" {
				a.mods[m]++
			}
			if c := ExceptionCode(e.Get("ExceptionCode", 6)); c != "" {
				a.exc[c]++
			}
			flags(a, e.Get("AppPath", 10), e.Get("PackageFullName", 13))
		case e.ID == 1002 && p == "application hang":
			app := baseName(e.Get("AppName", 0))
			if app == "" {
				continue
			}
			a := get(app, e.Time)
			a.f.Hangs++
			d.Hangs++
			if a.f.Version == "" {
				a.f.Version = trimDetail(e.Get("AppVersion", 1))
			}
			flags(a, e.Get("ExeFileName", 5), e.Get("PackageFullName", 7))
		case e.ID == 1001 && p == "windows error reporting":
			name := trimDetail(e.Get("EventName", 2))
			if name == "" || strings.ContainsAny(name, `\/`) {
				continue
			}
			r := reports[name]
			if r == nil {
				r = &scan.WerReport{Event: name, Last: isoOf(e.Time)}
				reports[name] = r
				rorder = append(rorder, name)
			}
			r.Count++
		}
	}
	for _, a := range apps {
		a.f.Modules = topCounts(a.mods, 3)
		a.f.Exceptions = topCounts(a.exc, 3)
		d.Apps = append(d.Apps, a.f)
	}
	sort.Slice(d.Apps, func(i, j int) bool {
		a, b := d.Apps[i], d.Apps[j]
		if a.Crashes+a.Hangs != b.Crashes+b.Hangs {
			return a.Crashes+a.Hangs > b.Crashes+b.Hangs
		}
		if a.Last != b.Last {
			return a.Last > b.Last
		}
		return a.App < b.App
	})
	if len(d.Apps) > 25 {
		d.Apps = d.Apps[:25]
	}
	for _, k := range rorder {
		d.Reports = append(d.Reports, *reports[k])
	}
	sort.SliceStable(d.Reports, func(i, j int) bool { return d.Reports[i].Count > d.Reports[j].Count })
	if len(d.Reports) > 20 {
		d.Reports = d.Reports[:20]
	}
	return d
}

// HealthScript legge con WMI e COM ciò che non ha un'API nativa semplice:
// l'indice di stabilità degli ultimi 30 giorni e i record di affidabilità
// raggruppati (senza utente, messaggi e nome del computer), la cronologia di
// Windows Update (API di Windows Update Agent, accessibile agli utenti
// standard; date in UTC, come le date di IAutomaticUpdatesResults: da
// verificare per la cronologia), lo stato del file system dei volumi
// (MSFT_Volume.HealthStatus). Gira in parallelo con PSScript, così l'analisi
// non si allunga.
const HealthScript = `$ErrorActionPreference='Stop';try{[Console]::OutputEncoding=[Text.Encoding]::UTF8}catch{};$r=[ordered]@{};$e=[ordered]@{};` +
	`$fu={param($d) if($d -and $d.Year -gt 2000){$d.ToString('yyyy-MM-ddTHH:mm:ss')+'Z'}else{''}};` +
	`try{$q=(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher();$n=$q.GetTotalHistoryCount();$h=@();if($n -gt 0){$h=@($q.QueryHistory(0,[Math]::Min($n,100))|ForEach-Object{@{title="$($_.Title)";date=(&$fu $_.Date);op=[int]$_.Operation;rc=[int]$_.ResultCode;hr=('0x{0:X8}' -f $_.HResult);id="$($_.UpdateIdentity.UpdateID)"}})};$r.wu=$h}catch{$e.wu=('0x{0:X8}' -f $_.Exception.HResult)};` +
	`try{$a=(New-Object -ComObject Microsoft.Update.AutoUpdate).Results;$r.wures=@{install=(&$fu $a.LastInstallationSuccessDate);search=(&$fu $a.LastSearchSuccessDate)}}catch{$e.wures="$_"};` +
	`try{$r.wureboot=[bool](New-Object -ComObject Microsoft.Update.SystemInfo).RebootRequired}catch{$e.wureboot="$_"};` +
	`try{$r.vols=@(Get-CimInstance -Namespace root/Microsoft/Windows/Storage -ClassName MSFT_Volume|Where-Object{$_.DriveLetter}|ForEach-Object{@{letter="$($_.DriveLetter)";health=[int]$_.HealthStatus}})}catch{$e.vols="$_"};` +
	`$since=[Management.ManagementDateTimeConverter]::ToDmtfDateTime((Get-Date).AddDays(-30));` +
	`try{$r.rel=@(Get-CimInstance -Query "SELECT SystemStabilityIndex,TimeGenerated FROM Win32_ReliabilityStabilityMetrics WHERE TimeGenerated >= '$since'" -OperationTimeoutSec 25|ForEach-Object{@{t=$_.TimeGenerated.ToUniversalTime().ToString('o');i=[double]$_.SystemStabilityIndex}})}catch{$e.rel="$_"};` +
	`try{$r.relrec=@(Get-CimInstance -Query "SELECT SourceName,EventIdentifier,ProductName,TimeGenerated FROM Win32_ReliabilityRecords WHERE TimeGenerated >= '$since'" -OperationTimeoutSec 25|Group-Object SourceName,EventIdentifier|` +
	`ForEach-Object{$l=$_.Group|Sort-Object TimeGenerated -Descending|Select-Object -First 1;@{source="$($l.SourceName)";id=[int]$l.EventIdentifier;product="$($l.ProductName)";count=[int]$_.Count;last=$l.TimeGenerated.ToUniversalTime().ToString('o')}})}catch{$e.relrec="$_"};` +
	`$r.errors=$e;ConvertTo-Json -Compress -Depth 5 -InputObject $r`

// healthOut rispecchia l'uscita di HealthScript.
type healthOut struct {
	Rel []struct {
		T string  `json:"t"`
		I float64 `json:"i"`
	} `json:"rel"`
	RelRec []struct {
		Source  string `json:"source"`
		ID      int    `json:"id"`
		Product string `json:"product"`
		Count   int    `json:"count"`
		Last    string `json:"last"`
	} `json:"relrec"`
	WU    *[]psUpdate `json:"wu"`
	WURes *struct {
		Install string `json:"install"`
		Search  string `json:"search"`
	} `json:"wures"`
	WUReboot *bool `json:"wureboot"`
	Vols     []struct {
		Letter string `json:"letter"`
		Health int    `json:"health"`
	} `json:"vols"`
	Errors map[string]string `json:"errors"`
}

func parseHealth(out string) (*healthOut, error) {
	i := strings.Index(out, "{")
	if i < 0 {
		return nil, errors.New("nessun dato in uscita")
	}
	var h healthOut
	if err := json.Unmarshal([]byte(strings.TrimSpace(out[i:])), &h); err != nil {
		return nil, fmt.Errorf("uscita non valida: %w", err)
	}
	return &h, nil
}

// relCategory classifica un record di affidabilità (classificazione di
// Polaris, dalle fonti più comuni).
func relCategory(source string, id int) string {
	s := strings.ToLower(strings.TrimSpace(source))
	switch {
	case s == "application error" && id == 1000:
		return "app-crash"
	case s == "application hang" && id == 1002:
		return "app-hang"
	case (s == "microsoft-windows-wer-systemerrorreporting" || s == "bugcheck") && id == 1001:
		return "windows-failure"
	case (s == "eventlog" && id == 6008) || (s == "microsoft-windows-kernel-power" && id == 41):
		return "shutdown"
	case s == "msiinstaller" && id == 11708:
		return "install-failed"
	case s == "msiinstaller" && (id == 11707 || id == 11724 || id == 1033 || id == 1034):
		return "install"
	case s == "microsoft-windows-windowsupdateclient" && id == 20:
		return "update-failed"
	case s == "microsoft-windows-windowsupdateclient" && id == 19:
		return "update"
	}
	return "other"
}

// ReliabilityFrom prepara l'indice di stabilità: un valore al giorno (l'ultimo),
// gli ultimi 30 giorni. profile è la cartella dell'utente, tolta dai nomi dei prodotti.
func ReliabilityFrom(h *healthOut, wmiEnabled *bool, profile string) *scan.Reliability {
	r := &scan.Reliability{WMIEnabled: wmiEnabled}
	type point struct {
		t time.Time
		i float64
	}
	byDay := map[string]point{}
	var last point
	for _, p := range h.Rel {
		t, err := time.Parse(time.RFC3339Nano, p.T)
		if err != nil || p.I < 0 || p.I > 10 {
			continue
		}
		t = t.UTC()
		day := t.Format("2006-01-02")
		if q, ok := byDay[day]; !ok || t.After(q.t) {
			byDay[day] = point{t, p.I}
		}
		if t.After(last.t) {
			last = point{t, p.I}
		}
	}
	for day, p := range byDay {
		r.Series = append(r.Series, scan.ReliabilityPoint{Date: day, Index: round1(p.i)})
	}
	sort.Slice(r.Series, func(i, j int) bool { return r.Series[i].Date < r.Series[j].Date })
	if len(r.Series) > 30 {
		r.Series = r.Series[len(r.Series)-30:]
	}
	if !last.t.IsZero() {
		v := round1(last.i)
		r.Index, r.IndexAt, r.Available = &v, isoOf(last.t), true
	}
	for _, g := range h.RelRec {
		if g.Count <= 0 || strings.TrimSpace(g.Source) == "" {
			continue
		}
		product := strings.TrimSpace(SanitizeCommand(g.Product, profile))
		if rs := []rune(product); len(rs) > 80 {
			product = string(rs[:80]) + "…"
		}
		last := g.Last
		if t, err := time.Parse(time.RFC3339Nano, g.Last); err == nil {
			last = isoOf(t)
		}
		r.Records = append(r.Records, scan.ReliabilityGroup{Category: relCategory(g.Source, g.ID), Source: trimDetail(g.Source), ID: g.ID, Product: product, Count: g.Count, Last: last})
	}
	sort.SliceStable(r.Records, func(i, j int) bool { return r.Records[i].Count > r.Records[j].Count })
	if len(r.Records) > 40 {
		r.Records = r.Records[:40]
	}
	if !r.Available {
		switch {
		case h.Errors["rel"] != "":
			r.Reason = "error"
		case wmiEnabled != nil && !*wmiEnabled:
			r.Reason = "disabled"
		default:
			r.Reason = "no-data"
		}
	}
	return r
}
