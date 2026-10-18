// Package pcinfo raccoglie i dati del computer: sistema operativo, processore,
// memoria, dischi con il loro stato di salute, volumi, alimentazione,
// programmi all'avvio, processi, eventi rilevanti del registro di sistema,
// antivirus e aggiornamenti. Solo letture: nessuna impostazione viene
// modificata.
//
// Le API native danno i dati veloci; uno script PowerShell (uno solo, con
// uscita JSON) legge ciò che Windows espone tramite CIM: dischi fisici,
// contatori di affidabilità (solo da amministratore), batteria, eventi,
// antivirus, aggiornamenti e schede video. In questo file stanno le parti
// indipendenti dal sistema, collaudate su qualunque piattaforma.
package pcinfo

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"lanterna/internal/scan"
)

// EventsDays è la finestra di lettura del registro di sistema.
const EventsDays = 30

// PSScript legge i dati CIM in un solo passaggio. Ogni sezione è protetta: un
// errore (per esempio i contatori di affidabilità senza privilegi di
// amministratore) finisce in "errors" e non ferma le altre. Degli eventi si
// leggono solo i livelli critico, errore e avviso: lo stesso codice NTFS 98,
// a livello informativo, significa "volume integro".
const PSScript = `$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.Encoding]::UTF8;$r=[ordered]@{};$e=[ordered]@{};` +
	`try{$p=Get-CimInstance Win32_Processor|Select-Object -First 1;$r.cpu=@{name="$($p.Name)".Trim();cores=[int]$p.NumberOfCores;threads=[int]$p.NumberOfLogicalProcessors;maxMhz=[int]$p.MaxClockSpeed}}catch{$e.cpu="$_"};` +
	`try{$r.gpus=@(Get-CimInstance Win32_VideoController|ForEach-Object{$d='';if($_.DriverDate){$d=$_.DriverDate.ToString('yyyy-MM-dd')};@{name="$($_.Name)".Trim();driverVersion="$($_.DriverVersion)";driverDate=$d}})}catch{$e.gpus="$_"};` +
	`try{$r.parts=@(Get-Partition|Where-Object{$_.DriveLetter}|ForEach-Object{@{letter="$($_.DriveLetter)";disk="$($_.DiskNumber)"}})}catch{$e.parts="$_"};` +
	`try{$r.disks=@(Get-PhysicalDisk|ForEach-Object{$d=$_;$rel=$null;` +
	`try{$c=$d|Get-StorageReliabilityCounter;$rel=@{temperature=$c.Temperature;temperatureMax=$c.TemperatureMax;wear=$c.Wear;powerOnHours=$c.PowerOnHours;readErrors=$c.ReadErrorsTotal;readUncorrected=$c.ReadErrorsUncorrected;writeErrors=$c.WriteErrorsTotal;writeUncorrected=$c.WriteErrorsUncorrected;startStop=$c.StartStopCycleCount;loadUnload=$c.LoadUnloadCycleCount}}catch{$e.reliability="$_"};` +
	`@{id="$($d.DeviceId)";name="$($d.FriendlyName)".Trim();media="$($d.MediaType)";bus="$($d.BusType)";size=[double]$d.Size;health="$($d.HealthStatus)";operational=@($d.OperationalStatus|ForEach-Object{"$_"});firmware="$($d.FirmwareVersion)".Trim();rpm=[long]$d.SpindleSpeed;rel=$rel}})}catch{$e.disks="$_"};` +
	`try{$b=Get-CimInstance -Namespace root/wmi -ClassName BatteryStaticData|Select-Object -First 1;$f=Get-CimInstance -Namespace root/wmi -ClassName BatteryFullChargedCapacity|Select-Object -First 1;$cy=$null;try{$cy=[long](Get-CimInstance -Namespace root/wmi -ClassName BatteryCycleCount|Select-Object -First 1).CycleCount}catch{};if($b){$r.battery=@{design=[long]$b.DesignedCapacity;full=[long]$f.FullChargedCapacity;cycles=$cy}}}catch{$e.battery="$_"};` +
	`try{$ev=@(Get-WinEvent -FilterHashtable @{LogName='System';Id=41,6008,1001,7,11,51,153,55,98,129,17,18,19,47;Level=1,2,3;StartTime=(Get-Date).AddDays(-30)} -MaxEvents 3000);` +
	`$r.events=@($ev|Group-Object ProviderName,Id|ForEach-Object{$l=$_.Group|Sort-Object TimeCreated -Descending|Select-Object -First 1;$dt='';try{$dt="$($l.Properties[0].Value)"}catch{};@{source="$($l.ProviderName)";id=[int]$l.Id;count=[int]$_.Count;last=$l.TimeCreated.ToUniversalTime().ToString('o');detail=$dt}})}` +
	`catch{if($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*'){$r.events=@()}else{$e.events="$_"}};` +
	`try{$r.av=@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct|ForEach-Object{$s=[long]$_.productState;@{name="$($_.displayName)";enabled=(($s -band 0x1000) -ne 0);upToDate=(($s -band 0x10) -eq 0);source='securitycenter'}})}catch{$e.av="$_"};` +
	`if(-not $r.av){try{$m=Get-MpComputerStatus;$r.av=@(@{name='Microsoft Defender Antivirus';enabled=[bool]($m.AntivirusEnabled -and $m.RealTimeProtectionEnabled);upToDate=([long]$m.AntivirusSignatureAge -le 7);source='defender'})}catch{$e.defender="$_"}};` +
	`try{$h=Get-HotFix|Where-Object{$_.InstalledOn}|Sort-Object InstalledOn -Descending|Select-Object -First 1;if($h){$r.updates=@{last=$h.InstalledOn.ToString('yyyy-MM-dd');kb="$($h.HotFixID)"}}}catch{$e.updates="$_"};` +
	`$r.errors=$e;ConvertTo-Json -Compress -Depth 5 -InputObject $r`

// psOut rispecchia l'uscita JSON di PSScript.
type psOut struct {
	CPU *struct {
		Name    string `json:"name"`
		Cores   int    `json:"cores"`
		Threads int    `json:"threads"`
		MaxMHz  int    `json:"maxMhz"`
	} `json:"cpu"`
	GPUs []struct {
		Name          string `json:"name"`
		DriverVersion string `json:"driverVersion"`
		DriverDate    string `json:"driverDate"`
	} `json:"gpus"`
	Parts []struct {
		Letter string `json:"letter"`
		Disk   string `json:"disk"`
	} `json:"parts"`
	Disks []struct {
		ID          string   `json:"id"`
		Name        string   `json:"name"`
		Media       string   `json:"media"`
		Bus         string   `json:"bus"`
		Size        float64  `json:"size"`
		Health      string   `json:"health"`
		Operational []string `json:"operational"`
		Firmware    string   `json:"firmware"`
		RPM         int      `json:"rpm"`
		Rel         *struct {
			Temperature      *float64 `json:"temperature"`
			TemperatureMax   *float64 `json:"temperatureMax"`
			Wear             *float64 `json:"wear"`
			PowerOnHours     *int64   `json:"powerOnHours"`
			ReadErrors       *int64   `json:"readErrors"`
			ReadUncorrected  *int64   `json:"readUncorrected"`
			WriteErrors      *int64   `json:"writeErrors"`
			WriteUncorrected *int64   `json:"writeUncorrected"`
			StartStop        *int64   `json:"startStop"`
			LoadUnload       *int64   `json:"loadUnload"`
		} `json:"rel"`
	} `json:"disks"`
	Battery *struct {
		Design *int64 `json:"design"`
		Full   *int64 `json:"full"`
		Cycles *int64 `json:"cycles"`
	} `json:"battery"`
	Events *[]struct {
		Source string `json:"source"`
		ID     int    `json:"id"`
		Count  int    `json:"count"`
		Last   string `json:"last"`
		Detail string `json:"detail"`
	} `json:"events"`
	AV []struct {
		Name     string `json:"name"`
		Enabled  bool   `json:"enabled"`
		UpToDate *bool  `json:"upToDate"`
		Source   string `json:"source"`
	} `json:"av"`
	Updates *struct {
		Last string `json:"last"`
		KB   string `json:"kb"`
	} `json:"updates"`
	Errors map[string]string `json:"errors"`
}

// parsePS estrae l'oggetto JSON dall'uscita di PowerShell (che può avere
// righe di avviso prima).
func parsePS(out string) (*psOut, error) {
	i := strings.Index(out, "{")
	if i < 0 {
		return nil, errors.New("nessun dato in uscita")
	}
	var p psOut
	if err := json.Unmarshal([]byte(strings.TrimSpace(out[i:])), &p); err != nil {
		return nil, fmt.Errorf("uscita non valida: %w", err)
	}
	return &p, nil
}

// MediaOf normalizza il tipo di supporto di MSFT_PhysicalDisk.
func MediaOf(media string, rpm int) string {
	switch strings.ToUpper(strings.TrimSpace(media)) {
	case "HDD", "3":
		return "hdd"
	case "SSD", "4":
		return "ssd"
	case "SCM", "5":
		return "scm"
	}
	// Alcuni controller non dichiarano il tipo ma la velocità di rotazione sì.
	if rpm > 0 && rpm != 0xFFFFFFFF {
		return "hdd"
	}
	return "unknown"
}

// HealthOf normalizza HealthStatus.
func HealthOf(h string) string {
	switch strings.ToLower(strings.TrimSpace(h)) {
	case "healthy", "0":
		return "healthy"
	case "warning", "1":
		return "warning"
	case "unhealthy", "2":
		return "unhealthy"
	}
	return "unknown"
}

// ClassifyEvent associa fonte e codice di un evento a una categoria
// comprensibile; "" per le combinazioni che non interessano (stessi codici
// usati da altri componenti).
func ClassifyEvent(source string, id int) string {
	s := strings.ToLower(source)
	switch {
	case s == "microsoft-windows-kernel-power" && id == 41, s == "eventlog" && id == 6008:
		return "unexpected-shutdown"
	case (s == "microsoft-windows-wer-systemerrorreporting" || s == "bugcheck") && id == 1001:
		return "bugcheck"
	case s == "disk" && (id == 7 || id == 11 || id == 51):
		return "disk-error"
	case s == "disk" && id == 153:
		return "disk-retry"
	case (s == "ntfs" || s == "microsoft-windows-ntfs") && (id == 55 || id == 98):
		return "filesystem"
	case (s == "storahci" || s == "stornvme" || s == "storport" || strings.HasPrefix(s, "iastor")) && id == 129:
		return "storage-reset"
	case s == "microsoft-windows-whea-logger" && id == 18:
		return "whea-fatal"
	case s == "microsoft-windows-whea-logger" && (id == 17 || id == 19 || id == 47):
		return "whea-corrected"
	}
	return ""
}

// keepDetail dice per quali categorie il primo parametro dell'evento è utile
// (codice della schermata blu, disco coinvolto) e non è un dato personale.
func keepDetail(kind string) bool {
	switch kind {
	case "bugcheck", "disk-error", "disk-retry", "filesystem", "storage-reset":
		return true
	}
	return false
}

// StartupEnabled interpreta un valore di StartupApproved: il primo byte pari
// (0x02, 0x06) indica un elemento attivo, dispari (0x03, 0x07) disattivato da
// Gestione attività o dalle Impostazioni.
func StartupEnabled(b []byte) bool {
	return len(b) == 0 || b[0]&1 == 0
}

// SanitizeCommand sostituisce la cartella dell'utente con %USERPROFILE%: i
// rapporti esportati non devono rivelare il nome dell'account.
func SanitizeCommand(cmd, profile string) string {
	cmd = strings.TrimSpace(cmd)
	if profile == "" || len(cmd) < len(profile) {
		return cmd
	}
	low := strings.ToLower(cmd)
	p := strings.ToLower(strings.TrimRight(profile, `\`))
	var b strings.Builder
	for {
		i := strings.Index(low, p)
		if i < 0 {
			b.WriteString(cmd)
			return b.String()
		}
		b.WriteString(cmd[:i])
		b.WriteString("%USERPROFILE%")
		cmd, low = cmd[i+len(p):], low[i+len(p):]
	}
}

// OSName corregge il nome commerciale: il registro di Windows 11 riporta
// ancora "Windows 10" in ProductName.
func OSName(product string, build int, server bool) string {
	product = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(product), "Microsoft "))
	if product == "" {
		product = "Windows"
	}
	if !server && build >= 22000 && strings.HasPrefix(product, "Windows 10") {
		product = "Windows 11" + strings.TrimPrefix(product, "Windows 10")
	}
	return product
}

// PlanKind riconosce gli schemi di risparmio energia predefiniti dal GUID.
func PlanKind(guid string) string {
	switch strings.ToLower(strings.Trim(guid, "{}")) {
	case "381b4222-f694-41f0-9685-ff5bb260df2e":
		return "balanced"
	case "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c":
		return "high"
	case "a1841308-3541-4fab-bc81-f71556f20b4a":
		return "saver"
	case "e9a42b02-d5df-448d-aa00-03f14749eb61":
		return "ultimate"
	}
	return "custom"
}

// ProcSample è la lettura di un processo in un istante.
type ProcSample struct {
	PID    uint32
	Name   string
	CPU    uint64 // tempo di CPU in unità da 100 ns (kernel + utente)
	Memory uint64 // memoria di lavoro in byte
}

// GroupProcesses confronta due letture e raggruppa per nome (i browser
// lanciano decine di processi): CPU in percentuale della capacità totale,
// memoria sommata. Restituisce i processi che pesano di più.
func GroupProcesses(before, after []ProcSample, elapsed time.Duration, ncpu int, top int) []scan.ProcessInfo {
	prev := map[uint32]ProcSample{}
	for _, p := range before {
		prev[p.PID] = p
	}
	type agg struct {
		name  string
		count int
		cpu   float64
		mem   float64
		hasCP bool
	}
	by := map[string]*agg{}
	capacity := float64(elapsed.Nanoseconds()/100) * float64(max(ncpu, 1))
	for _, p := range after {
		key := strings.ToLower(p.Name)
		a := by[key]
		if a == nil {
			a = &agg{name: p.Name}
			by[key] = a
		}
		a.count++
		a.mem += float64(p.Memory) / (1 << 20)
		if q, ok := prev[p.PID]; ok && capacity > 0 && p.CPU >= q.CPU {
			a.cpu += 100 * float64(p.CPU-q.CPU) / capacity
			a.hasCP = true
		}
	}
	list := make([]*agg, 0, len(by))
	for _, a := range by {
		list = append(list, a)
	}
	pick := map[*agg]bool{}
	sort.Slice(list, func(i, j int) bool {
		return list[i].cpu > list[j].cpu || (list[i].cpu == list[j].cpu && list[i].name < list[j].name)
	})
	for i := 0; i < len(list) && i < top; i++ {
		if list[i].cpu >= 0.5 {
			pick[list[i]] = true
		}
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].mem > list[j].mem || (list[i].mem == list[j].mem && list[i].name < list[j].name)
	})
	for i := 0; i < len(list) && i < top; i++ {
		pick[list[i]] = true
	}
	out := []scan.ProcessInfo{}
	for _, a := range list {
		if !pick[a] {
			continue
		}
		pi := scan.ProcessInfo{Name: a.name, Count: a.count, MemoryMB: round1(a.mem)}
		if a.hasCP {
			v := round1(a.cpu)
			pi.CPUPct = &v
		}
		out = append(out, pi)
	}
	sort.SliceStable(out, func(i, j int) bool { return cpuOf(out[i]) > cpuOf(out[j]) })
	return out
}

func cpuOf(p scan.ProcessInfo) float64 {
	if p.CPUPct == nil {
		return -1
	}
	return *p.CPUPct
}

func round1(v float64) float64 { return float64(int64(v*10+0.5)) / 10 }

// loadOf calcola il carico in percentuale dai tempi di GetSystemTimes: il
// tempo kernel comprende quello inattivo, quindi il totale è kernel + utente.
func loadOf(idle, total uint64) *float64 {
	if total == 0 {
		return nil
	}
	v := round1(100 * (1 - float64(idle)/float64(total)))
	v = min(max(v, 0), 100)
	return &v
}

// merge completa i dati nativi con quelli letti da PowerShell.
func merge(pc *scan.PcData, ps *psOut, systemDrive string) {
	if ps.CPU != nil && ps.CPU.Name != "" {
		if pc.CPU == nil {
			pc.CPU = &scan.PcCPU{Name: ps.CPU.Name}
		}
		if pc.CPU.Name == "" {
			pc.CPU.Name = ps.CPU.Name
		}
		pc.CPU.Cores = ps.CPU.Cores
		if ps.CPU.Threads > 0 {
			pc.CPU.Threads = ps.CPU.Threads
		}
		if ps.CPU.MaxMHz > 0 {
			pc.CPU.MaxMHz = ps.CPU.MaxMHz
		}
	}
	for _, g := range ps.GPUs {
		if g.Name == "" {
			continue
		}
		pc.GPUs = append(pc.GPUs, scan.PcGPU{Name: g.Name, DriverVersion: g.DriverVersion, DriverDate: g.DriverDate})
	}
	letterDisk := map[string]string{}
	for _, p := range ps.Parts {
		if p.Letter != "" {
			letterDisk[strings.ToUpper(p.Letter[:1])+":"] = p.Disk
		}
	}
	sysDisk := letterDisk[strings.ToUpper(systemDrive)]
	for i := range pc.Volumes {
		pc.Volumes[i].Disk = letterDisk[strings.ToUpper(pc.Volumes[i].Letter)]
	}
	for _, d := range ps.Disks {
		pd := scan.PhysicalDisk{
			ID:          d.ID,
			Name:        d.Name,
			Media:       MediaOf(d.Media, d.RPM),
			Bus:         d.Bus,
			SizeGB:      round1(d.Size / 1e9),
			Health:      HealthOf(d.Health),
			Operational: d.Operational,
			Firmware:    d.Firmware,
			System:      sysDisk != "" && d.ID == sysDisk,
		}
		if d.RPM > 0 && d.RPM != 0xFFFFFFFF {
			pd.SpindleRPM = d.RPM
		}
		if r := d.Rel; r != nil {
			rel := &scan.DiskReliability{
				WearPct:          r.Wear,
				PowerOnHours:     r.PowerOnHours,
				ReadErrors:       r.ReadErrors,
				ReadUncorrected:  r.ReadUncorrected,
				WriteErrors:      r.WriteErrors,
				WriteUncorrected: r.WriteUncorrected,
				StartStopCycles:  r.StartStop,
				LoadUnloadCycles: r.LoadUnload,
			}
			// Una temperatura pari a zero significa "non riportata".
			if r.Temperature != nil && *r.Temperature > 0 {
				rel.TemperatureC = r.Temperature
			}
			if r.TemperatureMax != nil && *r.TemperatureMax > 0 {
				rel.TemperatureMaxC = r.TemperatureMax
			}
			if pd.Media != "ssd" && pd.Media != "scm" {
				rel.WearPct = nil // l'usura ha senso solo per le memorie flash
			}
			if !relEmpty(rel) {
				pd.Reliability = rel
			}
		}
		pc.Disks = append(pc.Disks, pd)
	}
	if b := ps.Battery; b != nil && b.Design != nil && *b.Design > 0 {
		if pc.Battery == nil {
			pc.Battery = &scan.Battery{}
		}
		pc.Battery.DesignMWh = b.Design
		if b.Full != nil && *b.Full > 0 {
			pc.Battery.FullMWh = b.Full
		}
		if b.Cycles != nil && *b.Cycles > 0 {
			pc.Battery.Cycles = b.Cycles
		}
	}
	if ps.Events != nil {
		pc.EventsDays = EventsDays
		pc.Events = []scan.EventGroup{}
		for _, ev := range *ps.Events {
			kind := ClassifyEvent(ev.Source, ev.ID)
			if kind == "" {
				continue
			}
			g := scan.EventGroup{Kind: kind, Source: ev.Source, ID: ev.ID, Count: ev.Count, Last: ev.Last}
			if keepDetail(kind) {
				g.Detail = trimDetail(ev.Detail)
			}
			pc.Events = append(pc.Events, g)
		}
		sort.SliceStable(pc.Events, func(i, j int) bool { return pc.Events[i].Last > pc.Events[j].Last })
	}
	if ps.AV != nil {
		pc.Antivirus = []scan.AvProduct{}
		for _, a := range ps.AV {
			if a.Name != "" {
				pc.Antivirus = append(pc.Antivirus, scan.AvProduct{Name: a.Name, Enabled: a.Enabled, UpToDate: a.UpToDate, Source: a.Source})
			}
		}
	}
	if u := ps.Updates; u != nil && u.Last != "" {
		if pc.Updates == nil {
			pc.Updates = &scan.UpdateInfo{}
		}
		pc.Updates.LastInstalled, pc.Updates.LastKB = u.Last, u.KB
	}
}

// relEmpty riconosce i contatori senza alcun valore: senza privilegi alcune
// versioni di Windows restituiscono l'oggetto vuoto invece di un errore.
func relEmpty(r *scan.DiskReliability) bool {
	return r.TemperatureC == nil && r.TemperatureMaxC == nil && r.WearPct == nil && r.PowerOnHours == nil &&
		r.ReadErrors == nil && r.ReadUncorrected == nil && r.WriteErrors == nil && r.WriteUncorrected == nil &&
		r.StartStopCycles == nil && r.LoadUnloadCycles == nil
}

func trimDetail(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(s, "\r", " "), "\n", " "))
	if r := []rune(s); len(r) > 120 {
		s = string(r[:120])
	}
	return s
}
