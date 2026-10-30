// Package sensors è il monitor dei sensori di Polaris, sul modello della
// finestra "Sensors" di HWiNFO ma senza driver in kernel: legge solo ciò che
// Windows espone in modalità utente con interfacce documentate. Processore
// (utilizzo, frequenze effettive, limite di prestazioni, stati C, consumo se
// il PC espone i contatori di energia), zone termiche ACPI, scheda video
// (utilizzo per motore, memoria e, dal driver, temperatura, ventola,
// frequenze), memoria, dischi (attività, velocità, tempo di risposta,
// temperatura), rete, batteria e sistema.
//
// Le temperature, le tensioni e le ventole del processore e della scheda
// madre si leggono solo dai registri dei chip con un driver: Polaris non ne
// usa e lo dice (Snapshot.Missing).
package sensors

import (
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"lanterna/internal/cpuclock"
)

// Sensor è una grandezza misurata in questo istante.
type Sensor struct {
	// ID resta uguale da una lettura all'altra: l'interfaccia ci appoggia
	// minimo, massimo, media e grafico.
	ID    string  `json:"id"`
	Label string  `json:"label"`
	Value float64 `json:"value"`
	// Unit: "%", "MHz", "°C", "W", "V", "MB/s", "Mbit/s", "ms", "GB", "MB",
	// "Wh", "giri/min", "/s", "ore" o vuota (conteggi).
	Unit string `json:"unit"`
	// Soglie di attenzione e di allarme; con Below valgono verso il basso.
	Warn  *float64 `json:"warn,omitempty"`
	Crit  *float64 `json:"crit,omitempty"`
	Below bool     `json:"below,omitempty"`
	// Detail: riga di dettaglio, nascosta finché non si chiede di vederla.
	Detail bool `json:"detail,omitempty"`
}

// Group riunisce i sensori di un dispositivo.
type Group struct {
	ID string `json:"id"`
	// Kind: cpu, thermal, gpu, memory, disk, network, battery, system.
	Kind    string   `json:"kind"`
	Name    string   `json:"name"`
	Sub     string   `json:"sub,omitempty"`
	Sensors []Sensor `json:"sensors"`
}

// Snapshot è una lettura di tutti i sensori.
type Snapshot struct {
	At     time.Time `json:"at"`
	Groups []Group   `json:"groups"`
	// Missing elenca, in parole semplici, ciò che su questo PC non si legge.
	Missing []string `json:"missing,omitempty"`
}

// ErrUnavailable: niente contatori (sistema diverso da Windows).
var ErrUnavailable = errors.New("sensori non disponibili su questo sistema")

// Chiavi dei contatori PDH nella lettura grezza.
const (
	cPerf      = "cpu.perf"
	cFreq      = "cpu.freq"
	cTime      = "cpu.time"
	cUtility   = "cpu.utility"
	cLimit     = "cpu.limit"
	cC1        = "cpu.c1"
	cC2        = "cpu.c2"
	cC3        = "cpu.c3"
	cInterrupt = "cpu.interrupt"
	cDPC       = "cpu.dpc"
	cEnergy    = "energy.power"
	cTzTemp    = "tz.temp"
	cTzHP      = "tz.hp"
	cTzPassive = "tz.passive"
	cGpuEngine = "gpu.engine"
	cGpuDedic  = "gpu.dedicated"
	cGpuShared = "gpu.shared"
	cDiskIdle  = "disk.idle"
	cDiskRead  = "disk.read"
	cDiskWrite = "disk.write"
	cDiskSec   = "disk.sec"
	cDiskQueue = "disk.queue"
	cNetRx     = "net.rx"
	cNetTx     = "net.tx"
	cNetBw     = "net.bw"
	cPages     = "mem.pages"
	cPageFile  = "page.usage"
	cProcs     = "sys.processes"
	cThreads   = "sys.threads"
	cCtx       = "sys.ctx"
	cQueue     = "sys.queue"
	cUptime    = "sys.uptime"
)

// Counters sono i percorsi inglesi dei contatori PDH letti dal monitor.
var Counters = map[string]string{
	cPerf:      `\Processor Information(*)\% Processor Performance`,
	cFreq:      `\Processor Information(*)\Processor Frequency`,
	cTime:      `\Processor Information(*)\% Processor Time`,
	cUtility:   `\Processor Information(_Total)\% Processor Utility`,
	cLimit:     `\Processor Information(_Total)\% Performance Limit`,
	cC1:        `\Processor Information(_Total)\% C1 Time`,
	cC2:        `\Processor Information(_Total)\% C2 Time`,
	cC3:        `\Processor Information(_Total)\% C3 Time`,
	cInterrupt: `\Processor Information(_Total)\% Interrupt Time`,
	cDPC:       `\Processor Information(_Total)\% DPC Time`,
	cEnergy:    `\Energy Meter(*)\Power`,
	cTzTemp:    `\Thermal Zone Information(*)\Temperature`,
	cTzHP:      `\Thermal Zone Information(*)\High Precision Temperature`,
	cTzPassive: `\Thermal Zone Information(*)\% Passive Limit`,
	cGpuEngine: `\GPU Engine(*)\Utilization Percentage`,
	cGpuDedic:  `\GPU Adapter Memory(*)\Dedicated Usage`,
	cGpuShared: `\GPU Adapter Memory(*)\Shared Usage`,
	cDiskIdle:  `\PhysicalDisk(*)\% Idle Time`,
	cDiskRead:  `\PhysicalDisk(*)\Disk Read Bytes/sec`,
	cDiskWrite: `\PhysicalDisk(*)\Disk Write Bytes/sec`,
	cDiskSec:   `\PhysicalDisk(*)\Avg. Disk sec/Transfer`,
	cDiskQueue: `\PhysicalDisk(*)\Current Disk Queue Length`,
	cNetRx:     `\Network Interface(*)\Bytes Received/sec`,
	cNetTx:     `\Network Interface(*)\Bytes Sent/sec`,
	cNetBw:     `\Network Interface(*)\Current Bandwidth`,
	cPages:     `\Memory\Pages/sec`,
	cPageFile:  `\Paging File(_Total)\% Usage`,
	cProcs:     `\System\Processes`,
	cThreads:   `\System\Threads`,
	cCtx:       `\System\Context Switches/sec`,
	cQueue:     `\System\Processor Queue Length`,
	cUptime:    `\System\System Up Time`,
}

// Memory viene da GlobalMemoryStatusEx (byte).
type Memory struct {
	Total, Avail, CommitTotal, CommitLimit uint64
}

// GPU è la telemetria di una scheda video letta dal driver (D3DKMT). I valori
// assenti sono NaN.
type GPU struct {
	// LUID come nei nomi delle istanze PDH, in minuscolo:
	// "0x00000000_0x0000d1b8" (parte alta, poi parte bassa).
	LUID string
	Name string
	// Software: adattatore senza hardware (Microsoft Basic Render Driver).
	Software                   bool
	TempC, TempWarnC, TempMaxC float64
	FanRPM                     float64
	PowerPct                   float64
	CoreMHz, MemMHz            float64
	VoltageMV                  float64
}

// Battery è lo stato di una batteria (IOCTL della classe batteria). I valori
// assenti sono NaN.
type Battery struct {
	Name string
	// ChargePct: carica in percentuale, valida anche per le batterie che
	// riportano capacità relative (senza wattora).
	ChargePct                    float64
	CapacityWh, FullWh, DesignWh float64
	// RateW: positivo in carica, negativo in scarica.
	RateW, VoltageV, TempC        float64
	Charging, Discharging, OnLine bool
}

// Disk descrive un disco fisico (numero di Windows come chiave).
type Disk struct {
	Model string
	// Flash: SSD o NVMe (soglie di temperatura diverse dai dischi meccanici);
	// nil se non noto.
	Flash *bool
	// TempC: NaN se non letta.
	TempC float64
	// WarnC e CritC: soglie dichiarate dal disco (NaN se non le dichiara).
	WarnC, CritC float64
	// NeedsAdmin: disco ATA, SATA, SAS o dietro un controller RAID, la cui
	// temperatura si legge con SMART solo da amministratore.
	NeedsAdmin bool
}

// Raw è una lettura grezza di tutte le fonti.
type Raw struct {
	// Counters: chiave del contatore → istanza → valore.
	Counters  map[string]map[string]float64
	CPUName   string
	BaseMHz   float64
	Memory    *Memory
	GPUs      []GPU
	GPUErr    error
	Batteries []Battery
	Disks     map[string]Disk
	Elevated  bool
	// NoCounters: Windows non ha dato nessun contatore delle prestazioni.
	NoCounters bool
}

var nan = math.NaN()

func ok(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }

func pf(v float64) *float64 { return &v }

func round(v float64, d int) float64 {
	p := math.Pow(10, float64(d))
	return math.Round(v*p) / p
}

func clamp(v, lo, hi float64) float64 { return math.Max(lo, math.Min(hi, v)) }

// one restituisce il valore di un contatore senza istanze o dell'istanza
// "_Total".
func (r Raw) one(key string) (float64, bool) {
	m := r.Counters[key]
	if v, found := m[""]; found && ok(v) {
		return v, true
	}
	if v, found := m["_Total"]; found && ok(v) {
		return v, true
	}
	return 0, false
}

type builder struct {
	g *Group
}

func (b builder) add(s Sensor) {
	if !ok(s.Value) {
		return
	}
	b.g.Sensors = append(b.g.Sensors, s)
}

// Build trasforma una lettura grezza nei gruppi di sensori.
func Build(r Raw) Snapshot {
	var out Snapshot
	missing := func(s string) { out.Missing = append(out.Missing, s) }
	if r.NoCounters {
		missing("Contatori delle prestazioni di Windows non leggibili: mancano utilizzo, frequenze, attività dei dischi e rete. Succede quando la loro registrazione è danneggiata; di solito si ripristina con il comando lodctr /R da amministratore (da verificare caso per caso).")
	}
	if g := cpuGroup(r); len(g.Sensors) > 0 {
		out.Groups = append(out.Groups, g)
	}
	if _, has := r.Counters[cEnergy]; !has || len(r.Counters[cEnergy]) == 0 {
		missing("Consumo del processore: questo PC non espone a Windows i contatori di energia (Energy Meter).")
	}
	if g := thermalGroup(r); len(g.Sensors) > 0 {
		out.Groups = append(out.Groups, g)
	} else if len(r.Counters[cTzTemp])+len(r.Counters[cTzHP]) > 0 {
		missing("Zone termiche: il firmware di questo PC ne dichiara, ma con valori non validi (fermi a zero o fuori scala).")
	} else {
		missing("Zone termiche: il firmware di questo PC non ne dichiara a Windows.")
	}
	gpus, noTelemetry := gpuGroups(r)
	out.Groups = append(out.Groups, gpus...)
	if len(noTelemetry) > 0 {
		missing("Temperatura e frequenze di " + strings.Join(noTelemetry, ", ") + ": il driver non le fornisce a Windows (servono un driver WDDM 2.4 o successivo e il supporto del produttore).")
	}
	if g := memoryGroup(r); len(g.Sensors) > 0 {
		out.Groups = append(out.Groups, g)
	}
	disks, noTemp := diskGroups(r)
	out.Groups = append(out.Groups, disks...)
	if noTemp && !r.Elevated {
		missing("Temperatura dei dischi SATA: si legge avviando Polaris come amministratore.")
	}
	out.Groups = append(out.Groups, networkGroups(r)...)
	out.Groups = append(out.Groups, batteryGroups(r)...)
	if g := systemGroup(r); len(g.Sensors) > 0 {
		out.Groups = append(out.Groups, g)
	}
	missing("Temperature, tensioni e ventole del processore e della scheda madre: Windows non le espone senza un driver in kernel, che Polaris non usa. Per queste c'è HWiNFO nella Cassetta degli attrezzi.")
	return out
}

func cpuGroup(r Raw) Group {
	g := Group{ID: "cpu", Kind: "cpu", Name: strings.TrimSpace(r.CPUName)}
	if g.Name == "" {
		g.Name = "Processore"
	}
	b := builder{&g}
	if v, found := r.one(cTime); found {
		b.add(Sensor{ID: "cpu.usage", Label: "Utilizzo totale", Value: round(clamp(v, 0, 100), 1), Unit: "%"})
	}
	if v, found := r.one(cUtility); found {
		// Come Gestione attività: oltre la frequenza di base supera 100,
		// e Gestione attività la ferma a 100.
		b.add(Sensor{ID: "cpu.utility", Label: "Utilità (come Gestione attività)", Value: round(clamp(v, 0, 100), 1), Unit: "%"})
	}
	readings := map[string]cpuclock.Reading{}
	for key, set := range map[string]func(*cpuclock.Reading, float64){
		cPerf: func(x *cpuclock.Reading, v float64) { x.Perf = v },
		cFreq: func(x *cpuclock.Reading, v float64) { x.Freq = v },
		cTime: func(x *cpuclock.Reading, v float64) { x.Load = v },
	} {
		for inst, v := range r.Counters[key] {
			x, found := readings[inst]
			if !found {
				x = cpuclock.Reading{Perf: math.NaN(), Freq: math.NaN(), Load: math.NaN()}
			}
			set(&x, v)
			readings[inst] = x
		}
	}
	smp, clocked := cpuclock.Combine(readings, r.BaseMHz)
	if clocked {
		b.add(Sensor{ID: "cpu.clock", Label: "Frequenza effettiva media", Value: round(smp.MHz, 0), Unit: "MHz"})
		b.add(Sensor{ID: "cpu.maxclock", Label: "Core più veloce", Value: round(smp.MaxMHz, 0), Unit: "MHz"})
		if smp.PerfPct > 0 {
			b.add(Sensor{ID: "cpu.perf", Label: "Prestazioni rispetto alla base", Value: round(smp.PerfPct, 0), Unit: "%"})
		}
	}
	if v, found := r.one(cLimit); found && v > 0 {
		// Sotto 100 il processore non garantisce la frequenza nominale:
		// piano energetico, limite di potenza o surriscaldamento.
		b.add(Sensor{ID: "cpu.limit", Label: "Limite di prestazioni", Value: round(clamp(v, 0, 100), 0), Unit: "%", Warn: pf(95), Below: true})
	}
	for _, p := range energyPower(r.Counters[cEnergy]) {
		b.add(p)
	}
	for _, c := range []struct{ key, id, label string }{
		{cC1, "cpu.c1", "Tempo nello stato C1"},
		{cC2, "cpu.c2", "Tempo nello stato C2"},
		{cC3, "cpu.c3", "Tempo nello stato C3"},
		{cInterrupt, "cpu.interrupt", "Tempo per gli interrupt"},
		{cDPC, "cpu.dpc", "Tempo per le DPC"},
	} {
		if v, found := r.one(c.key); found {
			b.add(Sensor{ID: c.id, Label: c.label, Value: round(clamp(v, 0, 100), 1), Unit: "%", Detail: true})
		}
	}
	if clocked {
		for i, c := range smp.Cores {
			if c.MHz > 0 {
				b.add(Sensor{ID: "cpu.core." + c.ID + ".clock", Label: "Processore logico " + strconv.Itoa(i) + ": frequenza", Value: round(c.MHz, 0), Unit: "MHz", Detail: true})
			}
			b.add(Sensor{ID: "cpu.core." + c.ID + ".usage", Label: "Processore logico " + strconv.Itoa(i) + ": utilizzo", Value: c.LoadPct, Unit: "%", Detail: true})
		}
	}
	return g
}

// energyPower traduce i canali di Energy Meter (RAPL sui processori Intel e
// AMD che li espongono) in potenze in watt.
func energyPower(m map[string]float64) []Sensor {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []Sensor
	for _, n := range names {
		v := m[n]
		if !ok(v) || v < 0 {
			continue
		}
		w := v / 1000 // milliwatt
		if w > 2000 {
			continue
		}
		up := strings.ToUpper(n)
		label, id := "Potenza: "+n, "cpu.power."+slug(n)
		switch {
		case strings.HasSuffix(up, "_PKG"):
			label = "Potenza del processore (package)"
		case strings.HasSuffix(up, "_PP0"):
			label = "Potenza dei core"
		case strings.HasSuffix(up, "_PP1"):
			label = "Potenza della grafica integrata"
		case strings.HasSuffix(up, "_DRAM"):
			label = "Potenza della memoria"
		case strings.Contains(up, "PSYS") || strings.Contains(up, "PLATFORM"):
			label = "Potenza della piattaforma"
		}
		if len(names) > 1 && strings.HasPrefix(up, "RAPL_PACKAGE") && !strings.HasPrefix(up, "RAPL_PACKAGE0") {
			label += " (" + n + ")"
		}
		out = append(out, Sensor{ID: id, Label: label, Value: round(w, 1), Unit: "W"})
	}
	return out
}

// slug riduce un nome di istanza a un identificatore stabile.
func slug(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.TrimRight(b.String(), "-")
}

// zoneName accorcia il nome ACPI di una zona termica ("\_TZ.TZ00" → "TZ00").
func zoneName(inst string) string {
	n := inst
	if i := strings.LastIndexAny(n, `.\`); i >= 0 && i < len(n)-1 {
		n = n[i+1:]
	}
	return strings.TrimSpace(n)
}

func thermalGroup(r Raw) Group {
	g := Group{ID: "thermal", Kind: "thermal", Name: "Zone termiche ACPI", Sub: "dichiarate dal firmware"}
	b := builder{&g}
	zones := map[string]float64{}
	for inst, v := range r.Counters[cTzTemp] {
		if ok(v) && v > 0 {
			zones[inst] = v - 273.15 // kelvin
		}
	}
	for inst, v := range r.Counters[cTzHP] {
		if ok(v) && v > 0 {
			zones[inst] = v/10 - 273.15 // decimi di kelvin
		}
	}
	names := make([]string, 0, len(zones))
	for n := range zones {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		c := zones[n]
		// Zone a 0 °C o assurde: il firmware non le aggiorna.
		if c <= 0.5 || c > 150 {
			continue
		}
		b.add(Sensor{ID: "tz." + slug(n) + ".temp", Label: "Zona " + zoneName(n), Value: round(c, 1), Unit: "°C", Warn: pf(85), Crit: pf(95)})
		if p, found := r.Counters[cTzPassive][n]; found && ok(p) && p > 0 {
			b.add(Sensor{ID: "tz." + slug(n) + ".passive", Label: "Zona " + zoneName(n) + ": limite per il calore", Value: round(clamp(p, 0, 100), 0), Unit: "%", Warn: pf(100), Below: true, Detail: true})
		}
	}
	return g
}

// luidOf estrae il LUID, in minuscolo ("0x00000000_0x0000d1b8"), dal nome di
// un'istanza della scheda video
// ("pid_1234_luid_0x00000000_0x0000D1B8_phys_0_eng_0_engtype_3D").
func luidOf(inst string) string {
	i := strings.Index(inst, "luid_")
	if i < 0 {
		return ""
	}
	rest := inst[i+5:]
	parts := strings.SplitN(rest, "_", 3)
	if len(parts) < 2 {
		return ""
	}
	return strings.ToLower(parts[0] + "_" + parts[1])
}

// engineOf restituisce il motore ("phys_0_eng_3") e il suo tipo ("3D",
// "Copy", "VideoDecode"...): una scheda può avere più motori dello stesso
// tipo, per esempio due di codifica video.
func engineOf(inst string) (node, kind string) {
	i := strings.Index(inst, "engtype_")
	p := strings.Index(inst, "phys_")
	if i < 0 || p < 0 || p > i {
		return "", ""
	}
	return strings.TrimSuffix(inst[p:i], "_"), inst[i+8:]
}

var engineLabels = map[string]string{
	"3D":              "Motore 3D",
	"Copy":            "Copia",
	"VideoDecode":     "Decodifica video",
	"VideoEncode":     "Codifica video",
	"VideoProcessing": "Elaborazione video",
	"Compute":         "Calcolo",
	"Cuda":            "Calcolo (CUDA)",
}

// gpuGroups restituisce i gruppi delle schede video e i nomi di quelle
// mostrate senza telemetria dal driver.
func gpuGroups(r Raw) (groups []Group, noTelemetry []string) {
	type acc struct {
		nodes         map[string]float64 // motore → somma dei processi
		kinds         map[string]string  // motore → tipo
		dedic, shared float64
		hasMem        bool
	}
	by := map[string]*acc{}
	get := func(l string) *acc {
		a := by[l]
		if a == nil {
			a = &acc{nodes: map[string]float64{}, kinds: map[string]string{}, dedic: math.NaN(), shared: math.NaN()}
			by[l] = a
		}
		return a
	}
	// Come Gestione attività: per ogni motore la somma dei processi, per la
	// scheda il motore più impegnato.
	for inst, v := range r.Counters[cGpuEngine] {
		l := luidOf(inst)
		node, kind := engineOf(inst)
		if l == "" || node == "" || kind == "" || !ok(v) || v < 0 {
			continue
		}
		a := get(l)
		a.nodes[node] += v
		a.kinds[node] = kind
	}
	for inst, v := range r.Counters[cGpuDedic] {
		if l := luidOf(inst); l != "" && ok(v) {
			a := get(l)
			a.dedic, a.hasMem = v, true
		}
	}
	for inst, v := range r.Counters[cGpuShared] {
		if l := luidOf(inst); l != "" && ok(v) {
			a := get(l)
			a.shared, a.hasMem = v, true
		}
	}
	known := map[string]GPU{}
	var order []string
	for _, x := range r.GPUs {
		if x.Software {
			delete(by, x.LUID)
			continue
		}
		known[x.LUID] = x
		order = append(order, x.LUID)
		get(x.LUID)
	}
	var rest []string
	for l := range by {
		if _, found := known[l]; !found {
			rest = append(rest, l)
		}
	}
	sort.Strings(rest)
	order = append(order, rest...)
	n := 0
	for _, l := range order {
		a := by[l]
		if a == nil {
			continue
		}
		x, hasInfo := known[l]
		missingTelemetry := false
		g := Group{ID: "gpu." + l, Kind: "gpu", Name: strings.TrimSpace(x.Name)}
		if g.Name == "" {
			g.Name = "Scheda video " + strconv.Itoa(n+1)
		}
		b := builder{&g}
		pre := g.ID + "."
		// Per ogni tipo di motore il più impegnato (la riga di dettaglio),
		// per la scheda il massimo di tutti.
		engines := map[string]float64{}
		for node, v := range a.nodes {
			k := a.kinds[node]
			engines[k] = math.Max(engines[k], math.Min(100, v))
		}
		if len(a.nodes) > 0 {
			top := 0.0
			for _, v := range engines {
				top = math.Max(top, v)
			}
			b.add(Sensor{ID: pre + "usage", Label: "Utilizzo", Value: round(clamp(top, 0, 100), 1), Unit: "%"})
		}
		if hasInfo {
			if ok(x.TempC) && x.TempC > 0 && x.TempC < 150 {
				warn, crit := 85.0, 95.0
				if ok(x.TempWarnC) && x.TempWarnC > 40 && x.TempWarnC < 150 {
					warn = x.TempWarnC
				}
				if ok(x.TempMaxC) && x.TempMaxC > warn && x.TempMaxC < 150 {
					crit = x.TempMaxC
				}
				b.add(Sensor{ID: pre + "temp", Label: "Temperatura", Value: round(x.TempC, 1), Unit: "°C", Warn: pf(warn), Crit: pf(crit)})
			}
			if ok(x.FanRPM) && x.FanRPM > 0 && x.FanRPM < 30000 {
				b.add(Sensor{ID: pre + "fan", Label: "Ventola", Value: round(x.FanRPM, 0), Unit: "giri/min"})
			}
			if ok(x.PowerPct) && x.PowerPct > 0 && x.PowerPct <= 200 {
				// Percentuale indicata dal driver: Windows non documenta il
				// riferimento (non sono watt).
				b.add(Sensor{ID: pre + "power", Label: "Potenza (percentuale indicata dal driver)", Value: round(x.PowerPct, 1), Unit: "%"})
			}
			if ok(x.CoreMHz) && x.CoreMHz > 0 && x.CoreMHz < 10000 {
				b.add(Sensor{ID: pre + "coreclock", Label: "Frequenza del motore grafico", Value: round(x.CoreMHz, 0), Unit: "MHz"})
			}
			if ok(x.MemMHz) && x.MemMHz > 0 && x.MemMHz < 50000 {
				b.add(Sensor{ID: pre + "memclock", Label: "Frequenza della memoria video", Value: round(x.MemMHz, 0), Unit: "MHz"})
			}
			if ok(x.VoltageMV) && x.VoltageMV > 0 && x.VoltageMV < 3000 {
				b.add(Sensor{ID: pre + "voltage", Label: "Tensione del motore grafico", Value: round(x.VoltageMV/1000, 3), Unit: "V"})
			}
			missingTelemetry = !ok(x.TempC) && !ok(x.CoreMHz) && !ok(x.FanRPM)
		}
		if a.hasMem {
			if ok(a.dedic) {
				b.add(Sensor{ID: pre + "dedicated", Label: "Memoria dedicata in uso", Value: round(a.dedic/(1<<20), 0), Unit: "MB"})
			}
			if ok(a.shared) {
				b.add(Sensor{ID: pre + "shared", Label: "Memoria condivisa in uso", Value: round(a.shared/(1<<20), 0), Unit: "MB"})
			}
		}
		kinds := make([]string, 0, len(engines))
		for e := range engines {
			kinds = append(kinds, e)
		}
		sort.Strings(kinds)
		for _, e := range kinds {
			label := engineLabels[e]
			if label == "" {
				if strings.HasPrefix(e, "Compute") {
					label = "Calcolo " + strings.TrimPrefix(strings.TrimPrefix(e, "Compute"), "_")
				} else {
					label = "Motore " + e
				}
			}
			b.add(Sensor{ID: pre + "engine." + slug(e), Label: strings.TrimSpace(label), Value: round(clamp(engines[e], 0, 100), 1), Unit: "%", Detail: e != "3D"})
		}
		// La nota sulla telemetria mancante vale solo per le schede mostrate.
		if len(g.Sensors) > 0 {
			groups = append(groups, g)
			n++
			if missingTelemetry || !hasInfo && r.GPUErr != nil && len(r.GPUs) == 0 {
				noTelemetry = append(noTelemetry, g.Name)
			}
		}
	}
	return groups, noTelemetry
}

func memoryGroup(r Raw) Group {
	g := Group{ID: "memory", Kind: "memory", Name: "Memoria"}
	b := builder{&g}
	const gib = 1 << 30
	if m := r.Memory; m != nil && m.Total > 0 {
		used := float64(m.Total - min(m.Avail, m.Total))
		g.Sub = Number(round(float64(m.Total)/gib, 1)) + " GB utilizzabili"
		b.add(Sensor{ID: "mem.load", Label: "Memoria fisica in uso", Value: round(100*used/float64(m.Total), 0), Unit: "%", Warn: pf(85), Crit: pf(95)})
		b.add(Sensor{ID: "mem.used", Label: "Memoria fisica usata", Value: round(used/gib, 2), Unit: "GB"})
		b.add(Sensor{ID: "mem.avail", Label: "Memoria fisica disponibile", Value: round(float64(m.Avail)/gib, 2), Unit: "GB"})
		if m.CommitLimit > 0 {
			b.add(Sensor{ID: "mem.commit", Label: "Memoria impegnata", Value: round(float64(m.CommitTotal)/gib, 2), Unit: "GB"})
			b.add(Sensor{ID: "mem.commitload", Label: "Memoria impegnata sul limite", Value: round(100*float64(m.CommitTotal)/float64(m.CommitLimit), 0), Unit: "%", Warn: pf(85), Crit: pf(95)})
		}
	}
	if v, found := r.one(cPageFile); found {
		b.add(Sensor{ID: "mem.pagefile", Label: "File di paging usato", Value: round(clamp(v, 0, 100), 1), Unit: "%"})
	}
	if v, found := r.one(cPages); found && v >= 0 {
		b.add(Sensor{ID: "mem.pages", Label: "Pagine lette o scritte su disco", Value: round(v, 0), Unit: "/s", Detail: true})
	}
	return g
}

// diskInstance divide "0 C: D:" in numero del disco e lettere.
func diskInstance(inst string) (num, letters string, valid bool) {
	n, rest, _ := strings.Cut(strings.TrimSpace(inst), " ")
	if _, err := strconv.Atoi(n); err != nil {
		return "", "", false
	}
	return n, strings.TrimSpace(rest), true
}

func diskGroups(r Raw) (groups []Group, noTemp bool) {
	nums := map[string]string{}
	for _, key := range []string{cDiskIdle, cDiskRead, cDiskWrite, cDiskSec, cDiskQueue} {
		for inst := range r.Counters[key] {
			if n, _, valid := diskInstance(inst); valid {
				nums[n] = inst
			}
		}
	}
	for n := range r.Disks {
		if _, found := nums[n]; !found {
			nums[n] = ""
		}
	}
	keys := make([]string, 0, len(nums))
	for n := range nums {
		keys = append(keys, n)
	}
	sort.Slice(keys, func(i, j int) bool { a, _ := strconv.Atoi(keys[i]); b, _ := strconv.Atoi(keys[j]); return a < b })
	for _, n := range keys {
		inst := nums[n]
		_, letters, _ := diskInstance(inst)
		d, hasInfo := r.Disks[n]
		g := Group{ID: "disk." + n, Kind: "disk", Name: "Disco " + n, Sub: letters}
		if hasInfo && strings.TrimSpace(d.Model) != "" {
			g.Name = "Disco " + n + ": " + strings.TrimSpace(d.Model)
		}
		b := builder{&g}
		pre := g.ID + "."
		hasTemp := hasInfo && ok(d.TempC) && d.TempC > 0 && d.TempC < 120
		if hasTemp {
			// Come nella valutazione SMART: 70 e 80 °C per i dischi a stato
			// solido, 55 e 60 per quelli meccanici; a metà se non è noto.
			warn, crit := 60.0, 70.0
			if d.Flash != nil && *d.Flash {
				warn, crit = 70, 80
			} else if d.Flash != nil {
				warn, crit = 55, 60
			}
			// Le soglie dichiarate dal disco, se plausibili, valgono di più.
			if ok(d.WarnC) && d.WarnC >= 40 && d.WarnC < 120 {
				warn = d.WarnC
				if ok(d.CritC) && d.CritC > warn && d.CritC < 130 {
					crit = d.CritC
				} else if crit <= warn {
					crit = warn + 5
				}
			}
			b.add(Sensor{ID: pre + "temp", Label: "Temperatura", Value: round(d.TempC, 0), Unit: "°C", Warn: pf(warn), Crit: pf(crit)})
		}
		if inst != "" {
			if v, found := r.Counters[cDiskIdle][inst]; found && ok(v) {
				b.add(Sensor{ID: pre + "activity", Label: "Attività", Value: round(clamp(100-v, 0, 100), 1), Unit: "%"})
			}
			if v, found := r.Counters[cDiskRead][inst]; found && ok(v) && v >= 0 {
				b.add(Sensor{ID: pre + "read", Label: "Lettura", Value: round(v/1e6, 2), Unit: "MB/s"})
			}
			if v, found := r.Counters[cDiskWrite][inst]; found && ok(v) && v >= 0 {
				b.add(Sensor{ID: pre + "write", Label: "Scrittura", Value: round(v/1e6, 2), Unit: "MB/s"})
			}
			if v, found := r.Counters[cDiskSec][inst]; found && ok(v) && v >= 0 {
				b.add(Sensor{ID: pre + "latency", Label: "Tempo di risposta medio", Value: round(v*1000, 1), Unit: "ms", Warn: pf(100), Crit: pf(500)})
			}
			if v, found := r.Counters[cDiskQueue][inst]; found && ok(v) && v >= 0 {
				b.add(Sensor{ID: pre + "queue", Label: "Richieste in coda", Value: round(v, 0), Unit: "", Detail: true})
			}
		}
		if len(g.Sensors) > 0 {
			groups = append(groups, g)
			// La nota sull'amministratore vale solo per i dischi mostrati
			// che la richiedono davvero (non per NVMe, USB o dischi virtuali).
			if !hasTemp && hasInfo && d.NeedsAdmin {
				noTemp = true
			}
		}
	}
	return groups, noTemp
}

// virtualNIC: interfacce che non sono collegamenti reali.
func virtualNIC(name string) bool {
	l := strings.ToLower(name)
	for _, s := range []string{"isatap", "teredo", "loopback", "6to4", "pseudo", "kernel debug", "wan miniport"} {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

func networkGroups(r Raw) []Group {
	var names []string
	for inst, bw := range r.Counters[cNetBw] {
		if ok(bw) && bw > 0 && !virtualNIC(inst) {
			names = append(names, inst)
		}
	}
	sort.Strings(names)
	var out []Group
	for _, n := range names {
		g := Group{ID: "net." + slug(n), Kind: "network", Name: n}
		b := builder{&g}
		pre := g.ID + "."
		if v, found := r.Counters[cNetRx][n]; found && ok(v) && v >= 0 {
			b.add(Sensor{ID: pre + "rx", Label: "Ricezione", Value: round(v*8/1e6, 3), Unit: "Mbit/s"})
		}
		if v, found := r.Counters[cNetTx][n]; found && ok(v) && v >= 0 {
			b.add(Sensor{ID: pre + "tx", Label: "Invio", Value: round(v*8/1e6, 3), Unit: "Mbit/s"})
		}
		b.add(Sensor{ID: pre + "link", Label: "Velocità del collegamento", Value: round(r.Counters[cNetBw][n]/1e6, 0), Unit: "Mbit/s", Detail: true})
		out = append(out, g)
	}
	return out
}

func batteryGroups(r Raw) []Group {
	var out []Group
	for i, x := range r.Batteries {
		id := "battery." + strconv.Itoa(i)
		g := Group{ID: id, Kind: "battery", Name: strings.TrimSpace(x.Name)}
		if g.Name == "" {
			g.Name = "Batteria"
		}
		switch {
		case x.Charging:
			g.Sub = "in carica"
		case x.Discharging:
			g.Sub = "a batteria"
		case x.OnLine:
			g.Sub = "alimentatore collegato"
		}
		b := builder{&g}
		pre := id + "."
		if ok(x.ChargePct) {
			b.add(Sensor{ID: pre + "charge", Label: "Carica", Value: round(clamp(x.ChargePct, 0, 100), 0), Unit: "%", Warn: pf(20), Crit: pf(10), Below: true})
		}
		if ok(x.CapacityWh) {
			b.add(Sensor{ID: pre + "capacity", Label: "Energia residua", Value: round(x.CapacityWh, 1), Unit: "Wh"})
		}
		if ok(x.RateW) {
			b.add(Sensor{ID: pre + "rate", Label: "Potenza (positiva in carica, negativa in scarica)", Value: round(x.RateW, 1), Unit: "W"})
		}
		if ok(x.VoltageV) && x.VoltageV > 0 {
			b.add(Sensor{ID: pre + "voltage", Label: "Tensione", Value: round(x.VoltageV, 2), Unit: "V"})
		}
		if ok(x.FullWh) && ok(x.DesignWh) && x.DesignWh > 0 && x.FullWh > 0 {
			b.add(Sensor{ID: pre + "health", Label: "Salute (capacità rispetto a quella originale)", Value: round(clamp(100*x.FullWh/x.DesignWh, 0, 100), 0), Unit: "%", Warn: pf(50), Below: true})
		}
		if ok(x.TempC) && x.TempC > 0 && x.TempC < 100 {
			b.add(Sensor{ID: pre + "temp", Label: "Temperatura", Value: round(x.TempC, 1), Unit: "°C", Warn: pf(45), Crit: pf(60)})
		}
		if len(g.Sensors) > 0 {
			out = append(out, g)
		}
	}
	return out
}

func systemGroup(r Raw) Group {
	g := Group{ID: "system", Kind: "system", Name: "Sistema"}
	b := builder{&g}
	if v, found := r.one(cProcs); found {
		b.add(Sensor{ID: "sys.processes", Label: "Processi", Value: v, Unit: ""})
	}
	if v, found := r.one(cThreads); found {
		b.add(Sensor{ID: "sys.threads", Label: "Thread", Value: v, Unit: ""})
	}
	if v, found := r.one(cCtx); found {
		b.add(Sensor{ID: "sys.ctx", Label: "Cambi di contesto", Value: round(v, 0), Unit: "/s", Detail: true})
	}
	if v, found := r.one(cQueue); found {
		b.add(Sensor{ID: "sys.queue", Label: "Thread in attesa del processore", Value: v, Unit: "", Detail: true})
	}
	if v, found := r.one(cUptime); found && v > 0 {
		b.add(Sensor{ID: "sys.uptime", Label: "Tempo dall'avvio", Value: round(v/3600, 1), Unit: "ore"})
	}
	return g
}
