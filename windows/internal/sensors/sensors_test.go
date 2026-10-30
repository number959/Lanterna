package sensors

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"sync"
	"testing"
	"time"
)

func find(t *testing.T, s Snapshot, id string) Sensor {
	t.Helper()
	for _, g := range s.Groups {
		for _, x := range g.Sensors {
			if x.ID == id {
				return x
			}
		}
	}
	t.Fatalf("sensore %q assente", id)
	return Sensor{}
}

func has(s Snapshot, id string) bool {
	for _, g := range s.Groups {
		for _, x := range g.Sensors {
			if x.ID == id {
				return true
			}
		}
	}
	return false
}

func group(t *testing.T, s Snapshot, id string) Group {
	t.Helper()
	for _, g := range s.Groups {
		if g.ID == id {
			return g
		}
	}
	t.Fatalf("gruppo %q assente", id)
	return Group{}
}

func missingHas(s Snapshot, part string) bool {
	for _, m := range s.Missing {
		if strings.Contains(m, part) {
			return true
		}
	}
	return false
}

func TestBuildCPU(t *testing.T) {
	r := Raw{
		CPUName: " Intel(R) Core(TM) i5-1135G7 @ 2.40GHz ",
		Counters: map[string]map[string]float64{
			cPerf:      {"_Total": 150, "0,_Total": 150, "0,0": 160, "0,1": 140},
			cFreq:      {"_Total": 2400, "0,_Total": 2400, "0,0": 2400, "0,1": 2400},
			cTime:      {"_Total": 37.25, "0,_Total": 37.25, "0,0": 60, "0,1": 14.5},
			cUtility:   {"_Total": 128},
			cLimit:     {"_Total": 80},
			cC1:        {"_Total": 12.34},
			cDPC:       {"_Total": 0.4},
			cEnergy:    {"RAPL_Package0_PKG": 15321, "RAPL_Package0_PP0": 9050, "RAPL_Package0_DRAM": 1200, "PSYS": 21000},
			cInterrupt: {"_Total": nan},
		},
	}
	s := Build(r)
	g := group(t, s, "cpu")
	if g.Name != "Intel(R) Core(TM) i5-1135G7 @ 2.40GHz" || g.Kind != "cpu" {
		t.Fatalf("gruppo: %+v", g)
	}
	if v := find(t, s, "cpu.usage"); v.Value != 37.3 || v.Unit != "%" {
		t.Errorf("utilizzo: %+v", v)
	}
	if v := find(t, s, "cpu.utility"); v.Value != 100 {
		t.Errorf("utilità oltre 100 non fermata a 100: %+v", v)
	}
	if v := find(t, s, "cpu.clock"); v.Value != 3600 || v.Unit != "MHz" {
		t.Errorf("frequenza media: %+v", v)
	}
	if v := find(t, s, "cpu.maxclock"); v.Value != 3840 {
		t.Errorf("core più veloce: %+v", v)
	}
	if v := find(t, s, "cpu.limit"); v.Value != 80 || !v.Below || v.Warn == nil || *v.Warn != 95 {
		t.Errorf("limite di prestazioni: %+v", v)
	}
	if v := find(t, s, "cpu.power.rapl-package0-pkg"); v.Value != 15.3 || v.Unit != "W" || v.Label != "Potenza del processore (package)" {
		t.Errorf("potenza del package: %+v", v)
	}
	if v := find(t, s, "cpu.power.rapl-package0-pp0"); v.Label != "Potenza dei core" || v.Value != 9.1 {
		t.Errorf("potenza dei core: %+v", v)
	}
	if v := find(t, s, "cpu.power.psys"); v.Label != "Potenza della piattaforma" {
		t.Errorf("piattaforma: %+v", v)
	}
	if v := find(t, s, "cpu.c1"); !v.Detail || v.Value != 12.3 {
		t.Errorf("stato C1: %+v", v)
	}
	if has(s, "cpu.interrupt") {
		t.Error("un valore NaN non deve diventare un sensore")
	}
	if v := find(t, s, "cpu.core.0,1.clock"); v.Value != 3360 || !v.Detail || v.Label != "Processore logico 1: frequenza" {
		t.Errorf("core 1: %+v", v)
	}
	if v := find(t, s, "cpu.core.0,0.usage"); v.Value != 60 {
		t.Errorf("utilizzo del core 0: %+v", v)
	}
	if missingHas(s, "Energy Meter") {
		t.Error("con i contatori di energia non deve dire che mancano")
	}
	// Senza contatori di energia lo dice; il messaggio sul driver c'è sempre.
	s = Build(Raw{Counters: map[string]map[string]float64{cTime: {"_Total": 5}}})
	if !missingHas(s, "Energy Meter") || !missingHas(s, "driver in kernel") || !missingHas(s, "HWiNFO") {
		t.Errorf("mancanze: %q", s.Missing)
	}
	if g := group(t, s, "cpu"); g.Name != "Processore" {
		t.Errorf("nome di riserva: %q", g.Name)
	}
}

func TestBuildThermal(t *testing.T) {
	s := Build(Raw{Counters: map[string]map[string]float64{
		cTzTemp:    {`\_TZ.TZ00`: 320, `\_TZ.TZ01`: 0, `\_TZ.CPUZ`: 600, `\_TZ.THM0`: 301},
		cTzHP:      {`\_TZ.TZ00`: 3205},
		cTzPassive: {`\_TZ.TZ00`: 70, `\_TZ.THM0`: 100},
	}})
	g := group(t, s, "thermal")
	if g.Kind != "thermal" || len(g.Sensors) != 4 {
		t.Fatalf("zone: %+v", g)
	}
	// La temperatura ad alta precisione (decimi di kelvin) ha la precedenza.
	if v := find(t, s, "tz.tz-tz00.temp"); v.Value != 47.4 || v.Label != "Zona TZ00" || v.Unit != "°C" {
		t.Errorf("TZ00: %+v", v)
	}
	if v := find(t, s, "tz.tz-thm0.temp"); v.Value != 27.9 {
		t.Errorf("THM0: %+v", v)
	}
	if v := find(t, s, "tz.tz-tz00.passive"); v.Value != 70 || !v.Below {
		t.Errorf("limite passivo: %+v", v)
	}
	if has(s, "tz.tz-tz01.temp") || has(s, "tz.tz-cpuz.temp") {
		t.Error("zone a 0 K o oltre 150 °C vanno scartate")
	}
	if missingHas(s, "Zone termiche") {
		t.Error("con le zone non deve dire che mancano")
	}
	if s := Build(Raw{}); !missingHas(s, "non ne dichiara") {
		t.Errorf("senza zone: %q", s.Missing)
	}
	if s := Build(Raw{Counters: map[string]map[string]float64{cTzTemp: {`\_TZ.TZ00`: 0}}}); !missingHas(s, "valori non validi") {
		t.Errorf("zone a zero: %q", s.Missing)
	}
}

func TestBuildGPU(t *testing.T) {
	const l = "luid_0x00000000_0x0000D1B8"
	const sw = "luid_0x00000000_0x00010B20"
	s := Build(Raw{
		Counters: map[string]map[string]float64{
			cGpuEngine: {
				"pid_100_" + l + "_phys_0_eng_0_engtype_3D":          30,
				"pid_200_" + l + "_phys_0_eng_0_engtype_3D":          25,
				"pid_200_" + l + "_phys_0_eng_3_engtype_VideoDecode": 40,
				"pid_300_" + l + "_phys_0_eng_5_engtype_Copy":        2,
				"pid_300_" + l + "_phys_0_eng_7_engtype_Compute_1":   1,
				// Due motori di decodifica: conta il più impegnato, non la somma.
				"pid_200_" + l + "_phys_0_eng_4_engtype_VideoDecode":         30,
				"pid_400_luid_0x00000000_0x0000AAAA_phys_0_eng_0_engtype_3D": 3,
				"pid_500_" + sw + "_phys_0_eng_0_engtype_3D":                 9,
			},
			cGpuDedic:  {l + "_phys_0": 512 << 20},
			cGpuShared: {l + "_phys_0": 64 << 20},
		},
		GPUs: []GPU{
			{LUID: "0x00000000_0x0000d1b8", Name: "NVIDIA GeForce RTX 3060", TempC: 64.5, TempWarnC: 83, TempMaxC: 93, FanRPM: 1450, PowerPct: 37.2, CoreMHz: 1777, MemMHz: 7501, VoltageMV: 875},
			{LUID: "0x00000000_0x00010b20", Name: "Microsoft Basic Render Driver", Software: true},
		},
	})
	g := group(t, s, "gpu.0x00000000_0x0000d1b8")
	if g.Name != "NVIDIA GeForce RTX 3060" {
		t.Fatalf("nome: %q", g.Name)
	}
	// 3D: 30 + 25 = 55; decodifica 40: la scheda è al 55 %.
	if v := find(t, s, g.ID+".usage"); v.Value != 55 {
		t.Errorf("utilizzo: %+v", v)
	}
	if v := find(t, s, g.ID+".engine.3d"); v.Value != 55 || v.Detail || v.Label != "Motore 3D" {
		t.Errorf("motore 3D: %+v", v)
	}
	if v := find(t, s, g.ID+".engine.videodecode"); v.Value != 40 || !v.Detail {
		t.Errorf("decodifica: %+v", v)
	}
	if v := find(t, s, g.ID+".engine.compute-1"); v.Label != "Calcolo 1" {
		t.Errorf("calcolo: %+v", v)
	}
	if v := find(t, s, g.ID+".temp"); v.Value != 64.5 || *v.Warn != 83 || *v.Crit != 93 {
		t.Errorf("temperatura: %+v", v)
	}
	if v := find(t, s, g.ID+".voltage"); v.Value != 0.875 || v.Unit != "V" {
		t.Errorf("tensione: %+v", v)
	}
	if v := find(t, s, g.ID+".dedicated"); v.Value != 512 || v.Unit != "MB" {
		t.Errorf("memoria dedicata: %+v", v)
	}
	for _, id := range []string{".fan", ".power", ".coreclock", ".memclock", ".shared"} {
		find(t, s, g.ID+id)
	}
	// Una scheda vista solo dai contatori ha un nome generico; quella
	// software non compare.
	other := group(t, s, "gpu.0x00000000_0x0000aaaa")
	if other.Name != "Scheda video 2" {
		t.Errorf("seconda scheda: %q", other.Name)
	}
	for _, g := range s.Groups {
		if strings.Contains(g.ID, "10b20") {
			t.Error("l'adattatore software non va mostrato")
		}
	}
	if missingHas(s, "il driver non le fornisce") {
		t.Errorf("con la telemetria non deve dire che manca: %q", s.Missing)
	}
	// Driver senza telemetria (o D3DKMT non disponibile): lo dice.
	s = Build(Raw{Counters: map[string]map[string]float64{cGpuEngine: {"pid_1_" + l + "_phys_0_eng_0_engtype_3D": 5}}, GPUs: []GPU{{LUID: "0x00000000_0x0000d1b8", Name: "Intel(R) UHD Graphics", TempC: nan, TempWarnC: nan, TempMaxC: nan, FanRPM: nan, PowerPct: nan, CoreMHz: nan, MemMHz: nan, VoltageMV: nan}}})
	if !missingHas(s, "Temperatura e frequenze di Intel(R) UHD Graphics:") || group(t, s, "gpu.0x00000000_0x0000d1b8").Name != "Intel(R) UHD Graphics" {
		t.Errorf("senza telemetria: %q", s.Missing)
	}
	// Scheda senza telemetria e senza contatori (per esempio il video di una
	// macchina virtuale): non si mostra, e quindi nessuna nota.
	s = Build(Raw{GPUs: []GPU{emptyGPU("0x00000000_0x0000abcd", "Microsoft Hyper-V Video", false)}})
	if missingHas(s, "il driver non le fornisce") || len(s.Groups) != 0 && s.Groups[0].Kind == "gpu" {
		t.Errorf("scheda vuota: %q %+v", s.Missing, s.Groups)
	}
	s = Build(Raw{Counters: map[string]map[string]float64{cGpuEngine: {"pid_1_" + l + "_phys_0_eng_0_engtype_3D": 5}}, GPUErr: errors.New("no")})
	if !missingHas(s, "Temperatura e frequenze di Scheda video 1:") {
		t.Errorf("D3DKMT non disponibile: %q", s.Missing)
	}
}

func TestLuidOf(t *testing.T) {
	for in, want := range map[string]string{
		"pid_1_luid_0x00000000_0x0000D1B8_phys_0_eng_0_engtype_3D": "0x00000000_0x0000d1b8",
		"luid_0x00000001_0x0000A9F5_phys_0":                        "0x00000001_0x0000a9f5",
		"senza":                                                    "",
		"luid_0x1":                                                 "",
	} {
		if got := luidOf(in); got != want {
			t.Errorf("luidOf(%q) = %q, atteso %q", in, got, want)
		}
	}
}

func TestBuildMemoryDisksNetwork(t *testing.T) {
	yes, no := true, false
	s := Build(Raw{
		Memory: &Memory{Total: 16 << 30, Avail: 4 << 30, CommitTotal: 14 << 30, CommitLimit: 20 << 30},
		Counters: map[string]map[string]float64{
			cPageFile:  {"_Total": 12.5},
			cPages:     {"": 42.4},
			cDiskIdle:  {"0 C:": 85, "1 D: E:": 100.4, "_Total": 90},
			cDiskRead:  {"0 C:": 12_340_000, "1 D: E:": 0},
			cDiskWrite: {"0 C:": 1_000_000},
			cDiskSec:   {"0 C:": 0.0021},
			cDiskQueue: {"0 C:": 1},
			cNetBw:     {"Intel[R] Ethernet Connection I219-V": 1e9, "isatap.{1234}": 1e5, "Teredo Tunneling Pseudo-Interface": 1e5, "Disconnesso": 0},
			cNetRx:     {"Intel[R] Ethernet Connection I219-V": 1_250_000},
			cNetTx:     {"Intel[R] Ethernet Connection I219-V": 125_000},
		},
		Disks: map[string]Disk{
			"0": {Model: "Samsung SSD 980 1TB", Flash: &yes, TempC: 41},
			"1": {Model: "WDC WD20EZRZ", Flash: &no, TempC: nan, NeedsAdmin: true},
			"2": {Model: "USB", TempC: 58},
		},
	})
	if v := find(t, s, "mem.load"); v.Value != 75 || *v.Warn != 85 {
		t.Errorf("carico della memoria: %+v", v)
	}
	if v := find(t, s, "mem.used"); v.Value != 12 || v.Unit != "GB" {
		t.Errorf("usata: %+v", v)
	}
	if v := find(t, s, "mem.commitload"); v.Value != 70 {
		t.Errorf("impegnata: %+v", v)
	}
	if g := group(t, s, "memory"); g.Sub != "16 GB utilizzabili" || Build(Raw{Memory: &Memory{Total: 16_857_000_000, Avail: 1}}).Groups[0].Sub != "15,7 GB utilizzabili" {
		t.Errorf("memoria: %q", g.Sub)
	}
	find(t, s, "mem.pagefile")
	if v := find(t, s, "mem.pages"); !v.Detail || v.Value != 42 {
		t.Errorf("pagine: %+v", v)
	}
	d0 := group(t, s, "disk.0")
	if d0.Name != "Disco 0: Samsung SSD 980 1TB" || d0.Sub != "C:" {
		t.Errorf("disco 0: %+v", d0)
	}
	if v := find(t, s, "disk.0.temp"); *v.Warn != 70 || *v.Crit != 80 {
		t.Errorf("soglie SSD: %+v", v)
	}
	if v := find(t, s, "disk.0.activity"); v.Value != 15 {
		t.Errorf("attività: %+v", v)
	}
	if v := find(t, s, "disk.0.read"); v.Value != 12.34 || v.Unit != "MB/s" {
		t.Errorf("lettura: %+v", v)
	}
	if v := find(t, s, "disk.0.latency"); v.Value != 2.1 || v.Unit != "ms" {
		t.Errorf("tempo di risposta: %+v", v)
	}
	if v := find(t, s, "disk.1.activity"); v.Value != 0 {
		t.Errorf("tempo di inattività oltre 100: %+v", v)
	}
	if g := group(t, s, "disk.1"); g.Sub != "D: E:" {
		t.Errorf("lettere: %q", g.Sub)
	}
	if v := find(t, s, "disk.2.temp"); *v.Warn != 60 || *v.Crit != 70 {
		t.Errorf("soglie di un disco di tipo ignoto: %+v", v)
	}
	if has(s, "disk.1.temp") || has(s, "disk._total.activity") {
		t.Error("temperatura assente o totale non devono comparire")
	}
	if !missingHas(s, "amministratore") {
		t.Errorf("disco SATA senza temperatura, senza amministratore: %q", s.Missing)
	}
	// Chiavetta USB o NVMe senza temperatura: nessuna nota sull'amministratore.
	s2 := Build(Raw{Counters: map[string]map[string]float64{cDiskIdle: {"2 E:": 99}}, Disks: map[string]Disk{"2": {Model: "USB", TempC: nan}, "5": {Model: "Lettore di schede", TempC: nan, NeedsAdmin: true}}})
	if missingHas(s2, "amministratore") {
		t.Errorf("nota sull'amministratore per un disco USB o non mostrato: %q", s2.Missing)
	}
	nets := 0
	for _, g := range s.Groups {
		if g.Kind == "network" {
			nets++
		}
	}
	if nets != 1 {
		t.Errorf("interfacce di rete: %d", nets)
	}
	if v := find(t, s, "net.intel-r-ethernet-connection-i219-v.rx"); v.Value != 10 || v.Unit != "Mbit/s" {
		t.Errorf("ricezione: %+v", v)
	}
	if v := find(t, s, "net.intel-r-ethernet-connection-i219-v.link"); v.Value != 1000 || !v.Detail {
		t.Errorf("collegamento: %+v", v)
	}
}

func TestBuildBatterySystem(t *testing.T) {
	s := Build(Raw{
		Batteries: []Battery{{Name: "DELL 7FHHV", ChargePct: 75, CapacityWh: 30, FullWh: 40, DesignWh: 56, RateW: -8.25, VoltageV: 11.4, TempC: nan, Discharging: true}},
		Counters: map[string]map[string]float64{
			cProcs:   {"": 212},
			cThreads: {"": 2800},
			cUptime:  {"": 7200},
			cCtx:     {"": 15000.4},
		},
		Elevated: true,
	})
	g := group(t, s, "battery.0")
	if g.Name != "DELL 7FHHV" || g.Sub != "a batteria" {
		t.Errorf("batteria: %+v", g)
	}
	if v := find(t, s, "battery.0.charge"); v.Value != 75 || !v.Below {
		t.Errorf("carica: %+v", v)
	}
	if v := find(t, s, "battery.0.rate"); v.Value != -8.3 && v.Value != -8.2 {
		t.Errorf("potenza: %+v", v)
	}
	if v := find(t, s, "battery.0.health"); v.Value != 71 {
		t.Errorf("salute: %+v", v)
	}
	if has(s, "battery.0.temp") {
		t.Error("temperatura non letta non deve comparire")
	}
	if v := find(t, s, "sys.uptime"); v.Value != 2 || v.Unit != "ore" {
		t.Errorf("tempo dall'avvio: %+v", v)
	}
	if v := find(t, s, "sys.ctx"); !v.Detail || v.Value != 15000 {
		t.Errorf("cambi di contesto: %+v", v)
	}
	find(t, s, "sys.processes")
	if missingHas(s, "amministratore") {
		t.Error("nessun disco: niente avviso sull'amministratore")
	}
}

func TestSnapshotJSON(t *testing.T) {
	s := Build(Raw{Counters: map[string]map[string]float64{cTime: {"_Total": 5}, cLimit: {"_Total": 100}}})
	s.At = time.Date(2026, 10, 30, 9, 0, 0, 0, time.UTC)
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, want := range []string{
		`"at":"2026-10-30T09:00:00Z"`,
		`{"id":"cpu","kind":"cpu","name":"Processore","sensors":[{"id":"cpu.usage","label":"Utilizzo totale","value":5,"unit":"%"}`,
		`{"id":"cpu.limit","label":"Limite di prestazioni","value":100,"unit":"%","warn":95,"below":true}`,
		`"missing":[`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("JSON senza %s:\n%s", want, got)
		}
	}
}

type fakeSource struct {
	mu       sync.Mutex
	collects int
	closed   bool
	fail     error
	load     float64
}

func (f *fakeSource) Collect() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.collects++
	return f.fail
}

func (f *fakeSource) Read() (Raw, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return Raw{Counters: map[string]map[string]float64{cTime: {"_Total": f.load}}}, nil
}

func (f *fakeSource) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
}

func (f *fakeSource) state() (int, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.collects, f.closed
}

func TestMonitor(t *testing.T) {
	var opened []*fakeSource
	now := time.Unix(1_000_000, 0)
	var slept []time.Duration
	m := &Monitor{
		Open: func() (Source, error) {
			f := &fakeSource{load: 10}
			opened = append(opened, f)
			return f, nil
		},
		Now:   func() time.Time { return now },
		Sleep: func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil },
		Idle:  time.Hour,
	}
	defer m.Close()
	s, err := m.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if find(t, s, "cpu.usage").Value != 10 || !s.At.Equal(now) {
		t.Fatalf("prima lettura: %+v", s)
	}
	if n, _ := opened[0].state(); n != 2 || len(slept) != 1 || slept[0] != 500*time.Millisecond {
		t.Fatalf("la prima lettura deve raccogliere due volte con una pausa: %d raccolte, pause %v", n, slept)
	}
	now = now.Add(200 * time.Millisecond)
	if _, err := m.Read(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n, _ := opened[0].state(); n != 2 {
		t.Fatalf("lettura ravvicinata: %d raccolte", n)
	}
	now = now.Add(time.Second)
	opened[0].mu.Lock()
	opened[0].load = 20
	opened[0].mu.Unlock()
	s, _ = m.Read(context.Background())
	if n, _ := opened[0].state(); n != 3 || len(opened) != 1 || find(t, s, "cpu.usage").Value != 20 {
		t.Fatalf("lettura successiva: %d raccolte, %d aperture", n, len(opened))
	}
	now = now.Add(time.Second)
	opened[0].mu.Lock()
	opened[0].fail = errors.New("guasto")
	opened[0].mu.Unlock()
	if _, err := m.Read(context.Background()); err == nil {
		t.Fatal("errore non riportato")
	}
	if _, closed := opened[0].state(); !closed {
		t.Fatal("fonti non chiuse dopo l'errore")
	}
	now = now.Add(time.Second)
	if _, err := m.Read(context.Background()); err != nil || len(opened) != 2 {
		t.Fatalf("riapertura: %v, %d aperture", err, len(opened))
	}
}

func TestMonitorIdleAndUnavailable(t *testing.T) {
	f := &fakeSource{load: 1}
	m := &Monitor{Open: func() (Source, error) { return f, nil }, Sleep: func(context.Context, time.Duration) error { return nil }, Idle: 30 * time.Millisecond}
	defer m.Close()
	if _, err := m.Read(context.Background()); err != nil {
		t.Fatal(err)
	}
	closed := false
	for i := 0; i < 100 && !closed; i++ {
		time.Sleep(10 * time.Millisecond)
		_, closed = f.state()
	}
	if !closed {
		t.Fatal("fonti non chiuse dopo l'inattività")
	}
	if _, err := (&Monitor{}).Read(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("senza fonte: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m2 := &Monitor{Open: func() (Source, error) { return &fakeSource{}, nil }}
	if _, err := m2.Read(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("annullamento: %v", err)
	}
}

func TestParseBattery(t *testing.T) {
	info := make([]byte, batteryInfoSize)
	le := func(b []byte, off int, v uint32) {
		b[off], b[off+1], b[off+2], b[off+3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
	}
	le(info, 0, 0x80000000) // batteria di sistema, capacità in mWh
	le(info, 12, 56000)     // progettata
	le(info, 16, 41500)     // a piena carica
	st := make([]byte, batteryStatusSize)
	le(st, 0, batteryDischarging)
	le(st, 4, 20750)
	le(st, 8, 11520)
	le(st, 12, uint32(0xFFFFE0C0)) // -8000 mW
	b, valid := parseBattery("Batteria", info, st, 3031)
	if !valid || b.ChargePct != 50 || b.CapacityWh != 20.75 || b.FullWh != 41.5 || b.DesignWh != 56 || b.RateW != -8 || b.VoltageV != 11.52 || !b.Discharging || b.Charging {
		t.Fatalf("batteria: %+v", b)
	}
	if math.Abs(b.TempC-29.95) > 0.001 {
		t.Errorf("temperatura: %v", b.TempC)
	}
	// Valori sconosciuti e capacità relative: solo la percentuale.
	le(info, 0, batterySystemBattery|batteryCapacityRelative)
	le(info, 12, 100)
	le(info, 16, 100)
	le(st, 0, batteryPowerOnLine|batteryCharging)
	le(st, 4, 64)
	le(st, 8, batteryUnknownVoltage)
	le(st, 12, batteryUnknownRate)
	b, valid = parseBattery("", info, st, 0)
	if !valid || b.ChargePct != 64 || ok(b.CapacityWh) || ok(b.RateW) || ok(b.VoltageV) || ok(b.TempC) || !b.Charging || !b.OnLine {
		t.Fatalf("relativa: %+v", b)
	}
	le(st, 4, batteryUnknownCapacity)
	if _, valid := parseBattery("", info, st, 0); valid {
		t.Error("senza capacità non è una lettura utile")
	}
	// Gruppo di continuità o batteria non di sistema: esclusi.
	le(st, 4, 50)
	for _, caps := range []uint32{batterySystemBattery | batteryIsShortTerm, 0} {
		le(info, 0, caps)
		if _, valid := parseBattery("UPS", info, st, 0); valid {
			t.Errorf("capacità 0x%08X: doveva essere esclusa", caps)
		}
	}
	if _, valid := parseBattery("", info[:10], st, 0); valid {
		t.Error("dati troncati")
	}
}

func TestGPUPerfData(t *testing.T) {
	put32 := func(b []byte, off int, v uint32) {
		b[off], b[off+1], b[off+2], b[off+3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
	}
	put64 := func(b []byte, off int, v uint64) {
		put32(b, off, uint32(v))
		put32(b, off+4, uint32(v>>32))
	}
	g := emptyGPU(luidKey(0xD1B8, 0), "NVIDIA GeForce RTX 3060", false)
	if g.LUID != "0x00000000_0x0000d1b8" || luidKey(0x10, -1) != "0xffffffff_0x00000010" {
		t.Fatalf("LUID: %q %q", g.LUID, luidKey(0x10, -1))
	}
	perf := make([]byte, adapterPerfDataSize)
	put64(perf, 8, 7_501_000_000) // memoria in Hz
	put32(perf, 48, 1450)         // giri della ventola
	put32(perf, 52, 372)          // potenza in decimi di punto percentuale
	put32(perf, 56, 645)          // decimi di °C
	applyAdapterPerf(&g, perf)
	node := make([]byte, nodePerfDataSize)
	put64(node, 8, 1_777_000_000)
	put32(node, 32, 875)
	applyNodePerf(&g, node)
	caps := make([]byte, adapterPerfDataCapsSize)
	put32(caps, 28, 930)
	put32(caps, 32, 830)
	c := parseCaps(caps)
	if g.MemMHz != 7501 || g.FanRPM != 1450 || g.PowerPct != 37.2 || g.TempC != 64.5 || g.CoreMHz != 1777 || g.VoltageMV != 875 || c.TempMaxC != 93 || c.TempWarnC != 83 {
		t.Fatalf("telemetria: %+v %+v", g, c)
	}
	// Zeri e buffer corti: niente valori.
	z := emptyGPU("x", "", false)
	applyAdapterPerf(&z, make([]byte, adapterPerfDataSize))
	applyNodePerf(&z, make([]byte, 10))
	if ok(z.TempC) || ok(z.FanRPM) || ok(z.CoreMHz) || ok(z.MemMHz) || ok(parseCaps(nil).TempMaxC) {
		t.Errorf("valori inventati: %+v", z)
	}
}

func TestParseStorageTemp(t *testing.T) {
	desc := func(crit, warn int16, entries ...[3]int16) []byte {
		b := make([]byte, 24+16*len(entries))
		put16 := func(off int, v int16) { b[off], b[off+1] = byte(uint16(v)), byte(uint16(v)>>8) }
		b[4] = byte(len(b))
		put16(8, crit)
		put16(10, warn)
		put16(12, int16(len(entries)))
		for i, e := range entries {
			put16(24+16*i, e[0])
			put16(26+16*i, e[1])
			put16(28+16*i, e[2])
		}
		return b
	}
	// Samsung 990 PRO come in una lettura reale: composita a 48 °C, un
	// sensore non implementato (0 °C con soglia 0), soglie 82 e 85.
	temp, warn, crit, valid := parseStorageTemp(desc(85, 82, [3]int16{0, 48, 82}, [3]int16{1, 0, 0}))
	if !valid || temp != 48 || warn != 82 || crit != 85 {
		t.Fatalf("990 PRO: %v %v %v %v", temp, warn, crit, valid)
	}
	// Composita non riportata: vale il primo sensore plausibile; soglie assenti.
	temp, warn, crit, valid = parseStorageTemp(desc(tempNotReported, 0, [3]int16{0, tempNotReported, 0}, [3]int16{2, 39, 70}))
	if !valid || temp != 39 || ok(warn) || ok(crit) {
		t.Fatalf("sensore 2: %v %v %v %v", temp, warn, crit, valid)
	}
	// Indice assurdo, valori fuori misura, buffer corti o vuoti.
	for name, b := range map[string][]byte{
		"indice assurdo": desc(85, 82, [3]int16{0xFEE, 40, 1}),
		"fuori misura":   desc(85, 82, [3]int16{0, 300, 1}),
		"nessuna voce":   desc(85, 82),
		"troncato":       desc(85, 82, [3]int16{0, 40, 70})[:30],
		"vuoto":          nil,
	} {
		if _, _, _, valid := parseStorageTemp(b); valid {
			t.Errorf("%s: temperatura inventata", name)
		}
	}
	// Le soglie del disco sostituiscono quelle generali.
	yes := true
	s := Build(Raw{Disks: map[string]Disk{"0": {Model: "Samsung SSD 990 PRO 1TB", Flash: &yes, TempC: 48, WarnC: 82, CritC: 85}, "1": {Model: "X", Flash: &yes, TempC: 50, WarnC: 75, CritC: nan}}})
	if v := find(t, s, "disk.0.temp"); *v.Warn != 82 || *v.Crit != 85 {
		t.Errorf("soglie del disco: %+v", v)
	}
	if v := find(t, s, "disk.1.temp"); *v.Warn != 75 || *v.Crit != 80 {
		t.Errorf("solo la soglia di attenzione: %+v", v)
	}
}

func TestMonitorIdleAfterCachedRead(t *testing.T) {
	f := &fakeSource{load: 1}
	// Min lunghissimo: la seconda lettura arriva dalla cache.
	m := &Monitor{Open: func() (Source, error) { return f, nil }, Sleep: func(context.Context, time.Duration) error { return nil }, Idle: 60 * time.Millisecond, Min: time.Hour}
	defer m.Close()
	if _, err := m.Read(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	if _, err := m.Read(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if _, closed := f.state(); closed {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("fonti rimaste aperte dopo una lettura servita dalla cache")
}

func TestNoCounters(t *testing.T) {
	s := Build(Raw{NoCounters: true, Memory: &Memory{Total: 8 << 30, Avail: 4 << 30, CommitTotal: 5 << 30, CommitLimit: 10 << 30}})
	if !missingHas(s, "lodctr /R") || find(t, s, "mem.load").Value != 50 {
		t.Errorf("senza contatori: %q", s.Missing)
	}
	if missingHas(Build(Raw{}), "lodctr") {
		t.Error("nota sui contatori senza motivo")
	}
}
