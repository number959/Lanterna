package pcinfo

import (
	"strings"
	"testing"
	"time"

	"lanterna/internal/scan"
)

// Uscita tipica dello script su un portatile con SSD NVMe interno e disco USB
// esterno, avviato come amministratore. Davanti al JSON: il BOM e una riga di
// avviso, come può capitare con alcuni profili di PowerShell.
const psFixture = "\ufeffAVVISO: modulo caricato\r\n" + `{"cpu":{"name":"Intel(R) Core(TM) i7-1165G7 @ 2.80GHz","cores":4,"threads":8,"maxMhz":2803},` +
	`"gpus":[{"name":"Intel(R) Iris(R) Xe Graphics","driverVersion":"31.0.101.4502","driverDate":"2023-06-12"}],` +
	`"parts":[{"letter":"C","disk":"0"},{"letter":"D","disk":"1"}],` +
	`"disks":[{"id":"0","name":"Samsung SSD 980 1TB","media":"SSD","bus":"NVMe","size":1000204886016,"health":"Healthy","operational":["OK"],"firmware":"3B4QFXO7","rpm":0,` +
	`"rel":{"temperature":38,"temperatureMax":71,"wear":3,"powerOnHours":5120,"readErrors":0,"readUncorrected":null,"writeErrors":0,"writeUncorrected":null,"startStop":null,"loadUnload":null}},` +
	`{"id":"1","name":"WD Elements 25A2","media":"Unspecified","bus":"USB","size":2000398934016,"health":"Warning","operational":["Predictive Failure"],"firmware":"1021","rpm":7200,` +
	`"rel":{"temperature":0,"temperatureMax":0,"wear":0,"powerOnHours":20345,"readErrors":12,"readUncorrected":2,"writeErrors":null,"writeUncorrected":null,"startStop":4410,"loadUnload":91000}},` +
	`{"id":"2","name":"Lettore di schede","media":"Unspecified","bus":"SD","size":0,"health":"Healthy","operational":["OK"],"firmware":"","rpm":4294967295,` +
	`"rel":{"temperature":null,"temperatureMax":null,"wear":null,"powerOnHours":null,"readErrors":null,"readUncorrected":null,"writeErrors":null,"writeUncorrected":null,"startStop":null,"loadUnload":null}}],` +
	`"battery":{"design":56000,"full":43120,"cycles":0},` +
	`"events":[{"source":"Microsoft-Windows-Kernel-Power","id":41,"count":2,"last":"2026-10-02T07:15:00.0000000Z","detail":"0"},` +
	`{"source":"EventLog","id":6008,"count":2,"last":"2026-10-02T07:15:30.0000000Z","detail":"08:59:10"},` +
	`{"source":"disk","id":153,"count":14,"last":"2026-10-10T18:02:11.0000000Z","detail":"\\Device\\Harddisk1\\DR1"},` +
	`{"source":"Microsoft-Windows-Time-Service","id":129,"count":5,"last":"2026-10-12T09:00:00.0000000Z","detail":"time.windows.com"},` +
	`{"source":"Microsoft-Windows-WER-SystemErrorReporting","id":1001,"count":1,"last":"2026-09-28T21:40:00.0000000Z","detail":"0x0000009f (0x0000000000000003, 0xffffc00d1c4e8060)"}],` +
	`"av":[{"name":"Microsoft Defender Antivirus","enabled":true,"upToDate":true,"source":"securitycenter"}],` +
	`"updates":{"last":"2026-10-08","kb":"KB5044284"},"errors":{}}`

func TestParseAndMerge(t *testing.T) {
	ps, err := parsePS(psFixture)
	if err != nil {
		t.Fatal(err)
	}
	pc := &scan.PcData{
		CPU:     &scan.PcCPU{Name: "11th Gen Intel(R) Core(TM) i7-1165G7 @ 2.80GHz", Threads: 8, MaxMHz: 2803},
		Volumes: []scan.Volume{{Letter: "C:", Kind: "fixed", SizeGB: 999, FreeGB: 120, System: true}, {Letter: "D:", Kind: "fixed", SizeGB: 2000, FreeGB: 900}},
	}
	merge(pc, ps, "c:")

	if pc.CPU.Name != "11th Gen Intel(R) Core(TM) i7-1165G7 @ 2.80GHz" || pc.CPU.Cores != 4 {
		t.Errorf("processore: %+v", pc.CPU)
	}
	if len(pc.GPUs) != 1 || pc.GPUs[0].DriverDate != "2023-06-12" {
		t.Errorf("schede video: %+v", pc.GPUs)
	}
	if pc.Volumes[0].Disk != "0" || pc.Volumes[1].Disk != "1" {
		t.Errorf("volumi: %+v", pc.Volumes)
	}
	if len(pc.Disks) != 3 {
		t.Fatalf("dischi: %+v", pc.Disks)
	}
	ssd, hdd, sd := pc.Disks[0], pc.Disks[1], pc.Disks[2]
	if !ssd.System || ssd.Media != "ssd" || ssd.Health != "healthy" || ssd.SizeGB != 1000.2 || ssd.Reliability == nil ||
		*ssd.Reliability.TemperatureC != 38 || *ssd.Reliability.WearPct != 3 || *ssd.Reliability.PowerOnHours != 5120 {
		t.Errorf("SSD: %+v %+v", ssd, ssd.Reliability)
	}
	// Tipo non dichiarato ma velocità di rotazione sì: disco meccanico.
	// Temperatura zero = non riportata; usura ignorata per i dischi meccanici.
	if hdd.System || hdd.Media != "hdd" || hdd.SpindleRPM != 7200 || hdd.Health != "warning" || hdd.Reliability == nil ||
		hdd.Reliability.TemperatureC != nil || hdd.Reliability.WearPct != nil || *hdd.Reliability.ReadUncorrected != 2 || *hdd.Reliability.LoadUnloadCycles != 91000 {
		t.Errorf("HDD: %+v %+v", hdd, hdd.Reliability)
	}
	// 0xFFFFFFFF = velocità sconosciuta; contatori tutti vuoti = nessun dato.
	if sd.Media != "unknown" || sd.SpindleRPM != 0 || sd.Reliability != nil {
		t.Errorf("lettore: %+v", sd)
	}

	if pc.Battery == nil || *pc.Battery.DesignMWh != 56000 || *pc.Battery.FullMWh != 43120 || pc.Battery.Cycles != nil {
		t.Errorf("batteria: %+v", pc.Battery)
	}
	if pc.EventsDays != EventsDays || len(pc.Events) != 4 {
		t.Fatalf("eventi: %+v", pc.Events)
	}
	kinds := []string{}
	for _, e := range pc.Events {
		kinds = append(kinds, e.Kind)
	}
	if strings.Join(kinds, ",") != "disk-retry,unexpected-shutdown,unexpected-shutdown,bugcheck" {
		t.Errorf("ordine o filtro degli eventi: %v", kinds)
	}
	if pc.Events[0].Detail != `\Device\Harddisk1\DR1` || pc.Events[1].Detail != "" || pc.Events[3].Detail == "" {
		t.Errorf("dettagli: %+v", pc.Events)
	}
	if len(pc.Antivirus) != 1 || !pc.Antivirus[0].Enabled || !*pc.Antivirus[0].UpToDate {
		t.Errorf("antivirus: %+v", pc.Antivirus)
	}
	if pc.Updates == nil || pc.Updates.LastInstalled != "2026-10-08" || pc.Updates.LastKB != "KB5044284" {
		t.Errorf("aggiornamenti: %+v", pc.Updates)
	}
}

// Registro eventi illeggibile: "events" manca, la finestra resta a zero e
// l'elenco vuoto non viene scambiato per "nessun evento".
func TestMergeWithoutEvents(t *testing.T) {
	ps, err := parsePS(`{"disks":[],"errors":{"events":"Accesso negato","reliability":"Accesso negato"}}`)
	if err != nil {
		t.Fatal(err)
	}
	pc := &scan.PcData{}
	merge(pc, ps, "C:")
	if pc.EventsDays != 0 || pc.Events != nil || ps.Errors["events"] == "" || pc.Antivirus != nil {
		t.Fatalf("%+v %+v", pc, ps.Errors)
	}
	ps, _ = parsePS(`{"events":[],"av":[],"errors":{}}`)
	merge(pc, ps, "C:")
	if pc.EventsDays != EventsDays || pc.Events == nil || len(pc.Events) != 0 {
		t.Fatalf("nessun evento: %+v", pc)
	}
	// Centro sicurezza leggibile ma senza prodotti: elenco vuoto, non nullo.
	if pc.Antivirus == nil || len(pc.Antivirus) != 0 {
		t.Fatalf("antivirus: %#v", pc.Antivirus)
	}
}

func TestParsePSErrors(t *testing.T) {
	if _, err := parsePS("Get-CimInstance : Accesso negato"); err == nil {
		t.Error("uscita senza JSON accettata")
	}
	if _, err := parsePS(`{"cpu":`); err == nil {
		t.Error("JSON troncato accettato")
	}
}

func TestNormalizers(t *testing.T) {
	for _, c := range []struct {
		media string
		rpm   int
		want  string
	}{{"SSD", 0, "ssd"}, {"4", 0, "ssd"}, {"HDD", 5400, "hdd"}, {"Unspecified", 5400, "hdd"}, {"Unspecified", 0, "unknown"}, {"Unspecified", 0xFFFFFFFF, "unknown"}, {"SCM", 0, "scm"}} {
		if got := MediaOf(c.media, c.rpm); got != c.want {
			t.Errorf("MediaOf(%q,%d)=%q, atteso %q", c.media, c.rpm, got, c.want)
		}
	}
	for in, want := range map[string]string{"Healthy": "healthy", "0": "healthy", "Warning": "warning", "Unhealthy": "unhealthy", "2": "unhealthy", "": "unknown", "Unknown": "unknown"} {
		if got := HealthOf(in); got != want {
			t.Errorf("HealthOf(%q)=%q", in, got)
		}
	}
	for _, c := range []struct {
		src  string
		id   int
		want string
	}{
		{"Microsoft-Windows-Kernel-Power", 41, "unexpected-shutdown"},
		{"EventLog", 6008, "unexpected-shutdown"},
		{"Microsoft-Windows-WER-SystemErrorReporting", 1001, "bugcheck"},
		{"disk", 7, "disk-error"},
		{"Disk", 51, "disk-error"},
		{"disk", 153, "disk-retry"},
		{"Ntfs", 55, "filesystem"},
		{"Microsoft-Windows-Ntfs", 98, "filesystem"},
		{"stornvme", 129, "storage-reset"},
		{"iaStorAVC", 129, "storage-reset"},
		{"Microsoft-Windows-WHEA-Logger", 18, "whea-fatal"},
		{"Microsoft-Windows-WHEA-Logger", 47, "whea-corrected"},
		{"Microsoft-Windows-Time-Service", 129, ""},
		{"Microsoft-Windows-Kernel-Power", 7, ""},
		{"Service Control Manager", 7, ""},
	} {
		if got := ClassifyEvent(c.src, c.id); got != c.want {
			t.Errorf("ClassifyEvent(%q,%d)=%q, atteso %q", c.src, c.id, got, c.want)
		}
	}
}

func TestStartupEnabled(t *testing.T) {
	for _, c := range []struct {
		b    []byte
		want bool
	}{{nil, true}, {[]byte{2, 0, 0, 0}, true}, {[]byte{6, 0}, true}, {[]byte{3, 0, 0, 0, 0x5c, 0x1a}, false}, {[]byte{7}, false}} {
		if got := StartupEnabled(c.b); got != c.want {
			t.Errorf("StartupEnabled(% x)=%v", c.b, got)
		}
	}
}

func TestSanitizeCommand(t *testing.T) {
	p := `C:\Users\Mario Rossi`
	for in, want := range map[string]string{
		`"C:\Users\Mario Rossi\AppData\Local\Discord\Update.exe" --processStart Discord.exe`: `"%USERPROFILE%\AppData\Local\Discord\Update.exe" --processStart Discord.exe`,
		`c:\users\mario rossi\app.exe --log c:\users\MARIO ROSSI\log.txt`:                    `%USERPROFILE%\app.exe --log %USERPROFILE%\log.txt`,
		`"C:\Program Files\App\app.exe" /background`:                                         `"C:\Program Files\App\app.exe" /background`,
		`  C:\Users\Mario Rossi  `:                                                           `%USERPROFILE%`,
	} {
		if got := SanitizeCommand(in, p); got != want {
			t.Errorf("SanitizeCommand(%q)=%q, atteso %q", in, got, want)
		}
	}
	if got := SanitizeCommand(`C:\Users\Mario Rossi\x.exe`, p+`\`); got != `%USERPROFILE%\x.exe` {
		t.Errorf("barra finale nel profilo: %q", got)
	}
	if got := SanitizeCommand(`C:\x.exe`, ""); got != `C:\x.exe` {
		t.Errorf("profilo vuoto: %q", got)
	}
}

func TestOSNameAndPlan(t *testing.T) {
	for _, c := range []struct {
		product string
		build   int
		server  bool
		want    string
	}{
		{"Windows 10 Pro", 19045, false, "Windows 10 Pro"},
		{"Windows 10 Pro", 26100, false, "Windows 11 Pro"},
		{"Windows 10 Home", 22631, false, "Windows 11 Home"},
		{"Windows Server 2022 Standard", 20348, true, "Windows Server 2022 Standard"},
		{"Microsoft Windows Server 2025 Datacenter", 26100, true, "Windows Server 2025 Datacenter"},
		{"", 26100, false, "Windows"},
	} {
		if got := OSName(c.product, c.build, c.server); got != c.want {
			t.Errorf("OSName(%q,%d)=%q, atteso %q", c.product, c.build, got, c.want)
		}
	}
	for g, want := range map[string]string{
		"{381B4222-F694-41F0-9685-FF5BB260DF2E}": "balanced",
		"8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c":   "high",
		"a1841308-3541-4fab-bc81-f71556f20b4a":   "saver",
		"e9a42b02-d5df-448d-aa00-03f14749eb61":   "ultimate",
		"11111111-2222-3333-4444-555555555555":   "custom",
	} {
		if got := PlanKind(g); got != want {
			t.Errorf("PlanKind(%s)=%q", g, got)
		}
	}
}

func TestGroupProcesses(t *testing.T) {
	before := []ProcSample{
		{PID: 10, Name: "chrome.exe", CPU: 1_000_000, Memory: 200 << 20},
		{PID: 11, Name: "chrome.exe", CPU: 500_000, Memory: 150 << 20},
		{PID: 20, Name: "MsMpEng.exe", CPU: 9_000_000, Memory: 180 << 20},
		{PID: 30, Name: "idle-app.exe", CPU: 100, Memory: 5 << 20},
		{PID: 40, Name: "Teams.exe", CPU: 3_000_000, Memory: 400 << 20},
	}
	after := []ProcSample{
		{PID: 10, Name: "chrome.exe", CPU: 3_000_000, Memory: 220 << 20},
		{PID: 11, Name: "chrome.exe", CPU: 2_500_000, Memory: 150 << 20},
		{PID: 12, Name: "Chrome.exe", CPU: 50_000, Memory: 30 << 20}, // nato durante la misura
		{PID: 20, Name: "MsMpEng.exe", CPU: 10_000_000, Memory: 180 << 20},
		{PID: 30, Name: "idle-app.exe", CPU: 100, Memory: 5 << 20},
		{PID: 40, Name: "Teams.exe", CPU: 3_000_000, Memory: 400 << 20},
	}
	// 1 s su 4 processori logici = 4e7 unità da 100 ns.
	got := GroupProcesses(before, after, time.Second, 4, 2)
	names := []string{}
	for _, p := range got {
		names = append(names, p.Name)
	}
	// Per CPU: chrome (4e6 → 10%), MsMpEng (1e6 → 2,5%). Per memoria: chrome
	// (400 MB), Teams (400 MB). idle-app resta fuori.
	if strings.Join(names, ",") != "chrome.exe,MsMpEng.exe,Teams.exe" {
		t.Fatalf("processi: %v", names)
	}
	if got[0].Count != 3 || *got[0].CPUPct != 10 || got[0].MemoryMB != 400 {
		t.Errorf("chrome: %+v", got[0])
	}
	if *got[1].CPUPct != 2.5 || *got[2].CPUPct != 0 {
		t.Errorf("CPU: %+v %+v", got[1], got[2])
	}
	if out := GroupProcesses(nil, after, time.Second, 4, 3); len(out) == 0 || out[0].CPUPct != nil {
		t.Errorf("senza prima lettura la CPU non è misurabile: %+v", out)
	}
}

func TestTrimDetail(t *testing.T) {
	long := strings.Repeat("è", 130)
	if got := trimDetail(long); len([]rune(got)) != 120 || !strings.HasSuffix(got, "è") {
		t.Errorf("taglio su un carattere multibyte: %q", got[len(got)-4:])
	}
	if got := trimDetail(" riga\r\nseguente "); got != "riga  seguente" {
		t.Errorf("%q", got)
	}
}

func TestLoadOf(t *testing.T) {
	if loadOf(0, 0) != nil {
		t.Error("intervallo nullo")
	}
	if v := loadOf(750, 1000); v == nil || *v != 25 {
		t.Errorf("25%%: %v", v)
	}
	if v := loadOf(1200, 1000); *v != 0 {
		t.Errorf("limite inferiore: %v", *v)
	}
}

// Uscita di DefenderScript su un PC con una minaccia in quarantena e una
// ancora attiva; "mai" per la scansione completa (4294967295).
const defenderFixture = `{"defender":{"mode":"Normal","enabled":true,"realtime":true,"tamper":true,"sigVersion":"1.419.123.0","sigAge":0,` +
	`"sigUpdated":"2026-10-18T06:12:00.0000000Z","quickAge":1,"fullAge":4294967295,"quickEnd":"2026-10-17T12:30:00.0000000Z","fullEnd":"",` +
	`"engine":"1.1.24090.11","product":"4.18.24090.11"},` +
	`"threats":[{"name":"Trojan:Win32/Wacatac.B!ml","severity":5,"status":3,"active":false,"detected":"2026-10-12T09:15:00.0000000Z","changed":"2026-10-12T09:15:05.0000000Z"},` +
	`{"name":"","severity":0,"status":103,"active":true,"detected":"2026-10-16T18:00:00.0000000Z","changed":""}],"errors":{}}`

func TestParseDefender(t *testing.T) {
	d, threats, err := ParseDefender(defenderFixture)
	if err != nil {
		t.Fatal(err)
	}
	if d.Mode != "normal" || !d.Enabled || !d.RealTime || d.TamperProtected == nil || !*d.TamperProtected || d.SignatureVersion != "1.419.123.0" {
		t.Errorf("stato: %+v", d)
	}
	if d.SignatureAgeDays == nil || *d.SignatureAgeDays != 0 || d.QuickScanAgeDays == nil || *d.QuickScanAgeDays != 1 || d.FullScanAgeDays != nil {
		t.Errorf("età: firme %v, rapida %v, completa %v", d.SignatureAgeDays, d.QuickScanAgeDays, d.FullScanAgeDays)
	}
	if len(threats) != 2 {
		t.Fatalf("minacce: %+v", threats)
	}
	if th := threats[0]; th.Name != "Trojan:Win32/Wacatac.B!ml" || th.Severity != "severe" || th.Status != "quarantined" || th.Active {
		t.Errorf("prima minaccia: %+v", th)
	}
	if th := threats[1]; th.Name != "Minaccia senza nome" || th.Severity != "unknown" || th.Status != "failed" || !th.Active {
		t.Errorf("seconda minaccia: %+v", th)
	}
	// Modalità passiva (un altro antivirus è il principale) e servizio fermo.
	if d := defenderOf(&psDefender{Mode: "SxS Passive Mode"}); d.Mode != "passive" {
		t.Errorf("modalità: %s", d.Mode)
	}
	if _, _, err := ParseDefender(`{"errors":{"defender":"Il servizio non è in esecuzione"}}`); err == nil || !strings.Contains(err.Error(), "servizio") {
		t.Errorf("errore: %v", err)
	}
	// Nessuna minaccia: elenco vuoto, non nullo.
	ps, _ := parsePS(`{"defender":{"mode":"Normal"},"threats":[],"errors":{}}`)
	pc := &scan.PcData{}
	merge(pc, ps, "C:")
	if pc.Threats == nil || len(pc.Threats) != 0 || pc.Defender == nil {
		t.Errorf("nessuna minaccia: %+v %+v", pc.Threats, pc.Defender)
	}
}
