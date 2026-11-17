package pcinfo

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"lanterna/internal/scan"
)

func TestTpmVersionOf(t *testing.T) {
	str := func(p *string) string {
		if p == nil {
			return "nil"
		}
		return "'" + *p + "'"
	}
	for _, c := range []struct {
		code, ver uint32
		want      string
	}{
		{0, 2, "'2.0'"},
		{0, 1, "'1.2'"},
		{0, 0, "nil"},          // versione sconosciuta: non verificato
		{0x8028400F, 0, "''"},  // TBS_E_TPM_NOT_FOUND: nessun TPM
		{0x80284010, 0, "nil"}, // servizio TBS disattivato
		{0x80284002, 2, "nil"}, // parametro rifiutato
	} {
		if got := str(tpmVersionOf(c.code, c.ver)); got != c.want {
			t.Errorf("tpmVersionOf(%#x, %d) = %s, atteso %s", c.code, c.ver, got, c.want)
		}
	}
}

func TestAppraiser(t *testing.T) {
	key, target := latestAppraiserKey([]string{"19H1", "21H2", "22H2", "CO21H2", "NI22H2", "NI23H2", "GE24H2", "UNV", "GE25H2"})
	if key != "GE25H2" || target != "25H2" {
		t.Errorf("chiave più recente: %q %q", key, target)
	}
	// Solo chiavi di Windows 10 (senza nome in codice): niente verdetto per Windows 11.
	if key, _ := latestAppraiserKey([]string{"21H1", "21H2", "22H2"}); key != "" {
		t.Errorf("chiave di Windows 10 scelta: %q", key)
	}
	at := time.Date(2026, 11, 3, 9, 30, 0, 0, time.UTC)
	got := AppraiserOf("25H2", "Red", "CpuFms  Tpm,UefiSecureBoot Tpm None", at)
	want := &scan.Win11Appraiser{Target: "25H2", Verdict: "red", Reasons: []string{"CpuFms", "Tpm", "UefiSecureBoot"}, At: "2026-11-03T09:30:00Z"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("verdetto rosso:\n got %+v\nwant %+v", got, want)
	}
	got = AppraiserOf("24H2", "Green", "None", time.Time{})
	if got == nil || got.Verdict != "green" || got.Reasons != nil || got.At != "" {
		t.Errorf("verdetto verde: %+v", got)
	}
	// Valori sconosciuti o testo strano: si scartano.
	got = AppraiserOf("24H2", "Orange", `C:\Users\anna x<y Ram`, at)
	if got == nil || got.Verdict != "" || !reflect.DeepEqual(got.Reasons, []string{"Ram"}) {
		t.Errorf("valori non previsti: %+v", got)
	}
	if AppraiserOf("24H2", "", "", at) != nil {
		t.Error("chiave vuota: atteso nil")
	}
}

func TestAssignWddm(t *testing.T) {
	gpus := func(names ...string) []scan.PcGPU {
		out := []scan.PcGPU{}
		for _, n := range names {
			out = append(out, scan.PcGPU{Name: n})
		}
		return out
	}
	basic := wddmAdapter{Name: "Microsoft Basic Render Driver", Software: true, Version: 1300}
	// Per nome, anche con marchi scritti in modo diverso.
	g := gpus("Intel(R) UHD Graphics 770", "NVIDIA GeForce RTX 4060")
	AssignWddm(g, []wddmAdapter{basic, {Name: "NVIDIA GeForce RTX 4060", Version: 3200}, {Name: "Intel® UHD Graphics 770", Version: 3100}})
	if g[0].Wddm != 3100 || g[1].Wddm != 3200 {
		t.Errorf("per nome: %+v", g)
	}
	// Nomi diversi e due schede: non si sa quale sia quale.
	g = gpus("Intel(R) UHD Graphics 620", "AMD Radeon RX 6600")
	AssignWddm(g, []wddmAdapter{{Name: "Intel(R) UHD Graphics Family", Version: 3000}, {Name: "AMD Radeon(TM) Graphics", Version: 3100}})
	if g[0].Wddm != 0 || g[1].Wddm != 0 {
		t.Errorf("associazione incerta: %+v", g)
	}
	// Una sola scheda vera da entrambe le parti: si associa anche con nomi diversi.
	g = gpus("Intel(R) UHD Graphics 620", "Microsoft Remote Display Adapter")
	AssignWddm(g, []wddmAdapter{basic, {Name: "Intel(R) UHD Graphics Family", Version: 2700}})
	if g[0].Wddm != 2700 || g[1].Wddm != 0 {
		t.Errorf("scheda unica: %+v", g)
	}
	// Solo adattatori software o versioni non lette: nulla.
	g = gpus("Microsoft Basic Display Adapter")
	AssignWddm(g, []wddmAdapter{basic, {Name: "X", Version: 0}})
	if g[0].Wddm != 0 {
		t.Errorf("adattatore di base: %+v", g)
	}
	// Due schede uguali con lo stesso nome: non si sa quale.
	g = gpus("NVIDIA RTX A2000", "NVIDIA RTX A2000")
	AssignWddm(g, []wddmAdapter{{Name: "NVIDIA RTX A2000", Version: 3100}})
	if g[0].Wddm != 0 || g[1].Wddm != 0 {
		t.Errorf("schede omonime: %+v", g)
	}
}

func TestApplyHardwareExtra(t *testing.T) {
	ps, err := parsePS(`{"gpus":[{"name":"Intel(R) Iris(R) Xe Graphics","w":1920,"h":1200,"hz":60}],` +
		`"mon":[{"id":"DISPLAY\\BOE0A1C\\4&1a2b3c&0&UID8388688_0","w":30,"h":19,"vot":2147483648}],"sbCapable":true,"errors":{}}`)
	if err != nil {
		t.Fatal(err)
	}
	if ps.SBCapable == nil || !*ps.SBCapable || ps.Mon == nil || len(*ps.Mon) != 1 || (*ps.Mon)[0].Vot == nil || *(*ps.Mon)[0].Vot != 2147483648 {
		t.Fatalf("uscita dello script: %+v", ps)
	}
	off := false
	pc := &scan.PcData{Memory: &scan.PcMemory{TotalMB: 15_700}, Hardware: &scan.Hardware{Firmware: "uefi", SecureBoot: &off}}
	merge(pc, ps, "C:")
	two := "2.0"
	x := hwExtra{
		InstalledMB: 16_384, TPM: &two,
		Appraiser: &scan.Win11Appraiser{Target: "25H2", Verdict: "green"},
		Displays:  []rawDisplay{{Tech: techInternal, HasTech: true, Width: 1920, Height: 1200, Bits: 8, Path: `\\?\DISPLAY#BOE0A1C#4&1a2b3c&0&UID8388688#{e6f07b5f-ee97-4a90-b076-33f57bf4eaa7}`}},
		Wddm:      []wddmAdapter{{Name: "Intel(R) Iris(R) Xe Graphics", Version: 3100}},
	}
	raw := []rawDevice{pciDev("8086", "A0E8", "0A251028", "20", "0C0500"), pciDev("8086", "A082", "0A251028", "20", "060100")}
	applyHardwareExtra(pc, x, true, ps, raw, true, false)
	if pc.Memory.InstalledMB != 16_384 {
		t.Errorf("RAM installata: %d", pc.Memory.InstalledMB)
	}
	if pc.Win11 == nil || pc.Win11.TpmVersion == nil || *pc.Win11.TpmVersion != "2.0" || pc.Win11.SecureBootCapable == nil || !*pc.Win11.SecureBootCapable || pc.Win11.Appraiser.Verdict != "green" {
		t.Errorf("Windows 11: %+v", pc.Win11)
	}
	if len(pc.Hardware.Chipset) != 2 || pc.Hardware.Chipset[0].Device != "A082" {
		t.Errorf("chipset: %+v", pc.Hardware.Chipset)
	}
	if len(pc.Hardware.Displays) != 1 || pc.Hardware.Displays[0] != (scan.Display{Width: 1920, Height: 1200, DiagonalIn: 14.0, BitsPerColor: 8, Internal: true}) {
		t.Errorf("schermi: %+v", pc.Hardware.Displays)
	}
	if len(pc.GPUs) != 1 || pc.GPUs[0].Wddm != 3100 {
		t.Errorf("WDDM: %+v", pc.GPUs)
	}
	if len(pc.Notes) != 0 {
		t.Errorf("note inattese: %v", pc.Notes)
	}
	js, _ := json.Marshal(pc)
	for _, bad := range []string{"UID8388688", `DISPLAY\\`, "SUBSYS", "0A251028"} {
		if strings.Contains(string(js), bad) {
			t.Errorf("%s nel JSON: %s", bad, js)
		}
	}

	// Senza amministratore, Secure Boot spento: lo si dice. Lettura nativa
	// non finita in tempo, dispositivi non letti, RAM SMBIOS non plausibile.
	ps.SBCapable = nil
	pc = &scan.PcData{Memory: &scan.PcMemory{TotalMB: 8_000}, Hardware: &scan.Hardware{Firmware: "uefi", SecureBoot: &off}}
	applyHardwareExtra(pc, hwExtra{InstalledMB: 4_096}, false, ps, raw, false, false)
	if pc.Memory.InstalledMB != 0 || pc.Hardware.Chipset != nil || pc.Win11 == nil || pc.Win11.SecureBootCapable != nil || pc.Win11.TpmVersion != nil {
		t.Errorf("letture mancanti: %+v %+v %+v", pc.Memory, pc.Hardware, pc.Win11)
	}
	if len(pc.Notes) != 2 || !strings.Contains(pc.Notes[0], "non sono stati letti") || !strings.Contains(pc.Notes[1], "amministratore") {
		t.Errorf("note: %v", pc.Notes)
	}
	// Senza script e senza letture native nulla da dire su Windows 11.
	pc = &scan.PcData{}
	applyHardwareExtra(pc, hwExtra{}, false, nil, nil, false, true)
	if pc.Win11 != nil || pc.Hardware == nil || len(pc.Notes) != 1 {
		t.Errorf("senza dati: %+v %v", pc.Win11, pc.Notes)
	}
}

// Lo script passa a powershell.exe come argomento: con le virgolette
// protette deve restare sotto il limite della riga di comando di Windows
// (32767 caratteri).
func TestPSScriptFitsCommandLine(t *testing.T) {
	n := len(PSScript) + 2*strings.Count(PSScript, `"`) + strings.Count(PSScript, `\`)
	if n > 30_000 {
		t.Errorf("script troppo lungo per la riga di comando: circa %d caratteri", n)
	}
	for _, want := range []string{"WmiMonitorBasicDisplayParams", "WmiMonitorConnectionParams", "Confirm-SecureBootUEFI", "$r.mon=", "$r.sbCapable="} {
		if !strings.Contains(PSScript, want) {
			t.Errorf("manca %s nello script", want)
		}
	}
	// Mai l'EDID dal registro né i numeri di serie degli schermi.
	for _, bad := range []string{"EDID", "WmiMonitorID", "SerialNumber"} {
		if strings.Contains(PSScript, bad) {
			t.Errorf("lo script legge %s", bad)
		}
	}
}
