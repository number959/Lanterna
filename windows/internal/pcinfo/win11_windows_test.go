//go:build windows

package pcinfo

import (
	"context"
	"encoding/json"
	"testing"
	"time"
	"unsafe"

	"lanterna/internal/scan"
)

// Prova su Windows reale (nella CI, da amministratore): TPM, RAM
// installata, schermi, driver video, verdetto di Windows Update e chipset.
func TestHardwareWin11Windows(t *testing.T) {
	// Tbsi_GetDeviceInfo deve rispondere con un codice di TBS, non con un
	// errore di chiamata: senza TPM (molte macchine virtuali) è
	// TBS_E_TPM_NOT_FOUND.
	if err := procTbsiGetDeviceInfo.Find(); err != nil {
		t.Fatalf("tbs.dll: %v", err)
	}
	info := tpmDeviceInfo{structVersion: 2}
	r, _, _ := procTbsiGetDeviceInfo.Call(unsafe.Sizeof(info), uintptr(unsafe.Pointer(&info)))
	switch code := uint32(r); code {
	case tbsSuccess, tbsTPMNotFound:
		t.Logf("Tbsi_GetDeviceInfo: %#x, versione %d, interfaccia %d", code, info.tpmVersion, info.tpmInterfaceType)
	case 0x80284010: // TBS_E_SERVICE_DISABLED: il servizio c'è ma è disattivato
		t.Logf("servizio TBS disattivato (%#x)", code)
	default:
		t.Errorf("Tbsi_GetDeviceInfo: codice inatteso %#x", code)
	}
	tpm := tpmVersion()
	if tpm != nil && *tpm != "" && *tpm != "2.0" && *tpm != "1.2" {
		t.Errorf("versione del TPM: %q", *tpm)
	}

	mem := memInfo()
	inst := installedMB()
	if mem == nil {
		t.Fatal("memoria non letta")
	}
	if inst <= 0 || inst < mem.TotalMB {
		t.Errorf("RAM installata %d MB, vista da Windows %d MB", inst, mem.TotalMB)
	}
	t.Logf("RAM installata %d MB, totale %d MB", inst, mem.TotalMB)

	disp, err := readDisplays()
	t.Logf("schermi (QueryDisplayConfig): %d, errore %v", len(disp), err)
	for _, d := range disp {
		t.Logf("  %dx%d (nativa %dx%d), collegamento %#x, %d bit, percorso letto: %v", d.Width, d.Height, d.NativeWidth, d.NativeHeight, d.Tech, d.Bits, d.Path != "")
		if (d.NativeWidth == 0) != (d.NativeHeight == 0) {
			t.Errorf("risoluzione nativa a metà: %+v", d)
		}
	}
	for _, a := range readWddm() {
		t.Logf("scheda video %q: software %v, WDDM %d", a.Name, a.Software, a.Version)
		if !a.Software && a.Version != 0 && (a.Version < 1000 || a.Version > 9999) {
			t.Errorf("versione WDDM non plausibile: %d", a.Version)
		}
	}
	if a := readAppraiser(); a != nil {
		t.Logf("verdetto di Windows Update: %+v", *a)
	}

	// Tutto insieme, con i dispositivi veri: nel JSON niente ID d'istanza,
	// percorsi dei dispositivi o numeri di serie.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	raw, _, err := readDevices(ctx)
	if err != nil {
		t.Fatalf("dispositivi: %v", err)
	}
	x, ok := startHardwareExtra(ctx)()
	if !ok {
		t.Fatal("letture native non finite in tempo")
	}
	pc := &scan.PcData{Memory: mem, Hardware: hardwareNative()}
	applyHardwareExtra(pc, x, ok, nil, raw, true, true)
	js := privacyJSON(t, pc)
	t.Logf("chipset %+v; schermi %+v; Windows 11 %s", pc.Hardware.Chipset, pc.Hardware.Displays, win11JSON(pc.Win11))
	if len(pc.Hardware.Chipset) == 0 {
		t.Log("nessuna funzione del chipset (macchina virtuale senza bridge PCI?)")
	}
	for _, f := range pc.Hardware.Chipset {
		if len(f.Vendor) != 4 || len(f.Device) != 4 || (f.Class != "" && len(f.Class) != 4) {
			t.Errorf("funzione PCI non valida: %+v", f)
		}
	}
	// Controllo provato anche su Linux (TestLeaksDeviceIDs in win11_test.go).
	if leaksDeviceIDs(js) {
		t.Errorf("identificativi nel JSON: %s", js)
	}
}

func win11JSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
