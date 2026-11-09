//go:build windows

package pcinfo

import (
	"context"
	"strings"
	"testing"
	"time"

	"lanterna/internal/scan"
)

// Prove su Windows reale (nella CI): le letture native restituiscono dati
// plausibili. Nella CI l'agente gira come amministratore.

func TestReadDevicesWindows(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	raw, partial, err := readDevices(ctx)
	if err != nil || partial {
		t.Fatalf("lettura: %v (parziale %v)", err, partial)
	}
	classes := map[string]int{}
	withDriver := 0
	for _, r := range raw {
		classes[r.Class]++
		if r.Inf != "" && r.Date != "" && r.Version != "" {
			withDriver++
		}
	}
	if len(raw) < 10 || classes["DiskDrive"] == 0 || classes["Volume"] == 0 || withDriver < 5 {
		t.Errorf("dispositivi: %d, classi %v, con driver completo %d", len(raw), classes, withDriver)
	}
	if codeIntegrity() == nil {
		t.Error("integrità del codice non letta")
	}
	t.Logf("%d dispositivi, %d classi, %d con driver completo", len(raw), len(classes), withDriver)
}

func TestMaintenanceWindows(t *testing.T) {
	s := updateServices()
	if s == nil || s.WU == nil || s.WU.Start == "unknown" {
		t.Errorf("servizi di Windows Update: %+v", s)
	}
	drive := "C:"
	if d := volumeDirty(drive); d == nil {
		t.Errorf("stato da controllare di %s non letto", drive)
	}
	if m := readMemDiag(context.Background()); m == nil {
		t.Error("registro di sistema non letto per Diagnostica memoria")
	}
	if c := readFsChecks(context.Background()); c == nil {
		t.Error("registro Applicazione non letto per i controlli del disco")
	}
	if a := readApps(context.Background()); a == nil || a.Channel != "ok" || a.Wer == nil {
		t.Errorf("programmi: %+v", a)
	}
}

func TestAccessWindows(t *testing.T) {
	a := readAccounts()
	if a == nil || len(a.Local) == 0 || a.Admins == nil || a.Admins.Members == 0 {
		t.Fatalf("account: %+v", a)
	}
	builtin := false
	for _, l := range a.Local {
		if l.RID == 500 {
			builtin = true
		}
	}
	if !builtin {
		t.Error("Administrator integrato (RID 500) non trovato")
	}
	acc := readAccess()
	if acc == nil || acc.UAC == nil || acc.Lock == nil || acc.Autologon == nil {
		t.Errorf("accessi: %+v", acc)
	}
	p := readPrinting(context.Background())
	if p == nil || p.Spooler == nil || p.Printers == nil {
		t.Errorf("stampa: %+v", p)
	}
	t.Logf("account %d, amministratori %+v, UAC %+v, RDP %+v, stampanti %d, spooler %+v", len(a.Local), a.Admins, acc.UAC, acc.RDP, len(p.Printers), p.Spooler)
}

// Le macchine della CI sono virtuali e di solito senza controller USB: qui
// si prova che la lettura non si blocchi e non lasci uscire identificativi
// di istanza; l'albero con dispositivi veri non è provabile in CI.
func TestUsbWindows(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), usbTimeout)
	defer cancel()
	devs, err := usbDevices(ctx)
	if err != nil || len(devs) < 10 {
		t.Fatalf("dispositivi: %d (%v)", len(devs), err)
	}
	withParent := 0
	for _, d := range devs {
		if d.Parent != "" {
			withParent++
		}
	}
	if withParent < len(devs)/2 {
		t.Errorf("genitore letto per %d dispositivi su %d", withParent, len(devs))
	}
	u := readUsb(ctx)
	if u == nil || u.Read == "error" || u.Partial {
		t.Fatalf("albero USB: %+v", u)
	}
	ports, withDev := 0, 0
	var walk func(h *scan.UsbHub)
	walk = func(h *scan.UsbHub) {
		if h == nil {
			return
		}
		for _, p := range h.Ports {
			ports++
			if p.Device != nil {
				withDev++
				if strings.Contains(p.Device.Name, `\`) {
					t.Errorf("percorso o identificativo nel nome: %q", p.Device.Name)
				}
				walk(p.Device.Hub)
			}
		}
	}
	for _, c := range u.Controllers {
		walk(c.Hub)
	}
	t.Logf("USB: %s, %d controller, %d porte occupate, %d dispositivi", u.Read, len(u.Controllers), ports, withDev)
}
