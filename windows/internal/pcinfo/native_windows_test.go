//go:build windows

package pcinfo

import (
	"context"
	"testing"
	"time"
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
