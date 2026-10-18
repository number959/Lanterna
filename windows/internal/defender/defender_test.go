package defender

import (
	"strings"
	"testing"
	"time"

	"lanterna/internal/scan"
)

func TestArgs(t *testing.T) {
	for action, want := range map[string]string{Quick: "-Scan -ScanType 1", Full: "-Scan -ScanType 2", Update: "-SignatureUpdate"} {
		a, err := Args(action)
		if err != nil || strings.Join(a, " ") != want {
			t.Errorf("%s: %v %v", action, a, err)
		}
	}
	if _, err := Args("rm -rf"); err == nil {
		t.Error("azione arbitraria accettata")
	}
	if Timeouts[Full] < Timeouts[Quick] || Timeouts[Update] == 0 {
		t.Error("tempi massimi")
	}
}

func TestCheckExit(t *testing.T) {
	if CheckExit(Quick, 0, "") != nil || CheckExit(Full, 2, "found 1 threats") != nil {
		t.Error("esiti riusciti scambiati per errori")
	}
	// Per l'aggiornamento il codice 2 è un errore.
	if CheckExit(Update, 2, "") == nil {
		t.Error("aggiornamento fallito accettato")
	}
	err := CheckExit(Quick, -2147024891, "Scan starting...\r\nCmdTool: Failed with hr = 0x80070005. Check C:\\...\\MpCmdRun.log for more information\r\n")
	if err == nil || !strings.Contains(err.Error(), "0x80070005") || !strings.Contains(err.Error(), "-2147024891") {
		t.Errorf("errore: %v", err)
	}
}

func TestNewSinceAndMessage(t *testing.T) {
	start := time.Date(2026, 10, 18, 10, 0, 0, 0, time.UTC)
	threats := []scan.Threat{
		{Name: "Trojan:Win32/Wacatac.B!ml", Detected: "2026-10-18T10:03:00Z"},
		{Name: "PUA:Win32/Presenoker", Detected: "2026-09-01T08:00:00Z"},
		{Name: "Senza data"},
	}
	if n := NewSince(threats, start); n != 1 {
		t.Fatalf("nuove minacce: %d", n)
	}
	if m := Message(Full, 1, nil); !strings.Contains(m, "completa") || !strings.Contains(m, "1 minaccia") {
		t.Errorf("messaggio: %s", m)
	}
	if m := Message(Quick, 0, nil); !strings.Contains(m, "nessuna nuova minaccia") {
		t.Errorf("messaggio: %s", m)
	}
	if m := Message(Update, 0, &scan.DefenderInfo{SignatureVersion: "1.419.123.0"}); m != "Firme aggiornate: versione 1.419.123.0." {
		t.Errorf("messaggio: %s", m)
	}
}
