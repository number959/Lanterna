package main

import (
	"strings"
	"testing"
	"time"

	"lanterna/internal/scan"
)

func TestPrintCrashes(t *testing.T) {
	three, yes, no := 3, true, false
	d := &scan.CrashData{
		ReadAt:   "2026-10-31T09:00:00Z",
		Settings: &scan.CrashSettings{DumpEnabled: &three, MinidumpDir: `%SystemRoot%\Minidump`, AutoReboot: &yes, LogEvent: &yes, Overwrite: &no},
		Folder:   "ok",
		Total:    60,
		Dumps: []scan.CrashDump{
			{File: "092726-9999-01.dmp", Size: 1 << 20, Modified: "2026-09-27T21:15:00Z", Error: "accesso negato: serve avviare Polaris come amministratore"},
			{File: "092026-1234-01.dmp", Size: 524288, Time: "2026-09-20T10:00:00Z", Code: "0x000000d1",
				Params: []string{"0x0000000000000034", "0x0000000000000002", "0x0000000000000001", "0xfffff8045b603c78"}, Bits: 64, Machine: "x64", Build: 26100,
				DumpType: "triage", Drivers: 180, Probable: &scan.CrashCulprit{Driver: "fictnet.sys", Method: "param", Param: 4, Offset: "0x3c78"}, Stack: []string{"fictnet.sys", "fictaudio.sys"}},
			{File: "090226-5678-01.dmp", Size: 300000, Time: "2026-09-02T10:00:00Z", Code: "0x0000009f", Params: []string{"0x0000000000000003", "", "", ""},
				DumpType: "triage", Probable: &scan.CrashCulprit{Driver: "oldvpnflt.sy…", Method: "stack", Offset: "0x10", Unloaded: true}},
			{File: "081526-0001-01.dmp", Size: 300000, Time: "2026-08-15T10:00:00Z", Code: "0x00000124", DumpType: "triage"},
			{File: "081026-0001-01.dmp", Size: 300000, Time: "2026-08-10T10:00:00Z", Code: "0x0000001a", DumpType: "triage"},
			{File: "080526-0001-01.dmp", Size: 300000, Time: "2026-08-05T10:00:00Z", Code: "0x000000e2", DumpType: "triage"},
			{File: "080326-0001-01.dmp", Size: 300000, Time: "2026-08-03T10:00:00Z", DumpType: "triage"},
			{File: "080126-0001-01.dmp", Size: 300000, Code: "0x00abcdef", DumpType: "triage", Limited: "inconsistent"},
		},
		MemoryDump: &scan.CrashDump{File: "MEMORY.DMP", Size: 1_200_000_000, Time: "2026-09-27T21:14:03Z", Code: "0x0000009f", DumpType: "bitmap-kernel", Limited: "not-triage"},
		NeedsAdmin: true,
	}
	out := capture(t, func() { printCrashes(d, time.UTC) })
	for _, want := range []string{
		"Salvataggio dopo una schermata blu: dump piccolo (minidump)",
		`Cartella dei minidump: %SystemRoot%\Minidump`,
		"Riavvio automatico sì, evento nel registro di sistema sì, sovrascrive MEMORY.DMP no",
		"Schermate blu nei minidump: 60 (mostrati i 8 più recenti)",
		"27/09/2026 21:15 (data del file)  092726-9999-01.dmp",
		"Non letto: accesso negato",
		"20/09/2026 10:00  0x000000D1 DRIVER_IRQL_NOT_LESS_OR_EQUAL",
		"Parametri: 0x0000000000000034  0x0000000000000002",
		"Driver indicato (indizio, dall'indirizzo nel parametro 4): fictnet.sys +3c78",
		"Altri moduli nello stack: fictaudio.sys",
		"File: 092026-1234-01.dmp, dump piccolo (minidump), 524,3 KB, build 26100, x64",
		"Driver indicato (indizio, dallo stack salvato): oldvpnflt.sy… +10, già scaricato",
		"0x00000124 WHEA_UNCORRECTABLE_ERROR\n  Driver indicato: nessuno, errore segnalato dall'hardware",
		"0x0000001A MEMORY_MANAGEMENT\n  Driver indicato: nessun driver fuori dal nucleo di Windows (kernel e HAL) nello stack salvato",
		"0x000000E2 MANUALLY_INITIATED_CRASH\n  Driver indicato: nessuno, arresto provocato di proposito",
		"codice non scritto nel file\n  Driver indicato: non cercato, codice non scritto nel file",
		"0x00ABCDEF\n",
		"dati del minidump incoerenti: solo intestazione",
		"Dump della memoria (MEMORY.DMP):",
		"MEMORY.DMP, dump del kernel, 1,2 GB, solo intestazione",
		"Per leggere i file delle schermate blu serve avviare Polaris come amministratore.",
		"è un indizio, non una certezza",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("manca %q in:\n%s", want, out)
		}
	}

	if strings.Contains(out, "terze parti") {
		t.Errorf("solo kernel e HAL si saltano, non tutti i driver Microsoft:\n%s", out)
	}
	if strings.Count(out, "Driver indicato") != 6 || strings.Contains(out, "inconsistent") {
		t.Errorf("righe del driver indicato:\n%s", out)
	}

	zero := 0
	out = capture(t, func() {
		printCrashes(&scan.CrashData{Settings: &scan.CrashSettings{DumpEnabled: &zero}, Folder: "denied", NeedsAdmin: true, Dumps: []scan.CrashDump{}}, time.UTC)
	})
	for _, want := range []string{"Salvataggio dopo una schermata blu: nessun file", "le prossime non lasceranno file", "Cartella dei minidump non leggibile", "serve avviare Polaris come amministratore"} {
		if !strings.Contains(out, want) {
			t.Errorf("manca %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "indizio") {
		t.Errorf("avviso sull'indizio senza file:\n%s", out)
	}
	out = capture(t, func() { printCrashes(&scan.CrashData{Folder: "missing", Dumps: []scan.CrashDump{}}, time.UTC) })
	if !strings.Contains(out, "Impostazioni dei dump non leggibili.") || !strings.Contains(out, "Nessun file di schermata blu") {
		t.Errorf("senza impostazioni:\n%s", out)
	}
	// Cartella illeggibile per un errore diverso dai permessi: non è "nessun file".
	out = capture(t, func() {
		printCrashes(&scan.CrashData{Settings: d.Settings, Folder: "error", Dumps: []scan.CrashDump{}}, time.UTC)
	})
	if !strings.Contains(out, "Cartella dei minidump non leggibile: errore di lettura.") || strings.Contains(out, "Nessun file") {
		t.Errorf("cartella con errore:\n%s", out)
	}
	// Lettura fermata prima di arrivare alla cartella.
	out = capture(t, func() { printCrashes(&scan.CrashData{Partial: true, Dumps: []scan.CrashDump{}}, time.UTC) })
	if !strings.Contains(out, "Lettura dei file delle schermate blu non finita in tempo.") || strings.Contains(out, "Nessun file") || strings.Contains(out, "Lettura interrotta") {
		t.Errorf("lettura non finita:\n%s", out)
	}
}
