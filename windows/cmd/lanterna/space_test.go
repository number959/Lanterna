package main

import (
	"io"
	"os"
	"strings"
	"testing"

	"lanterna/internal/scan"
)

func TestSpaceFormat(t *testing.T) {
	for b, want := range map[int64]string{0: "0 B", 999: "999 B", 1000: "1,0 KB", 1_499_000: "1,5 MB", 999_960_000: "1,0 GB", 380_200_000_000: "380,2 GB", 2_000_000_000_000: "2,0 TB", -5: "0 B"} {
		if got := bytesText(b); got != want {
			t.Errorf("bytesText(%d) = %q, atteso %q", b, got, want)
		}
	}
	for n, want := range map[int64]string{0: "0", 999: "999", 1000: "1.000", 412345: "412.345", 1234567: "1.234.567", -1500: "-1.500"} {
		if got := thousands(n); got != want {
			t.Errorf("thousands(%d) = %q, atteso %q", n, got, want)
		}
	}
	if pct(1, 10000) != "<0,1 %" || pct(554, 1000) != "55,4 %" || pct(1, 0) != "" {
		t.Error("percentuali")
	}
	if clip("Documenti condivisi", 10) != "Documenti…" || clip("è", 3) != "è" {
		t.Error("clip")
	}
	if secondsText(400) != "meno di un secondo" || secondsText(52_400) != "52 s" || secondsText(150_000) != "2 min 30 s" {
		t.Error("durata")
	}
}

func TestPrintSpace(t *testing.T) {
	r := &scan.SpaceReport{
		Root: `C:\`, Drive: "C:", FS: "NTFS", TotalBytes: 500_000_000_000, FreeBytes: 100_000_000_000,
		AllocBytes: 380_000_000_000, SizeBytes: 379_000_000_000, Files: 412345, Dirs: 98765, Denied: 3,
		Errors: 2, CloudFiles: 2, CloudBytes: 5_000_000_000, LinkedBytes: 6_100_000_000, DurationMs: 52_000,
		Tree: &scan.SpaceNode{ID: 1, Name: `C:\`, Alloc: 380_000_000_000, OwnAlloc: 14_000_000_000, OwnFiles: 3,
			Children: []*scan.SpaceNode{{ID: 2, Name: "Users", Alloc: 210_000_000_000, Files: 300000}, {ID: 3, Name: "Windows", Alloc: 30_000_000_000, Files: 100000, Denied: true}},
			More:     &scan.SpaceMore{Dirs: 4, Alloc: 1_000_000}},
		TopFiles:   []scan.SpaceFile{{ID: 1, Path: `%USERPROFILE%\Video\film.mkv`, Alloc: 48_200_000_000}, {ID: 2, Path: `%USERPROFILE%\OneDrive\a.pdf`, Cloud: true}},
		Categories: []scan.SpaceType{{ID: "video", Alloc: 120_000_000_000, Files: 1234}, {ID: "nuova", Alloc: 1}},
		Hints:      []scan.SpaceHint{{ID: "recycle-bin", Path: `C:\$Recycle.Bin`, Alloc: 4_200_000_000}, {ID: "browser-cache", Alloc: 900_000_000}},
	}
	out := capture(t, func() { printSpace(r, 1, false) })
	for _, want := range []string{
		`Cosa occupa spazio in C:\ (NTFS)`,
		"Unità C: 500,0 GB in tutto, liberi 100,0 GB (20,0 %)",
		"Occupati 380,0 GB da 412.345 file in 98.765 cartelle",
		"Collegamenti fisici contati una volta sola: 6,1 GB",
		"File solo online: 2, 5,0 GB",
		"Cartelle non leggibili con i permessi attuali: 3",
		"Cartelle non lette per errori del disco o del file system: 2",
		"Spazio occupato non attribuito a file leggibili: 20,0 GB",
		"Users", "55,3 %", "(in parte non leggibile)", "altre 4 cartelle", "(file nella cartella stessa)",
		`48,2 GB  %USERPROFILE%\Video\film.mkv`,
		"Video", "nuova",
		`Cestino`, `C:\$Recycle.Bin`, "Cache dei browser",
		"Polaris non cancella nulla",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("manca %q in:\n%s", want, out)
		}
	}
	// --top 1: il secondo file non compare.
	if strings.Contains(out, "a.pdf") {
		t.Errorf("--top ignorato:\n%s", out)
	}
	// Analisi di una cartella o parziale: niente spazio non attribuito.
	r.Root, r.Partial = `C:\Users`, false
	if out := capture(t, func() { printSpace(r, 0, true) }); strings.Contains(out, "non attribuito") || strings.Contains(out, "File più grandi") || !strings.Contains(out, "riservate al sistema") {
		t.Errorf("cartella:\n%s", out)
	}
}

func capture(t *testing.T, f func()) string {
	t.Helper()
	old := os.Stdout
	rd, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(rd)
		done <- string(b)
	}()
	f()
	w.Close()
	os.Stdout = old
	return <-done
}
