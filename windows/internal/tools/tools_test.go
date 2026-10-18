package tools

import (
	"errors"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestDetect(t *testing.T) {
	files := map[string]bool{
		`C:\Program Files\CrystalDiskInfo\DiskInfo64.exe`:        true,
		`C:\Program Files\CPUID\CPU-Z\cpuz.exe`:                  true,
		`C:\Program Files\Malwarebytes\Anti-Malware\mbam.exe`:    true,
		`C:\Users\Anna\AppData\Local\Programs\WizTree\setup.exe`: true,
	}
	exists := func(p string) bool { return files[p] }
	entries := []Entry{
		// Icona con ",0" in coda e tra virgolette.
		{Name: "CrystalDiskInfo 9.4.4", Version: "9.4.4", Icon: `"C:\Program Files\CrystalDiskInfo\DiskInfo64.exe",0`},
		// Solo cartella di installazione.
		{Name: "CPUID CPU-Z 2.10", Version: "2.10", Location: `C:\Program Files\CPUID\CPU-Z\`},
		{Name: "Malwarebytes version 4.6.10.200", Version: "4.6.10.200", Location: `C:\Program Files\Malwarebytes\Anti-Malware`, Icon: `C:\Program Files\Malwarebytes\Anti-Malware\Uninstall.exe`},
		// Eseguibile non ammesso (un programma diverso con lo stesso nome): ignorato.
		{Name: "WizTree", Icon: `C:\Users\Anna\AppData\Local\Programs\WizTree\setup.exe`},
		// Voce rimasta dopo la disinstallazione: il file non c'è più.
		{Name: "HWiNFO64 Version 8.12", Location: `C:\Program Files\HWiNFO64`},
		{Name: "Programma qualunque", Location: `C:\Program Files\CPUID\CPU-Z`},
	}
	got := Detect(entries, exists)
	if len(got) != 3 {
		t.Fatalf("rilevati: %+v", got)
	}
	if got["crystaldiskinfo"].Path != `C:\Program Files\CrystalDiskInfo\DiskInfo64.exe` || got["crystaldiskinfo"].Version != "9.4.4" {
		t.Errorf("CrystalDiskInfo: %+v", got["crystaldiskinfo"])
	}
	if got["cpu-z"].Path != `C:\Program Files\CPUID\CPU-Z\cpuz.exe` {
		t.Errorf("CPU-Z: %+v", got["cpu-z"])
	}
	if got["malwarebytes"].Path != `C:\Program Files\Malwarebytes\Anti-Malware\mbam.exe` {
		t.Errorf("Malwarebytes: %+v", got["malwarebytes"])
	}
}

func TestResolve(t *testing.T) {
	inst := map[string]Installed{"cpu-z": {Path: `C:\Program Files\CPUID\CPU-Z\cpuz.exe`}}
	if tg, err := Resolve("reliability", "app", nil); err != nil || tg.File != "perfmon.exe" || tg.Args != "/rel" || tg.URL {
		t.Errorf("strumento di Windows: %+v %v", tg, err)
	}
	if tg, err := Resolve("cpu-z", "app", inst); err != nil || tg.File != `C:\Program Files\CPUID\CPU-Z\cpuz.exe` {
		t.Errorf("programma installato: %+v %v", tg, err)
	}
	if tg, err := Resolve("cpu-z", "site", nil); err != nil || !tg.URL || !strings.HasPrefix(tg.File, "https://") {
		t.Errorf("sito: %+v %v", tg, err)
	}
	if _, err := Resolve("hwinfo", "app", inst); !errors.Is(err, ErrNotInstalled) {
		t.Errorf("non installato: %v", err)
	}
	for _, c := range []struct{ id, target string }{{"cmd.exe", "app"}, {`C:\Windows\System32\cmd.exe`, "app"}, {"https://evil.example", "site"}, {"windows-update", "site"}, {"cpu-z", "run"}} {
		if _, err := Resolve(c.id, c.target, inst); err == nil {
			t.Errorf("accettato: %+v", c)
		}
	}
}

// I siti sono indirizzi https sui domini dei produttori e coincidono con il
// catalogo dell'interfaccia (core/src/tools.ts), che li mostra anche senza agente.
func TestCatalogMatchesInterface(t *testing.T) {
	src, err := os.ReadFile("../../../core/src/tools.ts")
	if err != nil {
		t.Fatal(err)
	}
	ts := string(src)
	for id, p := range Programs {
		u, err := url.Parse(p.Site)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			t.Errorf("%s: sito non valido %q", id, p.Site)
		}
		if !strings.Contains(ts, `id: '`+id+`'`) || !strings.Contains(ts, `'`+p.Site+`'`) {
			t.Errorf("%s: manca o è diverso in tools.ts (%s)", id, p.Site)
		}
	}
	for id := range WindowsTools {
		if !strings.Contains(ts, `id: '`+id+`'`) {
			t.Errorf("strumento di Windows %s assente in tools.ts", id)
		}
	}
	// E viceversa: nessun identificativo dell'interfaccia sconosciuto all'agente.
	for _, m := range regexp.MustCompile(`id: '([a-z0-9-]+)'`).FindAllStringSubmatch(ts, -1) {
		if _, w := WindowsTools[m[1]]; !w {
			if _, p := Programs[m[1]]; !p {
				t.Errorf("tools.ts: %s non è nel catalogo dell'agente", m[1])
			}
		}
	}
}
