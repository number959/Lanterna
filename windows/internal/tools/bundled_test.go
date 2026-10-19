package tools

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestFindBundled(t *testing.T) {
	orig := Bundled
	defer func() { Bundled = orig }()
	good, bad := []byte("eseguibile originale"), []byte("eseguibile sostituito")
	sum := sha256.Sum256(good)
	Bundled = map[string]Bundle{
		"crystaldiskinfo": {Dir: "CrystalDiskInfo", Version: "9.9.2", Exe: map[string]Binary{"amd64": {"DiskInfo64.exe", hex.EncodeToString(sum[:])}}},
		"crystaldiskmark": {Dir: "CrystalDiskMark", Version: "9.0.3", Exe: map[string]Binary{"amd64": {"DiskMark64.exe", hex.EncodeToString(sum[:])}}},
		"hwinfo":          {Dir: "HWiNFO", Version: "1", Exe: map[string]Binary{"amd64": {"HWiNFO64.exe", hex.EncodeToString(sum[:])}}},
	}
	root := t.TempDir()
	write := func(rel string, b []byte) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("CrystalDiskInfo/DiskInfo64.exe", good)
	write("CrystalDiskMark/DiskMark64.exe", bad)
	// HWiNFO: cartella senza l'eseguibile, come in un pacchetto incompleto.
	if err := os.MkdirAll(filepath.Join(root, "HWiNFO", "HWiNFO64.exe"), 0o755); err != nil {
		t.Fatal(err)
	}

	got := FindBundled(root, "amd64")
	if len(got) != 2 {
		t.Fatalf("trovati: %+v", got)
	}
	if in := got["crystaldiskinfo"]; in.Version != "9.9.2" || in.Problem != "" || in.Path != filepath.Join(root, "CrystalDiskInfo", "DiskInfo64.exe") {
		t.Errorf("copia integra: %+v", in)
	}
	if in := got["crystaldiskmark"]; in.Problem == "" || in.Path != "" {
		t.Errorf("copia modificata: %+v", in)
	}
	if got := FindBundled(root, "arm64"); len(got) != 0 {
		t.Errorf("architettura senza eseguibile: %+v", got)
	}
	if got := FindBundled(filepath.Join(root, "manca"), "amd64"); len(got) != 0 {
		t.Errorf("pacchetto senza strumenti: %+v", got)
	}
}

func TestMergePrefersVerifiedCopy(t *testing.T) {
	installed := map[string]Installed{
		"crystaldiskinfo": {Version: "9.4.4", Path: `C:\Program Files\CrystalDiskInfo\DiskInfo64.exe`},
		"crystaldiskmark": {Version: "8.0.6", Path: `C:\Program Files\CrystalDiskMark8\DiskMark64.exe`},
	}
	bundled := map[string]Included{
		"crystaldiskinfo": {Version: "9.9.2", Path: `D:\Polaris\strumenti\CrystalDiskInfo\DiskInfo64.exe`},
		"crystaldiskmark": {Version: "9.0.3", Problem: "modificato"},
	}
	all := Merge(installed, bundled)
	tg, err := Resolve("crystaldiskinfo", "app", all)
	if err != nil || tg.File != `D:\Polaris\strumenti\CrystalDiskInfo\DiskInfo64.exe` || tg.Dir != `D:\Polaris\strumenti\CrystalDiskInfo` {
		t.Errorf("copia inclusa: %+v %v", tg, err)
	}
	// La copia alterata non si usa: resta quella installata.
	if tg, err := Resolve("crystaldiskmark", "app", all); err != nil || tg.File != `C:\Program Files\CrystalDiskMark8\DiskMark64.exe` {
		t.Errorf("copia alterata: %+v %v", tg, err)
	}
	if installed["crystaldiskinfo"].Version != "9.4.4" {
		t.Error("Merge ha modificato la mappa dei programmi installati")
	}
}

// Versioni e nomi dei programmi inclusi coincidono in agente, script di build,
// avvisi di licenza e interfaccia.
func TestBundledMatchesBuild(t *testing.T) {
	read := func(p string) string {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	script, notices, ts := read("../../../scripts/strumenti.sh"), read("../../../scripts/notices.sh"), read("../../../core/src/tools.ts")
	hexRe := regexp.MustCompile(`^[0-9a-f]{64}$`)
	for id, b := range Bundled {
		p, ok := Programs[id]
		if !ok {
			t.Errorf("%s: incluso ma assente dal catalogo", id)
		}
		for arch, bin := range b.Exe {
			if !hexRe.MatchString(bin.SHA256) {
				t.Errorf("%s %s: impronta non valida", id, arch)
			}
			allowed := false
			for _, x := range p.Exes {
				allowed = allowed || strings.EqualFold(x, bin.Name)
			}
			if !allowed {
				t.Errorf("%s: %s non è tra gli eseguibili ammessi", id, bin.Name)
			}
		}
		if !regexp.MustCompile(`"` + b.Dir + ` ` + regexp.QuoteMeta(b.Version) + ` https://\S+ [0-9a-f]{64}"`).MatchString(script) {
			t.Errorf("%s %s: manca in scripts/strumenti.sh", b.Dir, b.Version)
		}
		if !strings.Contains(notices, "## "+b.Dir+" "+b.Version) {
			t.Errorf("%s %s: manca negli avvisi di scripts/notices.sh", b.Dir, b.Version)
		}
		if !regexp.MustCompile(`id: '` + id + `',[^}]*included: '` + regexp.QuoteMeta(b.Version) + `'`).MatchString(ts) {
			t.Errorf("%s: tools.ts non indica la versione inclusa %s", id, b.Version)
		}
	}
	if n := strings.Count(ts, "included: '"); n != len(Bundled) {
		t.Errorf("tools.ts indica %d programmi inclusi, l'agente %d", n, len(Bundled))
	}
}
