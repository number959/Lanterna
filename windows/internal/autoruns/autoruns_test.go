package autoruns

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"lanterna/internal/scan"
)

func msFile(folder string) *scan.FileFacts {
	return &scan.FileFacts{Path: "x", Folder: folder, Signature: &scan.FileSignature{Status: "valid", Signer: "Microsoft Windows", Microsoft: true}}
}

func TestWindowsEntry(t *testing.T) {
	third := &scan.FileFacts{Path: "x", Folder: "programFiles", Signature: &scan.FileSignature{Status: "valid", Signer: "Vendor Inc."}}
	whql := &scan.FileFacts{Path: "x", Folder: "windows", Signature: &scan.FileSignature{Status: "valid", Signer: "Microsoft Windows Hardware Compatibility Publisher"}}
	missing := &scan.FileFacts{Path: "x", Folder: "windows", Missing: true}
	unsigned := &scan.FileFacts{Path: "x", Folder: "appData", Signature: &scan.FileSignature{Status: "unsigned"}}
	for _, c := range []struct {
		name string
		it   item
		hide bool
	}{
		{"Microsoft in Windows", item{entry: scan.AutorunEntry{File: msFile("windows")}}, true},
		{"Microsoft in Program Files", item{entry: scan.AutorunEntry{File: msFile("programFiles")}}, true},
		{"Microsoft in una cartella dell'utente", item{entry: scan.AutorunEntry{File: msFile("appData")}}, false},
		{"di terzi", item{entry: scan.AutorunEntry{File: third}}, false},
		{"driver rifirmato da Microsoft (WHQL)", item{entry: scan.AutorunEntry{File: whql}}, false},
		{"file mancante", item{entry: scan.AutorunEntry{File: missing}}, false},
		{"senza firma", item{entry: scan.AutorunEntry{File: unsigned}}, false},
		{"senza file", item{entry: scan.AutorunEntry{}}, false},
		{"firma non verificata", item{entry: scan.AutorunEntry{File: &scan.FileFacts{Path: "x", Folder: "windows"}}}, false},
		{"rundll32 con DLL di Microsoft", item{entry: scan.AutorunEntry{File: msFile("windows"), Target: msFile("windows")}}, true},
		{"rundll32 con DLL di terzi", item{entry: scan.AutorunEntry{File: msFile("windows"), Target: third}}, false},
		{"rundll32 con DLL mancante", item{entry: scan.AutorunEntry{File: msFile("windows"), Target: missing}}, false},
		{"comando interpretato", item{entry: scan.AutorunEntry{File: msFile("windows")}, interpreted: true}, false},
		{"dirottamento firmato Microsoft", item{entry: scan.AutorunEntry{File: msFile("windows")}, hijack: true}, false},
		{"profilo di un altro utente", item{entry: scan.AutorunEntry{File: msFile("windows")}, unverified: true}, false},
	} {
		if got := windowsEntry(c.it); got != c.hide {
			t.Errorf("%s: nascosta %v, attesa %v", c.name, got, c.hide)
		}
	}
}

func TestAssemble(t *testing.T) {
	items := []item{
		{entry: scan.AutorunEntry{Category: "tasks", Name: "t1", File: msFile("windows")}},
		{entry: scan.AutorunEntry{Category: "logon", Name: "l1", File: &scan.FileFacts{Missing: true}}},
		{entry: scan.AutorunEntry{Category: "services", Name: "s1", File: msFile("windows")}},
		{entry: scan.AutorunEntry{Category: "services", Name: "s2"}},
		{entry: scan.AutorunEntry{Category: "browser", Name: "c"}, component: true},
		{entry: scan.AutorunEntry{Category: "browser", Name: "b"}},
		{entry: scan.AutorunEntry{Category: "hijacks", Name: "h", File: msFile("windows")}, hijack: true},
	}
	entries, counts := assemble(items)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name)
	}
	if strings.Join(names, ",") != "l1,h,s2,b" {
		t.Errorf("voci elencate in ordine di categoria: %v", names)
	}
	if counts["services"] != (scan.AutorunCount{Total: 2, Microsoft: 1}) || counts["tasks"] != (scan.AutorunCount{Total: 1, Microsoft: 1}) ||
		counts["browser"] != (scan.AutorunCount{Total: 2}) || counts["hijacks"] != (scan.AutorunCount{Total: 1}) {
		t.Errorf("conteggi: %+v", counts)
	}
	if e, c := assemble(nil); e == nil || len(e) != 0 || len(c) != 0 {
		t.Error("nessuna voce: elenco vuoto, non nil")
	}
}

func TestGather(t *testing.T) {
	var calls atomic.Int32
	facts := func(ctx context.Context, p string) *scan.FileFacts {
		calls.Add(1)
		if strings.HasPrefix(p, "ms:") {
			return msFile("windows")
		}
		return &scan.FileFacts{Path: "verificato " + p}
	}
	plain := func(p string) *scan.FileFacts { return &scan.FileFacts{Path: "solo " + p} }
	sources := []source{
		{"a", func(context.Context) sourceResult {
			return sourceResult{items: []item{{entry: scan.AutorunEntry{Category: "logon", Name: "a"}, file: "ms:a", target: "t"}, {entry: scan.AutorunEntry{Category: "logon"}}}}
		}},
		{"b", func(context.Context) sourceResult {
			time.Sleep(20 * time.Millisecond)
			return sourceResult{items: []item{{entry: scan.AutorunEntry{Category: "tasks"}, file: "f", unverified: true}}, denied: []string{"tasks"}, err: errors.New("parte mancata")}
		}},
	}
	items, denied, errs, partial := gather(context.Background(), sources, facts, plain, 3, time.Second)
	if len(items) != 3 || partial || len(errs) != 1 || len(denied) != 1 || calls.Load() != 2 {
		t.Fatalf("raccolta: %d voci, parziale %v, errori %v, negati %v, verifiche %d", len(items), partial, errs, denied, calls.Load())
	}
	for _, it := range items {
		switch it.entry.Category {
		case "logon":
			if it.file != "" && (!usable(it.entry.File) || it.entry.Target.Path != "verificato t") {
				t.Errorf("fatti: %+v", it.entry)
			}
		case "tasks":
			if it.entry.File == nil || it.entry.File.Path != "solo f" || it.entry.File.Signature != nil {
				t.Errorf("voce non verificabile: %+v", it.entry.File)
			}
		}
	}
	// Una sorgente bloccata: alla scadenza (più il margine) si restituisce
	// il resto, parziale.
	block := make(chan struct{})
	defer close(block)
	slow := []source{
		sources[0],
		{"bloccata", func(context.Context) sourceResult { <-block; return sourceResult{} }},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	items, _, _, partial = gather(ctx, slow, facts, plain, 2, 20*time.Millisecond)
	if !partial || len(items) != 2 || time.Since(start) > 2*time.Second {
		t.Errorf("sorgente bloccata: %d voci, parziale %v, %v", len(items), partial, time.Since(start))
	}
	// Verifica bloccata: le voci ricevono solo il percorso.
	stuck := func(ctx context.Context, p string) *scan.FileFacts { <-block; return nil }
	ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel2()
	items, _, _, partial = gather(ctx2, sources[:1], stuck, plain, 1, 20*time.Millisecond)
	if !partial || items[0].entry.File == nil || items[0].entry.File.Path != "solo ms:a" || items[0].entry.Target.Path != "solo t" {
		t.Errorf("verifica bloccata: %+v %v", items[0].entry, partial)
	}
}

func TestCleaner(t *testing.T) {
	c := cleaner{profile: `C:\Users\anna`, user: "anna"}
	for in, want := range map[string]string{
		`GoogleUpdateTaskUserS-1-5-21-1004336348-1177238915-682003330-1001UA`: `GoogleUpdateTaskUserS-1-5-21-…-1001UA`,
		`Backup di anna`:                     `Backup di ‹utente›`,
		`Backup di Anna e annabella`:         `Backup di ‹utente› e annabella`,
		`Notifica mario.rossi@example.it ok`: `Notifica ‹e-mail› ok`,
		`Iannacone`:                          `Iannacone`,
	} {
		if got := c.text(in); got != want {
			t.Errorf("text(%q) = %q, atteso %q", in, got, want)
		}
	}
	if got := c.path(`"C:\Users\anna\AppData\x.exe" --profile C:\Users\luca\y`); got != `"%USERPROFILE%\AppData\x.exe" --profile C:\Users\‹utente›\y` {
		t.Errorf("path: %q", got)
	}
	// Lettere che cambiano lunghezza in minuscolo prima del percorso: il
	// profilo non deve restare in chiaro.
	if got := c.path("İİ C:\\Users\\anna\\x.exe"); strings.Contains(got, "anna") {
		t.Errorf("profilo dopo İ: %q", got)
	}
	// Nomi troppo corti o comuni non si cercano come parole.
	if (cleaner{user: "pc"}).text("pc di casa") != "pc di casa" || (cleaner{user: "Admin"}).text("Admin tools") != "Admin tools" {
		t.Error("nomi comuni")
	}
}
