package autoruns

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"lanterna/internal/scan"
	"lanterna/internal/sign"
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
		{"sempre elencata (WMI, controllo programmato)", item{entry: scan.AutorunEntry{File: msFile("windows")}, always: true}, false},
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
	items, denied, errs, partial := gather(context.Background(), sources, facts, plain, nil, 3, time.Second)
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
	items, _, _, partial = gather(ctx, slow, facts, plain, nil, 2, 20*time.Millisecond)
	if !partial || len(items) != 2 || time.Since(start) > 2*time.Second {
		t.Errorf("sorgente bloccata: %d voci, parziale %v, %v", len(items), partial, time.Since(start))
	}
	// Verifica bloccata: le voci ricevono solo il percorso.
	stuck := func(ctx context.Context, p string) *scan.FileFacts { <-block; return nil }
	ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel2()
	items, _, _, partial = gather(ctx2, sources[:1], stuck, plain, nil, 1, 20*time.Millisecond)
	if !partial || items[0].entry.File == nil || items[0].entry.File.Path != "solo ms:a" || items[0].entry.Target.Path != "solo t" {
		t.Errorf("verifica bloccata: %+v %v", items[0].entry, partial)
	}
}

// Osservazione b della CI: alla prima analisi (cache delle firme vuota) si
// verificano prima i file più a rischio, così se il tempo scade restano
// senza verifica quelli di Windows e i suoi driver. Ogni percorso si
// verifica una volta sola; le altre azioni delle attività si verificano.
func TestGatherOrder(t *testing.T) {
	const profile = `C:\Users\anna`
	var mu sync.Mutex
	var calls []string
	facts := func(ctx context.Context, p string) *scan.FileFacts {
		mu.Lock()
		calls = append(calls, p)
		mu.Unlock()
		return &scan.FileFacts{Path: "verificato " + p}
	}
	plain := func(p string) *scan.FileFacts { return &scan.FileFacts{Path: "solo " + p} }
	rank := func(category, p string) int { return checkOrder(category, p, profile) }
	sources := []source{{"tutto", func(context.Context) sourceResult {
		return sourceResult{items: []item{
			{entry: scan.AutorunEntry{Category: "drivers"}, file: `C:\Windows\System32\drivers\a.sys`},
			{entry: scan.AutorunEntry{Category: "services"}, file: `C:\Windows\System32\svc.dll`},
			{entry: scan.AutorunEntry{Category: "services"}, file: `C:\Program Files\Vendor\v.exe`},
			{entry: scan.AutorunEntry{Category: "logon"}, file: `C:\Windows\System32\rundll32.exe`, target: `C:\Users\anna\AppData\Roaming\x.dll`},
			{entry: scan.AutorunEntry{Category: "tasks"}, file: `C:\Windows\System32\rundll32.exe`,
				others: []item{{entry: scan.AutorunEntry{Category: "tasks"}, file: `C:\Users\anna\Downloads\y.exe`}}},
			{entry: scan.AutorunEntry{Category: "drivers"}, file: `C:\Vendor\drv.sys`},
		}}
	}}}
	items, _, _, partial := gather(context.Background(), sources, facts, plain, rank, 1, time.Second)
	if partial {
		t.Fatal("parziale")
	}
	want := []string{
		`C:\Users\anna\AppData\Roaming\x.dll`, `C:\Users\anna\Downloads\y.exe`, `C:\Vendor\drv.sys`,
		`C:\Program Files\Vendor\v.exe`,
		`C:\Windows\System32\svc.dll`, `C:\Windows\System32\rundll32.exe`,
		`C:\Windows\System32\drivers\a.sys`,
	}
	if !reflect.DeepEqual(calls, want) {
		t.Errorf("ordine delle verifiche:\n%q\natteso\n%q", calls, want)
	}
	// rundll32.exe una volta sola, ma i fatti arrivano a tutte e due le voci;
	// l'altra azione dell'attività è verificata.
	if items[3].entry.File.Path != `verificato C:\Windows\System32\rundll32.exe` || items[4].entry.File.Path != items[3].entry.File.Path ||
		items[4].others[0].entry.File.Path != `verificato C:\Users\anna\Downloads\y.exe` {
		t.Errorf("fatti condivisi: %+v %+v", items[3].entry.File, items[4])
	}
	if items[3].entry.File == items[4].entry.File {
		t.Error("le voci condividono lo stesso oggetto dei fatti")
	}
	for c, want := range map[[2]string]int{
		{"logon", `C:\Users\anna\AppData\x.exe`}:         0,
		{"logon", `C:\ProgramData\x.exe`}:                0,
		{"logon", `D:\Strumenti\x.exe`}:                  0,
		{"logon", `\\srv\share\x.exe`}:                   0,
		{"services", `C:\Program Files (x86)\V\x.exe`}:   1,
		{"services", `C:\Windows\System32\x.dll`}:        2,
		{"drivers", `C:\Windows\System32\drivers\x.sys`}: 3,
		{"drivers", `C:\Program Files\V\x.sys`}:          1,
	} {
		if got := checkOrder(c[0], c[1], profile); got != want {
			t.Errorf("checkOrder(%q, %q) = %d, atteso %d", c[0], c[1], got, want)
		}
	}
}

// E14, E15 e G7: fatti senza verifica e file in rete.
func TestPlainAndNetworkFacts(t *testing.T) {
	const profile = `C:\Users\anna`
	clean := cleaner{profile: profile, user: "anna"}.path
	// Il tipo di cartella delle voci non verificate viene da
	// sign.Checker.Folder, che conosce anche il tipo delle unità: qui E: è
	// una chiavetta e Z: un'unità di rete.
	folder := func(p string) string {
		switch strings.ToUpper(p[:2]) {
		case "E:":
			return "removable"
		case "Z:":
			return "network"
		}
		return sign.FolderOf(p, profile)
	}
	plain := func(p string) *scan.FileFacts { return plainFacts(p, folder, clean) }
	if f := plain(`%LOCALAPPDATA%\Vendor\upd.exe`); f.Folder != "" || f.Path != `%LOCALAPPDATA%\Vendor\upd.exe` {
		t.Errorf("percorso con le variabili di un altro utente: %+v", f)
	}
	if f := plain(`C:\Users\anna\AppData\Local\x.exe`); f.Folder != "appData" || f.Path != `%USERPROFILE%\AppData\Local\x.exe` {
		t.Errorf("percorso nel profilo: %+v", f)
	}
	if f := plain(`E:\setup.exe`); f.Folder != "removable" {
		t.Errorf("chiavetta: %+v", f)
	}
	if f := plain(`Z:\Gestionale\agg.exe`); f.Folder != "network" {
		t.Errorf("unità di rete: %+v", f)
	}
	// Un nome senza cartella di un'attività non verificata: cartella non letta.
	if f := plain(`upd.exe`); f.Folder != "" {
		t.Errorf("nome senza cartella: %+v", f)
	}
	// La regola dei file in rete è quella di sign, comune ai processi.
	onNetwork := func(p string) bool { return sign.FolderOf(p, profile) == "network" }
	if !onNetwork(`\\attaccante\share\y.exe`) || !onNetwork(`\\host@SSL\DavWWWRoot\x.dll`) || onNetwork(`C:\x.exe`) {
		t.Error("percorsi di rete")
	}
	if f := sign.New(profile, clean).Facts(context.Background(), `\\srv\share\x.exe`); f.Missing || f.Folder != "network" || f.Signature == nil || f.Signature.Status != "unknown" {
		t.Errorf("file in rete: %+v", f)
	}
	// La forma lunga \\?\UNC\ diventa una condivisione, non un file di Windows.
	r := newFakeEnv().resolver()
	if p := r.Locate(`\\?\UNC\srv\share\x.exe`, false); !onNetwork(p) {
		t.Errorf("\\\\?\\UNC: %q", p)
	}
	// Anche \\.\UNC\ e i redirector raggiunti da GLOBALROOT sono in rete:
	// non si aprono.
	for _, p := range []string{`\\.\UNC\srv\share\x.exe`, `\??\UNC\srv\share\x.exe`, `\\.\GLOBALROOT\Device\Mup\srv\share\x.exe`,
		`\\?\GLOBALROOT\Device\WebDavRedirector\srv\x.dll`, `\??\GLOBALROOT\Device\LanmanRedirector\srv\s\x.dll`} {
		if l := r.Locate(p, false); !onNetwork(l) {
			t.Errorf("%q → %q non è in rete", p, l)
		}
	}
	if onNetwork(`\\?\C:\x.exe`) || onNetwork(`\\.\C:\x.exe`) || onNetwork(r.Locate(`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3\x.exe`, false)) {
		t.Error("percorso locale nella forma lunga preso per rete")
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
		// Attività di OneDrive e di Google per un account Microsoft Entra
		// ID: il SID è per intero l'ID della persona (pulitore comune).
		`OneDrive Standalone Update Task-S-1-12-1-1234567890-2345678901-3456789012-4567890123`: `OneDrive Standalone Update Task-S-1-12-1-…`,
		`OneDrive Reporting Task-S-1-12-1-11-22-33-44`:                                         `OneDrive Reporting Task-S-1-12-1-…`,
		`GoogleUpdateTaskUserS-1-12-1-1234567890-2345678901-3456789012-4567890123Core{X}`:      `GoogleUpdateTaskUserS-1-12-1-…Core{X}`,
		`GoogleUpdateTaskUserS-1-12-1-1-2-3-4UA`:                                               `GoogleUpdateTaskUserS-1-12-1-…UA`,
	} {
		if got := c.text(in); got != want {
			t.Errorf("text(%q) = %q, atteso %q", in, got, want)
		}
	}
	if got := c.path(`"C:\Users\anna\AppData\x.exe" --profile C:\Users\luca\y`); got != `"%USERPROFILE%\AppData\x.exe" --profile C:\Users\‹utente›\y` {
		t.Errorf("path: %q", got)
	}
	// Indirizzi pubblici nei comandi, anche attaccati agli operatori della
	// riga di comando; quelli della rete locale restano.
	for in, want := range map[string]string{
		`cmd.exe /c ping 203.0.113.5>nul & start C:\x\a.exe`: `cmd.exe /c ping ‹indirizzo›>nul & start C:\x\a.exe`,
		`cmd.exe /c ping -n 3 192.168.1.1>nul`:               `cmd.exe /c ping -n 3 192.168.1.1>nul`,
		`"\\203.0.113.5\share\agent.exe" /s`:                 `"\\‹indirizzo›\share\agent.exe" /s`,
	} {
		if got := c.command(in); got != want {
			t.Errorf("command(%q) = %q, atteso %q", in, got, want)
		}
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
