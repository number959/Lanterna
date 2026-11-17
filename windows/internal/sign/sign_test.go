package sign

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"lanterna/internal/pcinfo"
	"lanterna/internal/scan"
)

// fakes sostituisce verifica, informazioni di versione, ora e tipo di unità
// per la durata della prova; calls conta le verifiche.
type fakes struct {
	calls  int
	drives int
	clock  time.Time
}

func useFakes(t *testing.T, sig func(ctx context.Context) *scan.FileSignature, drive map[byte]uint32) *fakes {
	t.Helper()
	f := &fakes{clock: time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC)}
	oldV, oldR, oldN, oldD := verifyFile, readVersion, now, driveType
	t.Cleanup(func() { verifyFile, readVersion, now, driveType = oldV, oldR, oldN, oldD })
	verifyFile = func(ctx context.Context, _ string) *scan.FileSignature { f.calls++; return sig(ctx) }
	readVersion = func(string) (string, string, string) { return "Esempio Srl", "Prova", "1.0" }
	now = func() time.Time { return f.clock }
	driveType = func(root string) uint32 { f.drives++; return drive[root[0]|0x20] }
	return f
}

func tempExe(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "a.exe")
	if err := os.WriteFile(p, []byte("MZ"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, p
}

// Una verifica arrivata in fondo si tiene anche se il tempo è finito nel
// frattempo; una verifica saltata per il tempo no.
func TestFactsCacheCompleteAfterDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := useFakes(t, func(context.Context) *scan.FileSignature {
		cancel() // il tempo finisce durante la verifica
		return &scan.FileSignature{Status: "valid", Signer: "Esempio Srl"}
	}, nil)
	dir, p := tempExe(t)
	c := New(dir, nil)
	if got := c.Facts(ctx, p); got.Signature == nil || got.Signature.Status != "valid" || len(c.cache) != 1 {
		t.Fatalf("verifica completa scartata: %+v, cache %d", got, len(c.cache))
	}
	if got := c.Facts(context.Background(), p); f.calls != 1 || got.Signature == nil || got.Company != "Esempio Srl" {
		t.Fatalf("la seconda lettura rifà la verifica: %d verifiche, %+v", f.calls, got)
	}

	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	useFakes(t, func(context.Context) *scan.FileSignature { cancel2(); return nil }, nil)
	c2 := New(dir, nil)
	if got := c2.Facts(ctx2, p); got.Signature != nil || len(c2.cache) != 0 {
		t.Fatalf("verifica saltata messa in cache: %+v, cache %d", got, len(c2.cache))
	}
}

// Gli esiti transitori (file in uso, cataloghi non consultabili) si
// riprovano dopo transientTTL; gli altri restano finché il file non cambia.
func TestFactsTransientExpire(t *testing.T) {
	for _, c := range []struct {
		sig   scan.FileSignature
		retry bool
	}{
		{scan.FileSignature{Status: "unreadable", Code: "0x80070020"}, true},
		{scan.FileSignature{Status: "unknown", Code: "0x800706BA"}, true},
		{scan.FileSignature{Status: "unknown", Catalog: true, Code: "0x80070057"}, true},
		{scan.FileSignature{Status: "unknown", Code: "0x800B0100"}, false}, // app dello Store
		{scan.FileSignature{Status: "unsigned", Code: "0x800B0100"}, false},
		{scan.FileSignature{Status: "valid", Signer: "Esempio Srl"}, false},
	} {
		sig := c.sig
		f := useFakes(t, func(context.Context) *scan.FileSignature { s := sig; return &s }, nil)
		dir, p := tempExe(t)
		ch := New(dir, nil)
		ch.Facts(context.Background(), p)
		f.clock = f.clock.Add(transientTTL - time.Second)
		ch.Facts(context.Background(), p)
		if f.calls != 1 {
			t.Errorf("%+v: riverificato prima della scadenza (%d)", sig, f.calls)
		}
		f.clock = f.clock.Add(2 * time.Second)
		ch.Facts(context.Background(), p)
		if want := map[bool]int{true: 2, false: 1}[c.retry]; f.calls != want {
			t.Errorf("%+v: %d verifiche dopo la scadenza, attese %d", sig, f.calls, want)
		}
	}
}

// A tempo scaduto Facts non tocca il disco (os.Stat, tipo di unità): dà solo
// percorso e cartella.
func TestFactsExpiredNoDisk(t *testing.T) {
	f := useFakes(t, func(context.Context) *scan.FileSignature { return nil }, map[byte]uint32{'z': driveRemote})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := New(`C:\Users\anna`, nil)
	got := c.Facts(ctx, `Z:\Gestionale\manca.exe`)
	if got.Missing || got.Signature != nil || got.Folder != "other" || got.Path != `Z:\Gestionale\manca.exe` || f.drives != 0 || f.calls != 0 {
		t.Fatalf("tempo scaduto: %+v, %d letture del tipo di unità", got, f.drives)
	}
}

// Le lettere di unità rimovibili e di rete sono cartelle che l'utente può
// scrivere, come le condivisioni \\server. I file in rete non si aprono:
// fuori da Windows os.Stat su questi percorsi direbbe «mancante», e qui non
// lo deve dire nessuno di loro.
func TestFactsDriveFolder(t *testing.T) {
	f := useFakes(t, func(context.Context) *scan.FileSignature { return nil }, map[byte]uint32{'z': driveRemote, 'e': driveRemovable, 'd': 3})
	c := New(`C:\Users\anna`, nil)
	for p, want := range map[string]string{
		`Z:\Gestionale\app.exe`:  "network",
		`z:/Gestionale/b.exe`:    "network",
		`\\?\E:\setup.exe`:       "removable",
		`D:\Giochi\gioco.exe`:    "other",
		`\\server\share\app.exe`: "network",
	} {
		got := c.Facts(context.Background(), p)
		net := want == "network"
		if got.Folder != want || got.Missing == net || net != (got.Signature != nil && got.Signature.Status == "unknown") {
			t.Errorf("Facts(%q): cartella %q, attesa %q (%+v)", p, got.Folder, want, got)
		}
	}
	if f.drives != 3 {
		t.Errorf("letture del tipo di unità: %d, attese 3 (una per lettera)", f.drives)
	}
	f.clock = f.clock.Add(driveTTL)
	c.Facts(context.Background(), `Z:\x.exe`)
	if f.drives != 4 {
		t.Errorf("tipo di unità non riletto dopo driveTTL: %d", f.drives)
	}
	// Folder, per le voci senza verifica: lo stesso tipo di cartella.
	if c.Folder(`E:\x.exe`) != "removable" || c.Folder(`C:\Users\anna\Downloads\x.exe`) != "downloads" || c.Folder(`D:\x.exe`) != "other" {
		t.Error("Folder")
	}
	for in, want := range map[uint32]string{0: "", 1: "", driveRemovable: "removable", 3: "", driveRemote: "network", 5: "", 6: ""} {
		if driveFolderOf(in) != want {
			t.Errorf("driveFolderOf(%d) != %q", in, want)
		}
	}
	for in, want := range map[string]byte{`C:\x`: 'c', `d:/x`: 'd', `\\?\E:\x`: 'e', `\\.\Z:\x`: 'z', `//./z:/x`: 'z', `\\server\x`: 0, `C:x`: 0, `1:\x`: 0, ``: 0} {
		if got, ok := driveLetter(in); got != want || ok != (want != 0) {
			t.Errorf("driveLetter(%q) = %q %v", in, got, ok)
		}
	}
}

// Processi e avvio automatico: un file in rete, in qualsiasi forma, non si
// apre (né os.Stat né WinVerifyTrust né le informazioni di versione), anche
// a tempo scaduto e anche quando esiste davvero: firma non verificabile,
// cartella di rete, mai «mancante».
func TestFactsNetworkNoRead(t *testing.T) {
	f := useFakes(t, func(context.Context) *scan.FileSignature {
		return &scan.FileSignature{Status: "valid", Signer: "Esempio Srl"}
	}, map[byte]uint32{'z': driveRemote})
	expired, cancel := context.WithCancel(context.Background())
	cancel()
	c := New(`C:\Users\anna`, func(p string) string { return "pulito:" + p })
	for _, p := range []string{
		`\\srv\share\x.exe`,
		`\\srv@SSL\DavWWWRoot\x.exe`,
		`\\?\UNC\srv\share\x.exe`,
		`\\.\UNC\srv\share\x.exe`,
		`\\?\GLOBALROOT\Device\Mup\srv\share\x.exe`,
		`\\?\GLOBALROOT\Device\LanmanRedirector\srv\share\x.exe`,
		`\\.\GLOBALROOT\Device\WebDavRedirector\srv\x.dll`,
		`Z:\Gestionale\app.exe`,
		`\\.\Z:\Gestionale\app.exe`,
	} {
		for _, ctx := range []context.Context{context.Background(), expired} {
			got := c.Facts(ctx, p)
			if ctx == expired && strings.Contains(p, "Z:") {
				// A tempo scaduto il tipo dell'unità non si legge (TestFactsExpiredNoDisk).
				continue
			}
			if got.Folder != "network" || got.Missing || got.Signature == nil || got.Signature.Status != "unknown" || got.Company != "" || got.Path != "pulito:"+p {
				t.Errorf("Facts(%q): %+v", p, got)
			}
		}
	}
	if f.calls != 0 || len(c.cache) != 0 {
		t.Errorf("file in rete verificati: %d verifiche, cache %d", f.calls, len(c.cache))
	}
	// Un file vero sul disco locale si verifica ancora.
	dir, p := tempExe(t)
	if got := New(dir, nil).Facts(context.Background(), p); got.Signature == nil || got.Signature.Status != "valid" || f.calls != 1 {
		t.Errorf("file locale: %+v", got)
	}
}

// Il Checker comune pulisce i percorsi con il pulitore di pcinfo: niente
// nome dell'utente nelle cartelle reindirizzate su un server o fuori da
// C:\Users, niente SID nel Cestino.
func TestSharedCleaner(t *testing.T) {
	c := newShared(pcinfo.Cleaner{Profile: `C:\Users\mario.rossi`, User: "mario.rossi"})
	for _, p := range []string{
		`\\srv\home$\mario.rossi\Desktop\x.exe`,
		`D:\mario.rossi\x.exe`,
		`C:\Users\mario.rossi\AppData\Local\x.exe`,
		`C:\$Recycle.Bin\S-1-5-21-1111-2222-3333-1001\$RAB12CD.exe`,
	} {
		got := c.Facts(context.Background(), p)
		if strings.Contains(strings.ToLower(got.Path), "mario.rossi") || strings.Contains(got.Path, "1111-2222") {
			t.Errorf("Facts(%q).Path = %q", p, got.Path)
		}
	}
	if c.Profile != `C:\Users\mario.rossi` || c.Facts(context.Background(), `C:\Users\mario.rossi\Downloads\x.exe`).Folder != "downloads" {
		t.Error("profilo del Checker comune")
	}
}

// I contesti dei cataloghi si riusano, mai da due goroutine insieme, e si
// chiudono: dopo un errore, oltre il numero tenuto, quando sono vecchi e
// quando restano fermi.
func TestCatPool(t *testing.T) {
	oldN := now
	t.Cleanup(func() { now = oldN })
	clock := time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC)
	var cmu sync.Mutex
	now = func() time.Time { cmu.Lock(); defer cmu.Unlock(); return clock }
	advance := func(d time.Duration) { cmu.Lock(); clock = clock.Add(d); cmu.Unlock() }

	var mu sync.Mutex
	next := uintptr(0)
	open := map[uintptr]bool{}
	busy := map[uintptr]bool{}
	fail := false
	p := newCatPool(func(alg string) (uintptr, uint32) {
		mu.Lock()
		defer mu.Unlock()
		if fail {
			return 0, 0x80070005
		}
		next++
		open[next] = true
		return next, 0
	}, func(h uintptr) {
		mu.Lock()
		defer mu.Unlock()
		if !open[h] {
			t.Errorf("contesto %d chiuso due volte o mai aperto", h)
		}
		delete(open, h)
	})
	p.idle = time.Hour // il timer vero non scatta durante la prova: sweep si chiama a mano

	// Tante goroutine insieme: ogni contesto in uso da una sola.
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				c, f := p.get("SHA256")
				if c == nil {
					t.Errorf("contesto non aperto: %#x", f)
					return
				}
				mu.Lock()
				if busy[c.h] {
					t.Errorf("contesto %d usato da due goroutine", c.h)
				}
				busy[c.h] = true
				mu.Unlock()
				time.Sleep(10 * time.Microsecond)
				mu.Lock()
				busy[c.h] = false
				mu.Unlock()
				p.put(c, true)
			}
		}()
	}
	wg.Wait()
	mu.Lock()
	opened, still := int(next), len(open)
	mu.Unlock()
	if still > catKeep || len(p.free["SHA256"]) != still {
		t.Fatalf("contesti aperti %d, liberi %d (al massimo %d)", still, len(p.free["SHA256"]), catKeep)
	}
	if opened >= 16*50 {
		t.Fatalf("nessun riuso: %d contesti aperti per %d verifiche", opened, 16*50)
	}

	// Riuso dello stesso contesto; dopo un errore si chiude.
	c1, _ := p.get("SHA1")
	p.put(c1, true)
	c2, _ := p.get("SHA1")
	if c2 != c1 {
		t.Fatal("contesto libero non riusato")
	}
	p.put(c2, false)
	mu.Lock()
	if open[c2.h] {
		t.Fatal("contesto dopo un errore non chiuso")
	}
	mu.Unlock()

	// Vecchio: non si riusa e si chiude.
	c3, _ := p.get("SHA1")
	p.put(c3, true)
	advance(catMaxAge)
	if c4, _ := p.get("SHA1"); c4 == c3 {
		t.Fatal("contesto oltre catMaxAge riusato")
	} else {
		p.put(c4, true)
	}
	mu.Lock()
	if open[c3.h] {
		t.Fatal("contesto vecchio non chiuso")
	}
	mu.Unlock()

	// Fermi da idle: sweep li chiude tutti.
	advance(p.idle)
	p.sweep()
	mu.Lock()
	left := len(open)
	mu.Unlock()
	if left != 0 || len(p.free["SHA256"])+len(p.free["SHA1"]) != 0 {
		t.Fatalf("contesti fermi ancora aperti: %d", left)
	}

	// Cataloghi non consultabili: nessun contesto e il codice d'errore.
	mu.Lock()
	fail = true
	mu.Unlock()
	if c, f := p.get("SHA256"); c != nil || f != 0x80070005 {
		t.Fatalf("apertura non riuscita: %+v %#x", c, f)
	}
	p.put(nil, true)
}

func TestFolderOf(t *testing.T) {
	for _, k := range []string{"SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData", "TEMP", "TMP", "USERPROFILE"} {
		t.Setenv(k, "")
	}
	t.Setenv("SystemRoot", `C:\Windows`)
	t.Setenv("ProgramFiles", `C:\Program Files`)
	t.Setenv("ProgramFiles(x86)", `C:\Program Files (x86)`)
	t.Setenv("ProgramData", `C:\ProgramData`)
	t.Setenv("TEMP", `C:\Users\anna\AppData\Local\Temp`)
	prof := `C:\Users\anna`
	for path, want := range map[string]string{
		`C:\Windows\System32\svchost.exe`:                       "windows",
		`c:\windows\explorer.exe`:                               "windows",
		`C:\Program Files\Google\Chrome\Application\chrome.exe`: "programFiles",
		`C:\Program Files (x86)\Steam\steam.exe`:                "programFiles",
		`C:\ProgramData\Vendor\agent.exe`:                       "programData",
		`C:\Users\anna\AppData\Local\Temp\x\setup.exe`:          "temp",
		`C:\Windows\Temp\upd.exe`:                               "temp",
		`C:\Users\anna\Downloads\tool.exe`:                      "downloads",
		`C:\Users\anna\AppData\Roaming\App\app.exe`:             "appData",
		`C:\Users\anna\Desktop\a.exe`:                           "profile",
		`C:\Users\marco\AppData\Local\Prog\p.exe`:               "appData",
		`C:\Users\marco\Downloads\d.exe`:                        "downloads",
		`\\server\share\tool.exe`:                               "network",
		`\\?\C:\Windows\System32\drivers\x.sys`:                 "windows",
		`D:\Giochi\gioco.exe`:                                   "other",
		`C:\Windowsxyz\a.exe`:                                   "other",
		// Sottocartelle di Windows in cui ogni utente può scrivere.
		`C:\Windows\Tasks\x.exe`:                             "other",
		`C:\Windows\Tracing\x.exe`:                           "other",
		`C:\Windows\System32\spool\drivers\color\x.exe`:      "other",
		`C:\Windows\System32\spool\drivers\x64\3\driver.dll`: "windows",
		`C:\Windows\TasksX\a.exe`:                            "windows",
		// Condivisioni di rete in tutte le forme che l'avvio automatico
		// riconosce (forme lunghe, redirector, WebDAV); le copie shadow e i
		// volumi locali scritti per esteso no.
		`\\?\UNC\server\share\x.exe`:                            "network",
		`\\.\UNC\server\share\x.exe`:                            "network",
		`\??\UNC\server\share\x.exe`:                            "network",
		`\\?\GLOBALROOT\Device\Mup\server\share\x.exe`:          "network",
		`\\?\GLOBALROOT\Device\LanmanRedirector\srv\s\x.exe`:    "network",
		`\\.\GLOBALROOT\Device\WebDavRedirector\srv\x.dll`:      "network",
		`\\?\GLOBALROOT\??\UNC\server\share\x.exe`:              "network",
		`\Device\Mup\server\share\x.exe`:                        "network",
		`\\server@SSL\DavWWWRoot\x.exe`:                         "network",
		`//server/share/x.exe`:                                  "network",
		`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\x.exe`: "other",
		`\\?\GLOBALROOT\Device\MupX\server\x.exe`:               "other",
		`\Device\HarddiskVolume3\Windows\x.exe`:                 "other",
		`\\.\C:\x.exe`:                                          "other",
	} {
		if got := FolderOf(path, prof); got != want {
			t.Errorf("FolderOf(%q) = %q, atteso %q", path, got, want)
		}
	}
	if FolderOf("", prof) != "" {
		t.Error("percorso vuoto")
	}
	// Protette solo Windows e Programmi: in ProgramData e nelle cartelle
	// create alla radice di un'unità un utente può scrivere.
	for f, w := range map[string]bool{"appData": true, "temp": true, "downloads": true, "profile": true, "removable": true, "network": true,
		"programData": true, "other": true, "windows": false, "programFiles": false, "": false} {
		if UserWritable(f) != w {
			t.Errorf("UserWritable(%q) != %v", f, w)
		}
	}
}

func TestFactsMissingAndCache(t *testing.T) {
	dir := t.TempDir()
	c := New(dir, func(p string) string { return "S:" + filepath.Base(p) })
	f := c.Facts(context.Background(), filepath.Join(dir, "manca.exe"))
	if !f.Missing || f.Path != "S:manca.exe" {
		t.Fatalf("file mancante: %+v", f)
	}
	p := filepath.Join(dir, "c.exe")
	if err := os.WriteFile(p, []byte("MZ"), 0o644); err != nil {
		t.Fatal(err)
	}
	a := c.Facts(context.Background(), p)
	b := c.Facts(context.Background(), p)
	if a.Missing || b.Missing || a.Path != b.Path || len(c.cache) != 1 {
		t.Fatalf("cache: %+v %+v %d", a, b, len(c.cache))
	}
	if !IsMicrosoft(&scan.FileSignature{Status: "valid", Signer: "Microsoft Windows", Microsoft: true}) || IsMicrosoft(&scan.FileSignature{Status: "unsigned", Microsoft: true}) || IsMicrosoft(nil) || IsMicrosoft(&scan.FileSignature{Status: "valid", Signer: "Microsoft Windows Hardware Compatibility Publisher"}) {
		t.Error("IsMicrosoft")
	}
}
