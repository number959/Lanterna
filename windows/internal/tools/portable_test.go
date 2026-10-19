package tools

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func zipOf(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, body := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// withPortable sostituisce il catalogo per la durata del test.
func withPortable(t *testing.T, m map[string]Portable) {
	t.Helper()
	orig := Portables
	Portables = m
	t.Cleanup(func() { Portables = orig })
}

func testFetcher(t *testing.T, srv *httptest.Server, verify func(string) (Signature, error)) *Fetcher {
	t.Helper()
	return &Fetcher{
		Root:      t.TempDir(),
		Arch:      "amd64",
		Transport: srv.Client().Transport,
		Verify:    verify,
		Wait:      func(context.Context, time.Duration) error { return nil },
		UserAgent: "STARNET-Polaris/test",
	}
}

func validAs(signer string) func(string) (Signature, error) {
	return func(path string) (Signature, error) {
		if _, err := os.Stat(path); err != nil {
			return Signature{}, err
		}
		return Signature{Status: "Valid", Signer: signer, Version: "1.2.3.0", File: "1.2.3.0"}, nil
	}
}

func TestAllowedURL(t *testing.T) {
	hosts := []string{"download.example.com", ".dl.sourceforge.net"}
	cases := map[string]bool{
		"https://download.example.com/a.zip":            true,
		"https://psychz.dl.sourceforge.net/x.zip":       true,
		"http://download.example.com/a.zip":             false,
		"https://example.com/a.zip":                     false,
		"https://dl.sourceforge.net/x.zip":              false,
		"https://evil-dl.sourceforge.net.example/x.zip": false,
		"https://download.example.com.evil.net/a.zip":   false,
		"https://DOWNLOAD.EXAMPLE.COM/a.zip":            true,
	}
	for raw, ok := range cases {
		u, _ := url.Parse(raw)
		if err := allowedURL(u, hosts); (err == nil) != ok {
			t.Errorf("%s: %v", raw, err)
		}
	}
}

func TestFetchZipFindCheckRemove(t *testing.T) {
	body := zipOf(t, map[string]string{"tool64.exe": "MZ programma", "tool32.exe": "MZ altro", "lang/it.txt": "ciao"})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/files/tool.zip", http.StatusFound)
		case "/files/tool.zip":
			if r.Header.Get("User-Agent") != "STARNET-Polaris/test" {
				http.Error(w, "ua", http.StatusForbidden)
				return
			}
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	withPortable(t, map[string]Portable{
		"cpu-z": {URL: map[string]string{"*": srv.URL + "/start"}, Hosts: []string{"127.0.0.1"}, Zip: true, Exe: map[string]string{"amd64": "tool64.exe", "386": "tool32.exe"}, Signer: "Produttore", MaxMB: 1},
	})
	f := testFetcher(t, srv, validAs("Produttore"))
	var last int64
	d, err := f.Fetch(context.Background(), "cpu-z", func(done, total int64) { last = done })
	if err != nil {
		t.Fatal(err)
	}
	if d.Path != filepath.Join(f.Root, "cpu-z", "tool64.exe") || d.Signer != "Produttore" || d.Version != "1.2.3.0" || last != int64(len(body)) {
		t.Fatalf("scaricato: %+v (progresso %d di %d)", d, last, len(body))
	}
	if b, _ := os.ReadFile(filepath.Join(f.Root, "cpu-z", "lang", "it.txt")); string(b) != "ciao" {
		t.Errorf("file dello zip non estratti: %q", b)
	}
	if left, _ := filepath.Glob(filepath.Join(f.Root, ".cpu-z-*")); len(left) != 0 {
		t.Errorf("cartelle temporanee rimaste: %v", left)
	}
	found := f.Find()
	if g := found["cpu-z"]; g.Path != d.Path || g.Problem != "" || g.Date == "" {
		t.Fatalf("trovato: %+v", g)
	}
	if err := f.Check("cpu-z", d.Path); err != nil {
		t.Errorf("firma attesa: %v", err)
	}
	f.Verify = validAs("Altro editore")
	if err := f.Check("cpu-z", d.Path); err == nil {
		t.Error("firma di un altro editore accettata all'avvio")
	}
	// Il file cambia dopo il download: non si avvia più.
	if err := os.WriteFile(d.Path, []byte("MZ sostituito"), 0o644); err != nil {
		t.Fatal(err)
	}
	if g := f.Find()["cpu-z"]; g.Problem == "" || g.Path != "" {
		t.Fatalf("copia modificata: %+v", g)
	}
	if err := f.Remove("cpu-z"); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Find()["cpu-z"]; ok {
		t.Error("copia non eliminata")
	}
	if err := f.Remove("../altro"); !errors.Is(err, ErrUnknown) {
		t.Errorf("eliminazione fuori catalogo: %v", err)
	}
}

func TestFetchSingleExeWithRetry(t *testing.T) {
	calls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			http.Error(w, "No", http.StatusForbidden) // un mirror che rifiuta
			return
		}
		_, _ = w.Write([]byte("MZ scanner"))
	}))
	defer srv.Close()
	withPortable(t, map[string]Portable{
		"eset-online-scanner": {URL: map[string]string{"*": srv.URL + "/scanner.exe"}, Hosts: []string{"127.0.0.1"}, Exe: map[string]string{"*": "scanner.exe"}, Signer: "ESET", MaxMB: 1},
	})
	f := testFetcher(t, srv, validAs("ESET"))
	d, err := f.Fetch(context.Background(), "eset-online-scanner", nil)
	if err != nil || calls != 2 {
		t.Fatalf("%v dopo %d richieste", err, calls)
	}
	if b, _ := os.ReadFile(d.Path); string(b) != "MZ scanner" {
		t.Errorf("contenuto: %q", b)
	}
}

func TestFetchRejects(t *testing.T) {
	good := zipOf(t, map[string]string{"tool64.exe": "MZ"})
	sum := sha256.Sum256(good)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/fuori":
			http.Redirect(w, r, "https://download.example.invalid/tool.zip", http.StatusFound)
		case "/http":
			http.Redirect(w, r, "http://127.0.0.1/tool.zip", http.StatusFound)
		case "/pagina":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte("<html>Just a moment...</html>"))
		case "/grande":
			_, _ = w.Write(bytes.Repeat([]byte("x"), 2<<20))
		case "/traversal":
			_, _ = w.Write(zipOf(t, map[string]string{"../fuori.exe": "MZ", "tool64.exe": "MZ"}))
		case "/senza-exe":
			_, _ = w.Write(zipOf(t, map[string]string{"altro.exe": "MZ"}))
		default:
			_, _ = w.Write(good)
		}
	}))
	defer srv.Close()
	entry := func(path string) Portable {
		return Portable{URL: map[string]string{"*": srv.URL + path}, Hosts: []string{"127.0.0.1"}, Zip: true, Exe: map[string]string{"*": "tool64.exe"}, Signer: "Produttore", MaxMB: 1}
	}
	pinned := entry("/ok")
	pinned.SHA256 = map[string]string{"*": strings.Repeat("0", 64)}
	pinnedOK := entry("/ok")
	pinnedOK.Signer = ""
	pinnedOK.SHA256 = map[string]string{"*": hex.EncodeToString(sum[:])}
	cases := []struct {
		name   string
		p      Portable
		verify func(string) (Signature, error)
		ok     bool
		is     error
	}{
		{"sito non previsto", entry("/fuori"), validAs("Produttore"), false, ErrHost},
		{"reindirizzamento in chiaro", entry("/http"), validAs("Produttore"), false, ErrHost},
		{"pagina web", entry("/pagina"), validAs("Produttore"), false, nil},
		{"troppo grande", entry("/grande"), validAs("Produttore"), false, ErrTooLarge},
		{"percorso fuori cartella", entry("/traversal"), validAs("Produttore"), false, nil},
		{"eseguibile mancante", entry("/senza-exe"), validAs("Produttore"), false, nil},
		{"firma di altri", entry("/ok"), validAs("Altro"), false, errSignatureMismatch},
		{"firma non valida", entry("/ok"), func(string) (Signature, error) { return Signature{Status: "HashMismatch", Signer: "Produttore"}, nil }, false, errSignatureMismatch},
		{"impronta diversa", pinned, validAs("Produttore"), false, nil},
		{"impronta fissata giusta, senza firma", pinnedOK, nil, true, nil},
	}
	for _, c := range cases {
		withPortable(t, map[string]Portable{"wiztree": c.p})
		f := testFetcher(t, srv, c.verify)
		_, err := f.Fetch(context.Background(), "wiztree", nil)
		if (err == nil) != c.ok || (c.is != nil && !errors.Is(err, c.is)) {
			t.Errorf("%s: %v", c.name, err)
		}
		if !c.ok {
			if _, statErr := os.Stat(filepath.Join(f.Root, "wiztree")); statErr == nil {
				t.Errorf("%s: copia conservata nonostante l'errore", c.name)
			}
		}
		if _, err := os.Stat(filepath.Join(filepath.Dir(f.Root), "fuori.exe")); err == nil {
			t.Errorf("%s: file scritto fuori dalla cartella", c.name)
		}
	}
}

func TestFetchCancel(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000000")
		_, _ = w.Write([]byte("MZ"))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer srv.Close()
	withPortable(t, map[string]Portable{
		"adwcleaner": {URL: map[string]string{"*": srv.URL + "/a.exe"}, Hosts: []string{"127.0.0.1"}, Exe: map[string]string{"*": "a.exe"}, Signer: "X", MaxMB: 2},
	})
	f := testFetcher(t, srv, validAs("X"))
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(150 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	if _, err := f.Fetch(ctx, "adwcleaner", nil); err == nil || !strings.Contains(err.Error(), "interrotto") {
		t.Fatalf("interruzione: %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("interruzione troppo lenta")
	}
}

func TestFindExpiredAndArch(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("MZ msert")) }))
	defer srv.Close()
	withPortable(t, map[string]Portable{
		"safety-scanner": {URL: map[string]string{"*": srv.URL + "/msert.exe"}, Hosts: []string{"127.0.0.1"}, Exe: map[string]string{"*": "msert.exe"}, Signer: "Microsoft Corporation", MaxMB: 1, ExpiresDays: 10},
	})
	f := testFetcher(t, srv, validAs("Microsoft Corporation"))
	day0 := time.Date(2026, 10, 19, 10, 0, 0, 0, time.UTC)
	f.Now = func() time.Time { return day0 }
	if _, err := f.Fetch(context.Background(), "safety-scanner", nil); err != nil {
		t.Fatal(err)
	}
	if d := f.Find()["safety-scanner"]; d.Expired || d.Path == "" {
		t.Fatalf("appena scaricato: %+v", d)
	}
	f.Now = func() time.Time { return day0.Add(11 * 24 * time.Hour) }
	if d := f.Find()["safety-scanner"]; !d.Expired {
		t.Fatalf("dopo 11 giorni: %+v", d)
	}
}

func TestCanFetch(t *testing.T) {
	if err := CanFetch("cpu-z", "amd64"); err != nil {
		t.Errorf("cpu-z: %v", err)
	}
	if err := CanFetch("cpu-z", "arm64"); !errors.Is(err, ErrNoPortable) {
		t.Errorf("cpu-z su ARM: %v", err)
	}
	if err := CanFetch("crystaldiskinfo", "amd64"); !errors.Is(err, ErrNoPortable) {
		t.Errorf("programma senza versione portable: %v", err)
	}
	if err := CanFetch("cmd.exe", "amd64"); !errors.Is(err, ErrUnknown) {
		t.Errorf("sconosciuto: %v", err)
	}
}

func TestParseSignature(t *testing.T) {
	out := "\ufeffAVVISO: qualcosa\r\n{\"status\":\"Valid\",\"signer\":\"REALiX, s.r.o.\",\"version\":\"8.34-5770\",\"file\":\"8.34.0.0\"}\r\n"
	sig, err := ParseSignature([]byte(out))
	if err != nil || sig.Status != "Valid" || sig.Signer != "REALiX, s.r.o." {
		t.Fatalf("%+v %v", sig, err)
	}
	if _, err := ParseSignature([]byte("Get-AuthenticodeSignature : errore")); err == nil {
		t.Error("uscita senza JSON accettata")
	}
	if v := cleanVersion("14.21", "14.21.0.0"); v != "14.21" {
		t.Errorf("versione: %q", v)
	}
	if v := cleanVersion("", "4.27.0.0 (build 1)"); v != "4.27.0.0" {
		t.Errorf("versione dal file: %q", v)
	}
}

// Il catalogo dei download è coerente: indirizzi https verso gli host
// ammessi, un eseguibile per ogni indirizzo, firma o impronta per ciascuno,
// e le stesse informazioni mostrate dall'interfaccia (core/src/tools.ts).
func TestPortableCatalog(t *testing.T) {
	src, err := os.ReadFile("../../../core/src/tools.ts")
	if err != nil {
		t.Fatal(err)
	}
	ts := string(src)
	hexRe := regexp.MustCompile(`^[0-9a-f]{64}$`)
	for id, p := range Portables {
		if _, ok := Programs[id]; !ok {
			t.Errorf("%s: scaricabile ma assente dal catalogo", id)
		}
		if p.MaxMB <= 0 || len(p.URL) == 0 {
			t.Errorf("%s: limiti o indirizzi mancanti", id)
		}
		for key, raw := range p.URL {
			u, err := url.Parse(raw)
			if err != nil || allowedURL(u, p.Hosts) != nil {
				t.Errorf("%s: indirizzo %q fuori dagli host ammessi", id, raw)
			}
			if exe, _ := pick(p.Exe, key); exe == "" && key != "*" {
				t.Errorf("%s: nessun eseguibile per %s", id, key)
			}
			if p.Signer == "" && !hexRe.MatchString(p.SHA256[key]) {
				t.Errorf("%s: né firma né impronta per %s", id, key)
			}
			if h := p.SHA256[key]; h != "" && !hexRe.MatchString(h) {
				t.Errorf("%s: impronta non valida per %s", id, key)
			}
		}
		block := regexp.MustCompile(`id: '` + regexp.QuoteMeta(id) + `',[\s\S]*?portable: \{([^}]*)\}`).FindStringSubmatch(ts)
		if block == nil {
			t.Errorf("%s: tools.ts non descrive la versione portable", id)
			continue
		}
		raw, _ := pick(p.URL, "amd64")
		if raw == "" {
			raw, _ = pick(p.URL, "386")
		}
		u, _ := url.Parse(raw)
		for _, want := range []string{"from: '" + u.Hostname() + "'", "signer: '" + p.Signer + "'"} {
			if !strings.Contains(block[1], want) {
				t.Errorf("%s: in tools.ts manca %s", id, want)
			}
		}
		if p.Version != "" && !strings.Contains(block[1], "version: '"+p.Version+"'") {
			t.Errorf("%s: in tools.ts manca la versione %s", id, p.Version)
		}
	}
	if n := strings.Count(ts, "portable: {"); n != len(Portables) {
		t.Errorf("tools.ts descrive %d versioni portable, l'agente %d", n, len(Portables))
	}
}
