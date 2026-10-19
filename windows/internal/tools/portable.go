package tools

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Portable è un programma che Polaris scarica, solo su richiesta, dal sito
// ufficiale del produttore: la versione portable, che non si installa. Non
// viene ridistribuito con Polaris: lo scarica il PC dell'utente, come farebbe
// il browser, e l'uso resta soggetto alla licenza del produttore.
type Portable struct {
	// URL per architettura (GOARCH); "*" vale per tutte le altre.
	URL map[string]string
	// Hosts sono i soli siti ammessi, anche dopo i reindirizzamenti: il nome
	// esatto o, se inizia con un punto, un suo sottodominio.
	Hosts []string
	Zip   bool
	// Exe è il programma da avviare per architettura: il nome dentro lo zip
	// o quello con cui si salva il file scaricato.
	Exe map[string]string
	// Signer è il nome (CN) del certificato con cui il produttore firma
	// l'eseguibile: Polaris lo avvia solo se la firma è valida e di quel nome.
	Signer string
	// SHA256 fissa l'impronta del file scaricato, per architettura come URL,
	// quando l'indirizzo indica una versione precisa; senza, l'indirizzo dà
	// sempre l'ultima versione pubblicata e conta la firma.
	SHA256  map[string]string
	Version string
	MaxMB   int64
	// ExpiresDays: giorni dopo i quali il programma smette di funzionare e va
	// riscaricato (Microsoft Safety Scanner).
	ExpiresDays int
}

var sourceForge = []string{"downloads.sourceforge.net", ".dl.sourceforge.net"}

// Portables sono i programmi che si possono scaricare. Indirizzi, firmatari e
// impronte verificati il 19 ottobre 2026 sui file pubblicati dai produttori.
var Portables = map[string]Portable{
	"cpu-z": {
		URL:   map[string]string{"amd64": "https://download.cpuid.com/cpu-z/cpu-z_3.01-en.zip", "386": "https://download.cpuid.com/cpu-z/cpu-z_3.01-en.zip"},
		Hosts: []string{"download.cpuid.com"}, Zip: true,
		Exe:    map[string]string{"amd64": "cpuz_x64.exe", "386": "cpuz_x32.exe"},
		Signer: "CPUID", Version: "3.01", MaxMB: 20,
		SHA256: map[string]string{"amd64": "8ae3b45d43d97e6ce19535c045cd1e5394c7a3a5334dc01f63edd760ace40827", "386": "8ae3b45d43d97e6ce19535c045cd1e5394c7a3a5334dc01f63edd760ace40827"},
	},
	"hwinfo": {
		URL:   map[string]string{"*": "https://downloads.sourceforge.net/project/hwinfo/Windows_Portable/hwi_834.zip"},
		Hosts: sourceForge, Zip: true,
		Exe:    map[string]string{"amd64": "HWiNFO64.exe", "arm64": "HWiNFO_ARM64.exe", "386": "HWiNFO32.exe"},
		Signer: "REALiX, s.r.o.", Version: "8.34", MaxMB: 40,
		SHA256: map[string]string{"*": "42ee4be4d90be1e297228893dbc049a87daf99f3eb26f0a2ab0b7b666f45c85e"},
	},
	"autoruns": {
		URL:   map[string]string{"*": "https://download.sysinternals.com/files/Autoruns.zip"},
		Hosts: []string{"download.sysinternals.com"}, Zip: true,
		Exe:    map[string]string{"amd64": "Autoruns64.exe", "arm64": "Autoruns64a.exe", "386": "Autoruns.exe"},
		Signer: "Microsoft Corporation", MaxMB: 20,
	},
	"process-explorer": {
		URL:   map[string]string{"*": "https://download.sysinternals.com/files/ProcessExplorer.zip"},
		Hosts: []string{"download.sysinternals.com"}, Zip: true,
		Exe:    map[string]string{"amd64": "procexp64.exe", "arm64": "procexp64a.exe", "386": "procexp.exe"},
		Signer: "Microsoft Corporation", MaxMB: 20,
	},
	"adwcleaner": {
		URL:    map[string]string{"*": "https://downloads.malwarebytes.com/file/adwcleaner"},
		Hosts:  []string{"downloads.malwarebytes.com", "adwcleaner.malwarebytes.com"},
		Exe:    map[string]string{"*": "adwcleaner.exe"},
		Signer: "Malwarebytes Inc", MaxMB: 40,
	},
	"safety-scanner": {
		// Non esiste per ARM: su Windows 11 per ARM gira la versione x64 emulata.
		URL:    map[string]string{"amd64": "https://go.microsoft.com/fwlink/?LinkId=212732", "arm64": "https://go.microsoft.com/fwlink/?LinkId=212732", "386": "https://go.microsoft.com/fwlink/?LinkId=212733"},
		Hosts:  []string{"go.microsoft.com", "definitionupdates.microsoft.com"},
		Exe:    map[string]string{"*": "msert.exe"},
		Signer: "Microsoft Corporation", MaxMB: 400, ExpiresDays: 10,
	},
	"eset-online-scanner": {
		URL:    map[string]string{"*": "https://download.eset.com/com/eset/tools/online_scanner/latest/esetonlinescanner.exe"},
		Hosts:  []string{"download.eset.com"},
		Exe:    map[string]string{"*": "esetonlinescanner.exe"},
		Signer: "ESET, spol. s r.o.", MaxMB: 40,
	},
	"wiztree": {
		URL:   map[string]string{"amd64": "https://diskanalyzer.com/files/wiztree_4_33_portable.zip", "386": "https://diskanalyzer.com/files/wiztree_4_33_portable.zip"},
		Hosts: []string{"diskanalyzer.com", "antibodysoftware-17031.kxcdn.com"}, Zip: true,
		Exe:    map[string]string{"amd64": "WizTree64.exe", "386": "WizTree.exe"},
		Signer: "Antibody Software Limited", Version: "4.33", MaxMB: 40,
		SHA256: map[string]string{"amd64": "38b30aab08710613d8a06a7d3dfb777e43ed436cfd7d1ff8bd33d0b5b6bd2c6d", "386": "38b30aab08710613d8a06a7d3dfb777e43ed436cfd7d1ff8bd33d0b5b6bd2c6d"},
	},
}

// Downloaded è una versione portable già scaricata. Come per le copie
// incluse, Problem spiega perché non si avvia e Path resta vuoto.
type Downloaded struct {
	Version string `json:"version,omitempty"`
	Signer  string `json:"signer,omitempty"`
	Date    string `json:"date,omitempty"` // giorno del download (AAAA-MM-GG)
	Expired bool   `json:"expired,omitempty"`
	Problem string `json:"problem,omitempty"`
	Path    string `json:"-"`
}

// Signature è l'esito della verifica di Windows su un eseguibile firmato.
type Signature struct {
	Status  string `json:"status"` // "Valid" se la firma è integra e attendibile
	Signer  string `json:"signer"`
	Version string `json:"version"`
	File    string `json:"file"`
}

var (
	ErrNoPortable        = errors.New("per questo programma non c'è una versione portable da scaricare su questo PC: aprilo dal sito ufficiale")
	ErrHost              = errors.New("il download è passato da un sito non previsto ed è stato interrotto")
	ErrTooLarge          = errors.New("il file scaricato è più grande del previsto ed è stato scartato")
	ErrDownloadModified  = errors.New("la copia scaricata risulta modificata o sostituita: per sicurezza non viene avviata. Eliminala e riscaricala")
	errSignatureMismatch = errors.New("firma digitale non valida o di un altro editore")
)

const manifestName = "polaris.json"

type manifest struct {
	Version string `json:"version,omitempty"`
	Signer  string `json:"signer,omitempty"`
	Exe     string `json:"exe"`
	SHA256  string `json:"sha256"`
	URL     string `json:"url"`
	Date    string `json:"date"`
}

// pick sceglie il valore per l'architettura, o quello valido per tutte.
func pick(m map[string]string, arch string) (string, string) {
	if v, ok := m[arch]; ok {
		return v, arch
	}
	if v, ok := m["*"]; ok {
		return v, "*"
	}
	return "", ""
}

// CanFetch dice se il programma ha una versione portable per l'architettura.
func CanFetch(id, arch string) error {
	p, ok := Portables[id]
	if !ok {
		if _, known := Programs[id]; known {
			return ErrNoPortable
		}
		return ErrUnknown
	}
	if u, _ := pick(p.URL, arch); u == "" {
		return ErrNoPortable
	}
	if exe, _ := pick(p.Exe, arch); exe == "" {
		return ErrNoPortable
	}
	return nil
}

// allowedURL accetta solo https verso gli host del programma.
func allowedURL(u *url.URL, hosts []string) error {
	if u.Scheme != "https" {
		return fmt.Errorf("%w (indirizzo non https)", ErrHost)
	}
	h := strings.ToLower(u.Hostname())
	for _, a := range hosts {
		if strings.HasPrefix(a, ".") && strings.HasSuffix(h, a) || h == a {
			return nil
		}
	}
	return fmt.Errorf("%w (%s)", ErrHost, h)
}

// Fetcher scarica, verifica e conserva le versioni portable.
type Fetcher struct {
	Root      string // cartella dei programmi scaricati
	Arch      string
	Transport http.RoundTripper
	// Verify chiede a Windows firma e versione di un eseguibile.
	Verify    func(path string) (Signature, error)
	Now       func() time.Time
	UserAgent string
	// Wait è la pausa tra un tentativo e il successivo (i mirror di
	// SourceForge a volte rifiutano: il tentativo dopo ne sceglie un altro).
	Wait func(ctx context.Context, d time.Duration) error
}

// NewFetcher prepara i download nella cartella dei dati di Polaris
// (%LOCALAPPDATA%\STARNET Polaris\strumenti su Windows), passando dal proxy
// indicato come farebbe il browser.
func NewFetcher(userAgent string, proxy func(*http.Request) (*url.URL, error)) *Fetcher {
	base, err := os.UserCacheDir()
	if err != nil {
		base = os.TempDir()
	}
	return &Fetcher{
		Root:      filepath.Join(base, "STARNET Polaris", "strumenti"),
		Arch:      runtime.GOARCH,
		Transport: &http.Transport{Proxy: proxy, TLSHandshakeTimeout: 20 * time.Second, ResponseHeaderTimeout: time.Minute, IdleConnTimeout: 30 * time.Second},
		Verify:    defaultVerify,
		UserAgent: userAgent,
	}
}

func (f *Fetcher) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

// Find elenca le versioni portable già scaricate per questa architettura e
// controlla che l'eseguibile sia quello verificato al momento del download.
func (f *Fetcher) Find() map[string]Downloaded {
	out := map[string]Downloaded{}
	for id, p := range Portables {
		dir := filepath.Join(f.Root, id)
		b, err := os.ReadFile(filepath.Join(dir, manifestName))
		if err != nil {
			continue
		}
		var m manifest
		exe, _ := pick(p.Exe, f.Arch)
		if json.Unmarshal(b, &m) != nil || exe == "" || !strings.EqualFold(m.Exe, exe) {
			out[id] = Downloaded{Problem: "copia scaricata incompleta o per un'altra architettura: eliminala e riscaricala"}
			continue
		}
		d := Downloaded{Version: m.Version, Signer: m.Signer}
		if t, err := time.Parse(time.RFC3339, m.Date); err == nil {
			d.Date = t.Local().Format("2006-01-02")
			d.Expired = p.ExpiresDays > 0 && f.now().Sub(t) > time.Duration(p.ExpiresDays)*24*time.Hour
		}
		path := filepath.Join(dir, exe)
		if sum, err := fileSHA256(path); err != nil || sum != m.SHA256 {
			d.Problem = "il file è stato modificato o sostituito dopo il download: per sicurezza Polaris non lo avvia"
		} else {
			d.Path = path
		}
		out[id] = d
	}
	return out
}

// Check verifica la firma di una copia scaricata subito prima di avviarla.
func (f *Fetcher) Check(id, path string) error {
	p, ok := Portables[id]
	if !ok {
		return ErrUnknown
	}
	if p.Signer == "" {
		return nil
	}
	if f.Verify == nil {
		return errors.New("verifica della firma non disponibile su questo sistema")
	}
	sig, err := f.Verify(path)
	if err != nil {
		return fmt.Errorf("verifica della firma non riuscita: %w", err)
	}
	if sig.Status != "Valid" || sig.Signer != p.Signer {
		return fmt.Errorf("%w: atteso %q, trovato %q (%s)", errSignatureMismatch, p.Signer, sig.Signer, sig.Status)
	}
	return nil
}

// Remove elimina la copia scaricata di un programma.
func (f *Fetcher) Remove(id string) error {
	if _, ok := Portables[id]; !ok {
		return ErrUnknown
	}
	if err := os.RemoveAll(filepath.Join(f.Root, id)); err != nil {
		return fmt.Errorf("copia non eliminata (il programma è ancora aperto?): %w", err)
	}
	return nil
}

// Fetch scarica la versione portable dal sito ufficiale, la estrae, ne
// verifica impronta o firma e la sostituisce alla copia precedente.
// progress riceve i byte scaricati e il totale (-1 se non dichiarato).
func (f *Fetcher) Fetch(ctx context.Context, id string, progress func(done, total int64)) (Downloaded, error) {
	if err := CanFetch(id, f.Arch); err != nil {
		return Downloaded{}, err
	}
	p := Portables[id]
	rawURL, key := pick(p.URL, f.Arch)
	exe, _ := pick(p.Exe, f.Arch)
	if err := os.MkdirAll(f.Root, 0o755); err != nil {
		return Downloaded{}, err
	}
	tmp, err := os.MkdirTemp(f.Root, "."+id+"-")
	if err != nil {
		return Downloaded{}, err
	}
	defer os.RemoveAll(tmp)

	file := filepath.Join(tmp, "download")
	sum, err := f.download(ctx, p, rawURL, file, progress)
	if err != nil {
		return Downloaded{}, err
	}
	if want := p.SHA256[key]; want != "" && sum != want {
		return Downloaded{}, fmt.Errorf("l'impronta del file scaricato non è quella della versione verificata (%s): il produttore potrebbe averlo cambiato. Aprilo dal sito ufficiale", p.Version)
	}
	files := filepath.Join(tmp, "files")
	if err := os.MkdirAll(files, 0o755); err != nil {
		return Downloaded{}, err
	}
	if p.Zip {
		if err := extractZip(file, files, 6*p.MaxMB<<20); err != nil {
			return Downloaded{}, err
		}
	} else if err := os.Rename(file, filepath.Join(files, exe)); err != nil {
		return Downloaded{}, err
	}
	path := filepath.Join(files, exe)
	if st, err := os.Stat(path); err != nil || !st.Mode().IsRegular() {
		return Downloaded{}, fmt.Errorf("nel file scaricato manca %s", exe)
	}

	m := manifest{Version: p.Version, Exe: exe, URL: rawURL, Date: f.now().UTC().Format(time.RFC3339)}
	if p.Signer != "" {
		if f.Verify == nil {
			return Downloaded{}, errors.New("verifica della firma non disponibile su questo sistema")
		}
		sig, err := f.Verify(path)
		if err != nil {
			return Downloaded{}, fmt.Errorf("verifica della firma non riuscita: %w", err)
		}
		if sig.Status != "Valid" || sig.Signer != p.Signer {
			return Downloaded{}, fmt.Errorf("%w: atteso %q, trovato %q (%s). Il file è stato scartato", errSignatureMismatch, p.Signer, sig.Signer, sig.Status)
		}
		m.Signer = sig.Signer
		if m.Version == "" {
			m.Version = cleanVersion(sig.Version, sig.File)
		}
	}
	if m.SHA256, err = fileSHA256(path); err != nil {
		return Downloaded{}, err
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(filepath.Join(files, manifestName), b, 0o644); err != nil {
		return Downloaded{}, err
	}
	final := filepath.Join(f.Root, id)
	if err := os.RemoveAll(final); err != nil {
		return Downloaded{}, fmt.Errorf("copia precedente non sostituita (il programma è ancora aperto?): %w", err)
	}
	if err := os.Rename(files, final); err != nil {
		return Downloaded{}, err
	}
	return Downloaded{Version: m.Version, Signer: m.Signer, Date: f.now().Format("2006-01-02"), Path: filepath.Join(final, exe)}, nil
}

func (f *Fetcher) download(ctx context.Context, p Portable, rawURL, dest string, progress func(done, total int64)) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if err := allowedURL(u, p.Hosts); err != nil {
		return "", err
	}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar:       jar,
		Transport: f.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("troppi reindirizzamenti")
			}
			return allowedURL(req.URL, p.Hosts)
		},
	}
	var last error
	for _, wait := range []time.Duration{2 * time.Second, 4 * time.Second, 0} {
		sum, err := f.get(ctx, client, rawURL, dest, p.MaxMB<<20, progress)
		if err == nil {
			return sum, nil
		}
		last = err
		if errors.Is(err, ErrHost) || errors.Is(err, ErrTooLarge) || ctx.Err() != nil || wait == 0 {
			break
		}
		w := f.Wait
		if w == nil {
			w = sleep
		}
		if w(ctx, wait) != nil {
			break
		}
	}
	if ctx.Err() != nil {
		return "", errors.New("download interrotto")
	}
	return "", last
}

func (f *Fetcher) get(ctx context.Context, client *http.Client, rawURL, dest string, max int64, progress func(done, total int64)) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	if f.UserAgent != "" {
		req.Header.Set("User-Agent", f.UserAgent)
	}
	resp, err := client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) && errors.Is(ue.Err, ErrHost) {
			return "", ue.Err
		}
		return "", fmt.Errorf("sito non raggiungibile: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("il sito ha risposto %d", resp.StatusCode)
	}
	if strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") {
		return "", errors.New("il sito ha risposto con una pagina web invece del file")
	}
	if resp.ContentLength > max {
		return "", ErrTooLarge
	}
	out, err := os.Create(dest)
	if err != nil {
		return "", err
	}
	defer out.Close()
	h := sha256.New()
	pr := &progressReader{r: io.LimitReader(resp.Body, max+1), total: resp.ContentLength, fn: progress}
	n, err := io.Copy(io.MultiWriter(out, h), pr)
	if err != nil {
		return "", fmt.Errorf("download interrotto: %w", err)
	}
	if n > max {
		return "", ErrTooLarge
	}
	if resp.ContentLength >= 0 && n != resp.ContentLength {
		return "", errors.New("download incompleto")
	}
	return hex.EncodeToString(h.Sum(nil)), out.Close()
}

type progressReader struct {
	r     io.Reader
	done  int64
	total int64
	last  time.Time
	fn    func(done, total int64)
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.done += int64(n)
	if p.fn != nil && (time.Since(p.last) > 150*time.Millisecond || err != nil) {
		p.last = time.Now()
		p.fn(p.done, p.total)
	}
	return n, err
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// extractZip estrae l'archivio in dir rifiutando percorsi che escono dalla
// cartella e archivi troppo grandi una volta estratti.
func extractZip(path, dir string, maxTotal int64) error {
	r, err := zip.OpenReader(path)
	if err != nil {
		return errors.New("il file scaricato non è un archivio zip valido")
	}
	defer r.Close()
	if len(r.File) > 5000 {
		return errors.New("archivio con troppi file")
	}
	var total int64
	for _, zf := range r.File {
		if zf.FileInfo().IsDir() {
			continue
		}
		name := filepath.FromSlash(zf.Name)
		if !filepath.IsLocal(name) {
			return fmt.Errorf("archivio non valido: percorso %q", zf.Name)
		}
		total += int64(zf.UncompressedSize64)
		if total > maxTotal {
			return ErrTooLarge
		}
		if err := extractFile(zf, filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	return nil
}

func extractFile(zf *zip.File, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	rc, err := zf.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	w, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	n, err := io.Copy(w, io.LimitReader(rc, int64(zf.UncompressedSize64)+1))
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n != int64(zf.UncompressedSize64) {
		return errors.New("archivio danneggiato")
	}
	return nil
}

// cleanVersion sceglie la versione da mostrare tra quella del prodotto e
// quella del file dichiarate nell'eseguibile.
func cleanVersion(product, file string) string {
	v := strings.TrimSpace(product)
	if v == "" {
		v = strings.TrimSpace(file)
	}
	if i := strings.IndexAny(v, " ("); i > 0 {
		v = v[:i]
	}
	return v
}

// ParseSignature legge l'uscita JSON dello script di verifica.
func ParseSignature(out []byte) (Signature, error) {
	s := strings.TrimPrefix(strings.TrimSpace(string(out)), "\ufeff")
	if i := strings.Index(s, "{"); i >= 0 {
		s = s[i:]
	}
	var sig Signature
	if err := json.Unmarshal([]byte(s), &sig); err != nil {
		return Signature{}, errors.New("risposta della verifica non leggibile")
	}
	return sig, nil
}

// PortableIncluded rende le copie scaricate confrontabili con quelle incluse
// (per Merge).
func PortableIncluded(m map[string]Downloaded) map[string]Included {
	out := make(map[string]Included, len(m))
	for id, d := range m {
		out[id] = Included{Version: d.Version, Problem: d.Problem, Path: d.Path}
	}
	return out
}
