// Package sign dice chi ha firmato un file eseguibile e che cos'è: firma
// Authenticode verificata da Windows (WinVerifyTrust, firma incorporata o
// catalogo), informazioni di versione e tipo di cartella. Sola lettura e
// nessun accesso alla rete, per i processi come per l'avvio automatico: la
// revoca dei certificati non si controlla online, e un file in rete (una
// condivisione \\server in tutte le sue forme, oppure un'unità di rete
// collegata a una lettera, come Z:) non si apre, né per sapere se esiste né
// per la firma. Windows si collegherebbe a un server con le credenziali
// dell'utente, leggerebbe tutto il file dalla rete e, con il server
// irraggiungibile, si bloccherebbe per decine di secondi: il file risulta in
// una cartella "network", con la firma "unknown" (non verificabile).
//
// Lo usano i processi (Process Explorer) e l'avvio automatico (Autoruns)
// attraverso lo stesso Checker (Shared): lo stesso file si verifica una
// volta sola per tutta la vita del programma, anche tra un'analisi e
// l'altra, e la cache si rinnova se cambiano dimensione o data del file. Gli
// esiti che possono cambiare da soli (file in uso, cataloghi di Windows non
// consultabili) si riprovano dopo transientTTL.
package sign

import (
	"context"
	"os"
	"strings"
	"sync"
	"time"

	"lanterna/internal/pcinfo"
	"lanterna/internal/scan"
)

// transientTTL è la durata in cache degli esiti transitori (transient):
// basta a non ripeterli tra l'avvio automatico e i processi della stessa
// analisi, e l'analisi successiva li riprova.
const transientTTL = time.Minute

// driveTTL è la durata in cache del tipo di un'unità: la stessa lettera può
// diventare una chiavetta o un'unità di rete.
const driveTTL = time.Minute

// Sostituibili nelle prove: l'ora, la verifica della firma, le informazioni
// di versione e il tipo di unità (GetDriveType, 0 fuori da Windows).
var (
	now         = time.Now
	verifyFile  = verify
	readVersion = versionInfo
	driveType   = driveTypeOf
)

// Checker verifica i file e ne ricorda l'esito. È sicuro da usare da più
// goroutine.
type Checker struct {
	// Sanitize trasforma un percorso in quello esportabile (profilo
	// dell'utente → %USERPROFILE%); nil lascia il percorso com'è.
	Sanitize func(string) string
	// Profile è la cartella del profilo di chi usa Polaris, per il tipo di
	// cartella (FolderOf).
	Profile string

	mu     sync.Mutex
	cache  map[string]cached
	drives map[byte]drive
}

type cached struct {
	size  int64
	mod   time.Time
	at    time.Time // quando è stato verificato
	facts scan.FileFacts
}

type drive struct {
	folder string // "removable", "network" o vuoto
	at     time.Time
}

var (
	sharedOnce sync.Once
	shared     *Checker
)

// Shared restituisce il Checker comune a tutto il programma, con il profilo
// e il pulitore di chi usa Polaris (pcinfo.DefaultCleaner): processi e
// avvio automatico ne condividono la cache.
func Shared() *Checker {
	sharedOnce.Do(func() { shared = newShared(pcinfo.DefaultCleaner()) })
	return shared
}

// newShared prepara il Checker comune con il pulitore indicato: i percorsi
// esportati passano da cl.Path (profili, nome dell'utente, SID, e-mail,
// indirizzi pubblici).
func newShared(cl pcinfo.Cleaner) *Checker { return New(cl.Profile, cl.Path) }

// New prepara un Checker.
func New(profile string, sanitize func(string) string) *Checker {
	return &Checker{Profile: profile, Sanitize: sanitize, cache: map[string]cached{}, drives: map[byte]drive{}}
}

// Facts restituisce i fatti sul file indicato da un percorso assoluto già
// espanso (niente variabili d'ambiente, niente virgolette). Il percorso
// esportato passa da Sanitize. Non restituisce mai nil.
//
// Un file in rete (cartella "network": condivisione o unità di rete) non si
// apre: firma "unknown" e mai «mancante» (vedi il commento del pacchetto).
//
// A tempo scaduto restituisce solo percorso e cartella, senza toccare il
// disco: os.Stat su una condivisione non più raggiungibile si bloccherebbe
// per decine di secondi, oltre il tempo dichiarato della lettura.
func (c *Checker) Facts(ctx context.Context, path string) *scan.FileFacts {
	out := scan.FileFacts{Path: path, Folder: FolderOf(path, c.Profile)}
	if c.Sanitize != nil {
		out.Path = c.Sanitize(path)
	}
	if path != "" && ctx.Err() == nil {
		out.Folder = c.Folder(path)
	}
	if out.Folder == "network" {
		out.Signature = &scan.FileSignature{Status: "unknown"}
		return &out
	}
	if path == "" || ctx.Err() != nil {
		return &out
	}
	// Un processo a 32 bit su Windows a 64 bit legge System32 attraverso
	// Sysnative, altrimenti vedrebbe i file di SysWOW64 (nativePath).
	np := nativePath(path)
	st, err := os.Stat(np)
	if err != nil || st.IsDir() {
		out.Missing = err != nil && os.IsNotExist(err)
		if err != nil && !out.Missing {
			// Il file c'è ma non si legge (per esempio nel profilo di un
			// altro utente): firma non verificabile, non «non firmato».
			out.Signature = &scan.FileSignature{Status: "unreadable"}
		}
		return &out
	}
	key := strings.ToLower(path)
	c.mu.Lock()
	if v, ok := c.cache[key]; ok && v.size == st.Size() && v.mod.Equal(st.ModTime()) && !(transient(v.facts.Signature) && now().Sub(v.at) >= transientTTL) {
		c.mu.Unlock()
		f := v.facts
		f.Path, f.Folder = out.Path, out.Folder
		return &f
	}
	c.mu.Unlock()
	if ctx.Err() != nil {
		// Tempo finito durante os.Stat: nessuna verifica, e niente cache,
		// così la lettura successiva la fa.
		return &out
	}
	out.Signature = verifyFile(ctx, np)
	out.Company, out.Description, out.Version = readVersion(np)
	if out.Signature == nil && ctx.Err() != nil {
		// Verifica saltata per il tempo (nessuna firma incorporata e niente
		// tempo per i cataloghi): niente cache. Una verifica arrivata in
		// fondo invece è completa anche se il tempo è finito nel frattempo
		// (WinVerifyTrust non si interrompe) e si tiene: un file che da solo
		// richiede più del tempo massimo non riparte da capo a ogni lettura.
		return &out
	}
	c.mu.Lock()
	if c.cache == nil {
		c.cache = map[string]cached{}
	}
	c.cache[key] = cached{size: st.Size(), mod: st.ModTime(), at: now(), facts: out}
	c.mu.Unlock()
	return &out
}

// Folder è FolderOf con il tipo di unità: una lettera che non è una
// cartella nota ("other") può essere una chiavetta ("removable") o
// un'unità di rete collegata a una condivisione, come Z:\ ("network"). Non
// legge file: solo GetDriveType, una volta per lettera ogni driveTTL.
func (c *Checker) Folder(path string) string {
	f := FolderOf(path, c.Profile)
	if f == "other" {
		if d := c.driveFolder(path); d != "" {
			return d
		}
	}
	return f
}

// driveFolder dice se il percorso sta su un'unità rimovibile (chiavetta,
// scheda di memoria: "removable") o su un'unità di rete collegata a una
// lettera ("network"). Vuoto negli altri casi e fuori da Windows.
func (c *Checker) driveFolder(path string) string {
	d, ok := driveLetter(path)
	if !ok {
		return ""
	}
	c.mu.Lock()
	if v, ok := c.drives[d]; ok && now().Sub(v.at) < driveTTL {
		c.mu.Unlock()
		return v.folder
	}
	c.mu.Unlock()
	f := driveFolderOf(driveType(string([]byte{d, ':', '\\'})))
	c.mu.Lock()
	if c.drives == nil {
		c.drives = map[byte]drive{}
	}
	c.drives[d] = drive{folder: f, at: now()}
	c.mu.Unlock()
	return f
}

// Tipi di unità di GetDriveType (winbase.h).
const (
	driveRemovable = 2 // DRIVE_REMOVABLE
	driveRemote    = 4 // DRIVE_REMOTE
)

// driveFolderOf traduce il tipo di unità nel tipo di cartella.
func driveFolderOf(t uint32) string {
	switch t {
	case driveRemovable:
		return "removable"
	case driveRemote:
		return "network"
	}
	return ""
}

// driveLetter restituisce la lettera di unità, in minuscolo, di un percorso
// assoluto come C:\x, \\?\C:\x o \\.\C:\x.
func driveLetter(p string) (byte, bool) {
	p = strings.ReplaceAll(p, "/", `\`)
	if strings.HasPrefix(p, `\\?\`) || strings.HasPrefix(p, `\\.\`) {
		p = p[4:]
	}
	if len(p) < 3 || p[1] != ':' || p[2] != '\\' {
		return 0, false
	}
	if d := p[0] | 0x20; d >= 'a' && d <= 'z' {
		return d, true
	}
	return 0, false
}

// IsMicrosoft dice se la firma è valida e di Microsoft per un componente
// suo: lo decide la verifica (FileSignature.Microsoft, catena verso la
// radice Microsoft), non il nome del firmatario, perché Microsoft rifirma
// anche i driver di altri produttori.
func IsMicrosoft(s *scan.FileSignature) bool {
	return s != nil && s.Status == "valid" && s.Microsoft
}

// writableWindowsDirs sono sottocartelle di Windows in cui, con i permessi
// predefiniti, un utente senza privilegi può creare file: un programma lì
// non sta in una cartella protetta. Relative a %SystemRoot%.
var writableWindowsDirs = []string{`Tasks`, `Tracing`, `System32\spool\drivers\color`}

// FolderOf classifica la cartella di un percorso assoluto di Windows:
// windows | programFiles | programData | appData | temp | downloads |
// profile | removable | network | other. Si basa sul testo del percorso e
// sulle variabili d'ambiente standard, senza leggere il disco; "removable"
// e "network" per le lettere di unità li decide Checker.Folder (tipo di
// unità), qui si riconoscono solo le condivisioni di rete scritte nel
// percorso (networkPath). Le sottocartelle di Windows scrivibili da tutti
// (writableWindowsDirs) sono "other", non "windows". Lavora sulle barre
// rovesciate anche fuori da Windows, così si prova ovunque.
func FolderOf(path, profile string) string {
	p := winClean(path)
	if p == "" {
		return ""
	}
	if networkPath(p) {
		return "network"
	}
	p = strings.TrimPrefix(p, `\\?\`)
	under := func(root string) bool {
		root = winClean(root)
		return root != "" && (p == root || strings.HasPrefix(p, root+`\`))
	}
	env := func(name, fallback string) string {
		if v := os.Getenv(name); v != "" {
			return v
		}
		return fallback
	}
	prof := profile
	if prof == "" {
		prof = os.Getenv("USERPROFILE")
	}
	sysRoot := env("SystemRoot", `C:\Windows`)
	// Le cartelle temporanee prima di tutto: stanno dentro Windows o dentro il profilo.
	for _, t := range []string{os.Getenv("TEMP"), os.Getenv("TMP"), sysRoot + `\Temp`} {
		if t != "" && under(t) {
			return "temp"
		}
	}
	for _, d := range writableWindowsDirs {
		if under(sysRoot + `\` + d) {
			return "other"
		}
	}
	switch {
	case under(sysRoot):
		return "windows"
	case under(env("ProgramFiles", `C:\Program Files`)), under(env("ProgramFiles(x86)", `C:\Program Files (x86)`)), under(env("ProgramW6432", `C:\Program Files`)):
		return "programFiles"
	case under(env("ProgramData", `C:\ProgramData`)):
		return "programData"
	}
	if prof = winClean(prof); prof != "" {
		switch {
		case under(prof + `\appdata\local\temp`):
			return "temp"
		case under(prof + `\downloads`):
			return "downloads"
		case under(prof + `\appdata`):
			return "appData"
		case under(prof):
			return "profile"
		}
		// Profili di altri utenti sotto la stessa radice (C:\Users\altro\...).
		if i := strings.LastIndex(prof, `\`); i > 0 {
			root := prof[:i]
			if strings.HasPrefix(p, root+`\`) {
				rest := p[len(root)+1:]
				if k := strings.Index(rest, `\`); k > 0 {
					rest = rest[k+1:]
					switch {
					case strings.HasPrefix(rest, `appdata\local\temp\`):
						return "temp"
					case strings.HasPrefix(rest, `downloads\`):
						return "downloads"
					case strings.HasPrefix(rest, `appdata\`):
						return "appData"
					}
					return "profile"
				}
			}
		}
	}
	return "other"
}

// networkPath dice se un percorso già passato da winClean sta su una
// condivisione di rete scritta nel testo: \\server\... (anche WebDAV,
// \\server@SSL\...), le forme lunghe \\?\UNC\..., \\.\UNC\... e \??\UNC\...,
// e i redirector di rete (pcinfo.NetworkRedirectors) con il nome del
// dispositivo, anche raggiunti da GLOBALROOT (\Device\Mup\...,
// \\?\GLOBALROOT\Device\WebDavRedirector\...).
// Le altre forme lunghe sono locali: \\?\C:\..., una copia shadow
// \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\... È la regola unica per
// i processi e per l'avvio automatico.
func networkPath(p string) bool {
	for _, pre := range []string{`\\?\`, `\\.\`, `\??\`} {
		if rest, ok := strings.CutPrefix(p, pre); ok {
			if strings.HasPrefix(rest, `unc\`) {
				return true
			}
			if rest, ok = strings.CutPrefix(rest, `globalroot`); ok {
				return networkPath(rest)
			}
			return false
		}
	}
	if strings.HasPrefix(p, `\\`) {
		return true
	}
	for _, d := range pcinfo.NetworkRedirectors {
		if strings.HasPrefix(p, `\device\`+d+`\`) {
			return true
		}
	}
	return false
}

// winClean porta un percorso di Windows in minuscolo, con le sole barre
// rovesciate, senza doppioni (tranne il prefisso \\ delle condivisioni) e
// senza barra finale.
func winClean(p string) string {
	p = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(p, "/", `\`)))
	lead := ""
	if strings.HasPrefix(p, `\\`) {
		lead, p = `\\`, p[2:]
	}
	for strings.Contains(p, `\\`) {
		p = strings.ReplaceAll(p, `\\`, `\`)
	}
	return lead + strings.TrimSuffix(p, `\`)
}

// UserWritable dice se un tipo di cartella è, di norma, scrivibile da un
// utente senza privilegi: lì un programma può essere messo o sostituito
// senza chiedere l'amministratore. Sono protette solo Windows e Programmi.
// ProgramData lo è solo in parte: con i permessi predefiniti ogni utente
// può creare sottocartelle e file (e ne è proprietario). Le cartelle create
// alla radice di un'unità ("other") ereditano la modifica per gli utenti
// autenticati, e le altre unità di solito sono scrivibili.
func UserWritable(folder string) bool {
	switch folder {
	case "appData", "temp", "downloads", "profile", "removable", "network", "programData", "other":
		return true
	}
	return false
}
