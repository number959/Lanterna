// Package sign dice chi ha firmato un file eseguibile e che cos'è: firma
// Authenticode verificata da Windows (WinVerifyTrust, firma incorporata o
// catalogo), informazioni di versione e tipo di cartella. Sola lettura e
// nessun accesso alla rete: la revoca dei certificati non si controlla online.
//
// Lo usano i processi (Process Explorer) e l'avvio automatico (Autoruns):
// lo stesso file si verifica una volta sola grazie alla cache, che si
// rinnova se cambiano dimensione o data del file.
package sign

import (
	"context"
	"os"
	"strings"
	"sync"
	"time"

	"lanterna/internal/scan"
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

	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	size  int64
	mod   time.Time
	facts scan.FileFacts
}

// New prepara un Checker.
func New(profile string, sanitize func(string) string) *Checker {
	return &Checker{Profile: profile, Sanitize: sanitize, cache: map[string]cached{}}
}

// Facts restituisce i fatti sul file indicato da un percorso assoluto già
// espanso (niente variabili d'ambiente, niente virgolette). Il percorso
// esportato passa da Sanitize. Non restituisce mai nil.
func (c *Checker) Facts(ctx context.Context, path string) *scan.FileFacts {
	out := scan.FileFacts{Path: path, Folder: FolderOf(path, c.Profile)}
	if c.Sanitize != nil {
		out.Path = c.Sanitize(path)
	}
	if path == "" {
		return &out
	}
	st, err := os.Stat(path)
	if err != nil || st.IsDir() {
		out.Missing = err != nil && os.IsNotExist(err)
		return &out
	}
	key := strings.ToLower(path)
	c.mu.Lock()
	if v, ok := c.cache[key]; ok && v.size == st.Size() && v.mod.Equal(st.ModTime()) {
		c.mu.Unlock()
		f := v.facts
		f.Path, f.Folder = out.Path, out.Folder
		return &f
	}
	c.mu.Unlock()
	if ctx.Err() == nil {
		out.Signature = verify(ctx, path)
		out.Company, out.Description, out.Version = versionInfo(path)
	}
	c.mu.Lock()
	if c.cache == nil {
		c.cache = map[string]cached{}
	}
	c.cache[key] = cached{size: st.Size(), mod: st.ModTime(), facts: out}
	c.mu.Unlock()
	return &out
}

// IsMicrosoft dice se la firma è valida e di Microsoft per un componente
// suo: lo decide la verifica (FileSignature.Microsoft, catena verso la
// radice Microsoft), non il nome del firmatario, perché Microsoft rifirma
// anche i driver di altri produttori.
func IsMicrosoft(s *scan.FileSignature) bool {
	return s != nil && s.Status == "valid" && s.Microsoft
}

// FolderOf classifica la cartella di un percorso assoluto di Windows:
// windows | programFiles | programData | appData | temp | downloads |
// profile | removable | network | other. Si basa sul testo del percorso e
// sulle variabili d'ambiente standard, senza leggere il disco; "removable"
// lo decide chi chiama (tipo di unità), qui si riconoscono solo le
// condivisioni di rete. Lavora sulle barre rovesciate anche fuori da
// Windows, così si prova ovunque.
func FolderOf(path, profile string) string {
	p := winClean(path)
	if p == "" {
		return ""
	}
	if strings.HasPrefix(p, `\\`) && !strings.HasPrefix(p, `\\?\`) && !strings.HasPrefix(p, `\\.\`) {
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
// senza chiedere l'amministratore.
func UserWritable(folder string) bool {
	switch folder {
	case "appData", "temp", "downloads", "profile", "removable", "network":
		return true
	}
	return false
}
