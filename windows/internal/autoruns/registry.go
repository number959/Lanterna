package autoruns

import (
	"regexp"
	"strings"
	"unicode"

	"lanterna/internal/scan"
)

// reader costruisce le voci a partire dai valori letti (registro, file,
// script): risolve i file e pulisce i testi esportati.
type reader struct {
	res Resolver
	cl  cleaner
}

// commandItem prepara una voce che avvia una riga di comando: file,
// argomenti e, per i programmi di sistema che eseguono altro, il file
// eseguito davvero.
func (rd reader) commandItem(e scan.AutorunEntry, cmd string, wow32 bool) item {
	file, args, _ := rd.res.Split(cmd, wow32)
	return rd.execItem(e, cmd, file, args, wow32)
}

// execItem prepara una voce con il programma e gli argomenti già separati
// (da Split, o dai campi Path e Arguments di un'attività); cmd è il comando
// mostrato. Se il programma esegue altro (ProxyTarget), target è il file
// eseguito davvero; se non c'è un file da verificare la voce è un comando
// interpretato, che non si nasconde mai.
func (rd reader) execItem(e scan.AutorunEntry, cmd, file, args string, wow32 bool) item {
	it := item{entry: e}
	it.entry.Command = rd.cl.command(cmd)
	file = strings.TrimSpace(strings.Trim(strings.TrimSpace(file), `"`))
	if file == "" {
		return it
	}
	it.file = rd.res.Locate(file, wow32)
	if target, proxy := ProxyTarget(file, args); proxy {
		if target == "" {
			it.interpreted = strings.TrimSpace(args) != ""
		} else {
			it.target = rd.res.Locate(target, wow32)
		}
	}
	return it
}

// fileItem prepara una voce che carica un file (DLL, driver), senza
// argomenti.
func (rd reader) fileItem(e scan.AutorunEntry, file string, wow32 bool) item {
	it := item{entry: e}
	it.entry.Command = rd.cl.path(file)
	it.file = rd.res.Locate(file, wow32)
	return it
}

// runName toglie da un valore di RunOnce i prefissi «!» (il valore si
// cancella solo dopo che il programma è partito) e «*» (parte anche in
// modalità provvisoria).
func runName(name string) string {
	return strings.TrimLeft(name, "!*")
}

// runOnceExFile: le voci di RunOnceEx hanno la forma «file|funzione|argomenti»
// (una DLL e la funzione da chiamare) oppure sono una riga di comando.
func runOnceExFile(v string) (cmd string, dll bool) {
	if i := strings.IndexByte(v, '|'); i >= 0 {
		return strings.TrimSpace(v[:i]), true
	}
	return v, false
}

// splitList divide un elenco di comandi o file separati da virgole (il
// valore load, Userinit, Shell).
func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// splitAppInit divide AppInit_DLLs: le DLL sono separate da spazi o virgole.
func splitAppInit(v string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		if p = strings.Trim(p, `"`); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// defaultShell: il valore Shell predefinito di Windows è «explorer.exe»;
// si accetta anche il percorso completo nella cartella di Windows.
func (rd reader) defaultShell(cmd string) bool {
	file, args, _ := rd.res.Split(cmd, false)
	if args != "" || !strings.EqualFold(baseOf(file), "explorer.exe") && !strings.EqualFold(file, "explorer") {
		return false
	}
	return dirOf(file) == "" || strings.EqualFold(rd.res.Expand(dirOf(file), false), rd.res.sysRoot())
}

// defaultUserinit: il valore predefinito è
// «C:\Windows\system32\userinit.exe,» (un solo programma).
func (rd reader) defaultUserinit(cmd string) bool {
	file, args, _ := rd.res.Split(cmd, false)
	if args != "" {
		return false
	}
	if strings.EqualFold(file, "userinit.exe") || strings.EqualFold(file, "userinit") {
		return true
	}
	return strings.EqualFold(rd.res.Expand(file, false), rd.res.sysRoot()+`\system32\userinit.exe`)
}

// winlogonItems prepara le voci di Shell o di Userinit: ogni programma
// dell'elenco è una voce; quelle diverse dal predefinito sono dirottamenti.
func (rd reader) winlogonItems(scope, loc, value, data string) []item {
	var out []item
	for _, cmd := range splitList(data) {
		kind, def := "shell", false
		if strings.EqualFold(value, "Userinit") {
			kind, def = "userinit", rd.defaultUserinit(cmd)
		} else {
			def = rd.defaultShell(cmd)
		}
		it := rd.commandItem(scan.AutorunEntry{Category: "winlogon", Kind: kind, Scope: scope, Name: value, Location: loc, Enabled: true}, cmd, false)
		it.hijack = !def
		out = append(out, it)
	}
	return out
}

// DefaultBootExecute è il valore predefinito di BootExecute.
const DefaultBootExecute = "autocheck autochk *"

// Le espressioni sono le stesse del motore (BOOT_OPTION e BOOT_VOLUME in
// core/src/engine/autoruns.ts), senza il flag i: si applicano alla parola
// con le sole lettere A-Z portate in minuscolo (asciiLower), come fa /i in
// JavaScript senza u. Con (?i) Go confronterebbe anche «ſ» con «s» e il
// segno del kelvin con «k».
var (
	// bootOption: un'opzione di autochk, con o senza valore (/q, /v, /p,
	// /r, /k:C, /m). Il valore resta un argomento di autochk, che non lo
	// esegue.
	bootOption = regexp.MustCompile(`^/[a-z0-9]+(?::\S+)?$`)
	// bootVolume: un volume, \??\C:, \DosDevices\C: o \??\Volume{guid}.
	bootVolume = regexp.MustCompile(`^(?:(?:\\\?\?\\|\\dosdevices\\)[a-z]:|\\\?\?\\volume\{[0-9a-f-]+\})$`)
)

// asciiLower porta in minuscolo solo le lettere A-Z.
func asciiLower(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}, s)
}

// jsSpace sono gli spazi di \s in JavaScript, con cui il motore divide la
// riga in parole: quelli di Unicode (unicode.IsSpace) e U+FEFF, senza
// U+0085.
func jsSpace(r rune) bool {
	return r == '\ufeff' || (unicode.IsSpace(r) && r != '\u0085')
}

// bootExecuteDefault applica la regola comune al motore
// (bootExecuteKind in core/src/engine/autoruns.ts): la riga è quella di
// Windows se, divisa in parole senza badare a spazi e maiuscole, comincia
// con «autocheck autochk» e il resto sono solo opzioni di autochk,
// l'asterisco o volumi, con almeno un asterisco o un volume. Così sono di
// Windows anche «autocheck autochk /q /v *» (immagini di Azure) e il
// controllo del disco programmato «autocheck autochk /p \??\C:»
// (scheduled: c'è un volume, e il motore lo dice come informazione).
func bootExecuteDefault(v string) (def, scheduled bool) {
	f := strings.FieldsFunc(v, jsSpace)
	if len(f) < 3 || strings.ToLower(f[0]) != "autocheck" || strings.ToLower(f[1]) != "autochk" {
		return false, false
	}
	star := false
	for _, w := range f[2:] {
		switch lw := asciiLower(w); {
		case w == "*":
			star = true
		case bootVolume.MatchString(lw):
			scheduled = true
		case bootOption.MatchString(lw):
		default:
			return false, false
		}
	}
	if !star && !scheduled {
		return false, false
	}
	return true, scheduled
}

// isDefaultBootExecute: la riga è quella di Windows (bootExecuteDefault).
func isDefaultBootExecute(v string) bool {
	def, _ := bootExecuteDefault(v)
	return def
}

// bootExecuteFile: BootExecute avvia programmi nativi di System32;
// «autocheck X» avvia X.
func bootExecuteFile(v string) string {
	f := strings.Fields(v)
	if len(f) == 0 {
		return ""
	}
	name := f[0]
	if strings.EqualFold(name, "autocheck") && len(f) > 1 {
		name = f[1]
	}
	if strings.ContainsAny(name, `\/`) {
		return name
	}
	if extOf(name) == "" {
		name += ".exe"
	}
	return `%SystemRoot%\System32\` + name
}

func (rd reader) bootExecuteItems(loc string, values []string) []item {
	var out []item
	for _, v := range values {
		if v = strings.TrimSpace(v); v == "" {
			continue
		}
		it := rd.fileItem(scan.AutorunEntry{Category: "hijacks", Kind: "bootexecute", Scope: "machine", Name: "BootExecute", Location: loc, Enabled: true}, bootExecuteFile(v), false)
		it.entry.Command = rd.cl.path(v)
		def, scheduled := bootExecuteDefault(v)
		it.hijack = !def
		// Un controllo del disco programmato da Windows non è un
		// dirottamento, ma si elenca: il motore lo dice come informazione.
		it.always = scheduled
		out = append(out, it)
	}
	return out
}

// appInitItems: le DLL di AppInit_DLLs si caricano in ogni programma che usa
// user32.dll solo se LoadAppInit_DLLs vale 1 (e Secure Boot è spento): solo
// allora sono un dirottamento attivo.
func (rd reader) appInitItems(scope, loc, dlls string, load bool) []item {
	var out []item
	for _, d := range splitAppInit(dlls) {
		it := rd.fileItem(scan.AutorunEntry{Category: "hijacks", Kind: "appinit", Scope: scope, Name: baseOf(d), Location: loc, Enabled: load}, d, scope == "machine32")
		it.hijack = load
		out = append(out, it)
	}
	return out
}

// lsaFile: i pacchetti LSA si indicano col nome della DLL di System32, di
// solito senza estensione (forma osservata: «msv1_0», «kerberos»).
func lsaFile(name string) string {
	if strings.ContainsAny(name, `\/`) {
		return name
	}
	if extOf(name) == "" {
		name += ".dll"
	}
	return `%SystemRoot%\System32\` + name
}

func (rd reader) lsaItems(kind, loc string, names []string) []item {
	var out []item
	for _, n := range names {
		n = strings.TrimSpace(strings.Trim(strings.TrimSpace(n), `"`))
		if n == "" {
			continue
		}
		// Il nome è quello della DLL: un percorso completo (accettato da
		// Security Packages) resta, pulito, nel comando e nel file.
		out = append(out, rd.fileItem(scan.AutorunEntry{Category: "lsa", Kind: kind, Scope: "machine", Name: rd.cl.text(baseOf(n)), Location: loc, Enabled: true}, lsaFile(n), false))
	}
	return out
}

// printProcFile cerca la DLL di un processore di stampa nelle cartelle dei
// processori (spool\prtprocs\<ambiente>), la prima che esiste.
func (rd reader) printProcFile(driver string, dirs []string) string {
	if strings.ContainsAny(driver, `\/`) {
		return rd.res.Locate(driver, false)
	}
	first := ""
	for _, d := range dirs {
		p := strings.TrimRight(d, `\`) + `\` + driver
		if first == "" {
			first = p
		}
		if rd.res.exists(p) {
			return p
		}
	}
	return first
}

// shortcutItem prepara una voce della cartella Esecuzione automatica: per un
// collegamento .lnk il file è la sua destinazione. Un collegamento senza un
// file di destinazione (solo l'elenco della shell, come quelli alle app
// dello Store) o non leggibile si mostra senza verificarlo: il .lnk non è
// il programma, e verificarlo darebbe «senza firma» per errore.
func (rd reader) shortcutItem(e scan.AutorunEntry, path string, lnk []byte) item {
	if !strings.EqualFold(extOf(path), ".lnk") {
		return rd.fileItem(e, path, false)
	}
	sc, ok := parseLnk(lnk)
	if !ok {
		it := rd.fileItem(e, path, false)
		it.unverified = true
		return it
	}
	target := sc.Target
	if target == "" && sc.Relative != "" {
		target = dirOf(path) + `\` + sc.Relative
	}
	cmd := target
	if strings.Contains(target, " ") {
		cmd = `"` + target + `"`
	}
	if sc.Args != "" {
		cmd += " " + sc.Args
	}
	return rd.commandItem(e, cmd, false)
}
