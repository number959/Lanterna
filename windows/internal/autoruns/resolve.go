package autoruns

import (
	"path"
	"strings"
)

// Resolver trasforma i comandi e i percorsi letti nel registro, nelle
// attività e nei servizi nei file assoluti da verificare. Lavora sul testo
// con le regole di Windows (barre rovesciate, maiuscole indifferenti), così
// si prova anche fuori da Windows; il disco si tocca solo con Exists, in
// sola lettura.
type Resolver struct {
	// Getenv legge una variabile d'ambiente ("" se manca); su Windows i
	// nomi non distinguono le maiuscole.
	Getenv func(string) string
	// Exists dice se un file esiste.
	Exists func(string) bool
}

func (r Resolver) getenv(name string) string {
	if r.Getenv == nil {
		return ""
	}
	return r.Getenv(name)
}

func (r Resolver) exists(p string) bool {
	return r.Exists != nil && p != "" && r.Exists(p)
}

// sysRoot è la cartella di Windows (C:\Windows).
func (r Resolver) sysRoot() string {
	if v := strings.TrimRight(r.getenv("SystemRoot"), `\`); v != "" {
		return v
	}
	if v := strings.TrimRight(r.getenv("windir"), `\`); v != "" {
		return v
	}
	return `C:\Windows`
}

// variable restituisce il valore di una variabile per una voce nativa o a
// 32 bit. Per un programma a 32 bit Windows imposta ProgramFiles e
// CommonProgramFiles sulle cartelle «(x86)» (WOW64 Implementation Details):
// una voce di WOW6432Node espansa dall'agente a 64 bit punterebbe altrimenti
// alla cartella sbagliata e il file risulterebbe mancante per errore.
func (r Resolver) variable(name string, wow32 bool) string {
	switch {
	case wow32 && strings.EqualFold(name, "ProgramFiles"):
		if v := r.getenv("ProgramFiles(x86)"); v != "" {
			return v
		}
	case wow32 && strings.EqualFold(name, "CommonProgramFiles"):
		if v := r.getenv("CommonProgramFiles(x86)"); v != "" {
			return v
		}
	case !wow32 && strings.EqualFold(name, "ProgramFiles"):
		// ProgramW6432 è la cartella nativa anche se l'agente gira a 32 bit.
		if v := r.getenv("ProgramW6432"); v != "" {
			return v
		}
	case !wow32 && strings.EqualFold(name, "CommonProgramFiles"):
		if v := r.getenv("CommonProgramW6432"); v != "" {
			return v
		}
	}
	return r.getenv(name)
}

// Expand sostituisce le %VARIABILI% come ExpandEnvironmentStrings: quelle
// sconosciute restano come sono.
func (r Resolver) Expand(s string, wow32 bool) string {
	var b strings.Builder
	for {
		i := strings.IndexByte(s, '%')
		if i < 0 {
			break
		}
		j := strings.IndexByte(s[i+1:], '%')
		if j < 0 {
			break
		}
		name := s[i+1 : i+1+j]
		val := ""
		if name != "" && !strings.ContainsAny(name, " \\/\"") {
			val = r.variable(name, wow32)
		}
		if val == "" {
			b.WriteString(s[:i+2+j])
		} else {
			b.WriteString(s[:i])
			b.WriteString(val)
		}
		s = s[i+2+j:]
	}
	b.WriteString(s)
	return b.String()
}

// hasPrefixFold è strings.HasPrefix senza distinguere le maiuscole, sul
// testo originale (mai posizioni calcolate su strings.ToLower).
func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// under dice se p sta nella cartella dir (o è dir).
func under(p, dir string) bool {
	dir = strings.TrimRight(dir, `\`)
	return strings.EqualFold(p, dir) || hasPrefixFold(p, dir+`\`)
}

// isAbs: percorso con unità (C:\...) o condivisione di rete (\\server\...).
func isAbs(p string) bool {
	if len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') {
		c := p[0] | 0x20
		return c >= 'a' && c <= 'z'
	}
	return strings.HasPrefix(p, `\\`)
}

// baseOf è il nome del file, dopo l'ultima barra.
func baseOf(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// dirOf è la cartella di un percorso ("" se non ne ha).
func dirOf(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[:i]
	}
	return ""
}

// extOf è l'estensione dell'ultimo componente, con il punto ("" se manca).
func extOf(p string) string {
	b := baseOf(p)
	if i := strings.LastIndexByte(b, '.'); i > 0 {
		return b[i:]
	}
	return ""
}

// stem è il nome del file senza estensione, in minuscolo.
func stem(p string) string {
	b := baseOf(p)
	if e := extOf(b); e != "" {
		b = b[:len(b)-len(e)]
	}
	return strings.ToLower(b)
}

// execExts sono le estensioni dei file che Windows esegue o carica: servono
// a capire dove finisce il file in una riga di comando senza virgolette.
var execExts = map[string]bool{
	".exe": true, ".com": true, ".bat": true, ".cmd": true, ".sys": true, ".dll": true, ".scr": true, ".cpl": true,
	".ps1": true, ".vbs": true, ".vbe": true, ".js": true, ".jse": true, ".wsf": true, ".wsh": true, ".hta": true,
	".msi": true, ".msc": true, ".lnk": true, ".ocx": true, ".drv": true, ".pif": true,
}

func hasExecExt(p string) bool { return execExts[strings.ToLower(extOf(p))] }

// absolute porta un percorso già espanso nelle forme assolute in cui
// cercarlo, nell'ordine in cui Windows lo cercherebbe.
func (r Resolver) absolute(p string, wow32 bool) []string {
	p = strings.TrimSpace(p)
	sys := r.sysRoot()
	switch {
	case hasPrefixFold(p, `\??\UNC\`), hasPrefixFold(p, `\\?\UNC\`), hasPrefixFold(p, `\\.\UNC\`):
		// Condivisione di rete nelle forme lunghe: \\?\UNC\server\... (e
		// \\.\UNC\server\...) è \\server\...
		p = `\\` + p[8:]
	case hasPrefixFold(p, `\??\GLOBALROOT\`), hasPrefixFold(p, `\\?\GLOBALROOT\`):
		// Un dispositivo di Windows (copia shadow, redirector di rete): resta
		// nella forma \\?\, che sign.FolderOf riconosce (rete o locale).
		p = `\\?\` + p[4:]
	case hasPrefixFold(p, `\??\`), hasPrefixFold(p, `\\?\`):
		p = p[4:]
	}
	switch {
	case hasPrefixFold(p, `\SystemRoot\`):
		p = sys + p[len(`\SystemRoot`):]
	case hasPrefixFold(p, `SystemRoot\`):
		p = sys + `\` + p[len(`SystemRoot\`):]
	case hasPrefixFold(p, `System32\`), hasPrefixFold(p, `SysWOW64\`):
		// Forma dei driver: relativa alla cartella di Windows.
		p = sys + `\` + p
	}
	p = strings.ReplaceAll(p, "/", `\`)
	switch {
	case isAbs(p):
		sys32 := sys + `\System32`
		if wow32 && under(p, sys32) {
			// Un programma a 32 bit che chiede System32 legge SysWOW64.
			return []string{sys + `\SysWOW64` + p[len(sys32):], p}
		}
		return []string{p}
	case strings.HasPrefix(p, `\`):
		drive := strings.TrimRight(r.getenv("SystemDrive"), `\`)
		if drive == "" {
			drive = sys[:min(2, len(sys))]
		}
		return []string{drive + p}
	case !strings.Contains(p, `\`):
		// Solo il nome: si cerca come CreateProcess, nelle cartelle di
		// sistema e poi in quelle del PATH; senza estensione si prova .exe.
		names := []string{p}
		if extOf(p) == "" {
			names = []string{p + ".exe", p}
		}
		var dirs []string
		if wow32 {
			dirs = append(dirs, sys+`\SysWOW64`)
		}
		dirs = append(dirs, sys+`\System32`, sys, sys+`\System32\wbem`, sys+`\System32\WindowsPowerShell\v1.0`)
		for _, d := range strings.Split(r.getenv("PATH"), ";") {
			d = strings.TrimRight(strings.TrimSpace(r.Expand(strings.Trim(d, `"`), false)), `\`)
			if isAbs(d) {
				dirs = append(dirs, d)
			}
		}
		var out []string
		for _, d := range dirs {
			for _, n := range names {
				out = append(out, d+`\`+n)
			}
		}
		return out
	default:
		// Relativo con cartelle (raro): relativo alla cartella di Windows.
		return []string{sys + `\` + p}
	}
}

// Candidates sono i percorsi assoluti in cui cercare il file indicato da p,
// già senza argomenti: prima con le variabili della voce (a 32 bit se wow32),
// poi, per le voci a 32 bit, con quelle native.
func (r Resolver) Candidates(p string, wow32 bool) []string {
	p = strings.TrimSpace(strings.Trim(strings.TrimSpace(p), `"`))
	if p == "" {
		return nil
	}
	variants := []string{r.Expand(p, wow32)}
	if wow32 {
		if v := r.Expand(p, false); v != variants[0] {
			variants = append(variants, v)
		}
	}
	var out []string
	seen := map[string]bool{}
	for _, v := range variants {
		for _, c := range r.absolute(v, wow32) {
			if k := strings.ToLower(c); !seen[k] {
				seen[k] = true
				out = append(out, c)
			}
		}
	}
	return out
}

// Locate restituisce il primo candidato che esiste, altrimenti il primo
// candidato (che risulterà mancante), o "" se p è vuoto.
func (r Resolver) Locate(p string, wow32 bool) string {
	c := r.Candidates(p, wow32)
	for _, x := range c {
		if r.exists(x) {
			return x
		}
	}
	if len(c) == 0 {
		return ""
	}
	return c[0]
}

// Split separa il file dagli argomenti in una riga di comando, come
// CreateProcess: fra virgolette il file è il testo fra le virgolette; senza
// virgolette è il prefisso più corto che esiste, altrimenti il primo con
// un'estensione eseguibile (il file manca), altrimenti il primo pezzo. Il
// file che manca non va oltre un pezzo che non può continuare un nome: un
// argomento che comincia con «-», «/» o con le virgolette, o che contiene
// «:» (un percorso con l'unità, un indirizzo), così «powershell -File
// C:\x.ps1» ha come file powershell e non tutta la riga. quoted dice se il
// file era fra virgolette.
func (r Resolver) Split(cmd string, wow32 bool) (file, args string, quoted bool) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return "", "", false
	}
	if cmd[0] == '"' {
		if end := strings.IndexByte(cmd[1:], '"'); end >= 0 {
			return cmd[1 : 1+end], strings.TrimSpace(cmd[2+end:]), true
		}
		return strings.TrimSpace(cmd[1:]), "", true
	}
	// cuts sono tutti i punti in cui il file può finire; quelli fino a limit
	// (il primo pezzo che non può continuare un nome) valgono anche per un
	// file che manca. Un prefisso che esiste vale comunque, come per
	// CreateProcess: «C:\Program Files\Foo -Bar Baz\a.exe» esiste anche se
	// «-Bar» sembra un'opzione.
	var cuts []int
	limit := -1
	for i := 0; i < len(cmd); i++ {
		if cmd[i] == ' ' || cmd[i] == '\t' {
			cuts = append(cuts, i)
			if limit < 0 && argumentStart(cmd[i+1:]) {
				limit = len(cuts)
			}
		}
	}
	cuts = append(cuts, len(cmd))
	if limit < 0 {
		limit = len(cuts)
	}
	for _, c := range cuts {
		for _, x := range r.Candidates(cmd[:c], wow32) {
			if r.exists(x) {
				return cmd[:c], strings.TrimSpace(cmd[c:]), false
			}
		}
	}
	for _, c := range cuts[:limit] {
		if hasExecExt(cmd[:c]) {
			return cmd[:c], strings.TrimSpace(cmd[c:]), false
		}
	}
	return cmd[:cuts[0]], strings.TrimSpace(cmd[cuts[0]:]), false
}

// argumentStart: il pezzo che inizia s (dopo gli spazi) non può essere il
// seguito di un nome di file con spazi: le virgolette e «/» non stanno nei
// nomi, «:» solo dopo l'unità; «-» è un'opzione se segue una lettera o un
// altro «-» e il pezzo non ha cartelle («C:\Program Files\Foo - Bar\a.exe»
// e «C:\x\-Backup\a.exe» continuano).
func argumentStart(s string) bool {
	s = strings.TrimLeft(s, " \t")
	if s == "" {
		return false
	}
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		s = s[:i]
	}
	switch {
	case s[0] == '"' || s[0] == '/' || strings.Contains(s, ":"):
		return true
	case s[0] == '-' && len(s) > 1 && !strings.Contains(s, `\`):
		c := s[1] | 0x20
		return s[1] == '-' || c >= 'a' && c <= 'z'
	}
	return false
}

// InterceptorCandidates sono i file che CreateProcess proverebbe prima di
// file, se il percorso con spazi non è fra virgolette: per
// C:\Program Files\Vendor App\svc.exe sono C:\Program.exe e
// C:\Program Files\Vendor.exe. Un nome che ha già un'estensione si prova
// così com'è.
func InterceptorCandidates(file string) []string {
	var out []string
	for i := 0; i < len(file); i++ {
		if file[i] != ' ' {
			continue
		}
		prefix := strings.TrimRight(file[:i], " ")
		if prefix == "" || strings.HasSuffix(prefix, `\`) || strings.HasSuffix(prefix, ":") {
			continue
		}
		if extOf(prefix) == "" {
			prefix += ".exe"
		}
		if len(out) == 0 || out[len(out)-1] != prefix {
			out = append(out, prefix)
		}
	}
	return out
}

// token è un argomento di una riga di comando.
type token struct {
	text   string
	quoted bool
	end    int // posizione dopo l'argomento nel testo originale
}

// tokens divide una riga di comando in argomenti: gli spazi fuori dalle
// virgolette separano, le virgolette si tolgono (forma semplificata di
// CommandLineToArgvW, senza le sequenze con la barra rovesciata).
func tokens(s string) []token {
	var out []token
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) {
			break
		}
		var b strings.Builder
		in, q := false, false
		for i < len(s) && (in || (s[i] != ' ' && s[i] != '\t')) {
			if s[i] == '"' {
				in, q = !in, true
			} else {
				b.WriteByte(s[i])
			}
			i++
		}
		out = append(out, token{text: b.String(), quoted: q, end: i})
	}
	return out
}

// proxies sono i programmi di Windows, firmati da Microsoft, che eseguono
// altro codice ricevuto negli argomenti: la loro firma non dice nulla su
// ciò che eseguono. Fonti:
//   - MITRE ATT&CK T1218 (System Binary Proxy Execution) e le sottotecniche
//     .001 hh, .002 control (e rundll32 shell32.dll,Control_RunDLL), .003
//     cmstp, .004 installutil, .005 mshta, .007 msiexec, .008 odbcconf,
//     .009 regsvcs e regasm, .010 regsvr32, .011 rundll32, .012 verclsid,
//     .013 mavinject, .014 mmc;
//   - T1059 (interpreti: cmd, powershell e pwsh, wscript e cscript), T1202
//     (esecuzione indiretta: pcalua, forfiles, conhost), T1127.001
//     (msbuild), T1216 (script di sistema: pubprn.vbs,
//     SyncAppvPublishingServer), T1197 e T1105 (bitsadmin, certutil), T1047
//     (wmic), T1053.005 (schtasks);
//   - il progetto LOLBAS (lolbas-project.github.io): explorer, presentationhost,
//     ieexec, infdefaultinstall, scriptrunner, atbroker, diskshadow, ftp,
//     register-cimprovider, wuauclt, xwizard, runas, wsl e bash, e le DLL
//     «lanciatrici» di rundll32 (launchers).
//
// Per ognuno ProxyTarget sa dove sta il file eseguito; quando non lo sa (un
// comando, un indirizzo, un file INF) la voce è un «comando interpretato»:
// si elenca sempre e il motore dichiara il programma che lo esegue. L'elenco
// va tenuto uguale a INTERPRETERS di core/src/engine/autoruns.ts (con .exe).
var proxies = map[string]bool{
	"rundll32": true, "regsvr32": true, "mshta": true, "wscript": true, "cscript": true,
	"powershell": true, "pwsh": true, "cmd": true, "conhost": true,
	"msiexec": true, "control": true, "explorer": true, "pcalua": true, "forfiles": true,
	"installutil": true, "regasm": true, "regsvcs": true, "odbcconf": true, "cmstp": true,
	"mmc": true, "hh": true, "msbuild": true, "wmic": true, "certutil": true, "bitsadmin": true,
	"schtasks": true, "verclsid": true, "xwizard": true, "mavinject": true, "wuauclt": true,
	"register-cimprovider": true, "presentationhost": true, "ieexec": true, "infdefaultinstall": true,
	"scriptrunner": true, "syncappvpublishingserver": true, "atbroker": true, "diskshadow": true,
	"ftp": true, "runas": true, "wsl": true, "bash": true,
}

// launchers sono le DLL di Windows con una funzione che esegue o apre ciò
// che riceve come argomento (LOLBAS, sezione «Libraries»): con rundll32 il
// file eseguito è l'argomento, non la DLL. Nomi delle funzioni in minuscolo,
// anche nelle forme A e W.
var launchers = map[string][]string{
	"shell32":   {"shellexec_rundll", "shellexec_rundlla", "shellexec_rundllw", "control_rundll", "control_rundlla", "control_rundllw", "control_rundllasuser", "control_rundllasusera", "control_rundllasuserw"},
	"url":       {"fileprotocolhandler", "fileprotocolhandlera", "openurl", "openurla"},
	"ieframe":   {"openurl"},
	"shdocvw":   {"openurl"},
	"zipfldr":   {"routethecall"},
	"advpack":   {"launchinfsection", "launchinfsectionex", "registerocx"},
	"ieadvpack": {"launchinfsection", "launchinfsectionex", "registerocx"},
	"setupapi":  {"installhinfsection", "installhinfsectiona", "installhinfsectionw"},
	"syssetup":  {"setupinfobjectinstallaction"},
	"pcwutl":    {"launchapplication"},
	"dfshim":    {"shopenverbapplication"},
	"mshtml":    {"printhtml"},
	"desk":      {"installscreensaver"},
	"scrobj":    {"generatetypelib"},
	"shimgvw":   {"imageview_fullscreen"},
	"davclnt":   {"davsetcookie"},
	"comsvcs":   {"minidump", "#24"},
}

// maxProxyDepth limita i programmi che ne avviano altri (cmd /c powershell
// ..., conhost cmd /c ...).
const maxProxyDepth = 4

// hasScheme: "javascript:...", "http://...", ma non "C:\...".
func hasScheme(s string) bool {
	i := strings.IndexByte(s, ':')
	return i > 1 && !strings.ContainsAny(s[:i], `\/ .`)
}

// isOption: un argomento che comincia con «/» o «-».
func isOption(s string) bool {
	return strings.HasPrefix(s, "/") || strings.HasPrefix(s, "-")
}

// systemPath: un nome senza cartella (Windows lo cerca nelle cartelle di
// sistema) o un percorso in una delle cartelle di Windows che contengono i
// suoi programmi: la cartella di Windows, System32 e SysWOW64 (con wbem e
// WindowsPowerShell\v1.0), Microsoft.NET\Framework*\v... e gli script di
// stampa. Solo allora un programma o una DLL con il nome di uno di Windows
// si tratta come quello: una copia altrove, anche in una sottocartella di
// Windows scrivibile dagli utenti (Temp, Tasks, tracing...), è il file
// eseguito e si verifica.
func systemPath(p string) bool {
	p = strings.Trim(strings.TrimSpace(p), `"`)
	if !strings.ContainsAny(p, `\/`) {
		return true
	}
	l := strings.ToLower(strings.ReplaceAll(p, "/", `\`))
	rest := ""
	switch {
	case strings.HasPrefix(l, `%systemroot%\`), strings.HasPrefix(l, `%windir%\`), strings.HasPrefix(l, `\systemroot\`):
		rest = l[strings.IndexByte(l[1:], '\\')+2:]
	case strings.HasPrefix(l, `system32\`), strings.HasPrefix(l, `syswow64\`):
		rest = l
	case len(l) > 3 && l[1] == ':' && strings.HasPrefix(l[2:], `\windows\`):
		rest = l[len(`c:\windows\`):]
	default:
		return false
	}
	// «..» e «.» si risolvono: C:\Windows\Temp\..\System32 è System32,
	// C:\Windows\..\x non è più nella cartella di Windows.
	rest = path.Clean(strings.ReplaceAll(rest, `\`, "/"))
	if rest == ".." || strings.HasPrefix(rest, "../") {
		return false
	}
	dir := strings.ReplaceAll(dirOf(rest), "/", `\`)
	if dir == "." {
		dir = ""
	}
	switch dir {
	case "", "system32", "syswow64", `system32\wbem`, `syswow64\wbem`, `system32\windowspowershell\v1.0`, `syswow64\windowspowershell\v1.0`:
		return true
	}
	// Una sola cartella sotto queste (la versione, la lingua).
	for _, pre := range []string{`microsoft.net\framework\`, `microsoft.net\framework64\`, `system32\printing_admin_scripts\`, `syswow64\printing_admin_scripts\`} {
		if strings.HasPrefix(dir, pre) && !strings.Contains(dir[len(pre):], `\`) && len(dir) > len(pre) {
			return true
		}
	}
	return false
}

// proxyPath: dove un programma avviato da un altro (cmd /c ..., conhost,
// ShellExec_RunDLL) è quello di Windows con quel nome: le cartelle di
// sistema (systemPath) e, per PowerShell 7, la sua cartella in Program Files.
func proxyPath(p string) bool {
	if systemPath(p) {
		return true
	}
	l := strings.ToLower(strings.ReplaceAll(strings.Trim(strings.TrimSpace(p), `"`), "/", `\`))
	if stem(l) != "pwsh" {
		return false
	}
	d := dirOf(l) + `\`
	for _, pre := range []string{`%programfiles%\powershell\`, `c:\program files\powershell\`} {
		// Una sola cartella sotto, la versione (PowerShell\7\pwsh.exe).
		if v := strings.TrimSuffix(strings.TrimPrefix(d, pre), `\`); strings.HasPrefix(d, pre) && v != "" && !strings.Contains(v, `\`) {
			return true
		}
	}
	return false
}

// ProxyTarget estrae dagli argomenti di un programma di sistema che esegue
// altro (proxies) il file che esegue davvero. proxy dice se file è uno di
// quei programmi usato in quel modo (msiexec e wuauclt lo sono solo con le
// opzioni che eseguono un pacchetto o una DLL: il servizio di Windows
// Installer è «msiexec.exe /V»); target è "" quando esegue un comando
// scritto negli argomenti, un indirizzo o un file che non si verifica con
// la firma (powershell -Command, mshta javascript:..., regsvr32 /i:URL
// scrobj.dll, cmstp file.inf): un comando interpretato, da controllare.
func ProxyTarget(file, args string) (target string, proxy bool) {
	return proxyTarget(file, args, 0)
}

func proxyTarget(file, args string, depth int) (string, bool) {
	name := stem(strings.Trim(strings.TrimSpace(file), `"`))
	if !proxies[name] {
		return "", false
	}
	args = strings.TrimSpace(args)
	t := tokens(args)
	switch name {
	case "msiexec":
		return msiexecTarget(t)
	case "wuauclt":
		// /UpdateDeploymentProvider x.dll /RunHandlerComServer carica la DLL.
		if v, ok := valueAfter(t, "/updatedeploymentprovider"); ok {
			return v, true
		}
		return "", false
	}
	if len(t) == 0 {
		return "", true
	}
	switch name {
	case "rundll32":
		return rundll32Target(args, t, depth), true
	case "regsvr32":
		return regsvr32Target(t), true
	case "mshta":
		if hasScheme(t[0].text) {
			return "", true
		}
		return t[0].text, true
	case "wscript", "cscript":
		for i, x := range t {
			if strings.HasPrefix(x.text, "/") {
				continue
			}
			// Script di Windows che eseguono ciò che ricevono (T1216).
			if s := stem(x.text); (s == "pubprn" || s == "syncappvpublishingserver") && systemPath(x.text) && i+1 < len(t) {
				return "", true
			}
			return x.text, true
		}
		return "", true
	case "powershell", "pwsh":
		return powershellTarget(t), true
	case "cmd":
		return cmdTarget(args, t, depth), true
	case "conhost":
		return conhostTarget(args, t, depth), true
	case "control":
		// control.exe x.cpl (o una DLL caricata come pannello).
		return fileArg(t[0].text), true
	case "explorer":
		// explorer.exe x.exe apre (cioè esegue) il file; le opzioni (/n,
		// /select,..., /factory,...) si saltano.
		for _, x := range t {
			if !isOption(x.text) {
				return launched(x.text, "", depth), true
			}
		}
		return "", true
	case "mmc":
		for _, x := range t {
			if !isOption(x.text) {
				if strings.EqualFold(extOf(x.text), ".msc") {
					return x.text, true
				}
				return "", true
			}
		}
		return "", true
	case "pcalua":
		// pcalua -a programma [-c argomenti].
		if v, ok := valueAfter(t, "-a"); ok {
			return launched(v, "", depth), true
		}
		return "", true
	case "installutil", "regasm", "regsvcs":
		for _, x := range t {
			if !isOption(x.text) {
				return fileArg(x.text), true
			}
		}
		return "", true
	case "register-cimprovider":
		if v, ok := valueAfter(t, "-path"); ok {
			return fileArg(v), true
		}
		return "", true
	case "mavinject":
		if v, ok := valueAfter(t, "/injectrunning"); ok {
			return fileArg(v), true
		}
		return "", true
	case "odbcconf":
		// odbcconf /a {REGSVR x.dll}: registra (cioè carica) la DLL.
		for i, x := range t {
			if strings.EqualFold(strings.TrimLeft(x.text, "{"), "regsvr") && i+1 < len(t) {
				return fileArg(strings.TrimRight(t[i+1].text, "}")), true
			}
		}
		return "", true
	}
	// Gli altri eseguono un comando, un file INF, un progetto o un indirizzo:
	// nessun file da verificare con la firma.
	return "", true
}

// fileArg: l'argomento se indica un file eseguibile (anche «desk.cpl,,1»);
// "" per indirizzi, cartelle, nomi e comandi.
func fileArg(s string) string {
	if hasScheme(s) {
		return ""
	}
	if i := strings.IndexByte(s, ','); i > 0 {
		s = s[:i]
	}
	if hasExecExt(s) {
		return s
	}
	return ""
}

// launched: il file eseguito quando un programma ne apre un altro, x, con
// gli argomenti rest (rundll32 shell32.dll,ShellExec_RunDLL, explorer,
// pcalua -a). Se x è a sua volta un programma di Windows che esegue altro
// (cmd.exe /c ..., powershell.exe -enc ...), conta ciò che esegue quello:
// senza i suoi argomenti è un comando interpretato.
func launched(x, rest string, depth int) string {
	f := fileArg(x)
	if f != "" && depth < maxProxyDepth && proxyPath(f) {
		if inner, proxy := proxyTarget(f, rest, depth+1); proxy {
			return inner
		}
	}
	return f
}

// valueAfter: il valore che segue l'opzione indicata (senza maiuscole).
func valueAfter(t []token, option string) (string, bool) {
	for i, x := range t {
		if strings.EqualFold(x.text, option) {
			if i+1 < len(t) {
				return t[i+1].text, true
			}
			return "", true
		}
	}
	return "", false
}

// rundll32Target: la DLL, dopo le opzioni (/d nelle attività di Windows:
// «/d srrstr.dll,ExecuteScheduledSPPCreation»). -sta e -localserver
// attivano un oggetto COM dal CLSID: il file non è negli argomenti. Con una
// DLL lanciatrice di Windows (launchers) il file eseguito è l'argomento
// (launched). args è il testo a cui si riferiscono le posizioni di t.
func rundll32Target(args string, t []token, depth int) string {
	for len(t) > 0 && !t[0].quoted && isOption(t[0].text) {
		if o := strings.ToLower(t[0].text); o == "-sta" || o == "-localserver" {
			return ""
		}
		t = t[1:]
	}
	if len(t) == 0 {
		return ""
	}
	first := t[0].text
	if hasScheme(first) {
		return ""
	}
	dll, fn, rest := first, "", t[1:]
	if i := strings.IndexByte(first, ','); i >= 0 {
		dll, fn = first[:i], strings.TrimSpace(first[i+1:])
		if fn == "" && len(rest) > 0 {
			fn, rest = rest[0].text, rest[1:]
		}
	} else if len(rest) > 0 {
		fn, rest = rest[0].text, rest[1:]
	}
	dll = strings.TrimSpace(dll)
	if len(rest) > 0 && systemPath(dll) {
		fn = strings.ToLower(strings.TrimSpace(fn))
		for _, f := range launchers[stem(dll)] {
			if fn == f {
				return launched(rest[0].text, args[rest[0].end:], depth)
			}
		}
	}
	return dll
}

// regsvr32Target: la DLL registrata. Con /i: la funzione DllInstall riceve
// un argomento: un indirizzo, o qualsiasi valore con scrobj.dll (lo
// scriptlet, «Squiblydoo», T1218.010), è codice che non si verifica con la
// firma. Gli altri valori di /i: (/i:U shell32.dll di Windows) lasciano la
// DLL.
func regsvr32Target(t []token) string {
	dll, install, remote := "", false, false
	for _, x := range t {
		low := strings.ToLower(x.text)
		switch {
		case strings.HasPrefix(low, "/i:") || strings.HasPrefix(low, "-i:"):
			install = true
			remote = remote || hasScheme(strings.Trim(x.text[3:], `"`))
		case isOption(x.text):
		case dll == "":
			dll = x.text
		}
	}
	if install && (remote || stem(dll) == "scrobj" && systemPath(dll)) {
		return ""
	}
	return dll
}

// msiexecTarget: /i, /package, /a, /j..., /y, /z, /p e /update eseguono un
// pacchetto o una DLL (T1218.007); un indirizzo è un comando interpretato.
// Senza quelle opzioni (il servizio msiserver «msiexec.exe /V», /x di
// disinstallazione) msiexec non esegue codice indicato negli argomenti.
func msiexecTarget(t []token) (string, bool) {
	for i, x := range t {
		o := strings.ToLower(x.text)
		if len(o) < 2 || !isOption(o) {
			continue
		}
		switch o[1:] {
		case "i", "package", "a", "j", "jm", "ju", "y", "z", "p", "update":
			if i+1 >= len(t) || hasScheme(t[i+1].text) {
				return "", true
			}
			v := t[i+1].text
			switch strings.ToLower(extOf(v)) {
			case ".msi", ".msp", ".dll", ".ocx", ".exe":
				return v, true
			}
			return "", true
		}
	}
	return "", false
}

// powershellTarget cerca lo script di -File (o il primo argomento .ps1);
// -Command, -EncodedCommand o un comando scritto direttamente non hanno file.
func powershellTarget(t []token) string {
	// Parametri che prendono un valore (abbreviazioni ammesse da PowerShell).
	valued := []string{"executionpolicy", "ep", "windowstyle", "version", "psconsolefile", "inputformat", "outputformat", "configurationname", "workingdirectory", "wd", "settingsfile", "custompipename"}
	isPrefix := func(name, full string, minLen int) bool {
		return len(name) >= minLen && strings.HasPrefix(full, name)
	}
	for i := 0; i < len(t); i++ {
		x := t[i].text
		if !t[i].quoted && isOption(x) && len(x) > 1 {
			name := strings.ToLower(strings.TrimLeft(x, "-/"))
			if j := strings.IndexByte(name, ':'); j >= 0 {
				name = name[:j]
			}
			switch {
			case isPrefix(name, "file", 1):
				if i+1 < len(t) {
					return t[i+1].text
				}
				return ""
			case isPrefix(name, "command", 1), isPrefix(name, "encodedcommand", 1), name == "ec":
				return ""
			}
			for _, v := range valued {
				// -w e -v sono le abbreviazioni di -WindowStyle e -Version.
				if name == v || (len(name) >= 2 || name == "w" || name == "v") && strings.HasPrefix(v, name) {
					i++
					break
				}
			}
			continue
		}
		if strings.EqualFold(extOf(x), ".ps1") {
			return x
		}
		return ""
	}
	return ""
}

// cmdTarget: il programma o lo script eseguito da cmd /c (o /k), anche
// attraverso start e call. I comandi interni di cmd non hanno file.
func cmdTarget(args string, t []token, depth int) string {
	rest := ""
	for _, x := range t {
		if strings.EqualFold(x.text, "/c") || strings.EqualFold(x.text, "/k") || strings.EqualFold(x.text, "/r") {
			rest = args[x.end:]
			break
		}
	}
	rest = strings.TrimSpace(rest)
	in := tokens(rest)
	for len(in) > 0 && (strings.EqualFold(in[0].text, "call") || strings.HasPrefix(in[0].text, "/")) {
		in = in[1:]
	}
	if len(in) > 0 && strings.EqualFold(in[0].text, "start") {
		in = in[1:]
		// Il primo argomento fra virgolette di start è il titolo della finestra.
		if len(in) > 1 && in[0].quoted {
			in = in[1:]
		}
		for len(in) > 0 && strings.HasPrefix(in[0].text, "/") {
			in = in[1:]
		}
	}
	return runTarget(rest, in, depth)
}

// conhostTarget: conhost.exe [--headless] [--width n ...] comando (T1202):
// il comando dopo le opzioni.
func conhostTarget(args string, t []token, depth int) string {
	rest, in := args, t
	for len(in) > 0 {
		o := strings.ToLower(in[0].text)
		if !strings.HasPrefix(o, "-") && !strings.HasPrefix(o, "0x") {
			break
		}
		skip := 1
		switch o {
		case "--width", "--height", "--signal", "--server", "--feature":
			skip = 2
		}
		if skip > len(in) {
			skip = len(in)
		}
		rest = args[in[skip-1].end:]
		in = in[skip:]
	}
	rest = strings.TrimSpace(rest)
	return runTarget(rest, tokens(rest), depth)
}

// runTarget: il file eseguito da un comando scritto per intero il cui primo
// argomento è in[0] (rest è il testo a cui si riferiscono le posizioni di
// in). Se il programma è a sua volta un programma di sistema che esegue
// altro (cmd /c powershell ..., cmd /c wscript x.vbs), conta ciò che esegue
// quello; i comandi interni, gli indirizzi e i nomi senza estensione non
// hanno file.
func runTarget(rest string, in []token, depth int) string {
	if len(in) == 0 {
		return ""
	}
	x := in[0].text
	if hasScheme(x) {
		return ""
	}
	if depth < maxProxyDepth && proxyPath(x) {
		if inner, proxy := proxyTarget(x, rest[in[0].end:], depth+1); proxy {
			return inner
		}
	}
	if !strings.ContainsAny(x, `\/`) && !hasExecExt(x) {
		return "" // comando interno (echo, del, copy...) o nome senza estensione
	}
	return x
}
