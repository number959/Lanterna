//go:build windows

package autoruns

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/windows/registry"

	"lanterna/internal/pcinfo"
	"lanterna/internal/scan"
)

// Le chiavi si aprono solo per leggere i valori ed elencare le sottochiavi.
// La vista nativa è chiesta in modo esplicito (WOW64_64KEY, ignorata da
// Windows a 32 bit); quella a 32 bit (WOW6432Node) con WOW64_32KEY.
const (
	readAccess = registry.QUERY_VALUE | registry.ENUMERATE_SUB_KEYS
	viewNative = registry.WOW64_64KEY
	view32     = registry.WOW64_32KEY
)

func openKey(root registry.Key, path string, view uint32) (registry.Key, bool) {
	k, err := registry.OpenKey(root, path, readAccess|view)
	return k, err == nil
}

// stringValue legge un valore di testo (REG_SZ o REG_EXPAND_SZ, non espanso).
func stringValue(root registry.Key, path, name string, view uint32) (string, bool) {
	k, ok := openKey(root, path, view)
	if !ok {
		return "", false
	}
	defer k.Close()
	v, _, err := k.GetStringValue(name)
	return v, err == nil
}

func subKeys(root registry.Key, path string, view uint32) []string {
	k, ok := openKey(root, path, view)
	if !ok {
		return nil
	}
	defer k.Close()
	n, _ := k.ReadSubKeyNames(0)
	return n
}

// regPath è il percorso mostrato all'utente, come in Autoruns.
func regPath(root registry.Key, path string, view uint32) string {
	r := "HKLM"
	if root == registry.CURRENT_USER {
		r = "HKCU"
	}
	if view == view32 && hasPrefixFold(path, `SOFTWARE\`) {
		path = `SOFTWARE\WOW6432Node\` + path[len(`SOFTWARE\`):]
	}
	return r + `\` + path
}

// regLoc è regPath passato dal pulitore: le sottochiavi (IFEO,
// SilentProcessExit, RunOnceEx, stampa, provider di rete) hanno nomi scelti
// da chi le ha create, puliti come il nome della voce.
func (rd reader) regLoc(root registry.Key, path string, view uint32) string {
	return rd.cl.text(regPath(root, path, view))
}

func scopeOf(root registry.Key, view uint32) string {
	switch {
	case root == registry.CURRENT_USER:
		return "user"
	case view == view32:
		return "machine32"
	}
	return "machine"
}

// approved legge lo stato abilitato/disattivato delle voci da
// Explorer\StartupApproved, come Gestione attività. Duplicata da
// pcinfo.approved (non esportata), con la stessa interpretazione
// (pcinfo.StartupEnabled): chiave = nome del valore in minuscolo.
func approved(root registry.Key, sub string) map[string]bool {
	out := map[string]bool{}
	k, err := registry.OpenKey(root, `Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\`+sub, registry.QUERY_VALUE)
	if err != nil {
		return out
	}
	defer k.Close()
	names, _ := k.ReadValueNames(0)
	for _, n := range names {
		if b, _, err := k.GetBinaryValue(n); err == nil {
			out[strings.ToLower(n)] = pcinfo.StartupEnabled(b)
		}
	}
	return out
}

// dedupe toglie le voci uguali lette due volte (una chiave condivisa fra la
// vista nativa e quella a 32 bit restituisce gli stessi valori): stessa
// chiave a meno di WOW6432Node, stesso nome e stesso comando.
func dedupe(items []item) []item {
	seen := map[string]bool{}
	out := items[:0]
	for _, it := range items {
		loc := strings.Replace(strings.ToLower(it.entry.Location), `wow6432node\`, "", 1)
		k := strings.ToLower(it.entry.Category+"|"+it.entry.Kind+"|"+it.entry.Name+"|"+it.entry.Command) + "|" + loc
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, it)
	}
	return out
}

type regKey struct {
	root registry.Key
	path string
	view uint32
}

var (
	hkcu = registry.CURRENT_USER
	hklm = registry.LOCAL_MACHINE
)

// readRegistry legge le voci di avvio del registro e delle cartelle
// Esecuzione automatica.
func readRegistry(ctx context.Context, rd reader) sourceResult {
	var items []item
	for _, f := range []func(reader) []item{logonItems, startupFolderItems, winlogonRegItems, hijackItems, lsaRegItems, printItems, networkItems} {
		if ctx.Err() != nil {
			// Tempo scaduto: Collect lo dice già, in italiano (Partial).
			return sourceResult{items: dedupe(items)}
		}
		items = append(items, f(rd)...)
	}
	return sourceResult{items: dedupe(items)}
}

// logonItems: Run, RunOnce, RunOnceEx, Policies\Explorer\Run e il valore
// load.
func logonItems(rd reader) []item {
	var out []item
	const cv = `Software\Microsoft\Windows\CurrentVersion\`
	runKeys := []struct {
		key      regKey
		kind     string
		approved string
	}{
		{regKey{hkcu, cv + "Run", viewNative}, "run", "Run"},
		{regKey{hklm, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, viewNative}, "run", "Run"},
		{regKey{hklm, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, view32}, "run", "Run32"},
		{regKey{hkcu, cv + "RunOnce", viewNative}, "runonce", ""},
		{regKey{hklm, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, viewNative}, "runonce", ""},
		{regKey{hklm, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, view32}, "runonce", ""},
		{regKey{hkcu, cv + `Policies\Explorer\Run`, viewNative}, "policyrun", ""},
		{regKey{hklm, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`, viewNative}, "policyrun", ""},
	}
	for _, rk := range runKeys {
		k, ok := openKey(rk.key.root, rk.key.path, rk.key.view)
		if !ok {
			continue
		}
		ok2 := map[string]bool{}
		if rk.approved != "" {
			ok2 = approved(rk.key.root, rk.approved)
		}
		names, _ := k.ReadValueNames(0)
		scope := scopeOf(rk.key.root, rk.key.view)
		for _, n := range names {
			if n == "" {
				continue
			}
			cmd, _, err := k.GetStringValue(n)
			if err != nil || strings.TrimSpace(cmd) == "" {
				continue
			}
			en, found := ok2[strings.ToLower(n)]
			e := scan.AutorunEntry{Category: "logon", Kind: rk.kind, Scope: scope, Name: rd.cl.text(runName(n)), Location: rd.regLoc(rk.key.root, rk.key.path, rk.key.view), Enabled: !found || en}
			out = append(out, rd.commandItem(e, cmd, scope == "machine32"))
		}
		k.Close()
	}
	// RunOnceEx: sottochiavi con valori «file|funzione|argomenti» o comandi.
	for _, rk := range []regKey{{hkcu, cv + "RunOnceEx", viewNative}, {hklm, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx`, viewNative}, {hklm, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx`, view32}} {
		scope := scopeOf(rk.root, rk.view)
		for _, sub := range subKeys(rk.root, rk.path, rk.view) {
			k, ok := openKey(rk.root, rk.path+`\`+sub, rk.view)
			if !ok {
				continue
			}
			names, _ := k.ReadValueNames(0)
			for _, n := range names {
				if n == "" || strings.EqualFold(n, "Flags") || strings.EqualFold(n, "Title") {
					continue
				}
				v, _, err := k.GetStringValue(n)
				if err != nil || strings.TrimSpace(v) == "" {
					continue
				}
				e := scan.AutorunEntry{Category: "logon", Kind: "runonceex", Scope: scope, Name: rd.cl.text(sub + `\` + n), Location: rd.regLoc(rk.root, rk.path+`\`+sub, rk.view), Enabled: true}
				if cmd, dll := runOnceExFile(v); dll {
					it := rd.fileItem(e, cmd, scope == "machine32")
					it.entry.Command = rd.cl.command(v)
					out = append(out, it)
				} else {
					out = append(out, rd.commandItem(e, cmd, scope == "machine32"))
				}
			}
			k.Close()
		}
	}
	// Il valore load di HKCU\...\Windows NT\CurrentVersion\Windows.
	const winKey = `Software\Microsoft\Windows NT\CurrentVersion\Windows`
	if v, ok := stringValue(hkcu, winKey, "load", viewNative); ok {
		for _, cmd := range splitList(v) {
			e := scan.AutorunEntry{Category: "logon", Kind: "load", Scope: "user", Name: "load", Location: rd.regLoc(hkcu, winKey, viewNative), Enabled: true}
			out = append(out, rd.commandItem(e, cmd, false))
		}
	}
	return out
}

// shellFolder legge una cartella da User Shell Folders (anche reindirizzata),
// espandendo le variabili; fallback se il valore manca.
func shellFolder(root registry.Key, name, fallback string) string {
	if v, ok := stringValue(root, `Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`, name, viewNative); ok && strings.TrimSpace(v) != "" {
		if x, err := registry.ExpandString(v); err == nil && x != "" {
			return x
		}
	}
	return fallback
}

// startupFolderItems: le cartelle Esecuzione automatica dell'utente e comune.
func startupFolderItems(rd reader) []item {
	var out []item
	folders := []struct {
		dir   string
		root  registry.Key
		scope string
	}{
		{shellFolder(hkcu, "Startup", filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`)), hkcu, "user"},
		{shellFolder(hklm, "Common Startup", filepath.Join(os.Getenv("ProgramData"), `Microsoft\Windows\Start Menu\Programs\StartUp`)), hklm, "machine"},
	}
	for _, f := range folders {
		entries, err := os.ReadDir(f.dir)
		if err != nil {
			continue
		}
		ok := approved(f.root, "StartupFolder")
		for _, de := range entries {
			if de.IsDir() || strings.EqualFold(de.Name(), "desktop.ini") {
				continue
			}
			p := filepath.Join(f.dir, de.Name())
			en, found := ok[strings.ToLower(de.Name())]
			name := de.Name()
			name = strings.TrimSuffix(name, filepath.Ext(name))
			e := scan.AutorunEntry{Category: "logon", Kind: "folder", Scope: f.scope, Name: rd.cl.text(name), Location: rd.cl.path(f.dir), Enabled: !found || en}
			var lnk []byte
			if strings.EqualFold(filepath.Ext(p), ".lnk") {
				lnk, _ = readShared(p, 1<<20)
			}
			out = append(out, rd.shortcutItem(e, p, lnk))
		}
	}
	return out
}

// winlogonRegItems: Shell e Userinit di HKLM e HKCU.
func winlogonRegItems(rd reader) []item {
	var out []item
	for _, root := range []registry.Key{hklm, hkcu} {
		path := `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`
		if root == hklm {
			path = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
		}
		for _, v := range []string{"Shell", "Userinit"} {
			if data, ok := stringValue(root, path, v, viewNative); ok && strings.TrimSpace(data) != "" {
				out = append(out, rd.winlogonItems(scopeOf(root, viewNative), regPath(root, path, viewNative), v, data)...)
			}
		}
	}
	return out
}

// hijackItems: IFEO Debugger, SilentProcessExit, BootExecute, AppInit_DLLs.
func hijackItems(rd reader) []item {
	var out []item
	const ifeo = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
	for _, view := range []uint32{viewNative, view32} {
		scope := scopeOf(hklm, view)
		for _, exe := range subKeys(hklm, ifeo, view) {
			paths := []string{ifeo + `\` + exe}
			// Con UseFilter le opzioni stanno in sottochiavi per percorso completo.
			for _, s := range subKeys(hklm, ifeo+`\`+exe, view) {
				paths = append(paths, ifeo+`\`+exe+`\`+s)
			}
			for _, p := range paths {
				if dbg, ok := stringValue(hklm, p, "Debugger", view); ok && strings.TrimSpace(dbg) != "" {
					e := scan.AutorunEntry{Category: "hijacks", Kind: "ifeo", Scope: scope, Name: rd.cl.text(exe), Location: rd.regLoc(hklm, p, view), Enabled: true}
					it := rd.commandItem(e, dbg, view == view32)
					it.hijack = true
					out = append(out, it)
				}
			}
		}
	}
	const spe = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit`
	for _, exe := range subKeys(hklm, spe, viewNative) {
		if mon, ok := stringValue(hklm, spe+`\`+exe, "MonitorProcess", viewNative); ok && strings.TrimSpace(mon) != "" {
			e := scan.AutorunEntry{Category: "hijacks", Kind: "silentexit", Scope: "machine", Name: rd.cl.text(exe), Location: rd.regLoc(hklm, spe+`\`+exe, viewNative), Enabled: true}
			it := rd.commandItem(e, mon, false)
			it.hijack = true
			out = append(out, it)
		}
	}
	const sm = `SYSTEM\CurrentControlSet\Control\Session Manager`
	if k, ok := openKey(hklm, sm, viewNative); ok {
		if vals, _, err := k.GetStringsValue("BootExecute"); err == nil {
			out = append(out, rd.bootExecuteItems(regPath(hklm, sm, viewNative), vals)...)
		}
		k.Close()
	}
	const win = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`
	for _, view := range []uint32{viewNative, view32} {
		k, ok := openKey(hklm, win, view)
		if !ok {
			continue
		}
		dlls, _, err := k.GetStringValue("AppInit_DLLs")
		load, _, _ := k.GetIntegerValue("LoadAppInit_DLLs")
		k.Close()
		if err == nil && strings.TrimSpace(dlls) != "" {
			out = append(out, rd.appInitItems(scopeOf(hklm, view), regPath(hklm, win, view), dlls, load == 1)...)
		}
	}
	return out
}

// lsaRegItems: pacchetti di autenticazione, di sicurezza e di notifica
// delle password.
func lsaRegItems(rd reader) []item {
	var out []item
	const lsa = `SYSTEM\CurrentControlSet\Control\Lsa`
	for _, src := range []struct{ path, value, kind string }{
		{lsa, "Authentication Packages", "lsa-auth"},
		{lsa, "Security Packages", "lsa-security"},
		{lsa + `\OSConfig`, "Security Packages", "lsa-security"},
		{lsa, "Notification Packages", "lsa-notify"},
	} {
		k, ok := openKey(hklm, src.path, viewNative)
		if !ok {
			continue
		}
		vals, _, err := k.GetStringsValue(src.value)
		k.Close()
		if err == nil {
			out = append(out, rd.lsaItems(src.kind, regPath(hklm, src.path, viewNative), vals)...)
		}
	}
	return out
}

// printEnvironment è l'ambiente di stampa nativo (Print\Environments).
func printEnvironment() string {
	switch runtime.GOARCH {
	case "arm64":
		return "Windows ARM64"
	case "386":
		return "Windows NT x86"
	}
	return "Windows x64"
}

// printItems: monitor e processori di stampa (DLL caricate da spoolsv.exe).
func printItems(rd reader) []item {
	var out []item
	const mon = `SYSTEM\CurrentControlSet\Control\Print\Monitors`
	for _, m := range subKeys(hklm, mon, viewNative) {
		if drv, ok := stringValue(hklm, mon+`\`+m, "Driver", viewNative); ok && strings.TrimSpace(drv) != "" {
			e := scan.AutorunEntry{Category: "print", Kind: "printmon", Scope: "machine", Name: rd.cl.text(m), Location: rd.regLoc(hklm, mon+`\`+m, viewNative), Enabled: true}
			out = append(out, rd.fileItem(e, drv, false))
		}
	}
	procs := `SYSTEM\CurrentControlSet\Control\Print\Environments\` + printEnvironment() + `\Print Processors`
	// La cartella dei processori (GetPrintProcessorDirectory) è
	// spool\prtprocs\<ambiente>: si cerca in tutte le sottocartelle presenti.
	base := rd.res.sysRoot() + `\System32\spool\prtprocs`
	var dirs []string
	if des, err := os.ReadDir(base); err == nil {
		for _, d := range des {
			if d.IsDir() {
				dirs = append(dirs, base+`\`+d.Name())
			}
		}
	}
	for _, p := range subKeys(hklm, procs, viewNative) {
		if drv, ok := stringValue(hklm, procs+`\`+p, "Driver", viewNative); ok && strings.TrimSpace(drv) != "" {
			e := scan.AutorunEntry{Category: "print", Kind: "printproc", Scope: "machine", Name: rd.cl.text(p), Location: rd.regLoc(hklm, procs+`\`+p, viewNative), Enabled: true}
			it := item{entry: e}
			it.entry.Command = rd.cl.path(drv)
			it.file = rd.printProcFile(drv, dirs)
			out = append(out, it)
		}
	}
	return out
}

// networkItems: provider di rete in NetworkProvider\Order (ProviderOrder) e
// la DLL di ciascuno (Services\<nome>\NetworkProvider\ProviderPath).
func networkItems(rd reader) []item {
	var out []item
	order, ok := stringValue(hklm, `SYSTEM\CurrentControlSet\Control\NetworkProvider\Order`, "ProviderOrder", viewNative)
	if !ok {
		return nil
	}
	for _, name := range splitList(order) {
		key := `SYSTEM\CurrentControlSet\Services\` + name + `\NetworkProvider`
		p, ok := stringValue(hklm, key, "ProviderPath", viewNative)
		if !ok || strings.TrimSpace(p) == "" {
			continue
		}
		e := scan.AutorunEntry{Category: "network", Kind: "netprovider", Scope: "machine", Name: rd.cl.text(name), Location: rd.regLoc(hklm, key, viewNative), Enabled: true}
		out = append(out, rd.fileItem(e, p, false))
	}
	return out
}

// serviceDll è il file vero di un servizio ospitato da svchost.exe:
// ServiceDll in Parameters, altrimenti nella chiave del servizio.
func serviceDll(name string) string {
	base := `SYSTEM\CurrentControlSet\Services\` + name
	for _, p := range []string{base + `\Parameters`, base} {
		if v, ok := stringValue(hklm, p, "ServiceDll", viewNative); ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// comDLL è il file registrato per un ClassId COM (CLSID\{...}\InprocServer32,
// valore predefinito, o LocalServer32 per un server in un processo a sé): il
// file eseguito da un'azione COM di un'attività.
func comDLL(clsid string) string {
	clsid = strings.TrimSpace(clsid)
	if clsid == "" {
		return ""
	}
	if !strings.HasPrefix(clsid, "{") {
		clsid = "{" + clsid + "}"
	}
	for _, sub := range []string{"InprocServer32", "LocalServer32"} {
		if v, ok := stringValue(registry.CLASSES_ROOT, `CLSID\`+clsid+`\`+sub, "", viewNative); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// policyIDs sono gli ID delle estensioni imposte da ExtensionInstallForcelist
// (HKLM e HKCU).
func policyIDs(path string) map[string]bool {
	out := map[string]bool{}
	for _, root := range []registry.Key{hklm, hkcu} {
		k, ok := openKey(root, path, viewNative)
		if !ok {
			continue
		}
		names, _ := k.ReadValueNames(0)
		for _, n := range names {
			if v, _, err := k.GetStringValue(n); err == nil {
				if id := ParseForcelist(v); id != "" {
					out[id] = true
				}
			}
		}
		k.Close()
	}
	return out
}
