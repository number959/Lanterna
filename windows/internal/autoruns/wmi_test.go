package autoruns

import (
	"encoding/json"
	"strings"
	"testing"
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
