package autoruns

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestTaskConversions(t *testing.T) {
	for i, want := range map[int]string{0: "event", 1: "time", 2: "daily", 3: "weekly", 4: "monthly", 5: "monthly", 6: "idle", 7: "registration", 8: "boot", 9: "logon", 11: "session", 12: "other", 10: "other"} {
		if TriggerName(i) != want {
			t.Errorf("TriggerName(%d) = %q", i, TriggerName(i))
		}
	}
	// Ora locale con l'ora legale: senza il fuso di Roma si prova un fuso fisso.
	rome, err := time.LoadLocation("Europe/Rome")
	summer := "2026-07-16T06:00:00+02:00"
	if err != nil {
		rome, summer = time.FixedZone("CET", 3600), "2026-07-16T06:00:00+01:00"
	}
	for v, want := range map[float64]string{
		46336.5:   "2026-11-10T12:00:00+01:00", // inverno
		46219.25:  summer,
		0:         "",
		-5:        "",
		1e12:      "",
		45658.999: "2025-01-01T23:58:34+01:00",
	} {
		if got := OADate(v, rome); got != want {
			t.Errorf("OADate(%v) = %q, atteso %q", v, got, want)
		}
	}
	if ResultHex(0) != "0x0" || ResultHex(-2147024894) != "0x80070002" || ResultHex(0x41303) != "0x41303" {
		t.Error("ResultHex")
	}
	for _, c := range []struct {
		uid   string
		group bool
		lt    int
		want  string
	}{
		{"sys", false, 5, "system"}, {"svc", false, 5, "service"}, {"me", false, 3, "user"}, {"me", false, 1, "user"},
		{"", true, 4, "group"}, {"other", false, 3, "user"}, {"other", false, 1, "other"}, {"", false, 0, "other"},
	} {
		if got := runAsOf(c.uid, c.group, c.lt); got != c.want {
			t.Errorf("runAsOf(%q, %v, %d) = %q, atteso %q", c.uid, c.group, c.lt, got, c.want)
		}
	}
}

// Uscita di TasksScript come la scrive ConvertTo-Json: un elenco di un solo
// elemento a volte è un valore.
const tasksJSON = `AVVISO: riga prima del JSON
{"tasks":[
 {"p":"\\Microsoft\\Windows\\Defrag\\ScheduledDefrag","en":true,"hid":false,"last":46336.5,"res":0,"next":46343.04,"trig":[2],
  "exec":[{"path":"%windir%\\system32\\defrag.exe","args":"-c -h -o","wd":""}],"com":[],"lt":5,"rl":1,"uid":"sys","grp":false,"ms":true},
 {"p":"\\OneDrive Reporting Task-S-1-5-21-1111111111-2222222222-3333333333-1001","en":true,"hid":false,"last":0,"res":267011,"next":0,"trig":9,
  "exec":{"path":"%localappdata%\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe","args":"/reporting","wd":""},"com":[],"lt":3,"rl":0,"uid":"me","grp":false,"ms":false},
 {"p":"\\Vendor\\anna aggiorna","en":false,"hid":true,"last":0,"res":-2147024894,"next":0,"trig":[8,9,9],
  "exec":[{"path":"C:\\Windows\\System32\\cmd.exe","args":"/c ver","wd":""},{"path":"C:\\Users\\anna\\AppData\\Roaming\\Vendor\\upd.exe","args":"--mail mario.rossi@example.com","wd":""}],
  "com":"{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}","lt":1,"rl":0,"uid":"other","grp":false,"ms":false},
 {"p":"\\Microsoft\\Windows\\Sistema\\SoloCOM","en":true,"hid":false,"last":0,"res":0,"next":0,"trig":[],"exec":[],"com":["{A}"],"lt":4,"rl":0,"uid":"","grp":true,"ms":true},
 {"p":"\\Altro\\ProfiloAltrui","en":true,"hid":false,"last":0,"res":0,"next":0,"trig":[1],"exec":[{"path":"%LOCALAPPDATA%\\x\\x.exe","args":"","wd":""}],"com":[],"lt":1,"rl":0,"uid":"other","grp":false,"ms":false},
 {"p":"\\Altro\\Relativo","en":true,"hid":false,"last":0,"res":0,"next":0,"trig":[1],"exec":[{"path":"tool.exe","args":"","wd":"C:\\Vendor\\bin"}],"com":[],"lt":3,"rl":0,"uid":"me","grp":false,"ms":false}
],"folders":40,"denied":2,"unreadable":0,"errors":{}}`

func TestParseTasksAndItems(t *testing.T) {
	out, err := parseTasks([]byte(tasksJSON))
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Tasks) != 6 || out.Folders != 40 || out.Denied != 2 {
		t.Fatalf("attività: %+v", out)
	}
	env := newFakeEnv(`C:\Vendor\bin\tool.exe`)
	env.vars["windir"] = `C:\Windows`
	rd := testReader(env)
	com := func(c string) string {
		if c == "{A}" {
			return `%SystemRoot%\System32\sistema.dll`
		}
		return ""
	}
	loc := time.FixedZone("CET", 3600)
	var items []item
	for _, x := range out.Tasks {
		items = append(items, rd.taskItems(x, loc, com))
	}
	d := items[0]
	if d.entry.Name != "ScheduledDefrag" || d.entry.Location != `\Microsoft\Windows\Defrag\ScheduledDefrag` || d.entry.RunAs != "system" || !d.entry.Highest ||
		!d.entry.AuthorMicrosoft || d.entry.LastRun != "2026-11-10T12:00:00+01:00" || d.entry.LastResult != "0x0" || d.file != `C:\Windows\system32\defrag.exe` ||
		!reflect.DeepEqual(d.entry.Triggers, []string{"daily"}) || d.entry.Category != "tasks" || d.entry.Kind != "task" {
		t.Errorf("deframmentazione: %+v %q", d.entry, d.file)
	}
	o := items[1]
	if o.entry.Name != "OneDrive Reporting Task-S-1-5-21-…-1001" || strings.Contains(o.entry.Location, "1111111111") || o.entry.RunAs != "user" ||
		o.entry.LastRun != "" || o.entry.LastResult != "0x41303" || o.file != `C:\Users\anna\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe` || o.unverified {
		t.Errorf("attività con il SID: %+v %q", o.entry, o.file)
	}
	v := items[2]
	if v.entry.Name != "‹utente› aggiorna" || v.entry.Enabled || !v.entry.Hidden || v.entry.LastResult != "0x80070002" ||
		!reflect.DeepEqual(v.entry.Triggers, []string{"boot", "logon"}) || v.entry.RunAs != "other" {
		t.Errorf("attività del fornitore: %+v", v.entry)
	}
	// Si mostra l'azione fuori dalla cartella di Windows, con il conto delle altre.
	if v.file != `C:\Users\anna\AppData\Roaming\Vendor\upd.exe` || v.entry.Command != `%USERPROFILE%\AppData\Roaming\Vendor\upd.exe --mail ‹e-mail› (+2 altre azioni)` {
		t.Errorf("azione mostrata: %q %q", v.file, v.entry.Command)
	}
	c := items[3]
	if c.file != `C:\Windows\System32\sistema.dll` || c.entry.RunAs != "group" || c.entry.Triggers != nil || !strings.Contains(c.entry.Command, "(COM {A})") {
		t.Errorf("azione COM: %+v %q", c.entry, c.file)
	}
	if !items[4].unverified || items[4].file != `%LOCALAPPDATA%\x\x.exe` {
		t.Errorf("profilo di un altro utente: %+v", items[4])
	}
	if items[5].file != `C:\Vendor\bin\tool.exe` {
		t.Errorf("cartella di lavoro: %q", items[5].file)
	}
	// Nessun nome dell'utente o SID completo nelle voci esportate.
	b, _ := json.Marshal([]any{items[0].entry, items[1].entry, items[2].entry, items[3].entry, items[4].entry, items[5].entry})
	for _, bad := range []string{"anna", "mario", "1111111111", `C:\\Users`} {
		if strings.Contains(string(b), bad) {
			t.Errorf("%q nelle voci: %s", bad, b)
		}
	}
	if _, err := parseTasks([]byte("niente")); err == nil {
		t.Error("uscita senza JSON accettata")
	}
	if _, err := parseTasks([]byte("{rotto")); err == nil {
		t.Error("JSON rotto accettato")
	}
	e, err := parseTasks([]byte(`{"errors":{"connect":"0x80070005"}}`))
	if err != nil || e.Errors["connect"] == "" || !deniedCode(e.Errors["connect"]) {
		t.Errorf("connessione negata: %+v %v", e, err)
	}
}

// Lo script non interpola dati e non chiama metodi che modificano le
// attività.
func TestTasksScriptReadOnly(t *testing.T) {
	low := strings.ToLower(TasksScript + WMIScript)
	for _, bad := range []string{".run(", ".runex(", ".stop(", "registertask", "deletetask", "createfolder", "deletefolder", "setsecuritydescriptor", ".enabled=", "put_", "remove-ciminstance", "invoke-cimmethod", "set-ciminstance", "$env:"} {
		if strings.Contains(low, bad) {
			t.Errorf("lo script contiene %q", bad)
		}
	}
	if strings.Contains(TasksScript, "Author=") || strings.Contains(TasksScript, "UserId\"") {
		t.Error("lo script esporta autore o utente")
	}
}
