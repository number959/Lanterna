package autoruns

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"lanterna/internal/scan"
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
		{"", true, 4, "group"}, {"other", false, 3, "other"}, {"", false, 3, "user"}, {"other", false, 1, "other"}, {"", false, 0, "other"},
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

// Attività dei casi trovati dalla revisione.
const tasksFixJSON = `{"tasks":[
 {"p":"\\OneDrive Standalone Update Task-S-1-5-21-1111111111-2222222222-3333333333-1002","en":true,"hid":false,"last":46336.5,"res":0,"next":0,"trig":[9],
  "exec":[{"path":"%localappdata%\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe","args":"","wd":""}],"com":[],"lt":3,"rl":0,"uid":"other","grp":false,"ms":false},
 {"p":"\\MaiEseguita","en":true,"hid":false,"last":46336.5,"res":267011,"next":0,"trig":[1],"exec":[{"path":"C:\\x\\a.exe","args":"","wd":""}],"com":[],"lt":3,"rl":0,"uid":"me","grp":false,"ms":false},
 {"p":"\\DataSimbolica","en":true,"hid":false,"last":36494,"res":0,"next":0,"trig":[1],"exec":[{"path":"C:\\x\\a.exe","args":"","wd":""}],"com":[],"lt":3,"rl":0,"uid":"me","grp":false,"ms":false},
 {"p":"\\Backup","en":true,"hid":false,"last":0,"res":0,"next":0,"trig":[2],"exec":[{"path":"powershell","args":"-ExecutionPolicy Bypass -File C:\\Scripts\\backup.ps1","wd":""}],"com":[],"lt":5,"rl":1,"uid":"sys","grp":false,"ms":false},
 {"p":"\\Vendor\\Relativi","en":true,"hid":false,"last":0,"res":0,"next":0,"trig":[2],"exec":[
   {"path":"powershell.exe","args":"-ExecutionPolicy Bypass -File update.ps1","wd":"C:\\ProgramData\\Vendor"},
   {"path":"wscript.exe","args":"x.vbs","wd":"%ProgramData%\\Vendor\\"},
   {"path":"cmd.exe","args":"/c run.bat","wd":"C:\\ProgramData\\Vendor"}],"com":[],"lt":5,"rl":1,"uid":"sys","grp":false,"ms":false},
 {"p":"\\Due\\ProxyNellaSeconda","en":true,"hid":false,"last":0,"res":0,"next":0,"trig":[9],"exec":[
   {"path":"C:\\Windows\\System32\\defrag.exe","args":"-c","wd":""},
   {"path":"C:\\Windows\\System32\\rundll32.exe","args":"C:\\Users\\anna\\AppData\\Local\\evil.dll,Start","wd":""}],"com":[],"lt":3,"rl":0,"uid":"me","grp":false,"ms":false},
 {"p":"\\Due\\TutteInWindows","en":true,"hid":false,"last":0,"res":0,"next":0,"trig":[9],"exec":[
   {"path":"C:\\Windows\\System32\\notepad.exe","args":"","wd":""},
   {"path":"C:\\Windows\\Tasks\\upd.exe","args":"","wd":""}],"com":[],"lt":3,"rl":0,"uid":"me","grp":false,"ms":false},
 {"p":"\\AltroUtente\\CartellaDiLavoro","en":true,"hid":false,"last":0,"res":0,"next":0,"trig":[9],"exec":[
   {"path":"upd.exe","args":"","wd":"%LOCALAPPDATA%\\Vendor"},
   {"path":"powershell.exe","args":"-File agg.ps1","wd":"%APPDATA%\\Vendor"},
   {"path":"cmd.exe","args":"/c C:\\ProgramData\\Vendor\\run.bat","wd":"%LOCALAPPDATA%\\Vendor"}],"com":[],"lt":3,"rl":0,"uid":"other","grp":false,"ms":false}
],"folders":3,"denied":0,"unreadable":0,"broken":0,"errors":{}}`

func TestTaskFixes(t *testing.T) {
	out, err := parseTasks([]byte(tasksFixJSON))
	if err != nil {
		t.Fatal(err)
	}
	env := newFakeEnv(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `C:\Windows\System32\wscript.exe`, `C:\Windows\System32\cmd.exe`,
		`C:\ProgramData\Vendor\update.ps1`, `C:\ProgramData\Vendor\x.vbs`, `C:\ProgramData\Vendor\run.bat`)
	rd := testReader(env)
	loc := time.FixedZone("CET", 3600)
	var items []item
	for _, x := range out.Tasks {
		items = append(items, rd.taskItems(x, loc, nil))
	}
	// B4: l'attività InteractiveToken di un altro utente gira con il suo
	// profilo: non si espande con quello di chi usa Polaris.
	if o := items[0]; o.entry.RunAs != "other" || !o.unverified || o.file != `%localappdata%\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe` {
		t.Errorf("attività di un altro utente: runAs %q, non verificata %v, file %q", o.entry.RunAs, o.unverified, o.file)
	}
	// B9: mai eseguita, per l'esito o per la data simbolica del 1999.
	if items[1].entry.LastRun != "" || items[2].entry.LastRun != "" || items[1].entry.LastResult != "0x41303" {
		t.Errorf("mai eseguita: %q %q", items[1].entry.LastRun, items[2].entry.LastRun)
	}
	// B-M1: programma senza estensione e script .ps1 negli argomenti.
	if b := items[3]; b.file != `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` || b.target != `C:\Scripts\backup.ps1` {
		t.Errorf("powershell senza estensione: file %q, target %q", b.file, b.target)
	}
	// B7: lo script relativo si cerca nella cartella di lavoro.
	r := items[4]
	got := []string{r.target}
	for _, a := range r.others {
		got = append(got, a.target)
	}
	if !reflect.DeepEqual(got, []string{`C:\ProgramData\Vendor\update.ps1`, `C:\ProgramData\Vendor\x.vbs`, `C:\ProgramData\Vendor\run.bat`}) {
		t.Errorf("file relativi alla cartella di lavoro: %q", got)
	}
	// B6: si sceglie l'azione il cui file eseguito sta fuori da Windows.
	if p := items[5]; p.file != `C:\Windows\System32\rundll32.exe` || p.target != `C:\Users\anna\AppData\Local\evil.dll` || len(p.others) != 1 ||
		!strings.HasSuffix(p.entry.Command, "(+1 altra azione)") {
		t.Errorf("azione con rundll32: %+v", p)
	}
	// B6: tutte le azioni in Windows; dopo la verifica la seconda è senza
	// firma e si mostra quella, non la prima di Microsoft.
	w := items[6]
	if w.file != `C:\Windows\System32\notepad.exe` || len(w.others) != 1 {
		t.Fatalf("due azioni in Windows: %+v", w)
	}
	w.entry.File = msFile("windows")
	w.others[0].entry.File = &scan.FileFacts{Path: `C:\Windows\Tasks\upd.exe`, Folder: "windows", Signature: &scan.FileSignature{Status: "unsigned"}}
	entries, counts := assemble([]item{w})
	if len(entries) != 1 || entries[0].File.Path != `C:\Windows\Tasks\upd.exe` || counts["tasks"].Microsoft != 0 ||
		!strings.HasPrefix(entries[0].Command, `C:\Windows\Tasks\upd.exe`) {
		t.Errorf("seconda azione senza firma nascosta: %+v %+v", entries, counts)
	}
	// Attività di un altro utente con la cartella di lavoro nel suo profilo:
	// il programma senza cartella e lo script relativo non si cercano con il
	// profilo di chi usa Polaris; il resto si verifica.
	env.files[strings.ToLower(`C:\Users\anna\AppData\Local\Vendor\upd.exe`)] = true
	env.files[strings.ToLower(`C:\Users\anna\AppData\Roaming\Vendor\agg.ps1`)] = true
	o := rd.taskItems(out.Tasks[7], loc, nil)
	byFile := map[string]item{}
	for _, a := range append([]item{o}, o.others...) {
		byFile[a.file] = a
	}
	up, ps, cm := byFile["upd.exe"], byFile["powershell.exe"], byFile[`C:\Windows\System32\cmd.exe`]
	if len(byFile) != 3 || !up.unverified || !ps.unverified || ps.target != "agg.ps1" || cm.unverified || cm.target != `C:\ProgramData\Vendor\run.bat` {
		for f, a := range byFile {
			t.Errorf("azione di un altro utente: file %q, target %q, non verificata %v", f, a.target, a.unverified)
		}
	}
	// Tutte di Microsoft: la voce si nasconde.
	w.others[0].entry.File = msFile("windows")
	if entries, counts := assemble([]item{w}); len(entries) != 0 || counts["tasks"].Microsoft != 1 {
		t.Errorf("attività di Windows con due azioni: %+v %+v", entries, counts)
	}
}

// B10: l'accesso negato e gli altri errori dello script restano separati.
func TestTasksSource(t *testing.T) {
	rd := testReader(newFakeEnv())
	res := rd.tasksSource(&tasksOut{Broken: 2}, time.UTC, nil)
	if res.denied != nil || res.err == nil || !strings.Contains(res.err.Error(), "2 non lette per un errore diverso dai permessi") {
		t.Errorf("attività danneggiate: negati %v, errore %v", res.denied, res.err)
	}
	if res := rd.tasksSource(&tasksOut{Unreadable: 1}, time.UTC, nil); !reflect.DeepEqual(res.denied, []string{"tasks"}) || res.err != nil {
		t.Errorf("attività negate: %+v", res)
	}
	if res := rd.tasksSource(&tasksOut{Errors: map[string]string{"connect": "0x80070005"}}, time.UTC, nil); !reflect.DeepEqual(res.denied, []string{"tasks"}) || res.err != nil {
		t.Errorf("connessione negata: %+v", res)
	}
	if res := rd.tasksSource(&tasksOut{Errors: map[string]string{"connect": "0x800706BA"}}, time.UTC, nil); res.err == nil || res.denied != nil {
		t.Errorf("servizio non raggiungibile: %+v", res)
	}
	// B11 e B12: il codice è quello COM interno e gli account si confrontano
	// anche per SID (nomi localizzati).
	for _, want := range []string{"InnerException", ".Translate([Security.Principal.SecurityIdentifier])", "$r.broken=$nb", "-2147024891", "$mysid"} {
		if !strings.Contains(TasksScript, want) {
			t.Errorf("lo script non contiene %q", want)
		}
	}
	if strings.Contains(TasksScript, "$_.Exception.HResult") {
		t.Error("codice dell'errore preso dall'eccezione di PowerShell")
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
