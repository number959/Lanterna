package autoruns

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"lanterna/internal/scan"
	"lanterna/internal/sign"
)

// TasksScript elenca le attività pianificate con l'oggetto COM documentato
// «Schedule.Service» (Task Scheduler 2.0): Connect() sul computer locale con
// l'utente corrente, visita di tutte le cartelle da GetFolder('\') con
// GetFolders(0) e GetTasks(1), che comprende le attività nascoste
// (TASK_ENUM_HIDDEN). Si leggono solo proprietà: nessun metodo che avvia,
// ferma, modifica o registra un'attività.
//
// Per ogni attività esce solo: percorso, abilitata, nascosta, ultima e
// prossima esecuzione (come data OLE, convertita in Go), esito
// dell'ultima esecuzione, tipi numerici dei trigger, azioni Exec (Path,
// Arguments, WorkingDirectory) e ClassId delle azioni COM, tipo di accesso,
// livello di esecuzione, chi la esegue come categoria (sys, svc, me, other:
// mai il nome) e se l'autore dichiara Microsoft (solo il sì o no, mai il
// testo dell'autore). Le cartelle e le attività non leggibili si contano.
// Lo script non riceve dati dall'esterno.
const TasksScript = `$ErrorActionPreference='Stop';try{[Console]::OutputEncoding=[Text.Encoding]::UTF8}catch{};$r=[ordered]@{};$e=[ordered]@{};` +
	`$me=[Security.Principal.WindowsIdentity]::GetCurrent();$mine=@("$($me.User.Value)","$($me.Name)",("$($me.Name)" -split '\\')[-1])|Where-Object{$_};` +
	// Chi esegue l'attività, come categoria: sys (SYSTEM), svc (LOCAL SERVICE,
	// NETWORK SERVICE), me (chi usa Polaris), other; "" se non indicato.
	`$who={param($u) if(-not $u){return ''};$l=$u.ToLowerInvariant();` +
	`if($l -eq 's-1-5-18' -or $l -eq 'system' -or $l -eq 'localsystem' -or $l -eq 'nt authority\system'){return 'sys'};` +
	`if($l -eq 's-1-5-19' -or $l -eq 's-1-5-20' -or $l -like '*local service' -or $l -like '*network service' -or $l -like '*localservice' -or $l -like '*networkservice'){return 'svc'};` +
	`foreach($x in $mine){if($l -eq $x.ToLowerInvariant()){return 'me'}};return 'other'};` +
	`$od={param($d) try{if($d -and $d.Year -gt 1980){[double]$d.ToOADate()}else{[double]0}}catch{[double]0}};` +
	`try{$s=New-Object -ComObject Schedule.Service;$s.Connect();` +
	`$list=New-Object System.Collections.ArrayList;$nf=0;$nd=0;$ne=0;$q=New-Object System.Collections.Queue;$q.Enqueue($s.GetFolder('\'));` +
	`while($q.Count -gt 0){$f=$q.Dequeue();$nf++;` +
	`try{foreach($t in @($f.GetTasks(1))){try{$d=$t.Definition;$p=$d.Principal;$au="$($d.RegistrationInfo.Author)";` +
	`$x=[ordered]@{p="$($t.Path)";en=[bool]$t.Enabled;hid=[bool]$d.Settings.Hidden;last=(&$od $t.LastRunTime);res=[long]$t.LastTaskResult;next=(&$od $t.NextRunTime);` +
	`trig=@(@($d.Triggers)|ForEach-Object{[int]$_.Type});` +
	`exec=@(@($d.Actions)|Where-Object{[int]$_.Type -eq 0}|ForEach-Object{[ordered]@{path="$($_.Path)";args="$($_.Arguments)";wd="$($_.WorkingDirectory)"}});` +
	`com=@(@($d.Actions)|Where-Object{[int]$_.Type -eq 5}|ForEach-Object{"$($_.ClassId)"});` +
	`lt=[int]$p.LogonType;rl=[int]$p.RunLevel;uid=(&$who "$($p.UserId)");grp=[bool]("$($p.GroupId)");` +
	// Le attività di Windows hanno come autore una risorsa di sistema
	// «$(@%SystemRoot%\...)» (forma osservata): conta come dichiarazione di Microsoft.
	`ms=[bool]($au -match 'Microsoft' -or $au -like '$(@%SystemRoot%\*')};[void]$list.Add($x)}catch{$ne++}}}catch{$nd++};` +
	`try{foreach($c in @($f.GetFolders(0))){$q.Enqueue($c)}}catch{$nd++}};` +
	`$r.tasks=$list;$r.folders=$nf;$r.denied=$nd;$r.unreadable=$ne}catch{$e.connect=('0x{0:X8}' -f $_.Exception.HResult)};` +
	`$r.errors=$e;ConvertTo-Json -Compress -Depth 6 -InputObject $r`

// list accetta in JSON sia un valore sia un elenco (ConvertTo-Json di
// PowerShell a volte scrive un elenco di un solo elemento come valore).
type list[T any] []T

func (l *list[T]) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "null" {
		*l = nil
		return nil
	}
	if strings.HasPrefix(s, "[") {
		var v []T
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		*l = v
		return nil
	}
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*l = []T{v}
	return nil
}

type psExec struct {
	Path string `json:"path"`
	Args string `json:"args"`
	WD   string `json:"wd"`
}

type psTask struct {
	Path    string       `json:"p"`
	Enabled bool         `json:"en"`
	Hidden  bool         `json:"hid"`
	Last    float64      `json:"last"`
	Result  int64        `json:"res"`
	Next    float64      `json:"next"`
	Trig    list[int]    `json:"trig"`
	Exec    list[psExec] `json:"exec"`
	Com     list[string] `json:"com"`
	Logon   int          `json:"lt"`
	Level   int          `json:"rl"`
	UID     string       `json:"uid"`
	Group   bool         `json:"grp"`
	MS      bool         `json:"ms"`
}

type tasksOut struct {
	Tasks      list[psTask]      `json:"tasks"`
	Folders    int               `json:"folders"`
	Denied     int               `json:"denied"`
	Unreadable int               `json:"unreadable"`
	Errors     map[string]string `json:"errors"`
}

// jsonStart salta le righe di avviso prima del JSON.
func jsonStart(out []byte) ([]byte, error) {
	s := string(out)
	i := strings.Index(s, "{")
	if i < 0 {
		return nil, errors.New("nessun dato in uscita")
	}
	return []byte(strings.TrimSpace(s[i:])), nil
}

func parseTasks(out []byte) (*tasksOut, error) {
	b, err := jsonStart(out)
	if err != nil {
		return nil, err
	}
	var t tasksOut
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("uscita non valida: %w", err)
	}
	return &t, nil
}

// TriggerName traduce TASK_TRIGGER_TYPE2 (taskschd.h): 0 evento, 1 ora
// stabilita, 2 giornaliero, 3 settimanale, 4 e 5 mensile, 6 inattività,
// 7 registrazione, 8 avvio, 9 accesso, 11 cambio di sessione.
func TriggerName(t int) string {
	switch t {
	case 0:
		return "event"
	case 1:
		return "time"
	case 2:
		return "daily"
	case 3:
		return "weekly"
	case 4, 5:
		return "monthly"
	case 6:
		return "idle"
	case 7:
		return "registration"
	case 8:
		return "boot"
	case 9:
		return "logon"
	case 11:
		return "session"
	}
	return "other"
}

// OADate converte una data OLE (giorni dal 30/12/1899, ora locale, la
// frazione è l'ora del giorno) in RFC 3339; "" per le date assenti. Il
// giorno si aggiunge con time.Date, che tiene conto dell'ora legale.
func OADate(v float64, loc *time.Location) string {
	if v <= 1 || math.IsNaN(v) || math.IsInf(v, 0) || v > 2958465 {
		return ""
	}
	days := math.Floor(v)
	secs := int(math.Round((v - days) * 86400))
	return time.Date(1899, 12, 30+int(days), 0, 0, secs, 0, loc).Format(time.RFC3339)
}

// ResultHex scrive l'esito dell'ultima esecuzione come HRESULT esadecimale
// ("0x0", "0x80070002").
func ResultHex(v int64) string {
	return fmt.Sprintf("0x%X", uint32(v))
}

// runAsOf riduce chi esegue l'attività a una categoria: system, service,
// user (chi usa Polaris o chiunque abbia effettuato l'accesso, tipo
// InteractiveToken = 3), group, other.
func runAsOf(uid string, group bool, logonType int) string {
	switch {
	case uid == "sys":
		return "system"
	case uid == "svc":
		return "service"
	case uid == "me":
		return "user"
	case group || logonType == 4:
		return "group"
	case logonType == 3:
		return "user"
	}
	return "other"
}

// userVars sono le variabili che cambiano con l'utente: in un'attività che
// gira come un altro utente il file non si può cercare dal profilo di chi
// usa Polaris.
var userVars = []string{"%userprofile%", "%appdata%", "%localappdata%", "%temp%", "%tmp%", "%homepath%", "%homedrive%", "%username%", "%onedrive%"}

func usesUserVars(s string) bool {
	for _, v := range userVars {
		if strings.Contains(strings.ToLower(s), v) {
			return true
		}
	}
	return false
}

// taskItems prepara la voce di un'attività: una sola per attività, con
// l'azione da mostrare (la prima che non sarebbe di Windows, altrimenti la
// prima). com risolve il ClassId di un'azione COM nella DLL registrata.
func (rd reader) taskItems(t psTask, loc *time.Location, com func(string) string) item {
	path := t.Path
	name := baseOf(path)
	if name == "" {
		name = path
	}
	e := scan.AutorunEntry{Category: "tasks", Kind: "task", Name: rd.cl.text(name), Location: rd.cl.text(path), Enabled: t.Enabled}
	seen := map[string]bool{}
	for _, tr := range t.Trig {
		if n := TriggerName(tr); !seen[n] {
			seen[n] = true
			e.Triggers = append(e.Triggers, n)
		}
	}
	e.RunAs = runAsOf(t.UID, t.Group, t.Logon)
	e.Highest = t.Level == 1
	e.Hidden = t.Hidden
	e.AuthorMicrosoft = t.MS
	e.LastRun = OADate(t.Last, loc)
	e.NextRun = OADate(t.Next, loc)
	e.LastResult = ResultHex(t.Result)
	var actions []item
	for _, x := range t.Exec {
		cmd := strings.TrimSpace(x.Path)
		if cmd == "" {
			continue
		}
		if strings.Contains(cmd, " ") && !strings.HasPrefix(cmd, `"`) {
			cmd = `"` + cmd + `"`
		}
		if a := strings.TrimSpace(x.Args); a != "" {
			cmd += " " + a
		}
		it := rd.commandItem(e, cmd, false)
		// Un programma indicato senza cartella si cerca prima nella
		// cartella di lavoro dell'attività.
		if file, _, _ := rd.res.Split(cmd, false); file != "" && !strings.ContainsAny(file, `\/`) && strings.TrimSpace(x.WD) != "" {
			if p := rd.res.Locate(strings.TrimRight(strings.TrimSpace(x.WD), `\`)+`\`+file, false); rd.res.exists(p) {
				it.file = p
			}
		}
		if e.RunAs != "user" && e.RunAs != "group" && usesUserVars(x.Path+" "+x.Args) {
			// Le variabili sono quelle dell'utente dell'attività: il percorso
			// si mostra come è scritto, senza espanderlo con il profilo di chi
			// usa Polaris.
			it.unverified = true
			file, args, _ := rd.res.Split(cmd, false)
			it.file = file
			if t, proxy := ProxyTarget(file, args); proxy {
				it.target = t
			}
		}
		actions = append(actions, it)
	}
	for _, c := range t.Com {
		dll := ""
		if com != nil {
			dll = com(c)
		}
		it := item{entry: e}
		it.entry.Command = "COM " + c
		if dll != "" {
			it.entry.Command = rd.cl.path(dll) + " (COM " + c + ")"
			f, _, _ := rd.res.Split(dll, false)
			it.file = rd.res.Locate(f, false)
		}
		actions = append(actions, it)
	}
	if len(actions) == 0 {
		return item{entry: e}
	}
	// Si mostra la prima azione che non sarebbe nascosta come voce di
	// Windows; la verifica dei file arriva dopo, quindi qui si sceglie la
	// prima con un file fuori dalla cartella di Windows, poi la prima con un
	// comando interpretato o un file non verificabile, altrimenti la prima.
	pick := actions[0]
	found := false
	for _, a := range actions {
		if a.file != "" && !a.unverified && sign.FolderOf(a.file, rd.cl.profile) != "windows" {
			pick, found = a, true
			break
		}
	}
	for _, a := range actions {
		if !found && (a.interpreted || a.unverified || a.file == "") {
			pick, found = a, true
		}
	}
	if len(actions) > 1 {
		pick.entry.Command += fmt.Sprintf(" (+%d %s)", len(actions)-1, plural(len(actions)-1, "altra azione", "altre azioni"))
	}
	return pick
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
