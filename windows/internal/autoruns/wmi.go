package autoruns

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"lanterna/internal/scan"
)

// WMIScript legge le sottoscrizioni WMI permanenti nei namespace
// root/subscription e root/default: filtri (__EventFilter), consumatori
// (__EventConsumer, con le sottoclassi CommandLineEventConsumer,
// ActiveScriptEventConsumer, NTEventLogEventConsumer, LogFileEventConsumer,
// SMTPEventConsumer) e collegamenti (__FilterToConsumerBinding), con
// Get-CimInstance e 10 secondi al massimo per interrogazione. Solo letture:
// mai Remove-CimInstance o Invoke-CimMethod.
//
// Per ogni consumatore esce la classe, il nome, se è collegato a un filtro
// esistente, per CommandLine il programma e il modello del comando, per
// ActiveScript il motore, il file dello script e la lunghezza del testo
// (mai il testo, che può contenere qualunque cosa). Lo script non riceve
// dati dall'esterno.
const WMIScript = `$ErrorActionPreference='Stop';try{[Console]::OutputEncoding=[Text.Encoding]::UTF8}catch{};$r=[ordered]@{};$e=[ordered]@{};` +
	`$ce={param($x) if($x.Exception.NativeErrorCode){"$($x.Exception.NativeErrorCode)"}else{'0x{0:X8}' -f $x.Exception.HResult}};` +
	`$items=New-Object System.Collections.ArrayList;` +
	`foreach($ns in @('root/subscription','root/default')){try{` +
	`$fl=@{};foreach($x in @(Get-CimInstance -Namespace $ns -ClassName __EventFilter -OperationTimeoutSec 10)){$fl["$($x.Name)"]=1};` +
	`$bd=@{};foreach($x in @(Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -OperationTimeoutSec 10)){if($x.Consumer -and $x.Filter -and $fl.ContainsKey("$($x.Filter.Name)")){$bd["$($x.Consumer.Name)"]=1}};` +
	`foreach($c in @(Get-CimInstance -Namespace $ns -ClassName __EventConsumer -OperationTimeoutSec 10)){$k="$($c.CimSystemProperties.ClassName)";` +
	`$y=[ordered]@{ns=$ns;cls=$k;name="$($c.Name)";bound=$bd.ContainsKey("$($c.Name)")};` +
	`if($k -eq 'CommandLineEventConsumer'){$y.exe="$($c.ExecutablePath)";$y.cmd="$($c.CommandLineTemplate)"};` +
	`if($k -eq 'ActiveScriptEventConsumer'){$y.engine="$($c.ScriptingEngine)";$y.sfile="$($c.ScriptFileName)";$y.len=[int]("$($c.ScriptText)".Length)};` +
	`[void]$items.Add($y)}}catch{$e[$ns]=(&$ce $_)}};` +
	`$r.items=$items;$r.errors=$e;ConvertTo-Json -Compress -Depth 5 -InputObject $r`

type psConsumer struct {
	NS     string `json:"ns"`
	Class  string `json:"cls"`
	Name   string `json:"name"`
	Bound  bool   `json:"bound"`
	Exe    string `json:"exe"`
	Cmd    string `json:"cmd"`
	Engine string `json:"engine"`
	SFile  string `json:"sfile"`
	Len    int    `json:"len"`
}

type wmiOut struct {
	Items  list[psConsumer]  `json:"items"`
	Errors map[string]string `json:"errors"`
}

func parseWMI(out []byte) (*wmiOut, error) {
	b, err := jsonStart(out)
	if err != nil {
		return nil, err
	}
	var w wmiOut
	if err := json.Unmarshal(b, &w); err != nil {
		return nil, fmt.Errorf("uscita non valida: %w", err)
	}
	return &w, nil
}

// deniedCode riconosce un accesso negato di WMI: il codice CIM
// «AccessDenied», WBEM_E_ACCESS_DENIED (0x80041003) o E_ACCESSDENIED.
func deniedCode(s string) bool {
	s = strings.ToLower(s)
	return strings.Contains(s, "accessdenied") || strings.Contains(s, "0x80041003") || strings.Contains(s, "0x80070005")
}

// ConsumerKind traduce la classe del consumatore: commandline |
// activescript | eventlog | logfile | smtp | other.
func ConsumerKind(class string) string {
	switch strings.ToLower(class) {
	case "commandlineeventconsumer":
		return "commandline"
	case "activescripteventconsumer":
		return "activescript"
	case "nteventlogeventconsumer":
		return "eventlog"
	case "logfileeventconsumer":
		return "logfile"
	case "smtpeventconsumer":
		return "smtp"
	}
	return "other"
}

// consumerItem prepara la voce di un consumatore WMI. Il nome è scelto da
// chi l'ha creato e passa dal pulitore; dello script si dicono solo il
// motore e la lunghezza. Le sottoscrizioni permanenti si elencano tutte
// (always), anche se il programma che avviano è di Windows (msiexec,
// certutil, bitsadmin...): su un Windows pulito c'è solo «SCM Event Log
// Consumer», che il motore riconosce, e una sottoscrizione collegata che
// esegue un comando è da guardare comunque (T1546.003).
func (rd reader) consumerItem(c psConsumer) item {
	e := scan.AutorunEntry{Category: "wmi", Kind: "wmi", Name: rd.cl.text(c.Name), Enabled: c.Bound, Bound: c.Bound,
		Consumer: ConsumerKind(c.Class), Namespace: strings.ReplaceAll(c.NS, "/", `\`)}
	e.Location = e.Namespace
	it := item{entry: e}
	switch e.Consumer {
	case "commandline":
		cmd := strings.TrimSpace(c.Cmd)
		exe := strings.TrimSpace(c.Exe)
		if cmd == "" {
			cmd = exe
		}
		if exe == "" {
			it = rd.commandItem(e, cmd, false)
		} else {
			// ExecutablePath, se c'è, è il programma avviato; il modello del
			// comando ne contiene gli argomenti dopo il nome del programma.
			_, args, _ := rd.res.Split(cmd, false)
			it = rd.execItem(e, cmd, exe, args, false)
		}
	case "activescript":
		engine := strings.TrimSpace(c.Engine)
		if engine == "" {
			engine = "motore non indicato"
		}
		if f := strings.TrimSpace(c.SFile); f != "" {
			it.entry.Command = engine + ": " + rd.cl.path(f)
			it.file = rd.res.Locate(f, false)
		} else {
			it.entry.Command = engine + ": script incorporato di " + strconv.Itoa(c.Len) + " caratteri (testo non letto)"
			it.interpreted = true
		}
	}
	it.always = true
	return it
}
