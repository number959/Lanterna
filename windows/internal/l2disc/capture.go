package l2disc

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// DefaultDuration è la durata predefinita dell'ascolto: CDP si ripete ogni
// 60 secondi, LLDP e DTP ogni 30, le BPDU ogni 2.
const DefaultDuration = 61 * time.Second

const (
	maxDuration    = 5 * time.Minute
	setupTimeout   = 2 * time.Minute  // preparazione, chiusura e lettura della cattura
	cleanupTimeout = 30 * time.Second // chiusura della sessione dopo un'interruzione
	staleAge       = time.Hour        // cartelle temporanee lasciate da un avvio interrotto
	tempPrefix     = "polaris-l2-"
	sessionPrefix  = "Polaris-L2-"
)

// clampDuration riporta la durata richiesta entro i limiti, in secondi interi.
func clampDuration(d time.Duration) time.Duration {
	switch {
	case d <= 0:
		return DefaultDuration
	case d < time.Second:
		return time.Second
	case d > maxDuration:
		return maxDuration
	}
	return d.Truncate(time.Second)
}

// Indirizzi di destinazione ascoltati: LLDP (ponte più vicino, ponte non
// TPMR più vicino, ponte cliente più vicino; l'ultimo è anche quello delle
// BPDU IEEE), CDP/DTP/VTP e PVST+ di Cisco. Il filtro della cattura scarta
// tutto il resto: nessun'altra trama (e quindi nessun dato degli utenti)
// viene registrata.
var listenAddresses = []string{
	"01-80-c2-00-00-0e",
	"01-80-c2-00-00-03",
	"01-80-c2-00-00-00",
	"01-00-0c-cc-cc-cc",
	"01-00-0c-cc-cc-cd",
}

// captureTemplate è lo script PowerShell della cattura. Riceve nome della
// sessione, file .etl e secondi nelle variabili d'ambiente POLARIS_L2_*, e
// scrive una riga per evento con un prefisso riconoscibile:
//
//	L2NOMODULE                  cmdlet NetEventPacketCapture assenti
//	L2NOWIRED                   nessuna scheda cablata collegata
//	L2BUSY                      c'è già un'altra sessione di cattura
//	L2A <ifIndex> <MAC> <nome>  scheda in ascolto
//	L2START                     cattura avviata
//	L2FAIL <fase> <codice>      errore (solo il codice: il messaggio è nella
//	                            lingua di Windows e può contenere percorsi)
//	L2EVENTS <n>                eventi letti dal file
//	L2F <R|S> <ifIndex> <hex>   una trama ricevuta (R) o trasmessa dal PC (S)
//	L2END                       lettura conclusa
//	L2CLEAN                     sessione chiusa e rimossa
//
// Fonti, verificate fin dove possibile:
//   - cmdlet e parametri: documentazione Microsoft del modulo
//     NetEventPacketCapture ("Only one session can exist at a time",
//     TruncationLength predefinito di 128 byte, CaptureType Physical);
//   - eventi: provider Microsoft-Windows-NDIS-PacketCapture, evento 1001
//     (frammento di pacchetto) con i campi MiniportIfIndex, LowerIfIndex,
//     FragmentSize e Fragment, e parola chiave 0x100000000 per i pacchetti
//     trasmessi, come li legge etl2pcapng di Microsoft (licenza MIT); da
//     Windows 8.1 ogni pacchetto sta in un solo evento;
//   - indirizzi con i trattini, TruncationLength 0 (pacchetto intero, valore
//     non documentato da Microsoft) e modalità promiscua della scheda (senza,
//     la scheda può scartare i multicast di CDP e STP): come il modulo
//     PSDiscoveryProtocol (licenza MIT), da verificare su più PC;
//   - il frammento si legge per nome dall'XML dell'evento (esadecimale) e,
//     se l'XML non lo contiene in quella forma, con EventLogPropertySelector,
//     sempre per nome: la resa esadecimale nell'XML è da verificare.
//
// La modalità promiscua cambia solo ciò che la scheda accetta in ricezione
// e solo durante la sessione: non si trasmette nulla.
const captureTemplate = `$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}
$name = $env:POLARIS_L2_SESSION
$etl = $env:POLARIS_L2_ETL
$secs = [int]$env:POLARIS_L2_SECONDS
$code = { param($x) if ($x.Exception.NativeErrorCode) { "$($x.Exception.NativeErrorCode)" } else { '0x{0:X8}' -f $x.Exception.HResult } }
if (-not (Get-Command -Name New-NetEventSession -ErrorAction SilentlyContinue)) { 'L2NOMODULE'; return }
try { $ads = @(Get-NetAdapter -Physical | Where-Object { "$($_.Status)" -eq 'Up' -and [int]$_.InterfaceType -eq 6 }) } catch { 'L2FAIL adapters ' + (& $code $_); return }
if ($ads.Count -eq 0) { 'L2NOWIRED'; return }
foreach ($a in $ads) { 'L2A ' + [int]$a.ifIndex + ' ' + $a.MacAddress + ' ' + $a.Name }
try { $old = @(Get-NetEventSession) } catch { 'L2FAIL session ' + (& $code $_); return }
foreach ($s in $old) {
  if ("$($s.Name)" -like '@PREFIX@*') {
    try { Stop-NetEventSession -Name $s.Name | Out-Null } catch {}
    try { Remove-NetEventSession -Name $s.Name } catch {}
  } else { 'L2BUSY'; return }
}
$made = $false
try {
  try { New-NetEventSession -Name $name -CaptureMode SaveToFile -LocalFilePath $etl -MaxFileSize 64 | Out-Null; $made = $true } catch { 'L2FAIL session ' + (& $code $_); return }
  try { Add-NetEventPacketCaptureProvider -SessionName $name -LinkLayerAddress @ADDRS@ -CaptureType Physical -TruncationLength 0 | Out-Null } catch { 'L2FAIL provider ' + (& $code $_); return }
  foreach ($a in $ads) { try { Add-NetEventNetworkAdapter -Name $a.Name -PromiscuousMode $true | Out-Null } catch { 'L2FAIL adapter ' + (& $code $_); return } }
  try { Start-NetEventSession -Name $name | Out-Null } catch { 'L2FAIL start ' + (& $code $_); return }
  'L2START'
  $end = [DateTime]::UtcNow.AddSeconds($secs)
  while ([DateTime]::UtcNow -lt $end) { Start-Sleep -Milliseconds 250 }
  try { Stop-NetEventSession -Name $name | Out-Null } catch { 'L2FAIL stop ' + (& $code $_); return }
  $ev = @()
  try { $ev = @(Get-WinEvent -Path $etl -Oldest -FilterXPath '*[System[EventID=1001]]' -MaxEvents 20000) } catch { if ("$($_.FullyQualifiedErrorId)" -notlike 'NoMatchingEventsFound*') { 'L2FAIL read ' + (& $code $_); return } }
  'L2EVENTS ' + $ev.Count
  $sel = $null
  foreach ($e in $ev) {
    $idx = ''; $hex = ''
    try {
      foreach ($d in @(([xml]$e.ToXml()).Event.EventData.Data)) {
        switch ($d.GetAttribute('Name')) { 'MiniportIfIndex' { $idx = $d.InnerText } 'Fragment' { $hex = $d.InnerText } }
      }
    } catch {}
    if ($hex -notmatch '^(0x)?[0-9A-Fa-f]+$') {
      try {
        if ($null -eq $sel) { $sel = New-Object System.Diagnostics.Eventing.Reader.EventLogPropertySelector -ArgumentList (,[string[]]@("Event/EventData/Data[@Name='MiniportIfIndex']", "Event/EventData/Data[@Name='Fragment']")) }
        $v = $e.GetPropertyValues($sel)
        $idx = "$($v[0])"; $hex = ''
        if ($v[1] -is [byte[]]) { $hex = [BitConverter]::ToString($v[1]).Replace('-', '') }
      } catch { $hex = '' }
    }
    $dir = 'R'
    if ($e.Keywords -band 0x100000000) { $dir = 'S' }
    'L2F ' + $dir + ' ' + $idx + ' ' + $hex
  }
  'L2END'
} finally {
  $ok = $true
  if ($made) {
    try { Stop-NetEventSession -Name $name | Out-Null } catch {}
    try { Remove-NetEventSession -Name $name } catch { $ok = $false }
  }
  try { Remove-Item -LiteralPath $etl -Force -ErrorAction SilentlyContinue } catch {}
  if ($ok) { 'L2CLEAN' }
}`

// captureScript è captureTemplate con gli indirizzi e il prefisso delle sessioni.
var captureScript = strings.NewReplacer(
	"@ADDRS@", "@('"+strings.Join(listenAddresses, "','")+"')",
	"@PREFIX@", sessionPrefix,
).Replace(captureTemplate)

// cleanupScript chiude la sessione indicata in POLARIS_L2_SESSION: serve
// quando lo script della cattura è stato interrotto prima del suo finally.
const cleanupScript = `$ErrorActionPreference = 'SilentlyContinue'
$name = $env:POLARIS_L2_SESSION
if (Get-NetEventSession -Name $name) { Stop-NetEventSession -Name $name | Out-Null; Remove-NetEventSession -Name $name }
if (-not (Get-NetEventSession -Name $name)) { 'L2CLEAN' }`

// Messaggi per l'interfaccia (in italiano, senza percorsi né nomi utente).
const (
	msgAdmin       = "Per ascoltare gli annunci dello switch serve avviare Polaris come amministratore."
	msgUnsupported = "L'ascolto degli annunci dello switch è disponibile solo su Windows."
	msgNoModule    = "Questo Windows non offre la cattura dei pacchetti integrata (modulo NetEventPacketCapture)."
	msgNoWired     = "Nessuna scheda di rete cablata collegata: gli annunci dello switch arrivano solo dal cavo di rete."
	msgBusy        = "Cattura non avviata: in Windows è già attiva un'altra sessione di cattura dei pacchetti (per esempio di netsh trace o di un altro programma). Chiudila e riprova."
	msgIncomplete  = "Cattura non conclusa: Windows non ha restituito le trame ascoltate."
	msgCancelled   = "Ascolto interrotto prima della fine."
	msgTimeout     = "Ascolto non concluso entro il tempo massimo."
	msgUnreadable  = "Cattura eseguita, ma Windows ha restituito le trame in una forma non leggibile."
	msgNoTemp      = "Cattura non avviata: non è stato possibile preparare la cartella temporanea."
	msgNoPS        = "Cattura non avviata: PowerShell non è disponibile."
)

var failMessages = map[string]string{
	"adapters": "Cattura non avviata: Windows non ha elencato le schede di rete",
	"session":  "Cattura non avviata: Windows non ha creato la sessione di cattura",
	"provider": "Cattura non avviata: Windows non ha attivato il filtro della cattura",
	"adapter":  "Cattura non avviata: Windows non ha aggiunto la scheda di rete alla cattura",
	"start":    "Cattura non avviata: Windows non ha avviato la cattura",
	"stop":     "Cattura interrotta: Windows non ha fermato la cattura",
	"read":     "Cattura eseguita, ma il file della cattura non si legge",
}

// failMessage descrive l'errore di una fase dello script.
func failMessage(stage, code string) string {
	m, ok := failMessages[stage]
	if !ok {
		m = "Cattura non riuscita"
	}
	if code != "" {
		m += " (codice " + code + ")"
	}
	return m + "."
}

// accessDenied riconosce gli errori di accesso negato (CIM, Win32, WMI).
func accessDenied(code string) bool {
	switch strings.ToLower(code) {
	case "accessdenied", "0x80070005", "0x80041003":
		return true
	}
	return false
}

// captureOut è l'uscita dello script della cattura, già interpretata.
type captureOut struct {
	noModule, noWired, busy bool
	started, ended, clean   bool
	failStage, failCode     string
	events                  int
	adapters                []string // nomi delle schede in ascolto
	frames                  []Frame  // trame ricevute, senza quelle del PC
	own                     int      // trame trasmesse dal PC, scartate
	bad                     int      // righe di trama non decodificabili
}

// codeChars tiene del codice d'errore solo lettere, cifre e "x".
var codeChars = regexp.MustCompile(`[^0-9A-Za-z]`)

// parseCapture interpreta l'uscita di captureScript. Le trame trasmesse dal
// PC (parola chiave di trasmissione o MAC sorgente di una scheda in
// ascolto) si scartano.
func parseCapture(out string) captureOut {
	var c captureOut
	names := map[string]string{}
	own := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		// Con l'uscita in UTF-8 Windows PowerShell può anteporre il BOM alla
		// prima riga.
		line = strings.TrimLeft(strings.TrimRight(line, "\r"), "\uFEFF \t")
		tag, rest, _ := strings.Cut(line, " ")
		switch tag {
		case "L2NOMODULE":
			c.noModule = true
		case "L2NOWIRED":
			c.noWired = true
		case "L2BUSY":
			c.busy = true
		case "L2START":
			c.started = true
		case "L2END":
			c.ended = true
		case "L2CLEAN":
			c.clean = true
		case "L2FAIL":
			// Solo fase e codice: qualunque altro testo sulla riga si ignora.
			stage, code, _ := strings.Cut(rest, " ")
			code, _, _ = strings.Cut(strings.TrimSpace(code), " ")
			if c.failStage == "" {
				c.failStage = codeChars.ReplaceAllString(stage, "")
				c.failCode = codeChars.ReplaceAllString(code, "")
				if len(c.failCode) > 40 {
					c.failCode = c.failCode[:40]
				}
			}
		case "L2EVENTS":
			c.events, _ = strconv.Atoi(strings.TrimSpace(rest))
		case "L2A":
			f := strings.SplitN(rest, " ", 3)
			if len(f) < 3 {
				continue
			}
			if mac, err := hex.DecodeString(strings.ReplaceAll(f[1], "-", "")); err == nil && len(mac) == 6 {
				own[string(mac)] = true
			}
			if name := clean([]byte(f[2])); name != "" {
				names[f[0]] = name
				c.adapters = appendUnique(c.adapters, name, maxEntries)
			}
		case "L2F":
			f := strings.SplitN(rest, " ", 3)
			if len(f) < 3 {
				c.bad++
				continue
			}
			data, ok := decodeHex(f[2])
			switch {
			case !ok || len(data) < 14:
				c.bad++
			case f[0] == "S" || own[string(data[6:12])]:
				c.own++
			case len(c.frames) < maxFrames:
				c.frames = append(c.frames, Frame{Adapter: names[f[1]], Data: data})
			}
		}
	}
	return c
}

// decodeHex legge il frammento esadecimale, con o senza "0x" e trattini.
func decodeHex(s string) ([]byte, bool) {
	s = strings.TrimSpace(s)
	if len(s) > 2 && (s[:2] == "0x" || s[:2] == "0X") {
		s = s[2:]
	}
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	return b, err == nil && len(b) > 0
}

// unfinished dice se lo script si è fermato senza dire perché (interrotto,
// scaduto o fallito fuori dalle fasi previste).
func (c captureOut) unfinished() bool {
	return !c.noModule && !c.noWired && !c.busy && c.failStage == "" && !c.ended
}

// discovery trasforma l'uscita dello script nel risultato per l'interfaccia.
func (c captureOut) discovery(secs int) Discovery {
	switch {
	case c.noModule:
		return Discovery{Read: ReadUnsupported, Error: msgNoModule}
	case c.noWired:
		return Discovery{Read: ReadNoWired, Error: msgNoWired}
	case c.busy:
		return Discovery{Read: ReadError, Error: msgBusy}
	case c.failStage != "":
		d := Discovery{Read: ReadError, Error: failMessage(c.failStage, c.failCode), Adapters: c.adapters}
		if accessDenied(c.failCode) {
			d.Read = ReadAdmin
		}
		if c.started {
			d.Seconds = secs
		}
		return d
	case !c.ended:
		d := Discovery{Read: ReadError, Error: msgIncomplete, Adapters: c.adapters}
		if c.started {
			d.Seconds = secs
		}
		return d
	}
	d := SummarizeFrames(c.frames)
	d.Seconds, d.Adapters = secs, c.adapters
	if len(c.frames) == 0 && c.own == 0 && c.bad > 0 {
		d.Read, d.Error = ReadError, msgUnreadable
	}
	return d
}

// userPath riconosce i percorsi dentro le cartelle degli utenti.
var userPath = regexp.MustCompile(`(?i)(\\users\\|/users/|/home/)[^\\/\s"':]+`)

// scrub toglie da un messaggio d'errore i testi indicati (cartella della
// cattura, cartella temporanea, profilo e nome dell'utente; quelli più corti
// di 3 caratteri si ignorano) e qualunque percorso dentro le cartelle degli
// utenti.
func scrub(msg string, secrets ...string) string {
	secrets = slices.Clone(secrets)
	slices.SortFunc(secrets, func(a, b string) int { return len(b) - len(a) }) // prima i più lunghi
	for _, s := range secrets {
		if len(s) < 3 {
			continue
		}
		msg = regexp.MustCompile(`(?i)`+regexp.QuoteMeta(s)).ReplaceAllLiteralString(msg, "…")
	}
	return capRunes(userPath.ReplaceAllString(msg, "${1}…"))
}

// removeDir cancella la cartella della cattura, riprovando per qualche
// istante se il file .etl è ancora aperto.
func removeDir(dir string) {
	for i := 0; i < 10; i++ {
		if err := os.RemoveAll(dir); err == nil {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// removeStale cancella le cartelle della cattura lasciate da un avvio di
// Polaris interrotto bruscamente (più vecchie di staleAge). Restituisce
// quante ne ha cancellate.
func removeStale(tmp string, now time.Time) int {
	entries, err := os.ReadDir(tmp)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), tempPrefix) {
			continue
		}
		info, err := e.Info()
		if err != nil || now.Sub(info.ModTime()) < staleAge {
			continue
		}
		if os.RemoveAll(filepath.Join(tmp, e.Name())) == nil {
			n++
		}
	}
	return n
}
