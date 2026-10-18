// Package defender avvia, solo su richiesta esplicita, le operazioni di
// Microsoft Defender, l'antivirus integrato in Windows, con il suo strumento
// a riga di comando (MpCmdRun.exe): scansione rapida, scansione completa e
// aggiornamento delle firme. Lo stato e le minacce si rileggono alla fine,
// così l'interfaccia mostra subito l'esito senza una nuova analisi.
//
// Le scansioni non cancellano nulla da sole: eventuali minacce le gestisce
// Defender secondo le sue impostazioni (di norma la quarantena), come quando
// la scansione parte da Sicurezza di Windows.
package defender

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"lanterna/internal/scan"
)

// Azioni disponibili.
const (
	Quick  = "quick"
	Full   = "full"
	Update = "update"
)

// Timeout massimi: una scansione completa di un disco grande può durare ore.
var Timeouts = map[string]time.Duration{Quick: 45 * time.Minute, Full: 8 * time.Hour, Update: 10 * time.Minute}

// ErrUnavailable segnala che Defender non è installato o non risponde.
var ErrUnavailable = errors.New("Microsoft Defender non è disponibile su questo PC")

// Result è l'esito di un'operazione, con lo stato riletto alla fine.
type Result struct {
	Action     string             `json:"action"`
	StartedAt  string             `json:"startedAt"`
	DurationMs int64              `json:"durationMs"`
	Message    string             `json:"message"`
	NewThreats int                `json:"newThreats"`
	Defender   *scan.DefenderInfo `json:"defender,omitempty"`
	Threats    []scan.Threat      `json:"threats"`
}

// Args restituisce gli argomenti di MpCmdRun per un'azione.
func Args(action string) ([]string, error) {
	switch action {
	case Quick:
		return []string{"-Scan", "-ScanType", "1"}, nil
	case Full:
		return []string{"-Scan", "-ScanType", "2"}, nil
	case Update:
		return []string{"-SignatureUpdate"}, nil
	}
	return nil, fmt.Errorf("azione non valida: %q (quick, full o update)", action)
}

// CancelArgs interrompe la scansione in corso.
var CancelArgs = []string{"-Scan", "-Cancel"}

// CheckExit interpreta il codice di uscita di MpCmdRun: 0 è riuscito; per le
// scansioni anche 2, con cui lo strumento segnala di aver trovato minacce
// (l'elenco si rilegge comunque dallo stato di Defender).
func CheckExit(action string, code int, output string) error {
	if code == 0 || (code == 2 && action != Update) {
		return nil
	}
	last := ""
	for _, l := range strings.Split(strings.ReplaceAll(output, "\r", ""), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			last = l
		}
	}
	if r := []rune(last); len(r) > 160 {
		last = string(r[:160])
	}
	msg := fmt.Sprintf("MpCmdRun ha terminato con il codice %d", code)
	if last != "" {
		msg += ": " + last
	}
	return errors.New(msg)
}

// NewSince conta le minacce rilevate dopo l'istante indicato.
func NewSince(threats []scan.Threat, since time.Time) int {
	n := 0
	for _, t := range threats {
		if d, err := time.Parse(time.RFC3339, t.Detected); err == nil && !d.Before(since.Add(-time.Minute)) {
			n++
		}
	}
	return n
}

// Message riassume l'esito in italiano.
func Message(action string, newThreats int, d *scan.DefenderInfo) string {
	switch action {
	case Update:
		if d != nil && d.SignatureVersion != "" {
			return "Firme aggiornate: versione " + d.SignatureVersion + "."
		}
		return "Aggiornamento delle firme completato."
	default:
		kind := "rapida"
		if action == Full {
			kind = "completa"
		}
		if newThreats > 0 {
			return fmt.Sprintf("Scansione %s completata: Defender ha rilevato %d %s, nell'elenco qui sotto.", kind, newThreats, plural(newThreats, "minaccia", "minacce"))
		}
		return fmt.Sprintf("Scansione %s completata: nessuna nuova minaccia rilevata.", kind)
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
