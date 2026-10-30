// Package pdh legge i contatori delle prestazioni di Windows (Performance
// Data Helper), gli stessi di Gestione attività e di Performance Monitor. I
// contatori si aggiungono per nome inglese, che vale con Windows in qualunque
// lingua; quelli con il carattere jolly (*) restituiscono tutte le istanze.
// Tutto in modalità utente: niente driver e, per i contatori usati da
// Polaris, niente permessi di amministratore.
package pdh

import (
	"errors"
	"fmt"
)

// ErrUnavailable: PDH non c'è (sistema diverso da Windows).
var ErrUnavailable = errors.New("contatori delle prestazioni non disponibili su questo sistema")

// Counter identifica un contatore aggiunto a una query.
type Counter uintptr

// Errore restituito da una funzione PDH.
type Error struct {
	Op   string
	Code uint32
}

func (e *Error) Error() string { return fmt.Sprintf("%s: errore PDH 0x%08X", e.Op, e.Code) }

// Codici di PDH (pdhmsg.h) che i chiamanti distinguono.
const (
	// CstatusNoObject: l'oggetto (per esempio "Energy Meter") non esiste su
	// questo PC.
	CstatusNoObject = 0xC0000BB8
	// CstatusNoCounter: l'oggetto c'è ma non ha quel contatore.
	CstatusNoCounter = 0xC0000BB9
)

// Missing dice se l'errore indica un oggetto o un contatore assente su questo
// PC, cioè una funzione che il sistema non offre (e non un guasto).
func Missing(err error) bool {
	var e *Error
	return errors.As(err, &e) && (e.Code == CstatusNoObject || e.Code == CstatusNoCounter)
}
