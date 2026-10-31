package crash

import (
	"context"
	"time"

	"lanterna/internal/scan"
)

// Background è una lettura delle schermate blu avviata in parallelo alle
// altre letture dell'analisi del PC.
type Background struct {
	done chan *scan.CrashData
	stop context.CancelFunc
}

// Start avvia read in parallelo, con un tempo massimo.
func Start(ctx context.Context, timeout time.Duration, read func(context.Context) (*scan.CrashData, error)) *Background {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	b := &Background{done: make(chan *scan.CrashData, 1), stop: cancel}
	go func() {
		defer cancel()
		d, _ := read(cctx)
		b.done <- d
	}()
	return b
}

// Wait aspetta il risultato al massimo grace. Poi chiede alla lettura di
// fermarsi tra un file e l'altro e aspetta ancora al massimo stopWait ciò
// che ha già letto (Partial). Se nemmeno allora risponde, per esempio
// perché la cartella dei minidump è su una rete che non risponde,
// restituisce un risultato vuoto con Partial: così il rapporto dice che la
// lettura non è finita in tempo, invece di non dire nulla. nil solo se read
// non è disponibile (fuori da Windows).
func (b *Background) Wait(grace, stopWait time.Duration) *scan.CrashData {
	select {
	case d := <-b.done:
		return d
	case <-time.After(grace):
	}
	b.stop()
	select {
	case d := <-b.done:
		return d
	case <-time.After(stopWait):
		return &scan.CrashData{ReadAt: time.Now().UTC().Format(time.RFC3339), Dumps: []scan.CrashDump{}, Partial: true}
	}
}
