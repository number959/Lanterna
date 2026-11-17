package server

import (
	"context"
	"net/http"
	"sync"
	"time"

	"lanterna/internal/scan"
)

// Confronto del processore con l'elenco ufficiale dei processori supportati
// da Windows 11, solo su richiesta:
//
//	POST /api/win11/cpus   corpo {}: il PC scarica da learn.microsoft.com
//	                       l'elenco del produttore del processore e lo
//	                       confronta con il nome (al massimo 30 secondi);
//	                       risponde con l'esito (Win11CPUCheck). Se un
//	                       confronto è già in corso (un'altra finestra, la
//	                       pagina ricaricata) la richiesta lo aspetta e
//	                       risponde con lo stesso esito, senza errore.
//	GET  /api/win11/cpus   ultimo esito, 204 se non c'è
//
// La pagina non si salva: resta solo l'esito. Il confronto non dipende dalla
// richiesta che l'ha avviato: se la finestra si chiude finisce lo stesso, e
// l'esito resta per GET e per chi lo aspetta.

// win11Job è lo stato del confronto (protetto da mu).
type win11Job struct {
	mu   sync.Mutex
	run  *win11Run // confronto in corso, nil se nessuno
	last *scan.Win11CPUCheck
}

// win11Run è un confronto in corso: done si chiude alla fine, e da lì res
// è l'esito (nil se il confronto è andato in panic).
type win11Run struct {
	done    chan struct{}
	res     *scan.Win11CPUCheck
	waiters int // richieste che lo aspettano, per le prove (protetto da win11Job.mu)
}

// win11Timeout è il tempo massimo per scaricare e leggere la pagina.
const win11Timeout = 30 * time.Second

// startWin11 avvia il confronto, oppure restituisce quello già in corso.
func (s *Server) startWin11() *win11Run {
	j := &s.win11
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.run != nil {
		j.run.waiters++
		return j.run
	}
	run := &win11Run{done: make(chan struct{}), waiters: 1}
	j.run = run
	go func() {
		var res *scan.Win11CPUCheck
		defer func() {
			if recover() != nil {
				res = nil
			}
			j.mu.Lock()
			run.res = res
			if res != nil {
				j.last = res
			}
			j.run = nil
			j.mu.Unlock()
			close(run.done)
		}()
		ctx, cancel := context.WithTimeout(context.Background(), win11Timeout)
		defer cancel()
		res = s.Win11CPUs(ctx)
	}()
	return run
}

func (s *Server) win11Routes(mux *http.ServeMux) {
	j := &s.win11
	mux.HandleFunc("POST /api/win11/cpus", func(w http.ResponseWriter, r *http.Request) {
		if s.Win11CPUs == nil {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "confronto con l'elenco dei processori non disponibile"})
			return
		}
		var body struct{}
		if code, err := readJSON(w, r, &body); err != nil {
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		run := s.startWin11()
		select {
		case <-run.done:
		case <-r.Context().Done():
			// Chi ha chiesto non aspetta più: l'esito resta per GET.
			return
		}
		if run.res == nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "errore interno durante il confronto"})
			return
		}
		writeJSON(w, http.StatusOK, run.res)
	})
	mux.HandleFunc("GET /api/win11/cpus", func(w http.ResponseWriter, r *http.Request) {
		j.mu.Lock()
		last := j.last
		j.mu.Unlock()
		if last == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, http.StatusOK, last)
	})
}
