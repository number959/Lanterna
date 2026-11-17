package server

import (
	"context"
	"errors"
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
//	                       risponde con l'esito (Win11CPUCheck)
//	GET  /api/win11/cpus   ultimo esito, 204 se non c'è
//
// La pagina non si salva: resta solo l'esito.

// win11Job è lo stato del confronto (protetto da mu).
type win11Job struct {
	mu   sync.Mutex
	busy bool
	last *scan.Win11CPUCheck
}

// win11Timeout è il tempo massimo per scaricare e leggere la pagina.
const win11Timeout = 30 * time.Second

var errWin11Running = errors.New("confronto con l'elenco dei processori già in corso")

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
		j.mu.Lock()
		if j.busy {
			j.mu.Unlock()
			writeJSON(w, http.StatusConflict, map[string]string{"error": errWin11Running.Error()})
			return
		}
		j.busy = true
		j.mu.Unlock()
		var res *scan.Win11CPUCheck
		func() {
			defer func() {
				if recover() != nil {
					res = nil
				}
			}()
			ctx, cancel := context.WithTimeout(r.Context(), win11Timeout)
			defer cancel()
			res = s.Win11CPUs(ctx)
		}()
		j.mu.Lock()
		j.busy = false
		if res != nil {
			j.last = res
		}
		j.mu.Unlock()
		if res == nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "errore interno durante il confronto"})
			return
		}
		writeJSON(w, http.StatusOK, res)
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
