package server

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"lanterna/internal/scan"
	"lanterna/internal/speedtest"
)

// Test di velocità di Internet con M-Lab, su richiesta e con il consenso
// esplicito di chi lo avvia (il risultato è pubblicato da M-Lab con
// l'indirizzo IP pubblico):
//
//	POST   /api/speedtest  avvia il test ({"consent": true}); 400 senza
//	                       consenso, 409 se c'è già un test o un'analisi,
//	                       429 se è troppo presto (un test ogni due minuti,
//	                       dieci al giorno)
//	GET    /api/speedtest  fase, velocità in corso, esito o errore
//	DELETE /api/speedtest  interrompe il test

type speedState struct {
	Running  bool                `json:"running"`
	Progress *speedtest.Progress `json:"progress,omitempty"`
	Error    string              `json:"error,omitempty"`
	Result   *scan.SpeedTest     `json:"result,omitempty"`
	// WaitSec: secondi prima che si possa avviare il prossimo test; Left:
	// test ancora possibili oggi.
	WaitSec int `json:"waitSec,omitempty"`
	Left    int `json:"left"`
}

var errSpeedRunning = errors.New("test di velocità di Internet in corso: attendi che finisca o interrompilo")

func (s *Server) speedLimiter() *speedtest.Limiter {
	s.speedMu.Lock()
	defer s.speedMu.Unlock()
	if s.SpeedLimit == nil {
		s.SpeedLimit = speedtest.NewLimiter()
	}
	return s.SpeedLimit
}

// startSpeed avvia il test in background. Ordine dei lock come in
// startBench: prima mu (l'analisi), poi benchMu, poi speedMu. Non parte
// durante un'analisi né durante il test della CPU o del disco: si
// falserebbero a vicenda (la cifratura del test pesa sulla CPU alle velocità
// alte, il punteggio della CPU dipende dal carico).
func (s *Server) startSpeed() (int, error) {
	lim := s.speedLimiter()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return http.StatusConflict, errors.New("analisi in corso: il test di velocità ne falserebbe le misure")
	}
	s.benchMu.Lock()
	benchBusy := s.benchRunning
	s.benchMu.Unlock()
	if benchBusy {
		return http.StatusConflict, errors.New("test della CPU o del disco in corso: il test di velocità di Internet ne sarebbe falsato, attendi che finisca")
	}
	s.speedMu.Lock()
	defer s.speedMu.Unlock()
	if s.speedRunning {
		return http.StatusConflict, errors.New("test di velocità di Internet già in corso")
	}
	if err := lim.Take(); err != nil {
		return http.StatusTooManyRequests, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	// Il risultato precedente resta nell'interfaccia: qui si toglie, così a
	// fine test c'è solo quello nuovo (o nessuno, se è fallito).
	s.speedRunning, s.speedErr, s.speedProg, s.speedCancel, s.speedLast = true, "", nil, cancel, nil
	s.speedFinish = make(chan struct{})
	finish := s.speedFinish
	go func() {
		defer close(finish)
		defer cancel()
		var res *scan.SpeedTest
		var err error
		func() {
			defer func() {
				if r := recover(); r != nil {
					err = errors.New("errore interno durante il test")
				}
			}()
			res, err = s.SpeedTest(ctx, func(p speedtest.Progress) {
				s.speedMu.Lock()
				s.speedProg = &p
				s.speedMu.Unlock()
			})
		}()
		if err != nil && speedtest.NotReached(err) {
			lim.Release()
		}
		s.speedMu.Lock()
		defer s.speedMu.Unlock()
		s.speedRunning, s.speedCancel = false, nil
		switch {
		case errors.Is(err, context.Canceled):
			s.speedErr = "test interrotto"
		case errors.Is(err, context.DeadlineExceeded):
			s.speedErr = "test interrotto: tempo massimo superato"
		case err != nil:
			s.speedErr = err.Error()
		default:
			s.speedLast = res
		}
	}()
	return http.StatusAccepted, nil
}

// WaitSpeed attende la fine del test in corso (usato dai test).
func (s *Server) WaitSpeed() {
	s.speedMu.Lock()
	ch := s.speedFinish
	s.speedMu.Unlock()
	if ch != nil {
		<-ch
	}
}

func (s *Server) speedBusy() bool {
	s.speedMu.Lock()
	defer s.speedMu.Unlock()
	return s.speedRunning
}

func (s *Server) speedRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/speedtest", func(w http.ResponseWriter, r *http.Request) {
		if s.SpeedTest == nil {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "test di velocità di Internet non disponibile"})
			return
		}
		var body struct {
			Consent bool `json:"consent"`
		}
		if code, err := readJSON(w, r, &body); err != nil {
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		if !body.Consent {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "serve il consenso esplicito: M-Lab pubblica il risultato del test con l'indirizzo IP pubblico della connessione"})
			return
		}
		code, err := s.startSpeed()
		if err != nil {
			out := map[string]any{"error": err.Error()}
			var le *speedtest.LimitError
			if errors.As(err, &le) {
				sec := int((le.Wait + time.Second - 1) / time.Second)
				w.Header().Set("Retry-After", strconv.Itoa(sec))
				out["retryAfter"] = sec
			}
			writeJSON(w, code, out)
			return
		}
		writeJSON(w, code, map[string]bool{"started": true})
	})
	mux.HandleFunc("GET /api/speedtest", func(w http.ResponseWriter, r *http.Request) {
		wait, left := s.speedLimiter().Status()
		s.speedMu.Lock()
		st := speedState{Running: s.speedRunning, Progress: s.speedProg, Error: s.speedErr, Result: s.speedLast, Left: left}
		s.speedMu.Unlock()
		if !st.Running {
			st.Progress = nil
		}
		if wait > 0 {
			st.WaitSec = int((wait + time.Second - 1) / time.Second)
		}
		writeJSON(w, 200, st)
	})
	mux.HandleFunc("DELETE /api/speedtest", func(w http.ResponseWriter, r *http.Request) {
		s.speedMu.Lock()
		cancel := s.speedCancel
		s.speedMu.Unlock()
		if cancel != nil {
			cancel()
		}
		writeJSON(w, 200, map[string]bool{"stopping": cancel != nil})
	})
}
