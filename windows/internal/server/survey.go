package server

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"lanterna/internal/scan"
	"lanterna/internal/survey"
)

// Mappa del Wi-Fi per stanza: una misura alla volta, in background.
//
//	POST   /api/wifi/survey  avvia la misura di un punto ({"room": "Soggiorno",
//	                         "seconds": 15, "scan": true}): 202, 409 se un'altra
//	                         misura, un'analisi, un inventario o un test di
//	                         velocità sono in corso
//	GET    /api/wifi/survey  avanzamento (secondi, ultimo dBm) o esito
//	DELETE /api/wifi/survey  interrompe la misura in corso

// surveyJob è lo stato della misura (protetto da mu).
type surveyJob struct {
	mu      sync.Mutex
	running bool
	room    string
	prog    *survey.Progress
	err     string
	cancel  context.CancelFunc
	last    *scan.SurveySample
	finish  chan struct{}
}

type surveyState struct {
	Running  bool               `json:"running"`
	Room     string             `json:"room,omitempty"`
	Progress *survey.Progress   `json:"progress,omitempty"`
	Error    string             `json:"error,omitempty"`
	Result   *scan.SurveySample `json:"result,omitempty"`
}

var errSurveyRunning = errors.New("misura del Wi-Fi in corso: attendi che finisca o interrompila")

// surveyBusy dice se una misura del Wi-Fi è in corso (per non avviare
// un'analisi che ne falserebbe i valori).
func (s *Server) surveyBusy() bool {
	s.survey.mu.Lock()
	defer s.survey.mu.Unlock()
	return s.survey.running
}

// startSurvey avvia la misura in background. Ordine dei lock: mu (analisi),
// poi benchMu, invMu e survey.mu, come in startBench.
func (s *Server) startSurvey(opt survey.Options) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return errors.New("analisi in corso: la misura del Wi-Fi ne sarebbe falsata. Riprova quando l'analisi è finita")
	}
	// Un test di velocità carica processore o disco e allunga i tempi dei ping.
	s.benchMu.Lock()
	bench := s.benchRunning
	s.benchMu.Unlock()
	if bench {
		return errors.New("test di velocità in corso: la misura del Wi-Fi ne sarebbe falsata. Riprova quando il test è finito")
	}
	s.invMu.Lock()
	inv := s.invRunning
	s.invMu.Unlock()
	if inv {
		return errors.New("inventario della rete in corso: la misura del Wi-Fi ne sarebbe falsata. Riprova quando è finito")
	}
	j := &s.survey
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.running {
		return errSurveyRunning
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	j.running, j.room, j.err, j.prog, j.cancel, j.last = true, opt.Room, "", nil, cancel, nil
	j.finish = make(chan struct{})
	finish := j.finish
	opt.Progress = func(p survey.Progress) {
		j.mu.Lock()
		j.prog = &p
		j.mu.Unlock()
	}
	go func() {
		defer close(finish)
		defer cancel()
		var res *scan.SurveySample
		var err error
		func() {
			defer func() {
				if r := recover(); r != nil {
					err = errors.New("errore interno durante la misura del Wi-Fi")
				}
			}()
			res, err = s.Survey(ctx, opt)
		}()
		j.mu.Lock()
		defer j.mu.Unlock()
		j.running, j.cancel = false, nil
		switch {
		case errors.Is(err, context.Canceled):
			j.err = "misura interrotta"
		case errors.Is(err, context.DeadlineExceeded):
			j.err = "misura interrotta: tempo massimo superato"
		case err != nil:
			j.err = err.Error()
		case res != nil:
			j.last = res
		default:
			j.err = "misura terminata senza risultato"
		}
	}()
	return nil
}

// WaitSurvey attende la fine della misura in corso (per i test).
func (s *Server) WaitSurvey() {
	s.survey.mu.Lock()
	ch := s.survey.finish
	s.survey.mu.Unlock()
	if ch != nil {
		<-ch
	}
}

func (s *Server) surveyRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/wifi/survey", func(w http.ResponseWriter, r *http.Request) {
		if s.Survey == nil {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": survey.ErrUnavailable.Error()})
			return
		}
		var body struct {
			Room    string `json:"room"`
			Seconds int    `json:"seconds"`
			Scan    *bool  `json:"scan"`
		}
		if code, err := readJSON(w, r, &body); err != nil {
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		room, err := survey.Room(body.Room)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		secs, err := survey.Seconds(body.Seconds)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		opt := survey.Options{Room: room, Seconds: secs, Scan: body.Scan == nil || *body.Scan}
		if err := s.startSurvey(opt); err != nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"started": true, "room": room, "seconds": secs, "scan": opt.Scan})
	})
	mux.HandleFunc("GET /api/wifi/survey", func(w http.ResponseWriter, r *http.Request) {
		j := &s.survey
		j.mu.Lock()
		st := surveyState{Running: j.running, Room: j.room, Progress: j.prog, Error: j.err, Result: j.last}
		j.mu.Unlock()
		writeJSON(w, 200, st)
	})
	mux.HandleFunc("DELETE /api/wifi/survey", func(w http.ResponseWriter, r *http.Request) {
		s.survey.mu.Lock()
		cancel := s.survey.cancel
		s.survey.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		writeJSON(w, 200, map[string]bool{"stopping": cancel != nil})
	})
}
