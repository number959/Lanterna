package server

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"lanterna/internal/l2disc"
	"lanterna/internal/netdisc"
	"lanterna/internal/snmp"
)

// Scoperta delle altre reti e delle VLAN, solo su richiesta:
//
//	POST   /api/discover/l2    ascolta per circa un minuto gli annunci che lo
//	                           switch manda alla porta del PC (LLDP, CDP, DTP,
//	                           Spanning Tree) ({"seconds": 61}); Polaris non
//	                           trasmette nulla. Serve l'avvio come amministratore
//	GET    /api/discover/l2    avanzamento ed esito
//	DELETE /api/discover/l2    interrompe l'ascolto
//	POST   /api/discover/ad    legge le sottoreti definite in Active Directory ({})
//	GET    /api/discover/ad    esito dell'ultima lettura
//	POST   /api/discover/snmp  legge in sola lettura uno switch o un router con le
//	                           credenziali SNMP del tecnico ({"target": "10.0.0.2",
//	                           "authorized": true, "creds": {"version": "3", ...}}).
//	                           Le credenziali restano in memoria solo per la
//	                           durata della lettura: non si salvano, non si
//	                           restituiscono e non compaiono nei messaggi
//	GET    /api/discover/snmp  avanzamento ed esiti, uno per dispositivo
//	DELETE /api/discover/snmp  interrompe la lettura

// discJob è lo stato di una scoperta (protetto da mu).
type discJob struct {
	mu      sync.Mutex
	running bool
	started time.Time
	seconds int    // durata prevista (ascolto)
	target  string // dispositivo letto (SNMP)
	step    string // passo in corso (SNMP)
	err     string
	errKind string
	cancel  context.CancelFunc
	finish  chan struct{}
}

// discoverJobs raccoglie le tre scoperte: possono procedere insieme perché
// l'ascolto è passivo e le altre due fanno poche richieste.
type discoverJobs struct {
	l2     discJob
	l2Last *l2disc.Discovery
	ad     discJob
	adLast *netdisc.ADSubnets
	sn     discJob
	snLast []snmpEntry // le letture più recenti, una per dispositivo
}

// snmpEntry è l'esito di una lettura SNMP. DefaultCommunity segnala che il
// tecnico ha usato una community predefinita ("public" o "private"): la
// community non si conserva, si conserva solo questo fatto.
type snmpEntry struct {
	*snmp.Result
	DefaultCommunity bool `json:"defaultCommunity,omitempty"`
}

// maxSnmpResults è il numero massimo di dispositivi di cui si conserva l'ultima lettura.
const maxSnmpResults = 16

type discState struct {
	Running   bool   `json:"running"`
	StartedAt string `json:"startedAt,omitempty"`
	Seconds   int    `json:"seconds,omitempty"` // durata prevista dell'ascolto
	Elapsed   int    `json:"elapsed,omitempty"` // secondi trascorsi
	Target    string `json:"target,omitempty"`
	Step      string `json:"step,omitempty"`
	Error     string `json:"error,omitempty"`
	ErrorKind string `json:"errorKind,omitempty"`
	Result    any    `json:"result,omitempty"`
	Results   any    `json:"results,omitempty"`
}

var errDiscRunning = errors.New("scoperta già in corso: attendi che finisca o interrompila")

// state legge lo stato del lavoro; il chiamante tiene j.mu.
func (j *discJob) state() discState {
	st := discState{Running: j.running, Seconds: j.seconds, Target: j.target, Step: j.step, Error: j.err, ErrorKind: j.errKind}
	if !j.started.IsZero() {
		st.StartedAt = j.started.UTC().Format(time.RFC3339)
		if j.running {
			st.Elapsed = int(time.Since(j.started).Seconds())
		}
	}
	return st
}

// begin segna l'avvio; false se il lavoro è già in corso. Restituisce il
// contesto con il tempo massimo e il canale da chiudere alla fine.
func (j *discJob) begin(limit time.Duration) (context.Context, chan struct{}, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.running {
		return nil, nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	j.running, j.started, j.err, j.errKind, j.step, j.cancel = true, time.Now(), "", "", "", cancel
	j.finish = make(chan struct{})
	return ctx, j.finish, true
}

// end chiude il lavoro con l'eventuale errore (in italiano); il chiamante
// aggiorna l'esito nella stessa sezione critica tramite save.
func (j *discJob) end(err error, kind string, save func()) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.cancel != nil {
		j.cancel()
	}
	j.running, j.cancel, j.step = false, nil, ""
	if err != nil {
		j.err, j.errKind = err.Error(), kind
	}
	if save != nil {
		save()
	}
}

func (j *discJob) stop() bool {
	j.mu.Lock()
	cancel := j.cancel
	j.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return cancel != nil
}

func (j *discJob) wait() {
	j.mu.Lock()
	ch := j.finish
	j.mu.Unlock()
	if ch != nil {
		<-ch
	}
}

// WaitDiscover attende la fine delle scoperte in corso (per i test).
func (s *Server) WaitDiscover() {
	s.disc.l2.wait()
	s.disc.ad.wait()
	s.disc.sn.wait()
}

// defaultCommunity riconosce le community preimpostate su molti dispositivi.
func defaultCommunity(c snmp.Creds) bool {
	if v := strings.TrimSpace(c.Version); v == "3" || strings.EqualFold(v, "v3") {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(c.Community)) {
	case "public", "private":
		return true
	}
	return false
}

func (s *Server) discoverRoutes(mux *http.ServeMux) {
	d := &s.disc

	// ------------------------------------------------ ascolto degli switch
	mux.HandleFunc("POST /api/discover/l2", func(w http.ResponseWriter, r *http.Request) {
		if s.ListenL2 == nil {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "ascolto degli annunci degli switch non disponibile"})
			return
		}
		var body struct {
			Seconds int `json:"seconds"`
		}
		if code, err := readJSON(w, r, &body); err != nil {
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		secs := body.Seconds
		if secs <= 0 {
			secs = int(l2disc.DefaultDuration / time.Second)
		}
		if secs < 10 || secs > 180 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "durata dell'ascolto non valida: da 10 a 180 secondi"})
			return
		}
		// Margine per avvio e chiusura della cattura.
		ctx, finish, ok := d.l2.begin(time.Duration(secs)*time.Second + 45*time.Second)
		if !ok {
			writeJSON(w, http.StatusConflict, map[string]string{"error": errDiscRunning.Error()})
			return
		}
		d.l2.mu.Lock()
		d.l2.seconds = secs
		d.l2.mu.Unlock()
		go func() {
			defer close(finish)
			var res l2disc.Discovery
			var err error
			func() {
				defer func() {
					if r := recover(); r != nil {
						err = errors.New("errore interno durante l'ascolto")
					}
				}()
				res = s.ListenL2(ctx, time.Duration(secs)*time.Second)
			}()
			// Un ascolto interrotto da chi lo ha avviato non sostituisce
			// l'esito precedente: resta solo il messaggio.
			if err == nil && errors.Is(ctx.Err(), context.Canceled) {
				msg := res.Error
				if msg == "" {
					msg = "ascolto interrotto"
				}
				err = errors.New(msg)
			}
			d.l2.end(err, "", func() {
				if err == nil {
					d.l2Last = &res
				}
			})
		}()
		writeJSON(w, http.StatusAccepted, map[string]any{"started": true, "seconds": secs})
	})
	mux.HandleFunc("GET /api/discover/l2", func(w http.ResponseWriter, r *http.Request) {
		d.l2.mu.Lock()
		st := d.l2.state()
		if d.l2Last != nil {
			st.Result = d.l2Last
		}
		d.l2.mu.Unlock()
		writeJSON(w, 200, st)
	})
	mux.HandleFunc("DELETE /api/discover/l2", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]bool{"stopping": d.l2.stop()})
	})

	// ----------------------------------------- sottoreti di Active Directory
	mux.HandleFunc("POST /api/discover/ad", func(w http.ResponseWriter, r *http.Request) {
		if s.ADSubnets == nil {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "lettura delle sottoreti di Active Directory non disponibile"})
			return
		}
		var body struct{}
		if code, err := readJSON(w, r, &body); err != nil {
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		ctx, finish, ok := d.ad.begin(40 * time.Second)
		if !ok {
			writeJSON(w, http.StatusConflict, map[string]string{"error": errDiscRunning.Error()})
			return
		}
		go func() {
			defer close(finish)
			var res netdisc.ADSubnets
			var err error
			func() {
				defer func() {
					if r := recover(); r != nil {
						err = errors.New("errore interno durante la lettura di Active Directory")
					}
				}()
				res = s.ADSubnets(ctx)
			}()
			d.ad.end(err, "", func() {
				if err == nil {
					d.adLast = &res
				}
			})
		}()
		writeJSON(w, http.StatusAccepted, map[string]any{"started": true})
	})
	mux.HandleFunc("GET /api/discover/ad", func(w http.ResponseWriter, r *http.Request) {
		d.ad.mu.Lock()
		st := d.ad.state()
		if d.adLast != nil {
			st.Result = d.adLast
		}
		d.ad.mu.Unlock()
		writeJSON(w, 200, st)
	})

	// ------------------------------------------------------- lettura SNMP
	mux.HandleFunc("POST /api/discover/snmp", func(w http.ResponseWriter, r *http.Request) {
		if s.SNMP == nil {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "lettura SNMP non disponibile"})
			return
		}
		var body struct {
			Target     string     `json:"target"`
			Authorized bool       `json:"authorized"`
			Creds      snmp.Creds `json:"creds"`
		}
		if code, err := readJSON(w, r, &body); err != nil {
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		if !body.Authorized {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "serve la conferma esplicita di essere autorizzati a interrogare questo dispositivo"})
			return
		}
		cr := body.Creds
		def := defaultCommunity(cr)
		ctx, finish, ok := d.sn.begin(2 * time.Minute)
		if !ok {
			writeJSON(w, http.StatusConflict, map[string]string{"error": errDiscRunning.Error()})
			return
		}
		target := strings.TrimSpace(body.Target)
		d.sn.mu.Lock()
		d.sn.target = ""
		if len(target) <= 15 && !strings.ContainsAny(target, " \t") {
			// Nei messaggi compare solo un indirizzo plausibile: nel campo
			// potrebbe essere finita per sbaglio una password.
			d.sn.target = target
		}
		d.sn.mu.Unlock()
		go func() {
			defer close(finish)
			var res *snmp.Result
			var err error
			func() {
				defer func() {
					if r := recover(); r != nil {
						err = errors.New("errore interno durante la lettura SNMP")
					}
				}()
				res, err = s.SNMP(ctx, target, cr, func(step string) {
					d.sn.mu.Lock()
					d.sn.step = step
					d.sn.mu.Unlock()
				})
			}()
			kind := ""
			var se *snmp.Error
			if errors.As(err, &se) {
				kind = string(se.Kind)
			}
			d.sn.end(err, kind, func() {
				if res == nil {
					return
				}
				e := snmpEntry{Result: res, DefaultCommunity: def}
				d.snLast = slices.DeleteFunc(d.snLast, func(x snmpEntry) bool { return x.Target == res.Target })
				d.snLast = append([]snmpEntry{e}, d.snLast...)
				if len(d.snLast) > maxSnmpResults {
					d.snLast = d.snLast[:maxSnmpResults]
				}
			})
		}()
		writeJSON(w, http.StatusAccepted, map[string]any{"started": true})
	})
	mux.HandleFunc("GET /api/discover/snmp", func(w http.ResponseWriter, r *http.Request) {
		d.sn.mu.Lock()
		st := d.sn.state()
		st.Results = slices.Clone(d.snLast)
		if d.snLast == nil {
			st.Results = []snmpEntry{}
		}
		d.sn.mu.Unlock()
		writeJSON(w, 200, st)
	})
	mux.HandleFunc("DELETE /api/discover/snmp", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]bool{"stopping": d.sn.stop()})
	})
}
