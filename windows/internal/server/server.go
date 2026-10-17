// Package server espone l'interfaccia web e le API usate dall'interfaccia:
//
//	GET  /api/info      informazioni sull'agente
//	GET  /api/scan      ultima analisi (204 se non ancora eseguita)
//	POST /api/scan      avvia una nuova analisi (409 se già in corso)
//	GET  /api/progress  avanzamento reale dell'analisi in corso
//	GET  /api/ping      un singolo ping (target=gateway|internet) per il monitor
//	POST /api/inventory avvia l'inventario della sottorete ({"authorized": true})
//	GET  /api/inventory avanzamento e ultimo inventario
//	POST /api/reach     verifiche di raggiungibilità ({"targets": [...]})
//	GET  /api/reach     ultime verifiche (204 se nessuna)
//
// Ascolta solo su 127.0.0.1 e rifiuta richieste con Host diverso (difesa dal
// DNS rebinding) e POST provenienti da altre origini (difesa dal CSRF). Le
// richieste che generano traffico verso altri dispositivi (inventario e
// verifiche) devono inoltre avere un corpo JSON: un modulo HTML di un altro
// sito non può inviarlo senza un controllo preventivo che il server non accetta.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"lanterna/internal/collect"
	"lanterna/internal/infra"
	"lanterna/internal/scan"
)

// I font dell'interfaccia (woff2) e il favicon (ico) hanno il tipo dichiarato qui:
// la tabella interna di Go non li contiene e il registro di Windows non sempre li riporta.
func init() {
	_ = mime.AddExtensionType(".woff2", "font/woff2")
	_ = mime.AddExtensionType(".ico", "image/x-icon")
}

type Server struct {
	Collector *collect.Collector
	Web       fs.FS // interfaccia; nil = solo API
	Version   string
	// Ping misura un singolo tempo di risposta (nil = nessuna risposta).
	// preferTCP è vero quando nell'ultima analisi quell'host ha risposto solo via TCP.
	Ping func(ctx context.Context, ip string, tcpPorts []int, preferTCP bool) *float64

	// Infra abilita inventario e verifiche di raggiungibilità (nil = non disponibili).
	Infra    *infra.Prims
	InfraOpt infra.Options

	invMu      sync.Mutex
	invRunning bool
	invPhase   string
	invDone    int
	invTotal   int
	invErr     string
	invLast    *scan.Inventory
	invFinish  chan struct{}
	reachMu    sync.Mutex
	reachBusy  bool
	reachLast  *scan.ReachData

	mu       sync.Mutex
	last     []byte
	gateway  string
	methods  map[string]string // ip -> "icmp" | "tcp" nell'ultima analisi
	running  bool
	steps    []collect.Step
	runErr   string
	scanDone chan struct{}
}

type progress struct {
	Running bool           `json:"running"`
	Steps   []collect.Step `json:"steps"`
	Error   string         `json:"error,omitempty"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// Start avvia un'analisi in background; false se ce n'è già una in corso.
func (s *Server) Start() bool {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return false
	}
	s.running, s.runErr, s.steps = true, "", nil
	s.scanDone = make(chan struct{})
	done := s.scanDone
	s.mu.Unlock()
	go func() {
		defer close(done)
		var result *scan.Scan
		func() {
			defer func() {
				if r := recover(); r != nil {
					s.mu.Lock()
					s.runErr = "errore interno durante l'analisi"
					s.mu.Unlock()
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			result = s.Collector.Run(ctx, func(st []collect.Step) {
				s.mu.Lock()
				s.steps = st
				s.mu.Unlock()
			})
		}()
		s.mu.Lock()
		defer s.mu.Unlock()
		s.running = false
		if result != nil {
			s.last, _ = json.Marshal(result)
			s.methods = map[string]string{}
			if result.Gateway != nil {
				s.gateway = result.Gateway.IP
				if p := result.Gateway.Ping; p != nil && p.Received > 0 {
					s.methods[p.Target] = p.Method
				}
			}
			if result.Internet != nil {
				for _, t := range result.Internet.Targets {
					if t.Received > 0 {
						s.methods[t.Target] = t.Method
					}
				}
			}
		}
	}()
	return true
}

// Wait attende la fine dell'analisi in corso (usato dai test).
func (s *Server) Wait() {
	s.mu.Lock()
	ch := s.scanDone
	s.mu.Unlock()
	if ch != nil {
		<-ch
	}
}

type inventoryState struct {
	Running bool            `json:"running"`
	Phase   string          `json:"phase,omitempty"`
	Done    int             `json:"done"`
	Total   int             `json:"total"`
	Error   string          `json:"error,omitempty"`
	Result  *scan.Inventory `json:"result,omitempty"`
}

// readJSON accetta solo corpi JSON piccoli.
func readJSON(w http.ResponseWriter, r *http.Request, v any) (int, error) {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(ct), "application/json") {
		return http.StatusUnsupportedMediaType, errors.New("serve un corpo JSON (Content-Type: application/json)")
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return http.StatusBadRequest, errors.New("JSON non valido")
	}
	return 0, nil
}

// network individua la scheda principale: la prima attiva con un gateway
// IPv4 (le schede arrivano già ordinate come le sceglie Windows).
func (s *Server) network() (infra.InventoryRequest, error) {
	ads, err := s.Collector.Platform.Adapters()
	if err != nil {
		return infra.InventoryRequest{}, err
	}
	for _, a := range ads {
		if !a.Up || a.Kind == "loopback" {
			continue
		}
		gw := ""
		for _, g := range a.Gateways {
			if net.ParseIP(g).To4() != nil {
				gw = g
				break
			}
		}
		for _, c := range a.IPv4 {
			if ip, _, err := net.ParseCIDR(c); err == nil && !ip.IsLinkLocalUnicast() && gw != "" {
				return infra.InventoryRequest{CIDR: c, Adapter: a.Name, Gateway: gw, SelfMAC: a.MAC}, nil
			}
		}
	}
	return infra.InventoryRequest{}, errors.New("nessuna scheda di rete collegata con un indirizzo IPv4 e un gateway")
}

// WaitInventory attende la fine dell'inventario in corso (usato dai test).
func (s *Server) WaitInventory() {
	s.invMu.Lock()
	ch := s.invFinish
	s.invMu.Unlock()
	if ch != nil {
		<-ch
	}
}

func (s *Server) startInventory(req infra.InventoryRequest) bool {
	s.invMu.Lock()
	if s.invRunning {
		s.invMu.Unlock()
		return false
	}
	s.invRunning, s.invErr, s.invPhase, s.invDone, s.invTotal = true, "", "ping", 0, 0
	s.invFinish = make(chan struct{})
	finish := s.invFinish
	s.invMu.Unlock()
	go func() {
		defer close(finish)
		var inv *scan.Inventory
		var err error
		func() {
			defer func() {
				if r := recover(); r != nil {
					err = errors.New("errore interno durante l'inventario")
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
			defer cancel()
			inv, err = infra.Inventory(ctx, req, *s.Infra, s.InfraOpt, func(phase string, done, total int) {
				s.invMu.Lock()
				s.invPhase, s.invDone, s.invTotal = phase, done, total
				s.invMu.Unlock()
			})
		}()
		s.invMu.Lock()
		defer s.invMu.Unlock()
		s.invRunning = false
		if err != nil {
			s.invErr = err.Error()
		} else {
			s.invLast = inv
		}
	}()
	return true
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/info", func(w http.ResponseWriter, r *http.Request) {
		host, _ := os.Hostname()
		writeJSON(w, 200, map[string]string{"name": "STARNET Polaris", "version": s.Version, "platform": "windows", "host": host})
	})
	mux.HandleFunc("GET /api/scan", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		last := s.last
		s.mu.Unlock()
		if last == nil {
			w.WriteHeader(http.StatusNoContent) // nessuna analisi ancora: non è un errore
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write(last)
	})
	mux.HandleFunc("POST /api/scan", func(w http.ResponseWriter, r *http.Request) {
		if !s.Start() {
			writeJSON(w, 409, map[string]string{"error": "analisi già in corso"})
			return
		}
		writeJSON(w, 202, map[string]bool{"started": true})
	})
	mux.HandleFunc("GET /api/progress", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		p := progress{Running: s.running, Steps: s.steps, Error: s.runErr}
		s.mu.Unlock()
		if p.Steps == nil {
			p.Steps = []collect.Step{}
		}
		writeJSON(w, 200, p)
	})
	mux.HandleFunc("GET /api/ping", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("target")
		var ip string
		var ports []int
		switch target {
		case "gateway":
			s.mu.Lock()
			ip = s.gateway
			s.mu.Unlock()
			ports = []int{80, 443, 53}
		case "internet":
			ip, ports = collect.InternetTargets[0].IP, []int{443, 53}
		default:
			writeJSON(w, 400, map[string]string{"error": "target deve essere gateway o internet"})
			return
		}
		var v *float64
		if ip != "" && s.Ping != nil {
			s.mu.Lock()
			tcp := s.methods[ip] == "tcp"
			s.mu.Unlock()
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			v = s.Ping(ctx, ip, ports, tcp)
			cancel()
		}
		writeJSON(w, 200, map[string]any{"target": target, "ip": ip, "ms": v})
	})
	mux.HandleFunc("POST /api/inventory", func(w http.ResponseWriter, r *http.Request) {
		if s.Infra == nil {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "inventario non disponibile"})
			return
		}
		var body struct {
			Authorized bool `json:"authorized"`
		}
		if code, err := readJSON(w, r, &body); err != nil {
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		if !body.Authorized {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "serve la conferma esplicita di essere autorizzati ad analizzare questa rete"})
			return
		}
		req, err := s.network()
		if err == nil {
			_, _, _, err = infra.Plan(req.CIDR)
		}
		if err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
			return
		}
		if !s.startInventory(req) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "inventario già in corso"})
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"started": true, "network": req.CIDR, "adapter": req.Adapter})
	})
	mux.HandleFunc("GET /api/inventory", func(w http.ResponseWriter, r *http.Request) {
		s.invMu.Lock()
		st := inventoryState{Running: s.invRunning, Phase: s.invPhase, Done: s.invDone, Total: s.invTotal, Error: s.invErr, Result: s.invLast}
		s.invMu.Unlock()
		writeJSON(w, 200, st)
	})
	mux.HandleFunc("POST /api/reach", func(w http.ResponseWriter, r *http.Request) {
		if s.Infra == nil {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "verifiche non disponibili"})
			return
		}
		var body struct {
			Targets []scan.ReachTarget `json:"targets"`
		}
		if code, err := readJSON(w, r, &body); err != nil {
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		if err := infra.Validate(body.Targets); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		s.reachMu.Lock()
		if s.reachBusy {
			s.reachMu.Unlock()
			writeJSON(w, http.StatusConflict, map[string]string{"error": "verifiche già in corso"})
			return
		}
		s.reachBusy = true
		s.reachMu.Unlock()
		defer func() {
			s.reachMu.Lock()
			s.reachBusy = false
			s.reachMu.Unlock()
		}()
		from := ""
		if req, err := s.network(); err == nil {
			from = strings.SplitN(req.CIDR, "/", 2)[0]
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
		defer cancel()
		res, err := infra.Reach(ctx, body.Targets, from, *s.Infra, s.InfraOpt)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		s.reachMu.Lock()
		s.reachLast = res
		s.reachMu.Unlock()
		writeJSON(w, 200, res)
	})
	mux.HandleFunc("GET /api/reach", func(w http.ResponseWriter, r *http.Request) {
		s.reachMu.Lock()
		last := s.reachLast
		s.reachMu.Unlock()
		if last == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, 200, last)
	})
	if s.Web != nil {
		files := http.FileServer(http.FS(s.Web))
		mux.Handle("GET /", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
			files.ServeHTTP(w, r)
		}))
	}
	return guard(mux)
}

func isLocalHost(hostport string) bool {
	h := hostport
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		h = host
	}
	h = strings.Trim(h, "[]")
	return h == "127.0.0.1" || h == "localhost" || h == "::1"
}

func guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLocalHost(r.Host) {
			http.Error(w, "host non consentito", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if o := r.Header.Get("Origin"); o != "" && o != "http://"+r.Host {
				http.Error(w, "origine non consentita", http.StatusForbidden)
				return
			}
			if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
				http.Error(w, "origine non consentita", http.StatusForbidden)
				return
			}
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// Listen apre la porta indicata (0 = libera a caso) solo in locale.
func Listen(port int) (net.Listener, error) {
	return net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
}
