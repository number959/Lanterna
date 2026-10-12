// Package server espone l'interfaccia web e le API usate dall'interfaccia:
//
//	GET  /api/info      informazioni sull'agente
//	GET  /api/scan      ultima analisi (204 se non ancora eseguita)
//	POST /api/scan      avvia una nuova analisi (409 se già in corso)
//	GET  /api/progress  avanzamento reale dell'analisi in corso
//	GET  /api/ping      un singolo ping (target=gateway|internet) per il monitor
//
// Ascolta solo su 127.0.0.1 e rifiuta richieste con Host diverso (difesa dal
// DNS rebinding) e POST provenienti da altre origini (difesa dal CSRF).
package server

import (
	"context"
	"encoding/json"
	"io/fs"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"lanterna/internal/collect"
	"lanterna/internal/scan"
)

type Server struct {
	Collector *collect.Collector
	Web       fs.FS // interfaccia; nil = solo API
	Version   string
	// Ping misura un singolo tempo di risposta (nil = nessuna risposta).
	// preferTCP è vero quando nell'ultima analisi quell'host ha risposto solo via TCP.
	Ping func(ctx context.Context, ip string, tcpPorts []int, preferTCP bool) *float64

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

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/info", func(w http.ResponseWriter, r *http.Request) {
		host, _ := os.Hostname()
		writeJSON(w, 200, map[string]string{"name": "LANterna", "version": s.Version, "platform": "windows", "host": host})
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
