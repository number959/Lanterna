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
//	POST /api/bench     avvia un test di velocità ({"kind": "cpu"} oppure
//	                    {"kind": "disk", "drive": "C:", "confirm": true})
//	GET  /api/bench     avanzamento e ultimi risultati dei test di velocità
//	DELETE /api/bench   interrompe il test in corso
//	POST /api/defender  avvia un'operazione di Microsoft Defender
//	                    ({"action": "quick" | "full" | "update"})
//	GET  /api/defender  stato ed esito dell'ultima operazione
//	DELETE /api/defender interrompe la scansione in corso
//	GET  /api/cpu/clock frequenza effettiva dei core in questo istante (il
//	                    "Core Speed" di CPU-Z), dai contatori di Windows
//	GET  /api/tools     programmi della cassetta degli attrezzi installati,
//	                    inclusi nel pacchetto e scaricati, con il download in corso
//	POST /api/tools/fetch scarica dal sito ufficiale la versione portable
//	                    ({"tool": "cpu-z"}) e ne verifica la firma
//	DELETE /api/tools/fetch interrompe il download in corso (anche del kit)
//	POST /api/tools/kit prepara il kit per l'uso senza Internet: scarica e
//	                    verifica i programmi indicati nella cartella
//	                    strumenti-scaricati accanto a Polaris
//	                    ({"tools": ["cpu-z", "autoruns"]})
//	POST /api/tools/remove elimina una copia scaricata ({"tool": "cpu-z"})
//	POST /api/open      apre uno strumento di Windows, un programma incluso,
//	                    scaricato o installato, o il sito ufficiale
//	                    ({"tool": "cpu-z", "target": "site"})
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
	"maps"
	"mime"
	"net"
	"net/http"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"lanterna/internal/bench"
	"lanterna/internal/collect"
	"lanterna/internal/cpuclock"
	"lanterna/internal/defender"
	"lanterna/internal/infra"
	"lanterna/internal/scan"
	"lanterna/internal/sensors"
	"lanterna/internal/space"
	"lanterna/internal/tools"
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
	// CPUClock legge la frequenza effettiva dei core (nil: non disponibile).
	CPUClock func(ctx context.Context) (cpuclock.Sample, error)
	// Sensors legge il monitor dei sensori (nil: non disponibile).
	Sensors func(ctx context.Context) (sensors.Snapshot, error)

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

	// Test di velocità (nil = non disponibili). Non partono durante
	// un'analisi e viceversa: si falserebbero a vicenda.
	BenchCPU  func(ctx context.Context, report bench.Report) (*scan.CPUBench, error)
	BenchDisk func(ctx context.Context, drive string, report bench.Report) (*scan.DiskBench, error)
	// BenchDrive verifica subito che l'unità si possa provare (nil = nessun controllo).
	BenchDrive func(drive string) error

	benchMu      sync.Mutex
	benchRunning bool
	benchKind    string
	benchDrive   string
	benchProg    *bench.Progress
	benchErr     string
	benchCancel  context.CancelFunc
	benchCPU     *scan.CPUBench
	benchDisk    *scan.DiskBench
	benchFinish  chan struct{}

	// Analisi dello spazio (nil = non disponibile): che cosa occupa
	// un'unità, su richiesta. Non si sovrappone ai test di velocità, che ne
	// sarebbero falsati.
	SpaceScan func(ctx context.Context, root string, opt space.Options) (*space.Result, error)
	// SpaceOpen apre una cartella (o la cartella di un file) in Esplora file.
	SpaceOpen func(path string, selectFile bool) error

	spaceMu      sync.Mutex
	spaceRunning bool
	spaceDrive   string
	spaceProg    *space.Progress
	spaceErr     string
	spaceCancel  context.CancelFunc
	spaceLast    *scan.SpaceReport
	spaceResults map[string]*space.Result
	spaceFinish  chan struct{}

	// Microsoft Defender (nil = non disponibile): scansioni e aggiornamento
	// delle firme su richiesta. Non si sovrappongono ai test di velocità.
	DefenderRun func(ctx context.Context, action string) (*defender.Result, error)
	// DefenderReady verifica subito che Defender sia presente (nil = nessun controllo).
	DefenderReady func() error

	// Cassetta degli attrezzi (nil = non disponibile): programmi installati,
	// programmi inclusi nel pacchetto e apertura per identificativo, solo dalla
	// lista bianca.
	Tools    func() map[string]tools.Installed
	Bundled  func() map[string]tools.Included
	OpenTool func(id, target string) error

	// Versioni portable (nil = non disponibili): copie scaricate, download dal
	// sito ufficiale su richiesta, uno alla volta, ed eliminazione.
	Portable   func() map[string]tools.Downloaded
	FetchTool  func(ctx context.Context, id string, progress func(done, total int64)) (tools.Downloaded, error)
	RemoveTool func(id string) error
	// FetchKit scarica nel kit accanto a Polaris; KitCheck controlla prima
	// che la cartella si possa scrivere.
	FetchKit func(ctx context.Context, id string, progress func(done, total int64)) (tools.Downloaded, error)
	KitCheck func() error

	fetchMu      sync.Mutex
	fetchRunning bool
	fetchTool    string
	fetchDone    int64
	fetchTotal   int64
	fetchErr     string
	fetchCancel  context.CancelFunc
	fetchKit     bool
	fetchQueue   []string
	fetchReady   []string
	fetchFailed  map[string]string

	defMu      sync.Mutex
	defRunning bool
	defAction  string
	defStarted string
	defErr     string
	defResult  *defender.Result
	defCancel  context.CancelFunc
	defFinish  chan struct{}

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

var (
	errScanRunning  = errors.New("analisi già in corso")
	errBenchRunning = errors.New("test di velocità in corso: attendi che finisca o interrompilo")
)

// Start avvia un'analisi in background; false se ce n'è già una in corso o
// se un test di velocità sta girando.
func (s *Server) Start() bool { return s.startScan() == nil }

func (s *Server) startScan() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return errScanRunning
	}
	s.benchMu.Lock()
	busy := s.benchRunning
	s.benchMu.Unlock()
	if busy {
		s.mu.Unlock()
		return errBenchRunning
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
	return nil
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

type benchState struct {
	Running  bool            `json:"running"`
	Kind     string          `json:"kind,omitempty"`
	Drive    string          `json:"drive,omitempty"`
	Progress *bench.Progress `json:"progress,omitempty"`
	Error    string          `json:"error,omitempty"`
	CPU      *scan.CPUBench  `json:"cpu,omitempty"`
	Disk     *scan.DiskBench `json:"disk,omitempty"`
}

// startBench avvia un test in background. L'ordine dei lock (prima mu, poi
// benchMu) è lo stesso di startScan.
func (s *Server) startBench(kind, drive string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return errors.New("analisi in corso: il test di velocità ne falserebbe le misure")
	}
	s.benchMu.Lock()
	defer s.benchMu.Unlock()
	if s.benchRunning {
		return errors.New("test di velocità già in corso")
	}
	s.defMu.Lock()
	defBusy := s.defRunning
	s.defMu.Unlock()
	if defBusy {
		return errors.New("operazione di Microsoft Defender in corso: il test di velocità ne sarebbe falsato")
	}
	s.spaceMu.Lock()
	spaceBusy := s.spaceRunning
	s.spaceMu.Unlock()
	if spaceBusy {
		return errors.New("analisi dello spazio in corso: il test di velocità ne sarebbe falsato")
	}
	timeout := 2 * time.Minute
	if kind == "disk" {
		timeout = 3 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	s.benchRunning, s.benchKind, s.benchDrive, s.benchErr, s.benchProg, s.benchCancel = true, kind, drive, "", nil, cancel
	s.benchFinish = make(chan struct{})
	finish := s.benchFinish
	go func() {
		defer close(finish)
		defer cancel()
		report := func(p bench.Progress) {
			s.benchMu.Lock()
			s.benchProg = &p
			s.benchMu.Unlock()
		}
		var cpu *scan.CPUBench
		var disk *scan.DiskBench
		var err error
		func() {
			defer func() {
				if r := recover(); r != nil {
					err = errors.New("errore interno durante il test")
				}
			}()
			if kind == "cpu" {
				cpu, err = s.BenchCPU(ctx, report)
			} else {
				disk, err = s.BenchDisk(ctx, drive, report)
			}
		}()
		s.benchMu.Lock()
		defer s.benchMu.Unlock()
		s.benchRunning, s.benchCancel = false, nil
		switch {
		case errors.Is(err, context.Canceled):
			s.benchErr = "test interrotto"
		case errors.Is(err, context.DeadlineExceeded):
			s.benchErr = "test interrotto: tempo massimo superato"
		case err != nil:
			s.benchErr = err.Error()
		case cpu != nil:
			s.benchCPU = cpu
		case disk != nil:
			s.benchDisk = disk
		}
	}()
	return nil
}

type spaceState struct {
	Running  bool              `json:"running"`
	Drive    string            `json:"drive,omitempty"`
	Progress *space.Progress   `json:"progress,omitempty"`
	Error    string            `json:"error,omitempty"`
	Result   *scan.SpaceReport `json:"result,omitempty"`
}

// startSpace avvia l'analisi dello spazio di un'unità in background. Ordine
// dei lock: benchMu prima di spaceMu, come in startBench.
func (s *Server) startSpace(drive string) error {
	s.benchMu.Lock()
	defer s.benchMu.Unlock()
	if s.benchRunning {
		return errors.New("test di velocità in corso: l'analisi dello spazio ne falserebbe le misure")
	}
	s.spaceMu.Lock()
	defer s.spaceMu.Unlock()
	if s.spaceRunning {
		return errors.New("analisi dello spazio già in corso")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	s.spaceRunning, s.spaceDrive, s.spaceErr, s.spaceProg, s.spaceCancel = true, drive, "", nil, cancel
	s.spaceFinish = make(chan struct{})
	finish := s.spaceFinish
	go func() {
		defer close(finish)
		defer cancel()
		opt := space.Options{Progress: func(p space.Progress) {
			s.spaceMu.Lock()
			s.spaceProg = &p
			s.spaceMu.Unlock()
		}}
		var res *space.Result
		var err error
		func() {
			defer func() {
				if r := recover(); r != nil {
					err = errors.New("errore interno durante l'analisi dello spazio")
				}
			}()
			res, err = s.SpaceScan(ctx, drive+`\`, opt)
		}()
		s.spaceMu.Lock()
		defer s.spaceMu.Unlock()
		s.spaceRunning, s.spaceCancel = false, nil
		switch {
		case errors.Is(err, context.Canceled):
			s.spaceErr = "analisi interrotta: i valori sono parziali"
		case errors.Is(err, context.DeadlineExceeded):
			s.spaceErr = "analisi interrotta dopo 30 minuti: i valori sono parziali"
		case err != nil:
			s.spaceErr = err.Error()
		}
		// Anche un'analisi interrotta mostra ciò che ha letto (Partial).
		if res != nil {
			if s.spaceResults == nil {
				s.spaceResults = map[string]*space.Result{}
			}
			s.spaceResults[drive] = res
			s.spaceLast = &res.Report
		}
	}()
	return nil
}

// WaitSpace attende la fine dell'analisi dello spazio in corso (per i test).
func (s *Server) WaitSpace() {
	s.spaceMu.Lock()
	ch := s.spaceFinish
	s.spaceMu.Unlock()
	if ch != nil {
		<-ch
	}
}

type defenderState struct {
	Running   bool             `json:"running"`
	Action    string           `json:"action,omitempty"`
	StartedAt string           `json:"startedAt,omitempty"`
	Error     string           `json:"error,omitempty"`
	Result    *defender.Result `json:"result,omitempty"`
}

// startDefender avvia un'operazione di Defender in background. Ordine dei
// lock: benchMu prima di defMu, come in startBench.
func (s *Server) startDefender(action string) error {
	s.benchMu.Lock()
	defer s.benchMu.Unlock()
	if s.benchRunning {
		return errors.New("test di velocità in corso: la scansione ne falserebbe le misure")
	}
	s.defMu.Lock()
	defer s.defMu.Unlock()
	if s.defRunning {
		return errors.New("operazione di Microsoft Defender già in corso")
	}
	ctx, cancel := context.WithTimeout(context.Background(), defender.Timeouts[action])
	s.defRunning, s.defAction, s.defStarted, s.defErr, s.defCancel = true, action, time.Now().UTC().Format(time.RFC3339), "", cancel
	s.defFinish = make(chan struct{})
	finish := s.defFinish
	go func() {
		defer close(finish)
		defer cancel()
		var res *defender.Result
		var err error
		func() {
			defer func() {
				if r := recover(); r != nil {
					err = errors.New("errore interno durante l'operazione")
				}
			}()
			res, err = s.DefenderRun(ctx, action)
		}()
		s.defMu.Lock()
		defer s.defMu.Unlock()
		s.defRunning, s.defCancel = false, nil
		switch {
		case errors.Is(err, context.Canceled):
			s.defErr = "operazione interrotta"
		case errors.Is(err, context.DeadlineExceeded):
			s.defErr = "operazione interrotta: tempo massimo superato"
		case err != nil:
			s.defErr = err.Error()
		default:
			s.defResult = res
		}
	}()
	return nil
}

// WaitDefender attende la fine dell'operazione in corso (usato dai test).
func (s *Server) WaitDefender() {
	s.defMu.Lock()
	ch := s.defFinish
	s.defMu.Unlock()
	if ch != nil {
		<-ch
	}
}

// WaitBench attende la fine del test in corso (usato dai test).
func (s *Server) WaitBench() {
	s.benchMu.Lock()
	ch := s.benchFinish
	s.benchMu.Unlock()
	if ch != nil {
		<-ch
	}
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
		if err := s.startScan(); err != nil {
			writeJSON(w, 409, map[string]string{"error": err.Error()})
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
	mux.HandleFunc("GET /api/cpu/clock", func(w http.ResponseWriter, r *http.Request) {
		if s.CPUClock == nil {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": cpuclock.ErrUnavailable.Error()})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		smp, err := s.CPUClock(ctx)
		if err != nil {
			code := http.StatusServiceUnavailable
			if errors.Is(err, cpuclock.ErrUnavailable) {
				code = http.StatusNotImplemented
			}
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, smp)
	})
	mux.HandleFunc("GET /api/sensors", func(w http.ResponseWriter, r *http.Request) {
		if s.Sensors == nil {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": sensors.ErrUnavailable.Error()})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		snap, err := s.Sensors(ctx)
		if err != nil {
			code := http.StatusServiceUnavailable
			if errors.Is(err, sensors.ErrUnavailable) {
				code = http.StatusNotImplemented
			}
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, snap)
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
	mux.HandleFunc("POST /api/bench", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Kind    string `json:"kind"`
			Drive   string `json:"drive"`
			Confirm bool   `json:"confirm"`
		}
		if code, err := readJSON(w, r, &body); err != nil {
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		drive := ""
		switch body.Kind {
		case "cpu":
			if s.BenchCPU == nil {
				writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "test del processore non disponibile"})
				return
			}
		case "disk":
			if s.BenchDisk == nil {
				writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "test dei dischi non disponibile"})
				return
			}
			if !body.Confirm {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "serve la conferma: il test scrive sull'unità un file temporaneo, cancellato alla fine"})
				return
			}
			d, err := bench.NormalizeDrive(body.Drive)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			if s.BenchDrive != nil {
				if err := s.BenchDrive(d); err != nil {
					writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
					return
				}
			}
			drive = d
		default:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "kind deve essere cpu o disk"})
			return
		}
		if err := s.startBench(body.Kind, drive); err != nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"started": true, "kind": body.Kind, "drive": drive})
	})
	mux.HandleFunc("GET /api/bench", func(w http.ResponseWriter, r *http.Request) {
		s.benchMu.Lock()
		st := benchState{Running: s.benchRunning, Kind: s.benchKind, Drive: s.benchDrive, Progress: s.benchProg, Error: s.benchErr, CPU: s.benchCPU, Disk: s.benchDisk}
		s.benchMu.Unlock()
		writeJSON(w, 200, st)
	})
	mux.HandleFunc("DELETE /api/bench", func(w http.ResponseWriter, r *http.Request) {
		s.benchMu.Lock()
		cancel := s.benchCancel
		s.benchMu.Unlock()
		if cancel != nil {
			cancel()
		}
		writeJSON(w, 200, map[string]bool{"stopping": cancel != nil})
	})
	mux.HandleFunc("POST /api/space", func(w http.ResponseWriter, r *http.Request) {
		if s.SpaceScan == nil {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": space.ErrUnavailable.Error()})
			return
		}
		var body struct {
			Drive string `json:"drive"`
		}
		if code, err := readJSON(w, r, &body); err != nil {
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		drive := strings.ToUpper(strings.TrimSpace(body.Drive))
		if len(drive) != 2 || drive[1] != ':' || drive[0] < 'A' || drive[0] > 'Z' {
			writeJSON(w, 400, map[string]string{"error": "indicare un'unità, per esempio C:"})
			return
		}
		if err := s.startSpace(drive); err != nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"started": true, "drive": drive})
	})
	mux.HandleFunc("GET /api/space", func(w http.ResponseWriter, r *http.Request) {
		s.spaceMu.Lock()
		st := spaceState{Running: s.spaceRunning, Drive: s.spaceDrive, Progress: s.spaceProg, Error: s.spaceErr, Result: s.spaceLast}
		s.spaceMu.Unlock()
		writeJSON(w, 200, st)
	})
	mux.HandleFunc("DELETE /api/space", func(w http.ResponseWriter, r *http.Request) {
		s.spaceMu.Lock()
		cancel := s.spaceCancel
		s.spaceMu.Unlock()
		if cancel != nil {
			cancel()
		}
		writeJSON(w, 200, map[string]bool{"stopping": cancel != nil})
	})
	mux.HandleFunc("POST /api/space/open", func(w http.ResponseWriter, r *http.Request) {
		if s.SpaceOpen == nil {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": space.ErrUnavailable.Error()})
			return
		}
		var body struct {
			Drive string `json:"drive"`
			ID    int    `json:"id"`
			File  bool   `json:"file"`
		}
		if code, err := readJSON(w, r, &body); err != nil {
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		// Si aprono solo cartelle e file dell'ultima analisi, per numero: il
		// percorso vero resta nell'agente.
		s.spaceMu.Lock()
		res := s.spaceResults[strings.ToUpper(body.Drive)]
		var path string
		var found bool
		if res != nil {
			if body.File {
				path, found = res.FilePaths[body.ID]
			} else {
				path, found = res.NodePaths[body.ID]
			}
		}
		s.spaceMu.Unlock()
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "elemento non trovato: rifare l'analisi"})
			return
		}
		if err := s.SpaceOpen(path, body.File); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Esplora file non si è aperto"})
			return
		}
		writeJSON(w, 200, map[string]bool{"opened": true})
	})
	mux.HandleFunc("POST /api/defender", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Action string `json:"action"`
		}
		if code, err := readJSON(w, r, &body); err != nil {
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		if _, err := defender.Args(body.Action); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if s.DefenderRun == nil {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": defender.ErrUnavailable.Error()})
			return
		}
		if s.DefenderReady != nil {
			if err := s.DefenderReady(); err != nil {
				writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
				return
			}
		}
		if err := s.startDefender(body.Action); err != nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"started": true, "action": body.Action})
	})
	mux.HandleFunc("GET /api/defender", func(w http.ResponseWriter, r *http.Request) {
		s.defMu.Lock()
		st := defenderState{Running: s.defRunning, Action: s.defAction, StartedAt: s.defStarted, Error: s.defErr, Result: s.defResult}
		s.defMu.Unlock()
		writeJSON(w, 200, st)
	})
	mux.HandleFunc("DELETE /api/defender", func(w http.ResponseWriter, r *http.Request) {
		s.defMu.Lock()
		cancel := s.defCancel
		s.defMu.Unlock()
		if cancel != nil {
			cancel()
		}
		writeJSON(w, 200, map[string]bool{"stopping": cancel != nil})
	})
	mux.HandleFunc("GET /api/tools", func(w http.ResponseWriter, r *http.Request) {
		installed, bundled, portable := map[string]tools.Installed{}, map[string]tools.Included{}, map[string]tools.Downloaded{}
		if s.Tools != nil {
			installed = s.Tools()
		}
		if s.Bundled != nil {
			bundled = s.Bundled()
		}
		if s.Portable != nil {
			portable = s.Portable()
		}
		// Programmi che su questo PC si possono scaricare (anche nel kit).
		fetchable := []string{}
		if s.FetchTool != nil {
			for _, id := range slices.Sorted(maps.Keys(tools.Portables)) {
				if tools.CanFetch(id, runtime.GOARCH) == nil {
					fetchable = append(fetchable, id)
				}
			}
		}
		writeJSON(w, 200, map[string]any{"installed": installed, "bundled": bundled, "portable": portable, "fetchable": fetchable, "kit": s.FetchKit != nil, "fetch": s.fetchStatus()})
	})
	mux.HandleFunc("POST /api/tools/fetch", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Tool string `json:"tool"`
		}
		if code, err := readJSON(w, r, &body); err != nil {
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		if s.FetchTool == nil {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "download dei programmi non disponibile"})
			return
		}
		if err := tools.CanFetch(body.Tool, runtime.GOARCH); err != nil {
			code := http.StatusBadRequest
			if errors.Is(err, tools.ErrUnknown) {
				code = http.StatusNotFound
			}
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		if err := s.startFetch([]string{body.Tool}, false); err != nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"started": true, "tool": body.Tool})
	})
	mux.HandleFunc("POST /api/tools/kit", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Tools []string `json:"tools"`
		}
		if code, err := readJSON(w, r, &body); err != nil {
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		if s.FetchKit == nil || s.KitCheck == nil {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "kit per l'uso senza Internet non disponibile"})
			return
		}
		var ids []string
		for _, id := range body.Tools {
			if err := tools.CanFetch(id, runtime.GOARCH); err != nil {
				code := http.StatusBadRequest
				if errors.Is(err, tools.ErrUnknown) {
					code = http.StatusNotFound
				}
				writeJSON(w, code, map[string]string{"error": id + ": " + err.Error()})
				return
			}
			if !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
		}
		if len(ids) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "nessun programma da mettere nel kit"})
			return
		}
		if err := s.KitCheck(); err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
			return
		}
		if err := s.startFetch(ids, true); err != nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"started": true, "tools": ids})
	})
	mux.HandleFunc("DELETE /api/tools/fetch", func(w http.ResponseWriter, r *http.Request) {
		s.fetchMu.Lock()
		cancel := s.fetchCancel
		s.fetchMu.Unlock()
		if cancel != nil {
			cancel()
		}
		writeJSON(w, 200, map[string]bool{"stopping": cancel != nil})
	})
	mux.HandleFunc("POST /api/tools/remove", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Tool string `json:"tool"`
		}
		if code, err := readJSON(w, r, &body); err != nil {
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		if s.RemoveTool == nil {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "download dei programmi non disponibile"})
			return
		}
		if _, ok := tools.Portables[body.Tool]; !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": tools.ErrUnknown.Error()})
			return
		}
		s.fetchMu.Lock()
		busy := s.fetchRunning && (s.fetchTool == body.Tool || slices.Contains(s.fetchQueue, body.Tool))
		s.fetchMu.Unlock()
		if busy {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "download in corso per questo programma"})
			return
		}
		if err := s.RemoveTool(body.Tool); err != nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]bool{"removed": true})
	})
	mux.HandleFunc("POST /api/open", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Tool   string `json:"tool"`
			Target string `json:"target"`
		}
		if code, err := readJSON(w, r, &body); err != nil {
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		if s.OpenTool == nil {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "apertura degli strumenti non disponibile"})
			return
		}
		// La lista bianca si controlla prima di qualunque azione.
		if _, err := tools.Resolve(body.Tool, body.Target, map[string]tools.Installed{body.Tool: {Path: "-"}}); err != nil {
			code := http.StatusBadRequest
			if errors.Is(err, tools.ErrUnknown) {
				code = http.StatusNotFound
			}
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		if err := s.OpenTool(body.Tool, body.Target); err != nil {
			code := http.StatusInternalServerError
			switch {
			case errors.Is(err, tools.ErrNotInstalled), errors.Is(err, tools.ErrModified), errors.Is(err, tools.ErrDownloadModified):
				code = http.StatusUnprocessableEntity
			case errors.Is(err, tools.ErrCancelled):
				code = http.StatusConflict
			}
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]bool{"opened": true})
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

// fetchState è lo stato del download di una versione portable o della
// preparazione del kit (Kit), che scarica più programmi uno dopo l'altro.
type fetchState struct {
	Running bool   `json:"running"`
	Tool    string `json:"tool,omitempty"`
	Done    int64  `json:"done"`
	Total   int64  `json:"total"`
	Error   string `json:"error,omitempty"`
	Kit     bool   `json:"kit,omitempty"`
	// Solo per il kit: programmi ancora da scaricare, scaricati e verificati,
	// non riusciti con il motivo.
	Queue  []string          `json:"queue,omitempty"`
	Ready  []string          `json:"ready,omitempty"`
	Failed map[string]string `json:"failed,omitempty"`
}

func (s *Server) fetchStatus() fetchState {
	s.fetchMu.Lock()
	defer s.fetchMu.Unlock()
	st := fetchState{Running: s.fetchRunning, Tool: s.fetchTool, Done: s.fetchDone, Total: s.fetchTotal, Error: s.fetchErr, Kit: s.fetchKit,
		Queue: slices.Clone(s.fetchQueue), Ready: slices.Clone(s.fetchReady)}
	if len(s.fetchFailed) > 0 {
		st.Failed = maps.Clone(s.fetchFailed)
	}
	return st
}

// startFetch avvia in background il download di uno o più programmi, uno
// dopo l'altro: nella cartella del PC o, con kit, nel kit accanto a Polaris.
// Un lavoro alla volta. Nel kit un programma non riuscito non ferma gli
// altri; un'interruzione sì.
func (s *Server) startFetch(ids []string, kit bool) error {
	fetch := s.FetchTool
	if kit {
		fetch = s.FetchKit
	}
	s.fetchMu.Lock()
	defer s.fetchMu.Unlock()
	if s.fetchRunning {
		return errors.New("c'è già un download in corso")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute*time.Duration(len(ids)))
	s.fetchRunning, s.fetchCancel, s.fetchKit, s.fetchErr = true, cancel, kit, ""
	s.fetchTool, s.fetchDone, s.fetchTotal = ids[0], 0, -1
	s.fetchQueue, s.fetchReady, s.fetchFailed = slices.Clone(ids[1:]), nil, nil
	go func() {
		defer cancel()
		for i, id := range ids {
			s.fetchMu.Lock()
			s.fetchTool, s.fetchDone, s.fetchTotal, s.fetchQueue = id, 0, -1, slices.Clone(ids[i+1:])
			s.fetchMu.Unlock()
			_, err := fetch(ctx, id, func(done, total int64) {
				s.fetchMu.Lock()
				s.fetchDone, s.fetchTotal = done, total
				s.fetchMu.Unlock()
			})
			s.fetchMu.Lock()
			switch {
			case err == nil && kit:
				s.fetchReady = append(s.fetchReady, id)
			case err != nil && kit:
				if s.fetchFailed == nil {
					s.fetchFailed = map[string]string{}
				}
				s.fetchFailed[id] = err.Error()
			case err != nil:
				s.fetchErr = err.Error()
			}
			stop := ctx.Err() != nil
			if stop && kit {
				s.fetchErr = "preparazione del kit interrotta"
			}
			s.fetchMu.Unlock()
			if stop {
				break
			}
		}
		s.fetchMu.Lock()
		defer s.fetchMu.Unlock()
		s.fetchRunning, s.fetchCancel, s.fetchQueue = false, nil, nil
	}()
	return nil
}
