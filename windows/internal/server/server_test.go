package server

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"lanterna/internal/bench"
	"lanterna/internal/collect"
	"lanterna/internal/defender"
	"lanterna/internal/infra"
	"lanterna/internal/scan"
	"lanterna/internal/tools"
	"lanterna/internal/winapi"
)

type stubPlatform struct{}

func (stubPlatform) Adapters() ([]scan.Adapter, error) {
	return []scan.Adapter{{Name: "Ethernet", Kind: "ethernet", Up: true, IPv4: []string{"192.168.1.5/24"}, IPv6: []string{}, Gateways: []string{"192.168.1.1"}, DNS: []string{"192.168.1.1"}}}, nil
}
func (stubPlatform) Wifi(context.Context, bool) (*scan.WifiData, error) {
	return nil, errors.New("nessuna scheda Wi-Fi")
}
func (stubPlatform) NewPinger() (winapi.Pinger, error)   { return stubPinger{}, nil }
func (stubPlatform) Neighbors() ([]scan.Neighbor, error) { return []scan.Neighbor{}, nil }
func (stubPlatform) Firewall(context.Context) (*scan.FirewallData, error) {
	return nil, errors.New("n/d")
}
func (stubPlatform) OS() string     { return "test" }
func (stubPlatform) Elevated() bool { return false }
func (stubPlatform) Domain() string { return "" }
func (stubPlatform) PC(context.Context) (*scan.PcData, error) {
	return nil, errors.New("misura disponibile solo su Windows")
}
func (stubPlatform) SampleLoad(context.Context, time.Duration) (*float64, []scan.ProcessInfo) {
	return nil, nil
}

type stubPinger struct{}

func (stubPinger) Close() {}
func (stubPinger) Echo(dst net.IP, ttl, size int, df bool, _ time.Duration) winapi.EchoResult {
	return winapi.EchoResult{Status: winapi.EchoOK, From: dst, RTT: 4 * time.Millisecond}
}

func newServer() *Server {
	n := collect.RealNetwork
	n.CheckPorts = func(_ context.Context, _ string, p []scan.PortCheck, _ time.Duration) []scan.PortCheck { return p }
	n.RouterWeb = func(context.Context, string, bool) (*scan.RouterWeb, error) { return nil, errors.New("no") }
	n.MeasureDNS = func(_ context.Context, s, l string, _ []string) scan.DNSServerResult {
		return scan.DNSServerResult{Server: s, Label: l, OK: true, TimeMs: scan.Ptr(9.0)}
	}
	n.DiscoverUpnp = func(context.Context, string, time.Duration) (*scan.UpnpData, error) {
		return &scan.UpnpData{Devices: []scan.UpnpDevice{}}, nil
	}
	n.HTTPCheck = func(_ context.Context, u string) scan.HTTPCheck { return scan.HTTPCheck{URL: u, OK: true} }
	c := &collect.Collector{Platform: stubPlatform{}, Net: n, Version: "t",
		Opt: collect.Options{PingCount: 3, PingInterval: time.Millisecond, PingTimeout: 10 * time.Millisecond, MaxHops: 4}}
	return &Server{
		Collector: c,
		Version:   "t",
		Web: fstest.MapFS{
			"index.html":           {Data: []byte("<!doctype html><title>STARNET Polaris</title>")},
			"assets/inter.woff2":   {Data: []byte("wOF2\x00\x01\x00\x00")},
			"assets/index-abc.css": {Data: []byte("body{}")},
			"favicon.ico":          {Data: []byte("\x00\x00\x01\x00\x01\x00")},
		},
		Ping: c.QuickPing,
	}
}

func do(t *testing.T, h http.Handler, method, url string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, url, nil)
	req.Host = "127.0.0.1:8737"
	for k, v := range hdr {
		if k == "Host" {
			req.Host = v
		} else {
			req.Header.Set(k, v)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestGuards(t *testing.T) {
	h := newServer().Handler()
	if r := do(t, h, "GET", "/api/info", map[string]string{"Host": "evil.example:8737"}); r.Code != 403 {
		t.Fatalf("Host estraneo accettato: %d", r.Code)
	}
	if r := do(t, h, "GET", "/api/info", map[string]string{"Host": "localhost:8737"}); r.Code != 200 {
		t.Fatalf("localhost rifiutato: %d", r.Code)
	}
	if r := do(t, h, "POST", "/api/scan", map[string]string{"Origin": "https://evil.example"}); r.Code != 403 {
		t.Fatalf("POST da altra origine accettato: %d", r.Code)
	}
	if r := do(t, h, "POST", "/api/scan", map[string]string{"Sec-Fetch-Site": "cross-site"}); r.Code != 403 {
		t.Fatalf("POST cross-site accettato: %d", r.Code)
	}
	r := do(t, h, "GET", "/", nil)
	if r.Code != 200 || !strings.Contains(r.Header().Get("Content-Security-Policy"), "default-src 'self'") || r.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("intestazioni di sicurezza mancanti: %d %v", r.Code, r.Header())
	}
}

// I file dell'interfaccia escono con il tipo giusto: con nosniff il browser
// rifiuterebbe un foglio di stile servito come testo generico.
func TestStaticTypes(t *testing.T) {
	h := newServer().Handler()
	for path, want := range map[string]string{"/assets/inter.woff2": "font/woff2", "/assets/index-abc.css": "text/css; charset=utf-8", "/favicon.ico": "image/x-icon"} {
		if r := do(t, h, "GET", path, nil); r.Code != 200 || r.Header().Get("Content-Type") != want {
			t.Errorf("%s: %d %q, atteso %q", path, r.Code, r.Header().Get("Content-Type"), want)
		}
	}
}

func TestScanLifecycle(t *testing.T) {
	s := newServer()
	h := s.Handler()
	if r := do(t, h, "GET", "/api/scan", nil); r.Code != 204 {
		t.Fatalf("scan prima dell'analisi: %d", r.Code)
	}
	if r := do(t, h, "POST", "/api/scan", map[string]string{"Origin": "http://127.0.0.1:8737"}); r.Code != 202 {
		t.Fatalf("avvio: %d %s", r.Code, r.Body)
	}
	s.Wait()
	var p progress
	_ = json.Unmarshal(do(t, h, "GET", "/api/progress", nil).Body.Bytes(), &p)
	if p.Running || len(p.Steps) == 0 {
		t.Fatalf("avanzamento: %+v", p)
	}
	r := do(t, h, "GET", "/api/scan", nil)
	var sc scan.Scan
	if err := json.Unmarshal(r.Body.Bytes(), &sc); err != nil || r.Code != 200 {
		t.Fatalf("%d %v", r.Code, err)
	}
	if sc.Gateway == nil || sc.Gateway.IP != "192.168.1.1" || sc.Gateway.Ping.Received != 3 {
		t.Fatalf("scan: %+v", sc.Gateway)
	}
	if r.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("le API non devono essere messe in cache")
	}
	// Dopo l'analisi il monitor conosce il router.
	var pr struct {
		IP string   `json:"ip"`
		Ms *float64 `json:"ms"`
	}
	_ = json.Unmarshal(do(t, h, "GET", "/api/ping?target=gateway", nil).Body.Bytes(), &pr)
	if pr.IP != "192.168.1.1" || pr.Ms == nil || *pr.Ms < 4 {
		t.Fatalf("ping: %+v", pr)
	}
	if r := do(t, h, "GET", "/api/ping?target=8.8.4.4", nil); r.Code != 400 {
		t.Fatalf("target arbitrario accettato: %d", r.Code)
	}
}

func TestConcurrentStart(t *testing.T) {
	s := newServer()
	if !s.Start() {
		t.Fatal("primo avvio rifiutato")
	}
	if s.Start() {
		t.Fatal("secondo avvio accettato durante l'analisi")
	}
	s.Wait()
}

func doBody(t *testing.T, h http.Handler, method, url, ctype, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, url, strings.NewReader(body))
	req.Host = "127.0.0.1:8737"
	req.Header.Set("Origin", "http://127.0.0.1:8737")
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// Rete finta per inventario e verifiche: rispondono solo .1 e .9.
func infraServer() *Server {
	s := newServer()
	s.Infra = &infra.Prims{
		NewPinger: func() (winapi.Pinger, error) {
			return silentPinger{alive: map[string]bool{"192.168.1.1": true, "192.168.1.9": true}}, nil
		},
		Neighbors: func() ([]scan.Neighbor, error) {
			return []scan.Neighbor{{IP: "192.168.1.1", MAC: "a4:2b:b0:00:00:01"}, {IP: "192.168.1.40", MAC: "00:1b:a9:00:00:40"}}, nil
		},
		Dial: func(ctx context.Context, addr string, timeout time.Duration) (time.Duration, error) {
			if addr == "192.168.1.9:443" {
				return time.Millisecond, nil
			}
			return 0, errors.New("i/o timeout")
		},
	}
	s.InfraOpt = infra.Options{Interval: time.Microsecond, Workers: 4, PingTimeout: time.Millisecond, DialTimeout: time.Millisecond, NameTimeout: time.Millisecond}
	return s
}

type silentPinger struct{ alive map[string]bool }

func (silentPinger) Close() {}
func (p silentPinger) Echo(dst net.IP, ttl, size int, df bool, _ time.Duration) winapi.EchoResult {
	if p.alive[dst.String()] {
		return winapi.EchoResult{Status: winapi.EchoOK, From: dst, RTT: 2 * time.Millisecond}
	}
	return winapi.EchoResult{Status: winapi.EchoTimeout}
}

func TestInventoryEndpoint(t *testing.T) {
	s := infraServer()
	h := s.Handler()
	if r := doBody(t, h, "POST", "/api/inventory", "text/plain", `{"authorized":true}`); r.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("corpo non JSON accettato: %d", r.Code)
	}
	if r := doBody(t, h, "POST", "/api/inventory", "application/json", `{"authorized":false}`); r.Code != http.StatusBadRequest {
		t.Fatalf("senza conferma: %d", r.Code)
	}
	r := doBody(t, h, "POST", "/api/inventory", "application/json", `{"authorized":true}`)
	if r.Code != http.StatusAccepted || !strings.Contains(r.Body.String(), "192.168.1.5/24") {
		t.Fatalf("avvio: %d %s", r.Code, r.Body)
	}
	s.WaitInventory()
	var st inventoryState
	if err := json.Unmarshal(do(t, h, "GET", "/api/inventory", nil).Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Running || st.Error != "" || st.Result == nil || st.Result.Subnet != "192.168.1.0/24" {
		t.Fatalf("stato: %+v", st)
	}
	ips := []string{}
	for _, x := range st.Result.Hosts {
		ips = append(ips, x.IP)
	}
	if strings.Join(ips, ",") != "192.168.1.1,192.168.1.5,192.168.1.9,192.168.1.40" {
		t.Fatalf("host: %v", ips)
	}
}

func TestInventoryNonDisponibile(t *testing.T) {
	h := newServer().Handler() // senza Infra
	if r := doBody(t, h, "POST", "/api/inventory", "application/json", `{"authorized":true}`); r.Code != http.StatusNotImplemented {
		t.Fatalf("%d", r.Code)
	}
}

func TestReachEndpoint(t *testing.T) {
	h := infraServer().Handler()
	if r := do(t, h, "GET", "/api/reach", nil); r.Code != http.StatusNoContent {
		t.Fatalf("prima della verifica: %d", r.Code)
	}
	if r := doBody(t, h, "POST", "/api/reach", "application/json", `{"targets":[]}`); r.Code != http.StatusBadRequest {
		t.Fatalf("nessuna destinazione: %d", r.Code)
	}
	r := doBody(t, h, "POST", "/api/reach", "application/json", `{"targets":[{"host":"192.168.1.9","port":443,"expect":"reachable"},{"host":"10.9.9.9","port":3389,"expect":"isolated"},{"host":"8.8.8.8","port":53,"expect":"reachable"}]}`)
	var rd scan.ReachData
	if err := json.Unmarshal(r.Body.Bytes(), &rd); err != nil || r.Code != 200 {
		t.Fatalf("%d %v %s", r.Code, err, r.Body)
	}
	if rd.From != "192.168.1.5" || len(rd.Results) != 3 || rd.Results[0].Status != "open" || !rd.Results[0].OK || rd.Results[1].Status != "filtered" || !rd.Results[1].OK || rd.Results[2].Status != "refused" {
		t.Fatalf("risultati: %+v", rd)
	}
	if r := do(t, h, "GET", "/api/reach", nil); r.Code != 200 {
		t.Fatalf("ultime verifiche: %d", r.Code)
	}
	// Da un'altra origine nemmeno con il JSON giusto.
	req := httptest.NewRequest("POST", "/api/reach", strings.NewReader(`{"targets":[{"host":"192.168.1.9","port":443,"expect":"reachable"}]}`))
	req.Host = "127.0.0.1:8737"
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("POST da altra origine: %d", rec.Code)
	}
}

func TestBenchEndpoint(t *testing.T) {
	s := newServer()
	release := make(chan struct{})
	s.BenchCPU = func(ctx context.Context, report bench.Report) (*scan.CPUBench, error) {
		report(bench.Progress{Phase: "multi", Done: 0.5, Samples: []float64{100}})
		select {
		case <-release:
			return &scan.CPUBench{Threads: 8, SingleMBs: 40, MultiMBs: 250, SustainedMBs: 240}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	var gotDrive string
	s.BenchDisk = func(_ context.Context, drive string, _ bench.Report) (*scan.DiskBench, error) {
		gotDrive = drive
		return &scan.DiskBench{Drive: drive, FileMB: 1024, SeqReadMBs: 3000}, nil
	}
	h := s.Handler()
	post := func(body string) *httptest.ResponseRecorder {
		return doBody(t, h, "POST", "/api/bench", "application/json", body)
	}
	if r := doBody(t, h, "POST", "/api/bench", "text/plain", `{"kind":"cpu"}`); r.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("corpo non JSON: %d", r.Code)
	}
	for body, code := range map[string]int{
		`{"kind":"gpu"}`:                                http.StatusBadRequest,
		`{"kind":"disk","drive":"C:"}`:                  http.StatusBadRequest, // manca la conferma
		`{"kind":"disk","drive":"rete","confirm":true}`: http.StatusBadRequest,
	} {
		if r := post(body); r.Code != code {
			t.Fatalf("%s: %d %s", body, r.Code, r.Body)
		}
	}

	// Test del processore: un secondo avvio e un'analisi vengono rifiutati.
	if r := post(`{"kind":"cpu"}`); r.Code != http.StatusAccepted {
		t.Fatalf("avvio: %d %s", r.Code, r.Body)
	}
	if r := post(`{"kind":"cpu"}`); r.Code != http.StatusConflict {
		t.Fatalf("doppio avvio: %d", r.Code)
	}
	if r := do(t, h, "POST", "/api/scan", nil); r.Code != http.StatusConflict || !strings.Contains(r.Body.String(), "test di velocità") {
		t.Fatalf("analisi durante il test: %d %s", r.Code, r.Body)
	}
	var st benchState
	for i := 0; i < 100 && st.Progress == nil; i++ {
		_ = json.Unmarshal(do(t, h, "GET", "/api/bench", nil).Body.Bytes(), &st)
		time.Sleep(5 * time.Millisecond)
	}
	if !st.Running || st.Kind != "cpu" || st.Progress == nil || st.Progress.Phase != "multi" {
		t.Fatalf("avanzamento: %+v", st)
	}
	close(release)
	s.WaitBench()
	st = benchState{}
	_ = json.Unmarshal(do(t, h, "GET", "/api/bench", nil).Body.Bytes(), &st)
	if st.Running || st.CPU == nil || st.CPU.MultiMBs != 250 || st.Error != "" {
		t.Fatalf("risultato: %+v", st)
	}

	// Test del disco: lettera normalizzata, risultato conservato accanto a
	// quello del processore.
	if r := post(`{"kind":"disk","drive":"d","confirm":true}`); r.Code != http.StatusAccepted {
		t.Fatalf("disco: %d %s", r.Code, r.Body)
	}
	s.WaitBench()
	st = benchState{}
	_ = json.Unmarshal(do(t, h, "GET", "/api/bench", nil).Body.Bytes(), &st)
	if gotDrive != "D:" || st.Disk == nil || st.Disk.Drive != "D:" || st.CPU == nil {
		t.Fatalf("disco: %q %+v", gotDrive, st)
	}
}

func TestBenchStopAndScanExclusion(t *testing.T) {
	s := newServer()
	s.BenchCPU = func(ctx context.Context, _ bench.Report) (*scan.CPUBench, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	h := s.Handler()
	if r := doBody(t, h, "POST", "/api/bench", "application/json", `{"kind":"cpu"}`); r.Code != http.StatusAccepted {
		t.Fatal(r.Code)
	}
	if r := do(t, h, "DELETE", "/api/bench", nil); r.Code != 200 || !strings.Contains(r.Body.String(), "true") {
		t.Fatalf("interruzione: %d %s", r.Code, r.Body)
	}
	s.WaitBench()
	var st benchState
	_ = json.Unmarshal(do(t, h, "GET", "/api/bench", nil).Body.Bytes(), &st)
	if st.Running || st.Error != "test interrotto" || st.CPU != nil {
		t.Fatalf("dopo l'interruzione: %+v", st)
	}
	if r := do(t, h, "DELETE", "/api/bench", map[string]string{"Origin": "https://evil.example"}); r.Code != http.StatusForbidden {
		t.Fatalf("DELETE da altra origine: %d", r.Code)
	}
	// Durante un'analisi il test non parte.
	s.mu.Lock()
	s.running = true
	s.mu.Unlock()
	if r := doBody(t, h, "POST", "/api/bench", "application/json", `{"kind":"cpu"}`); r.Code != http.StatusConflict || !strings.Contains(r.Body.String(), "analisi in corso") {
		t.Fatalf("test durante l'analisi: %d %s", r.Code, r.Body)
	}
	s.mu.Lock()
	s.running = false
	s.mu.Unlock()
	// Unità non adatta: rifiutata subito, senza avviare nulla.
	s.BenchDisk = func(context.Context, string, bench.Report) (*scan.DiskBench, error) {
		t.Fatal("test avviato")
		return nil, nil
	}
	s.BenchDrive = func(d string) error { return errors.New(d + " non è un disco locale o rimovibile") }
	if r := doBody(t, h, "POST", "/api/bench", "application/json", `{"kind":"disk","drive":"Q:","confirm":true}`); r.Code != http.StatusUnprocessableEntity || !strings.Contains(r.Body.String(), "Q:") {
		t.Fatalf("unità non adatta: %d %s", r.Code, r.Body)
	}
	// Senza funzioni di test configurate: non disponibile.
	s.BenchCPU = nil
	if r := doBody(t, h, "POST", "/api/bench", "application/json", `{"kind":"cpu"}`); r.Code != http.StatusNotImplemented {
		t.Fatalf("non disponibile: %d", r.Code)
	}
}

func TestDefenderEndpoint(t *testing.T) {
	s := newServer()
	h := s.Handler()
	// Senza Defender configurato: non disponibile; azioni arbitrarie rifiutate.
	if r := doBody(t, h, "POST", "/api/defender", "application/json", `{"action":"quick"}`); r.Code != http.StatusNotImplemented {
		t.Fatalf("non disponibile: %d", r.Code)
	}
	release := make(chan struct{})
	var got []string
	var mu sync.Mutex
	s.DefenderRun = func(ctx context.Context, action string) (*defender.Result, error) {
		mu.Lock()
		got = append(got, action)
		mu.Unlock()
		select {
		case <-release:
			return &defender.Result{Action: action, Message: "Scansione rapida completata: nessuna nuova minaccia rilevata.", Threats: []scan.Threat{}}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	for body, code := range map[string]int{`{"action":"format"}`: 400, `{}`: 400} {
		if r := doBody(t, h, "POST", "/api/defender", "application/json", body); r.Code != code {
			t.Fatalf("%s: %d", body, r.Code)
		}
	}
	if r := doBody(t, h, "POST", "/api/defender", "text/plain", `{"action":"quick"}`); r.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("senza JSON: %d", r.Code)
	}
	if r := doBody(t, h, "POST", "/api/defender", "application/json", `{"action":"quick"}`); r.Code != http.StatusAccepted {
		t.Fatalf("avvio: %d %s", r.Code, r.Body)
	}
	// Una sola operazione alla volta, e niente test di velocità nel frattempo.
	if r := doBody(t, h, "POST", "/api/defender", "application/json", `{"action":"update"}`); r.Code != http.StatusConflict {
		t.Fatalf("seconda operazione: %d", r.Code)
	}
	s.BenchCPU = func(context.Context, bench.Report) (*scan.CPUBench, error) { t.Fatal("test avviato"); return nil, nil }
	if r := doBody(t, h, "POST", "/api/bench", "application/json", `{"kind":"cpu"}`); r.Code != http.StatusConflict || !strings.Contains(r.Body.String(), "Defender") {
		t.Fatalf("test durante la scansione: %d %s", r.Code, r.Body)
	}
	var st defenderState
	_ = json.Unmarshal(do(t, h, "GET", "/api/defender", nil).Body.Bytes(), &st)
	if !st.Running || st.Action != "quick" || st.StartedAt == "" {
		t.Fatalf("in corso: %+v", st)
	}
	close(release)
	s.WaitDefender()
	_ = json.Unmarshal(do(t, h, "GET", "/api/defender", nil).Body.Bytes(), &st)
	if st.Running || st.Error != "" || st.Result == nil || !strings.Contains(st.Result.Message, "nessuna nuova minaccia") {
		t.Fatalf("esito: %+v", st)
	}

	// Interruzione di una scansione completa (che altrimenti non finirebbe).
	release = make(chan struct{})
	if r := doBody(t, h, "POST", "/api/defender", "application/json", `{"action":"full"}`); r.Code != http.StatusAccepted {
		t.Fatalf("scansione completa: %d", r.Code)
	}
	if r := do(t, h, "DELETE", "/api/defender", nil); r.Code != 200 || !strings.Contains(r.Body.String(), "true") {
		t.Fatalf("interruzione: %d %s", r.Code, r.Body)
	}
	s.WaitDefender()
	_ = json.Unmarshal(do(t, h, "GET", "/api/defender", nil).Body.Bytes(), &st)
	if st.Running || st.Error != "operazione interrotta" {
		t.Fatalf("dopo l'interruzione: %+v", st)
	}
	// Durante un test di velocità la scansione non parte.
	s.benchMu.Lock()
	s.benchRunning = true
	s.benchMu.Unlock()
	if r := doBody(t, h, "POST", "/api/defender", "application/json", `{"action":"quick"}`); r.Code != http.StatusConflict {
		t.Fatalf("scansione durante il test: %d", r.Code)
	}
	s.benchMu.Lock()
	s.benchRunning = false
	s.benchMu.Unlock()
	// Defender assente: rifiutato subito.
	s.DefenderReady = func() error { return defender.ErrUnavailable }
	if r := doBody(t, h, "POST", "/api/defender", "application/json", `{"action":"quick"}`); r.Code != http.StatusUnprocessableEntity {
		t.Fatalf("Defender assente: %d", r.Code)
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(got, ",") != "quick,full" {
		t.Fatalf("azioni eseguite: %v", got)
	}
}

func TestToolsEndpoints(t *testing.T) {
	s := newServer()
	h := s.Handler()
	if r := do(t, h, "GET", "/api/tools", nil); r.Code != 200 || !strings.Contains(r.Body.String(), `"installed":{}`) || !strings.Contains(r.Body.String(), `"bundled":{}`) {
		t.Fatalf("senza rilevamento: %d %s", r.Code, r.Body)
	}
	if r := doBody(t, h, "POST", "/api/open", "application/json", `{"tool":"task-manager","target":"app"}`); r.Code != http.StatusNotImplemented {
		t.Fatalf("non disponibile: %d", r.Code)
	}
	var opened []string
	s.Tools = func() map[string]tools.Installed {
		return map[string]tools.Installed{"cpu-z": {Version: "2.10", Path: `C:\Program Files\CPUID\CPU-Z\cpuz.exe`}}
	}
	s.Bundled = func() map[string]tools.Included {
		return map[string]tools.Included{
			"crystaldiskinfo": {Version: "9.9.2", Path: `C:\Polaris\strumenti\CrystalDiskInfo\DiskInfo64.exe`},
			"crystaldiskmark": {Version: "9.0.3", Problem: "file modificato"},
		}
	}
	s.OpenTool = func(id, target string) error {
		switch {
		case id == "hwinfo" && target == "app":
			return tools.ErrNotInstalled
		case id == "crystaldiskmark" && target == "app":
			return tools.ErrModified
		case id == "windows-security":
			return tools.ErrCancelled
		}
		opened = append(opened, id+":"+target)
		return nil
	}
	r := do(t, h, "GET", "/api/tools", nil)
	if r.Code != 200 || !strings.Contains(r.Body.String(), `"cpu-z":{"version":"2.10"}`) || strings.Contains(r.Body.String(), "Program Files") {
		t.Fatalf("elenco (senza percorsi): %s", r.Body)
	}
	if !strings.Contains(r.Body.String(), `"crystaldiskinfo":{"version":"9.9.2"}`) || !strings.Contains(r.Body.String(), `"crystaldiskmark":{"version":"9.0.3","problem":"file modificato"}`) || strings.Contains(r.Body.String(), "strumenti") {
		t.Fatalf("programmi inclusi (senza percorsi): %s", r.Body)
	}
	cases := []struct {
		body string
		code int
	}{
		{`{"tool":"task-manager","target":"app"}`, 200},
		{`{"tool":"cpu-z","target":"site"}`, 200},
		{`{"tool":"cpu-z","target":"app"}`, 200},
		{`{"tool":"hwinfo","target":"app"}`, 422},
		{`{"tool":"crystaldiskinfo","target":"app"}`, 200},
		{`{"tool":"crystaldiskmark","target":"app"}`, 422},
		{`{"tool":"windows-security","target":"app"}`, 409},
		{`{"tool":"cmd.exe","target":"app"}`, 404},
		{`{"tool":"C:\\Windows\\System32\\cmd.exe","target":"app"}`, 404},
		{`{"tool":"windows-update","target":"site"}`, 400},
		{`{"tool":"cpu-z","target":"https://evil.example"}`, 400},
	}
	for _, c := range cases {
		if r := doBody(t, h, "POST", "/api/open", "application/json", c.body); r.Code != c.code {
			t.Errorf("%s: %d %s", c.body, r.Code, r.Body)
		}
	}
	if r := doBody(t, h, "POST", "/api/open", "text/plain", `{"tool":"task-manager","target":"app"}`); r.Code != http.StatusUnsupportedMediaType {
		t.Errorf("senza JSON: %d", r.Code)
	}
	if strings.Join(opened, ",") != "task-manager:app,cpu-z:site,cpu-z:app,crystaldiskinfo:app" {
		t.Fatalf("aperti: %v", opened)
	}
}

func TestToolsFetchEndpoints(t *testing.T) {
	s := newServer()
	h := s.Handler()
	if r := doBody(t, h, "POST", "/api/tools/fetch", "application/json", `{"tool":"cpu-z"}`); r.Code != http.StatusNotImplemented {
		t.Fatalf("non disponibile: %d", r.Code)
	}
	release := make(chan struct{})
	var removed []string
	s.FetchTool = func(ctx context.Context, id string, progress func(done, total int64)) (tools.Downloaded, error) {
		progress(1<<20, 5<<20)
		select {
		case <-release:
			return tools.Downloaded{Version: "3.01", Signer: "CPUID"}, nil
		case <-ctx.Done():
			return tools.Downloaded{}, errors.New("download interrotto")
		}
	}
	s.RemoveTool = func(id string) error { removed = append(removed, id); return nil }
	s.Portable = func() map[string]tools.Downloaded {
		return map[string]tools.Downloaded{"autoruns": {Version: "14.21", Signer: "Microsoft Corporation", Date: "2026-10-19", Path: `C:\Users\Anna\AppData\Local\STARNET Polaris\strumenti\autoruns\Autoruns64.exe`}}
	}
	for _, c := range []struct {
		body string
		code int
	}{
		{`{"tool":"cmd.exe"}`, 404},
		{`{"tool":"crystaldiskinfo"}`, 400}, // incluso nel pacchetto, non si scarica
		{`{"tool":"memtest86"}`, 400},
	} {
		if r := doBody(t, h, "POST", "/api/tools/fetch", "application/json", c.body); r.Code != c.code {
			t.Errorf("%s: %d %s", c.body, r.Code, r.Body)
		}
	}
	if r := doBody(t, h, "POST", "/api/tools/fetch", "text/plain", `{"tool":"cpu-z"}`); r.Code != http.StatusUnsupportedMediaType {
		t.Errorf("senza JSON: %d", r.Code)
	}
	if r := doBody(t, h, "POST", "/api/tools/fetch", "application/json", `{"tool":"cpu-z"}`); r.Code != http.StatusAccepted {
		t.Fatalf("avvio: %d %s", r.Code, r.Body)
	}
	if r := doBody(t, h, "POST", "/api/tools/fetch", "application/json", `{"tool":"hwinfo"}`); r.Code != http.StatusConflict {
		t.Errorf("secondo download: %d", r.Code)
	}
	if r := doBody(t, h, "POST", "/api/tools/remove", "application/json", `{"tool":"cpu-z"}`); r.Code != http.StatusConflict {
		t.Errorf("eliminazione durante il download: %d", r.Code)
	}
	// Attende lo stato voluto: in corso con l'avanzamento già riferito, oppure finito.
	waitFetch := func(running bool) string {
		t.Helper()
		for i := 0; i < 300; i++ {
			r := do(t, h, "GET", "/api/tools", nil)
			body := r.Body.String()
			if strings.Contains(body, `"running":`+strconv.FormatBool(running)) && !strings.Contains(body, `"total":-1`) {
				return body
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("stato del download non raggiunto")
		return ""
	}
	body := waitFetch(true)
	if !strings.Contains(body, `"fetch":{"running":true,"tool":"cpu-z","done":1048576,"total":5242880}`) {
		t.Errorf("avanzamento: %s", body)
	}
	if !strings.Contains(body, `"autoruns":{"version":"14.21","signer":"Microsoft Corporation","date":"2026-10-19"}`) || strings.Contains(body, "AppData") {
		t.Errorf("copie scaricate (senza percorsi): %s", body)
	}
	close(release)
	body = waitFetch(false)
	if strings.Contains(body, `"error"`) {
		t.Errorf("download riuscito con errore: %s", body)
	}
	// Un secondo download, interrotto.
	release = make(chan struct{})
	if r := doBody(t, h, "POST", "/api/tools/fetch", "application/json", `{"tool":"wiztree"}`); r.Code != http.StatusAccepted {
		t.Fatalf("nuovo avvio: %d", r.Code)
	}
	waitFetch(true)
	req := httptest.NewRequest("DELETE", "/api/tools/fetch", nil)
	req.Host = "127.0.0.1:8737"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"stopping":true`) {
		t.Fatalf("interruzione: %d %s", rec.Code, rec.Body)
	}
	if body := waitFetch(false); !strings.Contains(body, `"error":"download interrotto"`) {
		t.Errorf("esito dell'interruzione: %s", body)
	}
	for _, c := range []struct {
		body string
		code int
	}{
		{`{"tool":"cpu-z"}`, 200},
		{`{"tool":"../../Windows"}`, 404},
		{`{"tool":"crystaldiskinfo"}`, 404},
	} {
		if r := doBody(t, h, "POST", "/api/tools/remove", "application/json", c.body); r.Code != c.code {
			t.Errorf("eliminazione %s: %d %s", c.body, r.Code, r.Body)
		}
	}
	if strings.Join(removed, ",") != "cpu-z" {
		t.Errorf("eliminati: %v", removed)
	}
}
