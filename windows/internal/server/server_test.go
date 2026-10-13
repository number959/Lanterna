package server

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"lanterna/internal/collect"
	"lanterna/internal/scan"
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
