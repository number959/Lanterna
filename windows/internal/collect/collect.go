// Package collect esegue tutte le misure e produce uno scan.Scan.
// Le sonde girano in parallelo; ogni errore viene registrato e non ferma
// le altre misure.
package collect

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"lanterna/internal/probe"
	"lanterna/internal/scan"
	"lanterna/internal/winapi"
)

// Platform astrae le misure che dipendono dal sistema operativo.
type Platform interface {
	Adapters() ([]scan.Adapter, error)
	Wifi(ctx context.Context, rescan bool) (*scan.WifiData, error)
	NewPinger() (winapi.Pinger, error)
	Neighbors() ([]scan.Neighbor, error)
	Firewall(ctx context.Context) (*scan.FirewallData, error)
	OS() string
	Elevated() bool
}

// Native è la piattaforma reale (Windows; altrove ogni misura fallisce con
// un errore esplicito).
type Native struct{}

func (Native) Adapters() ([]scan.Adapter, error)                        { return winapi.Adapters() }
func (Native) Wifi(ctx context.Context, r bool) (*scan.WifiData, error) { return winapi.Wifi(ctx, r) }
func (Native) NewPinger() (winapi.Pinger, error)                        { return winapi.NewPinger() }
func (Native) Neighbors() ([]scan.Neighbor, error)                      { return winapi.Neighbors() }
func (Native) Firewall(ctx context.Context) (*scan.FirewallData, error) { return winapi.Firewall(ctx) }
func (Native) OS() string                                               { return winapi.OSDescription() }
func (Native) Elevated() bool                                           { return winapi.Elevated() }

// Network raccoglie le dipendenze di rete sostituibili nei test.
type Network struct {
	CheckPorts   func(ctx context.Context, host string, ports []scan.PortCheck, timeout time.Duration) []scan.PortCheck
	RouterWeb    func(ctx context.Context, host string, httpsOpen bool) (*scan.RouterWeb, error)
	MeasureDNS   func(ctx context.Context, server, label string, names []string) scan.DNSServerResult
	DiscoverUpnp func(ctx context.Context, localIP string, wait time.Duration) (*scan.UpnpData, error)
	HTTPCheck    func(ctx context.Context, url string) scan.HTTPCheck
	TCPConnect   func(ctx context.Context, addr string, timeout time.Duration) (time.Duration, error)
}

// RealNetwork usa le sonde vere.
var RealNetwork = Network{
	CheckPorts:   probe.CheckPorts,
	RouterWeb:    probe.RouterWeb,
	MeasureDNS:   probe.MeasureServer,
	DiscoverUpnp: probe.Discover,
	HTTPCheck:    probe.HTTPCheck,
	TCPConnect: func(ctx context.Context, addr string, timeout time.Duration) (time.Duration, error) {
		d := net.Dialer{Timeout: timeout}
		start := time.Now()
		c, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return 0, err
		}
		el := time.Since(start)
		c.Close()
		return el, nil
	},
}

// Options regola durata e intensità delle misure.
type Options struct {
	PingCount    int
	PingInterval time.Duration
	PingTimeout  time.Duration
	Rescan       bool
	UpnpWait     time.Duration
	MaxHops      int
	TraceStagger time.Duration
	// TCPInterval distanzia i tentativi della riserva TCP: connessioni troppo
	// ravvicinate verso lo stesso server possono essere rifiutate.
	TCPInterval time.Duration
}

var DefaultOptions = Options{PingCount: 20, PingInterval: 250 * time.Millisecond, PingTimeout: time.Second, Rescan: true, UpnpWait: 2500 * time.Millisecond, MaxHops: 20, TraceStagger: 40 * time.Millisecond, TCPInterval: 500 * time.Millisecond}

// Destinazioni pubbliche: resolver anycast, vicini a quasi tutti gli utenti.
var InternetTargets = []struct{ IP, Label string }{{"1.1.1.1", "Cloudflare"}, {"8.8.8.8", "Google"}, {"9.9.9.9", "Quad9"}}

var HTTPTargets = []string{"https://www.google.com/generate_204", "https://cp.cloudflare.com/generate_204"}

// Step è una fase dell'analisi, mostrata all'utente durante l'attesa.
type Step struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	State string `json:"state"` // pending | running | done | error
}

var stepDefs = []Step{
	{ID: "adapters", Label: "Schede di rete e indirizzi"},
	{ID: "wifi", Label: "Reti Wi-Fi e segnale"},
	{ID: "gateway", Label: "Router: risposta e stabilità"},
	{ID: "router", Label: "Router: servizi e pannello"},
	{ID: "internet", Label: "Latenza verso Internet"},
	{ID: "trace", Label: "Percorso e MTU"},
	{ID: "dns", Label: "Server DNS"},
	{ID: "web", Label: "Navigazione web (HTTPS)"},
	{ID: "upnp", Label: "UPnP"},
	{ID: "firewall", Label: "Firewall di Windows"},
	{ID: "lan", Label: "Dispositivi in rete"},
}

// Progress viene notificato a ogni cambio di stato.
type Progress func(steps []Step)

type tracker struct {
	mu    sync.Mutex
	steps []Step
	cb    Progress
}

func (t *tracker) set(id, state string) {
	t.mu.Lock()
	for i := range t.steps {
		if t.steps[i].ID == id {
			t.steps[i].State = state
		}
	}
	cp := append([]Step(nil), t.steps...)
	t.mu.Unlock()
	if t.cb != nil {
		t.cb(cp)
	}
}

// Collector esegue un'analisi completa.
type Collector struct {
	Platform Platform
	Net      Network
	Opt      Options
	Version  string
}

type errList struct {
	mu   sync.Mutex
	list []scan.ProbeError
}

func (e *errList) add(probe string, err error) {
	if err == nil {
		return
	}
	e.mu.Lock()
	e.list = append(e.list, scan.ProbeError{Probe: probe, Message: err.Error()})
	e.mu.Unlock()
}

// Run esegue tutte le misure. Non fallisce mai: ciò che non si riesce a
// misurare finisce in Scan.Errors.
func (c *Collector) Run(ctx context.Context, progress Progress) *scan.Scan {
	start := time.Now()
	tr := &tracker{steps: append([]Step(nil), stepDefs...), cb: progress}
	for i := range tr.steps {
		tr.steps[i].State = "pending"
	}
	host, _ := os.Hostname()
	s := &scan.Scan{
		Schema:   scan.SchemaVersion,
		Agent:    scan.AgentInfo{Name: "LANterna", Version: c.Version, Platform: "windows", Host: host, OS: c.Platform.OS(), StartedAt: start.UTC().Format(time.RFC3339)},
		Adapters: []scan.Adapter{},
	}
	el := c.Platform.Elevated()
	s.Agent.Elevated = &el
	errs := &errList{}
	step := func(id string, fn func() error) {
		tr.set(id, "running")
		if err := fn(); err != nil {
			errs.add(labelOf(id), err)
			tr.set(id, "error")
			return
		}
		tr.set(id, "done")
	}

	// 1. Schede di rete: servono a sapere qual è il router e quali DNS usare.
	var gw, localIP string
	var dnsServers []string
	step("adapters", func() error {
		ads, err := c.Platform.Adapters()
		if err != nil {
			return err
		}
		s.Adapters = ads
		gw, localIP, dnsServers = pickPrimary(ads)
		if gw == "" {
			return fmt.Errorf("nessun gateway IPv4 configurato")
		}
		return nil
	})

	var wg sync.WaitGroup
	run := func(id string, fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			step(id, fn)
		}()
	}

	var mu sync.Mutex // protegge i campi di s scritti in parallelo
	if gw != "" {
		s.Gateway = &scan.GatewayData{IP: gw}
	}

	run("wifi", func() error {
		w, err := c.Platform.Wifi(ctx, c.Opt.Rescan)
		if err != nil {
			return err
		}
		mu.Lock()
		s.Wifi = w
		mu.Unlock()
		if w.Error != "" && w.Error != scan.NoWifiAdapter && w.Connected == nil && len(w.Networks) == 0 {
			return fmt.Errorf("%s", w.Error)
		}
		return nil
	})

	run("gateway", func() error {
		if gw == "" {
			return fmt.Errorf("router non individuato")
		}
		st := c.pingSeries(ctx, gw, "Router", []int{80, 443, 53})
		mu.Lock()
		s.Gateway.Ping = &st
		mu.Unlock()
		if st.Error != "" && st.Received == 0 {
			return fmt.Errorf("%s", st.Error)
		}
		return nil
	})

	run("router", func() error {
		if gw == "" {
			return fmt.Errorf("router non individuato")
		}
		ports := c.Net.CheckPorts(ctx, gw, probe.RouterPorts, 1500*time.Millisecond)
		httpsOpen := false
		for _, p := range ports {
			if p.Open && p.Port == 443 {
				httpsOpen = true
			}
		}
		web, err := c.Net.RouterWeb(ctx, gw, httpsOpen)
		mu.Lock()
		s.Gateway.Ports = ports
		s.Gateway.Web = web
		mu.Unlock()
		if err != nil && anyOpen(ports, 80, 443, 8080) {
			return fmt.Errorf("pannello del router: %v", err)
		}
		return nil
	})

	inet := &scan.InternetData{Targets: make([]scan.PingStats, len(InternetTargets))}
	s.Internet = inet
	run("internet", func() error {
		var iwg sync.WaitGroup
		for i, t := range InternetTargets {
			iwg.Add(1)
			go func(i int, ip, label string) {
				defer iwg.Done()
				inet.Targets[i] = c.pingSeries(ctx, ip, label, []int{443, 53})
			}(i, t.IP, t.Label)
		}
		iwg.Wait()
		for _, t := range inet.Targets {
			if t.Received > 0 {
				return nil
			}
		}
		return fmt.Errorf("nessun server pubblico ha risposto (%s)", inet.Targets[0].Error)
	})

	run("trace", func() error {
		hops, err := c.traceroute(ctx, InternetTargets[0].IP)
		if err != nil {
			return err
		}
		mtu, mtuErr := c.pathMTU(ctx, InternetTargets[0].IP)
		mu.Lock()
		inet.Traceroute, inet.TraceTarget, inet.MTU = hops, InternetTargets[0].IP, mtu
		mu.Unlock()
		return mtuErr
	})

	run("web", func() error {
		res := make([]scan.HTTPCheck, len(HTTPTargets))
		var hwg sync.WaitGroup
		for i, u := range HTTPTargets {
			hwg.Add(1)
			go func(i int, u string) {
				defer hwg.Done()
				res[i] = c.Net.HTTPCheck(ctx, u)
			}(i, u)
		}
		hwg.Wait()
		mu.Lock()
		inet.HTTP = res
		mu.Unlock()
		for _, r := range res {
			if r.OK {
				return nil
			}
		}
		return fmt.Errorf("nessun sito di prova raggiungibile: %s", res[0].Error)
	})

	run("dns", func() error {
		d := &scan.DNSData{System: []scan.DNSServerResult{}, Public: []scan.DNSServerResult{}}
		type job struct {
			server, label string
			public        bool
		}
		var jobs []job
		for _, srv := range dnsServers {
			label := ""
			if srv == gw {
				label = "Router"
			}
			jobs = append(jobs, job{srv, label, false})
		}
		for _, t := range InternetTargets {
			jobs = append(jobs, job{t.IP, t.Label, true})
		}
		res := make([]scan.DNSServerResult, len(jobs))
		var dwg sync.WaitGroup
		for i, j := range jobs {
			dwg.Add(1)
			go func(i int, j job) {
				defer dwg.Done()
				res[i] = c.Net.MeasureDNS(ctx, j.server, j.label, probe.DNSNames)
			}(i, j)
		}
		dwg.Wait()
		for i, j := range jobs {
			if j.public {
				d.Public = append(d.Public, res[i])
			} else {
				d.System = append(d.System, res[i])
			}
		}
		mu.Lock()
		s.DNS = d
		mu.Unlock()
		if len(dnsServers) == 0 {
			return fmt.Errorf("nessun server DNS configurato")
		}
		return nil
	})

	run("upnp", func() error {
		u, err := c.Net.DiscoverUpnp(ctx, localIP, c.Opt.UpnpWait)
		if err != nil {
			return err
		}
		mu.Lock()
		if s.Gateway != nil {
			s.Gateway.Upnp = u
		}
		mu.Unlock()
		return nil
	})

	run("firewall", func() error {
		fw, err := c.Platform.Firewall(ctx)
		if err != nil {
			return err
		}
		mu.Lock()
		s.Firewall = fw
		mu.Unlock()
		return nil
	})
	wg.Wait()

	// 3. Tabella dei vicini per ultima: dopo ping e UPnP è più completa.
	step("lan", func() error {
		n, err := c.Platform.Neighbors()
		if err != nil {
			return err
		}
		s.LAN = &scan.LANData{Neighbors: n}
		if s.Gateway != nil {
			for _, x := range n {
				if x.IP == s.Gateway.IP {
					s.Gateway.MAC = x.MAC
				}
			}
		}
		return nil
	})

	s.Errors = errs.list
	if s.Errors == nil {
		s.Errors = []scan.ProbeError{}
	}
	sort.SliceStable(s.Errors, func(i, j int) bool { return stepIndex(s.Errors[i].Probe) < stepIndex(s.Errors[j].Probe) })
	s.Agent.DurationMs = time.Since(start).Milliseconds()
	return s
}

func labelOf(id string) string {
	for _, s := range stepDefs {
		if s.ID == id {
			return s.Label
		}
	}
	return id
}

func stepIndex(label string) int {
	for i, s := range stepDefs {
		if s.Label == label {
			return i
		}
	}
	return len(stepDefs)
}

func anyOpen(ports []scan.PortCheck, which ...int) bool {
	for _, p := range ports {
		for _, w := range which {
			if p.Open && p.Port == w {
				return true
			}
		}
	}
	return false
}

// pickPrimary sceglie router, IP locale e DNS dalla prima scheda attiva con
// gateway IPv4 (Adapters le restituisce già in ordine di preferenza).
func pickPrimary(ads []scan.Adapter) (gw, localIP string, dns []string) {
	for _, a := range ads {
		if !a.Up || a.Kind == "loopback" {
			continue
		}
		for _, g := range a.Gateways {
			if ip := net.ParseIP(g); ip != nil && ip.To4() != nil {
				gw = g
				break
			}
		}
		if gw == "" {
			continue
		}
		for _, cidr := range a.IPv4 {
			if ip, _, err := net.ParseCIDR(cidr); err == nil && !strings.HasPrefix(cidr, "169.254.") {
				localIP = ip.String()
				break
			}
		}
		for _, d := range a.DNS {
			if ip := net.ParseIP(d); ip != nil && ip.To4() != nil && len(dns) < 3 {
				dns = append(dns, d)
			}
		}
		return
	}
	return "", "", nil
}
