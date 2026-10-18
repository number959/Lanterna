package collect

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"lanterna/internal/scan"
	"lanterna/internal/winapi"
)

// fakeNet simula una rete: hop = salti fino alla destinazione, rtt per salto.
type fakeNet struct {
	icmpBroken bool            // NewPinger fallisce
	silent     map[string]bool // host che ignorano l'ICMP
	hops       int             // distanza di 1.1.1.1
	mtu        int             // MTU del percorso
	rtt        func(dst string) time.Duration
}

type fakePinger struct{ n *fakeNet }

func (p fakePinger) Close() {}

func (p fakePinger) Echo(dst net.IP, ttl, size int, df bool, timeout time.Duration) winapi.EchoResult {
	d := dst.String()
	if p.n.silent[d] {
		return winapi.EchoResult{Status: winapi.EchoTimeout}
	}
	if d == "1.1.1.1" && ttl < p.n.hops {
		return winapi.EchoResult{Status: winapi.EchoTTLExpired, From: net.IPv4(10, 0, 0, byte(ttl)), RTT: time.Duration(ttl) * 3 * time.Millisecond}
	}
	if df && size+28 > p.n.mtu {
		return winapi.EchoResult{Status: winapi.EchoTooBig}
	}
	return winapi.EchoResult{Status: winapi.EchoOK, From: dst, RTT: p.n.rtt(d)}
}

type fakePlatform struct {
	n        *fakeNet
	adapters []scan.Adapter
	wifiErr  error
	pcErr    error
	mu       sync.Mutex
	pingers  int
}

func (f *fakePlatform) Adapters() ([]scan.Adapter, error) { return f.adapters, nil }
func (f *fakePlatform) Wifi(context.Context, bool) (*scan.WifiData, error) {
	if f.wifiErr != nil {
		return nil, f.wifiErr
	}
	q := 80
	return &scan.WifiData{Source: "test", Connected: &scan.WifiConnection{SSID: "Casa", SignalQuality: &q}, Networks: []scan.Bss{}}, nil
}
func (f *fakePlatform) NewPinger() (winapi.Pinger, error) {
	if f.n.icmpBroken {
		return nil, errors.New("ICMP non disponibile")
	}
	f.mu.Lock()
	f.pingers++
	f.mu.Unlock()
	return fakePinger{f.n}, nil
}
func (f *fakePlatform) Neighbors() ([]scan.Neighbor, error) {
	return []scan.Neighbor{{IP: "192.168.1.1", MAC: "aa:bb:cc:dd:ee:ff"}, {IP: "192.168.1.30", MAC: "11:22:33:44:55:66"}}, nil
}
func (f *fakePlatform) Firewall(context.Context) (*scan.FirewallData, error) {
	t := true
	return &scan.FirewallData{Source: "test", Profiles: []scan.FirewallProfile{{Name: "private", Enabled: &t, Active: true}}}, nil
}
func (f *fakePlatform) OS() string     { return "test" }
func (f *fakePlatform) Elevated() bool { return false }
func (f *fakePlatform) Domain() string { return "" }
func (f *fakePlatform) PC(context.Context) (*scan.PcData, error) {
	if f.pcErr != nil {
		return nil, f.pcErr
	}
	return &scan.PcData{OS: &scan.PcOS{Name: "Windows 11 Pro", Build: 26100}, CPU: &scan.PcCPU{Name: "CPU di prova", Threads: 8}}, nil
}
func (f *fakePlatform) SampleLoad(context.Context, time.Duration) (*float64, []scan.ProcessInfo) {
	return scan.Ptr(12.5), []scan.ProcessInfo{{Name: "prova.exe", Count: 2, CPUPct: scan.Ptr(4.0), MemoryMB: 300}}
}

func fakeNetwork(tcpOK bool) Network {
	return Network{
		CheckPorts: func(_ context.Context, _ string, ports []scan.PortCheck, _ time.Duration) []scan.PortCheck {
			out := append([]scan.PortCheck(nil), ports...)
			for i := range out {
				out[i].Open = out[i].Port == 80 || out[i].Port == 53
			}
			return out
		},
		RouterWeb: func(context.Context, string, bool) (*scan.RouterWeb, error) {
			return &scan.RouterWeb{Title: "Router"}, nil
		},
		MeasureDNS: func(_ context.Context, server, label string, _ []string) scan.DNSServerResult {
			return scan.DNSServerResult{Server: server, Label: label, OK: true, TimeMs: scan.Ptr(12.0)}
		},
		DiscoverUpnp: func(context.Context, string, time.Duration) (*scan.UpnpData, error) {
			return &scan.UpnpData{Found: true, IGD: true, Devices: []scan.UpnpDevice{{ModelName: "X"}}}, nil
		},
		HTTPCheck: func(_ context.Context, u string) scan.HTTPCheck {
			return scan.HTTPCheck{URL: u, OK: true, Status: 204, TimeMs: scan.Ptr(80.0)}
		},
		TCPConnect: func(_ context.Context, addr string, _ time.Duration) (time.Duration, error) {
			if tcpOK && strings.HasSuffix(addr, ":443") {
				return 7 * time.Millisecond, nil
			}
			return 0, errors.New("i/o timeout")
		},
	}
}

var homeAdapters = []scan.Adapter{
	{Name: "Wi-Fi", Kind: "wifi", Up: true, IPv4: []string{"192.168.1.34/24"}, IPv6: []string{}, Gateways: []string{"192.168.1.1"}, DNS: []string{"192.168.1.1", "fe80::1"}},
	{Name: "vEthernet", Kind: "virtual", Up: true, IPv4: []string{"172.20.0.1/20"}, IPv6: []string{}, Gateways: []string{}, DNS: []string{}},
}

func fastOpts() Options {
	return Options{PingCount: 6, PingInterval: time.Millisecond, PingTimeout: 50 * time.Millisecond, UpnpWait: time.Millisecond, MaxHops: 12, TCPInterval: time.Millisecond}
}

func TestRunHealthyNetwork(t *testing.T) {
	n := &fakeNet{hops: 6, mtu: 1492, silent: map[string]bool{}, rtt: func(d string) time.Duration {
		if d == "192.168.1.1" {
			return 2 * time.Millisecond
		}
		return 18 * time.Millisecond
	}}
	c := &Collector{Platform: &fakePlatform{n: n, adapters: homeAdapters}, Net: fakeNetwork(false), Opt: fastOpts(), Version: "test"}
	var mu sync.Mutex
	var updates [][]Step
	s := c.Run(context.Background(), func(st []Step) { mu.Lock(); updates = append(updates, st); mu.Unlock() })

	if len(s.Errors) != 0 {
		t.Fatalf("errori inattesi: %+v", s.Errors)
	}
	if s.Gateway.IP != "192.168.1.1" || s.Gateway.MAC != "aa:bb:cc:dd:ee:ff" || s.Gateway.Ping.Received != 6 || *s.Gateway.Ping.AvgMs != 2 {
		t.Fatalf("gateway: %+v %+v", s.Gateway, s.Gateway.Ping)
	}
	if len(s.Internet.Traceroute) != 6 || s.Internet.Traceroute[0].IP != "10.0.0.1" || s.Internet.Traceroute[5].IP != "1.1.1.1" {
		t.Fatalf("traceroute: %+v", s.Internet.Traceroute)
	}
	if s.Internet.MTU == nil || s.Internet.MTU.MTU != 1492 {
		t.Fatalf("MTU: %+v", s.Internet.MTU)
	}
	if len(s.DNS.System) != 1 || s.DNS.System[0].Label != "Router" || len(s.DNS.Public) != 3 {
		t.Fatalf("DNS: %+v", s.DNS)
	}
	if !s.Gateway.Upnp.IGD || s.Firewall == nil || len(s.LAN.Neighbors) != 2 || s.Wifi.Connected.SSID != "Casa" {
		t.Fatalf("scan incompleto: %+v", s)
	}
	if s.PC == nil || s.PC.OS.Name != "Windows 11 Pro" || s.PC.CPU.LoadPct == nil || *s.PC.CPU.LoadPct != 12.5 || len(s.PC.Processes) != 1 {
		t.Fatalf("dati del computer: %+v", s.PC)
	}
	last := updates[len(updates)-1]
	for _, st := range last {
		if st.State != "done" {
			t.Fatalf("fase %s in stato %s", st.ID, st.State)
		}
	}
}

// Se i dati del computer non si leggono, la misura del carico non parte e
// l'errore compare una volta sola.
func TestRunWithoutPC(t *testing.T) {
	n := &fakeNet{hops: 3, mtu: 1500, silent: map[string]bool{}, rtt: func(string) time.Duration { return time.Millisecond }}
	c := &Collector{Platform: &fakePlatform{n: n, adapters: homeAdapters, pcErr: errors.New("misura disponibile solo su Windows")}, Net: fakeNetwork(false), Opt: fastOpts()}
	var last []Step
	var mu sync.Mutex
	s := c.Run(context.Background(), func(st []Step) { mu.Lock(); last = st; mu.Unlock() })
	if s.PC != nil || len(s.Errors) != 1 || s.Errors[0].Probe != "Computer: sistema, dischi ed eventi" {
		t.Fatalf("errori: %+v", s.Errors)
	}
	for _, st := range last {
		if (st.ID == "pc" || st.ID == "load") != (st.State == "error") {
			t.Fatalf("fase %s in stato %s", st.ID, st.State)
		}
	}
}

func TestMTUFullSize(t *testing.T) {
	n := &fakeNet{hops: 3, mtu: 1500, silent: map[string]bool{}, rtt: func(string) time.Duration { return time.Millisecond }}
	c := &Collector{Platform: &fakePlatform{n: n}, Net: fakeNetwork(false), Opt: fastOpts()}
	m, err := c.pathMTU(context.Background(), "1.1.1.1")
	if err != nil || m.MTU != 1500 {
		t.Fatalf("%+v %v", m, err)
	}
	n.mtu = 1400
	m, _ = c.pathMTU(context.Background(), "1.1.1.1")
	if m.MTU != 1400 {
		t.Fatalf("ricerca binaria: %+v", m)
	}
}

func TestICMPBrokenFallsBackToTCP(t *testing.T) {
	n := &fakeNet{icmpBroken: true, hops: 3, mtu: 1500, rtt: func(string) time.Duration { return time.Millisecond }}
	c := &Collector{Platform: &fakePlatform{n: n, adapters: homeAdapters}, Net: fakeNetwork(true), Opt: fastOpts()}
	s := c.Run(context.Background(), nil)
	tgt := s.Internet.Targets[0]
	if tgt.Method != "tcp" || tgt.Received == 0 || *tgt.AvgMs != 7 {
		t.Fatalf("riserva TCP non usata: %+v", tgt)
	}
	// Il percorso non è misurabile senza ICMP: errore registrato, non panico.
	found := false
	for _, e := range s.Errors {
		if e.Probe == "Percorso e MTU" {
			found = true
		}
	}
	if !found || s.Internet.Traceroute != nil {
		t.Fatalf("errori: %+v", s.Errors)
	}
}

func TestSilentRouterStopsEarly(t *testing.T) {
	n := &fakeNet{hops: 3, mtu: 1500, silent: map[string]bool{"192.168.1.1": true}, rtt: func(string) time.Duration { return time.Millisecond }}
	opt := fastOpts()
	opt.PingCount = 20
	c := &Collector{Platform: &fakePlatform{n: n, adapters: homeAdapters}, Net: fakeNetwork(false), Opt: opt}
	st := c.pingSeries(context.Background(), "192.168.1.1", "Router", []int{80})
	if st.Sent != 4 || st.Received != 0 || st.Error == "" {
		t.Fatalf("attesa interruzione dopo 4 echo senza risposta: %+v", st)
	}
}

func TestNoGateway(t *testing.T) {
	n := &fakeNet{hops: 3, mtu: 1500, silent: map[string]bool{}, rtt: func(string) time.Duration { return time.Millisecond }}
	ads := []scan.Adapter{{Name: "Ethernet", Kind: "ethernet", Up: true, IPv4: []string{"169.254.3.4/16"}, IPv6: []string{}, Gateways: []string{}, DNS: []string{}}}
	c := &Collector{Platform: &fakePlatform{n: n, adapters: ads, wifiErr: errors.New("nessuna scheda Wi-Fi")}, Net: fakeNetwork(false), Opt: fastOpts()}
	s := c.Run(context.Background(), nil)
	if s.Gateway != nil {
		t.Fatalf("gateway inventato: %+v", s.Gateway)
	}
	// Il Wi-Fi qui fallisce davvero (errore della piattaforma), quindi conta.
	probes := map[string]bool{}
	for _, e := range s.Errors {
		probes[e.Probe] = true
	}
	for _, want := range []string{"Schede di rete e indirizzi", "Reti Wi-Fi e segnale", "Router: risposta e stabilità"} {
		if !probes[want] {
			t.Errorf("manca l'errore %q in %+v", want, s.Errors)
		}
	}
}

func TestPickPrimary(t *testing.T) {
	gw, ip, dns := pickPrimary(homeAdapters)
	if gw != "192.168.1.1" || ip != "192.168.1.34" || len(dns) != 1 {
		t.Fatalf("%s %s %v", gw, ip, dns)
	}
}

func TestQuickPingHonoursMethod(t *testing.T) {
	n := &fakeNet{hops: 3, mtu: 1500, silent: map[string]bool{"1.1.1.1": true}, rtt: func(string) time.Duration { return 3 * time.Millisecond }}
	c := &Collector{Platform: &fakePlatform{n: n}, Net: fakeNetwork(true), Opt: fastOpts()}
	// ICMP filtrato: senza preferenza il monitor vede un pacchetto perso...
	if v := c.QuickPing(context.Background(), "1.1.1.1", []int{443}, false); v != nil {
		t.Fatalf("atteso nil, ottenuto %v", *v)
	}
	// ...ma se nell'analisi l'host ha risposto solo via TCP, il monitor usa TCP.
	if v := c.QuickPing(context.Background(), "1.1.1.1", []int{443}, true); v == nil {
		t.Fatal("con preferTCP il monitor deve misurare via TCP")
	}
	if v := c.QuickPing(context.Background(), "192.168.1.1", []int{443}, false); v == nil || *v != 3 {
		t.Fatalf("ICMP funzionante: %v", v)
	}
}

func TestNoWifiAdapterIsNotAFailure(t *testing.T) {
	n := &fakeNet{hops: 3, mtu: 1500, silent: map[string]bool{}, rtt: func(string) time.Duration { return time.Millisecond }}
	p := &noWifiPlatform{fakePlatform{n: n, adapters: homeAdapters}}
	c := &Collector{Platform: p, Net: fakeNetwork(false), Opt: fastOpts()}
	s := c.Run(context.Background(), nil)
	for _, e := range s.Errors {
		if e.Probe == "Reti Wi-Fi e segnale" {
			t.Fatalf("un PC senza scheda Wi-Fi non deve avere una misura fallita: %+v", s.Errors)
		}
	}
	if s.Wifi == nil || s.Wifi.Error != scan.NoWifiAdapter {
		t.Fatalf("%+v", s.Wifi)
	}
}

type noWifiPlatform struct{ fakePlatform }

func (*noWifiPlatform) Wifi(context.Context, bool) (*scan.WifiData, error) {
	return &scan.WifiData{Source: "test", Networks: []scan.Bss{}, Error: scan.NoWifiAdapter}, nil
}
