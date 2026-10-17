package infra

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"lanterna/internal/scan"
	"lanterna/internal/winapi"
)

var fast = Options{Interval: time.Microsecond, Workers: 4, PingTimeout: time.Millisecond, DialTimeout: time.Millisecond, NameTimeout: 50 * time.Millisecond}

// Rete finta: alcuni host rispondono al ping, altri solo all'ARP.
type fakeLAN struct {
	alive     map[string]time.Duration
	inFlight  int32
	maxFlight int32
	echoes    int32
}

type fakePinger struct{ l *fakeLAN }

func (p fakePinger) Close() {}

func (p fakePinger) Echo(dst net.IP, ttl, size int, df bool, timeout time.Duration) winapi.EchoResult {
	n := atomic.AddInt32(&p.l.inFlight, 1)
	for {
		m := atomic.LoadInt32(&p.l.maxFlight)
		if n <= m || atomic.CompareAndSwapInt32(&p.l.maxFlight, m, n) {
			break
		}
	}
	defer atomic.AddInt32(&p.l.inFlight, -1)
	atomic.AddInt32(&p.l.echoes, 1)
	time.Sleep(200 * time.Microsecond)
	if d, ok := p.l.alive[dst.String()]; ok {
		return winapi.EchoResult{Status: winapi.EchoOK, From: dst, RTT: d}
	}
	return winapi.EchoResult{Status: winapi.EchoTimeout}
}

func (l *fakeLAN) prims() Prims {
	return Prims{
		NewPinger: func() (winapi.Pinger, error) { return fakePinger{l}, nil },
		Neighbors: func() ([]scan.Neighbor, error) {
			return []scan.Neighbor{
				{IP: "192.168.10.1", MAC: "a4:2b:b0:00:00:01"},
				{IP: "192.168.10.30", MAC: "00:1b:a9:12:34:56"}, // stampante che ignora il ping
				{IP: "192.168.10.77", MAC: "da:a1:19:00:00:77"}, // telefono con MAC casuale
				{IP: "10.0.0.5", MAC: "00:00:00:00:00:05"},      // fuori sottorete: ignorato
			}, nil
		},
		LookupAddr: func(ctx context.Context, ip string) ([]string, error) {
			if ip == "192.168.10.12" {
				return []string{"ambulatorio-3.clinica.local."}, nil
			}
			return nil, errors.New("no PTR")
		},
		NetBIOS: func(ctx context.Context, ip net.IP, timeout time.Duration) string {
			if ip.String() == "192.168.10.30" {
				return "STAMPA-PIANO2 "
			}
			return ""
		},
	}
}

func TestPlan(t *testing.T) {
	n, hosts, note, err := Plan("192.168.10.50/24")
	if err != nil || n.String() != "192.168.10.0/24" || len(hosts) != 254 || note != "" {
		t.Fatalf("/24: %v %v %d %q", err, n, len(hosts), note)
	}
	if hosts[0].String() != "192.168.10.1" || hosts[253].String() != "192.168.10.254" {
		t.Fatalf("estremi: %v %v", hosts[0], hosts[253])
	}
	if _, hosts, _, _ := Plan("10.1.4.9/22"); len(hosts) != 1022 {
		t.Fatalf("/22: %d indirizzi", len(hosts))
	}
	n, hosts, note, err = Plan("172.20.33.7/16")
	if err != nil || n.String() != "172.20.33.0/24" || len(hosts) != 254 || !strings.Contains(note, "/16") {
		t.Fatalf("/16 limitata al /24 del PC: %v %v %d %q", err, n, len(hosts), note)
	}
	for _, bad := range []string{"8.8.8.8/24", "100.64.1.1/24", "2001:db8::1/64", "192.168.1.1/31", "x"} {
		if _, _, _, err := Plan(bad); err == nil {
			t.Fatalf("%s accettato", bad)
		}
	}
}

func TestPrivateAndRandomMAC(t *testing.T) {
	for ip, want := range map[string]bool{"10.2.3.4": true, "172.31.0.1": true, "172.32.0.1": false, "192.168.0.1": true, "8.8.8.8": false, "fd12::1": true, "2001:db8::1": false, "127.0.0.1": false} {
		if Private(net.ParseIP(ip)) != want {
			t.Fatalf("Private(%s) != %v", ip, want)
		}
	}
	if !RandomMAC("da:a1:19:00:00:77") || RandomMAC("00:1b:a9:12:34:56") || RandomMAC("non-un-mac") {
		t.Fatal("RandomMAC")
	}
}

func TestInventory(t *testing.T) {
	lan := &fakeLAN{alive: map[string]time.Duration{"192.168.10.1": 2 * time.Millisecond, "192.168.10.12": 4 * time.Millisecond, "192.168.10.200": time.Millisecond}}
	var phases sync.Map
	inv, err := Inventory(context.Background(), InventoryRequest{CIDR: "192.168.10.50/24", Adapter: "Ethernet", Gateway: "192.168.10.1", SelfMAC: "3c:58:c2:aa:bb:cc"}, lan.prims(), fast,
		func(phase string, done, total int) { phases.Store(phase, [2]int{done, total}) })
	if err != nil {
		t.Fatal(err)
	}
	if inv.Subnet != "192.168.10.0/24" || inv.Scanned != 253 || inv.Adapter != "Ethernet" {
		t.Fatalf("intestazione: %+v", inv)
	}
	if lan.echoes != 253 {
		t.Fatalf("echo inviati: %d (atteso uno per indirizzo, PC escluso)", lan.echoes)
	}
	if lan.maxFlight > int32(fast.Workers) {
		t.Fatalf("richieste contemporanee: %d oltre il limite %d", lan.maxFlight, fast.Workers)
	}
	got := map[string]scan.InventoryHost{}
	var order []string
	for _, h := range inv.Hosts {
		got[h.IP] = h
		order = append(order, h.IP)
	}
	want := []string{"192.168.10.1", "192.168.10.12", "192.168.10.30", "192.168.10.50", "192.168.10.77", "192.168.10.200"}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Fatalf("host: %v", order)
	}
	if g := got["192.168.10.1"]; !g.Gateway || g.MAC != "a4:2b:b0:00:00:01" || g.RttMs == nil || *g.RttMs != 2 {
		t.Fatalf("gateway: %+v", g)
	}
	if s := got["192.168.10.50"]; !s.Self || s.MAC != "3c:58:c2:aa:bb:cc" {
		t.Fatalf("questo PC: %+v", s)
	}
	if p := got["192.168.10.30"]; p.RttMs != nil || p.NetBIOS != "STAMPA-PIANO2" || p.RandomMAC {
		t.Fatalf("stampante vista solo via ARP: %+v", p)
	}
	if a := got["192.168.10.12"]; a.Name != "ambulatorio-3.clinica.local" {
		t.Fatalf("DNS inverso: %+v", a)
	}
	if !got["192.168.10.77"].RandomMAC {
		t.Fatal("MAC casuale non riconosciuto")
	}
	if v, ok := phases.Load("ping"); !ok || v.([2]int) != [2]int{253, 253} {
		t.Fatalf("avanzamento ping: %v", v)
	}
	if v, ok := phases.Load("nomi"); !ok || v.([2]int) != [2]int{6, 6} {
		t.Fatalf("avanzamento nomi: %v", v)
	}
}

func TestInventoryPubblicaRifiutata(t *testing.T) {
	lan := &fakeLAN{}
	if _, err := Inventory(context.Background(), InventoryRequest{CIDR: "81.2.3.4/24"}, lan.prims(), fast, nil); err == nil || lan.echoes != 0 {
		t.Fatalf("rete pubblica: err=%v echo=%d", err, lan.echoes)
	}
}

func TestInventoryInterrotto(t *testing.T) {
	lan := &fakeLAN{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Inventory(ctx, InventoryRequest{CIDR: "192.168.10.50/24"}, lan.prims(), fast, nil); err == nil {
		t.Fatal("contesto annullato: atteso errore")
	}
}

func refused() error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: &net.OpError{Err: syscall.ECONNREFUSED}}
}

func TestReach(t *testing.T) {
	lan := &fakeLAN{alive: map[string]time.Duration{"192.168.10.1": time.Millisecond}}
	p := lan.prims()
	p.LookupHost = func(ctx context.Context, host string) ([]string, error) {
		switch host {
		case "pacs.clinica.local":
			return []string{"fd00::20", "10.20.0.20"}, nil
		case "cartella.example.com":
			return []string{"203.0.113.9"}, nil
		}
		return nil, errors.New("NXDOMAIN")
	}
	p.Dial = func(ctx context.Context, addr string, timeout time.Duration) (time.Duration, error) {
		switch addr {
		case "10.20.0.20:104", "10.30.0.5:22":
			return time.Millisecond, nil
		case "10.20.0.21:443", "10.40.0.9:445":
			return 0, refused()
		}
		return 0, errors.New("i/o timeout")
	}
	targets := []scan.ReachTarget{
		{Label: "PACS", Host: "pacs.clinica.local", Port: 104, Expect: "reachable"},
		{Label: "Cartella", Host: "10.20.0.21", Port: 443, Expect: "reachable"},
		{Label: "Server da ospiti", Host: "10.20.0.22", Port: 3389, Expect: "isolated"},
		{Label: "Gestione", Host: "10.30.0.5", Port: 22, Expect: "isolated"},
		{Label: "File server", Host: "10.40.0.9", Port: 445, Expect: "isolated"},
		{Label: "Gateway", Host: "192.168.10.1", Expect: "reachable"},
		{Label: "Monitor", Host: "192.168.10.99", Expect: "isolated"},
		{Label: "Cloud", Host: "cartella.example.com", Port: 443, Expect: "reachable"},
		{Label: "Sconosciuto", Host: "nessuno.local", Port: 80, Expect: "reachable"},
	}
	rd, err := Reach(context.Background(), targets, "192.168.10.50", p, fast)
	if err != nil {
		t.Fatal(err)
	}
	type exp struct {
		status, ip string
		ok         bool
	}
	want := []exp{
		{"open", "10.20.0.20", true},
		{"closed", "10.20.0.21", false},
		{"filtered", "10.20.0.22", true},
		{"open", "10.30.0.5", false},
		{"closed", "10.40.0.9", false},
		{"reply", "192.168.10.1", true},
		{"noreply", "192.168.10.99", true},
		{"refused", "203.0.113.9", false},
		{"unresolved", "", false},
	}
	for i, w := range want {
		r := rd.Results[i]
		if r.Status != w.status || r.IP != w.ip || r.OK != w.ok || r.Label != targets[i].Label {
			t.Fatalf("%s: %+v (atteso %+v)", targets[i].Label, r, w)
		}
	}
	if rd.Results[2].RttMs != nil || rd.Results[0].RttMs == nil {
		t.Fatal("tempo di risposta: presente solo se l'host ha risposto")
	}
	if rd.From != "192.168.10.50" {
		t.Fatalf("from: %q", rd.From)
	}
}

func TestValidate(t *testing.T) {
	ok := scan.ReachTarget{Host: "10.0.0.1", Port: 443, Expect: "reachable"}
	if err := Validate([]scan.ReachTarget{ok}); err != nil {
		t.Fatal(err)
	}
	many := make([]scan.ReachTarget, MaxTargets+1)
	for i := range many {
		many[i] = ok
	}
	for name, ts := range map[string][]scan.ReachTarget{
		"vuoto":   nil,
		"troppi":  many,
		"porta":   {{Host: "10.0.0.1", Port: 70000, Expect: "reachable"}},
		"attesa":  {{Host: "10.0.0.1", Port: 80, Expect: "forse"}},
		"nessuno": {{Host: "  ", Expect: "isolated"}},
	} {
		if err := Validate(ts); err == nil {
			t.Fatalf("%s: accettato", name)
		}
	}
}

func TestClassifyDial(t *testing.T) {
	cases := map[string]error{
		"open":     nil,
		"closed":   refused(),
		"filtered": errors.New("dial tcp 10.0.0.1:80: i/o timeout"),
	}
	for want, err := range cases {
		if got := classifyDial(err); got != want {
			t.Fatalf("%v: %s invece di %s", err, got, want)
		}
	}
	if classifyDial(errors.New("connectex: No connection could be made because the target machine actively refused it.")) != "closed" {
		t.Fatal("messaggio di Windows non riconosciuto")
	}
	if classifyDial(syscall.Errno(10061)) != "closed" {
		t.Fatal("WSAECONNREFUSED non riconosciuto")
	}
}

func TestNBStat(t *testing.T) {
	q := nbstatQuery(0xbeef)
	if len(q) != 50 || q[0] != 0xbe || q[1] != 0xef || q[12] != 0x20 || string(q[13:15]) != "CK" || string(q[15:45]) != strings.Repeat("A", 30) || q[45] != 0 || q[47] != 0x21 {
		t.Fatalf("richiesta: % x", q)
	}
	// Risposta: intestazione, nome ripetuto, tipo NBSTAT, classe, TTL, lunghezza, 3 nomi, MAC.
	resp := []byte{0xbe, 0xef, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0}
	resp = append(resp, q[12:46]...)
	resp = append(resp, 0x00, 0x21, 0x00, 0x01, 0, 0, 0, 0, 0, 0x41)
	entry := func(name string, suffix byte, flags uint16) []byte {
		b := []byte((name + strings.Repeat(" ", 15))[:15])
		return append(b, suffix, byte(flags>>8), byte(flags))
	}
	resp = append(resp, 3)
	resp = append(resp, entry("CLINICA", 0x00, 0x8400)...) // gruppo (dominio)
	resp = append(resp, entry("PC-ACCETTAZIONE", 0x00, 0x0400)...)
	resp = append(resp, entry("PC-ACCETTAZIONE", 0x20, 0x0400)...)
	resp = append(resp, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
	name, err := parseNBStat(resp)
	if err != nil || name != "PC-ACCETTAZIONE" {
		t.Fatalf("%q %v", name, err)
	}
	if _, err := parseNBStat(q); err == nil {
		t.Fatal("una richiesta non è una risposta")
	}
	if _, err := parseNBStat(resp[:60]); err == nil {
		t.Fatal("risposta troncata accettata")
	}
}
