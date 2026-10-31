package survey

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"lanterna/internal/scan"
	"lanterna/internal/winapi"
)

// Radio finta: restituisce le letture preparate, una per chiamata.
type fakeRadio struct {
	mu      sync.Mutex
	links   []Link
	errs    map[int]error
	calls   int
	gw      string
	nets    []Seen
	scanned int
	scanErr error
	closed  bool
}

func (r *fakeRadio) Link() (Link, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	i := r.calls
	r.calls++
	if err := r.errs[i]; err != nil {
		return Link{}, err
	}
	if i >= len(r.links) {
		return r.links[len(r.links)-1], nil
	}
	return r.links[i], nil
}
func (r *fakeRadio) Scan(context.Context) error { r.scanned++; return r.scanErr }
func (r *fakeRadio) Networks() ([]Seen, error)  { return r.nets, nil }
func (r *fakeRadio) Gateway() string            { return r.gw }
func (r *fakeRadio) Close()                     { r.closed = true }

// Pinger finto: risponde in 3 ms tranne ai ping indicati (persi), conta quelli in volo.
type fakePinger struct {
	n        *atomic.Int32
	lost     map[int32]bool
	inflight *atomic.Int32
	maxIn    *atomic.Int32
	dst      *atomic.Value
}

func (p *fakePinger) Echo(dst net.IP, ttl, size int, df bool, timeout time.Duration) winapi.EchoResult {
	k := p.n.Add(1) - 1
	p.dst.Store(dst.String())
	in := p.inflight.Add(1)
	defer p.inflight.Add(-1)
	for {
		m := p.maxIn.Load()
		if in <= m || p.maxIn.CompareAndSwap(m, in) {
			break
		}
	}
	if size != 32 {
		return winapi.EchoResult{Status: winapi.EchoError, Err: errors.New("dimensione")}
	}
	if p.lost[k] {
		time.Sleep(timeout) // un ping perso aspetta tutto il timeout
		return winapi.EchoResult{Status: winapi.EchoTimeout}
	}
	time.Sleep(3 * time.Millisecond)
	return winapi.EchoResult{Status: winapi.EchoOK, From: dst, RTT: 3 * time.Millisecond}
}
func (p *fakePinger) Close() {}

func pingerFactory(lost ...int32) (func() (winapi.Pinger, error), *fakePinger) {
	fp := &fakePinger{n: new(atomic.Int32), lost: map[int32]bool{}, inflight: new(atomic.Int32), maxIn: new(atomic.Int32), dst: new(atomic.Value)}
	for _, l := range lost {
		fp.lost[l] = true
	}
	return func() (winapi.Pinger, error) { return fp, nil }, fp
}

func link(bssid string, dbm int) Link {
	return Link{SSID: "Casa", BSSID: bssid, RssiDbm: ip(dbm), RxKbps: 433300, TxKbps: 390000, Phy: "802.11ac", Channel: 36}
}

func fast(o Options) Options {
	o.tick, o.pingEvery, o.pingTimeout = 10*time.Millisecond, 2*time.Millisecond, 15*time.Millisecond
	return o
}

func TestRun(t *testing.T) {
	a, b := "aa:bb:cc:00:00:10", "aa:bb:cc:00:00:20"
	r := &fakeRadio{gw: "192.168.1.1", links: []Link{
		link(a, -70), link(a, -71), link(a, -69), link(a, -72), link(a, -70),
		link(b, -60), link(b, -61), link(b, -60), link(b, -62), link(b, -60), link(b, -61), link(b, -60),
	}, nets: []Seen{
		{Bss: scan.Bss{SSID: "Casa", BSSID: b, RssiDbm: -61, Channel: 36, Band: "5", WidthMhz: 80, CenterChannel: 42, FreqMhz: 5180}, AgeMs: 300},
		{Bss: scan.Bss{SSID: "Vicino", BSSID: "11:22:33:44:55:66", RssiDbm: -72, Channel: 40, Band: "5", WidthMhz: 20}, AgeMs: 300},
	}}
	newPinger, fp := pingerFactory(4, 9)
	var progress []Progress
	var mu sync.Mutex
	res, err := Run(context.Background(), r, newPinger, fast(Options{Room: " Studio ", Seconds: 12, Scan: true, Progress: func(p Progress) {
		mu.Lock()
		progress = append(progress, p)
		mu.Unlock()
	}}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Room != "Studio" || res.SSID != "Casa" || res.Seconds != 12 || len(res.Rssi) != 12 {
		t.Fatalf("%+v", res)
	}
	if res.MedianDbm != -61.5 || res.MinDbm != -72 || res.MaxDbm != -60 || res.SpreadDb != 12 || res.P10Dbm != -71 || res.Stuck {
		t.Fatalf("segnale: %+v", res)
	}
	if res.RxMbps != 433 || res.TxMbps != 390 || res.Phy != "802.11ac" || res.Channel != 36 || res.Band != "5" || res.WidthMhz != 80 {
		t.Fatalf("radio: %+v", res)
	}
	if len(res.Roams) != 1 || res.Roams[0].From != a || res.Roams[0].To != b || len(res.BSSIDs) != 2 {
		t.Fatalf("cambi: %+v", res.Roams)
	}
	g := res.Gateway
	// 12 letture × 10 ms / 2 ms = 60 ping, due persi; nessun ping blocca la serie.
	if g == nil || g.Target != "192.168.1.1" || g.Sent != 60 || g.Received != 58 || g.LossPct != 3.3 || g.MedianMs == nil || *g.MedianMs < 3 {
		t.Fatalf("router: %+v", g)
	}
	if fp.maxIn.Load() < 2 {
		t.Errorf("i ping non partono in parallelo: al più %d in volo", fp.maxIn.Load())
	}
	if fp.dst.Load() != "192.168.1.1" {
		t.Errorf("destinazione: %v", fp.dst.Load())
	}
	if r.scanned != 1 || res.Scan == nil || res.Scan.ConnectedDbm == nil || *res.Scan.ConnectedDbm != -61 || res.Scan.Neighbors.Cochannel != 1 {
		t.Fatalf("scansione: %d %+v", r.scanned, res.Scan)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(progress) != 13 || progress[0].Phase != "misura" || progress[11].Dbm == nil || *progress[11].Dbm != -60 || progress[12].Phase != "scansione" || progress[11].Roams != 1 {
		t.Fatalf("avanzamento: %d %+v", len(progress), progress[len(progress)-1])
	}
	if len(res.Notes) != 0 {
		t.Errorf("note inattese: %v", res.Notes)
	}
}

func TestRunWithoutScanAndGateway(t *testing.T) {
	r := &fakeRadio{gw: "", links: []Link{link("aa:bb:cc:00:00:10", -58)}, nets: []Seen{
		{Bss: scan.Bss{SSID: "Casa", BSSID: "aa:bb:cc:00:00:10", Channel: 37, Band: "6", WidthMhz: 160, FreqMhz: 6135}, AgeMs: 50_000},
	}}
	newPinger, _ := pingerFactory()
	res, err := Run(context.Background(), r, newPinger, fast(Options{Room: "Camera", Seconds: 10, Scan: false}))
	if err != nil {
		t.Fatal(err)
	}
	if r.scanned != 0 || res.Scan != nil {
		t.Fatal("scansione fatta senza richiesta")
	}
	// Banda e larghezza dalla lista già presente (anche se vecchia), senza scansione.
	if res.Band != "6" || res.WidthMhz != 160 || !res.Stuck || res.Gateway == nil || res.Gateway.Skipped == "" || res.Gateway.Sent != 0 {
		t.Fatalf("%+v %+v", res, res.Gateway)
	}
}

func TestRunPublicGatewayNotPinged(t *testing.T) {
	r := &fakeRadio{gw: "8.8.8.8", links: []Link{link("aa:bb:cc:00:00:10", -58)}}
	newPinger, fp := pingerFactory()
	res, err := Run(context.Background(), r, newPinger, fast(Options{Room: "Camera", Seconds: 10}))
	if err != nil {
		t.Fatal(err)
	}
	if fp.n.Load() != 0 || !strings.Contains(res.Gateway.Skipped, "pubblico") || res.Gateway.Target != "" {
		t.Fatalf("ping verso un indirizzo pubblico: %d %+v", fp.n.Load(), res.Gateway)
	}
	// Senza frequenza la banda viene dal canale: 36 è 5 GHz.
	if res.Band != "5" {
		t.Fatalf("banda: %q", res.Band)
	}
}

func TestRunErrors(t *testing.T) {
	newPinger, _ := pingerFactory()
	opt := fast(Options{Room: "Bagno", Seconds: 10})
	// Non collegato all'inizio.
	if _, err := Run(context.Background(), &fakeRadio{links: []Link{{}}}, newPinger, opt); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("non collegato: %v", err)
	}
	// Permesso di posizione negato: l'errore di Windows arriva così com'è.
	denied := errors.New("Windows richiede il permesso di posizione")
	if _, err := Run(context.Background(), &fakeRadio{links: []Link{{}}, errs: map[int]error{0: denied}}, newPinger, opt); err != denied {
		t.Fatalf("permesso: %v", err)
	}
	// Una lettura "non collegato" (cambio di access point) è tollerata, tre di fila no.
	gap := &fakeRadio{links: []Link{link("aa", -60)}, errs: map[int]error{3: ErrNotConnected}}
	res, err := Run(context.Background(), gap, newPinger, opt)
	if err != nil || len(res.Rssi) != 9 || len(res.Notes) != 2 || !strings.Contains(res.Notes[1], "interrotto per 1 secondo") {
		t.Fatalf("interruzione breve: %v %+v", err, res)
	}
	drop := &fakeRadio{links: []Link{link("aa", -60)}, errs: map[int]error{3: ErrNotConnected, 4: ErrNotConnected, 5: ErrNotConnected}}
	if _, err := Run(context.Background(), drop, newPinger, opt); err != errDropped {
		t.Fatalf("scollegato: %v", err)
	}
	// Cambio di rete durante la misura.
	sw := &fakeRadio{links: []Link{link("aa", -60), link("aa", -60), {SSID: "Altra", BSSID: "bb", RssiDbm: ip(-50)}}}
	if _, err := Run(context.Background(), sw, newPinger, opt); err != errSwitched {
		t.Fatalf("altra rete: %v", err)
	}
	// Ingressi non validi: nessuna lettura.
	bad := &fakeRadio{links: []Link{link("aa", -60)}}
	if _, err := Run(context.Background(), bad, newPinger, fast(Options{Room: "", Seconds: 10})); err == nil || bad.calls != 0 {
		t.Fatalf("stanza vuota: %v", err)
	}
	if _, err := Run(context.Background(), bad, newPinger, fast(Options{Room: "Bagno", Seconds: 30})); err == nil || bad.calls != 0 {
		t.Fatalf("30 secondi: %v", err)
	}
	// Interruzione.
	ctx, cancel := context.WithCancel(context.Background())
	slow := &fakeRadio{gw: "192.168.1.1", links: []Link{link("aa", -60)}}
	go func() { time.Sleep(25 * time.Millisecond); cancel() }()
	if _, err := Run(ctx, slow, newPinger, fast(Options{Room: "Bagno", Seconds: 20})); !errors.Is(err, context.Canceled) {
		t.Fatalf("interrotta: %v", err)
	}
}

func TestPingSeriesUnavailable(t *testing.T) {
	r := &fakeRadio{gw: "169.254.1.1", links: []Link{link("aa", -60)}}
	res, err := Run(context.Background(), r, func() (winapi.Pinger, error) { return nil, errors.New("ICMP bloccato") }, fast(Options{Room: "Studio", Seconds: 10}))
	if err != nil {
		t.Fatal(err)
	}
	// Link-local: si misura, ma il pinger non si apre: errore senza perdite inventate.
	if res.Gateway.Error == "" || res.Gateway.Sent != 0 || res.Gateway.Target != "169.254.1.1" {
		t.Fatalf("%+v", res.Gateway)
	}
}
