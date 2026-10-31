package speedtest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"lanterna/internal/scan"
)

// Un finto M-Lab locale: Locate v2 e i due servizi ndt7 su un unico server
// TLS di prova. Nessun test parla con M-Lab vero (pubblicherebbe l'indirizzo
// IP di chi lo esegue).

const (
	fakeClient = "203.0.113.7:54321"
	fakeUUID   = "ndt-TEST-UUID-0001"
)

type fakeMLab struct {
	srv *httptest.Server
	// machines: i server che Locate propone, nell'ordine; quelli in busy
	// rifiutano la negoziazione con 503.
	machines []string
	busy     map[string]bool
	// locateStatus diverso da 200 sostituisce la risposta di Locate.
	locateStatus int
	dur          time.Duration

	mu       sync.Mutex
	queries  []url.Values
	agents   []string
	paths    []string
	uploaded int64
	locates  int
	// active: un trasferimento è in corso (per le sonde finte).
	active atomic.Bool
}

func newFakeMLab(t *testing.T, machines ...string) *fakeMLab {
	f := &fakeMLab{machines: machines, busy: map[string]bool{}, dur: 400 * time.Millisecond}
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/nearest/ndt/ndt7", f.locate)
	mux.HandleFunc("/", f.ndt7)
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeMLab) locate(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.locates++
	f.agents = append(f.agents, r.UserAgent())
	f.queries = append(f.queries, r.URL.Query())
	f.mu.Unlock()
	if f.locateStatus != 0 {
		w.WriteHeader(f.locateStatus)
		return
	}
	host := strings.TrimPrefix(f.srv.URL, "https://")
	type loc struct {
		City    string `json:"city"`
		Country string `json:"country"`
	}
	type res struct {
		Machine  string            `json:"machine"`
		Location loc               `json:"location"`
		URLs     map[string]string `json:"urls"`
	}
	var out struct {
		Results []res `json:"results"`
	}
	cities := []string{"Milan", "Turin", "Rome", "Milan", "Paris"}
	for i, m := range f.machines {
		u := func(kind string) string {
			return fmt.Sprintf("wss://%s/%s/ndt/v7/%s?access_token=tok-%d", host, m, kind, i)
		}
		out.Results = append(out.Results, res{Machine: m, Location: loc{cities[i%len(cities)], "IT"}, URLs: map[string]string{
			"ws:///ndt/v7/download":  strings.Replace(u("download"), "wss:", "ws:", 1),
			"ws:///ndt/v7/upload":    strings.Replace(u("upload"), "wss:", "ws:", 1),
			"wss:///ndt/v7/download": u("download"),
			"wss:///ndt/v7/upload":   u("upload"),
		}})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

var upgrader = websocket.Upgrader{Subprotocols: []string{Subprotocol}, ReadBufferSize: 1 << 16, WriteBufferSize: 1 << 16}

func (f *fakeMLab) ndt7(w http.ResponseWriter, r *http.Request) {
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	machine, path := parts[0], "/"+parts[1]
	f.mu.Lock()
	f.queries = append(f.queries, r.URL.Query())
	f.agents = append(f.agents, r.UserAgent())
	f.paths = append(f.paths, machine+path)
	busy := f.busy[machine]
	f.mu.Unlock()
	if busy {
		http.Error(w, "capacità esaurita", http.StatusServiceUnavailable)
		return
	}
	if !slices.Contains(websocket.Subprotocols(r), Subprotocol) {
		http.Error(w, "manca il sottoprotocollo ndt7", http.StatusBadRequest)
		return
	}
	switch path {
	case "/ndt/v7/download":
		f.download(w, r)
	case "/ndt/v7/upload":
		f.upload(w, r)
	default:
		http.NotFound(w, r)
	}
}

// measurementJSON imita un messaggio del server, con indirizzo del client e
// identificativo del test che Polaris non deve conservare.
func measurementJSON(test string, elapsed time.Duration, bytes int64, tcp bool) []byte {
	m := map[string]any{
		"AppInfo":        map[string]int64{"ElapsedTime": elapsed.Microseconds(), "NumBytes": bytes},
		"ConnectionInfo": map[string]string{"Client": fakeClient, "Server": "192.0.2.10:443", "UUID": fakeUUID},
		"Origin":         "server",
		"Test":           test,
	}
	if tcp {
		m["TCPInfo"] = map[string]int64{"BytesSent": bytes * 102 / 100, "BytesRetrans": bytes * 3 / 100, "MinRTT": 9000, "RTT": 15400, "ElapsedTime": elapsed.Microseconds()}
	}
	b, _ := json.Marshal(m)
	return b
}

func (f *fakeMLab) download(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	f.active.Store(true)
	defer f.active.Store(false)
	buf := make([]byte, 1<<14)
	start := time.Now()
	var sent int64
	last := start
	for time.Since(start) < f.dur {
		if err := conn.WriteMessage(websocket.BinaryMessage, buf); err != nil {
			return
		}
		sent += int64(len(buf))
		if time.Since(last) > 50*time.Millisecond {
			last = time.Now()
			_ = conn.WriteMessage(websocket.TextMessage, measurementJSON("download", time.Since(start), sent, true))
		}
		time.Sleep(200 * time.Microsecond)
	}
	_ = conn.WriteMessage(websocket.TextMessage, measurementJSON("download", time.Since(start), sent, true))
	_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		if _, _, err := conn.NextReader(); err != nil {
			return
		}
	}
}

func (f *fakeMLab) upload(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	f.active.Store(true)
	defer f.active.Store(false)
	conn.SetReadLimit(1 << 25)
	start := time.Now()
	last := start
	var recv int64
	defer func() {
		f.mu.Lock()
		f.uploaded = recv
		f.mu.Unlock()
	}()
	for {
		kind, rd, err := conn.NextReader()
		if err != nil {
			return
		}
		if kind != websocket.BinaryMessage {
			continue
		}
		n, _ := io.Copy(io.Discard, rd)
		recv += n
		if time.Since(last) > 50*time.Millisecond {
			last = time.Now()
			_ = conn.WriteMessage(websocket.TextMessage, measurementJSON("upload", time.Since(start), recv, true))
		}
	}
}

func (f *fakeMLab) options() Options {
	pool := x509.NewCertPool()
	pool.AddCert(f.srv.Certificate())
	return Options{
		Version:    "1.2.3",
		LocateURL:  f.srv.URL + "/v2/nearest/ndt/ndt7",
		TLSConfig:  &tls.Config{RootCAs: pool},
		Idle:       200 * time.Millisecond,
		Duration:   400 * time.Millisecond,
		Hard:       3 * time.Second,
		Handshake:  3 * time.Second,
		ProbeEvery: 20 * time.Millisecond,
		Ping: func(ctx context.Context, tcp bool) *float64 {
			v := 10.0
			if f.active.Load() {
				v = 45
			}
			return &v
		},
		ProbeTarget: "1.1.1.1",
	}
}

func TestFullTest(t *testing.T) {
	f := newFakeMLab(t, "mlab1-mil05.mlab-oti.measurement-lab.org")
	var phases []string
	var mu sync.Mutex
	opt := f.options()
	opt.Progress = func(p Progress) {
		mu.Lock()
		defer mu.Unlock()
		if len(phases) == 0 || phases[len(phases)-1] != p.Phase {
			phases = append(phases, p.Phase)
		}
	}
	res, err := Run(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{PhaseLocate, PhaseIdle, PhaseDownload, PhaseUpload}; !slices.Equal(phases, want) {
		t.Errorf("fasi %v, attese %v", phases, want)
	}
	if res.Provider != "mlab-ndt7" || res.Server == nil || res.Server.Site != "mil05" || res.Server.City != "Milan" || res.Server.Country != "IT" {
		t.Errorf("server: %+v", res.Server)
	}
	d, u := res.Download, res.Upload
	if d == nil || d.Mbps <= 0 || d.Bytes <= 0 || d.Error != "" || d.Source != "client" {
		t.Fatalf("download: %+v", d)
	}
	if u == nil || u.Mbps <= 0 || u.Bytes <= 0 || u.Error != "" || u.Source != "server" {
		t.Fatalf("upload: %+v", u)
	}
	if d.MinRTTMs == nil || *d.MinRTTMs != 9 || d.RTTMs == nil || *d.RTTMs != 15.4 {
		t.Errorf("RTT del server: %v %v", d.MinRTTMs, d.RTTMs)
	}
	if d.RetransPct == nil || *d.RetransPct < 2.9 || *d.RetransPct > 3 || u.RetransPct != nil {
		t.Errorf("ritrasmissioni: %v (upload %v)", d.RetransPct, u.RetransPct)
	}
	if res.ProbeMethod != "icmp" || res.Idle == nil || *res.Idle.MedianMs != 10 || res.Idle.Received == 0 {
		t.Fatalf("latenza a riposo: %s %+v", res.ProbeMethod, res.Idle)
	}
	if d.Latency == nil || d.BloatMs == nil || *d.BloatMs != 35 || *d.BloatP95Ms != 35 {
		t.Errorf("bufferbloat in download: %+v %v", d.Latency, d.BloatMs)
	}
	if u.Latency == nil || u.BloatMs == nil || *u.BloatMs != 35 {
		t.Errorf("bufferbloat in upload: %+v %v", u.Latency, u.BloatMs)
	}
	if res.ViaProxy {
		t.Error("nessun proxy configurato")
	}
	// Mai indirizzo del PC, porta o identificativo del test.
	b, _ := json.Marshal(res)
	for _, bad := range []string{"203.0.113.7", "54321", "TEST-UUID", "192.0.2.10", "access_token", "tok-"} {
		if strings.Contains(string(b), bad) {
			t.Errorf("il risultato contiene %q: %s", bad, b)
		}
	}
}

func TestMetadataAndEarlyExit(t *testing.T) {
	f := newFakeMLab(t, "mlab2-trn02.mlab-oti.measurement-lab.org")
	if _, err := Run(context.Background(), f.options()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.queries) != 3 || len(f.paths) != 2 {
		t.Fatalf("richieste: %v %v", f.queries, f.paths)
	}
	// Locate: nessun parametro (né paese né altro).
	if len(f.queries[0]) != 0 {
		t.Errorf("Locate con parametri: %v", f.queries[0])
	}
	keys := func(q url.Values) []string {
		var k []string
		for x := range q {
			k = append(k, x)
		}
		slices.Sort(k)
		return k
	}
	if got := keys(f.queries[1]); !slices.Equal(got, []string{"access_token", "client_name", "client_version", "early_exit"}) {
		t.Errorf("parametri del download: %v", got)
	}
	if got := keys(f.queries[2]); !slices.Equal(got, []string{"access_token", "client_name", "client_version"}) {
		t.Errorf("parametri dell'upload: %v", got)
	}
	if q := f.queries[1]; q.Get("early_exit") != "250" || q.Get("client_name") != "starnet-polaris" || q.Get("client_version") != "1.2.3" || q.Get("access_token") != "tok-0" {
		t.Errorf("download: %v", q)
	}
	for _, ua := range f.agents {
		if ua != "starnet-polaris/1.2.3" {
			t.Errorf("User-Agent %q", ua)
		}
	}
}

func TestFallbackAcrossServers(t *testing.T) {
	f := newFakeMLab(t, "mlab1-mil06.mlab-oti.measurement-lab.org", "mlab1-trn02.mlab-oti.measurement-lab.org", "mlab3-mil07.mlab-oti.measurement-lab.org")
	f.busy["mlab1-mil06.mlab-oti.measurement-lab.org"] = true
	f.busy["mlab1-trn02.mlab-oti.measurement-lab.org"] = true
	res, err := Run(context.Background(), f.options())
	if err != nil {
		t.Fatal(err)
	}
	if res.Server.Site != "mil07" || res.Server.City != "Rome" {
		t.Errorf("server usato: %+v", res.Server)
	}
	want := []string{
		"mlab1-mil06.mlab-oti.measurement-lab.org/ndt/v7/download",
		"mlab1-trn02.mlab-oti.measurement-lab.org/ndt/v7/download",
		"mlab3-mil07.mlab-oti.measurement-lab.org/ndt/v7/download",
		"mlab3-mil07.mlab-oti.measurement-lab.org/ndt/v7/upload",
	}
	f.mu.Lock()
	paths := slices.Clone(f.paths)
	// Tutti occupati: errore chiaro, senza indirizzi.
	for _, m := range f.machines {
		f.busy[m] = true
	}
	f.mu.Unlock()
	if !slices.Equal(paths, want) {
		t.Errorf("tentativi %v", paths)
	}
	_, err = Run(context.Background(), f.options())
	if err == nil || !strings.Contains(err.Error(), "nessun server di M-Lab ha accettato il test: il server è occupato") || strings.Contains(err.Error(), "127.0.0.1") {
		t.Errorf("tutti occupati: %v", err)
	}
}

func TestLocateErrors(t *testing.T) {
	for _, c := range []struct {
		status int
		want   string
		busy   bool
	}{
		{http.StatusNoContent, "M-Lab è occupato, riprova più tardi", true},
		{http.StatusTooManyRequests, "M-Lab è occupato, riprova più tardi", true},
		{http.StatusProxyAuthRequired, "il proxy chiede un'autenticazione che Polaris non gestisce", false},
		{http.StatusServiceUnavailable, "M-Lab non ha trovato server disponibili", false},
		{http.StatusInternalServerError, "ha risposto con l'errore HTTP 500", false},
	} {
		f := newFakeMLab(t, "mlab1-mil05.mlab-oti.measurement-lab.org")
		f.locateStatus = c.status
		_, err := Run(context.Background(), f.options())
		if err == nil || !strings.Contains(err.Error(), c.want) || errors.Is(err, ErrBusy) != c.busy {
			t.Errorf("HTTP %d: %v", c.status, err)
		}
		if len(f.paths) != 0 {
			t.Errorf("HTTP %d: collegamenti ai server %v", c.status, f.paths)
		}
	}
	// Risposta senza server cifrati utilizzabili: come "occupato".
	if _, err := parseLocate([]byte(`{"results":[{"machine":"x","urls":{"ws:///ndt/v7/download":"ws://x/ndt/v7/download"}}]}`)); !errors.Is(err, ErrBusy) {
		t.Errorf("senza wss: %v", err)
	}
	if _, err := parseLocate([]byte(`non json`)); err == nil || errors.Is(err, ErrBusy) {
		t.Errorf("JSON non valido: %v", err)
	}
	// Servizio irraggiungibile: non conta per i limiti.
	f := newFakeMLab(t)
	opt := f.options()
	f.srv.Close()
	_, err := Run(context.Background(), opt)
	if err == nil || !NotReached(err) || !strings.HasPrefix(err.Error(), "M-Lab non raggiungibile") || strings.Contains(err.Error(), "127.0.0.1") {
		t.Errorf("irraggiungibile: %v", err)
	}
}

func TestParseLocate(t *testing.T) {
	body := `{"results":[
	 {"machine":"ndt-cia202870-824e392f.dimensione.autojoin.measurement-lab.org","location":{"city":"Rome","country":"IT"},"urls":{"wss:///ndt/v7/download":"wss://a/ndt/v7/download?access_token=1","wss:///ndt/v7/upload":"wss://a/ndt/v7/upload?access_token=2"}},
	 {"machine":"mlab1-mil05.mlab-oti.measurement-lab.org","urls":{"wss:///ndt/v7/download":"wss://b/ndt/v7/download?access_token=3","wss:///ndt/v7/upload":"wss://b/ndt/v7/upload?access_token=4"}},
	 {"machine":"c","urls":{"wss:///ndt/v7/download":"wss://c/d","wss:///ndt/v7/upload":"wss://c/u"}},
	 {"machine":"d","urls":{"wss:///ndt/v7/download":"wss://d/d","wss:///ndt/v7/upload":"wss://d/u"}},
	 {"machine":"e","urls":{"wss:///ndt/v7/download":"wss://e/d","wss:///ndt/v7/upload":"wss://e/u"}}]}`
	ts, err := parseLocate([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) != 4 || ts[0].server.Site != "cia202870" || ts[0].server.City != "Rome" || ts[1].server.Site != "mil05" || ts[1].server.City != "" || ts[3].server.Machine != "d" {
		t.Errorf("%+v", ts)
	}
	for m, want := range map[string]string{
		"mlab1-mil05.mlab-oti.measurement-lab.org":     "mil05",
		"ndt-mlab3-mil07.mlab-oti.measurement-lab.org": "mil07",
		"mlab1-mil10.mlab-oti.measurement-lab.org":     "mil10",
		"server.example": "",
	} {
		if got := siteOf(m); got != want {
			t.Errorf("siteOf(%q) = %q", m, got)
		}
	}
	// preferSame: dopo una nuova richiesta a Locate si resta sullo stesso server.
	fresh := []target{{server: serverOf("a")}, {server: serverOf("b")}, {server: serverOf("c")}}
	got := preferSame(fresh, []target{{server: serverOf("b")}})
	if got[0].server.Machine != "b" || got[1].server.Machine != "a" || got[2].server.Machine != "c" {
		t.Errorf("preferSame: %+v", got)
	}
	if u := untried(fresh, map[string]bool{"a": true, "c": true}); len(u) != 1 || u[0].server.Machine != "b" {
		t.Errorf("untried: %+v", u)
	}
}

func TestUploadCap(t *testing.T) {
	f := newFakeMLab(t, "mlab1-mil05.mlab-oti.measurement-lab.org")
	opt := f.options()
	opt.Duration = 3 * time.Second
	opt.Hard = 5 * time.Second
	f.dur = 200 * time.Millisecond
	opt.UploadCap = 3_000_000
	res, err := Run(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	u := res.Upload
	f.mu.Lock()
	got := f.uploaded
	f.mu.Unlock()
	if !u.Capped || u.Bytes > opt.UploadCap || u.Bytes < opt.UploadCap-minMessage || got > opt.UploadCap || u.Ms >= 3000 {
		t.Errorf("limite di upload: %+v, ricevuti dal server %d", u, got)
	}
}

func TestProxy(t *testing.T) {
	f := newFakeMLab(t, "mlab1-mil05.mlab-oti.measurement-lab.org")
	var connects atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "solo CONNECT", http.StatusMethodNotAllowed)
			return
		}
		connects.Add(1)
		dst, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, "destinazione irraggiungibile", http.StatusBadGateway)
			return
		}
		c, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			dst.Close()
			return
		}
		_, _ = c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		go func() { _, _ = io.Copy(dst, c); dst.Close() }()
		go func() { _, _ = io.Copy(c, dst); c.Close() }()
	}))
	defer proxy.Close()
	pu, _ := url.Parse(proxy.URL)
	opt := f.options()
	opt.Proxy = http.ProxyURL(pu)
	res, err := Run(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	// Locate, download e upload passano tutti dal proxy.
	if !res.ViaProxy || connects.Load() < 3 || res.Download.Mbps <= 0 || res.Upload.Mbps <= 0 {
		t.Errorf("proxy: %v, CONNECT %d, %+v %+v", res.ViaProxy, connects.Load(), res.Download, res.Upload)
	}

	// Proxy che chiede un'autenticazione (NTLM, Kerberos): messaggio chiaro.
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Proxy-Authenticate", "NTLM")
		w.WriteHeader(http.StatusProxyAuthRequired)
	}))
	defer auth.Close()
	au, _ := url.Parse(auth.URL)
	opt.Proxy = http.ProxyURL(au)
	_, err = Run(context.Background(), opt)
	if !errors.Is(err, ErrProxyAuth) || !NotReached(err) {
		t.Errorf("proxy con autenticazione su Locate: %v", err)
	}
	// Solo i WebSocket passano dal proxy che rifiuta.
	opt.Proxy = func(r *http.Request) (*url.URL, error) {
		if strings.Contains(r.URL.Path, "/ndt/v7/") {
			return au, nil
		}
		return nil, nil
	}
	_, err = Run(context.Background(), opt)
	if !errors.Is(err, ErrProxyAuth) {
		t.Errorf("proxy con autenticazione sui WebSocket: %v", err)
	}
}

func TestCancel(t *testing.T) {
	f := newFakeMLab(t, "mlab1-mil05.mlab-oti.measurement-lab.org")
	f.dur = 5 * time.Second
	opt := f.options()
	opt.Duration = 5 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	opt.Progress = func(p Progress) {
		if p.Phase == PhaseDownload && p.Mbps > 0 {
			cancel()
		}
	}
	start := time.Now()
	_, err := Run(ctx, opt)
	if !errors.Is(err, context.Canceled) || time.Since(start) > 3*time.Second {
		t.Errorf("interruzione: %v dopo %s", err, time.Since(start))
	}
}

func TestProberFallsBackToTCP(t *testing.T) {
	var tcpCalls atomic.Int32
	p := &prober{every: 5 * time.Millisecond, now: time.Now, ping: func(ctx context.Context, tcp bool) *float64 {
		if !tcp {
			return nil // ICMP bloccato
		}
		tcpCalls.Add(1)
		v := 21.04
		return &v
	}}
	out := p.run(context.Background(), 100*time.Millisecond, func(*float64, time.Duration) {})
	if p.method() != "tcp" || tcpCalls.Load() == 0 || countOK(out) != len(out) || len(out) == 0 {
		t.Errorf("metodo %s, %d campioni, %d TCP", p.method(), len(out), tcpCalls.Load())
	}
	l := latencyOf(out)
	if *l.MedianMs != 21 {
		t.Errorf("mediana %v", *l.MedianMs)
	}
	// Nessuna risposta neppure via TCP: niente latenza, il test continua.
	q := &prober{every: 5 * time.Millisecond, now: time.Now, ping: func(context.Context, bool) *float64 { return nil }}
	if out := q.run(context.Background(), 60*time.Millisecond, func(*float64, time.Duration) {}); len(out) != 0 || q.method() != "" {
		t.Errorf("senza risposte: %d campioni, metodo %q", len(out), q.method())
	}
}

func TestLatencyStats(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	l := latencyOf([]*float64{f(12), nil, f(10), f(30), f(11), f(13), nil, f(100), f(12), f(14), f(15), f(16)})
	if l.Sent != 12 || l.Received != 10 || *l.MinMs != 10 || *l.MedianMs != 13.5 || *l.P95Ms != 100 {
		t.Errorf("%+v %v %v", l, *l.MedianMs, *l.P95Ms)
	}
	if l := latencyOf([]*float64{nil, nil}); l.Received != 0 || l.MedianMs != nil {
		t.Errorf("senza risposte: %+v", l)
	}
	if latencyOf(nil) != nil {
		t.Error("senza campioni")
	}
}

func TestLimiter(t *testing.T) {
	now := time.Date(2026, 10, 31, 9, 0, 0, 0, time.Local)
	l := NewLimiter()
	l.Now = func() time.Time { return now }
	if err := l.Take(); err != nil {
		t.Fatal(err)
	}
	now = now.Add(80 * time.Second)
	err := l.Take()
	var le *LimitError
	if !errors.As(err, &le) || le.Wait != 40*time.Second || !strings.Contains(err.Error(), "tra 40 s") {
		t.Fatalf("pausa di due minuti: %v", err)
	}
	if w, left := l.Status(); w != 40*time.Second || left != 9 {
		t.Errorf("stato: %s %d", w, left)
	}
	// Un test che non ha raggiunto M-Lab non conta.
	now = now.Add(time.Minute)
	if err := l.Take(); err != nil {
		t.Fatal(err)
	}
	l.Release()
	if err := l.Take(); err != nil {
		t.Fatalf("dopo Release: %v", err)
	}
	for i := 0; i < 8; i++ {
		now = now.Add(2 * time.Minute)
		if err := l.Take(); err != nil {
			t.Fatalf("test %d: %v", i+3, err)
		}
	}
	now = now.Add(time.Hour)
	if err := l.Take(); err == nil || !strings.Contains(err.Error(), "oggi sono già stati fatti 10 test") {
		t.Fatalf("limite giornaliero: %v", err)
	}
	if _, left := l.Status(); left != 0 {
		t.Errorf("rimasti %d", left)
	}
	// Il giorno dopo si ricomincia.
	now = time.Date(2026, 11, 1, 8, 0, 0, 0, time.Local)
	if err := l.Take(); err != nil {
		t.Fatalf("giorno nuovo: %v", err)
	}
	if got := waitText(80 * time.Second); got != "1 min 20 s" {
		t.Errorf("waitText %q", got)
	}
	if got := waitText(2 * time.Minute); got != "2 min" {
		t.Errorf("waitText %q", got)
	}
}

func TestDescribeHidesAddresses(t *testing.T) {
	ip := net.ParseIP("198.51.100.23")
	errs := []error{
		&net.OpError{Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: ip, Port: 443}, Err: errors.New("connectex: No connection could be made because the target machine actively refused it.")},
		&net.OpError{Op: "read", Net: "tcp", Addr: &net.TCPAddr{IP: ip, Port: 443}, Err: errors.New("wsarecv: An existing connection was forcibly closed by the remote host.")},
		&net.DNSError{Err: "no such host", Name: "locate.measurementlab.net", Server: "192.168.1.1:53"},
		fmt.Errorf("proxyconnect tcp: dial tcp 10.0.0.8:3128: connect: connection refused"),
		errors.New("Proxy Authentication Required"),
		handshakeError{"il server è occupato"},
		websocket.ErrBadHandshake,
		context.DeadlineExceeded,
	}
	for _, e := range errs {
		s := describe(e)
		if s == "" || strings.ContainsAny(s, "0123456789") && !strings.Contains(s, "HTTP") {
			t.Errorf("%v -> %q", e, s)
		}
	}
	if !strings.Contains(describe(errors.New("Proxy Authentication Required")), "autenticazione") {
		t.Error("407 non riconosciuto")
	}
	if got := describe(errs[3]); got != "il proxy configurato su questo PC non risponde" {
		t.Errorf("proxy irraggiungibile: %q", got)
	}
}

func TestConsentText(t *testing.T) {
	all := strings.Join(ConsentText, " ")
	for _, k := range []string{"M-Lab", "indirizzo IP pubblico", "per sempre", "250 MB", PrivacyURL, AUPURL, "16 anni", "IP fisso", "STARNET Polaris"} {
		if !strings.Contains(all, k) {
			t.Errorf("manca %q", k)
		}
	}
	if !strings.Contains(LegalNote, "Ne.Me.Sys.") || !strings.Contains(LegalNote, "misurainternet.it") {
		t.Error("nota legale")
	}
}

func serverOf(m string) scan.SpeedServer { return scan.SpeedServer{Machine: m} }
