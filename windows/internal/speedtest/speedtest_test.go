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
	// later: i server proposti dalle richieste a Locate dopo la prima (nil =
	// sempre machines).
	later []string
	// appInfo: i messaggi di misura portano anche AppInfo (facoltativo nella
	// specifica; il server di M-Lab non lo invia).
	appInfo bool
	// ackExtra si aggiunge ai byte confermati in download (early_exit).
	ackExtra int64
	// closeAfter: in upload il server avvia la chiusura dopo questo tempo,
	// come ndt-server allo scadere dei suoi 10 secondi.
	closeAfter time.Duration
	// closeCode: codice della chiusura in upload (0 = 1000, chiusura regolare).
	closeCode int
	// dropDownload, dropUpload: dopo questo tempo il server chiude la
	// connessione TCP senza messaggio di chiusura, come una NAT, un Wi-Fi o
	// un proxy che cadono (0 = mai).
	dropDownload, dropUpload time.Duration

	mu       sync.Mutex
	queries  []url.Values
	agents   []string
	paths    []string
	uploaded int64
	// uploadDone: il gestore dell'upload ha finito e uploaded è definitivo.
	uploadDone bool
	locates    int
	// active: trasferimenti in corso (per le sonde finte). È un contatore e
	// non un sì/no: il gestore del download finisce dopo la chiusura del
	// client e può farlo quando l'upload è già cominciato.
	active atomic.Int32
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
	machines := f.machines
	if f.locates > 1 && f.later != nil {
		machines = f.later
	}
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
	for i, m := range machines {
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

// measurementJSON imita un messaggio di misura del server di M-Lab
// (ndt-server v0.25.0: TCPInfo, BBRInfo e ConnectionInfo, senza AppInfo),
// con indirizzo del client e identificativo del test che Polaris non deve
// conservare. I byte di TCPInfo comprendono TLS e WebSocket: qui 2 KB in più.
func (f *fakeMLab) measurementJSON(upload bool, elapsed time.Duration, bytes int64) []byte {
	us := elapsed.Microseconds()
	tcp := map[string]int64{"State": 1, "MinRTT": 9000, "RTT": 15400, "RTTVar": 2100, "ElapsedTime": us}
	if upload {
		tcp["BytesReceived"], tcp["BytesAcked"], tcp["BytesSent"] = bytes+2048, 1500, 1800
	} else {
		tcp["BytesAcked"], tcp["BytesSent"], tcp["BytesRetrans"], tcp["BytesReceived"] = bytes+2048+f.ackExtra, bytes*102/100, bytes*3/100, 600
	}
	m := map[string]any{
		"BBRInfo":        map[string]int64{"BW": 12_500_000, "MinRTT": 9000, "PacingGain": 256, "CwndGain": 512, "ElapsedTime": us},
		"ConnectionInfo": map[string]string{"Client": fakeClient, "Server": "192.0.2.10:443", "UUID": fakeUUID, "StartTime": "2026-10-31T09:10:00.123456789Z"},
		"TCPInfo":        tcp,
	}
	if f.appInfo {
		m["AppInfo"] = map[string]int64{"ElapsedTime": us, "NumBytes": bytes}
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
	f.active.Add(1)
	defer f.active.Add(-1)
	buf := make([]byte, 1<<14)
	start := time.Now()
	var sent int64
	last := start
	for time.Since(start) < f.dur {
		if f.dropDownload > 0 && time.Since(start) >= f.dropDownload {
			dropTCP(conn)
			return
		}
		if err := conn.WriteMessage(websocket.BinaryMessage, buf); err != nil {
			return
		}
		sent += int64(len(buf))
		if time.Since(last) > 50*time.Millisecond {
			last = time.Now()
			_ = conn.WriteMessage(websocket.TextMessage, f.measurementJSON(false, time.Since(start), sent))
		}
		time.Sleep(200 * time.Microsecond)
	}
	_ = conn.WriteMessage(websocket.TextMessage, f.measurementJSON(false, time.Since(start), sent))
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
	f.active.Add(1)
	defer f.active.Add(-1)
	conn.SetReadLimit(1 << 25)
	start := time.Now()
	last := start
	var recv int64
	defer func() {
		f.mu.Lock()
		f.uploaded = recv
		f.uploadDone = true
		f.mu.Unlock()
	}()
	closing := false
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
		if f.dropUpload > 0 && time.Since(start) >= f.dropUpload {
			dropTCP(conn)
			return
		}
		if closing {
			continue
		}
		if time.Since(last) > 50*time.Millisecond {
			last = time.Now()
			_ = conn.WriteMessage(websocket.TextMessage, f.measurementJSON(true, time.Since(start), recv))
		}
		// Come ndt-server: allo scadere del suo tempo invia la chiusura e
		// continua a leggere finché il client non risponde.
		if f.closeAfter > 0 && time.Since(start) >= f.closeAfter {
			_ = conn.WriteMessage(websocket.TextMessage, f.measurementJSON(true, time.Since(start), recv))
			code := websocket.CloseNormalClosure
			if f.closeCode != 0 {
				code = f.closeCode
			}
			_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, "Done sending"), time.Now().Add(time.Second))
			closing = true
		}
	}
}

// dropTCP chiude la connessione TCP sotto TLS e WebSocket: il client non
// riceve né il messaggio di chiusura di WebSocket né l'avviso di TLS.
func dropTCP(conn *websocket.Conn) {
	if tc, ok := conn.UnderlyingConn().(*tls.Conn); ok {
		_ = tc.NetConn().Close()
		return
	}
	_ = conn.UnderlyingConn().Close()
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
			if f.active.Load() > 0 {
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
	if res.ProbeTimeoutMs != 1000 || d.Latency.MedianAtLeast || u.Latency.MedianAtLeast || u.Server != nil || d.Capped {
		t.Errorf("attesa delle sonde %d, valori minimi %v %v, server dell'upload %+v, limite %v", res.ProbeTimeoutMs, d.Latency.MedianAtLeast, u.Latency.MedianAtLeast, u.Server, d.Capped)
	}
	if res.ViaProxy {
		t.Error("nessun proxy configurato")
	}
	// Mai indirizzo del PC, porta o identificativo del test.
	b, _ := json.Marshal(res)
	for _, bad := range []string{"203.0.113.7", "54321", "TEST-UUID", "192.0.2.10", "access_token", "tok-", "09:10:00.123456789"} {
		if strings.Contains(string(b), bad) {
			t.Errorf("il risultato contiene %q: %s", bad, b)
		}
	}
}

func TestMetadataAndEarlyExit(t *testing.T) {
	f := newFakeMLab(t, "mlab2-trn02.mlab-oti.measurement-lab.org")
	// Il server dice di aver ricevuto la conferma di 250 MB (TCPInfo.BytesAcked):
	// il download si è fermato per early_exit.
	f.ackExtra = earlyExitBytes
	res, err := Run(context.Background(), f.options())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Download.Capped {
		t.Errorf("limite di 250 MB in download: %+v", res.Download)
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
	// Il server conta i byte quando il suo gestore finisce, che può essere
	// dopo il ritorno di Run (in CI, su una macchina carica, è successo):
	// si aspetta la fine del gestore, con un limite.
	var got int64
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		f.mu.Lock()
		done := f.uploadDone
		got = f.uploaded
		f.mu.Unlock()
		if done || time.Now().After(deadline) {
			break
		}
	}
	// Il server riceve tutto ciò che il PC ha scritto, fino al limite e non
	// oltre. Bytes è il conteggio dell'ultimo messaggio del server (con 2 KB
	// di TLS e WebSocket nel finto M-Lab), che può precedere gli ultimi invii.
	if !u.Capped || got > opt.UploadCap || got < opt.UploadCap-minMessage || u.Bytes > opt.UploadCap+2048 || u.Ms >= 3000 {
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

// Coda oltre il secondo (per esempio ADSL o FTTC con l'upload pieno): a
// riposo le sonde rispondono, durante i trasferimenti nessuna risposta entro
// l'attesa. Il bufferbloat deve risultare di almeno 990 ms, non mancare.
func TestLostProbesUnderLoad(t *testing.T) {
	f := newFakeMLab(t, "mlab1-mil05.mlab-oti.measurement-lab.org")
	opt := f.options()
	opt.Ping = func(ctx context.Context, tcp bool) *float64 {
		if f.active.Load() > 0 {
			return nil
		}
		v := 10.0
		return &v
	}
	res, err := Run(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if res.ProbeTimeoutMs != 1000 || res.Idle == nil || *res.Idle.MedianMs != 10 || res.ProbeMethod != "icmp" {
		t.Fatalf("riposo: %+v, attesa %d, metodo %s", res.Idle, res.ProbeTimeoutMs, res.ProbeMethod)
	}
	for name, d := range map[string]*scan.SpeedDir{"download": res.Download, "upload": res.Upload} {
		l := d.Latency
		if l == nil || l.Sent < 5 || 2*l.Received >= l.Sent || !l.MedianAtLeast || !l.P95AtLeast || *l.MedianMs != 1000 || d.BloatMs == nil || *d.BloatMs != 990 || *d.BloatP95Ms != 990 {
			t.Errorf("%s: %+v, bufferbloat %v", name, l, d.BloatMs)
		}
	}
}

func TestLoadedLatencyCountsLostProbes(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	lost := func(n int) []*float64 { return make([]*float64, n) }
	idle := &scan.SpeedLatency{Sent: 20, Received: 20, MedianMs: f(10)}
	// Tutte senza risposta: almeno 1000 ms.
	l := loadedLatencyOf(lost(12), idle, 1000)
	if l.Sent != 12 || l.Received != 0 || l.MinMs != nil || *l.MedianMs != 1000 || !l.MedianAtLeast || *l.P95Ms != 1000 || !l.P95AtLeast {
		t.Errorf("tutte perse: %+v", l)
	}
	// Più della metà senza risposta: la mediana cade sulle sonde perse.
	l = loadedLatencyOf(append([]*float64{f(40), f(50), f(60), f(70), f(80)}, lost(6)...), idle, 1000)
	if *l.MedianMs != 1000 || !l.MedianAtLeast || *l.MinMs != 40 {
		t.Errorf("metà più una: %+v", l)
	}
	// Poche senza risposta: mediana dalle risposte, spostata in alto dalle
	// perse (31 invece di 29), 95° percentile minimo.
	some := append([]*float64{f(20), f(22), f(24), f(26), f(28), f(30), f(32), f(34), f(36), f(38)}, lost(2)...)
	l = loadedLatencyOf(some, idle, 1000)
	if *l.MedianMs != 31 || l.MedianAtLeast || *l.P95Ms != 1000 || !l.P95AtLeast {
		t.Errorf("poche perse: %+v %v %v", l, *l.MedianMs, *l.P95Ms)
	}
	if plain := latencyOf(some); *plain.MedianMs != 29 {
		t.Errorf("senza conteggio: %v", *plain.MedianMs)
	}
	// Perdite anche a riposo (metà): la stessa quota non conta come coda.
	l = loadedLatencyOf(append([]*float64{f(20), f(30)}, lost(2)...), &scan.SpeedLatency{Sent: 20, Received: 10, MedianMs: f(10)}, 1000)
	if *l.MedianMs != 25 || l.MedianAtLeast || l.P95AtLeast {
		t.Errorf("perdite casuali: %+v", l)
	}
	// Senza latenza a riposo non si può dire che cosa sia una sonda persa.
	if l := loadedLatencyOf(lost(5), nil, 1000); l.Received != 0 || l.MedianMs != nil || l.MedianAtLeast {
		t.Errorf("senza riposo: %+v", l)
	}
	if loadedLatencyOf(nil, idle, 1000) != nil {
		t.Error("senza campioni")
	}
}

// In upload la velocità è quella ricevuta dal server, dal suo TCPInfo (come
// lo invia ndt-server, senza AppInfo): i byte scritti dal PC comprendono
// quelli ancora in coda quando smette di inviare.
func TestUploadSpeedFromServer(t *testing.T) {
	msg := func(s string) *measurement {
		var m measurement
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			t.Fatal(err)
		}
		return &m
	}
	r := &dirResult{bytes: 13_000_000, elapsed: 10 * time.Second, upload: true,
		server: msg(`{"ConnectionInfo":{"Client":"203.0.113.7:54321","UUID":"x"},"BBRInfo":{"BW":1},"TCPInfo":{"BytesReceived":11000000,"ElapsedTime":9900000,"MinRTT":21000}}`)}
	if d := r.dir(nil, 1000); d.Source != "server" || d.Mbps != 8.9 || d.Bytes != 11_000_000 || d.Ms != 9900 || *d.MinRTTMs != 21 {
		t.Errorf("da TCPInfo: %+v", d)
	}
	// AppInfo, facoltativo nella specifica, se TCPInfo non ha i byte ricevuti.
	r.server = msg(`{"AppInfo":{"NumBytes":12000000,"ElapsedTime":10000000},"TCPInfo":{"MinRTT":21000}}`)
	if d := r.dir(nil, 1000); d.Source != "server" || d.Mbps != 9.6 {
		t.Errorf("da AppInfo: %+v", d)
	}
	// Un messaggio dei primi istanti non basta, e senza messaggi conta il PC.
	r.server = msg(`{"TCPInfo":{"BytesReceived":500000,"ElapsedTime":1000000}}`)
	if d := r.dir(nil, 1000); d.Source != "client" || d.Mbps != 10.4 || d.Bytes != 13_000_000 {
		t.Errorf("messaggio troppo vecchio: %+v", d)
	}
	r.server = nil
	if d := r.dir(nil, 1000); d.Source != "client" || d.Mbps != 10.4 {
		t.Errorf("senza messaggi: %+v", d)
	}
	// In download conta il PC, che riceve i dati.
	r.upload = false
	r.server = msg(`{"TCPInfo":{"BytesReceived":600,"BytesAcked":13100000,"BytesSent":13300000,"BytesRetrans":133000,"ElapsedTime":10000000}}`)
	if d := r.dir(nil, 1000); d.Source != "client" || d.Mbps != 10.4 || d.RetransPct == nil || *d.RetransPct != 1 {
		t.Errorf("download: %+v", d)
	}
}

// ndt-server avvia la chiusura allo scadere dei suoi 10 secondi, a volte
// prima che il client smetta di inviare: è una fine regolare, non un
// trasferimento interrotto.
func TestServerClosesDuringUpload(t *testing.T) {
	for i := 0; i < 3; i++ {
		f := newFakeMLab(t, "mlab1-mil05.mlab-oti.measurement-lab.org")
		f.dur = 200 * time.Millisecond
		f.closeAfter = 250 * time.Millisecond
		opt := f.options()
		opt.Duration = 1500 * time.Millisecond
		opt.UploadCap = 1 << 40
		res, err := Run(context.Background(), opt)
		if err != nil {
			t.Fatal(err)
		}
		if u := res.Upload; u.Error != "" || u.Mbps <= 0 || u.Ms >= 1500 || u.Source != "server" {
			t.Fatalf("prova %d: %+v", i+1, u)
		}
	}
}

// Un proxy o il server chiudono l'upload con un codice di errore (1011,
// errore interno): non è una fine regolare e il risultato lo dice, come per
// il download. Solo 1000, 1001 e 1005 sono chiusure regolari.
func TestServerClosesUploadWithError(t *testing.T) {
	for i := 0; i < 3; i++ {
		f := newFakeMLab(t, "mlab1-mil05.mlab-oti.measurement-lab.org")
		f.dur = 200 * time.Millisecond
		f.closeAfter = 250 * time.Millisecond
		f.closeCode = websocket.CloseInternalServerErr
		opt := f.options()
		opt.Duration = 1500 * time.Millisecond
		opt.UploadCap = 1 << 40
		res, err := Run(context.Background(), opt)
		if err != nil {
			t.Fatal(err)
		}
		u := res.Upload
		if u.Mbps <= 0 || !strings.HasPrefix(u.Error, "trasferimento interrotto prima della fine (il server ha chiuso la connessione segnalando un errore") {
			t.Fatalf("prova %d: %+v", i+1, u)
		}
	}
	for _, code := range []int{websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseNoStatusReceived} {
		if !normalEnd(&websocket.CloseError{Code: code}) {
			t.Errorf("chiusura %d non regolare", code)
		}
	}
	if normalEnd(&websocket.CloseError{Code: websocket.CloseInternalServerErr}) {
		t.Error("chiusura 1011 regolare")
	}
	// Una chiusura regolare non è descritta come un errore del server.
	if s := describe(&websocket.CloseError{Code: websocket.CloseNormalClosure, Text: "fine"}); strings.Contains(s, "errore") {
		t.Errorf("chiusura 1000: %q", s)
	}
}

// La connessione cade a metà, senza messaggio di chiusura: gorilla/websocket
// lo riporta come chiusura 1006, un codice che nessun server invia (RFC 6455,
// 7.4.1). Il risultato dice «connessione interrotta», non che il server ha
// segnalato un errore.
func TestConnectionDropped(t *testing.T) {
	const want = "trasferimento interrotto prima della fine (connessione interrotta): il valore può essere più basso del reale"
	for i := 0; i < 3; i++ {
		f := newFakeMLab(t, "mlab1-mil05.mlab-oti.measurement-lab.org")
		f.dropDownload = 150 * time.Millisecond
		res, err := Run(context.Background(), f.options())
		if err != nil {
			t.Fatal(err)
		}
		if d := res.Download; d.Error != want || d.Mbps <= 0 {
			t.Fatalf("download, prova %d: %+v", i+1, d)
		}
		if u := res.Upload; u.Error != "" {
			t.Fatalf("upload regolare, prova %d: %+v", i+1, u)
		}
	}
	for i := 0; i < 3; i++ {
		f := newFakeMLab(t, "mlab1-mil05.mlab-oti.measurement-lab.org")
		f.dropUpload = 150 * time.Millisecond
		opt := f.options()
		opt.UploadCap = 1 << 40
		res, err := Run(context.Background(), opt)
		if err != nil {
			t.Fatal(err)
		}
		if d := res.Download; d.Error != "" {
			t.Fatalf("download regolare, prova %d: %+v", i+1, d)
		}
		if u := res.Upload; u.Error != want || u.Mbps <= 0 {
			t.Fatalf("upload, prova %d: %+v", i+1, u)
		}
	}
	abnormal := &websocket.CloseError{Code: websocket.CloseAbnormalClosure, Text: io.ErrUnexpectedEOF.Error()}
	if got := describe(abnormal); got != "connessione interrotta" {
		t.Errorf("1006: %q", got)
	}
	if got := noServer(abnormal).Error(); got != "nessun server di M-Lab ha accettato il test: connessione interrotta" {
		t.Errorf("nessun server, 1006: %q", got)
	}
}

// Gli indirizzi scadono prima dell'upload e M-Lab non propone più il server
// del download: l'upload va su un altro server e il risultato lo dice; il
// server del download resta quello.
func TestUploadServerChange(t *testing.T) {
	old := tokenTTL
	tokenTTL = 400 * time.Millisecond
	t.Cleanup(func() { tokenTTL = old })
	const a, b = "mlab1-mil05.mlab-oti.measurement-lab.org", "mlab2-trn02.mlab-oti.measurement-lab.org"
	f := newFakeMLab(t, a)
	f.later = []string{b}
	res, err := Run(context.Background(), f.options())
	if err != nil {
		t.Fatal(err)
	}
	if res.Server.Machine != a || res.Server.Site != "mil05" || res.Upload.Server == nil || res.Upload.Server.Site != "trn02" || res.Upload.Error != "" || res.Download.Server != nil {
		t.Errorf("server: %+v, upload %+v su %+v", res.Server, res.Upload, res.Upload.Server)
	}
	f.mu.Lock()
	paths, locates := slices.Clone(f.paths), f.locates
	f.mu.Unlock()
	if !slices.Equal(paths, []string{a + "/ndt/v7/download", b + "/ndt/v7/upload"}) || locates != 2 {
		t.Errorf("tentativi %v, richieste a Locate %d", paths, locates)
	}
	// Se Locate propone ancora lo stesso server, l'upload resta lì.
	g := newFakeMLab(t, a)
	g.later = []string{b, a}
	res, err = Run(context.Background(), g.options())
	if err != nil {
		t.Fatal(err)
	}
	if res.Upload.Server != nil || res.Server.Machine != a {
		t.Errorf("stesso server: %+v %+v", res.Server, res.Upload.Server)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !slices.Equal(g.paths, []string{a + "/ndt/v7/download", a + "/ndt/v7/upload"}) {
		t.Errorf("tentativi %v", g.paths)
	}
}
