package speedtest

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"lanterna/internal/scan"
)

// measurement è il messaggio di misura di ndt7 (testo JSON). Si leggono solo
// AppInfo e TCPInfo: ConnectionInfo (indirizzo e porta del PC, identificativo
// del test) non ha un campo qui e quindi non viene mai conservato. Il server
// di M-Lab (ndt-server) invia TCPInfo, BBRInfo e ConnectionInfo, non AppInfo,
// che la specifica lascia facoltativo.
type measurement struct {
	AppInfo *struct {
		ElapsedTime int64 `json:"ElapsedTime"` // µs
		NumBytes    int64 `json:"NumBytes"`
	} `json:"AppInfo"`
	Origin  string `json:"Origin"`
	TCPInfo *struct {
		// Byte a livello TCP (comprese le intestazioni di TLS e WebSocket):
		// confermati dal PC in download, ricevuti dal server in upload.
		BytesAcked    *int64 `json:"BytesAcked"`
		BytesReceived *int64 `json:"BytesReceived"`
		BytesSent     *int64 `json:"BytesSent"`
		BytesRetrans  *int64 `json:"BytesRetrans"`
		ElapsedTime   *int64 `json:"ElapsedTime"` // µs dall'inizio del test, orologio del server
		MinRTT        *int64 `json:"MinRTT"`      // µs
		RTT           *int64 `json:"RTT"`         // µs
	} `json:"TCPInfo"`
}

// earlyExitBytes: il server ferma il download quando il PC ha confermato
// 250 MB (TCPInfo.BytesAcked, early_exit=250).
const earlyExitBytes = 250_000_000

// dirResult è l'esito grezzo di un verso del test.
type dirResult struct {
	bytes   int64
	elapsed time.Duration
	capped  bool
	// server: ultimo messaggio di misura del server (il più completo).
	server  *measurement
	loaded  []*float64
	upload  bool
	partial string
}

const (
	// minMessage e maxMessage: dimensione dei messaggi binari in upload, che
	// raddoppia quando è meno di un sedicesimo dei byte già inviati
	// (appendice della specifica). 1 MB basta anche per le linee veloci e
	// tiene preciso il limite di dati.
	minMessage = 1 << 13
	maxMessage = 1 << 20
	// readLimit: la specifica chiede di accettare messaggi fino a 1<<24 byte.
	readLimit = 1 << 25
	// closeGrace: dopo una scrittura fallita in upload, quanto si aspetta il
	// messaggio di chiusura del server prima di dire il trasferimento interrotto.
	closeGrace = 500 * time.Millisecond
)

// testURL aggiunge all'indirizzo di Locate (che porta il gettone di
// accesso) solo il nome e la versione del client e, per il download, il
// limite di 250 MB. Nessun altro dato: né sistema operativo né architettura.
func (t *tester) testURL(raw string, download bool) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "wss" {
		return "", errors.New("indirizzo del server non valido")
	}
	q := u.Query()
	q.Set("client_name", ClientName)
	q.Set("client_version", t.opt.Version)
	if download {
		q.Set("early_exit", earlyExit)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// tlsConfig: una copia per ogni uso (net/http modifica la configurazione
// che riceve), con TLS 1.2 come minimo.
func (t *tester) tlsConfig() *tls.Config {
	cfg := &tls.Config{}
	if t.opt.TLSConfig != nil {
		cfg = t.opt.TLSConfig.Clone()
	}
	if cfg.MinVersion < tls.VersionTLS12 {
		cfg.MinVersion = tls.VersionTLS12
	}
	return cfg
}

func (t *tester) dial(ctx context.Context, raw string) (*websocket.Conn, error) {
	// Solo HTTP/1.1: la negoziazione WebSocket non passa da HTTP/2.
	cfg := t.tlsConfig()
	cfg.NextProtos = []string{"http/1.1"}
	d := websocket.Dialer{
		Proxy:            t.opt.Proxy,
		TLSClientConfig:  cfg,
		HandshakeTimeout: t.opt.Handshake,
		Subprotocols:     []string{Subprotocol},
		ReadBufferSize:   1 << 18,
		WriteBufferSize:  1 << 18,
		NetDialContext:   (&net.Dialer{Timeout: t.opt.Handshake}).DialContext,
	}
	h := http.Header{}
	h.Set("User-Agent", UserAgent(t.opt.Version))
	ctx, cancel := context.WithTimeout(ctx, t.opt.Handshake)
	defer cancel()
	conn, resp, err := d.DialContext(ctx, raw, h)
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	if err != nil {
		if resp != nil {
			switch {
			case resp.StatusCode == http.StatusProxyAuthRequired:
				return nil, ErrProxyAuth
			case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable:
				return nil, handshakeError{"il server è occupato"}
			case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
				return nil, handshakeError{"il server ha rifiutato l'accesso (indirizzo scaduto)"}
			case resp.StatusCode >= 400:
				return nil, handshakeError{fmt.Sprintf("il server ha rifiutato il test (HTTP %d)", resp.StatusCode)}
			}
		}
		if isProxyAuth(err) {
			return nil, ErrProxyAuth
		}
		return nil, err
	}
	if conn.Subprotocol() != Subprotocol {
		conn.Close()
		return nil, handshakeError{"il server non ha confermato il protocollo ndt7"}
	}
	return conn, nil
}

// transfer esegue un verso del test sul server indicato, con le sonde di
// latenza che continuano su connessioni separate.
func (t *tester) transfer(ctx context.Context, phase string, tg target, p *prober) (*dirResult, error) {
	upload := phase == PhaseUpload
	raw := tg.download
	if upload {
		raw = tg.upload
	}
	u, err := t.testURL(raw, !upload)
	if err != nil {
		return nil, err
	}
	conn, err := t.dial(ctx, u)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	// Interrompere il test chiude subito la connessione.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	var mu sync.Mutex
	var mbps float64
	var lastLat *float64
	start := t.opt.Now()
	report := func() {
		mu.Lock()
		pr := Progress{Phase: phase, Mbps: round1(mbps), LatencyMs: lastLat, ElapsedMs: t.opt.Now().Sub(start).Milliseconds(), PhaseMs: t.opt.Duration.Milliseconds(), Server: &tg.server}
		mu.Unlock()
		t.opt.Progress(pr)
	}
	setSpeed := func(bytes int64, el time.Duration) {
		if el > 0 {
			mu.Lock()
			mbps = float64(bytes) * 8 / el.Seconds() / 1e6
			mu.Unlock()
		}
	}
	// Sonde di latenza sotto carico, fino alla fine del trasferimento.
	pctx, pcancel := context.WithCancel(ctx)
	loadedCh := make(chan []*float64, 1)
	go func() {
		loadedCh <- p.run(pctx, t.opt.Hard+t.opt.Handshake, func(v *float64, _ time.Duration) {
			mu.Lock()
			lastLat = v
			mu.Unlock()
		})
	}()
	// Avanzamento a ritmo fisso, indipendente dall'arrivo dei messaggi.
	tick := time.NewTicker(250 * time.Millisecond)
	tickDone := make(chan struct{})
	go func() {
		for {
			select {
			case <-tick.C:
				report()
			case <-tickDone:
				return
			}
		}
	}()

	var r *dirResult
	if upload {
		r, err = t.sendUpload(ctx, conn, start, setSpeed)
	} else {
		r, err = t.receiveDownload(ctx, conn, start, setSpeed)
	}
	tick.Stop()
	close(tickDone)
	pcancel()
	loaded := <-loadedCh
	if err != nil {
		return nil, err
	}
	r.loaded = loaded
	r.upload = upload
	report()
	return r, nil
}

// receiveDownload legge i messaggi del server fino alla chiusura (di
// solito dopo 10 secondi o 250 MB), al massimo per Hard dopo la
// negoziazione. Una connessione che si interrompe dopo aver ricevuto dati
// non annulla il test: la specifica chiede di tollerarlo.
func (t *tester) receiveDownload(ctx context.Context, conn *websocket.Conn, start time.Time, setSpeed func(int64, time.Duration)) (*dirResult, error) {
	conn.SetReadLimit(readLimit)
	_ = conn.SetReadDeadline(start.Add(t.opt.Hard))
	r := &dirResult{}
	lastData := start
	var endErr error
	for {
		kind, rd, err := conn.NextReader()
		if err != nil {
			endErr = err
			break
		}
		switch kind {
		case websocket.BinaryMessage:
			n, err := io.Copy(io.Discard, rd)
			r.bytes += n
			if err != nil {
				endErr = err
			}
		case websocket.TextMessage:
			b, err := io.ReadAll(io.LimitReader(rd, 1<<20))
			r.bytes += int64(len(b))
			if err != nil {
				endErr = err
			}
			var m measurement
			if json.Unmarshal(b, &m) == nil && m.TCPInfo != nil {
				r.server = &m
			}
		}
		if endErr != nil {
			break
		}
		lastData = t.opt.Now()
		setSpeed(r.bytes, lastData.Sub(start))
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	r.elapsed = lastData.Sub(start)
	if r.bytes == 0 {
		return nil, endErr
	}
	if !normalEnd(endErr) {
		r.partial = describe(endErr)
	}
	// early_exit: il server si ferma dopo 250 MB confermati dal PC (contati
	// con le intestazioni di TLS, quindi i byte utili sono un po' meno).
	if r.bytes >= earlyExitBytes || (r.server != nil && r.server.TCPInfo != nil && r.server.TCPInfo.BytesAcked != nil && *r.server.TCPInfo.BytesAcked >= earlyExitBytes) ||
		(r.server != nil && r.server.AppInfo != nil && r.server.AppInfo.NumBytes >= earlyExitBytes) {
		r.capped = true
	}
	return r, nil
}

// sendUpload invia dati casuali per Duration (o fino a UploadCap), poi
// chiude e attende la chiusura del server, al massimo fino a Hard.
func (t *tester) sendUpload(ctx context.Context, conn *websocket.Conn, start time.Time, setSpeed func(int64, time.Duration)) (*dirResult, error) {
	conn.SetReadLimit(1 << 20)
	r := &dirResult{}
	// srv: ultimo messaggio di misura del server, scritto dal lettore.
	var mu sync.Mutex
	var srv *measurement
	readDone := make(chan error, 1)
	go func() {
		for {
			kind, rd, err := conn.NextReader()
			if err != nil {
				readDone <- err
				return
			}
			if kind != websocket.TextMessage {
				// Durante l'upload il server non deve inviare dati binari.
				readDone <- errors.New("messaggio binario inatteso dal server")
				return
			}
			b, err := io.ReadAll(io.LimitReader(rd, 1<<20))
			if err != nil {
				readDone <- err
				return
			}
			var m measurement
			if json.Unmarshal(b, &m) == nil && (m.AppInfo != nil || m.TCPInfo != nil) {
				mu.Lock()
				srv = &m
				mu.Unlock()
			}
		}
	}()
	buf := make([]byte, maxMessage)
	_, _ = rand.Read(buf)
	size := minMessage
	hard := start.Add(t.opt.Hard)
	end := start.Add(t.opt.Duration)
	var sendErr error
	var readErr error
	serverClosed := false
loop:
	for {
		now := t.opt.Now()
		if !now.Before(end) {
			break
		}
		if r.bytes+int64(size) > t.opt.UploadCap {
			if size > minMessage && r.bytes+minMessage <= t.opt.UploadCap {
				size = minMessage // ultimi messaggi piccoli, per avvicinarsi al limite senza superarlo
			} else {
				r.capped = true
				break
			}
		}
		select {
		case readErr = <-readDone:
			serverClosed = true
			break loop
		default:
		}
		_ = conn.SetWriteDeadline(hard)
		if err := conn.WriteMessage(websocket.BinaryMessage, buf[:size]); err != nil {
			sendErr = err
			break
		}
		r.bytes += int64(size)
		setSpeed(r.bytes, t.opt.Now().Sub(start))
		if size < maxMessage && int64(size) <= r.bytes/16 && r.bytes+int64(size)*2 <= t.opt.UploadCap {
			size *= 2
		}
	}
	r.elapsed = t.opt.Now().Sub(start)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if sendErr != nil && !serverClosed {
		// Il server può avviare la chiusura in qualunque momento (specifica;
		// ndt-server lo fa dopo 10 secondi del suo orologio): una scrittura
		// che fallisce subito dopo il suo messaggio di chiusura è una fine
		// regolare. Si aspetta un attimo che il lettore lo riceva.
		select {
		case readErr = <-readDone:
			serverClosed = true
		case <-time.After(closeGrace):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if errors.Is(sendErr, websocket.ErrCloseSent) || (serverClosed && websocket.IsCloseError(readErr, websocket.CloseNormalClosure, websocket.CloseGoingAway)) {
			sendErr = nil
		}
	}
	if !serverClosed {
		_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), hard)
		wait := time.Until(hard)
		if wait < time.Second {
			wait = time.Second
		}
		select {
		case readErr = <-readDone:
		case <-time.After(wait):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if r.bytes == 0 {
		if sendErr == nil {
			sendErr = readErr
		}
		return nil, sendErr
	}
	if sendErr != nil && !normalEnd(sendErr) {
		r.partial = describe(sendErr)
	}
	mu.Lock()
	r.server = srv
	mu.Unlock()
	return r, nil
}

// normalEnd: chiusura regolare del server, o fine del tempo massimo.
func normalEnd(err error) bool {
	if err == nil || websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseNoStatusReceived) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// serverCount: byte ricevuti dal server e tempo trascorso sul suo orologio,
// dall'ultimo messaggio di misura: prima TCPInfo (BytesReceived ed
// ElapsedTime, che il server di M-Lab invia), poi AppInfo (facoltativo).
// Vale solo se copre almeno metà del tempo misurato dal PC: un messaggio
// dei primi istanti direbbe poco.
func (r *dirResult) serverCount() (bytes int64, elapsed time.Duration, ok bool) {
	m := r.server
	if m == nil {
		return 0, 0, false
	}
	if ti := m.TCPInfo; ti != nil && ti.BytesReceived != nil && ti.ElapsedTime != nil && *ti.BytesReceived > 0 && *ti.ElapsedTime > 0 {
		bytes, elapsed = *ti.BytesReceived, time.Duration(*ti.ElapsedTime)*time.Microsecond
	} else if a := m.AppInfo; a != nil && a.NumBytes > 0 && a.ElapsedTime > 0 {
		bytes, elapsed = a.NumBytes, time.Duration(a.ElapsedTime)*time.Microsecond
	} else {
		return 0, 0, false
	}
	return bytes, elapsed, 2*elapsed >= r.elapsed
}

// dir trasforma l'esito grezzo nel risultato, con il bufferbloat rispetto
// alla latenza a riposo; timeoutMs è l'attesa delle sonde di latenza.
func (r *dirResult) dir(idle *scan.SpeedLatency, timeoutMs float64) *scan.SpeedDir {
	d := &scan.SpeedDir{Bytes: r.bytes, Ms: r.elapsed.Milliseconds(), Source: "client", Capped: r.capped}
	if r.elapsed > 0 {
		d.Mbps = round1(float64(r.bytes) * 8 / r.elapsed.Seconds() / 1e6)
	}
	// In upload conta ciò che il server ha ricevuto, nel suo tempo: i byte
	// scritti dal PC comprendono quelli ancora in coda (nel buffer di invio
	// di Windows e nel modem) quando smette di inviare, e su un upload lento
	// o con molta coda darebbero una velocità più alta del vero.
	if b, el, ok := r.serverCount(); r.upload && ok {
		d.Bytes, d.Ms, d.Source = b, el.Milliseconds(), "server"
		d.Mbps = round1(float64(b) * 8 / el.Seconds() / 1e6)
	}
	if m := r.server; m != nil {
		if ti := m.TCPInfo; ti != nil {
			if ti.MinRTT != nil && *ti.MinRTT > 0 {
				d.MinRTTMs = scan.Ptr(round1(float64(*ti.MinRTT) / 1000))
			}
			if ti.RTT != nil && *ti.RTT > 0 {
				d.RTTMs = scan.Ptr(round1(float64(*ti.RTT) / 1000))
			}
			// Ritrasmissioni: hanno senso solo dove il server invia i dati.
			if !r.upload && ti.BytesSent != nil && ti.BytesRetrans != nil && *ti.BytesSent >= 1<<20 {
				d.RetransPct = scan.Ptr(round2(100 * float64(*ti.BytesRetrans) / float64(*ti.BytesSent)))
			}
		}
	}
	d.Latency = loadedLatencyOf(r.loaded, idle, timeoutMs)
	if idle != nil && idle.MedianMs != nil && d.Latency != nil && d.Latency.MedianMs != nil {
		d.BloatMs = scan.Ptr(round1(max(0, *d.Latency.MedianMs-*idle.MedianMs)))
		d.BloatP95Ms = scan.Ptr(round1(max(0, *d.Latency.P95Ms-*idle.MedianMs)))
	}
	if r.partial != "" {
		d.Error = "trasferimento interrotto prima della fine (" + r.partial + "): il valore può essere più basso del reale"
	}
	return d
}
