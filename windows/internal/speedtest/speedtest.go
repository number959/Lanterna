// Package speedtest misura la velocità della connessione a Internet con
// Measurement Lab (M-Lab), con un client ndt7 minimo scritto dalla specifica
// pubblica (github.com/m-lab/ndt-server, spec/ndt7-protocol.md, v0.11.0):
//
//  1. il servizio Locate di M-Lab indica fino a quattro server vicini, con
//     indirizzi che valgono un minuto;
//  2. la latenza a riposo si misura per circa 5 secondi con le stesse sonde
//     del monitor (ICMP verso 1.1.1.1, o TCP se i ping sono bloccati);
//  3. download per 10 secondi su una sola connessione WebSocket cifrata
//     (early_exit=250: il server si ferma a 250 MB), con le sonde di latenza
//     che continuano su connessioni separate;
//  4. upload per 10 secondi, al massimo 250 MB, con le stesse sonde.
//
// La latenza sotto carico meno quella a riposo è il bufferbloat, separato per
// download e upload. Il test parte solo su richiesta esplicita, dopo il
// consenso (M-Lab pubblica il risultato con l'indirizzo IP pubblico): qui
// non si salva, non si registra e non si stampa mai l'indirizzo del PC né
// l'identificativo del test che il server comunica nei messaggi di misura.
// Per Locate e WebSocket si usa lo stesso proxy del resto dell'agente.
package speedtest

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
	"time"

	"lanterna/internal/scan"
)

const (
	// DefaultLocateURL è il servizio di M-Lab che sceglie i server vicini
	// (in base alla posizione approssimativa dell'indirizzo IP), senza
	// parametri: niente paese indicato da Polaris.
	DefaultLocateURL = "https://locate.measurementlab.net/v2/nearest/ndt/ndt7"
	// Subprotocol identifica ndt7 nella negoziazione WebSocket.
	Subprotocol = "net.measurementlab.ndt.v7"
	// ClientName è l'unico nome che Polaris dichiara a M-Lab, con la versione.
	ClientName = "starnet-polaris"
	// DefaultUploadCap è il limite di dati in upload: il server ferma il
	// download a 250 MB (early_exit), l'upload lo limita il client.
	DefaultUploadCap = 250_000_000
	// earlyExit è l'unico valore che il server accetta per early_exit (MB).
	earlyExit = "250"
	// maxResults: Locate ne restituisce al massimo quattro.
	maxResults = 4
	// tokenTTL: gli indirizzi di Locate scadono dopo un minuto; oltre questo
	// margine si chiede di nuovo a Locate prima di collegarsi.
	tokenTTL = 55 * time.Second
)

// Fasi del test, nell'ordine.
const (
	PhaseLocate   = "locate"
	PhaseIdle     = "idle"
	PhaseDownload = "download"
	PhaseUpload   = "upload"
)

// Progress è l'avanzamento del test, circa quattro volte al secondo.
type Progress struct {
	Phase string `json:"phase"`
	// Mbps: velocità del trasferimento in corso (download o upload).
	Mbps float64 `json:"mbps,omitempty"`
	// LatencyMs: ultima latenza misurata (assente se il campione è andato perso).
	LatencyMs *float64 `json:"latencyMs,omitempty"`
	// ElapsedMs: dall'inizio della fase; PhaseMs: durata prevista della fase.
	ElapsedMs int64 `json:"elapsedMs"`
	PhaseMs   int64 `json:"phaseMs,omitempty"`
	// Server: città e sito del server scelto, appena noto.
	Server *scan.SpeedServer `json:"server,omitempty"`
}

// Options regola il test. I valori zero prendono quelli predefiniti.
type Options struct {
	// Version dell'agente: va nello User-Agent e in client_version.
	Version string
	// LocateURL: servizio Locate (DefaultLocateURL).
	LocateURL string
	// Proxy sceglie il proxy per Locate e per i WebSocket (nil = diretto).
	Proxy func(*http.Request) (*url.URL, error)
	// TLSConfig per le connessioni cifrate (nil = certificati di sistema).
	TLSConfig *tls.Config
	// Ping misura un tempo di risposta verso ProbeTarget (nil = nessuna
	// latenza). tcp chiede una connessione TCP invece dell'echo ICMP; il
	// risultato è nil se il campione è andato perso.
	Ping        func(ctx context.Context, tcp bool) *float64
	ProbeTarget string
	// Idle: durata della latenza a riposo (5 s). Duration: durata di ogni
	// verso (10 s). Hard: limite di ogni verso dopo la negoziazione (13 s,
	// come nella specifica). Handshake: limite per collegarsi (7 s).
	Idle      time.Duration
	Duration  time.Duration
	Hard      time.Duration
	Handshake time.Duration
	// ProbeEvery: intervallo delle sonde ICMP (250 ms); quelle TCP vanno a
	// metà ritmo.
	ProbeEvery time.Duration
	// UploadCap: byte al massimo in upload (DefaultUploadCap).
	UploadCap int64
	Progress  func(Progress)
	Now       func() time.Time
}

func (o Options) withDefaults() Options {
	if o.LocateURL == "" {
		o.LocateURL = DefaultLocateURL
	}
	if o.Version == "" {
		o.Version = "dev"
	}
	if o.Idle <= 0 {
		o.Idle = 5 * time.Second
	}
	if o.Duration <= 0 {
		o.Duration = 10 * time.Second
	}
	if o.Hard <= 0 {
		o.Hard = 13 * time.Second
	}
	if o.Handshake <= 0 {
		o.Handshake = 7 * time.Second
	}
	if o.ProbeEvery <= 0 {
		o.ProbeEvery = 250 * time.Millisecond
	}
	if o.UploadCap <= 0 {
		o.UploadCap = DefaultUploadCap
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Progress == nil {
		o.Progress = func(Progress) {}
	}
	return o
}

// UserAgent è l'intestazione con cui Polaris si presenta a M-Lab.
func UserAgent(version string) string { return ClientName + "/" + version }

// Run esegue il test completo. Restituisce errore se nessun download è
// riuscito; un upload non riuscito resta nel risultato (Upload.Error).
func Run(ctx context.Context, opt Options) (*scan.SpeedTest, error) {
	opt = opt.withDefaults()
	start := opt.Now()
	res := &scan.SpeedTest{StartedAt: start.UTC().Format(time.RFC3339), Provider: "mlab-ndt7", Probe: opt.ProbeTarget}
	t := &tester{opt: opt}

	opt.Progress(Progress{Phase: PhaseLocate})
	targets, err := t.locate(ctx)
	if err != nil {
		return nil, err
	}
	locatedAt := opt.Now()

	// Latenza a riposo: prima di ogni trasferimento, con la linea libera.
	p := &prober{ping: opt.Ping, every: opt.ProbeEvery, now: opt.Now}
	idle := p.run(ctx, opt.Idle, func(v *float64, el time.Duration) {
		opt.Progress(Progress{Phase: PhaseIdle, LatencyMs: v, ElapsedMs: el.Milliseconds(), PhaseMs: opt.Idle.Milliseconds()})
	})
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	res.ProbeMethod = p.method()
	res.Idle = latencyOf(idle)

	// Download sul primo server che accetta, poi upload sullo stesso. Un
	// server può rifiutare il test (capacità esaurita): si passa al successivo.
	var dl *dirResult
	var used target
	var lastErr error
	tried := map[string]bool{}
	for queue := targets; len(queue) > 0; {
		if opt.Now().Sub(locatedAt) > tokenTTL {
			// Gli indirizzi stanno per scadere: se ne chiedono di nuovi.
			if fresh, err := t.locate(ctx); err == nil {
				queue, locatedAt = untried(preferSame(fresh, queue), tried), opt.Now()
				if len(queue) == 0 {
					break
				}
			}
		}
		tg := queue[0]
		queue = queue[1:]
		tried[tg.server.Machine] = true
		dl, lastErr = t.transfer(ctx, PhaseDownload, tg, p)
		if lastErr == nil {
			used = tg
			break
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if errors.Is(lastErr, ErrProxyAuth) {
			return nil, lastErr
		}
	}
	if dl == nil {
		return nil, noServer(lastErr)
	}
	res.Server = &used.server
	res.ViaProxy = t.viaProxy(used.download)
	res.Download = dl.dir(res.Idle)

	if opt.Now().Sub(locatedAt) > tokenTTL {
		if fresh, err := t.locate(ctx); err == nil {
			used = preferSame(fresh, []target{used})[0]
		}
	}
	ul, err := t.transfer(ctx, PhaseUpload, used, p)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		res.Upload = &scan.SpeedDir{Error: "upload non riuscito: " + describe(err)}
	} else {
		res.Upload = ul.dir(res.Idle)
	}
	res.DurationMs = opt.Now().Sub(start).Milliseconds()
	return res, nil
}

// preferSame mette al primo posto, tra i risultati nuovi di Locate, il server
// che si stava per usare (con l'indirizzo appena emesso).
func preferSame(fresh, wanted []target) []target {
	if len(wanted) == 0 {
		return fresh
	}
	for i, f := range fresh {
		if f.server.Machine == wanted[0].server.Machine {
			out := append([]target{f}, fresh[:i]...)
			return append(out, fresh[i+1:]...)
		}
	}
	return fresh
}

// untried toglie i server già provati.
func untried(ts []target, tried map[string]bool) []target {
	var out []target
	for _, t := range ts {
		if !tried[t.server.Machine] {
			out = append(out, t)
		}
	}
	return out
}

func (t *tester) viaProxy(raw string) bool {
	if t.opt.Proxy == nil {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if u.Scheme == "wss" {
		u.Scheme = "https"
	} else if u.Scheme == "ws" {
		u.Scheme = "http"
	}
	p, err := t.opt.Proxy(&http.Request{Method: http.MethodGet, URL: u, Header: http.Header{}})
	return err == nil && p != nil
}

type tester struct {
	opt Options
}
