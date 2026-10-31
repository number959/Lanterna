// Package survey misura il Wi-Fi in un punto, per la mappa del Wi-Fi per
// stanza: l'utente va nella stanza, le dà un nome e preme un pulsante;
// Polaris legge per circa 15 secondi il segnale ricevuto dal PC (una volta al
// secondo), l'access point e le velocità radio, e intanto misura il router
// con un ping ogni 200 ms (solo se il suo indirizzo è privato o link-local).
// Alla fine, se richiesto, una sola scansione delle reti: mai durante la
// misura, perché una scansione aumenta la latenza.
//
// Solo letture: nessuna impostazione della scheda o del sistema viene
// cambiata. Su Windows 11 24H2 e successivi servono i permessi di posizione,
// e mentre la misura è in corso Windows mostra l'icona della posizione.
//
// I calcoli (statistiche, cambi di access point, scansione) stanno in file
// che si compilano ovunque e si collaudano con una radio finta; le chiamate a
// Windows in survey_windows.go.
package survey

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"lanterna/internal/scan"
	"lanterna/internal/winapi"
	"lanterna/internal/wlan"
)

var (
	// ErrUnavailable: misura possibile solo su Windows.
	ErrUnavailable = errors.New("la mappa del Wi-Fi si misura solo su Windows, con l'agente")
	// ErrNotConnected: la scheda Wi-Fi non è collegata (anche solo per un attimo).
	ErrNotConnected = errors.New("il PC non è collegato a una rete Wi-Fi")

	errDropped  = errors.New("il PC si è scollegato dalla rete Wi-Fi durante la misura: in questo punto la connessione non regge, oppure è stata chiusa. Ripeti la misura")
	errSwitched = errors.New("il PC è passato a un'altra rete Wi-Fi durante la misura: ripeti la misura restando collegato alla stessa rete")
)

// Link è una lettura della connessione Wi-Fi.
type Link struct {
	SSID    string
	BSSID   string
	RssiDbm *int
	RxKbps  uint32
	TxKbps  uint32
	Phy     string
	Channel int
}

// Radio è la scheda Wi-Fi scelta all'inizio della misura: tutte le letture
// riguardano quella scheda, anche se nel frattempo se ne collega un'altra.
type Radio interface {
	// Link legge la connessione; ErrNotConnected se la scheda non è collegata.
	Link() (Link, error)
	// Scan chiede una scansione e ne attende la fine (pochi secondi).
	Scan(ctx context.Context) error
	// Networks legge la lista delle reti, con l'età di ogni voce.
	Networks() ([]Seen, error)
	// Gateway è il gateway IPv4 della scheda ("" se non ne ha).
	Gateway() string
	Close()
}

// Progress è l'avanzamento della misura in corso.
type Progress struct {
	// Phase: "misura" (lettura del segnale e ping) o "scansione".
	Phase     string `json:"phase"`
	ElapsedMs int64  `json:"elapsedMs"`
	Seconds   int    `json:"seconds"`
	// Dbm: l'ultima lettura del segnale; Rssi tutte quelle fatte finora.
	Dbm     *int  `json:"dbm,omitempty"`
	Rssi    []int `json:"rssi"`
	Roams   int   `json:"roams"`
	Pings   int   `json:"pings"`
	Replies int   `json:"replies"`
}

// Options della misura.
type Options struct {
	Room    string
	Seconds int  // 10-20, 0 = 15
	Scan    bool // una scansione dopo la misura
	// Progress riceve l'avanzamento (può essere nil).
	Progress func(Progress)

	// Tempi (zero = valori reali): servono ai test.
	tick, pingEvery, pingTimeout time.Duration
}

const (
	pingEvery   = 200 * time.Millisecond
	pingTimeout = time.Second
	pingPayload = 32
	pingTTL     = 128
	// Letture "non collegato" di fila tollerate: durante un cambio di access
	// point la scheda risulta per un attimo in associazione.
	maxGap = 2
)

// Run esegue la misura con la radio indicata. newPinger crea un pinger ICMP
// per ogni ping in volo (IcmpSendEcho è bloccante: un ping perso non deve
// fermare la serie).
func Run(ctx context.Context, r Radio, newPinger func() (winapi.Pinger, error), opt Options) (*scan.SurveySample, error) {
	room, err := Room(opt.Room)
	if err != nil {
		return nil, err
	}
	secs, err := Seconds(opt.Seconds)
	if err != nil {
		return nil, err
	}
	tick, every, timeout := opt.tick, opt.pingEvery, opt.pingTimeout
	if tick == 0 {
		tick = time.Second
	}
	if every == 0 {
		every = pingEvery
	}
	if timeout == 0 {
		timeout = pingTimeout
	}

	first, err := r.Link()
	if errors.Is(err, ErrNotConnected) || (err == nil && first.SSID == "") {
		return nil, ErrNotConnected
	}
	if err != nil {
		return nil, err
	}
	start := time.Now()
	out := &scan.SurveySample{Room: room, StartedAt: start.UTC().Format(time.RFC3339), Seconds: secs, SSID: first.SSID, Rssi: []int{}, BSSIDs: []string{}, Roams: []scan.SurveyRoam{}}

	// Ping al router, in parallelo, solo verso indirizzi privati o link-local.
	var sent, replies atomic.Int32
	var pings chan pingResult
	pctx, stopPings := context.WithCancel(ctx)
	defer stopPings()
	gwText := r.Gateway()
	gw := net.ParseIP(gwText).To4()
	switch {
	case gw == nil:
		out.Gateway = &scan.SurveyPing{Skipped: "la scheda Wi-Fi non ha un gateway IPv4"}
	case !gw.IsPrivate() && !gw.IsLinkLocalUnicast():
		out.Gateway = &scan.SurveyPing{Skipped: "il router ha un indirizzo pubblico: per prudenza non si misura"}
	default:
		pings = make(chan pingResult, 1)
		n := int(time.Duration(secs) * tick / every)
		go func() { pings <- pingSeries(pctx, gw, n, every, timeout, newPinger, &sent, &replies) }()
	}

	report := func(p Progress) {
		if opt.Progress != nil {
			p.Seconds, p.Pings, p.Replies = secs, int(sent.Load()), int(replies.Load())
			p.ElapsedMs = time.Since(start).Milliseconds()
			opt.Progress(p)
		}
	}

	var readings []Reading
	var rx, tx []int
	channels := []int{}
	phy := ""
	gap, gaps, failed := 0, 0, 0
	var lastErr error
	for i := 0; i < secs; i++ {
		l, err := first, error(nil)
		if i > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Until(start.Add(time.Duration(i) * tick))):
			}
			l, err = r.Link()
		}
		at := time.Since(start).Milliseconds()
		switch {
		case errors.Is(err, ErrNotConnected):
			gap++
			gaps++
			if gap > maxGap {
				return nil, errDropped
			}
			continue
		case err != nil:
			failed++
			lastErr = err
			if failed > secs/2 {
				return nil, err
			}
			continue
		case l.SSID != first.SSID:
			return nil, errSwitched
		}
		gap = 0
		readings = append(readings, Reading{AtMs: at, BSSID: l.BSSID, Dbm: l.RssiDbm})
		if l.RssiDbm != nil {
			out.Rssi = append(out.Rssi, *l.RssiDbm)
		}
		if l.RxKbps > 0 {
			rx = append(rx, int(l.RxKbps/1000))
		}
		if l.TxKbps > 0 {
			tx = append(tx, int(l.TxKbps/1000))
		}
		if l.Phy != "" {
			phy = l.Phy
		}
		if l.Channel > 0 && (len(channels) == 0 || channels[len(channels)-1] != l.Channel) {
			channels = append(channels, l.Channel)
		}
		_, roams := Roams(readings)
		report(Progress{Phase: "misura", Dbm: l.RssiDbm, Rssi: append([]int(nil), out.Rssi...), Roams: len(roams)})
	}
	if pings != nil {
		res := <-pings
		if res.err != nil {
			out.Gateway = &scan.SurveyPing{Target: gw.String(), Error: res.err.Error()}
		} else {
			out.Gateway = PingStats(gw.String(), res.echoes)
			if res.failed > 0 && res.failed == len(res.echoes) {
				out.Gateway.Error = "nessun ping è partito: " + res.lastErr
			}
		}
	}
	out.DurationMs = time.Since(start).Milliseconds()

	if len(out.Rssi) < (secs+1)/2 {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, fmt.Errorf("Windows ha fornito solo %d letture del segnale su %d: ripeti la misura", len(out.Rssi), secs)
	}
	sig := SignalStats(out.Rssi)
	out.MedianDbm, out.MinDbm, out.MaxDbm, out.P10Dbm, out.SpreadDb, out.Stuck = sig.Median, sig.Min, sig.Max, sig.P10, sig.Spread, sig.Stuck
	out.BSSIDs, out.Roams = Roams(readings)
	out.RxMbps, out.TxMbps, out.Phy = medianInt(rx), medianInt(tx), phy
	if len(channels) > 0 {
		out.Channel = channels[len(channels)-1]
	}
	if n := len(out.Rssi); n < secs {
		out.Notes = append(out.Notes, fmt.Sprintf("%d letture del segnale su %d: la scheda non ha risposto ogni secondo.", n, secs))
	}
	if gaps > 0 {
		out.Notes = append(out.Notes, fmt.Sprintf("Il collegamento si è interrotto per %d %s durante la misura.", gaps, plural(gaps, "secondo", "secondi")))
	}
	if len(channels) > 1 {
		out.Notes = append(out.Notes, fmt.Sprintf("Il canale è cambiato durante la misura (%s).", joinInts(channels, " → ")))
	}

	// Dopo la misura: banda e larghezza dalla lista delle reti, e la scansione.
	last := lastBSSID(out)
	var nets []Seen
	var listErr, scanErr error
	if opt.Scan {
		report(Progress{Phase: "scansione", Rssi: append([]int(nil), out.Rssi...), Roams: len(out.Roams)})
		scanErr = r.Scan(ctx)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	nets, listErr = r.Networks()
	out.Band = wlan.BandFor(0, out.Channel)
	if c := connectedBss(nets, out.SSID, last); c != nil {
		out.Band, out.WidthMhz = c.Band, c.WidthMhz
		if out.Channel == 0 {
			out.Channel = c.Channel
		}
	}
	if opt.Scan {
		if listErr != nil {
			out.Scan = &scan.SurveyScan{Error: listErr.Error()}
		} else {
			out.Scan = Facts(nets, out.SSID, last, out.Band, out.Channel)
			if scanErr != nil {
				out.Scan.Error = "scansione non riuscita (" + scanErr.Error() + "): restano solo le reti sentite negli ultimi 10 secondi"
			}
			unknown := 0
			for _, n := range nets {
				if n.AgeMs < 0 {
					unknown++
				}
			}
			if unknown > 0 && unknown == len(nets) {
				out.Notes = append(out.Notes, "La scheda non indica quando ha sentito le reti: la scansione può includere dati di qualche secondo prima.")
			}
		}
	}
	return out, nil
}

// lastBSSID è l'access point a cui il PC era collegato alla fine della misura.
func lastBSSID(s *scan.SurveySample) string {
	if n := len(s.Roams); n > 0 {
		return s.Roams[n-1].To
	}
	if len(s.BSSIDs) > 0 {
		return s.BSSIDs[0]
	}
	return ""
}

type pingResult struct {
	echoes  []Echo
	failed  int
	lastErr string
	err     error
}

// pingSeries invia n ping a ip, uno ogni every, ciascuno in una goroutine
// propria con un pinger preso da una piccola riserva: un ping senza risposta
// (fino a timeout) non ritarda i successivi.
func pingSeries(ctx context.Context, ip net.IP, n int, every, timeout time.Duration, newPinger func() (winapi.Pinger, error), sent, replies *atomic.Int32) pingResult {
	if newPinger == nil {
		return pingResult{err: errors.New("ping non disponibile")}
	}
	p0, err := newPinger()
	if err != nil {
		return pingResult{err: fmt.Errorf("ping non disponibile: %v", err)}
	}
	pool := make(chan winapi.Pinger, 8)
	pool <- p0
	get := func() (winapi.Pinger, error) {
		select {
		case p := <-pool:
			return p, nil
		default:
			return newPinger()
		}
	}
	put := func(p winapi.Pinger) {
		select {
		case pool <- p:
		default:
			p.Close()
		}
	}
	echoes := make([]Echo, n)
	errs := make([]string, n)
	var wg sync.WaitGroup
	t0 := time.Now()
	launched := 0
loop:
	for k := 0; k < n; k++ {
		if k > 0 {
			select {
			case <-ctx.Done():
				break loop
			case <-time.After(time.Until(t0.Add(time.Duration(k) * every))):
			}
		}
		p, err := get()
		launched++
		sent.Add(1)
		if err != nil {
			errs[k] = err.Error()
			continue
		}
		wg.Add(1)
		go func(k int, p winapi.Pinger) {
			defer wg.Done()
			res := p.Echo(ip, pingTTL, pingPayload, false, timeout)
			put(p)
			switch {
			case res.Status == winapi.EchoOK:
				v := float64(res.RTT.Microseconds()) / 1000
				echoes[k] = &v
				replies.Add(1)
			case res.Status == winapi.EchoError && res.Err != nil:
				errs[k] = res.Err.Error()
			case res.Status == winapi.EchoError:
				errs[k] = "errore ICMP"
			}
		}(k, p)
	}
	wg.Wait()
	close(pool)
	for p := range pool {
		p.Close()
	}
	out := pingResult{echoes: echoes[:launched]}
	for _, e := range errs[:launched] {
		if e != "" {
			out.failed++
			out.lastErr = e
		}
	}
	return out
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func joinInts(xs []int, sep string) string {
	s := ""
	for i, x := range xs {
		if i > 0 {
			s += sep
		}
		s += fmt.Sprint(x)
	}
	return s
}
