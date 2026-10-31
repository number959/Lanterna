package speedtest

import (
	"context"
	"math"
	"sort"
	"sync"
	"time"

	"lanterna/internal/scan"
)

func round1(x float64) float64 { return math.Round(x*10) / 10 }
func round2(x float64) float64 { return math.Round(x*100) / 100 }

// prober ripete le sonde di latenza dell'agente a ritmo regolare: echo ICMP
// ogni 250 ms o, se i primi tre echo restano senza risposta (ping bloccati),
// connessioni TCP ogni 500 ms, come l'analisi. Le sonde viaggiano su
// connessioni separate da quella del test ("foreign probes" del metodo IETF
// sulla reattività): con BBR la latenza dentro la connessione del test
// sottostima la coda.
type prober struct {
	ping  func(ctx context.Context, tcp bool) *float64
	every time.Duration
	now   func() time.Time
	// timeout: quanto la sonda aspetta la risposta (le sonde dell'agente,
	// QuickPing, aspettano un secondo); il contesto le ferma poco dopo.
	timeout time.Duration

	mu      sync.Mutex
	tcp     bool
	decided bool
	none    bool
}

func (p *prober) method() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch {
	case p.ping == nil || p.none:
		return ""
	case p.tcp:
		return "tcp"
	}
	return "icmp"
}

// run misura per d (dall'ultima scelta del metodo) e restituisce i
// campioni, nil per quelli senza risposta. sample riceve ogni campione con
// il tempo trascorso.
func (p *prober) run(ctx context.Context, d time.Duration, sample func(v *float64, elapsed time.Duration)) []*float64 {
	if p.ping == nil {
		sleepCtx(ctx, d)
		return nil
	}
	var out []*float64
	start := p.now()
	end := start.Add(d)
	for ctx.Err() == nil && p.now().Before(end) {
		p.mu.Lock()
		tcp, none := p.tcp, p.none
		p.mu.Unlock()
		if none {
			sleepCtx(ctx, time.Until(end))
			break
		}
		t0 := p.now()
		wait := p.timeout
		if wait <= 0 {
			wait = time.Second
		}
		pctx, cancel := context.WithTimeout(ctx, wait+500*time.Millisecond)
		v := p.ping(pctx, tcp)
		cancel()
		if ctx.Err() != nil {
			break
		}
		if v != nil {
			r := round1(*v)
			v = &r
		}
		out = append(out, v)
		sample(v, p.now().Sub(start))
		p.mu.Lock()
		if !p.decided {
			switch {
			case v != nil:
				p.decided = true
			case len(out) >= 3 && countOK(out) == 0 && !p.tcp:
				// ICMP bloccato: si ricomincia con le connessioni TCP.
				p.tcp, out, end = true, nil, p.now().Add(d)
			case len(out) >= 3 && countOK(out) == 0:
				// Nessuna risposta neppure via TCP: niente latenza.
				p.none, p.decided, out = true, true, nil
			}
		}
		every := p.every
		if p.tcp {
			every *= 2
		}
		p.mu.Unlock()
		sleepCtx(ctx, min(every-p.now().Sub(t0), end.Sub(p.now())))
	}
	return out
}

func sleepCtx(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

func countOK(xs []*float64) int {
	n := 0
	for _, x := range xs {
		if x != nil {
			n++
		}
	}
	return n
}

// latencyOf riassume i campioni: minimo, mediana e 95° percentile (al rango
// più vicino) delle risposte; nil senza campioni.
func latencyOf(samples []*float64) *scan.SpeedLatency {
	if len(samples) == 0 {
		return nil
	}
	l := &scan.SpeedLatency{Sent: len(samples)}
	var ok []float64
	for _, s := range samples {
		if s != nil {
			ok = append(ok, *s)
		}
	}
	l.Received = len(ok)
	if len(ok) == 0 {
		return l
	}
	sort.Float64s(ok)
	l.MinMs = scan.Ptr(round1(ok[0]))
	l.MedianMs = scan.Ptr(round1(percentile(ok, 50)))
	l.P95Ms = scan.Ptr(round1(percentile(ok, 95)))
	return l
}

// loadedLatencyOf riassume i campioni presi durante un trasferimento. Se a
// riposo le sonde rispondevano, una sonda che ora resta senza risposta entro
// timeoutMs indica con ogni probabilità una coda più lunga dell'attesa (o un
// pacchetto scartato dalla coda piena): conta come latenza pari a timeoutMs,
// che è un minimo. Le perdite casuali, nella quota vista a riposo, restano
// fuori. Mediana e 95° percentile si calcolano su risposte e sonde contate
// così: se cadono su una sonda senza risposta valgono timeoutMs e sono
// segnati come valori minimi (MedianAtLeast, P95AtLeast). Senza questo
// conteggio una coda oltre il secondo, con tutte le sonde perse, non avrebbe
// mediana e sembrerebbe contenuta.
func loadedLatencyOf(samples []*float64, idle *scan.SpeedLatency, timeoutMs float64) *scan.SpeedLatency {
	l := latencyOf(samples)
	if l == nil || l.Received == l.Sent || timeoutMs <= 0 || idle == nil || idle.Sent == 0 || idle.MedianMs == nil {
		return l
	}
	lost := l.Sent - l.Received
	random := int(math.Round(float64(l.Sent) * float64(idle.Sent-idle.Received) / float64(idle.Sent)))
	censored := lost - random
	if censored <= 0 {
		return l
	}
	vals := make([]float64, 0, l.Received+censored)
	for _, s := range samples {
		if s != nil {
			vals = append(vals, *s)
		}
	}
	for i := 0; i < censored; i++ {
		vals = append(vals, timeoutMs)
	}
	sort.Float64s(vals)
	n := len(vals)
	l.MedianMs = scan.Ptr(round1(percentile(vals, 50)))
	l.P95Ms = scan.Ptr(round1(percentile(vals, 95)))
	// Le sonde contate a timeoutMs sono in fondo: il valore è un minimo se
	// il suo rango (per la mediana pari, il centrale più alto) cade tra loro.
	l.MedianAtLeast = n/2 >= l.Received
	l.P95AtLeast = int(math.Ceil(0.95*float64(n)))-1 >= l.Received
	return l
}

// percentile su valori ordinati: la mediana è la media dei due centrali
// quando sono pari, gli altri percentili usano il rango più vicino.
func percentile(sorted []float64, p float64) float64 {
	n := len(sorted)
	if p == 50 {
		if n%2 == 1 {
			return sorted[n/2]
		}
		return (sorted[n/2-1] + sorted[n/2]) / 2
	}
	i := int(math.Ceil(p/100*float64(n))) - 1
	if i < 0 {
		i = 0
	}
	if i >= n {
		i = n - 1
	}
	return sorted[i]
}
