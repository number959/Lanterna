package collect

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"lanterna/internal/probe"
	"lanterna/internal/scan"
	"lanterna/internal/winapi"
)

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	select {
	case <-time.After(d):
		return true
	case <-ctx.Done():
		return false
	}
}

// pingSeries invia una serie di echo ICMP a intervallo regolare. Se l'host
// non risponde ai primi echo (ICMP bloccato o filtrato) ripiega sul tempo di
// apertura di una connessione TCP sulle porte indicate: anche un rifiuto
// (RST) dimostra che l'host ha risposto e ne misura l'andata e ritorno.
func (c *Collector) pingSeries(ctx context.Context, target, label string, tcpPorts []int) scan.PingStats {
	ip := net.ParseIP(target)
	samples := make([]*float64, 0, c.Opt.PingCount)
	var lastErr error
	if p, err := c.Platform.NewPinger(); err == nil {
		for i := 0; i < c.Opt.PingCount && ctx.Err() == nil; i++ {
			t0 := time.Now()
			r := p.Echo(ip, 128, 32, false, c.Opt.PingTimeout)
			if r.Status == winapi.EchoOK {
				v := ms(r.RTT)
				samples = append(samples, &v)
			} else {
				samples = append(samples, nil)
				if r.Status == winapi.EchoError {
					lastErr = r.Err
				}
			}
			if i == 3 && countOK(samples) == 0 {
				break // quattro echo senza risposta: ICMP bloccato o host irraggiungibile
			}
			sleepCtx(ctx, c.Opt.PingInterval-time.Since(t0))
		}
		p.Close()
	} else {
		lastErr = err
	}
	st := probe.PingStats(target, label, "icmp", samples)
	if st.Received > 0 {
		return st
	}
	for _, port := range tcpPorts {
		addr := net.JoinHostPort(target, strconv.Itoa(port))
		var tcp []*float64
		for i := 0; i < c.Opt.PingCount && ctx.Err() == nil; i++ {
			t0 := time.Now()
			d, err := c.Net.TCPConnect(ctx, addr, c.Opt.PingTimeout)
			if err == nil || strings.Contains(err.Error(), "refused") {
				if err != nil {
					d = time.Since(t0)
				}
				v := ms(d)
				tcp = append(tcp, &v)
			} else {
				tcp = append(tcp, nil)
				if i == 1 && countOK(tcp) == 0 {
					break // porta filtrata: si prova la successiva
				}
			}
			sleepCtx(ctx, c.Opt.TCPInterval-time.Since(t0))
		}
		if countOK(tcp) > 0 {
			return probe.PingStats(target, label, "tcp", tcp)
		}
	}
	if lastErr != nil {
		st.Error = "ICMP non disponibile (" + lastErr.Error() + ") e nessuna risposta TCP"
	} else {
		st.Error = "nessuna risposta né ai ping né a connessioni TCP"
	}
	return st
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

// traceroute invia in parallelo un echo per ogni TTL: ogni router lungo il
// percorso risponde "TTL scaduto" e si ricostruisce la sequenza.
func (c *Collector) traceroute(ctx context.Context, target string) ([]scan.Hop, error) {
	ip := net.ParseIP(target)
	max := c.Opt.MaxHops
	res := make([]winapi.EchoResult, max+1)
	var wg sync.WaitGroup
	for ttl := 1; ttl <= max; ttl++ {
		wg.Add(1)
		go func(ttl int) {
			defer wg.Done()
			// Partenze scaglionate: lanciare tutte le sonde nello stesso istante
			// gonfierebbe i tempi dei primi salti.
			if !sleepCtx(ctx, time.Duration(ttl-1)*c.Opt.TraceStagger) {
				return
			}
			p, err := c.Platform.NewPinger()
			if err != nil {
				res[ttl] = winapi.EchoResult{Status: winapi.EchoError, Err: err}
				return
			}
			defer p.Close()
			// Due campioni per salto, si tiene il più rapido (come il minimo di tracert).
			var best winapi.EchoResult
			got := false
			for attempt := 0; attempt < 2 && ctx.Err() == nil; attempt++ {
				r := p.Echo(ip, ttl, 32, false, 1500*time.Millisecond)
				switch {
				case r.Status == winapi.EchoOK || r.Status == winapi.EchoTTLExpired || r.Status == winapi.EchoUnreachable:
					if !got || r.RTT < best.RTT {
						best, got = r, true
					}
				case !got:
					best = r
				}
			}
			res[ttl] = best
		}(ttl)
	}
	wg.Wait()
	allErr := true
	for ttl := 1; ttl <= max; ttl++ {
		if res[ttl].Status != winapi.EchoError {
			allErr = false
		}
	}
	if allErr {
		return nil, fmt.Errorf("traceroute non eseguibile: %v", res[1].Err)
	}
	var hops []scan.Hop
	lastResp := 0
	for ttl := 1; ttl <= max; ttl++ {
		r := res[ttl]
		h := scan.Hop{TTL: ttl}
		if r.From != nil && (r.Status == winapi.EchoOK || r.Status == winapi.EchoTTLExpired || r.Status == winapi.EchoUnreachable) {
			h.IP = r.From.String()
			if r.Status != winapi.EchoUnreachable {
				v := ms(r.RTT)
				h.RttMs = &v
			}
			lastResp = ttl
		}
		hops = append(hops, h)
		if r.Status == winapi.EchoOK || r.Status == winapi.EchoUnreachable {
			return hops, nil
		}
	}
	// Destinazione mai raggiunta: si tagliano i salti muti finali.
	if lastResp+1 < len(hops) {
		hops = hops[:lastResp+1]
	}
	return hops, nil
}

// pathMTU cerca il pacchetto più grande che attraversa il percorso senza
// essere frammentato (bit DF), con una ricerca binaria tra 1200 e 1472 byte
// di dati (1228-1500 byte di pacchetto IP).
func (c *Collector) pathMTU(ctx context.Context, target string) (*scan.MtuResult, error) {
	p, err := c.Platform.NewPinger()
	if err != nil {
		return nil, nil
	}
	defer p.Close()
	ip := net.ParseIP(target)
	fits := func(size int) bool {
		for attempt := 0; attempt < 2 && ctx.Err() == nil; attempt++ {
			r := p.Echo(ip, 128, size, true, time.Second)
			switch r.Status {
			case winapi.EchoOK:
				return true
			case winapi.EchoTimeout:
				continue // può essere una perdita: si riprova una volta
			default:
				return false
			}
		}
		return false
	}
	const method = "ICMP con bit DF (non frammentare)"
	if fits(1472) {
		return &scan.MtuResult{MTU: 1500, Method: method}, nil
	}
	if !fits(1200) {
		return nil, nil // ICMP filtrato: la misura non è possibile, non è un guasto
	}
	lo, hi := 1200, 1472
	for hi-lo > 1 && ctx.Err() == nil {
		mid := (lo + hi) / 2
		if fits(mid) {
			lo = mid
		} else {
			hi = mid
		}
	}
	return &scan.MtuResult{MTU: lo + 28, Method: method}, nil
}

// QuickPing misura un singolo tempo di risposta per il monitor in tempo
// reale: un echo ICMP, oppure una connessione TCP se l'ICMP non risponde.
func (c *Collector) QuickPing(ctx context.Context, target string, tcpPorts []int, preferTCP bool) *float64 {
	ip := net.ParseIP(target)
	if ip == nil {
		return nil
	}
	if p, err := c.Platform.NewPinger(); err == nil && !preferTCP {
		r := p.Echo(ip, 128, 32, false, time.Second)
		p.Close()
		if r.Status == winapi.EchoOK {
			v := ms(r.RTT)
			return &v
		}
		if r.Status != winapi.EchoError {
			return nil // timeout: pacchetto perso, è proprio ciò che il monitor deve mostrare
		}
	}
	for _, port := range tcpPorts {
		t0 := time.Now()
		_, err := c.Net.TCPConnect(ctx, net.JoinHostPort(target, strconv.Itoa(port)), time.Second)
		if err == nil || strings.Contains(err.Error(), "refused") {
			v := ms(time.Since(t0))
			return &v
		}
	}
	return nil
}
