package infra

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"lanterna/internal/scan"
	"lanterna/internal/winapi"
)

// MaxTargets è il numero massimo di destinazioni per una verifica.
const MaxTargets = 64

// Validate controlla le destinazioni prima di contattare qualunque host.
func Validate(targets []scan.ReachTarget) error {
	if len(targets) == 0 {
		return errors.New("nessuna destinazione da verificare")
	}
	if len(targets) > MaxTargets {
		return fmt.Errorf("al massimo %d destinazioni per verifica (ne sono arrivate %d)", MaxTargets, len(targets))
	}
	for i, t := range targets {
		if strings.TrimSpace(t.Host) == "" || len(t.Host) > 253 {
			return fmt.Errorf("destinazione %d: indirizzo o nome mancante", i+1)
		}
		if t.Port < 0 || t.Port > 65535 {
			return fmt.Errorf("destinazione %d: porta %d non valida", i+1, t.Port)
		}
		if t.Expect != "reachable" && t.Expect != "isolated" {
			return fmt.Errorf("destinazione %d: l'attesa deve essere reachable o isolated", i+1)
		}
	}
	return nil
}

// Reach verifica le destinazioni indicate dall'utente: per ciascuna una
// connessione TCP alla porta indicata o, senza porta, due ping. Solo verso
// indirizzi privati (un nome si risolve prima e deve dare un indirizzo
// privato); al massimo quattro verifiche contemporanee, con il ritmo prudente.
func Reach(ctx context.Context, targets []scan.ReachTarget, from string, p Prims, opt Options) (*scan.ReachData, error) {
	if err := Validate(targets); err != nil {
		return nil, err
	}
	out := &scan.ReachData{StartedAt: time.Now().UTC().Format(time.RFC3339), From: from, Results: make([]scan.ReachResult, len(targets))}
	workers := opt.Workers
	if workers > 4 {
		workers = 4
	}
	if workers < 1 {
		workers = 1
	}
	type job struct {
		i int
		t scan.ReachTarget
	}
	jobs := make(chan job)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				out.Results[j.i] = check(ctx, j.t, p, opt)
			}
		}()
	}
	pc := newPacer(opt.Interval * 3)
	for i, t := range targets {
		if !pc.wait(ctx) {
			break
		}
		select {
		case jobs <- job{i, t}:
		case <-ctx.Done():
		}
	}
	close(jobs)
	pc.stop()
	wg.Wait()
	for i := range out.Results {
		if out.Results[i].Status == "" { // non eseguita: contesto scaduto
			out.Results[i] = scan.ReachResult{ReachTarget: targets[i], Status: "error", Error: "verifica interrotta"}
		}
	}
	return out, nil
}

func check(ctx context.Context, t scan.ReachTarget, p Prims, opt Options) scan.ReachResult {
	t.Host = strings.TrimSpace(t.Host)
	r := scan.ReachResult{ReachTarget: t}
	ip := net.ParseIP(t.Host)
	if ip == nil {
		if p.LookupHost == nil {
			r.Status, r.Error = "unresolved", "risoluzione dei nomi non disponibile"
			return r
		}
		lctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		addrs, err := p.LookupHost(lctx, t.Host)
		cancel()
		for _, a := range addrs {
			if x := net.ParseIP(a); x != nil && (ip == nil || (ip.To4() == nil && x.To4() != nil)) {
				ip = x // si preferisce IPv4
			}
		}
		if err != nil || ip == nil {
			r.Status, r.Error = "unresolved", "nome non risolto dal DNS"
			return r
		}
	}
	r.IP = ip.String()
	if !Private(ip) {
		r.Status, r.Error = "refused", "destinazione non privata: le verifiche si fanno solo verso indirizzi della rete interna"
		return r
	}
	if t.Port > 0 {
		start := time.Now()
		_, err := p.Dial(ctx, net.JoinHostPort(ip.String(), strconv.Itoa(t.Port)), opt.DialTimeout)
		r.Status = classifyDial(err)
		if r.Status != "filtered" {
			v := ms(time.Since(start))
			r.RttMs = &v
		}
	} else {
		if ip.To4() == nil {
			r.Status, r.Error = "error", "il ping funziona solo con indirizzi IPv4: indica una porta"
			return r
		}
		if p.NewPinger == nil {
			r.Status, r.Error = "error", "ping non disponibile"
			return r
		}
		pg, err := p.NewPinger()
		if err != nil {
			r.Status, r.Error = "error", err.Error()
			return r
		}
		defer pg.Close()
		r.Status = "noreply"
		for try := 0; try < 2 && ctx.Err() == nil; try++ {
			res := pg.Echo(ip, 64, 32, false, opt.PingTimeout)
			if res.Status == winapi.EchoOK {
				v := ms(res.RTT)
				r.Status, r.RttMs = "reply", &v
				break
			}
		}
	}
	switch t.Expect {
	case "reachable":
		r.OK = r.Status == "open" || r.Status == "reply"
	case "isolated":
		r.OK = r.Status == "filtered" || r.Status == "noreply"
	}
	return r
}
