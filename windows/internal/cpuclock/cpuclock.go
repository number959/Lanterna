// Package cpuclock misura in tempo reale la frequenza effettiva dei core
// (il "Core Speed" di CPU-Z) con i contatori delle prestazioni di Windows,
// gli stessi di Gestione attività: "% Processor Performance" dice quanto il
// processore va rispetto alla frequenza nominale (oltre 100 % = turbo) e
// "Processor Frequency" dà la frequenza nominale. Il calcolo da APERF/MPERF lo
// fa Windows nel kernel: qui si leggono solo contatori documentati, in modalità
// utente e senza permessi di amministratore.
package cpuclock

import (
	"context"
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Sample è una lettura della frequenza dei core.
type Sample struct {
	// MHz è la frequenza effettiva media, come la mostra Gestione attività.
	MHz float64 `json:"mhz"`
	// MaxMHz è il core più veloce in questo istante.
	MaxMHz float64 `json:"maxMhz"`
	// BaseMHz è la frequenza nominale (di base).
	BaseMHz float64 `json:"baseMhz"`
	// PerfPct è la frequenza effettiva in percentuale della nominale.
	PerfPct float64 `json:"perfPct"`
	// LoadPct è il carico medio del processore.
	LoadPct float64   `json:"loadPct"`
	Cores   []Core    `json:"cores"`
	At      time.Time `json:"at"`
}

// Core è un processore logico ("gruppo,indice" per Windows).
type Core struct {
	ID      string  `json:"id"`
	MHz     float64 `json:"mhz"`
	LoadPct float64 `json:"loadPct"`
}

// ErrUnavailable: i contatori non esistono (sistema diverso da Windows, o un
// Windows che non li espone).
var ErrUnavailable = errors.New("contatori della frequenza del processore non disponibili su questo sistema")

// Reading sono i valori grezzi di un'istanza: percentuale delle prestazioni,
// frequenza nominale in MHz e carico; i campi a NaN non sono stati letti.
type Reading struct {
	Perf, Freq, Load float64
}

// Source legge i contatori: PDH su Windows, un sostituto nei test.
type Source interface {
	// Collect raccoglie un campione; i valori "di rapporto" (prestazioni,
	// carico) richiedono due raccolte.
	Collect() error
	// Read restituisce i valori dell'ultima raccolta per istanza ("_Total",
	// "0,_Total", "0,0", "0,1"...).
	Read() (map[string]Reading, error)
	Close()
}

// Sampler tiene aperti i contatori finché qualcuno li legge e li chiude dopo
// un periodo di inattività. Più letture ravvicinate condividono lo stesso
// campione.
type Sampler struct {
	Open func() (Source, error)
	// Fallback è la frequenza nominale da usare se Windows non la riporta.
	Fallback float64
	// Idle: dopo quanto senza letture si chiudono i contatori (60 s).
	Idle time.Duration
	// Min: intervallo minimo tra due raccolte (250 ms); sotto, si riusa
	// l'ultimo campione. Serve anche da attesa per la prima lettura.
	Min time.Duration
	Now func() time.Time
	// Sleep attende tra le prime due raccolte (sostituibile nei test).
	Sleep func(ctx context.Context, d time.Duration) error

	mu     sync.Mutex
	src    Source
	last   Sample
	lastAt time.Time
	used   time.Time
	timer  *time.Timer
}

func (s *Sampler) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Sampler) min() time.Duration {
	if s.Min > 0 {
		return s.Min
	}
	return 250 * time.Millisecond
}

func (s *Sampler) idle() time.Duration {
	if s.Idle > 0 {
		return s.Idle
	}
	return time.Minute
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Read restituisce la frequenza attuale dei core.
func (s *Sampler) Read(ctx context.Context) (Sample, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.used = now
	if s.src != nil && now.Sub(s.lastAt) < s.min() {
		return s.last, nil
	}
	if s.src == nil {
		if s.Open == nil {
			return Sample{}, ErrUnavailable
		}
		src, err := s.Open()
		if err != nil {
			return Sample{}, err
		}
		if err := src.Collect(); err != nil {
			src.Close()
			return Sample{}, err
		}
		sleep := s.Sleep
		if sleep == nil {
			sleep = sleepCtx
		}
		if err := sleep(ctx, s.min()); err != nil {
			src.Close()
			return Sample{}, err
		}
		s.src = src
	}
	if err := s.src.Collect(); err != nil {
		s.closeLocked()
		return Sample{}, err
	}
	r, err := s.src.Read()
	if err != nil {
		s.closeLocked()
		return Sample{}, err
	}
	smp, ok := Combine(r, s.Fallback)
	if !ok {
		s.closeLocked()
		return Sample{}, ErrUnavailable
	}
	smp.At = s.now()
	s.last, s.lastAt = smp, smp.At
	s.armLocked()
	return smp, nil
}

// armLocked programma la chiusura dei contatori dopo il periodo di inattività.
func (s *Sampler) armLocked() {
	if s.timer != nil {
		s.timer.Stop()
	}
	s.timer = time.AfterFunc(s.idle(), func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.src != nil && s.now().Sub(s.used) >= s.idle() {
			s.closeLocked()
		}
	})
}

func (s *Sampler) closeLocked() {
	if s.src != nil {
		s.src.Close()
		s.src = nil
	}
}

// Close chiude i contatori.
func (s *Sampler) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.timer != nil {
		s.timer.Stop()
	}
	s.closeLocked()
}

// instance divide il nome di un'istanza in gruppo e indice ("0,7" → 0, 7);
// false per i totali ("_Total", "0,_Total").
func instance(name string) (group, index int, ok bool) {
	g, i, found := strings.Cut(name, ",")
	if !found {
		return 0, 0, false
	}
	var err1, err2 error
	group, err1 = strconv.Atoi(g)
	index, err2 = strconv.Atoi(i)
	return group, index, err1 == nil && err2 == nil
}

func valid(v float64, max float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && v > 0 && v <= max
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }

// Combine calcola frequenze e carichi dai valori grezzi. La frequenza di un
// core è la sua nominale per la sua percentuale delle prestazioni; la media
// viene dall'istanza "_Total" se c'è, altrimenti dalla media dei core.
// false se non c'è nessuna frequenza utilizzabile.
func Combine(r map[string]Reading, fallback float64) (Sample, bool) {
	type core struct {
		g, i int
		c    Core
	}
	mhz := func(x Reading) float64 {
		base := x.Freq
		if !valid(base, 20000) {
			base = fallback
		}
		if !valid(base, 20000) || !valid(x.Perf, 1000) {
			return 0
		}
		return base * x.Perf / 100
	}
	var cores []core
	var sum, sumLoad float64
	var nLoad int
	var out Sample
	for name, x := range r {
		g, i, ok := instance(name)
		if !ok {
			continue
		}
		c := Core{ID: name, MHz: round1(mhz(x))}
		if !math.IsNaN(x.Load) && x.Load >= 0 {
			c.LoadPct = round1(math.Min(100, x.Load))
			sumLoad += c.LoadPct
			nLoad++
		}
		if c.MHz > 0 {
			sum += c.MHz
		}
		if c.MHz > out.MaxMHz {
			out.MaxMHz = c.MHz
		}
		cores = append(cores, core{g, i, c})
	}
	sort.Slice(cores, func(a, b int) bool {
		if cores[a].g != cores[b].g {
			return cores[a].g < cores[b].g
		}
		return cores[a].i < cores[b].i
	})
	out.Cores = make([]Core, len(cores))
	counted := 0
	for k, c := range cores {
		out.Cores[k] = c.c
		if c.c.MHz > 0 {
			counted++
		}
	}
	if t, ok := r["_Total"]; ok && mhz(t) > 0 {
		out.MHz = round1(mhz(t))
		out.PerfPct = round1(t.Perf)
		if valid(t.Freq, 20000) {
			out.BaseMHz = round1(t.Freq)
		}
		if !math.IsNaN(t.Load) && t.Load >= 0 {
			out.LoadPct = round1(math.Min(100, t.Load))
		}
	} else if counted > 0 {
		out.MHz = round1(sum / float64(counted))
	}
	if out.BaseMHz == 0 && valid(fallback, 20000) {
		out.BaseMHz = round1(fallback)
	}
	if out.PerfPct == 0 && out.BaseMHz > 0 && out.MHz > 0 {
		out.PerfPct = round1(100 * out.MHz / out.BaseMHz)
	}
	if out.LoadPct == 0 && nLoad > 0 {
		out.LoadPct = round1(sumLoad / float64(nLoad))
	}
	if out.MHz == 0 {
		return Sample{}, false
	}
	if out.MaxMHz < out.MHz {
		out.MaxMHz = out.MHz
	}
	return out, true
}
