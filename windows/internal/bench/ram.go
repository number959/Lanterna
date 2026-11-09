package bench

import (
	"context"
	"errors"
	"fmt"
	"math/bits"
	"math/rand/v2"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"lanterna/internal/scan"
)

// Test della RAM con Windows acceso, come HCI MemTest e MemTest64: il
// programma riserva la memoria libera (lasciandone una parte a Windows), la
// tiene bloccata in RAM e ci scrive e rilegge sequenze di bit con più
// algoritmi, contando le differenze. La memoria usata da Windows e dai
// programmi aperti non si può provare così: per quella serve un test da
// chiavetta (Memtest86+). Gli algoritmi seguono i test classici descritti
// nella documentazione di Memtest86+ e MemTest86 (indirizzo nella cella,
// inversioni in movimento con schemi fissi, casuali e "walking ones",
// sequenza casuale, modulo 20, spostamento di blocchi, decadimento dei bit):
// l'implementazione è di Polaris.

// RAMOptions descrive un test della RAM.
type RAMOptions struct {
	// Preset: quick | standard | long. Duration è la durata prevista: il test
	// si ferma allo scadere, anche a metà di un passaggio.
	Preset   string
	Duration time.Duration
	// MaxMB limita la memoria provata (0 = la memoria libera meno la riserva).
	MaxMB   int
	Threads int // 0 = tutti i processori logici
	// FadeWait è l'attesa del test di decadimento dei bit (solo "long").
	FadeWait time.Duration
	// OnAC dice se il PC è collegato all'alimentatore (nil = non disponibile).
	OnAC func() *bool

	inject func(w []uint64, test string, pass int) // solo per le prove
}

// RAMPresets sono le durate proposte all'utente.
var RAMPresets = map[string]time.Duration{"quick": 3 * time.Minute, "standard": 10 * time.Minute, "long": 30 * time.Minute}

// RAMOptionsFor restituisce le opzioni di una durata proposta.
func RAMOptionsFor(preset string) (RAMOptions, error) {
	d, ok := RAMPresets[preset]
	if !ok {
		return RAMOptions{}, fmt.Errorf("durata del test della RAM non valida: %q (quick, standard o long: 3, 10 o 30 minuti)", preset)
	}
	o := RAMOptions{Preset: preset, Duration: d}
	if preset == "long" {
		o.FadeWait = 90 * time.Second
	}
	return o, nil
}

// QuickRAM serve alle verifiche automatiche: 15 secondi su 256 MB.
var QuickRAM = RAMOptions{Preset: "quick", Duration: 15 * time.Second, MaxMB: 256}

// ErrRAMLow: la memoria libera non basta per un test utile.
var ErrRAMLow = errors.New("memoria libera insufficiente per il test: chiudi qualche programma e riprova")

// ramBlock è la memoria riservata per il test.
type ramBlock struct {
	words            []uint64
	lockedMB         int
	totalMB, availMB int
	free             func()
	// pressure dice se Windows è rimasto con poca memoria libera.
	pressure func() bool
}

// Nomi delle prove (scan.RAMTestStat.Name).
var ramTests = []string{"own-address", "mi-01", "mi-random", "random-seq", "mi-walk8", "modulo20", "block-move"}

// stopReason sono i motivi di arresto in ordine di priorità.
const (
	stopCompleted = "completed"
	stopTime      = "time"
	stopCancelled = "cancelled"
	stopLowMemory = "low-memory"
)

// ramRun è lo stato condiviso tra i thread di un test.
type ramRun struct {
	w        []uint64
	threads  int
	deadline time.Time
	stopped  atomic.Bool
	reason   atomic.Value // string
	touched  atomic.Int64 // byte scritti o letti
	mu       sync.Mutex
	errors   int
	badBits  uint64
	samples  []scan.RAMError
	perTest  map[string]*scan.RAMTestStat
	test     string
	pass     int
}

func (r *ramRun) stop(reason string) {
	if r.stopped.CompareAndSwap(false, true) {
		r.reason.Store(reason)
	}
}

// mismatch registra una differenza (raro: fuori dal ciclo veloce).
func (r *ramRun) mismatch(i int, exp, got uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errors++
	r.perTest[r.test].Errors++
	r.badBits |= exp ^ got
	if len(r.samples) < 20 {
		r.samples = append(r.samples, scan.RAMError{Test: r.test, Pass: r.pass, OffsetMB: round1(float64(i) * 8 / (1 << 20)), Expected: fmt.Sprintf("%016x", exp), Actual: fmt.Sprintf("%016x", got)})
	}
}

// parallel esegue f su segmenti contigui del blocco, uno per thread; f
// riceve l'indice iniziale e il segmento. Ogni thread controlla l'arresto
// ogni 1 MB circa.
func (r *ramRun) parallel(f func(base int, seg []uint64)) {
	n := len(r.w)
	per := (n + r.threads - 1) / r.threads
	var wg sync.WaitGroup
	for t := 0; t < r.threads; t++ {
		lo, hi := t*per, min((t+1)*per, n)
		if lo >= hi {
			break
		}
		wg.Add(1)
		go func(lo, hi int) {
			defer wg.Done()
			const step = 1 << 17 // 1 MiB di parole da 8 byte
			for s := lo; s < hi; s += step {
				if r.stopped.Load() {
					return
				}
				e := min(s+step, hi)
				f(s, r.w[s:e])
				r.touched.Add(int64(e-s) * 8)
			}
		}(lo, hi)
	}
	wg.Wait()
}

// mix è un rimescolamento a 64 bit (splitmix64): valori diversi per ogni
// cella, così nessuna pagina è uguale a un'altra.
func mix(x uint64) uint64 {
	x += 0x9e3779b97f4a7c15
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	return x ^ (x >> 31)
}

func (r *ramRun) fill(v uint64) {
	r.parallel(func(_ int, seg []uint64) {
		for i := range seg {
			seg[i] = v
		}
	})
}

// movingInversions: riempie con p; in avanti verifica p e scrive ^p; poi
// all'indietro verifica ^p e riscrive p.
func (r *ramRun) movingInversions(p uint64, hook func()) {
	r.fill(p)
	if hook != nil {
		hook()
	}
	r.parallel(func(base int, seg []uint64) {
		for i := range seg {
			if seg[i] != p {
				r.mismatch(base+i, p, seg[i])
			}
			seg[i] = ^p
		}
	})
	r.parallel(func(base int, seg []uint64) {
		for i := len(seg) - 1; i >= 0; i-- {
			if seg[i] != ^p {
				r.mismatch(base+i, ^p, seg[i])
			}
			seg[i] = p
		}
	})
}

func (r *ramRun) verifyFn(exp func(i int) uint64) {
	r.parallel(func(base int, seg []uint64) {
		for i := range seg {
			if e := exp(base + i); seg[i] != e {
				r.mismatch(base+i, e, seg[i])
			}
		}
	})
}

// runTest esegue una prova del passaggio indicato.
func (r *ramRun) runTest(name string, pass int, seed uint64, inject func([]uint64, string, int)) {
	hook := func() {
		if inject != nil && !r.stopped.Load() {
			inject(r.w, name, pass)
		}
	}
	switch name {
	case "own-address":
		r.parallel(func(base int, seg []uint64) {
			for i := range seg {
				seg[i] = mix(uint64(base+i) ^ seed)
			}
		})
		hook()
		r.verifyFn(func(i int) uint64 { return mix(uint64(i) ^ seed) })
	case "mi-01":
		r.movingInversions(0, hook)
		r.movingInversions(^uint64(0), nil)
	case "mi-random":
		r.movingInversions(mix(seed), hook)
	case "random-seq":
		r.parallel(func(base int, seg []uint64) {
			x := mix(seed ^ uint64(base))
			for i := range seg {
				x = mix(x)
				seg[i] = x
			}
		})
		hook()
		r.parallel(func(base int, seg []uint64) {
			x := mix(seed ^ uint64(base))
			for i := range seg {
				x = mix(x)
				if seg[i] != x {
					r.mismatch(base+i, x, seg[i])
				}
			}
		})
	case "mi-walk8":
		// Un bit acceso in ogni byte, in una posizione diversa a ogni passaggio.
		r.movingInversions(uint64(0x0101010101010101)<<(pass%8), hook)
	case "modulo20":
		// Uno schema ogni 20 celle e il suo opposto nelle altre: 4 posizioni
		// diverse a ogni passaggio.
		p := mix(seed ^ 0x20)
		for k := 0; k < 4 && !r.stopped.Load(); k++ {
			off := (pass*4 + k) % 20
			r.parallel(func(base int, seg []uint64) {
				for i := range seg {
					if (base+i)%20 == off {
						seg[i] = p
					} else {
						seg[i] = ^p
					}
				}
			})
			hook()
			r.parallel(func(base int, seg []uint64) {
				for i := range seg {
					if (base+i)%20 == off && seg[i] != p {
						r.mismatch(base+i, p, seg[i])
					}
				}
			})
		}
	case "block-move":
		half := len(r.w) / 2
		r.parallel(func(base int, seg []uint64) {
			for i := range seg {
				seg[i] = mix(uint64((base+i)%max(half, 1)) ^ seed)
			}
		})
		if r.stopped.Load() || half == 0 {
			return
		}
		// Copia la prima metà sulla seconda in blocchi, poi verifica le due metà.
		const blk = 1 << 18
		for s := 0; s < half && !r.stopped.Load(); s += blk {
			e := min(s+blk, half)
			copy(r.w[half+s:half+e], r.w[s:e])
			r.touched.Add(int64(e-s) * 16)
		}
		hook()
		r.verifyFn(func(i int) uint64 { return mix(uint64(i%half) ^ seed) })
	}
}

// RAM esegue il test della memoria. Restituisce il risultato anche se il
// test viene interrotto: vale per la parte provata.
func RAM(ctx context.Context, opt RAMOptions, report Report) (*scan.RAMTest, error) {
	return runRAM(ctx, opt, report, allocRAM)
}

func runRAM(ctx context.Context, opt RAMOptions, report Report, alloc func(maxMB int) (*ramBlock, error)) (*scan.RAMTest, error) {
	if report == nil {
		report = func(Progress) {}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if opt.Duration <= 0 {
		return nil, errors.New("durata del test non valida")
	}
	threads := opt.Threads
	if threads <= 0 {
		threads = runtime.NumCPU()
	}
	res := &scan.RAMTest{StartedAt: time.Now().UTC().Format(time.RFC3339), Preset: opt.Preset, PlannedSec: int(opt.Duration.Seconds()), Threads: threads}
	if opt.OnAC != nil {
		res.OnAC = opt.OnAC()
	}
	blk, err := alloc(opt.MaxMB)
	if err != nil {
		return nil, err
	}
	defer blk.free()
	res.TotalMB, res.AvailableMB, res.LockedMB = blk.totalMB, blk.availMB, blk.lockedMB
	res.TestedMB = len(blk.words) * 8 >> 20

	start := time.Now()
	run := &ramRun{w: blk.words, threads: threads, deadline: start.Add(opt.Duration), perTest: map[string]*scan.RAMTestStat{}}
	for _, t := range append(ramTests, "bit-fade") {
		run.perTest[t] = &scan.RAMTestStat{Name: t}
	}
	defer context.AfterFunc(ctx, func() { run.stop(stopCancelled) })()

	// Sorveglianza: tempo, memoria libera di Windows, avanzamento.
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		tick := time.NewTicker(200 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case now := <-tick.C:
				if now.After(run.deadline) {
					run.stop(stopTime)
				}
				if blk.pressure != nil && blk.pressure() {
					run.stop(stopLowMemory)
				}
				el := now.Sub(start)
				run.mu.Lock()
				test, pass, errs := run.test, run.pass, run.errors
				run.mu.Unlock()
				report(Progress{Phase: test, Done: frac(el, opt.Duration), Value: round1(float64(run.touched.Load()) / el.Seconds() / mb), Errors: errs, Pass: pass + 1})
			}
		}
	}()

	seed := rand.Uint64()
	for pass := 0; !run.stopped.Load(); pass++ {
		for _, t := range ramTests {
			if run.stopped.Load() {
				break
			}
			run.mu.Lock()
			run.test, run.pass = t, pass
			run.mu.Unlock()
			run.runTest(t, pass, mix(seed+uint64(pass)*0x51), opt.inject)
			if !run.stopped.Load() {
				run.perTest[t].Runs++
			}
		}
		if run.stopped.Load() {
			break
		}
		res.Passes++
		// Nel test lungo, alla fine del primo passaggio, il decadimento dei bit:
		// la memoria resta ferma con tutti zeri e poi tutti uni.
		if opt.FadeWait > 0 && pass == 0 {
			run.mu.Lock()
			run.test = "bit-fade"
			run.mu.Unlock()
			for _, p := range []uint64{0, ^uint64(0)} {
				run.fill(p)
				select {
				case <-time.After(opt.FadeWait):
				case <-ctx.Done():
				}
				if run.stopped.Load() || ctx.Err() != nil {
					break
				}
				run.verifyFn(func(int) uint64 { return p })
			}
			if !run.stopped.Load() {
				run.perTest["bit-fade"].Runs++
			}
		}
	}
	close(done)
	wg.Wait()

	reason, _ := run.reason.Load().(string)
	if reason == "" {
		reason = stopCompleted
	}
	res.Stop = reason
	res.DurationMs = time.Since(start).Milliseconds()
	if el := time.Since(start).Seconds(); el > 0 {
		res.MBs = round1(float64(run.touched.Load()) / el / mb)
	}
	res.Errors = run.errors
	res.ErrorSamples = run.samples
	if run.badBits != 0 {
		res.BadBits = fmt.Sprintf("%016x (%d bit)", run.badBits, bits.OnesCount64(run.badBits))
	}
	for _, t := range append(ramTests, "bit-fade") {
		if s := run.perTest[t]; s.Runs > 0 || s.Errors > 0 {
			res.Tests = append(res.Tests, *s)
		}
	}
	report(Progress{Phase: "done", Done: 1, Errors: res.Errors, Pass: res.Passes})
	if reason == stopCancelled && res.Passes == 0 && res.Errors == 0 {
		return res, context.Canceled
	}
	return res, nil
}
