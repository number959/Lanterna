package bench

import (
	"bytes"
	"compress/flate"
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

func TestCorpus(t *testing.T) {
	a, b := corpus(1<<20), corpus(1<<20)
	if !bytes.Equal(a, b) || len(a) != 1<<20 {
		t.Fatal("il testo di prova deve essere identico a ogni esecuzione")
	}
	var out bytes.Buffer
	w, _ := flate.NewWriter(&out, flate.DefaultCompression)
	_, _ = w.Write(a)
	_ = w.Close()
	// Comprimibile come un documento: né banale né casuale.
	if r := float64(len(a)) / float64(out.Len()); r < 2 || r > 8 {
		t.Fatalf("rapporto di compressione %.1f", r)
	}
}

func TestPeakSustained(t *testing.T) {
	s := []float64{90, 100, 100, 100, 98, 100, 99, 100, 70, 62, 60, 60}
	p, su := peakSustained(s, 0)
	if p != 100 || su != 60.7 {
		t.Fatalf("punta %v, prolungata %v", p, su)
	}
	if p, su := peakSustained([]float64{50}, 48); p != 48 || su != 48 {
		t.Fatalf("un solo campione: %v %v", p, su)
	}
	if p, su := peakSustained([]float64{40, 44}, 42); p != 42 || su != 44 {
		t.Fatalf("due campioni: %v %v", p, su)
	}
}

type recorder struct {
	mu   sync.Mutex
	list []Progress
}

func (r *recorder) add(p Progress) { r.mu.Lock(); r.list = append(r.list, p); r.mu.Unlock() }

func (r *recorder) phases() map[string]bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := map[string]bool{}
	for _, p := range r.list {
		m[p.Phase] = true
	}
	return m
}

func TestCPU(t *testing.T) {
	rec := &recorder{}
	opt := CPUOptions{Single: 400 * time.Millisecond, Multi: 2200 * time.Millisecond, Threads: 2, LoadSample: time.Millisecond,
		Load: func(context.Context, time.Duration) *float64 { v := 7.5; return &v },
		OnAC: func() *bool { v := true; return &v }}
	res, err := CPU(context.Background(), opt, rec.add)
	if err != nil {
		t.Fatal(err)
	}
	if res.SingleMBs <= 0 || res.MultiMBs <= 0 || res.SustainedMBs <= 0 || res.Threads != 2 || len(res.Samples) != 2 {
		t.Fatalf("risultato: %+v", res)
	}
	if res.OnAC == nil || !*res.OnAC || res.LoadBeforePct == nil || *res.LoadBeforePct != 7.5 || res.DurationMs < 2600 {
		t.Fatalf("contesto: %+v", res)
	}
	if ph := rec.phases(); !ph["load"] || !ph["single"] || !ph["multi"] {
		t.Fatalf("fasi: %v", ph)
	}
	last := 0.0
	for _, p := range rec.list {
		if p.Done < last || p.Done > 1 {
			t.Fatalf("avanzamento non monotono: %v dopo %v", p.Done, last)
		}
		last = p.Done
	}
}

func TestCPUCancel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := CPU(ctx, CPUOptions{Single: 5 * time.Second, Multi: 5 * time.Second, Threads: 1}, nil)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 2*time.Second {
		t.Fatalf("interruzione: %v dopo %v", err, time.Since(start))
	}
}

func TestFileSize(t *testing.T) {
	opt := DefaultDisk
	if n, note, err := fileSize(10<<30, opt); err != nil || n != 1<<30 || note != "" {
		t.Fatalf("spazio abbondante: %d %q %v", n, note, err)
	}
	// 2,5 GiB liberi: restano 512 MiB dopo la riserva di 2 GiB.
	if n, note, err := fileSize(5<<29, opt); err != nil || n != 512<<20 || note == "" {
		t.Fatalf("spazio ridotto: %d %q %v", n, note, err)
	}
	if n, _, err := fileSize(2<<30+100<<20, opt); err != nil || n != 64<<20 {
		t.Fatalf("arrotondamento a 64 MiB: %d %v", n, err)
	}
	if _, _, err := fileSize(2<<30+10<<20, opt); !errors.Is(err, ErrSpace) {
		t.Fatalf("spazio insufficiente accettato: %v", err)
	}
}

func TestDisk(t *testing.T) {
	dir := t.TempDir()
	rec := &recorder{}
	opt := DiskOptions{Drive: "C:", Dir: dir, FileMB: 8, PrepTime: 2 * time.Second, Measure: 250 * time.Millisecond}
	start := time.Now()
	res, err := Disk(context.Background(), opt, rec.add)
	if err != nil {
		t.Fatal(err)
	}
	if res.Drive != "C:" || res.FileMB != 8 || res.SeqWriteMBs <= 0 || res.SeqReadMBs <= 0 || res.RndReadIOPS <= 0 || res.RndWriteIOPS <= 0 || res.RndReadMBs <= 0 {
		t.Fatalf("risultato Q1: %+v", res)
	}
	if res.SeqQ8ReadMBs <= 0 || res.SeqQ8WriteMBs <= 0 || res.RndQ32ReadMBs <= 0 || res.RndQ32ReadIOPS <= 0 || res.RndQ32WriteMBs <= 0 || res.RndQ32WriteIOPS <= 0 {
		t.Fatalf("risultato Q8/Q32: %+v", res)
	}
	// Otto misure da 250 ms: il tempo complessivo resta vicino alla somma.
	if el := time.Since(start); el < 2*time.Second || el > 6*time.Second {
		t.Fatalf("durata %v", el)
	}
	ph := rec.phases()
	for _, want := range []string{"prep", "seq-q8-read", "rnd-q32-read", "seq-q8-write", "rnd-q32-write", "done"} {
		if !ph[want] {
			t.Fatalf("manca la fase %s: %v", want, ph)
		}
	}
	last := 0.0
	for _, p := range rec.list {
		if p.Done < last || p.Done > 1 {
			t.Fatalf("avanzamento non monotono: %v dopo %v", p.Done, last)
		}
		last = p.Done
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Fatalf("file di prova non cancellato: %v", left)
	}
}

func TestDiskCancelAndSpace(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Disk(ctx, DiskOptions{Dir: dir, FileMB: 8, PrepTime: time.Second, Measure: time.Second}, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("interruzione: %v", err)
	}
	// Interruzione a test avviato (dall'interfaccia, pulsante "Interrompi"),
	// anche durante una misura con 32 richieste in coda.
	for _, at := range []string{"seq-read", "rnd-q32-read", "rnd-q32-write"} {
		ctx, cancel = context.WithCancel(context.Background())
		start := time.Now()
		_, err := Disk(ctx, DiskOptions{Dir: dir, FileMB: 8, PrepTime: time.Second, Measure: 400 * time.Millisecond}, func(p Progress) {
			if p.Phase == at {
				cancel()
			}
		})
		cancel()
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("interruzione in %s: %v", at, err)
		}
		if el := time.Since(start); el > 5*time.Second {
			t.Fatalf("interruzione in %s lenta: %v", at, el)
		}
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Fatalf("file di prova non cancellato dopo l'interruzione: %v", left)
	}
	// Riserva impossibile da rispettare: nessun file creato.
	if _, err := Disk(context.Background(), DiskOptions{Dir: dir, FileMB: 8, Reserve: 1 << 62}, nil); !errors.Is(err, ErrSpace) {
		t.Fatalf("spazio: %v", err)
	}
}

func TestNormalizeDrive(t *testing.T) {
	for in, want := range map[string]string{"c": "C:", "C:": "C:", `d:\`: "D:", " e:/ ": "E:"} {
		if got, err := NormalizeDrive(in); err != nil || got != want {
			t.Errorf("NormalizeDrive(%q)=%q %v", in, got, err)
		}
	}
	for _, in := range []string{"", "CD", "1:", `\\server\share`, "C:\\Windows"} {
		if _, err := NormalizeDrive(in); err == nil {
			t.Errorf("NormalizeDrive(%q) accettato", in)
		}
	}
}

func TestBuffers(t *testing.T) {
	for i := 0; i < 20; i++ {
		b := alignedBuffer(block)
		if uintptr(unsafe.Pointer(&b[0]))%align != 0 || len(b) != block || cap(b) != block {
			t.Fatal("buffer non allineato")
		}
	}
	b := make([]byte, 3*small)
	fillRandom(b)
	stamp(b, 1)
	if bytes.Equal(b[:small], b[small:2*small]) {
		t.Fatal("settori identici")
	}
	c := append([]byte(nil), b...)
	stamp(b, 2)
	if bytes.Equal(b, c) {
		t.Fatal("il contatore non cambia i dati")
	}
}

// fakeFile conta le operazioni in corso contemporaneamente e gli offset usati.
type fakeFile struct {
	mu       sync.Mutex
	inFlight int
	peak     int
	offsets  []int64
	syncs    int
}

type fakeWorker struct{ f *fakeFile }

func (f *fakeFile) worker() (rw, error) { return fakeWorker{f}, nil }
func (f *fakeFile) Sync() error         { f.mu.Lock(); f.syncs++; f.mu.Unlock(); return nil }
func (f *fakeFile) Close() error        { return nil }

func (w fakeWorker) op(p []byte, off int64) (int, error) {
	f := w.f
	f.mu.Lock()
	f.inFlight++
	f.peak = max(f.peak, f.inFlight)
	f.offsets = append(f.offsets, off)
	f.mu.Unlock()
	time.Sleep(2 * time.Millisecond) // una "richiesta" che resta in coda
	f.mu.Lock()
	f.inFlight--
	f.mu.Unlock()
	return len(p), nil
}

func (w fakeWorker) ReadAt(p []byte, off int64) (int, error)  { return w.op(p, off) }
func (w fakeWorker) WriteAt(p []byte, off int64) (int, error) { return w.op(p, off) }
func (fakeWorker) Close() error                               { return nil }

func TestRunJobQueueDepth(t *testing.T) {
	var stop atomic.Bool
	for _, j := range profile {
		f := &fakeFile{}
		limit := int64(4 << 30) // abbastanza grande da non ricominciare durante la misura
		bytes, ops, el, err := runJob(f, j, limit, 150*time.Millisecond, &stop, func(int64, time.Duration) {})
		if err != nil {
			t.Fatal(err)
		}
		// Tutte le richieste previste restano in coda insieme.
		if f.peak != j.depth {
			t.Errorf("%s: %d richieste contemporanee, attese %d", j.phase, f.peak, j.depth)
		}
		if ops == 0 || bytes != ops*int64(j.block) || el < 150*time.Millisecond {
			t.Errorf("%s: %d byte, %d operazioni in %v", j.phase, bytes, ops, el)
		}
		if (f.syncs > 0) != j.write {
			t.Errorf("%s: svuotamento della cache %d volte", j.phase, f.syncs)
		}
		seen := map[int64]bool{}
		for _, off := range f.offsets {
			if off%int64(j.block) != 0 || off < 0 || off+int64(j.block) > limit {
				t.Fatalf("%s: offset %d fuori posto", j.phase, off)
			}
			seen[off] = true
		}
		// Le letture sequenziali non ripassano sugli stessi blocchi prima della fine del file.
		if !j.random && len(seen) != len(f.offsets) {
			t.Errorf("%s: blocchi ripetuti (%d distinti su %d)", j.phase, len(seen), len(f.offsets))
		}
	}
}

func TestRunJobWrapsAndStops(t *testing.T) {
	var stop atomic.Bool
	f := &fakeFile{}
	// Due blocchi soltanto: la lettura sequenziale ricomincia dall'inizio.
	_, ops, _, err := runJob(f, job{"seq-read", false, false, block, 1}, 2*block, 30*time.Millisecond, &stop, func(int64, time.Duration) {})
	if err != nil || ops < 3 || f.offsets[2] != 0 {
		t.Fatalf("ripartenza: %d operazioni, %v, %v", ops, f.offsets, err)
	}
	if _, _, _, err := runJob(f, job{"rnd-read", false, true, small, 1}, 100, time.Millisecond, &stop, func(int64, time.Duration) {}); err == nil {
		t.Fatal("file più piccolo di un blocco accettato")
	}
	stop.Store(true)
	start := time.Now()
	if _, _, _, err := runJob(&fakeFile{}, profile[2], 64<<20, 5*time.Second, &stop, func(int64, time.Duration) {}); err != nil || time.Since(start) > time.Second {
		t.Fatalf("arresto: %v dopo %v", err, time.Since(start))
	}
}
