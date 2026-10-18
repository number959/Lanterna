// Package bench misura, solo su richiesta esplicita, la velocità del
// processore e delle unità di archiviazione.
//
// Processore: comprime con compress/flate un testo sintetico, sempre uguale,
// prima con un solo thread e poi con tutti, campionando ogni secondo per
// vedere se le prestazioni calano col passare del tempo (calore, limiti di
// potenza). Il risultato è in MB/s di dati compressi: confrontabile tra
// esecuzioni di questo programma, non con i punteggi di altri benchmark.
//
// Unità: scrive un file temporaneo senza passare dalla cache di Windows
// (FILE_FLAG_NO_BUFFERING) e misura letture e scritture con il profilo di
// CrystalDiskMark: in sequenza a blocchi da 1 MiB con 8 richieste in coda e
// con una sola, in punti casuali a blocchi da 4 KiB con 32 richieste e con
// una sola. Il file viene creato con FILE_FLAG_DELETE_ON_CLOSE: Windows lo
// cancella alla chiusura, anche se il programma si interrompe. Ogni fase ha
// una durata massima, così una chiavetta lenta non tiene occupato il
// computer per minuti.
package bench

import (
	"compress/flate"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"lanterna/internal/scan"
)

// Progress descrive l'avanzamento di un test.
type Progress struct {
	Phase string  `json:"phase"`
	Done  float64 `json:"done"` // 0..1
	// Value è la velocità misurata finora nella fase in corso (MB/s).
	Value float64 `json:"value,omitempty"`
	// Samples sono le velocità secondo per secondo della fase multi-thread.
	Samples []float64 `json:"samples,omitempty"`
}

// Report riceve l'avanzamento; può essere nil.
type Report func(Progress)

const mb = 1e6 // MB/s decimali, come negli altri strumenti di misura dei dischi

// ---------- Processore ----------

type CPUOptions struct {
	Single  time.Duration // durata della fase a un thread
	Multi   time.Duration // durata della fase con tutti i thread
	Threads int           // 0 = tutti i processori logici
	// LoadSample misura il carico prima del test (0 = non misurare).
	LoadSample time.Duration
	// Load e OnAC leggono carico e alimentazione (nil = non disponibili).
	Load func(ctx context.Context, d time.Duration) *float64
	OnAC func() *bool
}

// DefaultCPU dura circa 25 secondi: abbastanza perché un portatile arrivi ai
// limiti di potenza prolungati, che molti processori applicano dopo 10-30 s.
var DefaultCPU = CPUOptions{Single: 3 * time.Second, Multi: 20 * time.Second, LoadSample: time.Second}

// QuickCPU serve alle verifiche automatiche.
var QuickCPU = CPUOptions{Single: time.Second, Multi: 3 * time.Second}

// chunk è la quantità compressa per ogni giro: abbastanza piccola da
// aggiornare il contatore molte volte al secondo.
const chunk = 256 << 10

// corpus genera un testo sintetico deterministico (parole, numeri, a capo),
// comprimibile circa come un documento: gli stessi byte a ogni esecuzione.
func corpus(n int) []byte {
	words := strings.Fields("rete router pacchetto indirizzo segnale canale banda latenza perdita server nome dominio porta cavo scheda " +
		"antenna potenza disco memoria processore sistema aggiornamento utente stampante telefono ufficio clinica reparto " +
		"ambulatorio paziente referto immagine archivio copia sicurezza firewall accesso password rapporto misura valore " +
		"tempo secondo minuto giorno settimana mese anno alto basso medio buono scarso ottimo critico avviso errore stato")
	b := make([]byte, 0, n+32)
	x := uint32(2463534242)
	for len(b) < n {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		b = append(b, words[x%uint32(len(words))]...)
		switch {
		case x&255 < 6:
			b = fmt.Appendf(b, " %d", x%100000)
		case x&15 == 0:
			b = append(b, ".\n"...)
			continue
		}
		b = append(b, ' ')
	}
	return b[:n]
}

// compressLoop comprime a ciclo finché stop non diventa vero, sommando i
// byte elaborati.
func compressLoop(data []byte, count *atomic.Int64, stop *atomic.Bool) {
	w, _ := flate.NewWriter(io.Discard, flate.DefaultCompression)
	for off := 0; !stop.Load(); off += chunk {
		if off+chunk > len(data) {
			off = 0
		}
		w.Reset(io.Discard)
		_, _ = w.Write(data[off : off+chunk])
		_ = w.Close()
		count.Add(chunk)
	}
}

// CPU esegue il test del processore.
func CPU(ctx context.Context, opt CPUOptions, report Report) (*scan.CPUBench, error) {
	if report == nil {
		report = func(Progress) {}
	}
	threads := opt.Threads
	if threads <= 0 {
		threads = runtime.NumCPU()
	}
	res := &scan.CPUBench{StartedAt: time.Now().UTC().Format(time.RFC3339), Threads: threads}
	start := time.Now()
	if opt.OnAC != nil {
		res.OnAC = opt.OnAC()
	}
	if opt.LoadSample > 0 && opt.Load != nil {
		report(Progress{Phase: "load"})
		res.LoadBeforePct = opt.Load(ctx, opt.LoadSample)
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	data := corpus(8 << 20)
	total := opt.Single + opt.Multi

	// Un thread: il primo mezzo secondo serve a scaldare (allocazioni, cache)
	// e non entra nella media.
	single, err := runCompress(ctx, data, 1, opt.Single, func(el time.Duration, mbs float64, _ []float64) {
		report(Progress{Phase: "single", Done: frac(el, total), Value: mbs})
	})
	if err != nil {
		return nil, err
	}
	res.SingleMBs = round1(single.avg)

	multi, err := runCompress(ctx, data, threads, opt.Multi, func(el time.Duration, mbs float64, samples []float64) {
		report(Progress{Phase: "multi", Done: frac(opt.Single+el, total), Value: mbs, Samples: samples})
	})
	if err != nil {
		return nil, err
	}
	res.Samples = multi.samples
	res.MultiMBs, res.SustainedMBs = peakSustained(multi.samples, multi.avg)
	res.DurationMs = time.Since(start).Milliseconds()
	return res, nil
}

type compressResult struct {
	avg     float64   // MB/s medi dopo il riscaldamento
	samples []float64 // MB/s secondo per secondo
}

// runCompress fa girare n thread per la durata indicata e campiona ogni
// secondo. tick riceve tempo trascorso, velocità media e campioni.
func runCompress(ctx context.Context, data []byte, n int, d time.Duration, tick func(time.Duration, float64, []float64)) (compressResult, error) {
	var count atomic.Int64
	var stop atomic.Bool
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			compressLoop(data, &count, &stop)
		}()
	}
	defer func() { stop.Store(true); wg.Wait() }()

	warm := min(500*time.Millisecond, d/4)
	start := time.Now()
	var warmBytes int64
	warmDone := false
	lastBytes, lastT := int64(0), start
	nextSample := start.Add(time.Second)
	var samples []float64
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return compressResult{}, ctx.Err()
		case now := <-t.C:
			el := now.Sub(start)
			c := count.Load()
			if !warmDone && el >= warm {
				warmBytes, warmDone = c, true
			}
			if !now.Before(nextSample) {
				samples = append(samples, round1(float64(c-lastBytes)/now.Sub(lastT).Seconds()/mb))
				lastBytes, lastT = c, now
				nextSample = nextSample.Add(time.Second)
			}
			avg := 0.0
			if warmDone && el > warm {
				avg = float64(c-warmBytes) / (el - warm).Seconds() / mb
			}
			if el >= d {
				if !warmDone || avg == 0 {
					avg = float64(c) / el.Seconds() / mb
				}
				tick(el, round1(avg), append([]float64(nil), samples...))
				return compressResult{avg: avg, samples: samples}, nil
			}
			tick(el, round1(avg), append([]float64(nil), samples...))
		}
	}
}

// peakSustained ricava dai campioni la velocità di punta (la migliore media
// su tre secondi nella prima metà del test) e quella prolungata (la media
// dell'ultimo quarto). Con meno di due campioni entrambe valgono la media.
func peakSustained(samples []float64, avg float64) (peak, sustained float64) {
	n := len(samples)
	if n < 2 {
		return round1(avg), round1(avg)
	}
	w := min(3, n)
	half := max(w, n/2)
	for i := 0; i+w <= half; i++ {
		peak = max(peak, mean(samples[i:i+w]))
	}
	sustained = mean(samples[n-max(1, n/4):])
	return round1(peak), round1(sustained)
}

func mean(v []float64) float64 {
	s := 0.0
	for _, x := range v {
		s += x
	}
	return s / float64(len(v))
}

func frac(el, total time.Duration) float64 {
	if total <= 0 {
		return 0
	}
	return math.Min(1, float64(el)/float64(total))
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }

// ---------- Unità di archiviazione ----------

type DiskOptions struct {
	Drive string // lettera dell'unità, per il risultato ("C:")
	Dir   string // cartella del file temporaneo
	// FileMB è la dimensione massima del file; PrepTime il tempo massimo per
	// scriverlo la prima volta (le unità lente lavorano su un file più piccolo).
	FileMB   int
	PrepTime time.Duration
	// Measure è la durata di ciascuna delle otto misure.
	Measure time.Duration
	// Reserve è lo spazio che deve restare libero dopo aver creato il file.
	Reserve uint64
}

// DefaultDisk: file da 1 GiB e misure da 4 secondi, come una versione breve
// del profilo predefinito di CrystalDiskMark; al massimo circa 50 secondi in
// tutto, almeno 2 GiB lasciati liberi.
var DefaultDisk = DiskOptions{FileMB: 1024, PrepTime: 15 * time.Second, Measure: 4 * time.Second, Reserve: 2 << 30}

// QuickDisk serve alle verifiche automatiche.
var QuickDisk = DiskOptions{FileMB: 256, PrepTime: 3 * time.Second, Measure: time.Second, Reserve: 1 << 30}

const (
	minFileMB = 64
	block     = 1 << 20
	small     = 4096
	align     = 4096 // allineamento richiesto da FILE_FLAG_NO_BUFFERING
)

// ErrSpace segnala che lo spazio libero non basta per il test.
var ErrSpace = errors.New("spazio libero insufficiente")

// file è il file temporaneo del test; Close lo cancella.
type file interface {
	// worker restituisce un esecutore di letture e scritture posizionate da
	// usare in una sola goroutine: più esecutori lavorano in parallelo sullo
	// stesso file, ed è così che si ottengono più richieste in coda.
	worker() (rw, error)
	Sync() error
	Close() error
}

type rw interface {
	ReadAt(p []byte, off int64) (int, error)
	WriteAt(p []byte, off int64) (int, error)
	Close() error
}

// alignedBuffer restituisce un buffer allineato a 4 KiB: la memoria di Go non
// si sposta, quindi l'allineamento resta valido per tutta la vita del buffer.
func alignedBuffer(size int) []byte {
	b := make([]byte, size+align)
	off := int(uintptr(unsafe.Pointer(&b[0])) & (align - 1))
	if off != 0 {
		off = align - off
	}
	return b[off : off+size : off+size]
}

// fileSize sceglie la dimensione del file in base allo spazio libero.
func fileSize(free uint64, opt DiskOptions) (int64, string, error) {
	want := uint64(opt.FileMB) << 20
	if free >= want+opt.Reserve {
		return int64(want), "", nil
	}
	if free < opt.Reserve+minFileMB<<20 {
		need := float64(opt.Reserve+minFileMB<<20) / 1e9
		return 0, "", fmt.Errorf("%w: servono almeno %.1f GB liberi", ErrSpace, need)
	}
	size := (free - opt.Reserve) &^ (minFileMB<<20 - 1)
	return int64(size), fmt.Sprintf("File di prova ridotto a %d MB per lo spazio libero.", size>>20), nil
}

// job è una delle otto misure del profilo.
type job struct {
	phase  string
	write  bool
	random bool
	block  int
	depth  int
}

// profile ricalca il profilo predefinito di CrystalDiskMark: prima le
// letture, poi le scritture. Le misure con una sola richiesta in coda sono
// quelle che contano di più per la reattività di Windows.
var profile = []job{
	{"seq-q8-read", false, false, block, 8},
	{"seq-read", false, false, block, 1},
	{"rnd-q32-read", false, true, small, 32},
	{"rnd-read", false, true, small, 1},
	{"seq-q8-write", true, false, block, 8},
	{"seq-write", true, false, block, 1},
	{"rnd-q32-write", true, true, small, 32},
	{"rnd-write", true, true, small, 1},
}

// Disk esegue il test dell'unità: scrive il file di prova, poi misura per
// ogni voce del profilo i dati letti o scritti in Measure secondi.
func Disk(ctx context.Context, opt DiskOptions, report Report) (*scan.DiskBench, error) {
	if report == nil {
		report = func(Progress) {}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	free, err := freeBytes(opt.Dir)
	if err != nil {
		return nil, fmt.Errorf("spazio libero non leggibile: %v", err)
	}
	size, note, err := fileSize(free, opt)
	if err != nil {
		return nil, err
	}
	f, err := createFile(opt.Dir)
	if err != nil {
		return nil, fmt.Errorf("impossibile creare il file di prova in %s: %v", opt.Dir, err)
	}
	defer f.Close()

	var stop atomic.Bool
	defer context.AfterFunc(ctx, func() { stop.Store(true) })()
	res := &scan.DiskBench{StartedAt: time.Now().UTC().Format(time.RFC3339), Drive: opt.Drive}
	start := time.Now()
	total := opt.PrepTime + time.Duration(len(profile))*opt.Measure
	var mu sync.Mutex
	var lastReport time.Time
	progress := func(phase string, base, el, span time.Duration, mbs float64) {
		mu.Lock()
		defer mu.Unlock()
		if now := time.Now(); now.Sub(lastReport) >= 200*time.Millisecond {
			lastReport = now
			report(Progress{Phase: phase, Done: frac(base+min(el, span), total), Value: round1(mbs)})
		}
	}

	// Preparazione: il file si scrive una volta in sequenza. Le scritture che
	// allungano un file Windows le esegue comunque una alla volta, per questo
	// le misure di scrittura avvengono dopo, sovrascrivendo il file.
	w, err := f.worker()
	if err != nil {
		return nil, err
	}
	buf := alignedBuffer(block)
	fillRandom(buf)
	var written int64
	t0 := time.Now()
	for seq := uint64(0); written < size && time.Since(t0) < opt.PrepTime; seq++ {
		if stop.Load() {
			w.Close()
			return nil, ctx.Err()
		}
		stamp(buf, seq)
		if _, err := w.WriteAt(buf, written); err != nil {
			w.Close()
			return nil, fmt.Errorf("scrittura: %v", err)
		}
		written += block
		el := time.Since(t0)
		progress("prep", 0, el, opt.PrepTime, float64(written)/el.Seconds()/mb)
	}
	w.Close()
	if err := f.Sync(); err != nil {
		return nil, fmt.Errorf("scrittura: %v", err)
	}
	res.FileMB = int(written >> 20)
	if written < size && note == "" {
		note = fmt.Sprintf("Unità lenta: in %d secondi il file di prova ha raggiunto %d MB.", int(opt.PrepTime.Seconds()), written>>20)
	}

	for i, j := range profile {
		base := opt.PrepTime + time.Duration(i)*opt.Measure
		bytes, ops, el, err := runJob(f, j, written, opt.Measure, &stop, func(done int64, el time.Duration) {
			progress(j.phase, base, el, opt.Measure, float64(done)/el.Seconds()/mb)
		})
		if err == nil && stop.Load() {
			err = ctx.Err()
		}
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, err
			}
			return nil, fmt.Errorf("%s: %w", phaseName[j.phase], err)
		}
		secs := el.Seconds()
		mbs, iops := round1(float64(bytes)/secs/mb), math.Round(float64(ops)/secs)
		switch j.phase {
		case "seq-q8-read":
			res.SeqQ8ReadMBs = mbs
		case "seq-read":
			res.SeqReadMBs = mbs
		case "rnd-q32-read":
			res.RndQ32ReadMBs, res.RndQ32ReadIOPS = mbs, iops
		case "rnd-read":
			res.RndReadMBs, res.RndReadIOPS = mbs, iops
		case "seq-q8-write":
			res.SeqQ8WriteMBs = mbs
		case "seq-write":
			res.SeqWriteMBs = mbs
		case "rnd-q32-write":
			res.RndQ32WriteMBs, res.RndQ32WriteIOPS = mbs, iops
		case "rnd-write":
			res.RndWriteMBs, res.RndWriteIOPS = mbs, iops
		}
	}
	report(Progress{Phase: "done", Done: 1})
	res.Note = note
	res.DurationMs = time.Since(start).Milliseconds()
	return res, nil
}

var phaseName = map[string]string{
	"seq-q8-read":   "lettura sequenziale Q8",
	"seq-read":      "lettura sequenziale",
	"rnd-q32-read":  "lettura casuale Q32",
	"rnd-read":      "lettura casuale",
	"seq-q8-write":  "scrittura sequenziale Q8",
	"seq-write":     "scrittura sequenziale",
	"rnd-q32-write": "scrittura casuale Q32",
	"rnd-write":     "scrittura casuale",
}

// runJob esegue una misura con j.depth goroutine, ciascuna con il proprio
// esecutore e il proprio buffer, per la durata indicata. Le letture
// sequenziali si spartiscono i blocchi in ordine, ricominciando dall'inizio
// a fine file; quelle casuali scelgono blocchi allineati in tutto il file.
// Per le scritture il tempo comprende lo svuotamento della cache dell'unità.
// Restituisce byte, operazioni e tempo trascorso fino all'ultima operazione.
func runJob(f file, j job, limit int64, d time.Duration, stop *atomic.Bool, progress func(done int64, el time.Duration)) (int64, int64, time.Duration, error) {
	blocks := limit / int64(j.block)
	if blocks < 1 {
		return 0, 0, 0, errors.New("file di prova troppo piccolo")
	}
	// Esecutori e buffer si preparano prima di far partire il cronometro.
	workers := make([]rw, 0, j.depth)
	bufs := make([][]byte, 0, j.depth)
	for range j.depth {
		w, err := f.worker()
		if err != nil {
			for _, w := range workers {
				w.Close()
			}
			return 0, 0, 0, err
		}
		buf := alignedBuffer(j.block)
		fillRandom(buf)
		workers, bufs = append(workers, w), append(bufs, buf)
	}
	var next, done, ops atomic.Int64
	var halt atomic.Bool
	var firstErr error
	var errOnce sync.Once
	var wg sync.WaitGroup
	t0 := time.Now()
	for g, w := range workers {
		buf := bufs[g]
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			defer w.Close()
			rnd := rand.New(rand.NewPCG(uint64(t0.UnixNano())+uint64(g), 0x9e3779b97f4a7c15))
			for n := uint64(0); !halt.Load() && !stop.Load(); n++ {
				var off int64
				if j.random {
					off = rnd.Int64N(blocks) * int64(j.block)
				} else {
					off = (next.Add(1) - 1) % blocks * int64(j.block)
				}
				var err error
				if j.write {
					stamp(buf, n<<6|uint64(g))
					_, err = w.WriteAt(buf, off)
				} else {
					_, err = w.ReadAt(buf, off)
				}
				if err != nil {
					errOnce.Do(func() { firstErr = err })
					halt.Store(true)
					return
				}
				ops.Add(1)
				if g == 0 {
					progress(done.Add(int64(j.block)), time.Since(t0))
				} else {
					done.Add(int64(j.block))
				}
				if time.Since(t0) >= d {
					halt.Store(true)
				}
			}
		}(g)
	}
	wg.Wait()
	if firstErr != nil {
		return 0, 0, 0, firstErr
	}
	if j.write {
		if err := f.Sync(); err != nil {
			return 0, 0, 0, err
		}
	}
	return done.Load(), ops.Load(), time.Since(t0), nil
}

// fillRandom riempie il buffer di dati non comprimibili: alcune unità
// comprimono i dati e con byte ripetitivi sembrerebbero più veloci.
func fillRandom(b []byte) {
	r := rand.New(rand.NewPCG(1, 2))
	for i := 0; i+8 <= len(b); i += 8 {
		v := r.Uint64()
		for j := 0; j < 8; j++ {
			b[i+j] = byte(v >> (8 * j))
		}
	}
}

// stamp rende unico ogni settore scritto (contatore nei primi 8 byte di ogni
// blocco da 4 KiB), contro la deduplicazione di alcuni controller.
func stamp(b []byte, seq uint64) {
	for i := 0; i+small <= len(b); i += small {
		v := seq<<12 | uint64(i/small)
		for j := 0; j < 8; j++ {
			b[i+j] = byte(v >> (8 * j))
		}
	}
}

// NormalizeDrive accetta "c", "C:", "c:\" e restituisce "C:".
func NormalizeDrive(d string) (string, error) {
	d = strings.TrimRight(strings.TrimSpace(d), `\/`)
	d = strings.TrimSuffix(d, ":")
	if len(d) != 1 || !(d[0] >= 'a' && d[0] <= 'z' || d[0] >= 'A' && d[0] <= 'Z') {
		return "", errors.New("unità non valida: serve una lettera, per esempio C:")
	}
	return strings.ToUpper(d) + ":", nil
}
