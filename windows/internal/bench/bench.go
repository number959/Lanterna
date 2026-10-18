// Package bench misura, solo su richiesta esplicita, la velocità del
// processore e delle unità di archiviazione.
//
// Processore: comprime con compress/flate un testo sintetico, sempre uguale,
// prima con un solo thread e poi con tutti, campionando ogni secondo per
// vedere se le prestazioni calano col passare del tempo (calore, limiti di
// potenza). Il risultato è in MB/s di dati compressi: confrontabile tra
// esecuzioni di questo programma, non con i punteggi di altri benchmark.
//
// Unità: scrive e rilegge un file temporaneo senza passare dalla cache di
// Windows (FILE_FLAG_NO_BUFFERING), in sequenza a blocchi da 1 MiB e in punti
// casuali a blocchi da 4 KiB con una richiesta alla volta. Il file viene
// creato con FILE_FLAG_DELETE_ON_CLOSE: Windows lo cancella alla chiusura,
// anche se il programma si interrompe. Ogni fase ha una durata massima,
// così una chiavetta lenta non tiene occupato il computer per minuti.
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
	Drive   string        // lettera dell'unità, per il risultato ("C:")
	Dir     string        // cartella del file temporaneo
	FileMB  int           // dimensione massima del file
	SeqTime time.Duration // durata massima di ogni fase sequenziale
	RndTime time.Duration // durata di ogni fase casuale
	// Reserve è lo spazio che deve restare libero dopo aver creato il file.
	Reserve uint64
}

// DefaultDisk: file da 1 GiB (come i benchmark più diffusi), al massimo
// circa 35 secondi in tutto, almeno 2 GiB lasciati liberi.
var DefaultDisk = DiskOptions{FileMB: 1024, SeqTime: 10 * time.Second, RndTime: 5 * time.Second, Reserve: 2 << 30}

// QuickDisk serve alle verifiche automatiche.
var QuickDisk = DiskOptions{FileMB: 256, SeqTime: 3 * time.Second, RndTime: time.Second, Reserve: 1 << 30}

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
	ReadAt(p []byte, off int64) (int, error)
	WriteAt(p []byte, off int64) (int, error)
	Sync() error
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

// Disk esegue il test dell'unità.
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
	buf := alignedBuffer(block)
	fillRandom(buf)
	total := 2*opt.SeqTime + 2*opt.RndTime
	phaseStart := time.Duration(0)
	var lastReport time.Time
	progress := func(phase string, el time.Duration, mbs float64) {
		if now := time.Now(); now.Sub(lastReport) >= 200*time.Millisecond {
			lastReport = now
			report(Progress{Phase: phase, Done: frac(phaseStart+el, total), Value: round1(mbs)})
		}
	}

	// 1. Scrittura sequenziale, svuotamento della cache dell'unità compreso.
	var written int64
	t0 := time.Now()
	for seq := uint64(0); written < size && time.Since(t0) < opt.SeqTime; seq++ {
		if stop.Load() {
			return nil, ctx.Err()
		}
		stamp(buf, seq)
		if _, err := f.WriteAt(buf, written); err != nil {
			return nil, fmt.Errorf("scrittura: %v", err)
		}
		written += block
		el := time.Since(t0)
		progress("seq-write", el, float64(written)/el.Seconds()/mb)
	}
	if err := f.Sync(); err != nil {
		return nil, fmt.Errorf("scrittura: %v", err)
	}
	res.FileMB = int(written >> 20)
	res.SeqWriteMBs = round1(float64(written) / time.Since(t0).Seconds() / mb)
	if written < size && note == "" {
		note = fmt.Sprintf("Unità lenta: in %d secondi sono stati scritti %d MB.", int(opt.SeqTime.Seconds()), written>>20)
	}

	// 2. Lettura sequenziale della parte scritta.
	phaseStart = opt.SeqTime
	var read int64
	t0 = time.Now()
	for read < written && time.Since(t0) < opt.SeqTime {
		if stop.Load() {
			return nil, ctx.Err()
		}
		if _, err := f.ReadAt(buf, read); err != nil {
			return nil, fmt.Errorf("lettura: %v", err)
		}
		read += block
		el := time.Since(t0)
		progress("seq-read", el, float64(read)/el.Seconds()/mb)
	}
	res.SeqReadMBs = round1(float64(read) / time.Since(t0).Seconds() / mb)

	// 3-4. Blocchi da 4 KiB in punti casuali, una richiesta alla volta.
	blocks := written / small
	rnd := rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), 0x9e3779b97f4a7c15))
	io4k := buf[:small]
	runRandom := func(phase string, write bool) (float64, float64, error) {
		var n int64
		t0 := time.Now()
		for time.Since(t0) < opt.RndTime {
			if stop.Load() {
				return 0, 0, ctx.Err()
			}
			off := rnd.Int64N(blocks) * small
			var err error
			if write {
				stamp(io4k, uint64(n))
				_, err = f.WriteAt(io4k, off)
			} else {
				_, err = f.ReadAt(io4k, off)
			}
			if err != nil {
				return 0, 0, err
			}
			n++
			el := time.Since(t0)
			progress(phase, el, float64(n*small)/el.Seconds()/mb)
		}
		if write {
			if err := f.Sync(); err != nil {
				return 0, 0, err
			}
		}
		el := time.Since(t0).Seconds()
		return round1(float64(n*small) / el / mb), math.Round(float64(n) / el), nil
	}
	phaseStart = 2 * opt.SeqTime
	if res.RndReadMBs, res.RndReadIOPS, err = runRandom("rnd-read", false); err != nil {
		return nil, fmt.Errorf("lettura casuale: %w", err)
	}
	phaseStart = 2*opt.SeqTime + opt.RndTime
	if res.RndWriteMBs, res.RndWriteIOPS, err = runRandom("rnd-write", true); err != nil {
		return nil, fmt.Errorf("scrittura casuale: %w", err)
	}
	report(Progress{Phase: "done", Done: 1})
	res.Note = note
	res.DurationMs = time.Since(start).Milliseconds()
	return res, nil
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
