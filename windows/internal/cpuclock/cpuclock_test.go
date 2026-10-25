package cpuclock

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"
	"time"
)

func TestInstance(t *testing.T) {
	for _, c := range []struct {
		name string
		g, i int
		ok   bool
	}{
		{"0,7", 0, 7, true},
		{"1,3", 1, 3, true},
		{"_Total", 0, 0, false},
		{"0,_Total", 0, 0, false},
		{"7", 0, 0, false},
	} {
		g, i, ok := instance(c.name)
		if ok != c.ok || ok && (g != c.g || i != c.i) {
			t.Errorf("instance(%q) = %d, %d, %v", c.name, g, i, ok)
		}
	}
}

func TestCombine(t *testing.T) {
	nan := math.NaN()
	r := map[string]Reading{
		"_Total":   {Perf: 150, Freq: 2900, Load: 12.34},
		"0,_Total": {Perf: 150, Freq: 2900, Load: 12},
		"0,0":      {Perf: 150, Freq: 2900, Load: 20},
		"0,1":      {Perf: 100, Freq: 2900, Load: 4},
		"0,10":     {Perf: 200, Freq: 2900, Load: 140}, // carico oltre 100: si taglia
		"0,2":      {Perf: nan, Freq: 2900, Load: nan}, // prestazioni non lette
	}
	s, ok := Combine(r, 0)
	if !ok {
		t.Fatal("nessun campione")
	}
	if s.MHz != 4350 || s.BaseMHz != 2900 || s.PerfPct != 150 || s.LoadPct != 12.3 || s.MaxMHz != 5800 {
		t.Fatalf("campione: %+v", s)
	}
	ids := []string{}
	for _, c := range s.Cores {
		ids = append(ids, c.ID)
	}
	if want := []string{"0,0", "0,1", "0,2", "0,10"}; len(ids) != 4 || ids[0] != want[0] || ids[1] != want[1] || ids[2] != want[2] || ids[3] != want[3] {
		t.Fatalf("ordine dei core: %v", ids)
	}
	if s.Cores[2].MHz != 0 || s.Cores[3].LoadPct != 100 || s.Cores[0].MHz != 4350 {
		t.Errorf("core: %+v", s.Cores)
	}

	// Senza "_Total" né frequenza per istanza: media dei core e nominale dal registro.
	s, ok = Combine(map[string]Reading{
		"0,0": {Perf: 120, Freq: nan, Load: 10},
		"0,1": {Perf: 80, Freq: nan, Load: 30},
	}, 3000)
	if !ok || s.MHz != 3000 || s.BaseMHz != 3000 || s.PerfPct != 100 || s.LoadPct != 20 || s.MaxMHz != 3600 {
		t.Fatalf("senza totale: %+v", s)
	}

	// Valori assurdi o mancanti: nessun campione.
	for name, r := range map[string]map[string]Reading{
		"vuoto":            {},
		"senza nominale":   {"_Total": {Perf: 120, Freq: nan, Load: 1}},
		"prestazioni zero": {"_Total": {Perf: 0, Freq: 3000, Load: 1}},
		"oltre 1000 %":     {"_Total": {Perf: 5000, Freq: 3000, Load: 1}},
		"infinito":         {"0,0": {Perf: math.Inf(1), Freq: 3000, Load: 1}},
	} {
		if s, ok := Combine(r, 0); ok {
			t.Errorf("%s: atteso nessun campione, ottenuto %+v", name, s)
		}
	}
}

type fakeSource struct {
	mu       sync.Mutex
	collects int
	closed   bool
	fail     error
	perf     float64
}

func (f *fakeSource) Collect() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.collects++
	return f.fail
}

func (f *fakeSource) Read() (map[string]Reading, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return map[string]Reading{"_Total": {Perf: f.perf, Freq: 2000, Load: 5}, "0,0": {Perf: f.perf, Freq: 2000, Load: 5}}, nil
}

func (f *fakeSource) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
}

func (f *fakeSource) state() (int, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.collects, f.closed
}

func TestSampler(t *testing.T) {
	var opened []*fakeSource
	now := time.Unix(1_000_000, 0)
	var slept []time.Duration
	s := &Sampler{
		Open: func() (Source, error) {
			f := &fakeSource{perf: 150}
			opened = append(opened, f)
			return f, nil
		},
		Now:   func() time.Time { return now },
		Sleep: func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil },
		Idle:  time.Hour,
	}
	defer s.Close()
	smp, err := s.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if smp.MHz != 3000 || !smp.At.Equal(now) {
		t.Fatalf("prima lettura: %+v", smp)
	}
	if n, _ := opened[0].state(); n != 2 || len(slept) != 1 || slept[0] != 250*time.Millisecond {
		t.Fatalf("la prima lettura deve raccogliere due volte con una pausa: %d raccolte, pause %v", n, slept)
	}
	// Entro 250 ms si riusa lo stesso campione.
	now = now.Add(100 * time.Millisecond)
	if _, err := s.Read(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n, _ := opened[0].state(); n != 2 {
		t.Fatalf("lettura ravvicinata: %d raccolte", n)
	}
	// Dopo, una sola raccolta in più, senza riaprire.
	now = now.Add(time.Second)
	opened[0].perf = 100
	smp, _ = s.Read(context.Background())
	if n, _ := opened[0].state(); n != 3 || len(opened) != 1 || smp.MHz != 2000 {
		t.Fatalf("lettura successiva: %d raccolte, %d aperture, %+v", n, len(opened), smp)
	}
	// Un errore chiude i contatori; la lettura dopo li riapre.
	now = now.Add(time.Second)
	opened[0].fail = errors.New("guasto")
	if _, err := s.Read(context.Background()); err == nil {
		t.Fatal("errore non riportato")
	}
	if _, closed := opened[0].state(); !closed {
		t.Fatal("contatori non chiusi dopo l'errore")
	}
	now = now.Add(time.Second)
	if _, err := s.Read(context.Background()); err != nil || len(opened) != 2 {
		t.Fatalf("riapertura: %v, %d aperture", err, len(opened))
	}
}

func TestSamplerIdleClose(t *testing.T) {
	f := &fakeSource{perf: 100}
	s := &Sampler{
		Open:  func() (Source, error) { return f, nil },
		Sleep: func(context.Context, time.Duration) error { return nil },
		Idle:  30 * time.Millisecond,
	}
	defer s.Close()
	if _, err := s.Read(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if _, closed := f.state(); closed {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("contatori non chiusi dopo l'inattività")
}

func TestSamplerUnavailable(t *testing.T) {
	if _, err := (&Sampler{}).Read(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("senza sorgente: %v", err)
	}
	// Valori inutilizzabili: non disponibile, contatori chiusi.
	f := &fakeSource{perf: 0}
	s := &Sampler{Open: func() (Source, error) { return f, nil }, Sleep: func(context.Context, time.Duration) error { return nil }}
	defer s.Close()
	if _, err := s.Read(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("valori nulli: %v", err)
	}
	if _, closed := f.state(); !closed {
		t.Fatal("contatori rimasti aperti")
	}
	// La pausa iniziale rispetta l'annullamento.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s2 := &Sampler{Open: func() (Source, error) { return &fakeSource{perf: 100}, nil }}
	if _, err := s2.Read(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("annullamento: %v", err)
	}
}
