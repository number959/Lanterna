package bench

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func smallBlock(mb int) func(int) (*ramBlock, error) {
	return func(int) (*ramBlock, error) {
		return &ramBlock{words: make([]uint64, mb<<20/8), totalMB: 8192, availMB: 4096, lockedMB: mb, free: func() {}}, nil
	}
}

func TestRAMClean(t *testing.T) {
	opt := RAMOptions{Preset: "quick", Duration: 700 * time.Millisecond, Threads: 3}
	var phases []string
	res, err := runRAM(context.Background(), opt, func(p Progress) { phases = append(phases, p.Phase) }, smallBlock(4))
	if err != nil {
		t.Fatal(err)
	}
	if res.Errors != 0 || res.Passes < 1 || res.TestedMB != 4 || res.LockedMB != 4 || res.Stop != "time" || res.TotalMB != 8192 || res.Threads != 3 {
		t.Fatalf("esito: %+v", res)
	}
	names := map[string]bool{}
	for _, s := range res.Tests {
		names[s.Name] = s.Runs > 0
	}
	for _, n := range ramTests {
		if !names[n] {
			t.Errorf("prova %s non eseguita: %+v", n, res.Tests)
		}
	}
	if names["bit-fade"] {
		t.Error("decadimento dei bit fuori dal test lungo")
	}
	if phases[len(phases)-1] != "done" {
		t.Errorf("ultima fase: %v", phases[len(phases)-1])
	}
}

func TestRAMFindsInjectedFault(t *testing.T) {
	for _, test := range ramTests {
		t.Run(test, func(t *testing.T) {
			opt := RAMOptions{Preset: "quick", Duration: time.Second, Threads: 2}
			// modulo20 controlla a ogni giro le celle di una sola posizione su 20.
			idx := 123457
			if test == "modulo20" {
				idx = 123460
			}
			opt.inject = func(w []uint64, name string, pass int) {
				if name == test && pass == 0 {
					w[idx] ^= 1 << 13 // un bit che si inverte, come in una cella guasta
				}
			}
			res, err := runRAM(context.Background(), opt, nil, smallBlock(2))
			if err != nil {
				t.Fatal(err)
			}
			if res.Errors == 0 || len(res.ErrorSamples) == 0 {
				t.Fatalf("guasto non trovato: %+v", res)
			}
			e := res.ErrorSamples[0]
			if e.Test != test || e.Pass != 0 || e.OffsetMB != 0.9 || !strings.HasPrefix(res.BadBits, "0000000000002000") {
				t.Errorf("errore: %+v, bit %s", e, res.BadBits)
			}
		})
	}
}

func TestRAMCancelAndLowMemory(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := runRAM(ctx, RAMOptions{Duration: time.Second}, nil, smallBlock(1)); !errors.Is(err, context.Canceled) {
		t.Errorf("annullato prima di partire: %v", err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	time.AfterFunc(300*time.Millisecond, cancel2)
	res, err := runRAM(ctx2, RAMOptions{Duration: time.Minute, Threads: 1}, nil, smallBlock(64))
	if res == nil || res.Stop != "cancelled" {
		t.Fatalf("interrotto: %+v %v", res, err)
	}
	low := func(int) (*ramBlock, error) {
		b, _ := smallBlock(64)(0)
		b.pressure = func() bool { return true }
		return b, nil
	}
	res, _ = runRAM(context.Background(), RAMOptions{Duration: time.Minute}, nil, low)
	if res == nil || res.Stop != "low-memory" {
		t.Fatalf("poca memoria: %+v", res)
	}
	if _, err := runRAM(context.Background(), RAMOptions{Duration: time.Second}, nil, func(int) (*ramBlock, error) { return nil, ErrRAMLow }); !errors.Is(err, ErrRAMLow) {
		t.Errorf("memoria insufficiente: %v", err)
	}
	if _, err := RAMOptionsFor("lungo"); err == nil {
		t.Error("durata non valida accettata")
	}
	if o, _ := RAMOptionsFor("long"); o.Duration != 30*time.Minute || o.FadeWait == 0 {
		t.Errorf("lungo: %+v", o)
	}
}

func TestRAMBitFade(t *testing.T) {
	opt := RAMOptions{Preset: "long", Duration: 3 * time.Second, FadeWait: 50 * time.Millisecond, Threads: 2}
	res, err := runRAM(context.Background(), opt, nil, smallBlock(1))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range res.Tests {
		if s.Name == "bit-fade" && s.Runs == 1 {
			found = true
		}
	}
	if !found || res.Errors != 0 {
		t.Errorf("decadimento dei bit: %+v", res.Tests)
	}
}
