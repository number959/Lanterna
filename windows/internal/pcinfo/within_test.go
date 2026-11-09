package pcinfo

import (
	"context"
	"testing"
	"time"
)

func TestWithin(t *testing.T) {
	v, ok := within(context.Background(), time.Second, func(context.Context) int { return 7 })
	if !ok || v != 7 {
		t.Fatalf("%d %v", v, ok)
	}
	// Una lettura che si accorge della scadenza consegna ciò che ha.
	v, ok = within(context.Background(), 20*time.Millisecond, func(c context.Context) int { <-c.Done(); return 3 })
	if !ok || v != 3 {
		t.Fatalf("parziale: %d %v", v, ok)
	}
	// Una chiamata bloccata si abbandona poco dopo la scadenza.
	start := time.Now()
	block := make(chan struct{})
	defer close(block)
	v, ok = within(context.Background(), 20*time.Millisecond, func(context.Context) int { <-block; return 9 })
	if ok || v != 0 || time.Since(start) > 4*time.Second {
		t.Fatalf("bloccata: %d %v dopo %v", v, ok, time.Since(start))
	}
}
