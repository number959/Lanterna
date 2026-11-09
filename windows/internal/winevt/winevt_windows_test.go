//go:build windows

package winevt

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Prove su Windows reale (nella CI): il registro di sistema ha sempre eventi,
// quindi EvtQuery, EvtNext, EvtRender e l'interpretazione dell'XML devono
// restituire fonte, codice e ora.
func TestQuerySystemWindows(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	events, err := Query(ctx, "System", XPath(nil, 0), 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 {
		t.Fatal("nessun evento nel registro di sistema")
	}
	for i, e := range events {
		if e.Provider == "" || e.ID <= 0 || e.Time.IsZero() {
			t.Errorf("evento %d non interpretato: %+v", i, e)
		}
		if i > 0 && e.Time.After(events[i-1].Time) {
			t.Errorf("ordine non dal più recente: %v dopo %v", e.Time, events[i-1].Time)
		}
	}
	t.Logf("ultimo evento: %s %d %s, %d valori", events[0].Provider, events[0].ID, events[0].Time.Format(time.RFC3339), len(events[0].Data))
}

func TestQueryMissingChannelWindows(t *testing.T) {
	_, err := Query(context.Background(), "Polaris-Canale-Inesistente/Operational", "*", 1)
	if !errors.Is(err, ErrNoChannel) {
		t.Errorf("registro inesistente: %v", err)
	}
}
