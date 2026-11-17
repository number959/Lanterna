package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"lanterna/internal/scan"
)

func TestWin11CPUs(t *testing.T) {
	s := newServer()
	h := s.Handler()
	post := func(ctype, body string) int {
		return doBody(t, h, "POST", "/api/win11/cpus", ctype, body).Code
	}
	if c := post("application/json", `{}`); c != http.StatusNotImplemented {
		t.Fatalf("non disponibile: %d", c)
	}
	if r := do(t, h, "GET", "/api/win11/cpus", nil); r.Code != http.StatusNoContent {
		t.Fatalf("nessun esito: %d", r.Code)
	}
	started, release := make(chan struct{}), make(chan struct{})
	s.Win11CPUs = func(ctx context.Context) *scan.Win11CPUCheck {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("confronto senza tempo massimo")
		}
		close(started)
		<-release
		return &scan.Win11CPUCheck{At: "2026-11-17T10:00:00Z", Source: "https://learn.microsoft.com/x", Version: "25H2", Kind: "series", Result: "listed", Match: "8th Generation Core i5 Processors", CPU: "Intel(R) Core(TM) i5-8250U", Rows: 87}
	}
	if c := post("text/plain", `{}`); c != http.StatusUnsupportedMediaType {
		t.Fatalf("senza JSON: %d", c)
	}
	if c := post("application/json", `{`); c != http.StatusBadRequest {
		t.Fatalf("JSON non valido: %d", c)
	}
	done := make(chan int)
	go func() { done <- post("application/json", `{}`) }()
	<-started
	if c := post("application/json", `{}`); c != http.StatusConflict {
		t.Errorf("secondo confronto insieme al primo: %d", c)
	}
	close(release)
	if c := <-done; c != http.StatusOK {
		t.Fatalf("confronto: %d", c)
	}
	r := do(t, h, "GET", "/api/win11/cpus", nil)
	var got scan.Win11CPUCheck
	if r.Code != http.StatusOK || json.Unmarshal(r.Body.Bytes(), &got) != nil || got.Result != "listed" || got.Rows != 87 {
		t.Fatalf("ultimo esito: %d %s", r.Code, r.Body)
	}
	// Da un altro sito il POST si rifiuta (CSRF), come per le altre richieste.
	if r := do(t, h, "POST", "/api/win11/cpus", map[string]string{"Origin": "https://evil.example", "Content-Type": "application/json"}); r.Code != http.StatusForbidden {
		t.Errorf("origine estranea: %d", r.Code)
	}
}
