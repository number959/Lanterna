package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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
	var calls atomic.Int32
	started, release := make(chan struct{}), make(chan struct{})
	s.Win11CPUs = func(ctx context.Context) *scan.Win11CPUCheck {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("confronto senza tempo massimo")
		}
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return &scan.Win11CPUCheck{At: "2026-11-17T10:00:00Z", Source: "https://learn.microsoft.com/x", Version: "25H2", Kind: "series", Result: "listed", Match: "8th Generation Core i5 Processors", CPU: "Intel(R) Core(TM) i5-8250U", Rows: 87}
	}
	if c := post("text/plain", `{}`); c != http.StatusUnsupportedMediaType {
		t.Fatalf("senza JSON: %d", c)
	}
	if c := post("application/json", `{`); c != http.StatusBadRequest {
		t.Fatalf("JSON non valido: %d", c)
	}
	first, second := make(chan *httptest.ResponseRecorder, 1), make(chan *httptest.ResponseRecorder, 1)
	go func() { first <- doBody(t, h, "POST", "/api/win11/cpus", "application/json", `{}`) }()
	<-started
	// Un secondo confronto insieme al primo (un'altra finestra, la pagina
	// ricaricata) non è un errore: aspetta il primo e ne riceve l'esito.
	go func() { second <- doBody(t, h, "POST", "/api/win11/cpus", "application/json", `{}`) }()
	waitWin11(t, s, 2)
	close(release)
	for i, ch := range []chan *httptest.ResponseRecorder{first, second} {
		r := <-ch
		var got scan.Win11CPUCheck
		if r.Code != http.StatusOK || json.Unmarshal(r.Body.Bytes(), &got) != nil || got.Result != "listed" || got.Rows != 87 {
			t.Errorf("confronto %d: %d %s", i+1, r.Code, r.Body)
		}
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("confronti eseguiti: %d, atteso 1", n)
	}
	r := do(t, h, "GET", "/api/win11/cpus", nil)
	var got scan.Win11CPUCheck
	if r.Code != http.StatusOK || json.Unmarshal(r.Body.Bytes(), &got) != nil || got.Result != "listed" || got.Rows != 87 {
		t.Fatalf("ultimo esito: %d %s", r.Code, r.Body)
	}
	// Finito il primo, un nuovo clic avvia un nuovo confronto.
	if c := post("application/json", `{}`); c != http.StatusOK || calls.Load() != 2 {
		t.Errorf("nuovo confronto: %d, confronti %d", c, calls.Load())
	}
	// Da un altro sito il POST si rifiuta (CSRF), come per le altre richieste.
	if r := do(t, h, "POST", "/api/win11/cpus", map[string]string{"Origin": "https://evil.example", "Content-Type": "application/json"}); r.Code != http.StatusForbidden {
		t.Errorf("origine estranea: %d", r.Code)
	}
}

// Se chi ha avviato il confronto se ne va (finestra chiusa), il confronto
// finisce lo stesso e l'esito resta per GET; un panic non blocca i successivi.
func TestWin11CPUsDetached(t *testing.T) {
	s := newServer()
	h := s.Handler()
	release := make(chan struct{})
	s.Win11CPUs = func(ctx context.Context) *scan.Win11CPUCheck {
		<-release
		return &scan.Win11CPUCheck{Result: "notListed", Version: "24H2", Kind: "model"}
	}
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("POST", "/api/win11/cpus", strings.NewReader(`{}`)).WithContext(ctx)
	req.Host = "127.0.0.1:8737"
	req.Header.Set("Origin", "http://127.0.0.1:8737")
	req.Header.Set("Content-Type", "application/json")
	done := make(chan struct{})
	go func() {
		h.ServeHTTP(httptest.NewRecorder(), req)
		close(done)
	}()
	waitWin11(t, s, 1)
	cancel()
	<-done
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		r := do(t, h, "GET", "/api/win11/cpus", nil)
		if r.Code == http.StatusOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("esito del confronto abbandonato non salvato: %d", r.Code)
		}
		time.Sleep(10 * time.Millisecond)
	}
	s.Win11CPUs = func(ctx context.Context) *scan.Win11CPUCheck { panic("prova") }
	if c := doBody(t, h, "POST", "/api/win11/cpus", "application/json", `{}`).Code; c != http.StatusInternalServerError {
		t.Errorf("panic: %d", c)
	}
	s.Win11CPUs = func(ctx context.Context) *scan.Win11CPUCheck { return &scan.Win11CPUCheck{Result: "listed"} }
	if c := doBody(t, h, "POST", "/api/win11/cpus", "application/json", `{}`).Code; c != http.StatusOK {
		t.Errorf("dopo il panic: %d", c)
	}
}

// waitWin11 aspetta che il confronto in corso abbia n richieste in attesa.
func waitWin11(t *testing.T, s *Server, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.win11.mu.Lock()
		ok := s.win11.run != nil && s.win11.run.waiters == n
		s.win11.mu.Unlock()
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("il confronto non ha %d richieste in attesa", n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
