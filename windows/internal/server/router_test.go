package server

import (
	"net/http"
	"strings"
	"testing"
)

// "Apri il pannello del router": l'interfaccia manda solo l'identificativo;
// l'indirizzo è quello del gateway dell'ultima analisi, e solo se privato.
func TestRouterPanel(t *testing.T) {
	s := newServer()
	h := s.Handler()
	open := func() *http.Response {
		return doBody(t, h, "POST", "/api/open", "application/json", `{"tool":"router-panel","target":"site"}`).Result()
	}
	if r := open(); r.StatusCode != http.StatusNotImplemented {
		t.Fatalf("senza funzione di apertura: %d", r.StatusCode)
	}
	var gotGW string
	var gotHTTPS bool
	calls := 0
	s.OpenRouter = func(gw string, https bool) error {
		calls++
		gotGW, gotHTTPS = gw, https
		return nil
	}
	if r := doBody(t, h, "POST", "/api/open", "application/json", `{"tool":"router-panel","target":"app"}`); r.Code != http.StatusBadRequest {
		t.Fatalf("target app: %d", r.Code)
	}
	// Nessuna analisi: niente da aprire.
	if r := doBody(t, h, "POST", "/api/open", "application/json", `{"tool":"router-panel","target":"site"}`); r.Code != http.StatusUnprocessableEntity || !strings.Contains(r.Body.String(), "esegui prima un'analisi") {
		t.Fatalf("senza analisi: %d %s", r.Code, r.Body)
	}
	// Gateway pubblico (per esempio una VPN o un collegamento diretto al modem): rifiutato.
	s.mu.Lock()
	s.gateway, s.gwHTTPS = "8.8.8.8", false
	s.mu.Unlock()
	if r := doBody(t, h, "POST", "/api/open", "application/json", `{"tool":"router-panel","target":"site"}`); r.Code != http.StatusUnprocessableEntity || !strings.Contains(r.Body.String(), "IPv4 privato") {
		t.Fatalf("gateway pubblico: %d %s", r.Code, r.Body)
	}
	if calls != 0 {
		t.Fatalf("aperto %d volte prima del gateway privato", calls)
	}
	s.mu.Lock()
	s.gateway, s.gwHTTPS = "192.168.1.1", true
	s.mu.Unlock()
	if r := open(); r.StatusCode != http.StatusOK {
		t.Fatalf("gateway privato: %d", r.StatusCode)
	}
	if calls != 1 || gotGW != "192.168.1.1" || !gotHTTPS {
		t.Fatalf("aperto con %q https=%v (%d volte)", gotGW, gotHTTPS, calls)
	}
	// Un indirizzo nel corpo della richiesta non conta: si apre sempre il gateway dell'analisi.
	if r := doBody(t, h, "POST", "/api/open", "application/json", `{"tool":"router-panel","target":"site","url":"http://8.8.8.8/"}`); r.Code != http.StatusOK || gotGW != "192.168.1.1" {
		t.Fatalf("indirizzo dall'interfaccia: %d %q", r.Code, gotGW)
	}
}

// Una nuova analisi senza router cancella quello dell'analisi precedente.
func TestRouterPanelForgetsOldGateway(t *testing.T) {
	s := newServer()
	s.mu.Lock()
	s.gateway, s.gwHTTPS = "10.99.99.1", true
	s.mu.Unlock()
	if err := s.startScan(); err != nil {
		t.Fatal(err)
	}
	s.Wait()
	s.mu.Lock()
	gw, https := s.gateway, s.gwHTTPS
	s.mu.Unlock()
	if gw == "10.99.99.1" || https {
		t.Fatalf("resta il router dell'analisi precedente: %q https=%v", gw, https)
	}
}
