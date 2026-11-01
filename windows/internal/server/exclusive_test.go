package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"lanterna/internal/scan"
	"lanterna/internal/speedtest"
	"lanterna/internal/survey"
)

// La misura del Wi-Fi per stanza e il test di velocità di Internet non si
// sovrappongono: il traffico del test falserebbe ping e perdite della misura,
// e i ping della misura il test. Il rifiuto non consuma un test dai limiti.
func TestSurveyAndSpeedExclusive(t *testing.T) {
	s := newServer()
	h := s.Handler()
	s.SpeedLimit = speedtest.NewLimiter()
	release := make(chan struct{})
	s.Survey = func(ctx context.Context, _ survey.Options) (*scan.SurveySample, error) {
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return &scan.SurveySample{Room: "Studio"}, nil
	}
	speedCalls := 0
	s.SpeedTest = func(ctx context.Context, _ func(speedtest.Progress)) (*scan.SpeedTest, error) {
		speedCalls++
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return &scan.SpeedTest{Provider: "mlab-ndt7", Download: &scan.SpeedDir{Mbps: 50, Bytes: 1, Ms: 1}}, nil
	}

	// Misura in corso: niente test di Internet.
	if r := doBody(t, h, "POST", "/api/wifi/survey", "application/json", `{"room":"Studio"}`); r.Code != http.StatusAccepted {
		t.Fatalf("avvio della misura: %d %s", r.Code, r.Body)
	}
	r := doBody(t, h, "POST", "/api/speedtest", "application/json", `{"consent":true}`)
	if r.Code != http.StatusConflict || !strings.Contains(r.Body.String(), "misura del Wi-Fi in corso") {
		t.Fatalf("test di Internet durante la misura: %d %s", r.Code, r.Body)
	}
	if st := speedGet(t, h); st.Left != speedtest.DefaultPerDay || speedCalls != 0 {
		t.Fatalf("il rifiuto ha contato: %+v, chiamate %d", st, speedCalls)
	}
	close(release)
	s.WaitSurvey()

	// Test di Internet in corso: niente misura.
	release = make(chan struct{})
	if r := doBody(t, h, "POST", "/api/speedtest", "application/json", `{"consent":true}`); r.Code != http.StatusAccepted {
		t.Fatalf("avvio del test di Internet: %d %s", r.Code, r.Body)
	}
	r = doBody(t, h, "POST", "/api/wifi/survey", "application/json", `{"room":"Studio"}`)
	if r.Code != http.StatusConflict || !strings.Contains(r.Body.String(), "test di velocità di Internet in corso") {
		t.Fatalf("misura durante il test di Internet: %d %s", r.Code, r.Body)
	}
	close(release)
	s.WaitSpeed()
	if st := speedGet(t, h); st.Result == nil || st.Error != "" {
		t.Fatalf("esito del test: %+v", st)
	}
}

// Un rifiuto di POST /api/scan dice perché: busy "scan" solo se è già in
// corso un'analisi (l'interfaccia ne segue l'avanzamento e mostra l'esito);
// se l'analisi non parte per un'altra attività (test della CPU o del disco,
// misura del Wi-Fi, test di Internet) niente busy, e l'interfaccia mostra il
// messaggio invece di ricaricare l'analisi precedente come se fosse nuova.
func TestScanConflictReason(t *testing.T) {
	s := newServer()
	h := s.Handler()
	set := func(mu *sync.Mutex, flag *bool, v bool) {
		mu.Lock()
		*flag = v
		mu.Unlock()
	}
	for _, c := range []struct {
		what     string
		mu       *sync.Mutex
		flag     *bool
		busy     string
		contains string
	}{
		{"analisi in corso", &s.mu, &s.running, "scan", "analisi già in corso"},
		{"test della CPU o del disco", &s.benchMu, &s.benchRunning, "", "test della CPU o del disco in corso"},
		{"misura del Wi-Fi", &s.survey.mu, &s.survey.running, "", "misura del Wi-Fi in corso"},
		{"test di Internet", &s.speedMu, &s.speedRunning, "", "test di velocità di Internet in corso"},
	} {
		set(c.mu, c.flag, true)
		r := doBody(t, h, "POST", "/api/scan", "", "")
		set(c.mu, c.flag, false)
		var body map[string]string
		if err := json.Unmarshal(r.Body.Bytes(), &body); err != nil || r.Code != http.StatusConflict {
			t.Fatalf("%s: %d %s", c.what, r.Code, r.Body)
		}
		busy, has := body["busy"]
		if busy != c.busy || has != (c.busy != "") || !strings.Contains(body["error"], c.contains) {
			t.Errorf("%s: %s", c.what, r.Body)
		}
	}
	// Con l'agente libero l'analisi parte.
	if r := doBody(t, h, "POST", "/api/scan", "", ""); r.Code != http.StatusAccepted {
		t.Fatalf("avvio: %d %s", r.Code, r.Body)
	}
	s.Wait()
}
