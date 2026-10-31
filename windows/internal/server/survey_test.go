package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"lanterna/internal/bench"
	"lanterna/internal/scan"
	"lanterna/internal/survey"
)

func TestSurveyEndpoint(t *testing.T) {
	s := newServer()
	h := s.Handler()
	post := func(body string) *httptest.ResponseRecorder {
		return doBody(t, h, "POST", "/api/wifi/survey", "application/json", body)
	}
	status := func() surveyState {
		var st surveyState
		r := do(t, h, "GET", "/api/wifi/survey", nil)
		if r.Code != 200 {
			t.Fatalf("stato: %d", r.Code)
		}
		if err := json.Unmarshal(r.Body.Bytes(), &st); err != nil {
			t.Fatal(err)
		}
		return st
	}
	if r := post(`{"room":"Soggiorno"}`); r.Code != http.StatusNotImplemented {
		t.Fatalf("non disponibile: %d", r.Code)
	}
	release := make(chan struct{})
	var got survey.Options
	s.Survey = func(ctx context.Context, opt survey.Options) (*scan.SurveySample, error) {
		got = opt
		dbm := -63
		opt.Progress(survey.Progress{Phase: "misura", ElapsedMs: 3000, Seconds: opt.Seconds, Dbm: &dbm, Rssi: []int{-62, -64, -63}})
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return &scan.SurveySample{Room: opt.Room, SSID: "Casa", Seconds: opt.Seconds, Rssi: []int{-62, -64, -63}, MedianDbm: -63, BSSIDs: []string{"aa:bb:cc:00:00:10"}, Roams: []scan.SurveyRoam{}}, nil
	}
	for _, body := range []string{`{"room":""}`, `{"room":"` + strings.Repeat("x", 41) + `"}`, `{"room":"Studio","seconds":5}`, `{"room":"Studio","seconds":21}`, `{"room":"A\u0007B"}`} {
		if r := post(body); r.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d", body, r.Code)
		}
	}
	if r := doBody(t, h, "POST", "/api/wifi/survey", "text/plain", `{"room":"Studio"}`); r.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("corpo non JSON: %d", r.Code)
	}
	if st := status(); st.Running || st.Result != nil {
		t.Fatalf("prima della misura: %+v", st)
	}
	r := post(`{"room":"  Sala d'attesa ","seconds":12}`)
	if r.Code != http.StatusAccepted || !strings.Contains(r.Body.String(), `"room":"Sala d'attesa"`) {
		t.Fatalf("avvio: %d %s", r.Code, r.Body)
	}
	if r := post(`{"room":"Studio"}`); r.Code != http.StatusConflict {
		t.Fatalf("doppia misura: %d", r.Code)
	}
	// Un'analisi completa non parte durante la misura (ne falserebbe i valori), né l'inventario.
	if r := doBody(t, h, "POST", "/api/scan", "", ""); r.Code != http.StatusConflict || !strings.Contains(r.Body.String(), "Wi-Fi") {
		t.Fatalf("analisi durante la misura: %d %s", r.Code, r.Body)
	}
	// Nemmeno un test di velocità: il carico allungherebbe i tempi dei ping.
	s.BenchCPU = func(context.Context, bench.Report) (*scan.CPUBench, error) { return &scan.CPUBench{}, nil }
	if r := doBody(t, h, "POST", "/api/bench", "application/json", `{"kind":"cpu"}`); r.Code != http.StatusConflict || !strings.Contains(r.Body.String(), "misura del Wi-Fi") {
		t.Fatalf("test di velocità durante la misura: %d %s", r.Code, r.Body)
	}
	var st surveyState
	for i := 0; i < 200; i++ {
		if st = status(); st.Progress != nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !st.Running || st.Room != "Sala d'attesa" || st.Progress == nil || *st.Progress.Dbm != -63 || st.Progress.Seconds != 12 {
		t.Fatalf("avanzamento: %+v", st)
	}
	close(release)
	s.WaitSurvey()
	st = status()
	if st.Running || st.Error != "" || st.Result == nil || st.Result.Room != "Sala d'attesa" || st.Result.MedianDbm != -63 {
		t.Fatalf("esito: %+v", st)
	}
	// Valori predefiniti: 15 secondi e scansione attiva; "scan": false la toglie.
	if got.Seconds != 12 || !got.Scan {
		t.Fatalf("opzioni: %+v", got)
	}
	release = make(chan struct{})
	if r := post(`{"room":"Studio","scan":false}`); r.Code != http.StatusAccepted {
		t.Fatalf("seconda misura: %d", r.Code)
	}
	// La nuova misura toglie l'esito precedente; DELETE la interrompe.
	if st := status(); st.Result != nil {
		t.Fatalf("esito vecchio durante la nuova misura: %+v", st.Result)
	}
	if r := do(t, h, "DELETE", "/api/wifi/survey", map[string]string{"Origin": "http://127.0.0.1:8737"}); r.Code != 200 || !strings.Contains(r.Body.String(), "true") {
		t.Fatalf("interruzione: %d %s", r.Code, r.Body)
	}
	s.WaitSurvey()
	if st := status(); st.Running || st.Error != "misura interrotta" || st.Result != nil || got.Seconds != 15 || got.Scan {
		t.Fatalf("dopo l'interruzione: %+v %+v", st, got)
	}
	// Da un'altra origine la misura non parte.
	if r := do(t, h, "POST", "/api/wifi/survey", map[string]string{"Origin": "https://evil.example", "Content-Type": "application/json"}); r.Code != http.StatusForbidden {
		t.Fatalf("da altra origine: %d", r.Code)
	}
}

// Durante un test di velocità del processore o del disco la misura del Wi-Fi
// non parte: il carico allungherebbe tempi e jitter del router.
func TestSurveyRefusedDuringBench(t *testing.T) {
	s := newServer()
	h := s.Handler()
	s.BenchCPU = func(ctx context.Context, _ bench.Report) (*scan.CPUBench, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	called := false
	s.Survey = func(context.Context, survey.Options) (*scan.SurveySample, error) {
		called = true
		return nil, errors.New("non doveva partire")
	}
	if r := doBody(t, h, "POST", "/api/bench", "application/json", `{"kind":"cpu"}`); r.Code != http.StatusAccepted {
		t.Fatalf("test: %d %s", r.Code, r.Body)
	}
	r := doBody(t, h, "POST", "/api/wifi/survey", "application/json", `{"room":"Studio"}`)
	if r.Code != http.StatusConflict || !strings.Contains(r.Body.String(), "test della CPU o del disco in corso") {
		t.Fatalf("misura durante il test: %d %s", r.Code, r.Body)
	}
	do(t, h, "DELETE", "/api/bench", nil)
	s.WaitBench()
	s.WaitSurvey()
	if called {
		t.Fatal("la misura è partita durante il test")
	}
}
