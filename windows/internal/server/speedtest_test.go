package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"lanterna/internal/scan"
	"lanterna/internal/speedtest"
)

func TestSpeedTestEndpoint(t *testing.T) {
	s := newServer()
	h := s.Handler()
	post := func(body string) *http.Response {
		return doBody(t, h, "POST", "/api/speedtest", "application/json", body).Result()
	}
	if r := post(`{"consent":true}`); r.StatusCode != http.StatusNotImplemented {
		t.Fatalf("non disponibile: %d", r.StatusCode)
	}
	now := time.Date(2026, 10, 31, 10, 0, 0, 0, time.Local)
	s.SpeedLimit = speedtest.NewLimiter()
	s.SpeedLimit.Now = func() time.Time { return now }
	release := make(chan struct{})
	calls := 0
	s.SpeedTest = func(ctx context.Context, progress func(speedtest.Progress)) (*scan.SpeedTest, error) {
		calls++
		progress(speedtest.Progress{Phase: speedtest.PhaseDownload, Mbps: 87.5, ElapsedMs: 3000, PhaseMs: 10000})
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return &scan.SpeedTest{StartedAt: "2026-10-31T10:00:00Z", Provider: "mlab-ndt7", Server: &scan.SpeedServer{City: "Milan", Country: "IT", Site: "mil05"},
			Download: &scan.SpeedDir{Mbps: 92.4, Bytes: 115_000_000, Ms: 10000}, Upload: &scan.SpeedDir{Mbps: 19.8, Bytes: 25_000_000, Ms: 10000}}, nil
	}
	// Il consenso è obbligatorio.
	for _, body := range []string{`{}`, `{"consent":false}`, `{"consent":"sì"}`} {
		r := post(body)
		if r.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s: %d", body, r.StatusCode)
		}
	}
	if r := doBody(t, h, "POST", "/api/speedtest", "text/plain", `{"consent":true}`); r.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("corpo non JSON: %d", r.Code)
	}
	if r := do(t, h, "POST", "/api/speedtest", map[string]string{"Origin": "https://evil.example", "Content-Type": "application/json"}); r.Code != http.StatusForbidden {
		t.Fatalf("da altra origine: %d", r.Code)
	}
	if calls != 0 {
		t.Fatal("test avviato senza consenso")
	}
	if r := post(`{"consent":true}`); r.StatusCode != http.StatusAccepted {
		t.Fatalf("avvio: %d", r.StatusCode)
	}
	waitFor(t, func() bool { return speedGet(t, h).Progress != nil })
	st := speedGet(t, h)
	if !st.Running || st.Progress.Phase != "download" || st.Progress.Mbps != 87.5 || st.Left != 9 {
		t.Fatalf("in corso: %+v", st)
	}
	// Un test alla volta, e niente analisi nel frattempo.
	if r := post(`{"consent":true}`); r.StatusCode != http.StatusConflict {
		t.Fatalf("doppio test: %d", r.StatusCode)
	}
	if r := do(t, h, "POST", "/api/scan", nil); r.Code != http.StatusConflict || !strings.Contains(r.Body.String(), "test di velocità di Internet in corso") {
		t.Fatalf("analisi durante il test: %d %s", r.Code, r.Body)
	}
	close(release)
	s.WaitSpeed()
	st = speedGet(t, h)
	if st.Running || st.Result == nil || st.Result.Download.Mbps != 92.4 || st.Error != "" || st.Progress != nil || st.WaitSec != 120 {
		t.Fatalf("esito: %+v", st)
	}
	// Troppo presto: 429 con l'attesa.
	now = now.Add(30 * time.Second)
	r := post(`{"consent":true}`)
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	if r.StatusCode != http.StatusTooManyRequests || r.Header.Get("Retry-After") != "90" || body["retryAfter"] != float64(90) || !strings.Contains(body["error"].(string), "tra 1 min 30 s") {
		t.Fatalf("pausa: %d %v %v", r.StatusCode, r.Header, body)
	}
	if calls != 1 {
		t.Fatalf("chiamate %d", calls)
	}
	// Interruzione.
	now = now.Add(2 * time.Minute)
	release = make(chan struct{})
	if r := post(`{"consent":true}`); r.StatusCode != http.StatusAccepted {
		t.Fatalf("secondo avvio: %d", r.StatusCode)
	}
	if r := do(t, h, "DELETE", "/api/speedtest", nil); r.Code != 200 || !strings.Contains(r.Body.String(), `"stopping":true`) {
		t.Fatalf("interruzione: %d %s", r.Code, r.Body)
	}
	s.WaitSpeed()
	if st := speedGet(t, h); st.Error != "test interrotto" || st.Result != nil {
		t.Fatalf("dopo l'interruzione: %+v", st)
	}
	// Un test che non raggiunge M-Lab non conta per i limiti.
	now = now.Add(3 * time.Minute)
	s.SpeedTest = func(context.Context, func(speedtest.Progress)) (*scan.SpeedTest, error) {
		return nil, speedtest.ErrProxyAuth
	}
	if r := post(`{"consent":true}`); r.StatusCode != http.StatusAccepted {
		t.Fatalf("terzo avvio: %d", r.StatusCode)
	}
	s.WaitSpeed()
	if st := speedGet(t, h); !strings.Contains(st.Error, "autenticazione") || st.WaitSec != 0 || st.Left != 8 {
		t.Fatalf("proxy: %+v", st)
	}
}

func speedGet(t *testing.T, h http.Handler) speedState {
	t.Helper()
	r := do(t, h, "GET", "/api/speedtest", nil)
	if r.Code != 200 {
		t.Fatalf("GET: %d", r.Code)
	}
	var st speedState
	if err := json.Unmarshal(r.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	return st
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if ok() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("tempo scaduto")
}
