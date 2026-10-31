package server

import (
	"context"
	"net/http"
	"strings"
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
