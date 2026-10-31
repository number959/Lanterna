package main

import (
	"strings"
	"testing"

	"lanterna/internal/scan"
)

func TestPrintSurvey(t *testing.T) {
	i := func(v int) *int { return &v }
	f := func(v float64) *float64 { return &v }
	s := &scan.SurveySample{
		Room: "Studio", SSID: "Casa-Rossi", Band: "5", Channel: 36, WidthMhz: 80, Phy: "802.11ac", Seconds: 15,
		Rssi: []int{-70, -71, -72}, MedianDbm: -71.5, MinDbm: -78, P10Dbm: -76, SpreadDb: 12, Stuck: false, RxMbps: 173, TxMbps: 144,
		BSSIDs:  []string{"aa:bb:cc:00:00:10", "aa:bb:cc:00:00:20"},
		Roams:   []scan.SurveyRoam{{AtMs: 6000, From: "aa:bb:cc:00:00:10", To: "aa:bb:cc:00:00:20"}},
		Gateway: &scan.SurveyPing{Target: "192.168.1.1", Sent: 75, Received: 73, LossPct: 2.7, MedianMs: f(4.2), P95Ms: f(31), JitterMs: f(6.5)},
		Scan: &scan.SurveyScan{Fresh: 9, Stale: 2, ConnectedDbm: i(-71), UtilizationPct: i(55), Stations: i(9),
			Alternatives: []scan.SurveyAlt{{BSSID: "aa:bb:cc:00:00:30", Band: "2.4", Channel: 6, RssiDbm: -58}},
			Neighbors:    scan.SurveyNeighbors{Visible: 12, Cochannel: 3, Strong: 1, StrongestDbm: i(-66), Channels: []int{36, 40}}},
		Notes: []string{"Il canale è cambiato durante la misura (36 → 44)."},
	}
	out := capture(t, func() { printSurvey(s) })
	for _, want := range []string{
		"Studio · rete Casa-Rossi", "5 GHz, canale 36, 80 MHz, 802.11ac", "mediana -71,5 dBm, minimo -78, cali (10° percentile) -76, escursione 12 dB, 3 letture",
		"ricezione 173 Mbit/s", "Cambi di access point da fermo: 1", "Router 192.168.1.1: risposte 73 su 75 (perdite 2,7 %)", "jitter 6,5 ms",
		"canale occupato al 55 %", "2,4 GHz canale 6 a -58 dBm", "12 visibili, 3 sullo stesso canale (1 forte, la più forte a -66 dBm)",
		"2 reti sentite più di 10 secondi prima", "Nota: Il canale è cambiato", "valgono per questo PC",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("manca %q in:\n%s", want, out)
		}
	}
	s2 := &scan.SurveySample{Room: "Bagno", SSID: "Casa", Rssi: []int{-80, -80, -80, -80, -80}, MedianDbm: -80, MinDbm: -80, P10Dbm: -80, Stuck: true,
		BSSIDs: []string{"aa:bb:cc:00:00:10"}, Gateway: &scan.SurveyPing{Skipped: "il router ha un indirizzo pubblico: per prudenza non si misura"}}
	out = capture(t, func() { printSurvey(s2) })
	for _, want := range []string{"mediana -80 dBm", "Valori fermi", "aa:bb:cc:00:00:10, nessun cambio", "Router: non misurato, il router ha un indirizzo pubblico"} {
		if !strings.Contains(out, want) {
			t.Errorf("manca %q in:\n%s", want, out)
		}
	}
}
