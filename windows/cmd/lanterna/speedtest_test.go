package main

import (
	"bytes"
	"strings"
	"testing"

	"lanterna/internal/scan"
)

func TestPrintSpeed(t *testing.T) {
	f := scan.Ptr[float64]
	r := &scan.SpeedTest{
		Provider: "mlab-ndt7", Server: &scan.SpeedServer{City: "Milan", Country: "IT", Site: "mil05", Machine: "mlab1-mil05.mlab-oti.measurement-lab.org"},
		Probe: "1.1.1.1", ProbeMethod: "icmp", ViaProxy: true,
		Idle: &scan.SpeedLatency{Sent: 20, Received: 20, MedianMs: f(12), P95Ms: f(15)},
		Download: &scan.SpeedDir{Mbps: 245.3, Bytes: 306_000_000, Ms: 10000, Capped: true, MinRTTMs: f(9.2), RetransPct: f(0.83),
			Latency: &scan.SpeedLatency{Sent: 40, Received: 38, MedianMs: f(38), P95Ms: f(52)}, BloatMs: f(26), BloatP95Ms: f(40)},
		Upload: &scan.SpeedDir{Mbps: 48.2, Bytes: 60_000_000, Ms: 10000,
			Latency: &scan.SpeedLatency{Sent: 40, Received: 40, MedianMs: f(140), P95Ms: f(190)}, BloatMs: f(128), BloatP95Ms: f(178)},
	}
	var b bytes.Buffer
	printSpeed(&b, r)
	out := b.String()
	for _, want := range []string{
		"Server: Milano, IT (mil05)", "Download: 245 Mbit/s (306,0 MB in 10 s, fermato al limite di 250 MB)", "Upload:   48,2 Mbit/s",
		"Latenza a riposo: 12 ms (mediana, ping verso 1.1.1.1)", "Latenza durante il download: 38 ms (+26 ms; 95° percentile +40 ms), 2 sonde su 40 senza risposta entro 1 s",
		"Latenza durante l'upload: 140 ms (+128 ms", "bufferbloat): alta, +128 ms", "soglie di Polaris", "minimo verso il server: 9,2 ms",
		"ritrasmessi in download: 0,8 %", "passato dal proxy", "Ne.Me.Sys.", "valore legale", "2,5 Gbit/s",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("manca %q in:\n%s", want, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if len([]rune(line)) > 160 {
			t.Errorf("riga troppo lunga: %s", line)
		}
	}
	if strings.Contains(out, "almeno") || strings.Contains(out, "altro server") {
		t.Errorf("valori minimi o altro server senza motivo:\n%s", out)
	}
	// Coda oltre il secondo in upload: tutte le sonde senza risposta. Il
	// giudizio è "alta" con un valore minimo, non "contenuta" (solo download).
	r.ProbeTimeoutMs = 1000
	r.Download.Latency, r.Download.BloatMs, r.Download.BloatP95Ms = &scan.SpeedLatency{Sent: 40, Received: 40, MedianMs: f(27), P95Ms: f(30)}, f(15), f(18)
	r.Upload = &scan.SpeedDir{Mbps: 9.1, Bytes: 11_000_000, Ms: 9700, Source: "server", Server: &scan.SpeedServer{City: "Turin", Country: "IT", Site: "trn02"},
		Latency: &scan.SpeedLatency{Sent: 20, Received: 0, MedianMs: f(1000), P95Ms: f(1000), MedianAtLeast: true, P95AtLeast: true}, BloatMs: f(988), BloatP95Ms: f(988)}
	b.Reset()
	printSpeed(&b, r)
	out = b.String()
	for _, want := range []string{
		"Latenza durante l'upload: almeno 1000 ms (almeno +988 ms; 95° percentile almeno +988 ms), 20 sonde su 20 senza risposta entro 1 s",
		"bufferbloat): alta, almeno +988 ms", "la maggior parte delle sonde", "la coda supera probabilmente", "su un altro server di M-Lab: Torino, IT (trn02)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("manca %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "contenuta") {
		t.Errorf("coda oltre il secondo giudicata contenuta:\n%s", out)
	}
	// Upload non riuscito.
	r.Upload = &scan.SpeedDir{Error: "upload non riuscito: connessione interrotta"}
	b.Reset()
	printSpeed(&b, r)
	if !strings.Contains(b.String(), "Upload:   non riuscito: connessione interrotta") {
		t.Errorf("upload non riuscito:\n%s", b.String())
	}
	if got := bloatGrade(29.9) + "/" + bloatGrade(30) + "/" + bloatGrade(100) + "/" + bloatGrade(100.1); got != "contenuta/da migliorare/da migliorare/alta" {
		t.Errorf("soglie: %s", got)
	}
}

func TestSpeedTestNeedsConsent(t *testing.T) {
	// Senza --accetto si stampa il consenso e non si avvia nulla.
	out := capture(t, func() {
		if err := runSpeedTest(nil); err != nil {
			t.Fatal(err)
		}
	})
	for _, want := range []string{"Measurement Lab", "indirizzo IP pubblico", "https://www.measurementlab.net/privacy/", "https://www.measurementlab.net/aup/", "polaris-cli speedtest --accetto", "Ho letto e accetto"} {
		if !strings.Contains(out, want) {
			t.Errorf("manca %q in:\n%s", want, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if len([]rune(line)) > 78 {
			t.Errorf("riga oltre 78 colonne: %q", line)
		}
	}
	if out := capture(t, func() { _ = runSpeedTest([]string{"--json"}) }); !strings.Contains(out, "--accetto") {
		t.Errorf("--json senza --accetto: %s", out)
	}
	if err := runSpeedTest([]string{"altro"}); err == nil {
		t.Error("argomento in più accettato")
	}
}
