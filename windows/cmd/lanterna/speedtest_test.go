package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"lanterna/internal/scan"
	"lanterna/internal/speedtest"
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

// bloatCase: un caso condiviso con il motore (core/test/speedtest.test.ts):
// gli stessi dati devono dare lo stesso giudizio nella riga di comando, nel
// rapporto, nel documento e nell'interfaccia.
type bloatCase struct {
	Nome    string         `json:"nome"`
	Speed   scan.SpeedTest `json:"speed"`
	Grade   string         `json:"grade"`
	Worst   float64        `json:"worst"`
	AtLeast bool           `json:"atLeast"`
	Heavy   []struct {
		Dir                string
		Lost, Sent, Excess int
	} `json:"heavy"`
}

func bloatCases(t *testing.T) []bloatCase {
	t.Helper()
	b, err := os.ReadFile("../../internal/speedtest/testdata/bufferbloat.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx struct {
		Casi []bloatCase `json:"casi"`
	}
	if err := json.Unmarshal(b, &fx); err != nil || len(fx.Casi) < 6 {
		t.Fatalf("casi: %v (%d)", err, len(fx.Casi))
	}
	return fx.Casi
}

// Stesso giudizio del motore: soglie della mediana e, verso per verso, oltre
// il 10 % di sonde senza risposta (al netto di quelle perse a riposo) almeno
// "da migliorare", anche con la mediana sotto 30 ms.
func TestBloatGradeMatchesEngine(t *testing.T) {
	for _, c := range bloatCases(t) {
		var b bytes.Buffer
		printSpeed(&b, &c.Speed)
		flat := strings.Join(strings.Fields(b.String()), " ")
		least := ""
		if c.AtLeast {
			least = "almeno "
		}
		want := fmt.Sprintf("Latenza sotto carico (bufferbloat): %s, %s+%s nel caso peggiore", c.Grade, least, msText(c.Worst))
		if !strings.Contains(flat, want) {
			t.Errorf("%s: manca %q in:\n%s", c.Nome, want, b.String())
		}
		// Giudizio alzato dalle sonde senza risposta: il verso e i conteggi.
		if c.Grade == "da migliorare" && c.Worst < 30 {
			for _, h := range c.Heavy {
				if w := fmt.Sprintf("%d sonde su %d in %s", h.Excess, h.Sent, h.Dir); !strings.Contains(flat, w) {
					t.Errorf("%s: manca %q in:\n%s", c.Nome, w, b.String())
				}
			}
			if !strings.Contains(flat, "soglia di Polaris") {
				t.Errorf("%s: la regola del 10 %% non è detta scelta di Polaris:\n%s", c.Nome, b.String())
			}
		}
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

// polaris-cli speedtest --accetto rispetta gli stessi limiti dell'agente,
// con lo stato nello stesso file: entro due minuti rifiuta con un messaggio
// in italiano ed esce con codice 1, senza collegarsi a M-Lab. Un test che
// non ha raggiunto M-Lab non conta; un file rovinato non blocca il test.
func TestSpeedTestCLILimit(t *testing.T) {
	if path := os.Getenv("POLARIS_TEST_LIMITE"); path != "" {
		// Processo figlio: il programma vero, con il file dei limiti di prova
		// e senza rete (se il test partisse, esce con un codice diverso).
		speedLimitPath = func() string { return path }
		speedRun = func(context.Context, speedtest.Options) (*scan.SpeedTest, error) {
			fmt.Fprintln(os.Stderr, "il test è partito")
			os.Exit(3)
			return nil, nil
		}
		os.Args = []string{"polaris-cli", "speedtest", "--accetto"}
		main()
		os.Exit(0)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, speedtest.LimitFile)
	oldPath, oldRun := speedLimitPath, speedRun
	t.Cleanup(func() { speedLimitPath, speedRun = oldPath, oldRun })
	speedLimitPath = func() string { return path }
	calls := 0
	var fail error
	speedRun = func(context.Context, speedtest.Options) (*scan.SpeedTest, error) {
		calls++
		if fail != nil {
			return nil, fail
		}
		return &scan.SpeedTest{Provider: "mlab-ndt7", Download: &scan.SpeedDir{Mbps: 50, Bytes: 1, Ms: 1}}, nil
	}
	// Il proxy rifiuta: M-Lab non è stato raggiunto, il tentativo non conta.
	fail = speedtest.ErrProxyAuth
	if err := runSpeedTest([]string{"--accetto", "--json"}); !errors.Is(err, speedtest.ErrProxyAuth) {
		t.Fatalf("proxy: %v", err)
	}
	fail = nil
	if out := capture(t, func() {
		if err := runSpeedTest([]string{"--accetto", "--json"}); err != nil {
			t.Fatal(err)
		}
	}); calls != 2 || !strings.Contains(out, "mlab-ndt7") {
		t.Fatalf("test dopo il rifiuto del proxy: %d chiamate, %s", calls, out)
	}
	// Subito dopo: rifiutato, senza collegarsi.
	err := runSpeedTest([]string{"--accetto"})
	var le *speedtest.LimitError
	if !errors.As(err, &le) || !strings.Contains(err.Error(), "hai appena fatto un test di velocità: per non pesare sui server di M-Lab il prossimo si può avviare tra") || calls != 2 {
		t.Fatalf("entro due minuti: %v (%d chiamate)", err, calls)
	}
	// Il programma vero: messaggio in italiano e codice di uscita 1.
	cmd := exec.Command(os.Args[0], "-test.run=^TestSpeedTestCLILimit$")
	cmd.Env = append(os.Environ(), "POLARIS_TEST_LIMITE="+path)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 1 || !strings.Contains(stderr.String(), "Errore: hai appena fatto un test di velocità") {
		t.Fatalf("uscita %v, errore:\n%s", err, stderr.String())
	}
	// File rovinato: il test parte lo stesso e il file torna valido.
	bad := filepath.Join(dir, "rovinato.json")
	if err := os.WriteFile(bad, []byte("{non è JSON"), 0o600); err != nil {
		t.Fatal(err)
	}
	speedLimitPath = func() string { return bad }
	_ = capture(t, func() {
		if err := runSpeedTest([]string{"--accetto", "--json"}); err != nil {
			t.Fatalf("file rovinato: %v", err)
		}
	})
	if b, _ := os.ReadFile(bad); calls != 3 || !strings.Contains(string(b), `"count":1`) {
		t.Fatalf("file rovinato: %d chiamate, %s", calls, b)
	}
}
