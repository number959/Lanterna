package engine

import (
	"encoding/json"
	"strings"
	"testing"
)

// Il test di velocità con M-Lab passa dal motore in goja come nel browser:
// giudizi, rapporto e documento, senza indirizzi IP.
func TestSpeedInGoja(t *testing.T) {
	e := load(t)
	scan := `{"schema":1,"agent":{"name":"STARNET Polaris","version":"t","platform":"windows","host":"PC","startedAt":"2026-10-31T09:00:00Z","durationMs":9000},
"adapters":[{"name":"Wi-Fi","kind":"wifi","up":true,"ipv4":["192.168.1.34/24"],"ipv6":[],"gateways":["192.168.1.1"],"dns":["192.168.1.1"]}],
"gateway":{"ip":"192.168.1.1"},"errors":[],
"internet":{"targets":[],"speed":{"startedAt":"2026-10-31T09:10:00Z","durationMs":27800,"provider":"mlab-ndt7",
 "server":{"city":"Milan","country":"IT","site":"mil05","machine":"mlab1-mil05.mlab-oti.measurement-lab.org"},"probe":"1.1.1.1","probeMethod":"icmp",
 "idle":{"sent":20,"received":20,"minMs":9.1,"medianMs":10.4,"p95Ms":12.2},
 "download":{"mbps":61.8,"bytes":77250000,"ms":10000,"source":"client","minRttMs":9.2,"retransPct":6.2,
   "latency":{"sent":40,"received":40,"medianMs":29.8,"p95Ms":41.6},"bloatMs":19.4,"bloatP95Ms":31.2},
 "upload":{"mbps":18.7,"bytes":23375000,"ms":10000,"source":"server",
   "latency":{"sent":40,"received":38,"medianMs":153,"p95Ms":198.8},"bloatMs":142.6,"bloatP95Ms":188.4,"error":"trasferimento interrotto (dial tcp 203.0.113.9:443)"}}}}`
	out, err := e.Analyze([]byte(scan))
	if err != nil {
		t.Fatal(err)
	}
	var a struct {
		Findings []struct {
			ID       string   `json:"id"`
			Severity string   `json:"severity"`
			Actions  []string `json:"actions"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out, &a); err != nil {
		t.Fatal(err)
	}
	sev := map[string]string{}
	for _, f := range a.Findings {
		sev[f.ID] = f.Severity
	}
	if sev["net.speed"] != "info" || sev["net.bufferbloat"] != "crit" || sev["net.speed.retrans"] != "info" {
		t.Fatalf("giudizi: %v", sev)
	}
	txt, err := e.Report([]byte(scan), true)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"[INFO] Velocità di Internet (M-Lab): download 61,8 · upload 18,7 Mbit/s",
		"[CRIT] Latenza sotto carico (bufferbloat): +19 ms in download · +143 ms in",
		"TEST DI VELOCITÀ DI INTERNET (M-LAB)",
		"Server M-Lab: Milano (mil05)",
		"Ne.Me.Sys.",
		"Riduci il bufferbloat con la gestione delle code (SQM) sul router",
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("manca %q nel rapporto:\n%s", want, txt)
		}
	}
	html, err := e.Document([]byte(scan), "t", "oggi")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(html, "<h2>Velocità di Internet</h2>") {
		t.Error("documento senza la sezione del test di velocità")
	}
	for _, doc := range []string{txt, html} {
		if strings.Contains(doc, "203.0.113.9") {
			t.Error("indirizzo IP nel rapporto o nel documento")
		}
	}

	// Coda oltre il secondo in upload: nessuna sonda ha risposto. Il giudizio
	// è alto con un valore minimo, anche se il download va bene.
	lost := strings.Replace(scan, `"latency":{"sent":40,"received":38,"medianMs":153,"p95Ms":198.8},"bloatMs":142.6,"bloatP95Ms":188.4,`,
		`"latency":{"sent":20,"received":0,"medianMs":1000,"p95Ms":1000,"medianAtLeast":true,"p95AtLeast":true},"bloatMs":989.6,"bloatP95Ms":989.6,`, 1)
	lost = strings.Replace(lost, `"probeMethod":"icmp",`, `"probeMethod":"icmp","probeTimeoutMs":1000,`, 1)
	txt, err = e.Report([]byte(lost), true)
	if err != nil {
		t.Fatal(err)
	}
	flat := strings.Join(strings.Fields(txt), " ")
	for _, want := range []string{
		"[CRIT] Latenza sotto carico (bufferbloat): +19 ms in download · almeno +990 ms in upload",
		"Latenza sotto carico: alta, almeno +990 ms in upload",
		"20 sonde su 20 senza risposta entro 1 s",
	} {
		if !strings.Contains(flat, want) {
			t.Errorf("manca %q nel rapporto:\n%s", want, txt)
		}
	}
}
