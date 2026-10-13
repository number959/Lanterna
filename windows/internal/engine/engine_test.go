package engine

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Usa il bundle prodotto da "npm run build" in core/: il test verifica che
// lo stesso file che finisce nell'exe giri correttamente in goja.
func load(t *testing.T) *Engine {
	src, err := os.ReadFile("../../../core/dist-engine/engine.js")
	if err != nil {
		t.Skip("engine.js non compilato: esegui prima npm run build in core/")
	}
	e, err := Load(src)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

const scanJSON = `{"schema":1,"agent":{"name":"STARNET Polaris","version":"t","platform":"windows","host":"PC","startedAt":"2026-10-12T20:00:00Z","durationMs":9000},
"adapters":[{"name":"Wi-Fi","kind":"wifi","up":true,"ipv4":["192.168.1.34/24"],"ipv6":[],"gateways":["192.168.1.1"],"dns":["192.168.1.1"]}],
"wifi":{"source":"wlanapi","connected":{"ssid":"Casa","bssid":"aa:bb:cc:00:00:01","signalQuality":40,"rxMbps":72,"txMbps":65,"phy":"802.11n"},
 "networks":[{"ssid":"Casa","bssid":"aa:bb:cc:00:00:01","rssiDbm":-78,"freqMhz":2437,"channel":6,"band":"2.4","widthMhz":20,"phy":"802.11n","connected":true,
   "security":{"protocol":"wpa2","akm":["PSK"],"pairwise":["CCMP","TKIP"],"pmf":"disabled"}}]},
"gateway":{"ip":"192.168.1.1","ping":{"target":"192.168.1.1","sent":20,"received":20,"avgMs":12.345,"minMs":3,"maxMs":40,"jitterMs":8.04}},
"errors":[{"probe":"UPnP","message":"nessuna risposta"}]}`

func TestReportInGoja(t *testing.T) {
	e := load(t)
	txt, err := e.Report([]byte(scanJSON), true)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"STARNET Polaris - rapporto", "Punteggio complessivo", "[CRIT] Potenza del segnale: -78 dBm", "Latenza verso il router: 12 ms", "(jitter): 8,0 ms", "PIANO D'AZIONE", "UPnP: nessuna risposta"} {
		if !strings.Contains(txt, want) {
			t.Errorf("manca %q nel rapporto:\n%s", want, txt)
		}
	}
}

func TestAnalyzeInGoja(t *testing.T) {
	e := load(t)
	out, err := e.Analyze([]byte(scanJSON))
	if err != nil {
		t.Fatal(err)
	}
	var a struct {
		Score    int `json:"score"`
		Findings []struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out, &a); err != nil {
		t.Fatal(err)
	}
	sev := map[string]string{}
	for _, f := range a.Findings {
		sev[f.ID] = f.Severity
	}
	if sev["wifi.rssi"] != "crit" || sev["wifi.security"] != "warn" || a.Score > 69 {
		t.Fatalf("analisi inattesa: punteggio %d, %v", a.Score, sev)
	}
}

func TestBadScript(t *testing.T) {
	if _, err := Load([]byte("var x = ;")); err == nil {
		t.Fatal("script non valido accettato")
	}
	if _, err := Load([]byte("var y = 1;")); err == nil {
		t.Fatal("script senza PolarisEngine accettato")
	}
}
