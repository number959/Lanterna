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

// I dati del computer (date, eventi, dischi) passano dal motore in goja come
// nel browser: giudizi, date in italiano e dettagli nel rapporto.
func TestPcInGoja(t *testing.T) {
	e := load(t)
	scan := `{"schema":1,"agent":{"name":"STARNET Polaris","version":"t","platform":"windows","host":"PC","startedAt":"2026-10-14T09:00:00Z","durationMs":9000,"elevated":true},
"adapters":[],"errors":[],
"pc":{"os":{"name":"Windows 11 Home","version":"23H2","build":22631,"ubr":4460,"edition":"Core","uptimeSec":1800000,"fastStartup":true},
 "memory":{"totalMB":7962,"availableMB":600},
 "disks":[{"id":"0","name":"Samsung SSD 980","media":"ssd","bus":"NVMe","sizeGB":1000.2,"health":"warning","operational":["Predictive Failure"],"system":true,
   "reliability":{"temperatureC":38,"wearPct":91,"powerOnHours":5120},
   "nvme":{"criticalWarning":0,"temperatureC":38,"availableSparePct":100,"spareThresholdPct":10,"percentageUsed":91,"dataReadGB":6321,"dataWrittenGB":250120.5,
     "powerCycles":1234,"powerOnHours":5120,"unsafeShutdowns":37,"mediaErrors":0,"errorLogEntries":12,"warningTempMinutes":0,"criticalTempMinutes":0}},
  {"id":"1","name":"WDC WD10EZEX","media":"hdd","bus":"SATA","sizeGB":1000.2,"health":"healthy",
   "smart":[{"id":5,"flags":51,"current":200,"worst":200,"threshold":140,"raw":0},{"id":9,"flags":50,"current":60,"worst":60,"threshold":0,"raw":29511},
     {"id":194,"flags":34,"current":110,"worst":98,"threshold":0,"raw":37},{"id":197,"flags":50,"current":200,"worst":200,"threshold":0,"raw":2}]}],
 "volumes":[{"letter":"C:","kind":"fixed","sizeGB":999,"freeGB":4,"system":true,"disk":"0"}],
 "events":[{"kind":"bugcheck","source":"Microsoft-Windows-WER-SystemErrorReporting","id":1001,"count":2,"last":"2026-10-08T21:40:00Z","detail":"0x0000009f (0x3)"}],
 "eventsDays":30,"antivirus":[],"updates":{"lastInstalled":"2025-11-11","pendingReboot":false},
 "bench":{"cpu":{"startedAt":"2026-10-14T09:05:00Z","threads":8,"singleMBs":30,"multiMBs":120,"sustainedMBs":80,"durationMs":23000}}}}`
	txt, err := e.Report([]byte(scan), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"rapporto di diagnostica di PC e rete",
		"[CRIT] Salute del disco di sistema: Samsung SSD 980: Critico 9 %",
		"SMART: Critico (vita 9 %); riserva 100 %, scritti 250 TB",
		"[ !! ] Salute del disco 1: WDC WD10EZEX: Attenzione · 37 °C · 29.511 ore",
		"2 settori in attesa di riallocazione",
		"SMART: Attenzione; C5 Settori in attesa di riallocazione 2",
		"dall'11 novembre 2025",
		"l'ultima l'8 ottobre 2026",
		"DRIVER_POWER_STATE_FAILURE",
		"[CRIT] Antivirus: nessuno",
		"COMPUTER: DETTAGLI",
		"Copia subito i dati e sostituisci il disco",
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("manca %q nel rapporto:\n%s", want, txt)
		}
	}
}
