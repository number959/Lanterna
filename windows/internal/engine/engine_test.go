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
 "defender":{"mode":"normal","enabled":true,"realTime":true,"tamperProtected":false,"signatureVersion":"1.419.98.0","signatureUpdated":"2026-10-14T06:00:00Z"},
 "threats":[{"name":"Trojan:Win32/Wacatac.B!ml","severity":"severe","status":"failed","active":true,"detected":"2026-10-13T18:00:00Z"}],
 "hardware":{"vendor":"ASUSTeK","model":"PC","chassis":"desktop","firmware":"uefi","secureBoot":false,"tpm":"",
   "cpu":{"vendor":"AuthenticAMD","family":25,"model":33,"stepping":2,"cores":6,"threads":12,"coreClasses":[6],
     "caches":[{"level":1,"kind":"data","sizeKB":32,"count":6,"ways":8},{"level":3,"kind":"unified","sizeKB":32768,"count":1,"ways":16}],"features":["SSE4.2","POPCNT","AVX2"]},
   "memory":{"slots":4,"modules":[{"slot":"DIMM_A1","sizeGB":8,"type":"DDR4","form":"DIMM","speedMTs":3200,"configuredMTs":2133,"vendor":"04CD","part":"F4-3200C16-8GVKB"},
     {"slot":"DIMM_A2","sizeGB":8,"type":"DDR4","form":"DIMM","speedMTs":3200,"configuredMTs":2133,"vendor":"04CD","part":"F4-3200C16-8GVKB"}]}},
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
		"[ !! ] Canali della memoria: canale singolo",
		"[CRIT] Minacce rilevate da Defender: 1 da risolvere",
		"Trojan:Win32/Wacatac.B!ml (gravità grave): azione non",
		"Gestisci le minacce rilevate",
		"[ !! ] Avvio protetto (Secure Boot): disattivato",
		"Processore: AMD famiglia 25 modello 33 stepping 2; 6 core, 12 thread",
		"DIMM_A1: 8 GB DDR4 DIMM, 3200 MT/s (lavora a 2133), G.Skill",
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("manca %q nel rapporto:\n%s", want, txt)
		}
	}
}

// Il documento stampabile esce dal motore incorporato nell'exe (report --html).
func TestDocumentInGoja(t *testing.T) {
	e := load(t)
	html, err := e.Document([]byte(scanJSON), "0.7.0", "19/10/2026 alle 10:00")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`<!doctype html><html lang="it">`, "<h1>Stato della rete</h1>", "Da sistemare per primo", "Valutazione completa", "Potenza del segnale", "STARNET Polaris 0.7.0", "il 19/10/2026 alle 10:00", "@page{size:A4"} {
		if !strings.Contains(html, want) {
			t.Errorf("manca %q nel documento", want)
		}
	}
	// Il BSSID del Wi-Fi è un indirizzo MAC: non deve comparire.
	if strings.Contains(html, "aa:bb:cc:00:00:01") {
		t.Error("indirizzo MAC nel documento")
	}
}

// Le versioni dei driver hanno la forma di un indirizzo IPv4: il documento le
// riconosce dal testo intorno (callback di replace con la posizione, senza
// lookbehind) e non le scambia per indirizzi pubblici, anche in goja.
func TestDocumentDriverVersionsInGoja(t *testing.T) {
	e := load(t)
	scan := `{"schema":1,"agent":{"name":"STARNET Polaris","version":"t","platform":"windows","host":"PC","startedAt":"2026-10-12T20:00:00Z","durationMs":9000},
"adapters":[],"errors":[],"pc":{"devices":{"total":1,"problems":0,"items":[{"name":"Acme Wireless","class":"Net","enumerator":"PCI",
 "driver":{"provider":"Acme","version":"22.40.0.7","date":"2016-11-05","inf":"oem18.inf","file":"acmewlan.sys"}}]}}}`
	html, err := e.Document([]byte(scan), "0.12.0", "12/10/2026 alle 22:00")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(html, "Acme 22.40.0.7") || strings.Contains(html, "[IP pubblico]") {
		i := strings.Index(html, "Acme")
		t.Errorf("versione del driver alterata nel documento: %q", html[max(0, i-40):min(len(html), i+120)])
	}
}

// Scoperta delle reti in goja: annunci dello switch, SNMP, Active Directory e
// inventario di un'altra sottorete producono gli stessi giudizi del browser.
const discoveryJSON = `{"schema":1,"agent":{"name":"STARNET Polaris","version":"t","platform":"windows","host":"PC","startedAt":"2026-10-12T20:00:00Z","durationMs":9000,"domain":"studio.local"},
"adapters":[{"name":"Ethernet","kind":"ethernet","up":true,"ipv4":["10.1.20.34/24"],"ipv6":[],"gateways":["10.1.20.1"],"dns":["10.1.10.5"]}],
"gateway":{"ip":"10.1.20.1"},
"lan":{"neighbors":[],"routes":[{"prefix":"10.1.30.0/24","nextHop":"10.1.20.1","origin":"dhcp"}]},
"infra":{
 "discovery":{
  "l2":{"read":"ok","seconds":61,"frames":9,"counts":{"lldp":2,"cdp":0,"dtp":2,"stp":5,"vtp":0,"eapol":0,"other":0},
   "lldp":[{"chassisId":"00:11:22:33:44:55","chassisIdType":"mac","portId":"Gi0/7","portIdType":"interface-name","ttl":120,"systemName":"SW-UFFICI","portVlanId":1,"vlans":[{"id":1,"name":"default"}],"speedMbps":100,"duplex":"half","frames":2}],
   "dtp":[{"version":1,"operStatus":"access","adminStatus":"desirable","frames":2}],
   "stp":[{"format":"pvst","protocol":"stp","vlan":40,"rootPriority":32768,"rootSysIdExt":40,"rootMac":"00:11:22:33:44:00","rootPathCost":19,"bridgePriority":32768,"bridgeSysIdExt":40,"bridgeMac":"00:11:22:33:44:55","portPriority":128,"portNumber":7,"messageAge":1,"maxAge":20,"helloTime":2,"forwardDelay":15,"frames":5}]},
  "ad":{"read":"ok","subnets":[{"prefix":"10.1.10.0/24","site":"Sede"},{"prefix":"10.2.0.0/16","site":"Filiale"}]},
  "snmp":[{"target":"10.1.20.1","version":"2c","defaultCommunity":true,"startedAt":"2026-10-12T20:05:00Z","durationMs":3000,"requests":20,
   "system":{"name":"RTR-STUDIO"},
   "interfaces":[{"index":10,"name":"Vlan10","vlanId":10,"ips":[{"ip":"10.1.10.1","prefix":24,"subnet":"10.1.10.0/24"}]},{"index":20,"name":"Vlan20","vlanId":20,"ips":[{"ip":"10.1.20.1","prefix":24,"subnet":"10.1.20.0/24"}]},{"index":40,"name":"Vlan40","vlanId":40,"ips":[{"ip":"10.1.40.1","prefix":24,"subnet":"10.1.40.0/24"}]}],
   "vlans":[{"id":10,"name":"SERVER"},{"id":20,"name":"UFFICI"},{"id":40,"name":"TELECAMERE"}],
   "lldpNeighbors":[],"arp":[{"ifIndex":40,"ip":"10.1.40.21","mac":"bc:ad:28:00:00:21"}],"fdb":[],
   "sections":{"system":{"state":"ok","rows":1},"interfaces":{"state":"ok","rows":3},"vlans":{"state":"ok","rows":3},"lldp":{"state":"absent","rows":0},"arp":{"state":"ok","rows":1},"fdb":{"state":"absent","rows":0}}}]},
 "remote":[{"subnet":"10.1.40.0/24","scanned":254,"startedAt":"2026-10-12T20:06:00Z","durationMs":9000,"hosts":[{"ip":"10.1.40.21","rttMs":4}]}]},
"errors":[]}`

func TestDiscoveryInGoja(t *testing.T) {
	e := load(t)
	out, err := e.Analyze([]byte(discoveryJSON))
	if err != nil {
		t.Fatal(err)
	}
	var a struct {
		Findings []struct {
			ID       string   `json:"id"`
			Severity string   `json:"severity"`
			Verdict  string   `json:"verdict"`
			Actions  []string `json:"actions"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out, &a); err != nil {
		t.Fatal(err)
	}
	sev := map[string]string{}
	verdict := map[string]string{}
	for _, f := range a.Findings {
		sev[f.ID] = f.Severity
		verdict[f.ID] = f.Verdict
	}
	want := map[string]string{
		"lan.switchport":               "warn", // half duplex
		"lan.dtp":                      "warn", // dynamic desirable
		"lan.vlan1":                    "warn", // VLAN 1 con altre VLAN
		"lan.stp":                      "info",
		"lan.snmp.10.1.20.1":           "crit", // community predefinita
		"lan.vlans":                    "info",
		"infra.inventory.10.1.40.0/24": "info",
	}
	for id, s := range want {
		if sev[id] != s {
			t.Errorf("%s: gravità %q, attesa %q", id, sev[id], s)
		}
	}
	if !strings.Contains(verdict["lan.vlans"], "VLAN 40 TELECAMERE (10.1.40.0/24)") || !strings.Contains(verdict["lan.vlans"], "Active Directory") {
		t.Errorf("riepilogo delle reti: %s", verdict["lan.vlans"])
	}
	if !strings.Contains(verdict["lan.stp"], "classico") {
		t.Errorf("Spanning Tree: %s", verdict["lan.stp"])
	}
	txt, err := e.Report([]byte(discoveryJSON), true)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"Reti e VLAN scoperte", "Negoziazione del trunk (DTP)", "Spegni la negoziazione del trunk"} {
		if !strings.Contains(txt, w) {
			t.Errorf("manca %q nel rapporto", w)
		}
	}
}
