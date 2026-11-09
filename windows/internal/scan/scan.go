// Package scan definisce il contratto dati condiviso con il nucleo web
// (core/src/engine/types.ts). I nomi JSON devono restare identici: il motore
// di analisi legge esattamente questi campi.
package scan

const SchemaVersion = 1

type Scan struct {
	Schema   int           `json:"schema"`
	Agent    AgentInfo     `json:"agent"`
	Adapters []Adapter     `json:"adapters"`
	Wifi     *WifiData     `json:"wifi,omitempty"`
	Gateway  *GatewayData  `json:"gateway,omitempty"`
	Internet *InternetData `json:"internet,omitempty"`
	DNS      *DNSData      `json:"dns,omitempty"`
	LAN      *LANData      `json:"lan,omitempty"`
	Firewall *FirewallData `json:"firewall,omitempty"`
	// Infra contiene inventario e verifiche di raggiungibilità: non li produce
	// l'analisi automatica ma l'interfaccia, su richiesta esplicita, e li
	// unisce al rapporto perché finiscano nell'esportazione.
	Infra *InfraData `json:"infra,omitempty"`
	// PC descrive il computer: sistema, memoria, dischi, avvio, eventi. I test
	// di velocità (Bench) si eseguono su richiesta e li unisce l'interfaccia.
	PC     *PcData      `json:"pc,omitempty"`
	Errors []ProbeError `json:"errors"`
}

type AgentInfo struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Platform   string `json:"platform"`
	Host       string `json:"host,omitempty"`
	OS         string `json:"os,omitempty"`
	StartedAt  string `json:"startedAt"`
	DurationMs int64  `json:"durationMs"`
	Elevated   *bool  `json:"elevated,omitempty"`
	// Domain è il dominio DNS del PC (Active Directory), vuoto se il PC non è in un dominio.
	Domain string `json:"domain,omitempty"`
}

type ProbeError struct {
	Probe   string `json:"probe"`
	Message string `json:"message"`
}

type Adapter struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Kind        string   `json:"kind"` // wifi | ethernet | loopback | virtual | other
	MAC         string   `json:"mac,omitempty"`
	Up          bool     `json:"up"`
	IPv4        []string `json:"ipv4"`
	IPv6        []string `json:"ipv6"`
	Gateways    []string `json:"gateways"`
	DNS         []string `json:"dns"`
	DHCP        *bool    `json:"dhcp,omitempty"`
	MTU         int      `json:"mtu,omitempty"`
	LinkMbps    int64    `json:"linkMbps,omitempty"`
	DNSSuffix   string   `json:"dnsSuffix,omitempty"`  // suffisso DNS della connessione (es. clinica.local)
	DHCPServer  string   `json:"dhcpServer,omitempty"` // server DHCP che ha assegnato l'indirizzo IPv4
}

type WifiSecurity struct {
	Protocol string   `json:"protocol"`
	AKM      []string `json:"akm"`
	Pairwise []string `json:"pairwise"`
	Group    string   `json:"group,omitempty"`
	PMF      string   `json:"pmf,omitempty"`
	WPS      bool     `json:"wps,omitempty"`
}

// Roaming: funzioni di roaming assistito annunciate nel beacon.
type Roaming struct {
	K        bool   `json:"k"`
	V        bool   `json:"v"`
	R        bool   `json:"r"`
	MDID     string `json:"mdid,omitempty"`
	FTOverDS bool   `json:"ftOverDs,omitempty"`
}

type BssLoad struct {
	Stations       int `json:"stations"`
	UtilizationPct int `json:"utilizationPct"`
}

type Bss struct {
	SSID          string        `json:"ssid"`
	BSSID         string        `json:"bssid"`
	RssiDbm       int           `json:"rssiDbm"`
	FreqMhz       int           `json:"freqMhz"`
	Channel       int           `json:"channel"`
	Band          string        `json:"band"`
	WidthMhz      int           `json:"widthMhz"`
	CenterChannel int           `json:"centerChannel,omitempty"`
	Phy           string        `json:"phy,omitempty"`
	BssLoad       *BssLoad      `json:"bssLoad,omitempty"`
	Security      *WifiSecurity `json:"security,omitempty"`
	Country       string        `json:"country,omitempty"`
	Roaming       *Roaming      `json:"roaming,omitempty"` // assente se Windows non ha fornito gli elementi del beacon
	Connected     bool          `json:"connected,omitempty"`
}

type WifiConnection struct {
	Interface     string `json:"interface,omitempty"`
	SSID          string `json:"ssid"`
	BSSID         string `json:"bssid,omitempty"`
	SignalQuality *int   `json:"signalQuality,omitempty"`
	RssiDbm       *int   `json:"rssiDbm,omitempty"`
	RxMbps        int    `json:"rxMbps,omitempty"`
	TxMbps        int    `json:"txMbps,omitempty"`
	Phy           string `json:"phy,omitempty"`
	Band          string `json:"band,omitempty"`
	Channel       int    `json:"channel,omitempty"`
	WidthMhz      int    `json:"widthMhz,omitempty"`
	Auth          string `json:"auth,omitempty"`
	Cipher        string `json:"cipher,omitempty"`
}

// NoWifiAdapter è l'errore Wi-Fi di un PC senza scheda Wi-Fi: non è una
// misura fallita ma una sezione non applicabile.
const NoWifiAdapter = "nessuna scheda Wi-Fi presente"

type WifiData struct {
	Source    string          `json:"source"`
	Connected *WifiConnection `json:"connected,omitempty"`
	Networks  []Bss           `json:"networks"`
	Error     string          `json:"error,omitempty"`
	// Survey è la mappa del Wi-Fi per stanza: l'analisi automatica non la
	// produce mai, la compila l'interfaccia una misura alla volta.
	Survey *WifiSurvey `json:"survey,omitempty"`
}

// ---------- mappa del Wi-Fi per stanza ----------

// WifiSurvey raccoglie le misure fatte stanza per stanza con questo PC.
type WifiSurvey struct {
	Rooms []SurveyRoom `json:"rooms"`
}

// SurveyRoom è una stanza (nome di luogo scelto dall'utente) con uno o più
// punti misurati: il giudizio della stanza è quello del punto peggiore.
type SurveyRoom struct {
	Name    string         `json:"name"`
	Samples []SurveySample `json:"samples"`
}

// SurveySample è una misura di 10-20 secondi fatta restando fermi in un
// punto. I BSSID sono solo quelli della rete a cui il PC è collegato e
// servono per la vista locale; le reti dei vicini compaiono solo come
// conteggi, canali e dBm, mai con nome o BSSID.
type SurveySample struct {
	Room       string `json:"room"`
	StartedAt  string `json:"startedAt"`
	DurationMs int64  `json:"durationMs"`
	Seconds    int    `json:"seconds"`
	SSID       string `json:"ssid"`
	Band       string `json:"band,omitempty"`
	Channel    int    `json:"channel,omitempty"`
	WidthMhz   int    `json:"widthMhz,omitempty"`
	Phy        string `json:"phy,omitempty"`
	// Rssi: segnale ricevuto dal PC, una lettura al secondo (dBm).
	Rssi      []int   `json:"rssi"`
	MedianDbm float64 `json:"medianDbm"`
	MinDbm    int     `json:"minDbm"`
	MaxDbm    int     `json:"maxDbm"`
	P10Dbm    int     `json:"p10Dbm"`
	SpreadDb  int     `json:"spreadDb"`
	// Stuck: tutte le letture identiche, la scheda forse non aggiorna il
	// valore ogni secondo: instabilità e cali non sono valutabili.
	Stuck bool `json:"stuck,omitempty"`
	// Estimated: la scheda non fornisce il segnale in dBm e i valori sono
	// ricavati dalla qualità del segnale riportata da Windows (0-100 da -100
	// a -50 dBm, interpolazione lineare documentata da Microsoft).
	Estimated bool `json:"estimated,omitempty"`
	// Velocità radio negoziate (mediana, Mbit/s).
	RxMbps int `json:"rxMbps,omitempty"`
	TxMbps int `json:"txMbps,omitempty"`
	// BSSIDs: access point della propria rete a cui il PC è stato collegato
	// durante la misura, nell'ordine; Roams: i passaggi dall'uno all'altro.
	BSSIDs  []string     `json:"bssids"`
	Roams   []SurveyRoam `json:"roams"`
	Gateway *SurveyPing  `json:"gateway,omitempty"`
	// Scan: la scansione fatta dopo la misura (assente se esclusa).
	Scan  *SurveyScan `json:"scan,omitempty"`
	Notes []string    `json:"notes,omitempty"`
}

// SurveyRoam è un cambio di access point durante la misura.
type SurveyRoam struct {
	AtMs    int64  `json:"atMs"`
	From    string `json:"from"`
	To      string `json:"to"`
	FromDbm *int   `json:"fromDbm,omitempty"`
	ToDbm   *int   `json:"toDbm,omitempty"`
}

// SurveyPing sono i ping al router (gateway IPv4) durante la misura, ogni
// 200 ms, solo se il suo indirizzo è privato o link-local. Jitter: media
// delle differenze assolute tra tempi consecutivi (IPDV, RFC 5481).
type SurveyPing struct {
	Target   string   `json:"target,omitempty"`
	Sent     int      `json:"sent"`
	Received int      `json:"received"`
	LossPct  float64  `json:"lossPct"`
	MedianMs *float64 `json:"medianMs,omitempty"`
	P95Ms    *float64 `json:"p95Ms,omitempty"`
	JitterMs *float64 `json:"jitterMs,omitempty"`
	// Skipped: perché il router non è stato misurato.
	Skipped string `json:"skipped,omitempty"`
	Error   string `json:"error,omitempty"`
	// NoReply: i ping sono partiti ma il router non ha risposto a nessuno.
	// Molti router e firewall ignorano i ping: da soli non sono perdite.
	NoReply bool `json:"noReply,omitempty"`
}

// SurveyScan è ciò che una scansione dopo la misura dice di quel punto.
// Le voci sentite più di 10 secondi prima si scartano (Stale).
type SurveyScan struct {
	Fresh int `json:"fresh"`
	Stale int `json:"stale"`
	// La rete collegata vista dalla scansione.
	ConnectedDbm   *int `json:"connectedDbm,omitempty"`
	UtilizationPct *int `json:"utilizationPct,omitempty"`
	Stations       *int `json:"stations,omitempty"`
	// Alternatives: il miglior altro access point della stessa rete per banda.
	Alternatives []SurveyAlt     `json:"alternatives,omitempty"`
	Neighbors    SurveyNeighbors `json:"neighbors"`
	Error        string          `json:"error,omitempty"`
}

// SurveyAlt è un altro access point della propria rete (stesso SSID).
type SurveyAlt struct {
	BSSID   string `json:"bssid"`
	Band    string `json:"band"`
	Channel int    `json:"channel"`
	RssiDbm int    `json:"rssiDbm"`
}

// SurveyNeighbors riassume le reti dei vicini, senza nomi né BSSID.
type SurveyNeighbors struct {
	// Visible: altre reti sentite, su tutte le bande.
	Visible int `json:"visible"`
	// Cochannel: reti che occupano lo stesso spettro della rete collegata;
	// Strong quelle sopra -75 dBm; Channels i loro canali.
	Cochannel    int   `json:"cochannel"`
	Strong       int   `json:"strong"`
	StrongestDbm *int  `json:"strongestDbm,omitempty"`
	Channels     []int `json:"channels,omitempty"`
}

type PingStats struct {
	Target   string     `json:"target"`
	Label    string     `json:"label,omitempty"`
	Sent     int        `json:"sent"`
	Received int        `json:"received"`
	MinMs    *float64   `json:"minMs,omitempty"`
	AvgMs    *float64   `json:"avgMs,omitempty"`
	MaxMs    *float64   `json:"maxMs,omitempty"`
	JitterMs *float64   `json:"jitterMs,omitempty"`
	Samples  []*float64 `json:"samples,omitempty"`
	Method   string     `json:"method,omitempty"`
	Error    string     `json:"error,omitempty"`
}

type PortCheck struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
	Open    bool   `json:"open"`
}

type UpnpDevice struct {
	FriendlyName string `json:"friendlyName,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	ModelName    string `json:"modelName,omitempty"`
	ModelNumber  string `json:"modelNumber,omitempty"`
	Server       string `json:"server,omitempty"`
	Location     string `json:"location,omitempty"`
	DeviceType   string `json:"deviceType,omitempty"`
}

type UpnpData struct {
	Found      bool         `json:"found"`
	IGD        bool         `json:"igd"`
	Devices    []UpnpDevice `json:"devices"`
	ExternalIP string       `json:"externalIp,omitempty"`
}

type RouterWeb struct {
	Server string `json:"server,omitempty"`
	Title  string `json:"title,omitempty"`
	HTTPS  bool   `json:"https,omitempty"`
}

type GatewayData struct {
	IP    string      `json:"ip"`
	MAC   string      `json:"mac,omitempty"`
	Ping  *PingStats  `json:"ping,omitempty"`
	Ports []PortCheck `json:"ports,omitempty"`
	Upnp  *UpnpData   `json:"upnp,omitempty"`
	Web   *RouterWeb  `json:"web,omitempty"`
}

type Hop struct {
	TTL   int      `json:"ttl"`
	IP    string   `json:"ip,omitempty"`
	RttMs *float64 `json:"rttMs,omitempty"`
}

type MtuResult struct {
	MTU    int    `json:"mtu"`
	Method string `json:"method"`
}

type HTTPCheck struct {
	URL    string   `json:"url"`
	OK     bool     `json:"ok"`
	Status int      `json:"status,omitempty"`
	TimeMs *float64 `json:"timeMs,omitempty"`
	Error  string   `json:"error,omitempty"`
}

type InternetData struct {
	Targets     []PingStats `json:"targets"`
	Traceroute  []Hop       `json:"traceroute,omitempty"`
	TraceTarget string      `json:"traceTarget,omitempty"`
	MTU         *MtuResult  `json:"mtu,omitempty"`
	HTTP        []HTTPCheck `json:"http,omitempty"`
	// Speed è il test di velocità con M-Lab: non lo esegue l'analisi
	// automatica ma l'utente, su richiesta e dopo il consenso; lo unisce
	// l'interfaccia, come i test del PC.
	Speed *SpeedTest `json:"speed,omitempty"`
}

// SpeedTest è il test di velocità di Internet con Measurement Lab (M-Lab,
// protocollo ndt7): una connessione per verso verso un server scelto da
// M-Lab, con la latenza misurata a riposo e durante i trasferimenti. Non
// contiene mai l'indirizzo IP del PC, la porta né l'identificativo del test
// che il server comunica.
type SpeedTest struct {
	StartedAt  string `json:"startedAt"`
	DurationMs int64  `json:"durationMs"`
	// Provider: "mlab-ndt7".
	Provider string       `json:"provider"`
	Server   *SpeedServer `json:"server,omitempty"`
	// Probe: server pubblico delle misure di latenza ("1.1.1.1"); ProbeMethod
	// "icmp" o "tcp" (connessioni TCP quando i ping sono bloccati).
	Probe       string `json:"probe,omitempty"`
	ProbeMethod string `json:"probeMethod,omitempty"`
	// ProbeTimeoutMs: quanto una sonda aspetta la risposta (1000). Durante i
	// trasferimenti una sonda senza risposta conta come latenza di almeno
	// questo valore (vedi SpeedLatency).
	ProbeTimeoutMs int `json:"probeTimeoutMs,omitempty"`
	// Idle: latenza a riposo, prima dei trasferimenti.
	Idle     *SpeedLatency `json:"idle,omitempty"`
	Download *SpeedDir     `json:"download,omitempty"`
	Upload   *SpeedDir     `json:"upload,omitempty"`
	// ViaProxy: il test è passato da un proxy (misura il percorso del proxy).
	ViaProxy bool `json:"viaProxy,omitempty"`
	// Simulated: risultato simulato dall'interfaccia nelle demo (mai dall'agente).
	Simulated bool `json:"simulated,omitempty"`
}

// SpeedServer è il server di M-Lab usato, come lo indica il servizio Locate.
type SpeedServer struct {
	City    string `json:"city,omitempty"`    // in inglese, come la dà M-Lab ("Milan")
	Country string `json:"country,omitempty"` // codice ISO ("IT")
	Site    string `json:"site,omitempty"`    // sito di M-Lab ("mil05")
	Machine string `json:"machine,omitempty"` // nome pubblico del server
}

// SpeedLatency riassume le misure di latenza di una fase; i campioni senza
// risposta contano in Sent ma non in Received. A riposo mediana e 95°
// percentile sono quelli delle risposte. Durante i trasferimenti, se a
// riposo le sonde rispondevano, una sonda senza risposta conta come latenza
// pari all'attesa della sonda (SpeedTest.ProbeTimeoutMs), tolta la quota
// persa anche a riposo: MedianAtLeast e P95AtLeast dicono che il valore cade
// su sonde senza risposta, quindi è un minimo ("almeno").
type SpeedLatency struct {
	Sent          int      `json:"sent"`
	Received      int      `json:"received"`
	MinMs         *float64 `json:"minMs,omitempty"`
	MedianMs      *float64 `json:"medianMs,omitempty"`
	P95Ms         *float64 `json:"p95Ms,omitempty"`
	MedianAtLeast bool     `json:"medianAtLeast,omitempty"`
	P95AtLeast    bool     `json:"p95AtLeast,omitempty"`
}

// SpeedDir è un verso del test (download o upload). Mbps è il goodput,
// cioè i dati utili al secondo; Bytes e Ms sono i valori da cui si calcola.
type SpeedDir struct {
	Mbps  float64 `json:"mbps"`
	Bytes int64   `json:"bytes"`
	Ms    int64   `json:"ms"`
	// Source: "client" (byte contati dal PC, senza le intestazioni di TLS e
	// WebSocket) o "server" (in upload: byte ricevuti dal server nel tempo
	// del server, dal suo TCP_INFO; comprendono le intestazioni di TLS e
	// WebSocket, di solito meno dell'1 %). In upload i byte scritti dal PC
	// comprenderebbero anche quelli ancora in coda quando smette di inviare.
	Source string `json:"source,omitempty"`
	// Server: il server di questo verso, solo se diverso da SpeedTest.Server
	// (l'upload passa a un altro server quando M-Lab non propone più quello
	// del download).
	Server *SpeedServer `json:"server,omitempty"`
	// Capped: il trasferimento si è fermato al limite di dati (250 MB).
	Capped bool `json:"capped,omitempty"`
	// Dal TCP_INFO del server: RTT minimo e medio, ritrasmissioni (solo download).
	MinRTTMs   *float64 `json:"minRttMs,omitempty"`
	RTTMs      *float64 `json:"rttMs,omitempty"`
	RetransPct *float64 `json:"retransPct,omitempty"`
	// Latency: latenza misurata durante il trasferimento; BloatMs e
	// BloatP95Ms la latenza aggiunta rispetto al riposo (mediana e 95°
	// percentile meno la mediana a riposo): sono valori minimi quando lo
	// sono quelli di Latency (MedianAtLeast, P95AtLeast).
	Latency    *SpeedLatency `json:"latency,omitempty"`
	BloatMs    *float64      `json:"bloatMs,omitempty"`
	BloatP95Ms *float64      `json:"bloatP95Ms,omitempty"`
	Error      string        `json:"error,omitempty"`
}

type DNSServerResult struct {
	Server string   `json:"server"`
	Label  string   `json:"label,omitempty"`
	OK     bool     `json:"ok"`
	TimeMs *float64 `json:"timeMs,omitempty"`
	Error  string   `json:"error,omitempty"`
}

type DNSData struct {
	System []DNSServerResult `json:"system"`
	Public []DNSServerResult `json:"public"`
}

type Neighbor struct {
	IP  string `json:"ip"`
	MAC string `json:"mac,omitempty"`
}

type LANData struct {
	Neighbors []Neighbor `json:"neighbors"`
}

type FirewallProfile struct {
	Name    string `json:"name"` // domain | private | public
	Enabled *bool  `json:"enabled"`
	Active  bool   `json:"active,omitempty"`
}

type FirewallData struct {
	Source   string            `json:"source"`
	Profiles []FirewallProfile `json:"profiles"`
}

// ---------------------------------------------------------------- infrastruttura

// InventoryHost è un dispositivo trovato nella sottorete del PC.
type InventoryHost struct {
	IP        string   `json:"ip"`
	MAC       string   `json:"mac,omitempty"`
	RandomMAC bool     `json:"randomMac,omitempty"` // indirizzo amministrato localmente (MAC casuale o virtuale)
	Name      string   `json:"name,omitempty"`      // DNS inverso
	NetBIOS   string   `json:"netbios,omitempty"`
	RttMs     *float64 `json:"rttMs,omitempty"` // assente = non ha risposto al ping (visto solo via ARP)
	Self      bool     `json:"self,omitempty"`
	Gateway   bool     `json:"gateway,omitempty"`
}

// Inventory è il censimento della sottorete locale.
type Inventory struct {
	Subnet     string          `json:"subnet"` // sottorete esaminata (CIDR)
	Adapter    string          `json:"adapter,omitempty"`
	Scanned    int             `json:"scanned"` // indirizzi interrogati
	Note       string          `json:"note,omitempty"`
	StartedAt  string          `json:"startedAt"`
	DurationMs int64           `json:"durationMs"`
	Hosts      []InventoryHost `json:"hosts"`
}

// ReachTarget è una destinazione da verificare: Port 0 = solo ping.
// Expect vale "reachable" (servizio critico: deve rispondere) oppure
// "isolated" (segmentazione: da questa rete non deve rispondere).
type ReachTarget struct {
	Label  string `json:"label,omitempty"`
	Host   string `json:"host"`
	Port   int    `json:"port,omitempty"`
	Expect string `json:"expect"`
}

// ReachResult: Status è open | closed | filtered (porta TCP), reply |
// noreply (ping), unresolved (nome non risolto) o refused (destinazione non
// ammessa: solo indirizzi privati).
type ReachResult struct {
	ReachTarget
	IP     string   `json:"ip,omitempty"`
	Status string   `json:"status"`
	RttMs  *float64 `json:"rttMs,omitempty"`
	OK     bool     `json:"ok"`
	Error  string   `json:"error,omitempty"`
}

type ReachData struct {
	StartedAt string        `json:"startedAt"`
	From      string        `json:"from,omitempty"` // indirizzo del PC al momento della verifica
	Results   []ReachResult `json:"results"`
}

// Assessment è l'autovalutazione delle misure organizzative: la compila
// l'utente nell'interfaccia, l'agente non la produce mai.
type Assessment struct {
	// Risposte per domanda: "yes", "partial", "no" o "na".
	Answers   map[string]string `json:"answers"`
	UpdatedAt string            `json:"updatedAt,omitempty"`
}

type InfraData struct {
	Inventory  *Inventory  `json:"inventory,omitempty"`
	Reach      *ReachData  `json:"reach,omitempty"`
	Certs      *CertData   `json:"certs,omitempty"`
	Assessment *Assessment `json:"assessment,omitempty"`
}

// CertTarget è un servizio di cui controllare il certificato TLS: un nome o
// un indirizzo della rete locale (anche un indirizzo https://...), con la
// porta (443 se manca).
type CertTarget struct {
	Label string `json:"label,omitempty"`
	Host  string `json:"host"`
	Port  int    `json:"port,omitempty"`
}

// CertData raccoglie i certificati dei servizi indicati dall'utente.
type CertData struct {
	CheckedAt string       `json:"checkedAt"`
	Results   []CertResult `json:"results"`
}

// CertResult è il certificato presentato da un servizio e come lo vede
// questo PC. Le date sono RFC 3339; DaysLeft è negativo se è scaduto.
type CertResult struct {
	CertTarget
	IP    string `json:"ip,omitempty"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	// StartTLS: protocollo usato prima della cifratura ("smtp").
	StartTLS   string `json:"starttls,omitempty"`
	TLSVersion string `json:"tlsVersion,omitempty"`
	Cipher     string `json:"cipher,omitempty"`
	// LegacyOnly: il servizio offre solo TLS 1.0 o 1.1; LegacyToo: li
	// accetta oltre a TLS 1.2 o 1.3.
	LegacyOnly bool `json:"legacyOnly,omitempty"`
	LegacyToo  bool `json:"legacyToo,omitempty"`
	// ClientCert: il servizio chiede anche un certificato al client (TLS
	// reciproco, per esempio un PACS DICOM).
	ClientCert   bool     `json:"clientCert,omitempty"`
	Subject      string   `json:"subject,omitempty"`
	Org          string   `json:"org,omitempty"`
	Issuer       string   `json:"issuer,omitempty"`
	IssuerOrg    string   `json:"issuerOrg,omitempty"`
	DNSNames     []string `json:"dnsNames,omitempty"`
	IPs          []string `json:"ips,omitempty"`
	NotBefore    string   `json:"notBefore,omitempty"`
	NotAfter     string   `json:"notAfter,omitempty"`
	DaysLeft     int      `json:"daysLeft"`
	LifetimeDays int      `json:"lifetimeDays,omitempty"`
	KeyType      string   `json:"keyType,omitempty"`
	KeyBits      int      `json:"keyBits,omitempty"`
	SigAlg       string   `json:"sigAlg,omitempty"`
	// WeakSig: firma con SHA-1 o MD5.
	WeakSig    bool `json:"weakSig,omitempty"`
	SelfSigned bool `json:"selfSigned,omitempty"`
	// NameMatch: il nome o l'indirizzo usato è tra quelli del certificato;
	// CNOnly: il certificato ha solo il Common Name, senza nomi alternativi.
	NameMatch bool `json:"nameMatch"`
	CNOnly    bool `json:"cnOnly,omitempty"`
	ChainLen  int  `json:"chainLen,omitempty"`
	// Trust: come lo valuta Windows su questo PC, senza scaricare nulla:
	// trusted, untrusted-root, partial-chain, invalid-signature, wrong-usage,
	// distrusted; vuoto se non verificabile (fuori da Windows).
	Trust       string `json:"trust,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"` // SHA-256 del certificato
}

// ---------- PC ----------

type PcData struct {
	OS        *PcOS          `json:"os,omitempty"`
	CPU       *PcCPU         `json:"cpu,omitempty"`
	Memory    *PcMemory      `json:"memory,omitempty"`
	GPUs      []PcGPU        `json:"gpus,omitempty"`
	Disks     []PhysicalDisk `json:"disks,omitempty"`
	Volumes   []Volume       `json:"volumes,omitempty"`
	Battery   *Battery       `json:"battery,omitempty"`
	Power     *PowerInfo     `json:"power,omitempty"`
	Startup   []StartupItem  `json:"startup,omitempty"`
	Processes []ProcessInfo  `json:"processes,omitempty"`
	// Events raggruppa gli eventi rilevanti del registro di sistema degli
	// ultimi EventsDays giorni. EventsDays vale zero se il registro non è
	// stato letto: così un elenco vuoto (omesso) significa "nessun evento".
	Events     []EventGroup `json:"events,omitempty"`
	EventsDays int          `json:"eventsDays,omitempty"`
	// Antivirus è null se il Centro sicurezza non è leggibile, [] se non
	// risulta alcun prodotto registrato.
	Antivirus []AvProduct `json:"antivirus"`
	// Defender è lo stato di Microsoft Defender (assente se non leggibile);
	// Threats le minacce della sua cronologia: null se non lette, [] se nessuna.
	Defender *DefenderInfo `json:"defender,omitempty"`
	Threats  []Threat      `json:"threats"`
	Updates  *UpdateInfo   `json:"updates,omitempty"`
	// Hardware è la scheda tecnica, come in CPU-Z.
	Hardware *Hardware  `json:"hardware,omitempty"`
	Bench    *BenchData `json:"bench,omitempty"`
	// Space è l'analisi di ciò che occupa spazio, un rapporto per unità: si
	// esegue su richiesta e la unisce l'interfaccia, come i test di velocità.
	Space []SpaceReport `json:"space,omitempty"`
	// Crashes sono le schermate blu lette dai file di Windows (minidump) e le
	// impostazioni con cui Windows li salva; nil se non lette.
	Crashes *CrashData `json:"crashes,omitempty"`
	// Devices è lo stato dei dispositivi e dei loro driver, come Gestione
	// dispositivi; nil se non letto.
	Devices *DevicesData `json:"devices,omitempty"`
	// Boot è la durata di avvio e spegnimento misurata da Windows; Apps i
	// programmi che si sono chiusi da soli o bloccati; Reliability l'indice
	// di stabilità di Monitoraggio affidabilità. nil se non letti.
	Boot        *BootPerf    `json:"boot,omitempty"`
	Apps        *AppFailures `json:"apps,omitempty"`
	Reliability *Reliability `json:"reliability,omitempty"`
	// MemDiag è l'esito di Diagnostica memoria Windows; FsChecks i controlli
	// del file system degli ultimi EventsDays giorni (nil se non letti).
	MemDiag  *MemDiagInfo `json:"memDiag,omitempty"`
	FsChecks []FsCheck    `json:"fsChecks"`
	// Encryption è lo stato di BitLocker e della crittografia del
	// dispositivo; Backup punti di ripristino e backup di Windows;
	// Accounts gli account locali (senza nomi); Access accesso automatico,
	// Desktop remoto, Controllo account utente e blocco dello schermo;
	// Printing stampanti e servizio di stampa. nil se non letti.
	Encryption *EncryptionInfo `json:"encryption,omitempty"`
	Backup     *BackupInfo     `json:"backup,omitempty"`
	Accounts   *AccountsInfo   `json:"accounts,omitempty"`
	Access     *AccessInfo     `json:"access,omitempty"`
	Printing   *PrintingInfo   `json:"printing,omitempty"`
	// Notes spiega i limiti della raccolta (dati SMART solo da amministratore...).
	Notes []string `json:"notes,omitempty"`
}

type PcOS struct {
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"` // es. "24H2"
	Build       int    `json:"build,omitempty"`
	UBR         int    `json:"ubr,omitempty"`
	Edition     string `json:"edition,omitempty"` // EditionID, es. "Professional"
	Arch        string `json:"arch,omitempty"`
	InstallDate string `json:"installDate,omitempty"`
	BootTime    string `json:"bootTime,omitempty"`
	UptimeSec   int64  `json:"uptimeSec,omitempty"`
	Server      bool   `json:"server,omitempty"`
	FastStartup *bool  `json:"fastStartup,omitempty"`
}

type PcCPU struct {
	Name    string `json:"name"`
	Cores   int    `json:"cores,omitempty"`
	Threads int    `json:"threads,omitempty"`
	MaxMHz  int    `json:"maxMhz,omitempty"`
	// LoadPct è il carico medio misurato per circa un secondo durante l'analisi.
	LoadPct *float64 `json:"loadPct,omitempty"`
}

type PcMemory struct {
	TotalMB       int64 `json:"totalMB"`
	AvailableMB   int64 `json:"availableMB"`
	CommitMB      int64 `json:"commitMB,omitempty"`
	CommitLimitMB int64 `json:"commitLimitMB,omitempty"`
}

type PcGPU struct {
	Name          string `json:"name"`
	DriverVersion string `json:"driverVersion,omitempty"`
	DriverDate    string `json:"driverDate,omitempty"` // AAAA-MM-GG
	VRAMMB        int    `json:"vramMB,omitempty"`
	// Width, Height e RefreshHz descrivono lo schermo collegato in questo momento.
	Width     int `json:"width,omitempty"`
	Height    int `json:"height,omitempty"`
	RefreshHz int `json:"refreshHz,omitempty"`
}

// Hardware è la scheda tecnica del computer. Nessun numero di serie: i
// rapporti esportati non devono identificare la macchina.
type Hardware struct {
	Vendor string `json:"vendor,omitempty"` // produttore del computer
	Model  string `json:"model,omitempty"`
	// Chassis: desktop | laptop | workstation | server | tablet | other.
	Chassis string    `json:"chassis,omitempty"`
	Board   *HwBoard  `json:"board,omitempty"`
	CPU     *HwCPU    `json:"cpu,omitempty"`
	Memory  *HwMemory `json:"memory,omitempty"`
	// Firmware: uefi | bios (avvio legacy).
	Firmware   string `json:"firmware,omitempty"`
	SecureBoot *bool  `json:"secureBoot,omitempty"`
	// TPM è la versione del chip di sicurezza ("2.0", "1.2"); "" se non
	// risulta alcun TPM; nil se non è stato possibile verificarlo.
	TPM        *string `json:"tpm,omitempty"`
	Hypervisor bool    `json:"hypervisor,omitempty"`
}

type HwBoard struct {
	Vendor      string `json:"vendor,omitempty"`
	Product     string `json:"product,omitempty"`
	Version     string `json:"version,omitempty"`
	BiosVendor  string `json:"biosVendor,omitempty"`
	BiosVersion string `json:"biosVersion,omitempty"`
	BiosDate    string `json:"biosDate,omitempty"` // AAAA-MM-GG
}

type HwCPU struct {
	Vendor   string `json:"vendor,omitempty"` // GenuineIntel, AuthenticAMD...
	Family   int    `json:"family,omitempty"`
	Model    int    `json:"model,omitempty"`
	Stepping int    `json:"stepping,omitempty"`
	Socket   string `json:"socket,omitempty"`
	// BusMHz è la frequenza esterna (BCLK) nominale dichiarata dal firmware
	// (SMBIOS, Win32_Processor.ExternalClock): non è misurata.
	BusMHz   int `json:"busMhz,omitempty"`
	Packages int `json:"packages,omitempty"`
	Cores    int `json:"cores,omitempty"`
	Threads  int `json:"threads,omitempty"`
	// CoreClasses conta i core per classe di efficienza, dalla più potente:
	// [8, 16] = 8 core P e 16 core E; un solo valore = processore non ibrido.
	CoreClasses []int     `json:"coreClasses,omitempty"`
	Caches      []HwCache `json:"caches,omitempty"`
	// Features elenca le estensioni del set di istruzioni ("SSE4.2", "AVX2").
	Features []string `json:"features,omitempty"`
	// Virtualization dice se le estensioni di virtualizzazione sono attive nel
	// firmware (nil se Windows non lo riporta, per esempio con Hyper-V attivo).
	Virtualization *bool `json:"virtualization,omitempty"`
}

type HwCache struct {
	Level  int    `json:"level"`
	Kind   string `json:"kind"` // data | instruction | unified
	SizeKB int    `json:"sizeKB"`
	Count  int    `json:"count"` // quante ce ne sono (una per core, o condivise)
	Ways   int    `json:"ways,omitempty"`
}

type HwMemory struct {
	Slots   int        `json:"slots,omitempty"`
	MaxGB   float64    `json:"maxGB,omitempty"`
	Modules []HwModule `json:"modules,omitempty"`
}

type HwModule struct {
	Slot   string  `json:"slot,omitempty"`
	Bank   string  `json:"bank,omitempty"`
	SizeGB float64 `json:"sizeGB"`
	Type   string  `json:"type,omitempty"` // DDR4, DDR5, LPDDR5...
	Form   string  `json:"form,omitempty"` // DIMM | SODIMM
	// SpeedMTs è la velocità dichiarata dal modulo, ConfiguredMTs quella a cui lavora.
	SpeedMTs      int    `json:"speedMTs,omitempty"`
	ConfiguredMTs int    `json:"configuredMTs,omitempty"`
	Vendor        string `json:"vendor,omitempty"`
	Part          string `json:"part,omitempty"`
	VoltageMV     int    `json:"voltageMV,omitempty"`
}

type PhysicalDisk struct {
	ID          string           `json:"id,omitempty"` // numero del disco per Windows
	Name        string           `json:"name"`
	Media       string           `json:"media"` // hdd | ssd | scm | unknown
	Bus         string           `json:"bus,omitempty"`
	SizeGB      float64          `json:"sizeGB"`
	Health      string           `json:"health,omitempty"` // healthy | warning | unhealthy | unknown
	Operational []string         `json:"operational,omitempty"`
	Firmware    string           `json:"firmware,omitempty"`
	SpindleRPM  int              `json:"spindleRpm,omitempty"`
	System      bool             `json:"system,omitempty"`
	Reliability *DiskReliability `json:"reliability,omitempty"`
	// Smart elenca gli attributi SMART dei dischi ATA (SATA), NVMe il registro
	// di salute dei dischi NVMe: si leggono dal disco, come fanno
	// CrystalDiskInfo e smartctl, solo da amministratore.
	Smart []SmartAttr `json:"smart,omitempty"`
	NVMe  *NVMeHealth `json:"nvme,omitempty"`
}

// SmartAttr è un attributo SMART di un disco ATA: valore normalizzato attuale
// e peggiore (di solito da 100 o 200 a scendere), soglia sotto la quale il
// produttore considera il disco guasto e dato grezzo a 48 bit, il cui
// significato dipende dall'attributo e dal produttore.
type SmartAttr struct {
	ID      int `json:"id"`
	Flags   int `json:"flags"` // bit 0: attributo di pre-guasto
	Current int `json:"current"`
	Worst   int `json:"worst"`
	// Threshold è nil se il disco non ha restituito le soglie.
	Threshold *int  `json:"threshold,omitempty"`
	Raw       int64 `json:"raw"`
}

// NVMeHealth è la pagina di registro 02h ("SMART / Health Information")
// della specifica NVMe, uguale per tutti i produttori.
type NVMeHealth struct {
	// CriticalWarning: bit 0 riserva sotto soglia, 1 temperatura, 2
	// affidabilità degradata, 3 sola lettura, 4 memoria di backup guasta, 5
	// memoria persistente in sola lettura.
	CriticalWarning   int  `json:"criticalWarning"`
	TemperatureC      *int `json:"temperatureC,omitempty"`
	AvailableSparePct int  `json:"availableSparePct"`
	SpareThresholdPct int  `json:"spareThresholdPct"`
	// PercentageUsed è la stima del produttore della durata consumata: può
	// superare 100.
	PercentageUsed int `json:"percentageUsed"`
	// DataReadGB e DataWrittenGB sono in miliardi di byte.
	DataReadGB          float64 `json:"dataReadGB"`
	DataWrittenGB       float64 `json:"dataWrittenGB"`
	PowerCycles         int64   `json:"powerCycles"`
	PowerOnHours        int64   `json:"powerOnHours"`
	UnsafeShutdowns     int64   `json:"unsafeShutdowns"`
	MediaErrors         int64   `json:"mediaErrors"`
	ErrorLogEntries     int64   `json:"errorLogEntries"`
	WarningTempMinutes  int64   `json:"warningTempMinutes"`
	CriticalTempMinutes int64   `json:"criticalTempMinutes"`
}

// DiskReliability riporta i contatori di affidabilità (derivati da SMART)
// che Windows espone solo ai programmi avviati come amministratore.
type DiskReliability struct {
	TemperatureC     *float64 `json:"temperatureC,omitempty"`
	TemperatureMaxC  *float64 `json:"temperatureMaxC,omitempty"`
	WearPct          *float64 `json:"wearPct,omitempty"`
	PowerOnHours     *int64   `json:"powerOnHours,omitempty"`
	ReadErrors       *int64   `json:"readErrors,omitempty"`
	ReadUncorrected  *int64   `json:"readUncorrected,omitempty"`
	WriteErrors      *int64   `json:"writeErrors,omitempty"`
	WriteUncorrected *int64   `json:"writeUncorrected,omitempty"`
	StartStopCycles  *int64   `json:"startStopCycles,omitempty"`
	LoadUnloadCycles *int64   `json:"loadUnloadCycles,omitempty"`
}

type Volume struct {
	Letter string  `json:"letter"` // "C:"
	Label  string  `json:"label,omitempty"`
	FS     string  `json:"fs,omitempty"`
	Kind   string  `json:"kind"` // fixed | removable
	SizeGB float64 `json:"sizeGB"`
	FreeGB float64 `json:"freeGB"`
	System bool    `json:"system,omitempty"`
	Disk   string  `json:"disk,omitempty"` // ID del disco fisico
	// Dirty: Windows controllerà il volume al prossimo avvio (nil se non
	// verificabile). Health è lo stato del file system secondo Windows:
	// healthy | scan | spotfix | repair (MSFT_Volume.HealthStatus).
	Dirty  *bool  `json:"dirty,omitempty"`
	Health string `json:"health,omitempty"`
}

type Battery struct {
	DesignMWh *int64 `json:"designMWh,omitempty"`
	FullMWh   *int64 `json:"fullMWh,omitempty"`
	Cycles    *int64 `json:"cycles,omitempty"`
	ChargePct *int   `json:"chargePct,omitempty"`
}

type PowerInfo struct {
	Plan         string `json:"plan,omitempty"`
	PlanKind     string `json:"planKind,omitempty"` // balanced | high | saver | ultimate | custom
	OnAC         *bool  `json:"onAC,omitempty"`
	HasBattery   bool   `json:"hasBattery,omitempty"`
	BatterySaver bool   `json:"batterySaver,omitempty"`
}

type StartupItem struct {
	Name     string `json:"name"`
	Command  string `json:"command,omitempty"`
	Location string `json:"location"` // user | machine | machine32 | user-folder | common-folder
	Enabled  bool   `json:"enabled"`
}

type ProcessInfo struct {
	Name     string   `json:"name"`
	Count    int      `json:"count"`
	CPUPct   *float64 `json:"cpuPct,omitempty"`
	MemoryMB float64  `json:"memoryMB"`
}

type EventGroup struct {
	Kind   string `json:"kind"`
	Source string `json:"source"`
	ID     int    `json:"id"`
	Count  int    `json:"count"`
	Last   string `json:"last"`
	Detail string `json:"detail,omitempty"`
}

type AvProduct struct {
	Name     string `json:"name"`
	Enabled  bool   `json:"enabled"`
	UpToDate *bool  `json:"upToDate,omitempty"`
	Source   string `json:"source,omitempty"` // securitycenter | defender
}

// DefenderInfo riassume Get-MpComputerStatus.
type DefenderInfo struct {
	// Mode: normal | passive (un altro antivirus è il principale) | edr | altro.
	Mode     string `json:"mode,omitempty"`
	Enabled  bool   `json:"enabled"`
	RealTime bool   `json:"realTime"`
	// TamperProtected: protezione da manomissioni (nil se Windows non la riporta).
	TamperProtected  *bool  `json:"tamperProtected,omitempty"`
	SignatureVersion string `json:"signatureVersion,omitempty"`
	SignatureAgeDays *int   `json:"signatureAgeDays,omitempty"`
	SignatureUpdated string `json:"signatureUpdated,omitempty"` // RFC 3339
	// QuickScanAgeDays e FullScanAgeDays sono nil se la scansione non è mai stata eseguita.
	QuickScanAgeDays *int   `json:"quickScanAgeDays,omitempty"`
	FullScanAgeDays  *int   `json:"fullScanAgeDays,omitempty"`
	QuickScanEnd     string `json:"quickScanEnd,omitempty"`
	FullScanEnd      string `json:"fullScanEnd,omitempty"`
	EngineVersion    string `json:"engineVersion,omitempty"`
	ProductVersion   string `json:"productVersion,omitempty"`
}

// Threat è una minaccia della cronologia di Defender: nome e stato, senza
// percorsi dei file né nomi utente.
type Threat struct {
	Name string `json:"name"`
	// Severity: low | moderate | high | severe | unknown.
	Severity string `json:"severity"`
	// Status: detected | cleaned | quarantined | removed | allowed | blocked |
	// failed | unknown.
	Status   string `json:"status"`
	Active   bool   `json:"active,omitempty"`
	Detected string `json:"detected,omitempty"` // RFC 3339
	Changed  string `json:"changed,omitempty"`
}

type UpdateInfo struct {
	LastInstalled string   `json:"lastInstalled,omitempty"` // AAAA-MM-GG
	LastKB        string   `json:"lastKB,omitempty"`
	PendingReboot bool     `json:"pendingReboot"`
	RebootReasons []string `json:"rebootReasons,omitempty"`
	// History è la cronologia di Windows Update (API di Windows Update
	// Agent), dalla più recente: nil se non letta, [] se vuota.
	// HistoryError è il codice dell'errore se la lettura non è riuscita.
	History      []UpdateEntry `json:"history"`
	HistoryError string        `json:"historyError,omitempty"`
	// LastSuccess e LastSearch: ultima installazione riuscita e ultima
	// ricerca riuscita secondo Windows Update (comprese le firme di Defender).
	LastSuccess string         `json:"lastSuccess,omitempty"`
	LastSearch  string         `json:"lastSearch,omitempty"`
	Service     *UpdateService `json:"service,omitempty"`
	Policy      *UpdatePolicy  `json:"policy,omitempty"`
}

// UpdateEntry è una voce della cronologia di Windows Update.
type UpdateEntry struct {
	Title string `json:"title"`
	KB    string `json:"kb,omitempty"`
	// Kind: quality | feature | driver | definition | other.
	Kind string `json:"kind"`
	// Operation: install | uninstall | other. Result: succeeded |
	// succeededWithErrors | failed | aborted | inProgress | notStarted.
	Operation string `json:"operation"`
	Result    string `json:"result"`
	HResult   string `json:"hresult,omitempty"` // "0x800F081F"
	Date      string `json:"date"`
	UpdateID  string `json:"updateId,omitempty"`
}

// UpdateService è il modo di avvio dei servizi di Windows Update.
type UpdateService struct {
	WU  *ServiceState `json:"wu,omitempty"`  // wuauserv, Windows Update
	USO *ServiceState `json:"uso,omitempty"` // UsoSvc, Servizio orchestratore aggiornamenti
	// BITS è il servizio di trasferimento intelligente in background.
	BITS *ServiceState `json:"bits,omitempty"`
}

// ServiceState: Start è auto | delayed | manual | disabled | unknown.
type ServiceState struct {
	Start   string `json:"start"`
	Running bool   `json:"running,omitempty"`
}

// UpdatePolicy sono i criteri di gruppo di Windows Update (mai l'indirizzo
// del server dell'organizzazione).
type UpdatePolicy struct {
	NoAutoUpdate bool `json:"noAutoUpdate,omitempty"`
	AUOptions    int  `json:"auOptions,omitempty"`
	// Managed: aggiornamenti da un server dell'organizzazione (WSUS).
	Managed bool `json:"managed,omitempty"`
}

// MemDiagInfo è l'esito di Diagnostica memoria Windows letto dal registro di
// sistema (MemoryDiagnostics-Results e -Schedule) dell'ultimo anno.
type MemDiagInfo struct {
	Days          int             `json:"days"`
	Results       []MemDiagResult `json:"results"`
	LastScheduled string          `json:"lastScheduled,omitempty"`
}

// MemDiagResult è l'esito di un test della memoria.
type MemDiagResult struct {
	Time   string `json:"time"`
	ID     int    `json:"id"`
	Errors bool   `json:"errors,omitempty"`
}

// FsCheck è un controllo del file system registrato nel registro
// Applicazione: all'avvio (Wininit 1001) o lanciato a mano (Chkdsk). Solo
// ora, fonte e lettera dell'unità: il resoconto può contenere nomi di file.
type FsCheck struct {
	Time   string `json:"time"`
	Source string `json:"source"` // wininit | chkdsk
	ID     int    `json:"id"`
	Drive  string `json:"drive,omitempty"`
}

type BenchData struct {
	CPU  *CPUBench   `json:"cpu,omitempty"`
	Disk []DiskBench `json:"disk,omitempty"`
	// RAM è l'ultimo test della memoria con Windows acceso.
	RAM *RAMTest `json:"ram,omitempty"`
}

// RAMTest è l'esito del test della RAM con Windows acceso: vale solo per la
// memoria libera provata, non per quella usata da Windows e dai programmi.
type RAMTest struct {
	StartedAt  string `json:"startedAt"`
	DurationMs int64  `json:"durationMs"`
	Preset     string `json:"preset"` // quick | standard | long
	PlannedSec int    `json:"plannedSec"`
	// Stop: completed | time | cancelled | low-memory.
	Stop        string `json:"stop"`
	TotalMB     int    `json:"totalMB"`
	AvailableMB int    `json:"availableMB"`
	TestedMB    int    `json:"testedMB"`
	// LockedMB è la parte tenuta bloccata in RAM: il resto può essere stato
	// spostato su disco o compresso da Windows, ed è meno affidabile.
	LockedMB int `json:"lockedMB"`
	Threads  int `json:"threads"`
	// Passes sono i passaggi completi; MBs la velocità media, solo indicativa.
	Passes       int           `json:"passes"`
	MBs          float64       `json:"mbs,omitempty"`
	Tests        []RAMTestStat `json:"tests"`
	Errors       int           `json:"errors"`
	ErrorSamples []RAMError    `json:"errorSamples,omitempty"`
	// BadBits sono i bit trovati diversi (OR delle differenze), in esadecimale.
	BadBits string `json:"badBits,omitempty"`
	OnAC    *bool  `json:"onAC,omitempty"`
	Note    string `json:"note,omitempty"`
}

// RAMTestStat conta le esecuzioni e gli errori di una prova.
type RAMTestStat struct {
	Name   string `json:"name"`
	Runs   int    `json:"runs"`
	Errors int    `json:"errors"`
}

// RAMError è una differenza trovata: la posizione è nel blocco del test,
// non indica il modulo né lo slot.
type RAMError struct {
	Test     string  `json:"test"`
	Pass     int     `json:"pass"`
	OffsetMB float64 `json:"offsetMB"`
	Expected string  `json:"expected"`
	Actual   string  `json:"actual"`
}

type CPUBench struct {
	StartedAt    string    `json:"startedAt"`
	Threads      int       `json:"threads"`
	SingleMBs    float64   `json:"singleMBs"`
	MultiMBs     float64   `json:"multiMBs"`
	SustainedMBs float64   `json:"sustainedMBs"`
	Samples      []float64 `json:"samples,omitempty"`
	OnAC         *bool     `json:"onAC,omitempty"`
	// LoadBeforePct è il carico della CPU misurato subito prima del test.
	LoadBeforePct *float64 `json:"loadBeforePct,omitempty"`
	DurationMs    int64    `json:"durationMs"`
}

// DiskBench riporta il profilo stile CrystalDiskMark: i campi Seq e Rnd sono
// le misure con una sola richiesta in coda (SEQ1M Q1T1 e RND4K Q1T1), i
// campi Q8 e Q32 quelle con 8 e 32 richieste (SEQ1M Q8T1 e RND4K Q32T1),
// assenti nei risultati delle versioni precedenti.
type DiskBench struct {
	StartedAt       string  `json:"startedAt"`
	Drive           string  `json:"drive"`
	FileMB          int     `json:"fileMB"`
	SeqReadMBs      float64 `json:"seqReadMBs"`
	SeqWriteMBs     float64 `json:"seqWriteMBs"`
	RndReadMBs      float64 `json:"rndReadMBs"`
	RndReadIOPS     float64 `json:"rndReadIops"`
	RndWriteMBs     float64 `json:"rndWriteMBs"`
	RndWriteIOPS    float64 `json:"rndWriteIops"`
	SeqQ8ReadMBs    float64 `json:"seqQ8ReadMBs,omitempty"`
	SeqQ8WriteMBs   float64 `json:"seqQ8WriteMBs,omitempty"`
	RndQ32ReadMBs   float64 `json:"rndQ32ReadMBs,omitempty"`
	RndQ32ReadIOPS  float64 `json:"rndQ32ReadIops,omitempty"`
	RndQ32WriteMBs  float64 `json:"rndQ32WriteMBs,omitempty"`
	RndQ32WriteIOPS float64 `json:"rndQ32WriteIops,omitempty"`
	DurationMs      int64   `json:"durationMs"`
	Note            string  `json:"note,omitempty"`
}

// Ptr è una scorciatoia per i campi opzionali.
func Ptr[T any](v T) *T { return &v }

// SpaceReport dice che cosa occupa spazio su un'unità (o in una cartella),
// come WizTree: cartelle, file più grandi, tipi di file e cartelle note che
// si possono ripulire. I byte "alloc" sono lo spazio occupato sul disco (i
// file solo online di OneDrive valgono zero, i collegamenti fisici si
// contano una volta); "size" è la dimensione dei dati. I percorsi sono
// mostrati senza nomi utente (%USERPROFILE%, ‹utente N›).
type SpaceReport struct {
	Root  string `json:"root"`  // percorso analizzato, per esempio "C:\\"
	Drive string `json:"drive"` // unità, per esempio "C:"
	FS    string `json:"fs,omitempty"`
	// TotalBytes e FreeBytes descrivono l'unità; la differenza tra lo spazio
	// usato e AllocBytes è ciò che la scansione non vede (metadati del file
	// system, punti di ripristino, cartelle non leggibili).
	TotalBytes int64 `json:"totalBytes"`
	FreeBytes  int64 `json:"freeBytes"`
	AllocBytes int64 `json:"allocBytes"`
	SizeBytes  int64 `json:"sizeBytes"`
	Files      int64 `json:"files"`
	Dirs       int64 `json:"dirs"`
	// Denied è il numero di cartelle non leggibili con i permessi di chi usa
	// Polaris; DeniedPaths ne riporta alcune.
	Denied      int64    `json:"denied,omitempty"`
	DeniedPaths []string `json:"deniedPaths,omitempty"`
	// Errors: cartelle non lette per errori del disco o del file system (non
	// per i permessi). Le cartelle sparite durante l'analisi non si contano.
	Errors int64 `json:"errors,omitempty"`
	// File solo online (OneDrive e simili): non occupano spazio sul disco.
	CloudFiles int64 `json:"cloudFiles,omitempty"`
	CloudBytes int64 `json:"cloudBytes,omitempty"`
	// LinkedBytes: spazio non contato due volte grazie ai collegamenti fisici
	// (per esempio tra WinSxS e System32).
	LinkedBytes int64       `json:"linkedBytes,omitempty"`
	Tree        *SpaceNode  `json:"tree,omitempty"`
	TopFiles    []SpaceFile `json:"topFiles,omitempty"`
	Types       []SpaceType `json:"types,omitempty"`
	Categories  []SpaceType `json:"categories,omitempty"`
	Hints       []SpaceHint `json:"hints,omitempty"`
	StartedAt   string      `json:"startedAt"`
	DurationMs  int64       `json:"durationMs"`
	// Partial: analisi interrotta prima della fine.
	Partial bool `json:"partial,omitempty"`
}

// SpaceNode è una cartella; i figli sono solo i più grandi, gli altri sono
// riassunti in More.
type SpaceNode struct {
	ID       int          `json:"id"`
	Name     string       `json:"name"`
	Path     string       `json:"path"`
	Alloc    int64        `json:"alloc"`
	Size     int64        `json:"size"`
	Files    int64        `json:"files"`
	Dirs     int64        `json:"dirs,omitempty"`
	OwnAlloc int64        `json:"ownAlloc,omitempty"` // file direttamente nella cartella
	OwnFiles int64        `json:"ownFiles,omitempty"`
	Denied   bool         `json:"denied,omitempty"`
	Children []*SpaceNode `json:"children,omitempty"`
	More     *SpaceMore   `json:"more,omitempty"`
}

// SpaceMore riassume le sottocartelle non mostrate una per una.
type SpaceMore struct {
	Dirs  int64 `json:"dirs"`
	Alloc int64 `json:"alloc"`
}

// SpaceFile è uno dei file più grandi; ID serve ad aprirne la cartella.
type SpaceFile struct {
	ID       int    `json:"id"`
	Path     string `json:"path"`
	Alloc    int64  `json:"alloc"`
	Size     int64  `json:"size"`
	Modified string `json:"modified,omitempty"`
	Cloud    bool   `json:"cloud,omitempty"`
}

// SpaceType raccoglie i file per estensione (".mp4") o per categoria
// ("video", "image", "audio", "document", "archive", "program",
// "virtualdisk", "system", "other").
type SpaceType struct {
	ID    string `json:"id"`
	Alloc int64  `json:"alloc"`
	Files int64  `json:"files"`
}

// SpaceHint è una cartella o un file noto (file temporanei, Windows.old,
// Cestino, ibernazione...): il significato e i consigli li dà l'interfaccia.
type SpaceHint struct {
	ID     string `json:"id"`
	Path   string `json:"path,omitempty"`
	Alloc  int64  `json:"alloc"`
	Files  int64  `json:"files,omitempty"`
	NodeID int    `json:"nodeId,omitempty"`
}

// CrashData raccoglie le schermate blu (arresti di sistema, "bug check")
// dai file che Windows salva dopo l'arresto: i minidump della cartella
// indicata in CrashControl (di solito C:\Windows\Minidump) e l'intestazione
// di MEMORY.DMP. Dei driver si tengono solo i nomi dei file, senza percorsi;
// nessun nome di processo, nessun dato del debugger.
type CrashData struct {
	ReadAt   string         `json:"readAt"`
	Settings *CrashSettings `json:"settings,omitempty"`
	// Folder è lo stato della cartella dei minidump: ok | missing (non
	// esiste: nessun arresto salvato) | denied (serve l'amministratore) |
	// error.
	Folder string `json:"folder,omitempty"`
	// NeedsAdmin: la cartella o i file non sono leggibili con i permessi di
	// chi usa Polaris (normale senza amministratore).
	NeedsAdmin bool `json:"needsAdmin,omitempty"`
	// Total è il numero di file .dmp nella cartella; Dumps ne contiene al
	// massimo 50, i più recenti prima.
	Total int         `json:"total"`
	Dumps []CrashDump `json:"dumps"`
	// MemoryDump è l'intestazione di MEMORY.DMP, se il file esiste.
	MemoryDump *CrashDump `json:"memoryDump,omitempty"`
	// Partial: lettura interrotta prima della fine (tempo scaduto); con
	// Folder vuoto non è arrivata alla cartella dei minidump.
	Partial bool `json:"partial,omitempty"`
}

// CrashSettings sono i valori di HKLM\SYSTEM\CurrentControlSet\Control\
// CrashControl, letti senza modificarli. I puntatori sono nil se il valore
// non c'è.
type CrashSettings struct {
	// DumpEnabled è CrashDumpEnabled: 0 nessun file, 1 dump completo (della
	// memoria attiva con FilterPages), 2 dump del kernel, 3 dump piccolo
	// (minidump), 7 dump automatico.
	DumpEnabled *int `json:"dumpEnabled,omitempty"`
	FilterPages bool `json:"filterPages,omitempty"`
	// MinidumpDir e DumpFile sono come nel registro (%SystemRoot%\Minidump),
	// con la cartella dell'utente sostituita da %USERPROFILE%.
	MinidumpDir string `json:"minidumpDir,omitempty"`
	DumpFile    string `json:"dumpFile,omitempty"`
	AutoReboot  *bool  `json:"autoReboot,omitempty"`
	Overwrite   *bool  `json:"overwrite,omitempty"`
	LogEvent    *bool  `json:"logEvent,omitempty"`
}

// CrashDump è un file di dump: codice di arresto e parametri dall'intestazione
// e, per i minidump a 64 bit, il driver indicato come probabile causa.
type CrashDump struct {
	File     string `json:"file"` // solo il nome del file
	Size     int64  `json:"size"`
	Modified string `json:"modified,omitempty"` // data del file, RFC 3339
	// Time è l'ora dell'arresto scritta nel file (UTC), vuota se assente.
	Time string `json:"time,omitempty"`
	// Code e Params sono esadecimali ("0x000000d1", "0xfffff8800a1b2c3d"):
	// i parametri a 64 bit superano gli interi esatti di JavaScript.
	Code       string   `json:"code,omitempty"`
	Params     []string `json:"params,omitempty"`
	Bits       int      `json:"bits,omitempty"`    // 64 | 32
	Machine    string   `json:"machine,omitempty"` // x64 | x86 | arm64
	Build      int      `json:"build,omitempty"`   // build di base di Windows
	Processors int      `json:"processors,omitempty"`
	// DumpType: triage (dump piccolo, minidump) | kernel | full | header |
	// bitmap-full | bitmap-kernel | automatic | kernel-user | unknown.
	DumpType string `json:"dumpType,omitempty"`
	// Drivers è il numero di driver caricati elencati nel minidump.
	Drivers  int           `json:"drivers,omitempty"`
	Probable *CrashCulprit `json:"probable,omitempty"`
	// Stack: moduli diversi dal kernel trovati nello stack salvato, in
	// ordine, al massimo 6.
	Stack []string `json:"stack,omitempty"`
	// Limited dice perché ci sono solo i dati dell'intestazione: not-triage
	// (dump del kernel o completo), 32bit, too-large, inconsistent.
	Limited string `json:"limited,omitempty"`
	Error   string `json:"error,omitempty"`
}

// CrashCulprit è il driver indicato come probabile causa: un indizio, non una
// certezza. Method: param (indirizzo nel parametro che la documentazione del
// codice indica) | stack (primo modulo non del kernel nello stack salvato).
type CrashCulprit struct {
	Driver   string `json:"driver"`
	Method   string `json:"method"`
	Param    int    `json:"param,omitempty"`
	Offset   string `json:"offset,omitempty"` // distanza dall'inizio del driver
	Unloaded bool   `json:"unloaded,omitempty"`
}

// DevicesData è lo stato dei dispositivi presenti, come Gestione dispositivi.
// Nessun identificativo d'istanza (contiene numeri di serie e indirizzi
// Bluetooth) e nessun nome scelto dall'utente: vedi pcinfo.SanitizeHardwareID
// e pcinfo.DeviceName.
type DevicesData struct {
	// Total conta i dispositivi presenti; Problems quelli con un codice di
	// problema, compresi i disattivati (codice 22).
	Total    int `json:"total"`
	Problems int `json:"problems"`
	// Classes conta i dispositivi presenti per classe di installazione.
	Classes []DeviceClassCount `json:"classes,omitempty"`
	// Items sono i dispositivi con un problema, quelli con un driver di terze
	// parti e quelli il cui driver compare nelle schermate blu lette.
	Items []DeviceInfo `json:"items"`
	// CodeIntegrity è lo stato della verifica delle firme dei driver; nil se
	// Windows non lo comunica.
	CodeIntegrity *CodeIntegrity `json:"codeIntegrity,omitempty"`
	// Partial: la lettura si è fermata prima della fine (tempo massimo).
	Partial bool `json:"partial,omitempty"`
}

// DeviceClassCount conta i dispositivi di una classe (Net, Display...).
type DeviceClassCount struct {
	Class    string `json:"class"`
	Count    int    `json:"count"`
	Problems int    `json:"problems,omitempty"`
}

// DeviceInfo è un dispositivo come lo mostra Gestione dispositivi.
type DeviceInfo struct {
	Name  string `json:"name"`
	Class string `json:"class,omitempty"`
	// Enumerator è il bus che ha trovato il dispositivo: PCI, USB, ACPI,
	// HDAUDIO, BTHENUM, SWD...
	Enumerator string `json:"enumerator,omitempty"`
	// HardwareID tiene solo i codici di produttore, modello e revisione
	// (PCI\VEN_10DE&DEV_2206&SUBSYS_...&REV_A1).
	HardwareID string `json:"hardwareId,omitempty"`
	// Problem è il codice di Gestione dispositivi (Codice 10, 28, 43...), 0
	// se nessuno; ProblemStatus l'NTSTATUS che lo accompagna ("0xC0000034").
	Problem       int    `json:"problem,omitempty"`
	ProblemStatus string `json:"problemStatus,omitempty"`
	// Service è il servizio (driver) del dispositivo, come nvlddmkm.
	Service string      `json:"service,omitempty"`
	Driver  *DriverInfo `json:"driver,omitempty"`
}

// DriverInfo è il driver installato per un dispositivo.
type DriverInfo struct {
	Provider string `json:"provider,omitempty"`
	Version  string `json:"version,omitempty"`
	// Date è la data dichiarata dal produttore nel file INF (AAAA-MM-GG).
	Date string `json:"date,omitempty"`
	// Inf è il nome del file INF: oem42.inf per i driver di terze parti,
	// il nome originale (machine.inf, netrtwlane.inf...) per quelli di Windows.
	Inf   string `json:"inf,omitempty"`
	Inbox bool   `json:"inbox,omitempty"`
	// File è il file del driver (solo il nome, mai il percorso): nvlddmkm.sys.
	File string `json:"file,omitempty"`
}

// CodeIntegrity è lo stato della verifica delle firme del codice nel kernel
// (NtQuerySystemInformation, SystemCodeIntegrityInformation).
type CodeIntegrity struct {
	Options uint32 `json:"options"`
	// Enabled: Windows carica in kernel solo codice firmato.
	Enabled bool `json:"enabled"`
	// TestSigning: modalità test, accetta driver firmati con qualunque
	// certificato (sul desktop compare la scritta "Modalità test").
	TestSigning bool `json:"testSigning,omitempty"`
	// DebugMode: debug del kernel attivo, che consente codice non firmato.
	DebugMode bool `json:"debugMode,omitempty"`
	// HVCI: integrità della memoria (Isolamento core) attiva.
	HVCI bool `json:"hvci,omitempty"`
}

// BootPerf è la durata di avvio e spegnimento come la misura Windows nel
// registro Microsoft-Windows-Diagnostics-Performance/Operational.
type BootPerf struct {
	// Days è la finestra letta; Channel lo stato del registro: ok | denied
	// (serve l'amministratore) | missing (registro assente) | error.
	Days    int    `json:"days"`
	Channel string `json:"channel"`
	// FirmwareMs è l'ultimo tempo del firmware prima di Windows (FwPOSTTime,
	// "Ultimo tempo BIOS" in Gestione attività); nil se il firmware non lo comunica.
	FirmwareMs *int64 `json:"firmwareMs,omitempty"`
	// Boots: gli avvii misurati (evento 100), il più recente prima.
	Boots []BootRecord `json:"boots"`
	// Slow: i componenti che Windows ha segnalato come lenti all'avvio
	// (eventi 101-110) o allo spegnimento (201-203), raggruppati.
	Slow []BootSlow `json:"slow,omitempty"`
	// Shutdowns: gli spegnimenti misurati (evento 200), il più recente prima.
	Shutdowns []ShutdownRecord `json:"shutdowns,omitempty"`
}

// BootRecord è un avvio misurato da Windows.
type BootRecord struct {
	Time    string `json:"time"`
	TotalMs int64  `json:"totalMs"`
	// MainPathMs va dall'accensione di Windows al desktop; PostBootMs dal
	// desktop al sistema pronto (programmi all'avvio).
	MainPathMs  int64 `json:"mainPathMs,omitempty"`
	PostBootMs  int64 `json:"postBootMs,omitempty"`
	StartupApps int   `json:"startupApps,omitempty"`
	Degraded    bool  `json:"degraded,omitempty"`
	AfterUpdate bool  `json:"afterUpdate,omitempty"`
}

// BootSlow è un componente segnalato come lento.
type BootSlow struct {
	// Phase: boot | shutdown. Kind: app | driver | service | core |
	// prefetch | policy | device | session.
	Phase string `json:"phase"`
	Kind  string `json:"kind"`
	// Name è solo il nome del file o del servizio, mai il percorso.
	Name          string `json:"name"`
	Friendly      string `json:"friendly,omitempty"`
	Version       string `json:"version,omitempty"`
	TotalMs       int64  `json:"totalMs"`
	DegradationMs int64  `json:"degradationMs"`
	Count         int    `json:"count"`
	Last          string `json:"last"`
}

// ShutdownRecord è uno spegnimento misurato da Windows.
type ShutdownRecord struct {
	Time     string `json:"time"`
	TotalMs  int64  `json:"totalMs"`
	Degraded bool   `json:"degraded,omitempty"`
}

// AppFailures sono i programmi che si sono chiusi da soli (evento 1000) o
// bloccati (1002) nel registro Applicazione, e i rapporti di Segnalazione
// errori Windows (1001). Niente percorsi, identificativi dei processi o dei
// rapporti.
type AppFailures struct {
	Days    int    `json:"days"`
	Channel string `json:"channel"` // ok | denied | error
	Crashes int    `json:"crashes"`
	Hangs   int    `json:"hangs"`
	// Apps: raggruppati per programma, dal più frequente (al massimo 25).
	Apps    []AppFailure `json:"apps"`
	Reports []WerReport  `json:"reports,omitempty"`
	Wer     *WerSettings `json:"wer,omitempty"`
}

// AppFailure riassume gli arresti di un programma.
type AppFailure struct {
	App     string `json:"app"` // nome del file eseguibile
	Version string `json:"version,omitempty"`
	Crashes int    `json:"crashes"`
	Hangs   int    `json:"hangs"`
	Last    string `json:"last"`
	// Modules: i moduli in errore (solo il nome del file); Exceptions i
	// codici di eccezione ("0xc0000005"); i tre più frequenti.
	Modules    []NameCount `json:"modules,omitempty"`
	Exceptions []NameCount `json:"exceptions,omitempty"`
	// Store: app dello Store o pacchettizzata; UserFolder: eseguibile nella
	// cartella di un utente; System: eseguibile di Windows.
	Store      bool `json:"store,omitempty"`
	UserFolder bool `json:"userFolder,omitempty"`
	System     bool `json:"system,omitempty"`
}

// NameCount è un nome con il numero di volte.
type NameCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// WerReport conta i rapporti di Segnalazione errori per tipo (APPCRASH,
// APPHANG, BlueScreen, LiveKernelEvent...).
type WerReport struct {
	Event string `json:"event"`
	Count int    `json:"count"`
	Last  string `json:"last"`
}

// WerSettings sono le impostazioni di Segnalazione errori Windows lette dal
// registro, senza modificarle.
type WerSettings struct {
	Disabled        bool `json:"disabled,omitempty"`
	DontShowUI      bool `json:"dontShowUI,omitempty"`
	LoggingDisabled bool `json:"loggingDisabled,omitempty"`
	// Policy: almeno un valore viene dai criteri di gruppo.
	Policy bool `json:"policy,omitempty"`
	// LocalDumps: Windows salva una copia della memoria dei programmi che si chiudono.
	LocalDumps      bool `json:"localDumps,omitempty"`
	CorporateServer bool `json:"corporateServer,omitempty"`
}

// Reliability è l'indice di stabilità di Monitoraggio affidabilità
// (Win32_ReliabilityStabilityMetrics) e i suoi record raggruppati
// (Win32_ReliabilityRecords), senza utente né messaggi.
type Reliability struct {
	Available bool `json:"available"`
	// Reason spiega perché manca: no-data | disabled | error.
	Reason string `json:"reason,omitempty"`
	// Index è l'ultimo valore (da 1 a 10), IndexAt quando è stato calcolato.
	Index   *float64           `json:"index,omitempty"`
	IndexAt string             `json:"indexAt,omitempty"`
	Series  []ReliabilityPoint `json:"series,omitempty"`
	Records []ReliabilityGroup `json:"records,omitempty"`
	// WMIEnabled è il valore WMIEnable del registro; nil se assente.
	WMIEnabled *bool `json:"wmiEnabled,omitempty"`
}

// ReliabilityPoint è l'ultimo indice di un giorno.
type ReliabilityPoint struct {
	Date  string  `json:"date"`
	Index float64 `json:"index"`
}

// ReliabilityGroup raggruppa i record di affidabilità per fonte e codice.
type ReliabilityGroup struct {
	// Category: app-crash | app-hang | windows-failure | shutdown |
	// install-failed | update-failed | install | update | other
	// (classificazione di Polaris).
	Category string `json:"category"`
	Source   string `json:"source"`
	ID       int    `json:"id"`
	Product  string `json:"product,omitempty"`
	Count    int    `json:"count"`
	Last     string `json:"last"`
}

// EncryptionInfo è lo stato della cifratura dei volumi
// (Win32_EncryptableVolume, solo da amministratore). Mai la chiave di
// ripristino: dell'identificativo della chiave restano i primi 8 caratteri,
// quelli che Windows mostra per riconoscerla.
type EncryptionInfo struct {
	// Read: ok | denied (serve l'amministratore) | absent (BitLocker non
	// presente) | error.
	Read string `json:"read"`
	// PreventAuto: la crittografia automatica del dispositivo è impedita
	// (PreventDeviceEncryption).
	PreventAuto *bool       `json:"preventAuto,omitempty"`
	Volumes     []EncVolume `json:"volumes,omitempty"`
}

// EncVolume è lo stato di cifratura di un volume con lettera.
type EncVolume struct {
	Letter string `json:"letter"`
	Kind   string `json:"kind"` // os | fixed | removable | unknown
	// Conversion: decrypted | encrypted | encrypting | decrypting |
	// encrypt-paused | decrypt-paused | unknown.
	Conversion    string `json:"conversion"`
	Percent       *int   `json:"percent,omitempty"`
	UsedSpaceOnly bool   `json:"usedSpaceOnly,omitempty"`
	// Protection: on | off | unknown.
	Protection string `json:"protection"`
	Locked     bool   `json:"locked,omitempty"`
	Method     string `json:"method,omitempty"`
	// Protectors: i tipi di protezione della chiave (tpm, recovery-password...);
	// nil se non letti, [] se nessuno (chiave in chiaro).
	Protectors    []string `json:"protectors"`
	SuspendCount  *int     `json:"suspendCount,omitempty"`
	RecoveryKeyID string   `json:"recoveryKeyId,omitempty"`
}

// BackupInfo raccoglie punti di ripristino, Backup e ripristino di Windows e
// le cartelle sincronizzate con OneDrive.
type BackupInfo struct {
	RestorePoints *RestorePoints   `json:"restorePoints,omitempty"`
	ImageBackup   *ImageBackupInfo `json:"imageBackup,omitempty"`
	// OneDrive: le cartelle Desktop, Documenti e Immagini stanno nella
	// cartella di OneDrive (solo i nomi delle cartelle, mai i percorsi).
	OneDrive []string `json:"oneDrive,omitempty"`
}

// RestorePoints sono i punti di ripristino del sistema (SystemRestore, solo
// da amministratore), senza le descrizioni.
type RestorePoints struct {
	// Read: ok | denied | unsupported (Windows Server) | error.
	Read             string `json:"read"`
	DisabledByPolicy bool   `json:"disabledByPolicy,omitempty"`
	Count            int    `json:"count"`
	Newest           string `json:"newest,omitempty"`
	// NewestType: app-install | app-uninstall | driver-install | settings |
	// cancelled | windows-update | other.
	NewestType string `json:"newestType,omitempty"`
	Oldest     string `json:"oldest,omitempty"`
}

// ImageBackupInfo è l'esito di Backup e ripristino di Windows (Windows 7)
// dagli eventi di Microsoft-Windows-Backup degli ultimi Days giorni.
type ImageBackupInfo struct {
	Read        string `json:"read"` // ok | denied | error
	Days        int    `json:"days"`
	LastSuccess string `json:"lastSuccess,omitempty"`
	LastFailure string `json:"lastFailure,omitempty"`
	FailureID   int    `json:"failureId,omitempty"`
	Failures    int    `json:"failures,omitempty"`
}

// AccountsInfo sono gli account locali, identificati dal RID e mai dal nome.
type AccountsInfo struct {
	// Local: nil se non letti.
	Local  []LocalAccount `json:"local"`
	Admins *AdminGroup    `json:"admins,omitempty"`
	// CurrentIsAdmin: chi usa Polaris è nel gruppo Administrators.
	CurrentIsAdmin *bool `json:"currentIsAdmin,omitempty"`
}

// LocalAccount è un account locale.
type LocalAccount struct {
	RID int `json:"rid"`
	// Kind: builtin-admin | guest | default | wdag | user.
	Kind    string `json:"kind"`
	Enabled bool   `json:"enabled"`
	Admin   bool   `json:"admin,omitempty"`
	Current bool   `json:"current,omitempty"`
	// PasswordNotRequired: Windows non richiede una password (non vuol dire
	// che sia vuota). PasswordNeverExpires: la password non scade.
	PasswordNotRequired  bool `json:"passwordNotRequired,omitempty"`
	PasswordNeverExpires bool `json:"passwordNeverExpires,omitempty"`
	LockedOut            bool `json:"lockedOut,omitempty"`
}

// AdminGroup conta i membri del gruppo Administrators.
type AdminGroup struct {
	Members      int `json:"members"`
	LocalEnabled int `json:"localEnabled"`
	// Other: account e gruppi di dominio o di Microsoft Entra.
	Other int `json:"other,omitempty"`
}

// AccessInfo sono le impostazioni di accesso al PC, lette dal registro.
type AccessInfo struct {
	Autologon *AutologonInfo `json:"autologon,omitempty"`
	RDP       *RdpInfo       `json:"rdp,omitempty"`
	UAC       *UacInfo       `json:"uac,omitempty"`
	Lock      *LockInfo      `json:"lock,omitempty"`
}

// AutologonInfo: accesso automatico all'avvio, senza chiedere la password.
type AutologonInfo struct {
	Enabled bool `json:"enabled"`
	// PasswordInRegistry: la password è scritta in chiaro nel registro
	// (DefaultPassword); Polaris ne controlla solo l'esistenza.
	PasswordInRegistry bool `json:"passwordInRegistry,omitempty"`
}

// RdpInfo è lo stato di Desktop remoto.
type RdpInfo struct {
	Enabled  bool `json:"enabled"`
	ByPolicy bool `json:"byPolicy,omitempty"`
	// NLA: autenticazione a livello di rete richiesta prima della sessione.
	NLA  bool `json:"nla"`
	Port int  `json:"port,omitempty"`
}

// UacInfo è il Controllo dell'account utente.
type UacInfo struct {
	Enabled bool `json:"enabled"`
	// ConsentAdmin è ConsentPromptBehaviorAdmin: 0 eleva senza chiedere,
	// 5 (predefinito) chiede conferma per i programmi non di Windows.
	ConsentAdmin  int  `json:"consentAdmin"`
	SecureDesktop bool `json:"secureDesktop"`
}

// LockInfo è il blocco automatico dello schermo.
type LockInfo struct {
	// InactivitySec è il limite di inattività dei criteri (0 = nessuno).
	InactivitySec int `json:"inactivitySec,omitempty"`
	// Screen saver attivo, con richiesta della password, dopo SaverSec secondi.
	SaverActive bool `json:"saverActive,omitempty"`
	SaverSecure bool `json:"saverSecure,omitempty"`
	SaverSec    int  `json:"saverSec,omitempty"`
}

// PrintingInfo sono le stampanti e il servizio di stampa (spooler). Mai i
// titoli dei documenti né i nomi di chi stampa.
type PrintingInfo struct {
	Spooler *ServiceState `json:"spooler,omitempty"`
	// Printers: nil se non lette (servizio di stampa fermo).
	Printers []Printer `json:"printers"`
	// Connections conta le stampanti condivise da altri computer.
	Connections int `json:"connections,omitempty"`
}

// Printer è una stampante installata su questo PC.
type Printer struct {
	Name string `json:"name"`
	// Kind: tcp | wsd | usb | virtual | other.
	Kind    string `json:"kind"`
	Default bool   `json:"default,omitempty"`
	Shared  bool   `json:"shared,omitempty"`
	Port    string `json:"port,omitempty"`
	Driver  string `json:"driver,omitempty"`
	// Status sono i bit di PRINTER_STATUS; Flags gli stati decodificati.
	Status      uint32   `json:"status,omitempty"`
	Flags       []string `json:"flags,omitempty"`
	WorkOffline bool     `json:"workOffline,omitempty"`
	Jobs        int      `json:"jobs"`
	// Stuck: lavori fermi da più di 15 minuti; JobErrors lavori in errore.
	Stuck     int `json:"stuck,omitempty"`
	JobErrors int `json:"jobErrors,omitempty"`
	// OldestMin è l'età in minuti del lavoro più vecchio in coda.
	OldestMin int `json:"oldestMin,omitempty"`
}
