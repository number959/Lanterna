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
}

type BenchData struct {
	CPU  *CPUBench   `json:"cpu,omitempty"`
	Disk []DiskBench `json:"disk,omitempty"`
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
