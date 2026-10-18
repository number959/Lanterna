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
	Assessment *Assessment `json:"assessment,omitempty"`
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
	Updates   *UpdateInfo `json:"updates,omitempty"`
	Bench     *BenchData  `json:"bench,omitempty"`
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

type DiskBench struct {
	StartedAt    string  `json:"startedAt"`
	Drive        string  `json:"drive"`
	FileMB       int     `json:"fileMB"`
	SeqReadMBs   float64 `json:"seqReadMBs"`
	SeqWriteMBs  float64 `json:"seqWriteMBs"`
	RndReadMBs   float64 `json:"rndReadMBs"`
	RndReadIOPS  float64 `json:"rndReadIops"`
	RndWriteMBs  float64 `json:"rndWriteMBs"`
	RndWriteIOPS float64 `json:"rndWriteIops"`
	DurationMs   int64   `json:"durationMs"`
	Note         string  `json:"note,omitempty"`
}

// Ptr è una scorciatoia per i campi opzionali.
func Ptr[T any](v T) *T { return &v }
