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
	Errors   []ProbeError  `json:"errors"`
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
}

type WifiSecurity struct {
	Protocol string   `json:"protocol"`
	AKM      []string `json:"akm"`
	Pairwise []string `json:"pairwise"`
	Group    string   `json:"group,omitempty"`
	PMF      string   `json:"pmf,omitempty"`
	WPS      bool     `json:"wps,omitempty"`
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

// Ptr è una scorciatoia per i campi opzionali.
func Ptr[T any](v T) *T { return &v }
