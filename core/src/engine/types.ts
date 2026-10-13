// Contratto dati di STARNET Polaris.
// Ogni sonda (Windows oggi, Android ed ESP32 in futuro) produce uno `Scan`
// con soli dati grezzi; l'interpretazione la fa sempre e solo il motore
// (`analyze`), così le spiegazioni restano identiche su ogni piattaforma.
// Tutti i campi opzionali possono mancare: una sonda che non sa misurare
// qualcosa lo omette, e il motore lo segnala come "non misurato".

export const SCHEMA_VERSION = 1;

export type Platform = 'windows' | 'android' | 'esp32' | 'linux' | 'demo';

export interface Scan {
  schema: number;
  agent: AgentInfo;
  adapters: Adapter[];
  wifi?: WifiData;
  gateway?: GatewayData;
  internet?: InternetData;
  dns?: DnsData;
  lan?: LanData;
  firewall?: FirewallData;
  /** Sonde fallite: non bloccano l'analisi, vengono mostrate all'utente. */
  errors: ProbeError[];
}

export interface AgentInfo {
  name: string;
  version: string;
  platform: Platform;
  host?: string;
  os?: string;
  startedAt: string; // ISO 8601
  durationMs: number;
  elevated?: boolean;
}

export interface ProbeError {
  probe: string;
  message: string;
}

export type AdapterKind = 'wifi' | 'ethernet' | 'loopback' | 'virtual' | 'other';

export interface Adapter {
  name: string;
  description?: string;
  kind: AdapterKind;
  mac?: string;
  up: boolean;
  ipv4: string[]; // in notazione CIDR, es. "192.168.1.20/24"
  ipv6: string[];
  gateways: string[];
  dns: string[];
  dhcp?: boolean;
  mtu?: number;
  /** Velocità di collegamento negoziata in Mbit/s (trasmissione). */
  linkMbps?: number;
}

// ---------- Wi-Fi ----------

export type Band = '2.4' | '5' | '6';
export type SecurityProtocol = 'open' | 'owe' | 'wep' | 'wpa' | 'wpa2' | 'wpa2/wpa3' | 'wpa3' | 'unknown';
export type Pmf = 'disabled' | 'capable' | 'required';

export interface WifiSecurity {
  protocol: SecurityProtocol;
  /** Es. "PSK", "SAE", "802.1X", "OWE". */
  akm: string[];
  /** Es. "CCMP", "TKIP", "GCMP-256". */
  pairwise: string[];
  group?: string;
  pmf?: Pmf;
  wps?: boolean;
}

export interface BssLoad {
  stations: number;
  /** Occupazione del canale 0-100 % (il frame la riporta in 0-255). */
  utilizationPct: number;
}

export interface Bss {
  ssid: string; // "" se la rete è nascosta
  bssid: string;
  rssiDbm: number;
  freqMhz: number;
  channel: number;
  band: Band;
  /** Larghezza di canale effettiva in MHz (20/40/80/160/320). */
  widthMhz: number;
  /** Canale centrale del blocco largo (es. 42 per 36-48 a 80 MHz). */
  centerChannel?: number;
  /** Standard più recente annunciato: "802.11n", "802.11ac", "802.11ax", "802.11be"... */
  phy?: string;
  bssLoad?: BssLoad;
  security?: WifiSecurity;
  country?: string;
  connected?: boolean;
}

export interface WifiConnection {
  interface?: string;
  ssid: string;
  bssid?: string;
  /** Qualità 0-100 riportata da Windows (scala lineare -100..-50 dBm). */
  signalQuality?: number;
  rssiDbm?: number;
  rxMbps?: number;
  txMbps?: number;
  phy?: string;
  band?: Band;
  channel?: number;
  widthMhz?: number;
  auth?: string;
  cipher?: string;
}

export interface WifiData {
  source: 'wlanapi' | 'netsh' | 'android' | 'esp32' | 'demo' | 'none';
  connected?: WifiConnection;
  networks: Bss[];
  error?: string;
}

// ---------- Rete ----------

export interface PingStats {
  target: string;
  label?: string;
  sent: number;
  received: number;
  minMs?: number;
  avgMs?: number;
  maxMs?: number;
  /** Variazione media tra campioni consecutivi (RFC 3550 semplificato). */
  jitterMs?: number;
  samples?: (number | null)[];
  method?: 'icmp' | 'tcp';
  error?: string;
}

export interface PortCheck {
  port: number;
  service: string;
  open: boolean;
}

export interface UpnpDevice {
  friendlyName?: string;
  manufacturer?: string;
  modelName?: string;
  modelNumber?: string;
  server?: string;
  location?: string;
  deviceType?: string;
}

export interface UpnpData {
  /** true = almeno un dispositivo ha risposto all'M-SEARCH. */
  found: boolean;
  /** true = il router espone il servizio IGD (port forwarding automatico). */
  igd: boolean;
  devices: UpnpDevice[];
  externalIp?: string;
}

export interface GatewayData {
  ip: string;
  mac?: string;
  ping?: PingStats;
  ports?: PortCheck[];
  upnp?: UpnpData;
  /** Intestazione "Server" e titolo della pagina web del router. */
  web?: { server?: string; title?: string; https?: boolean };
}

export interface Hop {
  ttl: number;
  ip?: string;
  rttMs?: number;
}

export interface MtuResult {
  /** MTU di percorso stimata (payload massimo + 28 byte di intestazioni). */
  mtu: number;
  method: string;
}

export interface HttpCheck {
  url: string;
  ok: boolean;
  status?: number;
  timeMs?: number;
  error?: string;
}

export interface InternetData {
  targets: PingStats[];
  traceroute?: Hop[];
  traceTarget?: string;
  mtu?: MtuResult;
  http?: HttpCheck[];
}

export interface DnsServerResult {
  server: string;
  label?: string;
  ok: boolean;
  /** Tempo mediano di risposta, ms. */
  timeMs?: number;
  error?: string;
}

export interface DnsData {
  system: DnsServerResult[];
  public: DnsServerResult[];
}

export interface Neighbor {
  ip: string;
  mac?: string;
}

export interface LanData {
  neighbors: Neighbor[];
}

export interface FirewallProfile {
  name: 'domain' | 'private' | 'public';
  enabled: boolean | null;
  active?: boolean;
}

export interface FirewallData {
  source: string;
  profiles: FirewallProfile[];
}

// ---------- Risultato dell'analisi ----------

export type Severity = 'ok' | 'info' | 'warn' | 'crit' | 'unknown';
export type Category = 'wifi' | 'lan' | 'internet' | 'dns' | 'router' | 'security';

export interface Finding {
  /** Identificativo stabile, es. "wifi.rssi" o "router.port.23". */
  id: string;
  /** Chiave della voce di knowledge base che spiega il valore. */
  metric: string;
  category: Category;
  title: string;
  /** Valore leggibile, es. "-67 dBm". */
  value: string;
  severity: Severity;
  /** Cosa significa *questo* valore, nel contesto della rete misurata. */
  verdict: string;
  /** Azioni correttive suggerite (chiavi del catalogo azioni). */
  actions: string[];
  /** Dati numerici utili ai grafici. */
  numeric?: number;
}

export interface Action {
  id: string;
  title: string;
  why: string;
  steps: string[];
  effort: 'facile' | 'media' | 'avanzata';
  impact: 'alto' | 'medio' | 'basso';
}

export interface PlanItem {
  action: Action;
  /** Gravità più alta tra i problemi che l'azione risolve. */
  severity: Severity;
  findings: string[];
  priority: number;
}

export interface CategoryScore {
  category: Category;
  label: string;
  score: number | null; // null = niente da valutare
  worst: Severity;
  counts: Record<Severity, number>;
}

export interface ChannelScore {
  channel: number;
  /** Etichetta del blocco, es. "36-48" per i blocchi da 80 MHz a 5 GHz. */
  label: string;
  /** Interferenza stimata 0-100 (0 = canale libero). */
  load: number;
  networks: number;
  dfs?: boolean;
}

export interface ChannelAdvice {
  band: Band;
  current?: number;
  recommended?: number;
  scores: ChannelScore[];
  note: string;
}

export interface Analysis {
  engineVersion: string;
  score: number;
  grade: 'ottima' | 'buona' | 'discreta' | 'critica';
  headline: string;
  categories: CategoryScore[];
  findings: Finding[];
  plan: PlanItem[];
  channels: ChannelAdvice[];
}
