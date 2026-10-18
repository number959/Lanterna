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
  /**
   * Inventario e verifiche di raggiungibilità: non li produce l'analisi
   * automatica ma l'utente, su richiesta esplicita, dalla sezione
   * Infrastruttura; l'interfaccia li unisce al rapporto.
   */
  infra?: InfraData;
  /**
   * Il computer da cui parte l'analisi: sistema, memoria, dischi, avvio,
   * eventi, sicurezza. I test di velocità (bench) si eseguono su richiesta e
   * li unisce l'interfaccia.
   */
  pc?: PcData;
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
  /** Dominio DNS del PC (Active Directory); assente nei gruppi di lavoro. */
  domain?: string;
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
  /** Suffisso DNS della connessione, es. "clinica.local". */
  dnsSuffix?: string;
  /** Server DHCP che ha assegnato l'indirizzo IPv4. */
  dhcpServer?: string;
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

/** Funzioni di roaming assistito annunciate nel beacon. */
export interface Roaming {
  /** 802.11k: l'AP fornisce l'elenco dei vicini (Neighbor Report). */
  k: boolean;
  /** 802.11v: gestione della transizione (BSS Transition Management). */
  v: boolean;
  /** 802.11r: transizione veloce (Fast BSS Transition). */
  r: boolean;
  /** Identificativo del Mobility Domain: gli AP con lo stesso valore condividono le chiavi FT. */
  mdid?: string;
  ftOverDs?: boolean;
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
  /** Assente quando la sonda non ha potuto leggere gli elementi del beacon. */
  roaming?: Roaming;
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

// ---------- Infrastruttura (su richiesta) ----------

export interface InventoryHost {
  ip: string;
  mac?: string;
  /** MAC amministrato localmente: casuale (telefoni, PC moderni) o virtuale. */
  randomMac?: boolean;
  /** Nome dal DNS inverso. */
  name?: string;
  netbios?: string;
  /** Tempo di risposta al ping; assente = visto solo tramite ARP. */
  rttMs?: number;
  self?: boolean;
  gateway?: boolean;
}

export interface Inventory {
  subnet: string;
  adapter?: string;
  scanned: number;
  note?: string;
  startedAt: string;
  durationMs: number;
  hosts: InventoryHost[];
}

export type ReachExpect = 'reachable' | 'isolated';
export type ReachStatus = 'open' | 'closed' | 'filtered' | 'reply' | 'noreply' | 'unresolved' | 'refused' | 'error';

export interface ReachTarget {
  label?: string;
  host: string;
  /** 0 o assente = solo ping. */
  port?: number;
  expect: ReachExpect;
}

export interface ReachResult extends ReachTarget {
  ip?: string;
  status: ReachStatus;
  rttMs?: number;
  /** true = l'esito corrisponde all'attesa. */
  ok: boolean;
  error?: string;
}

export interface ReachData {
  startedAt: string;
  /** Indirizzo del PC da cui sono partite le verifiche. */
  from?: string;
  results: ReachResult[];
}

/** Risposta a una domanda dell'autovalutazione; "na" = non applicabile. */
export type AnswerValue = 'yes' | 'partial' | 'no' | 'na';

export interface AssessmentData {
  /** Risposte per identificativo di domanda (catalogo in kb/assessment). */
  answers: Record<string, AnswerValue>;
  updatedAt?: string;
}

export interface InfraData {
  inventory?: Inventory;
  reach?: ReachData;
  /** Autovalutazione delle misure organizzative: dichiarata dall'utente, non misurata. */
  assessment?: AssessmentData;
}

// ---------- Computer ----------

export interface PcData {
  os?: PcOs;
  cpu?: PcCpu;
  memory?: PcMemory;
  gpus?: PcGpu[];
  disks?: PhysicalDisk[];
  volumes?: Volume[];
  battery?: Battery;
  power?: PowerInfo;
  startup?: StartupItem[];
  processes?: ProcessInfo[];
  /**
   * Eventi rilevanti del registro di sistema degli ultimi `eventsDays` giorni.
   * `eventsDays` assente = registro non letto; presente senza eventi = nessun
   * evento nel periodo.
   */
  events?: EventGroup[];
  eventsDays?: number;
  /** null = Centro sicurezza non leggibile; [] = nessun prodotto registrato. */
  antivirus?: AvProduct[] | null;
  /** Stato di Microsoft Defender (assente se non leggibile). */
  defender?: DefenderInfo;
  /** Cronologia delle minacce di Defender: null = non letta, [] = nessuna. */
  threats?: Threat[] | null;
  updates?: UpdateInfo;
  /** Scheda tecnica (processore, scheda madre, memoria, firmware), come in CPU-Z. */
  hardware?: Hardware;
  bench?: BenchData;
  /** Limiti della raccolta (dati SMART solo da amministratore, PowerShell assente...). */
  notes?: string[];
}

export interface PcOs {
  name: string;
  /** Versione commerciale, es. "24H2". */
  version?: string;
  build?: number;
  /** Revisione della build (Update Build Revision): cresce con gli aggiornamenti mensili. */
  ubr?: number;
  /** EditionID del registro, es. "Professional", "Core" (Home), "EnterpriseS" (LTSC). */
  edition?: string;
  arch?: string;
  installDate?: string;
  bootTime?: string;
  uptimeSec?: number;
  server?: boolean;
  /** Avvio rapido attivo: "Arresta il sistema" non azzera il tempo di accensione. */
  fastStartup?: boolean;
}

export interface PcCpu {
  name: string;
  cores?: number;
  threads?: number;
  maxMhz?: number;
  /** Carico medio misurato per circa un secondo e mezzo a fine analisi. */
  loadPct?: number;
}

export interface PcMemory {
  totalMB: number;
  availableMB: number;
  /** Memoria impegnata (RAM + file di paging) e suo limite. */
  commitMB?: number;
  commitLimitMB?: number;
}

export interface PcGpu {
  name: string;
  driverVersion?: string;
  driverDate?: string; // AAAA-MM-GG
  vramMB?: number;
  /** Risoluzione e frequenza dello schermo collegato durante l'analisi. */
  width?: number;
  height?: number;
  refreshHz?: number;
}

/** Scheda tecnica del computer, come in CPU-Z. Nessun numero di serie. */
export interface Hardware {
  vendor?: string;
  model?: string;
  chassis?: 'desktop' | 'laptop' | 'workstation' | 'server' | 'tablet' | 'other';
  board?: HwBoard;
  cpu?: HwCpu;
  memory?: HwMemory;
  /** uefi oppure bios (avvio legacy). */
  firmware?: 'uefi' | 'bios';
  secureBoot?: boolean;
  /** Versione del TPM ("2.0", "1.2"); "" = nessun TPM; assente = non verificato. */
  tpm?: string;
  hypervisor?: boolean;
}

export interface HwBoard {
  vendor?: string;
  product?: string;
  version?: string;
  biosVendor?: string;
  biosVersion?: string;
  biosDate?: string; // AAAA-MM-GG
}

export interface HwCpu {
  vendor?: string;
  family?: number;
  model?: number;
  stepping?: number;
  socket?: string;
  packages?: number;
  cores?: number;
  threads?: number;
  /** Core per classe di efficienza, dalla più potente: [8, 16] = 8 P e 16 E. */
  coreClasses?: number[];
  caches?: HwCache[];
  /** Estensioni del set di istruzioni ("SSE4.2", "AVX2"...). */
  features?: string[];
  /** Virtualizzazione attiva nel firmware; assente se Windows non la riporta (per esempio con Hyper-V attivo). */
  virtualization?: boolean;
}

export interface HwCache {
  level: number;
  kind: 'data' | 'instruction' | 'unified';
  sizeKB: number;
  count: number;
  ways?: number;
}

export interface HwMemory {
  slots?: number;
  maxGB?: number;
  modules?: HwModule[];
}

export interface HwModule {
  slot?: string;
  bank?: string;
  sizeGB: number;
  type?: string;
  form?: 'DIMM' | 'SODIMM';
  /** Velocità dichiarata dal modulo e velocità a cui lavora, in MT/s. */
  speedMTs?: number;
  configuredMTs?: number;
  vendor?: string;
  part?: string;
  voltageMV?: number;
}

export type DiskMedia = 'hdd' | 'ssd' | 'scm' | 'unknown';
export type DiskHealth = 'healthy' | 'warning' | 'unhealthy' | 'unknown';

export interface PhysicalDisk {
  /** Numero del disco per Windows ("0", "1"...). */
  id?: string;
  name: string;
  media: DiskMedia;
  /** Interfaccia: "NVMe", "SATA", "USB", "RAID"... */
  bus?: string;
  sizeGB: number;
  health?: DiskHealth;
  operational?: string[];
  firmware?: string;
  spindleRpm?: number;
  /** Contiene la partizione di Windows. */
  system?: boolean;
  reliability?: DiskReliability;
  /** Attributi SMART dei dischi ATA (SATA), letti dal disco come amministratore. */
  smart?: SmartAttr[];
  /** Registro di salute dei dischi NVMe (pagina 02h della specifica). */
  nvme?: NVMeHealth;
}

/**
 * Attributo SMART ATA: valore normalizzato attuale e peggiore (di solito da
 * 100 o 200 a scendere), soglia del produttore e dato grezzo a 48 bit.
 */
export interface SmartAttr {
  id: number;
  /** Bit 0: attributo di pre-guasto (il suo superamento della soglia indica un guasto imminente). */
  flags: number;
  current: number;
  worst: number;
  /** Assente se il disco non ha restituito le soglie. */
  threshold?: number;
  raw: number;
}

/** Pagina di registro "SMART / Health Information" della specifica NVMe. */
export interface NVMeHealth {
  /** Bit 0 riserva sotto soglia, 1 temperatura, 2 affidabilità degradata, 3 sola lettura, 4 backup della memoria volatile guasto, 5 memoria persistente in sola lettura. */
  criticalWarning: number;
  temperatureC?: number;
  availableSparePct: number;
  spareThresholdPct: number;
  /** Stima del produttore della durata consumata; può superare 100. */
  percentageUsed: number;
  /** Miliardi di byte. */
  dataReadGB: number;
  dataWrittenGB: number;
  powerCycles: number;
  powerOnHours: number;
  unsafeShutdowns: number;
  mediaErrors: number;
  errorLogEntries: number;
  warningTempMinutes: number;
  criticalTempMinutes: number;
}

/** Contatori di affidabilità (derivati da SMART), leggibili solo come amministratore. */
export interface DiskReliability {
  temperatureC?: number;
  temperatureMaxC?: number;
  /** Percentuale della durata nominale consumata (SSD): 0 = nuovo, 100 = durata dichiarata raggiunta. */
  wearPct?: number;
  powerOnHours?: number;
  readErrors?: number;
  readUncorrected?: number;
  writeErrors?: number;
  writeUncorrected?: number;
  startStopCycles?: number;
  loadUnloadCycles?: number;
}

export interface Volume {
  letter: string; // "C:"
  label?: string;
  fs?: string;
  kind: 'fixed' | 'removable';
  sizeGB: number;
  freeGB: number;
  system?: boolean;
  /** Disco fisico che contiene il volume (id di PhysicalDisk). */
  disk?: string;
}

export interface Battery {
  designMWh?: number;
  fullMWh?: number;
  cycles?: number;
  chargePct?: number;
}

export type PlanKind = 'balanced' | 'high' | 'saver' | 'ultimate' | 'custom';

export interface PowerInfo {
  plan?: string;
  planKind?: PlanKind;
  onAC?: boolean;
  hasBattery?: boolean;
  batterySaver?: boolean;
}

export type StartupLocation = 'user' | 'machine' | 'machine32' | 'user-folder' | 'common-folder';

export interface StartupItem {
  name: string;
  /** Comando, con la cartella dell'utente sostituita da %USERPROFILE%. */
  command?: string;
  location: StartupLocation;
  enabled: boolean;
}

export interface ProcessInfo {
  /** Nome dell'eseguibile; i processi con lo stesso nome sono sommati. */
  name: string;
  count: number;
  cpuPct?: number;
  memoryMB: number;
}

export type EventKind =
  | 'unexpected-shutdown'
  | 'bugcheck'
  | 'disk-error'
  | 'disk-retry'
  | 'filesystem'
  | 'storage-reset'
  | 'whea-fatal'
  | 'whea-corrected';

export interface EventGroup {
  kind: EventKind;
  source: string;
  id: number;
  count: number;
  /** Ultima occorrenza, ISO 8601. */
  last: string;
  /** Primo parametro dell'evento: codice di arresto, disco coinvolto. */
  detail?: string;
}

export interface AvProduct {
  name: string;
  enabled: boolean;
  upToDate?: boolean;
  source?: 'securitycenter' | 'defender';
}

/** Stato di Microsoft Defender (Get-MpComputerStatus). */
export interface DefenderInfo {
  /** normal = antivirus principale; passive = un altro antivirus è il principale. */
  mode?: 'normal' | 'passive' | 'edr' | 'other';
  enabled: boolean;
  realTime: boolean;
  tamperProtected?: boolean;
  signatureVersion?: string;
  signatureAgeDays?: number;
  signatureUpdated?: string;
  /** Assenti se la scansione non è mai stata completata. */
  quickScanAgeDays?: number;
  fullScanAgeDays?: number;
  quickScanEnd?: string;
  fullScanEnd?: string;
  engineVersion?: string;
  productVersion?: string;
}

export type ThreatSeverity = 'low' | 'moderate' | 'high' | 'severe' | 'unknown';
export type ThreatStatus = 'detected' | 'cleaned' | 'quarantined' | 'removed' | 'allowed' | 'blocked' | 'failed' | 'unknown';

/** Minaccia della cronologia di Defender: nome e stato, senza percorsi né nomi utente. */
export interface Threat {
  name: string;
  severity: ThreatSeverity;
  status: ThreatStatus;
  active?: boolean;
  detected?: string;
  changed?: string;
}

export interface UpdateInfo {
  /** Data dell'ultimo aggiornamento installato (AAAA-MM-GG). */
  lastInstalled?: string;
  lastKB?: string;
  pendingReboot: boolean;
  rebootReasons?: string[];
}

export interface BenchData {
  cpu?: CpuBench;
  /** Ultimo test per ogni unità. */
  disk?: DiskBench[];
}

export interface CpuBench {
  startedAt: string;
  threads: number;
  /** MB/s compressi con un thread e con tutti (punta e media finale). */
  singleMBs: number;
  multiMBs: number;
  sustainedMBs: number;
  /** MB/s secondo per secondo della fase con tutti i thread. */
  samples?: number[];
  onAC?: boolean;
  loadBeforePct?: number;
  durationMs: number;
}

/**
 * Profilo stile CrystalDiskMark. I campi seq e rnd sono le misure con una
 * sola richiesta in coda (SEQ1M Q1T1, RND4K Q1T1); quelli Q8 e Q32 le misure
 * con 8 e 32 richieste (SEQ1M Q8T1, RND4K Q32T1), assenti nei risultati delle
 * versioni precedenti alla 0.6.
 */
export interface DiskBench {
  startedAt: string;
  drive: string;
  fileMB: number;
  seqReadMBs: number;
  seqWriteMBs: number;
  rndReadMBs: number;
  rndReadIops: number;
  rndWriteMBs: number;
  rndWriteIops: number;
  seqQ8ReadMBs?: number;
  seqQ8WriteMBs?: number;
  rndQ32ReadMBs?: number;
  rndQ32ReadIops?: number;
  rndQ32WriteMBs?: number;
  rndQ32WriteIops?: number;
  durationMs: number;
  note?: string;
}

// ---------- Risultato dell'analisi ----------

export type Severity = 'ok' | 'info' | 'warn' | 'crit' | 'unknown';
export type Category = 'wifi' | 'lan' | 'internet' | 'dns' | 'router' | 'security' | 'infra' | 'pc';

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
