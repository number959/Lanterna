import type { CertData, CertTarget, CpuBench, DefenderInfo, DiskBench, Inventory, RamTest, ReachData, ReachTarget, Scan, SpaceReport, SpeedServer, SpeedTest, SurveySample, Threat } from '../engine';
import type { CrashData } from '../engine';

// Comunicazione con l'agente locale (Polaris.exe serve / finestra).
// L'interfaccia è servita dallo stesso agente, quindi i percorsi sono relativi.

export interface AgentInfo {
  name: string;
  version: string;
  platform: string;
  host?: string;
}

export interface ProgressStep {
  id: string;
  label: string;
  state: 'pending' | 'running' | 'done' | 'error';
}

export interface Progress {
  running: boolean;
  steps: ProgressStep[];
  error?: string;
}

async function getJson<T>(url: string, init?: RequestInit): Promise<T> {
  const r = await fetch(url, { cache: 'no-store', ...init });
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
  return (await r.json()) as T;
}

export async function agentInfo(): Promise<AgentInfo | null> {
  try {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), 1500);
    const info = await getJson<AgentInfo>('api/info', { signal: ctl.signal });
    clearTimeout(t);
    return info?.name ? info : null;
  } catch {
    return null;
  }
}

export async function lastScan(): Promise<Scan | null> {
  const r = await fetch('api/scan', { cache: 'no-store' });
  if (r.status === 204 || r.status === 404) return null;
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return (await r.json()) as Scan;
}

/**
 * Avvia una nuova analisi e attende la fine, notificando l'avanzamento reale.
 * Un 409 perché un'analisi è già in corso (busy "scan"; un agente precedente,
 * senza busy, lo dice con il solo messaggio) se ne segue l'avanzamento; ogni
 * altro 409 (test della CPU o del disco, misura del Wi-Fi, test di Internet)
 * è un rifiuto, con il messaggio dell'agente.
 */
export async function runScan(onProgress: (p: Progress) => void): Promise<Scan> {
  const start = await fetch('api/scan', { method: 'POST' });
  if (start.status === 409) {
    let body: { error?: string; busy?: string } = {};
    try {
      body = (await start.json()) ?? {};
    } catch {
      // corpo non JSON
    }
    const running = body.busy === 'scan' || (body.busy === undefined && body.error === 'analisi già in corso');
    if (!running) throw new Error(body.error || 'Avvio analisi: HTTP 409');
  } else if (!start.ok) throw new Error(`Avvio analisi: HTTP ${start.status}`);
  for (;;) {
    await new Promise((r) => setTimeout(r, 400));
    const p = await getJson<Progress>('api/progress');
    onProgress(p);
    if (!p.running) {
      if (p.error) throw new Error(p.error);
      const s = await lastScan();
      if (!s) throw new Error('Analisi terminata senza risultato');
      return s;
    }
  }
}

export async function ping(target: 'gateway' | 'internet'): Promise<number | null> {
  const r = await getJson<{ ms: number | null }>(`api/ping?target=${target}`);
  return r.ms;
}

// ---- Infrastruttura: partono solo su richiesta esplicita dell'utente.

/** Errore restituito dall'agente, con il messaggio in italiano già pronto da mostrare. */
async function errorOf(r: Response): Promise<Error> {
  try {
    const body = (await r.json()) as { error?: string };
    if (body.error) return new Error(body.error);
  } catch {
    // corpo non JSON
  }
  return new Error(`HTTP ${r.status}`);
}

async function postJson<T>(url: string, body: unknown): Promise<T> {
  const r = await fetch(url, { method: 'POST', cache: 'no-store', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  if (!r.ok) throw await errorOf(r);
  return (await r.json()) as T;
}

export interface InventoryProgress {
  running: boolean;
  phase?: 'ping' | 'nomi' | string;
  done: number;
  total: number;
  error?: string;
  result?: Inventory;
}

export const inventoryStatus = () => getJson<InventoryProgress>('api/inventory');

/**
 * Avvia l'inventario (serve la conferma di autorizzazione) e ne attende la
 * fine riportando l'avanzamento reale. `resume` riprende un inventario già
 * in corso senza avviarne un altro.
 */
export async function runInventory(onProgress: (p: InventoryProgress) => void, opts: { resume?: boolean; signal?: AbortSignal } = {}): Promise<Inventory> {
  if (!opts.resume) await postJson<{ started: boolean }>('api/inventory', { authorized: true });
  for (;;) {
    await new Promise((r) => setTimeout(r, 500));
    if (opts.signal?.aborted) throw new DOMException('interrotto', 'AbortError');
    const p = await inventoryStatus();
    onProgress(p);
    if (!p.running) {
      if (p.error) throw new Error(p.error);
      if (!p.result) throw new Error('Inventario terminato senza risultato');
      return p.result;
    }
  }
}

export const runReach = (targets: ReachTarget[]) => postJson<ReachData>('api/reach', { targets });

/**
 * Legge i certificati TLS dei servizi indicati (al massimo 20, solo indirizzi
 * privati). La risposta arriva alla fine del controllo, fino a circa due
 * minuti; 409 se un controllo è già in corso, 501 se l'agente non lo offre.
 */
export const runCerts = (targets: CertTarget[]) => postJson<CertData>('api/certs', { targets });

/** L'ultimo controllo dei certificati fatto dall'agente, o null se non ce n'è. */
export async function lastCerts(): Promise<CertData | null> {
  const r = await fetch('api/certs', { cache: 'no-store' });
  if (r.status === 204 || r.status === 404) return null;
  if (!r.ok) throw await errorOf(r);
  return (await r.json()) as CertData;
}

/** Rilegge subito impostazioni e file delle schermate blu (solo letture); 501 se l'agente non lo offre. */
export async function readCrashes(): Promise<CrashData> {
  const r = await fetch('api/crashes', { cache: 'no-store' });
  if (!r.ok) throw await errorOf(r);
  return (await r.json()) as CrashData;
}

// ---- Mappa del Wi-Fi per stanza: una misura alla volta, su richiesta.

export interface SurveyProgress {
  /** "misura" (segnale e ping) o "scansione" (alla fine). */
  phase: 'misura' | 'scansione';
  elapsedMs: number;
  seconds: number;
  /** Ultima lettura del segnale; rssi: tutte quelle fatte finora. */
  dbm?: number;
  rssi: number[];
  roams: number;
  pings: number;
  replies: number;
}

export interface SurveyState {
  running: boolean;
  room?: string;
  progress?: SurveyProgress;
  error?: string;
  /** Esito dell'ultima misura (l'agente lo toglie all'avvio della successiva). */
  result?: SurveySample;
}

export interface SurveyRequest {
  room: string;
  /** Da 10 a 20 secondi (predefiniti 15). */
  seconds?: number;
  /** Una scansione delle reti alla fine (predefinita sì). */
  scan?: boolean;
}

export const surveyStatus = () => getJson<SurveyState>('api/wifi/survey');

/** Interrompe la misura in corso. */
export async function stopSurvey(): Promise<void> {
  const r = await fetch('api/wifi/survey', { method: 'DELETE', cache: 'no-store' });
  if (!r.ok) throw await errorOf(r);
}

/**
 * Avvia la misura di un punto e ne attende la fine (circa 15 secondi, più
 * la scansione); `resume` segue una misura già avviata. 409 se è in corso
 * un'altra misura, un'analisi o un inventario.
 */
export async function runSurvey(req: SurveyRequest, onProgress: (st: SurveyState) => void, opts: { resume?: boolean } = {}): Promise<SurveySample> {
  if (!opts.resume) await postJson<{ started: boolean }>('api/wifi/survey', req);
  for (;;) {
    await new Promise((r) => setTimeout(r, 400));
    const st = await surveyStatus();
    onProgress(st);
    if (!st.running) {
      if (st.error) throw new Error(st.error);
      if (!st.result) throw new Error('Misura terminata senza risultato');
      return st.result;
    }
  }
}

// ---- Test di velocità: partono solo su richiesta esplicita dell'utente.

export interface BenchProgress {
  phase: string;
  done: number;
  /** Velocità misurata finora nella fase in corso (MB/s). */
  value?: number;
  /** MB/s secondo per secondo della fase multi-thread del processore. */
  samples?: number[];
  /** Test della RAM: errori trovati finora e passaggio in corso. */
  errors?: number;
  pass?: number;
}

export interface BenchState {
  running: boolean;
  kind?: 'cpu' | 'disk' | 'ram';
  drive?: string;
  progress?: BenchProgress;
  error?: string;
  cpu?: CpuBench;
  disk?: DiskBench;
  ram?: RamTest;
}

export type BenchRequest = { kind: 'cpu' } | { kind: 'disk'; drive: string; confirm: true };
export type RamRequest = { kind: 'ram'; preset: 'quick' | 'standard' | 'long'; confirm: true };

/**
 * Avvia il test della RAM e ne attende la fine; un test interrotto
 * restituisce comunque l'esito della parte provata.
 */
export async function runRamTest(req: RamRequest, onProgress: (st: BenchState) => void, opts: { resume?: boolean } = {}): Promise<RamTest> {
  if (!opts.resume) await postJson<{ started: boolean }>('api/bench', req);
  const startedAt = Date.now();
  for (;;) {
    await new Promise((r) => setTimeout(r, 400));
    const st = await benchStatus();
    onProgress(st);
    if (!st.running) {
      // Ripreso un test già in corso, il risultato è il suo anche se è partito prima.
      if (st.ram && (opts.resume || Date.parse(st.ram.startedAt) >= startedAt - 60000)) return st.ram;
      throw new Error(st.error || 'Test terminato senza risultato');
    }
  }
}

export const benchStatus = () => getJson<BenchState>('api/bench');

/** Interrompe il test in corso (il file temporaneo del test dei dischi viene cancellato). */
export async function stopBench(): Promise<void> {
  const r = await fetch('api/bench', { method: 'DELETE', cache: 'no-store' });
  if (!r.ok) throw await errorOf(r);
}

/**
 * Avvia un test di velocità e ne attende la fine riportando l'avanzamento
 * reale; `resume` segue un test già avviato (per esempio da un'altra finestra).
 */
export async function runBench(req: BenchRequest, onProgress: (st: BenchState) => void, opts: { resume?: boolean } = {}): Promise<CpuBench | DiskBench> {
  if (!opts.resume) await postJson<{ started: boolean }>('api/bench', req);
  for (;;) {
    await new Promise((r) => setTimeout(r, 300));
    const st = await benchStatus();
    onProgress(st);
    if (!st.running) {
      if (st.error) throw new Error(st.error);
      const res = req.kind === 'cpu' ? st.cpu : st.disk;
      if (!res) throw new Error('Test terminato senza risultato');
      return res;
    }
  }
}

// ---- Cosa occupa spazio: legge l'elenco dei file di un'unità, su richiesta.

export interface SpaceProgress {
  dirs: number;
  files: number;
  alloc: number;
  elapsedMs: number;
}

export interface SpaceState {
  running: boolean;
  drive?: string;
  progress?: SpaceProgress;
  error?: string;
  /** Ultima analisi (anche interrotta: partial). */
  result?: SpaceReport;
}

export const spaceStatus = () => getJson<SpaceState>('api/space');

/** Interrompe l'analisi in corso: resta il risultato parziale. */
export async function stopSpace(): Promise<void> {
  const r = await fetch('api/space', { method: 'DELETE', cache: 'no-store' });
  if (!r.ok) throw await errorOf(r);
}

/**
 * Avvia l'analisi dello spazio di un'unità e ne attende la fine; un'analisi
 * interrotta restituisce comunque i valori letti fino a quel momento.
 */
export async function runSpace(drive: string, onProgress: (st: SpaceState) => void, opts: { resume?: boolean } = {}): Promise<{ report: SpaceReport; error?: string }> {
  if (!opts.resume) await postJson<{ started: boolean }>('api/space', { drive });
  for (;;) {
    await new Promise((r) => setTimeout(r, 400));
    const st = await spaceStatus();
    onProgress(st);
    if (!st.running) {
      // L'agente toglie il risultato precedente all'avvio: questo è il nuovo.
      if (!st.result) throw new Error(st.error || 'Analisi terminata senza risultato');
      return { report: st.result, error: st.error };
    }
  }
}

/**
 * Apre in Esplora file una cartella (o la cartella di un file, selezionandolo)
 * dell'ultima analisi. `startedAt` è quello del rapporto mostrato: se nel
 * frattempo l'unità è stata analizzata di nuovo (anche da un'altra finestra)
 * gli identificativi sono cambiati e l'agente risponde "elemento non trovato".
 */
export const openSpaceItem = (drive: string, id: number, file: boolean, startedAt: string) =>
  postJson<{ opened: boolean }>('api/space/open', { drive, id, file, startedAt });

// ---- Test di velocità di Internet con M-Lab: solo su richiesta, con il consenso.

export interface SpeedProgress {
  phase: 'locate' | 'idle' | 'download' | 'upload';
  mbps?: number;
  latencyMs?: number;
  elapsedMs: number;
  phaseMs?: number;
  server?: SpeedServer;
}

export interface SpeedState {
  running: boolean;
  progress?: SpeedProgress;
  error?: string;
  result?: SpeedTest;
  /** Secondi prima che l'agente accetti un altro test; test ancora possibili oggi. */
  waitSec?: number;
  left: number;
}

export const speedStatus = () => getJson<SpeedState>('api/speedtest');

/** Interrompe il test in corso. */
export async function stopSpeed(): Promise<void> {
  const r = await fetch('api/speedtest', { method: 'DELETE', cache: 'no-store' });
  if (!r.ok) throw await errorOf(r);
}

/**
 * Avvia il test (l'utente ha appena dato il consenso) e ne attende la fine,
 * riportando l'avanzamento. 409 se c'è già un test o un'analisi, 429 se è
 * troppo presto: il messaggio dell'agente dice quanto aspettare.
 */
export async function runSpeed(onProgress: (st: SpeedState) => void, opts: { resume?: boolean } = {}): Promise<SpeedTest> {
  if (!opts.resume) await postJson<{ started: boolean }>('api/speedtest', { consent: true });
  for (;;) {
    await new Promise((r) => setTimeout(r, 400));
    const st = await speedStatus();
    onProgress(st);
    if (!st.running) {
      if (!st.result) throw new Error(st.error || 'Test terminato senza risultato');
      return st.result;
    }
  }
}

// ---- Microsoft Defender: scansioni e aggiornamento delle firme su richiesta.

export type DefenderAction = 'quick' | 'full' | 'update';

export interface DefenderResult {
  action: DefenderAction;
  startedAt: string;
  durationMs: number;
  message: string;
  newThreats: number;
  defender?: DefenderInfo;
  threats: Threat[] | null;
}

export interface DefenderState {
  running: boolean;
  action?: DefenderAction;
  startedAt?: string;
  error?: string;
  result?: DefenderResult;
}

export const defenderStatus = () => getJson<DefenderState>('api/defender');

/** Interrompe la scansione in corso. */
export async function stopDefender(): Promise<void> {
  const r = await fetch('api/defender', { method: 'DELETE', cache: 'no-store' });
  if (!r.ok) throw await errorOf(r);
}

/**
 * Avvia un'operazione di Defender e ne attende la fine (una scansione
 * completa può durare ore: lo stato si controlla ogni secondo); `resume`
 * segue un'operazione già avviata.
 */
export async function runDefender(action: DefenderAction, onProgress: (st: DefenderState) => void, opts: { resume?: boolean } = {}): Promise<DefenderResult> {
  if (!opts.resume) await postJson<{ started: boolean }>('api/defender', { action });
  for (;;) {
    await new Promise((r) => setTimeout(r, 1000));
    const st = await defenderStatus();
    onProgress(st);
    if (!st.running) {
      if (st.error) throw new Error(st.error);
      if (!st.result) throw new Error('Operazione terminata senza esito');
      return st.result;
    }
  }
}

// ---- Cassetta degli attrezzi: l'agente apre solo voci della sua lista bianca.

/** Versione portable già scaricata dal sito ufficiale. */
export interface PortableState {
  version?: string;
  signer?: string;
  /** Giorno del download (AAAA-MM-GG). */
  date?: string;
  /** Scaduta (Microsoft Safety Scanner smette di funzionare dopo 10 giorni). */
  expired?: boolean;
  /** Presente se il file non è quello verificato: allora non si avvia. */
  problem?: string;
  /** Copia nel kit per l'uso senza Internet, accanto a Polaris. */
  kit?: boolean;
}

/**
 * Download in corso o appena concluso (total -1 se il sito non dichiara la
 * dimensione). Per il kit (kit true) i programmi si scaricano uno dopo
 * l'altro: queue quelli che mancano, ready quelli pronti, failed quelli non
 * riusciti con il motivo.
 */
export interface FetchState {
  running: boolean;
  tool?: string;
  done: number;
  total: number;
  error?: string;
  kit?: boolean;
  queue?: string[];
  ready?: string[];
  failed?: Record<string, string>;
}

export interface ToolsState {
  installed: Record<string, { version?: string }>;
  /** Programmi inclusi nel pacchetto: problem se il file non è l'originale (e allora non si avvia). */
  bundled?: Record<string, { version: string; problem?: string }>;
  portable?: Record<string, PortableState>;
  /** Programmi che su questo PC si possono scaricare. */
  fetchable?: string[];
  /** L'agente sa preparare il kit per l'uso senza Internet. */
  kit?: boolean;
  fetch?: FetchState;
}

export const toolsStatus = () => getJson<ToolsState>('api/tools');

/** Frequenza effettiva dei core in un istante, dai contatori delle prestazioni di Windows. */
export interface CpuClockSample {
  /** Media dei core, come la mostra Gestione attività (MHz). */
  mhz: number;
  /** Il core più veloce in questo istante (MHz). */
  maxMhz: number;
  /** Frequenza nominale (MHz). */
  baseMhz: number;
  /** Frequenza effettiva in percentuale della nominale: oltre 100 = turbo. */
  perfPct: number;
  loadPct: number;
  cores: { id: string; mhz: number; loadPct: number }[];
  at: string;
}

export async function cpuClock(signal?: AbortSignal): Promise<CpuClockSample> {
  const r = await fetch('api/cpu/clock', { cache: 'no-store', signal });
  if (!r.ok) throw await errorOf(r);
  return (await r.json()) as CpuClockSample;
}

/** Un sensore del monitor (come una riga di HWiNFO). */
export interface SensorReading {
  /** Stabile da una lettura all'altra. */
  id: string;
  label: string;
  value: number;
  /** "%", "MHz", "°C", "W", "V", "MB/s", "Mbit/s", "ms", "GB", "MB", "Wh", "giri/min", "/s", "ore" o vuota. */
  unit: string;
  /** Soglie di attenzione e di allarme; con below valgono verso il basso. */
  warn?: number;
  crit?: number;
  below?: boolean;
  /** Riga di dettaglio, nascosta finché non si chiede di vederla. */
  detail?: boolean;
}

export type SensorKind = 'cpu' | 'thermal' | 'gpu' | 'memory' | 'disk' | 'network' | 'battery' | 'system';

export interface SensorGroup {
  id: string;
  kind: SensorKind;
  name: string;
  sub?: string;
  sensors: SensorReading[];
}

export interface SensorSnapshot {
  at: string;
  groups: SensorGroup[];
  /** Ciò che su questo PC non si legge, in parole semplici. */
  missing?: string[];
}

/** Legge i sensori dall'agente (contatori di Windows, driver video, batteria, SMART). */
export async function readSensors(signal?: AbortSignal): Promise<SensorSnapshot> {
  const r = await fetch('api/sensors', { cache: 'no-store', signal });
  if (!r.ok) throw await errorOf(r);
  return (await r.json()) as SensorSnapshot;
}

/** Scarica dal sito ufficiale la versione portable e ne verifica la firma (in background). */
export const fetchTool = (tool: string) => postJson<{ started: boolean }>('api/tools/fetch', { tool });

export async function cancelFetch(): Promise<void> {
  const r = await fetch('api/tools/fetch', { method: 'DELETE', cache: 'no-store' });
  if (!r.ok) throw await errorOf(r);
}

/** Prepara il kit per l'uso senza Internet accanto a Polaris (in background). */
export const prepareKit = (tools: string[]) => postJson<{ started: boolean; tools: string[] }>('api/tools/kit', { tools });

/** Elimina la copia scaricata. */
export const removeTool = (tool: string) => postJson<{ removed: boolean }>('api/tools/remove', { tool });

/** Apre uno strumento di Windows, un programma (la copia inclusa in Polaris o quella installata: app) o il suo sito ufficiale (site). */
export const openTool = (tool: string, target: 'app' | 'site') => postJson<{ opened: boolean }>('api/open', { tool, target });

export function download(name: string, content: string, type: string) {
  const blob = new Blob([content], { type });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    URL.revokeObjectURL(a.href);
    a.remove();
  }, 0);
}

export function isScan(x: unknown): x is Scan {
  const s = x as Scan;
  return !!s && typeof s === 'object' && typeof s.schema === 'number' && !!s.agent && Array.isArray(s.adapters) && Array.isArray(s.errors);
}
