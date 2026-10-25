import type { CpuBench, DefenderInfo, DiskBench, Inventory, ReachData, ReachTarget, Scan, Threat } from '../engine';

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

/** Avvia una nuova analisi e attende la fine, notificando l'avanzamento reale. */
export async function runScan(onProgress: (p: Progress) => void): Promise<Scan> {
  const start = await fetch('api/scan', { method: 'POST' });
  if (!start.ok && start.status !== 409) throw new Error(`Avvio analisi: HTTP ${start.status}`);
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

// ---- Test di velocità: partono solo su richiesta esplicita dell'utente.

export interface BenchProgress {
  phase: string;
  done: number;
  /** Velocità misurata finora nella fase in corso (MB/s). */
  value?: number;
  /** MB/s secondo per secondo della fase multi-thread del processore. */
  samples?: number[];
}

export interface BenchState {
  running: boolean;
  kind?: 'cpu' | 'disk';
  drive?: string;
  progress?: BenchProgress;
  error?: string;
  cpu?: CpuBench;
  disk?: DiskBench;
}

export type BenchRequest = { kind: 'cpu' } | { kind: 'disk'; drive: string; confirm: true };

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
