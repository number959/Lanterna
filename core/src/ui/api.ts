import type { Scan } from '../engine';

// Comunicazione con l'agente locale (lanterna.exe serve / finestra).
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
