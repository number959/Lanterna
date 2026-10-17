import { useCallback, useEffect, useRef, useState } from 'react';
import { ping } from './api';

// Sessione del monitor: un ping al secondo verso router e Internet. Vive
// nell'App, non nella pagina, così continua mentre si consultano le altre
// sezioni; tiene l'intera sessione (fino a 12 ore) per il riepilogo e il CSV.

export interface MonitorSample {
  /** Istante della misura (ms dall'epoca). */
  t: number;
  gw: number | null;
  inet: number | null;
}

export interface MonitorSession {
  /** true = misure reali dall'agente; false = valori simulati (demo). */
  live: boolean;
  running: boolean;
  startedAt?: number;
  samples: MonitorSample[];
  /** Cresce a ogni misura: serve ai grafici per animare lo scorrimento. */
  tick: number;
  start: () => void;
  pause: () => void;
  reset: () => void;
}

export const MAX_SAMPLES = 12 * 3600;

export function useMonitor(live: boolean): MonitorSession {
  const [running, setRunning] = useState(false);
  const [startedAt, setStartedAt] = useState<number>();
  const [samples, setSamples] = useState<MonitorSample[]>([]);
  const [tick, setTick] = useState(0);
  const n = useRef(0);

  useEffect(() => {
    if (!running) return;
    let alive = true;
    const id = setInterval(async () => {
      n.current++;
      const t = Date.now();
      let gw: number | null;
      let inet: number | null;
      if (live) {
        [gw, inet] = await Promise.all([ping('gateway').catch(() => null), ping('internet').catch(() => null)]);
        if (!alive) return;
      } else {
        // Demo: valori simulati, chiaramente indicati nell'interfaccia.
        const burst = n.current % 23 > 17;
        gw = Math.random() < 0.03 ? null : Math.round((4 + Math.random() * 6 + (burst ? 25 : 0)) * 10) / 10;
        inet = Math.random() < 0.02 ? null : Math.round((26 + Math.random() * 9 + (burst ? 40 : 0)) * 10) / 10;
      }
      setSamples((xs) => {
        const next = xs.length >= MAX_SAMPLES ? xs.slice(xs.length - MAX_SAMPLES + 1) : xs.slice();
        next.push({ t, gw, inet });
        return next;
      });
      setTick((k) => k + 1);
    }, 1000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [running, live]);

  const start = useCallback(() => {
    setStartedAt((s) => s ?? Date.now());
    setRunning(true);
  }, []);
  const pause = useCallback(() => setRunning(false), []);
  const reset = useCallback(() => {
    setSamples([]);
    setTick(0);
    setStartedAt((s) => (s === undefined ? s : Date.now()));
  }, []);

  return { live, running, startedAt, samples, tick, start, pause, reset };
}

// ---- Riepilogo della sessione

export interface MonitorEvent {
  series: 'gw' | 'inet';
  kind: 'outage' | 'peak';
  start: number;
  end: number;
  /** Per i picchi: valore massimo in ms. */
  max?: number;
}

export interface SeriesSummary {
  count: number;
  lostPct: number;
  avg?: number;
  p95?: number;
  max?: number;
  maxAt?: number;
  outages: number;
  outageSec: number;
}

/** Interruzione = almeno tre misure perse di fila; le perdite isolate contano solo nella percentuale. */
const OUTAGE_MIN = 3;

function percentile(sorted: number[], p: number): number {
  return sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))];
}

export function summarize(samples: MonitorSample[], key: 'gw' | 'inet'): { stats: SeriesSummary; events: MonitorEvent[] } {
  const vals = samples.map((s) => s[key]);
  const ok = vals.filter((v): v is number => v !== null);
  const sorted = [...ok].sort((a, b) => a - b);
  const median = sorted.length ? percentile(sorted, 50) : 0;
  // Picco: ben oltre il valore tipico della sessione (2,5 volte la mediana e almeno 30 ms in più).
  const threshold = Math.max(median * 2.5, median + 30);
  const events: MonitorEvent[] = [];
  let maxV: number | undefined;
  let maxAt: number | undefined;
  let lostRun = 0;
  let peak: MonitorEvent | null = null;
  let outageSec = 0;
  let outages = 0;
  const closeLost = (endIdx: number) => {
    if (lostRun >= OUTAGE_MIN) {
      const start = samples[endIdx - lostRun].t;
      const end = samples[endIdx - 1].t;
      events.push({ series: key, kind: 'outage', start, end });
      outages++;
      outageSec += lostRun;
    }
    lostRun = 0;
  };
  for (let i = 0; i < samples.length; i++) {
    const s = samples[i];
    const v = s[key];
    if (v === null) {
      lostRun++;
      if (peak) {
        events.push(peak);
        peak = null;
      }
      continue;
    }
    closeLost(i);
    if (maxV === undefined || v > maxV) {
      maxV = v;
      maxAt = s.t;
    }
    if (sorted.length >= 10 && v > threshold) {
      if (peak) {
        peak.end = s.t;
        peak.max = Math.max(peak.max ?? 0, v);
      } else peak = { series: key, kind: 'peak', start: s.t, end: s.t, max: v };
    } else if (peak) {
      events.push(peak);
      peak = null;
    }
  }
  closeLost(samples.length);
  if (peak) events.push(peak);
  return {
    stats: {
      count: vals.length,
      lostPct: vals.length ? (100 * (vals.length - ok.length)) / vals.length : 0,
      avg: ok.length ? ok.reduce((a, b) => a + b, 0) / ok.length : undefined,
      p95: sorted.length ? percentile(sorted, 95) : undefined,
      max: maxV,
      maxAt,
      outages,
      outageSec,
    },
    events,
  };
}

/** CSV per fogli di calcolo italiani: separatore ";" e virgola decimale, con BOM per Excel. */
export function toCsv(rows: (string | number | null | undefined)[][]): string {
  const cell = (v: string | number | null | undefined) => {
    if (v === null || v === undefined) return '';
    const s = typeof v === 'number' ? String(v).replace('.', ',') : v;
    return /[";\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  return '﻿' + rows.map((r) => r.map(cell).join(';')).join('\r\n') + '\r\n';
}

export function monitorCsv(samples: MonitorSample[]): string {
  const pad = (n: number) => String(n).padStart(2, '0');
  const local = (t: number) => {
    const d = new Date(t);
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  };
  return toCsv([['ora', 'router_ms', 'internet_ms'], ...samples.map((s) => [local(s.t), s.gw, s.inet])]);
}
