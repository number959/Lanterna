import type { PingStats } from '../engine/types';

// Generatori di misure plausibili per le reti dimostrative: deterministici,
// così la demo e i test vedono sempre gli stessi valori.

export const pingSamples = (base: number, spread: number, n: number, lost: number[] = [], phase = 0) =>
  Array.from({ length: n }, (_, i) =>
    lost.includes(i) ? null : Math.round((base + spread * Math.abs(Math.sin(i * 1.7 + phase)) * (0.6 + 0.4 * Math.abs(Math.cos(i * 0.9 + phase)))) * 10) / 10,
  );

export function stats(target: string, label: string, samples: (number | null)[], method: 'icmp' | 'tcp' = 'icmp'): PingStats {
  const ok = samples.filter((s): s is number => s !== null);
  let j = 0;
  for (let i = 1; i < ok.length; i++) j += Math.abs(ok[i] - ok[i - 1]);
  return {
    target,
    label,
    sent: samples.length,
    received: ok.length,
    minMs: Math.min(...ok),
    avgMs: Math.round((ok.reduce((a, b) => a + b, 0) / ok.length) * 10) / 10,
    maxMs: Math.max(...ok),
    jitterMs: Math.round((j / Math.max(1, ok.length - 1)) * 10) / 10,
    samples,
    method,
  };
}
