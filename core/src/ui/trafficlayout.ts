import type { TrafficPacket, TrafficScenario } from '../engine';

// Disposizione e tempi di "Il traffico passo passo", senza React: i nodi della
// scena in colonne per distanza dal PC (in righe sullo schermo stretto), le
// strade tra i nodi e la linea del tempo della riproduzione.

export type Pt = { x: number; y: number };

export interface Slot {
  x: number;
  y: number;
  /** Scala del disegno del dispositivo. */
  s: number;
  /** Etichetta a destra del disegno (elenchi) invece che sotto. */
  right: boolean;
  /** Caratteri che stanno nell'etichetta. */
  chars: number;
  /** Ascissa (o, in verticale, ordinata non usata) della linea comune da cui parte il ramo. */
  trunk?: number;
}

export interface StageLayout {
  w: number;
  h: number;
  vertical: boolean;
  slots: Map<string, Slot>;
  parent: Map<string, string>;
}

/** Larghezza media di un carattere dell'etichetta a 12 px. */
export const CHAR_W = 6.8;
/** Sotto questa larghezza la scena si dispone dall'alto in basso. */
export const VERTICAL_BELOW = 540;
/** Da quanti nodi alla stessa distanza si passa all'elenco con le etichette a destra. */
const FAN = 3;

/** I nodi attraversati, sempre nel verso che si allontana dal PC. */
export function outwardPaths(sc: TrafficScenario, has: (id: string) => boolean): string[][] {
  return sc.steps
    .flatMap((s) => s.packets)
    .map((p) => (p.dir === 'response' ? [...p.hops].reverse() : p.hops).filter(has))
    .filter((h) => h.length > 0);
}

export function stageLayout(sc: TrafficScenario, has: (id: string) => boolean, width: number): StageLayout {
  const w = Math.max(300, Math.floor(width) || 0);
  const vertical = w < VERTICAL_BELOW;
  const paths = outwardPaths(sc, has);
  // La strada principale: quella verso Internet, altrimenti la più lunga.
  const main = paths.find((h) => h[h.length - 1] === 'internet') ?? paths.reduce<string[]>((a, b) => (b.length > a.length ? b : a), []);
  const depth = new Map<string, number>();
  const parent = new Map<string, string>();
  const order: string[] = [];
  const visit = (id: string, d: number, from?: string) => {
    if (depth.has(id)) return;
    depth.set(id, d);
    order.push(id);
    if (from) parent.set(id, from);
  };
  for (const h of [main, ...paths]) {
    if (!h.length) continue;
    visit(h[0], 0);
    for (let i = 1; i < h.length; i++) visit(h[i], depth.get(h[i - 1])! + 1, h[i - 1]);
  }
  for (const id of sc.lanes) if (has(id)) visit(id, 0);
  const levels: string[][] = [];
  for (const id of order) {
    const d = depth.get(id)!;
    (levels[d] = levels[d] || []).push(id);
  }
  const slots = new Map<string, Slot>();

  if (!vertical) {
    const SP = 96;
    const SPF = 56;
    const TOP = 96;
    const BOTTOM = 60;
    const MX = 70;
    const fan = (lv: string[]) => lv.length >= FAN;
    const n = levels.length;
    const lastFan = n > 0 && fan(levels[n - 1]);
    const xr = lastFan ? w - 210 : w - MX;
    const step = n > 1 ? (xr - MX) / (n - 1) : 0;
    const span = (lv: string[]) => (lv.length - 1) * (fan(lv) ? SPF : SP);
    const inner = Math.max(0, ...levels.map(span));
    const h = Math.max(300, TOP + inner + BOTTOM);
    const cy = TOP + (h - TOP - BOTTOM) / 2;
    levels.forEach((lv, c) => {
      const x = n === 1 ? w / 2 : MX + c * step;
      const f = fan(lv);
      const gap = f ? SPF : SP;
      // Etichette sotto il disegno: centrate, quindi limitate anche dal bordo più vicino.
      const room = f ? (c === n - 1 ? w - x - 36 : step - 70) : Math.min(n > 1 ? step - 14 : w - 24, 2 * Math.min(x, w - x) - 8);
      lv.forEach((id, j) => {
        const trunk = f && parent.has(id) ? x - 46 : undefined;
        slots.set(id, { x, y: cy + (j - (lv.length - 1) / 2) * gap, s: f ? 0.6 : 0.9, right: f, chars: Math.max(6, Math.floor(room / CHAR_W)), trunk });
      });
    });
    return { w, h, vertical, slots, parent };
  }

  // Schermo stretto: dall'alto in basso, le etichette a destra; più nodi alla
  // stessa distanza diventano un elenco rientrato, collegato da una linea comune.
  const X0 = 50;
  const XI = 112;
  let y = 66;
  for (const lv of levels) {
    if (lv.length === 1) {
      slots.set(lv[0], { x: X0, y, s: 0.74, right: true, chars: Math.max(6, Math.floor((w - X0 - 30 - 8) / CHAR_W)) });
      y += 86;
    } else {
      for (const id of lv) {
        slots.set(id, { x: XI, y, s: 0.58, right: true, chars: Math.max(6, Math.floor((w - XI - 26 - 8) / CHAR_W)), trunk: X0 });
        y += 60;
      }
      y += 18;
    }
  }
  const last = Math.max(0, ...[...slots.values()].map((sl) => sl.y));
  return { w, h: Math.max(240, last + 44), vertical, slots, parent };
}

/** Strada tra due nodi vicini, nel verso da a verso b. */
export function route(L: StageLayout, a: string, b: string): Pt[] {
  const sa = L.slots.get(a);
  const sb = L.slots.get(b);
  if (!sa || !sb) return [];
  const branch = (from: Slot, to: Slot): Pt[] | undefined => {
    if (to.trunk === undefined) return undefined;
    if (L.vertical) {
      if (Math.abs(from.x - to.trunk) > 1) return undefined;
      return [{ x: from.x, y: from.y }, { x: to.trunk, y: to.y }, { x: to.x, y: to.y }];
    }
    if (to.trunk - from.x < 30) return undefined;
    return [{ x: from.x, y: from.y }, { x: to.trunk, y: from.y }, { x: to.trunk, y: to.y }, { x: to.x, y: to.y }];
  };
  if (L.parent.get(b) === a) {
    const r = branch(sa, sb);
    if (r) return r;
  }
  if (L.parent.get(a) === b) {
    const r = branch(sb, sa);
    if (r) return r.reverse();
  }
  return [{ x: sa.x, y: sa.y }, { x: sb.x, y: sb.y }];
}

/** Punto a una frazione f (0..1) di una spezzata, in proporzione alla lunghezza. */
export function onPolyline(pts: Pt[], f: number): Pt {
  if (!pts.length) return { x: 0, y: 0 };
  const seg: number[] = [];
  let total = 0;
  for (let i = 1; i < pts.length; i++) {
    const l = Math.hypot(pts[i].x - pts[i - 1].x, pts[i].y - pts[i - 1].y);
    seg.push(l);
    total += l;
  }
  if (!total) return pts[0];
  let r = Math.min(1, Math.max(0, f)) * total;
  for (let i = 0; i < seg.length; i++) {
    if (r <= seg[i] || i === seg.length - 1) {
      const k = seg[i] ? Math.min(1, r / seg[i]) : 1;
      return { x: pts[i].x + (pts[i + 1].x - pts[i].x) * k, y: pts[i].y + (pts[i + 1].y - pts[i].y) * k };
    }
    r -= seg[i];
  }
  return pts[pts.length - 1];
}

/** Punto a una frazione t (0..1) del viaggio: ogni tratto tra due nodi dura uguale. */
export function along(routes: Pt[][], t: number): Pt {
  const n = routes.length;
  if (!n) return { x: 0, y: 0 };
  const d = Math.min(n, Math.max(0, t * n));
  const i = Math.min(n - 1, Math.floor(d));
  return onPolyline(routes[i], d - i);
}

// ------------------------------------------------ linea del tempo

/** Tempo per un tratto tra due nodi a velocità 1×. */
export const SEG_MS = 800;
/** Sosta all'arrivo, perché si veda dove è arrivato. */
export const HOLD_MS = 420;
/** Sosta di un pacchetto scartato, con la ✕. */
export const HOLD_STOP_MS = 1400;
/** Un passo senza pacchetti. */
export const DWELL_MS = 2000;

export type Entry = { si: number; p?: TrafficPacket };

/** Indice dell'ultimo nodo raggiunto dal pacchetto. */
export const reachOf = (p: TrafficPacket) => p.stopAt ?? p.hops.length - 1;
export const travelMs = (p: TrafficPacket) => Math.max(1, reachOf(p)) * SEG_MS;
export const entryMs = (e: Entry) => (e.p ? travelMs(e.p) + (e.p.stopAt !== undefined ? HOLD_STOP_MS : HOLD_MS) : DWELL_MS);

/** Un elemento per pacchetto, e uno per ogni passo senza pacchetti. */
export function timeline(sc: TrafficScenario): Entry[] {
  return sc.steps.flatMap((s, si) => (s.packets.length ? s.packets.map((p) => ({ si, p })) : [{ si }]));
}

/** Avanza la posizione {i, t} di dt millisecondi; done quando la scena è finita. */
export function advance(es: Entry[], cur: { i: number; t: number }, dt: number, speed: number): { cur: { i: number; t: number }; done: boolean } {
  const e = es[cur.i];
  if (!e) return { cur, done: true };
  const t = cur.t + (dt * speed) / entryMs(e);
  if (t < 1) return { cur: { i: cur.i, t }, done: false };
  if (cur.i + 1 < es.length) return { cur: { i: cur.i + 1, t: 0 }, done: false };
  return { cur: { i: cur.i, t: 1 }, done: true };
}

/** Frazione del viaggio compiuta dal pacchetto, dalla frazione t dell'elemento. */
export function progressOf(e: Entry | undefined, t: number): number {
  if (!e?.p) return 0;
  return Math.min(1, (t * entryMs(e)) / travelMs(e.p));
}

/** Testo accorciato con i puntini. */
export const clip = (s: string, n: number) => (s.length > n ? `${s.slice(0, Math.max(1, n - 1))}…` : s);

const STOP_TEXT = { ok: 'bloccato, come previsto', warn: 'nessuna risposta', crit: 'nessuna risposta' } as const;

/** Nota sull'esito del pacchetto: scartato, passato quando non dovrebbe, rifiutato. */
export function packetNote(p: TrafficPacket): { text: string; sev: 'ok' | 'warn' | 'crit' } | undefined {
  if (p.stopAt !== undefined) return { text: STOP_TEXT[p.sev ?? 'warn'], sev: p.sev ?? 'warn' };
  if (p.sev === 'crit') return { text: 'passa, ma non dovrebbe', sev: 'crit' };
  if (p.sev === 'warn') return { text: 'risponde con un rifiuto', sev: 'warn' };
  return undefined;
}
