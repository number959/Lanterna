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

/** Caratteri che servono almeno nelle etichette: un indirizzo IPv4 intero. */
const MIN_CHARS = 15;

export function stageLayout(sc: TrafficScenario, has: (id: string) => boolean, width: number): StageLayout {
  const w = Math.max(300, Math.floor(width) || 0);
  if (w >= VERTICAL_BELOW) {
    const L = layoutOf(sc, has, w, false);
    // Tra 540 e 760 px, se le etichette non contengono un indirizzo intero, meglio dall'alto in basso.
    if (w >= 760 || Math.min(...[...L.slots.values()].map((sl) => sl.chars)) >= MIN_CHARS) return L;
  }
  return layoutOf(sc, has, w, true);
}

function layoutOf(sc: TrafficScenario, has: (id: string) => boolean, w: number, vertical: boolean): StageLayout {
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
  // Il nodo della strada principale sta in mezzo agli altri della sua colonna.
  const onMain = new Set(main);
  for (const lv of levels) {
    const mi = lv.findIndex((id) => onMain.has(id));
    if (mi < 0 || lv.length < 2) continue;
    const [m] = lv.splice(mi, 1);
    lv.splice(Math.floor(lv.length / 2), 0, m);
  }
  const slots = new Map<string, Slot>();

  if (!vertical) {
    const SP = 96;
    const SPF = 56;
    const TOP = 96;
    const BOTTOM = 60;
    const MX = 60;
    const fan = (lv: string[]) => lv.length >= FAN;
    const n = levels.length;
    const lastFan = n > 0 && fan(levels[n - 1]);
    const xr = lastFan ? w - 190 : w - MX;
    // Le colonne con un elenco hanno bisogno di più spazio, per le etichette a destra.
    const need: number[] = levels.map((lv, c) => (c < n - 1 ? (fan(lv) ? 250 : 120) : 0));
    const total = need.reduce((a, b) => a + b, 0);
    const k = total > 0 ? (xr - MX) / total : 0;
    const xs: number[] = [];
    levels.forEach((_, c) => xs.push(n === 1 ? w / 2 : c === 0 ? MX : xs[c - 1] + need[c - 1] * k));
    const span = (lv: string[]) => (lv.length - 1) * (fan(lv) ? SPF : SP);
    const inner = Math.max(0, ...levels.map(span));
    const h = Math.max(300, TOP + inner + BOTTOM);
    const cy = TOP + (h - TOP - BOTTOM) / 2;
    levels.forEach((lv, c) => {
      const x = xs[c];
      const f = fan(lv);
      const gap = f ? SPF : SP;
      const left = c > 0 ? x - xs[c - 1] : 2 * x;
      const right = c < n - 1 ? xs[c + 1] - x : 2 * (w - x);
      // Etichette a destra fino alla colonna dopo; sotto il disegno, centrate tra le vicine e dentro il bordo.
      const room = f ? (c === n - 1 ? w - x - 36 : right - 80) : Math.min(left, right) - 14;
      lv.forEach((id, j) => {
        const trunk = f && parent.has(id) ? x - 46 : undefined;
        slots.set(id, { x, y: cy + (j - (lv.length - 1) / 2) * gap, s: f ? 0.6 : 0.9, right: f, chars: Math.max(6, Math.floor(room / CHAR_W)), trunk });
      });
    });
    return { w, h, vertical, slots, parent };
  }

  // Schermo stretto: un albero dall'alto in basso, le etichette a destra. Un
  // solo figlio continua sotto il padre; più figli diventano un elenco
  // rientrato, collegato da una linea comune che scende dal padre.
  const kids = new Map<string, string[]>();
  for (const id of order) {
    const pa = parent.get(id);
    if (!pa) continue;
    const l = kids.get(pa);
    if (l) l.push(id);
    else kids.set(pa, [id]);
  }
  const X0 = 50;
  const IND = 62;
  let y = 66;
  const place = (id: string, x: number, trunk: number | undefined, sc: number) => {
    slots.set(id, { x, y, s: sc, right: true, chars: Math.max(6, Math.floor((w - x - 32 * (sc / 0.74) - 10) / CHAR_W)), trunk });
    y += trunk === undefined ? 86 : 60;
    const ch = kids.get(id) ?? [];
    if (ch.length === 1) place(ch[0], x, undefined, sc);
    else if (ch.length) {
      for (const c of ch) place(c, x + IND, x, 0.58);
      y += 18;
    }
  };
  for (const id of order) if (!parent.has(id) && !slots.has(id)) place(id, X0, undefined, 0.74);
  const last = Math.max(0, ...[...slots.values()].map((sl) => sl.y));
  return { w, h: Math.max(240, last + 44), vertical, slots, parent };
}

/** Strada tra due nodi vicini, nel verso da a verso b. */
export function route(L: StageLayout, a: string, b: string): Pt[] {
  const sa = L.slots.get(a);
  const sb = L.slots.get(b);
  if (!sa || !sb) return [];
  // Sempre disegnata dal padre al figlio, poi rovesciata se serve.
  if (L.parent.get(a) === b && L.parent.get(b) !== a) return route(L, b, a).reverse();
  const pts: Pt[] = [{ x: sa.x, y: sa.y }];
  let y0 = sa.y;
  // Da un nodo con l'etichetta a destra la linea esce dal basso, sotto l'etichetta.
  if (!L.vertical && sa.right && sb.x > sa.x + 30) {
    y0 = sa.y + 26;
    pts.push({ x: sa.x, y: y0 });
  }
  if (L.parent.get(b) === a && sb.trunk !== undefined) {
    if (L.vertical) {
      if (Math.abs(sa.x - sb.trunk) <= 1) {
        pts.push({ x: sb.trunk, y: sb.y }, { x: sb.x, y: sb.y });
        return pts;
      }
    } else if (sb.trunk - sa.x >= 30) {
      pts.push({ x: sb.trunk, y: y0 }, { x: sb.trunk, y: sb.y }, { x: sb.x, y: sb.y });
      return pts;
    }
  }
  if (y0 !== sa.y) pts.push({ x: sb.x - 34, y: y0 });
  pts.push({ x: sb.x, y: sb.y });
  return pts;
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

/** Nota sull'esito del pacchetto, come la scrive il motore; per i pacchetti scartati senza nota, una generica. */
export function packetNote(p: TrafficPacket): { text: string; sev: 'ok' | 'warn' | 'crit' } | undefined {
  if (p.note) return { text: p.note, sev: p.sev ?? 'warn' };
  if (p.stopAt !== undefined) return { text: STOP_TEXT[p.sev ?? 'warn'], sev: p.sev ?? 'warn' };
  return undefined;
}

/** Il nodo dove segnalare un pacchetto passato da una zona che doveva essere isolata: il dispositivo isolato. */
export const breachNode = (p: TrafficPacket) => (p.dir === 'response' ? p.hops[0] : p.hops[reachOf(p)]);
