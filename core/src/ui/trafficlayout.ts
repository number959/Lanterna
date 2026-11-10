import type { TrafficPacket, TrafficScenario } from '../engine';

// Disposizione e tempi di "Il traffico passo passo", senza React: i nodi della
// scena su una griglia isometrica, la telecamera che inquadra i nodi già
// comparsi, le corsie tra i nodi, le etichette che non si sovrappongono e la
// linea del tempo della riproduzione.

export type Pt = { x: number; y: number };

/** Larghezza di un carattere delle etichette (monospaziato a 11,5 px). */
export const CHAR_W = 7;

/** I nodi attraversati, sempre nel verso che si allontana dal PC. */
export function outwardPaths(sc: TrafficScenario, has: (id: string) => boolean): string[][] {
  return sc.steps
    .flatMap((s) => s.packets)
    .map((p) => (p.dir === 'response' ? [...p.hops].reverse() : p.hops).filter(has))
    .filter((h) => h.length > 0);
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

/** Riga breve sotto l'etichetta del pacchetto in viaggio ("A? www.esempio.it", "→ 443"). */
export function briefOf(p: TrafficPacket): string {
  const i = p.info;
  let m: RegExpExecArray | null;
  if ((m = /^Standard query response A (.+)$/.exec(i))) return `A ${m[1]}`;
  if ((m = /^Standard query A (.+)$/.exec(i))) return `A? ${m[1]}`;
  if ((m = /SNI=([^)]+)\)/.exec(i))) return `SNI=${m[1]}`;
  if ((m = /\(GET ([^)]+)\)/.exec(i))) return `GET ${m[1]}`;
  if ((m = /^Application Data \((.+)\)$/.exec(i))) return m[1];
  if ((m = /^(?:\[Ritrasmissione\] )?(\S+) → (\S+) \[([^\]]+)\]/.exec(i))) return `${m[1]} → ${m[2]}${i.startsWith('[') ? ' (di nuovo)' : ''}`;
  if ((m = /TTL=(\d+)/.exec(i))) return `TTL=${m[1]}`;
  if ((m = /seq=(\d+)/.exec(i))) return `seq=${m[1]}`;
  if (/^Time-to-live exceeded/.test(i)) return `da ${p.src}`;
  if (/^Echo \(ping\) reply/.test(i)) return `da ${p.src}`;
  if (/^Echo \(ping\) request/.test(i)) return `a ${p.dst}`;
  if ((m = /^DHCP (Discover|Request)/.exec(i))) return '0.0.0.0 → tutti';
  if ((m = /^DHCP (?:Offer|ACK) (.+)$/.exec(i))) return m[1];
  if (/^IPP successful-ok/.test(i)) return 'successful-ok';
  if (/Print-Job/.test(i)) return 'Print-Job';
  if (/^Alert/.test(i)) return 'Alert';
  return clip(i, 24);
}

/** La parte di strada già percorsa (per la scia del pacchetto), fino alla frazione t. */
export function trailOf(routes: Pt[][], t: number): Pt[] {
  const n = routes.length;
  if (!n || t <= 0) return [];
  const d = Math.min(n, t * n);
  const k = Math.min(n - 1, Math.floor(d));
  const pts: Pt[] = [];
  for (let i = 0; i < k; i++) for (const q of routes[i]) if (!pts.length || pts[pts.length - 1].x !== q.x || pts[pts.length - 1].y !== q.y) pts.push(q);
  const r = routes[k];
  const f = d - k;
  if (!r.length) return pts;
  // Fino al punto raggiunto sulla spezzata del tratto in corso.
  const seg: number[] = [];
  let total = 0;
  for (let i = 1; i < r.length; i++) {
    const l = Math.hypot(r[i].x - r[i - 1].x, r[i].y - r[i - 1].y);
    seg.push(l);
    total += l;
  }
  let left = f * total;
  if (!pts.length || pts[pts.length - 1].x !== r[0].x || pts[pts.length - 1].y !== r[0].y) pts.push(r[0]);
  for (let i = 0; i < seg.length; i++) {
    if (left >= seg[i]) {
      pts.push(r[i + 1]);
      left -= seg[i];
      continue;
    }
    const q = seg[i] ? left / seg[i] : 0;
    pts.push({ x: r[i].x + (r[i + 1].x - r[i].x) * q, y: r[i].y + (r[i + 1].y - r[i].y) * q });
    break;
  }
  return pts;
}


// ---------------------------------------------------------------- scena isometrica

/** Passo della griglia isometrica, in pixel della scena (a zoom 1). */
export const ISO_G = 84;
const IC = Math.cos(Math.PI / 6);
/** Scala dei disegni rispetto allo zoom della telecamera. */
export const GLYPH = 0.95;
/** Zoom massimo: con il solo PC in scena il portatile è grande, come all'inizio di un racconto. */
export const K_MAX = 2;
/** Durata di un movimento della telecamera. */
export const CAM_MS = 850;
/** Sotto questa larghezza la strada scende a zig-zag invece di andare verso destra. */
export const NARROW_BELOW = 600;

export type Box = { x0: number; y0: number; x1: number; y1: number };
export type Side = 'left' | 'right' | 'below';

export interface IsoScene {
  /** Posizione di ogni nodo sulla scena (prima della telecamera), sul punto a terra del disegno. */
  places: Map<string, Pt>;
  parent: Map<string, string>;
  /** Punti intermedi della corsia tra un nodo e il figlio ("genitore>figlio"): la dorsale delle colonne. */
  via: Map<string, Pt[]>;
  /** Da che parte scrivere l'etichetta di ogni nodo (fissata per tutta la scena, così non salta). */
  sides: Map<string, Side>;
  /** Per ogni nodo, il primo pacchetto della linea del tempo che lo raggiunge e a quale salto. */
  first: Map<string, { entry: number; hop: number }>;
  root?: string;
}

const isoPt = (gx: number, gy: number): Pt => ({ x: (gx - gy) * IC * ISO_G, y: (gx + gy) * 0.5 * ISO_G });
const plus = (a: Pt, b: Pt, m = 1): Pt => ({ x: a.x + b.x * m, y: a.y + b.y * m });
/** Distanza verticale tra i nodi di una colonna. */
const COL_GAP = 80;

/**
 * Disposizione come in uno schema isometrico. La strada principale (verso
 * Internet, altrimenti la più lunga) procede a zig-zag lungo le diagonali: in
 * alto a destra e in basso a destra sullo schermo largo; sullo schermo stretto
 * scende, un mezzo passo a destra e uno a sinistra, con le etichette tutte a
 * destra. Con due figli il secondo prende l'altra diagonale; con tre o più
 * (sullo schermo stretto già con due) i figli stanno in colonna, raggiunti da
 * una dorsale comune, con le etichette a destra. Un nodo non va mai sopra un
 * altro.
 */
export function isoScene(sc: TrafficScenario, has: (id: string) => boolean, entries: Entry[], narrow = false): IsoScene {
  const paths = outwardPaths(sc, has);
  const main = paths.find((h) => h[h.length - 1] === 'internet') ?? paths.reduce<string[]>((a, b) => (b.length > a.length ? b : a), []);
  const parent = new Map<string, string>();
  const order: string[] = [];
  const seen = new Set<string>();
  const visit = (id: string, from?: string) => {
    if (seen.has(id)) return;
    seen.add(id);
    order.push(id);
    if (from) parent.set(id, from);
  };
  for (const h of [main, ...paths]) {
    if (!h.length) continue;
    visit(h[0]);
    for (let i = 1; i < h.length; i++) visit(h[i], h[i - 1]);
  }
  const onMain = new Set(main);
  const kids = new Map<string, string[]>();
  for (const id of order) {
    const pa = parent.get(id);
    if (!pa) continue;
    const l = kids.get(pa) ?? [];
    l.push(id);
    kids.set(pa, l);
  }
  for (const l of kids.values()) l.sort((a, b) => Number(onMain.has(b)) - Number(onMain.has(a)));

  const STEPS: Pt[] = narrow ? [isoPt(2, 1), isoPt(1, 2)] : [isoPt(0, -2), isoPt(2, 0)];
  const pos = new Map<string, Pt>();
  const via = new Map<string, Pt[]>();
  const column = new Set<string>();
  const taken = (p: Pt) => [...pos.values()].some((q) => Math.abs(q.x - p.x) < 110 && Math.abs(q.y - p.y) < 58);
  const firstFree = (base: Pt, cands: Pt[]): Pt => {
    for (const c of cands) {
      const p = plus(base, c);
      if (!taken(p)) return p;
    }
    for (let m = 2; m < 16; m++) {
      const p = plus(base, cands[0], m);
      if (!taken(p)) return p;
    }
    return plus(base, cands[0]);
  };
  const place = (id: string, p: Pt, turn: number) => {
    pos.set(id, p);
    const ch = kids.get(id) ?? [];
    if (!ch.length) return;
    const dir = STEPS[turn % 2];
    const other = STEPS[(turn + 1) % 2];
    if (ch.length === 1 || (ch.length === 2 && !narrow)) {
      place(ch[0], firstFree(p, [dir, other, plus(dir, other)]), turn + 1);
      if (ch[1]) place(ch[1], firstFree(p, [other, plus(dir, other), plus(other, other)]), turn);
      return;
    }
    // Colonna: a destra (largo) o sotto, rientrata (stretto, già da due figli:
    // con le etichette tutte a destra due nodi affiancati si toccherebbero).
    // La si sposta finché è libera.
    const n = ch.length;
    const at = (j: number, shift: number): Pt =>
      narrow ? { x: p.x + 92, y: p.y + 118 + shift + j * COL_GAP } : { x: p.x + 300 + shift, y: p.y + (j - (n - 1) / 2) * COL_GAP };
    let shift = 0;
    while (shift < 2000 && ch.some((_, j) => taken(at(j, shift)))) shift += narrow ? COL_GAP : 150;
    // Sullo schermo stretto il figlio della strada principale va in fondo: il
    // suo seguito scende sotto la colonna invece di attraversarla.
    const col = narrow && onMain.has(ch[0]) && kids.get(ch[0])?.length ? [...ch.slice(1), ch[0]] : ch;
    col.forEach((c, j) => {
      const q = at(j, shift);
      // La dorsale: in verticale lungo la colonna, poi un tratto dritto fino al nodo.
      via.set(`${id}>${c}`, narrow ? [{ x: p.x, y: q.y }] : [{ x: q.x - 96, y: p.y }, { x: q.x - 96, y: q.y }]);
      column.add(c);
      // Posti riservati prima di scendere nei sottoalberi.
      pos.set(c, q);
    });
    col.forEach((c, j) => place(c, at(j, shift), turn + 1));
  };
  const root = main[0] ?? sc.lanes.find(has);
  if (root) place(root, { x: 0, y: 0 }, 0);
  for (const id of sc.lanes) if (has(id) && !pos.has(id)) place(id, firstFree({ x: 0, y: 0 }, [isoPt(2, 2), isoPt(3, 3), isoPt(-2, 0)]), 0);

  // Lato delle etichette: a destra sullo schermo stretto e nelle colonne; altrove il più lontano dalle corsie.
  const adj = new Map<string, Pt[]>();
  const toward = (a: string, b: string): Pt | undefined => {
    const v = via.get(`${a}>${b}`);
    if (v?.length) return v[0];
    const w = via.get(`${b}>${a}`);
    if (w?.length) return w[w.length - 1];
    return pos.get(b);
  };
  for (const h of paths)
    for (let i = 1; i < h.length; i++) {
      const [a, b] = [h[i - 1], h[i]];
      if (a === b) continue;
      for (const [x, y] of [
        [a, b],
        [b, a],
      ]) {
        const t = toward(x, y);
        if (!t) continue;
        const l = adj.get(x) ?? [];
        l.push(t);
        adj.set(x, l);
      }
    }
  const sides = new Map<string, Side>();
  for (const [id, p] of pos) sides.set(id, narrow || column.has(id) ? 'right' : sideAway(p, adj.get(id) ?? []));

  // Quando compare ogni nodo: al primo pacchetto che va verso di lui. I nodi
  // oltre il punto in cui il pacchetto si ferma compaiono all'ultimo tratto.
  const first = new Map<string, { entry: number; hop: number }>();
  if (root) first.set(root, { entry: 0, hop: 0 });
  entries.forEach((e, i) => {
    if (!e.p) return;
    const end = reachOf(e.p);
    e.p.hops.forEach((h, k) => {
      if (!first.has(h)) first.set(h, { entry: i, hop: Math.min(k, end) });
    });
  });
  return { places: pos, parent, via, sides, first, root };
}

/** Il lato (sinistra, sotto, destra) più lontano dalle direzioni delle corsie; a parità, in quest'ordine. */
function sideAway(p: Pt, toward: Pt[]): Side {
  const angles = toward.map((q) => Math.atan2(q.y - p.y, q.x - p.x));
  const SIDES: [Side, number][] = [
    ['left', Math.PI],
    ['below', Math.PI / 2],
    ['right', 0],
  ];
  const gap = (a: number, b: number) => {
    const d = Math.abs(a - b) % (2 * Math.PI);
    return d > Math.PI ? 2 * Math.PI - d : d;
  };
  let best: Side = 'left';
  let score = -1;
  for (const [side, a] of SIDES) {
    const sc = angles.length ? Math.min(...angles.map((b) => gap(a, b))) : Math.PI;
    if (sc > score + 1e-6) {
      best = side;
      score = sc;
    }
  }
  return best;
}

/**
 * Il nodo è in scena: raggiunto da un pacchetto precedente, o il pacchetto in
 * corso gli arriverà entro due tratti. Così la telecamera allarga
 * l'inquadratura con un tratto di anticipo e arriva prima del pacchetto.
 */
export function revealed(scene: IsoScene, id: string, entryIdx: number, hopAt: number): boolean {
  const f = scene.first.get(id);
  if (!f) return false;
  return f.entry < entryIdx || (f.entry === entryIdx && hopAt >= f.hop - 2);
}

export interface Camera {
  /** Zoom. */
  k: number;
  /** Spostamento: punto sullo schermo = punto della scena × k + (x, y). */
  x: number;
  y: number;
}

export const toScreen = (c: Camera, p: Pt): Pt => ({ x: p.x * c.k + c.x, y: p.y * c.k + c.y });

/** Inquadratura che contiene i riquadri dati (in coordinate della scena) nel palco w × h. */
export function fitCamera(boxes: Box[], w: number, h: number, kMax = K_MAX, pad = 18): Camera {
  if (!boxes.length) return { k: 1, x: w / 2, y: h / 2 };
  const x0 = Math.min(...boxes.map((b) => b.x0));
  const y0 = Math.min(...boxes.map((b) => b.y0));
  const x1 = Math.max(...boxes.map((b) => b.x1));
  const y1 = Math.max(...boxes.map((b) => b.y1));
  const k = Math.max(0.2, Math.min(kMax, (w - 2 * pad) / Math.max(1, x1 - x0), (h - 2 * pad) / Math.max(1, y1 - y0)));
  return { k, x: w / 2 - ((x0 + x1) / 2) * k, y: h / 2 - ((y0 + y1) / 2) * k };
}

/** Quello che serve sapere di un nodo per metterlo in scena. */
export interface IsoInfo {
  name: string;
  sub: string;
  /** Altezza del disegno sopra il punto a terra, a scala 1. */
  top: number;
}

/** Fumetto con l'indirizzo che si scrive, sopra il PC. */
export const bubbleW = (text: string) => 34 + text.length * 7.2;
export const BUBBLE_H = 24;

const LABEL_H = 30;
/** Caratteri al massimo nelle etichette: l'inquadratura li fa stare, sullo schermo si accorciano solo se toccherebbero altro. */
const LABEL_LONG = 30;

/** Riquadro del disegno sullo schermo, attorno al punto a terra p con scala s. */
export function glyphBox(p: Pt, s: number, top: number): Box {
  return { x0: p.x - 46 * s, x1: p.x + 46 * s, y0: p.y - top * s, y1: p.y + 22 * s };
}

/** Riquadro dell'etichetta sullo schermo, con n caratteri. */
export function labelBox(p: Pt, s: number, side: Side, n: number): Box {
  const w = n * CHAR_W;
  if (side === 'left') return { x0: p.x - 40 * s - 8 - w, x1: p.x - 40 * s - 8, y0: p.y - 9, y1: p.y - 9 + LABEL_H };
  if (side === 'right') return { x0: p.x + 40 * s + 8, x1: p.x + 40 * s + 8 + w, y0: p.y - 9, y1: p.y - 9 + LABEL_H };
  return { x0: p.x - w / 2, x1: p.x + w / 2, y0: p.y + 22 * s + 4, y1: p.y + 22 * s + 4 + LABEL_H };
}

/** Riquadro del fumetto sopra il disegno. */
export function bubbleBox(p: Pt, s: number, top: number, text: string): Box {
  const w = bubbleW(text);
  const y1 = p.y - top * s - 14;
  return { x0: p.x - w / 2 - 18, x1: p.x + w / 2 - 18, y0: y1 - BUBBLE_H, y1 };
}

/**
 * Altezza del palco. Sullo schermo largo segue la larghezza; su quello
 * stretto cresce con la scena (le colonne lunghe), perché a fine scena i
 * disegni restino ad almeno metà grandezza e le etichette non si tocchino.
 */
export function stageHeight(scene: IsoScene, w: number): number {
  if (w >= NARROW_BELOW) return Math.min(440, Math.max(300, Math.round(w * 0.5)));
  const ys = [...scene.places.values()].map((p) => p.y);
  const span = ys.length ? Math.max(...ys) - Math.min(...ys) + 120 : 0;
  return Math.min(760, Math.max(380, Math.round(w * 1.2), Math.round(span * 0.5 + 76)));
}

/** Inquadratura dei nodi dati, con i disegni, le etichette intere e il fumetto dentro il palco. */
export function sceneCamera(scene: IsoScene, ids: string[], info: (id: string) => IsoInfo, w: number, h: number, bubble?: { id: string; text: string }): Camera {
  let k = K_MAX;
  let cam: Camera = { k, x: 0, y: 0 };
  for (let it = 0; it < 5; it++) {
    const s = k * GLYPH;
    const boxes: Box[] = [];
    for (const id of ids) {
      const p = scene.places.get(id);
      if (!p) continue;
      const nf = info(id);
      // Sullo schermo con il punto a terra nell'origine, poi riportati alla scena.
      const o = { x: 0, y: 0 };
      const n = Math.min(LABEL_LONG, Math.max(nf.name.length, nf.sub.length));
      const parts = [glyphBox(o, s, nf.top), labelBox(o, s, scene.sides.get(id) ?? 'left', n)];
      if (bubble?.id === id) parts.push(bubbleBox(o, s, nf.top, bubble.text));
      for (const b of parts) boxes.push({ x0: p.x + b.x0 / k, x1: p.x + b.x1 / k, y0: p.y + b.y0 / k, y1: p.y + b.y1 / k });
    }
    cam = fitCamera(boxes, w, h);
    if (Math.abs(cam.k - k) < 1e-3) break;
    k = cam.k;
  }
  return cam;
}

export interface Placed {
  p: Pt;
  s: number;
  side: Side;
  /** Caratteri dell'etichetta che stanno senza toccare i vicini. */
  chars: number;
  glyph: Box;
  label: Box;
}

const hit = (a: Box, b: Box) => a.x0 < b.x1 && b.x0 < a.x1 && a.y0 < b.y1 && b.y0 < a.y1;

/**
 * I nodi sullo schermo con la telecamera data. Le etichette si accorciano
 * (con i puntini) se toccherebbero un altro disegno, un'altra etichetta o il
 * bordo del palco largo w, ma gli indirizzi restano interi.
 */
export function frameScene(scene: IsoScene, ids: string[], info: (id: string) => IsoInfo, cam: Camera, w = Infinity): Map<string, Placed> {
  const s = cam.k * GLYPH;
  const out = new Map<string, Placed>();
  const glyphs = new Map<string, Box>();
  for (const id of ids) {
    const q = scene.places.get(id);
    if (q) glyphs.set(id, glyphBox(toScreen(cam, q), s, info(id).top));
  }
  const labels: Box[] = [];
  for (const id of ids) {
    const q = scene.places.get(id);
    const g = glyphs.get(id);
    if (!q || !g) continue;
    const p = toScreen(cam, q);
    const nf = info(id);
    const side = scene.sides.get(id) ?? 'left';
    const full = Math.min(LABEL_LONG, Math.max(nf.name.length, nf.sub.length));
    const least = Math.min(full, Math.max(8, nf.sub.length));
    let chars = full;
    let box = labelBox(p, s, side, chars);
    const clash = (b: Box) => b.x0 < 0 || b.x1 > w || labels.some((l) => hit(l, b)) || [...glyphs].some(([o, gb]) => o !== id && hit(gb, b));
    while (chars > least && clash(box)) box = labelBox(p, s, side, --chars);
    labels.push(box);
    out.set(id, { p, s, side, chars, glyph: g, label: box });
  }
  return out;
}

/** La spezzata spostata di off di lato (a destra del verso di percorrenza, sullo schermo), con i giunti ad angolo. */
export function offsetLine(pts: Pt[], off: number): Pt[] {
  const n = pts.length;
  const nor = (a: Pt, b: Pt): Pt => {
    const l = Math.hypot(b.x - a.x, b.y - a.y) || 1;
    return { x: -(b.y - a.y) / l, y: (b.x - a.x) / l };
  };
  return pts.map((p, i) => {
    const n1 = i > 0 ? nor(pts[i - 1], p) : nor(p, pts[1]);
    const n2 = i < n - 1 ? nor(p, pts[i + 1]) : n1;
    const m = { x: n1.x + n2.x, y: n1.y + n2.y };
    const ml = Math.hypot(m.x, m.y) || 1;
    const u = { x: m.x / ml, y: m.y / ml };
    const k = Math.min(3, 1 / Math.max(0.2, u.x * n1.x + u.y * n1.y));
    return { x: p.x + u.x * off * k, y: p.y + u.y * off * k };
  });
}

/**
 * Due corsie tratteggiate lungo la spezzata da a a b: l'andata (a → b) da un
 * lato e il ritorno (b → a) dall'altro, accorciate alle estremità per non
 * entrare nei disegni.
 */
export function lanes(pts: Pt[], off: number, shrinkA: number, shrinkB: number): { out: Pt[]; back: Pt[] } {
  const q = pts.map((p) => ({ ...p }));
  const cut = (i: number, j: number, by: number) => {
    const l = Math.hypot(q[j].x - q[i].x, q[j].y - q[i].y) || 1;
    const d = Math.min(by, l * 0.4);
    q[i] = { x: q[i].x + ((q[j].x - q[i].x) / l) * d, y: q[i].y + ((q[j].y - q[i].y) / l) * d };
  };
  if (q.length >= 2) {
    cut(0, 1, shrinkA);
    cut(q.length - 1, q.length - 2, shrinkB);
  }
  return { out: offsetLine(q, off), back: offsetLine(q, -off).reverse() };
}

/** Indirizzo da scrivere nel fumetto all'inizio della scena: il sito, per la scena del browser. */
export function typedTarget(sc: TrafficScenario): string | undefined {
  if (sc.id !== 'web') return undefined;
  return sc.steps[0]?.fields.find((f) => f.k === 'Destinazione')?.v;
}

/** Telecamera a metà strada tra due inquadrature: centro in linea retta, zoom in scala logaritmica. */
export function lerpCamera(a: Camera, b: Camera, w: number, h: number, f: number): Camera {
  const e = f < 0.5 ? 4 * f * f * f : 1 - Math.pow(-2 * f + 2, 3) / 2;
  const ca = { x: (w / 2 - a.x) / a.k, y: (h / 2 - a.y) / a.k };
  const cb = { x: (w / 2 - b.x) / b.k, y: (h / 2 - b.y) / b.k };
  const k = Math.exp(Math.log(a.k) + (Math.log(b.k) - Math.log(a.k)) * e);
  const cx = ca.x + (cb.x - ca.x) * e;
  const cy = ca.y + (cb.y - ca.y) * e;
  return { k, x: w / 2 - cx * k, y: h / 2 - cy * k };
}

/** Righe della griglia a terra visibili nel palco, già sullo schermo. */
export function groundLines(cam: Camera, w: number, h: number): [Pt, Pt][] {
  const inv = (x: number, y: number) => {
    const sx = (x - cam.x) / cam.k / (IC * ISO_G);
    const sy = (y - cam.y) / cam.k / (0.5 * ISO_G);
    return { gx: (sx + sy) / 2, gy: (sy - sx) / 2 };
  };
  const cs = [inv(0, 0), inv(w, 0), inv(0, h), inv(w, h)];
  const gx0 = Math.floor(Math.min(...cs.map((c) => c.gx)));
  const gx1 = Math.ceil(Math.max(...cs.map((c) => c.gx)));
  const gy0 = Math.floor(Math.min(...cs.map((c) => c.gy)));
  const gy1 = Math.ceil(Math.max(...cs.map((c) => c.gy)));
  if ((gx1 - gx0) * (gy1 - gy0) > 4000) return [];
  const out: [Pt, Pt][] = [];
  for (let gx = gx0; gx <= gx1; gx++) out.push([toScreen(cam, isoPt(gx, gy0)), toScreen(cam, isoPt(gx, gy1))]);
  for (let gy = gy0; gy <= gy1; gy++) out.push([toScreen(cam, isoPt(gx0, gy)), toScreen(cam, isoPt(gx1, gy))]);
  return out;
}
