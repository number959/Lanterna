import { CELL_H, CELL_W, ZONE_BUS } from '../engine';
import type { DeviceKind, MapNode, MapSegment, NetworkMap } from '../engine';
import { iso } from './isoprims';

// Mappa della rete in prospettiva isometrica: funzioni pure, senza React, per
// proiettare la disposizione piana della mappa (topology.ts) sul piano a terra
// isometrico, mettere i titoli delle zone dove non coprono nulla, tracciare le
// due corsie del traffico (richiesta e risposta), inquadrare la camera e
// calcolare l'ordine dell'entrata in scena. Le coordinate "di schermo" qui sono
// quelle del mondo disegnato, prima della trasformazione della camera.

export type Pt = [number, number];
export interface View {
  x: number;
  y: number;
  k: number;
}
export interface Rect {
  x0: number;
  y0: number;
  x1: number;
  y1: number;
}

/** Scala del piano: un'unità della disposizione diventa ISO_SCALE pixel lungo gli assi isometrici. */
export const ISO_SCALE = 1.08;
/** Spessore delle piattaforme delle zone (pixel). */
export const ZONE_DEPTH = 9;
/** Spazio in più tra due zone impilate sullo stesso lato della dorsale, per il titolo. */
export const STACK_GAP = 30;
/** Spazio in più tra il gateway e le zone. */
export const HEAD_GAP = 24;

const clamp = (v: number, a: number, b: number) => Math.max(a, Math.min(b, v));

/** Proiezione di un punto della disposizione (x, y) a quota z. */
export function project(x: number, y: number, z = 0): Pt {
  return iso(x * ISO_SCALE, y * ISO_SCALE, z);
}
export const projectPath = (pts: Pt[]): Pt[] => pts.map(([x, y]) => project(x, y));

// ---------------------------------------------------------------- disposizione

/**
 * Copia della mappa con più spazio tra le zone: in prospettiva una zona
 * impilata sotto un'altra le sta davanti e di lato, e il suo titolo ha bisogno
 * di aria. Si spostano le zone, i loro dispositivi e la fine della dorsale.
 */
export function spaceMap(map: NetworkMap, stack = STACK_GAP, head = HEAD_GAP): NetworkMap {
  const segments = map.segments.map((s) => ({ ...s }));
  const shift = new Map<string, number>();
  for (const side of ['left', 'right', 'center'] as const) {
    segments
      .filter((s) => (s.side ?? 'center') === side)
      .sort((a, b) => a.y - b.y)
      .forEach((s, i) => shift.set(s.id, head + i * stack));
  }
  let most = 0;
  for (const s of segments) {
    const d = shift.get(s.id) ?? 0;
    most = Math.max(most, d);
    s.y += d;
    if (s.ey !== undefined) s.ey += d;
  }
  const nodes = map.nodes.map((n) => ({ ...n, y: n.y + (shift.get(n.segment) ?? 0) }));
  const bb = map.backbone;
  const backbone = bb && { ...bb, y2: Math.max(bb.y2, ...segments.map((s) => s.ey ?? bb.y2)) };
  return { ...map, nodes, segments, backbone, height: map.height + most };
}

// ---------------------------------------------------------------- percorsi (nella disposizione piana)

/**
 * Dalla linea di raccolta della zona al dispositivo: dritto per la prima riga,
 * per le righe sotto lungo il corridoio a sinistra della colonna, così la
 * linea non passa sopra i dispositivi della riga superiore.
 */
export function nodeDrop(z: MapSegment, n: MapNode): Pt[] {
  const busY = z.y + ZONE_BUS;
  if (n.y - busY < CELL_H) return [[n.x, busY], [n.x, n.y]];
  const gx = n.x - CELL_W / 2 + 4;
  return [[gx, busY], [gx, n.y], [n.x, n.y]];
}

/** Dalla linea di raccolta della zona alla dorsale (o al bordo superiore, se la zona è al centro). */
export function zoneExit(map: NetworkMap, z: MapSegment): Pt[] {
  const bx = map.backbone?.x ?? z.x + z.w / 2;
  if (z.side === 'center' || z.ex === undefined || z.ey === undefined) return [[bx, z.y + ZONE_BUS], [bx, z.y]];
  return [[z.ex, z.ey], [bx, z.ey]];
}

/** Punti del percorso tra i nodi: dentro una zona passa dalla linea di raccolta, tra le zone dalla dorsale. */
export function routePoints(map: NetworkMap, ids: string[]): Pt[] {
  const nodes = new Map(map.nodes.map((n) => [n.id, n]));
  const zones = new Map(map.segments.map((s) => [s.id, s]));
  const pts: Pt[] = [];
  const zoneOf = (n: MapNode) => zones.get(n.segment);
  for (let i = 0; i < ids.length; i++) {
    const b = nodes.get(ids[i]);
    if (!b) continue;
    if (!pts.length) {
      pts.push([b.x, b.y]);
      continue;
    }
    const a = nodes.get(ids[i - 1]);
    if (!a) {
      pts.push([b.x, b.y]);
      continue;
    }
    const za = zoneOf(a);
    const zb = zoneOf(b);
    if (za && zb && za === zb) {
      pts.push(...nodeDrop(za, a).reverse(), ...nodeDrop(zb, b));
    } else if (za && !zb) {
      pts.push(...nodeDrop(za, a).reverse(), ...zoneExit(map, za), [b.x, b.y]);
    } else if (!za && zb) {
      pts.push(...zoneExit(map, zb).reverse(), ...nodeDrop(zb, b));
    } else if (za && zb) {
      pts.push(...nodeDrop(za, a).reverse(), ...zoneExit(map, za), ...zoneExit(map, zb).reverse(), ...nodeDrop(zb, b));
    } else pts.push([b.x, b.y]);
  }
  // Toglie i punti ripetuti e apre i tratti in cui il percorso torna indietro.
  return unfold(pts.filter((p, i) => i === 0 || p[0] !== pts[i - 1][0] || p[1] !== pts[i - 1][1]));
}

/** Distanza (unità della disposizione) tra i due rami di un percorso che torna sui suoi passi. */
export const UNFOLD = 8;

const unit = (a: Pt, b: Pt): Pt => {
  const l = Math.hypot(b[0] - a[0], b[1] - a[1]) || 1;
  return [(b[0] - a[0]) / l, (b[1] - a[1]) / l];
};
const segLen = (a: Pt, b: Pt) => Math.hypot(b[0] - a[0], b[1] - a[1]);
const samePt = (a: Pt, b: Pt) => Math.abs(a[0] - b[0]) < 0.01 && Math.abs(a[1] - b[1]) < 0.01;

/**
 * Un percorso che raggiunge un dispositivo e riparte per la stessa strada
 * (l'access point nella zona del PC, il gateway tra due VLAN) si ripiega su se
 * stesso: le corsie di andata e ritorno finirebbero una sopra l'altra. Qui il
 * ramo di arrivo si sposta di lato (2·gap sul tratto in comune, gap negli
 * altri), il ramo di partenza resta sulla linea, e il dispositivo si raggiunge
 * con un breve tratto laterale. I tratti restano paralleli agli assi.
 */
export function unfold(input: Pt[], gap = UNFOLD): Pt[] {
  let pts = simplify(input);
  let from = 1;
  for (let guard = 0; guard < 12; guard++) {
    let v = -1;
    for (let i = Math.max(1, from); i < pts.length - 1; i++) {
      const u = unit(pts[i - 1], pts[i]);
      const w = unit(pts[i], pts[i + 1]);
      if (u[0] * w[0] + u[1] * w[1] < -0.99) {
        v = i;
        break;
      }
    }
    if (v < 0) return pts;
    const fwd = unfoldAt(pts, v, gap);
    const back = fwd ? null : unfoldAt(pts.slice().reverse(), pts.length - 1 - v, gap);
    const next = fwd ?? back?.reverse();
    if (next) pts = simplify(next);
    else from = v + 1;
  }
  return pts;
}

/** Apre l'inversione a U nel punto v, se il ramo di arrivo è il più corto; null se non si può. */
function unfoldAt(pts: Pt[], v: number, gap: number): Pt[] | null {
  // Tratti in comune: In_j = pts[v-j-1] → pts[v-j], Out_j = pts[v+j] → pts[v+j+1].
  let q = -1;
  for (let j = 0; v - j - 1 >= 0 && v + j + 1 < pts.length; j++) {
    const u = unit(pts[v - j - 1], pts[v - j]);
    const w = unit(pts[v + j], pts[v + j + 1]);
    if (u[0] * w[0] + u[1] * w[1] > -0.99) break;
    q = j;
    if (!samePt(pts[v - j - 1], pts[v + j + 1])) {
      // Il tratto più esterno è in comune solo in parte: lo sposta il ramo più corto.
      if (segLen(pts[v - j - 1], pts[v - j]) > segLen(pts[v + j], pts[v + j + 1])) return null;
      break;
    }
  }
  if (q < 0) return null;
  const f = v - q - 1;
  // Tratto che porta all'inizio del ramo ripiegato: si accorcia di 2·gap.
  if (f < 1 || segLen(pts[f - 1], pts[f]) <= 2 * gap + 1) return null;
  const a = unit(pts[f - 1], pts[f]);
  const normal = (j: number): Pt => {
    const d = unit(pts[v - j - 1], pts[v - j]);
    return [-d[1], d[0]];
  };
  const nq = normal(q);
  const side = -(nq[0] * a[0] + nq[1] * a[1]);
  if (Math.abs(Math.abs(side) - 1) > 0.01) return null;
  const offIn = (j: number): Pt => {
    const n = normal(j);
    const m = side * (j === q ? 2 * gap : gap);
    return [n[0] * m, n[1] * m];
  };
  const offOut = (j: number): Pt => (j === q ? [0, 0] : [-offIn(j)[0], -offIn(j)[1]]);
  const add = (p: Pt, ...ds: Pt[]): Pt => ds.reduce<Pt>((s, d) => [s[0] + d[0], s[1] + d[1]], [p[0], p[1]]);
  const inb: Pt[] = [];
  for (let i = f; i <= v; i++) {
    const j = v - i;
    inb.push(i === f ? add(pts[i], offIn(q)) : i === v ? add(pts[i], offIn(0)) : add(pts[i], offIn(j), offIn(j - 1)));
  }
  const out: Pt[] = [];
  for (let i = v; i <= v + q; i++) {
    const j = i - v;
    out.push(i === v ? add(pts[i], offOut(0)) : add(pts[i], offOut(j - 1), offOut(j)));
  }
  // Ogni tratto spostato conserva il suo verso: nessun nuovo ripiegamento.
  const keeps = (a0: Pt, a1: Pt, b0: Pt, b1: Pt) => {
    const u = unit(a0, a1);
    const w = unit(b0, b1);
    return segLen(b0, b1) > 0.5 && u[0] * w[0] + u[1] * w[1] > 0.99;
  };
  for (let k = 0; k + 1 < inb.length; k++) if (!keeps(pts[f + k], pts[f + k + 1], inb[k], inb[k + 1])) return null;
  const tail = pts[v + q + 1];
  for (let k = 0; k <= q; k++) if (!keeps(pts[v + k], pts[v + k + 1], out[k], k < q ? out[k + 1] : tail)) return null;
  return [...pts.slice(0, f), ...inb, ...out, ...pts.slice(v + q + 1)];
}

/** Percorso da questo PC al nodo scelto, ricavato dai percorsi noti. */
export function pathToNode(map: NetworkMap, node: MapNode): string[] {
  const self = map.nodes.find((n) => n.self);
  if (!self || node === self) return [];
  const direct = map.flows.find((f) => f.path[f.path.length - 1] === node.id);
  if (direct) return direct.path;
  const inet = map.flows.find((f) => f.kind === 'internet');
  const gw = map.nodes.find((n) => n.gateway);
  if (inet) {
    const i = inet.path.indexOf(node.id);
    if (i >= 0) return inet.path.slice(0, i + 1);
  }
  const toGw = inet && gw ? inet.path.slice(0, inet.path.indexOf(gw.id) + 1) : gw ? [self.id, gw.id] : [self.id];
  if (node.segment === self.segment) {
    // Un dispositivo in Wi-Fi dello stesso access point o nella stessa rete: il traffico non passa dal router.
    const ap = toGw.length > 2 ? toGw[1] : undefined;
    return ap && node.id !== ap ? [self.id, ap, node.id] : [self.id, node.id];
  }
  if (node.segment.startsWith('seg:wifi')) return toGw;
  return [...toGw, node.id];
}

/** Dorsale, rami verso le zone e catena verso Internet, proiettati: le linee che un titolo non deve coprire. */
export function wireSegments(map: NetworkMap): Segment[] {
  const lines: Pt[][] = [];
  const bb = map.backbone;
  if (bb && map.segments.length) lines.push([[bb.x, bb.y1], [bb.x, bb.y2]]);
  for (const s of map.segments) lines.push(zoneExit(map, s));
  const core = map.nodes.filter((n) => n.segment === 'core');
  for (const l of map.links) {
    const a = core.find((n) => n.id === l.from);
    const b = core.find((n) => n.id === l.to);
    if (a && b) lines.push([[a.x, a.y], [b.x, b.y]]);
  }
  const out: Segment[] = [];
  for (const pts of lines) {
    const pp = projectPath(pts);
    for (let i = 1; i < pp.length; i++) out.push([pp[i - 1], pp[i]]);
  }
  return out;
}

// ---------------------------------------------------------------- scena

export interface SceneZone {
  s: MapSegment;
  /** Angoli del piano: in fondo, a destra, davanti, a sinistra. */
  T: Pt;
  R: Pt;
  B: Pt;
  L: Pt;
  /** Contorno completo (piano e spessore), per gli ingombri. */
  hull: Pt[];
  center: Pt;
  label: ZoneLabel;
}
export interface ZoneLabel {
  x: number;
  y: number;
  anchor: 'start' | 'middle' | 'end';
  title: string;
  sub: string;
  rect: Rect;
}
export interface SceneNode {
  n: MapNode;
  /** Punto a terra. */
  p: Pt;
  sc: number;
  /** Altezza del disegno sopra il punto a terra, già in scala. */
  h: number;
  /** Ingombro del disegno con le etichette. */
  box: Rect;
  /** Lo stesso, più stretto: il disegno e, sotto, le due righe di testo. */
  parts: Rect[];
}
export interface Scene {
  zones: SceneZone[];
  /**
   * Dispositivi in ordine di lettura, che è anche l'ordine del Tab: prima la
   * catena verso Internet, poi zona per zona, riga per riga. In questa
   * proiezione è anche un ordine di disegno corretto: di due dispositivi che si
   * coprono, quello davanti viene dopo.
   */
  nodes: SceneNode[];
  bounds: Rect;
}

export const NODE_SCALE = 0.75;
export const BIG_SCALE = 0.9;
export const LABEL_CHARS = 16;
const NAME_CH = 6.9;
const IP_CH = 6.2;
const TITLE_CH = 7.9;
const SUB_CH = 6.7;
const TITLE_MAX = 34;

export function ellipsis(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n - 1)}…` : s;
}

export const nodeScale = (n: MapNode) => (n.kind === 'internet' || n.gateway ? BIG_SCALE : NODE_SCALE);

/** Ingombro di un dispositivo: il disegno sopra il punto a terra, nome e IP sotto. */
export function nodeParts(n: MapNode, p: Pt, h: number, sc: number): Rect[] {
  const name = ellipsis(n.label, LABEL_CHARS).length * NAME_CH;
  const ip = (n.ip ?? '').length * IP_CH;
  const tw = Math.max(name, ip) / 2 + 3;
  const gw = 46 * sc;
  return [
    { x0: p[0] - gw, x1: p[0] + gw, y0: p[1] - h - (n.self ? 18 : 4), y1: p[1] + 17 },
    { x0: p[0] - tw, x1: p[0] + tw, y0: p[1] + 17, y1: p[1] + (n.ip ? 45 : 33) },
  ];
}
export const nodeBox = (n: MapNode, p: Pt, h: number, sc = NODE_SCALE): Rect => union(nodeParts(n, p, h, sc));

/**
 * Titolo e sottotitolo di una zona. Per le zone che non sono la rete del PC
 * l'etichetta ("VLAN 20 AMMINISTRAZIONE · 10.20.20.0/24") si divide al primo
 * " · ": il nome nel titolo (accorciato solo lui, se serve), il prefisso degli
 * indirizzi nel sottotitolo con il conteggio.
 */
export function zoneTexts(s: MapSegment, count: number): { title: string; sub: string } {
  const n = s.kind !== 'wifi' ? `${count} ${count === 1 ? 'dispositivo' : 'dispositivi'}` : 'rete Wi-Fi';
  if (s.kind === 'local') return { title: ellipsis(s.label, TITLE_MAX), sub: [s.vlan ? `VLAN ${s.vlan}` : '', s.subnet ?? '', n].filter(Boolean).join(' · ') };
  const cut = s.label.indexOf(' · ');
  const name = cut > 0 ? s.label.slice(0, cut) : s.label;
  const prefix = cut > 0 ? s.label.slice(cut + 3) : '';
  return { title: ellipsis(name, TITLE_MAX), sub: [prefix, n].filter(Boolean).join(' · ') };
}

/**
 * Firma della rete disegnata: dispositivi e zone con la loro posizione, e i
 * percorsi. Una nuova analisi della stessa rete (test di velocità, banco della
 * CPU, spazio su disco) dà la stessa firma: scelta, vista ed entrata restano.
 */
export function networkSignature(map: NetworkMap): string {
  return [
    map.nodes.map((n) => `${n.id}@${n.x},${n.y}`).join(';'),
    map.segments.map((s) => `${s.id}@${s.x},${s.y}`).join(';'),
    map.flows.map((f) => f.id).join(';'),
  ].join('|');
}

/** Reticolo a terra di una zona: linee lungo i due assi isometrici, ogni "step" unità, da bordo a bordo. */
export function latticePath(s: MapSegment, step = 28): string {
  const out: string[] = [];
  const seg = (a: Pt, b: Pt) => out.push(`M${a[0].toFixed(1)} ${a[1].toFixed(1)}L${b[0].toFixed(1)} ${b[1].toFixed(1)}`);
  for (let x = s.x + step; x < s.x + s.w - 4; x += step) seg(project(x, s.y), project(x, s.y + s.h));
  for (let y = s.y + step; y < s.y + s.h - 4; y += step) seg(project(s.x, y), project(s.x + s.w, y));
  return out.join('');
}

function zoneCorners(s: MapSegment) {
  const T = project(s.x, s.y);
  const R = project(s.x + s.w, s.y);
  const B = project(s.x + s.w, s.y + s.h);
  const L = project(s.x, s.y + s.h);
  const d = (p: Pt): Pt => [p[0], p[1] + ZONE_DEPTH];
  return { T, R, B, L, hull: [T, R, d(R), d(B), d(L), L] as Pt[] };
}

function textRect(x: number, y: number, anchor: ZoneLabel['anchor'], w: number): Rect {
  const x0 = anchor === 'start' ? x : anchor === 'end' ? x - w : x - w / 2;
  // y è la linea di base del titolo; il sottotitolo sta 14 px sotto.
  return { x0: x0 - 3, x1: x0 + w + 3, y0: y - 12, y1: y + 18 };
}

/** Le linee che un titolo non deve coprire: dorsale, rami verso le zone, catena verso Internet. */
export type Segment = [Pt, Pt];

/**
 * Costruisce la scena proiettata: zone come piattaforme, dispositivi con il
 * loro ingombro e i titoli delle zone nella prima posizione libera tra quelle
 * candidate (a sinistra dell'angolo sinistro, sopra l'angolo in fondo, sotto
 * l'angolo davanti, a destra dell'angolo destro).
 */
export function buildScene(map: NetworkMap, topOf: (k: DeviceKind) => number, wires: Segment[] = wireSegments(map)): Scene {
  const counts = new Map<string, number>();
  for (const n of map.nodes) counts.set(n.segment, (counts.get(n.segment) ?? 0) + 1);
  const zoneIndex = new Map(map.segments.map((s, i) => [s.id, i]));
  const zoneRank = (n: MapNode) => (n.segment === 'core' ? -1 : (zoneIndex.get(n.segment) ?? map.segments.length));
  const nodes: SceneNode[] = map.nodes
    .map((n) => {
      const p = project(n.x, n.y);
      const sc = nodeScale(n);
      const h = topOf(n.kind) * sc;
      const parts = nodeParts(n, p, h, sc);
      return { n, p, sc, h, box: union(parts), parts };
    })
    .sort((a, b) => zoneRank(a.n) - zoneRank(b.n) || a.n.y - b.n.y || a.n.x - b.n.x);
  const corners = map.segments.map((s) => ({ s, ...zoneCorners(s) }));
  const placed: Rect[] = [];
  const zones: SceneZone[] = corners.map((c) => {
    const { title, sub } = zoneTexts(c.s, counts.get(c.s.id) ?? 0);
    const w = Math.max(title.length * TITLE_CH, sub.length * SUB_CH);
    const { T, R, B, L } = c;
    const D = ZONE_DEPTH;
    const cand: Record<string, [number, number, ZoneLabel['anchor']]> = {
      leftOfL: [L[0] - 14, L[1] - 12, 'end'],
      aboveT: [T[0], T[1] - 26, 'middle'],
      aboveTEnd: [T[0] + 10, T[1] - 26, 'end'],
      aboveTStart: [T[0] - 10, T[1] - 26, 'start'],
      belowB: [B[0], B[1] + D + 18, 'middle'],
      belowBStart: [B[0] - 18, B[1] + D + 18, 'start'],
      belowBEnd: [B[0] + 18, B[1] + D + 18, 'end'],
      rightOfR: [R[0] + 14, R[1] + 6, 'start'],
    };
    const side = c.s.side ?? 'center';
    const order =
      side === 'right'
        ? ['belowBStart', 'rightOfR', 'belowB', 'aboveTStart', 'belowBEnd', 'aboveT', 'leftOfL', 'aboveTEnd']
        : side === 'left'
          ? ['leftOfL', 'aboveTEnd', 'aboveT', 'belowBEnd', 'belowB', 'aboveTStart', 'rightOfR', 'belowBStart']
          : ['aboveT', 'leftOfL', 'aboveTEnd', 'rightOfR', 'belowB', 'aboveTStart', 'belowBStart', 'belowBEnd'];
    let best: ZoneLabel | undefined;
    let bestCost = Infinity;
    for (const key of order) {
      const [x, y, anchor] = cand[key];
      const rect = textRect(x, y, anchor, w);
      const cost = labelCost(rect, corners.map((o) => o.hull), nodes, wires, placed);
      if (cost < bestCost) {
        bestCost = cost;
        best = { x, y, anchor, title, sub, rect };
      }
      if (cost === 0) break;
    }
    placed.push(best!.rect);
    const center = project(c.s.x + c.s.w / 2, c.s.y + c.s.h / 2);
    return { s: c.s, T, R, B, L, hull: c.hull, center, label: best! };
  });
  const rects = [...zones.map((z) => hullRect(z.hull)), ...zones.map((z) => z.label.rect), ...nodes.map((n) => n.box)];
  return { zones, nodes, bounds: union(rects) };
}

function labelCost(r: Rect, hulls: Pt[][], nodes: SceneNode[], wires: Segment[], placed: Rect[]): number {
  let cost = 0;
  for (const h of hulls) if (rectPolyOverlap(r, h)) cost += 4;
  for (const n of nodes) if (n.parts.some((b) => rectsOverlap(r, b))) cost += 4;
  for (const p of placed) if (rectsOverlap(r, p)) cost += 8;
  for (const s of wires) if (rectPolyOverlap(r, s)) cost += 1;
  return cost;
}

/**
 * Etichetta di un collegamento (tempo di risposta, segnale Wi-Fi): accanto al
 * tratto più lungo, dal lato in alto, nella prima posizione che non copre un
 * dispositivo o un titolo.
 */
export function placeLinkLabel(pts: Pt[], text: string, obstacles: Rect[]): { x: number; y: number; anchor: 'start' | 'end'; rect: Rect } {
  let seg = 1;
  let bl = -1;
  for (let i = 1; i < pts.length; i++) {
    const l = Math.hypot(pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1]);
    if (l > bl) {
      bl = l;
      seg = i;
    }
  }
  const a = pts[seg - 1];
  const b = pts[seg];
  const l = Math.max(1, bl);
  const u: Pt = [(b[0] - a[0]) / l, (b[1] - a[1]) / l];
  let up: Pt = [-u[1], u[0]];
  if (up[1] > 0) up = [-up[0], -up[1]];
  const w = text.length * 6.4 + 4;
  const area = (r: Rect) => obstacles.reduce((t, o) => t + Math.max(0, Math.min(r.x1, o.x1) - Math.max(r.x0, o.x0)) * Math.max(0, Math.min(r.y1, o.y1) - Math.max(r.y0, o.y0)), 0);
  let best: { x: number; y: number; anchor: 'start' | 'end'; rect: Rect } | undefined;
  let bestArea = Infinity;
  for (const off of [12, 22])
    for (const f of [0.5, 0.38, 0.62, 0.26, 0.74])
      for (const side of [up, [-up[0], -up[1]] as Pt]) {
        const x = a[0] + (b[0] - a[0]) * f + side[0] * off;
        const y = a[1] + (b[1] - a[1]) * f + side[1] * off + 4;
        const anchor = side[0] < 0 ? 'end' : 'start';
        const rect: Rect = { x0: anchor === 'end' ? x - w : x, x1: anchor === 'end' ? x : x + w, y0: y - 10, y1: y + 3 };
        const cost = area(rect);
        if (cost === 0) return { x, y, anchor, rect };
        if (cost < bestArea) {
          bestArea = cost;
          best = { x, y, anchor, rect };
        }
      }
  return best!;
}

// ---------------------------------------------------------------- geometria

export const hullRect = (pts: Pt[]): Rect => ({
  x0: Math.min(...pts.map((p) => p[0])),
  x1: Math.max(...pts.map((p) => p[0])),
  y0: Math.min(...pts.map((p) => p[1])),
  y1: Math.max(...pts.map((p) => p[1])),
});

export function union(rs: Rect[]): Rect {
  if (!rs.length) return { x0: 0, y0: 0, x1: 1, y1: 1 };
  return {
    x0: Math.min(...rs.map((r) => r.x0)),
    y0: Math.min(...rs.map((r) => r.y0)),
    x1: Math.max(...rs.map((r) => r.x1)),
    y1: Math.max(...rs.map((r) => r.y1)),
  };
}

export const rectsOverlap = (a: Rect, b: Rect) => a.x0 < b.x1 && b.x0 < a.x1 && a.y0 < b.y1 && b.y0 < a.y1;

/** Un rettangolo e un poligono convesso (o un segmento) si sovrappongono? Teorema dell'asse separatore. */
export function rectPolyOverlap(r: Rect, poly: Pt[]): boolean {
  const rp: Pt[] = [
    [r.x0, r.y0],
    [r.x1, r.y0],
    [r.x1, r.y1],
    [r.x0, r.y1],
  ];
  const axes: Pt[] = [
    [1, 0],
    [0, 1],
  ];
  for (let i = 0; i < poly.length; i++) {
    const a = poly[i];
    const b = poly[(i + 1) % poly.length];
    if (a[0] !== b[0] || a[1] !== b[1]) axes.push([a[1] - b[1], b[0] - a[0]]);
    if (poly.length === 2) break;
  }
  for (const [ax, ay] of axes) {
    let a0 = Infinity;
    let a1 = -Infinity;
    let b0 = Infinity;
    let b1 = -Infinity;
    for (const [x, y] of rp) {
      const d = x * ax + y * ay;
      a0 = Math.min(a0, d);
      a1 = Math.max(a1, d);
    }
    for (const [x, y] of poly) {
      const d = x * ax + y * ay;
      b0 = Math.min(b0, d);
      b1 = Math.max(b1, d);
    }
    if (a1 <= b0 || b1 <= a0) return false;
  }
  return true;
}

export function polyLength(pts: Pt[]): number {
  let l = 0;
  for (let i = 1; i < pts.length; i++) l += Math.hypot(pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1]);
  return l;
}

/** Tronca un percorso a una frazione della sua lunghezza (per i percorsi bloccati). */
export function truncate(pts: Pt[], frac: number): Pt[] {
  const total = polyLength(pts) * frac;
  const out: Pt[] = [pts[0]];
  let acc = 0;
  for (let i = 1; i < pts.length; i++) {
    const seg = Math.hypot(pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1]);
    if (acc + seg >= total) {
      const t = seg ? (total - acc) / seg : 0;
      out.push([pts[i - 1][0] + (pts[i][0] - pts[i - 1][0]) * t, pts[i - 1][1] + (pts[i][1] - pts[i - 1][1]) * t]);
      return out;
    }
    acc += seg;
    out.push(pts[i]);
  }
  return out;
}

/** Toglie i punti ripetuti e quelli allineati in mezzo a un tratto dritto. */
export function simplify(pts: Pt[]): Pt[] {
  const out: Pt[] = [];
  for (const p of pts) {
    const last = out[out.length - 1];
    if (last && Math.abs(last[0] - p[0]) < 0.01 && Math.abs(last[1] - p[1]) < 0.01) continue;
    if (out.length >= 2) {
      const a = out[out.length - 2];
      const b = last;
      const cross = (b[0] - a[0]) * (p[1] - b[1]) - (b[1] - a[1]) * (p[0] - b[0]);
      const dot = (b[0] - a[0]) * (p[0] - b[0]) + (b[1] - a[1]) * (p[1] - b[1]);
      if (Math.abs(cross) < 0.01 && dot > 0) {
        out[out.length - 1] = p;
        continue;
      }
    }
    out.push(p);
  }
  return out;
}

/** Distanza delle due corsie (andata e ritorno) dal centro del percorso, in pixel. */
export const LANE = 4;

/**
 * Linea parallela a un percorso, a distanza d (positiva a destra del verso di
 * marcia, sullo schermo): le due corsie del traffico, andata e ritorno. Negli
 * angoli il punto sta sulla bisettrice; nelle inversioni a U si aggiungono due
 * punti, così la corsia gira attorno al punto invece di tagliarlo.
 */
export function offsetPolyline(input: Pt[], d: number): Pt[] {
  const pts = simplify(input);
  if (pts.length < 2) return pts.slice();
  const normal = (a: Pt, b: Pt): Pt => {
    const dx = b[0] - a[0];
    const dy = b[1] - a[1];
    const l = Math.hypot(dx, dy) || 1;
    return [-dy / l, dx / l];
  };
  const out: Pt[] = [];
  for (let i = 0; i < pts.length; i++) {
    const p = pts[i];
    const n1 = i > 0 ? normal(pts[i - 1], p) : undefined;
    const n2 = i < pts.length - 1 ? normal(p, pts[i + 1]) : undefined;
    if (!n1 || !n2) {
      const n = (n1 ?? n2)!;
      out.push([p[0] + n[0] * d, p[1] + n[1] * d]);
      continue;
    }
    const dot = n1[0] * n2[0] + n1[1] * n2[1];
    if (dot < -0.8) {
      out.push([p[0] + n1[0] * d, p[1] + n1[1] * d], [p[0] + n2[0] * d, p[1] + n2[1] * d]);
      continue;
    }
    const mx = n1[0] + n2[0];
    const my = n1[1] + n2[1];
    const ml = Math.hypot(mx, my) || 1;
    const scale = d / Math.max(0.5, (mx / ml) * n1[0] + (my / ml) * n1[1]);
    out.push([p[0] + (mx / ml) * scale, p[1] + (my / ml) * scale]);
  }
  return out;
}

/** Punte di freccia lungo un percorso: una a circa due terzi di ogni tratto abbastanza lungo. */
export function arrowsAlong(pts: Pt[], minLen = 46, at = 0.66): { p: Pt; dir: Pt }[] {
  const out: { p: Pt; dir: Pt }[] = [];
  for (let i = 1; i < pts.length; i++) {
    const a = pts[i - 1];
    const b = pts[i];
    const l = Math.hypot(b[0] - a[0], b[1] - a[1]);
    if (l < minLen) continue;
    out.push({ p: [a[0] + (b[0] - a[0]) * at, a[1] + (b[1] - a[1]) * at], dir: [(b[0] - a[0]) / l, (b[1] - a[1]) / l] });
  }
  return out;
}

/** Triangolo di una punta di freccia (lunga 6, larga 5) centrata in p. */
export function arrowPoints({ p, dir }: { p: Pt; dir: Pt }, len = 6, wid = 5): string {
  const [ux, uy] = dir;
  const [nx, ny] = [-uy, ux];
  const tip: Pt = [p[0] + (ux * len) / 2, p[1] + (uy * len) / 2];
  const b1: Pt = [p[0] - (ux * len) / 2 + (nx * wid) / 2, p[1] - (uy * len) / 2 + (ny * wid) / 2];
  const b2: Pt = [p[0] - (ux * len) / 2 - (nx * wid) / 2, p[1] - (uy * len) / 2 - (ny * wid) / 2];
  return [tip, b1, b2].map((q) => `${q[0].toFixed(1)},${q[1].toFixed(1)}`).join(' ');
}

export const pathD = (pts: Pt[]) => pts.map((p, i) => `${i ? 'L' : 'M'}${p[0].toFixed(1)} ${p[1].toFixed(1)}`).join(' ');

// ---------------------------------------------------------------- camera

/** Vista che mostra tutto il rettangolo, centrato, con un margine. */
export function fitView(b: Rect, w: number, h: number, pad = 16, kMin = 0.2, kMax = 1.3): View {
  return frameView(b, { x0: pad, y0: pad, x1: w - pad, y1: h - pad }, kMin, kMax);
}

/** Vista che mette il rettangolo b (mondo) al centro dell'area a (schermo). */
export function frameView(b: Rect, a: Rect, kMin = 0.2, kMax = 1.3): View {
  const bw = Math.max(1, b.x1 - b.x0);
  const bh = Math.max(1, b.y1 - b.y0);
  const k = clamp(Math.min(Math.max(1, a.x1 - a.x0) / bw, Math.max(1, a.y1 - a.y0) / bh), kMin, kMax);
  return { k, x: (a.x0 + a.x1) / 2 - ((b.x0 + b.x1) / 2) * k, y: (a.y0 + a.y1) / 2 - ((b.y0 + b.y1) / 2) * k };
}

/** Ingrandisce attorno al punto (px, py) dello schermo. */
export function zoomAbout(v: View, px: number, py: number, factor: number, kMin = 0.2, kMax = 3): View {
  const k = clamp(v.k * factor, kMin, kMax);
  return { k, x: px - ((px - v.x) * k) / v.k, y: py - ((py - v.y) * k) / v.k };
}

export const toScreen = (v: View, p: Pt): Pt => [v.x + p[0] * v.k, v.y + p[1] * v.k];

/**
 * Passaggio tra due viste: il centro dell'inquadratura si sposta in linea
 * retta e lo zoom cambia in modo geometrico, così ingrandire e spostarsi
 * insieme non fa "ondeggiare" la scena.
 */
export function lerpView(a: View, b: View, t: number, w: number, h: number): View {
  if (t <= 0) return a;
  if (t >= 1) return b;
  const ca: Pt = [(w / 2 - a.x) / a.k, (h / 2 - a.y) / a.k];
  const cb: Pt = [(w / 2 - b.x) / b.k, (h / 2 - b.y) / b.k];
  const k = a.k * Math.pow(b.k / a.k, t);
  const cx = ca[0] + (cb[0] - ca[0]) * t;
  const cy = ca[1] + (cb[1] - ca[1]) * t;
  return { k, x: w / 2 - cx * k, y: h / 2 - cy * k };
}

export const easeOutCubic = (t: number) => 1 - Math.pow(1 - clamp(t, 0, 1), 3);
export const easeInOutCubic = (t: number) => {
  const x = clamp(t, 0, 1);
  return x < 0.5 ? 4 * x * x * x : 1 - Math.pow(-2 * x + 2, 3) / 2;
};

/**
 * Spazio sopra un dispositivo d'arrivo per l'etichetta del pacchetto ferma (pausa o "riduci
 * movimento"), che sta sopra il disegno: alta fino a 6 + 47 px oltre il disegno, larga fino a
 * circa 110 px, più la distanza della corsia.
 */
export const CHIP_ROOM = 58;
export function chipRoom(sn: SceneNode): Rect {
  return { x0: sn.p[0] - 56, x1: sn.p[0] + 56, y0: sn.p[1] - sn.h - CHIP_ROOM, y1: sn.p[1] };
}

/** Riquadro di un percorso proiettato con i dispositivi che attraversa e l'etichetta del pacchetto all'arrivo. */
export function routeBounds(map: NetworkMap, scene: Scene, ids: string[]): Rect {
  const boxes = scene.nodes.filter((s) => ids.includes(s.n.id)).map((s) => s.box);
  const route = ids.length > 1 ? projectPath(routePoints(map, ids)) : [];
  const last = scene.nodes.find((s) => s.n.id === ids[ids.length - 1]);
  return union([...boxes, ...(route.length > 1 ? [hullRect(route)] : []), ...(last ? [chipRoom(last)] : [])]);
}

/**
 * Inquadra un percorso nell'area data. Se intero diventerebbe illeggibile
 * (zoom sotto "readable"), inquadra l'ultimo tratto e, al limite, il solo
 * dispositivo d'arrivo.
 */
export function frameRoute(map: NetworkMap, scene: Scene, ids: string[], area: Rect, kMax = 1.15, readable = 0.5): View {
  const tries = [ids, ids.slice(-2), ids.slice(-1)].filter((t) => t.length > 0);
  let v: View = { x: 0, y: 0, k: 1 };
  for (const t of tries) {
    v = frameView(routeBounds(map, scene, t), area, 0.2, kMax);
    if (v.k >= readable) return v;
  }
  return v;
}

/**
 * Area della scena che resta visibile accanto al pannello dei dettagli (a destra, o in basso sul
 * telefono), con un margine. Il pannello (styles.css) sta a 12 px dai bordi: a destra è largo
 * fino a 330 px, in basso è alto il 58% della mappa, quindi comincia a 0,42·h − 12.
 */
export function visibleArea(w: number, h: number, panel: 'right' | 'bottom' | 'none'): Rect {
  if (panel === 'right') return { x0: 16, y0: 16, x1: Math.max(120, w - Math.min(330, w - 24) - 36), y1: h - 16 };
  if (panel === 'bottom') return { x0: 16, y0: 12, x1: w - 16, y1: Math.max(100, h * 0.42 - 22) };
  return { x0: 16, y0: 16, x1: w - 16, y1: h - 16 };
}

// ---------------------------------------------------------------- entrata in scena

export const ENTER = {
  /** Durata della salita di una zona. */
  zone: 460,
  /** Durata della caduta di un dispositivo. */
  node: 380,
  /** Durata del disegno di un collegamento. */
  wire: 520,
  /** Tutta l'entrata non supera questo tempo. */
  total: 1500,
} as const;

export interface Entrance {
  zone: Map<string, number>;
  node: Map<string, number>;
  /** Quando cominciano a disegnarsi i collegamenti e quando i percorsi del traffico. */
  wires: number;
  flows: number;
  /** Quando compaiono i pacchetti. */
  packets: number;
  end: number;
}

/**
 * Ordine dell'entrata: prima le zone (quella del PC per prima), poi i
 * dispositivi uno alla volta a partire da questo PC e allontanandosi, poi i
 * collegamenti e i percorsi. Distanze nella disposizione piana.
 */
export function entranceSchedule(map: NetworkMap): Entrance {
  const self = map.nodes.find((n) => n.self) ?? map.nodes.find((n) => n.gateway) ?? map.nodes[0];
  const ox = self?.x ?? 0;
  const oy = self?.y ?? 0;
  const dist = (x: number, y: number) => Math.hypot(x - ox, y - oy);
  const zone = new Map<string, number>();
  const zs = map.segments
    .slice()
    .sort((a, b) => (a.id === self?.segment ? -1 : b.id === self?.segment ? 1 : dist(a.x + a.w / 2, a.y + a.h / 2) - dist(b.x + b.w / 2, b.y + b.h / 2)));
  const zStep = zs.length > 1 ? Math.min(60, 360 / (zs.length - 1)) : 0;
  zs.forEach((s, i) => zone.set(s.id, Math.round(i * zStep)));
  const node = new Map<string, number>();
  const ns = map.nodes.slice().sort((a, b) => (a.self ? -1 : b.self ? 1 : dist(a.x, a.y) - dist(b.x, b.y)));
  // Questo PC compare subito con la sua zona, poi gli altri a distanza crescente.
  const start = 110;
  const lastStart = ENTER.total - ENTER.node;
  const rest = ns.length - (ns[0]?.self ? 1 : 0);
  const step = rest > 1 ? Math.min(28, (lastStart - start) / (rest - 1)) : 0;
  let k = 0;
  for (const n of ns) node.set(n.id, n.self ? 0 : Math.round(start + k++ * step));
  const lastNode = Math.max(0, ...node.values());
  const wires = Math.round(Math.max(360, lastNode - 450));
  const flows = Math.round(Math.min(ENTER.total - ENTER.wire - 80, wires + 220));
  const packets = flows + ENTER.wire - 220;
  return { zone, node, wires, flows, packets, end: Math.max(lastNode + ENTER.node, flows + ENTER.wire, wires + 160 + ENTER.wire, packets + 250) };
}
