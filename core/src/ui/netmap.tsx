import {
  BrickWall,
  Cctv,
  CircleHelp,
  Cloud,
  Globe,
  HardDrive,
  HeartPulse,
  Laptop,
  Layers,
  Lightbulb,
  List,
  LocateFixed,
  Maximize2,
  Monitor,
  Network,
  Pause,
  Phone,
  Play,
  Printer,
  RadioTower,
  Router,
  Search,
  Server,
  Smartphone,
  Tablet,
  Tv,
  Waypoints,
  X,
  ZoomIn,
  ZoomOut,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { AnimatePresence, m, useReducedMotion } from 'motion/react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { KeyboardEvent as ReactKeyboardEvent, PointerEvent as ReactPointerEvent } from 'react';
import { buildNetworkMap, CELL_H, CELL_W, KIND_GROUP, KIND_LABEL, KIND_ORDER, KIND_PLURAL, ZONE_BUS } from '../engine';
import type { Analysis, DeviceKind, MapFlow, MapNode, MapSegment, NetworkMap, Scan, Severity } from '../engine';
import { TableWrap } from './components';

// Mappa della rete interattiva: zone per sottorete, VLAN e rete Wi-Fi; un'icona
// per tipo di dispositivo; i percorsi del traffico di questo PC animati come
// pacchetti che scorrono. Zoom con i pulsanti, Ctrl + rotella o due dita;
// trascinamento per spostarsi. Con "riduci movimento" i pacchetti non si
// muovono e il percorso resta disegnato. L'elenco testuale è l'alternativa
// accessibile alla mappa.

type Pt = [number, number];

export const KIND_ICON: Record<DeviceKind, LucideIcon> = {
  internet: Globe,
  isp: Cloud,
  router: Router,
  firewall: BrickWall,
  switch: Network,
  ap: RadioTower,
  pc: Monitor,
  laptop: Laptop,
  server: Server,
  vm: Layers,
  nas: HardDrive,
  printer: Printer,
  phone: Smartphone,
  tablet: Tablet,
  voip: Phone,
  camera: Cctv,
  tv: Tv,
  iot: Lightbulb,
  medical: HeartPulse,
  unknown: CircleHelp,
};

const KIND_COLOR: Partial<Record<DeviceKind, string>> = {
  medical: 'var(--p3)',
  camera: 'var(--p7)',
  iot: 'var(--p1)',
  printer: 'var(--p5)',
  tv: 'var(--p4)',
  voip: 'var(--p9)',
};
const GROUP_COLOR = { rete: 'var(--accent)', server: 'var(--p2)', postazioni: 'var(--p0)', periferiche: 'var(--p4)', altro: 'var(--text-3)' } as const;
export const kindColor = (k: DeviceKind) => KIND_COLOR[k] ?? GROUP_COLOR[KIND_GROUP[k]];

const SEV_COLOR: Record<Severity, string> = { ok: 'var(--ok)', info: 'var(--info)', warn: 'var(--warn)', crit: 'var(--crit)', unknown: 'var(--text-3)' };
const CONF_TEXT = { alta: 'riconosciuto con certezza', media: 'riconosciuto con buona probabilità', bassa: 'ipotesi da verificare' } as const;

const BUS = ZONE_BUS;
const R = 24; // raggio dei nodi

const clamp = (v: number, a: number, b: number) => Math.max(a, Math.min(b, v));

function ellipsis(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n - 1)}…` : s;
}

/**
 * Dalla linea di raccolta della zona al dispositivo: dritto per la prima riga,
 * per le righe sotto lungo il corridoio a sinistra della colonna, così la
 * linea non passa sopra i dispositivi della riga superiore.
 */
function nodeDrop(z: MapSegment, n: MapNode): Pt[] {
  const busY = z.y + BUS;
  if (n.y - busY < CELL_H) return [[n.x, busY], [n.x, n.y]];
  const gx = n.x - CELL_W / 2 + 4;
  return [[gx, busY], [gx, n.y], [n.x, n.y]];
}

/** Dalla linea di raccolta della zona alla dorsale (o al bordo superiore, se la zona è al centro). */
function zoneExit(map: NetworkMap, z: MapSegment): Pt[] {
  const bx = map.backbone?.x ?? z.x + z.w / 2;
  if (z.side === 'center' || z.ex === undefined || z.ey === undefined) return [[bx, z.y + BUS], [bx, z.y]];
  return [[z.ex, z.ey], [bx, z.ey]];
}

/** Punti del percorso tra i nodi: dentro una zona passa dalla linea di raccolta, tra le zone dalla dorsale. */
function routePoints(map: NetworkMap, ids: string[]): Pt[] {
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
  // Toglie i punti ripetuti.
  return pts.filter((p, i) => i === 0 || p[0] !== pts[i - 1][0] || p[1] !== pts[i - 1][1]);
}

const pathD = (pts: Pt[]) => pts.map((p, i) => `${i ? 'L' : 'M'}${p[0].toFixed(1)} ${p[1].toFixed(1)}`).join(' ');

function polyLength(pts: Pt[]): number {
  let l = 0;
  for (let i = 1; i < pts.length; i++) l += Math.hypot(pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1]);
  return l;
}

/** Tronca un percorso a una frazione della sua lunghezza (per i percorsi bloccati). */
function truncate(pts: Pt[], frac: number): Pt[] {
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

function pathText(map: NetworkMap, ids: string[]): string {
  const names = new Map(map.nodes.map((n) => [n.id, n.self ? 'questo PC' : n.label]));
  return ids.map((id) => names.get(id) ?? id).join(' → ');
}

// ---------------------------------------------------------------- disegno

function Zone({ s, count }: { s: MapSegment; count: number }) {
  const tone = s.kind === 'local' ? 'var(--accent)' : s.kind === 'remote' ? 'var(--p2)' : 'var(--p1)';
  const n = s.kind !== 'wifi' ? `${count} ${count === 1 ? 'dispositivo' : 'dispositivi'}` : '';
  // Nelle zone strette il titolo dice già la VLAN: il sottotitolo resta il conteggio.
  const sub = s.kind === 'local' ? [s.vlan ? `VLAN ${s.vlan}` : '', s.subnet ?? '', n].filter(Boolean).join(' · ') : n;
  const room = Math.max(12, Math.floor((s.w - 32 - sub.length * 6.2) / 7.4));
  return (
    <g className={`nm-zone nm-zone-${s.kind}`}>
      <rect x={s.x} y={s.y} width={s.w} height={s.h} rx={18} style={{ fill: `color-mix(in srgb, ${tone} 7%, transparent)`, stroke: `color-mix(in srgb, ${tone} 38%, transparent)` }} strokeDasharray={s.kind === 'wifi' ? '6 6' : undefined} />
      <text x={s.x + 16} y={s.y + 20} className="nm-zone-title">
        {ellipsis(s.label, room)}
      </text>
      {sub && (
        <text x={s.x + s.w - 14} y={s.y + 20} className="nm-zone-sub" textAnchor="end">
          {sub}
        </text>
      )}
      {s.kind === 'wifi' && s.note && (
        <foreignObject x={s.x + 12} y={s.y + 30} width={s.w - 24} height={s.h - 36}>
          <p className="nm-zone-note">{s.note}</p>
        </foreignObject>
      )}
      {s.kind !== 'wifi' && <line x1={s.x + 16} x2={s.x + s.w - 16} y1={s.y + BUS} y2={s.y + BUS} className="nm-bus" />}
    </g>
  );
}

function NodeGlyph({ n, dim, selected, playing, onPick }: { n: MapNode; dim: boolean; selected: boolean; playing: boolean; onPick: (n: MapNode) => void }) {
  const Icon = KIND_ICON[n.kind];
  const color = kindColor(n.kind);
  const big = n.kind === 'internet' || n.gateway;
  const r = big ? R + 6 : R;
  const onKey = (e: ReactKeyboardEvent) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      onPick(n);
    }
  };
  const label = n.label;
  return (
    <g
      className={`nm-node${dim ? ' dim' : ''}${selected ? ' sel' : ''}${n.self ? ' self' : ''}`}
      transform={`translate(${n.x.toFixed(1)} ${n.y.toFixed(1)})`}
      tabIndex={0}
      role="button"
      aria-label={`${KIND_LABEL[n.kind]}: ${label}${n.self ? ' (questo PC)' : ''}${n.ip ? `, ${n.ip}` : ''}${n.confidence === 'bassa' ? ', tipo da verificare' : ''}`}
      aria-pressed={selected}
      onClick={(e) => {
        e.stopPropagation();
        onPick(n);
      }}
      onKeyDown={onKey}
      onPointerDown={(e) => e.stopPropagation()}
    >
      {n.self && <circle r={r + 9} className={`nm-halo${playing ? ' live' : ''}`} />}
      {n.self && (
        <text y={-r - 14} textAnchor="middle" className="nm-you">
          questo PC
        </text>
      )}
      {selected && <circle r={r + 6} className="nm-sel-ring" />}
      <circle r={r} className="nm-disc" style={{ stroke: color }} strokeDasharray={n.inferred ? '4 4' : undefined} />
      <Icon x={-(big ? 14 : 12)} y={-(big ? 14 : 12)} width={big ? 28 : 24} height={big ? 28 : 24} color={color} strokeWidth={1.9} aria-hidden />
      {n.sev && (n.sev === 'warn' || n.sev === 'crit') && <circle cx={r * 0.72} cy={-r * 0.72} r={6} style={{ fill: SEV_COLOR[n.sev] }} className="nm-dot" />}
      {n.confidence === 'bassa' && !n.self && (
        <g transform={`translate(${r * 0.72} ${r * 0.72})`} className="nm-doubt">
          <circle r={7.5} />
          <text y={3.6} textAnchor="middle">
            ?
          </text>
        </g>
      )}
      <text y={r + 16} textAnchor="middle" className="nm-label">
        {ellipsis(label, 16)}
      </text>
      {n.ip && (
        <text y={r + 30} textAnchor="middle" className="nm-ip">
          {n.ip}
        </text>
      )}
    </g>
  );
}

function FlowPath({ pts, color, active, playing, blocked, speed }: { pts: Pt[]; color: string; active: boolean; playing: boolean; blocked: boolean; speed: number }) {
  if (pts.length < 2) return null;
  const d = pathD(pts);
  const len = polyLength(pts);
  const dur = clamp(len / speed, 1.2, 9);
  const end = pts[pts.length - 1];
  return (
    <g className={`nm-flow${active ? ' active' : ''}`} style={{ color }}>
      <path d={d} className="nm-flow-line" />
      {playing &&
        [0, 1, 2].map((i) => (
          <circle key={i} r={active ? 5 : 3.5} className="nm-packet" opacity={0}>
            <animateMotion dur={`${dur.toFixed(2)}s`} begin={`${((dur / 3) * i).toFixed(2)}s`} repeatCount="indefinite" path={d} keyPoints="0;1" keyTimes="0;1" calcMode="linear" />
            <animate attributeName="opacity" values="0;1;1;0" keyTimes="0;0.1;0.85;1" dur={`${dur.toFixed(2)}s`} begin={`${((dur / 3) * i).toFixed(2)}s`} repeatCount="indefinite" />
          </circle>
        ))}
      {!playing && active && <circle cx={end[0]} cy={end[1]} r={5} className="nm-packet" />}
      {blocked && (
        <g transform={`translate(${end[0].toFixed(1)} ${end[1].toFixed(1)})`} className="nm-stop">
          <circle r={11} />
          <path d="M-5 -5 L5 5 M5 -5 L-5 5" />
        </g>
      )}
    </g>
  );
}

// ---------------------------------------------------------------- componente

export interface NetMapProps {
  scan: Scan;
  analysis?: Analysis;
  /** Altezza della mappa in pixel (sul telefono si riduce). */
  height?: number;
  /** Solo la mappa, senza comandi, filtri e note (per le videoguide). */
  compact?: boolean;
}

export function NetMap({ scan, analysis, height = 620, compact = false }: NetMapProps) {
  const map = useMemo(() => buildNetworkMap(scan, analysis), [scan, analysis]);
  const reduce = useReducedMotion();
  const wrapRef = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ w: 900, h: height });
  const [view, setView] = useState<{ x: number; y: number; k: number } | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [hidden, setHidden] = useState<DeviceKind[]>([]);
  const [query, setQuery] = useState('');
  const [playing, setPlaying] = useState(true);
  const [activeFlow, setActiveFlow] = useState<string>('flow:internet');
  const [list, setList] = useState(false);
  const live = playing && !reduce;

  useEffect(() => {
    const el = wrapRef.current;
    if (!el || typeof ResizeObserver === 'undefined') return;
    const ro = new ResizeObserver(() => setSize({ w: el.clientWidth, h: el.clientHeight }));
    ro.observe(el);
    setSize({ w: el.clientWidth, h: el.clientHeight });
    return () => ro.disconnect();
  }, [list]);

  const fit = useMemo(() => {
    const k = clamp(Math.min((size.w - 24) / map.width, (size.h - 24) / map.height), 0.2, 1.3);
    return { k, x: (size.w - map.width * k) / 2, y: (size.h - map.height * k) / 2 };
  }, [size, map]);
  // Se la mappa intera diventerebbe illeggibile (telefono, reti grandi) si parte da questo PC.
  const initial = useMemo(() => {
    if (fit.k >= 0.45) return fit;
    const c = map.nodes.find((n) => n.self) ?? map.nodes.find((n) => n.gateway);
    if (!c) return fit;
    const k = 0.8;
    return { k, x: size.w / 2 - c.x * k, y: size.h / 2.6 - c.y * k };
  }, [fit, map, size]);
  const t = view ?? initial;

  const zoomAt = useCallback(
    (factor: number, cx?: number, cy?: number) => {
      setView((v) => {
        const cur = v ?? initial;
        const k = clamp(cur.k * factor, 0.2, 3);
        const px = cx ?? size.w / 2;
        const py = cy ?? size.h / 2;
        return { k, x: px - ((px - cur.x) * k) / cur.k, y: py - ((py - cur.y) * k) / cur.k };
      });
    },
    [initial, size],
  );

  // Ctrl + rotella (e il pizzico del touchpad) fanno lo zoom; la rotella da sola scorre la pagina.
  useEffect(() => {
    const el = wrapRef.current?.querySelector('svg');
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      if (!e.ctrlKey && !e.metaKey) return;
      e.preventDefault();
      const r = el.getBoundingClientRect();
      zoomAt(Math.exp(-e.deltaY * 0.0022), e.clientX - r.left, e.clientY - r.top);
    };
    el.addEventListener('wheel', onWheel, { passive: false });
    return () => el.removeEventListener('wheel', onWheel);
  }, [zoomAt, list]);

  // Trascinamento e pizzico con due dita.
  const pointers = useRef(new Map<number, Pt>());
  const pinch = useRef<{ d: number; k: number } | null>(null);
  const onPointerDown = (e: ReactPointerEvent<SVGSVGElement>) => {
    (e.currentTarget as Element).setPointerCapture(e.pointerId);
    pointers.current.set(e.pointerId, [e.clientX, e.clientY]);
    if (pointers.current.size === 2) {
      const [a, b] = [...pointers.current.values()];
      pinch.current = { d: Math.hypot(a[0] - b[0], a[1] - b[1]), k: t.k };
    }
  };
  const onPointerMove = (e: ReactPointerEvent<SVGSVGElement>) => {
    const prev = pointers.current.get(e.pointerId);
    if (!prev) return;
    pointers.current.set(e.pointerId, [e.clientX, e.clientY]);
    if (pointers.current.size === 2 && pinch.current) {
      const [a, b] = [...pointers.current.values()];
      const d = Math.hypot(a[0] - b[0], a[1] - b[1]);
      const r = e.currentTarget.getBoundingClientRect();
      const k = clamp((pinch.current.k * d) / pinch.current.d, 0.2, 3);
      zoomAt(k / t.k, (a[0] + b[0]) / 2 - r.left, (a[1] + b[1]) / 2 - r.top);
      return;
    }
    const dx = e.clientX - prev[0];
    const dy = e.clientY - prev[1];
    if (dx || dy) setView((v) => ({ ...(v ?? initial), x: (v ?? initial).x + dx, y: (v ?? initial).y + dy }));
  };
  const onPointerUp = (e: ReactPointerEvent<SVGSVGElement>) => {
    pointers.current.delete(e.pointerId);
    if (pointers.current.size < 2) pinch.current = null;
  };
  const onCanvasKey = (e: ReactKeyboardEvent) => {
    if (e.target !== e.currentTarget) return;
    const step = 60;
    const k = e.key;
    if (k === '+' || k === '=') zoomAt(1.25);
    else if (k === '-') zoomAt(0.8);
    else if (k === '0') setView(fit);
    else if (k.startsWith('Arrow')) setView((v) => {
      const c = v ?? initial;
      return { ...c, x: c.x + (k === 'ArrowLeft' ? step : k === 'ArrowRight' ? -step : 0), y: c.y + (k === 'ArrowUp' ? step : k === 'ArrowDown' ? -step : 0) };
    });
    else return;
    e.preventDefault();
  };

  const kinds = useMemo(() => KIND_ORDER.filter((k) => (map.counts[k] ?? 0) > 0), [map]);
  const q = query.trim().toLowerCase();
  const matches = (n: MapNode) =>
    !q || [n.label, n.ip ?? '', n.vendor ?? '', KIND_LABEL[n.kind], ...n.names].some((x) => x.toLowerCase().includes(q));
  const visible = (n: MapNode) => n.segment === 'core' || hidden.indexOf(n.kind) < 0;
  const sel = map.nodes.find((n) => n.id === selected);
  const selPath = sel ? pathToNode(map, sel) : [];

  const flows = map.flows;
  const shownFlows: { f: MapFlow; active: boolean }[] = sel
    ? []
    : flows.filter((f) => f.id === activeFlow || f.kind === 'internet').map((f) => ({ f, active: f.id === activeFlow }));

  const counts = new Map<string, number>();
  for (const n of map.nodes) counts.set(n.segment, (counts.get(n.segment) ?? 0) + 1);

  // Dorsale sotto il gateway, rami verso le zone, collegamenti tra i nodi.
  const byId = new Map(map.nodes.map((n) => [n.id, n]));
  const segById = new Map(map.segments.map((s) => [s.id, s]));
  const bb = map.backbone;
  const stubs = map.segments.map((s) => ({ s, pts: zoneExit(map, s) }));
  const linkPaths = map.links
    .filter((l) => l.kind !== 'lan' && !segById.has(l.from))
    .map((l) => {
      const a = byId.get(l.from);
      const b = byId.get(l.to);
      let pts: Pt[] = [];
      let curve = false;
      if (a && b) {
        if (a.segment === b.segment && a.segment !== 'core') {
          pts = [[a.x, a.y], [b.x, b.y]];
          curve = true;
        } else if (a.segment !== 'core' && b.segment === 'core' && l.inferred) pts = [];
        else pts = routePoints(map, [a.id, b.id]);
      }
      return { l, pts, curve };
    })
    .filter((x) => x.pts.length > 1);
  const curveD = (pts: Pt[]) => {
    const [a, b] = pts;
    const mx = (a[0] + b[0]) / 2;
    const my = Math.min(a[1], b[1]) - 46;
    return `M${a[0]} ${a[1]} Q${mx} ${my} ${b[0]} ${b[1]}`;
  };

  const pick = (n: MapNode) => setSelected((s) => (s === n.id ? null : n.id));

  if (!map.nodes.length) return <p className="muted">Nessun dato di rete da disegnare.</p>;

  return (
    <div className={`netmap${compact ? ' compact' : ''}`}>
      {!compact && (
      <div className="nm-toolbar" role="toolbar" aria-label="Comandi della mappa">
        <label className="nm-search">
          <Search size={15} aria-hidden />
          <input type="search" placeholder="Cerca nome, IP o produttore" value={query} onChange={(e) => setQuery(e.target.value)} aria-label="Cerca nella mappa" />
        </label>
        <span className="spacer" />
        <button className="btn small icon" onClick={() => zoomAt(1.25)} aria-label="Ingrandisci" title="Ingrandisci (+)">
          <ZoomIn size={16} aria-hidden />
        </button>
        <button className="btn small icon" onClick={() => zoomAt(0.8)} aria-label="Riduci" title="Riduci (−)">
          <ZoomOut size={16} aria-hidden />
        </button>
        <button className="btn small icon" onClick={() => setView(fit)} aria-label="Mostra tutta la mappa" title="Mostra tutto (0)">
          <Maximize2 size={16} aria-hidden />
        </button>
        {!reduce && (
          <button className="btn small icon" onClick={() => setPlaying((p) => !p)} aria-label="Ferma i pacchetti animati" aria-pressed={!playing} title="Ferma i pacchetti animati">
            {playing ? <Pause size={16} aria-hidden /> : <Play size={16} aria-hidden />}
          </button>
        )}
        <button className={`btn small${list ? ' on' : ''}`} onClick={() => setList((l) => !l)} aria-pressed={list}>
          <List size={15} aria-hidden /> Elenco
        </button>
      </div>
      )}

      {!compact && (
      <div className="nm-chips" role="group" aria-label="Tipi di dispositivo">
        {kinds.map((k) => {
          const Icon = KIND_ICON[k];
          const off = hidden.indexOf(k) >= 0;
          return (
            <button
              key={k}
              className={`nm-chip${off ? ' off' : ''}`}
              aria-pressed={!off}
              onClick={() => setHidden((h) => (off ? h.filter((x) => x !== k) : [...h, k]))}
              title={off ? `Mostra ${KIND_PLURAL[k].toLowerCase()}` : `Nascondi ${KIND_PLURAL[k].toLowerCase()}`}
            >
              <Icon size={14} color={kindColor(k)} aria-hidden /> {KIND_PLURAL[k]} <b>{map.counts[k]}</b>
            </button>
          );
        })}
      </div>
      )}

      {list ? (
        <NetMapList map={map} />
      ) : (
        <div className="nm-stage" ref={wrapRef} style={{ height }}>
          <svg
            className={`nm-canvas${live ? ' live' : ''}`}
            role="group"
            aria-label={`Mappa della rete: ${map.nodes.length} elementi. Usa Tab per scegliere un dispositivo; + e − per lo zoom, 0 per adattare, frecce per spostarti.`}
            tabIndex={0}
            onKeyDown={onCanvasKey}
            onPointerDown={onPointerDown}
            onPointerMove={onPointerMove}
            onPointerUp={onPointerUp}
            onPointerCancel={onPointerUp}
            onClick={() => setSelected(null)}
          >
            <defs>
              <pattern id="nm-grid" width="28" height="28" patternUnits="userSpaceOnUse">
                <circle cx="1" cy="1" r="1" className="nm-grid-dot" />
              </pattern>
            </defs>
            <rect width="100%" height="100%" fill="url(#nm-grid)" />
            <g transform={`translate(${t.x.toFixed(1)} ${t.y.toFixed(1)}) scale(${t.k.toFixed(4)})`}>
              {map.segments.map((s) => (
                <Zone key={s.id} s={s} count={counts.get(s.id) ?? 0} />
              ))}
              {/* Collegamenti dei dispositivi alla linea di raccolta della zona. */}
              {map.nodes
                .filter((n) => n.segment !== 'core' && visible(n))
                .map((n) => {
                  const s = segById.get(n.segment);
                  return s ? <path key={`drop-${n.id}`} d={pathD(nodeDrop(s, n))} className="nm-drop" /> : null;
                })}
              {bb && map.segments.length > 0 && <path d={`M${bb.x} ${bb.y1 + R + 6} L${bb.x} ${bb.y2}`} className="nm-link nm-backbone" />}
              {stubs.map(({ s, pts }) => (
                <path key={`stub-${s.id}`} d={pathD(pts)} className={`nm-link ${s.kind === 'remote' ? 'nm-routed' : s.kind === 'wifi' ? 'nm-wifi' : 'nm-backbone'}`} />
              ))}
              {linkPaths.map(({ l, pts, curve }) => (
                <path
                  key={l.id}
                  d={curve ? curveD(pts) : pathD(pts)}
                  className={`nm-link nm-${l.kind}${l.inferred ? ' inferred' : ''}`}
                  style={l.sev && l.sev !== 'ok' ? { stroke: SEV_COLOR[l.sev] } : undefined}
                />
              ))}
              {linkPaths
                .filter(({ l }) => l.label)
                .map(({ l, pts }) => {
                  const mid = pts[Math.floor((pts.length - 1) / 2)];
                  const nxt = pts[Math.floor((pts.length - 1) / 2) + 1] ?? mid;
                  return (
                    <text key={`lbl-${l.id}`} x={(mid[0] + nxt[0]) / 2 + 8} y={(mid[1] + nxt[1]) / 2} className="nm-link-label">
                      {l.label}
                    </text>
                  );
                })}
              {shownFlows.map(({ f, active }) => {
                const pts = routePoints(map, f.path);
                const blocked = f.kind === 'blocked';
                return (
                  <FlowPath
                    key={f.id}
                    pts={blocked && f.sev === 'ok' ? truncate(pts, 0.82) : pts}
                    color={f.sev === 'crit' ? 'var(--crit)' : f.sev === 'warn' ? 'var(--warn)' : blocked ? 'var(--p2)' : 'var(--accent)'}
                    active={active}
                    playing={live}
                    blocked={blocked && f.sev === 'ok'}
                    speed={f.rttMs ? clamp(380 - f.rttMs * 3, 120, 380) : 300}
                  />
                );
              })}
              {sel && selPath.length > 1 && <FlowPath pts={routePoints(map, selPath)} color="var(--accent)" active playing={live} blocked={false} speed={300} />}
              {map.nodes.filter(visible).map((n) => (
                <NodeGlyph key={n.id} n={n} dim={!matches(n)} selected={n.id === selected} playing={live} onPick={pick} />
              ))}
            </g>
          </svg>
          <AnimatePresence>
            {sel && (
              <m.aside
                className="nm-panel"
                key={sel.id}
                initial={{ opacity: 0, x: 16 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 16 }}
                transition={{ duration: reduce ? 0 : 0.2 }}
                aria-label={`Dettagli: ${sel.label}`}
              >
                <NodeDetails map={map} n={sel} path={selPath} onClose={() => setSelected(null)} />
              </m.aside>
            )}
          </AnimatePresence>
          {!compact && <p className="nm-hint faint">Trascina per spostarti · Ctrl + rotella o due dita per lo zoom · tocca un dispositivo per i dettagli</p>}
        </div>
      )}

      {!list && !compact && flows.length > 0 && (
        <div className="nm-flows" role="group" aria-label="Percorsi del traffico di questo PC">
          <span className="nm-flows-title">
            <Waypoints size={15} aria-hidden /> Percorsi del traffico
          </span>
          {flows.map((f) => (
            <button
              key={f.id}
              className={`nm-chip flow${f.id === activeFlow && !sel ? ' on' : ''}`}
              aria-pressed={f.id === activeFlow && !sel}
              onClick={() => {
                setSelected(null);
                setActiveFlow(f.id);
              }}
              title={f.note}
            >
              <i className="nm-flow-dot" style={{ background: f.sev === 'crit' ? 'var(--crit)' : f.sev === 'warn' ? 'var(--warn)' : f.kind === 'blocked' ? 'var(--p2)' : 'var(--accent)' }} aria-hidden />
              {f.label}
              {f.kind === 'blocked' && <span className="faint"> · bloccato{f.sev === 'ok' ? ' (giusto)' : ' NO'}</span>}
            </button>
          ))}
        </div>
      )}
      {!list && !sel && !compact && (
        <p className="nm-flow-note" aria-live="polite">
          {(() => {
            const f = flows.find((x) => x.id === activeFlow);
            return f ? `${f.label}: ${pathText(map, f.path)}. ${f.note}` : '';
          })()}
        </p>
      )}
      {!compact && <Legend />}
      {!compact &&
        map.notes.map((n) => (
          <p key={n} className="faint nm-note">
            {n}
          </p>
        ))}
    </div>
  );
}

function NodeDetails({ map, n, path, onClose }: { map: NetworkMap; n: MapNode; path: string[]; onClose: () => void }) {
  const Icon = KIND_ICON[n.kind];
  const seg = map.segments.find((s) => s.id === n.segment);
  return (
    <>
      <div className="nm-panel-head">
        <span className="nm-panel-icon" style={{ color: kindColor(n.kind) }}>
          <Icon size={22} aria-hidden />
        </span>
        <div>
          <b>{n.self ? `${n.label} (questo PC)` : n.label}</b>
          <span className="faint">
            {KIND_LABEL[n.kind]} · {CONF_TEXT[n.confidence]}
          </span>
        </div>
        <button className="btn small icon" onClick={onClose} aria-label="Chiudi i dettagli">
          <X size={16} aria-hidden />
        </button>
      </div>
      <dl className="kv nm-kv">
        {n.ip && (
          <>
            <dt>Indirizzo IP</dt>
            <dd className="mono">{n.ip}</dd>
          </>
        )}
        {n.mac && (
          <>
            <dt>MAC</dt>
            <dd className="mono">{n.mac}</dd>
          </>
        )}
        {n.vendor && (
          <>
            <dt>Produttore</dt>
            <dd>{n.vendor}</dd>
          </>
        )}
        {n.names.length > 0 && (
          <>
            <dt>Nomi</dt>
            <dd>{n.names.join(', ')}</dd>
          </>
        )}
        {n.roles.length > 0 && (
          <>
            <dt>Ruolo</dt>
            <dd>{n.roles.join(', ')}</dd>
          </>
        )}
        {seg && (
          <>
            <dt>Zona</dt>
            <dd>
              {seg.label}
              {seg.vlan ? ` (VLAN ${seg.vlan})` : ''}
            </dd>
          </>
        )}
        {n.rttMs !== undefined && (
          <>
            <dt>Risposta</dt>
            <dd>{`${n.rttMs < 10 ? n.rttMs.toFixed(1) : Math.round(n.rttMs)} ms`.replace('.', ',')}</dd>
          </>
        )}
      </dl>
      <p className="nm-why-title">Perché questo tipo</p>
      <ul className="nm-why">
        {n.reasons.map((r) => (
          <li key={r}>{r}</li>
        ))}
      </ul>
      {n.signals.length > 0 && (
        <details className="nm-signals">
          <summary>Segnali raccolti</summary>
          <ul>
            {n.signals.map((s) => (
              <li key={s}>{s}</li>
            ))}
          </ul>
        </details>
      )}
      {path.length > 1 && (
        <p className="nm-path">
          <LocateFixed size={14} aria-hidden /> {pathText(map, path)}
        </p>
      )}
    </>
  );
}

function Legend() {
  return (
    <details className="nm-legend">
      <summary>Legenda</summary>
      <ul>
        <li>
          <svg width="40" height="10" aria-hidden>
            <line x1="2" x2="38" y1="5" y2="5" className="nm-link nm-cable" />
          </svg>{' '}
          cavo o collegamento diretto
        </li>
        <li>
          <svg width="40" height="10" aria-hidden>
            <line x1="2" x2="38" y1="5" y2="5" className="nm-link nm-wifi" />
          </svg>{' '}
          Wi-Fi
        </li>
        <li>
          <svg width="40" height="10" aria-hidden>
            <line x1="2" x2="38" y1="5" y2="5" className="nm-link nm-routed" />
          </svg>{' '}
          traffico tra reti, attraverso il router o il firewall
        </li>
        <li>
          <svg width="40" height="10" aria-hidden>
            <line x1="2" x2="38" y1="5" y2="5" className="nm-link nm-cable inferred" />
          </svg>{' '}
          collegamento dedotto, non misurato
        </li>
        <li>
          <span className="nm-legend-dot" style={{ background: 'var(--accent)' }} /> pacchetti del percorso scelto ·{' '}
          <span className="nm-legend-dot" style={{ background: 'var(--p2)' }} /> percorso bloccato come previsto ·{' '}
          <span className="nm-legend-dot" style={{ background: 'var(--crit)' }} /> problema
        </li>
        <li>
          <span className="nm-legend-q">?</span> tipo riconosciuto con pochi indizi: da verificare · bordo tratteggiato: dispositivo dedotto
        </li>
      </ul>
    </details>
  );
}

/** Alternativa testuale alla mappa: zone e dispositivi in tabella. */
export function NetMapList({ map }: { map: NetworkMap }) {
  const zones = [{ id: 'core', label: 'Collegamento verso Internet' } as Pick<MapSegment, 'id' | 'label'>, ...map.segments];
  return (
    <div className="nm-list">
      {zones.map((z) => {
        const ns = map.nodes.filter((n) => n.segment === z.id);
        if (!ns.length) return null;
        const seg = map.segments.find((s) => s.id === z.id);
        return (
          <TableWrap key={z.id} label={z.label}>
            <table className="pc-table">
              <caption>
                {z.label}
                {seg?.vlan ? ` · VLAN ${seg.vlan}` : ''}
                {seg?.subnet && seg.kind === 'local' ? ` · ${seg.subnet}` : ''}
              </caption>
              <thead>
                <tr>
                  <th>Dispositivo</th>
                  <th>Tipo</th>
                  <th>Indirizzo</th>
                  <th>Produttore</th>
                  <th>Perché</th>
                </tr>
              </thead>
              <tbody>
                {ns.map((n) => {
                  const Icon = KIND_ICON[n.kind];
                  return (
                    <tr key={n.id}>
                      <td>
                        <Icon size={15} color={kindColor(n.kind)} aria-hidden /> {n.self ? `${n.label} (questo PC)` : n.label}
                      </td>
                      <td>
                        {KIND_LABEL[n.kind]}
                        <span className="faint"> · {n.confidence}</span>
                      </td>
                      <td className="mono">{n.ip ?? '—'}</td>
                      <td>{n.vendor ?? '—'}</td>
                      <td className="faint">{n.reasons[0] ?? ''}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </TableWrap>
        );
      })}
    </div>
  );
}
