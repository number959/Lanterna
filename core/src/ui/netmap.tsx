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
import { memo, useCallback, useEffect, useId, useLayoutEffect, useMemo, useRef, useState } from 'react';
import type { KeyboardEvent as ReactKeyboardEvent, PointerEvent as ReactPointerEvent } from 'react';
import { buildNetworkMap, KIND_GROUP, KIND_LABEL, KIND_ORDER, KIND_PLURAL, ZONE_BUS } from '../engine';
import type { Analysis, DeviceKind, MapFlow, MapNode, MapSegment, NetworkMap, Scan, Severity } from '../engine';
import { TableWrap } from './components';
import { IsoDevice, isoTop } from './isoart';
import {
  arrowPoints,
  arrowsAlong,
  buildScene,
  easeInOutCubic,
  easeOutCubic,
  ellipsis,
  entranceSchedule,
  frameRoute,
  frameView,
  LABEL_CHARS,
  latticePath,
  lerpView,
  nodeDrop,
  offsetPolyline,
  pathD,
  pathToNode,
  placeLinkLabel,
  polyLength,
  project,
  projectPath,
  routeBounds,
  routePoints,
  spaceMap,
  toScreen,
  truncate,
  visibleArea,
  zoneExit,
  ZONE_DEPTH,
  zoomAbout,
} from './netmap-iso';
import type { Pt, SceneNode, SceneZone, View } from './netmap-iso';

export { pathToNode } from './netmap-iso';

// Mappa della rete interattiva in prospettiva isometrica, come gli schemi
// tecnici a linee: le zone (sottoreti, VLAN, reti Wi-Fi) sono piattaforme a
// terra, i dispositivi disegni a linee in piedi sul loro punto, i percorsi del
// traffico di questo PC due corsie tratteggiate (andata e ritorno) su cui
// scorre il pacchetto con l'etichetta del protocollo. All'apertura la scena si
// costruisce: salgono le zone, cadono i dispositivi uno alla volta a partire
// da questo PC, si disegnano i collegamenti, e la camera si allontana. Zoom con
// i pulsanti, Ctrl + rotella o due dita; trascinamento per spostarsi; i
// cambi di inquadratura scorrono. Con "riduci movimento" tutto compare subito e
// i pacchetti restano fermi. L'elenco testuale è l'alternativa accessibile.

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

// Colori dei disegni nella console blu notte (mappa e traffico passo passo):
// tinte chiare per gruppo, contrasto ≥ 7:1 sul fondo.
const CONSOLE_KIND: Partial<Record<DeviceKind, string>> = { medical: '#ffadc4', camera: '#ffbf9a', voip: '#8fe3d1', iot: '#a8e6a1' };
const CONSOLE_GROUP = { rete: '#9fd8ff', server: '#cbb5ff', postazioni: '#c6d3e8', periferiche: '#ffd59a', altro: '#a9b9d3' } as const;
export const consoleColor = (k: DeviceKind) => CONSOLE_KIND[k] ?? CONSOLE_GROUP[KIND_GROUP[k]];

/** Etichetta e colore dei pacchetti di un percorso, come nel traffico passo passo. */
function flowTag(f: MapFlow): string {
  if (f.kind === 'internet') return 'HTTPS';
  if (f.kind === 'dns') return 'DNS QUERY';
  const port = Number(f.id.split(':').pop());
  return port ? `TCP ${port}` : 'PING';
}
function flowColor(f: MapFlow): string {
  if (f.sev === 'crit') return 'var(--c-crit)';
  if (f.sev === 'warn') return 'var(--c-warn)';
  if (f.kind === 'blocked') return 'var(--c-blocked)';
  if (f.kind === 'dns') return 'var(--c-dns)';
  if (f.kind === 'service') return 'var(--c-tcp)';
  return 'var(--c-https)';
}

const SEV_COLOR: Record<Severity, string> = { ok: 'var(--ok)', info: 'var(--info)', warn: 'var(--warn)', crit: 'var(--crit)', unknown: 'var(--text-3)' };
const CONF_TEXT = { alta: 'riconosciuto con certezza', media: 'riconosciuto con buona probabilità', bassa: 'ipotesi da verificare' } as const;

const clamp = (v: number, a: number, b: number) => Math.max(a, Math.min(b, v));
const ptsAttr = (pts: Pt[]) => pts.map((p) => `${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(' ');
const ms = (v: number) => `${Math.round(v)}ms`;
/** Distanza delle due corsie dal centro del percorso. */
const LANE = 4;

function pathText(map: NetworkMap, ids: string[]): string {
  const names = new Map(map.nodes.map((n) => [n.id, n.self ? 'questo PC' : n.label]));
  return ids.map((id) => names.get(id) ?? id).join(' → ');
}

// ---------------------------------------------------------------- disegno

/** Zona come piattaforma a terra: piano, spessore sui due lati davanti, linea di raccolta e titolo diritto. */
function ZonePlate({ z, delay }: { z: SceneZone; delay: number }) {
  const { s, T, R, B, L, label } = z;
  const dn = (p: Pt): Pt => [p[0], p[1] + ZONE_DEPTH];
  const bus = s.kind !== 'wifi' ? projectPath([[s.x + 16, s.y + ZONE_BUS], [s.x + s.w - 16, s.y + ZONE_BUS]]) : null;
  const top = ptsAttr([T, R, B, L]);
  return (
    <g className={`nm-zone nm-zone-${s.kind}`} style={{ animationDelay: ms(delay) }}>
      <polygon points={ptsAttr([L, B, dn(B), dn(L)])} className="nm-plat-l" />
      <polygon points={ptsAttr([B, R, dn(R), dn(B)])} className="nm-plat-r" />
      <polygon points={top} className="nm-plat-t" />
      <path d={latticePath(s)} className="nm-plat-lat" />
      {bus && <path d={pathD(bus)} className="nm-bus" />}
      <text x={label.x.toFixed(1)} y={label.y.toFixed(1)} textAnchor={label.anchor} className="nm-zone-title">
        {label.title}
      </text>
      {label.sub && (
        <text x={label.x.toFixed(1)} y={(label.y + 14).toFixed(1)} textAnchor={label.anchor} className="nm-zone-sub">
          {label.sub}
        </text>
      )}
      {s.kind === 'wifi' && s.note && (
        <foreignObject x={(z.center[0] - 105).toFixed(1)} y={(z.center[1] - 30).toFixed(1)} width={210} height={62}>
          <p className="nm-zone-note">{s.note}</p>
        </foreignObject>
      )}
    </g>
  );
}

interface NodeProps {
  sn: SceneNode;
  dim: boolean;
  selected: boolean;
  playing: boolean;
  delay: number;
  onPick: (n: MapNode) => void;
  onFocusNode: (n: MapNode, el: Element) => void;
}

/** Dispositivo in piedi sul suo punto a terra, con nome e IP diritti sotto. */
const NodeIso = memo(function NodeIso({ sn, dim, selected, playing, delay, onPick, onFocusNode }: NodeProps) {
  const { n, p, sc, h } = sn;
  const onKey = (e: ReactKeyboardEvent) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      onPick(n);
    }
  };
  const head = n.self ? 22 : 8;
  return (
    <g
      className={`nm-node${dim ? ' dim' : ''}${selected ? ' sel' : ''}${n.self ? ' self' : ''}`}
      transform={`translate(${p[0].toFixed(1)} ${p[1].toFixed(1)})`}
      tabIndex={0}
      role="button"
      aria-label={`${KIND_LABEL[n.kind]}: ${n.label}${n.self ? ' (questo PC)' : ''}${n.ip ? `, ${n.ip}` : ''}${n.confidence === 'bassa' ? ', tipo da verificare' : ''}${n.inferred ? ', dedotto' : ''}`}
      aria-pressed={selected}
      onClick={(e) => {
        e.stopPropagation();
        onPick(n);
      }}
      onKeyDown={onKey}
      onPointerDown={(e) => e.stopPropagation()}
      onFocus={(e) => onFocusNode(n, e.currentTarget)}
    >
      <g className="nm-node-in" style={{ animationDelay: ms(delay) }}>
        <rect x={-46} y={-h - head} width={92} height={h + head + 50} rx={12} className="nm-hit" />
        {/* Ellissi a terra (cerchi orizzontali in prospettiva): questo PC, dedotto, scelto. */}
        {n.self && <ellipse rx={48} ry={27.7} className={`nm-halo${playing ? ' live' : ''}`} />}
        {n.self && <ellipse rx={38} ry={21.9} className="nm-self-ring" />}
        {n.inferred && <ellipse rx={36} ry={20.8} className="nm-inferred" />}
        {selected && <ellipse rx={46} ry={26.6} className="nm-sel-ring" />}
        <g className="nm-glyph" style={{ color: consoleColor(n.kind) }}>
          <IsoDevice kind={n.kind} scale={sc} />
        </g>
        {n.self && (
          <text y={-h - 9} textAnchor="middle" className="nm-you">
            questo PC
          </text>
        )}
        {n.sev && (n.sev === 'warn' || n.sev === 'crit') && <circle cx={30} cy={-h + 6} r={5.5} style={{ fill: SEV_COLOR[n.sev] }} className="nm-dot" />}
        {n.confidence === 'bassa' && !n.self && (
          <g transform="translate(33 -10)" className="nm-doubt">
            <circle r={7.5} />
            <text y={3.6} textAnchor="middle">
              ?
            </text>
          </g>
        )}
        <text y={29} textAnchor="middle" className="nm-label">
          {ellipsis(n.label, LABEL_CHARS)}
        </text>
        {n.ip && (
          <text y={41} textAnchor="middle" className="nm-ip">
            {n.ip}
          </text>
        )}
      </g>
    </g>
  );
});

/** Un percorso del traffico già proiettato: centro, corsia di andata e di ritorno. */
interface FlowGeo {
  id: string;
  pts: Pt[];
  req: Pt[];
  res: Pt[];
  color: string;
  active: boolean;
  blocked: boolean;
  dur: number;
  tag: string;
  info: string;
}

/** Corsie tratteggiate con le punte di freccia: sotto i dispositivi. */
function FlowLanes({ g }: { g: FlowGeo }) {
  if (!g.active)
    return (
      <g className="nm-flow" style={{ color: g.color }}>
        <path d={pathD(g.pts)} className="nm-flow-line" />
      </g>
    );
  return (
    <g className="nm-flow active" style={{ color: g.color }}>
      <path d={pathD(g.req)} className="nm-lane" />
      {g.res.length > 1 && <path d={pathD(g.res)} className="nm-lane res" />}
      {arrowsAlong(g.req).map((a, i) => (
        <polygon key={`q${i}`} points={arrowPoints(a)} className="nm-arrow" />
      ))}
      {g.res.length > 1 &&
        arrowsAlong(g.res).map((a, i) => (
          <polygon key={`r${i}`} points={arrowPoints(a)} className="nm-arrow res" />
        ))}
    </g>
  );
}

/** Etichetta del pacchetto (protocollo) con il riquadro della destinazione, come nel traffico passo passo. */
function Chip({ tag, info }: { tag: string; info: string }) {
  const cw = tag.length * 6.9 + 14;
  const iw = Math.max(cw, info.length * 5.9 + 12);
  return (
    <g className="nm-chip-pkt">
      <line y1={-14} y2={-5} className="nm-pkt-stem" />
      <rect x={-iw / 2} y={-30} width={iw} height={15} rx={3} className="nm-pkt-box" />
      <text y={-19.4} textAnchor="middle" className="nm-pkt-i">
        {info}
      </text>
      <rect x={-cw / 2} y={-47} width={cw} height={17} rx={3} fill="currentColor" />
      <text y={-34.6} textAnchor="middle" className="nm-pkt-t">
        {tag}
      </text>
    </g>
  );
}

/**
 * Pacchetti (SMIL, sopra i dispositivi): sul percorso scelto il pacchetto con
 * l'etichetta va lungo la corsia di andata e la risposta torna sull'altra; sui
 * percorsi di sfondo scorrono due puntini.
 */
function FlowPackets({ g, playing }: { g: FlowGeo; playing: boolean }) {
  const end = g.req.length > 1 ? g.req[g.req.length - 1] : g.pts[g.pts.length - 1];
  const stop = g.pts[g.pts.length - 1];
  const reply = g.active && !g.blocked && g.res.length > 1;
  // Un ciclo: andata, poi ritorno (o una breve pausa, se non c'è risposta).
  const cycle = reply ? g.dur * 2 : g.dur + 0.6;
  const go = g.dur / cycle;
  const t = (v: number) => v.toFixed(3);
  return (
    <g className={`nm-flow-pk${g.active ? ' active' : ''}`} style={{ color: g.color }}>
      {playing && g.active && (
        <>
          <g opacity={0} className="nm-pkt">
            <Chip tag={g.tag} info={g.info} />
            <circle r={4.6} className="nm-packet" />
            <animateMotion dur={`${cycle.toFixed(2)}s`} repeatCount="indefinite" path={pathD(g.req)} keyPoints="0;1;1" keyTimes={`0;${t(go)};1`} calcMode="linear" />
            <animate attributeName="opacity" values="0;1;1;0;0" keyTimes={`0;${t(go * 0.08)};${t(go * 0.92)};${t(go)};1`} dur={`${cycle.toFixed(2)}s`} repeatCount="indefinite" />
          </g>
          {reply && (
            <g opacity={0} className="nm-pkt">
              <circle r={3.6} className="nm-packet res" />
              <animateMotion dur={`${cycle.toFixed(2)}s`} repeatCount="indefinite" path={pathD(g.res)} keyPoints="0;0;1" keyTimes={`0;${t(go)};1`} calcMode="linear" />
              <animate attributeName="opacity" values="0;0;1;1;0" keyTimes={`0;${t(go)};${t(go + 0.04)};${t(0.97)};1`} dur={`${cycle.toFixed(2)}s`} repeatCount="indefinite" />
            </g>
          )}
        </>
      )}
      {playing &&
        !g.active &&
        [0, 1].map((i) => (
          <g key={i} opacity={0} className="nm-pkt">
            <circle r={3} className="nm-packet" />
            <animateMotion dur={`${g.dur.toFixed(2)}s`} begin={`${((g.dur / 2) * i).toFixed(2)}s`} repeatCount="indefinite" path={pathD(g.pts)} calcMode="linear" />
            <animate attributeName="opacity" values="0;1;1;0" keyTimes="0;0.08;0.88;1" dur={`${g.dur.toFixed(2)}s`} begin={`${((g.dur / 2) * i).toFixed(2)}s`} repeatCount="indefinite" />
          </g>
        ))}
      {!playing && g.active && (
        <g transform={`translate(${end[0].toFixed(1)} ${end[1].toFixed(1)})`} className="nm-pkt">
          <Chip tag={g.tag} info={g.info} />
          <circle r={4.6} className="nm-packet" />
        </g>
      )}
      {g.blocked && (
        <g transform={`translate(${stop[0].toFixed(1)} ${stop[1].toFixed(1)})`} className="nm-stop">
          <ellipse rx={12} ry={8} className="nm-stop-ground" />
          <circle r={10} cy={-6} />
          <path d="M-4.5 -10.5 L4.5 -1.5 M4.5 -10.5 L-4.5 -1.5" />
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

type CamMode = 'glide' | 'jump';
type Wire = { key: string; d: string; cls: string; style?: { stroke: string }; delay: number; draw: string };

export function NetMap({ scan, analysis, height = 620, compact = false }: NetMapProps) {
  // La disposizione piana del motore, con più aria tra le zone, proiettata sul piano isometrico.
  const map = useMemo(() => spaceMap(buildNetworkMap(scan, analysis)), [scan, analysis]);
  const scene = useMemo(() => buildScene(map, isoTop), [map]);
  const enter = useMemo(() => entranceSchedule(map), [map]);
  const reduce = !!useReducedMotion();
  const uid = useId().replace(/:/g, '');
  const wrapRef = useRef<HTMLDivElement>(null);
  const [measured, setMeasured] = useState<{ w: number; h: number } | null>(null);
  const size = measured ?? { w: 900, h: height };
  const [view, setView] = useState<View | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [hidden, setHidden] = useState<DeviceKind[]>([]);
  const [query, setQuery] = useState('');
  const [playing, setPlaying] = useState(true);
  const [activeFlow, setActiveFlow] = useState<string>('flow:internet');
  const [list, setList] = useState(false);
  const [entering, setEntering] = useState(!reduce);
  const live = playing && !reduce;

  useLayoutEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const read = () => setMeasured({ w: el.clientWidth || 900, h: el.clientHeight || height });
    read();
    if (typeof ResizeObserver === 'undefined') return;
    const ro = new ResizeObserver(read);
    ro.observe(el);
    return () => ro.disconnect();
  }, [list, height]);

  // Adatta: tutta la scena, sopra la riga dei suggerimenti in basso.
  const fit = useMemo(() => frameView(scene.bounds, { x0: 14, y0: 14, x1: size.w - 14, y1: size.h - (compact ? 14 : 30) }, 0.2, 1.3), [scene, size.w, size.h, compact]);
  // Se la mappa intera diventerebbe illeggibile (telefono, reti grandi) si parte dal percorso di
  // questo PC verso Internet, come nella storia del pacchetto; se non entra, da questo PC.
  const initial = useMemo(() => {
    if (fit.k >= 0.45) return fit;
    const inet = map.flows.find((f) => f.kind === 'internet');
    if (inet && inet.path.length > 1) {
      const v = frameView(routeBounds(map, scene, inet.path), { x0: 20, y0: 24, x1: size.w - 20, y1: size.h - 40 }, 0.2, 1);
      if (v.k >= 0.55) return v;
    }
    const c = scene.nodes.find((s) => s.n.self) ?? scene.nodes.find((s) => s.n.gateway);
    if (!c) return fit;
    const k = 0.8;
    return { k, x: size.w / 2 - c.p[0] * k, y: size.h / 2.3 - (c.p[1] - 10) * k };
  }, [fit, map, scene, size.w, size.h]);
  const t = view ?? initial;

  // ------------------------------------------------ camera
  // La trasformazione del mondo si scrive direttamente sul gruppo: durante le
  // transizioni React non ridisegna i dispositivi a ogni fotogramma.
  const camEl = useRef<SVGGElement | null>(null);
  const shown = useRef<View>(initial);
  const anim = useRef<{ from: View; to: View; t0: number; dur: number; ease: (t: number) => number } | null>(null);
  const raf = useRef(0);
  const pending = useRef<CamMode | null>(null);
  const intro = useRef(!reduce);
  const sizeRef = useRef(size);
  sizeRef.current = size;
  const targetRef = useRef(t);
  targetRef.current = t;
  const initialRef = useRef(initial);
  initialRef.current = initial;
  const sceneRef = useRef(scene);
  sceneRef.current = scene;

  const apply = useCallback((v: View) => {
    shown.current = v;
    camEl.current?.setAttribute('transform', `translate(${v.x.toFixed(2)} ${v.y.toFixed(2)}) scale(${v.k.toFixed(4)})`);
  }, []);
  const camRef = useCallback(
    (el: SVGGElement | null) => {
      camEl.current = el;
      if (el) apply(shown.current);
    },
    [apply],
  );
  const stop = useCallback(() => {
    cancelAnimationFrame(raf.current);
    anim.current = null;
  }, []);
  const glide = useCallback(
    (to: View, dur: number, ease: (t: number) => number = easeOutCubic) => {
      anim.current = { from: shown.current, to, t0: performance.now(), dur, ease };
      cancelAnimationFrame(raf.current);
      const tick = (now: number) => {
        const a = anim.current;
        if (!a) return;
        const p = Math.min(1, (now - a.t0) / a.dur);
        apply(p >= 1 ? a.to : lerpView(a.from, a.to, a.ease(p), sizeRef.current.w, sizeRef.current.h));
        if (p < 1) raf.current = requestAnimationFrame(tick);
        else anim.current = null;
      };
      raf.current = requestAnimationFrame(tick);
    },
    [apply],
  );
  useEffect(() => () => cancelAnimationFrame(raf.current), []);

  /** Nuova inquadratura: "glide" scorre (pulsanti, tastiera, scelta), "jump" è immediata (trascinamento, pizzico, rotella). */
  const go = useCallback((next: View | ((cur: View) => View), mode: CamMode) => {
    pending.current = mode;
    setView((v) => {
      const cur = v ?? initialRef.current;
      return { ...(typeof next === 'function' ? next(cur) : next) };
    });
  }, []);
  /** Ferma una transizione in corso dove si trova, prima di un gesto. */
  const freeze = useCallback(() => {
    if (!anim.current) return;
    stop();
    go({ ...shown.current }, 'jump');
  }, [go, stop]);

  // Entrata in scena all'apertura e quando cambia l'analisi.
  const epoch = useRef({ map, n: 0 });
  if (epoch.current.map !== map) epoch.current = { map, n: epoch.current.n + 1 };
  const firstMap = useRef(map);
  useLayoutEffect(() => {
    if (firstMap.current !== map) {
      firstMap.current = map;
      setSelected(null);
      pending.current = null;
      setView(null);
    }
    if (reduce) {
      intro.current = false;
      setEntering(false);
      return;
    }
    intro.current = true;
    setEntering(true);
    const timer = window.setTimeout(() => setEntering(false), enter.end + 120);
    return () => window.clearTimeout(timer);
  }, [map, reduce, enter]);

  useLayoutEffect(() => {
    if (!measured) return;
    const target = view ?? initial;
    const mode = pending.current;
    pending.current = null;
    if (intro.current) {
      intro.current = false;
      // La camera parte vicina a questo PC e si allontana mentre la scena si costruisce.
      const c = scene.nodes.find((s) => s.n.self) ?? scene.nodes.find((s) => s.n.gateway);
      const [sx, sy] = c ? toScreen(target, c.p) : [size.w / 2, size.h / 2];
      apply(zoomAbout(target, sx, sy, 1.7, 0.1, 4));
      glide(target, 1450, easeInOutCubic);
      return;
    }
    if (mode === 'glide' && !reduce) glide(target, 620);
    else if (mode === 'jump' || !anim.current) {
      stop();
      apply(target);
    } else anim.current.to = target;
  }, [view, initial, measured, reduce, scene, size.w, size.h, apply, glide, stop]);

  const zoomAt = useCallback(
    (factor: number, cx?: number, cy?: number, mode: CamMode = 'glide') => {
      const px = cx ?? sizeRef.current.w / 2;
      const py = cy ?? sizeRef.current.h / 2;
      if (mode === 'jump') freeze();
      go((cur) => zoomAbout(cur, px, py, factor), mode);
    },
    [go, freeze],
  );

  // Ctrl + rotella (e il pizzico del touchpad) fanno lo zoom; la rotella da sola scorre la pagina.
  useEffect(() => {
    const el = wrapRef.current?.querySelector('svg');
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      if (!e.ctrlKey && !e.metaKey) return;
      e.preventDefault();
      const r = el.getBoundingClientRect();
      zoomAt(Math.exp(-e.deltaY * 0.0022), e.clientX - r.left, e.clientY - r.top, 'jump');
    };
    el.addEventListener('wheel', onWheel, { passive: false });
    return () => el.removeEventListener('wheel', onWheel);
  }, [zoomAt, list]);

  // Trascinamento e pizzico con due dita: immediati, senza transizione.
  const pointers = useRef(new Map<number, Pt>());
  const pinch = useRef<{ d: number; k: number } | null>(null);
  const moved = useRef(0);
  const onPointerDown = (e: ReactPointerEvent<SVGSVGElement>) => {
    (e.currentTarget as Element).setPointerCapture(e.pointerId);
    freeze();
    if (!pointers.current.size) moved.current = 0;
    pointers.current.set(e.pointerId, [e.clientX, e.clientY]);
    if (pointers.current.size === 2) {
      const [a, b] = [...pointers.current.values()];
      pinch.current = { d: Math.hypot(a[0] - b[0], a[1] - b[1]), k: shown.current.k };
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
      moved.current += 10;
      go((cur) => zoomAbout(cur, (a[0] + b[0]) / 2 - r.left, (a[1] + b[1]) / 2 - r.top, k / cur.k), 'jump');
      return;
    }
    const dx = e.clientX - prev[0];
    const dy = e.clientY - prev[1];
    moved.current += Math.abs(dx) + Math.abs(dy);
    if (dx || dy) go((cur) => ({ ...cur, x: cur.x + dx, y: cur.y + dy }), 'jump');
  };
  const onPointerUp = (e: ReactPointerEvent<SVGSVGElement>) => {
    pointers.current.delete(e.pointerId);
    if (pointers.current.size < 2) pinch.current = null;
  };
  const onCanvasKey = (e: ReactKeyboardEvent) => {
    if (e.target !== e.currentTarget) return;
    const step = 80;
    const k = e.key;
    if (k === '+' || k === '=') zoomAt(1.25);
    else if (k === '-') zoomAt(0.8);
    else if (k === '0') go(fit, 'glide');
    else if (k.startsWith('Arrow'))
      go((c) => ({ ...c, x: c.x + (k === 'ArrowLeft' ? step : k === 'ArrowRight' ? -step : 0), y: c.y + (k === 'ArrowUp' ? step : k === 'ArrowDown' ? -step : 0) }), 'glide');
    else return;
    e.preventDefault();
  };

  const kinds = useMemo(() => KIND_ORDER.filter((k) => (map.counts[k] ?? 0) > 0), [map]);
  const q = query.trim().toLowerCase();
  const matches = (n: MapNode) =>
    !q || [n.label, n.ip ?? '', n.vendor ?? '', KIND_LABEL[n.kind], ...n.names].some((x) => x.toLowerCase().includes(q));
  const visible = (n: MapNode) => n.segment === 'core' || hidden.indexOf(n.kind) < 0;
  const sel = map.nodes.find((n) => n.id === selected);
  const selPath = useMemo(() => (sel ? pathToNode(map, sel) : []), [map, sel]);

  const pick = useCallback((n: MapNode) => setSelected((s) => (s === n.id ? null : n.id)), []);
  // Con il tasto Tab la camera porta in vista il dispositivo raggiunto, se è fuori dallo schermo.
  const onFocusNode = useCallback(
    (n: MapNode, el: Element) => {
      let kb = true;
      try {
        kb = el.matches(':focus-visible');
      } catch {
        kb = true;
      }
      if (!kb) return;
      const sn = sceneRef.current.nodes.find((s) => s.n.id === n.id);
      if (!sn) return;
      const { w, h } = sizeRef.current;
      const [sx, sy] = toScreen(targetRef.current, sn.p);
      if (sx > 60 && sx < w - 60 && sy > 60 && sy < h - 60) return;
      go((cur) => ({ ...cur, x: w / 2 - sn.p[0] * cur.k, y: h / 2.2 - sn.p[1] * cur.k }), 'glide');
    },
    [go],
  );

  // Scelto un dispositivo, la camera inquadra il percorso da questo PC fino a lui, accanto al pannello.
  useEffect(() => {
    if (!sel) return;
    const ids = selPath.length > 1 ? selPath : [sel.id];
    const narrow = typeof window !== 'undefined' && !!window.matchMedia?.('(max-width: 760px)').matches;
    const { w, h } = sizeRef.current;
    go(frameRoute(map, scene, ids, visibleArea(w, h, narrow ? 'bottom' : 'right'), 1.15, 0.5), 'glide');
    // Solo quando cambia la scelta (non a ogni ridisegno): dopo, l'utente sposta e ingrandisce come vuole.
  }, [selected]);

  // ------------------------------------------------ geometria proiettata
  const byId = useMemo(() => new Map(map.nodes.map((n) => [n.id, n])), [map]);
  const segById = useMemo(() => new Map(map.segments.map((s) => [s.id, s])), [map]);

  const wires = useMemo(() => {
    const out: Wire[] = [];
    const w0 = enter.wires;
    const bb = map.backbone;
    if (bb && map.segments.length) {
      const pts = projectPath([[bb.x, bb.y1], [bb.x, bb.y2]]);
      out.push({ key: 'bb', d: pathD(pts), cls: 'nm-link nm-backbone', delay: w0, draw: pathD(pts) });
    }
    for (const s of map.segments) {
      const pts = projectPath(zoneExit(map, s));
      out.push({ key: `stub-${s.id}`, d: pathD(pts), cls: `nm-link ${s.kind === 'remote' ? 'nm-routed' : s.kind === 'wifi' ? 'nm-wifi' : 'nm-backbone'}`, delay: w0 + 90, draw: pathD(pts.slice().reverse()) });
    }
    for (const l of map.links) {
      if (l.kind === 'lan' || segById.has(l.from)) continue;
      const a = byId.get(l.from);
      const b = byId.get(l.to);
      if (!a || !b) continue;
      const style = l.sev && l.sev !== 'ok' ? { stroke: SEV_COLOR[l.sev] } : undefined;
      const cls = `nm-link nm-${l.kind}${l.inferred ? ' inferred' : ''}`;
      if (a.segment === b.segment && a.segment !== 'core') {
        // Collegamento senza fili nella stessa zona: un arco che passa nell'aria.
        const pa = project(a.x, a.y);
        const pb = project(b.x, b.y);
        const c: Pt = [(pa[0] + pb[0]) / 2, (pa[1] + pb[1]) / 2 - 76];
        const d = `M${pa[0].toFixed(1)} ${pa[1].toFixed(1)} Q${c[0].toFixed(1)} ${c[1].toFixed(1)} ${pb[0].toFixed(1)} ${pb[1].toFixed(1)}`;
        out.push({ key: l.id, d, cls, style, delay: w0 + 160, draw: d });
      } else if (a.segment !== 'core' && b.segment === 'core' && l.inferred) continue;
      else {
        const pts = projectPath(routePoints(map, [a.id, b.id]));
        if (pts.length > 1) out.push({ key: l.id, d: pathD(pts), cls, style, delay: w0 + 160, draw: pathD(pts) });
      }
    }
    return out;
  }, [map, byId, segById, enter]);

  const linkLabels = useMemo(() => {
    const obstacles = [...scene.nodes.flatMap((s) => s.parts), ...scene.zones.map((z) => z.label.rect)];
    return map.links
      .filter((l) => l.label && l.kind !== 'lan' && !segById.has(l.from))
      .map((l) => {
        const a = byId.get(l.from);
        const b = byId.get(l.to);
        if (!a || !b) return null;
        if (a.segment === b.segment && a.segment !== 'core') {
          const pa = project(a.x, a.y);
          const pb = project(b.x, b.y);
          return { id: l.id, text: l.label!, p: [(pa[0] + pb[0]) / 2 + 6, (pa[1] + pb[1]) / 2 - 42] as Pt, anchor: 'start' as const };
        }
        const pts = projectPath(routePoints(map, [a.id, b.id]));
        if (pts.length < 2) return null;
        const at = placeLinkLabel(pts, l.label!, obstacles);
        return { id: l.id, text: l.label!, p: [at.x, at.y] as Pt, anchor: at.anchor };
      })
      .filter((x): x is { id: string; text: string; p: Pt; anchor: 'start' | 'end' } => !!x);
  }, [map, byId, segById, scene]);

  const flows = map.flows;
  const flowGeo = useMemo(() => {
    const geo = (id: string, path: string[], color: string, active: boolean, blocked: boolean, speed: number, tag: string): FlowGeo | null => {
      const full = projectPath(routePoints(map, path));
      if (full.length < 2) return null;
      const pts = blocked ? truncate(full, 0.82) : full;
      const dest = byId.get(path[path.length - 1]);
      const info = dest ? `→ ${dest.kind === 'internet' ? 'Internet' : (dest.ip ?? dest.label)}` : '';
      return {
        id,
        pts,
        req: active ? offsetPolyline(pts, LANE) : [],
        res: active && !blocked ? offsetPolyline(pts.slice().reverse(), LANE) : [],
        color,
        active,
        blocked,
        dur: clamp(polyLength(pts) / speed, 1.6, 9),
        tag,
        info: tag === 'DNS QUERY' && dest?.ip ? `A? → ${dest.ip}` : info,
      };
    };
    if (sel) return selPath.length > 1 ? [geo('sel', selPath, 'var(--c-https)', true, false, 240, 'PERCORSO')].filter((g): g is FlowGeo => !!g) : [];
    return flows
      .filter((f) => f.id === activeFlow || f.kind === 'internet')
      .map((f) => {
        const blocked = f.kind === 'blocked' && f.sev === 'ok';
        return geo(f.id, f.path, flowColor(f), f.id === activeFlow, blocked, f.rttMs ? clamp(300 - f.rttMs * 3, 110, 300) : 240, flowTag(f));
      })
      .filter((g): g is FlowGeo => !!g)
      .sort((a, b) => Number(a.active) - Number(b.active));
  }, [map, byId, flows, activeFlow, sel, selPath]);

  const drawMask = `${uid}-draw`;
  const flowDelay = enter.flows;
  const shownNodes = scene.nodes.filter((s) => visible(s.n));
  const counts = scene.zones.length;

  if (!map.nodes.length) return <p className="muted">Nessun dato di rete da disegnare.</p>;

  const b = scene.bounds;
  return (
    <div className={`netmap console${compact ? ' compact' : ''}`}>
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
          <button className="btn small icon" onClick={() => go(fit, 'glide')} aria-label="Mostra tutta la mappa" title="Mostra tutto (0)">
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
                <Icon size={14} color={consoleColor(k)} aria-hidden /> {KIND_PLURAL[k]} <b>{map.counts[k]}</b>
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
            aria-label={`Mappa della rete: ${map.nodes.length} elementi in ${counts} ${counts === 1 ? 'zona' : 'zone'}. Usa Tab per scegliere un dispositivo; + e − per lo zoom, 0 per adattare, frecce per spostarti.`}
            tabIndex={0}
            onKeyDown={onCanvasKey}
            onPointerDown={onPointerDown}
            onPointerMove={onPointerMove}
            onPointerUp={onPointerUp}
            onPointerCancel={onPointerUp}
            onClick={() => {
              if (moved.current < 6) setSelected(null);
            }}
          >
            <defs>
              {entering && (
                <mask id={drawMask} maskUnits="userSpaceOnUse" x={b.x0 - 400} y={b.y0 - 400} width={b.x1 - b.x0 + 800} height={b.y1 - b.y0 + 800}>
                  {wires.map((w) => (
                    <path key={w.key} d={w.draw} pathLength={1} className="nm-draw" style={{ animationDelay: ms(w.delay) }} />
                  ))}
                  {shownNodes
                    .filter((s) => s.n.segment !== 'core')
                    .map((s) => {
                      const z = segById.get(s.n.segment);
                      return z ? <path key={`d-${s.n.id}`} d={pathD(projectPath(nodeDrop(z, s.n)))} pathLength={1} className="nm-draw" style={{ animationDelay: ms(enter.wires + 160) }} /> : null;
                    })}
                  {flowGeo.map((g) => (
                    <path key={`f-${g.id}`} d={pathD(g.pts)} pathLength={1} className="nm-draw wide" style={{ animationDelay: ms(flowDelay) }} />
                  ))}
                </mask>
              )}
            </defs>
            <g ref={camRef}>
              <g key={epoch.current.n} className={`nm-world${entering ? ' nm-enter' : ''}`} style={{ ['--pk' as string]: ms(enter.packets) }}>
                <g className="nm-zones">
                  {scene.zones.map((z) => (
                    <ZonePlate key={z.s.id} z={z} delay={enter.zone.get(z.s.id) ?? 0} />
                  ))}
                </g>
                <g className="nm-wires" mask={entering ? `url(#${drawMask})` : undefined}>
                  {/* Collegamenti dei dispositivi alla linea di raccolta della zona. */}
                  {shownNodes
                    .filter((s) => s.n.segment !== 'core')
                    .map((s) => {
                      const z = segById.get(s.n.segment);
                      return z ? <path key={`drop-${s.n.id}`} d={pathD(projectPath(nodeDrop(z, s.n)))} className="nm-drop" /> : null;
                    })}
                  {wires.map((w) => (
                    <path key={w.key} d={w.d} className={w.cls} style={w.style} />
                  ))}
                  {flowGeo.map((g) => (
                    <FlowLanes key={g.id} g={g} />
                  ))}
                </g>
                <g className="nm-nodes">
                  {shownNodes.map((s) => (
                    <NodeIso
                      key={s.n.id}
                      sn={s}
                      dim={!matches(s.n)}
                      selected={s.n.id === selected}
                      playing={live}
                      delay={enter.node.get(s.n.id) ?? 0}
                      onPick={pick}
                      onFocusNode={onFocusNode}
                    />
                  ))}
                </g>
                <g className="nm-pkts">
                  {linkLabels.map((l) => (
                    <text key={`lbl-${l.id}`} x={l.p[0].toFixed(1)} y={l.p[1].toFixed(1)} textAnchor={l.anchor} className="nm-link-label">
                      {l.text}
                    </text>
                  ))}
                  {flowGeo.map((g) => (
                    <FlowPackets key={g.id} g={g} playing={live} />
                  ))}
                </g>
              </g>
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
              <i className="nm-flow-dot" style={{ background: flowColor(f) }} aria-hidden />
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
        <span className="nm-panel-icon" style={{ color: consoleColor(n.kind) }}>
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
          <svg width="40" height="14" aria-hidden className="nm-legend-lanes">
            <line x1="2" x2="38" y1="4" y2="4" className="nm-lane" />
            <line x1="2" x2="38" y1="10" y2="10" className="nm-lane res" />
            <polygon points="27,1 33,4 27,7" className="nm-arrow" />
            <polygon points="13,7 7,10 13,13" className="nm-arrow res" />
          </svg>{' '}
          percorso scelto: corsia di andata (richiesta, con l'etichetta del protocollo) e di ritorno (risposta)
        </li>
        <li>
          <span className="nm-legend-dot" style={{ background: 'var(--accent)' }} /> pacchetti del percorso scelto ·{' '}
          <span className="nm-legend-dot" style={{ background: 'var(--p2)' }} /> percorso bloccato come previsto ·{' '}
          <span className="nm-legend-dot" style={{ background: 'var(--crit)' }} /> problema
        </li>
        <li>
          <span className="nm-legend-q">?</span> tipo riconosciuto con pochi indizi: da verificare · ellisse tratteggiata a terra: dispositivo dedotto · etichetta sul pacchetto: il protocollo (HTTPS, DNS, TCP con la porta, PING) e la destinazione
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
