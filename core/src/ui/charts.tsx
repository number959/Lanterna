import { AnimatePresence, animate, m, useMotionValue, useReducedMotion, useSpring } from 'motion/react';
import { useEffect, useId, useState } from 'react';
import type { PointerEvent } from 'react';
import { channelToFreq, spectrum } from '../engine';
import type { Band, Bss, ChannelAdvice } from '../engine';
import { ease, spring } from './motion';
import { useWidth } from './hooks';

// Grafici SVG disegnati alla larghezza reale del contenitore (1 unità = 1 px)
// e animati con Motion: le linee si tracciano, le barre crescono, il monitor
// scorre in modo continuo.

// Colori delle reti: variabili CSS diverse per tema scuro e chiaro (vedi --p0…--p9).
const PALETTE = Array.from({ length: 10 }, (_, i) => `var(--p${i})`);

const RANGE: Record<Band, { lo: number; hi: number; ticks: number[] }> = {
  '2.4': { lo: 2400, hi: 2484, ticks: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13] },
  '5': { lo: 5160, hi: 5840, ticks: [36, 44, 52, 60, 100, 108, 116, 124, 132, 140, 149, 157, 165] },
  '6': { lo: 5925, hi: 7125, ticks: [1, 33, 65, 97, 129, 161, 193, 225] },
};

const RSSI_TOP = -30;
const RSSI_BOTTOM = -95;

/**
 * Curva monotona (Fritsch-Carlson): passa per tutti i punti senza creare
 * picchi o avvallamenti che i dati non hanno.
 */
export function smoothPath(pts: [number, number][]): string {
  const n = pts.length;
  if (n === 0) return '';
  if (n === 1) return `M${pts[0][0]},${pts[0][1]}`;
  if (n === 2) return `M${pts[0][0]},${pts[0][1]}L${pts[1][0]},${pts[1][1]}`;
  const dx: number[] = [];
  const slope: number[] = [];
  for (let i = 0; i < n - 1; i++) {
    dx[i] = pts[i + 1][0] - pts[i][0];
    slope[i] = dx[i] ? (pts[i + 1][1] - pts[i][1]) / dx[i] : 0;
  }
  const t: number[] = [slope[0]];
  for (let i = 1; i < n - 1; i++) {
    if (slope[i - 1] * slope[i] <= 0) t[i] = 0;
    else {
      const w1 = 2 * dx[i] + dx[i - 1];
      const w2 = dx[i] + 2 * dx[i - 1];
      t[i] = (w1 + w2) / (w1 / slope[i - 1] + w2 / slope[i]);
    }
  }
  t[n - 1] = slope[n - 2];
  let d = `M${pts[0][0].toFixed(1)},${pts[0][1].toFixed(1)}`;
  for (let i = 0; i < n - 1; i++) {
    const [x0, y0] = pts[i];
    const [x1, y1] = pts[i + 1];
    const h = dx[i] / 3;
    d += `C${(x0 + h).toFixed(1)},${(y0 + t[i] * h).toFixed(1)} ${(x1 - h).toFixed(1)},${(y1 - t[i + 1] * h).toFixed(1)} ${x1.toFixed(1)},${y1.toFixed(1)}`;
  }
  return d;
}

/** Spezza una serie in tratti continui (null = pacchetto perso). */
function segments(samples: (number | null)[], x: (i: number) => number, y: (v: number) => number) {
  const out: [number, number][][] = [];
  let cur: [number, number][] = [];
  samples.forEach((v, i) => {
    if (v === null) {
      if (cur.length) out.push(cur);
      cur = [];
    } else cur.push([x(i), y(v)]);
  });
  if (cur.length) out.push(cur);
  return out;
}

let measureCtx: CanvasRenderingContext2D | null | undefined;
/** Larghezza reale di un'etichetta nel font dell'interfaccia (per le targhette e le collisioni). */
function labelWidth(text: string, weight: number) {
  if (measureCtx === undefined) measureCtx = document.createElement('canvas').getContext('2d');
  if (!measureCtx) return text.length * 6.4;
  measureCtx.font = `${weight} 11px 'Inter Variable', system-ui, sans-serif`;
  return measureCtx.measureText(text).width;
}

/** Tooltip che segue il puntatore con un leggero ritardo fisico. */
function useFollow() {
  const x = useSpring(0, { stiffness: 520, damping: 42, mass: 0.6 });
  const y = useSpring(0, { stiffness: 520, damping: 42, mass: 0.6 });
  return { x, y };
}

interface Tip {
  lines: string[];
}

export function SpectrumChart({ networks, band, mySsid }: { networks: Bss[]; band: Band; mySsid?: string }) {
  const [ref, w] = useWidth<HTMLDivElement>();
  const [tip, setTip] = useState<Tip | null>(null);
  const [hover, setHover] = useState<string | null>(null);
  const follow = useFollow();
  const reduce = useReducedMotion();
  const gid = useId();
  // Dopo l'entrata le etichette reagiscono al passaggio del puntatore senza ritardo.
  const [entered, setEntered] = useState(false);
  useEffect(() => {
    const t = setTimeout(() => setEntered(true), 1200);
    return () => clearTimeout(t);
  }, []);
  const h = 290;
  const pad = { l: 44, r: 14, t: 26, b: 32 };
  const r = RANGE[band];
  const nets = networks.filter((b) => b.band === band).sort((a, b) => a.rssiDbm - b.rssiDbm);
  const x = (f: number) => pad.l + ((f - r.lo) / (r.hi - r.lo)) * (w - pad.l - pad.r);
  const y = (rssi: number) => pad.t + ((RSSI_TOP - Math.max(RSSI_BOTTOM, Math.min(RSSI_TOP, rssi))) / (RSSI_TOP - RSSI_BOTTOM)) * (h - pad.t - pad.b);
  const base = h - pad.b;
  const colorOf = new Map<string, string>();
  let ci = 0;
  for (const n of [...nets].sort((a, b) => a.ssid.localeCompare(b.ssid))) {
    colorOf.set(n.bssid, n.ssid === mySsid ? 'var(--accent)' : PALETTE[ci++ % PALETTE.length]);
  }
  // Etichette: dalla rete più forte alla più debole, ciascuna nella prima
  // posizione libera sopra il proprio picco; se non c'è spazio si omette
  // (il nome resta nel tooltip e nella tabella).
  const labels = new Map<string, { x: number; y: number; w: number }>();
  if (w > 0) {
    const boxes: { x0: number; x1: number; y: number }[] = [];
    const order = [...nets].sort((a, b) => (b.ssid === mySsid ? 1 : 0) - (a.ssid === mySsid ? 1 : 0) || b.rssiDbm - a.rssiDbm);
    for (const n of order) {
      if (labels.size >= 8) break;
      const [lo, hi] = spectrum(n);
      const cx = (x(lo) + x(hi)) / 2;
      const tw = labelWidth((n.ssid || '(nascosta)').slice(0, 18), n.ssid === mySsid ? 700 : 500) + 10;
      for (let k = 0; k < 4; k++) {
        const ly = y(n.rssiDbm) - 7 - k * 13;
        if (ly < pad.t - 6) break;
        const box = { x0: cx - tw / 2, x1: cx + tw / 2, y: ly };
        if (!boxes.some((b) => b.x0 < box.x1 && box.x0 < b.x1 && Math.abs(b.y - box.y) < 12)) {
          boxes.push(box);
          labels.set(n.bssid, { x: cx, y: ly, w: tw });
          break;
        }
      }
    }
  }
  const move = (e: PointerEvent<SVGGElement>, n: Bss) => {
    const box = (e.currentTarget.ownerSVGElement as SVGSVGElement).getBoundingClientRect();
    const tx = Math.max(0, Math.min(e.clientX - box.left + 14, w - 240));
    const ty = Math.max(0, e.clientY - box.top - 76);
    // Alla prima comparsa il tooltip nasce sotto il puntatore; poi lo insegue con la molla.
    if (tip) {
      follow.x.set(tx);
      follow.y.set(ty);
    } else {
      follow.x.jump(tx);
      follow.y.jump(ty);
    }
    if (hover !== n.bssid) {
      setHover(n.bssid);
      setTip({
        lines: [
          `${n.ssid || '(rete nascosta)'}${n.ssid === mySsid ? ' · la tua rete' : ''}`,
          `canale ${n.channel} · ${n.widthMhz} MHz · ${n.rssiDbm} dBm`,
          `${n.phy ?? ''}${n.security ? ' · ' + n.security.protocol.toUpperCase() : ''}`.trim(),
        ],
      });
    }
  };
  return (
    <div ref={ref} className="chart-wrap" onPointerLeave={() => { setTip(null); setHover(null); }}>
      {w > 0 && (
        <svg className="chart" width={w} height={h} viewBox={`0 0 ${w} ${h}`} role="img" aria-label={`Spettro ${band} GHz: ${nets.length} reti`}>
          <defs>
            <clipPath id={`${gid}-clip`}>
              <rect x={pad.l} y={0} width={Math.max(0, w - pad.l - pad.r)} height={base} />
            </clipPath>
          </defs>
          {[-40, -50, -60, -70, -80, -90].map((d) => (
            <g key={d}>
              <line className="grid-line" x1={pad.l} x2={w - pad.r} y1={y(d)} y2={y(d)} strokeDasharray="2 5" />
              <text x={pad.l - 8} y={y(d) + 4} textAnchor="end">{d}</text>
            </g>
          ))}
          <line x1={pad.l} x2={w - pad.r} y1={y(-67)} y2={y(-67)} stroke="var(--ok)" strokeOpacity="0.55" strokeDasharray="6 5" />
          <text x={w - pad.r} y={y(-67) - 6} textAnchor="end" style={{ fill: 'var(--ok)' }}>-67 dBm: soglia "buono"</text>
          <text x={8} y={pad.t - 10}>dBm</text>
          {r.ticks.map((ch) => (
            <text key={ch} x={x(channelToFreq(ch, band))} y={h - 10} textAnchor="middle">{ch}</text>
          ))}
          <g clipPath={`url(#${gid}-clip)`}>
            {nets.map((n, i) => {
              const [lo, hi] = spectrum(n);
              const x0 = x(lo);
              const x1 = x(hi);
              const yt = y(n.rssiDbm);
              const k = (x1 - x0) * 0.18;
              const d = `M${x0},${base} C${x0 + k * 0.6},${base} ${x0 + k * 0.4},${yt} ${x0 + k},${yt} L${x1 - k},${yt} C${x1 - k * 0.4},${yt} ${x1 - k * 0.6},${base} ${x1},${base}`;
              const col = colorOf.get(n.bssid)!;
              const mine = n.ssid === mySsid;
              const dim = hover !== null && hover !== n.bssid;
              return (
                <m.g
                  key={n.bssid}
                  animate={{ opacity: dim ? 0.18 : 1 }}
                  transition={spring.smooth}
                  onPointerMove={(e) => move(e, n)}
                  style={{ cursor: 'crosshair' }}
                >
                  <m.path
                    d={`${d} Z`}
                    fill={col}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: mine ? 0.24 : 0.1 }}
                    transition={{ duration: 0.8, delay: reduce ? 0 : 0.3 + i * 0.035 }}
                  />
                  <m.path
                    d={d}
                    fill="none"
                    stroke={col}
                    strokeWidth={mine ? 3 : 1.8}
                    strokeLinejoin="round"
                    initial={{ pathLength: reduce ? 1 : 0 }}
                    animate={{ pathLength: 1 }}
                    transition={{ duration: 1.1, ease: ease.out, delay: i * 0.035 }}
                  />
                </m.g>
              );
            })}
          </g>
          {/* Etichette disegnate per ultime, sopra tutte le curve. */}
          <g pointerEvents="none">
            {nets.map((n, i) => {
              const pos = labels.get(n.bssid);
              if (!pos) return null;
              const mine = n.ssid === mySsid;
              const dim = hover !== null && hover !== n.bssid;
              return (
                <m.g
                  key={n.bssid}
                  // Per gli elementi SVG "y" di Motion è una traslazione, non l'attributo:
                  // l'etichetta parte 6 px più in basso e sale al suo posto.
                  initial={{ opacity: 0, y: 6 }}
                  animate={{ opacity: dim ? 0.2 : 1, y: 0 }}
                  transition={{ ...spring.smooth, delay: entered ? 0 : 0.5 + i * 0.03 }}
                >
                  {/* Targhetta del colore di fondo: il nome resta leggibile sopra le curve. */}
                  <rect x={pos.x - pos.w / 2} y={pos.y - 10.5} width={pos.w} height={14} rx={4} fill="var(--surface)" fillOpacity={0.88} />
                  <text x={pos.x} y={pos.y} textAnchor="middle" style={{ fill: colorOf.get(n.bssid), fontWeight: mine ? 700 : 500 }}>
                    {(n.ssid || '(nascosta)').slice(0, 18)}
                  </text>
                </m.g>
              );
            })}
          </g>
          {!nets.length && (
            <text x={w / 2} y={h / 2} textAnchor="middle">Nessuna rete rilevata in questa banda</text>
          )}
        </svg>
      )}
      <AnimatePresence>
        {tip && (
          <m.div
            className="tooltip"
            style={{ x: follow.x, y: follow.y }}
            initial={{ opacity: 0, scale: 0.94 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.96, transition: { duration: 0.12 } }}
            transition={spring.snappy}
          >
            {tip.lines.map((l, i) => (
              <div key={i} style={i === 0 ? { fontWeight: 650 } : { color: 'var(--text-2)' }}>{l}</div>
            ))}
          </m.div>
        )}
      </AnimatePresence>
    </div>
  );
}

export function ChannelLoad({ advice }: { advice: ChannelAdvice }) {
  const [ref, w] = useWidth<HTMLDivElement>();
  const reduce = useReducedMotion();
  const h = 180;
  const pad = { l: 8, r: 8, t: 24, b: 36 };
  const n = advice.scores.length;
  if (!n) return null;
  const bw = (w - pad.l - pad.r) / n;
  const y = (v: number) => pad.t + (1 - v / 100) * (h - pad.t - pad.b);
  const isCur = (s: { channel: number }) =>
    advice.current !== undefined && (advice.band === '2.4' ? s.channel === advice.current : advice.current >= s.channel && advice.current <= s.channel + 12);
  return (
    <div ref={ref}>
      {w > 0 && (
        <svg className="chart" width={w} height={h} viewBox={`0 0 ${w} ${h}`} role="img" aria-label={`Interferenza stimata per canale, banda ${advice.band} GHz`}>
          {advice.scores.map((s, i) => {
            const rec = s.channel === advice.recommended;
            const cur = isCur(s);
            const fill = rec ? 'var(--ok)' : s.load > 66 ? 'var(--crit)' : s.load > 33 ? 'var(--warn)' : 'var(--info)';
            const top = y(Math.max(s.load, 2));
            const cx = pad.l + i * bw + bw / 2;
            return (
              <g key={s.label}>
                <m.rect
                  x={pad.l + i * bw + bw * 0.16}
                  y={top}
                  width={bw * 0.68}
                  height={h - pad.b - top}
                  rx={5}
                  fill={fill}
                  fillOpacity={rec ? 0.9 : 0.5}
                  stroke={cur ? 'var(--accent)' : 'none'}
                  strokeWidth={cur ? 2.5 : 0}
                  style={{ originY: 1, transformBox: 'fill-box' }}
                  initial={{ scaleY: reduce ? 1 : 0 }}
                  animate={{ scaleY: 1 }}
                  transition={{ ...spring.smooth, delay: reduce ? 0 : 0.1 + i * 0.035 }}
                >
                  <title>{`Canale ${s.label}: interferenza ${s.load}/100, ${s.networks} reti${s.dfs ? ' (DFS)' : ''}`}</title>
                </m.rect>
                <m.text
                  x={cx}
                  y={top - 7}
                  textAnchor="middle"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: reduce ? 0 : 0.35 + i * 0.035 }}
                >
                  {s.load}
                </m.text>
                <text x={cx} y={h - pad.b + 16} textAnchor="middle" style={rec ? { fill: 'var(--ok)', fontWeight: 700 } : cur ? { fill: 'var(--accent-text)', fontWeight: 700 } : undefined}>
                  {s.label}
                </text>
                {(rec || cur) && (
                  <text x={cx} y={h - 4} textAnchor="middle" style={{ fill: rec ? 'var(--ok)' : 'var(--accent-text)', fontSize: 10, fontWeight: 600 }}>
                    {rec && cur ? 'attuale ✓' : rec ? 'consigliato' : 'attuale'}
                  </text>
                )}
              </g>
            );
          })}
        </svg>
      )}
    </div>
  );
}

const niceCeil = (v: number) => [5, 10, 20, 30, 50, 80, 100, 150, 200, 300, 500, 800, 1000, 2000, 5000].find((s) => s >= v) ?? Math.ceil(v / 1000) * 1000;

type Series = { label: string; color: string; samples: (number | null)[] };

/** Serie di latenze di un'analisi; `null` = pacchetto perso (segnato sull'asse). */
export function LatencyChart({ series, height = 170 }: { series: Series[]; height?: number }) {
  const [ref, w] = useWidth<HTMLDivElement>();
  const reduce = useReducedMotion();
  const gid = useId();
  const h = height;
  const pad = { l: 40, r: 10, t: 12, b: 22 };
  const n = Math.max(2, ...series.map((s) => s.samples.length));
  const max = niceCeil(Math.max(5, ...series.flatMap((s) => s.samples.filter((v): v is number => v !== null))) * 1.1);
  const x = (i: number) => pad.l + (i / Math.max(1, n - 1)) * (w - pad.l - pad.r);
  const y = (v: number) => pad.t + (1 - v / max) * (h - pad.t - pad.b);
  return (
    <div ref={ref}>
      {w > 0 && (
        <svg className="chart" width={w} height={h} viewBox={`0 0 ${w} ${h}`} role="img" aria-label={`Latenza: ${series.map((s) => s.label).join(', ')}`}>
          <defs>
            {series.map((s, si) => (
              <linearGradient key={si} id={`${gid}-a${si}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0" stopColor={s.color} stopOpacity={series.length > 1 ? 0.12 : 0.28} />
                <stop offset="1" stopColor={s.color} stopOpacity="0" />
              </linearGradient>
            ))}
          </defs>
          {[0, max / 2, max].map((t) => (
            <g key={t}>
              <line className="grid-line" x1={pad.l} x2={w - pad.r} y1={y(t)} y2={y(t)} strokeDasharray="2 5" />
              <text x={pad.l - 7} y={y(t) + 4} textAnchor="end">{Math.round(t)}</text>
            </g>
          ))}
          <text x={pad.l - 7} y={h - 4} textAnchor="end">ms</text>
          {series.map((s, si) =>
            segments(s.samples, x, y).map((seg, k) => {
              const d = smoothPath(seg);
              const area = seg.length > 1 ? `${d}L${seg[seg.length - 1][0]},${h - pad.b}L${seg[0][0]},${h - pad.b}Z` : '';
              return (
                <g key={`${si}-${k}`}>
                  {area && (
                    <m.path d={area} fill={`url(#${gid}-a${si})`} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.9, delay: reduce ? 0 : 0.5 + si * 0.1 }} />
                  )}
                  <m.path
                    d={d}
                    fill="none"
                    stroke={s.color}
                    strokeWidth={2}
                    strokeLinejoin="round"
                    strokeLinecap="round"
                    initial={{ pathLength: reduce ? 1 : 0 }}
                    animate={{ pathLength: 1 }}
                    transition={{ duration: 1.2, ease: ease.out, delay: si * 0.12 }}
                  />
                </g>
              );
            }),
          )}
          {series.map((s, si) =>
            s.samples.map((v, i) =>
              v === null ? (
                <m.circle key={`${si}-${i}`} cx={x(i)} cy={h - pad.b} r={3.5} fill="var(--crit)" initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ ...spring.snappy, delay: reduce ? 0 : 0.8 }}>
                  <title>pacchetto perso</title>
                </m.circle>
              ) : null,
            ),
          )}
        </svg>
      )}
    </div>
  );
}

/**
 * Grafico del monitor: i campioni entrano da destra e tutto scorre verso
 * sinistra in modo continuo (lo spostamento di un passo dura quanto
 * l'intervallo tra due misure), invece di avanzare a scatti.
 */
export function LiveChart({ series, tick, maxPoints = 60, height = 230, intervalMs = 1000 }: { series: Series[]; tick: number; maxPoints?: number; height?: number; intervalMs?: number }) {
  const [ref, w] = useWidth<HTMLDivElement>();
  const reduce = useReducedMotion();
  const gid = useId();
  const offset = useMotionValue(0);
  const h = height;
  const pad = { l: 40, r: 12, t: 12, b: 22 };
  const step = (w - pad.l - pad.r) / Math.max(1, maxPoints - 1);
  const all = series.flatMap((s) => s.samples.filter((v): v is number => v !== null));
  const max = niceCeil(Math.max(10, ...all) * 1.15);
  const len = Math.max(0, ...series.map((s) => s.samples.length));
  const off = maxPoints - len;
  const x = (i: number) => pad.l + (i + off) * step;
  const y = (v: number) => pad.t + (1 - v / max) * (h - pad.t - pad.b);

  useEffect(() => {
    if (reduce || !step || tick === 0) {
      offset.set(0);
      return;
    }
    offset.set(step);
    const c = animate(offset, 0, { duration: (intervalMs * 0.98) / 1000, ease: 'linear' });
    return () => c.stop();
  }, [tick, step, reduce, intervalMs, offset]);

  return (
    <div ref={ref}>
      {w > 0 && (
        <svg className="chart" width={w} height={h} viewBox={`0 0 ${w} ${h}`} role="img" aria-label={`Latenza in tempo reale: ${series.map((s) => s.label).join(', ')}`}>
          <defs>
            <clipPath id={`${gid}-clip`}>
              <rect x={pad.l} y={0} width={Math.max(0, w - pad.l - pad.r)} height={h} />
            </clipPath>
            {series.map((s, si) => (
              <linearGradient key={si} id={`${gid}-a${si}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0" stopColor={s.color} stopOpacity="0.22" />
                <stop offset="1" stopColor={s.color} stopOpacity="0" />
              </linearGradient>
            ))}
          </defs>
          {[0, max / 2, max].map((t) => (
            <g key={t}>
              <line className="grid-line" x1={pad.l} x2={w - pad.r} y1={y(t)} y2={y(t)} strokeDasharray="2 5" />
              <text x={pad.l - 7} y={y(t) + 4} textAnchor="end">{Math.round(t)}</text>
            </g>
          ))}
          <text x={pad.l - 7} y={h - 4} textAnchor="end">ms</text>
          <g clipPath={`url(#${gid}-clip)`}>
            <m.g style={{ x: offset }}>
              {series.map((s, si) => {
                const segs = segments(s.samples, x, y);
                return (
                  <g key={s.label}>
                    {segs.map((seg, k) => {
                      const d = smoothPath(seg);
                      const area = seg.length > 1 ? `${d}L${seg[seg.length - 1][0]},${h - pad.b}L${seg[0][0]},${h - pad.b}Z` : '';
                      return (
                        <g key={k}>
                          {area && <path d={area} fill={`url(#${gid}-a${si})`} />}
                          <path d={d} fill="none" stroke={s.color} strokeWidth={2.2} strokeLinejoin="round" strokeLinecap="round" />
                        </g>
                      );
                    })}
                    {s.samples.map((v, i) =>
                      v === null ? <rect key={i} x={x(i) - 1.5} y={h - pad.b - 10} width={3} height={10} rx={1.5} fill="var(--crit)" /> : null,
                    )}
                    {(() => {
                      const last = s.samples[s.samples.length - 1];
                      if (last === null || last === undefined) return null;
                      const cx = x(s.samples.length - 1);
                      const cy = y(last);
                      return (
                        <g>
                          <circle cx={cx} cy={cy} r={9} fill={s.color} opacity={0.18} />
                          <circle cx={cx} cy={cy} r={4} fill={s.color} stroke="var(--surface)" strokeWidth={2} />
                        </g>
                      );
                    })()}
                  </g>
                );
              })}
            </m.g>
          </g>
        </svg>
      )}
    </div>
  );
}

export function HBars({ items, unit = 'ms' }: { items: { label: string; value: number | null; highlight?: boolean; note?: string }[]; unit?: string }) {
  const reduce = useReducedMotion();
  const max = Math.max(1, ...items.map((i) => i.value ?? 0));
  return (
    <div className="hops">
      {items.map((it, i) => (
        <div key={it.label} className="hop" style={{ gridTemplateColumns: 'minmax(0, 170px) 1fr 84px' }}>
          <span style={{ fontWeight: it.highlight ? 650 : 400, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={it.note}>
            {it.label}
          </span>
          <span className="bar" style={{ display: 'block' }}>
            {it.value !== null && (
              <m.i
                style={{ background: it.highlight ? 'linear-gradient(90deg, var(--accent-2), var(--accent))' : undefined }}
                initial={{ scaleX: reduce ? it.value / max : 0 }}
                animate={{ scaleX: it.value / max }}
                transition={{ ...spring.gentle, delay: reduce ? 0 : 0.15 + i * 0.06 }}
              />
            )}
          </span>
          <span className="mono" style={{ textAlign: 'right' }}>{it.value === null ? 'nessuna risp.' : `${Math.round(it.value)} ${unit}`}</span>
        </div>
      ))}
    </div>
  );
}
