import { useState } from 'react';
import { channelToFreq, spectrum } from '../engine';
import type { Band, Bss, ChannelAdvice } from '../engine';
import { useWidth } from './hooks';

// Grafici SVG disegnati alla larghezza reale del contenitore (1 unità = 1 px).

const PALETTE = ['#5aa9ff', '#3ddc97', '#c792ea', '#ff7eb6', '#4dd0e1', '#e6b84a', '#9ccc65', '#f78c6c', '#7986cb', '#4db6ac'];

const RANGE: Record<Band, { lo: number; hi: number; ticks: number[] }> = {
  '2.4': { lo: 2400, hi: 2484, ticks: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13] },
  '5': { lo: 5160, hi: 5840, ticks: [36, 44, 52, 60, 100, 108, 116, 124, 132, 140, 149, 157, 165] },
  '6': { lo: 5925, hi: 7125, ticks: [1, 33, 65, 97, 129, 161, 193, 225] },
};

const RSSI_TOP = -30;
const RSSI_BOTTOM = -95;

interface Tip {
  x: number;
  y: number;
  lines: string[];
}

export function SpectrumChart({ networks, band, mySsid }: { networks: Bss[]; band: Band; mySsid?: string }) {
  const [ref, w] = useWidth<HTMLDivElement>();
  const [tip, setTip] = useState<Tip | null>(null);
  const [hover, setHover] = useState<string | null>(null);
  const h = 280;
  const pad = { l: 44, r: 12, t: 22, b: 30 };
  const r = RANGE[band];
  const nets = networks.filter((b) => b.band === band).sort((a, b) => a.rssiDbm - b.rssiDbm);
  const x = (f: number) => pad.l + ((f - r.lo) / (r.hi - r.lo)) * (w - pad.l - pad.r);
  const y = (rssi: number) => pad.t + ((RSSI_TOP - Math.max(RSSI_BOTTOM, Math.min(RSSI_TOP, rssi))) / (RSSI_TOP - RSSI_BOTTOM)) * (h - pad.t - pad.b);
  const base = h - pad.b;
  const colorOf = new Map<string, string>();
  let ci = 0;
  for (const n of [...nets].sort((a, b) => a.ssid.localeCompare(b.ssid))) {
    if (n.ssid === mySsid) colorOf.set(n.bssid, 'var(--accent)');
    else colorOf.set(n.bssid, PALETTE[ci++ % PALETTE.length]);
  }
  // Etichette: dalla rete più forte alla più debole, ciascuna nella prima
  // posizione libera sopra il proprio picco; se non c'è spazio si omette
  // (il nome resta nel tooltip e nella tabella).
  const labels = new Map<string, { x: number; y: number }>();
  if (w > 0) {
    const boxes: { x0: number; x1: number; y: number }[] = [];
    const order = [...nets].sort((a, b) => (b.ssid === mySsid ? 1 : 0) - (a.ssid === mySsid ? 1 : 0) || b.rssiDbm - a.rssiDbm);
    for (const n of order) {
      if (labels.size >= 8) break;
      const [lo, hi] = spectrum(n);
      const cx = (x(lo) + x(hi)) / 2;
      const tw = Math.min(18, (n.ssid || '(nascosta)').length) * 6.4 + 6;
      for (let k = 0; k < 4; k++) {
        const ly = y(n.rssiDbm) - 6 - k * 13;
        if (ly < pad.t - 4) break;
        const box = { x0: cx - tw / 2, x1: cx + tw / 2, y: ly };
        if (!boxes.some((b) => b.x0 < box.x1 && box.x0 < b.x1 && Math.abs(b.y - box.y) < 12)) {
          boxes.push(box);
          labels.set(n.bssid, { x: cx, y: ly });
          break;
        }
      }
    }
  }

  return (
    <div ref={ref} style={{ position: 'relative' }} onMouseLeave={() => { setTip(null); setHover(null); }}>
      {w > 0 && (
        <svg className="chart" width={w} height={h} viewBox={`0 0 ${w} ${h}`} role="img" aria-label={`Spettro ${band} GHz: ${nets.length} reti`}>
          {[-40, -50, -60, -70, -80, -90].map((d) => (
            <g key={d}>
              <line className="grid-line" x1={pad.l} x2={w - pad.r} y1={y(d)} y2={y(d)} strokeDasharray={d === -67 ? '' : '2 4'} />
              <text x={pad.l - 6} y={y(d) + 4} textAnchor="end">{d}</text>
            </g>
          ))}
          <line x1={pad.l} x2={w - pad.r} y1={y(-67)} y2={y(-67)} stroke="var(--ok)" strokeOpacity="0.5" strokeDasharray="6 4" />
          <text x={w - pad.r} y={y(-67) - 5} textAnchor="end" style={{ fill: 'var(--ok)' }}>-67 dBm: soglia "buono"</text>
          <text x={8} y={pad.t - 8}>dBm</text>
          {r.ticks.map((ch) => (
            <text key={ch} x={x(channelToFreq(ch, band))} y={h - 10} textAnchor="middle">{ch}</text>
          ))}
          {nets.map((n, i) => {
            const [lo, hi] = spectrum(n);
            const x0 = x(lo);
            const x1 = x(hi);
            const yt = y(n.rssiDbm);
            const k = (x1 - x0) * 0.18;
            const d = `M${x0},${base} C${x0 + k * 0.6},${base} ${x0 + k * 0.4},${yt} ${x0 + k},${yt} L${x1 - k},${yt} C${x1 - k * 0.4},${yt} ${x1 - k * 0.6},${base} ${x1},${base}`;
            const col = colorOf.get(n.bssid)!;
            const mine = n.ssid === mySsid;
            const dim = hover && hover !== n.bssid;
            return (
              <g
                key={n.bssid}
                style={{ ['--i' as string]: i, opacity: dim ? 0.25 : 1, transition: 'opacity .2s' }}
                onMouseMove={(e) => {
                  const box = (e.currentTarget.ownerSVGElement as SVGSVGElement).getBoundingClientRect();
                  setHover(n.bssid);
                  setTip({
                    x: e.clientX - box.left,
                    y: e.clientY - box.top,
                    lines: [
                      `${n.ssid || '(rete nascosta)'}${mine ? ' · la tua' : ''}`,
                      `canale ${n.channel} · ${n.widthMhz} MHz · ${n.rssiDbm} dBm`,
                      `${n.phy ?? ''} ${n.security ? '· ' + n.security.protocol.toUpperCase() : ''}`.trim(),
                    ],
                  });
                }}
              >
                <path className="fade" d={`${d} Z`} fill={col} fillOpacity={mine ? 0.22 : 0.1} />
                <path className="draw" d={d} fill="none" stroke={col} strokeWidth={mine ? 3 : 1.8} pathLength={1} style={{ ['--len' as string]: 1 }} />
              </g>
            );
          })}
          {/* Etichette disegnate per ultime, sopra tutte le curve. */}
          <g pointerEvents="none">
            {nets.map((n, i) => {
              const pos = labels.get(n.bssid);
              if (!pos) return null;
              const mine = n.ssid === mySsid;
              return (
                <text
                  key={n.bssid}
                  className="fade"
                  x={pos.x}
                  y={pos.y}
                  textAnchor="middle"
                  // Contorno del colore di fondo: il nome resta leggibile sopra le curve.
                  style={{ ['--i' as string]: i, fill: colorOf.get(n.bssid), fontWeight: mine ? 700 : 500, opacity: hover && hover !== n.bssid ? 0.25 : 1, paintOrder: 'stroke', stroke: 'var(--surface)', strokeWidth: 3, strokeLinejoin: 'round' }}
                >
                  {(n.ssid || '(nascosta)').slice(0, 18)}
                </text>
              );
            })}
          </g>
          {!nets.length && (
            <text x={w / 2} y={h / 2} textAnchor="middle">Nessuna rete rilevata in questa banda</text>
          )}
        </svg>
      )}
      {tip && (
        <div className="tooltip" style={{ left: Math.min(tip.x + 12, w - 230), top: Math.max(0, tip.y - 70) }}>
          {tip.lines.map((l, i) => (
            <div key={i} style={i === 0 ? { fontWeight: 650 } : { color: 'var(--text-2)' }}>{l}</div>
          ))}
        </div>
      )}
    </div>
  );
}

export function ChannelLoad({ advice }: { advice: ChannelAdvice }) {
  const [ref, w] = useWidth<HTMLDivElement>();
  const h = 170;
  const pad = { l: 8, r: 8, t: 22, b: 34 };
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
            return (
              <g key={s.label} style={{ ['--i' as string]: i }}>
                <rect
                  className="fade"
                  x={pad.l + i * bw + bw * 0.15}
                  y={top}
                  width={bw * 0.7}
                  height={h - pad.b - top}
                  rx={4}
                  fill={fill}
                  fillOpacity={rec ? 0.9 : 0.55}
                  stroke={cur ? 'var(--accent)' : 'none'}
                  strokeWidth={cur ? 2.5 : 0}
                >
                  <title>{`Canale ${s.label}: interferenza ${s.load}/100, ${s.networks} reti${s.dfs ? ' (DFS)' : ''}`}</title>
                </rect>
                <text x={pad.l + i * bw + bw / 2} y={top - 6} textAnchor="middle">{s.load}</text>
                <text x={pad.l + i * bw + bw / 2} y={h - pad.b + 15} textAnchor="middle" style={rec ? { fill: 'var(--ok)', fontWeight: 700 } : cur ? { fill: 'var(--accent)', fontWeight: 700 } : undefined}>
                  {s.label}
                </text>
                {(rec || cur) && (
                  <text x={pad.l + i * bw + bw / 2} y={h - 4} textAnchor="middle" style={{ fill: rec ? 'var(--ok)' : 'var(--accent)', fontSize: 10 }}>
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

/** Serie di latenze; `null` = pacchetto perso (segnato in rosso sull'asse). */
export function LatencyChart({ series, height = 160, maxPoints, live }: { series: { label: string; color: string; samples: (number | null)[] }[]; height?: number; maxPoints?: number; live?: boolean }) {
  const [ref, w] = useWidth<HTMLDivElement>();
  const h = height;
  const pad = { l: 40, r: 10, t: 12, b: 22 };
  const n = maxPoints ?? Math.max(2, ...series.map((s) => s.samples.length));
  const all = series.flatMap((s) => s.samples.filter((v): v is number => v !== null));
  const max = Math.max(10, ...all) * 1.15;
  // In modalità live i campioni entrano da destra e scorrono verso sinistra.
  const len = Math.max(0, ...series.map((s) => s.samples.length));
  const off = live ? Math.max(0, n - len) : 0;
  const x = (i: number) => pad.l + ((i + off) / Math.max(1, n - 1)) * (w - pad.l - pad.r);
  const y = (v: number) => pad.t + (1 - v / max) * (h - pad.t - pad.b);
  const ticks = [0, max / 3, (2 * max) / 3].map((v) => Math.round(v));
  return (
    <div ref={ref}>
      {w > 0 && (
        <svg className="chart" width={w} height={h} viewBox={`0 0 ${w} ${h}`} role="img" aria-label={`Latenza: ${series.map((s) => s.label).join(', ')}`}>
          {ticks.map((t) => (
            <g key={t}>
              <line className="grid-line" x1={pad.l} x2={w - pad.r} y1={y(t)} y2={y(t)} strokeDasharray="2 4" />
              <text x={pad.l - 6} y={y(t) + 4} textAnchor="end">{t}</text>
            </g>
          ))}
          <text x={pad.l - 6} y={h - 6} textAnchor="end">ms</text>
          {series.map((s, si) => {
            const pts: string[] = [];
            let seg = '';
            s.samples.forEach((v, i) => {
              if (v === null) {
                if (seg) pts.push(seg);
                seg = '';
                return;
              }
              seg += `${seg ? 'L' : 'M'}${x(i).toFixed(1)},${y(v).toFixed(1)} `;
            });
            if (seg) pts.push(seg);
            return (
              <g key={s.label} style={{ ['--i' as string]: si }}>
                {pts.map((d, k) => (
                  <path key={k} className={live ? '' : 'draw'} d={d} fill="none" stroke={s.color} strokeWidth={2} strokeLinejoin="round" pathLength={live ? undefined : 1} style={live ? undefined : { ['--len' as string]: 1 }} />
                ))}
                {s.samples.map((v, i) =>
                  v === null ? <circle key={i} cx={x(i)} cy={h - pad.b} r={3.5} fill="var(--crit)"><title>pacchetto perso</title></circle> : null,
                )}
              </g>
            );
          })}
        </svg>
      )}
    </div>
  );
}

export function HBars({ items, unit = 'ms' }: { items: { label: string; value: number | null; highlight?: boolean; note?: string }[]; unit?: string }) {
  const max = Math.max(1, ...items.map((i) => i.value ?? 0));
  return (
    <div className="hops">
      {items.map((it, i) => (
        <div key={it.label} className="hop" style={{ gridTemplateColumns: 'minmax(0, 170px) 1fr 80px', ['--i' as string]: i }}>
          <span style={{ fontWeight: it.highlight ? 650 : 400, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={it.note}>
            {it.label}
          </span>
          <span className="bar" style={{ display: 'block' }}>
            {it.value !== null && <i style={{ width: `${(100 * it.value) / max}%`, background: it.highlight ? 'var(--accent)' : undefined }} />}
          </span>
          <span className="mono" style={{ textAlign: 'right' }}>{it.value === null ? 'nessuna risp.' : `${Math.round(it.value)} ${unit}`}</span>
        </div>
      ))}
    </div>
  );
}
