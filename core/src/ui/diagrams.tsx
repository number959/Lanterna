import {
  AppWindow,
  Cctv,
  Disc3,
  Ear,
  FileText,
  Globe,
  HardDrive,
  Lock,
  MemoryStick,
  Monitor,
  Network,
  Power,
  Printer,
  RadioTower,
  RotateCcw,
  Router,
  Server,
  ShieldAlert,
  TriangleAlert,
  Usb,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { m, useReducedMotion } from 'motion/react';
import type { Variants } from 'motion/react';
import { useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import type { DiagramId } from '../guides';
import { hexPath } from './brand';
import { ease } from './motion';

// Diagrammi delle guide. Sono SVG disegnati a mano con i colori del tema:
// si animano una volta quando entrano nella vista e raccontano il concetto
// nell'ordine in cui va letto (prima la struttura, poi il flusso). Con
// "riduci movimento" restano fermi nello stato finale e i pacchetti in
// movimento non compaiono: l'informazione è comunque completa.

interface DProps {
  still: boolean;
}

type Pt = readonly [number, number];

const fade = (delay = 0, duration = 0.5): Variants => ({
  hidden: { opacity: 0 },
  show: { opacity: 1, transition: { delay, duration, ease: ease.out } },
});

const slide = (delay: number, dx = 0, dy = 10): Variants => ({
  hidden: { opacity: 0, x: dx, y: dy },
  show: { opacity: 1, x: 0, y: 0, transition: { delay, duration: 0.55, ease: ease.out } },
});

const draw = (delay = 0, duration = 0.7): Variants => ({
  hidden: { pathLength: 0, opacity: 0 },
  show: { pathLength: 1, opacity: 1, transition: { pathLength: { delay, duration, ease: ease.out }, opacity: { delay, duration: 0.01 } } },
});

const pop = (delay = 0): Variants => ({
  hidden: { opacity: 0, scale: 0.4 },
  show: { opacity: 1, scale: 1, transition: { delay, type: 'spring', stiffness: 420, damping: 22 } },
});

const mix = (color: string, pct: number) => `color-mix(in srgb, ${color} ${pct}%, var(--surface-2))`;

/** Disegno che si anima entrando nella vista, oppure fermo nello stato finale. */
function Stage({ still, w, h, label, children }: DProps & { w: number; h: number; label: string; children: ReactNode }) {
  const anim = still
    ? ({ initial: false, animate: 'show' } as const)
    : ({ initial: 'hidden', whileInView: 'show', viewport: { once: true, amount: 0.35 } } as const);
  return (
    <m.svg viewBox={`0 0 ${w} ${h}`} className="diagram-svg" role="img" aria-label={label} {...anim}>
      {children}
    </m.svg>
  );
}

/** Movimento lungo una spezzata a velocità costante: compare all'inizio, svanisce all'arrivo. */
function travel(pts: Pt[], delay: number, duration: number): Variants {
  const seg = pts.slice(1).map((p, i) => Math.hypot(p[0] - pts[i][0], p[1] - pts[i][1]));
  const total = seg.reduce((a, b) => a + b, 0) || 1;
  let acc = 0;
  const times = [0, ...seg.map((d) => (acc += d) / total)];
  const move = { delay, duration, times, ease: 'linear' as const };
  return {
    hidden: { opacity: 0, x: pts[0][0], y: pts[0][1] },
    show: {
      opacity: [0, 1, 1, 0],
      x: pts.map((p) => p[0]),
      y: pts.map((p) => p[1]),
      transition: { x: move, y: move, opacity: { delay, duration, times: [0, 0.06, 0.9, 1] } },
    },
  };
}

/** Pacchetto che percorre una spezzata a velocità costante. */
function Token({ pts, delay, duration, color, r = 6.5 }: { pts: Pt[]; delay: number; duration: number; color: string; r?: number }) {
  return <m.circle r={r} cx={0} cy={0} style={{ fill: color }} className="d-token" variants={travel(pts, delay, duration)} />;
}

/** Qualunque disegno (un pacchetto con l'etichetta, un documento) che percorre una spezzata. */
function Mover({ pts, delay, duration, children }: { pts: Pt[]; delay: number; duration: number; children: ReactNode }) {
  return <m.g variants={travel(pts, delay, duration)}>{children}</m.g>;
}

/** Pacchetto con un'etichetta breve (LLDP, TTL 3...), centrato nell'origine. */
function Chip({ text, c }: { text: string; c: string }) {
  const w = text.length * 6.6 + 16;
  return (
    <g>
      <rect x={-w / 2} y={-10} width={w} height={20} rx={10} strokeWidth={1.4} style={{ fill: mix(c, 34), stroke: c }} />
      <text className="d-m" y={3.8} textAnchor="middle" style={{ fill: 'var(--text)' }}>
        {text}
      </text>
    </g>
  );
}

/** Icona di Lucide centrata in (x, y). */
function Glyph({ I, x, y, s = 22, c = 'var(--text)' }: { I: LucideIcon; x: number; y: number; s?: number; c?: string }) {
  return <I x={x - s / 2} y={y - s / 2} width={s} height={s} color={c} strokeWidth={1.9} aria-hidden />;
}

/** Punta di freccia in `at`; `deg` è la direzione (0 = verso destra, 90 = verso il basso). */
function Tip({ at, deg, delay = 0, color = 'var(--accent)' }: { at: Pt; deg: number; delay?: number; color?: string }) {
  return (
    <g transform={`translate(${at[0]} ${at[1]}) rotate(${deg})`}>
      <m.path d="M0 0 L-10 -5.5 L-10 5.5 Z" style={{ fill: color }} variants={fade(delay, 0.2)} />
    </g>
  );
}

/** Barra che cresce da sinistra. */
function Grow({ x, y, w, h, delay, dur = 0.7, rx = 5, style, className }: { x: number; y: number; w: number; h: number; delay: number; dur?: number; rx?: number; style?: Record<string, string | number>; className?: string }) {
  return (
    <m.rect
      x={x}
      y={y}
      width={w}
      height={h}
      rx={rx}
      className={className}
      style={{ originX: 0, ...style }}
      variants={{ hidden: { scaleX: 0, opacity: 0 }, show: { scaleX: 1, opacity: 1, transition: { delay, duration: dur, ease: ease.out } } }}
    />
  );
}

/** Punto del bordo del rettangolo nella direzione di p. */
function rectEdge(x: number, y: number, w: number, h: number, p: Pt): Pt {
  const cx = x + w / 2;
  const cy = y + h / 2;
  const dx = p[0] - cx;
  const dy = p[1] - cy;
  const k = Math.min(dx ? w / 2 / Math.abs(dx) : Infinity, dy ? h / 2 / Math.abs(dy) : Infinity);
  return [cx + dx * k, cy + dy * k];
}

/** Punto a distanza d da a, verso b. */
function along(a: Pt, b: Pt, d: number): Pt {
  const l = Math.hypot(b[0] - a[0], b[1] - a[1]) || 1;
  return [a[0] + ((b[0] - a[0]) * d) / l, a[1] + ((b[1] - a[1]) * d) / l];
}

const poly = (pts: Pt[]) => pts.map((p, i) => `${i ? 'L' : 'M'}${p[0].toFixed(1)} ${p[1].toFixed(1)}`).join(' ');

/** Esito di un flusso: spunta (permesso) o croce (bloccato). */
function Verdict({ at, ok, delay }: { at: Pt; ok: boolean; delay: number }) {
  return (
    <g transform={`translate(${at[0]} ${at[1]})`}>
      <m.g variants={pop(delay)}>
        <circle r={11} className={ok ? 'd-ok-bg' : 'd-crit-bg'} />
        {ok ? <path d="M-5 0.5 L-1.5 4 L5.5 -3.5" className="d-ok-mark" /> : <path d="M-4 -4 L4 4 M4 -4 L-4 4" className="d-crit-mark" />}
      </m.g>
    </g>
  );
}

// ---------------------------------------------------------------- livelli

function Osi({ still }: DProps) {
  const rows = [
    { t: 'Applicazione', s: 'HTTP, DNS, DICOM, HL7', l: 'L7–L5' },
    { t: 'Trasporto', s: 'TCP e UDP · porte', l: 'L4' },
    { t: 'Rete', s: 'IP · router e gateway', l: 'L3' },
    { t: 'Collegamento e fisico', s: 'Ethernet, Wi-Fi · MAC', l: 'L2–L1' },
  ];
  const Y = (i: number) => 40 + i * 56;
  const cy = (i: number) => Y(i) + 23;
  const stack = (x: number, side: -1 | 1, who: string) => (
    <g>
      <m.text className="d-h" x={x + 111} y={24} textAnchor="middle" variants={fade(0.05)}>
        {who}
      </m.text>
      {rows.map((r, i) => (
        <m.g key={r.t} variants={slide(0.12 + i * 0.08, side * 18, 0)}>
          <rect className="d-box" x={x} y={Y(i)} width={222} height={46} rx={10} style={{ fill: mix('var(--accent)', 18 - i * 4) }} />
          <text className="d-t" x={x + 14} y={Y(i) + 20}>{r.t}</text>
          <text className="d-s" x={x + 14} y={Y(i) + 37}>{r.s}</text>
          <text className="d-m" x={x + 208} y={Y(i) + 20} textAnchor="end">{r.l}</text>
        </m.g>
      ))}
    </g>
  );
  const path: Pt[] = [[270, cy(0)], [270, cy(1)], [270, cy(2)], [270, cy(3)], [270, 270], [320, 270], [370, 270], [370, cy(3)], [370, cy(2)], [370, cy(1)], [370, cy(0)]];
  const widths = [1, 1.3, 1.6, 1.9, 1.9, 1.9, 1.9, 1.6, 1.3, 1, 1];
  const times = path.map((_, i) => i / (path.length - 1));
  const run = { delay: 1.15, duration: 5.4, times, ease: 'easeInOut' as const };
  return (
    <Stage still={still} w={640} h={316} label="Due pile di livelli, PC e server: i dati scendono i livelli del mittente, attraversano la rete e risalgono quelli del destinatario.">
      {rows.map((_, i) => (
        <m.line key={i} className="d-line d-faint" x1={246} x2={394} y1={cy(i)} y2={cy(i)} strokeDasharray="3 6" variants={fade(0.55 + i * 0.06)} />
      ))}
      <m.path className="d-line" d={`M270 ${cy(0)} V270 H370 V${cy(0)}`} variants={draw(0.6, 0.9)} />
      <m.path className="d-node" d={hexPath(320, 270, 17)} variants={pop(0.9)} />
      <m.text className="d-m" x={320} y={274} textAnchor="middle" variants={fade(1)}>rete</m.text>
      {stack(24, -1, 'PC')}
      {stack(394, 1, 'Server')}
      <m.text className="d-s" x={24} y={306} variants={fade(1.1)}>scendendo, ogni livello aggiunge la sua intestazione</m.text>
      <m.text className="d-s" x={616} y={306} textAnchor="end" variants={fade(1.1)}>salendo, ogni livello toglie la sua</m.text>
      {!still && (
        <m.g
          variants={{
            hidden: { opacity: 0, x: path[0][0], y: path[0][1] },
            show: {
              opacity: [0, 1, 1, 0],
              x: path.map((p) => p[0]),
              y: path.map((p) => p[1]),
              transition: { x: run, y: run, opacity: { delay: run.delay, duration: run.duration, times: [0, 0.04, 0.96, 1] } },
            },
          }}
        >
          <m.rect
            x={-10}
            y={-7}
            width={20}
            height={14}
            rx={4}
            className="d-packet"
            variants={{ hidden: { scaleX: 1 }, show: { scaleX: widths, transition: run } }}
          />
        </m.g>
      )}
    </Stage>
  );
}

// ---------------------------------------------------------------- sottorete

const PREFIXES = [16, 22, 24, 26, 28];
const IP = [192, 168, 1, 20];

const toDotted = (n: number) => [24, 16, 8, 0].map((sh) => (n >>> sh) & 255).join('.');
const fmtInt = (n: number) => n.toLocaleString('it-IT');

function Subnet({ still }: DProps) {
  const [prefix, setPrefix] = useState(24);
  const bits = IP.flatMap((o) => o.toString(2).padStart(8, '0').split(''));
  const cell = 16;
  const gap = 2;
  const ow = 8 * cell + 7 * gap; // 142
  const ox = (k: number) => 15 + k * (ow + 14);
  const bx = (i: number) => ox(Math.floor(i / 8)) + (i % 8) * (cell + gap);
  const ipN = IP.reduce((a, o) => a * 256 + o, 0);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const net = (ipN & mask) >>> 0;
  const bcast = (net | (~mask >>> 0)) >>> 0;
  const hosts = 2 ** (32 - prefix) - 2;
  const netEnd = bx(prefix - 1) + cell;
  const hostStart = bx(prefix);
  const clampX = (x: number) => Math.min(560, Math.max(90, x));
  const netX = clampX((bx(0) + netEnd) / 2);
  const hostX = clampX((hostStart + bx(31) + cell) / 2);
  const pills = [
    { t: `Maschera ${toDotted(mask)}`, x: 112 },
    { t: `Rete ${toDotted(net)}`, x: 320 },
    { t: `Broadcast ${toDotted(bcast)}`, x: 528 },
  ];
  const morph = { type: 'spring', stiffness: 260, damping: 30 } as const;
  return (
    <>
      <Stage still={still} w={640} h={224} label={`L'indirizzo 192.168.1.20/${prefix} in binario: i primi ${prefix} bit indicano la rete, gli ultimi ${32 - prefix} il dispositivo.`}>
        <m.text className="d-big" x={320} y={32} textAnchor="middle" variants={fade(0)}>
          192.168.1.20<tspan className="d-acc-t">/{prefix}</tspan>
        </m.text>
        {IP.map((o, k) => (
          <m.text key={k} className="d-oct" x={ox(k) + ow / 2} y={70} textAnchor="middle" variants={fade(0.1 + k * 0.05)}>
            {o}
          </m.text>
        ))}
        {bits.map((b, i) => (
          <m.g key={i} variants={pop(0.25 + i * 0.022)}>
            <rect className="d-bitcell" x={bx(i)} y={80} width={cell} height={26} rx={4} style={{ fill: mix(i < prefix ? 'var(--accent)' : 'var(--signal)', b === '1' ? 34 : 14) }} />
            <text className="d-bit" x={bx(i) + cell / 2} y={97.5} textAnchor="middle">{b}</text>
          </m.g>
        ))}
        <m.g variants={fade(1.1)}>
          <m.path className="d-brace d-acc-s" initial={false} animate={{ d: `M${bx(0)} 114 v7 H${netEnd} v-7` }} transition={morph} />
          <m.path className="d-brace d-sig-s" initial={false} animate={{ d: `M${hostStart} 114 v7 H${bx(31) + cell} v-7` }} transition={morph} />
        </m.g>
        <m.g variants={fade(1.3)}>
          <m.text className="d-t d-acc-t" y={142} textAnchor="middle" initial={false} animate={{ attrX: netX }} transition={morph}>rete: {prefix} bit</m.text>
          <m.text className="d-s" y={159} textAnchor="middle" initial={false} animate={{ attrX: netX }} transition={morph}>uguali in tutta la sottorete</m.text>
          <m.text className="d-t d-sig-t" y={142} textAnchor="middle" initial={false} animate={{ attrX: hostX }} transition={morph}>host: {32 - prefix} bit</m.text>
          <m.text className="d-s" y={159} textAnchor="middle" initial={false} animate={{ attrX: hostX }} transition={morph}>{fmtInt(hosts)} indirizzi utilizzabili</m.text>
        </m.g>
        {pills.map((p, i) => (
          <m.g key={i} variants={slide(1.5 + i * 0.1, 0, 8)}>
            <rect className="d-pill" x={p.x - 98} y={184} width={196} height={28} rx={14} />
            <text className="d-mono" x={p.x} y={202.5} textAnchor="middle">{p.t}</text>
          </m.g>
        ))}
      </Stage>
      <div className="diagram-controls" role="radiogroup" aria-label="Maschera di rete">
        {PREFIXES.map((p) => (
          <button key={p} role="radio" aria-checked={p === prefix} className={p === prefix ? 'on' : undefined} onClick={() => setPrefix(p)}>
            /{p}
          </button>
        ))}
      </div>
    </>
  );
}

// ---------------------------------------------------------------- DHCP

function Dhcp({ still }: DProps) {
  const L = 110;
  const R = 530;
  const steps = [
    { dir: 1, t: '1 · DISCOVER', s: 'in broadcast: c\'è un server DHCP?' },
    { dir: -1, t: '2 · OFFER', s: 'ti propongo 192.168.1.20' },
    { dir: 1, t: '3 · REQUEST', s: 'accetto 192.168.1.20 (ancora in broadcast)' },
    { dir: -1, t: '4 · ACK', s: 'confermato: lease di 24 ore, gateway e DNS' },
  ];
  const Y = (i: number) => 98 + i * 52;
  const at = (i: number) => 0.45 + i * 0.75;
  const head = (x: number, t: string, s: string, d: number) => (
    <m.g variants={slide(d, 0, -8)}>
      <rect className="d-box" x={x - 72} y={14} width={144} height={46} rx={10} />
      <text className="d-t" x={x} y={34} textAnchor="middle">{t}</text>
      <text className="d-s" x={x} y={51} textAnchor="middle">{s}</text>
    </m.g>
  );
  return (
    <Stage still={still} w={640} h={330} label="Il dialogo DHCP in quattro messaggi tra il PC e il server: Discover, Offer, Request, Ack.">
      {head(L, 'PC', 'client', 0)}
      {head(R, 'Server DHCP', 'router o server', 0.08)}
      <m.line className="d-line d-faint" x1={L} x2={L} y1={60} y2={278} strokeDasharray="3 5" variants={fade(0.25)} />
      <m.line className="d-line d-faint" x1={R} x2={R} y1={60} y2={278} strokeDasharray="3 5" variants={fade(0.25)} />
      {steps.map((s, i) => {
        const y = Y(i);
        const x1 = s.dir > 0 ? L + 6 : R - 6;
        const x2 = s.dir > 0 ? R - 8 : L + 8;
        const tip = s.dir > 0 ? `M${R - 6} ${y} l-10 -5.5 v11 z` : `M${L + 6} ${y} l10 -5.5 v11 z`;
        return (
          <g key={s.t}>
            <m.path className="d-arrow" d={`M${x1} ${y} H${x2}`} variants={draw(at(i), 0.55)} />
            <m.path className="d-arrow-tip" d={tip} variants={fade(at(i) + 0.45, 0.2)} />
            <m.text className="d-t d-mono-t" x={320} y={y - 10} textAnchor="middle" variants={fade(at(i) + 0.15)}>{s.t}</m.text>
            <m.text className="d-s" x={320} y={y + 18} textAnchor="middle" variants={fade(at(i) + 0.25)}>{s.s}</m.text>
          </g>
        );
      })}
      <m.g variants={pop(at(4) - 0.1)}>
        <rect className="d-ok-pill" x={L - 78} y={288} width={156} height={30} rx={15} />
        <text className="d-mono d-ok-t" x={L} y={307.5} textAnchor="middle">192.168.1.20/24 ✓</text>
      </m.g>
    </Stage>
  );
}

// ---------------------------------------------------------------- canali 2,4 GHz

function Channels24({ still }: DProps) {
  const X = (f: number) => 34 + (f - 2400) * 6.9;
  const base = 186;
  const fc = (n: number) => 2407 + 5 * n;
  const hump = (f: number, top: number) =>
    `M${X(f - 11)} ${base} C${X(f - 6)} ${base} ${X(f - 7)} ${top} ${X(f)} ${top} C${X(f + 7)} ${top} ${X(f + 6)} ${base} ${X(f + 11)} ${base}`;
  const all = Array.from({ length: 13 }, (_, i) => i + 1);
  const good = [1, 6, 11];
  return (
    <Stage still={still} w={640} h={244} label="Canali Wi-Fi a 2,4 GHz: ogni canale occupa circa 20 MHz, quindi solo 1, 6 e 11 non si sovrappongono; il canale 3 disturba sia l'1 sia il 6.">
      <m.text className="d-t d-acc-t" x={320} y={20} textAnchor="middle" variants={fade(1.2)}>1, 6 e 11: i soli tre canali che non si sovrappongono</m.text>
      <m.line className="d-axis" x1={X(2400)} x2={X(2484)} y1={base} y2={base} variants={fade(0)} />
      {all
        .filter((n) => !good.includes(n))
        .map((n, i) => (
          <m.path key={n} className="d-hump-faint" d={hump(fc(n), 92)} variants={draw(0.15 + i * 0.05, 0.6)} />
        ))}
      {good.map((n, i) => (
        <m.path key={n} className="d-hump" d={hump(fc(n), 62)} variants={draw(0.75 + i * 0.15, 0.7)} />
      ))}
      {good.map((n, i) => (
        <m.path key={`f${n}`} className="d-hump-fill" d={hump(fc(n), 62)} variants={fade(1.2 + i * 0.1, 0.5)} />
      ))}
      <m.path className="d-hump-warn" d={hump(fc(3), 76)} variants={draw(2, 0.6)} />
      <m.g variants={fade(2.4)}>
        <line className="d-leader" x1={X(fc(3))} x2={X(fc(3))} y1={50} y2={74} />
        <text className="d-s d-warn-t" x={X(fc(3))} y={44} textAnchor="middle">il 3 si sovrappone all'1 e al 6</text>
      </m.g>
      {all.map((n) => (
        <m.text key={n} className={good.includes(n) ? 'd-ch d-ch-good' : 'd-ch'} x={X(fc(n))} y={base + 18} textAnchor="middle" variants={fade(0.1 + n * 0.03)}>
          {n}
        </m.text>
      ))}
      <m.text className="d-s" x={X(2400)} y={234} variants={fade(0.4)}>2,400 GHz</m.text>
      <m.text className="d-s" x={X(2483.5)} y={234} textAnchor="end" variants={fade(0.4)}>2,4835 GHz</m.text>
      <m.text className="d-s" x={320} y={234} textAnchor="middle" variants={fade(0.4)}>canali distanti 5 MHz, larghi circa 20</m.text>
    </Stage>
  );
}

// ---------------------------------------------------------------- roaming

function Roaming({ still }: DProps) {
  // Le celle si sovrappongono tra 305 e 335: è lì che avviene il passaggio.
  const A: Pt = [180, 110];
  const B: Pt = [460, 110];
  const yDev = 180;
  const xs = [96, 262, 320, 372, 544];
  const times = [0, 0.36, 0.5, 0.6, 1];
  const run = { delay: 0.9, duration: 6, times, ease: 'easeInOut' as const };
  const switchAt = [0, 0.36, 0.52, 0.56, 1];
  const phases = [
    { x: 120, t: '802.11k', s: 'l\'AP indica i vicini', d: 1.1 },
    { x: 320, t: '802.11v', s: 'l\'AP invita a spostarsi', d: 0.9 + 6 * 0.4 },
    { x: 520, t: '802.11r', s: 'chiavi già pronte', d: 0.9 + 6 * 0.53 },
  ];
  const ap = (p: Pt, name: string, ch: string, d: number) => (
    <m.g variants={pop(d)}>
      <path className="d-ap" d={hexPath(p[0], p[1], 19)} />
      <text className="d-m" x={p[0]} y={p[1] + 4} textAnchor="middle">AP</text>
      <text className="d-t" x={p[0]} y={p[1] - 46} textAnchor="middle">{name}</text>
      <text className="d-s" x={p[0]} y={p[1] - 29} textAnchor="middle">{ch}</text>
    </m.g>
  );
  const device = (
    <g>
      <rect className="d-device" x={-9} y={-14} width={18} height={28} rx={4} />
      <line className="d-device-line" x1={-3} x2={3} y1={10} y2={10} />
    </g>
  );
  const reading = (t: string, cls: string, op: number[]) => (
    <m.text className={`d-mono ${cls}`} x={0} y={36} textAnchor="middle" variants={{ hidden: { opacity: 0 }, show: { opacity: op, transition: { ...run, times: switchAt, ease: 'linear' } } }}>
      {t}
    </m.text>
  );
  return (
    <Stage still={still} w={640} h={290} label="Un dispositivo cammina da un access point all'altro: con 802.11k, v e r il passaggio è guidato e rapido.">
      <m.circle className="d-cell" cx={A[0]} cy={A[1]} r={170} variants={fade(0.1, 0.8)} />
      <m.circle className="d-cell" cx={B[0]} cy={B[1]} r={170} variants={fade(0.2, 0.8)} />
      <m.line className="d-line d-faint" x1={60} x2={580} y1={yDev + 21} y2={yDev + 21} strokeDasharray="2 6" variants={fade(0.4)} />
      {ap(A, 'AP 1', 'canale 36', 0.25)}
      {ap(B, 'AP 2', 'canale 44', 0.35)}
      {still ? (
        <g>
          <line className="d-link" x1={B[0]} y1={B[1] + 19} x2={xs[4]} y2={yDev - 14} />
          <g transform={`translate(${xs[4]} ${yDev})`}>
            {device}
            <text className="d-mono d-ok-t" x={0} y={36} textAnchor="middle">-51 dBm</text>
          </g>
        </g>
      ) : (
        <>
          <m.line
            className="d-link"
            x1={A[0]}
            y1={A[1] + 19}
            y2={yDev - 14}
            variants={{ hidden: { opacity: 0, x2: xs[0] }, show: { opacity: [1, 1, 1, 0, 0], x2: xs, transition: { ...run, opacity: { ...run, times: switchAt, ease: 'linear' } } } }}
          />
          <m.line
            className="d-link"
            x1={B[0]}
            y1={B[1] + 19}
            y2={yDev - 14}
            variants={{ hidden: { opacity: 0, x2: xs[0] }, show: { opacity: [0, 0, 0, 1, 1], x2: xs, transition: { ...run, opacity: { ...run, times: switchAt, ease: 'linear' } } } }}
          />
          <m.g variants={{ hidden: { opacity: 0, x: xs[0], y: yDev }, show: { opacity: 1, x: xs, y: yDev, transition: { x: run, opacity: { delay: 0.7, duration: 0.3 } } } }}>
            {device}
            {reading('-48 dBm', 'd-ok-t', [1, 0, 0, 0, 0])}
            {reading('-71 dBm', 'd-warn-t', [0, 1, 1, 0, 0])}
            {reading('-51 dBm', 'd-ok-t', [0, 0, 0, 1, 1])}
          </m.g>
        </>
      )}
      {phases.map((p) => (
        <m.g key={p.t} variants={slide(still ? 0 : p.d, 0, 8)}>
          <text className="d-t d-acc-t" x={p.x} y={262} textAnchor="middle">{p.t}</text>
          <text className="d-s" x={p.x} y={278} textAnchor="middle">{p.s}</text>
        </m.g>
      ))}
    </Stage>
  );
}

// ---------------------------------------------------------------- VLAN

function Vlan({ still }: DProps) {
  const V = [
    { id: 10, name: 'Personale', c: 'var(--accent)', devs: ['PC 1', 'PC 2'] },
    { id: 20, name: 'Dispositivi medicali', c: 'var(--p1)', devs: ['Ecografo', 'Monitor'] },
    { id: 30, name: 'Ospiti', c: 'var(--p4)', devs: ['Tablet', 'Telefono'] },
  ];
  const devX = [76, 158, 286, 368, 496, 578];
  const trunkX = [313, 320, 327];
  return (
    <Stage still={still} w={640} h={292} label="Uno switch con porte in tre VLAN e un collegamento trunk verso il firewall: gli ospiti raggiungono Internet ma non i dispositivi medicali.">
      <m.g variants={slide(0, 0, -8)}>
        <rect className="d-box d-fw" x={250} y={14} width={140} height={46} rx={10} />
        <text className="d-t" x={320} y={34} textAnchor="middle">Firewall</text>
        <text className="d-s" x={320} y={51} textAnchor="middle">regole tra le VLAN</text>
      </m.g>
      <m.g variants={slide(0.1, 10, 0)}>
        <line className="d-line" x1={390} x2={470} y1={37} y2={37} />
        <rect className="d-pill" x={470} y={22} width={120} height={30} rx={15} />
        <text className="d-t" x={530} y={42} textAnchor="middle">Internet</text>
      </m.g>
      {V.map((v, i) => (
        <m.line key={v.id} x1={trunkX[i]} x2={trunkX[i]} y1={60} y2={124} style={{ stroke: v.c }} className="d-trunk" variants={draw(0.35 + i * 0.08, 0.5)} />
      ))}
      <m.text className="d-s" x={338} y={96} variants={fade(0.6)}>trunk 802.1Q · VLAN 10, 20, 30</m.text>
      <m.g variants={slide(0.15, 0, 8)}>
        <rect className="d-box" x={40} y={124} width={560} height={44} rx={10} />
        <text className="d-t" x={56} y={146}>Switch gestito</text>
      </m.g>
      {devX.map((x, i) => {
        const v = V[Math.floor(i / 2)];
        return (
          <g key={x}>
            <m.rect x={x - 13} y={152} width={26} height={11} rx={3} style={{ fill: v.c }} variants={pop(0.4 + i * 0.05)} />
            <m.line x1={x} x2={x} y1={163} y2={206} style={{ stroke: v.c }} className="d-wire" variants={draw(0.55 + i * 0.05, 0.35)} />
            <m.g variants={slide(0.6 + i * 0.05, 0, 8)}>
              <rect className="d-dev" x={x - 37} y={206} width={74} height={26} rx={8} style={{ stroke: v.c }} />
              <text className="d-s d-dev-t" x={x} y={223} textAnchor="middle">{v.devs[i % 2]}</text>
            </m.g>
          </g>
        );
      })}
      {V.map((v, i) => (
        <m.text key={v.id} className="d-t" x={(devX[i * 2] + devX[i * 2 + 1]) / 2} y={262} textAnchor="middle" style={{ fill: v.c }} variants={fade(0.9 + i * 0.08)}>
          VLAN {v.id}
          <tspan className="d-s" x={(devX[i * 2] + devX[i * 2 + 1]) / 2} dy={17}>{v.name}</tspan>
        </m.text>
      ))}
      {!still && (
        <>
          <Token pts={[[496, 206], [496, 165], [327, 146], [327, 60], [390, 37], [470, 37]]} delay={1.5} duration={2.2} color="var(--p4)" />
          <Verdict at={[600, 22]} ok delay={3.7} />
          <m.text className="d-s d-ok-t" x={530} y={70} textAnchor="middle" variants={fade(3.8)}>ospiti → Internet: consentito</m.text>
          <Token pts={[[578, 206], [578, 165], [327, 146], [327, 62]]} delay={4.1} duration={1.8} color="var(--p4)" />
          <Verdict at={[327, 76]} ok={false} delay={5.8} />
          <m.text className="d-s d-crit-t" x={304} y={100} textAnchor="end" variants={fade(5.9)}>ospiti → VLAN 20: bloccato</m.text>
        </>
      )}
      {still && (
        <>
          <Verdict at={[600, 22]} ok delay={0} />
          <text className="d-s d-ok-t" x={530} y={70} textAnchor="middle">ospiti → Internet: consentito</text>
          <Verdict at={[327, 76]} ok={false} delay={0} />
          <text className="d-s d-crit-t" x={304} y={100} textAnchor="end">ospiti → VLAN 20: bloccato</text>
        </>
      )}
    </Stage>
  );
}

// ---------------------------------------------------------------- clinica

interface Zone {
  t: string;
  s: string;
  x: number;
  y: number;
}

const ZW = 184;
const ZH = 62;
const FW: Pt = [320, 190];

/** Punto del bordo del riquadro nella direzione del firewall. */
function edge(z: Zone): Pt {
  const cx = z.x + ZW / 2;
  const cy = z.y + ZH / 2;
  const dx = FW[0] - cx;
  const dy = FW[1] - cy;
  const k = Math.min(dx ? ZW / 2 / Math.abs(dx) : Infinity, dy ? ZH / 2 / Math.abs(dy) : Infinity);
  return [cx + dx * k, cy + dy * k];
}

/** Punto a distanza r dal centro del firewall verso p. */
function toward(p: Pt, r: number): Pt {
  const d = Math.hypot(p[0] - FW[0], p[1] - FW[1]) || 1;
  return [FW[0] + ((p[0] - FW[0]) * r) / d, FW[1] + ((p[1] - FW[1]) * r) / d];
}

function Clinic({ still }: DProps) {
  const Z: Record<string, Zone> = {
    srv: { t: 'Server clinici', s: 'cartella, PACS, laboratorio', x: 16, y: 20 },
    net: { t: 'Internet e DMZ', s: 'portali, posta, VPN', x: 228, y: 20 },
    mgmt: { t: 'Gestione', s: 'apparati, amministratori', x: 440, y: 20 },
    pc: { t: 'Postazioni', s: 'reparti, ambulatori', x: 16, y: 159 },
    voip: { t: 'Telefonia', s: 'telefoni, centralino', x: 440, y: 159 },
    med: { t: 'Dispositivi medicali', s: 'diagnostica, monitor', x: 16, y: 298 },
    iot: { t: 'Impianti e IoT', s: 'telecamere, accessi', x: 228, y: 298 },
    guest: { t: 'Ospiti', s: 'solo Internet', x: 440, y: 298 },
  };
  const keys = Object.keys(Z);
  const flows = [
    { from: 'pc', to: 'srv', ok: true, c: 'var(--accent)', d: 1.3 },
    { from: 'med', to: 'srv', ok: true, c: 'var(--p1)', d: 3.1 },
    { from: 'guest', to: 'net', ok: true, c: 'var(--p4)', d: 4.9 },
    { from: 'guest', to: 'srv', ok: false, c: 'var(--p4)', d: 6.7 },
  ];
  return (
    <Stage still={still} w={640} h={380} label="Le zone di una rete sanitaria attorno al firewall interno: le postazioni e i dispositivi medicali raggiungono i server clinici, gli ospiti solo Internet.">
      {keys.map((k, i) => {
        const p = edge(Z[k]);
        return <m.line key={k} className="d-line" x1={p[0]} y1={p[1]} x2={FW[0]} y2={FW[1]} variants={draw(0.5 + i * 0.05, 0.5)} />;
      })}
      {keys.map((k, i) => {
        const z = Z[k];
        const hot = k === 'srv' || k === 'med';
        return (
          <m.g key={k} variants={slide(0.05 + i * 0.05, 0, 10)}>
            <rect className={hot ? 'd-box d-zone-hot' : 'd-box'} x={z.x} y={z.y} width={ZW} height={ZH} rx={12} />
            <text className="d-t" x={z.x + 14} y={z.y + 26}>{z.t}</text>
            <text className="d-s" x={z.x + 14} y={z.y + 45}>{z.s}</text>
          </m.g>
        );
      })}
      <m.g variants={pop(0.35)}>
        <path className="d-fw-hex" d={hexPath(FW[0], FW[1], 50)} />
        <text className="d-t" x={FW[0]} y={FW[1] - 2} textAnchor="middle">Firewall</text>
        <text className="d-s" x={FW[0]} y={FW[1] + 15} textAnchor="middle">interno</text>
      </m.g>
      {flows.map((f) => {
        const a = edge(Z[f.from]);
        const b = edge(Z[f.to]);
        const end = f.ok ? b : toward(a, 54);
        return (
          <g key={`${f.from}-${f.to}`}>
            {!still && <Token pts={f.ok ? [a, FW, b] : [a, end]} delay={f.d} duration={f.ok ? 1.6 : 1.1} color={f.c} />}
            <Verdict at={f.ok ? [b[0] + (b[0] < FW[0] ? 14 : -14), b[1] + (b[1] < FW[1] ? 12 : -12)] : toward(a, 66)} ok={f.ok} delay={still ? 0 : f.d + (f.ok ? 1.6 : 1.1)} />
          </g>
        );
      })}
    </Stage>
  );
}

// ---------------------------------------------------------------- mappa della rete

function NetmapD({ still }: DProps) {
  const inet: Pt = [320, 38];
  const gw: Pt = [320, 110];
  const sw: Pt = [320, 196];
  const busY = 238;
  const devY = 282;
  const R = 21;
  const devs = [
    { x: 92, I: RadioTower, c: 'var(--accent)', t: 'Access point', s: 'dedotto dal Wi-Fi', dashed: true },
    { x: 206, I: Monitor, c: 'var(--p0)', t: 'Questo PC', s: '192.168.1.20', self: true },
    { x: 320, I: Printer, c: 'var(--p5)', t: 'Stampante', s: '192.168.1.30' },
    { x: 434, I: Server, c: 'var(--p2)', t: 'Server', s: '192.168.1.10' },
    { x: 548, I: Cctv, c: 'var(--p7)', t: 'Telecamera', s: 'ipotesi', doubt: true },
  ];
  const path: Pt[] = [[206, devY - R], [206, busY], [320, busY], [320, sw[1]], [320, gw[1]], [320, inet[1]]];
  const chain = (p: Pt, I: LucideIcon, r: number, d: number) => (
    <m.g variants={pop(d)}>
      <circle cx={p[0]} cy={p[1]} r={r} className="d-box" style={{ stroke: 'var(--accent)', strokeWidth: 1.8 }} />
      <Glyph I={I} x={p[0]} y={p[1]} s={r + 2} c="var(--accent)" />
    </m.g>
  );
  return (
    <Stage
      still={still}
      w={640}
      h={356}
      label="Una piccola rete d'ufficio come la disegna la mappa: Internet, il router con il firewall, lo switch e i dispositivi collegati, cioè un access point dedotto dal Wi-Fi, questo PC, una stampante, un server e una telecamera da verificare. Il traffico di questo PC verso Internet passa dallo switch e dal router."
    >
      <m.rect x={16} y={150} width={608} height={198} rx={16} variants={fade(0.3)} style={{ fill: 'color-mix(in srgb, var(--accent) 6%, transparent)', stroke: 'color-mix(in srgb, var(--accent) 38%, transparent)' }} />
      <m.text className="d-t" x={32} y={174} variants={fade(0.35)}>
        Rete dell'ufficio
      </m.text>
      <m.text className="d-m" x={608} y={174} textAnchor="end" variants={fade(0.35)}>
        192.168.1.0/24 · 5 dispositivi
      </m.text>
      <m.line className="d-line" x1={320} x2={320} y1={inet[1] + 22} y2={gw[1] - 22} variants={draw(0.15, 0.3)} />
      <m.line className="d-line" x1={320} x2={320} y1={gw[1] + 22} y2={sw[1] - 19} variants={draw(0.3, 0.35)} />
      <m.line className="d-line" x1={320} x2={320} y1={sw[1] + 19} y2={busY} variants={draw(0.55, 0.2)} />
      <m.line className="d-line" x1={devs[0].x} x2={devs[4].x} y1={busY} y2={busY} variants={draw(0.6, 0.5)} />
      {devs.map((d, i) => (
        <m.line key={d.t} className="d-line" x1={d.x} x2={d.x} y1={busY} y2={devY - R} variants={draw(0.8 + i * 0.06, 0.2)} />
      ))}
      <m.path d={poly(path)} fill="none" strokeWidth={3.2} strokeLinejoin="round" strokeLinecap="round" style={{ stroke: 'var(--accent)', opacity: 0.85 }} variants={draw(1.7, 1)} />
      <Tip at={[320, inet[1] + 24]} deg={-90} delay={2.5} />
      <m.text className="d-s d-acc-t" x={308} y={144} textAnchor="end" variants={fade(2.2)}>
        traffico di questo PC verso Internet
      </m.text>
      {!still && [0, 0.6, 1.2].map((o) => <Token key={o} pts={path} delay={2.5 + o} duration={2} color="var(--accent)" r={5.5} />)}
      {chain(inet, Globe, 22, 0.05)}
      {chain(gw, Router, 22, 0.18)}
      {chain(sw, Network, 19, 0.42)}
      <m.text className="d-t" x={350} y={43} variants={fade(0.1)}>
        Internet
      </m.text>
      <m.g variants={fade(0.25)}>
        <text className="d-t" x={350} y={106}>Router e firewall</text>
        <text className="d-m" x={350} y={122}>gateway 192.168.1.1</text>
      </m.g>
      <m.text className="d-t" x={348} y={201} variants={fade(0.5)}>
        Switch
      </m.text>
      {devs.map((d, i) => (
        <m.g key={d.t} variants={slide(0.85 + i * 0.08, 0, 10)}>
          {d.self && <circle cx={d.x} cy={devY} r={R + 7} fill="none" strokeWidth={2} style={{ stroke: 'var(--accent)', opacity: 0.6 }} />}
          <circle cx={d.x} cy={devY} r={R} className="d-box" strokeDasharray={d.dashed ? '4 4' : undefined} style={{ fill: 'var(--surface)', stroke: d.c, strokeWidth: 1.8 }} />
          <Glyph I={d.I} x={d.x} y={devY} s={22} c={d.c} />
          <text className={d.self ? 'd-t d-acc-t' : 'd-t'} x={d.x} y={devY + R + 18} textAnchor="middle">
            {d.t}
          </text>
          <text className="d-m" x={d.x} y={devY + R + 32} textAnchor="middle">
            {d.s}
          </text>
        </m.g>
      ))}
      <g transform={`translate(${548 + R * 0.72} ${devY + R * 0.72})`}>
        <m.g variants={pop(1.5)}>
          <circle r={7.5} strokeWidth={1.6} style={{ fill: 'var(--surface)', stroke: 'var(--warn)' }} />
          <text y={3.6} textAnchor="middle" style={{ fill: 'var(--warn)', font: '700 10px var(--font)' }}>
            ?
          </text>
        </m.g>
      </g>
    </Stage>
  );
}

// ---------------------------------------------------------------- LLDP e CDP

function Lldp({ still }: DProps) {
  const px = (i: number) => 36 + i * 19;
  const p12x = px(11) + 7;
  const cy = 124;
  const pc: Pt = [578, cy];
  const path: Pt[] = [[p12x, 66], [p12x, cy], [pc[0] - 28, cy]];
  const fields = [
    { k: 'Switch', v: 'SW-PIANO2', s: 'nome e indirizzo', d: 2.45 },
    { k: 'Porta', v: '12', s: 'Gi1/0/12', d: 2.57 },
    { k: 'VLAN dati', v: '30 · Uffici', s: 'VLAN della porta', d: 2.69 },
    { k: 'VLAN voce', v: '40', s: 'LLDP-MED o CDP', d: 4.25 },
  ];
  const packets = [
    { t: 'LLDP', c: 'var(--accent)', d: 1.1 },
    { t: 'CDP', c: 'var(--p2)', d: 2.9 },
    { t: 'DTP', c: 'var(--warn)', d: 4.6 },
  ];
  return (
    <Stage
      still={still}
      w={640}
      h={330}
      label="Lo switch annuncia periodicamente sulla porta del PC il proprio nome, la porta 12, la VLAN dati 30 e la VLAN voce 40, con LLDP e CDP. Il PC con Polaris ascolta soltanto e non trasmette nulla verso lo switch. Un annuncio DTP avvisa che la porta potrebbe diventare un trunk."
    >
      <m.g variants={slide(0, 0, -8)}>
        <rect className="d-box" x={20} y={20} width={268} height={64} rx={10} />
        <text className="d-t" x={36} y={42}>Switch di piano</text>
        <text className="d-mono" x={272} y={42} textAnchor="end">SW-PIANO2</text>
        {Array.from({ length: 12 }, (_, i) => (
          <rect key={i} x={px(i)} y={54} width={14} height={12} rx={2} strokeWidth={1} style={i === 11 ? { fill: mix('var(--accent)', 45), stroke: 'var(--accent)' } : { fill: 'var(--surface)', stroke: 'var(--line-strong)' }} />
        ))}
      </m.g>
      <m.path d={poly(path)} className="d-line" strokeWidth={2.2} style={{ stroke: 'var(--accent)' }} variants={draw(0.35, 0.7)} />
      <Tip at={[pc[0] - 28, cy]} deg={0} delay={0.95} />
      <m.text className="d-m d-acc-t" x={226} y={106} textAnchor="end" variants={fade(0.6)}>
        porta 12
      </m.text>
      <m.g variants={pop(0.5)}>
        <circle cx={pc[0]} cy={pc[1]} r={26} className="d-box" style={{ fill: 'var(--surface)', stroke: 'var(--p0)', strokeWidth: 1.8 }} />
        <Glyph I={Monitor} x={pc[0]} y={pc[1]} s={24} c="var(--p0)" />
      </m.g>
      <m.g variants={fade(0.7)}>
        <text className="d-t" x={pc[0]} y={cy + 46} textAnchor="middle">PC con Polaris</text>
      </m.g>
      <m.g variants={fade(0.9)}>
        <text className="d-s" x={272} y={cy + 24}>annunci ogni 30 secondi (LLDP) o 60 (CDP)</text>
        <Glyph I={Ear} x={279} y={cy + 38} s={14} c="var(--accent-text)" />
        <text className="d-s" x={292} y={cy + 42}>il PC ascolta e non trasmette nulla</text>
      </m.g>
      {!still &&
        packets.map((p) => (
          <Mover key={p.t} pts={path} delay={p.d} duration={1.3}>
            <Chip text={p.t} c={p.c} />
          </Mover>
        ))}
      <m.g variants={fade(1.9)}>
        <rect className="d-box" x={20} y={186} width={600} height={96} rx={12} />
        <text className="d-h" x={36} y={208}>Che cosa annuncia lo switch</text>
      </m.g>
      {fields.map((f, i) => (
        <m.g key={f.k} variants={slide(f.d, 0, 8)}>
          <text className="d-s" x={36 + i * 150} y={232}>{f.k}</text>
          <text className="d-t" x={36 + i * 150} y={254}>{f.v}</text>
          <text className="d-m" x={36 + i * 150} y={271}>{f.s}</text>
        </m.g>
      ))}
      <m.g variants={pop(5.95)}>
        <rect x={20} y={294} width={330} height={28} rx={14} strokeWidth={1.2} style={{ fill: 'var(--warn-bg)', stroke: 'var(--warn)' }} />
        <Glyph I={TriangleAlert} x={38} y={308} s={15} c="var(--warn)" />
        <text className="d-s" x={52} y={312} style={{ fill: 'var(--text)' }}>
          DTP attivo: la porta potrebbe diventare trunk
        </text>
      </m.g>
    </Stage>
  );
}

// ---------------------------------------------------------------- instradamento tra VLAN

function InterVlan({ still }: DProps) {
  const FWc: Pt = [320, 163];
  const BW = 206;
  const BH = 74;
  const box = {
    srv: { t: 'Server', v: 10, s: '10.0.10.0/24 · server DHCP', c: 'var(--p2)', x: 16, y: 16 },
    med: { t: 'Medicali', v: 60, s: '10.0.60.0/24 · ecografi', c: 'var(--p3)', x: 418, y: 16 },
    uff: { t: 'Uffici', v: 30, s: '10.0.30.0/24 · postazioni', c: 'var(--accent)', x: 16, y: 236 },
    osp: { t: 'Ospiti', v: 90, s: '10.0.90.0/24 · solo Internet', c: 'var(--p4)', x: 418, y: 236 },
  };
  const keys = Object.keys(box) as (keyof typeof box)[];
  const edgeOf = (k: keyof typeof box) => rectEdge(box[k].x, box[k].y, BW, BH, FWc);
  const eU = edgeOf('uff');
  const eS = edgeOf('srv');
  const eO = edgeOf('osp');
  const stop = along(FWc, eO, 60);
  // Il relay passa accanto al firewall, su un percorso a parte.
  const relay: Pt[] = [[150, 236], [276, FWc[1]], [150, 90]];
  return (
    <Stage
      still={still}
      w={640}
      h={326}
      label="Un firewall, o uno switch di livello 3, al centro instrada tra le VLAN Server 10, Medicali 60, Uffici 30 e Ospiti 90. Il traffico dagli Uffici ai Server è consentito, quello dagli Ospiti ai Medicali è bloccato. Il relay DHCP inoltra la richiesta di un PC della VLAN 30 al server DHCP della VLAN 10 e la risposta torna indietro."
    >
      {keys.map((k, i) => {
        const p = edgeOf(k);
        return <m.line key={k} className="d-line" x1={p[0]} y1={p[1]} x2={FWc[0]} y2={FWc[1]} variants={draw(0.5 + i * 0.06, 0.45)} />;
      })}
      <m.path d={poly(relay)} fill="none" strokeWidth={1.8} strokeDasharray="5 5" style={{ stroke: 'var(--accent)' }} variants={fade(4.4, 0.6)} />
      <Tip at={along([150, 90], [276, FWc[1]], 2)} deg={(Math.atan2(90 - FWc[1], 150 - 276) * 180) / Math.PI} delay={5.2} />
      {keys.map((k, i) => {
        const b = box[k];
        return (
          <m.g key={k} variants={slide(0.05 + i * 0.06, 0, 10)}>
            <rect className="d-box" x={b.x} y={b.y} width={BW} height={BH} rx={12} style={{ stroke: b.c }} />
            <text className="d-t" x={b.x + 14} y={b.y + 28}>{b.t}</text>
            <rect x={b.x + BW - 78} y={b.y + 12} width={64} height={22} rx={11} style={{ fill: mix(b.c, 30) }} />
            <text className="d-m" x={b.x + BW - 46} y={b.y + 27} textAnchor="middle" style={{ fill: 'var(--text)' }}>
              VLAN {b.v}
            </text>
            <text className="d-s" x={b.x + 14} y={b.y + 54}>{b.s}</text>
          </m.g>
        );
      })}
      <m.g variants={pop(0.35)}>
        <path className="d-fw-hex" d={hexPath(FWc[0], FWc[1], 50)} />
        <text className="d-t" x={FWc[0]} y={FWc[1] - 2} textAnchor="middle">Firewall</text>
        <text className="d-s" x={FWc[0]} y={FWc[1] + 15} textAnchor="middle">o switch L3</text>
      </m.g>
      <m.text className="d-s" x={320} y={234} textAnchor="middle" variants={fade(0.6)}>
        regole tra le VLAN
      </m.text>
      {!still && (
        <>
          <Token pts={[eU, FWc, eS]} delay={1.3} duration={1.6} color="var(--ok)" />
          <Token pts={[eO, stop]} delay={3.2} duration={1.1} color="var(--p4)" />
          <Mover pts={[relay[0], relay[1]]} delay={4.9} duration={0.9}>
            <Chip text="DHCP" c="var(--accent)" />
          </Mover>
          <Mover pts={[relay[1], relay[2]]} delay={5.8} duration={0.9}>
            <Chip text="relay" c="var(--accent)" />
          </Mover>
          <Token pts={[eS, FWc, eU]} delay={6.9} duration={1.5} color="var(--p2)" r={5.5} />
        </>
      )}
      <Verdict at={along(eS, FWc, 20)} ok delay={still ? 0 : 2.9} />
      <Verdict at={along(FWc, eO, 74)} ok={false} delay={still ? 0 : 4.3} />
      <m.g variants={fade(still ? 0 : 3)}>
        <text className="d-t" x={24} y={150}>Uffici → Server</text>
        <text className="d-s d-ok-t" x={24} y={167}>consentito</text>
      </m.g>
      <m.g variants={fade(still ? 0 : 4.4)}>
        <text className="d-t" x={616} y={150} textAnchor="end">Ospiti → Medicali</text>
        <text className="d-s d-crit-t" x={616} y={167} textAnchor="end">bloccato</text>
      </m.g>
      <m.g variants={fade(still ? 0 : 5.6)}>
        <text className="d-t d-acc-t" x={24} y={198}>relay DHCP</text>
        <text className="d-s" x={24} y={215}>dalla VLAN 30 al server</text>
      </m.g>
    </Stage>
  );
}

// ---------------------------------------------------------------- SNMP in sola lettura

function Snmp({ still }: DProps) {
  const pc: Pt = [64, 76];
  const ask: Pt[] = [[92, 64], [404, 64]];
  const back: Pt[] = [[404, 88], [92, 88]];
  const cards = [
    { t: 'Elenco delle VLAN', rows: ['10 Server      30 Uffici', '60 Medicali    90 Ospiti'], x: 16, y: 148 },
    { t: 'Tabella ARP: IP e MAC', rows: ['10.0.30.21 ↔ 3c:58:c2:aa:01:21', '10.0.60.14 ↔ 00:1b:4f:aa:60:14'], x: 328, y: 148 },
    { t: 'Indirizzi MAC per porta', rows: ['porta 12 ← 3c:58:c2:aa:01:21', 'porta 24 ← 00:1b:4f:aa:60:14'], x: 16, y: 240 },
    { t: 'Vicini LLDP', rows: ['porta 48 → SW-PIANO2', 'porta 3  → AP-CORRIDOIO'], x: 328, y: 240 },
  ];
  const arrive = (i: number) => 2.5 + i * 0.6 + 1.1;
  return (
    <Stage
      still={still}
      w={640}
      h={332}
      label="Il PC con Polaris fa domande in sola lettura a un router o a uno switch di livello 3, con la community o l'utente SNMPv3 indicati dal tecnico e non salvati. Il dispositivo risponde con le sue tabelle: l'elenco delle VLAN, la tabella ARP con indirizzi IP e MAC, gli indirizzi MAC visti su ogni porta e i vicini LLDP."
    >
      <m.g variants={pop(0)}>
        <circle cx={pc[0]} cy={pc[1]} r={26} className="d-box" style={{ fill: 'var(--surface)', stroke: 'var(--p0)', strokeWidth: 1.8 }} />
        <Glyph I={Monitor} x={pc[0]} y={pc[1]} s={24} c="var(--p0)" />
      </m.g>
      <m.text className="d-t" x={pc[0]} y={122} textAnchor="middle" variants={fade(0.1)}>
        PC con Polaris
      </m.text>
      <m.g variants={slide(0.1, 10, 0)}>
        <rect className="d-box" x={410} y={42} width={214} height={68} rx={12} style={{ stroke: 'var(--accent)' }} />
        <Glyph I={Network} x={436} y={76} s={24} c="var(--accent)" />
        <text className="d-t" x={458} y={70}>Router o switch L3</text>
        <text className="d-s" x={458} y={88}>risponde con le tabelle</text>
      </m.g>
      <m.path className="d-arrow" d={poly(ask)} variants={draw(0.4, 0.5)} />
      <Tip at={ask[1]} deg={0} delay={0.85} />
      <m.path className="d-line" d={poly(back)} strokeDasharray="4 5" variants={fade(0.5, 0.5)} />
      <Tip at={back[1]} deg={180} delay={0.95} color="var(--text-3)" />
      <m.g variants={pop(0.7)}>
        <rect className="d-pill" x={187} y={30} width={124} height={24} rx={12} style={{ stroke: 'var(--ok)' }} />
        <Glyph I={Lock} x={204} y={42} s={14} c="var(--ok)" />
        <text className="d-s" x={216} y={46} style={{ fill: 'var(--text)' }}>sola lettura</text>
      </m.g>
      <m.g variants={fade(0.9)}>
        <text className="d-s" x={249} y={112} textAnchor="middle">community SNMPv2c o utente SNMPv3</text>
        <text className="d-s" x={249} y={128} textAnchor="middle">indicati dal tecnico, non salvati</text>
      </m.g>
      {!still && (
        <>
          <Mover pts={ask} delay={1.1} duration={1.2}>
            <Chip text="domanda" c="var(--accent)" />
          </Mover>
          {cards.map((c, i) => (
            <Token key={c.t} pts={back} delay={2.5 + i * 0.6} duration={1.1} color="var(--p2)" r={5.5} />
          ))}
        </>
      )}
      {cards.map((c, i) => (
        <m.g key={c.t} variants={pop(still ? 0 : arrive(i))}>
          <rect className="d-box" x={c.x} y={c.y} width={296} height={82} rx={12} />
          <text className="d-t" x={c.x + 14} y={c.y + 24}>{c.t}</text>
          {c.rows.map((r, j) => (
            <text key={r} className="d-mono" x={c.x + 14} y={c.y + 48 + j * 20} style={{ whiteSpace: 'pre' }}>
              {r}
            </text>
          ))}
        </m.g>
      ))}
    </Stage>
  );
}

// ---------------------------------------------------------------- traceroute

function Traceroute({ still }: DProps) {
  const Y = 86;
  const pcX = 44;
  const hops = [
    { x: 150, n: 'router di casa', ip: '192.168.1.1', ms: 1 },
    { x: 260, n: 'operatore', ip: '10.4.18.1', ms: 8 },
    { x: 370, n: 'operatore', ip: '100.64.12.1', ms: 9 },
    { x: 480, n: 'rete di transito', ip: '203.0.113.9', ms: 14 },
    { x: 594, n: 'destinazione', ip: '198.51.100.20', ms: 15 },
  ];
  // Andata e ritorno di ogni sonda, una dopo l'altra.
  const v = 600;
  let t = 1;
  const probes = hops.map((h, i) => {
    const out = Math.max(0.45, (h.x - pcX) / v);
    const p = { start: t, die: t + out, home: t + out * 2 + 0.1, out, i };
    t = p.home + 0.15;
    return p;
  });
  const rowY = (i: number) => 184 + i * 28;
  return (
    <Stage
      still={still}
      w={640}
      h={330}
      label="Traceroute: il PC invia pacchetti con TTL 1, 2, 3, 4 e 5. Ogni router toglie 1 al TTL e, quando arriva a zero, scarta il pacchetto e risponde tempo scaduto; il pacchetto con TTL 5 arriva alla destinazione, che risponde. L'elenco dei router si costruisce così, con tempi di risposta che crescono con la distanza."
    >
      <m.text className="d-s" x={320} y={20} textAnchor="middle" variants={fade(0)}>
        Ogni router toglie 1 al TTL: a zero scarta il pacchetto e risponde «tempo scaduto»
      </m.text>
      <m.line className="d-line" x1={pcX} x2={hops[4].x} y1={Y} y2={Y} variants={draw(0.2, 0.6)} />
      <m.g variants={pop(0.05)}>
        <circle cx={pcX} cy={Y} r={20} className="d-box" style={{ fill: 'var(--surface)', stroke: 'var(--p0)', strokeWidth: 1.8 }} />
        <Glyph I={Monitor} x={pcX} y={Y} s={20} c="var(--p0)" />
      </m.g>
      <m.text className="d-s" x={pcX} y={Y + 38} textAnchor="middle" variants={fade(0.1)}>
        PC
      </m.text>
      {hops.map((h, i) => {
        const dest = i === hops.length - 1;
        const c = dest ? 'var(--ok)' : 'var(--accent)';
        return (
          <g key={h.ip}>
            <m.g variants={pop(0.25 + i * 0.08)}>
              <circle cx={h.x} cy={Y} r={dest ? 20 : 18} className="d-box" style={{ fill: 'var(--surface)', stroke: c, strokeWidth: 1.8 }} />
              <Glyph I={dest ? Server : Router} x={h.x} y={Y} s={dest ? 20 : 18} c={c} />
            </m.g>
            <m.text className="d-s" x={h.x} y={Y + 38} textAnchor="middle" variants={fade(0.3 + i * 0.08)}>
              {dest ? 'destinazione' : `router ${i + 1}`}
            </m.text>
          </g>
        );
      })}
      {!still &&
        probes.map((p) => (
          <g key={p.i}>
            <Mover pts={[[pcX + 20, Y], [hops[p.i].x, Y]]} delay={p.start} duration={p.out}>
              <Chip text={`TTL ${p.i + 1}`} c="var(--accent)" />
            </Mover>
            <Token pts={[[hops[p.i].x, Y], [pcX + 20, Y]]} delay={p.die + 0.1} duration={p.out} color={p.i === hops.length - 1 ? 'var(--ok)' : 'var(--warn)'} r={5} />
          </g>
        ))}
      {probes.map((p) => {
        const dest = p.i === hops.length - 1;
        return (
          <g key={p.i} transform={`translate(${hops[p.i].x} ${Y - 36})`}>
            <m.g variants={pop(still ? 0 : p.die)}>
              <Chip text={dest ? 'risponde' : `TTL ${p.i + 1} scaduto`} c={dest ? 'var(--ok)' : 'var(--warn)'} />
            </m.g>
          </g>
        );
      })}
      <m.g variants={fade(0.6)}>
        <text className="d-h" x={24} y={160}>#</text>
        <text className="d-h" x={52} y={160}>Router</text>
        <text className="d-h" x={330} y={160}>Tempo di risposta</text>
      </m.g>
      {probes.map((p) => {
        const h = hops[p.i];
        const y = rowY(p.i);
        const dest = p.i === hops.length - 1;
        const d = still ? 0 : p.home;
        return (
          <g key={p.i}>
            <m.g variants={fade(d, 0.3)}>
              <text className="d-mono" x={28} y={y + 4}>{p.i + 1}</text>
              <text className="d-s" x={52} y={y + 4} style={{ fill: 'var(--text-2)' }}>{h.n}</text>
              <text className="d-m" x={180} y={y + 4}>{h.ip}</text>
              <text className="d-mono" x={330 + h.ms * 11 + 8} y={y + 4}>{h.ms} ms</text>
            </m.g>
            <Grow x={330} y={y - 7} w={h.ms * 11} h={14} delay={d} dur={0.5} rx={4} style={{ fill: mix(dest ? 'var(--ok)' : 'var(--accent)', 55) }} />
          </g>
        );
      })}
    </Stage>
  );
}

// ---------------------------------------------------------------- velocità USB

function UsbSpeed({ still }: DProps) {
  const port = (y: number, d: number) => (
    <m.g variants={slide(d, -10, 0)}>
      <rect className="d-box" x={24} y={y - 26} width={62} height={62} rx={10} />
      <rect x={33} y={y - 8} width={44} height={18} rx={3} strokeWidth={1.4} style={{ fill: 'var(--surface)', stroke: 'var(--text-2)' }} />
      <rect x={37} y={y - 4} width={36} height={6} rx={1.5} style={{ fill: 'var(--accent)' }} />
      <text className="d-m d-acc-t" x={55} y={y - 13} textAnchor="middle">SS</text>
      <text className="d-s" x={55} y={y + 52} textAnchor="middle">porta USB 3</text>
    </m.g>
  );
  const disk = (y: number, label: string, d: number) => (
    <m.g variants={slide(d, 10, 0)}>
      <Glyph I={HardDrive} x={572} y={y} s={40} c="var(--text)" />
      <text className="d-s" x={572} y={y + 40} textAnchor="middle">{label}</text>
    </m.g>
  );
  const aSS = 74;
  const aU2 = 94;
  const bSS = 214;
  const bU2 = 234;
  return (
    <Stage
      still={still}
      w={640}
      h={318}
      label="Un disco USB 3 collegato a una porta USB 3 usa la parte SuperSpeed del connettore, a 5 Gbit/s. Lo stesso disco collegato con un cavo o un hub USB 2 passa dalla porta USB 2 compagna, contenuta nello stesso connettore, e va a 480 Mbit/s, circa 40 MB/s."
    >
      <m.text className="d-h" x={24} y={24} variants={fade(0)}>
        Disco USB 3 su porta USB 3
      </m.text>
      {port(84, 0.05)}
      <m.line x1={86} x2={548} y1={aSS} y2={aSS} strokeWidth={5} strokeLinecap="round" style={{ stroke: 'var(--accent)' }} variants={draw(0.3, 0.7)} />
      <m.line className="d-line d-faint" x1={86} x2={548} y1={aU2} y2={aU2} variants={draw(0.35, 0.7)} />
      <m.text className="d-m d-acc-t" x={100} y={aSS - 10} variants={fade(0.6)}>
        SuperSpeed
      </m.text>
      <m.text className="d-m" x={100} y={aU2 + 16} variants={fade(0.6)}>
        USB 2, non usata
      </m.text>
      {disk(84, 'disco USB 3', 0.2)}
      <m.g variants={fade(1)}>
        <text className="d-t d-ok-t" x={330} y={aSS - 12} textAnchor="middle">5 Gbit/s</text>
        <text className="d-s" x={330} y={aU2 + 17} textAnchor="middle">centinaia di MB/s</text>
      </m.g>
      {!still && Array.from({ length: 6 }, (_, i) => <Token key={i} pts={[[90, aSS], [544, aSS]]} delay={1.1 + i * 0.22} duration={0.85} color="var(--accent)" r={4.5} />)}

      <m.text className="d-h" x={24} y={166} variants={fade(2.4)}>
        Lo stesso disco con un cavo o un hub USB 2
      </m.text>
      {port(224, 2.45)}
      <m.line className="d-line d-faint" x1={86} x2={282} y1={bSS} y2={bSS} strokeDasharray="3 5" variants={fade(2.6, 0.5)} />
      <m.line x1={86} x2={548} y1={bU2} y2={bU2} strokeWidth={2.4} strokeLinecap="round" style={{ stroke: 'var(--warn)' }} variants={draw(2.65, 0.8)} />
      <m.text className="d-m" x={100} y={bSS - 9} variants={fade(2.9)}>
        SuperSpeed, non collegata
      </m.text>
      <m.text className="d-m d-warn-t" x={100} y={bU2 + 16} variants={fade(2.9)}>
        porta USB 2 compagna
      </m.text>
      <m.g variants={pop(2.75)}>
        <rect className="d-box" x={282} y={198} width={96} height={52} rx={10} style={{ stroke: 'var(--warn)' }} />
        <text className="d-t" x={330} y={221} textAnchor="middle">hub USB 2</text>
        <text className="d-s" x={330} y={239} textAnchor="middle">o cavo USB 2</text>
      </m.g>
      {disk(224, 'lo stesso disco', 2.5)}
      <m.g variants={fade(3.2)}>
        <text className="d-t d-warn-t" x={462} y={bU2 - 12} textAnchor="middle">480 Mbit/s</text>
        <text className="d-s" x={462} y={bU2 + 17} textAnchor="middle">circa 40 MB/s</text>
      </m.g>
      {!still && [0, 1.6].map((o) => <Token key={o} pts={[[90, bU2], [282, bU2], [378, bU2], [544, bU2]]} delay={3.4 + o} duration={3.4} color="var(--warn)" r={4.5} />)}
      <m.text className="d-s" x={320} y={304} textAnchor="middle" variants={fade(3.6)}>
        Nel connettore USB 3 ci sono due porte: SuperSpeed e una USB 2 compagna.
      </m.text>
    </Stage>
  );
}

// ---------------------------------------------------------------- test della RAM

function RamTest({ still }: DProps) {
  const X0 = 24;
  const W = 592;
  const GB = W / 16;
  const segs = [
    { x: X0, w: 6 * GB, c: 'var(--text-3)', pct: 26 },
    { x: X0 + 6 * GB, w: 2 * GB, c: 'var(--warn)', pct: 30 },
    { x: X0 + 8 * GB, w: 8 * GB, c: 'var(--accent)', pct: 26 },
  ];
  const bits = '1010101001010101'.split('');
  const bad = 6;
  const cx = (i: number) => 110 + i * 26;
  return (
    <Stage
      still={still}
      w={640}
      h={300}
      label="La RAM come una barra di 16 GB: 6 GB usati da Windows e dai programmi, che da Windows non si possono provare; 2 GB di riserva lasciati liberi per Windows; 8 GB provati da Polaris, bloccati in RAM. Polaris scrive schemi di bit e li rilegge: un bit che torna diverso è un errore."
    >
      <m.text className="d-h" x={X0} y={24} variants={fade(0)}>
        Memoria RAM · 16 GB
      </m.text>
      {segs.map((s, i) => (
        <Grow key={i} x={s.x} y={36} w={s.w} h={58} delay={0.1 + i * 0.25} dur={0.55} rx={i === 1 ? 0 : 8} style={{ fill: mix(s.c, s.pct), stroke: s.c, strokeWidth: 1.2 }} />
      ))}
      <m.g variants={fade(0.45)}>
        <text className="d-t" x={X0 + 14} y={60}>Windows e programmi</text>
        <text className="d-s" x={X0 + 14} y={80} style={{ fill: 'var(--text-2)' }}>6 GB · non si provano da Windows</text>
      </m.g>
      <m.g variants={fade(0.7)}>
        <text className="d-t" x={X0 + 6 * GB + GB} y={60} textAnchor="middle">riserva</text>
        <text className="d-s" x={X0 + 6 * GB + GB} y={80} textAnchor="middle" style={{ fill: 'var(--text-2)' }}>2 GB</text>
      </m.g>
      <m.g variants={fade(0.95)}>
        <Glyph I={Lock} x={X0 + 8 * GB + 22} y={55} s={16} c="var(--accent-text)" />
        <text className="d-t" x={X0 + 8 * GB + 36} y={60}>provata da Polaris</text>
        <text className="d-s" x={X0 + 8 * GB + 14} y={80} style={{ fill: 'var(--text-2)' }}>8 GB · bloccata in RAM per il test</text>
      </m.g>
      <m.path className="d-line d-faint" d={`M${X0 + 8 * GB} 96 L40 142 M${X0 + W} 96 L600 142`} variants={draw(1.2, 0.4)} />
      <m.g variants={fade(1.3)}>
        <rect className="d-box" x={24} y={142} width={592} height={146} rx={12} />
        <text className="d-h" x={40} y={166}>Schemi di bit scritti e poi riletti</text>
        <text className="d-s" x={40} y={196}>scritto</text>
        <text className="d-s" x={40} y={236}>riletto</text>
      </m.g>
      {bits.map((b, i) => (
        <m.g key={`w${i}`} variants={pop(still ? 0 : 1.6 + i * 0.05)}>
          <rect x={cx(i) - 11} y={178} width={22} height={26} rx={4} style={{ fill: mix('var(--accent)', b === '1' ? 34 : 14) }} />
          <text className="d-bit" x={cx(i)} y={196} textAnchor="middle">{b}</text>
        </m.g>
      ))}
      {bits.map((b, i) => {
        const wrong = i === bad;
        const r = wrong ? (b === '1' ? '0' : '1') : b;
        return (
          <m.g key={`r${i}`} variants={pop(still ? 0 : 2.6 + i * 0.05)}>
            <rect
              x={cx(i) - 11}
              y={218}
              width={22}
              height={26}
              rx={4}
              strokeWidth={wrong ? 2 : 0}
              style={wrong ? { fill: 'var(--crit-bg)', stroke: 'var(--crit)' } : { fill: mix('var(--ok)', r === '1' ? 30 : 12) }}
            />
            <text className="d-bit" x={cx(i)} y={236} textAnchor="middle">{r}</text>
          </m.g>
        );
      })}
      <m.g variants={fade(still ? 0 : 3.6)}>
        <line x1={cx(bad)} x2={cx(bad)} y1={246} y2={256} strokeWidth={1.2} style={{ stroke: 'var(--crit)' }} />
        <text className="d-s d-crit-t" x={cx(bad) - 14} y={272}>scritto 1, riletto 0: un errore della memoria</text>
      </m.g>
      <m.g variants={fade(still ? 0 : 3.4)}>
        <text className="d-s d-ok-t" x={548} y={236}>gli altri</text>
        <text className="d-s d-ok-t" x={548} y={252}>coincidono</text>
      </m.g>
    </Stage>
  );
}

// ---------------------------------------------------------------- fasi dell'avvio

function BootPhases({ still }: DProps) {
  const X0 = 200;
  const K = (616 - X0) / 90;
  const tx = (s: number) => X0 + s * K;
  const rows = [
    { t: 'Firmware', s: 'BIOS o UEFI', from: 0, to: 9, c: 'var(--p2)' },
    { t: 'Fino al desktop', s: 'driver e servizi', from: 9, to: 47, c: 'var(--accent)' },
    { t: 'Dopo l\'accesso', s: 'programmi all\'avvio', from: 47, to: 90, c: 'var(--p4)' },
  ];
  const slow = [
    { row: 1, from: 22, to: 33, n: '1', t: 'servizio di aggiornamento', s: '11 secondi in più del solito' },
    { row: 2, from: 62, to: 80, n: '2', t: 'programma di sincronizzazione', s: '18 secondi in più del solito' },
  ];
  const Y = (i: number) => 42 + i * 46;
  return (
    <Stage
      still={still}
      w={640}
      h={276}
      label="Un avvio di Windows su una linea del tempo: il firmware, BIOS o UEFI, dura 9 secondi; l'avvio di Windows fino al desktop, con driver e servizi, 38 secondi; dopo l'accesso i programmi all'avvio richiedono altri 43 secondi. Windows segnala come lenti un servizio di aggiornamento e un programma di sincronizzazione."
    >
      <m.text className="d-h" x={24} y={22} variants={fade(0)}>
        Un avvio di Windows
      </m.text>
      <m.text className="d-m" x={616} y={22} textAnchor="end" variants={fade(0)}>
        totale 90 secondi
      </m.text>
      {rows.map((r, i) => (
        <g key={r.t}>
          <m.g variants={slide(0.1 + i * 0.5, -8, 0)}>
            <text className="d-t" x={24} y={Y(i) + 10}>{r.t}</text>
            <text className="d-s" x={24} y={Y(i) + 27}>{r.s}</text>
          </m.g>
          <Grow x={tx(r.from)} y={Y(i)} w={(r.to - r.from) * K} h={26} delay={0.2 + i * 0.5} dur={0.5} style={{ fill: mix(r.c, 30), stroke: r.c, strokeWidth: 1.2 }} />
          <m.text className="d-mono" x={r.to - r.from < 15 ? tx(r.to) + 8 : tx(r.to) - 8} y={Y(i) + 18} textAnchor={r.to - r.from < 15 ? 'start' : 'end'} variants={fade(0.55 + i * 0.5)}>
            {r.to - r.from} s
          </m.text>
        </g>
      ))}
      {slow.map((s, i) => (
        <g key={s.n}>
          <Grow x={tx(s.from)} y={Y(s.row) + 3} w={(s.to - s.from) * K} h={20} delay={1.9 + i * 0.4} dur={0.35} rx={4} style={{ fill: 'var(--warn-bg)', stroke: 'var(--warn)', strokeWidth: 1.4 }} />
          <g transform={`translate(${tx(s.from) + 12} ${Y(s.row) + 13})`}>
            <m.g variants={pop(2.2 + i * 0.4)}>
              <circle r={8} strokeWidth={1.4} style={{ fill: 'var(--surface)', stroke: 'var(--warn)' }} />
              <text y={3.8} textAnchor="middle" style={{ fill: 'var(--warn)', font: '700 11px var(--font)' }}>
                {s.n}
              </text>
            </m.g>
          </g>
        </g>
      ))}
      <m.g variants={fade(0.4)}>
        <line className="d-axis" x1={X0} x2={616} y1={180} y2={180} />
        {[0, 30, 60, 90].map((s) => (
          <g key={s}>
            <line className="d-axis" x1={tx(s)} x2={tx(s)} y1={180} y2={185} />
            <text className="d-m" x={tx(s)} y={198} textAnchor={s === 0 ? 'start' : s === 90 ? 'end' : 'middle'}>
              {s} s
            </text>
          </g>
        ))}
      </m.g>
      {slow.map((s, i) => (
        <m.g key={s.n} variants={slide(2.5 + i * 0.4, 0, 8)}>
          <g transform={`translate(${32 + i * 304} 230)`}>
            <circle r={9} strokeWidth={1.4} style={{ fill: 'var(--surface)', stroke: 'var(--warn)' }} />
            <text y={4} textAnchor="middle" style={{ fill: 'var(--warn)', font: '700 11px var(--font)' }}>
              {s.n}
            </text>
          </g>
          <text className="d-t" x={48 + i * 304} y={226}>{s.t}</text>
          <text className="d-s d-warn-t" x={48 + i * 304} y={244}>{s.s}</text>
        </m.g>
      ))}
      <m.text className="d-s" x={24} y={268} variants={fade(3.3)}>
        Windows annota i componenti che hanno rallentato l'avvio rispetto al solito.
      </m.text>
    </Stage>
  );
}

// ---------------------------------------------------------------- percorso di una stampa

function Doc({ c = 'var(--text-2)', fill = 'var(--surface)', w = 1.4 }: { c?: string; fill?: string; w?: number }) {
  return (
    <g>
      <path d="M-7 -9 H3 L7 -5 V9 H-7 Z" strokeWidth={w} strokeLinejoin="round" style={{ fill, stroke: c }} />
      <path d="M-4 -2 H4 M-4 2 H4 M-4 6 H2" strokeWidth={1} style={{ stroke: c }} />
    </g>
  );
}

function PrintPath({ still }: DProps) {
  const Y = 70;
  const BW = 132;
  const bx = [16, 175, 334, 492];
  const cxs = bx.map((x) => x + BW / 2);
  const slots = [206, 241, 276];
  const port: Pt = [cxs[2], Y];
  const inP: Pt = [102, Y];
  const head: Pt = [slots[2], Y];
  const toPrinter: Pt = [536, Y];
  const titles = [
    { t: 'Programma', s: 'Word, posta, PDF' },
    { t: 'Coda di stampa', s: 'servizio di stampa' },
    { t: 'Porta', s: 'verso la stampante' },
    { t: 'Stampante', s: 'comunica lo stato' },
  ];
  return (
    <Stage
      still={still}
      w={640}
      h={240}
      label="Il percorso di una stampa: il programma consegna il lavoro alla coda del servizio di stampa di Windows, che lo manda alla porta, USB, rete TCP/IP o WSD, e da lì alla stampante. La stampante comunica carta esaurita: il lavoro in testa alla coda si ferma e blocca quelli che arrivano dopo."
    >
      {bx.map((x, i) => (
        <m.g key={x} variants={slide(0.05 + i * 0.1, 0, 10)}>
          <rect className="d-box" x={x} y={30} width={BW} height={120} rx={12} />
          <text className="d-t" x={x + BW / 2} y={120} textAnchor="middle">{titles[i].t}</text>
          <text className="d-s" x={x + BW / 2} y={138} textAnchor="middle">{titles[i].s}</text>
        </m.g>
      ))}
      <m.g variants={fade(0.2)}>
        <Glyph I={FileText} x={cxs[0]} y={Y} s={30} c="var(--text-2)" />
        {slots.map((s) => (
          <rect key={s} x={s - 14} y={Y - 13} width={28} height={26} rx={5} strokeDasharray="3 3" strokeWidth={1} style={{ fill: 'none', stroke: 'var(--line-strong)' }} />
        ))}
        <Glyph I={Printer} x={cxs[3]} y={Y} s={30} c="var(--text-2)" />
      </m.g>
      <m.g variants={fade(0.35)}>
        {['USB', 'rete TCP/IP', 'WSD'].map((p, i) => (
          <g key={p}>
            <rect x={cxs[2] - 48} y={Y - 32 + i * 22} width={96} height={18} rx={9} strokeWidth={1} style={i === 1 ? { fill: mix('var(--accent)', 30), stroke: 'var(--accent)' } : { fill: 'var(--surface)', stroke: 'var(--line-strong)' }} />
            <text className="d-m" x={cxs[2]} y={Y - 19 + i * 22} textAnchor="middle" style={{ fill: i === 1 ? 'var(--text)' : undefined }}>
              {p}
            </text>
          </g>
        ))}
      </m.g>
      {[0, 1, 2].map((i) => (
        <g key={i}>
          <m.line className="d-arrow" x1={bx[i] + BW + 2} x2={bx[i + 1] - 4} y1={90} y2={90} variants={draw(0.5 + i * 0.1, 0.3)} />
          <Tip at={[bx[i + 1] - 2, 90]} deg={0} delay={0.75 + i * 0.1} />
        </g>
      ))}
      {!still && (
        <>
          <Mover pts={[inP, head]} delay={1} duration={0.9}>
            <Doc c="var(--accent)" />
          </Mover>
          <Mover pts={[head, port, toPrinter]} delay={2.05} duration={1.1}>
            <Doc c="var(--accent)" />
          </Mover>
          <Mover pts={[inP, head]} delay={4.4} duration={0.9}>
            <Doc c="var(--crit)" />
          </Mover>
          <Mover pts={[inP, [slots[1], Y]]} delay={5.6} duration={0.8}>
            <Doc c="var(--accent)" />
          </Mover>
          <Mover pts={[inP, [slots[0], Y]]} delay={6.6} duration={0.7}>
            <Doc c="var(--accent)" />
          </Mover>
        </>
      )}
      <g transform={`translate(${slots[2]} ${Y})`}>
        <m.g variants={pop(still ? 0 : 5.3)}>
          <Doc c="var(--crit)" fill="var(--crit-bg)" w={1.8} />
        </m.g>
      </g>
      <g transform={`translate(${slots[2] + 12} ${Y - 15})`}>
        <m.g variants={pop(still ? 0 : 5.45)}>
          <circle r={7.5} strokeWidth={1.5} style={{ fill: 'var(--surface)', stroke: 'var(--crit)' }} />
          <text y={3.6} textAnchor="middle" style={{ fill: 'var(--crit)', font: '700 10px var(--font)' }}>
            !
          </text>
        </m.g>
      </g>
      {[1, 0].map((s, i) => (
        <g key={s} transform={`translate(${slots[s]} ${Y})`}>
          <m.g variants={pop(still ? 0 : 6.4 + i * 1)}>
            <Doc />
          </m.g>
        </g>
      ))}
      <m.g variants={pop(still ? 0 : 3.3)}>
        <rect x={498} y={160} width={120} height={26} rx={13} strokeWidth={1.2} style={{ fill: 'var(--warn-bg)', stroke: 'var(--warn)' }} />
        <text className="d-s" x={558} y={177} textAnchor="middle" style={{ fill: 'var(--text)' }}>
          carta esaurita
        </text>
      </m.g>
      <m.path d={`M498 173 H${cxs[1]} V154`} fill="none" strokeWidth={1.4} strokeDasharray="4 4" style={{ stroke: 'var(--warn)' }} variants={fade(still ? 0 : 3.6, 0.5)} />
      <Tip at={[cxs[1], 152]} deg={-90} delay={still ? 0 : 4.1} color="var(--warn)" />
      <m.text className="d-m d-warn-t" x={420} y={167} textAnchor="middle" variants={fade(still ? 0 : 3.9)}>
        stato
      </m.text>
      <m.g variants={fade(still ? 0 : 7.4)}>
        <rect x={110} y={196} width={262} height={28} rx={14} strokeWidth={1.2} style={{ fill: 'var(--crit-bg)', stroke: 'var(--crit)' }} />
        <text className="d-s" x={241} y={214} textAnchor="middle" style={{ fill: 'var(--text)' }}>
          un lavoro fermo in testa blocca la coda
        </text>
      </m.g>
    </Stage>
  );
}

// ---------------------------------------------------------------- Memtest86+ da chiavetta

function MemtestUsb({ still }: DProps) {
  const W = 104;
  const xs = [16, 142, 268, 394, 520];
  const steps = [
    { I: Disc3, t: 'memtest.iso', s: ['immagine di', 'Memtest86+'] },
    { I: AppWindow, t: 'Rufus', s: ['scrive in', 'modalità DD'] },
    { I: Usb, t: 'Chiavetta', s: ['il contenuto', 'si cancella'] },
    { I: Power, t: 'Menu di avvio', s: ['F12, F11, F8', 'o Esc'] },
    { I: MemoryStick, t: 'Memtest86+', s: ['prova la RAM', 'fuori da Windows'] },
  ];
  const cx = (i: number) => xs[i] + W / 2;
  return (
    <Stage
      still={still}
      w={640}
      h={276}
      label="Preparare Memtest86+: il file memtest.iso si scrive con Rufus in modalità immagine DD su una chiavetta, che viene cancellata. Il PC si avvia dalla chiavetta con il menu di avvio e Memtest86+ prova la RAM fuori da Windows, un passaggio dopo l'altro. L'Avvio protetto può rifiutare la chiavetta."
    >
      {steps.map((s, i) => (
        <m.g key={s.t} variants={slide(0.05 + i * 0.12, 0, 10)}>
          <rect className="d-box" x={xs[i]} y={24} width={W} height={124} rx={12} style={i === 4 ? { stroke: 'var(--accent)' } : undefined} />
          <Glyph I={s.I} x={cx(i)} y={56} s={28} c={i === 4 ? 'var(--accent)' : 'var(--text-2)'} />
          <text className="d-t" x={cx(i)} y={98} textAnchor="middle">{s.t}</text>
          <text className="d-s" x={cx(i)} y={118} textAnchor="middle">{s.s[0]}</text>
          <text className="d-s" x={cx(i)} y={134} textAnchor="middle">{s.s[1]}</text>
        </m.g>
      ))}
      {[0, 1, 2, 3].map((i) => (
        <g key={i}>
          <m.line className="d-arrow" x1={xs[i] + W + 3} x2={xs[i + 1] - 6} y1={56} y2={56} variants={draw(0.7 + i * 0.1, 0.2)} />
          <Tip at={[xs[i + 1] - 3, 56]} deg={0} delay={0.85 + i * 0.1} />
        </g>
      ))}
      {!still && (
        <>
          <Token pts={[[cx(0), 56], [cx(1), 56], [cx(2), 56]]} delay={1.3} duration={1.4} color="var(--accent)" />
          <Token pts={[[cx(2), 56], [cx(3), 56], [cx(4), 56]]} delay={2.9} duration={1.4} color="var(--ok)" />
        </>
      )}
      <m.g variants={fade(still ? 0 : 4.3)}>
        <rect className="d-box" x={330} y={166} width={294} height={96} rx={12} style={{ stroke: 'var(--accent)' }} />
        <text className="d-t" x={346} y={190}>Memtest86+ al lavoro</text>
        <rect x={346} y={202} width={262} height={12} rx={6} style={{ fill: 'var(--surface-3)' }} />
      </m.g>
      <Grow x={346} y={202} w={262} h={12} delay={still ? 0 : 4.5} dur={still ? 0.01 : 2.4} rx={6} style={{ fill: 'var(--accent)' }} />
      <m.g variants={fade(still ? 0 : 6.9)}>
        <text className="d-s d-ok-t" x={346} y={234}>passaggio 1 completato · 0 errori</text>
        <text className="d-s" x={346} y={252}>meglio lasciarlo lavorare tutta la notte</text>
      </m.g>
      <m.g variants={fade(still ? 0 : 1)}>
        <rect x={16} y={166} width={300} height={96} rx={12} strokeWidth={1.2} style={{ fill: 'var(--warn-bg)', stroke: 'var(--warn)' }} />
        <Glyph I={ShieldAlert} x={36} y={186} s={18} c="var(--warn)" />
        <text className="d-t" x={52} y={191}>Avvio protetto</text>
        <text className="d-s" x={30} y={214} style={{ fill: 'var(--text-2)' }}>può rifiutare la chiavetta: si disattiva</text>
        <text className="d-s" x={30} y={232} style={{ fill: 'var(--text-2)' }}>solo per il test, poi si riattiva.</text>
        <text className="d-s" x={30} y={250} style={{ fill: 'var(--text-2)' }}>Con BitLocker serve la chiave di ripristino.</text>
      </m.g>
    </Stage>
  );
}

const DIAGRAMS: Record<DiagramId, (p: DProps) => JSX.Element> = {
  osi: Osi,
  subnet: Subnet,
  dhcp: Dhcp,
  channels24: Channels24,
  roaming: Roaming,
  vlan: Vlan,
  clinic: Clinic,
  netmap: NetmapD,
  lldp: Lldp,
  intervlan: InterVlan,
  snmp: Snmp,
  traceroute: Traceroute,
  usbspeed: UsbSpeed,
  ramtest: RamTest,
  bootphases: BootPhases,
  printpath: PrintPath,
  memtestusb: MemtestUsb,
};

/** Identificativi dei disegni disponibili (per i controlli su guide e videoguide). */
export const DIAGRAM_IDS = Object.keys(DIAGRAMS) as DiagramId[];

export function Diagram({ id, caption }: { id: DiagramId; caption: string }) {
  const reduce = useReducedMotion();
  const [run, setRun] = useState(0);
  const D = DIAGRAMS[id];
  // Sugli schermi stretti lo schema scorre in orizzontale: allora deve poter
  // ricevere il focus, per scorrerlo anche con la tastiera.
  const stage = useRef<HTMLDivElement>(null);
  const [scrolls, setScrolls] = useState(false);
  useEffect(() => {
    const el = stage.current;
    if (!el || typeof ResizeObserver === 'undefined') return;
    const check = () => setScrolls(el.scrollWidth > el.clientWidth + 1);
    check();
    const ro = new ResizeObserver(check);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  return (
    <figure className="diagram">
      <div className="diagram-stage" ref={stage} {...(scrolls ? { tabIndex: 0, role: 'group', 'aria-label': `Schema che scorre in orizzontale: ${caption}` } : {})}>
        <D key={run} still={!!reduce} />
      </div>
      <figcaption>
        <span>{caption}</span>
        {!reduce && (
          <button className="btn small" onClick={() => setRun((r) => r + 1)} aria-label="Riproduci l'animazione del diagramma">
            <RotateCcw size={14} aria-hidden /> Riproduci
          </button>
        )}
      </figcaption>
    </figure>
  );
}
