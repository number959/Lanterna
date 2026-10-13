import { RotateCcw } from 'lucide-react';
import { m, useReducedMotion } from 'motion/react';
import type { Variants } from 'motion/react';
import { useState } from 'react';
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

/** Pacchetto che percorre una spezzata a velocità costante. */
function Token({ pts, delay, duration, color, r = 6.5 }: { pts: Pt[]; delay: number; duration: number; color: string; r?: number }) {
  const seg = pts.slice(1).map((p, i) => Math.hypot(p[0] - pts[i][0], p[1] - pts[i][1]));
  const total = seg.reduce((a, b) => a + b, 0) || 1;
  let acc = 0;
  const times = [0, ...seg.map((d) => (acc += d) / total)];
  const move = { delay, duration, times, ease: 'linear' as const };
  return (
    <m.circle
      r={r}
      cx={0}
      cy={0}
      style={{ fill: color }}
      className="d-token"
      variants={{
        hidden: { opacity: 0, x: pts[0][0], y: pts[0][1] },
        show: {
          opacity: [0, 1, 1, 0],
          x: pts.map((p) => p[0]),
          y: pts.map((p) => p[1]),
          transition: { x: move, y: move, opacity: { delay, duration, times: [0, 0.06, 0.9, 1] } },
        },
      }}
    />
  );
}

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

const DIAGRAMS: Record<DiagramId, (p: DProps) => JSX.Element> = {
  osi: Osi,
  subnet: Subnet,
  dhcp: Dhcp,
  channels24: Channels24,
  roaming: Roaming,
  vlan: Vlan,
  clinic: Clinic,
};

export function Diagram({ id, caption }: { id: DiagramId; caption: string }) {
  const reduce = useReducedMotion();
  const [run, setRun] = useState(0);
  const D = DIAGRAMS[id];
  return (
    <figure className="diagram">
      <div className="diagram-stage">
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
