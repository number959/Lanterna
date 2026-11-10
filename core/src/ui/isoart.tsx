import type { ReactNode } from 'react';
import type { DeviceKind } from '../engine';
import './isoart.css';
import { Box, face, iso, line, poly, rect } from './isoprims';
import type { BoxProps, IsoArt, P3 } from './isoprims';
export { iso } from './isoprims';
import { NET_ART } from './isoart-net';
import { HOME_ART } from './isoart-home';

// Dispositivi in prospettiva isometrica (30°), disegnati a linee su fondo scuro
// come negli schemi tecnici: tre facce per ogni volume (sopra più chiara, a
// sinistra media, a destra più scura), contorni nel colore corrente e
// dettagli (tasti, porte, spie) appoggiati sulle facce. Il punto (0, 0) è il
// centro dell'appoggio a terra: il dispositivo "sta in piedi" sul punto del
// nodo. Unità in pixel a scala 1; il disegno occupa circa 90 × 80 px.
//
// Assi: x scende verso destra, y scende verso sinistra, z sale.

// ---------------------------------------------------------------- dispositivi

function Laptop() {
  const base: BoxProps = { x: -21, y: -15, w: 42, d: 30, h: 2.6 };
  const keys: ReactNode[] = [];
  // Tastiera: tre file di tasti sulla parte posteriore del piano.
  for (let r = 0; r < 4; r++)
    for (let c = 0; c < 10; c++) keys.push(rect(face.top, base, 5 + c * 3.3, 3 + r * 3.1, 7.6 + c * 3.3, 5.4 + r * 3.1, 'iso-key', `k${r}-${c}`));
  const H = 2.6;
  // Schermo inclinato all'indietro, con lo spessore visibile a destra.
  const s0: P3 = [-20, -15, H];
  const s1: P3 = [20, -15, H];
  const s2: P3 = [20, -21, H + 27];
  const s3: P3 = [-20, -21, H + 27];
  const inset = (a: number, b: number): P3 => [-20 + a, -15 - (6 * b) / 27, H + b];
  return (
    <>
      <Box {...base} />
      {keys}
      {rect(face.top, base, 15, 19, 27, 26, 'iso-pad')}
      {poly([s1, [21.6, -15, H], [21.6, -21, H + 27], s2], 'iso-r')}
      {poly([s0, s1, s2, s3], 'iso-l')}
      {poly([inset(2.2, 2), inset(37.8, 2), inset(37.8, 25), inset(2.2, 25)], 'iso-screen')}
      {line(inset(2.2, 21.5), inset(37.8, 21.5))}
      {line(inset(2.2, 18.5), inset(37.8, 18.5), 'iso-d faint')}
    </>
  );
}

function Router() {
  const b: BoxProps = { x: -17, y: -13, w: 34, d: 26, h: 12 };
  const top = face.top;
  return (
    <>
      {/* Antenna dietro, prima del corpo. */}
      {line([10, -9, 12], [10, -9, 36], 'iso-ant')}
      <Box {...b} />
      {[0, 1, 2, 3].map((i) => rect(top, b, 6 + i * 5, 4, 9 + i * 5, 6.4, 'iso-led', i))}
      {(() => {
        const [cx, cy] = iso(10, -9, 37.5);
        return <circle cx={cx.toFixed(2)} cy={cy.toFixed(2)} r={2.6} className="iso-ball" />;
      })()}
      {/* Sinistra: tasto di accensione e una porta; destra: la fila delle porte. */}
      {(() => {
        const [cx, cy] = iso(...face.left(b, 6, 6));
        return <circle cx={cx.toFixed(2)} cy={cy.toFixed(2)} r={2.4} className="iso-d" />;
      })()}
      {rect(face.left, b, 11, 3.5, 16, 8.5, 'iso-port')}
      {rect(face.right, b, 4, 3.5, 22, 8.5, 'iso-port')}
    </>
  );
}

export function ServerStack({ units = 3, w = 28, d = 28 }: { units?: number; w?: number; d?: number }) {
  const out: ReactNode[] = [];
  for (let i = 0; i < units; i++) {
    const b: BoxProps = { x: -w / 2, y: -d / 2, z: i * 10, w, d, h: 8 };
    out.push(
      <g key={i}>
        <Box {...b} />
        {rect(face.left, b, 3, 2.4, w - 6, 5.2, 'iso-strip')}
        {rect(face.right, b, 3, 3, 9, 5, 'iso-port')}
        {(() => {
          const [cx, cy] = iso(...face.right(b, d - 5, 4));
          return <circle cx={cx.toFixed(2)} cy={cy.toFixed(2)} r={1.2} className="iso-ball" />;
        })()}
      </g>,
    );
  }
  const topBox: BoxProps = { x: -w / 2, y: -d / 2, z: (units - 1) * 10, w, d, h: 8 };
  out.push(<g key="t">{rect(face.top, topBox, 6, 6, w - 6, d - 6, 'iso-inset')}</g>);
  return <>{out}</>;
}

function Cloud() {
  // Internet: una nuvola piatta con il globo, come un'insegna sopra il terreno.
  return (
    <g transform="translate(0 -26)">
      <path
        d="M-30 14 Q-44 14 -44 2 Q-44 -9 -32 -10 Q-30 -26 -12 -27 Q0 -27 6 -18 Q12 -22 18 -20 Q30 -16 29 -6 Q40 -4 40 5 Q39 14 30 14 Z"
        className="iso-cloud"
      />
      <circle cx="-2" cy="-1" r="11" className="iso-d" />
      <path d="M-13 -1 H9 M-2 -12 Q-9 -1 -2 10 Q5 -1 -2 -12 M-11 -6.5 H7 M-11 4.5 H7" className="iso-d" />
    </g>
  );
}

/** Volume generico con un segno sulla faccia: per i tipi non ancora disegnati. */
export function Generic({ mark = '?' }: { mark?: string }) {
  const b: BoxProps = { x: -14, y: -14, w: 28, d: 28, h: 18 };
  const [cx, cy] = iso(...face.left(b, 14, 9));
  return (
    <>
      <Box {...b} />
      <text x={cx.toFixed(2)} y={(cy + 4).toFixed(2)} textAnchor="middle" className="iso-mark">
        {mark}
      </text>
    </>
  );
}

const ART: Partial<Record<DeviceKind, IsoArt>> = {
  laptop: { draw: Laptop, top: 52 },
  router: { draw: Router, top: 46 },
  server: { draw: () => <ServerStack />, top: 48 },
  internet: { draw: Cloud, top: 56 },
  ...NET_ART,
  ...HOME_ART,
};

/** Altezza del disegno sopra il punto a terra (scala 1), per mettere etichette e pacchetti. */
export const isoTop = (kind: DeviceKind) => ART[kind]?.top ?? 40;

export function IsoDevice({ kind, x = 0, y = 0, scale = 1 }: { kind: DeviceKind; x?: number; y?: number; scale?: number }) {
  const art = ART[kind];
  return (
    <g transform={`translate(${x.toFixed(1)} ${y.toFixed(1)}) scale(${scale})`} className="iso" aria-hidden>
      {art ? art.draw() : <Generic />}
    </g>
  );
}
