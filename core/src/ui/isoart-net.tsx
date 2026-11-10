import type { ReactNode } from 'react';
import type { DeviceKind } from '../engine';
import './isoart-net.css';
import { Box, disc, face, iso, line, poly } from './isoprims';
import type { BoxProps, IsoArt, P3 } from './isoprims';

// Dispositivi di rete in prospettiva isometrica: firewall, switch, access point, NAS, macchine virtuali, telecamere, rete dell'operatore.
// Ogni disegno usa le primitive di isoprims.tsx (Box, face, rect, line, poly, disc, iso)
// e le classi di isoart.css (più i dettagli di isoart-net.css); il punto (0, 0) è il centro dell'appoggio a terra.
// Ordine del pittore: prima le parti lontane (x + y piccoli, in basso), poi le vicine.

// ------------------------------------------------------------------ aiuti

/** Punto di una faccia in coordinate locali (u, v). */
type Pt = (u: number, v: number) => P3;
type FaceFn = (b: BoxProps, u: number, v: number) => P3;

const n2 = (n: number) => n.toFixed(2);
const on = (f: FaceFn, b: BoxProps): Pt => (u, v) => f(b, u, v);

/** Rettangolo (u0..u1, v0..v1) su una faccia qualsiasi, anche inclinata. */
const quad = (p: Pt, u0: number, v0: number, u1: number, v1: number, cls: string, key?: string | number) =>
  poly([p(u0, v0), p(u1, v0), p(u1, v1), p(u0, v1)], cls, key);

/** Cerchio di raggio r su una faccia: diventa l'ellisse giusta per la prospettiva. */
function ring(p: Pt, cu: number, cv: number, r: number, cls: string, key?: string | number) {
  const list: P3[] = [];
  for (let i = 0; i < 32; i++) {
    const a = (i / 32) * Math.PI * 2;
    list.push(p(cu + r * Math.cos(a), cv + r * Math.sin(a)));
  }
  return poly(list, cls, key);
}

/** Pallino nello spazio dello schermo, centrato su un punto 3D. */
function dot(q: P3, r: number, cls = 'iso-ball', key?: string | number) {
  const [cx, cy] = iso(...q);
  return <circle key={key} cx={n2(cx)} cy={n2(cy)} r={r} className={cls} />;
}

/** Arco piatto nello spazio dello schermo, da a0 ad a1 gradi (0 = destra, 90 = giù, -90 = su). */
function arc(cx: number, cy: number, r: number, a0: number, a1: number, cls: string, key?: string | number) {
  const rad = (a: number) => (a * Math.PI) / 180;
  const x0 = cx + r * Math.cos(rad(a0));
  const y0 = cy + r * Math.sin(rad(a0));
  const x1 = cx + r * Math.cos(rad(a1));
  const y1 = cy + r * Math.sin(rad(a1));
  const large = Math.abs(a1 - a0) > 180 ? 1 : 0;
  const sweep = a1 > a0 ? 1 : 0;
  return <path key={key} d={`M${n2(x0)} ${n2(y0)} A${n2(r)} ${n2(r)} 0 ${large} ${sweep} ${n2(x1)} ${n2(y1)}`} className={cls} />;
}

/** Fianco di un cilindro verticale (da z0 a z1, raggio r), da disegnare prima del disco di sopra. */
function cylSide(x: number, y: number, z0: number, z1: number, r: number, cls: string) {
  const [cx, yb] = iso(x, y, z0);
  const [, yt] = iso(x, y, z1);
  const rx = r * 1.2247;
  const ry = r * 0.7071;
  return (
    <path
      d={`M${n2(cx - rx)} ${n2(yt)} L${n2(cx - rx)} ${n2(yb)} A${n2(rx)} ${n2(ry)} 0 0 0 ${n2(cx + rx)} ${n2(yb)} L${n2(cx + rx)} ${n2(yt)} Z`}
      className={cls}
    />
  );
}

/** Parallelepipedo inclinato in avanti (beccheggio attorno all'asse x): il davanti (+y) scende. */
interface OBox {
  o: P3;
  w: number;
  d: number;
  h: number;
  /** Inclinazione in radianti. */
  pitch: number;
}

function oframe(b: OBox) {
  const c = Math.cos(b.pitch);
  const s = Math.sin(b.pitch);
  const at = (x: number, y: number, z: number): P3 => [b.o[0] + x, b.o[1] + y * c + z * s, b.o[2] - y * s + z * c];
  return {
    at,
    /** Faccia davanti (y = d): u lungo x, v lungo l'altezza. */
    left: ((u, v) => at(u, b.d, v)) as Pt,
    /** Fianco destro (x = w): u lungo la lunghezza, v lungo l'altezza. */
    right: ((u, v) => at(b.w, u, v)) as Pt,
    /** Sopra (z = h): u lungo x, v lungo la lunghezza. */
    top: ((u, v) => at(u, v, b.h)) as Pt,
  };
}

function OBoxShape({ b, tone = '' }: { b: OBox; tone?: string }) {
  const { at } = oframe(b);
  const { w, d, h } = b;
  return (
    <>
      {poly([at(w, 0, 0), at(w, d, 0), at(w, d, h), at(w, 0, h)], `iso-r ${tone}`)}
      {poly([at(0, d, 0), at(w, d, 0), at(w, d, h), at(0, d, h)], `iso-l ${tone}`)}
      {poly([at(0, 0, h), at(w, 0, h), at(w, d, h), at(0, d, h)], `iso-t ${tone}`)}
    </>
  );
}

// ------------------------------------------------------------------ firewall

/**
 * Mattoni su una faccia: file orizzontali e giunti sfalsati, misurati dallo
 * spigolo davanti (u = len) così il muro "gira" l'angolo senza interruzioni.
 */
function bricks(p: Pt, len: number, h: number, rows: number, brick: number, key: string) {
  const rh = h / rows;
  const out: ReactNode[] = [];
  for (let r = 1; r < rows; r++) out.push(line(p(0, r * rh), p(len, r * rh), 'iso-d faint isn-brick', `${key}h${r}`));
  for (let r = 0; r < rows; r++) {
    for (let k = len - (r % 2 ? brick / 2 : brick); k > 0.8; k -= brick)
      out.push(line(p(k, r * rh), p(k, (r + 1) * rh), 'iso-d faint isn-brick', `${key}v${r}-${k.toFixed(1)}`));
  }
  return out;
}

function Firewall() {
  const b: BoxProps = { x: -20, y: -13, w: 40, d: 26, h: 16 };
  // Scudo appoggiato sopra: s verso destra sullo schermo, t verso il basso.
  const cz = b.h;
  const k = Math.SQRT1_2;
  const sp = (s: number, t: number): P3 => [-1 + (s + t) * k, 1 + (t - s) * k, cz];
  const shield: P3[] = [sp(-7, -6.5), sp(0, -8), sp(7, -6.5), sp(7, 0), sp(5, 4.5), sp(0, 8.5), sp(-5, 4.5), sp(-7, 0)];
  const inner: P3[] = [sp(-4.4, -4.2), sp(0, -5.2), sp(4.4, -4.2), sp(4.4, -0.2), sp(3, 2.6), sp(0, 5.4), sp(-3, 2.6), sp(-4.4, -0.2)];
  return (
    <>
      <Box {...b} />
      {bricks(on(face.left, b), b.w, b.h, 4, 8, 'l')}
      {bricks(on(face.right, b), b.d, b.h, 4, 8, 'r')}
      {poly(shield, 'iso-inset isn-emblem')}
      {poly(inner, 'iso-d faint')}
      {/* Spie lungo il bordo davanti a sinistra. */}
      {[0, 1, 2].map((i) => quad(on(face.top, b), 3 + i * 4, b.d - 3.6, 5.4 + i * 4, b.d - 2, 'iso-led', `led${i}`))}
    </>
  );
}

// ------------------------------------------------------------------ switch

function Switch() {
  const b: BoxProps = { x: -26, y: -12, w: 52, d: 24, h: 9 };
  const L = on(face.left, b);
  const R = on(face.right, b);
  const T = on(face.top, b);
  const n = 11;
  const pitch = 3.5;
  const out: ReactNode[] = [];
  // Due file di porte sul davanti, con le spie sopra ogni colonna.
  for (let i = 0; i < n; i++) {
    const u = 3.5 + i * pitch;
    out.push(quad(L, u, 1.3, u + 2.7, 3.9, 'iso-port isn-port', `p0-${i}`));
    out.push(quad(L, u, 5, u + 2.7, 7.6, 'iso-port isn-port', `p1-${i}`));
    out.push(quad(T, u + 0.6, b.d - 2.4, u + 2.1, b.d - 1.2, 'iso-led', `led${i}`));
  }
  return (
    <>
      <Box {...b} />
      {out}
      {/* Porte in fibra (uplink) a destra del davanti. */}
      {quad(L, 44, 1.3, 49, 3.9, 'iso-port', 'sfp0')}
      {quad(L, 44, 5, 49, 7.6, 'iso-port', 'sfp1')}
      {/* Sopra: una targhetta e le feritoie dell'aria verso il fondo. */}
      {quad(T, 30, 4, 46, 9, 'iso-inset', 'tag')}
      {[0, 1, 2, 3].map((i) => line(T(4 + i * 4, 3.5), T(4 + i * 4, 12), 'iso-d faint', `v${i}`))}
      {/* Fianco destro: alimentazione e porta della console. */}
      {quad(R, 4, 2.5, 9, 6.5, 'iso-port', 'pwr')}
      {quad(R, 13, 3, 17, 6, 'iso-port isn-port', 'con')}
    </>
  );
}

// ------------------------------------------------------------------ access point

function AccessPoint() {
  const R = 18;
  const z0 = 2.2;
  const H = 5;
  const zt = z0 + H;
  // Glow lungo il bordo davanti del disco, a metà altezza.
  const glow: string[] = [];
  for (let a = 62; a <= 118; a += 4) {
    const t = (a * Math.PI) / 180;
    const [sx, sy] = iso(R * Math.cos(t) * 0.7071 + R * Math.sin(t) * 0.7071, R * Math.sin(t) * 0.7071 - R * Math.cos(t) * 0.7071, z0 + H * 0.45);
    glow.push(`${n2(sx)},${n2(sy)}`);
  }
  const [, wy] = iso(0, 0, zt);
  const wc = wy - 15; // centro delle onde, sopra il disco
  return (
    <>
      {/* Piedino, poi il disco con il suo fianco. */}
      {cylSide(0, 0, 0, z0, 7, 'iso-r')}
      {disc(0, 0, z0, 7, 'iso-t')}
      {cylSide(0, 0, z0, zt, R, 'iso-l')}
      {disc(0, 0, zt, R, 'iso-t')}
      {disc(0, 0, zt, 12.5, 'iso-d faint')}
      {disc(0, 0, zt, 3.4, 'iso-inset')}
      {dot([0, 0, zt], 1.3)}
      <polyline points={glow.join(' ')} className="iso-d isn-glow" />
      {/* Onde del Wi-Fi sopra l'apparecchio. */}
      {arc(0, wc, 6, -135, -45, 'iso-d isn-wave', 'w0')}
      {arc(0, wc, 11.5, -137, -43, 'iso-d isn-wave', 'w1')}
      {arc(0, wc, 17, -139, -41, 'iso-d isn-wave far', 'w2')}
      <circle cx="0" cy={n2(wc)} r={1.8} className="iso-ball" />
    </>
  );
}

// ------------------------------------------------------------------ NAS

function Nas() {
  const b: BoxProps = { x: -11, y: -13, w: 22, d: 26, h: 30 };
  const L = on(face.left, b);
  const R = on(face.right, b);
  const T = on(face.top, b);
  const bays = [3, 10.5, 18].map((v, i) => (
    <g key={i}>
      {quad(L, 2.5, v, 19.5, v + 6, 'iso-port')}
      {line(L(4.5, v + 2.2), L(12.5, v + 2.2), 'iso-d')}
      {quad(L, 15.5, v + 2.4, 17.5, v + 3.8, 'iso-led')}
    </g>
  ));
  return (
    <>
      <Box {...b} />
      {bays}
      {/* Pulsante di accensione e spie in alto sul davanti. */}
      {ring(L, 5, 27, 1.7, 'iso-d')}
      {[0, 1, 2].map((i) => quad(L, 10 + i * 3.4, 26.4, 12 + i * 3.4, 27.6, 'iso-led', `s${i}`))}
      {/* Fianco: la griglia della ventola. */}
      {ring(R, 13, 15, 8, 'iso-port')}
      {ring(R, 13, 15, 5.2, 'iso-d faint')}
      {ring(R, 13, 15, 2.2, 'iso-d')}
      {line(R(5, 15), R(21, 15), 'iso-d faint')}
      {line(R(13, 7), R(13, 23), 'iso-d faint')}
      {quad(T, 4, 5, 18, 21, 'iso-inset')}
    </>
  );
}

// ------------------------------------------------------------------ macchina virtuale

/** Volume "virtuale": contorno tratteggiato; le copie dietro sono traslucide e con gli spigoli nascosti a vista. */
function VirtualBox({ b, ghost = '' }: { b: BoxProps; ghost?: string }) {
  const z = b.z ?? 0;
  const o: P3 = [b.x, b.y, z];
  return (
    <g className={ghost ? `isn-ghost ${ghost}` : undefined}>
      {ghost && (
        <>
          {line(o, [b.x + b.w, b.y, z], 'iso-d faint isn-hidden')}
          {line(o, [b.x, b.y + b.d, z], 'iso-d faint isn-hidden')}
          {line(o, [b.x, b.y, z + b.h], 'iso-d faint isn-hidden')}
        </>
      )}
      <Box {...b} tone={ghost ? 'isn-virt' : 'isn-dash'} />
    </g>
  );
}

function VirtualMachine() {
  const box = (dy: number, dz: number): BoxProps => ({ x: -12, y: -12 + dy, z: dz, w: 24, d: 24, h: 14 });
  const f = box(0, 0);
  const L = on(face.left, f);
  const R = on(face.right, f);
  const T = on(face.top, f);
  return (
    <>
      <VirtualBox b={box(-13, 15)} ghost="far" />
      <VirtualBox b={box(-6.5, 7.5)} ghost="mid" />
      <VirtualBox b={f} />
      {/* Il volume davanti è un piccolo server: striscia, porta e spia. */}
      {quad(L, 3, 3, f.w - 9, 6, 'iso-strip')}
      {quad(L, f.w - 6.5, 3, f.w - 3, 6, 'iso-port isn-port')}
      {line(L(3, 9.5), L(f.w - 3, 9.5), 'iso-d faint')}
      {quad(R, 3, 4, 8, 8, 'iso-port isn-port')}
      {dot(R(f.d - 4, 6), 1.2)}
      {/* Sopra: il segno delle copie, tre quadratini sfalsati. */}
      {[0, 1, 2].map((i) => quad(T, 6 + i * 3, 13 - i * 3, 12 + i * 3, 19 - i * 3, i === 2 ? 'iso-inset' : 'iso-d faint', `c${i}`))}
    </>
  );
}

// ------------------------------------------------------------------ telecamera

function Camera() {
  const pitch = (10 * Math.PI) / 180;
  const body: OBox = { o: [-6.5, -13, 22.5], w: 13, d: 34, h: 12, pitch };
  const f = oframe(body);
  // Tettuccio parasole: copre la parte davanti, un po' più largo e sporgente.
  const shade: OBox = { o: f.at(-0.6, 12, body.h + 0.2), w: body.w + 1.2, d: body.d - 12 + 1.6, h: 1.3, pitch };
  const base: BoxProps = { x: -6, y: -6, w: 12, d: 12, h: 2 };
  const pole: BoxProps = { x: -1.7, y: -1.7, z: 2, w: 3.4, d: 3.4, h: 14.5 };
  const joint: BoxProps = { x: -3, y: -3, z: 16.5, w: 6, d: 6, h: 3.8 };
  return (
    <>
      <Box {...base} />
      <Box {...pole} />
      <Box {...joint} />
      <OBoxShape b={body} />
      {/* Fianco: la cornice davanti e la spia di stato. */}
      {line(f.right(body.d - 4, 0), f.right(body.d - 4, body.h), 'iso-d faint')}
      {line(f.right(2, 3), f.right(body.d - 8, 3), 'iso-d faint')}
      {quad(f.right, body.d - 9.5, 6, body.d - 7, 7.6, 'iso-led')}
      {/* Obiettivo sul davanti: anello, vetro e riflesso, con due spie a infrarossi. */}
      {ring(f.left, 6.5, 5.1, 4.3, 'iso-port')}
      {ring(f.left, 6.5, 5.1, 2.6, 'iso-screen')}
      {dot(f.left(5.7, 6), 0.85)}
      {[2, 11].map((u) => dot(f.left(u, 9.8), 0.6, 'iso-ball', u))}
      <OBoxShape b={shade} />
    </>
  );
}

// ------------------------------------------------------------------ rete dell'operatore

function Tower() {
  const base: BoxProps = { x: -16, y: -16, w: 32, d: 32, h: 2 };
  const z0 = 2;
  const H = 41;
  const B = 13;
  const T = 3.2;
  const half = (z: number) => B + ((T - B) * (z - z0)) / (H - z0);
  const corner = (sx: number, sy: number, z: number): P3 => [sx * half(z), sy * half(z), z];
  const levels = [z0, 14.5, 24.5, 32, 37.5, H];
  // Lati: prima i due dietro (x = -s, y = -s), poi i due davanti.
  const sides: [number, number, number, number, boolean][] = [
    [-1, -1, -1, 1, true],
    [-1, -1, 1, -1, true],
    [1, -1, 1, 1, false],
    [-1, 1, 1, 1, false],
  ];
  const out: ReactNode[] = [];
  sides.forEach(([ax, ay, bx, by, back], si) => {
    const cls = back ? 'iso-d faint isn-brace back' : 'iso-d isn-brace';
    for (let i = 0; i < levels.length - 1; i++) {
      const z1 = levels[i];
      const z2 = levels[i + 1];
      out.push(line(corner(ax, ay, z1), corner(bx, by, z2), cls, `x${si}-${i}`));
      out.push(line(corner(bx, by, z1), corner(ax, ay, z2), cls, `y${si}-${i}`));
      if (i > 0) out.push(line(corner(ax, ay, z1), corner(bx, by, z1), cls, `h${si}-${i}`));
    }
    if (si === 1) out.push(line(corner(-1, -1, z0), corner(-1, -1, H), 'iso-d faint isn-leg back', 'legb'));
  });
  const legs = [
    [1, -1],
    [-1, 1],
    [1, 1],
  ].map(([sx, sy]) => line(corner(sx, sy, z0), corner(sx, sy, H), 'iso-ant isn-leg', `leg${sx}${sy}`));
  // In cima: palo con tre antenne a pannello (prima quella dietro), luce e onde radio.
  const panel = (x: number, y: number, w: number, d: number): BoxProps => ({ x, y, z: H + 1, w, d, h: 8.5 });
  const mastTop = H + 15;
  const [, my] = iso(0, 0, H + 10);
  return (
    <>
      <Box {...base} />
      {out}
      {legs}
      {line([0, 0, H - 2], [0, 0, mastTop], 'iso-ant')}
      <Box {...panel(-5.6, -1.6, 1.4, 3.2)} />
      <Box {...panel(4.2, -1.6, 1.4, 3.2)} />
      <Box {...panel(-1.6, 4.2, 3.2, 1.4)} />
      {line([-4.2, 0, H + 6], [4.2, 0, H + 6], 'iso-d faint')}
      {dot([0, 0, mastTop + 1], 2.2)}
      {arc(0, my, 8, -30, 30, 'iso-d isn-wave', 'r0')}
      {arc(0, my, 13, -32, 32, 'iso-d isn-wave far', 'r1')}
      {arc(0, my, 8, 150, 210, 'iso-d isn-wave', 'l0')}
      {arc(0, my, 13, 148, 212, 'iso-d isn-wave far', 'l1')}
    </>
  );
}

export const NET_ART: Partial<Record<DeviceKind, IsoArt>> = {
  firewall: { draw: Firewall, top: 39 },
  switch: { draw: Switch, top: 34 },
  ap: { draw: AccessPoint, top: 45 },
  nas: { draw: Nas, top: 48 },
  vm: { draw: VirtualMachine, top: 54 },
  camera: { draw: Camera, top: 49 },
  isp: { draw: Tower, top: 63 },
};
