import type { ReactNode } from 'react';
import type { DeviceKind } from '../engine';
import { Box, disc, face, iso, line, poly, pts, rect } from './isoprims';
import type { BoxProps, IsoArt, P3 } from './isoprims';

// Postazioni e periferiche in prospettiva isometrica: PC, stampante, telefono, tablet, telefono VoIP, TV, domotica, dispositivi medicali, sconosciuti.
// Ogni disegno usa le primitive di isoprims.tsx (Box, face, rect, line, poly, disc, iso)
// e le classi di isoart.css; il punto (0, 0) è il centro dell'appoggio a terra.
// Le parti lontane si disegnano per prime (ordine del pittore); il davanti dei
// dispositivi guarda verso il basso a sinistra (faccia "sinistra", y crescente),
// come lo schermo del portatile di riferimento.

type Face = (b: BoxProps, u: number, v: number) => P3;
type UV = [number, number];

/** Linea spezzata appoggiata su una faccia, in coordinate della faccia. */
const trace = (f: Face, b: BoxProps, uv: UV[], cls = 'iso-d', key?: string | number) => (
  <polyline key={key} points={pts(uv.map(([u, v]) => f(b, u, v)))} className={cls} style={{ fill: 'none' }} />
);

/** Linea spezzata nello spazio, senza riempimento. */
const path3 = (list: P3[], cls = 'iso-d', key?: string | number) => (
  <polyline key={key} points={pts(list)} className={cls} style={{ fill: 'none' }} />
);

/** Punto tondo (non in prospettiva), per spie, tasti e ruote. */
const dot = (p: P3, r: number, cls: string, key?: string | number) => {
  const [cx, cy] = iso(...p);
  return <circle key={key} cx={cx.toFixed(2)} cy={cy.toFixed(2)} r={r} className={cls} />;
};

/** Lastra inclinata all'indietro (schermi appoggiati): davanti, fianco destro e bordo sopra. */
function leaning(x0: number, x1: number, y0: number, z0: number, h: number, lean: number, d: number) {
  const front = (u: number, v: number): P3 => [x0 + u, y0 - (lean * v) / h, z0 + v];
  const Z = z0 + h;
  const yt = y0 - lean;
  const shape = (
    <>
      {poly([[x1, y0, z0], [x1, y0 - d, z0], [x1, yt - d, Z], [x1, yt, Z]], 'iso-r')}
      {poly([[x0, yt, Z], [x1, yt, Z], [x1, yt - d, Z], [x0, yt - d, Z]], 'iso-t')}
      {poly([front(0, 0), front(x1 - x0, 0), front(x1 - x0, h), front(0, h)], 'iso-l')}
    </>
  );
  return { shape, front };
}

/** Punti di un rettangolo in coordinate di una faccia qualunque. */
const quad = (f: (u: number, v: number) => P3, u0: number, v0: number, u1: number, v1: number, cls: string, key?: string | number) =>
  poly([f(u0, v0), f(u1, v0), f(u1, v1), f(u0, v1)], cls, key);

// ---------------------------------------------------------------- PC fisso

function Pc() {
  const foot: BoxProps = { x: -10, y: -18, w: 16, d: 10, h: 1.6 };
  const neck: BoxProps = { x: -4.5, y: -16.5, w: 5, d: 2.5, h: 10 };
  const mon: BoxProps = { x: -23, y: -14, z: 7.5, w: 42, d: 3, h: 26 };
  const kb: BoxProps = { x: -18, y: -1, w: 31, d: 11, h: 1.8 };
  const mouse: BoxProps = { x: 16, y: 3, w: 5, d: 7, h: 2.2 };
  const keys: ReactNode[] = [];
  for (let r = 0; r < 3; r++)
    for (let c = 0; c < 11; c++) keys.push(rect(face.top, kb, 1.4 + c * 2.7, 1.3 + r * 2.4, 3.4 + c * 2.7, 3 + r * 2.4, 'iso-key', `k${r}-${c}`));
  keys.push(rect(face.top, kb, 1.4, 8.5, 6.1, 10, 'iso-key', 'a'));
  keys.push(rect(face.top, kb, 7.0, 8.5, 22.3, 10, 'iso-key', 'sp'));
  keys.push(rect(face.top, kb, 23.2, 8.5, 29.6, 10, 'iso-key', 'b'));
  const L = face.left;
  return (
    <>
      <Box {...foot} />
      <Box {...neck} />
      <Box {...mon} />
      {rect(L, mon, 2, 2.6, 40, 24, 'iso-screen')}
      {/* Barra del browser: tre pallini, la barra dell'indirizzo, poi i contenuti. */}
      {line(L(mon, 2, 20.4), L(mon, 40, 20.4))}
      {[0, 1, 2].map((i) => dot(L(mon, 4 + i * 2, 22.2), 0.7, 'iso-ball', `w${i}`))}
      {rect(L, mon, 12, 21.4, 31, 23, 'iso-key')}
      {line(L(mon, 5, 17.2), L(mon, 24, 17.2), 'iso-d faint')}
      {line(L(mon, 5, 14.8), L(mon, 30, 14.8), 'iso-d faint')}
      {rect(L, mon, 5, 5, 18, 12.4, 'iso-inset')}
      {line(L(mon, 21, 11.6), L(mon, 36, 11.6), 'iso-d faint')}
      {line(L(mon, 21, 9.2), L(mon, 33, 9.2), 'iso-d faint')}
      {line(L(mon, 21, 6.8), L(mon, 35, 6.8), 'iso-d faint')}
      {dot(L(mon, 38.5, 1.3), 0.6, 'iso-ball')}
      <Box {...kb} />
      {keys}
      <Box {...mouse} />
      {line(face.top(mouse, 2.5, 0.4), face.top(mouse, 2.5, 3), 'iso-key')}
    </>
  );
}

// ---------------------------------------------------------------- stampante

function Printer() {
  const b: BoxProps = { x: -18, y: -14, w: 36, d: 28, h: 14 };
  const T = face.top;
  // Vassoio di entrata dietro, inclinato all'indietro, con un foglio.
  const tray = (u: number, s: number): P3 => [b.x + u, -10.5 - 7 * s, 14 + 13 * s];
  const out: BoxProps = { x: -12, y: 14, z: 2.6, w: 24, d: 6.5, h: 1 };
  return (
    <>
      <Box {...b} />
      {/* Piano dello scanner: la linea del coperchio e il pannello dei comandi. */}
      {line(T(b, 1.5, 4.5), T(b, 34.5, 4.5), 'iso-d faint')}
      {rect(T, b, 21, 15, 33.5, 25.5, 'iso-inset')}
      {rect(T, b, 22.5, 16.5, 28.5, 21, 'iso-screen')}
      {[0, 1, 2].map((i) => rect(T, b, 29.6, 16.3 + i * 3, 32.2, 18.3 + i * 3, 'iso-key', `c${i}`))}
      {rect(T, b, 22.5, 22.3, 24.3, 24, 'iso-led')}
      {/* Destra: le prese d'aria e una porta. */}
      {[0, 1, 2, 3].map((i) => line(face.right(b, 4 + i * 2.2, 4), face.right(b, 4 + i * 2.2, 10), 'iso-d faint', `v${i}`))}
      {rect(face.right, b, 18, 4, 24, 7.5, 'iso-port')}
      {/* Fessura di uscita sul davanti e il vassoio con un foglio stampato. */}
      {rect(face.left, b, 5, 3.6, 31, 7.4, 'iso-port')}
      {line(face.left(b, 3, 10.5), face.left(b, 12, 10.5), 'iso-d faint')}
      <Box {...out} />
      {rect(T, out, 3, -1.2, 21, 5.2, 'iso-inset')}
      {[0, 1, 2].map((i) => line(T(out, 5, 0.8 + i * 1.5), T(out, 15 + (i % 2) * 3, 0.8 + i * 1.5), 'iso-d faint', `o${i}`))}
      {poly([tray(4, 0), tray(32, 0), tray(32, 1), tray(4, 1)], 'iso-l')}
      {poly([tray(8, 0.12), tray(28, 0.12), tray(28, 1.3), tray(8, 1.3)], 'iso-inset')}
      {[0, 1, 2, 3].map((i) => line(tray(11, 1.12 - i * 0.2), tray(i % 2 ? 21 : 25, 1.12 - i * 0.2), 'iso-d faint', `t${i}`))}
    </>
  );
}

// ---------------------------------------------------------------- telefono e tablet

/** Base d'appoggio con il dispositivo inclinato all'indietro, schermo e cornice. */
function Handheld({ w, h, dock, phone }: { w: number; h: number; dock: BoxProps; phone: boolean }) {
  const x0 = -w / 2;
  const x1 = w / 2;
  const z0 = dock.z! + dock.h;
  const y0 = dock.y + dock.d - 3.2;
  const lip: BoxProps = { x: x0 - 1, y: y0, z: z0, w: w + 2, d: 1.6, h: 1.8 };
  const s = leaning(x0, x1, y0, z0, h, 4, 2.6);
  const f = s.front;
  const m = phone ? 1.3 : 2;
  const icons: ReactNode[] = [];
  if (phone) {
    // Telefono: la griglia delle app.
    const pitch = (w - 2 * m - 3) / 3;
    for (let r = 0; r < 4; r++)
      for (let c = 0; c < 3; c++) {
        const u = m + 1.5 + c * pitch + pitch * 0.18;
        const v = h - 6 - r * pitch;
        icons.push(quad(f, u, v - pitch * 0.62, u + pitch * 0.62, v, 'iso-key', `${r}-${c}`));
      }
  } else {
    // Tablet: barra laterale con le voci, un riquadro grande e righe di testo.
    icons.push(line(f(m + 6, m + 1), f(m + 6, h - m - 1), 'iso-d faint', 'side'));
    for (let i = 0; i < 5; i++) icons.push(line(f(m + 1.5, h - m - 3 - i * 3), f(m + 4.5, h - m - 3 - i * 3), 'iso-d faint', `s${i}`));
    icons.push(quad(f, m + 8, h - m - 13, w - m - 1.6, h - m - 2, 'iso-inset', 'hero'));
    for (let i = 0; i < 4; i++) icons.push(line(f(m + 8, h - m - 16.5 - i * 3), f(w - m - (i % 2 ? 6 : 2.5), h - m - 16.5 - i * 3), 'iso-d faint', `l${i}`));
  }
  return (
    <>
      {/* Sostegno dietro, poi la base. */}
      {poly([[x0 + w * 0.3, y0 - 3, z0 + h * 0.45], [x1 - w * 0.3, y0 - 3, z0 + h * 0.45], [x1 - w * 0.3, dock.y + 0.5, dock.z! + dock.h], [x0 + w * 0.3, dock.y + 0.5, dock.z! + dock.h]], 'iso-r')}
      <Box {...dock} />
      {s.shape}
      {quad(f, m, phone ? 3 : m + 0.6, w - m, h - (phone ? 3 : m + 0.6), 'iso-screen')}
      {icons}
      <Box {...lip} />
      {phone ? (
        <>
          {/* Tacca in alto con l'altoparlante e la barra in basso. */}
          {quad(f, w / 2 - 3, h - 3.4, w / 2 + 3, h - 1.6, 'iso-port')}
          {line(f(w / 2 - 3, 4.5), f(w / 2 + 3, 4.5), 'iso-d')}
        </>
      ) : (
        <>
          {dot(f(w / 2, h - m / 2 - 0.3), 0.7, 'iso-ball')}
        </>
      )}
      {rect(face.left, dock, dock.w - 6, dock.h / 2 - 0.5, dock.w - 3, dock.h / 2 + 0.5, 'iso-led')}
    </>
  );
}

const Phone = () => <Handheld w={16} h={30} phone dock={{ x: -10, y: -6, z: 0, w: 20, d: 12, h: 2.4 }} />;
const Tablet = () => <Handheld w={26} h={33} phone={false} dock={{ x: -16, y: -7, z: 0, w: 32, d: 13, h: 2.4 }} />;

// ---------------------------------------------------------------- telefono VoIP

/** Filo a spirale lungo una curva (a, c di controllo, b), come un'onda nella proiezione. */
function coil(a: P3, c: P3, b: P3, turns: number, amp: number) {
  const N = 180;
  const P: [number, number][] = [];
  for (let i = 0; i <= N; i++) {
    const t = i / N;
    const k = (j: number) => (1 - t) * (1 - t) * a[j] + 2 * (1 - t) * t * c[j] + t * t * b[j];
    P.push(iso(k(0), k(1), k(2)));
  }
  const out: string[] = [];
  for (let i = 0; i <= N; i++) {
    const [x, y] = P[i];
    const [x1, y1] = P[Math.min(i + 1, N)];
    const [x0, y0] = P[Math.max(i - 1, 0)];
    const len = Math.hypot(x1 - x0, y1 - y0) || 1;
    const tx = (x1 - x0) / len;
    const ty = (y1 - y0) / len;
    const th = (2 * Math.PI * turns * i) / N;
    const e = Math.min(1, i / 12, (N - i) / 12);
    out.push(`${(x - ty * amp * e * Math.sin(th)).toFixed(2)},${(y + tx * amp * e * Math.sin(th)).toFixed(2)}`);
  }
  return <polyline points={out.join(' ')} className="iso-d" style={{ fill: 'none' }} />;
}

function Voip() {
  const x0 = -17;
  const X = 17;
  const y0 = -13;
  const Y = 13;
  const hb = 13;
  const hf = 4.5;
  const zt = (y: number) => hb - ((hb - hf) * (y - y0)) / (Y - y0);
  /** Punto sul piano inclinato: u lungo x, v lungo y. */
  const top = (u: number, v: number, lift = 0): P3 => [x0 + u, y0 + v, zt(y0 + v) + lift];
  const keys: ReactNode[] = [];
  for (let r = 0; r < 4; r++)
    for (let c = 0; c < 3; c++) keys.push(quad(top, 15 + c * 4.6, 13 + r * 3.1, 18.4 + c * 4.6, 15.3 + r * 3.1, 'iso-key', `${r}-${c}`));
  /** Pezzo della cornetta: un blocco che segue la pendenza. */
  const piece = (u0: number, u1: number, v0: number, v1: number, t: number, k: string) => {
    const a = (u: number, v: number, l: number) => top(u, v, l);
    return (
      <g key={k}>
        {poly([a(u1, v0, 0.6), a(u1, v1, 0.6), a(u1, v1, t), a(u1, v0, t)], 'iso-r')}
        {poly([a(u0, v1, 0.6), a(u1, v1, 0.6), a(u1, v1, t), a(u0, v1, t)], 'iso-l')}
        {poly([a(u0, v0, t), a(u1, v0, t), a(u1, v1, t), a(u0, v1, t)], 'iso-t')}
      </g>
    );
  };
  // Filo a spirale: dalla cornetta scende davanti e torna nella presa.
  const cord = coil([x0 + 4.5, y0 + 24.8, zt(y0 + 24.8) + 0.8], [x0 + 1, Y + 13, -4], [x0 + 13.2, Y + 0.2, 1.7], 8, 1.1);
  return (
    <>
      {poly([[X, y0, 0], [X, Y, 0], [X, Y, hf], [X, y0, hb]], 'iso-r')}
      {poly([[x0, Y, 0], [X, Y, 0], [X, Y, hf], [x0, Y, hf]], 'iso-l')}
      {poly([top(0, 0), top(34, 0), top(34, 26), top(0, 26)], 'iso-t')}
      {/* Display in alto, tasti funzione e tastierino. */}
      {quad(top, 13, 2.2, 32, 9.8, 'iso-screen')}
      {line(top(14.5, 4.6), top(25, 4.6), 'iso-d faint')}
      {line(top(14.5, 7), top(21, 7), 'iso-d faint')}
      {[0, 1, 2].map((i) => quad(top, 30.2, 11.4 + i * 3.8, 32.6, 13.4 + i * 3.8, 'iso-key', `f${i}`))}
      {keys}
      {dot(top(32, 24, 0.2), 0.9, 'iso-ball')}
      {/* Cornetta a sinistra: auricolare, impugnatura, microfono. */}
      {line(top(11, 1.5), top(11, 24.5), 'iso-d faint')}
      {piece(1.8, 9.8, 1.4, 7.6, 4.4, 'ear')}
      {piece(2.8, 8.8, 7.6, 18.4, 3, 'grip')}
      {piece(1.8, 9.8, 18.4, 24.6, 4.4, 'mic')}
      {rect(face.left, { x: x0, y: y0, w: X - x0, d: Y - y0, h: hf }, 12, 0.9, 14.4, 2.5, 'iso-port')}
      {cord}
      {rect(face.right, { x: x0, y: y0, w: X - x0, d: Y - y0, h: hf }, 3, 1.4, 8, 3.2, 'iso-port')}
    </>
  );
}

// ---------------------------------------------------------------- TV

function Tv() {
  const foot: BoxProps = { x: -11, y: -8, w: 22, d: 10, h: 1.6 };
  const neck: BoxProps = { x: -2.5, y: -5, w: 5, d: 2.5, h: 6 };
  const p: BoxProps = { x: -27, y: -2.5, z: 4.5, w: 54, d: 3, h: 30 };
  const L = face.left;
  return (
    <>
      <Box {...foot} />
      <Box {...neck} />
      <Box {...p} />
      {rect(L, p, 1.8, 2.8, 52.2, 28.4, 'iso-screen')}
      {/* Simbolo di riproduzione e la barra di avanzamento. */}
      {poly([L(p, 23.5, 11.5), L(p, 23.5, 20.5), L(p, 31, 16)], 'iso-d')}
      {line(L(p, 6, 6.5), L(p, 48, 6.5), 'iso-d faint')}
      {line(L(p, 6, 6.5), L(p, 21, 6.5), 'iso-d')}
      {dot(L(p, 21, 6.5), 1, 'iso-ball')}
      {line(L(p, 37, 26), L(p, 47, 17), 'iso-d faint')}
      {line(L(p, 41, 26), L(p, 48.5, 19.3), 'iso-d faint')}
      {dot(L(p, 49.5, 1.4), 0.6, 'iso-ball')}
    </>
  );
}

// ---------------------------------------------------------------- domotica

/** Ellisse di un cerchio orizzontale come tracciato chiuso (per gli anelli con fill-rule). */
function ring(z: number, r: number) {
  const f = (n: number) => n.toFixed(2);
  const [cx, cy] = iso(0, 0, z);
  const rx = r * 1.2247;
  const ry = r * 0.7071;
  return `M${f(cx - rx)} ${f(cy)} A${f(rx)} ${f(ry)} 0 1 0 ${f(cx + rx)} ${f(cy)} A${f(rx)} ${f(ry)} 0 1 0 ${f(cx - rx)} ${f(cy)} Z`;
}

/** Archi del Wi-Fi su un piano: centro (cu, cv), "su" lungo v. */
const wifi = (f: (u: number, v: number) => P3, cu: number, cv: number, radii: number[], cls: string) =>
  radii.map((rad) => {
    const out: P3[] = [];
    for (let i = 0; i <= 10; i++) {
      const t = Math.PI / 4 + (i / 10) * (Math.PI / 2);
      out.push(f(cu + rad * Math.cos(t), cv + rad * Math.sin(t)));
    }
    return path3(out, cls, rad);
  });

/**
 * Prisma a pianta quadrata con gli spigoli verticali arrotondati (lato 2a,
 * raggio c): i fianchi visibili prendono il tono della faccia più vicina.
 */
function roundedPrism(a: number, c: number, h: number) {
  const ring2: [number, number][] = [];
  const corners: [number, number, number][] = [
    [a - c, -a + c, -90],
    [a - c, a - c, 0],
    [-a + c, a - c, 90],
    [-a + c, -a + c, 180],
  ];
  for (const [cx, cy, a0] of corners)
    for (let i = 0; i <= 3; i++) {
      const t = ((a0 + i * 30) * Math.PI) / 180;
      ring2.push([cx + c * Math.cos(t), cy + c * Math.sin(t)]);
    }
  // Facce in tinta piena senza contorno, poi solo la sagoma: lo spigolo resta morbido.
  const sides: ReactNode[] = [];
  const seen: P3[] = [];
  for (let i = 0; i < ring2.length; i++) {
    const [x0, y0] = ring2[i];
    const [x1, y1] = ring2[(i + 1) % ring2.length];
    // Normale verso l'esterno; visibile se guarda verso chi osserva (+x, +y).
    const nx = y1 - y0;
    const ny = -(x1 - x0);
    if (nx + ny <= 0.01) continue;
    sides.push(<polygon key={i} points={pts([[x0, y0, 0], [x1, y1, 0], [x1, y1, h], [x0, y0, h]])} className={nx > ny ? 'iso-r' : 'iso-l'} style={{ stroke: 'none' }} />);
    if (!seen.length) seen.push([x0, y0, 0]);
    seen.push([x1, y1, 0]);
  }
  const first = seen[0];
  const last = seen[seen.length - 1];
  return (
    <>
      {sides}
      {path3([[first[0], first[1], h], ...seen, [last[0], last[1], h]], 'iso-t')}
      {poly(ring2.map(([x, y]) => [x, y, h] as P3), 'iso-t')}
    </>
  );
}

function Iot() {
  // Centralina della domotica: un cubo con gli spigoli arrotondati, l'anello di
  // luce sopra e il simbolo della casa connessa sul davanti.
  const a = 14;
  const h = 21;
  const front = (u: number, v: number): P3 => [u, a, v];
  const right = (u: number, v: number): P3 => [a, u, v];
  return (
    <>
      {roundedPrism(a, 4.5, h)}
      {/* Anello di luce e il tasto al centro. */}
      <path d={`${ring(h, 9.4)} ${ring(h, 7.6)}`} className="iso-strip" fillRule="evenodd" />
      {disc(0, 0, h, 2.6, 'iso-inset')}
      {/* Casa con il Wi-Fi dentro, disegnata sulla faccia davanti. */}
      {path3([front(-4.6, 10), front(-4.6, 3.4), front(4.6, 3.4), front(4.6, 10)], 'iso-d')}
      {path3([front(-6.2, 9.2), front(0, 15), front(6.2, 9.2)], 'iso-d')}
      {wifi(front, 0, 4.6, [1.8, 3.6], 'iso-d')}
      {dot(front(0, 4.9), 0.75, 'iso-ball')}
      {/* Fianco: griglia dell'altoparlante e la spia. */}
      {[0, 1, 2].map((i) => line(right(-4.5 + i * 3, 6.5), right(-4.5 + i * 3, 14.5), 'iso-d faint', `g${i}`))}
      {dot(right(5, 3.4), 0.8, 'iso-ball')}
    </>
  );
}

// ---------------------------------------------------------------- medicale

function Medical() {
  const zb = 19;
  const b: BoxProps = { x: -16, y: -8, z: zb, w: 32, d: 16, h: 20 };
  const L = face.left;
  const leg = (x: number, y: number, k: string) => (
    <g key={k}>
      {line([0, 0, 1.6], [x, y, 1.6], 'iso-ant')}
      {dot([x, y, 0.8], 1.9, 'iso-port')}
    </g>
  );
  const ecg: UV[] = [
    [3.6, 9.4], [6.5, 9.4], [7.4, 10.5], [8.3, 9.4], [9.6, 9.4], [10.4, 7.8], [11.6, 15.4], [12.8, 6], [13.8, 9.4], [15.4, 9.4], [16.6, 11], [17.8, 9.4], [20.4, 9.4],
  ];
  const zt = zb + b.h;
  return (
    <>
      {/* Base a ruote: le gambe dietro, l'asta, le gambe davanti. */}
      {leg(-12, 0, 'a')}
      {leg(0, -12, 'b')}
      {line([0, 0, 1.6], [0, 0, zb + 1], 'iso-ant')}
      {leg(12, 0, 'c')}
      {leg(0, 12, 'd')}
      <Box {...b} />
      {rect(L, b, 2.4, 2.6, 21.6, 17.4, 'iso-screen')}
      {trace(L, b, ecg, 'iso-d')}
      {line(L(b, 4, 14.6), L(b, 8.5, 14.6), 'iso-d faint')}
      {line(L(b, 4, 4.8), L(b, 10, 4.8), 'iso-d faint')}
      {line(L(b, 15, 4.8), L(b, 20, 4.8), 'iso-d faint')}
      {/* Croce sanitaria a tratti e due manopole. */}
      {line(L(b, 24.2, 13), L(b, 29.8, 13), 'iso-ant')}
      {line(L(b, 27, 10.2), L(b, 27, 15.8), 'iso-ant')}
      {dot(L(b, 25.3, 5.4), 1.5, 'iso-d')}
      {dot(L(b, 28.7, 5.4), 1.5, 'iso-d')}
      {[0, 1, 2].map((i) => line(face.right(b, 4 + i * 2.4, 5), face.right(b, 4 + i * 2.4, 15), 'iso-d faint', `v${i}`))}
      {/* Maniglia sopra. */}
      {path3([[-10, -1, zt], [-10, -1, zt + 4.5], [10, -1, zt + 4.5], [10, -1, zt]], 'iso-ant')}
    </>
  );
}

// ---------------------------------------------------------------- sconosciuto

function Unknown() {
  const b: BoxProps = { x: -14, y: -14, w: 28, d: 28, h: 20 };
  // Punto interrogativo disteso sulla faccia sinistra: gancio, gambo e punto.
  const q: UV[] = [];
  for (let i = 0; i <= 14; i++) {
    const t = ((160 - (i / 14) * 225) * Math.PI) / 180;
    q.push([14 + 4.2 * Math.cos(t), 13.2 + 4 * Math.sin(t)]);
  }
  q.push([14, 7.6], [14, 6.6]);
  return (
    <>
      <Box {...b} />
      {rect(face.top, b, 5, 5, 23, 23, 'iso-d faint')}
      {trace(face.left, b, q, 'iso-ant')}
      {rect(face.left, b, 12.9, 2.6, 15.1, 4.6, 'iso-led')}
    </>
  );
}

export const HOME_ART: Partial<Record<DeviceKind, IsoArt>> = {
  pc: { draw: Pc, top: 54 },
  printer: { draw: Printer, top: 48 },
  phone: { draw: Phone, top: 40 },
  tablet: { draw: Tablet, top: 46 },
  voip: { draw: Voip, top: 32 },
  tv: { draw: Tv, top: 52 },
  iot: { draw: Iot, top: 36 },
  medical: { draw: Medical, top: 53 },
  unknown: { draw: Unknown, top: 36 },
};
