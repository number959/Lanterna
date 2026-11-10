import type { ReactNode } from 'react';

// Primitive della prospettiva isometrica (30°) per i disegni dei dispositivi:
// proiezione, parallelepipedi con le tre facce visibili, punti e rettangoli
// sulle facce, linee, poligoni ed ellissi a terra. Assi: x scende verso destra,
// y scende verso sinistra, z sale. Le classi sono in isoart.css.

const C = Math.cos(Math.PI / 6);

/** Proiezione isometrica di un punto (x, y, z). */
export function iso(x: number, y: number, z = 0): [number, number] {
  return [(x - y) * C, (x + y) * 0.5 - z];
}

export type P3 = [number, number, number];
export const pts = (list: P3[]) =>
  list
    .map(([x, y, z]) => {
      const [a, b] = iso(x, y, z);
      return `${a.toFixed(2)},${b.toFixed(2)}`;
    })
    .join(' ');
export const poly = (list: P3[], cls: string, key?: string | number) => <polygon key={key} points={pts(list)} className={cls} />;
export const line = (a: P3, b: P3, cls = 'iso-d', key?: string | number) => {
  const [x1, y1] = iso(...a);
  const [x2, y2] = iso(...b);
  return <line key={key} x1={x1.toFixed(2)} y1={y1.toFixed(2)} x2={x2.toFixed(2)} y2={y2.toFixed(2)} className={cls} />;
};

export interface BoxProps {
  x: number;
  y: number;
  z?: number;
  w: number;
  d: number;
  h: number;
  /** Classe aggiuntiva per le facce (per esempio "iso-glass"). */
  tone?: string;
}

/** Parallelepipedo: faccia destra (x = x+w), sinistra (y = y+d), sopra (z = z+h). */
export function Box({ x, y, z = 0, w, d, h, tone = '' }: BoxProps) {
  const X = x + w;
  const Y = y + d;
  const Z = z + h;
  return (
    <>
      {poly([[X, y, z], [X, Y, z], [X, Y, Z], [X, y, Z]], `iso-r ${tone}`)}
      {poly([[x, Y, z], [X, Y, z], [X, Y, Z], [x, Y, Z]], `iso-l ${tone}`)}
      {poly([[x, y, Z], [X, y, Z], [X, Y, Z], [x, Y, Z]], `iso-t ${tone}`)}
    </>
  );
}

/** Punti sulle facce visibili di un parallelepipedo, in coordinate della faccia (u, v). */
export const face = {
  /** Faccia sinistra (y = y+d): u lungo x, v lungo z. */
  left: (b: BoxProps, u: number, v: number): P3 => [b.x + u, b.y + b.d, (b.z ?? 0) + v],
  /** Faccia destra (x = x+w): u lungo y, v lungo z. */
  right: (b: BoxProps, u: number, v: number): P3 => [b.x + b.w, b.y + u, (b.z ?? 0) + v],
  /** Faccia sopra (z = z+h): u lungo x, v lungo y. */
  top: (b: BoxProps, u: number, v: number): P3 => [b.x + u, b.y + v, (b.z ?? 0) + b.h],
};

/** Rettangolo su una faccia (u0..u1, v0..v1). */
export function rect(f: (b: BoxProps, u: number, v: number) => P3, b: BoxProps, u0: number, v0: number, u1: number, v1: number, cls: string, key?: string | number) {
  return poly([f(b, u0, v0), f(b, u1, v0), f(b, u1, v1), f(b, u0, v1)], cls, key);
}

/** Ellisse di un cerchio orizzontale di raggio r centrato in (x, y, z). */
export function disc(x: number, y: number, z: number, r: number, cls: string) {
  const [cx, cy] = iso(x, y, z);
  return <ellipse cx={cx.toFixed(2)} cy={cy.toFixed(2)} rx={(r * 1.2247).toFixed(2)} ry={(r * 0.7071).toFixed(2)} className={cls} />;
}


export type IsoArt = { draw: () => ReactNode; /** altezza del disegno sopra il punto a terra, a scala 1 */ top: number };
