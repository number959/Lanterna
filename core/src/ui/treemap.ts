// Disposizione "squarified" (Bruls, Huizing, van Wijk, 2000) per la mappa
// dello spazio: rettangoli con area proporzionale al valore e lati il più
// possibile simili, così anche le cartelle piccole restano leggibili. Gli
// elementi vanno passati già in ordine decrescente.

export interface Rect {
  x: number;
  y: number;
  w: number;
  h: number;
}

export interface Placed<T> {
  item: T;
  rect: Rect;
}

interface Area<T> {
  a: number;
  item: T;
}

/** Il peggior rapporto tra i lati di una riga di aree disposta lungo un lato lungo `side`. */
function worst<T>(row: Area<T>[], side: number): number {
  let sum = 0;
  let max = 0;
  let min = Infinity;
  for (const r of row) {
    sum += r.a;
    max = Math.max(max, r.a);
    min = Math.min(min, r.a);
  }
  const s2 = sum * sum;
  const side2 = side * side;
  return Math.max((side2 * max) / s2, s2 / (side2 * min));
}

/** Dispone una riga lungo il lato corto del rettangolo e restituisce lo spazio rimasto. */
function place<T>(row: Area<T>[], r: Rect, out: Placed<T>[]): Rect {
  const sum = row.reduce((s, x) => s + x.a, 0);
  if (r.w >= r.h) {
    // Colonna a sinistra.
    const w = sum / r.h;
    let y = r.y;
    for (const x of row) {
      const h = x.a / w;
      out.push({ item: x.item, rect: { x: r.x, y, w, h } });
      y += h;
    }
    return { x: r.x + w, y: r.y, w: Math.max(0, r.w - w), h: r.h };
  }
  // Riga in alto.
  const h = sum / r.w;
  let x0 = r.x;
  for (const x of row) {
    const w = x.a / h;
    out.push({ item: x.item, rect: { x: x0, y: r.y, w, h } });
    x0 += w;
  }
  return { x: r.x, y: r.y + h, w: r.w, h: Math.max(0, r.h - h) };
}

export function squarify<T>(items: { value: number; item: T }[], rect: Rect): Placed<T>[] {
  const out: Placed<T>[] = [];
  const valid = items.filter((i) => i.value > 0 && Number.isFinite(i.value));
  const total = valid.reduce((s, i) => s + i.value, 0);
  if (total <= 0 || rect.w <= 0 || rect.h <= 0) return out;
  const scale = (rect.w * rect.h) / total;
  const areas = valid.map((i) => ({ a: i.value * scale, item: i.item }));
  let r = { ...rect };
  let row: Area<T>[] = [];
  for (let i = 0; i < areas.length; ) {
    const side = Math.min(r.w, r.h);
    const cand = [...row, areas[i]];
    if (row.length === 0 || worst(cand, side) <= worst(row, side)) {
      row = cand;
      i++;
    } else {
      r = place(row, r, out);
      row = [];
    }
  }
  if (row.length) place(row, r, out);
  return out;
}
