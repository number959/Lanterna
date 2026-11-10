import { describe, expect, it } from 'vitest';
import { analyze, buildNetworkMap } from '../src/engine';
import type { DeviceKind, NetworkMap } from '../src/engine';
import { clinicScan } from '../src/demo/clinic';
import { demoScan } from '../src/demo/sample';
import {
  arrowsAlong,
  buildScene,
  easeOutCubic,
  ENTER,
  entranceSchedule,
  fitView,
  frameRoute,
  frameView,
  hullRect,
  ISO_SCALE,
  latticePath,
  lerpView,
  offsetPolyline,
  pathToNode,
  placeLinkLabel,
  project,
  projectPath,
  rectPolyOverlap,
  rectsOverlap,
  routeBounds,
  routePoints,
  simplify,
  spaceMap,
  STACK_GAP,
  toScreen,
  truncate,
  visibleArea,
  zoomAbout,
} from '../src/ui/netmap-iso';
import type { Pt, Rect, Scene } from '../src/ui/netmap-iso';

// Mappa della rete in prospettiva isometrica: proiezione, spazio tra le zone,
// titoli che non coprono nulla, corsie del traffico, camera ed entrata in scena.

const C = Math.cos(Math.PI / 6);
const near = (a: number, b: number, eps = 1e-6) => Math.abs(a - b) < eps;
const dist = (a: Pt, b: Pt) => Math.hypot(a[0] - b[0], a[1] - b[1]);
/** Altezze dei disegni simili a quelle vere (isoart.tsx), senza dipendere dai disegni. */
const topOf = (k: DeviceKind) => (k === 'internet' ? 56 : k === 'isp' ? 66 : k === 'tv' ? 50 : 48);

const casa = () => spaceMap(buildNetworkMap(demoScan, analyze(demoScan)));
const clinica = () => spaceMap(buildNetworkMap(clinicScan, analyze(clinicScan)));

/** Distanza di un punto dalla retta di un tratto. */
function segDist(p: Pt, a: Pt, b: Pt): number {
  const dx = b[0] - a[0];
  const dy = b[1] - a[1];
  return Math.abs((p[0] - a[0]) * dy - (p[1] - a[1]) * dx) / Math.hypot(dx, dy);
}

describe('proiezione isometrica', () => {
  it('assi a 30°: x scende a destra, y scende a sinistra, z sale', () => {
    expect(project(0, 0)).toEqual([0, 0]);
    const [ax, ay] = project(100, 0);
    expect(near(ax, 100 * ISO_SCALE * C)).toBe(true);
    expect(near(ay, 50 * ISO_SCALE)).toBe(true);
    const [bx, by] = project(0, 100);
    expect(near(bx, -100 * ISO_SCALE * C)).toBe(true);
    expect(near(by, 50 * ISO_SCALE)).toBe(true);
    expect(project(0, 0, 10)[1]).toBe(-10);
    // Pendenza dei due assi: 30° sopra l'orizzontale.
    expect(near(Math.atan2(ay, ax), Math.PI / 6)).toBe(true);
  });

  it('reticolo di una zona: linee lungo i due assi, dentro il piano', () => {
    const z = { id: 'z', label: 'z', kind: 'local' as const, sources: [], x: 0, y: 0, w: 140, h: 84 };
    const d = latticePath(z, 28);
    // 4 linee a x costante (28, 56, 84, 112) e 2 a y costante (28, 56).
    expect(d.match(/M/g)!.length).toBe(6);
    const nums = d.match(/-?\d+(\.\d+)?/g)!.map(Number);
    const xs = nums.filter((_, i) => i % 2 === 0);
    const [l, r] = [project(0, 84)[0], project(140, 0)[0]];
    expect(Math.min(...xs)).toBeGreaterThanOrEqual(l - 0.1);
    expect(Math.max(...xs)).toBeLessThanOrEqual(r + 0.1);
  });

  it('un rettangolo diventa un parallelogramma con i lati opposti uguali', () => {
    const [T, R, B, L] = projectPath([[10, 20], [210, 20], [210, 120], [10, 120]]);
    expect(near(dist(T, R), dist(L, B))).toBe(true);
    expect(near(dist(T, L), dist(R, B))).toBe(true);
    // L'angolo in fondo sta più in alto di tutti, quello davanti più in basso.
    expect(T[1]).toBeLessThan(Math.min(R[1], L[1]));
    expect(B[1]).toBeGreaterThan(Math.max(R[1], L[1]));
  });
});

describe('disposizione con più aria tra le zone', () => {
  it('le zone impilate sullo stesso lato si allontanano, i dispositivi le seguono, la mappa originale resta com\'è', () => {
    const base = buildNetworkMap(clinicScan, analyze(clinicScan));
    const before = JSON.stringify(base);
    const m = spaceMap(base);
    expect(JSON.stringify(base)).toBe(before);
    for (const side of ['left', 'right'] as const) {
      const col = m.segments.filter((s) => s.side === side).sort((a, b) => a.y - b.y);
      for (let i = 1; i < col.length; i++) expect(col[i].y - (col[i - 1].y + col[i - 1].h)).toBeGreaterThanOrEqual(34 + STACK_GAP - 0.01);
    }
    for (const n of m.nodes) {
      const s = m.segments.find((z) => z.id === n.segment);
      const o = base.nodes.find((x) => x.id === n.id)!;
      if (!s) expect(n.y).toBe(o.y);
      else {
        expect(n.y - o.y).toBe(s.y - base.segments.find((z) => z.id === s.id)!.y);
        expect(n.y).toBeGreaterThan(s.y);
        expect(n.y).toBeLessThan(s.y + s.h);
      }
    }
    expect(m.backbone!.y2).toBe(Math.max(...m.segments.map((s) => s.ey ?? 0)));
  });

  it('percorsi: il percorso verso un server di un\'altra VLAN passa dal firewall', () => {
    const m = clinica();
    const srv = m.nodes.find((n) => n.ip === '10.20.50.10')!;
    expect(pathToNode(m, srv)).toEqual(['ip:10.20.30.57', 'ip:10.20.30.202', 'ip:10.20.30.1', 'ip:10.20.50.10']);
    const pts = routePoints(m, pathToNode(m, srv));
    // Solo tratti dritti nella disposizione: in prospettiva seguono gli assi isometrici.
    for (let i = 1; i < pts.length; i++) expect(pts[i][0] === pts[i - 1][0] || pts[i][1] === pts[i - 1][1]).toBe(true);
  });
});

/** Tutti i titoli delle zone liberi: non si toccano tra loro, non coprono altre zone né dispositivi. */
function labelClashes(sc: Scene): string[] {
  const out: string[] = [];
  sc.zones.forEach((z, i) => {
    const r = z.label.rect;
    for (const o of sc.zones) if (rectPolyOverlap(r, o.hull)) out.push(`${z.s.label} copre la zona ${o.s.label}`);
    for (const o of sc.zones.slice(i + 1)) if (rectsOverlap(r, o.label.rect)) out.push(`${z.s.label} tocca il titolo di ${o.s.label}`);
    for (const n of sc.nodes) if (n.parts.some((b) => rectsOverlap(r, b))) out.push(`${z.s.label} copre ${n.n.label}`);
  });
  return out;
}

describe('scena proiettata', () => {
  it('casa: titolo libero, nessuna etichetta di dispositivo sopra un altro dispositivo', () => {
    const sc = buildScene(casa(), topOf);
    expect(labelClashes(sc)).toEqual([]);
    const clash: string[] = [];
    for (const a of sc.nodes)
      for (const b of sc.nodes) if (a !== b && rectsOverlap(a.parts[1], b.parts[0])) clash.push(`${a.n.label} su ${b.n.label}`);
    for (let i = 0; i < sc.nodes.length; i++)
      for (let j = i + 1; j < sc.nodes.length; j++) if (rectsOverlap(sc.nodes[i].parts[1], sc.nodes[j].parts[1])) clash.push(`${sc.nodes[i].n.label} e ${sc.nodes[j].n.label}`);
    expect(clash).toEqual([]);
  });

  it('poliambulatorio: le zone non si sovrappongono e ogni titolo trova un posto libero', () => {
    const sc = buildScene(clinica(), topOf);
    expect(sc.zones.length).toBe(13);
    for (let i = 0; i < sc.zones.length; i++)
      for (let j = i + 1; j < sc.zones.length; j++) {
        // Due parallelogrammi convessi: basta che nessun vertice dell'uno cada dentro l'altro e che i riquadri non si incrocino troppo.
        const a = sc.zones[i];
        const b = sc.zones[j];
        const inside = (p: Pt, poly: Pt[]) => rectPolyOverlap({ x0: p[0] - 0.5, y0: p[1] - 0.5, x1: p[0] + 0.5, y1: p[1] + 0.5 }, poly);
        expect(a.hull.some((p) => inside(p, b.hull)) || b.hull.some((p) => inside(p, a.hull))).toBe(false);
      }
    expect(labelClashes(sc)).toEqual([]);
  });

  it('ordine di lettura (Tab) che è anche un ordine di disegno corretto; riquadro che contiene tutto', () => {
    for (const m of [casa(), clinica()]) {
      const sc = buildScene(m, topOf);
      // Prima la catena verso Internet, poi zona per zona.
      const zoneOrder = sc.nodes.map((s) => (s.n.segment === 'core' ? -1 : m.segments.findIndex((z) => z.id === s.n.segment)));
      for (let i = 1; i < zoneOrder.length; i++) expect(zoneOrder[i]).toBeGreaterThanOrEqual(zoneOrder[i - 1]);
      // Di due dispositivi che si coprono, quello più in basso sullo schermo (davanti) viene disegnato dopo.
      for (let i = 0; i < sc.nodes.length; i++)
        for (let j = i + 1; j < sc.nodes.length; j++)
          if (rectsOverlap(sc.nodes[i].box, sc.nodes[j].box)) expect(sc.nodes[j].p[1]).toBeGreaterThan(sc.nodes[i].p[1]);
    }
    const sc = buildScene(clinica(), topOf);
    const b = sc.bounds;
    const inside = (r: Rect) => r.x0 >= b.x0 && r.x1 <= b.x1 && r.y0 >= b.y0 && r.y1 <= b.y1;
    expect(sc.nodes.every((n) => inside(n.box))).toBe(true);
    expect(sc.zones.every((z) => inside(hullRect(z.hull)) && inside(z.label.rect))).toBe(true);
    // Gateway e Internet più grandi.
    expect(sc.nodes.find((n) => n.n.gateway)!.sc).toBeGreaterThan(sc.nodes.find((n) => n.n.self)!.sc);
  });
});

describe('corsie del traffico', () => {
  it('su un tratto dritto la corsia è parallela, alla distanza data e a destra del verso', () => {
    const lane = offsetPolyline([[0, 0], [100, 0]], 3);
    expect(lane).toEqual([[0, 3], [100, 3]]);
    const back = offsetPolyline([[100, 0], [0, 0]], 3);
    expect(back).toEqual([[100, -3], [0, -3]]);
  });

  it('negli angoli il punto sta a distanza d da entrambi i tratti; nelle inversioni a U si aggiunge un punto', () => {
    const path: Pt[] = projectPath([[0, 0], [0, 100], [120, 100]]);
    const lane = offsetPolyline(path, 4);
    expect(lane.length).toBe(3);
    expect(near(segDist(lane[1], path[0], path[1]), 4, 1e-6)).toBe(true);
    expect(near(segDist(lane[1], path[1], path[2]), 4, 1e-6)).toBe(true);
    const u = offsetPolyline([[0, 0], [0, 50], [0, 10]], 3);
    expect(u.length).toBe(4);
    for (const p of u) expect(Math.abs(p[0])).toBeCloseTo(3, 6);
    // Andata e ritorno: due corsie distinte ai due lati del percorso.
    const ret = offsetPolyline(path.slice().reverse(), 4);
    expect(dist(lane[0], ret[ret.length - 1])).toBeCloseTo(8, 6);
  });

  it('frecce sui tratti lunghi, nel verso di marcia; punti ripetuti e allineati tolti; percorsi troncati', () => {
    const arr = arrowsAlong([[0, 0], [100, 0], [100, 20], [100, 120]]);
    expect(arr.length).toBe(2);
    expect(arr[0].dir).toEqual([1, 0]);
    expect(arr[1].dir).toEqual([0, 1]);
    expect(simplify([[0, 0], [0, 0], [10, 0], [20, 0], [20, 5]])).toEqual([[0, 0], [20, 0], [20, 5]]);
    const half = truncate([[0, 0], [100, 0], [100, 100]], 0.25);
    expect(half[half.length - 1]).toEqual([50, 0]);
  });

  it('etichetta di un collegamento lontana dagli ostacoli', () => {
    const obst: Rect[] = [{ x0: 40, y0: -40, x1: 60, y1: 40 }];
    const l = placeLinkLabel([[0, 0], [100, 0]], '44 ms', obst);
    expect(rectsOverlap(l.rect, obst[0])).toBe(false);
  });
});

describe('camera', () => {
  it('adatta: il riquadro intero sta nello schermo, centrato; lo zoom resta nei limiti', () => {
    const b: Rect = { x0: -500, y0: 100, x1: 700, y1: 700 };
    const v = fitView(b, 1100, 600, 16, 0.2, 1.3);
    const a = toScreen(v, [b.x0, b.y0]);
    const z = toScreen(v, [b.x1, b.y1]);
    expect(a[0]).toBeGreaterThanOrEqual(15.99);
    expect(z[0]).toBeLessThanOrEqual(1100 - 15.99);
    expect(a[1]).toBeGreaterThanOrEqual(15.99);
    expect(z[1]).toBeLessThanOrEqual(600 - 15.99);
    expect((a[0] + z[0]) / 2).toBeCloseTo(550, 6);
    expect(fitView({ x0: 0, y0: 0, x1: 10, y1: 10 }, 1000, 1000).k).toBe(1.3);
    expect(fitView({ x0: 0, y0: 0, x1: 1e5, y1: 10 }, 1000, 1000).k).toBe(0.2);
  });

  it('inquadra un percorso nell\'area accanto al pannello', () => {
    const area = visibleArea(1140, 640, 'right');
    expect(area.x1).toBeLessThan(1140 - 330);
    expect(visibleArea(366, 440, 'bottom').y1).toBeLessThan(440 * 0.45);
    const v = frameView({ x0: 0, y0: 0, x1: 200, y1: 100 }, area, 0.3, 1.15);
    const c = toScreen(v, [100, 50]);
    expect(c[0]).toBeCloseTo((area.x0 + area.x1) / 2, 6);
    expect(c[1]).toBeCloseTo((area.y0 + area.y1) / 2, 6);
  });

  it('percorso scelto: intero se leggibile, altrimenti l\'ultimo tratto o il solo arrivo', () => {
    const m = clinica();
    const sc = buildScene(m, topOf);
    const srv = m.nodes.find((n) => n.ip === '10.20.50.10')!;
    const ids = pathToNode(m, srv);
    const wide = frameRoute(m, sc, ids, visibleArea(1140, 640, 'right'), 1.15, 0.5);
    expect(wide.k).toBeGreaterThanOrEqual(0.5);
    // Tutto il percorso dentro l'area visibile accanto al pannello.
    const b = routeBounds(m, sc, ids);
    const area = visibleArea(1140, 640, 'right');
    const a = toScreen(wide, [b.x0, b.y0]);
    const z = toScreen(wide, [b.x1, b.y1]);
    expect(a[0]).toBeGreaterThanOrEqual(area.x0 - 0.01);
    expect(z[0]).toBeLessThanOrEqual(area.x1 + 0.01);
    // Sul telefono il percorso intero sarebbe troppo piccolo: si inquadra la fine, leggibile.
    const phone = frameRoute(m, sc, ids, visibleArea(366, 440, 'bottom'), 1.15, 0.5);
    expect(phone.k).toBeGreaterThanOrEqual(0.5);
    const p = toScreen(phone, sc.nodes.find((s) => s.n.id === srv.id)!.p);
    expect(p[0]).toBeGreaterThan(0);
    expect(p[0]).toBeLessThan(366);
  });

  it('zoom attorno a un punto fermo; passaggio tra due viste con lo zoom geometrico', () => {
    const v = { x: 40, y: -20, k: 0.8 };
    const z = zoomAbout(v, 300, 200, 1.5);
    const wBefore: Pt = [(300 - v.x) / v.k, (200 - v.y) / v.k];
    expect(toScreen(z, wBefore)[0]).toBeCloseTo(300, 6);
    expect(toScreen(z, wBefore)[1]).toBeCloseTo(200, 6);
    const a = { x: 0, y: 0, k: 0.5 };
    const b = { x: 300, y: -100, k: 2 };
    expect(lerpView(a, b, 0, 800, 600)).toEqual(a);
    expect(lerpView(a, b, 1, 800, 600)).toEqual(b);
    expect(lerpView(a, b, 0.5, 800, 600).k).toBeCloseTo(1, 6);
    expect(easeOutCubic(0)).toBe(0);
    expect(easeOutCubic(1)).toBe(1);
    expect(easeOutCubic(0.5)).toBeGreaterThan(0.5);
  });
});

describe('entrata in scena', () => {
  const check = (m: NetworkMap) => {
    const e = entranceSchedule(m);
    const self = m.nodes.find((n) => n.self)!;
    expect(e.node.get(self.id)).toBe(Math.min(...e.node.values()));
    // Prima la zona del PC, poi le altre; i collegamenti dopo i primi dispositivi.
    expect(e.zone.get(self.segment)).toBe(0);
    expect(e.wires).toBeGreaterThan(Math.min(...e.node.values()));
    expect(e.flows).toBeGreaterThanOrEqual(e.wires);
    expect(e.end).toBeLessThanOrEqual(ENTER.total);
    expect(Math.max(...e.node.values()) + ENTER.node).toBeLessThanOrEqual(ENTER.total);
    const delays = m.nodes.filter((n) => !n.self).map((n) => e.node.get(n.id)!).sort((a, b) => a - b);
    const step = (delays[delays.length - 1] - delays[0]) / (delays.length - 1);
    expect(e.node.get(self.id)).toBe(0);
    expect(step).toBeGreaterThanOrEqual(18);
    expect(step).toBeLessThanOrEqual(30);
    return e;
  };
  it('casa e poliambulatorio: questo PC per primo, poi via via più lontano, tutto entro 1,5 s', () => {
    check(casa());
    const m = clinica();
    const e = check(m);
    const self = m.nodes.find((n) => n.self)!;
    const far = m.nodes.slice().sort((a, b) => Math.hypot(b.x - self.x, b.y - self.y) - Math.hypot(a.x - self.x, a.y - self.y))[0];
    expect(e.node.get(far.id)).toBe(Math.max(...e.node.values()));
  });
});
