import { describe, expect, it } from 'vitest';
import { clinicScan } from '../src/demo/clinic';
import { demoScan } from '../src/demo/sample';
import { simulatedSpace } from '../src/demo/space';
import { ACTIONS, analyze, METRICS, pctText, reclaimableBytes, renderDocument, sizeText, SPACE_CATEGORY_LABEL, SPACE_HINTS, unattributedBytes } from '../src/engine';
import type { SpaceNode, SpaceReport } from '../src/engine';
import { squarify } from '../src/ui/treemap';

const walk = (n: SpaceNode, f: (n: SpaceNode) => void) => {
  f(n);
  for (const c of n.children ?? []) walk(c, f);
};

describe('mappa dello spazio (squarified)', () => {
  it('rispetta le proporzioni e resta nel rettangolo', () => {
    const values = [500, 433, 300, 120, 80, 60, 33, 12, 6, 2, 1];
    const rect = { x: 10, y: 20, w: 600, h: 340 };
    const out = squarify(
      values.map((v, i) => ({ value: v, item: i })),
      rect,
    );
    expect(out).toHaveLength(values.length);
    const total = values.reduce((a, b) => a + b, 0);
    let area = 0;
    for (const p of out) {
      const a = p.rect.w * p.rect.h;
      area += a;
      expect(a / (rect.w * rect.h)).toBeCloseTo(values[p.item] / total, 6);
      expect(p.rect.x).toBeGreaterThanOrEqual(rect.x - 1e-6);
      expect(p.rect.y).toBeGreaterThanOrEqual(rect.y - 1e-6);
      expect(p.rect.x + p.rect.w).toBeLessThanOrEqual(rect.x + rect.w + 1e-6);
      expect(p.rect.y + p.rect.h).toBeLessThanOrEqual(rect.y + rect.h + 1e-6);
    }
    expect(area).toBeCloseTo(rect.w * rect.h, 3);
    // I rettangoli grandi sono quasi quadrati.
    const big = out.find((p) => p.item === 0)!;
    expect(Math.max(big.rect.w / big.rect.h, big.rect.h / big.rect.w)).toBeLessThan(3);
    // Nessuna sovrapposizione.
    for (let i = 0; i < out.length; i++)
      for (let j = i + 1; j < out.length; j++) {
        const a = out[i].rect;
        const b = out[j].rect;
        const ox = Math.min(a.x + a.w, b.x + b.w) - Math.max(a.x, b.x);
        const oy = Math.min(a.y + a.h, b.y + b.h) - Math.max(a.y, b.y);
        expect(ox <= 1e-6 || oy <= 1e-6).toBe(true);
      }
  });

  it('ignora valori nulli e rettangoli vuoti', () => {
    expect(squarify([{ value: 0, item: 'a' }, { value: -3, item: 'b' }, { value: NaN, item: 'c' }], { x: 0, y: 0, w: 10, h: 10 })).toEqual([]);
    expect(squarify([{ value: 4, item: 'a' }], { x: 0, y: 0, w: 0, h: 10 })).toEqual([]);
    expect(squarify([{ value: 4, item: 'a' }], { x: 0, y: 0, w: 8, h: 5 })).toEqual([{ item: 'a', rect: { x: 0, y: 0, w: 8, h: 5 } }]);
  });
});

describe('cosa occupa spazio: formati e catalogo', () => {
  it('scrive dimensioni e percentuali in italiano', () => {
    expect(sizeText(0)).toBe('0 B');
    expect(sizeText(999)).toBe('999 B');
    expect(sizeText(1_499_000)).toBe('1,5 MB');
    expect(sizeText(999_960_000)).toBe('1,0 GB');
    expect(sizeText(380_200_000_000)).toBe('380,2 GB');
    expect(pctText(1, 10000)).toBe('<0,1 %');
    expect(pctText(553, 1000)).toBe('55,3 %');
    expect(pctText(1, 0)).toBe('');
  });

  it('ha nome, spiegazione e consiglio per ogni cartella nota dell\'agente', () => {
    // Gli stessi identificativi di windows/internal/space/hints.go.
    const ids = ['temp-user', 'temp-windows', 'update-cache', 'delivery-optimization', 'windows-old', 'upgrade-files', 'recycle-bin', 'winsxs', 'installer',
      'error-reports', 'crash-dumps', 'browser-cache', 'package-cache', 'downloads', 'onedrive', 'hibernation', 'pagefile', 'virtual-disks'];
    expect(Object.keys(SPACE_HINTS).sort()).toEqual([...ids].sort());
    for (const h of Object.values(SPACE_HINTS)) {
      expect(h.label.length).toBeGreaterThan(3);
      expect(h.what.length).toBeGreaterThan(30);
      expect(h.how.length).toBeGreaterThan(30);
    }
    expect(Object.keys(SPACE_CATEGORY_LABEL).sort()).toEqual(['archive', 'audio', 'document', 'image', 'other', 'program', 'system', 'video', 'virtualdisk']);
  });
});

describe('analisi dello spazio simulata', () => {
  const cases: [string, SpaceReport][] = [
    ['casa C:', simulatedSpace(demoScan, 'C:')],
    ['casa E:', simulatedSpace(demoScan, 'e:')],
    ['ambulatorio C:', simulatedSpace(clinicScan, 'C:')],
    ['ambulatorio D:', simulatedSpace(clinicScan, 'D:')],
  ];

  it.each(cases)('%s è coerente', (_, r) => {
    const tree = r.tree!;
    expect(r.allocBytes).toBe(tree.alloc);
    expect(r.totalBytes - r.freeBytes).toBeGreaterThanOrEqual(r.allocBytes);
    const ids = new Set<number>();
    walk(tree, (n) => {
      ids.add(n.id);
      const kids = (n.children ?? []).reduce((s, c) => s + c.alloc, 0);
      expect(n.alloc).toBe((n.ownAlloc ?? 0) + kids + (n.more?.alloc ?? 0));
      // Figli in ordine decrescente.
      const a = (n.children ?? []).map((c) => c.alloc);
      expect(a).toEqual([...a].sort((x, y) => y - x));
      // Nessun nome utente: solo %USERPROFILE% o ‹utente N›.
      expect(n.path).not.toMatch(/\\Users\\(?!%|‹|Public)/);
    });
    expect(ids.size).toBeGreaterThan(5);
    for (const h of r.hints ?? []) {
      expect(SPACE_HINTS[h.id]).toBeDefined();
      if (h.nodeId !== undefined) expect(ids.has(h.nodeId)).toBe(true);
    }
    const cats = (r.categories ?? []).reduce((s, c) => s + c.alloc, 0);
    expect(cats).toBe(r.allocBytes);
  });

  it('mostra il caso tipico del PC di casa: C: quasi pieno, Windows.old e download', () => {
    const r = cases[0][1];
    expect(r.hints?.some((h) => h.id === 'windows-old' && h.nodeId)).toBe(true);
    expect(reclaimableBytes(r)).toBeGreaterThan(30e9);
    expect(unattributedBytes(r)).toBeGreaterThan(0);
    expect(r.cloudFiles).toBeGreaterThan(0);
    expect(r.linkedBytes).toBeGreaterThan(0);
  });

  it('non dà spazio non attribuito per una cartella o un\'analisi interrotta', () => {
    const r = cases[0][1];
    expect(unattributedBytes({ ...r, partial: true })).toBe(0);
    expect(unattributedBytes({ ...r, root: 'C:\\Users' })).toBe(0);
  });
});

describe('cosa occupa spazio nel motore e nel documento', () => {
  const withSpace = (scan: typeof demoScan, drives: string[]) => ({ ...scan, pc: { ...scan.pc!, space: drives.map((d) => simulatedSpace(scan, d, new Date('2026-10-30T09:00:00Z'))) } });

  it('valuta lo spazio recuperabile e propone azioni mirate', () => {
    const a = analyze(withSpace(demoScan, ['C:']));
    const f = a.findings.find((x) => x.id === 'pc.spacereclaim.C')!;
    expect(f.severity).toBe('info');
    expect(f.value).toMatch(/^circa \d+,\d GB$/);
    expect(f.verdict).toContain('Installazione precedente di Windows');
    expect(f.verdict).toContain('Cartella Download');
    expect(f.verdict).toContain('30/10/2026');
    expect(f.actions).toEqual(expect.arrayContaining(['remove-windows-old', 'free-disk-space', 'review-large-files']));
    // Lo spazio quasi esaurito su C: dice dove sta lo spazio e mette prima Windows.old.
    const low = a.findings.find((x) => x.id === 'pc.space.C')!;
    expect(low.severity).not.toBe('ok');
    expect(low.verdict).toContain("Dall'analisi delle cartelle");
    expect(low.actions[0]).toBe('remove-windows-old');
    for (const id of [...f.actions, ...low.actions]) expect(ACTIONS[id], id).toBeDefined();
    expect(METRICS['pc.spacereclaim']).toBeDefined();
  });

  it('senza analisi suggerisce di farla quando lo spazio scarseggia', () => {
    const a = analyze(demoScan);
    expect(a.findings.find((x) => x.id === 'pc.space.C')!.actions).toEqual(['space-analysis', 'free-disk-space']);
    expect(a.findings.some((x) => x.id.startsWith('pc.spacereclaim'))).toBe(false);
  });

  it('propone di compattare i dischi virtuali grandi', () => {
    const a = analyze(withSpace(clinicScan, ['C:', 'D:']));
    const d = a.findings.find((x) => x.id === 'pc.spacereclaim.D')!;
    expect(d.actions).toEqual(['compact-virtual-disks']);
    expect(a.findings.find((x) => x.id === 'pc.spacereclaim.C')!.actions).not.toContain('remove-windows-old');
  });

  it('nel documento mette totali, tipi e cartelle note, senza nomi di file o profili', () => {
    const scan = withSpace(demoScan, ['C:']);
    const html = renderDocument(scan, analyze(scan));
    expect(html).toContain('<h2>Cosa occupa spazio</h2>');
    expect(html).toContain('Unità C:, analisi del 30/10/2026');
    expect(html).toContain('Installazione precedente di Windows (Windows.old)');
    expect(html).toContain('Si libera con Windows');
    expect(html).not.toContain('Vacanze 2025.mkv');
    expect(html).not.toContain('%USERPROFILE%');
    expect(html).not.toContain('Videos');
  });
});
