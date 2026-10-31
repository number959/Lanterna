import { describe, expect, it } from 'vitest';
import { clinicScan } from '../src/demo/clinic';
import { demoScan } from '../src/demo/sample';
import { simulatedSpace } from '../src/demo/space';
import { ACTIONS, analyze, METRICS, pctText, reclaimableBytes, renderDocument, sizeText, SPACE_CATEGORY_LABEL, SPACE_HINTS, unattributedBytes } from '../src/engine';
import type { Scan, SpaceNode, SpaceReport } from '../src/engine';
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

  it('conta come recuperabile solo ciò che liberano gli strumenti di Windows', () => {
    // Le cache dei browser si svuotano dal browser; i download di Windows Update li gestisce Windows.
    expect(SPACE_HINTS['browser-cache'].risk).toBe('app');
    expect(SPACE_HINTS['update-cache'].risk).toBe('keep');
    expect(SPACE_HINTS['update-cache'].how).not.toContain('Pulizia disco');
    expect(SPACE_HINTS['windows-old'].how).toContain('Windows.old\\Users');
    expect(SPACE_HINTS['virtual-disks'].how).toContain('WindowsImageBackup');
    const r = { hints: [{ id: 'browser-cache', alloc: 6e9 }, { id: 'update-cache', alloc: 3e9 }, { id: 'temp-user', alloc: 2e9 }] } as SpaceReport;
    expect(reclaimableBytes(r)).toBe(2e9);
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
    const byId = new Map<number, SpaceNode>();
    walk(tree, (n) => byId.set(n.id, n));
    for (const h of r.hints ?? []) {
      expect(SPACE_HINTS[h.id]).toBeDefined();
      // L'agente ricava la cartella nota dalla cartella stessa.
      if (h.nodeId !== undefined) expect(Math.abs(byId.get(h.nodeId)!.alloc - h.alloc), h.id).toBeLessThan(1e6);
    }
    const cats = (r.categories ?? []).reduce((s, c) => s + c.alloc, 0);
    expect(cats).toBe(r.allocBytes);
    // Lo spazio non attribuito resta sotto il 10 % dello spazio usato.
    const used = r.totalBytes - r.freeBytes;
    expect((used - r.allocBytes) / used).toBeLessThan(0.1);
    // Ogni tipo vale almeno i file più grandi elencati con quell'estensione; i file di sistema esattamente.
    const keyOf = (path: string) => {
      const name = path.split('\\').pop()!.toLowerCase();
      return name === 'pagefile.sys' || name === 'hiberfil.sys' ? name : name.slice(name.lastIndexOf('.'));
    };
    const listed = new Map<string, number>();
    for (const f of r.topFiles ?? []) listed.set(keyOf(f.path), (listed.get(keyOf(f.path)) ?? 0) + f.alloc);
    for (const [key, sum] of listed) {
      const t = (r.types ?? []).find((x) => x.id === key);
      expect(t, key).toBeDefined();
      if (key.endsWith('.sys')) expect(t!.alloc, key).toBe(sum);
      else expect(t!.alloc, key).toBeGreaterThanOrEqual(sum);
    }
  });

  it('mostra il caso tipico del PC di casa: C: quasi pieno, Windows.old e download', () => {
    const r = cases[0][1];
    expect(r.hints?.some((h) => h.id === 'windows-old' && h.nodeId)).toBe(true);
    expect(reclaimableBytes(r)).toBeGreaterThan(25e9);
    expect(unattributedBytes(r)).toBeGreaterThan(0);
    expect(r.cloudFiles).toBeGreaterThan(0);
    expect(r.linkedBytes).toBeGreaterThan(0);
  });

  it('nell\'ambulatorio il backup d\'immagine non è un disco virtuale e i download sono quelli dell\'utente', () => {
    const c = cases[2][1];
    const dl = c.hints?.find((h) => h.id === 'downloads');
    expect(dl?.path).toBe('%USERPROFILE%\\Downloads');
    expect(dl?.nodeId).toBeDefined();
    const d = cases[3][1];
    expect(d.hints?.some((h) => h.id === 'virtual-disks')).toBe(false);
    expect(d.topFiles?.some((f) => /\\WindowsImageBackup\\.*\.vhdx$/.test(f.path))).toBe(true);
  });

  it('non dà spazio non attribuito per una cartella o un\'analisi interrotta', () => {
    const r = cases[0][1];
    expect(unattributedBytes({ ...r, partial: true })).toBe(0);
    expect(unattributedBytes({ ...r, root: 'C:\\Users' })).toBe(0);
  });
});

describe('cosa occupa spazio nel motore e nel documento', () => {
  const withSpace = (scan: typeof demoScan, drives: string[]) => ({ ...scan, pc: { ...scan.pc!, space: drives.map((d) => simulatedSpace(scan, d, new Date('2026-10-30T09:00:00Z'))) } });
  const withReports = (scan: Scan, space: SpaceReport[]): Scan => ({ ...scan, pc: { ...scan.pc!, space } });

  it('valuta lo spazio recuperabile e propone azioni mirate', () => {
    const a = analyze(withSpace(demoScan, ['C:']));
    const f = a.findings.find((x) => x.id === 'pc.spacereclaim.C')!;
    expect(f.severity).toBe('info');
    expect(f.value).toMatch(/^circa \d+,\d GB$/);
    expect(f.verdict).toContain('Installazione precedente di Windows');
    expect(f.verdict).toContain('Cartella Download');
    expect(f.verdict).toContain('30/10/2026');
    expect(f.verdict).toContain('Si svuotano dal programma che le usa: Cache dei browser 4,2 GB.');
    expect(f.verdict).not.toContain('Download di Windows Update');
    expect(f.actions).toEqual(expect.arrayContaining(['remove-windows-old', 'free-disk-space', 'review-large-files']));
    expect(f.actions).not.toContain('space-analysis');
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

  it('propone di compattare i dischi virtuali grandi, non i backup d\'immagine', () => {
    const a = analyze(withSpace(clinicScan, ['C:', 'D:']));
    expect(a.findings.find((x) => x.id === 'pc.spacereclaim.D')!.actions).not.toContain('compact-virtual-disks');
    expect(a.findings.find((x) => x.id === 'pc.spacereclaim.C')!.actions).not.toContain('remove-windows-old');
    const vm = { ...simulatedSpace(clinicScan, 'D:'), hints: [{ id: 'virtual-disks', alloc: 42e9, files: 2 }] };
    const b = analyze(withReports(clinicScan, [vm]));
    expect(b.findings.find((x) => x.id === 'pc.spacereclaim.D')!.actions).toEqual(['compact-virtual-disks']);
  });

  it('propone di rimuovere Windows.old solo sull\'unità di sistema', () => {
    const old = { ...simulatedSpace(clinicScan, 'D:'), hints: [{ id: 'windows-old', alloc: 15e9, files: 90000 }] };
    const a = analyze(withReports(clinicScan, [old]));
    expect(a.findings.find((x) => x.id === 'pc.spacereclaim.D')!.actions).not.toContain('remove-windows-old');
  });

  it('con un\'analisi interrotta non dice che non c\'è nulla e propone di ripeterla', () => {
    const full = simulatedSpace(demoScan, 'C:', new Date('2026-10-30T09:00:00Z'));
    const part: SpaceReport = { ...full, partial: true, hints: full.hints!.filter((h) => h.id === 'downloads' || h.id === 'onedrive') };
    const a = analyze(withReports(demoScan, [part]));
    const f = a.findings.find((x) => x.id === 'pc.spacereclaim.C')!;
    expect(f.severity).toBe('info');
    expect(f.value).toBe('nulla di rilevante (analisi parziale)');
    expect(f.verdict).not.toContain('Nessuna cartella');
    expect(f.verdict).toContain('Analisi interrotta: i valori possono essere più alti');
    expect(f.actions).toContain('space-analysis');
    const low = a.findings.find((x) => x.id === 'pc.space.C')!;
    expect(low.verdict).toContain('(analisi parziale).');
    expect(low.actions).toContain('space-analysis');
  });

  it('senza i diritti di amministratore avverte che il recuperabile può essere più alto', () => {
    // Senza amministratore la cartella Temp di Windows non si legge e manca dalle cartelle note.
    const full = simulatedSpace(demoScan, 'C:');
    const scan = withReports(demoScan, [{ ...full, hints: full.hints!.filter((h) => h.id !== 'temp-windows') }]);
    const a = analyze({ ...scan, agent: { ...scan.agent, elevated: false } });
    const f = a.findings.find((x) => x.id === 'pc.spacereclaim.C')!;
    expect(f.verdict).toContain('amministratore');
    expect(f.actions).toContain('space-analysis');
    const b = analyze({ ...scan, agent: { ...scan.agent, elevated: true } });
    expect(b.findings.find((x) => x.id === 'pc.spacereclaim.C')!.verdict).not.toContain('amministratore');
  });

  it('tiene le cache dei browser fuori dal recuperabile', () => {
    const r = { ...simulatedSpace(demoScan, 'C:'), hints: [{ id: 'browser-cache', alloc: 6e9, files: 30000 }] };
    const f = analyze(withReports(demoScan, [r])).findings.find((x) => x.id === 'pc.spacereclaim.C')!;
    expect(f.severity).toBe('ok');
    expect(f.value).toBe('nulla di rilevante');
    expect(f.verdict).not.toContain('Si libera con gli strumenti di Windows');
    expect(f.verdict).toContain('Si svuotano dal programma che le usa: Cache dei browser 6,0 GB.');
    expect(f.actions).not.toContain('free-disk-space');
  });

  it('nel documento mette totali, tipi e cartelle note, senza nomi di file o profili', () => {
    const scan = withSpace(demoScan, ['C:']);
    const html = renderDocument(scan, analyze(scan));
    expect(html).toContain('<h2>Cosa occupa spazio</h2>');
    expect(html).toContain('Unità C:, analisi del 30/10/2026');
    expect(html).toContain('Installazione precedente di Windows (Windows.old)');
    expect(html).toContain('Si libera con Windows');
    expect(html).toContain('Si libera dal programma');
    expect(html).not.toContain('Vacanze 2025.mkv');
    expect(html).not.toContain('%USERPROFILE%');
    expect(html).not.toContain('Videos');
    const err = withReports(demoScan, [{ ...scan.pc.space[0], errors: 3 }]);
    expect(renderDocument(err, analyze(err))).toContain('3 cartelle non lette per errori del disco');
  });
});
