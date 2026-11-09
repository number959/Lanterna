import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { ACTIONS, analyze, documentParts, failedUpdates, lastQualityUpdate, METRICS, WU_ERRORS, wuErrorText, wuGroup } from '../src/engine';
import type { Finding, Scan, UpdateEntry } from '../src/engine';
import { clinicScan } from '../src/demo/clinic';
import { demoScan } from '../src/demo/sample';
import { guideById } from '../src/guides';
import { MaintCard } from '../src/ui/maint';

// Aggiornamenti non riusciti e servizio di Windows Update, esito di
// Diagnostica memoria, file system da controllare.

const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const find = (s: Scan, id: string): Finding | undefined => analyze(s).findings.find((f) => f.id === id);
const entry = (p: Partial<UpdateEntry>): UpdateEntry => ({ title: 'Aggiornamento (KB5000001)', kb: 'KB5000001', kind: 'quality', operation: 'install', result: 'succeeded', date: '2026-10-01T03:00:00Z', ...p });
const NOW = Date.parse('2026-10-12T20:30:00Z');

describe('Windows Update', () => {
  it('spiega i codici e li raggruppa', () => {
    expect(wuErrorText('0x800F081F')).toBe('0x800F081F (CBS_E_SOURCE_MISSING: mancano file dell\'archivio dei componenti di Windows)');
    expect(wuErrorText('0x12345678')).toBe('0x12345678');
    expect(wuErrorText(undefined)).toBe('senza codice');
    expect(wuGroup('0x80070422')).toBe('service');
    expect(wuGroup('0xC1900101')).toBe('driver');
    expect(wuGroup('0x1')).toBe('other');
    for (const k of Object.keys(WU_ERRORS)) expect(k).toMatch(/^0x[0-9A-F]{8}$/);
  });

  it('un fallimento seguito da un successo dello stesso aggiornamento è risolto; le firme di Defender non contano', () => {
    const h = [
      entry({ result: 'succeeded', date: '2026-10-05T03:00:00Z', updateId: 'u1' }),
      entry({ result: 'failed', hresult: '0x80242014', date: '2026-10-03T03:00:00Z', updateId: 'u1' }),
      entry({ kb: 'KB5000002', title: 'B (KB5000002)', result: 'failed', hresult: '0x800F081F', date: '2026-10-02T03:00:00Z' }),
      entry({ kb: 'KB5000002', title: 'B (KB5000002)', result: 'failed', hresult: '0x800F081F', date: '2026-10-01T03:00:00Z' }),
      entry({ kind: 'definition', kb: 'KB2267602', result: 'failed', date: '2026-10-04T03:00:00Z' }),
      entry({ kb: 'KB5000003', result: 'failed', date: '2026-08-01T03:00:00Z' }),
    ];
    const f = failedUpdates(h, NOW);
    expect(f.map((x) => [x.entry.kb, x.resolved])).toEqual([
      ['KB5000001', true],
      ['KB5000002', false],
    ]);
    expect(failedUpdates(null, NOW)).toEqual([]);
  });

  it('ultimo aggiornamento: il più recente tra cronologia e Get-HotFix, senza firme e driver', () => {
    expect(lastQualityUpdate({ pendingReboot: false, lastInstalled: '2026-09-09', lastKB: 'KB1', history: [entry({ date: '2026-10-01T03:00:00Z', kb: 'KB2' })] })).toEqual({ date: '2026-10-01T03:00:00Z', kb: 'KB2' });
    expect(lastQualityUpdate({ pendingReboot: false, lastInstalled: '2026-09-09', lastKB: 'KB1', history: [entry({ kind: 'definition', date: '2026-10-11T03:00:00Z' }), entry({ kind: 'driver', date: '2026-10-10T03:00:00Z' })] })).toEqual({
      date: '2026-09-09',
      kb: 'KB1',
    });
    expect(lastQualityUpdate(undefined)).toBeUndefined();
  });

  it('casa: aggiornamenti cumulativi falliti per l\'archivio dei componenti', () => {
    const s = clone(demoScan);
    const f = find(s, 'pc.updates.failed')!;
    expect(f.severity).toBe('warn');
    expect(f.value).toBe('2 non installati negli ultimi 30 giorni');
    expect(f.verdict).toContain('KB5066835 l\'8 ottobre 2026: errore 0x800F081F (CBS_E_SOURCE_MISSING');
    expect(f.verdict).toContain('si ripara con DISM e SFC');
    expect(f.actions).toEqual(['repair-windows', 'update-windows']);
    expect(find(s, 'pc.updates')!.value).toContain('11/11/2025');
    expect(find(s, 'pc.updates.service')).toBeUndefined();
  });

  it('servizio disattivato: critico; criteri senza server dell\'organizzazione: da migliorare; gestito: informazione', () => {
    const s = clone(clinicScan);
    expect(find(s, 'pc.updates.failed')).toBeUndefined();
    expect(find(s, 'pc.updates.service')).toBeUndefined();
    s.pc!.updates!.service!.wu = { start: 'disabled' };
    let f = find(s, 'pc.updates.service')!;
    expect(f.severity).toBe('crit');
    expect(f.actions).toEqual(['enable-windows-update']);
    s.pc!.updates!.service!.wu = { start: 'manual' };
    s.pc!.updates!.policy = { noAutoUpdate: true, managed: true };
    f = find(s, 'pc.updates.service')!;
    expect(f.severity).toBe('info');
    expect(f.actions).toEqual([]);
    s.pc!.updates!.policy = { noAutoUpdate: true };
    expect(find(s, 'pc.updates.service')!.severity).toBe('warn');
    s.pc!.updates!.policy = undefined;
    s.pc!.updates!.historyError = '0x80070422';
    expect(find(s, 'pc.updates.service')!.severity).toBe('crit');
  });
});

describe('Diagnostica memoria Windows', () => {
  it('casa: test pianificato senza esito; clinica: nessun errore', () => {
    const h = find(clone(demoScan), 'pc.memdiag')!;
    expect(h.severity).toBe('info');
    expect(h.verdict).toContain('pianificato il 28 settembre 2026');
    const c = find(clone(clinicScan), 'pc.memdiag')!;
    expect(c.severity).toBe('ok');
    expect(c.value).toBe('nessun errore, 18/06/2026');
  });

  it('errori: critico; nessun test: nessuna voce', () => {
    const s = clone(clinicScan);
    s.pc!.memDiag = { days: 365, results: [{ time: '2026-10-01T08:00:00Z', id: 1202, errors: true }] };
    const f = find(s, 'pc.memdiag')!;
    expect(f.severity).toBe('crit');
    expect(f.actions).toEqual(['test-memory', 'check-hardware']);
    s.pc!.memDiag = { days: 365, results: [] };
    expect(find(s, 'pc.memdiag')).toBeUndefined();
  });
});

describe('file system', () => {
  it('casa: chiavetta da controllare e un controllo all\'avvio; clinica: disco dell\'archivio da correggere', () => {
    const h = find(clone(demoScan), 'pc.fs')!;
    expect(h.severity).toBe('info');
    expect(h.verdict).toContain('E:: Windows lo controllerà al prossimo avvio');
    expect(h.verdict).toContain('scollegata senza la rimozione sicura');
    const c = find(clone(clinicScan), 'pc.fs')!;
    expect(c.severity).toBe('warn');
    expect(c.verdict).toContain('D:: secondo Windows serve una correzione rapida');
    expect(c.actions).toEqual(['check-disk-errors', 'backup-replace-disk']);
  });

  it('disco di sistema da riparare: critico; tre controlli all\'avvio: da migliorare; niente da segnalare: nessuna voce', () => {
    const s = clone(clinicScan);
    s.pc!.volumes![0].health = 'repair';
    expect(find(s, 'pc.fs')!.severity).toBe('crit');
    const b = clone(clinicScan);
    b.pc!.volumes!.forEach((v) => {
      v.dirty = false;
      v.health = 'healthy';
    });
    expect(find(b, 'pc.fs')).toBeUndefined();
    b.pc!.fsChecks = [1, 2, 3].map((d) => ({ time: `2026-10-0${d}T08:00:00Z`, source: 'wininit' as const, id: 1001, drive: 'C:' }));
    const f = find(b, 'pc.fs')!;
    expect(f.severity).toBe('warn');
    expect(f.verdict).toContain('3 controlli all\'avvio negli ultimi 30 giorni');
  });

  it('eventi NTFS: riparazione automatica e scritture non riuscite', () => {
    const s = clone(clinicScan);
    s.pc!.events = [{ kind: 'fs-repaired', source: 'Microsoft-Windows-Ntfs', id: 130, count: 2, last: '2026-10-10T10:00:00Z', detail: 'C:' }];
    let f = find(s, 'pc.events.disk')!;
    expect(f.severity).toBe('info');
    expect(f.verdict).toContain('Windows ha trovato e corretto da solo');
    s.pc!.events = [{ kind: 'fs-flush', source: 'Microsoft-Windows-Ntfs', id: 140, count: 12, last: '2026-10-10T10:00:00Z' }];
    f = find(s, 'pc.events.disk')!;
    expect(f.severity).toBe('warn');
    expect(f.verdict).toContain('12 scritture sul disco non riuscite');
  });
});

describe('catalogo, guida, documento e scheda', () => {
  it('voci, azioni e guida', () => {
    for (const id of ['pc.memdiag', 'pc.updates.failed', 'pc.updates.service', 'pc.fs']) expect(METRICS[id], id).toBeTruthy();
    expect(ACTIONS['enable-windows-update']).toBeTruthy();
    const g = guideById('manutenzione-windows')!;
    const table = g.blocks.find((b) => b.t === 'table' && b.caption === 'Codici di Windows Update');
    expect(table && table.t === 'table' ? table.rows.length : 0).toBe(Object.keys(WU_ERRORS).length);
  });

  it('documento e scheda', () => {
    const s = clone(demoScan);
    const html = documentParts(s, analyze(s)).body;
    expect(html).toContain('<h2>Aggiornamenti e controlli di Windows</h2>');
    expect(html).toContain('KB5066835');
    expect(html).toContain('nessun esito registrato');
    const card = renderToStaticMarkup(createElement(MaintCard, { pc: s.pc!, live: false, now: NOW }));
    expect(card).toContain('2 ancora da installare');
    expect(card).toContain('Test pianificato il 28/09/2026');
    expect(card).not.toContain('KB2267602');
    expect(card).not.toContain('Apri');
    const live = renderToStaticMarkup(createElement(MaintCard, { pc: clone(clinicScan).pc!, live: true, now: NOW }));
    expect(live).toContain('gestito dall&#x27;organizzazione');
    expect(live).toContain('serve una correzione rapida');
    expect(live).toContain('Apri la cronologia degli aggiornamenti');
  });
});
