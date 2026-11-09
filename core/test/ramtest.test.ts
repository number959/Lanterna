import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { ACTIONS, analyze, METRICS, ramTestSeverity } from '../src/engine';
import type { RamTest, Scan } from '../src/engine';
import { demoScan } from '../src/demo/sample';
import { RamTestCard, simulatedRamTest } from '../src/ui/ramtest';
import type { ViewProps } from '../src/ui/views';

// Test della RAM con Windows acceso: giudizio (errori, parziale, pulito),
// simulazione della demo e scheda.

const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const base = (p: Partial<RamTest> = {}): RamTest => ({
  startedAt: '2026-10-12T20:00:00Z',
  durationMs: 180000,
  preset: 'quick',
  plannedSec: 180,
  stop: 'time',
  totalMB: 8192,
  availableMB: 4096,
  testedMB: 3072,
  lockedMB: 3072,
  threads: 8,
  passes: 3,
  tests: [{ name: 'own-address', runs: 3, errors: 0 }],
  errors: 0,
  ...p,
});
const withRam = (r: RamTest): Scan => {
  const s = clone(demoScan);
  s.pc!.bench = { ...(s.pc!.bench ?? {}), ram: r };
  return s;
};

describe('test della RAM', () => {
  it('pulito, parziale, con errori', () => {
    expect(ramTestSeverity(base())).toBe('ok');
    expect(ramTestSeverity(base({ lockedMB: 1024 }))).toBe('info');
    expect(ramTestSeverity(base({ passes: 0 }))).toBe('info');
    expect(ramTestSeverity(base({ stop: 'cancelled' }))).toBe('info');
    expect(ramTestSeverity(base({ testedMB: 1024, lockedMB: 1024 }))).toBe('info');
    expect(ramTestSeverity(base({ errors: 1 }))).toBe('crit');
    const ok = analyze(withRam(base())).findings.find((f) => f.id === 'pc.ramtest')!;
    expect(ok.severity).toBe('ok');
    expect(ok.value).toBe('nessun errore su 3,0 GB');
    expect(ok.verdict).toContain('Non garantisce che tutta la RAM sia sana');
    const bad = analyze(withRam(base({ errors: 3, errorSamples: [{ test: 'mi-01', pass: 0, offsetMB: 12.5, expected: '0000000000000000', actual: '0000000000002000' }], badBits: '0000000000002000 (1 bit)' }))).findings.find((f) => f.id === 'pc.ramtest')!;
    expect(bad.severity).toBe('crit');
    expect(bad.actions).toEqual(['ram-default-settings', 'memtest-usb']);
    expect(METRICS['pc.ramtest']).toBeTruthy();
    expect(ACTIONS['memtest-usb'] && ACTIONS['ram-default-settings']).toBeTruthy();
  });

  it('simulazione della demo e scheda', () => {
    const sim = simulatedRamTest(clone(demoScan), 'long');
    expect(sim.errors).toBe(0);
    expect(sim.tests.some((t) => t.name === 'bit-fade')).toBe(true);
    expect(ramTestSeverity(sim)).not.toBe('crit');
    const props = { scan: withRam(base({ errors: 1, errorSamples: [{ test: 'mi-01', pass: 0, offsetMB: 12.5, expected: '0000000000000000', actual: '0000000000002000' }], badBits: '0000000000002000 (1 bit)' })), live: true, source: 'agent', addBench: () => undefined } as unknown as ViewProps;
    const html = renderToStaticMarkup(createElement(RamTestCard, props));
    expect(html).toContain('Avvia il test della RAM');
    expect(html).toContain('1 errore trovato su 3,0 GB');
    expect(html).toContain('Inversioni con zeri e uni');
    expect(html).toContain('non indica il modulo né lo slot');
    const off = renderToStaticMarkup(createElement(RamTestCard, { ...props, live: false, source: 'file' } as ViewProps));
    expect(off).toContain('Il test si avvia solo con Polaris in esecuzione su questo PC');
  });
});
