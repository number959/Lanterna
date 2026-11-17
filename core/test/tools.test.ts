import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { ACTIONS } from '../src/engine';
import { ACTION_APPS, ACTION_TOOLS, TOOLS, WINDOWS_TOOLS } from '../src/tools';

describe('cassetta degli attrezzi', () => {
  it('identificativi unici, siti https e licenza dichiarata', () => {
    const ids = [...TOOLS.map((t) => t.id), ...WINDOWS_TOOLS.map((w) => w.id)];
    expect(new Set(ids).size).toBe(ids.length);
    for (const t of TOOLS) {
      expect(t.site, t.id).toMatch(/^https:\/\/[a-z0-9.-]+\//);
      expect(t.license.length, t.id).toBeGreaterThan(5);
      expect(t.what.length, t.id).toBeGreaterThan(20);
    }
  });

  it('inclusi nel pacchetto solo i programmi ridistribuibili, gli altri si scaricano', () => {
    const included = TOOLS.filter((t) => t.included);
    expect(included.map((t) => t.id).sort()).toEqual(['bluescreenview', 'crystaldiskinfo', 'crystaldiskmark', 'usbtreeview']);
    for (const t of included) {
      expect(t.included, t.id).toMatch(/^\d+\.\d+(\.\d+)?$/);
      expect(t.license, t.id).toMatch(/licenza MIT|ridistribuibile|includerlo in altri programmi/);
      expect(t.portable, t.id).toBeUndefined();
    }
    // CPU-Z resta fuori dal pacchetto: il produttore non ne concede la
    // ridistribuzione. Polaris lo scarica dal sito ufficiale, con la firma.
    const cpuz = TOOLS.find((t) => t.id === 'cpu-z');
    expect(cpuz?.included).toBeUndefined();
    expect(cpuz?.portable?.signer).toBe('CPUID');
    for (const t of TOOLS.filter((x) => x.portable)) {
      const p = t.portable!;
      expect(p.from, t.id).toMatch(/^[a-z0-9.-]+\.[a-z]+$/);
      // Senza firmatario solo un file da non avviare, verificato con l'impronta del produttore (l'immagine di Memtest86+).
      if (p.reveal) expect(p.signer, t.id).toBe('');
      else expect(p.signer.length, t.id).toBeGreaterThan(2);
      expect(p.mb, t.id).toBeGreaterThan(0);
      expect(p.terms.length, t.id).toBeGreaterThan(5);
    }
  });

  it('le scorciatoie del piano d\'azione puntano ad azioni e strumenti esistenti', () => {
    const actions = new Set(Object.keys(ACTIONS));
    const tools = new Set(WINDOWS_TOOLS.map((w) => w.id));
    for (const [action, list] of Object.entries(ACTION_TOOLS)) {
      expect(actions.has(action), action).toBe(true);
      for (const id of list) expect(tools.has(id), `${action}: ${id}`).toBe(true);
    }
  });

  it('«Polaris fa già» rimanda a sezioni che esistono nella vista Computer', () => {
    const pc = readFileSync(new URL('../src/ui/pc.tsx', import.meta.url), 'utf-8');
    const sections = new Set([...pc.matchAll(/<Section title="([^"]+)"/g)].map((m) => m[1]));
    expect(sections.has('Processi')).toBe(true);
    for (const t of TOOLS) {
      for (const m of (t.polaris ?? '').matchAll(/Computer > ((?:(?! e Computer)[^:;,.])+)/g)) expect(sections.has(m[1].trim()), `${t.id}: ${m[1]}`).toBe(true);
    }
    const ref = (id: string) => TOOLS.find((t) => t.id === id)!.polaris!;
    expect(ref('process-explorer')).toMatch(/^Computer > Processi:/);
    expect(ref('tcpview')).toMatch(/^Computer > Processi:/);
    expect(ref('autoruns')).toMatch(/^Computer > Avvio automatico:/);
    expect(ref('process-monitor')).toContain('Computer > Processi');
    expect(ref('pc-health-check')).toMatch(/^Computer > Requisiti di Windows 11:/);
    // La scheda Processi ha l'albero: non si dice più che serve Process Explorer per vederlo.
    expect(ref('process-explorer')).not.toMatch(/per l'albero/);
  });

  it('TCPView e Process Monitor compaiono nelle azioni su connessioni, avvio e servizi', () => {
    expect(ACTION_APPS['review-listening-app']).toContain('tcpview');
    expect(ACTION_APPS['review-startup-entry']).toContain('process-monitor');
    expect(ACTION_APPS['fix-unquoted-service-path']).toContain('process-monitor');
  });
});
