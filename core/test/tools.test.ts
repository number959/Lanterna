import { describe, expect, it } from 'vitest';
import { ACTIONS } from '../src/engine';
import { ACTION_TOOLS, TOOLS, WINDOWS_TOOLS } from '../src/tools';

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
    expect(included.map((t) => t.id).sort()).toEqual(['bluescreenview', 'crystaldiskinfo', 'crystaldiskmark']);
    for (const t of included) {
      expect(t.included, t.id).toMatch(/^\d+\.\d+(\.\d+)?$/);
      expect(t.license, t.id).toMatch(/licenza MIT|ridistribuibile/);
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
      expect(p.signer.length, t.id).toBeGreaterThan(2);
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
});
