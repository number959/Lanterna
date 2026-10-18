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

  it('le scorciatoie del piano d\'azione puntano ad azioni e strumenti esistenti', () => {
    const actions = new Set(Object.keys(ACTIONS));
    const tools = new Set(WINDOWS_TOOLS.map((w) => w.id));
    for (const [action, list] of Object.entries(ACTION_TOOLS)) {
      expect(actions.has(action), action).toBe(true);
      for (const id of list) expect(tools.has(id), `${action}: ${id}`).toBe(true);
    }
  });
});
