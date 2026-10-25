import { describe, expect, it } from 'vitest';
import { pushSample, simulateClock } from '../src/ui/clock';
import type { ClockState } from '../src/ui/clock';

describe('velocità dei core in tempo reale', () => {
  it('la simulazione della demo resta plausibile e coerente', () => {
    for (let t = 0; t < 200; t++) {
      const s = simulateClock(2900, 16, t);
      expect(s.cores).toHaveLength(16);
      for (const c of s.cores) {
        expect(c.mhz).toBeGreaterThanOrEqual(2900 * 0.6);
        expect(c.mhz).toBeLessThanOrEqual(2900 * 1.65);
        expect(c.loadPct).toBeGreaterThanOrEqual(0);
        expect(c.loadPct).toBeLessThanOrEqual(100);
      }
      const avg = s.cores.reduce((a, c) => a + c.mhz, 0) / 16;
      expect(Math.abs(s.mhz - avg)).toBeLessThanOrEqual(0.5);
      expect(s.maxMhz).toBe(Math.max(...s.cores.map((c) => c.mhz)));
      expect(s.perfPct).toBe(Math.round((100 * s.mhz) / 2900));
    }
    // Ripetibile: stessi valori allo stesso istante.
    expect(simulateClock(3200, 8, 42).cores).toEqual(simulateClock(3200, 8, 42).cores);
    // E varia nel tempo.
    expect(simulateClock(3200, 8, 1).mhz).not.toBe(simulateClock(3200, 8, 12).mhz);
  });

  it('tiene gli ultimi 60 secondi e il massimo della sessione', () => {
    let st: ClockState = { history: [], peak: 0, tick: 0 };
    for (let t = 0; t < 75; t++) st = pushSample(st, simulateClock(2000, 4, t));
    expect(st.history).toHaveLength(60);
    expect(st.tick).toBe(75);
    const seen = Array.from({ length: 75 }, (_, t) => simulateClock(2000, 4, t).maxMhz);
    expect(st.peak).toBe(Math.max(...seen));
    expect(st.history[59]).toBe(simulateClock(2000, 4, 74).mhz);
    expect(st.error).toBeUndefined();
  });
});
