import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { CUES, schedule } from '../src/ui/sound';
import type { Cue } from '../src/ui/sound';

// Contesto audio finto: registra oscillatori, frequenze e inviluppi.
class FakeParam {
  events: [string, number, number][] = [];
  value = 0;
  setValueAtTime(v: number, t: number) {
    this.events.push(['set', v, t]);
  }
  exponentialRampToValueAtTime(v: number, t: number) {
    this.events.push(['exp', v, t]);
  }
}
class FakeNode {
  gain = new FakeParam();
  frequency = new FakeParam();
  type = '';
  started?: number;
  stopped?: number;
  connected: unknown[] = [];
  connect(n: unknown) {
    this.connected.push(n);
    return n;
  }
  start(t: number) {
    this.started = t;
  }
  stop(t: number) {
    this.stopped = t;
  }
}
class FakeCtx {
  state: 'suspended' | 'running' = 'suspended';
  currentTime = 10;
  destination = new FakeNode();
  oscillators: FakeNode[] = [];
  gains: FakeNode[] = [];
  createOscillator() {
    const o = new FakeNode();
    this.oscillators.push(o);
    return o;
  }
  createGain() {
    const g = new FakeNode();
    this.gains.push(g);
    return g;
  }
  resume() {
    this.state = 'running';
    return Promise.resolve();
  }
}

describe('suoni dell\'interfaccia', () => {
  it('segnali brevi, udibili e senza volumi eccessivi', () => {
    for (const [cue, notes] of Object.entries(CUES)) {
      expect(notes.length, cue).toBeGreaterThan(0);
      const end = Math.max(...notes.map((n) => n.t + n.d));
      expect(end, `${cue} dura troppo`).toBeLessThanOrEqual(0.8);
      for (const n of notes) {
        expect(n.f, cue).toBeGreaterThanOrEqual(100);
        expect(n.f, cue).toBeLessThanOrEqual(3000);
        expect(n.d, cue).toBeGreaterThan(0);
        expect(n.t, cue).toBeGreaterThanOrEqual(0);
        expect(n.g ?? 1, cue).toBeLessThanOrEqual(1);
      }
    }
  });

  it('programma ogni nota con attacco e coda morbidi', () => {
    const ctx = new FakeCtx();
    const out = new FakeNode();
    schedule(ctx as unknown as BaseAudioContext, out as unknown as AudioNode, 'complete', 2);
    expect(ctx.oscillators).toHaveLength(CUES.complete.length);
    CUES.complete.forEach((n, i) => {
      const o = ctx.oscillators[i];
      const g = ctx.gains[i];
      expect(o.frequency.events[0]).toEqual(['set', n.f, 2 + n.t]);
      expect(o.started).toBeCloseTo(2 + n.t);
      expect(o.stopped!).toBeGreaterThan(2 + n.t + n.d);
      // Parte quasi da zero, sale al picco e torna quasi a zero: niente clic.
      expect(g.gain.events[0][1]).toBeLessThan(0.001);
      expect(g.gain.events.at(-1)![1]).toBeLessThan(0.001);
      expect(g.connected).toContain(out);
    });
  });
});

describe('interruttore e riproduzione', () => {
  let store: Record<string, string>;
  let created: FakeCtx[];

  beforeEach(() => {
    vi.resetModules();
    store = {};
    created = [];
    vi.stubGlobal('localStorage', {
      getItem: (k: string) => store[k] ?? null,
      setItem: (k: string, v: string) => {
        store[k] = v;
      },
    });
    vi.stubGlobal(
      'AudioContext',
      class extends FakeCtx {
        constructor() {
          super();
          created.push(this);
        }
      },
    );
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('accesi in partenza; la scelta resta salvata', async () => {
    const s = await import('../src/ui/sound');
    expect(s.soundOn()).toBe(true);
    s.setSound(false);
    expect(store['polaris.sound']).toBe('off');
    s.play('success');
    expect(created).toHaveLength(0); // spenti: nessun contesto audio creato

    vi.resetModules();
    const again = await import('../src/ui/sound');
    expect(again.soundOn()).toBe(false);
  });

  it('muti fino al primo gesto, poi suonano; lo stesso segnale non si accavalla', async () => {
    const s = await import('../src/ui/sound');
    s.play('success');
    expect(created).toHaveLength(1);
    const ctx = created[0];
    expect(ctx.oscillators).toHaveLength(0); // contesto ancora sospeso: nessun recupero più tardi

    await s.unlockAudio();
    expect(ctx.state).toBe('running');
    s.play('success');
    expect(ctx.oscillators).toHaveLength(CUES.success.length);
    s.play('success'); // stesso istante: ignorato
    expect(ctx.oscillators).toHaveLength(CUES.success.length);
    s.play('error'); // un altro segnale suona
    expect(ctx.oscillators).toHaveLength(CUES.success.length + CUES.error.length);
    ctx.currentTime += 0.5;
    s.play('success');
    expect(ctx.oscillators).toHaveLength(2 * CUES.success.length + CUES.error.length);
  });

  it('riacceso, conferma con un tocco', async () => {
    store['polaris.sound'] = 'off';
    const s = await import('../src/ui/sound');
    s.setSound(true);
    expect(store['polaris.sound']).toBe('on');
    await Promise.resolve();
    await Promise.resolve();
    const ctx = created[0];
    expect(ctx.oscillators.map((o) => o.frequency.events[0][1])).toEqual(CUES.tap.map((n) => n.f));
  });

  it('senza Web Audio non succede nulla', async () => {
    vi.stubGlobal('AudioContext', undefined);
    const s = await import('../src/ui/sound');
    expect(() => s.play('alert' as Cue)).not.toThrow();
    await expect(s.unlockAudio()).resolves.toBeUndefined();
  });
});
