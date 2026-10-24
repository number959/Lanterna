import { useSyncExternalStore } from 'react';

// Suoni dell'interfaccia, sintetizzati al momento con Web Audio: nessun file
// audio da scaricare o da licenziare. Sono brevi, a volume basso, e si
// spengono con l'interruttore nella barra in alto (la scelta resta su questo
// PC). Il browser li lascia partire solo dopo il primo clic o tasto premuto
// nella pagina: prima di allora restano muti, senza recuperi in ritardo.

export type Cue = 'tap' | 'open' | 'success' | 'complete' | 'warn' | 'error' | 'alert';

/** Una nota: frequenza (Hz), inizio e durata (s), forma d'onda, volume relativo. */
export interface Note {
  f: number;
  t: number;
  d: number;
  type?: OscillatorType;
  g?: number;
}

// Note della scala di Do (Hz).
const C5 = 523.25;
const E5 = 659.25;
const G5 = 783.99;
const B5 = 987.77;
const C6 = 1046.5;

export const CUES: Record<Cue, Note[]> = {
  // Navigazione: un tocco appena percettibile.
  tap: [{ f: 1318.5, t: 0, d: 0.035, g: 0.35 }],
  // Si apre qualcosa: una quinta che sale.
  open: [
    { f: E5, t: 0, d: 0.08, g: 0.6 },
    { f: B5, t: 0.055, d: 0.13, g: 0.6 },
  ],
  // Operazione riuscita.
  success: [
    { f: G5, t: 0, d: 0.1, type: 'triangle', g: 0.8 },
    { f: C6, t: 0.08, d: 0.22, type: 'triangle', g: 0.8 },
  ],
  // Analisi, test o verifiche concluse: arpeggio con un riflesso finale.
  complete: [
    { f: C5, t: 0, d: 0.12, type: 'triangle', g: 0.7 },
    { f: E5, t: 0.09, d: 0.12, type: 'triangle', g: 0.7 },
    { f: G5, t: 0.18, d: 0.14, type: 'triangle', g: 0.7 },
    { f: C6, t: 0.27, d: 0.42, type: 'triangle', g: 0.8 },
    { f: C6 * 2, t: 0.27, d: 0.3, g: 0.12 },
  ],
  // Qualcosa da controllare: due note che scendono.
  warn: [
    { f: 587.33, t: 0, d: 0.13, type: 'triangle', g: 0.8 },
    { f: 466.16, t: 0.12, d: 0.24, type: 'triangle', g: 0.8 },
  ],
  // Errore: più grave e scuro.
  error: [
    { f: 392, t: 0, d: 0.15, type: 'triangle', g: 0.9 },
    { f: 277.18, t: 0.14, d: 0.32, type: 'triangle', g: 0.9 },
    { f: 138.59, t: 0.14, d: 0.32, g: 0.4 },
  ],
  // Interruzione della connessione durante il monitor: richiamo ripetuto.
  alert: [0, 0.17, 0.34, 0.51].map((t, i) => ({ f: i % 2 ? 660 : 880, t, d: 0.13, type: 'square' as const, g: 0.22 })),
};

/** Volume generale: basso, perché i suoni accompagnano e non devono disturbare. */
export const VOLUME = 0.14;

/** Programma le note di un suono a partire dall'istante t0 del contesto audio. */
export function schedule(ctx: BaseAudioContext, out: AudioNode, cue: Cue, t0: number): void {
  for (const n of CUES[cue]) {
    const o = ctx.createOscillator();
    const g = ctx.createGain();
    const start = t0 + n.t;
    const peak = n.g ?? 1;
    o.type = n.type ?? 'sine';
    o.frequency.setValueAtTime(n.f, start);
    // Attacco breve e coda esponenziale: niente "clic" all'inizio e alla fine.
    g.gain.setValueAtTime(0.0001, start);
    g.gain.exponentialRampToValueAtTime(peak, start + 0.012);
    g.gain.exponentialRampToValueAtTime(0.0001, start + n.d);
    o.connect(g);
    g.connect(out);
    o.start(start);
    o.stop(start + n.d + 0.02);
  }
}

// ---- Stato: acceso o spento, ricordato su questo PC

const KEY = 'polaris.sound';
const listeners = new Set<() => void>();

function readPref(): boolean {
  try {
    return globalThis.localStorage?.getItem(KEY) !== 'off';
  } catch {
    return true;
  }
}

let enabled = readPref();

export function soundOn(): boolean {
  return enabled;
}

export function setSound(on: boolean): void {
  enabled = on;
  try {
    globalThis.localStorage?.setItem(KEY, on ? 'on' : 'off');
  } catch {
    // Senza memoria del browser la scelta vale fino alla chiusura.
  }
  listeners.forEach((l) => l());
  // Conferma udibile appena acceso (dopo lo sblocco, che è asincrono).
  if (on) void unlockAudio().then(() => play('tap'));
}

function subscribe(l: () => void) {
  listeners.add(l);
  return () => {
    listeners.delete(l);
  };
}

/** Stato dei suoni per i componenti, con la funzione per cambiarlo. */
export function useSound(): [boolean, (on: boolean) => void] {
  return [useSyncExternalStore(subscribe, soundOn, soundOn), setSound];
}

// ---- Riproduzione

type AudioCtor = new () => AudioContext;

let ctx: AudioContext | null = null;
let master: GainNode | null = null;
const last: Partial<Record<Cue, number>> = {};

function audio(): AudioContext | null {
  if (ctx) return ctx;
  const g = globalThis as { AudioContext?: AudioCtor; webkitAudioContext?: AudioCtor };
  const Ctor = g.AudioContext ?? g.webkitAudioContext;
  if (!Ctor) return null;
  try {
    ctx = new Ctor();
    master = ctx.createGain();
    master.gain.value = VOLUME;
    master.connect(ctx.destination);
  } catch {
    ctx = null;
  }
  return ctx;
}

/** Va chiamata dentro un clic o un tasto: il browser consente l'audio da lì in poi. */
export function unlockAudio(): Promise<void> {
  const c = audio();
  if (!c || c.state !== 'suspended') return Promise.resolve();
  return c.resume().catch(() => undefined);
}

/**
 * Suona un segnale, se i suoni sono accesi e il browser li consente. Lo
 * stesso segnale ripetuto entro 120 ms suona una volta sola (per esempio
 * due messaggi che arrivano insieme).
 */
export function play(cue: Cue): void {
  if (!enabled) return;
  const c = audio();
  if (!c || !master) return;
  if (c.state !== 'running') {
    // Ancora sospeso (nessun clic finora): il suono si salta, così non si
    // accumulano suoni che partirebbero tutti insieme più tardi.
    return;
  }
  const now = c.currentTime;
  const prev = last[cue];
  if (prev !== undefined && now - prev < 0.12) return;
  last[cue] = now;
  schedule(c, master, cue, now + 0.005);
}

/** Sblocca l'audio al primo gesto nella pagina (pulsanti, tasti, tocchi). */
export function installAudioUnlock(): () => void {
  if (typeof window === 'undefined') return () => undefined;
  const on = () => {
    if (enabled) void unlockAudio();
  };
  const opts = { capture: true, passive: true } as const;
  window.addEventListener('pointerdown', on, opts);
  window.addEventListener('keydown', on, opts);
  return () => {
    window.removeEventListener('pointerdown', on, opts);
    window.removeEventListener('keydown', on, opts);
  };
}
