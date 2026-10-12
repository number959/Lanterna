import { useSyncExternalStore } from 'react';

// Grafica leggera: niente trasparenze sfocate, grana, bagliori in movimento e
// filtri SVG di sfocatura. Si attiva da sola se i fotogrammi risultano lenti
// (rendering senza GPU: macchine virtuali, desktop remoto, PC datati) oppure
// per scelta dell'utente, che vince sulla misura automatica.

export type FxPref = 'auto' | 'full' | 'lite';
const KEY = 'lanterna.fx';

interface FxState {
  lite: boolean;
  auto: boolean; // attivata dalla misura, non dall'utente
}

let state: FxState = { lite: false, auto: false };
const listeners = new Set<() => void>();

function set(next: FxState) {
  state = next;
  document.documentElement.classList.toggle('lite', next.lite);
  listeners.forEach((l) => l());
}

export function readFxPref(): FxPref {
  try {
    const v = localStorage.getItem(KEY);
    if (v === 'full' || v === 'lite') return v;
  } catch {
    /* archiviazione non disponibile */
  }
  return 'auto';
}

export function setFxPref(pref: FxPref) {
  try {
    if (pref === 'auto') localStorage.removeItem(KEY);
    else localStorage.setItem(KEY, pref);
  } catch {
    /* resta solo per questa sessione */
  }
  set({ lite: pref === 'lite', auto: false });
}

export const useFx = () =>
  useSyncExternalStore(
    (cb) => {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
    () => state,
  );

/** Mediana dei tempi tra fotogrammi sopra la quale si passa alla grafica leggera (~38 fps). */
const SLOW_MS = 26;

/**
 * Applica la preferenza salvata e, se è "auto", misura i fotogrammi per alcuni
 * secondi a pagina visibile: se la mediana di una finestra di 90 fotogrammi è
 * lenta, attiva la grafica leggera.
 */
export function initFx() {
  const pref = readFxPref();
  set({ lite: pref === 'lite', auto: false });
  if (pref !== 'auto' || typeof requestAnimationFrame !== 'function') return;
  let samples: number[] = [];
  let last = 0;
  let windows = 0;
  const loop = (t: number) => {
    if (document.visibilityState !== 'visible') {
      last = 0;
      requestAnimationFrame(loop);
      return;
    }
    if (last) samples.push(t - last);
    last = t;
    if (samples.length >= 90) {
      samples.sort((a, b) => a - b);
      if (samples[45] > SLOW_MS && readFxPref() === 'auto') {
        set({ lite: true, auto: true });
        return;
      }
      samples = [];
      if (++windows >= 4) return;
    }
    requestAnimationFrame(loop);
  };
  // Il primo secondo è occupato dall'avvio e dalle animazioni d'entrata: non fa testo.
  setTimeout(() => requestAnimationFrame(loop), 1200);
}
