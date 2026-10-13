import { useCallback, useEffect, useState } from 'react';
import { flushSync } from 'react-dom';

// Tema: preferenza dell'utente (auto/scuro/chiaro) e tema effettivo, esposto
// come classe "dark"/"light" su <html> (la usano anche le scale Radix Colors).

export type ThemePref = 'auto' | 'dark' | 'light';
const KEY = 'polaris.theme';

const media = () => window.matchMedia?.('(prefers-color-scheme: light)');

export function effective(pref: ThemePref): 'dark' | 'light' {
  if (pref !== 'auto') return pref;
  return media()?.matches ? 'light' : 'dark';
}

export function readPref(): ThemePref {
  try {
    const v = localStorage.getItem(KEY);
    if (v === 'dark' || v === 'light' || v === 'auto') return v;
    if (v) return JSON.parse(v) as ThemePref; // formato della versione precedente
  } catch {
    /* archiviazione non disponibile */
  }
  return 'auto';
}

export function apply(theme: 'dark' | 'light') {
  const el = document.documentElement;
  el.classList.toggle('dark', theme === 'dark');
  el.classList.toggle('light', theme === 'light');
  el.style.colorScheme = theme;
}

type DocWithVT = Document & { startViewTransition?: (cb: () => void) => { ready: Promise<void> } };

/**
 * Esegue un aggiornamento con una View Transition (se disponibile, se
 * l'utente non preferisce il movimento ridotto e se non è attiva la grafica
 * leggera): il nuovo tema si espande come un cerchio di luce dal punto
 * indicato. Senza GPU il ritaglio animato di due immagini a tutta pagina
 * costa troppo, quindi con la grafica leggera il cambio è immediato.
 */
export function revealFrom(update: () => void, origin?: { x: number; y: number }) {
  const doc = document as DocWithVT;
  const reduce = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
  const lite = document.documentElement.classList.contains('lite');
  if (!doc.startViewTransition || reduce || lite) {
    update();
    return;
  }
  const t = doc.startViewTransition(() => flushSync(update));
  if (!origin) return;
  t.ready
    .then(() => {
      const r = Math.hypot(Math.max(origin.x, innerWidth - origin.x), Math.max(origin.y, innerHeight - origin.y));
      document.documentElement.animate(
        { clipPath: [`circle(0px at ${origin.x}px ${origin.y}px)`, `circle(${r}px at ${origin.x}px ${origin.y}px)`] },
        { duration: 700, easing: 'cubic-bezier(0.16, 1, 0.3, 1)', pseudoElement: '::view-transition-new(root)' },
      );
    })
    .catch(() => undefined);
}

export function useTheme(): [ThemePref, (next: ThemePref, origin?: { x: number; y: number }) => void] {
  const [pref, setPref] = useState<ThemePref>(readPref);
  useEffect(() => {
    apply(effective(pref));
    if (pref !== 'auto') return;
    const m = media();
    const on = () => apply(effective('auto'));
    m?.addEventListener('change', on);
    return () => m?.removeEventListener('change', on);
  }, [pref]);
  const set = useCallback((next: ThemePref, origin?: { x: number; y: number }) => {
    try {
      localStorage.setItem(KEY, next);
    } catch {
      /* resta solo in memoria */
    }
    const before = effective(pref);
    const after = effective(next);
    if (before === after) {
      setPref(next);
      return;
    }
    revealFrom(() => {
      setPref(next);
      apply(after);
    }, origin);
  }, [pref]);
  return [pref, set];
}
