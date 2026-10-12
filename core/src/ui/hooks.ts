import { useEffect, useLayoutEffect, useRef, useState } from 'react';

/**
 * Larghezza reale in pixel di un contenitore: i grafici SVG la usano come
 * viewBox, così un'unità SVG = un pixel e testi e linee non vengono
 * stirati o rimpiccioliti a seconda della finestra.
 */
export function useWidth<T extends HTMLElement>(): [React.RefObject<T>, number] {
  const ref = useRef<T>(null);
  const [w, setW] = useState(0);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    setW(Math.floor(el.getBoundingClientRect().width));
    const ro = new ResizeObserver((entries) => {
      const nw = Math.floor(entries[0].contentRect.width);
      setW((old) => (old === nw ? old : nw));
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  return [ref, w];
}

/** Numero che "sale" fino al valore finale (rispetta riduci-movimento). */
export function useCountUp(target: number, ms = 1200): number {
  const [v, setV] = useState(0);
  useEffect(() => {
    if (window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) {
      setV(target);
      return;
    }
    let raf = 0;
    const t0 = performance.now();
    const tick = (t: number) => {
      const k = Math.min(1, (t - t0) / ms);
      const e = 1 - Math.pow(1 - k, 3);
      setV(Math.round(target * e));
      if (k < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target, ms]);
  return v;
}

export function useLocalState<T>(key: string, initial: T): [T, (v: T) => void] {
  const [v, setV] = useState<T>(() => {
    try {
      const raw = localStorage.getItem(key);
      return raw ? (JSON.parse(raw) as T) : initial;
    } catch {
      return initial;
    }
  });
  const set = (nv: T) => {
    setV(nv);
    try {
      localStorage.setItem(key, JSON.stringify(nv));
    } catch {
      /* archiviazione non disponibile: lo stato resta in memoria */
    }
  };
  return [v, set];
}
