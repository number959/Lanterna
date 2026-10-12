import type { Transition, Variants } from 'motion/react';

// Linguaggio del movimento di LANterna: "una luce che si accende".
// Gli elementi entrano salendo appena e rischiarandosi, con una curva che
// decelera a lungo (nessun rimbalzo gratuito); le interazioni dirette usano
// molle fisiche, così seguono il gesto e si possono interrompere a metà.
// Tempi: micro 150-200 ms, transizioni 300-450 ms, dati 600-1200 ms.

export const ease = {
  /** Decelerazione lunga: per tutto ciò che entra in scena. */
  out: [0.16, 1, 0.3, 1] as const,
  /** Simmetrica e breve: per ciò che esce. */
  inOut: [0.65, 0, 0.35, 1] as const,
};

export const spring = {
  /** Pressioni, interruttori, indicatori: risposta immediata, nessuna oscillazione visibile. */
  snappy: { type: 'spring', stiffness: 520, damping: 40, mass: 0.7 } satisfies Transition,
  /** Spostamenti di layout e pannelli che si aprono. */
  smooth: { type: 'spring', stiffness: 240, damping: 30, mass: 0.9 } satisfies Transition,
  /** Valori numerici e grafici che "si assestano". */
  gentle: { type: 'spring', stiffness: 90, damping: 20, mass: 1 } satisfies Transition,
};

/** Elemento singolo che entra: sale di poco e si accende. */
export const rise: Variants = {
  hidden: { opacity: 0, y: 14 },
  show: { opacity: 1, y: 0, transition: { duration: 0.55, ease: ease.out } },
};

/** Contenitore che fa entrare i figli in sequenza. */
export const cascade = (step = 0.045, delay = 0): Variants => ({
  hidden: {},
  show: { transition: { staggerChildren: step, delayChildren: delay } },
});

/**
 * Cambio di pagina: l'uscita è rapida e sale appena; l'entrata è una
 * dissolvenza breve mentre le sezioni arrivano in cascata (ciascuna con "rise").
 */
export const page: Variants = {
  hidden: { opacity: 0 },
  show: {
    opacity: 1,
    transition: { duration: 0.3, ease: ease.out, staggerChildren: 0.055, delayChildren: 0.02 },
  },
  exit: { opacity: 0, y: -8, transition: { duration: 0.16, ease: ease.inOut } },
};
