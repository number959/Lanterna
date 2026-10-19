import type { CSSProperties, ReactNode } from 'react';

// Icone e caricamenti animati. Le animazioni sono in CSS (styles.css, "Icone
// animate e caricamenti"): partono solo se il sistema non chiede di ridurre il
// movimento, costano pochissimo (trasformazioni e tratti di piccole icone) e
// non toccano il marchio, che resta senza effetti.

export type IconMotion = 'draw' | 'pop' | 'spin' | 'pulse' | 'bounce' | 'sweep' | 'blink' | 'wave';

/**
 * Anima l'icona che contiene. "draw" (i tratti si disegnano) e "pop" (entra
 * con una piccola spinta) partono quando l'elemento compare: per ripeterli
 * basta cambiarne la chiave. Gli altri girano finché `on` è vero.
 */
export function Anim({ kind, on = true, children }: { kind: IconMotion; on?: boolean; children: ReactNode }) {
  return (
    <span className={`ico ico-${kind}${on ? ' on' : ''}`} aria-hidden="true">
      {children}
    </span>
  );
}

// Esagono a punta in alto, percorso in senso orario dal vertice superiore come
// la cornice del logo nell'animazione d'avvio.
const HEX = 'M12 2.5 20.23 7.25v9.5L12 21.5l-8.23-4.75v-9.5Z';

/** Caricamento: un tratto che percorre l'esagono, con il centro che pulsa. */
export function HexLoader({ size = 18, label }: { size?: number; label?: string }) {
  return (
    <span className="hex-loader" role={label ? 'status' : undefined} aria-label={label} aria-hidden={label ? undefined : true}>
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" strokeWidth={2.2} strokeLinejoin="round">
        <path className="hl-track" d={HEX} pathLength={100} />
        <path className="hl-run" d={HEX} pathLength={100} />
        <circle className="hl-core" cx="12" cy="12" r="2.6" />
      </svg>
    </span>
  );
}

/** Segnaposto con un riflesso che scorre, mentre i dati arrivano. */
export function Skeleton({ w = '100%', h = 12, r = 6, style }: { w?: number | string; h?: number; r?: number; style?: CSSProperties }) {
  return <span className="skeleton" style={{ width: w, height: h, borderRadius: r, ...style }} aria-hidden="true" />;
}
