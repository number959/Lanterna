import { m, useReducedMotion } from 'motion/react';
import { useId } from 'react';
import { CYAN_FRAME, CYAN_STAR, FRAME, LETTERS, LOGO_VIEWBOX, STAR_LEFT, STAR_RIGHT, SYMBOL_VIEWBOX } from './brand-paths';
import { AnimatedNumber } from './components';
import { ease, spring } from './motion';

// Marchio STARNET e forme che ne derivano.
//
// Il marchio è disegnato con i tracciati originali e solo nelle due versioni
// previste dalla guida: a colori (blu profondo e ciano) sui fondi chiari,
// bianca sui fondi scuri. Le classi .logo-main/.logo-accent prendono i colori
// dal tema (vedi styles.css). Nessuna ombra né effetto sul marchio: l'unica
// animazione è l'entrata, che termina sempre sulla forma originale.

/** Linea mediana dell'anello esagonale, dal vertice alto in senso orario (spessore dell'anello ~69). */
const FRAME_CENTERLINE = 'M627.5,201.75 L907,360.5 L907,670.5 L627.5,829.25 L348,670.5 L348,360.5 Z';

function Mark({ intro, delay = 0 }: { intro: boolean; delay?: number }) {
  const uid = useId().replace(/:/g, '');
  const reduce = useReducedMotion();
  const play = intro && !reduce;
  const frameClip = `${uid}-frame`;
  const starClip = `${uid}-star`;
  const reveal = `${uid}-reveal`;
  return (
    <>
      <defs>
        <clipPath id={frameClip}>
          <path d={FRAME} clipRule="evenodd" />
        </clipPath>
        <clipPath id={starClip}>
          <path d={STAR_RIGHT} clipRule="evenodd" />
        </clipPath>
        {play && (
          // La cornice si rivela in senso orario dal vertice alto: lo stesso verso del tratto ciano.
          <mask id={reveal} maskUnits="userSpaceOnUse" x="215" y="105" width="824" height="824">
            <m.path
              d={FRAME_CENTERLINE}
              fill="none"
              stroke="#fff"
              strokeWidth={84}
              strokeLinejoin="round"
              initial={{ pathLength: 0 }}
              animate={{ pathLength: 1 }}
              transition={{ duration: 0.95, ease: ease.inOut, delay }}
            />
          </mask>
        )}
      </defs>
      <g mask={play ? `url(#${reveal})` : undefined}>
        <path className="logo-main" d={FRAME} fillRule="evenodd" />
        <polygon className="logo-accent" points={CYAN_FRAME} clipPath={`url(#${frameClip})`} />
      </g>
      {/* Le due metà della stella arrivano dai lati opposti e si incastrano lungo la S. */}
      <m.g
        initial={play ? { opacity: 0, x: -46, y: 30 } : false}
        animate={{ opacity: 1, x: 0, y: 0 }}
        transition={{ ...spring.smooth, delay: delay + 0.45 }}
      >
        <path className="logo-main" d={STAR_LEFT} fillRule="evenodd" />
      </m.g>
      <m.g
        initial={play ? { opacity: 0, x: 46, y: -30 } : false}
        animate={{ opacity: 1, x: 0, y: 0 }}
        transition={{ ...spring.smooth, delay: delay + 0.45 }}
      >
        <path className="logo-main" d={STAR_RIGHT} fillRule="evenodd" />
        <polygon className="logo-accent" points={CYAN_STAR} clipPath={`url(#${starClip})`} />
      </m.g>
    </>
  );
}

/** Solo simbolo (la guida lo indica per gli spazi piccoli). */
export function BrandSymbol({ size = 32, intro = false, delay = 0, title, x, y }: { size?: number; intro?: boolean; delay?: number; title?: string; x?: number; y?: number }) {
  // x e y servono quando il simbolo è annidato dentro un altro disegno SVG.
  return (
    <svg className="brand-mark" x={x} y={y} width={size} height={size} viewBox={SYMBOL_VIEWBOX} role={title ? 'img' : undefined} aria-label={title} aria-hidden={title ? undefined : true}>
      <Mark intro={intro} delay={delay} />
    </svg>
  );
}

/** Logo completo: simbolo sopra la scritta STARNET, nelle proporzioni originali. */
export function BrandLogo({ width = 132, intro = false, title = 'STARNET' }: { width?: number; intro?: boolean; title?: string }) {
  const reduce = useReducedMotion();
  const play = intro && !reduce;
  return (
    <svg className="brand-mark" width={width} height={(width * 1014) / 1228} viewBox={LOGO_VIEWBOX} role="img" aria-label={title}>
      <Mark intro={intro} />
      <m.g initial={play ? 'hidden' : false} animate="show" variants={{ show: { transition: { staggerChildren: 0.05, delayChildren: 0.75 } } }}>
        {LETTERS.map((d, i) => (
          <m.path
            key={i}
            className="logo-main"
            d={d}
            fillRule="evenodd"
            variants={{ hidden: { opacity: 0, y: 26 }, show: { opacity: 1, y: 0, transition: { duration: 0.5, ease: ease.out } } }}
          />
        ))}
      </m.g>
    </svg>
  );
}

/** Esagono a punta in alto come la cornice del marchio, dal vertice alto in senso orario. */
export function hexPath(cx: number, cy: number, r: number) {
  const pts = Array.from({ length: 6 }, (_, i) => {
    const a = ((-90 + i * 60) * Math.PI) / 180;
    return `${(cx + r * Math.cos(a)).toFixed(2)},${(cy + r * Math.sin(a)).toFixed(2)}`;
  });
  return `M${pts.join(' L')} Z`;
}

const scoreColor = (s: number) => (s >= 85 ? 'var(--ok)' : s >= 70 ? 'var(--info)' : s >= 50 ? 'var(--warn)' : 'var(--crit)');

/**
 * Punteggio come la cornice del logo: l'anello esagonale si riempie dal vertice
 * alto in senso orario, proprio come il tratto ciano del marchio.
 */
export function HexGauge({ score, size = 214 }: { score: number; size?: number }) {
  const gid = useId().replace(/:/g, '');
  const reduce = useReducedMotion();
  const c = size / 2;
  const r = size / 2 - 12;
  const color = scoreColor(score);
  const outer = hexPath(c, c, r);
  const inner = hexPath(c, c, r - 19);
  return (
    <div className="gauge" style={{ width: size, height: size }} role="img" aria-label={`Punteggio ${score} su 100`}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-hidden="true">
        <defs>
          <linearGradient id={`${gid}-g`} x1="1" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor={color} />
            <stop offset="1" stopColor={color} stopOpacity="0.7" />
          </linearGradient>
        </defs>
        <path d={inner} fill="none" stroke="var(--line-strong)" strokeWidth={1} />
        <path d={outer} fill="none" stroke="var(--surface-3)" strokeWidth={14} strokeLinejoin="round" />
        <m.path
          d={outer}
          fill="none"
          stroke={`url(#${gid}-g)`}
          strokeWidth={14}
          strokeLinejoin="round"
          strokeLinecap="round"
          initial={{ pathLength: reduce ? score / 100 : 0 }}
          animate={{ pathLength: score / 100 }}
          transition={{ ...spring.gentle, delay: 0.15 }}
        />
        {Array.from({ length: 6 }, (_, i) => {
          const a = ((-90 + i * 60) * Math.PI) / 180;
          return <circle key={i} cx={c + (r - 19) * Math.cos(a)} cy={c + (r - 19) * Math.sin(a)} r={2} fill="var(--line-strong)" />;
        })}
      </svg>
      <div className="gauge-num" aria-hidden="true">
        <strong>
          <AnimatedNumber value={score} />
        </strong>
        <span className="of">su 100</span>
      </div>
    </div>
  );
}

/** Stella a quattro punte stilizzata (decorazioni e indicatori, non il marchio). */
export function Sparkle({ size = 12, className }: { size?: number; className?: string }) {
  return (
    <svg className={className} width={size} height={size} viewBox="0 0 24 24" aria-hidden="true">
      <path d="M12 0 C12.9 7.6 16.4 11.1 24 12 C16.4 12.9 12.9 16.4 12 24 C11.1 16.4 7.6 12.9 0 12 C7.6 11.1 11.1 7.6 12 0 Z" fill="currentColor" />
    </svg>
  );
}
