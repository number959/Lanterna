import type { DeviceKind } from '../engine';

// Disegni a linee dei dispositivi per "Il traffico passo passo": tratti
// sottili su fondo scuro, in vista di tre quarti. Coordinate in un riquadro di
// 64 × 56 centrato nel punto del nodo; il colore viene da currentColor.

type Art = 'laptop' | 'desktop' | 'router' | 'firewall' | 'switch' | 'ap' | 'server' | 'nas' | 'printer' | 'phone' | 'camera' | 'cloud' | 'isp' | 'box';

const ART: Record<DeviceKind, Art> = {
  internet: 'cloud',
  isp: 'isp',
  router: 'router',
  firewall: 'firewall',
  switch: 'switch',
  ap: 'ap',
  pc: 'desktop',
  laptop: 'laptop',
  server: 'server',
  vm: 'server',
  nas: 'nas',
  printer: 'printer',
  phone: 'phone',
  tablet: 'phone',
  voip: 'phone',
  camera: 'camera',
  tv: 'desktop',
  iot: 'box',
  medical: 'box',
  unknown: 'box',
};

const S = { fill: 'var(--tx-fill)', stroke: 'currentColor', strokeWidth: 1.6, strokeLinejoin: 'round' as const, strokeLinecap: 'round' as const };
const L = { fill: 'none', stroke: 'currentColor', strokeWidth: 1.6, strokeLinejoin: 'round' as const, strokeLinecap: 'round' as const };

/** Scatola in tre quarti: faccia superiore a rombo e due facce laterali. */
function Slab({ y, h = 8, w = 22, d = 9 }: { y: number; h?: number; w?: number; d?: number }) {
  const cx = 32;
  const top = `M${cx - w} ${y} L${cx} ${y - d} L${cx + w} ${y} L${cx} ${y + d} Z`;
  const left = `M${cx - w} ${y} L${cx - w} ${y + h} L${cx} ${y + d + h} L${cx} ${y + d} Z`;
  const right = `M${cx} ${y + d} L${cx} ${y + d + h} L${cx + w} ${y + h} L${cx + w} ${y} Z`;
  return (
    <>
      <path d={left} {...S} style={{ fill: 'var(--tx-fill-2)' }} />
      <path d={right} {...S} />
      <path d={top} {...S} />
    </>
  );
}

export function DeviceArt({ kind, x, y, scale = 1 }: { kind: DeviceKind; x: number; y: number; scale?: number }) {
  const art = ART[kind];
  return (
    <g transform={`translate(${x - 32 * scale} ${y - 28 * scale}) scale(${scale})`} aria-hidden>
      {art === 'laptop' && (
        <>
          <path d="M14 8 L44 8 Q46 8 46 10 L46 31 L12 31 L12 10 Q12 8 14 8 Z" {...S} />
          <path d="M16 12 H42 V28 H16 Z" {...L} opacity={0.55} />
          <path d="M6 33 L52 33 L58 41 L0 41 Z" {...S} />
          <path d="M22 37 H36" {...L} opacity={0.6} />
        </>
      )}
      {art === 'desktop' && (
        <>
          <path d="M10 6 H54 V34 H10 Z" {...S} />
          <path d="M14 10 H50 V30 H14 Z" {...L} opacity={0.55} />
          <path d="M28 34 L26 42 H38 L36 34" {...L} />
          <path d="M20 44 H44" {...L} />
        </>
      )}
      {art === 'router' && (
        <>
          <path d="M20 22 L18 6 M44 22 L46 6" {...L} />
          <Slab y={30} h={8} w={24} d={9} />
          <circle cx="20" cy="40" r="1.3" fill="currentColor" />
          <circle cx="25" cy="42" r="1.3" fill="currentColor" />
          <circle cx="30" cy="44" r="1.3" fill="currentColor" />
        </>
      )}
      {art === 'firewall' && (
        <>
          <Slab y={22} h={18} w={22} d={9} />
          <path d="M10 28 L32 37 M10 34 L32 43 M21 26 L21 38 M15 31 L15 41 M26 35 L26 45 M32 37 L54 28 M32 43 L54 34 M43 32 L43 44 M38 34 L38 46 M48 30 L48 42" {...L} opacity={0.7} />
        </>
      )}
      {art === 'switch' && (
        <>
          <Slab y={28} h={6} w={28} d={10} />
          {[0, 1, 2, 3, 4, 5].map((i) => (
            <path key={i} d={`M${7 + i * 4} ${30 + i * 1.6} l2.6 1 v2.6 l-2.6 -1 z`} {...L} strokeWidth={1.1} />
          ))}
          <path d="M40 33 l8 -3 M40 36 l8 -3" {...L} opacity={0.6} />
        </>
      )}
      {art === 'ap' && (
        <>
          <ellipse cx="32" cy="36" rx="20" ry="7" {...S} />
          <path d="M12 36 v3 a20 7 0 0 0 40 0 v-3" {...L} />
          <path d="M24 20 a11 11 0 0 1 16 0 M19 15 a18 18 0 0 1 26 0 M28.5 24.5 a5 5 0 0 1 7 0" {...L} />
        </>
      )}
      {art === 'server' && (
        <>
          <Slab y={36} h={7} />
          <Slab y={26} h={7} />
          <Slab y={16} h={7} />
          <circle cx="16" cy="22" r="1.1" fill="currentColor" />
          <circle cx="16" cy="32" r="1.1" fill="currentColor" />
          <circle cx="16" cy="42" r="1.1" fill="currentColor" />
        </>
      )}
      {art === 'nas' && (
        <>
          <Slab y={18} h={24} w={16} d={7} />
          <path d="M19 24 L31 29 M19 30 L31 35 M19 36 L31 41" {...L} opacity={0.75} />
        </>
      )}
      {art === 'printer' && (
        <>
          <path d="M22 18 L22 6 L42 6 L42 18" {...S} />
          <Slab y={26} h={12} w={22} d={8} />
          <path d="M20 40 L22 50 L42 50 L44 40" {...S} />
        </>
      )}
      {art === 'phone' && (
        <>
          <rect x="22" y="6" width="20" height="40" rx="4" {...S} />
          <path d="M28 10 H36 M30 41 H34" {...L} />
        </>
      )}
      {art === 'camera' && (
        <>
          <path d="M14 14 H40 L46 22 H20 Z" {...S} />
          <path d="M20 22 V30 H46 V22" {...S} />
          <circle cx="44" cy="26" r="3" {...L} />
          <path d="M26 30 L30 44 M22 44 H38" {...L} />
        </>
      )}
      {art === 'cloud' && (
        <>
          <path d="M16 40 Q6 40 6 31 Q6 23 15 22 Q16 11 28 10 Q38 10 42 18 Q46 15 50 17 Q58 20 57 28 Q62 31 61 36 Q60 40 54 40 Z" {...S} />
          <circle cx="33" cy="28" r="8" {...L} />
          <path d="M25 28 H41 M33 20 Q28 28 33 36 Q38 28 33 20" {...L} opacity={0.8} />
        </>
      )}
      {art === 'isp' && (
        <>
          <path d="M32 8 L22 46 M32 8 L42 46 M26 30 H38 M24 38 H40 M28 20 H36" {...L} />
          <path d="M20 8 a14 14 0 0 1 24 0 M16 4 a20 20 0 0 1 32 0" {...L} opacity={0.7} />
        </>
      )}
      {art === 'box' && (
        <>
          <Slab y={24} h={14} w={18} d={8} />
          <circle cx="32" cy="24" r="3" {...L} />
        </>
      )}
    </g>
  );
}
