// Genera core/src/ui/brand-paths.ts dai master vettoriali ufficiali in brand/
// (uso: node scripts/brand.mjs, dalla radice del progetto). I tracciati sono
// copiati così come sono: l'interfaccia li ricompone senza modificarne forme
// o proporzioni, come chiede la guida del marchio.
import fs from 'node:fs';

const root = new URL('../', import.meta.url);
const svg = fs.readFileSync(new URL('brand/STARNET_22_Logo_Colore.svg', root), 'utf8');
const symbol = fs.readFileSync(new URL('brand/STARNET_22_Simbolo_Colore.svg', root), 'utf8');

const attr = (tag, name) => new RegExp(`${name}="([^"]*)"`).exec(tag)?.[1];
const paths = new Map([...svg.matchAll(/<path id="([^"]+)" d="([^"]+)"/g)].map((m) => [m[1], m[2]]));
const clips = new Map([...svg.matchAll(/<clipPath id="([^"]+)"><path d="([^"]+)"/g)].map((m) => [m[1], m[2]]));
const accents = [...svg.matchAll(/<polygon [^>]*\/>/g)].map((m) => ({
  points: attr(m[0], 'points'),
  fill: attr(m[0], 'fill'),
  clip: /url\(#([^)]+)\)/.exec(attr(m[0], 'clip-path') ?? '')?.[1],
}));

// I ritagli delle parti ciano coincidono con la cornice e con la metà destra della stella.
if (clips.get('clip-frame') !== paths.get('frame')) throw new Error('clip-frame diverso dalla cornice');
if (clips.get('clip-star-right') !== paths.get('star-right')) throw new Error('clip-star-right diverso dalla stella');
if (accents.length !== 2 || accents.some((a) => a.fill !== '#00B9FE')) throw new Error('parti ciano inattese');
const letters = [...paths.keys()].filter((k) => k.startsWith('letter-')).sort();
if (letters.length !== 7) throw new Error('scritta STARNET incompleta');
const symbolViewBox = attr(/<svg [^>]*>/.exec(symbol)[0], 'viewBox');
const logoViewBox = attr(/<svg [^>]*>/.exec(svg)[0], 'viewBox');
const navy = [...new Set([...svg.matchAll(/fill="(#022D62)"/g)].map((m) => m[1]))];
if (navy.length !== 1) throw new Error('blu profondo non trovato');

const q = JSON.stringify;
const out = `// Tracciati del marchio STARNET (master vettoriale, versione 22).
// Generato da scripts/brand.mjs a partire da brand/*.svg: non modificare a mano.

export const BRAND_NAVY = '#022D62';
export const BRAND_CYAN = '#00B9FE';

/** Riquadri originali: solo simbolo e logo completo (simbolo sopra la scritta). */
export const SYMBOL_VIEWBOX = ${q(symbolViewBox)};
export const LOGO_VIEWBOX = ${q(logoViewBox)};

/** Cornice esagonale (anello, regola evenodd). */
export const FRAME = ${q(paths.get('frame'))};
/** Metà sinistra e destra della stella: tra le due corre il canale a S. */
export const STAR_LEFT = ${q(paths.get('star-left'))};
export const STAR_RIGHT = ${q(paths.get('star-right'))};
/** Zone ciano della versione a colori: ritagliate dalla cornice e dalla metà destra della stella. */
export const CYAN_FRAME = ${q(accents.find((a) => a.clip === 'clip-frame').points)};
export const CYAN_STAR = ${q(accents.find((a) => a.clip === 'clip-star-right').points)};
/** Lettere della scritta, nell'ordine S T A R N E T. */
export const LETTERS: readonly string[] = ${q(letters.map((k) => paths.get(k)))};
`;
fs.writeFileSync(new URL('core/src/ui/brand-paths.ts', root), out);
console.log(`Scritto core/src/ui/brand-paths.ts (${out.length} caratteri, ${letters.length} lettere)`);
