// Rigenera core/src/ui/fonts.css con i soli sottoinsiemi latini dei font
// Fontsource installati (uso: node scripts/fonts.mjs, dalla radice del progetto).
import fs from 'node:fs';

const root = new URL('../core/', import.meta.url);
const read = (p) => fs.readFileSync(new URL(p, root), 'utf8');

/**
 * Una regola @font-face copiata dal foglio del pacchetto. `axes` sceglie il file
 * variabile: "wght" (solo peso) o "standard" (peso e larghezza, per Saira).
 */
function face(pkg, family, file, subset, axes = 'wght') {
  const css = read(`node_modules/@fontsource-variable/${pkg}/${axes}.css`);
  const name = `${file}-${subset}-${axes}-normal.woff2`;
  const block = css.split('@font-face').find((b) => b.includes(name));
  if (!block) throw new Error(`sottoinsieme ${subset} (${axes}) non trovato in ${pkg}`);
  const weight = /font-weight:\s*([^;]+);/.exec(block)[1].trim();
  const stretch = /font-stretch:\s*([^;]+);/.exec(block)?.[1].trim();
  const range = /unicode-range:\s*([^;]+);/.exec(block)[1].trim();
  return `@font-face {
  font-family: "${family}";
  font-style: normal;
  font-display: swap;
  font-weight: ${weight};${stretch ? `\n  font-stretch: ${stretch};` : ''}
  src: url("../../node_modules/@fontsource-variable/${pkg}/files/${name}") format("woff2-variations");
  unicode-range: ${range};
}
`;
}

let out = `/* Font incorporati da Fontsource (file: SIL Open Font License 1.1, vedi THIRD_PARTY_NOTICES.md).
   Solo i sottoinsiemi latini: coprono l'italiano e restano leggeri dentro l'eseguibile.
   Saira con l'asse della larghezza: i titoli usano la versione estesa, vicina alla scritta STARNET.
   Generato da scripts/fonts.mjs: non modificare a mano. */

`;
out += face('inter', 'Inter Variable', 'inter', 'latin');
out += face('inter', 'Inter Variable', 'inter', 'latin-ext');
out += face('saira', 'Saira Variable', 'saira', 'latin', 'standard');
out += face('jetbrains-mono', 'JetBrains Mono Variable', 'jetbrains-mono', 'latin');
fs.writeFileSync(new URL('src/ui/fonts.css', root), out);
console.log('scritto core/src/ui/fonts.css');
