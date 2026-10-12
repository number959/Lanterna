// Elenca i pacchetti npm che finiscono davvero nell'interfaccia incorporata
// nell'eseguibile, uno per riga (percorso relativo a core/):
//  - JavaScript: le sorgenti della mappa del bundle di produzione, compresi
//    i pacchetti annidati (es. motion/node_modules/framer-motion);
//  - CSS e font: i fogli .css importati da un pacchetto e gli url() che
//    puntano dentro node_modules (es. i file woff2 di Fontsource).
// Uso: node scripts/bundled-packages.mjs <cartella-assets-con-mappe> <cartella-sorgenti>
import fs from 'node:fs';
import path from 'node:path';

const [assetsDir, srcDir] = process.argv.slice(2);
const core = path.resolve(srcDir, '..');
const found = new Set();
// Radice del pacchetto più interno: …/node_modules/<nome> o …/node_modules/@scope/<nome>.
const root = (p) => /^(.*node_modules\/(?:@[^/]+\/)?[^/]+)/.exec(p.replaceAll('\\', '/'))?.[1];

for (const f of fs.readdirSync(assetsDir).filter((f) => f.endsWith('.js.map'))) {
  const map = JSON.parse(fs.readFileSync(path.join(assetsDir, f), 'utf8'));
  for (const s of map.sources) {
    const r = root(path.relative(core, path.resolve(assetsDir, map.sourceRoot ?? '', s)));
    if (r) found.add(r);
  }
}

const walk = (d) =>
  fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]));
for (const file of walk(srcDir).filter((f) => /\.(css|tsx?)$/.test(f))) {
  const text = fs.readFileSync(file, 'utf8');
  for (const m of text.matchAll(/import\s+['"]((?:@[^/'"]+\/)?[^./'"][^/'"]*)\/[^'"]*\.css['"]/g)) found.add(`node_modules/${m[1]}`);
  for (const m of text.matchAll(/url\(\s*['"]?([^'")]*node_modules\/[^'")]+)/g)) {
    const r = root(path.relative(core, path.resolve(path.dirname(file), m[1])));
    if (r) found.add(r);
  }
}

const list = [...found].filter((d) => fs.existsSync(path.join(core, d, 'package.json'))).sort();
if (!list.length) throw new Error('nessun pacchetto trovato: la mappa del bundle manca?');
console.log(list.join('\n'));
