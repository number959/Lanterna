// Compila l'anteprima della mappa della rete (core/preview) in un unico file
// HTML autonomo: script e stili incorporati, nessuna risorsa esterna.
// Uso: node scripts/preview-netmap.mjs [file di uscita]
import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'core');
const out = resolve(process.argv[2] ?? join(root, 'dist-preview', 'mappa-della-rete.html'));
execFileSync('npx', ['vite', 'build', '-c', 'vite.preview.config.ts', '--logLevel', 'warn'], { cwd: root, stdio: 'inherit' });
const dist = join(root, 'dist-preview');
const assets = join(dist, 'assets');
const files = readdirSync(assets);
const css = files.filter((f) => f.endsWith('.css')).map((f) => readFileSync(join(assets, f), 'utf8')).join('\n');
const js = files.filter((f) => f.endsWith('.js')).map((f) => readFileSync(join(assets, f), 'utf8')).join('\n');
// Frammento senza doctype/html/head/body: titolo, stili, contenitore e script.
const html = [
  '<title>Mappa della rete Polaris</title>',
  '<meta name="claude:viewport-fit-sides" content="cover">',
  `<style>${css.replace(/<\/style/gi, '<\\/style')}</style>`,
  '<div id="root"></div>',
  `<script type="module">${js.replace(/<\/script/gi, '<\\/script')}</script>`,
].join('\n');
writeFileSync(out, html);
console.log(`${out}: ${(html.length / 1024).toFixed(0)} KB`);
