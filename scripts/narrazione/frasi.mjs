// Scrive in JSON tutte le frasi della narrazione delle videoguide
// (core/src/guides/video.ts), nell'ordine in cui si ascoltano.
// Uso: node scripts/narrazione/frasi.mjs [file di uscita]   (senza file: su stdout)
import { writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', 'core');
const { build } = createRequire(join(root, 'package.json'))('esbuild');
const out = await build({ entryPoints: [join(root, 'src/guides/video.ts')], bundle: true, format: 'esm', write: false, logLevel: 'silent' });
const mod = await import(`data:text/javascript;base64,${Buffer.from(out.outputFiles[0].text).toString('base64')}`);
const frasi = mod.VIDEOS.flatMap((v) =>
  v.scenes.flatMap((s, si) => s.narration.map((testo, ti) => ({ video: v.id, titolo: v.title, scena: si + 1, titoloScena: s.title, frase: ti + 1, testo }))),
);
const json = JSON.stringify(frasi, null, 1);
if (process.argv[2]) writeFileSync(process.argv[2], json + '\n');
else process.stdout.write(json + '\n');
