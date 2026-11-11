// Stampa la sezione di THIRD_PARTY_NOTICES.md sulla voce della narrazione
// delle videoguide, con i dati dell'indice (core/src/guides/narrazione.ts):
// così i crediti restano allineati alla voce che c'è davvero nel programma.
// La chiama scripts/notices.sh.
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const qui = dirname(fileURLToPath(import.meta.url));
const root = resolve(qui, '..', '..');
const src = readFileSync(join(root, 'core/src/guides/narrazione.ts'), 'utf8');
const voce = JSON.parse(src.match(/export const VOCE[^=]*= (\{[\s\S]*?\});/)[1]);
const clip = Object.values(JSON.parse(src.match(/export const CLIP[^=]*= (\{[\s\S]*\});/)[1]));
for (const k of ['nome', 'motore', 'modello', 'licenza']) if (!voce[k]) throw new Error(`narrazione.ts: manca ${k} della voce`);
const minuti = Math.round(clip.reduce((a, c) => a + c.ms, 0) / 60000);

const righe = [
  `## Narrazione delle videoguide (voce sintetica «${voce.nome}»)`,
  '',
  `La narrazione delle videoguide è registrata: ${clip.length} file Ogg Opus, circa ${minuti} minuti in tutto (core/src/guides/narrazione/). ` +
    `Le registrazioni sono state generate una volta con ${voce.motore} (${voce.modello}) dallo script scripts/narrazione/genera.py; ` +
    `nel programma ci sono soltanto le registrazioni, non il modello né il suo codice. Modello e licenza: ${voce.licenza}.`,
];
// Una voce creata da una descrizione ha il suo campione e la sua scheda in scripts/narrazione/voci.
const rif = voce.modello.match(/voce di riferimento ([\w-]+)\.flac/);
if (rif) {
  const scheda = JSON.parse(readFileSync(join(qui, 'voci', 'voci.json'), 'utf8'));
  if (!scheda.voci[rif[1]] || !existsSync(join(qui, 'voci', `${rif[1]}.flac`))) throw new Error(`scripts/narrazione/voci: manca la voce ${rif[1]}`);
  righe.push(
    '',
    `La voce è stata creata da una descrizione a parole con ${scheda.modello} (stesso produttore e stessa licenza; descrizione in scripts/narrazione/voci/voci.json, ` +
      `campione in scripts/narrazione/voci/${rif[1]}.flac): nasce dalla sola descrizione, senza la registrazione di una persona da imitare.`,
  );
}
process.stdout.write(righe.join('\n') + '\n\n');
