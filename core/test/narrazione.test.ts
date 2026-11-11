import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { VIDEOS } from '../src/guides';
import { CLIP, VOCE } from '../src/guides/narrazione';
import { allRecorded, clipOf } from '../src/ui/narrazione';
import { readingMs, videoMinutes } from '../src/ui/videoguide';

// Narrazione registrata delle videoguide: ogni frase ha la sua registrazione,
// con il testo di oggi (una frase cambiata senza rifare la registrazione fa
// fallire la prova), i file sono Ogg Opus veri e di peso ragionevole, e
// nell'indice non restano registrazioni di frasi che non esistono più.

const dir = join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'guides', 'narrazione');
const frasi = VIDEOS.flatMap((v) => v.scenes.flatMap((s) => s.narration.map((t) => ({ video: v.id, t }))));

describe('narrazione registrata', () => {
  it('la voce è dichiarata: nome, motore, modello e licenza', () => {
    expect(VOCE).toBeDefined();
    for (const k of ['nome', 'motore', 'modello', 'licenza'] as const) expect(VOCE![k].trim().length, k).toBeGreaterThan(2);
  });

  it('una voce creata da una descrizione ha ancora il suo campione e la sua scheda', () => {
    // Il campione è la voce: senza, una frase cambiata non si può più registrare con la stessa voce.
    const m = /voce di riferimento ([\w-]+)\.flac/.exec(VOCE!.modello);
    if (!m) return;
    const voci = join(dir, '..', '..', '..', '..', 'scripts', 'narrazione', 'voci');
    expect(existsSync(join(voci, `${m[1]}.flac`)), `${m[1]}.flac`).toBe(true);
    const scheda = JSON.parse(readFileSync(join(voci, 'voci.json'), 'utf8')) as { voci: Record<string, string>; testo: string };
    expect(Object.keys(scheda.voci)).toContain(m[1]);
    expect(scheda.testo.length).toBeGreaterThan(20);
  });

  it('ogni frase di ogni videoguida ha la sua registrazione, con il testo di oggi', () => {
    const mancanti = frasi.filter((f) => !CLIP[f.t]).map((f) => `${f.video}: ${f.t}`);
    expect(mancanti, 'frasi senza registrazione: rilancia scripts/narrazione/genera.py').toEqual([]);
    for (const v of VIDEOS) expect(allRecorded(v.scenes.flatMap((s) => s.narration)), v.id).toBe(true);
    expect(clipOf(frasi[0].t)!.url).toMatch(/\.ogg$/);
    expect(clipOf('Una frase che non esiste.')).toBeUndefined();
    expect(allRecorded([])).toBe(false);
  });

  it('nessuna registrazione di frasi che non esistono più, nessun file fuori dall\'indice', () => {
    const testi = new Set(frasi.map((f) => f.t));
    expect(Object.keys(CLIP).filter((t) => !testi.has(t))).toEqual([]);
    const nomi = Object.values(CLIP).map((c) => c.file);
    expect(new Set(nomi).size).toBe(nomi.length);
    expect(readdirSync(dir).filter((f) => f.endsWith('.ogg')).sort()).toEqual([...nomi].sort());
  });

  it('i file sono Ogg Opus, con una durata credibile per la lunghezza della frase', () => {
    let totale = 0;
    for (const [testo, c] of Object.entries(CLIP)) {
      const b = readFileSync(join(dir, c.file));
      expect(b.subarray(0, 4).toString('latin1'), c.file).toBe('OggS');
      expect(b.includes(Buffer.from('OpusHead')), c.file).toBe(true);
      // Tra 35 e 140 millisecondi per carattere: una frase tagliata o con parole ripetute esce da qui.
      expect(c.ms / testo.length, testo).toBeGreaterThan(35);
      expect(c.ms / testo.length, testo).toBeLessThan(140);
      // Il peso segue la durata (circa 32 kbit/s): né un file vuoto né uno fuori misura.
      const kbit = (statSync(join(dir, c.file)).size * 8) / c.ms;
      expect(kbit, c.file).toBeGreaterThan(12);
      expect(kbit, c.file).toBeLessThan(64);
      totale += b.length;
    }
    // Tutta la narrazione resta leggera dentro il programma.
    expect(totale).toBeLessThan(6_000_000);
  });

  it('la durata delle videoguide viene dalle registrazioni', () => {
    for (const v of VIDEOS) {
      const ms = v.scenes.reduce((a, s) => a + s.narration.reduce((b, t) => b + CLIP[t].ms + 350, 0), 0);
      expect(videoMinutes(v), v.id).toBe(Math.max(1, Math.round(ms / 60000)));
    }
    // Senza registrazione resta la stima dal numero di caratteri.
    expect(readingMs('Breve.')).toBe(2400);
  });
});
