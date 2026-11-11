import { describe, expect, it } from 'vitest';
import { italianVoices, readingMs, videoMinutes } from '../src/ui/videoguide';
import { VIDEOS } from '../src/guides';

// Lettore delle videoguide: scelta della voce di Windows, usata in alternativa
// alla narrazione registrata (solo voci italiane installate sul PC, Elsa per
// prima), tempi di lettura senza voce, durata stimata.

const v = (name: string, lang: string, localService: boolean) => ({ name, lang, localService, voiceURI: name, default: false }) as SpeechSynthesisVoice;

describe('voci', () => {
  it('solo voci italiane locali, con Elsa per prima', () => {
    const list = italianVoices([
      v('Microsoft Cosimo - Italian (Italy)', 'it-IT', true),
      v('Microsoft Elsa - Italian (Italy)', 'it-IT', true),
      v('Microsoft Isabella Online (Natural) - Italian (Italy)', 'it-IT', false),
      v('Microsoft Zira - English (United States)', 'en-US', true),
      v('Italiano generico', 'it', true),
    ]);
    expect(list.map((x) => x.name)).toEqual(['Microsoft Elsa - Italian (Italy)', 'Italiano generico', 'Microsoft Cosimo - Italian (Italy)']);
    expect(italianVoices([v('Google italiano', 'it-IT', false)])).toEqual([]);
  });
});

describe('tempi', () => {
  it('lettura senza voce: almeno 2,4 secondi, più veloce con la velocità alta', () => {
    expect(readingMs('Breve.')).toBe(2400);
    expect(readingMs('x'.repeat(140))).toBe(10000);
    expect(readingMs('x'.repeat(140), 1.25)).toBe(8000);
  });

  it('ogni videoguida ha una durata stimata di almeno un minuto', () => {
    for (const g of VIDEOS) expect(videoMinutes(g), g.id).toBeGreaterThanOrEqual(1);
  });
});
