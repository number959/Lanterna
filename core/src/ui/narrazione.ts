import { CLIP, VOCE } from '../guides/narrazione';

// Narrazione registrata delle videoguide: una registrazione per frase, generata
// una volta con una voce neurale (scripts/narrazione) e inclusa nel programma.
// Non serve una voce installata sul PC e durante l'ascolto nulla esce dal
// computer: i file arrivano dal programma stesso, come le immagini.

const URLS = import.meta.glob('../guides/narrazione/*.ogg', { eager: true, query: '?url', import: 'default' }) as Record<string, string>;

export interface Clip {
  url: string;
  /** Durata della registrazione a velocità normale. */
  ms: number;
}

/** La registrazione di una frase, se c'è. */
export function clipOf(text: string): Clip | undefined {
  const c = CLIP[text];
  if (!c) return undefined;
  const url = URLS[`../guides/narrazione/${c.file}`];
  return url ? { url, ms: c.ms } : undefined;
}

/** Tutte le frasi hanno la loro registrazione: la voce registrata si può proporre. */
export const allRecorded = (texts: string[]) => texts.length > 0 && texts.every((t) => !!clipOf(t));

export { VOCE };
