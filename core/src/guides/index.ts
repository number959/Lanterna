import type { Block, Chapter, ChapterId, GlossaryTerm, Guide } from './types';
import { fondamenti } from './fondamenti';
import { wifi } from './wifi';
import { cablata } from './cablata';
import { servizi } from './servizi';
import { sicurezza } from './sicurezza';
import { complesse } from './complesse';
import { diagnosi } from './diagnosi';
import { glossario } from './glossario';
import { pc } from './pc';
import { uso } from './uso';

export type * from './types';

export const CHAPTERS: Chapter[] = [
  { id: 'uso', title: 'Usare STARNET Polaris', summary: 'Primi passi, le sezioni del programma, piano d\'azione ed esportazioni, strumenti avanzati, riga di comando e domande frequenti.' },
  { id: 'pc', title: 'Il computer', summary: 'Come funziona un PC, dischi HDD e SSD e la loro salute, test di velocità, memoria, avvio, aggiornamenti, registro eventi, batteria e il metodo per un PC lento.' },
  { id: 'fondamenti', title: 'Fondamenti', summary: 'Come funziona una rete: livelli, indirizzi, DHCP, DNS, instradamento, porte, IPv6 e le misure di qualità.' },
  { id: 'wifi', title: 'Wi-Fi', summary: 'Segnale, bande e canali, standard, sicurezza, progettazione, roaming, più access point e interferenze.' },
  { id: 'cablata', title: 'Rete cablata', summary: 'Cavi e fibra, switch e VLAN, anelli e ridondanza, PoE, architettura di una rete aziendale.' },
  { id: 'servizi', title: 'Servizi di rete', summary: 'Firewall, VPN, QoS, gestione e monitoraggio, linea Internet, telefonia, stampa e dominio.' },
  { id: 'sicurezza', title: 'Sicurezza', summary: 'Principi, segmentazione, credenziali e aggiornamenti, minacce comuni, log e backup.' },
  { id: 'complesse', title: 'Reti complesse e sanità', summary: 'La rete di una clinica: dispositivi medicali, DICOM e HL7, Wi-Fi sanitario, norme, continuità, inventario e analisi su larga scala.' },
  { id: 'diagnosi', title: 'Diagnosi', summary: 'Il metodo, gli strumenti di Windows e i problemi tipici con le loro cause.' },
];

export const GUIDES: Guide[] = [...uso, ...pc, ...fondamenti, ...wifi, ...cablata, ...servizi, ...sicurezza, ...complesse, ...diagnosi];

const collator = new Intl.Collator('it', { sensitivity: 'base', numeric: true });
export const GLOSSARY: GlossaryTerm[] = [...glossario].sort((a, b) => collator.compare(a.term, b.term));

const byId = new Map(GUIDES.map((g) => [g.id, g]));

export function guideById(id: string): Guide | undefined {
  return byId.get(id);
}

export function chapterOf(id: ChapterId): Chapter {
  return CHAPTERS.find((c) => c.id === id)!;
}

export function guidesOf(chapter: ChapterId): Guide[] {
  return GUIDES.filter((g) => g.chapter === chapter);
}

/** Guide che spiegano una metrica (chiave della knowledge base). */
export function guidesForMetric(metric: string): Guide[] {
  return GUIDES.filter((g) => g.metrics?.includes(metric));
}

/** Guide collegate a un'azione del catalogo. */
export function guidesForAction(action: string): Guide[] {
  return GUIDES.filter((g) => g.actions?.includes(action));
}

/** Guida precedente e successiva nell'ordine di lettura. */
export function neighbours(id: string): { prev?: Guide; next?: Guide } {
  const i = GUIDES.findIndex((g) => g.id === id);
  if (i < 0) return {};
  return { prev: GUIDES[i - 1], next: GUIDES[i + 1] };
}

// ------------------------------------------------------------ markup in linea

export type Inline =
  | { t: 'text'; s: string }
  | { t: 'b'; s: string }
  | { t: 'code'; s: string }
  | { t: 'link'; id: string; s: string };

const INLINE = /\*\*(.+?)\*\*|`([^`]+)`|\[\[([a-z0-9-]+)(?:\|([^\]]+))?\]\]/g;

/** Scompone il markup minimo delle guide: **grassetto**, `codice`, [[id]] e [[id|testo]]. */
export function parseInline(text: string): Inline[] {
  const out: Inline[] = [];
  let last = 0;
  for (const m of text.matchAll(INLINE)) {
    const at = m.index ?? 0;
    if (at > last) out.push({ t: 'text', s: text.slice(last, at) });
    if (m[1] !== undefined) out.push({ t: 'b', s: m[1] });
    else if (m[2] !== undefined) out.push({ t: 'code', s: m[2] });
    else {
      const id = m[3];
      out.push({ t: 'link', id, s: m[4] ?? byId.get(id)?.title ?? id });
    }
    last = at + m[0].length;
  }
  if (last < text.length) out.push({ t: 'text', s: text.slice(last) });
  return out;
}

/** Testo senza markup (ricerca, anteprime, esportazione). */
export function plainText(text: string): string {
  return parseInline(text).map((x) => x.s).join('');
}

/** Tutti i collegamenti [[id]] presenti in un testo. */
export function linksIn(text: string): string[] {
  return parseInline(text).flatMap((x) => (x.t === 'link' ? [x.id] : []));
}

/** Tutti i testi di un blocco, nell'ordine in cui compaiono. */
export function blockTexts(b: Block): string[] {
  switch (b.t) {
    case 'p':
    case 'h':
    case 'code':
      return [b.text];
    case 'note':
      return b.title ? [b.title, b.text] : [b.text];
    case 'list':
      return b.items;
    case 'table':
      return [...(b.caption ? [b.caption] : []), ...b.head, ...b.rows.flat()];
    case 'diagram':
      return [b.caption];
  }
}

/** Titoli di sezione di una guida, per l'indice laterale. */
export function headingsOf(g: Guide): string[] {
  return g.blocks.flatMap((b) => (b.t === 'h' ? [b.text] : []));
}

/** Tempo di lettura stimato in minuti (circa 180 parole al minuto per testo tecnico). */
export function readingMinutes(g: Guide): number {
  const words = g.blocks.flatMap(blockTexts).join(' ').split(/\s+/).filter(Boolean).length;
  return Math.max(1, Math.round(words / 180));
}

// ------------------------------------------------------------------- ricerca

/** Minuscolo e senza accenti: "Qualità" e "qualita" coincidono. */
export function fold(s: string): string {
  return s.normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase();
}

interface Indexed {
  guide: Guide;
  title: string;
  tags: string;
  summary: string;
  headings: string;
  body: string;
  /** Testo originale dei blocchi, per l'estratto. */
  raw: string[];
}

let index: Indexed[] | null = null;

function buildIndex(): Indexed[] {
  return GUIDES.map((g) => {
    const raw = g.blocks.flatMap(blockTexts).map(plainText);
    return {
      guide: g,
      title: fold(g.title),
      tags: fold((g.tags ?? []).join(' | ')),
      summary: fold(g.summary),
      headings: fold(headingsOf(g).join(' | ')),
      body: fold(raw.join(' \n ')),
      raw,
    };
  });
}

export type SearchHit =
  | { kind: 'guide'; guide: Guide; score: number; snippet?: string }
  | { kind: 'term'; term: GlossaryTerm; score: number };

function tokens(q: string): string[] {
  return fold(q)
    .split(/[\s,;:!?()"']+/)
    .map((t) => t.replace(/^[.]+|[.]+$/g, ''))
    .filter((t) => t.length >= 2 || /\d/.test(t));
}

function wordStart(hay: string, tok: string): boolean {
  let i = hay.indexOf(tok);
  while (i >= 0) {
    if (i === 0 || !/[a-z0-9]/.test(hay[i - 1])) return true;
    i = hay.indexOf(tok, i + 1);
  }
  return false;
}

function snippetFor(raw: string[], tok: string): string | undefined {
  for (const r of raw) {
    const f = fold(r);
    const i = f.indexOf(tok);
    if (i < 0) continue;
    // Sul testo italiano fold() conserva la lunghezza (le lettere accentate
    // perdono solo il segno): la posizione trovata vale anche sull'originale.
    const start = Math.max(0, i - 60);
    const end = Math.min(r.length, i + tok.length + 90);
    return (start > 0 ? '…' : '') + r.slice(start, end).trim() + (end < r.length ? '…' : '');
  }
  return undefined;
}

/**
 * Ricerca nel testo completo di guide e glossario. Tutte le parole cercate
 * devono comparire (in titolo, parole chiave, riassunto, sezioni o testo);
 * il punteggio premia i campi più importanti e gli inizi di parola.
 */
export function search(query: string, limit = 30): SearchHit[] {
  const toks = tokens(query);
  if (!toks.length) return [];
  index ??= buildIndex();
  const hits: SearchHit[] = [];
  for (const x of index) {
    let score = 0;
    let all = true;
    for (const t of toks) {
      let s = 0;
      if (x.title.includes(t)) s += wordStart(x.title, t) ? 12 : 6;
      if (x.tags.includes(t)) s += wordStart(x.tags, t) ? 8 : 4;
      if (x.summary.includes(t)) s += 4;
      if (x.headings.includes(t)) s += 3;
      if (x.body.includes(t)) s += 1 + Math.min(4, x.body.split(t).length - 2) * 0.5;
      if (s === 0) {
        all = false;
        break;
      }
      score += s;
    }
    if (all) hits.push({ kind: 'guide', guide: x.guide, score, snippet: snippetFor(x.raw, toks[0]) });
  }
  for (const term of GLOSSARY) {
    const name = fold(term.term + ' ' + (term.full ?? ''));
    const def = fold(term.def);
    let score = 0;
    let all = true;
    for (const t of toks) {
      let s = 0;
      if (name.includes(t)) s += wordStart(name, t) ? 14 : 7;
      if (def.includes(t)) s += 1.5;
      if (s === 0) {
        all = false;
        break;
      }
      score += s;
    }
    if (all) hits.push({ kind: 'term', term, score });
  }
  return hits.sort((a, b) => b.score - a.score).slice(0, limit);
}
