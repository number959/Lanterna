import { describe, expect, it } from 'vitest';
import { ACTIONS, METRICS } from '../src/engine';
import { blockTexts, CHAPTERS, fold, GLOSSARY, GUIDES, guideById, linksIn, parseInline, plainText, search } from '../src/guides';

// La biblioteca è un insieme di dati scritti a mano: questi test impediscono
// collegamenti rotti, riferimenti a misure o azioni inesistenti e markup
// lasciato a metà.

const metricIds = new Set(Object.keys(METRICS));
const actionIds = new Set(Object.keys(ACTIONS));
const allTexts = (id: string) => {
  const g = guideById(id)!;
  return [g.title, g.summary, ...g.blocks.flatMap(blockTexts)];
};

describe('biblioteca delle guide', () => {
  it('ha identificativi unici e capitoli validi, ognuno con almeno una guida', () => {
    const ids = GUIDES.map((g) => g.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const c of CHAPTERS) expect(GUIDES.some((g) => g.chapter === c.id), c.id).toBe(true);
    for (const g of GUIDES) expect(CHAPTERS.some((c) => c.id === g.chapter), g.id).toBe(true);
  });

  it('ha tutti i collegamenti interni verso guide esistenti', () => {
    const broken: string[] = [];
    for (const g of GUIDES) {
      for (const t of allTexts(g.id)) for (const id of linksIn(t)) if (!guideById(id)) broken.push(`${g.id} → ${id}`);
    }
    expect(broken).toEqual([]);
  });

  it('non collega una guida a sé stessa', () => {
    for (const g of GUIDES) for (const t of allTexts(g.id)) expect(linksIn(t), g.id).not.toContain(g.id);
  });

  it('collega solo misure e azioni presenti nella knowledge base', () => {
    for (const g of GUIDES) {
      for (const m of g.metrics ?? []) expect(metricIds.has(m), `${g.id}: metrica ${m}`).toBe(true);
      for (const a of g.actions ?? []) expect(actionIds.has(a), `${g.id}: azione ${a}`).toBe(true);
    }
  });

  it('spiega ogni misura in almeno una guida', () => {
    const covered = new Set(GUIDES.flatMap((g) => g.metrics ?? []));
    expect([...metricIds].filter((m) => !covered.has(m))).toEqual([]);
  });

  it('non lascia markup aperto', () => {
    for (const g of GUIDES) {
      for (const t of allTexts(g.id)) {
        const left = plainText(t);
        expect(left.includes('**'), `${g.id}: ${t.slice(0, 60)}`).toBe(false);
        expect(left.includes('[['), `${g.id}: ${t.slice(0, 60)}`).toBe(false);
        expect(left.includes(']]'), `${g.id}: ${t.slice(0, 60)}`).toBe(false);
      }
    }
  });

  it('ha tabelle con righe della stessa lunghezza dell\'intestazione', () => {
    for (const g of GUIDES) {
      for (const b of g.blocks) {
        if (b.t !== 'table') continue;
        for (const r of b.rows) expect(r.length, `${g.id}: ${r[0]}`).toBe(b.head.length);
      }
    }
  });

  it('ha un glossario senza doppioni e con rimandi validi', () => {
    const terms = GLOSSARY.map((t) => fold(t.term));
    expect(new Set(terms).size).toBe(terms.length);
    for (const t of GLOSSARY) if (t.guide) expect(guideById(t.guide), t.term).toBeDefined();
    expect(GLOSSARY.length).toBeGreaterThanOrEqual(100);
  });

  it('copre gli argomenti chiesti per le reti sanitarie', () => {
    for (const id of ['rete-clinica-architettura', 'dispositivi-medicali-in-rete', 'dicom-hl7-pacs', 'wifi-sanitario', 'privacy-normativa-sanita', 'segmentazione']) {
      expect(guideById(id), id).toBeDefined();
    }
  });
});

describe('markup in linea', () => {
  it('riconosce grassetto, codice e collegamenti', () => {
    expect(parseInline('a **b** `c` [[dns]] [[dhcp|il DHCP]] d')).toEqual([
      { t: 'text', s: 'a ' },
      { t: 'b', s: 'b' },
      { t: 'text', s: ' ' },
      { t: 'code', s: 'c' },
      { t: 'text', s: ' ' },
      { t: 'link', id: 'dns', s: guideById('dns')!.title },
      { t: 'text', s: ' ' },
      { t: 'link', id: 'dhcp', s: 'il DHCP' },
      { t: 'text', s: ' d' },
    ]);
  });

  it('lascia intatto il testo senza markup', () => {
    expect(parseInline('solo testo')).toEqual([{ t: 'text', s: 'solo testo' }]);
    expect(plainText('`ipconfig /all` e **169.254**')).toBe('ipconfig /all e 169.254');
  });
});

describe('ricerca', () => {
  it('trova per titolo, ignorando maiuscole e accenti', () => {
    const r = search('qualita servizio');
    expect(r[0]).toMatchObject({ kind: 'guide' });
    expect(r[0].kind === 'guide' && r[0].guide.id).toBe('qos');
  });

  it('trova i protocolli sanitari e le porte', () => {
    const top = (q: string) => search(q).find((h) => h.kind === 'guide');
    expect(top('DICOM')?.kind === 'guide' && top('DICOM')?.guide.id).toBe('dicom-hl7-pacs');
    const port = search('11112');
    expect(port.some((h) => h.kind === 'guide' && h.guide.id === 'dicom-hl7-pacs')).toBe(true);
  });

  it('richiede che tutte le parole compaiano', () => {
    expect(search('ransomware zzzzzz')).toEqual([]);
  });

  it('include il glossario', () => {
    const r = search('SNMP');
    expect(r.some((h) => h.kind === 'term' && h.term.term === 'SNMP')).toBe(true);
  });

  it('restituisce un estratto del testo', () => {
    const r = search('kerberos');
    const g = r.find((h) => h.kind === 'guide');
    expect(g && g.kind === 'guide' && g.snippet && fold(g.snippet).includes('kerberos')).toBe(true);
  });

  it('ignora le ricerche vuote', () => {
    expect(search('  ')).toEqual([]);
  });
});

describe('due test di velocità: del PC e di Internet', () => {
  const texts = (id: string) => allTexts(id).map(plainText);
  const blocksOf = (id: string) => guideById(id)!.blocks;

  it('nessuna frase dice che "i test di velocità non partono": il test di Internet non si ferma', () => {
    // L'agente blocca durante una scansione di Defender o un'analisi dello spazio solo i test della CPU e del disco.
    for (const g of GUIDES) for (const t of allTexts(g.id)) expect(plainText(t), g.id).not.toMatch(/test di velocità non partono/i);
    expect(texts('strumenti-avanzati').join(' ')).toContain('durante una scansione i test del processore e del disco non partono');
    expect(texts('spazio-disco').join(' ')).toContain('i test del processore e del disco non partono');
  });

  it('titoli e intestazioni distinguono i test del PC da quello di Internet', () => {
    const heads = blocksOf('strumenti-avanzati').filter((b) => b.t === 'h').map((b) => (b.t === 'h' ? b.text : ''));
    expect(heads).not.toContain('Test di velocità');
    expect(heads).toContain('Test del processore e del disco');
    expect(guideById('test-velocita')!.title).toMatch(/processore e del disco/);
    expect(guideById('velocita-internet')!.title).toMatch(/di Internet/);
  });

  it('la tabella delle sezioni elenca schermate blu, mappa del Wi-Fi e test di velocità di Internet', () => {
    const table = blocksOf('sezioni-del-programma').find((b) => b.t === 'table');
    const rows = table && table.t === 'table' ? table.rows : [];
    const row = (section: string) => rows.find((r) => r[1] === section)!;
    expect(row('Computer')[2]).toContain('file delle schermate blu');
    expect(row('Computer')[2]).toContain('test di velocità del processore e del disco');
    expect(row('Wi-Fi')[2]).toContain('mappa del Wi-Fi per stanza');
    expect(row('Internet e DNS')[2]).toContain('test di velocità di Internet');
  });

  it('le domande frequenti e la privacy non negano il test di velocità di Internet', () => {
    const faq = blocksOf('domande-frequenti');
    const i = faq.findIndex((b) => b.t === 'h' && b.text === 'Misura la velocità della mia linea Internet?');
    const answer = faq[i + 1];
    expect(answer.t === 'p' && answer.text).toMatch(/^Sì/);
    expect(answer.t === 'p' && linksIn(answer.text)).toContain('velocita-internet');
    const privacy = blocksOf('primi-passi').find((b) => b.t === 'note' && b.title === 'I tuoi dati');
    expect(privacy && privacy.t === 'note' && privacy.text).toContain('M-Lab');
    expect(privacy && privacy.t === 'note' && privacy.text).toContain('indirizzo IP pubblico');
  });
});
