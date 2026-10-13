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
