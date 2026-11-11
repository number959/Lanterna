import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { CHAPTERS, GUIDES, VIDEOS, guideById, videoById } from '../src/guides';
import type { DiagramId } from '../src/guides';
import { DIAGRAM_IDS, Diagram } from '../src/ui/diagrams';

// Videoguide: la narrazione è registrata con una voce sintetica (o letta da
// una voce di Windows) ed è anche il sottotitolo. Questi test tengono le frasi brevi e
// pronunciabili, e ogni scena collegata a un disegno o a una mappa esistenti.

const MAPS = ['casa', 'clinica'];
// Simboli che la voce leggerebbe male o salterebbe, e virgolette (niente nomi di menu tra virgolette).
const FORBIDDEN = /[→←%/≥≤…()"«»]/;

const sentences = VIDEOS.flatMap((v) => v.scenes.flatMap((s) => s.narration.map((t) => ({ v: v.id, s: s.title, t }))));

describe('videoguide', () => {
  it('hanno identificativi unici, capitoli validi e una guida scritta esistente', () => {
    const ids = VIDEOS.map((v) => v.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const v of VIDEOS) {
      expect(CHAPTERS.some((c) => c.id === v.chapter), v.id).toBe(true);
      expect(v.guide, v.id).toBeDefined();
      expect(guideById(v.guide!), `${v.id} → ${v.guide}`).toBeDefined();
      expect(videoById(v.id)).toBe(v);
    }
  });

  it('comprendono le videoguide previste', () => {
    for (const id of ['mappa-della-rete', 'prima-analisi', 'scoprire-vlan', 'wifi-segnale-canali', 'indirizzi-dhcp', 'segmentazione-sanita', 'ram-memtest', 'usb-lento', 'percorso-internet']) {
      expect(videoById(id), id).toBeDefined();
    }
  });

  it('hanno da 4 a 7 scene, con titoli brevi e diversi', () => {
    for (const v of VIDEOS) {
      expect(v.scenes.length, v.id).toBeGreaterThanOrEqual(4);
      expect(v.scenes.length, v.id).toBeLessThanOrEqual(7);
      const titles = v.scenes.map((s) => s.title);
      expect(new Set(titles).size, v.id).toBe(titles.length);
      for (const t of titles) expect(t.length, `${v.id}: ${t}`).toBeLessThanOrEqual(32);
    }
  });

  it('ogni scena ha un disegno esistente oppure una mappa dimostrativa, non entrambi', () => {
    const known = new Set<string>(DIAGRAM_IDS);
    for (const v of VIDEOS) {
      for (const s of v.scenes) {
        const where = `${v.id}: ${s.title}`;
        expect(!!s.diagram !== !!s.map, where).toBe(true);
        if (s.diagram) expect(known.has(s.diagram), where).toBe(true);
        if (s.map) expect(MAPS, where).toContain(s.map);
      }
    }
  });

  it('ogni scena ha da 2 a 5 frasi', () => {
    for (const v of VIDEOS) {
      for (const s of v.scenes) {
        expect(s.narration.length, `${v.id}: ${s.title}`).toBeGreaterThanOrEqual(2);
        expect(s.narration.length, `${v.id}: ${s.title}`).toBeLessThanOrEqual(5);
      }
    }
  });

  it('ogni frase è breve, una sola e senza simboli da leggere', () => {
    for (const x of sentences) {
      const where = `${x.v} / ${x.s}: ${x.t}`;
      expect(x.t.length, where).toBeLessThanOrEqual(200);
      expect(x.t.length, where).toBeGreaterThan(10);
      expect(FORBIDDEN.test(x.t), where).toBe(false);
      expect(x.t, where).toMatch(/^[A-ZÀ-Ý0-9]/);
      expect(x.t, where).toMatch(/[.?!]$/);
      // Una frase per sottotitolo: niente punto seguito da un'altra frase.
      expect(/[.?!;]\s+\S/.test(x.t), where).toBe(false);
      expect(x.t.includes('  '), where).toBe(false);
    }
  });

  it('scrive i numeri con le unità da pronunciare, non le sigle delle unità', () => {
    for (const x of sentences) {
      const where = `${x.v} / ${x.s}: ${x.t}`;
      expect(/\d\s*(GHz|MHz|Mbit|Gbit|MB|GB|ms|dBm|dB)\b/.test(x.t), where).toBe(false);
    }
  });

  it('ogni videoguida compare nella sua guida scritta', () => {
    for (const v of VIDEOS) {
      const g = guideById(v.guide!)!;
      expect(g.blocks.some((b) => b.t === 'video' && b.id === v.id), `${v.id} in ${g.id}`).toBe(true);
    }
  });

  it('i blocchi video delle guide portano a videoguide esistenti, una volta per guida', () => {
    for (const g of GUIDES) {
      const ids = g.blocks.flatMap((b) => (b.t === 'video' ? [b.id] : []));
      expect(new Set(ids).size, g.id).toBe(ids.length);
      for (const id of ids) expect(videoById(id), `${g.id} → ${id}`).toBeDefined();
    }
  });
});

describe('disegni', () => {
  const used = new Set<DiagramId>([
    ...GUIDES.flatMap((g) => g.blocks.flatMap((b) => (b.t === 'diagram' ? [b.id] : []))),
    ...VIDEOS.flatMap((v) => v.scenes.flatMap((s) => (s.diagram ? [s.diagram] : []))),
  ]);

  it('ogni disegno è usato almeno in una guida o in una videoguida', () => {
    expect(DIAGRAM_IDS.filter((id) => !used.has(id))).toEqual([]);
  });

  it('ogni disegno nuovo compare in almeno una guida scritta', () => {
    const inGuides = new Set(GUIDES.flatMap((g) => g.blocks.flatMap((b) => (b.t === 'diagram' ? [b.id] : []))));
    for (const id of ['netmap', 'lldp', 'intervlan', 'snmp', 'traceroute', 'usbspeed', 'ramtest', 'bootphases', 'printpath', 'memtestusb'] as DiagramId[]) {
      expect(inGuides.has(id), id).toBe(true);
    }
  });

  it('ogni disegno è un\'immagine con una descrizione in italiano, senza segnaposto', () => {
    for (const id of DIAGRAM_IDS) {
      const html = renderToStaticMarkup(createElement(Diagram, { id, caption: 'Didascalia di prova' }));
      expect(html, id).toMatch(/<svg[^>]*role="img"/);
      const label = /aria-label="([^"]*)"/.exec(html)?.[1] ?? '';
      expect(label.length, id).toBeGreaterThan(60);
      expect(label, id).not.toMatch(/preparazione/i);
      expect(html, id).toContain('viewBox="0 0 640 ');
      expect(html, id).toContain('Didascalia di prova');
    }
  });
});
