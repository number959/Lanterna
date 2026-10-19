import { describe, expect, it } from 'vitest';
import { analyze, documentParts, renderDocument } from '../src/engine';
import type { Scan } from '../src/engine';
import { clinicScan } from '../src/demo/clinic';
import { demoScan } from '../src/demo/sample';

const clone = (s: Scan): Scan => JSON.parse(JSON.stringify(s));

describe('documento stampabile sullo stato del PC', () => {
  it('contiene riepilogo, sezioni del computer, piano con caselle e spazio per la firma', () => {
    for (const scan of [demoScan, clinicScan]) {
      const a = analyze(scan);
      const html = renderDocument(scan, a, { version: '0.7.0', generated: '19/10/2026 alle 10:00' });
      expect(html.startsWith('<!doctype html><html lang="it">')).toBe(true);
      expect(html).toContain('@page{size:A4');
      expect(html).toContain(scan.pc ? 'Stato del computer' : 'Stato della rete');
      expect(html).toContain(`<b>${a.score}</b>`);
      for (const s of ['Da sistemare per primo', 'Sistema', 'Sicurezza', 'Dischi e spazio', 'Valutazione completa', 'Scheda tecnica', "Piano d'azione", 'Note e firma'])
        expect(html, s).toContain(`<h2>${s}</h2>`);
      // Una casella da spuntare per ogni azione, e i giudizi con testo oltre al colore.
      expect(html.match(/class="pd-box"/g)?.length).toBe(a.plan.length);
      expect(html).toMatch(/pd-sev pd-(crit|warn)"><b aria-hidden="true">[✕!]<\/b> (Critico|Attenzione)/);
      expect(html).toContain('STARNET Polaris 0.7.0');
      expect(html).toContain('il 19/10/2026 alle 10:00');
    }
  });

  it('logo a colori su fondo chiaro, nessuna risorsa esterna né script', () => {
    const html = renderDocument(demoScan, analyze(demoScan));
    expect(html).toContain('<svg class="pd-logo"');
    expect(html).toContain('fill="#022D62"');
    expect(html).toContain('fill="#00B9FE"');
    expect(html).not.toMatch(/<script|<link|<img|<iframe|url\(http/i);
    expect(html).not.toMatch(/\s(src|href)="https?:/i);
  });

  it('niente MAC, IP pubblici o markup dai dati misurati', () => {
    const scan = clone(clinicScan);
    scan.agent.host = '<script>alert(1)</script>';
    const a = analyze(scan);
    a.findings[0] = { ...a.findings[0], verdict: 'Router aa:bb:cc:dd:ee:ff, indirizzo pubblico 93.184.216.34, gateway 192.168.1.1, DNS 8.8.8.8, firme 1.461.96.0 <b>x</b>' };
    const { body, title } = documentParts(scan, a);
    expect(body).not.toContain('<script>');
    expect(body).toContain('&lt;script&gt;');
    expect(title).toContain('<script>'); // il titolo va nel <title>, dove renderDocument lo protegge
    expect(renderDocument(scan, a)).toContain('<title>Stato del computer · &lt;script&gt;');
    expect(body).not.toContain('aa:bb:cc:dd:ee:ff');
    expect(body).toContain('[MAC]');
    expect(body).not.toContain('93.184.216.34');
    expect(body).toContain('[IP pubblico]');
    expect(body).toContain('192.168.1.1');
    expect(body).toContain('8.8.8.8');
    expect(body).toContain('1.461.96.0');
    expect(body).toContain('&lt;b&gt;x&lt;/b&gt;');
  });

  it('senza dati del computer resta un documento sulla rete', () => {
    const scan = clone(demoScan);
    delete scan.pc;
    const html = renderDocument(scan, analyze(scan));
    expect(html).toContain('<h1>Stato della rete</h1>');
    expect(html).not.toContain('<h2>Dischi e spazio</h2>');
    expect(html).toContain('<h2>Valutazione completa</h2>');
  });

  it('gli stili restano dentro .pdoc, salvo la pagina di stampa', () => {
    const { css } = documentParts(demoScan, analyze(demoScan));
    const rules = css
      .replace(/@media[^{]*\{/g, '')
      .split('}')
      .map((r) => r.trim())
      .filter((r) => r.includes('{'));
    for (const r of rules) {
      const sel = r.slice(0, r.indexOf('{')).trim();
      if (sel.startsWith('@page')) continue;
      for (const part of sel.split(',')) expect(part.trim(), sel).toMatch(/^\.pdoc/);
    }
  });
});
