import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { analyze, win11Requirements } from '../src/engine';
import type { Scan, Win11CPUCheck } from '../src/engine';
import { clinicScan } from '../src/demo/clinic';
import { demoScan } from '../src/demo/sample';
import { chipsetRow, codeNameRow, displayText, HardwareCard } from '../src/ui/pc';
import { DEMO_LIST_SOURCE, listResultText, sameWin11Target, simulatedWin11List, Win11Card } from '../src/ui/win11';

// Scheda «Requisiti di Windows 11» (come Controllo integrità PC), confronto
// con l'elenco ufficiale su richiesta (simulato nella demo) e righe nuove
// della scheda tecnica: nome in codice, chipset, schermi.

const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const card = (scan: Scan, live = false, source: 'agent' | 'demo' | 'file' = 'demo') =>
  renderToStaticMarkup(createElement(Win11Card, { scan, analysis: analyze(scan), live, source, addWin11List: () => true }));

const listed: Win11CPUCheck = {
  at: '2026-11-17T09:00:00Z',
  source: 'https://learn.microsoft.com/en-us/windows-hardware/design/minimum/supported/windows-11-25h2-supported-intel-processors',
  version: '25H2',
  kind: 'series',
  result: 'listed',
  match: 'Intel Core 12th Gen',
  cpu: '12th Gen Intel(R) Core(TM) i5-12500T',
  rows: 23,
};

describe('scheda Requisiti di Windows 11', () => {
  it('una riga per requisito con lo stato a icona e a parole (portatile con Windows 11)', () => {
    const html = card(demoScan);
    expect(html).toContain('Requisiti di Windows 11');
    expect(html).toContain('come Controllo integrità PC');
    expect(html).toContain('Windows 11 è già installato');
    expect((html.match(/class="w11-row"/g) ?? []).length).toBe(win11Requirements(demoScan).length);
    expect(html).toContain('TPM 2.0');
    expect(html).toContain('rispettato');
    expect(html).toContain('15,6&quot;, 1920×1080, 8 bit per colore');
    expect(html).toContain('DirectX 12 non è verificato da Polaris');
    expect(html).toContain('POPCNT e SSE4.2');
    // Il giudizio del motore in testa.
    expect(html).toContain('class="sev ok"');
  });

  it('PC fisso con Windows 10: lo schermo non si applica, Secure Boot spento da verificare, verdetto di Windows Update come indizio', () => {
    const html = card(clinicScan);
    expect(html).toContain('Per passare a Windows 11');
    expect(html).toContain('data-status="na"');
    expect(html).toContain('non si applica ai PC fissi');
    expect(html).toContain('spento: probabilmente attivabile');
    expect(html).toContain('da verificare');
    expect(html).toContain('Verdetto di Windows Update (indizio)');
    expect(html).toContain('Windows 10 versione 2004 o successiva');
  });

  it('il confronto con l\'elenco ufficiale: nella demo simulato e dichiarato, con l\'agente letto dal PC e non salvato, nei file solo l\'esito salvato', () => {
    const demo = card(demoScan);
    expect(demo).toContain('Controlla nell&#x27;elenco ufficiale Microsoft');
    expect(demo).toContain('Nella demo l&#x27;esito è simulato');
    const live = card(clinicScan, true, 'agent');
    expect(live).toContain('learn.microsoft.com');
    expect(live).toContain('La pagina non viene salvata');
    expect(live).toContain('aria-describedby="w11-check-note"');
    const file = card(clinicScan, false, 'file');
    expect(file).not.toContain('Controlla nell');
    expect(file).toContain('non contiene il confronto con l&#x27;elenco ufficiale');
  });

  it("con l'esito nel rapporto lo mostra e la riga del processore lo usa", () => {
    const s = clone(clinicScan);
    s.pc!.win11List = listed;
    const html = card(s, true, 'agent');
    expect(html).toContain('Il processore è nell&#x27;elenco ufficiale Microsoft per Windows 11 25H2 (elenco per serie): Intel Core 12th Gen.');
    expect(html).toContain('Pagina letta da learn.microsoft.com');
    expect(html).toContain('23 righe nell&#x27;elenco');
    expect(html).toContain('Controlla di nuovo');
    expect(win11Requirements(s).find((r) => r.id === 'cpu-gen')!.detail).toContain('letto su richiesta da questo PC');
  });

  it('esito simulato della demo, dalle regole di Polaris', () => {
    const r = simulatedWin11List(demoScan.pc!, '2026-11-17T09:00:00Z');
    expect(r).toMatchObject({ source: DEMO_LIST_SOURCE, version: '25H2', kind: 'series', result: 'listed', match: 'Core i5 di 11ª generazione' });
    const s = clone(demoScan);
    s.pc!.win11List = r;
    expect(card(s)).toContain('Esito simulato nella demo: nessuna pagina è stata letta');
    const old = clone(demoScan.pc!);
    old.cpu!.name = 'Intel(R) Core(TM) i7-6700 CPU @ 3.40GHz';
    expect(simulatedWin11List(old).result).toBe('notListed');
    const amd = clone(demoScan.pc!);
    amd.cpu!.name = 'AMD Ryzen 5 5600X 6-Core Processor';
    expect(simulatedWin11List(amd)).toMatchObject({ version: '24H2', kind: 'model', result: 'listed' });
  });

  it('testi dell\'esito: mai «non supportato» certo', () => {
    expect(listResultText({ ...listed, result: 'notListed', match: undefined }).text).toContain('la verifica definitiva è Controllo integrità PC');
    expect(listResultText({ ...listed, result: 'notListed' }).text).not.toMatch(/non supportato/);
    const u = listResultText({ ...listed, result: 'unknown', error: 'la pagina di Microsoft non ha la tabella attesa' });
    expect(u.sev).toBe('unknown');
    expect(u.text).toContain('(la pagina di Microsoft non ha la tabella attesa)');
  });

  it("l'esito si unisce solo al rapporto dello stesso PC e della stessa analisi, dall'agente o dalla demo", () => {
    const t = { host: clinicScan.agent.host, startedAt: clinicScan.agent.startedAt, live: true };
    expect(sameWin11Target(t, clinicScan, 'agent')).toBe(true);
    expect(sameWin11Target(t, clinicScan, 'file')).toBe(false);
    expect(sameWin11Target(t, clinicScan, 'demo')).toBe(false);
    expect(sameWin11Target({ ...t, live: false }, clinicScan, 'demo')).toBe(true);
    expect(sameWin11Target({ ...t, startedAt: '2020-01-01T00:00:00Z' }, clinicScan, 'agent')).toBe(false);
    expect(sameWin11Target({ ...t, host: 'ALTRO' }, clinicScan, 'agent')).toBe(false);
    expect(sameWin11Target(undefined, clinicScan, 'agent')).toBe(false);
  });

  it('non compare sui server né sui rapporti senza Windows 10 o 11', () => {
    const s = clone(clinicScan);
    s.pc!.os!.server = true;
    expect(card(s)).toBe('');
  });
});

describe('scheda tecnica: nome in codice, chipset, schermi', () => {
  it('nome in codice del processore, con «(da verificare)» quando è incerto', () => {
    expect(codeNameRow(demoScan.pc!.hardware!.cpu, demoScan.pc!.cpu!.name)).toMatch(/^Tiger Lake/);
    expect(codeNameRow(demoScan.pc!.hardware!.cpu, demoScan.pc!.cpu!.name)).not.toContain('da verificare');
    // Un AMD Zen fuori tabella resta «da verificare».
    expect(codeNameRow({ vendor: 'AuthenticAMD', family: 25, model: 0x7f, stepping: 0 }, 'AMD Prova')).toContain('(da verificare)');
    expect(codeNameRow(undefined, 'Processore sconosciuto')).toBeUndefined();
    const html = renderToStaticMarkup(createElement(HardwareCard, { pc: demoScan.pc!, live: false, source: 'demo' }));
    expect(html).toContain('Nome in codice');
    expect(html).toContain('Tiger Lake');
  });

  it('chipset nella scheda della scheda madre e schermi nella scheda video', () => {
    const board = renderToStaticMarkup(createElement(HardwareCard, { pc: clinicScan.pc!, live: false, source: 'demo', initialTab: 'board' }));
    expect(board).toContain('Chipset');
    expect(renderToStaticMarkup(createElement('div', null, chipsetRow(clinicScan.pc!.hardware!)))).toMatch(/Q670|serie 600|700/);
    const gpu = renderToStaticMarkup(createElement(HardwareCard, { pc: demoScan.pc!, live: false, source: 'demo', initialTab: 'gpu' }));
    expect(gpu).toContain('Schermo integrato');
    expect(gpu).toContain('15,6 pollici · 1920 × 1080 · 8 bit per colore');
    expect(gpu).toContain('WDDM 2.9');
    expect(displayText({})).toBe('dimensioni non dichiarate');
    // Senza dati dal firmware la riga del chipset non compare.
    const noChip = clone(clinicScan.pc!);
    delete noChip.hardware!.chipset;
    expect(chipsetRow(noChip.hardware!)).toBeUndefined();
  });
});
