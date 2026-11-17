import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import type { ProcessDetail, Scan } from '../src/engine';
import { clinicScan } from '../src/demo/clinic';
import { demoScan } from '../src/demo/sample';
import { connText, listenText, ownerText, procCheck, procRows, procSignature, ProcsCard, remotePortsText } from '../src/ui/procs';
import type { ProcView } from '../src/ui/procs';

// Sezione Processi della vista Computer: righe, filtri, ordinamento, albero
// padre-figlio, testi delle colonne e scheda resa con i dati delle demo.

const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const view = (patch: Partial<ProcView> = {}): ProcView => ({ query: '', filter: 'all', sort: { k: 'cpu', dir: -1 }, tree: false, ...patch });
const names = (s: Scan, v: ProcView) => procRows(s, v).map((r) => r.p.name);
const card = (scan: Scan, live = false, source: 'agent' | 'demo' | 'file' = 'demo') =>
  renderToStaticMarkup(createElement(ProcsCard, { scan, live, source, addProcs: () => true }));

describe('righe della tabella dei processi', () => {
  it('ordina per CPU e per nome, nei due versi', () => {
    const byCpu = procRows(demoScan, view());
    expect(byCpu[0].p.name).toBe('MsMpEng.exe');
    expect(byCpu[1].p.name).toBe('chrome.exe');
    const byName = names(demoScan, view({ sort: { k: 'name', dir: 1 } }));
    expect(byName[0].toLowerCase() <= byName[1].toLowerCase()).toBe(true);
    const back = names(demoScan, view({ sort: { k: 'name', dir: -1 } }));
    expect(back[0]).toBe(byName[byName.length - 1]);
    // Per firma: prima le più gravi.
    expect(procRows(demoScan, view({ sort: { k: 'sig', dir: 1 } }))[0].check.why.length).toBeGreaterThan(0);
  });

  it('«Solo da controllare» tiene firme da guardare, senza firma in AppData e i programmi in ascolto da controllare', () => {
    expect(names(demoScan, view({ filter: 'check' })).sort()).toEqual(['acmeshare.exe', 'phototray.exe']);
    const acme = procRows(demoScan, view({ filter: 'check' })).find((r) => r.p.name === 'acmeshare.exe')!;
    expect(acme.check.why).toEqual(['senza firma in una cartella dell\'utente', 'in ascolto su tutte le reti']);
    // Clinica: il gateway PACS senza firma riceve da tutta la rete sulla porta DICOM.
    expect(names(clinicScan, view({ filter: 'check' }))).toEqual(['pacsgw.exe']);
  });

  it('«In ascolto sulla rete» esclude chi ascolta solo questo PC (Polaris compreso)', () => {
    const l = names(demoScan, view({ filter: 'listen' }));
    expect(l).toContain('acmeshare.exe');
    expect(l).toContain('System');
    expect(l).not.toContain('STARNET-Polaris.exe');
    expect(names(clinicScan, view({ filter: 'listen' }))).not.toContain('agent.exe');
  });

  it('la ricerca guarda nome, descrizione, produttore e servizi', () => {
    expect(names(demoScan, view({ query: 'media server' }))).toEqual(['acmeshare.exe']);
    expect(names(demoScan, view({ query: 'dnscache' }))).toEqual(['svchost.exe']);
    expect(names(demoScan, view({ query: 'nessuno-così' }))).toEqual([]);
  });

  it("l'albero mette i figli sotto il padre e mostra gli antenati dei processi trovati come contesto", () => {
    const rows = procRows(demoScan, view({ tree: true, sort: { k: 'name', dir: 1 } }));
    const i = rows.findIndex((r) => r.p.pid === 6012);
    expect(rows[i].depth).toBe(1);
    expect(rows[i].parent?.name).toBe('explorer.exe');
    const kids = rows.slice(i + 1, i + 3);
    expect(kids.map((r) => [r.p.pid, r.depth])).toEqual([
      [6044, 2],
      [6100, 2],
    ]);
    // La finestra di Polaris sotto l'agente.
    const web = rows.find((r) => r.p.pid === 8164)!;
    expect(web.parent?.pid).toBe(8120);
    const found = procRows(demoScan, view({ tree: true, query: 'chrome' }));
    expect(found[0].p.name).toBe('explorer.exe');
    expect(found[0].ctx).toBe(true);
    expect(found.filter((r) => !r.ctx).every((r) => r.p.name === 'chrome.exe')).toBe(true);
    // Un padre avviato dopo il figlio è un PID riusato: il figlio resta in cima.
    const s = clone(demoScan);
    const items = s.pc!.procs!.items;
    items.find((p) => p.pid === 4720)!.started = '2026-10-12T20:00:00Z';
    items.find((p) => p.pid === 6012)!.started = '2026-10-12T19:00:00Z';
    const r2 = procRows(s, view({ tree: true }));
    expect(r2.find((r) => r.p.pid === 6012)!.depth).toBe(0);
  });

  it('i processi di Polaris non si giudicano', () => {
    const polaris = demoScan.pc!.procs!.items.find((p) => p.polaris)!;
    expect(procCheck(polaris, [polaris.pid])).toEqual({ sev: 'ok', why: [] });
  });
});

describe('testi delle colonne', () => {
  const p = (patch: Partial<ProcessDetail>): ProcessDetail => ({ pid: 100, name: 'prova.exe', ...patch });

  it('firma: non leggibile, nucleo di Windows, senza firma in una cartella dell\'utente, firma valida', () => {
    expect(procSignature(p({ access: 'none' }))).toEqual({ text: 'Non leggibile senza amministratore', tone: 'unknown' });
    expect(procSignature(p({ pid: 4, name: 'System' })).text).toBe('Nucleo di Windows: nessun file da verificare');
    expect(procSignature(p({ file: { path: '%USERPROFILE%\\AppData\\x.exe', folder: 'appData', signature: { status: 'unsigned' } } })).tone).toBe('warn');
    expect(procSignature(p({ file: { path: 'C:\\Program Files\\x.exe', folder: 'programFiles', signature: { status: 'unsigned' } } })).tone).toBe('info');
    const ok = procSignature(p({ file: { path: 'C:\\Windows\\System32\\svchost.exe', folder: 'windows', signature: { status: 'valid', signer: 'Microsoft Windows', catalog: true } } }));
    expect(ok).toEqual({ text: 'Firma verificata · Microsoft Windows (catalogo di Windows)', tone: 'ok' });
    expect(procSignature(p({ file: { path: 'C:\\x.exe', signature: { status: 'tampered' } } })).tone).toBe('crit');
  });

  it('utente per categoria, rete per destinazione senza indirizzi', () => {
    expect(ownerText(p({ owner: 'self' }))).toBe('Tu');
    expect(ownerText(p({ owner: 'self', elevated: true }))).toBe('Tu, come amministratore');
    expect(ownerText(p({ owner: 'system' }))).toBe('Sistema');
    expect(ownerText(p({ owner: 'other' }))).toBe('Altro account');
    expect(ownerText(p({ access: 'none' }))).toBe('Non leggibile');
    expect(listenText([{ proto: 'tcp', port: 8200, scope: 'all' }, { proto: 'udp', port: 1900, scope: 'all' }, { proto: 'tcp', port: 8200, scope: 'all' }])).toBe(
      'TCP 8200 (tutte le reti), UDP 1900 (tutte le reti)',
    );
    expect(listenText([{ proto: 'tcp', port: 8737, scope: 'local' }])).toBe('TCP 8737 (solo questo PC)');
    expect(connText({ internet: 2, lan: 1 })).toBe('2 verso Internet, 1 in rete locale');
    expect(connText({ local: 3 })).toBe('3 su questo PC');
    expect(remotePortsText({ remotePorts: [{ port: 443, count: 14 }] })).toBe('porta 443');
    expect(remotePortsText({ remotePorts: [{ port: 443, count: 12 }, { port: 80, count: 2 }] })).toBe('porte 443 (12), 80 (2)');
  });
});

describe('scheda Processi', () => {
  it('nella demo: tabella ordinabile, filtri con etichetta, albero a interruttore, Polaris segnato, nessun aggiornamento dal vivo', () => {
    const html = card(demoScan);
    expect(html).toContain('Processi in esecuzione');
    expect(html).toContain('acmeshare.exe');
    expect(html).toContain('AcmeShare Media Server');
    expect(html).toContain('da controllare: senza firma in una cartella dell&#x27;utente, in ascolto su tutte le reti');
    expect(html).toContain('STARNET Polaris: escluso dai giudizi');
    expect(html).toContain('aria-sort="descending"');
    expect((html.match(/aria-sort=/g) ?? []).length).toBe(7);
    expect(html).toContain('aria-label="Cerca un processo"');
    expect(html).toContain('aria-pressed="true"');
    expect(html).toContain('role="switch"');
    expect(html).toContain('Solo da controllare (2)');
    expect(html).toContain('14 verso Internet');
    expect(html).toContain('in ascolto: TCP 8200 (tutte le reti), UDP 1900 (tutte le reti)');
    expect(html).toContain('7 processi di altri account non si aprono');
    expect(html).toContain('nella demo l&#x27;elenco non si aggiorna dal vivo');
    expect(html).toContain('revoca dei certificati non è controllata');
    expect(html).not.toContain('Aggiorna');
    expect(html).toContain('tabindex="0"');
  });

  it("con l'agente c'è «Aggiorna»; senza elenco nel rapporto si può leggere", () => {
    const live = clone(demoScan);
    expect(card(live, true, 'agent')).toContain('Aggiorna');
    delete live.pc!.procs;
    const none = card(live, true, 'agent');
    expect(none).toContain('Leggi i processi');
    expect(none).toContain('non contiene l&#x27;elenco dei processi');
  });

  it('dopo una lettura dal vivo senza CPU lo dice e ordina per memoria', () => {
    const s = clone(demoScan);
    for (const p of s.pc!.procs!.items) delete p.cpuPct;
    const html = card(s, true, 'agent');
    expect(html).toContain('la colonna CPU resta vuota');
    expect(html).toMatch(/aria-sort="descending" class="num"><button>Memoria/);
    expect(procRows(s, { query: '', filter: 'all', sort: { k: 'mem', dir: -1 }, tree: false })[0].p.name).toBe('ms-teams.exe');
  });

  it('nessun indirizzo, profilo o riga di comando nella scheda', () => {
    for (const s of [demoScan, clinicScan]) {
      const html = card(s);
      expect(html).not.toMatch(/C:\\Users\\/i);
      expect(html).not.toMatch(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
      // Nei dati nessun campo di indirizzo o di riga di comando (i numeri di versione somigliano a un IPv4).
      expect(JSON.stringify(s.pc!.procs)).not.toMatch(/"(?:remote|remoteAddr|address|addr|ip|commandLine|cmdline|user|sid)"\s*:/i);
    }
  });
});
