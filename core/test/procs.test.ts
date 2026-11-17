import vm from 'node:vm';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { describe, expect, it } from 'vitest';
import {
  ACTIONS,
  analyze,
  documentParts,
  fileSeverity,
  folderLabel,
  isLookalike,
  listeners,
  METRICS,
  ownerLabel,
  procGroups,
  renderDocument,
  renderText,
  signatureLabel,
} from '../src/engine';
import type { FileFacts, FolderKind, ProcessDetail, Scan, SignatureStatus } from '../src/engine';
import { clinicScan } from '../src/demo/clinic';
import { demoScan } from '../src/demo/sample';
import { guideById } from '../src/guides';

// Processi con firma e connessioni (come Process Explorer): giudizi «da
// controllare», Polaris escluso, firewall, processi non leggibili, privacy.

const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const file = (path: string, folder: FolderKind, status?: SignatureStatus, signer?: string): FileFacts => ({ path, folder, signature: status ? { status, signer } : undefined });
const proc = (pid: number, name: string, f?: FileFacts, extra: Partial<ProcessDetail> = {}): ProcessDetail => ({ pid, name, file: f, ...extra });
const withProcs = (items: ProcessDetail[], extra: Partial<NonNullable<Scan['pc']>['procs']> = {}, firewallOff = false): Scan => {
  const s = clone(demoScan);
  s.pc!.procs = { at: '2026-10-12T20:30:14Z', connsRead: true, items, ...extra };
  s.firewall = { source: 'registry', profiles: [{ name: 'private', enabled: !firewallOff, active: true }] };
  return s;
};
const find = (s: Scan, id: string) => analyze(s).findings.find((f) => f.id === id);
const chrome = file('C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', 'programFiles', 'valid', 'Google LLC');

describe('etichette', () => {
  it('firma, cartella, utente', () => {
    expect(signatureLabel({ status: 'valid', signer: 'Microsoft Windows', catalog: true })).toEqual({ text: 'Firma verificata · Microsoft Windows (catalogo di Windows)', tone: 'ok' });
    expect(signatureLabel({ status: 'unsigned' })).toEqual({ text: 'Nessuna firma digitale', tone: 'info' });
    expect(signatureLabel({ status: 'tampered' })).toEqual({ text: 'File modificato dopo la firma', tone: 'crit' });
    expect(signatureLabel({ status: 'revoked', signer: 'Acme' }).tone).toBe('crit');
    expect(signatureLabel({ status: 'distrusted' }).text).toBe('Firmatario bloccato su questo PC');
    for (const s of ['expired', 'untrustedRoot', 'wrongUsage', 'invalid'] as const) expect(signatureLabel({ status: s }).tone).toBe('warn');
    expect(signatureLabel({ status: 'policy' }).tone).toBe('info');
    expect(signatureLabel({ status: 'unreadable' }).tone).toBe('unknown');
    expect(signatureLabel({ status: 'unknown', code: '0x80092003' }).text).toBe('Firma da verificare (codice 0x80092003)');
    expect(signatureLabel(undefined)).toEqual({ text: 'Firma non verificata', tone: 'unknown' });
    expect(folderLabel('appData')).toBe('AppData dell\'utente');
    expect(folderLabel(undefined)).toBe('cartella non letta');
    expect(ownerLabel('self')).toBe('questo utente');
    expect(ownerLabel('system')).toBe('sistema');
    expect(ownerLabel(undefined)).toBe('non leggibile');
  });

  it('gravità del file: firma e cartella dell\'utente', () => {
    expect(fileSeverity(file('C:\\x.exe', 'programFiles', 'unsigned'))).toBe('info');
    expect(fileSeverity(file('%USERPROFILE%\\AppData\\x.exe', 'appData', 'unsigned'))).toBe('warn');
    expect(fileSeverity(file('E:\\x.exe', 'removable', 'unsigned'))).toBe('warn');
    expect(fileSeverity(file('C:\\x.exe', 'programFiles', 'expired'))).toBe('warn');
    expect(fileSeverity(file('C:\\x.exe', 'windows', 'tampered'))).toBe('crit');
    expect(fileSeverity(chrome)).toBe('ok');
    expect(fileSeverity(file('C:\\x.exe', 'other'))).toBe('unknown');
  });

  it('nomi dei programmi di Windows fuori posto', () => {
    expect(isLookalike(proc(1, 'svchost.exe', file('C:\\Windows\\System32\\svchost.exe', 'windows')))).toBe(false);
    expect(isLookalike(proc(1, 'svchost.exe', file('C:\\Windows\\SysWOW64\\svchost.exe', 'windows')))).toBe(false);
    expect(isLookalike(proc(1, 'explorer.exe', file('C:\\WINDOWS\\explorer.exe', 'windows')))).toBe(false);
    expect(isLookalike(proc(1, 'svchost.exe', file('%USERPROFILE%\\AppData\\Local\\Temp\\svchost.exe', 'temp')))).toBe(true);
    expect(isLookalike(proc(1, 'LSASS.EXE', file('C:\\Windows\\lsass.exe', 'windows')))).toBe(true);
    expect(isLookalike(proc(1, 'csrss.exe'))).toBe(false); // senza percorso non si giudica
    expect(isLookalike(proc(1, 'chrome.exe', chrome))).toBe(false);
  });
});

describe('giudizi sui processi', () => {
  it('firma alterata: critico; lo stesso file si giudica una volta', () => {
    const bad = file('C:\\Program Files\\Acme\\acme.exe', 'programFiles', 'tampered', 'Acme');
    const s = withProcs([proc(10, 'acme.exe', bad), proc(11, 'acme.exe', bad), proc(12, 'chrome.exe', chrome)]);
    expect(procGroups(s.pc!.procs!.items)).toHaveLength(2);
    const f = find(s, 'pc.procs.signature');
    expect(f).toMatchObject({ severity: 'crit', value: '1 programma da controllare su 2', actions: ['defender-scan-file', 'check-file-origin'] });
    expect(f?.verdict).toContain('acme.exe (2 processi): file modificato dopo la firma');
    expect(f?.verdict).not.toMatch(/virus|malware/i);
  });

  it('senza firma: avviso solo da una cartella dell\'utente', () => {
    const s = withProcs([proc(10, 'tool.exe', file('C:\\Program Files\\Tool\\tool.exe', 'programFiles', 'unsigned')), proc(12, 'chrome.exe', chrome)]);
    expect(find(s, 'pc.procs.signature')).toMatchObject({ severity: 'ok', value: '1 su 2 con firma verificata' });
    expect(find(s, 'pc.procs.signature')?.verdict).toContain('salvo 1 programma senza firma installato in cartelle protette');
    const u = withProcs([proc(10, 'tool.exe', file('%USERPROFILE%\\Downloads\\tool.exe', 'downloads', 'unsigned'))]);
    expect(find(u, 'pc.procs.signature')?.severity).toBe('warn');
  });

  it('STARNET Polaris e la sua finestra sono esclusi', () => {
    const me = file('%USERPROFILE%\\Downloads\\STARNET-Polaris.exe', 'downloads', 'unsigned');
    const s = withProcs([proc(10, 'STARNET-Polaris.exe', me, { polaris: true, listen: [{ proto: 'tcp', port: 8737, scope: 'all' }] }), proc(12, 'chrome.exe', chrome)]);
    expect(find(s, 'pc.procs.signature')?.severity).toBe('ok');
    expect(find(s, 'pc.procs.listen')?.severity).toBe('ok');
  });

  it('in ascolto su tutte le reti: avviso, critico con il firewall spento', () => {
    const share = file('%USERPROFILE%\\AppData\\Roaming\\Share\\share.exe', 'appData', 'unsigned');
    const items = [
      proc(4, 'System', undefined, { listen: [{ proto: 'tcp', port: 445, scope: 'all' }] }),
      proc(20, 'share.exe', share, { listen: [{ proto: 'tcp', port: 8200, scope: 'all' }, { proto: 'tcp', port: 8200, scope: 'all', ipv6: true }] }),
      proc(21, 'chrome.exe', chrome, { listen: [{ proto: 'tcp', port: 9222, scope: 'all' }] }),
    ];
    expect(listeners(withProcs(items)).map((l) => [l.proc.name, l.ports, l.risky])).toEqual([
      ['System', [445], false],
      ['share.exe', [8200], true],
      ['chrome.exe', [9222], false],
    ]);
    const warn = find(withProcs(items), 'pc.procs.listen');
    expect(warn).toMatchObject({ severity: 'warn', value: '1 programma da controllare', actions: ['review-listening-app', 'check-file-origin'] });
    expect(warn?.verdict).toContain('Polaris non legge le singole regole');
    const crit = find(withProcs(items, {}, true), 'pc.procs.listen');
    expect(crit).toMatchObject({ severity: 'crit', value: '1 programma da controllare, firewall spento' });
    expect(crit?.actions[0]).toBe('enable-firewall');
  });

  it('UDP, ascolto locale e tabelle non lette non si giudicano', () => {
    const share = file('%USERPROFILE%\\AppData\\share.exe', 'appData', 'unsigned');
    const items = [proc(20, 'share.exe', share, { listen: [{ proto: 'udp', port: 1900, scope: 'all' }, { proto: 'tcp', port: 9000, scope: 'local' }] })];
    expect(find(withProcs(items), 'pc.procs.listen')).toMatchObject({ severity: 'ok', value: 'nessun programma in ascolto su tutte le reti' });
    expect(find(withProcs(items, { connsRead: false }), 'pc.procs.listen')).toBeUndefined();
  });

  it('programma con il nome di un file di Windows altrove', () => {
    const s = withProcs([proc(30, 'svchost.exe', file('%USERPROFILE%\\AppData\\Local\\Temp\\svchost.exe', 'temp', 'unsigned'))]);
    const f = find(s, 'pc.procs.lookalike');
    expect(f).toMatchObject({ severity: 'warn', value: '1 processo fuori posto', actions: ['defender-scan-file', 'check-file-origin'] });
    expect(find(withProcs([proc(12, 'chrome.exe', chrome)]), 'pc.procs.lookalike')).toBeUndefined();
  });

  it('processi non leggibili senza amministratore: mai «in regola»', () => {
    expect(find(withProcs([proc(12, 'chrome.exe', chrome)], { unreadable: 6 }), 'pc.procs.unreadable')).toMatchObject({ severity: 'info', value: '6 processi non leggibili senza amministratore' });
    expect(find(withProcs([proc(12, 'chrome.exe', chrome)], { unreadable: 4 }), 'pc.procs.unreadable')).toBeUndefined();
    expect(find(withProcs([proc(12, 'chrome.exe', chrome)], { unreadable: 9, elevated: true }), 'pc.procs.unreadable')).toBeUndefined();
  });
});

describe('demo, rapporto, documento e privacy', () => {
  it('casa: server senza firma in ascolto con il firewall spento; clinica: gateway PACS', () => {
    expect(find(demoScan, 'pc.procs.listen')?.severity).toBe('crit');
    expect(find(demoScan, 'pc.procs.signature')?.severity).toBe('warn');
    expect(find(demoScan, 'pc.procs.unreadable')?.severity).toBe('info');
    expect(find(clinicScan, 'pc.procs.listen')?.severity).toBe('warn');
    expect(find(clinicScan, 'pc.procs.listen')?.verdict).toContain('pacsgw.exe (porta 104');
    expect(find(clinicScan, 'pc.procs.signature')?.severity).toBe('ok');
  });

  it('nei dati delle demo nessun nome utente né indirizzo remoto', () => {
    for (const s of [demoScan, clinicScan]) {
      // Le versioni dei file ("5.2.0.14") hanno la forma di un indirizzo: si tolgono prima.
      const json = JSON.stringify([s.pc!.procs, s.pc!.autoruns], (k, v) => (k === 'version' ? undefined : v));
      expect(json).not.toMatch(/C:\\\\Users\\\\/i);
      expect(json).not.toMatch(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/);
      expect(json).not.toMatch(/S-1-5-21/);
    }
  });

  it('rapporto entro 90 colonne e documento senza IP pubblici né IPv6 globali', () => {
    for (const s of [demoScan, clinicScan]) {
      const txt = renderText(s, analyze(s), { verbose: true });
      expect(txt).toContain(' Processi (');
      expect(txt).toContain('In ascolto su tutte le reti:');
      for (const line of txt.split('\n')) expect(line.length).toBeLessThanOrEqual(90);
    }
    const doc = documentParts(demoScan, analyze(demoScan)).body;
    expect(doc).toContain('<h2>Processi e avvio automatico</h2>');
    expect(doc).toContain('acmeshare.exe (8200) <b>da controllare</b>');
    expect(doc).toContain('gli indirizzi remoti non sono registrati');
    // Il filtro del documento toglie gli IPv6 globali e lascia orari, link-local e loopback.
    const s = clone(demoScan);
    s.pc!.hardware!.vendor = 'Acme 2001:db8:85a3::8a2e:370:7334 2a00:1450:4002:0809:0000:0000:0000:200e fe80::1c2d:3e4f ::1 10:30:45';
    const body = documentParts(s, analyze(s)).body;
    expect(body).not.toContain('2001:db8');
    expect(body).not.toContain('2a00:1450');
    expect(body).toContain('[IP pubblico] [IP pubblico] fe80::1c2d:3e4f ::1 10:30:45');
  });

  it('knowledge base, azioni e guida', () => {
    for (const id of ['pc.procs.signature', 'pc.procs.listen', 'pc.procs.lookalike', 'pc.procs.unreadable']) {
      expect(METRICS[id], id).toBeDefined();
      expect(guideById('processi-firme')?.metrics).toContain(id);
    }
    expect(METRICS['pc.procs.signature'].limits).toContain('revoca');
    for (const id of ['check-file-origin', 'defender-scan-file', 'review-listening-app']) expect(ACTIONS[id], id).toBeDefined();
    // Niente servizi esterni a cui caricare i file: al più si cerca il nome.
    expect(ACTIONS['check-file-origin'].steps.join(' ')).not.toMatch(/virustotal/i);
  });

  it('il motore della riga di comando (ES2015, goja) dà gli stessi giudizi sulla clinica', async () => {
    const entry = fileURLToPath(new URL('../src/engine/global.ts', import.meta.url));
    const out = await build({ entryPoints: [entry], bundle: true, format: 'iife', target: 'es2015', write: false });
    const code = out.outputFiles[0].text;
    expect(code).not.toMatch(/\basync\b|\bawait\b/);
    expect(code).not.toMatch(/[\w)\]]\s*\?\?\s*[\w("'[]/);
    expect(code).not.toMatch(/[\w)\]]\?\.[\w([]/);
    expect(code).not.toContain('toLocaleString');
    expect(code).not.toContain('(?<'); // niente lookbehind
    const ctx: Record<string, unknown> = {};
    ctx.globalThis = ctx;
    vm.createContext(ctx);
    vm.runInContext(code, ctx);
    const engine = ctx.PolarisEngine as { analyzeJson(s: string): string; reportHtml(s: string, v: string, g: string): string };
    const json = JSON.stringify(clinicScan);
    expect(JSON.parse(engine.analyzeJson(json))).toEqual(JSON.parse(JSON.stringify(analyze(clinicScan))));
    expect(engine.reportHtml(json, '0.14.0', 'oggi')).toBe(renderDocument(clinicScan, analyze(clinicScan), { version: '0.14.0', generated: 'oggi' }));
  });
});
