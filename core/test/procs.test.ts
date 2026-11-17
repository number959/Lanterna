import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { describe, expect, it } from 'vitest';
import {
  ACTIONS,
  analyze,
  documentParts,
  fileSeverity,
  folderLabel,
  isKernelProc,
  isLookalike,
  listeners,
  METRICS,
  ownerLabel,
  procGroups,
  protectedFolder,
  renderDocument,
  renderText,
  signatureLabel,
  userWritable,
} from '../src/engine';
import type { FileFacts, FolderKind, Listener, ProcessDetail, Scan, SignatureStatus } from '../src/engine';
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

  it('cartelle: protette solo Windows e Programmi, le altre scrivibili come sign.UserWritable dell\'agente (decisione 1)', () => {
    const all: FolderKind[] = ['windows', 'programFiles', 'programData', 'appData', 'temp', 'downloads', 'profile', 'removable', 'network', 'other'];
    for (const k of all) expect(userWritable(k), k).toBe(!protectedFolder(k));
    expect(all.filter((k) => protectedFolder(k))).toEqual(['windows', 'programFiles']);
    const go = readFileSync(fileURLToPath(new URL('../../windows/internal/sign/sign.go', import.meta.url)), 'utf8');
    const fn = /func UserWritable\(folder string\) bool \{\s*switch folder \{\s*case ([^:]+):/.exec(go);
    expect(fn, 'sign.UserWritable in sign.go').not.toBeNull();
    const goSet = (fn![1].match(/"([^"]+)"/g) || []).map((x) => x.slice(1, -1));
    expect(all.filter((k) => userWritable(k)).sort()).toEqual(goSet.sort());
    expect(userWritable(undefined)).toBe(false);
    expect(protectedFolder(undefined)).toBe(false);
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

  it('senza firma: avviso solo da una cartella che un utente può scrivere', () => {
    const s = withProcs([proc(10, 'tool.exe', file('C:\\Program Files\\Tool\\tool.exe', 'programFiles', 'unsigned')), proc(12, 'chrome.exe', chrome)]);
    expect(find(s, 'pc.procs.signature')).toMatchObject({ severity: 'ok', value: '1 su 2 con firma verificata' });
    expect(find(s, 'pc.procs.signature')?.verdict).toBe(
      '1 programma su 2 ha una firma digitale valida; 1 programma senza firma è installato in Programmi o nella cartella di Windows, dove scrive solo l\'amministratore.',
    );
    const u = withProcs([proc(10, 'tool.exe', file('%USERPROFILE%\\Downloads\\tool.exe', 'downloads', 'unsigned'))]);
    expect(find(u, 'pc.procs.signature')?.severity).toBe('warn');
  });

  it('ProgramData e le cartelle fuori da Programmi e Windows non sono «protette»', () => {
    // C:\ProgramData: BUILTIN\Users crea file e cartelle; C:\Tools: Authenticated Users può modificare.
    expect(fileSeverity(file('C:\\ProgramData\\xyz\\evil.exe', 'programData', 'unsigned'))).toBe('warn');
    expect(fileSeverity(file('C:\\Tools\\nc.exe', 'other', 'unsigned'))).toBe('warn');
    expect(fileSeverity(file('C:\\Windows\\x.exe', 'windows', 'unsigned'))).toBe('info');
    const s = withProcs([
      proc(10, 'evil.exe', file('C:\\ProgramData\\xyz\\evil.exe', 'programData', 'unsigned')),
      proc(11, 'httpd.exe', file('C:\\xampp\\apache\\bin\\httpd.exe', 'other', 'unsigned')),
      proc(12, 'chrome.exe', chrome),
    ]);
    const f = find(s, 'pc.procs.signature');
    expect(f).toMatchObject({ severity: 'warn', value: '2 programmi da controllare su 3' });
    expect(f?.verdict).not.toContain('cartelle protette');
    expect(f?.verdict).toContain('ProgramData');
  });

  it('il verdetto senza problemi segue i conteggi: firme «policy», nessuna firma verificata', () => {
    // Firma non attendibile per le impostazioni del PC: informazione, mai «firma valida».
    const pol = withProcs([proc(10, 'acme.exe', file('C:\\Program Files\\Acme\\acme.exe', 'programFiles', 'policy')), proc(12, 'chrome.exe', chrome)]);
    const f = find(pol, 'pc.procs.signature');
    expect(f).toMatchObject({ severity: 'info', value: '1 su 2 con firma verificata', actions: ['check-file-origin'] });
    expect(f?.verdict).toContain('1 programma non è attendibile per le impostazioni di questo PC');
    expect(f?.verdict).not.toContain('I programmi in esecuzione hanno una firma digitale valida');
    // Nessuna firma verificata e nessun file da controllare: non si sa.
    const none = withProcs([proc(10, 'a.exe', file('C:\\Program Files\\A\\a.exe', 'programFiles', 'unreadable')), proc(11, 'b.exe', file('C:\\Program Files\\B\\b.exe', 'programFiles', 'unknown'))]);
    expect(find(none, 'pc.procs.signature')).toMatchObject({ severity: 'unknown', value: '0 su 2 con firma verificata' });
    expect(find(none, 'pc.procs.signature')?.verdict).not.toMatch(/firma digitale valida\./);
    // Tutti con firma valida.
    expect(find(withProcs([proc(12, 'chrome.exe', chrome)]), 'pc.procs.signature')?.verdict).toBe('I programmi in esecuzione hanno una firma digitale valida.');
  });

  it('lo stesso percorso ripulito con esiti diversi resta in due gruppi (più utenti sullo stesso PC)', () => {
    // C:\Users\a\... e C:\Users\b\... diventano lo stesso percorso ripulito.
    const path = 'C:\\Users\\‹utente›\\AppData\\Local\\Programs\\App\\app.exe';
    const s = withProcs([proc(10, 'app.exe', file(path, 'appData', 'valid', 'Acme')), proc(11, 'app.exe', file(path, 'appData', 'tampered', 'Acme')), proc(12, 'app.exe', file(path, 'appData', 'valid', 'Acme'))]);
    expect(procGroups(s.pc!.procs!.items).map((g) => [g.file.signature!.status, g.count])).toEqual([
      ['valid', 2],
      ['tampered', 1],
    ]);
    expect(find(s, 'pc.procs.signature')).toMatchObject({ severity: 'crit', value: '1 programma da controllare su 2' });
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

  it('in ascolto senza verifica (processo non apribile, firma non verificata): mai «firmati», informazione', () => {
    const items = [
      proc(4, 'System', undefined, { listen: [{ proto: 'tcp', port: 445, scope: 'all' }] }),
      // Servizio di un altro account: senza amministratore non si apre (l'agente non mette il file).
      proc(30, 'vncserver.exe', undefined, { access: 'none', owner: 'unknown', listen: [{ proto: 'tcp', port: 5900, scope: 'all' }] }),
      // Verifica della firma non finita in tempo: il file c'è, la firma no.
      proc(31, 'agent.exe', file('C:\\Program Files\\Acme\\agent.exe', 'programFiles'), { listen: [{ proto: 'tcp', port: 8080, scope: 'all' }] }),
      proc(32, 'svc.exe', file('C:\\Program Files\\Acme\\svc.exe', 'programFiles', 'unreadable'), { listen: [{ proto: 'tcp', port: 7000, scope: 'all' }] }),
      proc(21, 'chrome.exe', chrome, { listen: [{ proto: 'tcp', port: 9222, scope: 'all' }] }),
    ];
    expect(listeners(withProcs(items)).map((l) => [l.proc.name, l.risky, l.unverified, l.kernel])).toEqual([
      ['System', false, false, true],
      ['vncserver.exe', false, true, false],
      ['agent.exe', false, true, false],
      ['svc.exe', false, true, false],
      ['chrome.exe', false, false, false],
    ]);
    const f = find(withProcs(items), 'pc.procs.listen');
    expect(f).toMatchObject({ severity: 'info', value: '5 programmi in ascolto, 3 non verificati', actions: [] });
    expect(f?.verdict).toContain('3 programmi che non si sono potuti verificare');
    expect(f?.verdict).toContain('vncserver.exe (porta 5900)');
    expect(f?.verdict).toContain('1 programma in ascolto su tutte le reti ha una firma valida e sta in Programmi o nella cartella di Windows');
    expect(f?.verdict).toContain('System, il nucleo di Windows (porta 445), non ha un file da verificare');
    expect(f?.verdict).not.toMatch(/sono firmati|cartelle protette/);
    // Con uno da controllare, i non verificati si dicono a parte.
    const share = proc(20, 'share.exe', file('%USERPROFILE%\\AppData\\share.exe', 'appData', 'unsigned'), { listen: [{ proto: 'tcp', port: 8200, scope: 'all' }] });
    const w = find(withProcs([...items, share]), 'pc.procs.listen');
    expect(w?.severity).toBe('warn');
    expect(w?.verdict).toContain('Altri 3 programmi in ascolto non si sono potuti verificare');
    // Solo programmi verificati: a posto, senza parlare di cartelle protette.
    const ok = find(withProcs([items[0], items[4]]), 'pc.procs.listen');
    expect(ok).toMatchObject({ severity: 'ok', value: '2 programmi in ascolto, nessuno da controllare' });
  });

  it('nucleo di Windows con la regola dell\'agente: il nome da solo non basta; da amministratore niente «senza amministratore»', () => {
    // Un processo non letto in tempo che si chiama «Idle» o «Registry» ma non è figlio di System non è il nucleo (kernelPseudo dell'agente).
    const items = [
      proc(5000, 'Idle', undefined, { parentPid: 700, listen: [{ proto: 'tcp', port: 4444, scope: 'all' }] }),
      proc(5001, 'Registry', undefined, { parentPid: 700, listen: [{ proto: 'tcp', port: 4445, scope: 'all' }] }),
      proc(120, 'Registry', undefined, { parentPid: 4 }),
    ];
    expect(listeners(withProcs(items)).map((l) => [l.proc.name, l.kernel, l.unverified])).toEqual([
      ['Idle', false, true],
      ['Registry', false, true],
    ]);
    expect(isKernelProc(items[2])).toBe(true);
    expect(isKernelProc(items[1])).toBe(false);
    const f = find(withProcs(items), 'pc.procs.listen');
    expect(f).toMatchObject({ severity: 'info', value: '2 programmi in ascolto, 2 non verificati' });
    expect(f?.verdict).not.toContain('nucleo di Windows');
    // Da amministratore i processi che non si aprono sono protetti da Windows: «senza amministratore» sarebbe falso.
    const closed = proc(30, 'vncserver.exe', undefined, { access: 'none', owner: 'unknown', listen: [{ proto: 'tcp', port: 5900, scope: 'all' }] });
    const admin = find(withProcs([closed], { elevated: true }), 'pc.procs.listen');
    expect(admin?.severity).toBe('info');
    expect(admin?.verdict).toContain('protetti da Windows');
    expect(admin?.verdict).not.toMatch(/senza amministratore|avviando Polaris come amministratore/);
    expect(find(withProcs([closed]), 'pc.procs.listen')?.verdict).toContain('avviando Polaris come amministratore');
  });

  it('in ascolto da ProgramData o da un\'altra cartella: da controllare anche con la firma valida', () => {
    const svc = proc(40, 'vendorsvc.exe', file('C:\\ProgramData\\Vendor\\vendorsvc.exe', 'programData', 'valid', 'Vendor'), { listen: [{ proto: 'tcp', port: 7070, scope: 'all' }] });
    expect(listeners(withProcs([svc]))[0].risky).toBe(true);
    expect(find(withProcs([svc]), 'pc.procs.listen')?.severity).toBe('warn');
  });

  it('UDP, ascolto locale e tabelle non lette non si giudicano', () => {
    const share = file('%USERPROFILE%\\AppData\\share.exe', 'appData', 'unsigned');
    const items = [proc(20, 'share.exe', share, { listen: [{ proto: 'udp', port: 1900, scope: 'all' }, { proto: 'tcp', port: 9000, scope: 'local' }] })];
    expect(find(withProcs(items), 'pc.procs.listen')).toMatchObject({ severity: 'ok', value: 'nessun programma in ascolto su tutte le reti' });
    expect(find(withProcs(items, { connsRead: false }), 'pc.procs.listen')).toBeUndefined();
    // Nel rapporto le tabelle non lette (connsRead assente nel JSON) si dicono «non lette», mai «nessun programma».
    const unread = withProcs(items);
    delete unread.pc!.procs!.connsRead;
    const txt = renderText(unread, analyze(unread));
    expect(txt).toContain('In ascolto su tutte le reti: non letto');
    expect(txt).not.toContain('In ascolto su tutte le reti: nessun programma');
    // Lo stesso nel documento.
    const body = documentParts(unread, analyze(unread)).body;
    expect(body).toContain('In ascolto su tutte le reti: non letto');
    expect(body).not.toContain('In ascolto su tutte le reti: nessun programma');
    expect(documentParts(withProcs(items), analyze(withProcs(items))).body).toContain('In ascolto su tutte le reti: nessun programma');
  });

  it('documento: i programmi in ascolto non verificati si dicono, come nel rapporto', () => {
    const closed = proc(30, 'vncserver.exe', undefined, { access: 'none', owner: 'unknown', listen: [{ proto: 'tcp', port: 5900, scope: 'all' }] });
    const share = proc(20, 'share.exe', file('%USERPROFILE%\\AppData\\share.exe', 'appData', 'unsigned'), { listen: [{ proto: 'tcp', port: 8200, scope: 'all' }] });
    const signed = proc(40, 'chrome.exe', chrome, { listen: [{ proto: 'tcp', port: 9222, scope: 'all' }] });
    const s = withProcs([closed, share, signed]);
    const ls: Listener[] = listeners(s);
    expect(ls.map((l) => [l.proc.name, l.risky, l.unverified])).toEqual([
      ['vncserver.exe', false, true],
      ['share.exe', true, false],
      ['chrome.exe', false, false],
    ]);
    const body = documentParts(s, analyze(s)).body;
    expect(body).toContain('vncserver.exe (5900) non verificato; share.exe (8200) <b>da controllare</b>; chrome.exe (9222).');
    expect(renderText(s, analyze(s)).replace(/\s+/g, ' ')).toContain('vncserver.exe (5900) non verificato; share.exe (8200) da controllare; chrome.exe (9222)');
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

  it('rapporto e documento: da amministratore i processi non apribili sono protetti da Windows (decisione 5)', () => {
    const user = withProcs([proc(12, 'chrome.exe', chrome)], { unreadable: 6 });
    const admin = withProcs([proc(12, 'chrome.exe', chrome)], { unreadable: 6, elevated: true });
    const one = withProcs([proc(12, 'chrome.exe', chrome)], { unreadable: 1, elevated: true });
    const doc = (s: Scan) => documentParts(s, analyze(s)).body;
    const txt = (s: Scan) => renderText(s, analyze(s)).replace(/\s+/g, ' ');
    expect(doc(user)).toContain('6 processi non leggibili senza amministratore.');
    expect(doc(admin)).toContain('6 processi non leggibili, protetti da Windows.');
    expect(doc(admin)).not.toContain('senza amministratore');
    expect(doc(one)).toContain('1 processo non leggibile, protetto da Windows.');
    expect(txt(user)).toContain('6 processi non leggibili senza amministratore');
    expect(txt(admin)).toContain('6 processi non leggibili, protetti da Windows');
    expect(txt(one)).toContain('1 processo non leggibile, protetto da Windows');
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
    // Un percorso dello Store più lungo della riga: va spezzato, non sforato.
    const long = clone(clinicScan);
    long.pc!.procs!.items.push(
      proc(9100, 'WindowsTerminal.exe', file('C:\\Program Files\\WindowsApps\\Microsoft.WindowsTerminal_1.21.2361.0_x64__8wekyb3d8bbwe\\WindowsTerminal.exe', 'programFiles', 'unsigned')),
    );
    for (const s of [demoScan, clinicScan, long]) {
      const txt = renderText(s, analyze(s), { verbose: true });
      expect(txt).toContain(' Processi (');
      expect(txt).toContain('In ascolto su tutte le reti:');
      for (const line of txt.split('\n')) expect(line.length).toBeLessThanOrEqual(90);
    }
    expect(renderText(long, analyze(long), { verbose: true })).toContain('WindowsTerminal.exe');
    // Un percorso lungo più righe le riempie fino in fondo: niente righe di due caratteri né spazi dentro il percorso.
    const deep = clone(clinicScan);
    const path = 'C:\\Program Files\\WindowsApps\\' + 'Microsoft.WindowsTerminal_1.21.2361.0_x64__8wekyb3d8bbwe\\'.repeat(4) + 'WindowsTerminal.exe';
    deep.pc!.procs!.items.push(proc(9100, 'WindowsTerminal.exe', file(path, 'programFiles', 'unsigned')));
    const lines = renderText(deep, analyze(deep), { verbose: true, width: 90 }).split('\n');
    const at = lines.findIndex((l) => l.startsWith('     WindowsTerminal.exe: '));
    const cont: string[] = [];
    for (let i = at + 1; i < lines.length && /^ {7}\S/.test(lines[i]); i++) cont.push(lines[i]);
    expect(cont.length).toBeGreaterThan(2);
    for (const l of cont.slice(0, -1)) expect(l.length, l).toBe(90);
    expect(lines[at].endsWith('C:\\Program') && cont.map((l) => l.trim()).join('')).toBe(path.slice('C:\\Program '.length));
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
    // La guida dice la stessa gravità del giudizio: un nome di Windows fuori posto è «da controllare» (avviso).
    const guide = JSON.stringify(guideById('processi-firme')!.blocks);
    expect(guide).toContain('Polaris lo segnala come da controllare.');
    expect(guide).not.toContain('da controllare subito.');
    expect(guide).toContain('ProgramData');
    // La riga di comando elenca i comandi della 0.14.0.
    const cli = JSON.stringify(guideById('riga-di-comando')!.blocks);
    for (const c of ['polaris-cli procs [--json]', 'polaris-cli autoruns [--json]', 'polaris-cli win11 [--json]']) expect(cli, c).toContain(c);
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
