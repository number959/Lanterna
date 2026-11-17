import { describe, expect, it } from 'vitest';
import {
  ACTIONS,
  analyze,
  AUTORUN_CATEGORIES,
  autorunCounts,
  autorunIssues,
  categoryLabel,
  categoryLower,
  categoryShort,
  consumerLabel,
  entryFile,
  interpretedInline,
  METRICS,
  renderText,
  sourceLabel,
  startLabel,
  triggerLabel,
} from '../src/engine';
import type { AutorunEntry, FileFacts, FolderKind, Scan, SignatureStatus } from '../src/engine';
import { bootExecuteKind, isDefaultShell, isDefaultUserinit } from '../src/engine/autoruns';
import { clinicScan } from '../src/demo/clinic';
import { demoScan } from '../src/demo/sample';
import { guideById } from '../src/guides';

// Avvio automatico esteso (come Autoruns): file mancanti, firme e cartelle,
// dirottamenti noti, WMI, estensioni, percorsi senza virgolette, attività
// pianificate; le categorie lette solo in parte restano da verificare.

const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const ms = (path: string): FileFacts => ({ path, folder: 'windows', signature: { status: 'valid', signer: 'Microsoft Windows', catalog: true, microsoft: true } });
const file = (path: string, folder: FolderKind, status?: SignatureStatus, signer?: string, extra: Partial<FileFacts> = {}): FileFacts => ({ path, folder, signature: status ? { status, signer } : undefined, ...extra });
const entry = (category: AutorunEntry['category'], name: string, f?: FileFacts, extra: Partial<AutorunEntry> = {}): AutorunEntry => ({ category, name, file: f, enabled: true, ...extra });
const withAutoruns = (entries: AutorunEntry[], extra: Partial<NonNullable<Scan['pc']>['autoruns']> = {}, domain?: string): Scan => {
  const s = clone(demoScan);
  s.pc!.autoruns = { entries, ...extra };
  if (domain) s.agent.domain = domain;
  return s;
};
const issues = (entries: AutorunEntry[], extra?: Partial<NonNullable<Scan['pc']>['autoruns']>, domain?: string) =>
  autorunIssues(withAutoruns(entries, extra, domain)).map((x) => [x.entry.name, x.kind, x.severity]);
const find = (s: Scan, id: string) => analyze(s).findings.find((f) => f.id === id);
const appData = (n: string) => `%USERPROFILE%\\AppData\\Local\\${n}`;

describe('etichette in italiano', () => {
  it('categorie, attivazioni, avvio, origine, consumer', () => {
    for (const c of AUTORUN_CATEGORIES) {
      expect(categoryLabel(c).length, c).toBeGreaterThan(3);
      expect(categoryShort(c).length, c).toBeGreaterThan(3);
    }
    expect(categoryLower('tasks')).toBe('attività pianificate');
    expect(categoryLower('winlogon')).toBe('Winlogon');
    for (const t of ['logon', 'boot', 'time', 'daily', 'weekly', 'monthly', 'idle', 'event', 'registration', 'session', 'other'] as const) expect(triggerLabel(t).length).toBeGreaterThan(2);
    expect(startLabel('delayed')).toBe('automatico ritardato');
    expect(startLabel(undefined)).toBe('');
    expect(sourceLabel('policy')).toBe('imposta da criteri');
    expect(sourceLabel('unpacked')).toBe('caricata in modalità sviluppatore');
    expect(consumerLabel('commandline')).toBe('esegue un comando');
  });

  it('il file che conta: quello eseguito dal programma di Windows', () => {
    const dll = file('%USERPROFILE%\\AppData\\Roaming\\x.dll', 'appData', 'unsigned');
    const e = entry('logon', 'x', ms('C:\\Windows\\System32\\rundll32.exe'), { target: dll });
    expect(entryFile(e)).toBe(dll);
    expect(interpretedInline(e)).toBe(false);
    expect(interpretedInline(entry('logon', 'y', ms('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe')))).toBe(true);
  });
});

describe('voci da guardare', () => {
  it('file mancanti: informazione, avviso per servizi automatici e driver d\'avvio', () => {
    const gone = file('C:\\Program Files\\Old\\old.exe', 'programFiles', undefined, undefined, { missing: true });
    expect(
      issues([
        entry('logon', 'Old', gone),
        entry('services', 'OldSvc', gone, { start: 'auto' }),
        entry('services', 'OldManual', gone, { start: 'manual' }),
        entry('drivers', 'olddrv', gone, { start: 'boot' }),
        entry('browser', 'Ext', gone, { source: 'store' }),
      ]),
    ).toEqual([
      ['Old', 'missing', 'info'],
      ['OldSvc', 'missing', 'warn'],
      ['OldManual', 'missing', 'info'],
      ['olddrv', 'missing', 'warn'],
      ['Ext', 'extensions', 'info'],
    ]);
    const x32 = autorunIssues(withAutoruns([entry('logon', 'Old32', gone, { scope: 'machine32' })]))[0];
    expect(x32.why).toContain('Program Files (x86)');
  });

  it('firme e cartelle per accesso, servizi e driver', () => {
    expect(
      issues([
        entry('logon', 'Unsigned', file(appData('u.exe'), 'appData', 'unsigned')),
        entry('logon', 'UnsignedOff', file(appData('u.exe'), 'appData', 'unsigned'), { enabled: false }),
        entry('logon', 'Signed', file(appData('s.exe'), 'appData', 'valid', 'Acme')),
        entry('logon', 'Expired', file('C:\\Program Files\\e.exe', 'programFiles', 'expired', 'Acme')),
        entry('logon', 'Tampered', file('C:\\Program Files\\t.exe', 'programFiles', 'tampered'), { enabled: false }),
        entry('services', 'SvcUser', file(appData('svc.exe'), 'appData', 'unsigned'), { account: 'system', start: 'auto' }),
        entry('services', 'SvcSigned', file(appData('svc2.exe'), 'appData', 'valid', 'Acme'), { account: 'system', start: 'auto' }),
        entry('logon', 'Defender', ms('C:\\Windows\\System32\\SecurityHealthSystray.exe')),
        entry('logon', 'Script', ms('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'), { command: 'powershell -w hidden -c "..."' }),
        entry('logon', 'Rundll', ms('C:\\Windows\\System32\\rundll32.exe'), { target: file('%USERPROFILE%\\AppData\\Local\\Temp\\x.dll', 'temp', 'unsigned') }),
      ]),
    ).toEqual([
      ['Unsigned', 'unsigned', 'warn'],
      ['Expired', 'unsigned', 'warn'],
      ['Tampered', 'unsigned', 'crit'],
      ['SvcUser', 'unsigned', 'crit'],
      ['SvcSigned', 'unsigned', 'warn'],
      ['Script', 'unsigned', 'info'],
      ['Rundll', 'unsigned', 'warn'],
    ]);
  });

  it('dirottamenti noti: Shell, Userinit, IFEO, BootExecute, AppInit, LSA e stampa', () => {
    // Shell e Userinit come li scrive l'agente: una voce per ogni programma dell'elenco.
    const s = withAutoruns([
      entry('winlogon', 'Shell', undefined, { kind: 'shell', command: 'explorer.exe' }),
      entry('winlogon', 'ShellPath', undefined, { kind: 'shell', command: '"C:\\Windows\\explorer.exe"' }),
      entry('winlogon', 'ShellSosia', file('%USERPROFILE%\\AppData\\Roaming\\explorer.exe', 'appData', 'unsigned'), { kind: 'shell', command: '%USERPROFILE%\\AppData\\Roaming\\explorer.exe' }),
      entry('winlogon', 'ShellArgs', ms('C:\\Windows\\explorer.exe'), { kind: 'shell', command: 'explorer.exe /factory' }),
      entry('winlogon', 'Userinit', undefined, { kind: 'userinit', command: 'C:\\Windows\\system32\\userinit.exe' }),
      entry('winlogon', 'UserinitSosia', file('C:\\Users\\Public\\userinit.exe', 'other', 'unsigned'), { kind: 'userinit', command: 'C:\\Users\\Public\\userinit.exe' }),
      entry('hijacks', 'sethc.exe', file('C:\\Tools\\cmd.exe', 'other', 'unsigned'), { kind: 'ifeo' }),
      entry('hijacks', 'taskmgr.exe', { path: 'C:\\Tools\\procexp64.exe', folder: 'other', signature: { status: 'valid', signer: 'Microsoft Corporation', microsoft: true } }, { kind: 'ifeo' }),
      entry('hijacks', 'BootExecute', undefined, { kind: 'bootexecute', command: 'autocheck  autochk *' }),
      entry('hijacks', 'BootExecute2', undefined, { kind: 'bootexecute', command: 'autocheck autochk * acmedefrag' }),
      entry('hijacks', 'AppInit', file('C:\\Windows\\x.dll', 'windows', 'unsigned'), { kind: 'appinit', command: 'C:\\Windows\\x.dll' }),
      entry('lsa', 'acmepw', file('C:\\Windows\\System32\\acmepw.dll', 'windows', 'unsigned'), { kind: 'lsa-notify' }),
      entry('print', 'Acme Port', file('C:\\Windows\\System32\\acmepm.dll', 'windows', 'valid', 'Acme Printing'), { kind: 'printmon' }),
      entry('network', 'msnp', ms('C:\\Windows\\System32\\ntlanman.dll'), { kind: 'netprovider' }),
    ]);
    s.pc!.hardware!.secureBoot = false;
    expect(autorunIssues(s).map((x) => [x.entry.name, x.severity])).toEqual([
      ['ShellSosia', 'crit'],
      ['ShellArgs', 'crit'],
      ['UserinitSosia', 'crit'],
      ['sethc.exe', 'crit'],
      ['taskmgr.exe', 'info'],
      ['BootExecute2', 'warn'],
      ['AppInit', 'warn'],
      ['acmepw', 'warn'],
      ['Acme Port', 'info'],
    ]);
    // Con Secure Boot attivo AppInit è ignorato da Windows.
    s.pc!.hardware!.secureBoot = true;
    expect(autorunIssues(s).find((x) => x.entry.name === 'AppInit')?.severity).toBe('info');
    const f = find(s, 'pc.autoruns.hijack');
    expect(f).toMatchObject({ severity: 'crit', actions: ['review-startup-entry', 'defender-scan-file'] });
    expect(f?.verdict).not.toMatch(/virus|malware/i);
  });

  it('sottoscrizioni WMI: comando collegato grave, il consumer di Windows escluso', () => {
    expect(
      issues([
        entry('wmi', 'Run', undefined, { consumer: 'commandline', bound: true }),
        entry('wmi', 'Orphan', undefined, { consumer: 'activescript', bound: false }),
        entry('wmi', 'SCM Event Log Consumer', undefined, { consumer: 'eventlog', bound: true }),
        entry('wmi', 'AcmeLog', undefined, { consumer: 'logfile', bound: true }),
      ]),
    ).toEqual([
      ['Run', 'wmi', 'crit'],
      ['Orphan', 'wmi', 'info'],
      ['AcmeLog', 'wmi', 'info'],
    ]);
  });

  it('estensioni: criteri su un PC non gestito, modalità sviluppatore, store', () => {
    const list = [
      entry('browser', 'Forced', undefined, { browser: 'chrome', source: 'policy', allSites: true }),
      entry('browser', 'Dev', undefined, { browser: 'edge', source: 'unpacked' }),
      entry('browser', 'Ext', undefined, { browser: 'chrome', source: 'external', allSites: true }),
      entry('browser', 'Store', undefined, { browser: 'firefox', source: 'store', allSites: true }),
      entry('browser', 'Inside', undefined, { browser: 'chrome', source: 'component' }),
    ];
    expect(issues(list)).toEqual([
      ['Forced', 'extensions', 'warn'],
      ['Dev', 'extensions', 'warn'],
      ['Ext', 'extensions', 'warn'],
      ['Store', 'extensions', 'info'],
    ]);
    // Su un PC nel dominio i criteri sono dell'organizzazione.
    expect(issues(list, {}, 'clinica.local')[0]).toEqual(['Forced', 'extensions', 'info']);
    expect(find(withAutoruns(list), 'pc.autoruns.extensions')).toMatchObject({ severity: 'warn', value: '3 estensioni da controllare', actions: ['remove-browser-extension'] });
  });

  it('percorsi senza virgolette: avviso solo con un file intercettore', () => {
    const svc = file('C:\\Program Files\\Acme App\\svc.exe', 'programFiles', 'valid', 'Acme');
    const u = (interceptors: number) => entry('services', 'AcmeSvc', svc, { unquoted: true, interceptors, start: 'auto', account: 'system' });
    expect(issues([u(0)])).toEqual([['AcmeSvc', 'unquoted', 'info']]);
    expect(issues([u(1)])).toEqual([['AcmeSvc', 'unquoted', 'warn']]);
    expect(find(withAutoruns([u(1)]), 'pc.autoruns.unquoted')).toMatchObject({ severity: 'warn', actions: ['fix-unquoted-service-path', 'defender-scan-file'] });
  });

  it('attività pianificate di altri produttori', () => {
    expect(
      issues([
        entry('tasks', 'Hidden', file(appData('upd.exe'), 'appData', 'unsigned'), { hidden: true, runAs: 'user' }),
        entry('tasks', 'Updater', file(appData('g.exe'), 'appData', 'valid', 'Acme'), { runAs: 'user' }),
        entry('tasks', 'AsSystem', file(appData('s.exe'), 'appData', 'unsigned'), { runAs: 'system' }),
        entry('tasks', 'Highest', file(appData('h.exe'), 'appData', 'valid', 'Acme'), { runAs: 'user', highest: true }),
        entry('tasks', 'Windows', file(appData('w.exe'), 'appData', 'unsigned'), { authorMicrosoft: true }),
        entry('tasks', 'Inline', ms('C:\\Windows\\System32\\cmd.exe'), { command: 'cmd /c echo' }),
        entry('tasks', 'Quiet', file('C:\\Program Files\\Acme\\a.exe', 'programFiles', 'valid', 'Acme'), { hidden: true, triggers: ['logon'] }),
      ]),
    ).toEqual([
      ['Hidden', 'tasks', 'warn'],
      ['Updater', 'tasks', 'info'],
      ['AsSystem', 'tasks', 'crit'],
      ['Highest', 'tasks', 'warn'],
      ['Windows', 'tasks', 'warn'],
      ['Inline', 'tasks', 'info'],
      ['Quiet', 'tasks', 'info'],
    ]);
  });

  it('attività: l\'autore dichiarato «Microsoft» non salva un file senza firma; critico solo come SYSTEM', () => {
    const fake = file('%USERPROFILE%\\AppData\\Roaming\\Upd\\upd.exe', 'appData', 'unsigned');
    const task = (name: string, extra: Partial<AutorunEntry>) => entry('tasks', name, fake, { hidden: true, triggers: ['logon'], ...extra });
    expect(
      issues([
        // La stessa attività, con e senza l'autore dichiarato: decide la firma del file (MITRE T1036.004).
        task('Finta', { runAs: 'system', highest: true, authorMicrosoft: true }),
        task('Vera', { runAs: 'system', highest: true }),
        // Privilegi elevati di un utente o account di servizio: avviso, non critico (scala di pc.autoruns.tasks).
        task('Utente', { runAs: 'user', highest: true }),
        task('Servizio', { runAs: 'service' }),
        // Le attività di Windows con un comando interpretato non si elencano tra quelle da conoscere.
        entry('tasks', 'WinInline', ms('C:\\Windows\\System32\\cmd.exe'), { command: 'cmd /c echo', authorMicrosoft: true }),
        // ProgramData e le cartelle nella radice del disco sono scrivibili da un utente.
        entry('tasks', 'Dati', file('C:\\ProgramData\\xyz\\svc.exe', 'programData', 'unsigned'), { runAs: 'system' }),
        entry('tasks', 'Radice', file('C:\\Tools\\nc.exe', 'other', 'unsigned'), { runAs: 'user' }),
      ]),
    ).toEqual([
      ['Finta', 'tasks', 'crit'],
      ['Vera', 'tasks', 'crit'],
      ['Utente', 'tasks', 'warn'],
      ['Servizio', 'tasks', 'warn'],
      ['Dati', 'tasks', 'crit'],
      ['Radice', 'tasks', 'warn'],
    ]);
    const why = autorunIssues(withAutoruns([task('Finta', { runAs: 'system', authorMicrosoft: true })]))[0].why;
    expect(why).toContain('con privilegi di sistema');
    expect(why).toContain('autore dichiarato Microsoft');
    expect(autorunIssues(withAutoruns([task('Utente', { runAs: 'user', highest: true })]))[0].why).toContain('con privilegi elevati');
  });
});

describe('regole dell\'agente rifatte nel motore', () => {
  it('BootExecute: le righe di Windows come isDefaultBootExecute dell\'agente (stessi esempi della prova Go)', () => {
    // Predefinite: nessun giudizio.
    for (const v of ['autocheck autochk *', 'autocheck autochk /q /v *', 'AUTOCHECK  autochk   *', 'autocheck autochk /k:C *']) expect(bootExecuteKind(v), v).toBe('default');
    // Controllo del disco programmato da Windows su un volume (chkdsk al riavvio): al massimo informazione.
    for (const v of ['autocheck autochk /p \\??\\C:', 'autocheck autochk /r \\??\\D:', 'autocheck autochk /m \\DosDevices\\E:', 'autocheck autochk \\??\\Volume{1b2c3d4e-0000-0000-0000-100000000000}']) expect(bootExecuteKind(v), v).toBe('scheduled');
    // Tutto il resto non è di Windows.
    for (const v of ['autocheck autochk * evil.exe', 'autocheck evil', 'autochk *', 'autocheck autochk', 'autocheck autochk /q', '']) expect(bootExecuteKind(v), v).toBe('other');
    const list = (cmds: string[]) => issues(cmds.map((command, i) => entry('hijacks', `BootExecute${i}`, ms('C:\\Windows\\System32\\autochk.exe'), { kind: 'bootexecute', command })));
    expect(list(['autocheck autochk /q /v *', 'autocheck autochk /k:C *'])).toEqual([]);
    expect(list(['autocheck autochk /p \\??\\C:', 'autocheck autochk /r \\??\\D:'])).toEqual([
      ['BootExecute0', 'hijack', 'info'],
      ['BootExecute1', 'hijack', 'info'],
    ]);
    expect(autorunIssues(withAutoruns([entry('hijacks', 'BootExecute', undefined, { kind: 'bootexecute', command: 'autocheck autochk /r \\??\\D:' })]))[0].why).toContain('controllo del disco programmato');
    expect(list(['autocheck autochk * evil.exe', 'autocheck evil', 'autochk *']).map((x) => x[2])).toEqual(['warn', 'warn', 'warn']);
  });

  it('Shell e Userinit: solo i programmi di Windows nella loro cartella, senza argomenti (come l\'agente)', () => {
    for (const v of ['explorer.exe', 'explorer', 'Explorer.EXE', 'C:\\Windows\\explorer.exe', '%SystemRoot%\\explorer.exe', '%windir%\\explorer.exe', '"C:\\Windows\\explorer.exe"', ' explorer.exe ']) expect(isDefaultShell(v), v).toBe(true);
    for (const v of ['explorer.exe /factory', '%USERPROFILE%\\AppData\\Roaming\\explorer.exe', 'C:\\Windows\\System32\\explorer.exe', 'C:\\Windows\\explorer', '"C:\\Windows\\explorer.exe" /x', 'explorer.exe, C:\\ProgramData\\x\\run.exe', 'cmd.exe', '']) expect(isDefaultShell(v), v).toBe(false);
    for (const v of ['userinit.exe', 'userinit', 'C:\\Windows\\system32\\userinit.exe', '%SystemRoot%\\System32\\userinit.exe', 'C:\\Windows\\system32\\userinit.exe,']) expect(isDefaultUserinit(v), v).toBe(true);
    for (const v of ['C:\\Users\\Public\\userinit.exe', 'userinit.exe /x', 'C:\\Windows\\userinit.exe', 'C:\\Windows\\system32\\userinit.exe,C:\\Users\\Public\\x.exe', '']) expect(isDefaultUserinit(v), v).toBe(false);
  });

  it('IFEO: strumenti di accessibilità sostituiti gravi, debugger mancante che blocca il programma, interpreti non rassicurano', () => {
    const cmd = ms('C:\\Windows\\System32\\cmd.exe');
    const gone = file('C:\\nonexistent.exe', 'other', undefined, undefined, { missing: true });
    expect(
      issues([
        entry('hijacks', 'sethc.exe', cmd, { kind: 'ifeo', command: 'C:\\Windows\\System32\\cmd.exe' }),
        entry('hijacks', 'Utilman.exe', cmd, { kind: 'ifeo', command: 'cmd.exe' }),
        entry('hijacks', 'MsMpEng.exe', gone, { kind: 'ifeo', command: 'C:\\nonexistent.exe' }),
        entry('hijacks', 'notepad.exe', cmd, { kind: 'ifeo', command: 'cmd.exe' }),
      ]),
    ).toEqual([
      ['sethc.exe', 'hijack', 'crit'],
      ['Utilman.exe', 'hijack', 'crit'],
      ['MsMpEng.exe', 'hijack', 'warn'],
      ['notepad.exe', 'hijack', 'warn'],
    ]);
    const s = withAutoruns([entry('hijacks', 'MsMpEng.exe', gone, { kind: 'ifeo' })]);
    expect(autorunIssues(s)[0].why).toBe('MsMpEng.exe non può partire: il «debugger» impostato non esiste');
    expect(find(s, 'pc.autoruns.missing')).toBeUndefined();
    const crit = find(withAutoruns([entry('hijacks', 'sethc.exe', cmd, { kind: 'ifeo' })]), 'pc.autoruns.hijack');
    expect(crit?.severity).toBe('crit');
    expect(crit?.verdict).toContain('strumenti di accessibilità');
  });

  it('ProgramData e le altre cartelle fuori da Programmi e Windows sono scrivibili da un utente', () => {
    expect(
      issues([
        entry('logon', 'Dati', file('C:\\ProgramData\\xyz\\svc.exe', 'programData', 'unsigned')),
        entry('logon', 'Radice', file('C:\\Tools\\nc.exe', 'other', 'unsigned')),
        entry('logon', 'Programmi', file('C:\\Program Files\\Acme\\a.exe', 'programFiles', 'unsigned')),
        entry('services', 'SvcDati', file('C:\\ProgramData\\xyz\\svc.exe', 'programData', 'unsigned'), { account: 'system', start: 'auto' }),
        entry('services', 'SvcAccount', file('C:\\ProgramData\\xyz\\svc2.exe', 'programData', 'unsigned'), { start: 'auto' }),
        // Defender gira da ProgramData ed è di Microsoft: nessun giudizio.
        entry('services', 'WinDefend', { path: 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MsMpEng.exe', folder: 'programData', signature: { status: 'valid', signer: 'Microsoft Corporation', microsoft: true } }, { account: 'system', start: 'auto' }),
      ]),
    ).toEqual([
      ['Dati', 'unsigned', 'warn'],
      ['Radice', 'unsigned', 'warn'],
      ['SvcDati', 'unsigned', 'crit'],
      ['SvcAccount', 'unsigned', 'warn'],
    ]);
    // Account non letto: non si presume LocalSystem.
    const why = autorunIssues(withAutoruns([entry('services', 'SvcAccount', file('C:\\ProgramData\\xyz\\svc2.exe', 'programData', 'unsigned'), { start: 'auto' })]))[0].why;
    expect(why).toContain('account non letto');
    expect(why).not.toContain('LocalSystem');
  });

  it('estensioni imposte da criteri fuori da un dominio: normali con Intune o Entra ID, altrimenti da riconoscere', () => {
    const f = find(withAutoruns([entry('browser', 'Forced', undefined, { browser: 'chrome', source: 'policy' })]), 'pc.autoruns.extensions');
    expect(f?.severity).toBe('warn');
    expect(f?.verdict).toContain('dominio Active Directory');
    expect(f?.verdict).toContain('Intune');
    expect(f?.verdict).not.toContain('non gestito da un\'organizzazione');
  });
});

describe('giudizi e categorie da verificare', () => {
  it('nulla da segnalare: a posto solo se tutto è stato letto', () => {
    const clean = withAutoruns([entry('logon', 'Signed', file('C:\\Program Files\\a.exe', 'programFiles', 'valid', 'Acme'))]);
    expect(find(clean, 'pc.autoruns.unsigned')).toMatchObject({ severity: 'ok', value: 'nessuna voce da controllare' });
    expect(find(clean, 'pc.autoruns.hijack')?.severity).toBe('ok');
    expect(find(clean, 'pc.autoruns.tasks')).toBeUndefined();
    expect(find(clean, 'pc.autoruns.wmi')).toBeUndefined();
    const denied = withAutoruns([], { denied: ['tasks', 'wmi', 'services'] });
    expect(find(denied, 'pc.autoruns.tasks')).toMatchObject({ severity: 'unknown', value: 'da verificare da amministratore' });
    expect(find(denied, 'pc.autoruns.wmi')).toMatchObject({ severity: 'unknown', value: 'da verificare da amministratore' });
    const uns = find(denied, 'pc.autoruns.unsigned');
    expect(uns?.severity).toBe('info');
    expect(uns?.verdict).toContain('servizi: si leggono solo in parte senza amministratore');
    for (const f of analyze(denied).findings.filter((x) => x.id.startsWith('pc.autoruns'))) expect(f.verdict, f.id).not.toMatch(/nessun problema/i);
  });

  it('demo: casa con estensione imposta da criteri e aggiornatore nascosto; clinica con il servizio dei referti', () => {
    expect(find(demoScan, 'pc.autoruns.extensions')?.severity).toBe('warn');
    expect(find(demoScan, 'pc.autoruns.tasks')?.severity).toBe('warn');
    expect(find(demoScan, 'pc.autoruns.tasks')?.verdict).toContain('le altre sono da verificare da amministratore');
    expect(find(demoScan, 'pc.autoruns.unsigned')?.severity).toBe('warn');
    expect(find(demoScan, 'pc.autoruns.missing')?.severity).toBe('info');
    expect(find(clinicScan, 'pc.autoruns.unquoted')?.severity).toBe('info');
    expect(find(clinicScan, 'pc.autoruns.wmi')?.severity).toBe('info');
    expect(find(clinicScan, 'pc.autoruns.extensions')?.severity).toBe('info');
    expect(find(clinicScan, 'pc.autoruns.tasks')?.severity).toBe('unknown');
    expect(autorunCounts(clinicScan).map((c) => c.category)).toEqual(AUTORUN_CATEGORIES);
  });

  it('rapporto, knowledge base, azioni e guide', () => {
    const txt = renderText(demoScan, analyze(demoScan));
    expect(txt).toContain(' Avvio automatico');
    expect(txt).toContain('[ !! ] Acme Coupon Helper (estensione)');
    expect(txt).toContain('Da verificare da amministratore: attività pianificate');
    for (const id of ['pc.autoruns.missing', 'pc.autoruns.unsigned', 'pc.autoruns.hijack', 'pc.autoruns.wmi', 'pc.autoruns.extensions', 'pc.autoruns.unquoted', 'pc.autoruns.tasks']) {
      expect(METRICS[id], id).toBeDefined();
      expect(guideById('avvio-automatico')?.metrics).toContain(id);
    }
    expect(METRICS['pc.startup'].limits).toContain('avvio automatico esteso');
    for (const id of ['review-startup-entry', 'remove-browser-extension', 'review-wmi-subscription', 'fix-unquoted-service-path']) expect(ACTIONS[id], id).toBeDefined();
    // Polaris non toglie nulla: la rimozione WMI è spiegata, non è un comando da copiare.
    for (const s of ACTIONS['review-wmi-subscription'].steps) if (typeof s !== 'string' && s.cmd) expect(s.cmd).not.toMatch(/Remove-|Set-|Invoke-/);
    const table = guideById('avvio-processi')!.blocks.find((b) => b.t === 'table');
    expect(JSON.stringify(table)).toContain('sì, in Avvio automatico');
    // Nella guida le sigle e i nomi propri restano come sono (categoryLower, non toLowerCase).
    const guide = JSON.stringify(guideById('avvio-automatico')!.blocks);
    expect(guide).toContain('sottoscrizioni WMI; estensioni dei browser; Winlogon; dirottamenti noti (IFEO, BootExecute, AppInit); pacchetti di sicurezza (LSA)');
    expect(guide).not.toMatch(/sottoscrizioni wmi|\(ifeo, bootexecute/);
  });
});
