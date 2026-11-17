import type { AutorunEntry, AutorunsData, FileFacts, FileSignature, FolderKind, ProcessesData } from '../engine/types';

// Processi e avvio automatico dimostrativi, come li legge l'agente: percorsi
// già ripuliti (%USERPROFILE%), nessun nome utente, SID, indirizzo remoto o
// nome di profilo del browser. I programmi da controllare hanno nomi di
// fantasia ("Acme...") per non attribuire difetti a prodotti reali.
//
// Demo di casa (portatile non gestito, firewall del profilo privato spento,
// Polaris avviato senza amministratore): un server multimediale senza firma
// in AppData in ascolto su tutte le reti e avviato all'accesso, un programma
// con la firma scaduta, l'attività nascosta di un aggiornatore senza firma in
// AppData, un'estensione del browser imposta da criteri su un PC che non è in
// un dominio, una voce che punta a un programma disinstallato.
// Demo della clinica (PC nel dominio): il gateway PACS senza firma in ascolto
// sulla porta DICOM, il servizio dei referti con il percorso senza virgolette
// (nessun file intercettore), una sottoscrizione WMI dell'antivirus aziendale
// che scrive nel registro eventi, un'estensione imposta dall'organizzazione.
//
// I dati sono quelli che l'agente può produrre (lo controlla
// test/autoruns.test.ts): per ogni categoria il totale è la somma delle voci
// di Microsoft non elencate e di quelle elencate (per le estensioni anche i
// componenti interni del browser, contati e non elencati); «unreadable» è il
// numero dei processi con access 'none', che hanno owner 'unknown'; gli
// pseudo-processi del nucleo (System) non hanno owner; i processi di Polaris
// si aprono e hanno il file; i servizi non hanno scope; le cartelle sono
// scritte per esteso.

const sig = (signer: string, extra: Partial<FileSignature> = {}): FileSignature => ({ status: 'valid', signer, ...extra });
const file = (path: string, folder: FolderKind, signature?: FileSignature, extra: Partial<FileFacts> = {}): FileFacts => ({ path, folder, signature, ...extra });
/** Componente di Windows firmato nel catalogo. */
const win = (path: string): FileFacts => file(path, 'windows', sig('Microsoft Windows', { catalog: true, microsoft: true }));
const msCorp = (path: string, folder: FolderKind): FileFacts => file(path, folder, sig('Microsoft Corporation', { microsoft: true }));

const SVCHOST = 'C:\\Windows\\System32\\svchost.exe';
/** Polaris e la sua finestra WebView2: esclusi dai giudizi, ma l'agente li apre come gli altri processi dell'utente. */
const polarisExe = file('%USERPROFILE%\\Downloads\\STARNET-Polaris\\STARNET-Polaris.exe', 'downloads', { status: 'unsigned' }, { description: 'STARNET Polaris' });
const webview = msCorp('C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\142.0.3595.65\\msedgewebview2.exe', 'programFiles');
/** Processo di un altro account che senza amministratore non si apre: l'agente ne conosce solo il nome. */
const closed = { access: 'none' as const, owner: 'unknown' as const };

// ---------------------------------------------------------------- Casa

const homeAcmeShare = file('%USERPROFILE%\\AppData\\Roaming\\AcmeShare\\acmeshare.exe', 'appData', { status: 'unsigned' }, { company: 'AcmeShare', description: 'AcmeShare Media Server', version: '2.4.1' });
const homeAcmePhoto = file('C:\\Program Files (x86)\\Acme Photo\\phototray.exe', 'programFiles', sig('Acme Imaging Ltd', { status: 'expired', code: '0x800B0101' }), { company: 'Acme Imaging', description: 'Acme Photo Tray', version: '5.2.0.14' });
const chrome = file('C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', 'programFiles', sig('Google LLC'), { company: 'Google LLC', description: 'Google Chrome', version: '142.0.7444.60' });

export const homeProcs: ProcessesData = {
  at: '2026-10-12T20:30:14Z',
  elevated: false,
  connsRead: true,
  // Processi di altri account che senza amministratore non si aprono (elencati sotto con access: 'none').
  unreadable: 6,
  items: [
    { pid: 4, name: 'System', listen: [{ proto: 'tcp', port: 445, scope: 'all' }, { proto: 'tcp', port: 139, scope: 'specific' }] },
    { pid: 412, parentPid: 4, name: 'smss.exe', ...closed },
    { pid: 640, name: 'csrss.exe', ...closed },
    { pid: 732, name: 'wininit.exe', ...closed },
    { pid: 880, parentPid: 732, name: 'services.exe', ...closed },
    { pid: 896, parentPid: 732, name: 'lsass.exe', ...closed },
    { pid: 1012, parentPid: 880, name: 'svchost.exe', file: win(SVCHOST), owner: 'system', services: ['RpcSs', 'RpcEptMapper'], listen: [{ proto: 'tcp', port: 135, scope: 'all' }] },
    { pid: 1468, parentPid: 880, name: 'svchost.exe', file: win(SVCHOST), owner: 'system', services: ['Dnscache'], listen: [{ proto: 'udp', port: 5353, scope: 'all' }] },
    { pid: 1820, parentPid: 880, name: 'svchost.exe', ...closed },
    { pid: 2216, parentPid: 880, name: 'MsMpEng.exe', file: msCorp('C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MsMpEng.exe', 'programData'), owner: 'system', memoryMB: 214, cpuPct: 6.1 },
    { pid: 4720, parentPid: 4688, name: 'explorer.exe', file: win('C:\\Windows\\explorer.exe'), owner: 'self', memoryMB: 162, cpuPct: 0.6 },
    { pid: 5104, parentPid: 4720, name: 'SecurityHealthSystray.exe', file: win('C:\\Windows\\System32\\SecurityHealthSystray.exe'), owner: 'self' },
    {
      pid: 5260,
      parentPid: 4720,
      name: 'RtkAudUService64.exe',
      file: file('C:\\Windows\\System32\\DriverStore\\FileRepository\\realtekservice.inf_amd64\\RtkAudUService64.exe', 'windows', sig('Realtek Semiconductor Corp.')),
      owner: 'self',
    },
    { pid: 6012, parentPid: 4720, name: 'chrome.exe', file: chrome, owner: 'self', memoryMB: 610, cpuPct: 5.2, conns: { internet: 14, remotePorts: [{ port: 443, count: 14 }] } },
    { pid: 6044, parentPid: 6012, name: 'chrome.exe', file: chrome, owner: 'self', memoryMB: 420, cpuPct: 2.1 },
    { pid: 6100, parentPid: 6012, name: 'chrome.exe', file: chrome, owner: 'self', memoryMB: 380, cpuPct: 1.4 },
    {
      pid: 6840,
      parentPid: 4720,
      name: 'ms-teams.exe',
      file: msCorp('C:\\Program Files\\WindowsApps\\MSTeams\\ms-teams.exe', 'programFiles'),
      owner: 'self',
      memoryMB: 890,
      cpuPct: 2,
      conns: { internet: 6, remotePorts: [{ port: 443, count: 6 }] },
    },
    {
      pid: 7012,
      parentPid: 4720,
      name: 'Spotify.exe',
      file: file('%USERPROFILE%\\AppData\\Roaming\\Spotify\\Spotify.exe', 'appData', sig('Spotify AB')),
      owner: 'self',
      memoryMB: 421,
      cpuPct: 0.8,
      listen: [{ proto: 'udp', port: 57621, scope: 'all' }],
      conns: { internet: 3, remotePorts: [{ port: 443, count: 3 }] },
    },
    { pid: 7290, parentPid: 4720, name: 'Discord.exe', file: file('%USERPROFILE%\\AppData\\Local\\Discord\\app-1.0.9170\\Discord.exe', 'appData', sig('Discord Inc.')), owner: 'self', memoryMB: 352, cpuPct: 0.4 },
    // Server multimediale senza firma in AppData, in ascolto su tutte le reti.
    {
      pid: 7488,
      parentPid: 4720,
      name: 'acmeshare.exe',
      file: homeAcmeShare,
      owner: 'self',
      memoryMB: 96,
      cpuPct: 0.3,
      listen: [{ proto: 'tcp', port: 8200, scope: 'all' }, { proto: 'udp', port: 1900, scope: 'all' }],
      conns: { lan: 2, remotePorts: [{ port: 8200, count: 2 }] },
    },
    { pid: 7610, parentPid: 4720, name: 'phototray.exe', file: homeAcmePhoto, owner: 'self', arch: 'x86', memoryMB: 38 },
    // STARNET Polaris e la sua finestra: esclusi dai giudizi.
    { pid: 8120, parentPid: 4720, name: 'STARNET-Polaris.exe', polaris: true, file: polarisExe, owner: 'self', listen: [{ proto: 'tcp', port: 8737, scope: 'local' }] },
    { pid: 8164, parentPid: 8120, name: 'msedgewebview2.exe', polaris: true, file: webview, owner: 'self' },
  ],
};

const run = (name: string, command: string, f: FileFacts, scope: AutorunEntry['scope'] = 'user', enabled = true): AutorunEntry => ({
  category: 'logon',
  kind: 'run',
  scope,
  name,
  location: scope === 'user' ? 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' : scope === 'machine32' ? 'HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run' : 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
  command,
  file: f,
  enabled,
});

export const homeAutoruns: AutorunsData = {
  elevated: false,
  // Senza amministratore si vedono solo le attività leggibili da questo utente.
  denied: ['tasks'],
  counts: {
    logon: { total: 8, microsoft: 2 },
    tasks: { total: 160, microsoft: 158 },
    services: { total: 269, microsoft: 268 },
    drivers: { total: 411, microsoft: 410 },
    // Le sottoscrizioni WMI non hanno un file firmato: l'agente le elenca tutte.
    wmi: { total: 1 },
    // 3 estensioni elencate e 4 componenti interni di Chrome ed Edge, contati e non elencati.
    browser: { total: 7 },
    winlogon: { total: 2, microsoft: 2 },
    hijacks: { total: 1, microsoft: 1 },
    lsa: { total: 6, microsoft: 6 },
    print: { total: 5, microsoft: 5 },
    network: { total: 3, microsoft: 3 },
  },
  entries: [
    run('Spotify', '"%USERPROFILE%\\AppData\\Roaming\\Spotify\\Spotify.exe" --autostart --minimized', file('%USERPROFILE%\\AppData\\Roaming\\Spotify\\Spotify.exe', 'appData', sig('Spotify AB'))),
    run('Discord', '"%USERPROFILE%\\AppData\\Local\\Discord\\Update.exe" --processStart Discord.exe', file('%USERPROFILE%\\AppData\\Local\\Discord\\Update.exe', 'appData', sig('Discord Inc.'))),
    run('Steam', '"C:\\Program Files (x86)\\Steam\\steam.exe" -silent', file('C:\\Program Files (x86)\\Steam\\steam.exe', 'programFiles', sig('Valve Corp.'))),
    run('AcmeShare', '"%USERPROFILE%\\AppData\\Roaming\\AcmeShare\\acmeshare.exe" --tray', homeAcmeShare),
    run('AcmePhotoTray', '"C:\\Program Files (x86)\\Acme Photo\\phototray.exe"', homeAcmePhoto, 'machine32'),
    // Programma disinstallato: la voce è rimasta.
    run('AcmeSyncHelper', '"C:\\Program Files\\AcmeSync\\SyncHelper.exe" /background', file('C:\\Program Files\\AcmeSync\\SyncHelper.exe', 'programFiles', undefined, { missing: true }), 'machine', false),
    {
      category: 'tasks',
      kind: 'task',
      name: 'Aggiornamento AcmeSoft',
      location: '\\AcmeSoft\\Aggiornamento AcmeSoft',
      command: '"%USERPROFILE%\\AppData\\Local\\AcmeSoft\\Update\\acmeupd.exe" /silent',
      file: file('%USERPROFILE%\\AppData\\Local\\AcmeSoft\\Update\\acmeupd.exe', 'appData', { status: 'unsigned' }, { company: 'AcmeSoft', description: 'AcmeSoft Updater' }),
      enabled: true,
      triggers: ['logon', 'daily'],
      runAs: 'user',
      hidden: true,
      lastRun: '2026-10-12T19:02:00Z',
      lastResult: '0x0',
      nextRun: '2026-10-13T19:02:00Z',
    },
    {
      category: 'tasks',
      kind: 'task',
      name: 'GoogleUpdaterTaskUser',
      location: '\\GoogleUpdaterTaskUser',
      command: '"%USERPROFILE%\\AppData\\Local\\Google\\GoogleUpdater\\updater.exe" --wake',
      file: file('%USERPROFILE%\\AppData\\Local\\Google\\GoogleUpdater\\updater.exe', 'appData', sig('Google LLC')),
      enabled: true,
      triggers: ['logon', 'daily'],
      runAs: 'user',
      lastRun: '2026-10-12T18:40:00Z',
      lastResult: '0x0',
    },
    // Avvio manuale e fermo: l'agente non scrive running (omitempty).
    {
      category: 'services',
      kind: 'service',
      name: 'Steam Client Service',
      location: 'HKLM\\System\\CurrentControlSet\\Services\\Steam Client Service',
      command: '"C:\\Program Files (x86)\\Common Files\\Steam\\steamservice.exe" /RunAsService',
      file: file('C:\\Program Files (x86)\\Common Files\\Steam\\steamservice.exe', 'programFiles', sig('Valve Corp.')),
      enabled: true,
      start: 'manual',
      account: 'system',
    },
    {
      category: 'drivers',
      kind: 'driver',
      name: 'acmewlan',
      command: '\\SystemRoot\\System32\\drivers\\acmewlan.sys',
      file: file('C:\\Windows\\System32\\drivers\\acmewlan.sys', 'windows', sig('Microsoft Windows Hardware Compatibility Publisher')),
      enabled: true,
      start: 'system',
      running: true,
    },
    // Il consumer che Windows crea da sé: si elenca (nessun file da verificare) ma non si giudica.
    { category: 'wmi', kind: 'wmi', name: 'SCM Event Log Consumer', namespace: 'root\\subscription', consumer: 'eventlog', bound: true, enabled: true },
    // Estensioni: nessun nome di profilo, solo il numero.
    { category: 'browser', kind: 'extension', name: 'Acme Coupon Helper', browser: 'chrome', extId: 'acmecouponhelperacmecouponhelperac', version: '3.1.4', source: 'policy', profile: 1, allSites: true, enabled: true },
    { category: 'browser', kind: 'extension', name: 'Traduttore rapido', browser: 'chrome', extId: 'traduttorerapidotraduttorerapidotr', version: '1.12.0', source: 'store', profile: 1, allSites: true, enabled: true },
    { category: 'browser', kind: 'extension', name: 'Acme PDF Viewer', browser: 'edge', extId: 'acmepdfvieweracmepdfvieweracmepdfv', version: '2.0.3', source: 'store', profile: 1, enabled: false },
  ],
};

// ---------------------------------------------------------------- Clinica

const pacsGw = file('C:\\Program Files\\Acme PACS Gateway\\pacsgw.exe', 'programFiles', { status: 'unsigned' }, { company: 'Acme Medical Imaging', description: 'Acme PACS Gateway', version: '7.3.2' });
const refSvc = file('C:\\Program Files (x86)\\Acme Referti\\Servizio Referti\\refsvc.exe', 'programFiles', sig('Acme Medical Software S.r.l.'), { company: 'Acme Medical Software', description: 'Servizio referti' });
const endpoint = file('C:\\Program Files\\Acme Endpoint\\EndpointAgent.exe', 'programFiles', sig('Acme Endpoint Security S.p.A.'));

export const clinicProcs: ProcessesData = {
  at: '2026-10-14T09:12:16Z',
  elevated: false,
  connsRead: true,
  unreadable: 3,
  items: [
    { pid: 4, name: 'System', listen: [{ proto: 'tcp', port: 445, scope: 'all' }] },
    { pid: 620, name: 'csrss.exe', ...closed },
    { pid: 860, name: 'services.exe', ...closed },
    { pid: 876, name: 'lsass.exe', ...closed },
    { pid: 1010, parentPid: 860, name: 'svchost.exe', file: win(SVCHOST), owner: 'system', services: ['RpcSs'], listen: [{ proto: 'tcp', port: 135, scope: 'all' }] },
    { pid: 2380, parentPid: 860, name: 'EndpointAgent.exe', file: endpoint, owner: 'system', memoryMB: 210, cpuPct: 1.2, conns: { lan: 2, remotePorts: [{ port: 443, count: 2 }] } },
    { pid: 2412, parentPid: 860, name: 'EndpointAgent.exe', file: endpoint, owner: 'system', memoryMB: 100, cpuPct: 0.7 },
    // Gateway verso il PACS: riceve le immagini sulla porta DICOM da tutta la rete, senza firma.
    { pid: 2650, parentPid: 860, name: 'pacsgw.exe', file: pacsGw, owner: 'system', services: ['AcmePacsGw'], memoryMB: 64, listen: [{ proto: 'tcp', port: 104, scope: 'all' }], conns: { lan: 3, remotePorts: [{ port: 104, count: 3 }] } },
    { pid: 2702, parentPid: 860, name: 'refsvc.exe', file: refSvc, owner: 'system', arch: 'x86', services: ['AcmeRefertiSvc'], memoryMB: 48, conns: { lan: 1, remotePorts: [{ port: 1433, count: 1 }] } },
    { pid: 4410, parentPid: 4380, name: 'explorer.exe', file: win('C:\\Windows\\explorer.exe'), owner: 'self', memoryMB: 120, cpuPct: 0.3 },
    { pid: 5020, parentPid: 4410, name: 'chrome.exe', file: chrome, owner: 'self', memoryMB: 1180, cpuPct: 4.2, conns: { internet: 8, lan: 1, remotePorts: [{ port: 443, count: 9 }] } },
    { pid: 5310, parentPid: 4410, name: 'Teams.exe', file: msCorp('%USERPROFILE%\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe', 'appData'), owner: 'self', memoryMB: 760, cpuPct: 2.4, conns: { internet: 5, remotePorts: [{ port: 443, count: 5 }] } },
    { pid: 5602, parentPid: 4410, name: 'OUTLOOK.EXE', file: msCorp('C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE', 'programFiles'), owner: 'self', memoryMB: 290, cpuPct: 0.7, conns: { lan: 2, remotePorts: [{ port: 443, count: 2 }] } },
    {
      pid: 5720,
      parentPid: 4410,
      name: 'agent.exe',
      file: file('C:\\Program Files (x86)\\FirmaDigitale\\agent.exe', 'programFiles', sig('FirmaDigitale S.r.l.')),
      owner: 'self',
      arch: 'x86',
      listen: [{ proto: 'tcp', port: 9443, scope: 'local' }],
    },
    { pid: 6120, parentPid: 4410, name: 'STARNET-Polaris.exe', polaris: true, file: polarisExe, owner: 'self', listen: [{ proto: 'tcp', port: 8737, scope: 'local' }] },
    { pid: 6188, parentPid: 6120, name: 'msedgewebview2.exe', polaris: true, file: webview, owner: 'self' },
  ],
};

export const clinicAutoruns: AutorunsData = {
  elevated: false,
  denied: ['tasks'],
  counts: {
    logon: { total: 6, microsoft: 3 },
    tasks: { total: 139, microsoft: 139 },
    services: { total: 247, microsoft: 244 },
    drivers: { total: 392, microsoft: 391 },
    wmi: { total: 2 },
    browser: { total: 1 },
    winlogon: { total: 2, microsoft: 2 },
    hijacks: { total: 1, microsoft: 1 },
    lsa: { total: 6, microsoft: 6 },
    print: { total: 6, microsoft: 5 },
    network: { total: 3, microsoft: 3 },
  },
  entries: [
    run('IAStorIcon', '"C:\\Program Files\\Intel\\Intel(R) Rapid Storage Technology\\IAStorIconLaunch.exe"', file('C:\\Program Files\\Intel\\Intel(R) Rapid Storage Technology\\IAStorIconLaunch.exe', 'programFiles', sig('Intel Corporation')), 'machine'),
    run('FirmaDigitale', '"C:\\Program Files (x86)\\FirmaDigitale\\agent.exe" /tray', file('C:\\Program Files (x86)\\FirmaDigitale\\agent.exe', 'programFiles', sig('FirmaDigitale S.r.l.')), 'machine32'),
    {
      category: 'logon',
      kind: 'folder',
      scope: 'machine',
      name: 'Scanner referti',
      location: 'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp',
      command: '"C:\\Program Files\\Acme Referti\\scanner.exe"',
      file: file('C:\\Program Files\\Acme Referti\\scanner.exe', 'programFiles', sig('Acme Medical Software S.r.l.')),
      enabled: true,
    },
    {
      category: 'services',
      kind: 'service',
      name: 'AcmeRefertiSvc',
      location: 'HKLM\\System\\CurrentControlSet\\Services\\AcmeRefertiSvc',
      command: 'C:\\Program Files (x86)\\Acme Referti\\Servizio Referti\\refsvc.exe -service',
      file: refSvc,
      enabled: true,
      start: 'auto',
      running: true,
      account: 'system',
      unquoted: true,
      interceptors: 0,
    },
    {
      category: 'services',
      kind: 'service',
      name: 'AcmePacsGw',
      location: 'HKLM\\System\\CurrentControlSet\\Services\\AcmePacsGw',
      command: '"C:\\Program Files\\Acme PACS Gateway\\pacsgw.exe" --service',
      file: pacsGw,
      enabled: true,
      start: 'auto',
      running: true,
      account: 'system',
    },
    {
      category: 'services',
      kind: 'service',
      name: 'AcmeEndpoint',
      location: 'HKLM\\System\\CurrentControlSet\\Services\\AcmeEndpoint',
      command: '"C:\\Program Files\\Acme Endpoint\\EndpointAgent.exe"',
      file: endpoint,
      enabled: true,
      start: 'auto',
      running: true,
      account: 'system',
    },
    {
      category: 'drivers',
      kind: 'driver',
      name: 'acmescr',
      command: '\\SystemRoot\\System32\\drivers\\acmescr.sys',
      file: file('C:\\Windows\\System32\\drivers\\acmescr.sys', 'windows', sig('Microsoft Windows Hardware Compatibility Publisher')),
      enabled: true,
      start: 'manual',
    },
    {
      category: 'print',
      kind: 'printmon',
      name: 'Acme Port Monitor',
      location: 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors\\Acme Port Monitor',
      file: file('C:\\Windows\\System32\\acmepmon.dll', 'windows', sig('Acme Printing Systems')),
      enabled: true,
    },
    // L'antivirus aziendale registra i suoi eventi con una sottoscrizione WMI.
    { category: 'wmi', kind: 'wmi', name: 'AcmeEndpointMonitor', namespace: 'root\\subscription', consumer: 'eventlog', bound: true, enabled: true },
    { category: 'wmi', kind: 'wmi', name: 'SCM Event Log Consumer', namespace: 'root\\subscription', consumer: 'eventlog', bound: true, enabled: true },
    { category: 'browser', kind: 'extension', name: 'Acme SSO', browser: 'edge', extId: 'acmessoacmessoacmessoacmessoacmess', version: '4.0.1', source: 'policy', profile: 1, allSites: true, enabled: true },
  ],
};
