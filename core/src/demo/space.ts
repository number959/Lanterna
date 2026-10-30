import type { Scan, SpaceFile, SpaceHint, SpaceNode, SpaceReport, SpaceType } from '../engine/types';

// Analisi dello spazio simulata per i PC dimostrativi: alberi plausibili e
// deterministici (stessi dati, stesso risultato), con i percorsi già ripuliti
// dai nomi utente come li produce l'agente. Il portatile di casa ha C: quasi
// pieno per colpa di Windows.old, dei download e dei video; il PC
// dell'ambulatorio ha un disco di archivio con immagini e backup.

/** Cartella: spazio dei file che contiene direttamente (GB), numero di file, sottocartelle. */
interface Dir {
  n: string;
  gb?: number;
  files?: number;
  denied?: boolean;
  kids?: Dir[];
  /** Sottocartelle piccole non mostrate una per una: [quante, GB]. */
  more?: [number, number];
}

const GB = 1e9;
const d = (n: string, gb: number, files: number, kids?: Dir[], more?: [number, number]): Dir => ({ n, gb, files, kids, more });

// ---------------------------------------------------------------- Portatile di casa, C:

const homeC: Dir = d('C:\\', 7.74, 4, [
  d('Users', 0, 2, [
    d('%USERPROFILE%', 0.02, 6, [
      d('Videos', 22.4, 64, [d('Vacanze', 9.1, 212), d('Telefono', 6.3, 418)]),
      d('Downloads', 21.9, 486, [d('Programmi', 2.4, 38)]),
      d('AppData', 0, 3, [
        d('Local', 2.1, 120, [
          d('Microsoft', 0.8, 400, [
            d('Edge', 0, 0, [d('User Data', 0.4, 60, [d('Default', 0.5, 900, [d('Cache', 1.4, 5200), d('Code Cache', 0.3, 2100)])])]),
            d('OneDrive', 1.1, 300),
            d('Teams', 0.9, 2400),
            d('WindowsApps', 0.6, 40),
          ]),
          d('Temp', 6.1, 8300, [d('Setup-aggiornamento', 0.7, 140)]),
          d('Google', 0, 0, [d('Chrome', 0.6, 80, [d('User Data', 0.3, 120, [d('Default', 1.6, 3100, [d('Cache', 1.9, 9100), d('Code Cache', 0.6, 4400)])])])]),
          d('Packages', 3.8, 15400),
          d('Spotify', 0.4, 60, [d('Data', 2.2, 3800)]),
          d('CrashDumps', 0.4, 6),
        ], [214, 1.3]),
        d('Roaming', 1.4, 2900, [d('Zoom', 0.4, 300), d('Microsoft', 0.9, 1200)], [61, 0.5]),
        d('LocalLow', 0.2, 140),
      ]),
      d('Pictures', 10.6, 7400, [d('Telefono', 1.4, 860)]),
      d('OneDrive', 3.1, 640, [d('Documenti', 1.9, 820), d('Immagini', 4.7, 2100)]),
      d('Documents', 4.3, 1900, [d('Scuola', 0.6, 340)]),
      d('Desktop', 2.4, 58),
      d('Music', 1.8, 420),
    ]),
    d('Public', 0.9, 30),
  ]),
  d('Windows.old', 0, 4, [d('Windows', 14.2, 89000), d('Program Files', 3.9, 21000), d('Users', 2.3, 6100)]),
  d('Windows', 0.3, 60, [
    d('WinSxS', 7.9, 61000),
    d('System32', 5.6, 17000, [d('DriverStore', 2.1, 9800)]),
    d('SoftwareDistribution', 0.3, 900, [d('Download', 4.3, 1600)]),
    d('Installer', 2.9, 410),
    d('Microsoft.NET', 0.9, 4100),
    d('assembly', 1.4, 2600),
    d('SysWOW64', 1.1, 5300),
    d('Temp', 1.2, 2100),
    d('Fonts', 0.5, 1200),
  ], [118, 2.6]),
  d('Program Files (x86)', 0.1, 10, [d('Steam', 0.8, 900, [d('steamapps', 13.6, 3400)]), d('Microsoft', 1.1, 900)], [22, 0.9]),
  d('Program Files', 0.1, 12, [d('WindowsApps', 4.2, 18000, undefined), d('Microsoft Office', 3.1, 5300), d('Google', 0.4, 210), d('Common Files', 0.9, 2300)], [47, 3.1]),
  d('ProgramData', 0.1, 20, [
    d('Microsoft', 1.3, 3000, [d('Windows', 0.1, 50, [d('WER', 0.6, 90)])]),
    d('Package Cache', 1.3, 420),
    d('Steam', 0.3, 40),
  ], [31, 0.4]),
  d('$Recycle.Bin', 0, 1, [d('S-1-5-21-…-1001', 3.9, 260)]),
]);

const homeCFiles: [string, number, string][] = [
  ['%USERPROFILE%\\Videos\\Vacanze\\Vacanze 2025.mkv', 6.42, '2025-08-30'],
  ['%USERPROFILE%\\Downloads\\Win11_24H2_Italian_x64.iso', 5.82, '2025-03-14'],
  ['C:\\pagefile.sys', 4.29, '2026-10-12'],
  ['C:\\hiberfil.sys', 3.18, '2026-10-12'],
  ['%USERPROFILE%\\Videos\\Recita di Natale.mp4', 3.91, '2024-12-20'],
  ['%USERPROFILE%\\Downloads\\backup-telefono-2024.zip', 2.74, '2024-11-02'],
  ['C:\\Program Files (x86)\\Steam\\steamapps\\common\\Gioco\\data\\textures.pak', 2.61, '2026-06-03'],
  ['%USERPROFILE%\\Videos\\Telefono\\VID_20250712.mp4', 1.96, '2025-07-12'],
  ['%USERPROFILE%\\Downloads\\Office_Installer_vecchio.img', 1.88, '2023-09-21'],
  ['C:\\Windows\\Installer\\1a2b3c.msp', 0.94, '2025-02-11'],
  ['%USERPROFILE%\\AppData\\Local\\Temp\\Setup-aggiornamento\\payload.cab', 0.71, '2026-04-09'],
  ['%USERPROFILE%\\OneDrive\\Immagini\\Album matrimonio.zip', 1.42, '2023-06-10'],
];

const homeCHints: [string, number, number, string?][] = [
  ['downloads', 24.3, 524, '%USERPROFILE%\\Downloads'],
  ['windows-old', 20.4, 116104, 'C:\\Windows.old'],
  ['onedrive', 9.7, 3560, '%USERPROFILE%\\OneDrive'],
  ['winsxs', 7.9, 61000, 'C:\\Windows\\WinSxS'],
  ['temp-user', 6.8, 8440, '%USERPROFILE%\\AppData\\Local\\Temp'],
  ['browser-cache', 4.2, 20800],
  ['update-cache', 4.3, 1600, 'C:\\Windows\\SoftwareDistribution\\Download'],
  ['pagefile', 4.56, 2],
  ['recycle-bin', 3.9, 260, 'C:\\$Recycle.Bin'],
  ['hibernation', 3.18, 1, 'C:\\hiberfil.sys'],
  ['installer', 2.9, 410, 'C:\\Windows\\Installer'],
  ['package-cache', 1.3, 420, 'C:\\ProgramData\\Package Cache'],
  ['temp-windows', 1.2, 2100, 'C:\\Windows\\Temp'],
  ['error-reports', 0.6, 90, 'C:\\ProgramData\\Microsoft\\Windows\\WER'],
  ['crash-dumps', 0.4, 6, '%USERPROFILE%\\AppData\\Local\\CrashDumps'],
];

// ---------------------------------------------------------------- Ambulatorio, C: e D:

const clinicC: Dir = d('C:\\', 6.1, 4, [
  d('Users', 0, 2, [
    d('%USERPROFILE%', 0.01, 6, [
      d('AppData', 0, 3, [
        d('Local', 1.4, 300, [
          d('Microsoft', 0.9, 900, [d('Edge', 0, 0, [d('User Data', 0.3, 50, [d('Default', 0.4, 700, [d('Cache', 0.9, 4100), d('Code Cache', 0.2, 1400)])])]), d('Teams', 1.3, 3100), d('Outlook', 6.8, 12)]),
          d('Temp', 2.3, 5100),
        ], [102, 0.8]),
        d('Roaming', 0.9, 2100),
      ]),
      d('Documents', 2.1, 1300),
      d('Downloads', 3.4, 210),
      d('Desktop', 0.6, 40),
    ]),
    d('‹utente 1›', 0, 4, [d('AppData', 4.8, 9800), d('Documents', 1.2, 600), d('Downloads', 2.2, 140)]),
    d('‹utente 2›', 0, 4, [d('AppData', 3.9, 8100), d('Downloads', 1.1, 90)]),
    d('Public', 0.2, 20),
  ]),
  d('Windows', 0.3, 60, [
    d('WinSxS', 8.6, 64000),
    d('System32', 5.9, 17500, [d('DriverStore', 2.4, 10200)]),
    d('SoftwareDistribution', 0.3, 800, [d('Download', 2.8, 1100)]),
    d('Installer', 4.6, 620),
    d('assembly', 1.6, 2800),
    d('Microsoft.NET', 1.0, 4300),
    d('SysWOW64', 1.2, 5400),
    d('Temp', 0.6, 900),
  ], [121, 2.9]),
  d('Program Files', 0.1, 12, [d('Gestionale Ambulatorio', 6.9, 8800, [d('Database', 18.4, 22)]), d('Microsoft Office', 3.3, 5600), d('Visualizzatore DICOM', 1.2, 900)], [52, 3.4]),
  d('Program Files (x86)', 0.1, 10, [d('Microsoft', 1.2, 900), d('Firma digitale', 0.4, 300)], [18, 0.8]),
  d('ProgramData', 0.1, 20, [
    d('Microsoft', 1.6, 3200, [d('Windows', 0.1, 50, [d('WER', 0.3, 40)])]),
    d('Package Cache', 2.2, 640),
    d('Gestionale Ambulatorio', 0.2, 30, [d('Backup locale', 21.7, 30)]),
  ], [40, 0.6]),
  d('$Recycle.Bin', 0, 1, [d('S-1-5-21-…-1104', 0.8, 70)]),
]);

const clinicCFiles: [string, number, string][] = [
  ['C:\\Program Files\\Gestionale Ambulatorio\\Database\\archivio.mdf', 16.2, '2026-10-12'],
  ['C:\\ProgramData\\Gestionale Ambulatorio\\Backup locale\\backup-2026-10-11.bak', 5.41, '2026-10-11'],
  ['C:\\ProgramData\\Gestionale Ambulatorio\\Backup locale\\backup-2026-10-10.bak', 5.39, '2026-10-10'],
  ['C:\\ProgramData\\Gestionale Ambulatorio\\Backup locale\\backup-2026-10-09.bak', 5.37, '2026-10-09'],
  ['C:\\ProgramData\\Gestionale Ambulatorio\\Backup locale\\backup-2026-10-08.bak', 5.35, '2026-10-08'],
  ['%USERPROFILE%\\AppData\\Local\\Microsoft\\Outlook\\posta-ambulatorio.ost', 6.71, '2026-10-12'],
  ['C:\\pagefile.sys', 4.29, '2026-10-12'],
  ['C:\\Program Files\\Gestionale Ambulatorio\\Database\\archivio_log.ldf', 2.1, '2026-10-12'],
];

const clinicCHints: [string, number, number, string?][] = [
  ['winsxs', 8.6, 64000, 'C:\\Windows\\WinSxS'],
  ['downloads', 6.7, 440],
  ['installer', 4.6, 620, 'C:\\Windows\\Installer'],
  ['pagefile', 4.29, 1],
  ['update-cache', 2.8, 1100, 'C:\\Windows\\SoftwareDistribution\\Download'],
  ['temp-user', 2.3, 5100, '%USERPROFILE%\\AppData\\Local\\Temp'],
  ['package-cache', 2.2, 640, 'C:\\ProgramData\\Package Cache'],
  ['browser-cache', 1.1, 5500],
  ['recycle-bin', 0.8, 70, 'C:\\$Recycle.Bin'],
  ['temp-windows', 0.6, 900, 'C:\\Windows\\Temp'],
  ['error-reports', 0.3, 40, 'C:\\ProgramData\\Microsoft\\Windows\\WER'],
];

const clinicD: Dir = d('D:\\', 0.02, 3, [
  d('Immagini diagnostiche', 0.1, 20, [d('2026', 96.4, 61000), d('2025', 118.2, 79000), d('2024', 74.9, 52000)], [6, 31.7]),
  d('Archivio documenti', 0.3, 200, [d('Referti', 61.8, 184000), d('Consensi firmati', 38.6, 92000), d('Fatture', 12.4, 41000)]),
  d('Backup', 0, 3, [d('Gestionale', 88.5, 62), d('Posta', 31.2, 14), d('Immagine di sistema', 21.4, 3)]),
  d('Condivisa', 9.8, 4100, [d('Modulistica', 1.4, 380)]),
  d('$Recycle.Bin', 0, 1, [d('S-1-5-21-…-1104', 4.8, 1900)]),
  { n: 'System Volume Information', denied: true },
]);

const clinicDFiles: [string, number, string][] = [
  ['D:\\Backup\\Immagine di sistema\\AMB-07.vhdx', 19.8, '2026-09-30'],
  ['D:\\Backup\\Gestionale\\gestionale-2026-10.zip', 15.1, '2026-10-01'],
  ['D:\\Backup\\Gestionale\\gestionale-2026-09.zip', 14.8, '2026-09-01'],
  ['D:\\Backup\\Gestionale\\gestionale-2026-08.zip', 14.6, '2026-08-01'],
  ['D:\\Backup\\Gestionale\\gestionale-2026-07.zip', 14.3, '2026-07-01'],
  ['D:\\Backup\\Gestionale\\gestionale-2026-06.zip', 14.1, '2026-06-01'],
  ['D:\\Backup\\Posta\\archivio-posta-2025.pst', 12.7, '2026-01-08'],
  ['D:\\Backup\\Gestionale\\gestionale-2026-05.zip', 13.9, '2026-05-01'],
];

const clinicDHints: [string, number, number, string?][] = [
  ['virtual-disks', 19.8, 1],
  ['recycle-bin', 4.8, 1900, 'D:\\$Recycle.Bin'],
];

// ---------------------------------------------------------------- Costruzione

interface Built {
  node: SpaceNode;
  files: number;
  dirs: number;
}

function build(dir: Dir, parentPath: string | null, next: () => number): Built {
  const path = parentPath === null ? dir.n : parentPath.startsWith('%') || parentPath.length > 3 ? `${parentPath}\\${dir.n}` : `${parentPath}${dir.n}`;
  // Il profilo dell'utente compare come %USERPROFILE% anche nel percorso.
  const shown = dir.n === '%USERPROFILE%' ? '%USERPROFILE%' : path;
  const node: SpaceNode = { id: next(), name: dir.n, path: shown, alloc: 0, size: 0, files: 0 };
  const own = Math.round((dir.gb ?? 0) * GB);
  let alloc = own;
  let files = dir.files ?? 0;
  let dirs = 0;
  if (own > 0 || files > 0) {
    node.ownAlloc = own;
    node.ownFiles = files;
  }
  if (dir.denied) node.denied = true;
  const kids = (dir.kids ?? []).map((k) => build(k, shown, next));
  for (const k of kids) {
    alloc += k.node.alloc;
    files += k.files;
    dirs += 1 + k.dirs;
  }
  if (dir.more) {
    node.more = { dirs: dir.more[0], alloc: Math.round(dir.more[1] * GB) };
    alloc += node.more.alloc;
    dirs += dir.more[0];
    files += Math.round(dir.more[0] * 9);
  }
  // Ogni cartella ha in media qualche sottocartella minuscola non elencata.
  dirs += Math.round((dir.files ?? 0) / 40);
  if (kids.length) node.children = kids.map((k) => k.node).sort((a, b) => b.alloc - a.alloc || a.name.localeCompare(b.name));
  node.alloc = alloc;
  node.size = Math.round(alloc * 0.987);
  node.files = files;
  if (dirs > 0) node.dirs = dirs;
  return { node, files, dirs };
}

function findPath(n: SpaceNode, path: string): SpaceNode | undefined {
  if (n.path.toLowerCase() === path.toLowerCase()) return n;
  for (const c of n.children ?? []) {
    const f = findPath(c, path);
    if (f) return f;
  }
  return undefined;
}

// Ripartizione per tipo di file: [estensione, quota dello spazio, file per GB].
const HOME_TYPES: [string, number, number][] = [
  ['.mkv', 0.14, 8], ['.mp4', 0.12, 60], ['.dll', 0.12, 900], ['.pak', 0.07, 30], ['.jpg', 0.07, 900], ['.exe', 0.06, 160], ['.iso', 0.045, 1],
  ['.zip', 0.04, 20], ['.cab', 0.03, 60], ['pagefile.sys', 0.02, 0.5], ['.esd', 0.02, 1], ['.png', 0.02, 1500], ['.heic', 0.02, 600], ['hiberfil.sys', 0.015, 0.3],
  ['.msp', 0.013, 20], ['.pdf', 0.012, 200], ['.img', 0.009, 1], ['.mp3', 0.008, 120], ['.docx', 0.006, 300],
];
const CLINIC_C_TYPES: [string, number, number][] = [
  ['.mdf', 0.09, 0.1], ['.bak', 0.12, 0.3], ['.dll', 0.13, 900], ['.ost', 0.035, 0.2], ['.exe', 0.05, 160], ['pagefile.sys', 0.022, 0.3], ['.cab', 0.03, 60],
  ['.msp', 0.025, 20], ['.ldf', 0.011, 0.5], ['.pdf', 0.01, 200], ['.docx', 0.006, 300], ['.jpg', 0.008, 900],
];
const CLINIC_D_TYPES: [string, number, number][] = [
  ['.dcm', 0.5, 600], ['.pdf', 0.21, 2500], ['.zip', 0.16, 0.5], ['.vhdx', 0.033, 0.05], ['.pst', 0.052, 0.2], ['.jpg', 0.01, 900], ['.docx', 0.006, 300],
];

const CATEGORY: Record<string, string> = {
  '.mkv': 'video', '.mp4': 'video', '.dll': 'program', '.exe': 'program', '.msp': 'program', '.pak': 'other', '.iso': 'archive', '.zip': 'archive',
  '.cab': 'archive', '.img': 'archive', '.esd': 'archive', '.jpg': 'image', '.png': 'image', '.heic': 'image', '.docx': 'document', '.pdf': 'document', '.ost': 'document',
  '.pst': 'document', '.mp3': 'audio', '.vhdx': 'virtualdisk', 'pagefile.sys': 'system', 'hiberfil.sys': 'system',
};

function types(total: number, files: number, spec: [string, number, number][]): { types: SpaceType[]; categories: SpaceType[] } {
  const list: SpaceType[] = spec.map(([id, share, perGB]) => ({ id, alloc: Math.round(total * share), files: Math.max(1, Math.round(((total * share) / GB) * perGB)) }));
  const usedA = list.reduce((s, t) => s + t.alloc, 0);
  const usedF = list.reduce((s, t) => s + t.files, 0);
  const cats = new Map<string, SpaceType>();
  for (const t of list) {
    const c = CATEGORY[t.id] ?? 'other';
    const x = cats.get(c) ?? { id: c, alloc: 0, files: 0 };
    x.alloc += t.alloc;
    x.files += t.files;
    cats.set(c, x);
  }
  // Il resto (estensioni minori) va in "Altro".
  const other = cats.get('other') ?? { id: 'other', alloc: 0, files: 0 };
  other.alloc += Math.max(0, total - usedA);
  other.files += Math.max(0, files - usedF);
  cats.set('other', other);
  const order = (a: SpaceType, b: SpaceType) => b.alloc - a.alloc || a.id.localeCompare(b.id);
  return { types: list.sort(order), categories: [...cats.values()].sort(order) };
}

interface Plan {
  tree: Dir;
  files: [string, number, string][];
  hints: [string, number, number, string?][];
  types: [string, number, number][];
  cloud?: [number, number];
  linkedGB?: number;
  denied?: string[];
  seconds: number;
}

function planFor(scan: Scan, drive: string): Plan | null {
  const clinic = scan.agent.host === 'AMB-07';
  const D = drive.toUpperCase();
  if (D === 'C:' && !clinic) return { tree: homeC, files: homeCFiles, hints: homeCHints, types: HOME_TYPES, cloud: [1840, 42.6], linkedGB: 5.6, denied: ['C:\\System Volume Information', 'C:\\Windows\\CSC', 'C:\\Windows\\System32\\LogFiles\\WMI\\RtBackup'], seconds: 19 };
  if (D === 'C:' && clinic) return { tree: clinicC, files: clinicCFiles, hints: clinicCHints, types: CLINIC_C_TYPES, linkedGB: 6.1, denied: ['C:\\System Volume Information', 'C:\\Users\\‹utente 1›\\AppData\\Local\\Microsoft\\Credentials'], seconds: 24 };
  if (D === 'D:' && clinic) return { tree: clinicD, files: clinicDFiles, hints: clinicDHints, types: CLINIC_D_TYPES, denied: ['D:\\System Volume Information'], seconds: 71 };
  return null;
}

/** Unità senza un albero preparato (per esempio la chiavetta USB): cartelle generiche in proporzione allo spazio usato. */
function genericTree(drive: string, usedGB: number): Plan {
  const u = Math.max(0.05, usedGB);
  return {
    tree: d(`${drive.toUpperCase()}\\`, u * 0.02, 3, [d('DCIM', 0, 1, [d('Foto', u * 0.38, 2400), d('Video', u * 0.31, 140)]), d('Documenti', u * 0.17, 860), d('Musica', u * 0.12, 1100)]),
    files: [],
    hints: [],
    types: [['.jpg', 0.38, 600], ['.mp4', 0.31, 40], ['.pdf', 0.1, 300], ['.mp3', 0.12, 120], ['.docx', 0.05, 300]],
    seconds: 2,
  };
}

/**
 * Analisi dello spazio plausibile per un'unità della demo, coerente con lo
 * spazio totale e libero del volume.
 */
export function simulatedSpace(scan: Scan, drive: string, now = new Date()): SpaceReport {
  const D = drive.toUpperCase();
  const vol = scan.pc?.volumes?.find((v) => v.letter.toUpperCase() === D);
  const totalBytes = Math.round((vol?.sizeGB ?? 256) * GB);
  const freeBytes = Math.round((vol?.freeGB ?? 64) * GB);
  const plan = planFor(scan, D) ?? genericTree(D, ((vol?.sizeGB ?? 256) - (vol?.freeGB ?? 64)) * 0.97);
  let id = 0;
  const { node: tree, files, dirs } = build(plan.tree, null, () => ++id);
  const topFiles: SpaceFile[] = plan.files
    .map(([path, gb, day]) => ({ path, alloc: Math.round(gb * GB), size: Math.round(gb * GB * 0.9995), modified: `${day}T10:00:00Z` }))
    .sort((a, b) => b.alloc - a.alloc)
    .map((f, i) => ({ id: i + 1, ...f }));
  const hints: SpaceHint[] = plan.hints
    .map(([hid, gb, n, path]) => {
      const h: SpaceHint = { id: hid, alloc: Math.round(gb * GB), files: n };
      if (path) {
        h.path = path;
        const node = findPath(tree, path);
        if (node) h.nodeId = node.id;
      }
      return h;
    })
    .sort((a, b) => b.alloc - a.alloc);
  const t = types(tree.alloc, files, plan.types);
  const r: SpaceReport = {
    root: `${D}\\`,
    drive: D,
    fs: vol?.fs ?? 'NTFS',
    totalBytes,
    freeBytes,
    allocBytes: tree.alloc,
    sizeBytes: tree.size,
    files,
    dirs,
    tree,
    topFiles,
    types: t.types,
    categories: t.categories,
    hints,
    startedAt: now.toISOString(),
    durationMs: plan.seconds * 1000 + 420,
  };
  if (plan.denied?.length) {
    r.denied = plan.denied.length;
    r.deniedPaths = plan.denied;
  }
  if (plan.cloud) {
    r.cloudFiles = plan.cloud[0];
    r.cloudBytes = Math.round(plan.cloud[1] * GB);
  }
  if (plan.linkedGB) r.linkedBytes = Math.round(plan.linkedGB * GB);
  return r;
}
