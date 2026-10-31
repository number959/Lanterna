import { num } from './fmt';
import { BUGCHECKS, dateIt, on } from './pc';
import type { CrashCulprit, CrashData, CrashDump, CrashDumpType, CrashSettings, EventGroup, Finding, Scan, Severity } from './types';

// Schermate blu lette dai file di Windows, come BlueScreenView: l'agente
// legge i minidump (codice di arresto, parametri, driver indicato) e le
// impostazioni di CrashControl; qui si trasformano in giudizi che non
// ripetono il conteggio delle schermate blu, già dato da "pc.events.bsod"
// con l'evento 1001 del registro di sistema (e con i minidump dello stesso
// periodo, se il registro ne riporta meno: vedi analyzeEvents in pc.ts).
// Gira anche in goja: niente Intl, solo funzioni di ES2015 (indexOf al
// posto di includes).
//
// Nomi ufficiali dei codici: Microsoft Learn, "Bug Check Code Reference"
// (https://learn.microsoft.com/windows-hardware/drivers/debugger/bug-check-code-reference2),
// letta il 31/10/2026. Oltre ai 17 codici di BUGCHECKS (pc.ts) Polaris
// riconosce: 0x19, 0x24, 0x4E, 0x74, 0x77, 0x7B, 0x7F, 0x8E, 0x9C, 0xA0, 0xBE,
// 0xC2, 0xC4, 0xC5, 0xE2, 0xEA, 0xED, 0xF7, 0xFC, 0xFE, 0x101, 0x109, 0x10D,
// 0x113, 0x117, 0x119, 0x12B, 0x144, 0x1C8, 0x1000007E, 0x1000008E,
// 0xC000021A, 0xDEADDEAD. Le spiegazioni in italiano sono di Polaris. Lo
// stesso elenco di nomi è in windows/internal/crash/names.go (riga di
// comando): un test controlla che coincidano.

/** Codici di arresto oltre a BUGCHECKS: nome ufficiale e significato in breve. */
export const BUGCHECKS_MORE: Record<string, [string, string]> = {
  '0x00000019': ['BAD_POOL_HEADER', 'struttura della memoria del sistema danneggiata: di solito un driver'],
  '0x00000024': ['NTFS_FILE_SYSTEM', 'errore nel file system NTFS: disco, cavo o file system danneggiato'],
  '0x0000004e': ['PFN_LIST_CORRUPT', 'elenco delle pagine di memoria danneggiato: driver o RAM'],
  '0x00000074': ['BAD_SYSTEM_CONFIG_INFO', 'configurazione di sistema nel registro danneggiata'],
  '0x00000077': ['KERNEL_STACK_INPAGE_ERROR', 'dati di sistema non letti dal file di paging: disco, cavo o RAM'],
  '0x0000007b': ['INACCESSIBLE_BOOT_DEVICE', 'all\'avvio Windows non riesce a leggere il disco: driver del controller, impostazioni del firmware o disco'],
  '0x0000007f': ['UNEXPECTED_KERNEL_MODE_TRAP', 'errore del processore non gestito: hardware, RAM o driver'],
  '0x0000008e': ['KERNEL_MODE_EXCEPTION_NOT_HANDLED', 'eccezione in un driver o in un componente del sistema'],
  '0x0000009c': ['MACHINE_CHECK_EXCEPTION', 'errore hardware grave segnalato dal processore'],
  '0x000000a0': ['INTERNAL_POWER_ERROR', 'errore nella gestione dell\'alimentazione: driver, firmware o ibernazione'],
  '0x000000be': ['ATTEMPTED_WRITE_TO_READONLY_MEMORY', 'un driver ha scritto in memoria di sola lettura'],
  '0x000000c2': ['BAD_POOL_CALLER', 'un driver ha usato la memoria del sistema in modo non valido'],
  '0x000000c4': ['DRIVER_VERIFIER_DETECTED_VIOLATION', 'Verifica driver, attiva su questo PC, ha trovato un errore in un driver'],
  '0x000000c5': ['DRIVER_CORRUPTED_EXPOOL', 'un driver ha danneggiato la memoria del sistema'],
  '0x000000e2': ['MANUALLY_INITIATED_CRASH', 'arresto provocato di proposito, per esempio dalla tastiera per creare un dump'],
  '0x000000ea': ['THREAD_STUCK_IN_DEVICE_DRIVER', 'un driver, spesso quello video, è rimasto bloccato'],
  '0x000000ed': ['UNMOUNTABLE_BOOT_VOLUME', 'il volume di avvio non si apre: disco, cavo o file system'],
  '0x000000f7': ['DRIVER_OVERRAN_STACK_BUFFER', 'un driver ha scritto oltre un\'area di memoria'],
  '0x000000fc': ['ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY', 'tentativo di eseguire codice in memoria non eseguibile: driver o memoria danneggiata'],
  '0x000000fe': ['BUGCODE_USB_DRIVER', 'errore in un driver USB'],
  '0x00000101': ['CLOCK_WATCHDOG_TIMEOUT', 'un core del processore ha smesso di rispondere: processore, overclock, BIOS o temperature'],
  '0x00000109': ['CRITICAL_STRUCTURE_CORRUPTION', 'codice o dati del kernel modificati: driver, RAM o programmi che agganciano il kernel'],
  '0x0000010d': ['WDF_VIOLATION', 'errore in un driver basato su Windows Driver Framework'],
  '0x00000113': ['VIDEO_DXGKRNL_FATAL_ERROR', 'errore grave del sottosistema grafico: driver video'],
  '0x00000117': ['VIDEO_TDR_TIMEOUT_DETECTED', 'la scheda video non ha risposto in tempo: driver video o surriscaldamento'],
  '0x00000119': ['VIDEO_SCHEDULER_INTERNAL_ERROR', 'errore nella gestione dei compiti della scheda video: driver video'],
  '0x0000012b': ['FAULTY_HARDWARE_CORRUPTED_PAGE', 'una pagina di memoria si è danneggiata: RAM difettosa'],
  '0x00000144': ['BUGCODE_USB3_DRIVER', 'errore nel driver USB 3'],
  '0x000001c8': ['MANUALLY_INITIATED_POWER_BUTTON_HOLD', 'arresto provocato tenendo premuto il pulsante di accensione'],
  '0x1000007e': ['SYSTEM_THREAD_EXCEPTION_NOT_HANDLED_M', 'come 0x7E: eccezione in un driver'],
  '0x1000008e': ['KERNEL_MODE_EXCEPTION_NOT_HANDLED_M', 'come 0x8E: eccezione in un driver o in un componente del sistema'],
  '0xc000021a': ['WINLOGON_FATAL_ERROR', 'si è fermato un processo essenziale dell\'accesso: file di sistema danneggiati o programmi incompatibili'],
  '0xdeaddead': ['MANUALLY_INITIATED_CRASH1', 'arresto provocato di proposito dal debugger o da uno strumento'],
};

/** Dove cercare, per famiglia di codici: guida le azioni proposte. */
export type CrashFamily = 'driver' | 'memory' | 'disk' | 'video' | 'hardware' | 'system' | 'manual';

const FAMILY_CODES: Record<CrashFamily, string[]> = {
  driver: ['0a', 'd1', '1e', '7e', '1000007e', '8e', '1000008e', '3b', '9f', 'c2', 'c4', 'c5', 'ea', 'f7', 'fc', 'be', '10d', 'fe', '144', '19', '13a', '139', '109', '133'],
  memory: ['1a', '4e', '50', '12b'],
  disk: ['7a', '77', '7b', 'ed', 'f4', '154', '24', 'ef', '74', 'c000021a'],
  video: ['116', '117', '113', '119'],
  hardware: ['124', '9c', '101', '7f'],
  system: ['a0'],
  manual: ['e2', '1c8', 'deaddead'],
};
const FAMILY: { [code: string]: CrashFamily } = {};
for (const f of Object.keys(FAMILY_CODES) as CrashFamily[]) for (const c of FAMILY_CODES[f]) FAMILY[crashCode('0x' + c)] = f;

/** Dove cercare la causa, per famiglia. */
export const CRASH_FAMILY_TEXT: Record<CrashFamily, string> = {
  driver: 'un driver',
  memory: 'la memoria (RAM) o un driver',
  disk: 'il disco, il suo collegamento o il file system',
  video: 'la scheda video, il suo driver o le temperature',
  hardware: 'l\'hardware: processore, RAM, alimentazione o temperature',
  system: 'un componente di Windows o un driver',
  manual: 'nessuna: è un arresto provocato di proposito',
};

const FAMILY_ACTIONS: Record<CrashFamily, string[]> = {
  driver: ['diagnose-bsod'],
  memory: ['test-memory', 'diagnose-bsod'],
  disk: ['check-disk-errors', 'diagnose-bsod'],
  video: ['update-gpu-driver', 'check-temperatures'],
  hardware: ['check-hardware', 'check-temperatures'],
  system: ['diagnose-bsod'],
  manual: [],
};

/** Codice normalizzato come nel registro eventi: "0x000000d1"; "" se non valido. */
export function crashCode(code?: string): string {
  const m = /^0x([0-9a-f]{1,8})$/i.exec((code || '').trim());
  return m ? '0x' + ('00000000' + m[1].toLowerCase()).slice(-8) : '';
}

export interface BugcheckInfo {
  code: string;
  name?: string;
  meaning?: string;
  family?: CrashFamily;
}

/** Nome, significato e famiglia di un codice di arresto, se Polaris lo conosce. */
export function bugcheckInfo(code?: string): BugcheckInfo {
  const c = crashCode(code);
  const known = BUGCHECKS[c] || BUGCHECKS_MORE[c];
  const out: BugcheckInfo = { code: c };
  if (known) {
    out.name = known[0];
    out.meaning = known[1];
  }
  if (FAMILY[c]) out.family = FAMILY[c];
  return out;
}

/** "0x000000d1 DRIVER_IRQL_NOT_LESS_OR_EQUAL", oppure il codice con la nota che Polaris non lo conosce. */
export function bugcheckText(code?: string): string {
  const i = bugcheckInfo(code);
  if (!i.code) return 'codice non scritto nel file';
  return i.name ? `${i.code} ${i.name}` : `${i.code} (non è nell'elenco di Polaris)`;
}

/**
 * Codice e parametri dal dettaglio dell'evento 1001 (BugCheck), per esempio
 * "0x0000009f (0x0000000000000003, 0xffffe50c3c7a5060, ...)".
 */
export function parseBugcheckEvent(detail?: string): { code: string; params: string[] } | undefined {
  const m = /(0x[0-9a-f]{1,8})\s*\(([^)]*)\)/i.exec(detail || '') || /(0x[0-9a-f]{1,8})/i.exec(detail || '');
  if (!m) return undefined;
  const code = crashCode(m[1]);
  if (!code) return undefined;
  const params = m[2] ? m[2].split(',').map((p) => p.trim()).filter((p) => /^0x[0-9a-f]+$/i.test(p)).map((p) => p.toLowerCase()) : [];
  return { code, params };
}

/** L'evento 1001 più recente tra quelli raggruppati (il dettaglio è dell'ultima occorrenza). */
export function lastBugcheckEvent(events?: EventGroup[]): EventGroup | undefined {
  let last: EventGroup | undefined;
  for (const e of events ?? []) if (e.kind === 'bugcheck' && (!last || e.last > last.last)) last = e;
  return last;
}

export const CRASH_DUMP_TYPE: Record<CrashDumpType, string> = {
  triage: 'dump piccolo (minidump)',
  kernel: 'dump del kernel',
  full: 'dump completo',
  header: 'solo intestazione',
  'bitmap-full': 'dump completo',
  'bitmap-kernel': 'dump del kernel',
  automatic: 'dump automatico',
  'kernel-user': 'dump del kernel e dei processi',
  unknown: 'tipo non riconosciuto',
};

/** Perché di un file si leggono solo i dati dell'intestazione. */
export const CRASH_LIMITED: Record<NonNullable<CrashDump['limited']>, string> = {
  'not-triage': 'dei dump del kernel e completi Polaris legge solo l\'intestazione',
  '32bit': 'dump a 32 bit: solo l\'intestazione',
  'too-large': 'file molto grande: solo l\'intestazione',
  inconsistent: 'dati del minidump incoerenti: solo l\'intestazione',
};

const DUMP_ENABLED: { [v: number]: string } = { 0: 'nessun file', 1: 'dump completo della memoria', 2: 'dump del kernel', 3: 'dump piccolo (minidump)', 7: 'dump automatico' };

/** Che cosa salva Windows dopo una schermata blu (CrashDumpEnabled). */
export function crashSetting(s?: CrashSettings): string {
  if (!s || s.dumpEnabled === undefined) return 'impostazione non letta';
  if (s.dumpEnabled === 1 && s.filterPages) return 'dump della memoria attiva';
  return DUMP_ENABLED[s.dumpEnabled] || `valore ${s.dumpEnabled}`;
}

/** Come è stato trovato il driver: "dall'indirizzo nel parametro 4" o "dallo stack salvato". */
export function culpritHow(p: CrashCulprit): string {
  return p.method === 'param' ? `dall'indirizzo nel parametro ${p.param ?? '?'}` : 'dallo stack salvato';
}

/** Ora dell'arresto scritta nel file, o data del file. */
export const crashWhen = (d: CrashDump) => d.time || d.modified || '';

/** Il file è stato letto e ha un codice. */
export const crashRead = (d: CrashDump) => !d.error && !!crashCode(d.code);

/**
 * Perché un file letto non ha un driver indicato. L'agente salta solo il
 * nucleo di Windows (kernel, HAL e PSHED, vedi Ignored in
 * windows/internal/crash/parse.go): gli altri driver Microsoft possono
 * essere indicati. Per 0x124 e per gli arresti provocati a mano non cerca.
 */
export function noCulpritText(d: CrashDump): string {
  const info = bugcheckInfo(d.code);
  if (!info.code) return 'non cercato: codice non scritto nel file';
  if (info.family === 'manual') return 'nessuno: arresto provocato di proposito';
  if (info.code === '0x00000124') return 'nessuno: errore segnalato dall\'hardware';
  if (d.limited || d.dumpType !== 'triage') return 'non cercato: di questo file si legge solo l\'intestazione';
  return 'nessun driver fuori dal nucleo di Windows (kernel e HAL) nello stack salvato';
}

/** Riga riassuntiva: "0x000000d1 DRIVER_IRQL_NOT_LESS_OR_EQUAL; indizio: fictnet.sys (parametro 4)". */
export function crashSummary(d: CrashDump): string {
  if (d.error) return `non letto: ${d.error}`;
  const parts = [bugcheckText(d.code)];
  const p = d.probable;
  if (p) parts.push(`indizio: ${p.driver} (${p.method === 'param' ? `parametro ${p.param ?? '?'}` : 'stack'}${p.unloaded ? ', già scaricato' : ''})`);
  else if (crashCode(d.code) && d.dumpType === 'triage' && !d.limited && bugcheckInfo(d.code).family !== 'manual')
    parts.push(crashCode(d.code) === '0x00000124' ? 'nessun driver: errore segnalato dall\'hardware' : 'nessun driver indicato fuori dal nucleo di Windows');
  if (d.limited) parts.push(CRASH_LIMITED[d.limited]);
  return parts.join('; ');
}

/** Stato della cartella dei minidump in breve: "4 file", "nessun file", "cartella non leggibile"... */
export function crashFolderText(c: CrashData): string {
  if (c.partial && !c.folder) return 'lettura non finita in tempo';
  if (c.folder === 'denied' || c.folder === 'error') return 'cartella non leggibile';
  if (c.total) return `${c.total} file${c.partial ? ', lettura interrotta prima della fine' : ''}`;
  return 'nessun file';
}

export interface CrashGroup {
  /** Chiave di confronto: nome del driver in minuscolo o codice. */
  key: string;
  label: string;
  count: number;
  first: string;
  last: string;
  codes: string[];
  unloaded?: boolean;
}

function group(c: CrashData | undefined, keyOf: (d: CrashDump) => string | undefined, labelOf: (d: CrashDump) => string, min: number): CrashGroup[] {
  const map: { [k: string]: CrashGroup } = {};
  const order: string[] = [];
  for (const d of c?.dumps ?? []) {
    if (!crashRead(d)) continue;
    const key = keyOf(d);
    if (!key) continue;
    const when = crashWhen(d);
    let g = map[key];
    if (!g) {
      g = map[key] = { key, label: labelOf(d), count: 0, first: when, last: when, codes: [] };
      order.push(key);
    }
    g.count++;
    if (when && (!g.first || when < g.first)) g.first = when;
    if (when > g.last) g.last = when;
    const code = crashCode(d.code);
    if (code && g.codes.indexOf(code) < 0) g.codes.push(code);
    if (d.probable && d.probable.unloaded) g.unloaded = true;
  }
  return order
    .map((k) => map[k])
    .filter((g) => g.count >= min)
    .sort((a, b) => b.count - a.count || (b.last > a.last ? 1 : b.last < a.last ? -1 : 0));
}

/** Un driver indicato in almeno due minidump: soglia scelta da Polaris. */
export const CRASH_REPEAT = 2;
/** Una ripetizione conta come avviso se l'ultima volta è entro 30 giorni dall'analisi (scelta di Polaris, come la finestra degli eventi). */
export const CRASH_RECENT_DAYS = 30;

/** Driver indicati in almeno `min` minidump, dal più frequente. */
export const crashDrivers = (c?: CrashData, min = CRASH_REPEAT) =>
  group(
    c,
    (d) => (d.probable ? d.probable.driver.toLowerCase() : undefined),
    (d) => d.probable!.driver,
    min,
  );

/** Codici presenti in almeno `min` minidump, dal più frequente. */
export const crashCodes = (c?: CrashData, min = CRASH_REPEAT) => group(c, (d) => crashCode(d.code) || undefined, (d) => crashCode(d.code), min);

const DAY = 86400000;

/** "il 27 settembre 2026" oppure "dal 2 settembre 2026 al 27 settembre 2026". */
function span(g: CrashGroup): string {
  if (!g.first || !g.last) return 'in date non scritte nei file';
  return dateIt(g.first) === dateIt(g.last) ? on(g.last, 'il') : `${on(g.first, 'dal')} ${on(g.last, 'al')}`;
}

type Add = (f: Omit<Finding, 'actions'> & { actions?: string[] }) => void;

/**
 * Giudizi che solo i minidump permettono: driver o codice ricorrente,
 * salvataggio dei dump disattivato, file non leggibili senza
 * amministratore. Il numero di schermate blu resta in "pc.events.bsod".
 */
export function analyzeCrashes(scan: Scan, add: Add) {
  const pc = scan.pc;
  const c = pc?.crashes;
  if (!pc || !c) return;
  const now = Date.parse(scan.agent.startedAt) || Date.now();
  const recent = (iso: string) => {
    const t = Date.parse(iso);
    return !isNaN(t) && now - t <= CRASH_RECENT_DAYS * DAY;
  };
  const read = (c.dumps ?? []).filter(crashRead);
  const bsod = (pc.events ?? []).filter((e) => e.kind === 'bugcheck');
  const nEvents = bsod.reduce((a, e) => a + e.count, 0);
  const hadCrashes = nEvents > 0 || c.total > 0 || !!(c.memoryDump && crashCode(c.memoryDump.code));
  const clue =
    'È un indizio, non una certezza: Polaris lo ricava dal parametro che la documentazione Microsoft indica per quel codice o dallo stack salvato, senza i simboli di debug.';

  const drivers = crashDrivers(c);
  if (drivers.length) {
    const top = drivers[0];
    const sev: Severity = recent(top.last) ? 'warn' : 'info';
    const others = drivers.slice(1, 4).map((d) => `${d.label} (${d.count})`);
    add({
      id: 'pc.crash.driver',
      metric: 'pc.crash.driver',
      category: 'pc',
      title: 'Driver ricorrente nelle schermate blu',
      value: `${top.label}: ${top.count} su ${read.length}`,
      numeric: top.count,
      severity: sev,
      verdict:
        `Il driver ${top.label}${top.unloaded ? ' (già scaricato al momento dell\'arresto in almeno un caso)' : ''} è indicato in ${top.count} schermate blu su ${read.length} lette, ${span(top)}; ` +
        `codic${top.codes.length === 1 ? 'e' : 'i'} ${top.codes.map(bugcheckText).join(', ')}. ${clue} Aggiornalo o ripristinalo prima di sostituire componenti.` +
        (others.length ? ` Indicati più volte anche: ${others.join(', ')}.` : '') +
        (sev === 'info' ? ` L'ultima volta è stata più di ${CRASH_RECENT_DAYS} giorni prima dell'analisi.` : ''),
      actions: ['update-crash-driver', 'diagnose-bsod'],
    });
  }

  // Gli arresti provocati di proposito (0xE2 dalla tastiera...) non sono un
  // problema da cercare: conta il primo codice ricorrente tra gli altri.
  const topCode = crashCodes(c).filter((g) => bugcheckInfo(g.key).family !== 'manual')[0];
  const info = topCode ? bugcheckInfo(topCode.key) : undefined;
  if (!drivers.length && topCode && info) {
    const sev: Severity = recent(topCode.last) ? 'warn' : 'info';
    const what = info.name
      ? `${bugcheckText(topCode.key)}${info.meaning ? ` (${info.meaning})` : ''}`
      : `${topCode.key}, un codice che non è nell'elenco di Polaris: cercalo nella documentazione Microsoft dei codici di arresto`;
    add({
      id: 'pc.crash.code',
      metric: 'pc.crash.code',
      category: 'pc',
      title: 'Codice ricorrente nelle schermate blu',
      value: `${topCode.key}: ${topCode.count} su ${read.length}`,
      numeric: topCode.count,
      severity: sev,
      verdict:
        `Lo stesso codice di arresto compare in ${topCode.count} schermate blu su ${read.length} lette, ${span(topCode)}: ${what}.` +
        (info.family ? ` Dove cercare: ${CRASH_FAMILY_TEXT[info.family]}.` : '') +
        ' Nei minidump non c\'è un driver indicato più volte.' +
        (sev === 'info' ? ` L'ultima volta è stata più di ${CRASH_RECENT_DAYS} giorni prima dell'analisi.` : ''),
      actions: info.family ? FAMILY_ACTIONS[info.family] : ['diagnose-bsod'],
    });
  }

  const s = c.settings;
  if (s && (s.dumpEnabled === 0 || s.logEvent === false)) {
    const off = s.dumpEnabled === 0;
    add({
      id: 'pc.crash.settings',
      metric: 'pc.crash.settings',
      category: 'pc',
      title: 'Salvataggio delle schermate blu',
      value: off ? 'disattivato' : 'senza evento nel registro',
      severity: off && hadCrashes ? 'warn' : 'info',
      verdict: off
        ? `Windows è impostato per non salvare nulla dopo una schermata blu: se ne capita un'altra non resterà un file da esaminare${s.logEvent === false ? ' né un evento nel registro di sistema' : ', solo il codice nel registro eventi'}.` +
          (hadCrashes ? ' Su questo PC ci sono già state schermate blu: conviene riattivarlo.' : '') +
          ' Il dump piccolo (minidump) occupa poco spazio e basta per una prima analisi. Polaris non cambia l\'impostazione: è un passo da fare a mano.'
        : 'Windows salva i file delle schermate blu ma non le annota nel registro di sistema: Polaris le conta dai minidump, quindi se un file manca anche il conteggio risulta incompleto.',
      actions: ['enable-minidump'],
    });
  }

  if (c.needsAdmin && !read.length && (nEvents > 0 || c.total > 0)) {
    const ev = parseBugcheckEvent(lastBugcheckEvent(pc.events)?.detail);
    add({
      id: 'pc.crash.access',
      metric: 'pc.crash.access',
      category: 'pc',
      title: 'File delle schermate blu',
      value: 'serve l\'amministratore',
      severity: 'info',
      verdict:
        (nEvents
          ? `Windows ha registrato ${num(nEvents, 'schermata blu', 'schermate blu')}${pc.eventsDays ? ` negli ultimi ${pc.eventsDays} giorni` : ''}`
          : `Nella cartella dei minidump ci sono ${num(c.total, 'file', 'file')}`) +
        ', ma i file con i dettagli (minidump) si leggono solo avviando Polaris come amministratore: senza, il driver indicato non si vede.' +
        (ev ? ` Dal registro eventi, l'ultimo codice è ${bugcheckText(ev.code)}.` : ''),
      actions: ['read-crash-files'],
    });
  }
}
