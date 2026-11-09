import { more, num } from './fmt';
import { dateIt, on } from './pc';
import type { Finding, FsCheck, PcData, Scan, Severity, UpdateEntry, Volume } from './types';

// Manutenzione di Windows: esito di Diagnostica memoria, aggiornamenti non
// riusciti e servizio di Windows Update, stato del file system dei volumi.
// Fonti: registro di sistema (MemoryDiagnostics-Results), API di Windows
// Update Agent (cronologia), Gestione servizi, FSCTL_IS_VOLUME_DIRTY e
// MSFT_Volume, registro Applicazione (Wininit, Chkdsk). Le soglie sono
// scelte di Polaris. Gira anche in goja: niente Intl.
//
// Significato dei codici di Windows Update: pagine Microsoft Learn "Windows
// Update error codes by component" e "Windows Update common errors and
// mitigation", lette il 9/11/2026; le spiegazioni in italiano sono di Polaris.

/** Gruppo di un errore di Windows Update: guida il consiglio. */
export type WuErrorGroup = 'store' | 'network' | 'restart' | 'service' | 'space' | 'driver' | 'app' | 'access' | 'other';

/** Codici di Windows Update: nome Microsoft, significato e gruppo. */
export const WU_ERRORS: Record<string, [string, string, WuErrorGroup]> = {
  '0x80070002': ['ERROR_FILE_NOT_FOUND', 'un file necessario all\'aggiornamento non è stato trovato', 'store'],
  '0x800F081F': ['CBS_E_SOURCE_MISSING', 'mancano file dell\'archivio dei componenti di Windows', 'store'],
  '0x80073712': ['ERROR_SXS_COMPONENT_STORE_CORRUPT', 'l\'archivio dei componenti di Windows è in uno stato incoerente', 'store'],
  '0x800F0831': ['CBS_E_STORE_CORRUPTION', 'archivio dei componenti di Windows danneggiato', 'store'],
  '0x80070570': ['ERROR_FILE_CORRUPT', 'file o cartella danneggiati e illeggibili', 'store'],
  '0x8007371B': ['ERROR_SXS_TRANSACTION_CLOSURE_INCOMPLETE', 'archivio dei componenti di Windows incompleto', 'store'],
  '0x80073701': ['ERROR_SXS_ASSEMBLY_MISSING', 'manca un componente di Windows', 'store'],
  '0x800736CC': ['ERROR_SXS_FILE_HASH_MISMATCH', 'un file di Windows non corrisponde a quello atteso', 'store'],
  '0x800F0922': ['CBS_E_INSTALLERS_FAILED', 'l\'installazione dei componenti non è riuscita', 'store'],
  '0x8024402C': ['WU_E_PT_WINHTTP_NAME_NOT_RESOLVED', 'il nome del server di Windows Update non è stato risolto (DNS o proxy)', 'network'],
  '0x80240034': ['WU_E_DOWNLOAD_FAILED', 'il download dell\'aggiornamento non è riuscito', 'network'],
  '0x80072EE2': ['ERROR_INTERNET_TIMEOUT', 'il server non ha risposto in tempo', 'network'],
  '0x80072EFD': ['ERROR_INTERNET_CANNOT_CONNECT', 'connessione al server non riuscita', 'network'],
  '0x80072EFE': ['ERROR_INTERNET_CONNECTION_ABORTED', 'connessione interrotta (firewall o proxy)', 'network'],
  '0x8024401B': ['WU_E_PT_HTTP_STATUS_PROXY_AUTH_REQ', 'il proxy richiede l\'autenticazione', 'network'],
  '0x80244022': ['WU_E_PT_HTTP_STATUS_SERVICE_UNAVAIL', 'servizio di Windows Update momentaneamente non disponibile', 'network'],
  '0x80070422': ['ERROR_SERVICE_DISABLED', 'il servizio Windows Update è disattivato', 'service'],
  '0x8024002E': ['WU_E_WU_DISABLED', 'Windows Update è disattivato o limitato dai criteri', 'service'],
  '0x80070005': ['E_ACCESSDENIED', 'accesso negato', 'access'],
  '0x80070020': ['ERROR_SHARING_VIOLATION', 'un file è bloccato da un altro programma (spesso antivirus o backup)', 'app'],
  '0x80240022': ['WU_E_ALL_UPDATES_FAILED', 'nessun aggiornamento installato (spesso un antivirus che blocca la cartella degli aggiornamenti)', 'app'],
  '0x8024200B': ['WU_E_UH_INSTALLERFAILURE', 'il programma di installazione dell\'aggiornamento non è riuscito', 'other'],
  '0x80242014': ['WU_E_UH_POSTREBOOTSTILLPENDING', 'l\'aggiornamento aspetta ancora il riavvio', 'restart'],
  '0x80070070': ['ERROR_DISK_FULL', 'spazio su disco insufficiente', 'space'],
  '0xC1900101': ['MOSETUP_E_ROLLBACK', 'l\'aggiornamento di versione è stato annullato, di solito per un driver', 'driver'],
  '0xC1900208': ['MOSETUP_E_COMPAT_INSTALLREQ_BLOCK', 'un programma installato non è compatibile con la nuova versione', 'app'],
  '0xC1900200': ['MOSETUP_E_COMPAT_SYSREQ_BLOCK', 'il PC non soddisfa i requisiti della nuova versione', 'other'],
  '0xC190020E': ['MOSETUP_E_INSUFFICIENT_SPACE', 'spazio su disco insufficiente per la nuova versione', 'space'],
};

/** "0x800F081F (CBS_E_SOURCE_MISSING: mancano file...)". */
export function wuErrorText(code?: string): string {
  if (!code) return 'senza codice';
  const e = WU_ERRORS[code.toUpperCase().replace('0X', '0x')];
  return e ? `${code} (${e[0]}: ${e[1]})` : code;
}

const WU_GROUP_HINT: Record<WuErrorGroup, string> = {
  store: 'L\'archivio dei componenti di Windows è danneggiato: si ripara con DISM e SFC, come amministratore.',
  network: 'Il PC non riesce a scaricare gli aggiornamenti: controlla connessione, DNS, proxy e firewall.',
  restart: 'L\'aggiornamento aspetta un riavvio: riavvia il PC.',
  service: 'Il servizio Windows Update è disattivato: Windows non può installare aggiornamenti.',
  space: 'Manca spazio sul disco di sistema.',
  driver: 'Un aggiornamento di versione annullato dipende quasi sempre da un driver o dal firmware: aggiornali prima di riprovare.',
  app: 'Un programma (spesso un antivirus o un programma di backup) blocca i file degli aggiornamenti.',
  access: 'Windows Update non ha i permessi necessari: spesso un antivirus o criteri di sicurezza.',
  other: '',
};

/** Gruppo di un codice, 'other' se sconosciuto. */
export const wuGroup = (code?: string): WuErrorGroup => (code ? (WU_ERRORS[code.toUpperCase().replace('0X', '0x')]?.[2] ?? 'other') : 'other');

/** Aggiornamenti falliti negli ultimi `days` giorni: risolti se poi installati con successo. */
export function failedUpdates(history: UpdateEntry[] | null | undefined, now: number, days = 30): { entry: UpdateEntry; resolved: boolean }[] {
  const h = history ?? [];
  const at = (e: UpdateEntry) => Date.parse(e.date);
  const out: { entry: UpdateEntry; resolved: boolean }[] = [];
  const seen: string[] = [];
  for (const e of h) {
    if (e.kind === 'definition' || e.operation !== 'install' || e.result !== 'failed') continue;
    const t = at(e);
    if (isNaN(t) || now - t > days * DAY) continue;
    const key = e.updateId || e.kb || e.title;
    if (seen.indexOf(key) >= 0) continue;
    seen.push(key);
    const resolved = h.some(
      (x) => x !== e && (x.result === 'succeeded' || x.result === 'succeededWithErrors') && ((e.updateId && x.updateId === e.updateId) || (e.kb && x.kb === e.kb)) && at(x) > t,
    );
    out.push({ entry: e, resolved });
  }
  return out;
}

const DAY = 86400000;

type Add = (f: Omit<Finding, 'actions'> & { actions?: string[] }) => void;

function analyzeMemDiag(pc: PcData, now: number, add: Add) {
  const m = pc.memDiag;
  if (!m) return;
  const last = m.results[0];
  const sched = m.lastScheduled ? Date.parse(m.lastScheduled) : NaN;
  const pending = !isNaN(sched) && (!last || sched > Date.parse(last.time)) && now - sched > DAY;
  if (!last && !pending) return; // nessun test registrato: Polaris non può dire che la RAM sia sana
  if (last && last.errors) {
    add({
      id: 'pc.memdiag',
      metric: 'pc.memdiag',
      category: 'pc',
      title: 'Test della memoria (Diagnostica memoria Windows)',
      value: `errori hardware, ${dateIt(last.time)}`,
      severity: 'crit',
      verdict: `Diagnostica memoria Windows ha trovato errori hardware nella RAM ${on(last.time, 'il')}. Un guasto della memoria non si ripara da solo: causa schermate blu, programmi che si chiudono e file danneggiati. Disattiva overclock e profili XMP/EXPO e prova un modulo alla volta per trovare quello guasto.`,
      actions: ['test-memory', 'check-hardware'],
    });
    return;
  }
  if (pending) {
    add({
      id: 'pc.memdiag',
      metric: 'pc.memdiag',
      category: 'pc',
      title: 'Test della memoria (Diagnostica memoria Windows)',
      value: 'pianificato, esito non registrato',
      severity: 'info',
      verdict: `Un test della memoria è stato pianificato ${on(m.lastScheduled!, 'il')}, ma Windows non ne ha registrato l'esito: il test non è partito o è stato interrotto.${last ? ` L'ultimo esito registrato, ${on(last.time, 'il')}, non aveva errori.` : ''}`,
      actions: ['test-memory'],
    });
    return;
  }
  add({
    id: 'pc.memdiag',
    metric: 'pc.memdiag',
    category: 'pc',
    title: 'Test della memoria (Diagnostica memoria Windows)',
    value: `nessun errore, ${dateIt(last!.time)}`,
    severity: 'ok',
    verdict: `L'ultimo test di Diagnostica memoria Windows, ${on(last!.time, 'il')}, non ha trovato errori: un guasto evidente della RAM è escluso, uno intermittente no.`,
  });
}

function analyzeUpdatesHealth(pc: PcData, now: number, add: Add) {
  const u = pc.updates;
  if (!u) return;
  const managed = !!u.policy?.managed;
  const wu = u.service?.wu;
  const disabled = wu?.start === 'disabled' || (u.historyError ?? '').toUpperCase() === '0X80070422';
  if (disabled || u.policy?.noAutoUpdate) {
    const sev: Severity = disabled ? 'crit' : managed ? 'info' : 'warn';
    add({
      id: 'pc.updates.service',
      metric: 'pc.updates.service',
      category: 'security',
      title: 'Servizio Windows Update',
      value: disabled ? 'disattivato' : 'aggiornamenti automatici spenti dai criteri',
      severity: sev,
      verdict: disabled
        ? 'Il servizio Windows Update è disattivato: Windows non può cercare né installare aggiornamenti, compresi quelli di sicurezza. Succede con i programmi di "ottimizzazione" o per errore.'
        : managed
          ? 'Gli aggiornamenti automatici sono spenti dai criteri di gruppo e gli aggiornamenti arrivano da un server dell\'organizzazione: è una scelta del reparto informatico.'
          : 'Gli aggiornamenti automatici sono spenti dai criteri di gruppo (NoAutoUpdate) senza un server dell\'organizzazione: spesso lo fanno programmi di "ottimizzazione". Il PC riceve gli aggiornamenti solo se qualcuno li cerca a mano.',
      actions: disabled || !managed ? ['enable-windows-update'] : [],
    });
  }
  const failed = failedUpdates(u.history, now);
  if (!failed.length) return;
  const open = failed.filter((f) => !f.resolved);
  const sev: Severity = open.length ? 'warn' : 'info';
  const shown = (open.length ? open : failed).slice(0, 3);
  const groups: WuErrorGroup[] = [];
  for (const f of open) {
    const g = wuGroup(f.entry.hresult);
    if (groups.indexOf(g) < 0) groups.push(g);
  }
  const hints = groups.map((g) => WU_GROUP_HINT[g]).filter(Boolean);
  const actions: string[] = [];
  if (groups.indexOf('store') >= 0) actions.push('repair-windows');
  if (groups.indexOf('restart') >= 0) actions.push('restart-pc');
  if (groups.indexOf('space') >= 0) actions.push('free-disk-space');
  if (groups.indexOf('driver') >= 0) actions.push('update-drivers');
  if (groups.indexOf('service') >= 0) actions.push('enable-windows-update');
  if (open.length) actions.push('update-windows');
  add({
    id: 'pc.updates.failed',
    metric: 'pc.updates.failed',
    category: 'security',
    title: 'Aggiornamenti non riusciti',
    value: open.length ? `${num(open.length, 'non installato', 'non installati')} negli ultimi 30 giorni` : `${failed.length} riusciti al secondo tentativo`,
    numeric: open.length,
    severity: sev,
    verdict:
      shown.map((f) => `${f.entry.kb ? f.entry.kb : f.entry.title} ${on(f.entry.date, 'il')}: errore ${wuErrorText(f.entry.hresult)}`).join('; ') +
      more((open.length ? open : failed).length, 3) +
      '. ' +
      (open.length ? hints.join(' ') || 'Riprova da Windows Update; se il codice si ripete, cercalo sulle pagine Microsoft degli errori di Windows Update.' : 'Windows li ha poi installati con successo: nessuna azione necessaria.') +
      (managed ? ' Gli aggiornamenti di questo PC sono gestiti dall\'organizzazione.' : ''),
    actions,
  });
}

const HEALTH_TEXT: Record<NonNullable<Volume['health']>, string> = {
  healthy: 'sano',
  scan: 'da analizzare',
  spotfix: 'serve una correzione rapida',
  repair: 'serve una riparazione completa',
};

function analyzeFileSystem(pc: PcData, add: Add) {
  const vols = pc.volumes ?? [];
  const dirty = vols.filter((v) => v.dirty);
  const bad = vols.filter((v) => v.health && v.health !== 'healthy');
  const checks: FsCheck[] = pc.fsChecks ?? [];
  const boots = checks.filter((c) => c.source === 'wininit');
  if (!dirty.length && !bad.length && !boots.length) return;
  const sysBad = bad.filter((v) => v.system && v.health === 'repair');
  const fixedDirty = dirty.filter((v) => v.kind === 'fixed');
  let sev: Severity = 'info';
  if (bad.some((v) => v.health === 'repair' || v.health === 'spotfix') || fixedDirty.length || boots.length >= 3) sev = 'warn';
  if (sysBad.length) sev = 'crit';
  const parts: string[] = [];
  if (dirty.length)
    parts.push(
      `${dirty.map((v) => v.letter).join(', ')}: Windows ${dirty.length === 1 ? 'lo controllerà' : 'li controllerà'} al prossimo avvio (il file system è segnato da controllare, di solito dopo uno spegnimento brusco o un errore)` +
        (dirty.every((v) => v.kind === 'removable') ? '; è un\'unità rimovibile, probabilmente scollegata senza la rimozione sicura' : ''),
    );
  for (const v of bad) parts.push(`${v.letter}: secondo Windows ${HEALTH_TEXT[v.health!]}`);
  if (boots.length)
    parts.push(
      `${num(boots.length, 'controllo', 'controlli')} all'avvio negli ultimi 30 giorni${boots[0].drive ? ` (l'ultimo su ${boots[0].drive}, ${on(boots[0].time, 'il')})` : ` (l'ultimo ${on(boots[0].time, 'il')})`}` +
        (boots.length >= 3 ? ': il volume torna a essere segnato da controllare, per spegnimenti bruschi, cadute di corrente o un disco che si sta guastando' : ''),
    );
  add({
    id: 'pc.fs',
    metric: 'pc.fs',
    category: 'pc',
    title: 'File system da controllare',
    value: sysBad.length ? `${sysBad[0].letter}: riparazione completa` : dirty.length ? `${dirty.map((v) => v.letter).join(', ')} da controllare` : bad.length ? `${bad[0].letter}: ${HEALTH_TEXT[bad[0].health!]}` : `${boots.length} controlli all'avvio`,
    numeric: dirty.length + bad.length + boots.length,
    severity: sev,
    verdict: `${parts.join('; ')}.` + (sev !== 'info' ? ' Prima di intervenire tieni aggiornato il backup: un file system danneggiato può essere il segno di un disco che si guasta.' : ''),
    actions: sev === 'info' ? ['check-disk-errors'] : ['check-disk-errors', 'backup-replace-disk'],
  });
}

/** Giudizi su memoria, aggiornamenti e file system. */
export function analyzeMaint(scan: Scan, add: Add) {
  const pc = scan.pc;
  if (!pc) return;
  const now = Date.parse(scan.agent.startedAt) || Date.now();
  analyzeMemDiag(pc, now, add);
  analyzeUpdatesHealth(pc, now, add);
  analyzeFileSystem(pc, add);
}
