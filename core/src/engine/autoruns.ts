import { more, num } from './fmt';
import { fileName, folderLabel, isMicrosoftSigned, lc1, SIG_CRIT, SIG_WARN, signatureLabel, userWritable } from './procs';
import type { AutorunCategory, AutorunEntry, FileFacts, Finding, Scan, Severity } from './types';

// Avvio automatico esteso, come Autoruns: ciò che parte da solo oltre alle
// chiavi Run (pc.startup resta il conteggio dei programmi all'accesso).
// L'agente elenca le voci non di Microsoft, quelle con il file mancante e
// quelle in cartelle che un utente può scrivere; le voci di Windows firmate
// da Microsoft si contano soltanto (come «Hide Windows Entries» di
// Autoruns). Polaris non disattiva e non cancella nulla. I giudizi
// descrivono un fatto e invitano a verificare: mai «malware». Ricerca del
// 17/11/2026, fonti:
// - Autoruns su Microsoft Learn (categorie); Run e RunOnce, AppInit e
//   Secure Boot, ordine di ricerca di CreateProcess (Microsoft Learn);
// - MITRE ATT&CK: T1547.001 (Run, BootExecute), T1547.004 (Winlogon Shell e
//   Userinit), T1546.012 (IFEO Debugger, SilentProcessExit), T1546.010
//   (AppInit), T1546.003 (sottoscrizioni WMI), T1053.005 (attività
//   pianificate), T1574.009 (percorsi senza virgolette), T1176.001 (estensioni
//   dei browser), T1547.002/.005/.010/.012, T1556.002/.008 (LSA, stampa,
//   provider di rete), T1218 (programmi di sistema che eseguono altro codice);
// - CommandLineEventConsumer e ActiveScriptEventConsumer girano come
//   LocalSystem (Microsoft Learn); il consumer «SCM Event Log Consumer» è
//   escluso dalle regole pubbliche di Splunk e Sigma, non da Microsoft;
// - ExtensionInstallForcelist (Chrome, Edge su Microsoft Learn): fuori da un
//   dominio Chrome ed Edge forzano solo estensioni dello store.

type Add = (f: Omit<Finding, 'actions'> & { actions?: string[] }) => void;

export const AUTORUN_CATEGORIES: AutorunCategory[] = ['logon', 'tasks', 'services', 'drivers', 'wmi', 'browser', 'winlogon', 'hijacks', 'lsa', 'print', 'network'];

const CATEGORY: Record<AutorunCategory, string> = {
  logon: 'Accesso (Run, RunOnce, cartelle)',
  tasks: 'Attività pianificate',
  services: 'Servizi',
  drivers: 'Driver',
  wmi: 'Sottoscrizioni WMI',
  browser: 'Estensioni dei browser',
  winlogon: 'Winlogon',
  hijacks: 'Dirottamenti noti (IFEO, BootExecute, AppInit)',
  lsa: 'Pacchetti di sicurezza (LSA)',
  print: 'Monitor e processori di stampa',
  network: 'Provider di rete',
};

const SHORT: Record<AutorunCategory, string> = {
  logon: 'avvio all\'accesso',
  tasks: 'attività pianificata',
  services: 'servizio',
  drivers: 'driver',
  wmi: 'sottoscrizione WMI',
  browser: 'estensione',
  winlogon: 'Winlogon',
  hijacks: 'dirottamento noto',
  lsa: 'pacchetto di sicurezza',
  print: 'stampa',
  network: 'provider di rete',
};

/** Nome breve della categoria, per una voce dentro una frase ("servizio", "attività pianificata"). */
export function categoryShort(c: AutorunCategory): string {
  return SHORT[c] || c;
}

/** Nome della categoria dentro una frase: in minuscolo, tranne i nomi propri (Winlogon). */
export function categoryLower(c: AutorunCategory): string {
  return c === 'winlogon' ? categoryLabel(c) : lc1(categoryLabel(c));
}

/** Nome italiano della categoria. */
export function categoryLabel(c: AutorunCategory): string {
  return CATEGORY[c] || c;
}

const TRIGGER: Record<NonNullable<AutorunEntry['triggers']>[number], string> = {
  logon: 'all\'accesso',
  boot: 'all\'avvio',
  time: 'a un\'ora stabilita',
  daily: 'ogni giorno',
  weekly: 'ogni settimana',
  monthly: 'ogni mese',
  idle: 'con il PC inattivo',
  event: 'a un evento',
  registration: 'alla creazione o modifica dell\'attività',
  session: 'a connessione, disconnessione o blocco della sessione',
  other: 'altro',
};

/** Quando parte un'attività pianificata. */
export function triggerLabel(t: NonNullable<AutorunEntry['triggers']>[number]): string {
  return TRIGGER[t] || t;
}

const START: Record<NonNullable<AutorunEntry['start']>, string> = {
  boot: 'all\'avvio (driver di avvio)',
  system: 'all\'avvio del sistema',
  auto: 'automatico',
  delayed: 'automatico ritardato',
  manual: 'manuale',
  disabled: 'disabilitato',
};

/** Tipo di avvio di un servizio o di un driver. */
export function startLabel(s?: AutorunEntry['start']): string {
  return s ? START[s] : '';
}

const SOURCE: Record<NonNullable<AutorunEntry['source']>, string> = {
  store: 'dallo store',
  policy: 'imposta da criteri',
  external: 'installata da un altro programma',
  sideload: 'caricata dalla riga di comando',
  unpacked: 'caricata in modalità sviluppatore',
  component: 'componente del browser',
  default: 'preinstallata',
  other: 'altra origine',
};

/** Da dove viene un'estensione del browser. */
export function sourceLabel(s?: AutorunEntry['source']): string {
  return s ? SOURCE[s] : 'origine non letta';
}

const CONSUMER: Record<NonNullable<AutorunEntry['consumer']>, string> = {
  commandline: 'esegue un comando',
  activescript: 'esegue uno script',
  eventlog: 'scrive nel registro eventi',
  logfile: 'scrive in un file di log',
  smtp: 'invia un messaggio di posta',
  other: 'altra azione',
};

/** Che cosa fa una sottoscrizione WMI. */
export function consumerLabel(c?: AutorunEntry['consumer']): string {
  return c ? CONSUMER[c] : 'azione non letta';
}

const RUNAS: Record<NonNullable<AutorunEntry['runAs']>, string> = { system: 'SYSTEM', service: 'account di servizio', user: 'utente che ha effettuato l\'accesso', group: 'un gruppo di utenti', other: 'un altro account' };
/** Con quale account gira un'attività (solo la categoria). */
export const runAsLabel = (r?: AutorunEntry['runAs']) => (r ? RUNAS[r] : '');

const ACCOUNT: Record<NonNullable<AutorunEntry['account']>, string> = { system: 'LocalSystem', localservice: 'Servizio locale', networkservice: 'Servizio di rete', user: 'un account utente', other: 'un altro account' };
/** Account di un servizio (solo la categoria). */
export const accountLabel = (a?: AutorunEntry['account']) => (a ? ACCOUNT[a] : '');

const BROWSER: Record<NonNullable<AutorunEntry['browser']>, string> = { chrome: 'Chrome', edge: 'Edge', brave: 'Brave', firefox: 'Firefox' };
/** Nome del browser. */
export const browserLabel = (b?: AutorunEntry['browser']) => (b ? BROWSER[b] : 'browser');

/** Il file che conta per la voce: quello eseguito da rundll32, powershell... se c'è, altrimenti il file della voce. */
export const entryFile = (e: AutorunEntry): FileFacts | undefined => e.target || e.file;

/** Programmi di Windows che eseguono altro codice (MITRE T1218): la loro firma Microsoft non dice nulla su ciò che eseguono. */
const INTERPRETERS = ['powershell.exe', 'pwsh.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe'];
export const isInterpreter = (f?: FileFacts) => !!f && INTERPRETERS.indexOf(fileName(f.path).toLowerCase()) >= 0;

/** Comando interpretato senza un file da verificare (powershell -Command, cmd /c...). */
export const interpretedInline = (e: AutorunEntry) => !e.target && isInterpreter(e.file);

/** Voce di Microsoft: firma Microsoft del file che conta (mai l'autore dichiarato), senza comandi interpretati. */
const microsoftEntry = (e: AutorunEntry) => {
  const f = entryFile(e);
  return !interpretedInline(e) && !!f && isMicrosoftSigned(f.signature);
};

export type AutorunIssueKind = 'missing' | 'unsigned' | 'hijack' | 'wmi' | 'extensions' | 'unquoted' | 'tasks';

export interface AutorunIssue {
  entry: AutorunEntry;
  kind: AutorunIssueKind;
  severity: Severity;
  /** Perché la voce va guardata, in breve. */
  why: string;
}

const PRIVILEGED_SERVICE = (e: AutorunEntry) => e.category === 'drivers' || e.account === 'system';
const ACTIVE_START = (e: AutorunEntry) => e.enabled && (e.start === 'auto' || e.start === 'delayed' || e.start === 'boot' || e.start === 'system');

const sigWhy = (f: FileFacts) => `${lc1(signatureLabel(f.signature).text)}, ${folderLabel(f.folder)}`;

/**
 * Il programma e gli argomenti di un comando di Winlogon, come Split
 * dell'agente: fra virgolette il programma è il testo fra le virgolette;
 * senza virgolette un comando con spazi ha degli argomenti (o un percorso
 * con spazi, che non è mai quello di Windows).
 */
function splitCommand(cmd: string): { file: string; args: string } {
  const c = cmd.trim();
  if (c.charAt(0) !== '"') return { file: c, args: '' };
  const end = c.indexOf('"', 1);
  return end < 0 ? { file: c.slice(1).trim(), args: '' } : { file: c.slice(1, end), args: c.slice(end + 1).trim() };
}

/** Le parti di un valore separate da virgole (l'agente fa già una voce per programma: qui per i dati più vecchi). */
const commaParts = (cmd: string) =>
  cmd
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean);

/** Una parte del comando è esattamente il programma indicato, senza argomenti. */
const exactly = (part: string, re: RegExp) => {
  const c = splitCommand(part);
  return !c.args && re.test(c.file);
};

/** Il programma di Windows nella cartella di Windows: C:\Windows, %SystemRoot% o %windir%. */
const SHELL_RE = /^(?:explorer(?:\.exe)?|(?:[a-z]:\\windows|%systemroot%|%windir%)\\explorer\.exe)$/i;
const USERINIT_RE = /^(?:userinit(?:\.exe)?|(?:[a-z]:\\windows|%systemroot%|%windir%)\\system32\\userinit\.exe)$/i;

/**
 * Shell di Winlogon come quella di Windows, con la regola dell'agente
 * (defaultShell): «explorer.exe» o «explorer» senza cartella, oppure
 * explorer.exe nella cartella di Windows, sempre senza argomenti.
 */
export function isDefaultShell(cmd: string): boolean {
  const parts = commaParts(cmd);
  return parts.length > 0 && parts.every((p) => exactly(p, SHELL_RE));
}

/**
 * Userinit come quello di Windows, con la regola dell'agente
 * (defaultUserinit): «userinit.exe» o «userinit» senza cartella, oppure
 * userinit.exe in System32 della cartella di Windows, senza argomenti.
 */
export function isDefaultUserinit(cmd: string): boolean {
  const parts = commaParts(cmd);
  return parts.length > 0 && parts.every((p) => exactly(p, USERINIT_RE));
}

/** Opzione di autochk: «/q», «/k:C». */
const BOOT_OPTION = /^\/[a-z0-9]+(?::\S+)?$/i;
/** Volume: \??\C:, \DosDevices\C:, \??\Volume{guid}. */
const BOOT_VOLUME = /^(?:(?:\\\?\?\\|\\dosdevices\\)[a-z]:|\\\?\?\\volume\{[0-9a-f-]+\})$/i;

/**
 * Riga di BootExecute di Windows, con la stessa regola dell'agente
 * (isDefaultBootExecute): divisa in parole senza badare a spazi e maiuscole,
 * inizia con «autocheck autochk» e il resto sono solo opzioni («/q»,
 * «/k:C»), l'asterisco o volumi (\??\C:, \DosDevices\C:, \??\Volume{guid}),
 * con almeno un asterisco o un volume. «default»: la riga predefinita
 * (con l'asterisco); «scheduled»: un controllo del disco programmato da
 * Windows su un volume (chkdsk al riavvio); «other»: qualsiasi altra riga.
 */
export function bootExecuteKind(cmd: string): 'default' | 'scheduled' | 'other' {
  const w = cmd.trim().split(/\s+/);
  if (w.length < 3 || w[0].toLowerCase() !== 'autocheck' || w[1].toLowerCase() !== 'autochk') return 'other';
  let star = false;
  let volume = false;
  for (const x of w.slice(2)) {
    if (x === '*') star = true;
    else if (BOOT_VOLUME.test(x)) volume = true;
    else if (!BOOT_OPTION.test(x)) return 'other';
  }
  return volume ? 'scheduled' : star ? 'default' : 'other';
}

/** Strumenti di accessibilità che si aprono dalla schermata di accesso, prima di entrare (come SYSTEM). */
const ACCESSIBILITY = ['sethc.exe', 'utilman.exe', 'osk.exe', 'magnify.exe', 'narrator.exe', 'displayswitch.exe', 'atbroker.exe'];

function hijackIssue(e: AutorunEntry, secureBoot?: boolean): AutorunIssue | undefined {
  const cmd = (e.command || (e.file && e.file.path) || '').trim();
  const f = entryFile(e);
  const issue = (severity: Severity, why: string): AutorunIssue => ({ entry: e, kind: 'hijack', severity, why });
  switch (e.kind) {
    case 'shell':
      return isDefaultShell(cmd) ? undefined : issue('crit', `la shell di Windows non è explorer.exe della cartella di Windows (${cmd || 'vuota'})`);
    case 'userinit':
      return isDefaultUserinit(cmd) ? undefined : issue('crit', `Userinit non è userinit.exe della cartella di sistema (${cmd || 'vuoto'})`);
    case 'ifeo':
      // Il «debugger» di uno strumento di accessibilità parte dalla schermata di accesso come SYSTEM, senza password (MITRE T1546.008).
      if (ACCESSIBILITY.indexOf(e.name.toLowerCase()) >= 0) return issue('crit', `uno strumento di accessibilità della schermata di accesso (${e.name}) è sostituito da un altro programma (debugger IFEO): dalla schermata di accesso partirebbe quello, con i privilegi di sistema`);
      // Un debugger che non esiste impedisce al programma indicato di partire (si usa per bloccare antivirus e strumenti).
      if (f && f.missing) return issue('warn', `${e.name} non può partire: il «debugger» impostato non esiste`);
      return f && isMicrosoftSigned(f.signature) && !isInterpreter(f)
        ? issue('info', 'un programma firmato da Microsoft è impostato come «debugger» di un altro (per esempio Process Explorer al posto di Gestione attività)')
        : issue('warn', 'un altro programma parte al posto di quello indicato (debugger IFEO)');
    case 'silentexit':
      return issue('warn', 'un programma viene avviato quando un altro si chiude (SilentProcessExit)');
    case 'bootexecute': {
      const k = bootExecuteKind(cmd);
      if (k === 'default') return undefined;
      if (k === 'scheduled') return issue('info', `controllo del disco programmato da Windows al prossimo riavvio, come chkdsk (${cmd})`);
      return issue('warn', `BootExecute diverso da quello di Windows, «autocheck autochk *» (${cmd})`);
    }
    case 'appinit':
      if (!e.enabled || !cmd) return undefined;
      return secureBoot ? issue('info', 'AppInit_DLLs impostato ma inattivo, perché Secure Boot è attivo') : issue('warn', 'AppInit_DLLs attivo: una DLL viene caricata in ogni programma con interfaccia grafica');
  }
  if (e.category === 'lsa' || e.category === 'print' || e.category === 'network') {
    if (!f || f.missing || isMicrosoftSigned(f.signature)) return undefined;
    const s = f.signature;
    if (s && SIG_CRIT.indexOf(s.status) >= 0) return issue('crit', `DLL di sistema con ${sigWhy(f)}`);
    if (s && s.status === 'valid') return issue('info', `DLL di ${s.signer || 'un altro produttore'} caricata da un componente di sistema`);
    return issue('warn', `DLL caricata da un componente di sistema: ${sigWhy(f)}`);
  }
  return undefined;
}

/** Tutte le voci da guardare, ciascuna con il giudizio a cui appartiene. */
export function autorunIssues(scan: Scan): AutorunIssue[] {
  const data = scan.pc && scan.pc.autoruns;
  if (!data) return [];
  const hw = scan.pc && scan.pc.hardware;
  const secureBoot = hw && hw.secureBoot === true;
  const managed = !!scan.agent.domain;
  const out: AutorunIssue[] = [];
  const push = (entry: AutorunEntry, kind: AutorunIssueKind, severity: Severity, why: string) => out.push({ entry, kind, severity, why });
  for (const e of data.entries) {
    const f = entryFile(e);
    const s = f && f.signature;
    // File mancante (tutte le categorie tranne le estensioni; per un debugger IFEO mancante decide hijackIssue: blocca il programma).
    if (e.category !== 'browser' && e.kind !== 'ifeo' && f && f.missing) {
      const svc = (e.category === 'services' || e.category === 'drivers') && ACTIVE_START(e);
      push(e, 'missing', svc ? 'warn' : 'info', `file mancante${e.scope === 'machine32' ? ' (voce a 32 bit: da verificare anche in Program Files (x86))' : ''}`);
      continue;
    }
    // Dirottamenti noti e componenti di sistema (Winlogon, IFEO, BootExecute, AppInit, LSA, stampa, rete).
    if (e.category === 'winlogon' || e.category === 'hijacks' || e.category === 'lsa' || e.category === 'print' || e.category === 'network') {
      const h = hijackIssue(e, secureBoot);
      if (h) out.push(h);
      continue;
    }
    if (e.category === 'wmi') {
      if (e.consumer === 'eventlog' && /^SCM Event Log Consumer$/i.test(e.name)) continue;
      const exec = e.consumer === 'commandline' || e.consumer === 'activescript';
      if (exec && e.bound) push(e, 'wmi', 'crit', `sottoscrizione WMI che ${consumerLabel(e.consumer)} come SYSTEM a ogni evento`);
      else if (exec) push(e, 'wmi', 'info', `sottoscrizione WMI che ${consumerLabel(e.consumer)}, non collegata a un filtro: resto inattivo`);
      else push(e, 'wmi', 'info', `sottoscrizione WMI di un altro produttore che ${consumerLabel(e.consumer)}`);
      continue;
    }
    if (e.category === 'browser') {
      if (e.source === 'component') continue;
      const risky =
        e.enabled &&
        ((e.source === 'policy' && !managed) || e.source === 'unpacked' || e.source === 'sideload' || (!!e.allSites && (e.source === 'external' || e.source === 'other')));
      const sites = e.allSites ? ', può leggere e modificare tutti i siti' : '';
      push(e, 'extensions', risky ? 'warn' : 'info', `${browserLabel(e.browser)}: ${sourceLabel(e.source)}${e.source === 'policy' && !managed ? ' su un PC che non è in un dominio Active Directory' : ''}${sites}${e.enabled ? '' : ', disattivata'}`);
      continue;
    }
    if (e.category === 'services' && e.unquoted) {
      push(e, 'unquoted', e.interceptors ? 'warn' : 'info', e.interceptors ? `percorso senza virgolette: ${num(e.interceptors, 'file intercettore esiste già', 'file intercettori esistono già')}` : 'percorso con spazi senza virgolette, nessun file intercettore');
    }
    if (!f || !s) continue;
    if (e.category === 'tasks') {
      // Decide la firma del file: l'autore dichiarato («Microsoft») lo scrive
      // chi crea l'attività, ed è una tecnica nota di mascheramento (MITRE
      // T1036.004). Serve solo a non elencare tra le voci da conoscere le
      // attività di Windows che eseguono comandi interpretati o sono nascoste.
      if (SIG_CRIT.indexOf(s.status) >= 0) push(e, 'tasks', 'crit', sigWhy(f));
      else if (!e.enabled || microsoftEntry(e)) continue;
      else if (SIG_WARN.indexOf(s.status) >= 0) push(e, 'tasks', 'warn', `${sigWhy(f)}${e.authorMicrosoft ? ', autore dichiarato Microsoft' : ''}`);
      else if (userWritable(f.folder)) {
        const sys = e.runAs === 'system';
        const priv = sys || e.runAs === 'service' || !!e.highest;
        const valid = s.status === 'valid';
        const author = e.authorMicrosoft ? ', autore dichiarato Microsoft' : '';
        if (!valid && sys) push(e, 'tasks', 'crit', `${sigWhy(f)}, con privilegi di sistema${author}`);
        else if (!valid || priv || e.hidden) push(e, 'tasks', 'warn', `${sigWhy(f)}${sys ? ', con privilegi di sistema' : priv ? ', con privilegi elevati' : ''}${e.hidden ? ', attività nascosta' : ''}${author}`);
        else push(e, 'tasks', 'info', `${sigWhy(f)}: di solito un aggiornatore installato per l'utente`);
      } else if (e.authorMicrosoft) continue;
      else if (interpretedInline(e)) push(e, 'tasks', 'info', `comando eseguito da ${fileName(f.path)}: la firma di Microsoft dell'interprete non dice nulla su ciò che esegue`);
      else if (e.hidden && (e.triggers || []).some((t) => t === 'logon' || t === 'boot')) push(e, 'tasks', 'info', 'attività di un altro produttore nascosta, che parte all\'accesso o all\'avvio');
      continue;
    }
    if (e.category === 'logon' || e.category === 'services' || e.category === 'drivers') {
      // Account di un servizio non letto: non si sa se gira come SYSTEM, e non lo si presume.
      const account = PRIVILEGED_SERVICE(e) ? ', con privilegi di sistema' : e.category === 'services' && !e.account ? ', account non letto' : '';
      if (SIG_CRIT.indexOf(s.status) >= 0) push(e, 'unsigned', 'crit', sigWhy(f));
      else if (!e.enabled || microsoftEntry(e)) continue;
      else if (userWritable(f.folder) && s.status !== 'valid') push(e, 'unsigned', PRIVILEGED_SERVICE(e) ? 'crit' : 'warn', `${sigWhy(f)}${account}`);
      else if (userWritable(f.folder) && PRIVILEGED_SERVICE(e)) push(e, 'unsigned', 'warn', `${sigWhy(f)}, con privilegi di sistema`);
      else if (SIG_WARN.indexOf(s.status) >= 0) push(e, 'unsigned', 'warn', sigWhy(f));
      else if (interpretedInline(e)) push(e, 'unsigned', 'info', `comando eseguito da ${fileName(f.path)}: la firma di Microsoft dell'interprete non dice nulla su ciò che esegue`);
    }
  }
  return out;
}

const RANK: Record<Severity, number> = { unknown: 0, ok: 1, info: 2, warn: 3, crit: 4 };
const worstOf = (list: AutorunIssue[]): Severity => list.reduce<Severity>((a, x) => (RANK[x.severity] > RANK[a] ? x.severity : a), 'ok');
const listText = (list: AutorunIssue[], n = 4) =>
  list
    .slice(0, n)
    .map((x) => `${x.entry.name} (${x.why})`)
    .join('; ') + more(list.length, n);
const byWorst = (list: AutorunIssue[]) => list.slice().sort((a, b) => RANK[b.severity] - RANK[a.severity]);

/** Categorie lette solo in parte senza amministratore, in italiano. */
function deniedText(denied: AutorunCategory[], among: AutorunCategory[]): string {
  const d = denied.filter((c) => among.indexOf(c) >= 0);
  return d.length ? `${d.map((c) => categoryLower(c)).join(', ')}: si leggono solo in parte senza amministratore, da verificare da amministratore.` : '';
}

/** Giudizi sull'avvio automatico esteso. */
export function analyzeAutoruns(scan: Scan, add: Add) {
  const data = scan.pc && scan.pc.autoruns;
  if (!data) return;
  const issues = autorunIssues(scan);
  const denied = data.denied || [];
  const of = (k: AutorunIssueKind) => byWorst(issues.filter((x) => x.kind === k));
  const partial = data.partial ? ' La lettura non è finita in tempo: l\'elenco può essere incompleto.' : '';

  // File mancanti.
  const miss = of('missing');
  if (miss.length) {
    const sev = worstOf(miss);
    add({
      id: 'pc.autoruns.missing',
      metric: 'pc.autoruns.missing',
      category: 'pc',
      title: 'Avvio automatico: file mancanti',
      value: num(miss.length, 'voce punta a un file mancante', 'voci puntano a file mancanti'),
      numeric: miss.length,
      severity: sev,
      verdict:
        `${miss
          .slice(0, 4)
          .map((x) => `${x.entry.name} (${categoryShort(x.entry.category)})`)
          .join('; ')}${more(miss.length, 4)}. ` +
        (sev === 'warn'
          ? 'Un servizio automatico o un driver che parte all\'avvio senza il suo file provoca un errore a ogni accensione: di solito è un programma disinstallato male.'
          : 'Di solito è un programma disinstallato male: la voce resta ma non fa nulla, e si può togliere.'),
      actions: ['review-startup-entry'],
    });
  }

  // File non firmati o con firma non valida (accesso, servizi, driver).
  const uns = of('unsigned');
  const unsDenied = deniedText(denied, ['logon', 'services', 'drivers']);
  {
    // Con categorie lette solo in parte non si dice mai «nessun problema».
    const sev: Severity = uns.length ? worstOf(uns) : unsDenied ? 'info' : 'ok';
    const bad = uns.filter((x) => x.severity === 'warn' || x.severity === 'crit');
    add({
      id: 'pc.autoruns.unsigned',
      metric: 'pc.autoruns.unsigned',
      category: 'pc',
      title: 'Avvio automatico: firme e cartelle',
      value: bad.length
        ? num(bad.length, 'voce da controllare', 'voci da controllare')
        : uns.length
          ? num(uns.length, 'comando interpretato', 'comandi interpretati')
          : unsDenied
            ? 'nulla tra le voci lette, il resto da verificare da amministratore'
            : 'nessuna voce da controllare',
      numeric: bad.length,
      severity: sev,
      verdict:
        (uns.length
          ? `${listText(uns)}. ` +
            (sev === 'crit'
              ? 'Un file alterato dopo la firma, o un programma senza firma valida in una cartella che un utente può scrivere ma avviato con i privilegi di sistema, è il caso più delicato: chiunque scriva in quella cartella può far girare codice come SYSTEM. Va controllato subito.'
              : sev === 'warn'
                ? 'Un programma senza firma in una cartella che un utente può scrivere (AppData, Download, ProgramData, cartelle create nella radice del disco), avviato da solo, non è per forza pericoloso ma va riconosciuto: verifica da dove viene.'
                : 'Sono comandi eseguiti da un programma di Windows (PowerShell, cmd, script): la firma di Microsoft dell\'interprete non dice nulla su ciò che eseguono.')
          : 'Nelle voci lette (accesso, servizi e driver) nessun programma avviato da solo è senza firma in una cartella che un utente può scrivere o con una firma alterata.') +
        (unsDenied ? ` ${unsDenied}` : '') +
        partial,
      actions: sev === 'crit' ? ['defender-scan-file', 'check-file-origin', 'review-startup-entry'] : sev === 'warn' ? ['check-file-origin', 'defender-scan-file', 'review-startup-entry'] : [],
    });
  }

  // Dirottamenti noti.
  const hij = of('hijack');
  const hijDenied = deniedText(denied, ['winlogon', 'hijacks', 'lsa', 'print', 'network']);
  {
    const sev: Severity = hij.length ? worstOf(hij) : hijDenied ? 'info' : 'ok';
    add({
      id: 'pc.autoruns.hijack',
      metric: 'pc.autoruns.hijack',
      category: 'pc',
      title: 'Avvio automatico: dirottamenti noti',
      value: hij.length ? num(hij.length, 'voce da controllare', 'voci da controllare') : hijDenied ? 'nessuno tra le voci lette' : 'nessuno',
      numeric: hij.length,
      severity: sev,
      verdict: hij.length
        ? `${listText(hij)}. ` +
          (sev === 'crit'
            ? 'Shell e Userinit di Winlogon, gli strumenti di accessibilità della schermata di accesso e le DLL dei componenti di sistema decidono che cosa parte all\'accesso o dentro Windows: un valore diverso da quello di Windows, o un file alterato, è una tecnica nota per far partire un programma prima di tutto il resto o con i privilegi di sistema. Va controllato subito, da un tecnico.'
            : sev === 'warn'
              ? 'Sono punti di Windows usati anche da programmi legittimi (antivirus, strumenti di disco o di diagnostica), ma raramente: ogni voce va riconosciuta, da un tecnico.'
              : 'Sono voci da conoscere in punti delicati di Windows: un controllo del disco programmato da Windows, un «debugger» firmato da Microsoft, DLL di altri produttori normali per alcuni antivirus, VPN e stampanti. Da controllare se non le riconosci.')
        : `Shell e Userinit di Winlogon sono quelli di Windows; nessun debugger IFEO, BootExecute diverso da quello di Windows o AppInit attivo, e nessuna DLL senza firma nei pacchetti di sicurezza, nella stampa o nei provider di rete.${hijDenied ? ` ${hijDenied}` : ''}`,
      actions: sev === 'crit' || sev === 'warn' ? ['review-startup-entry', 'defender-scan-file'] : hij.length ? ['review-startup-entry'] : [],
    });
  }

  // Sottoscrizioni WMI permanenti.
  const wmi = of('wmi');
  if (wmi.length || denied.indexOf('wmi') >= 0) {
    const sev: Severity = wmi.length ? worstOf(wmi) : 'unknown';
    add({
      id: 'pc.autoruns.wmi',
      metric: 'pc.autoruns.wmi',
      category: 'pc',
      title: 'Avvio automatico: sottoscrizioni WMI',
      value: wmi.length ? num(wmi.length, 'sottoscrizione', 'sottoscrizioni') : 'da verificare da amministratore',
      numeric: wmi.length,
      severity: sev,
      verdict: wmi.length
        ? `${listText(wmi)}. ` +
          (sev === 'crit'
            ? 'Una sottoscrizione WMI che esegue un comando o uno script parte da sola a ogni evento indicato, come SYSTEM, e non compare tra i programmi all\'avvio: è una tecnica nota di persistenza. A volte la usano programmi di gestione aziendali: va riconosciuta, da un tecnico.'
            : 'Sono sottoscrizioni WMI di altri programmi che non eseguono comandi, o che non sono collegate a un evento: da riconoscere, ma non partono da sole.') +
          (denied.indexOf('wmi') >= 0 ? ' Lo spazio WMI si legge solo in parte senza amministratore: da verificare da amministratore.' : '')
        : 'Le sottoscrizioni WMI permanenti si leggono solo avviando Polaris come amministratore: da verificare da amministratore.',
      actions: sev === 'crit' ? ['review-wmi-subscription', 'defender-scan-file'] : wmi.length ? ['review-wmi-subscription'] : [],
    });
  }

  // Estensioni dei browser.
  const ext = of('extensions');
  if (ext.length) {
    const risky = ext.filter((x) => x.severity === 'warn');
    const active = ext.filter((x) => x.entry.enabled).length;
    add({
      id: 'pc.autoruns.extensions',
      metric: 'pc.autoruns.extensions',
      category: 'pc',
      title: 'Estensioni dei browser',
      value: risky.length ? num(risky.length, 'estensione da controllare', 'estensioni da controllare') : num(active, 'estensione attiva', 'estensioni attive'),
      numeric: risky.length,
      severity: risky.length ? 'warn' : 'info',
      verdict: risky.length
        ? `${listText(risky)}. Un'estensione imposta da criteri non si può togliere dal browser: su un PC che non è in un dominio Active Directory è normale se il PC è gestito dall'organizzazione con Intune o Microsoft Entra ID, altrimenti è un modo noto per installare pubblicità o spiare la navigazione. Una caricata in modalità sviluppatore o dalla riga di comando non è passata dallo store. Se non la riconosci, toglila.`
        : `${num(active, 'estensione attiva', 'estensioni attive')} nei browser di questo utente, nessuna con segnali da controllare. Ogni estensione vede le pagine su cui ha permessi: tieni solo quelle che usi.`,
      actions: risky.length ? ['remove-browser-extension'] : [],
    });
  }

  // Servizi con percorso senza virgolette.
  const unq = of('unquoted');
  if (unq.length) {
    const inter = unq.filter((x) => x.severity === 'warn');
    add({
      id: 'pc.autoruns.unquoted',
      metric: 'pc.autoruns.unquoted',
      category: 'pc',
      title: 'Servizi con percorso senza virgolette',
      value: inter.length ? num(inter.length, 'servizio con un file intercettore', 'servizi con un file intercettore') : num(unq.length, 'servizio', 'servizi'),
      numeric: inter.length,
      severity: inter.length ? 'warn' : 'info',
      verdict:
        `${listText(unq)}. Se il percorso del programma contiene spazi e non è tra virgolette, Windows prova prima i percorsi più corti (per esempio C:\\Program.exe). ` +
        (inter.length
          ? 'Uno di quei file esiste già: all\'avvio del servizio verrebbe eseguito al posto del programma giusto, di solito come SYSTEM. Va controllato subito, da un tecnico.'
          : 'Nessuno di quei file esiste e i permessi di Windows di solito impediscono di crearli: è un difetto di installazione da correggere con calma, non un pericolo immediato.'),
      actions: inter.length ? ['fix-unquoted-service-path', 'defender-scan-file'] : ['fix-unquoted-service-path'],
    });
  }

  // Attività pianificate di altri produttori.
  const tasks = of('tasks');
  if (tasks.length || denied.indexOf('tasks') >= 0) {
    const sev: Severity = tasks.length ? worstOf(tasks) : 'unknown';
    const bad = tasks.filter((x) => x.severity === 'warn' || x.severity === 'crit');
    add({
      id: 'pc.autoruns.tasks',
      metric: 'pc.autoruns.tasks',
      category: 'pc',
      title: 'Attività pianificate di altri produttori',
      value: tasks.length ? (bad.length ? num(bad.length, 'attività da controllare', 'attività da controllare') : num(tasks.length, 'attività da conoscere', 'attività da conoscere')) : 'da verificare da amministratore',
      numeric: bad.length,
      severity: sev,
      verdict: tasks.length
        ? `${listText(byWorst(tasks))}. ` +
          (sev === 'crit' || sev === 'warn'
            ? 'Un\'attività che esegue un programma da una cartella che un utente può scrivere, senza firma valida, nascosta o con privilegi elevati, è il modo più comune per far ripartire un programma indesiderato, anche quando l\'autore dichiarato è Microsoft: verifica da dove viene.'
            : 'Sono attività di altri produttori, di solito aggiornatori installati per l\'utente: da conoscere, non da togliere per forza.') +
          (denied.indexOf('tasks') >= 0 ? ' Senza amministratore si vedono solo le attività leggibili da questo utente: le altre sono da verificare da amministratore.' : '')
        : 'Senza amministratore si vedono solo le attività pianificate leggibili da questo utente, e tra queste non c\'è nulla da segnalare: le altre sono da verificare da amministratore.',
      actions: sev === 'crit' ? ['defender-scan-file', 'check-file-origin', 'review-startup-entry'] : sev === 'warn' ? ['check-file-origin', 'review-startup-entry'] : tasks.length ? ['review-startup-entry'] : [],
    });
  }
}

/** Conteggi per categoria nell'ordine di Autoruns: totale e voci di Microsoft. */
export function autorunCounts(scan: Scan): { category: AutorunCategory; total: number; microsoft: number }[] {
  const data = scan.pc && scan.pc.autoruns;
  if (!data) return [];
  const counts = data.counts || {};
  const out: { category: AutorunCategory; total: number; microsoft: number }[] = [];
  for (const c of AUTORUN_CATEGORIES) {
    const v = counts[c];
    const listed = data.entries.filter((e) => e.category === c).length;
    if (!v && !listed) continue;
    out.push({ category: c, total: v ? v.total : listed, microsoft: (v && v.microsoft) || 0 });
  }
  return out;
}
