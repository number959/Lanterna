import { more, num } from './fmt';
import type { FileFacts, FileSignature, Finding, FolderKind, ProcessDetail, Scan, Severity } from './types';

// Processi con firma digitale e connessioni, come Process Explorer: giudizi
// sempre formulati come «da controllare», mai come prova di malware. Ricerca
// del 17/11/2026, fonti:
// - codici di WinVerifyTrust (Microsoft Learn, «COM Error Codes (Security
//   and Setup)»): firma alterata, revocata o firmatario bloccato sono i casi
//   gravi; scaduta, radice non riconosciuta, uso non previsto vanno visti;
// - App Control for Business («Filepath rules don't provide the same
//   security guarantees that explicit signer rules do», regole solo su
//   cartelle scrivibili dai soli amministratori), regole ASR di Defender
//   («Block use of copied or impersonated system tools» tratta come strumenti
//   di sistema i file in %windir%\System32 e SysWOW64), Sigcheck («You
//   should investigate the purpose of any files that are not signed»), CISA
//   AA23-278A;
// - MIB_TCPROW_OWNER_PID («A value of zero indicates the listener can accept
//   a connection on any interface») e Windows Firewall (blocca il traffico in
//   ingresso non richiesto, salvo regole): Polaris non legge le singole regole.
// La firma si verifica senza rete: la revoca dei certificati non si controlla
// online. Senza amministratore alcuni processi non si aprono: si contano.

type Add = (f: Omit<Finding, 'actions'> & { actions?: string[] }) => void;

export type Tone = 'ok' | 'info' | 'warn' | 'crit' | 'unknown';

/**
 * Cartelle che un utente senza privilegi può scrivere (come sign.UserWritable
 * dell'agente). Con i permessi predefiniti di Windows un utente crea cartelle
 * e file anche in C:\ProgramData (BUILTIN\Users: crea file e cartelle) e
 * nelle cartelle create nella radice di un disco (Authenticated Users:
 * modifica): "programData" e "other" non sono protette. Protette sono solo
 * Programmi e la cartella di Windows, dove scrive solo l'amministratore.
 */
const USER_WRITABLE: FolderKind[] = ['appData', 'temp', 'downloads', 'profile', 'removable', 'network', 'programData', 'other'];
export const userWritable = (folder?: FolderKind) => !!folder && USER_WRITABLE.indexOf(folder) >= 0;

/** Cartelle protette: Programmi e la cartella di Windows. */
export const protectedFolder = (folder?: FolderKind) => folder === 'windows' || folder === 'programFiles';

/** Firme gravi: il file è stato cambiato dopo la firma, o il certificato è revocato o bloccato. */
export const SIG_CRIT = ['tampered', 'revoked', 'distrusted'];
/** Firme da guardare: scadute, autorità non riconosciuta, certificato non adatto, firma non valida. */
export const SIG_WARN = ['expired', 'untrustedRoot', 'wrongUsage', 'invalid'];

/** Firma valida di Microsoft per un componente suo (non i driver di altri rifirmati da Microsoft). */
export const isMicrosoftSigned = (s?: FileSignature) => !!s && s.status === 'valid' && !!s.microsoft;

/** Testo e tono della firma per tabella, rapporto e documento. */
export function signatureLabel(sig?: FileSignature): { text: string; tone: Tone } {
  if (!sig) return { text: 'Firma non verificata', tone: 'unknown' };
  switch (sig.status) {
    case 'valid':
      return { text: `Firma verificata${sig.signer ? ` · ${sig.signer}` : ''}${sig.catalog ? ' (catalogo di Windows)' : ''}`, tone: 'ok' };
    case 'unsigned':
      return { text: 'Nessuna firma digitale', tone: 'info' };
    case 'tampered':
      return { text: 'File modificato dopo la firma', tone: 'crit' };
    case 'revoked':
      return { text: `Certificato revocato${sig.signer ? ` · ${sig.signer}` : ''}`, tone: 'crit' };
    case 'distrusted':
      return { text: `Firmatario bloccato su questo PC${sig.signer ? ` · ${sig.signer}` : ''}`, tone: 'crit' };
    case 'expired':
      return { text: `Firma scaduta${sig.signer ? ` · ${sig.signer}` : ''}`, tone: 'warn' };
    case 'untrustedRoot':
      return { text: `Firmato da un'autorità non riconosciuta da Windows${sig.signer ? ` · ${sig.signer}` : ''}`, tone: 'warn' };
    case 'wrongUsage':
      return { text: 'Certificato non previsto per firmare programmi', tone: 'warn' };
    case 'policy':
      return { text: 'Non attendibile per le impostazioni di questo PC', tone: 'info' };
    case 'invalid':
      return { text: 'Firma non valida', tone: 'warn' };
    case 'unreadable':
      return { text: 'File non leggibile: firma da verificare', tone: 'unknown' };
    default:
      return { text: `Firma da verificare${sig.code ? ` (codice ${sig.code})` : ''}`, tone: 'unknown' };
  }
}

const FOLDER: Record<FolderKind, string> = {
  windows: 'cartella di Windows',
  programFiles: 'Programmi',
  programData: 'ProgramData (dati dei programmi)',
  appData: 'AppData dell\'utente',
  temp: 'cartella temporanea',
  downloads: 'Download',
  profile: 'cartella dell\'utente',
  removable: 'unità rimovibile',
  network: 'unità di rete',
  other: 'altra cartella',
};

/** Tipo di cartella in italiano. */
export function folderLabel(folder?: FolderKind): string {
  return folder ? FOLDER[folder] || folder : 'cartella non letta';
}

const OWNER: Record<NonNullable<ProcessDetail['owner']>, string> = { self: 'questo utente', system: 'sistema', other: 'altro account', unknown: 'non leggibile' };

/** Utente del processo, solo per categoria. */
export function ownerLabel(owner?: ProcessDetail['owner']): string {
  return owner ? OWNER[owner] : 'non leggibile';
}

/** La prima lettera in minuscolo, per inserire un'etichetta in una frase senza toccare i nomi propri. */
export const lc1 = (s: string) => s.charAt(0).toLowerCase() + s.slice(1);

/** Nome del file da un percorso di Windows. */
export const fileName = (path?: string) => (path || '').split(/[\\/]/).pop() || '';

/** Processi su cui si danno giudizi: tutti tranne STARNET Polaris e le sue finestre. */
const judged = (p: ProcessDetail) => !p.polaris;

/**
 * Processo del nucleo di Windows senza un file da verificare (System, PID 4;
 * Registry, Memory Compression, Secure System), con la stessa regola di
 * kernelPseudo dell'agente: PID 0 e 4, e i figli di System senza «.exe» nel
 * nome. Il nome da solo non basta: un processo qualsiasi può chiamarsi
 * «Registry» o «Idle», e se non si è potuto leggere resta non verificato.
 */
export const isKernelProc = (p: ProcessDetail) => p.pid === 0 || p.pid === 4 || (p.parentPid === 4 && !/\.exe$/i.test(p.name || ''));

export interface ProcGroup {
  file: FileFacts;
  names: string[];
  count: number;
  procs: ProcessDetail[];
}

/**
 * I processi raggruppati per file eseguibile: lo stesso file si giudica una
 * volta. La chiave comprende l'esito della verifica: i percorsi sono già
 * ripuliti (C:\Users\‹utente›\...), e i file di due utenti diversi con lo
 * stesso percorso ripulito ma firme diverse restano due gruppi.
 */
export function procGroups(items: ProcessDetail[]): ProcGroup[] {
  const map: { [k: string]: ProcGroup } = {};
  const out: ProcGroup[] = [];
  for (const p of items) {
    if (!judged(p) || !p.file || !p.file.path) continue;
    const s = p.file.signature;
    const k = [p.file.path.toLowerCase(), s ? s.status : '', (s && s.signer) || '', (s && s.code) || '', p.file.folder || '', p.file.missing ? 'mancante' : ''].join('|');
    let g = map[k];
    if (!g) {
      g = map[k] = { file: p.file, names: [], count: 0, procs: [] };
      out.push(g);
    }
    if (g.names.indexOf(p.name) < 0) g.names.push(p.name);
    g.count++;
    g.procs.push(p);
  }
  return out;
}

/** Gravità di un file eseguito: firma grave, firma da guardare, senza firma in una cartella che un utente può scrivere. */
export function fileSeverity(f?: FileFacts): Severity {
  const s = f && f.signature;
  if (!f || !s) return 'unknown';
  if (SIG_CRIT.indexOf(s.status) >= 0) return 'crit';
  if (SIG_WARN.indexOf(s.status) >= 0) return 'warn';
  if (s.status === 'unsigned' && userWritable(f.folder)) return 'warn';
  if (s.status === 'policy' || s.status === 'unsigned') return 'info';
  if (s.status === 'valid') return 'ok';
  return 'unknown';
}

const RANK: Record<Severity, number> = { unknown: 0, ok: 1, info: 2, warn: 3, crit: 4 };
const worst = (a: Severity, b: Severity): Severity => (RANK[b] > RANK[a] ? b : a);

const groupText = (g: ProcGroup) => `${g.names[0]}${g.count > 1 ? ` (${g.count} processi)` : ''}: ${lc1(signatureLabel(g.file.signature).text)}, ${folderLabel(g.file.folder)}`;

/** Nomi dei programmi di Windows che girano solo da System32 (o da %windir% per explorer.exe). */
export const SYSTEM_NAMES = ['svchost.exe', 'lsass.exe', 'csrss.exe', 'services.exe', 'winlogon.exe', 'smss.exe', 'explorer.exe', 'wininit.exe', 'lsaiso.exe', 'taskhostw.exe', 'dllhost.exe', 'conhost.exe', 'spoolsv.exe', 'rundll32.exe'];

/** Un processo col nome di un programma di Windows avviato da un'altra cartella. */
export function isLookalike(p: ProcessDetail): boolean {
  const name = (p.name || '').toLowerCase();
  if (SYSTEM_NAMES.indexOf(name) < 0 || !p.file || !p.file.path) return false;
  const path = p.file.path.toLowerCase().replace(/\//g, '\\');
  // Il percorso dentro la cartella di Windows, se lo è.
  const m = /^(?:[a-z]:\\windows|%systemroot%|%windir%)\\(.*)$/.exec(path);
  if (!m) return true;
  if (/^(?:system32|syswow64|sysnative)\\[^\\]+$/.test(m[1])) return false;
  return !(name === 'explorer.exe' && m[1] === 'explorer.exe');
}

const firewallOff = (scan: Scan) => !!scan.firewall && scan.firewall.profiles.some((p) => p.active && p.enabled === false);

/** Un programma in ascolto su tutte le reti, con l'esito della verifica. */
export interface Listener {
  proc: ProcessDetail;
  ports: number[];
  /** Da controllare: firma non valida, o file in una cartella che un utente può scrivere. */
  risky: boolean;
  /**
   * Non verificato: senza amministratore il processo non si apre, oppure il
   * file non ha una firma verificata (lettura non finita in tempo, file non
   * leggibile). Né da controllare né a posto: si dice che non si sa.
   */
  unverified: boolean;
  /** Nucleo di Windows (System, PID 4): non ha un file da verificare. */
  kernel: boolean;
}

/** Programmi in ascolto su tutte le interfacce (TCP), con la gravità di ciascuno. */
export function listeners(scan: Scan): Listener[] {
  const items = (scan.pc && scan.pc.procs && scan.pc.procs.items) || [];
  const out: Listener[] = [];
  for (const p of items) {
    if (!judged(p)) continue;
    const ports = (p.listen || []).filter((l) => l.proto === 'tcp' && l.scope === 'all').map((l) => l.port);
    if (!ports.length) continue;
    const uniq = ports.filter((x, i) => ports.indexOf(x) === i).sort((a, b) => a - b);
    const f = p.file && p.file.path && p.access !== 'none' ? p.file : undefined;
    const sig = f && f.signature;
    const kernel = !f && p.access !== 'none' && isKernelProc(p);
    const risky = !!f && ((!!sig && sig.status !== 'valid' && sig.status !== 'unreadable' && sig.status !== 'unknown') || userWritable(f.folder));
    const unverified = !risky && !kernel && (!f || !sig || sig.status === 'unreadable' || sig.status === 'unknown');
    out.push({ proc: p, ports: uniq, risky, unverified, kernel });
  }
  return out;
}

/** Giudizi sui processi: firme, programmi in ascolto, nomi di Windows fuori posto, processi non leggibili. */
export function analyzeProcs(scan: Scan, add: Add) {
  const data = scan.pc && scan.pc.procs;
  if (!data) return;
  const items = data.items.filter(judged);
  const groups = procGroups(items);

  // Firma digitale dei programmi in esecuzione.
  if (groups.some((g) => g.file.signature)) {
    const bad = groups.map((g) => ({ g, sev: fileSeverity(g.file) })).filter((x) => x.sev === 'crit' || x.sev === 'warn');
    bad.sort((a, b) => RANK[b.sev] - RANK[a.sev]);
    const status = (g: ProcGroup) => (g.file.signature ? g.file.signature.status : undefined);
    const verified = groups.filter((g) => status(g) === 'valid').length;
    // Senza firma ma non da controllare: in Programmi o nella cartella di Windows, o in una cartella non letta.
    const unsignedProt = groups.filter((g) => status(g) === 'unsigned' && protectedFolder(g.file.folder)).length;
    const unsignedNoFolder = groups.filter((g) => status(g) === 'unsigned' && !g.file.folder).length;
    const policy = groups.filter((g) => status(g) === 'policy').length;
    const unchecked = groups.filter((g) => !g.file.signature || status(g) === 'unknown' || status(g) === 'unreadable').length;
    const crit = bad.some((b) => b.sev === 'crit');
    let sev: Severity = policy ? 'info' : 'ok';
    for (const b of bad) sev = worst(sev, b.sev);
    // Nessun file verificato e nessuno da controllare: non si sa.
    if (!bad.length && !verified && !policy && !unsignedProt && !unsignedNoFolder) sev = 'unknown';
    const policyText = policy
      ? `${policy === 1 ? '1 programma non è attendibile' : `${policy} programmi non sono attendibili`} per le impostazioni di questo PC (criteri di Windows o App Control): verifica che sia voluto`
      : '';
    const okParts: string[] = [];
    if (unsignedProt)
      okParts.push(`${unsignedProt === 1 ? '1 programma senza firma è installato' : `${unsignedProt} programmi senza firma sono installati`} in Programmi o nella cartella di Windows, dove scrive solo l'amministratore`);
    if (unsignedNoFolder) okParts.push(`${num(unsignedNoFolder, 'programma è', 'programmi sono')} senza firma, in una cartella non riconosciuta`);
    if (policyText) okParts.push(policyText);
    add({
      id: 'pc.procs.signature',
      metric: 'pc.procs.signature',
      category: 'pc',
      title: 'Firma dei programmi in esecuzione',
      value: bad.length ? `${num(bad.length, 'programma da controllare', 'programmi da controllare')} su ${groups.length}` : `${verified} su ${groups.length} con firma verificata`,
      numeric: bad.length,
      severity: sev,
      verdict: bad.length
        ? `Da controllare: ${bad
            .slice(0, 4)
            .map((b) => groupText(b.g))
            .join('; ')}${more(bad.length, 4)}. ` +
          (crit
            ? 'Un file modificato dopo la firma, o con un certificato revocato o bloccato, non è quello pubblicato dal produttore: può essere danneggiato o alterato. Analizzalo con Microsoft Defender e verifica da dove viene.'
            : 'Un programma senza firma in una cartella che un utente può scrivere (AppData, Download, ProgramData, cartelle create nella radice del disco), o con una firma scaduta o non riconosciuta, non è per forza pericoloso (molti programmi installati per utente non sono firmati), ma va riconosciuto: verifica da dove viene.') +
          (policyText ? ` Inoltre ${lc1(policyText)}.` : '') +
          (unchecked ? ` ${num(unchecked, 'altro file non è stato verificato', 'altri file non sono stati verificati')}.` : '')
        : (verified === groups.length
            ? 'I programmi in esecuzione hanno una firma digitale valida'
            : verified
              ? `${verified === 1 ? '1 programma su' : `${verified} programmi su`} ${groups.length} ${verified === 1 ? 'ha' : 'hanno'} una firma digitale valida`
              : 'Nessun programma in esecuzione ha una firma verificata') +
          (okParts.length ? `; ${okParts.join('; ')}` : '') +
          '.' +
          (unchecked ? ` ${num(unchecked, 'file non è stato verificato', 'file non sono stati verificati')}.` : ''),
      actions: sev === 'crit' ? ['defender-scan-file', 'check-file-origin'] : sev === 'warn' ? ['check-file-origin', 'defender-scan-file'] : policy ? ['check-file-origin'] : [],
    });
  }

  // Programmi in ascolto su tutte le interfacce.
  if (data.connsRead) {
    const ls = listeners(scan);
    const risky = ls.filter((l) => l.risky);
    const unverified = ls.filter((l) => l.unverified);
    const kernel = ls.filter((l) => l.kernel);
    const signed = ls.filter((l) => !l.risky && !l.unverified && !l.kernel);
    const off = firewallOff(scan);
    const sev: Severity = risky.length ? (off ? 'crit' : 'warn') : unverified.length ? 'info' : 'ok';
    const ports = (l: Listener) => `porta ${l.ports.slice(0, 3).join(', ')}${l.ports.length > 3 ? '...' : ''}`;
    const item = (l: Listener) => `${l.proc.name} (${ports(l)}${l.proc.file && l.proc.access !== 'none' ? `; ${lc1(signatureLabel(l.proc.file.signature).text)}, ${folderLabel(l.proc.file.folder)}` : ''})`;
    const plain = (l: Listener) => `${l.proc.name} (${ports(l)})`;
    // Da amministratore «senza amministratore» sarebbe falso: i processi che non si aprono sono protetti da Windows.
    const why = data.elevated ? 'processi protetti da Windows, che non si aprono nemmeno da amministratore, oppure firma non verificata in tempo' : 'senza amministratore non si aprono, oppure la firma non è stata verificata in tempo';
    const unverifiedText = unverified.length
      ? `${unverified.length === 1 ? 'Accetta connessioni da tutta la rete 1 programma che non si è potuto verificare' : `Accettano connessioni da tutta la rete ${unverified.length} programmi che non si sono potuti verificare`} (${why}): ${unverified
          .slice(0, 4)
          .map(plain)
          .join('; ')}${more(unverified.length, 4)}. Non sono né da controllare né a posto${data.elevated ? '.' : ': per verificarli ripeti l\'analisi avviando Polaris come amministratore.'}`
      : '';
    const signedText = signed.length
      ? signed.length === 1
        ? '1 programma in ascolto su tutte le reti ha una firma valida e sta in Programmi o nella cartella di Windows.'
        : `${signed.length} programmi in ascolto su tutte le reti hanno una firma valida e stanno in Programmi o nella cartella di Windows.`
      : '';
    const kernelText = kernel.length ? `System, il nucleo di Windows (${ports(kernel[0])}), non ha un file da verificare.` : '';
    add({
      id: 'pc.procs.listen',
      metric: 'pc.procs.listen',
      category: 'pc',
      title: 'Programmi in ascolto sulla rete',
      value: risky.length
        ? `${num(risky.length, 'programma da controllare', 'programmi da controllare')}${off ? ', firewall spento' : ''}`
        : unverified.length
          ? `${num(ls.length, 'programma', 'programmi')} in ascolto, ${unverified.length} non ${unverified.length === 1 ? 'verificato' : 'verificati'}`
          : ls.length
            ? `${num(ls.length, 'programma', 'programmi')} in ascolto, nessuno da controllare`
            : 'nessun programma in ascolto su tutte le reti',
      numeric: risky.length,
      severity: sev,
      verdict: risky.length
        ? `Accettano connessioni da tutta la rete: ${risky
            .slice(0, 4)
            .map(item)
            .join('; ')}${more(risky.length, 4)}. Un programma senza firma valida, o avviato da una cartella che un utente può scrivere, che aspetta connessioni dall'esterno va riconosciuto: se non serve, chiudilo o toglilo dall'avvio. ` +
          (off
            ? 'Il firewall del profilo in uso è spento: la porta è raggiungibile da ogni dispositivo della rete.'
            : 'Il firewall di Windows di norma blocca le connessioni in ingresso non richieste, salvo regole: Polaris non legge le singole regole.') +
          (unverified.length ? ` ${unverified.length === 1 ? 'Un altro programma in ascolto non si è potuto verificare' : `Altri ${unverified.length} programmi in ascolto non si sono potuti verificare`}: ${unverified.slice(0, 4).map(plain).join('; ')}${more(unverified.length, 4)}.` : '')
        : ls.length
          ? [unverifiedText, signedText, kernelText].filter(Boolean).join(' ')
          : 'Nessun programma accetta connessioni TCP da tutta la rete.',
      actions: risky.length ? (off ? ['enable-firewall', 'review-listening-app', 'check-file-origin'] : ['review-listening-app', 'check-file-origin']) : [],
    });
  }

  // Nomi dei programmi di Windows avviati da un'altra cartella.
  const fake = items.filter(isLookalike);
  if (fake.length) {
    add({
      id: 'pc.procs.lookalike',
      metric: 'pc.procs.lookalike',
      category: 'pc',
      title: 'Programmi con il nome di un file di Windows',
      value: num(fake.length, 'processo fuori posto', 'processi fuori posto'),
      numeric: fake.length,
      severity: 'warn',
      verdict:
        `${fake
          .slice(0, 4)
          .map((p) => `${p.name} da ${p.file && p.file.path}`)
          .join('; ')}${more(fake.length, 4)}. Questi nomi appartengono a programmi di Windows che girano solo dalla cartella di sistema (System32): una copia con lo stesso nome altrove è un modo noto per confondersi tra i processi di Windows. Va controllata subito.`,
      actions: ['defender-scan-file', 'check-file-origin'],
    });
  }

  // Processi non leggibili senza amministratore: non verificati, mai «in regola».
  const unread = data.unreadable || 0;
  if (unread >= PROCS_UNREADABLE_INFO && !data.elevated) {
    add({
      id: 'pc.procs.unreadable',
      metric: 'pc.procs.unreadable',
      category: 'pc',
      title: 'Processi non verificati',
      value: `${num(unread, 'processo non leggibile', 'processi non leggibili')} senza amministratore`,
      numeric: unread,
      severity: 'info',
      verdict: `Senza i permessi di amministratore Windows non lascia aprire ${num(unread, 'processo', 'processi')} di altri account: di questi si conosce solo il nome, non il file né la firma. Per verificarli tutti ripeti l'analisi avviando Polaris come amministratore.${data.partial ? ' La lettura dei processi non è finita in tempo: l\'elenco può essere incompleto.' : ''}`,
    });
  }
}

/** Da quanti processi non leggibili lo si segnala (scelta di Polaris). */
export const PROCS_UNREADABLE_INFO = 5;
