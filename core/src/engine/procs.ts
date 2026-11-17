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

/** Cartelle che un utente senza privilegi può scrivere (come sign.UserWritable dell'agente). */
const USER_WRITABLE: FolderKind[] = ['appData', 'temp', 'downloads', 'profile', 'removable', 'network'];
export const userWritable = (folder?: FolderKind) => !!folder && USER_WRITABLE.indexOf(folder) >= 0;

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

/** Processi su cui si danno giudizi: non Polaris, e non i processi di sistema senza file (System, Registry...). */
const judged = (p: ProcessDetail) => !p.polaris;

export interface ProcGroup {
  file: FileFacts;
  names: string[];
  count: number;
  procs: ProcessDetail[];
}

/** I processi raggruppati per file eseguibile: lo stesso file si giudica una volta. */
export function procGroups(items: ProcessDetail[]): ProcGroup[] {
  const map: { [k: string]: ProcGroup } = {};
  const out: ProcGroup[] = [];
  for (const p of items) {
    if (!judged(p) || !p.file || !p.file.path) continue;
    const k = p.file.path.toLowerCase();
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

/** Gravità di un file eseguito: firma grave, firma da guardare, senza firma in una cartella dell'utente. */
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

/** Programmi in ascolto su tutte le interfacce (TCP), con la gravità di ciascuno. */
export function listeners(scan: Scan): { proc: ProcessDetail; ports: number[]; risky: boolean }[] {
  const items = (scan.pc && scan.pc.procs && scan.pc.procs.items) || [];
  const out: { proc: ProcessDetail; ports: number[]; risky: boolean }[] = [];
  for (const p of items) {
    if (!judged(p)) continue;
    const ports = (p.listen || []).filter((l) => l.proto === 'tcp' && l.scope === 'all').map((l) => l.port);
    if (!ports.length) continue;
    const uniq = ports.filter((x, i) => ports.indexOf(x) === i).sort((a, b) => a - b);
    const sig = p.file && p.file.signature;
    // Senza file (System, PID 4) non c'è nulla da verificare: è il kernel.
    const risky = !!p.file && !!p.file.path && ((!!sig && sig.status !== 'valid' && sig.status !== 'unreadable' && sig.status !== 'unknown') || userWritable(p.file.folder));
    out.push({ proc: p, ports: uniq, risky });
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
    let sev: Severity = 'ok';
    for (const b of bad) sev = worst(sev, b.sev);
    const verified = groups.filter((g) => g.file.signature && g.file.signature.status === 'valid').length;
    const unsigned = groups.filter((g) => g.file.signature && g.file.signature.status === 'unsigned').length;
    const unchecked = groups.filter((g) => !g.file.signature || g.file.signature.status === 'unknown' || g.file.signature.status === 'unreadable').length;
    const crit = bad.some((b) => b.sev === 'crit');
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
            : 'Un programma senza firma in una cartella che l\'utente può scrivere, o con una firma scaduta o non riconosciuta, non è per forza pericoloso (molti programmi installati per utente non sono firmati), ma va riconosciuto: verifica da dove viene.') +
          (unchecked ? ` ${num(unchecked, 'altro file non è stato verificato', 'altri file non sono stati verificati')}.` : '')
        : `I programmi in esecuzione hanno una firma digitale valida${unsigned ? `, salvo ${num(unsigned, 'programma senza firma installato', 'programmi senza firma installati')} in cartelle protette` : ''}.` +
          (unchecked ? ` ${num(unchecked, 'file non è stato verificato', 'file non sono stati verificati')}.` : ''),
      actions: sev === 'crit' ? ['defender-scan-file', 'check-file-origin'] : sev === 'warn' ? ['check-file-origin', 'defender-scan-file'] : [],
    });
  }

  // Programmi in ascolto su tutte le interfacce.
  if (data.connsRead) {
    const ls = listeners(scan);
    const risky = ls.filter((l) => l.risky);
    const off = firewallOff(scan);
    const sev: Severity = risky.length ? (off ? 'crit' : 'warn') : 'ok';
    const item = (l: { proc: ProcessDetail; ports: number[] }) =>
      `${l.proc.name} (porta ${l.ports.slice(0, 3).join(', ')}${l.ports.length > 3 ? '...' : ''}${l.proc.file ? `; ${lc1(signatureLabel(l.proc.file.signature).text)}, ${folderLabel(l.proc.file.folder)}` : ''})`;
    add({
      id: 'pc.procs.listen',
      metric: 'pc.procs.listen',
      category: 'pc',
      title: 'Programmi in ascolto sulla rete',
      value: risky.length ? `${num(risky.length, 'programma da controllare', 'programmi da controllare')}${off ? ', firewall spento' : ''}` : ls.length ? `${num(ls.length, 'programma', 'programmi')} in ascolto, nessuno da controllare` : 'nessun programma in ascolto su tutte le reti',
      numeric: risky.length,
      severity: sev,
      verdict: risky.length
        ? `Accettano connessioni da tutta la rete: ${risky
            .slice(0, 4)
            .map(item)
            .join('; ')}${more(risky.length, 4)}. Un programma senza firma o avviato da una cartella dell'utente che aspetta connessioni dall'esterno va riconosciuto: se non serve, chiudilo o toglilo dall'avvio. ` +
          (off
            ? 'Il firewall del profilo in uso è spento: la porta è raggiungibile da ogni dispositivo della rete.'
            : 'Il firewall di Windows di norma blocca le connessioni in ingresso non richieste, salvo regole: Polaris non legge le singole regole.')
        : ls.length
          ? 'I programmi in ascolto su tutte le reti sono firmati e installati in cartelle protette.'
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
