import { num } from './fmt';
import { dateIt, isHome, on } from './pc';
import type { EncVolume, Finding, PcData, Scan, Severity } from './types';

// Protezione dei dati e degli accessi: cifratura del disco (BitLocker e
// crittografia del dispositivo), punti di ripristino e backup, account
// locali, accesso automatico, Desktop remoto, Controllo dell'account utente,
// blocco dello schermo. L'agente legge impostazioni e stati senza nomi, senza
// password e senza la chiave di ripristino. Le soglie sono scelte di Polaris.
// Gira anche in goja: niente Intl.

/** Algoritmo di cifratura, come lo chiama Windows. */
export const ENC_METHOD: Record<string, string> = {
  none: 'nessuno',
  'aes128-diffuser': 'AES 128 con diffusore',
  'aes256-diffuser': 'AES 256 con diffusore',
  aes128: 'AES 128',
  aes256: 'AES 256',
  hardware: 'cifratura hardware del disco',
  'xts-aes128': 'XTS-AES 128',
  'xts-aes256': 'XTS-AES 256',
  unknown: 'non indicato',
};

/** Protezioni della chiave, in italiano. */
export const ENC_PROTECTOR: Record<string, string> = {
  tpm: 'TPM',
  'tpm-pin': 'TPM e PIN',
  'tpm-startup-key': 'TPM e chiave di avvio',
  'tpm-pin-startup-key': 'TPM, PIN e chiave di avvio',
  'recovery-password': 'chiave di ripristino',
  'startup-key': 'chiave di avvio su chiavetta',
  password: 'password',
  'public-key': 'certificato',
  'tpm-certificate': 'TPM e certificato',
  other: 'altro',
};

/** Il PC è portatile (o tablet): più esposto a perdita e furto. */
export function isPortable(pc: PcData): boolean {
  const c = pc.hardware?.chassis;
  if (c) return c === 'laptop' || c === 'tablet';
  return !!pc.power?.hasBattery;
}

/** Stato di cifratura di un volume, in breve. */
export function encText(v: EncVolume): string {
  const method = v.method && v.method !== 'none' && v.method !== 'unknown' ? ` (${ENC_METHOD[v.method] ?? v.method})` : '';
  switch (v.conversion) {
    case 'decrypted':
      return 'non cifrato';
    case 'encrypting':
      return `cifratura in corso${v.percent !== undefined ? `, ${v.percent}%` : ''}`;
    case 'decrypting':
      return `decifratura in corso${v.percent !== undefined ? `, ${v.percent}%` : ''}`;
    case 'encrypt-paused':
      return `cifratura in pausa${v.percent !== undefined ? ` al ${v.percent}%` : ''}`;
    case 'decrypt-paused':
      return `decifratura in pausa${v.percent !== undefined ? ` al ${v.percent}%` : ''}`;
    case 'encrypted':
      return `cifrato${method}, protezione ${v.protection === 'on' ? 'attiva' : v.protection === 'off' ? 'non attiva' : 'in stato sconosciuto'}`;
  }
  return 'stato sconosciuto';
}

const DAY = 86400000;
type Add = (f: Omit<Finding, 'actions'> & { actions?: string[] }) => void;

function analyzeEncryption(scan: Scan, pc: PcData, add: Add) {
  const e = pc.encryption;
  if (!e || pc.os?.server || e.read === 'absent' || e.read === 'error') return;
  const word = isHome(pc.os?.edition) ? 'la crittografia del dispositivo' : 'BitLocker';
  const portable = isPortable(pc);
  if (e.read === 'denied') {
    add({
      id: 'pc.encryption',
      metric: 'pc.encryption',
      category: 'security',
      title: 'Cifratura del disco',
      value: 'non letta senza amministratore',
      severity: 'unknown',
      verdict: `Windows mostra lo stato di ${word === 'BitLocker' ? 'BitLocker' : 'BitLocker e della crittografia del dispositivo'} solo ai programmi avviati come amministratore: per controllarlo avvia Polaris con "Esegui come amministratore".`,
    });
    return;
  }
  const os = (e.volumes ?? []).filter((v) => v.kind === 'os')[0];
  if (!os) return;
  const corp = !!scan.agent.domain;
  const keyAdvice = corp
    ? ' La chiave di ripristino dei PC aziendali la custodisce di solito il reparto informatico: verifica con loro che ci sia.'
    : os.recoveryKeyId
      ? ` Polaris non legge mai la chiave di ripristino: controlla da un altro dispositivo, su aka.ms/myrecoverykey, che ci sia quella con l'identificativo che inizia per ${os.recoveryKeyId}, oppure che sia stampata o salvata altrove.`
      : '';
  const prot = os.protectors ?? [];
  let sev: Severity = 'ok';
  let value = `${os.letter} ${encText(os)}`;
  let verdict: string;
  let actions: string[] = [];
  if (os.conversion === 'encrypted' && os.protection === 'on') {
    const noRecovery = os.protectors !== null && prot.indexOf('recovery-password') < 0;
    sev = noRecovery ? 'warn' : 'ok';
    verdict =
      `Il disco di sistema è cifrato e protetto${prot.length ? ` (${prot.map((p) => ENC_PROTECTOR[p] ?? p).join(', ')})` : ''}: se il PC viene perso o rubato, i dati non si leggono senza Windows o la chiave di ripristino.` +
      (noRecovery ? ' Manca però una chiave di ripristino: se il chip TPM o la scheda madre si guastano, o cambia il firmware, i dati possono andare persi.' : keyAdvice);
    actions = ['save-recovery-key'];
  } else if (os.conversion === 'encrypted' && os.protection === 'off' && prot.length === 0 && os.protectors !== null) {
    sev = 'warn';
    value = `${os.letter} cifrato, protezione mai attivata`;
    verdict =
      'Il disco è cifrato ma la protezione non è mai stata attivata: la chiave è salvata in chiaro sul disco stesso, quindi chi ha il disco legge i dati. Succede con la crittografia automatica del dispositivo quando si usa solo un account locale: accedendo con un account Microsoft (o attivando BitLocker) la protezione si attiva e la chiave di ripristino viene salvata.';
    actions = ['activate-encryption'];
  } else if (os.conversion === 'encrypted' && os.protection === 'off') {
    sev = 'warn';
    value = `${os.letter} cifrato, protezione sospesa`;
    verdict =
      'La protezione del disco è sospesa: i dati restano cifrati ma la chiave è leggibile sul disco, quindi in questo momento non sono protetti. ' +
      (os.suspendCount !== undefined && os.suspendCount > 0
        ? `Windows la riattiverà da solo dopo ${num(os.suspendCount, 'riavvio', 'riavvii')}.`
        : 'Resta sospesa finché qualcuno non la riattiva.') +
      ' Di solito la sospende un aggiornamento del firmware o del BIOS.';
    actions = ['resume-bitlocker'];
  } else if (os.conversion === 'decrypted') {
    sev = portable ? 'warn' : 'info';
    verdict =
      (portable
        ? 'Il disco del portatile non è cifrato: se il PC viene perso o rubato, chiunque può leggere i file collegando il disco a un altro computer.'
        : 'Il disco non è cifrato: in caso di furto del PC o del disco i file si leggono collegandolo a un altro computer.') +
      (e.preventAuto ? ' La crittografia automatica del dispositivo è impedita da un\'impostazione del registro.' : '') +
      ` Con ${word} i dati sono protetti senza rallentamenti apprezzabili sui PC recenti.`;
    actions = ['activate-encryption'];
  } else {
    sev = 'info';
    verdict = `Stato della cifratura del disco di sistema: ${encText(os)}. Polaris lo ricontrolla alla prossima analisi.`;
  }
  const others = (e.volumes ?? []).filter((v) => v.kind === 'fixed' && v.conversion === 'decrypted');
  if (sev === 'ok' && others.length) verdict += ` Non sono cifrati gli altri dischi interni: ${others.map((v) => v.letter).join(', ')}.`;
  add({ id: 'pc.encryption', metric: 'pc.encryption', category: 'security', title: 'Cifratura del disco', value, severity: sev, verdict, actions });
}

function analyzeRestore(pc: PcData, now: number, add: Add) {
  const r = pc.backup?.restorePoints;
  if (!r || pc.os?.server) return;
  if (r.disabledByPolicy) {
    add({
      id: 'pc.restore',
      metric: 'pc.restore',
      category: 'pc',
      title: 'Punti di ripristino',
      value: 'spenti dai criteri',
      severity: 'info',
      verdict: 'Ripristino configurazione di sistema è spento dai criteri di gruppo: se un aggiornamento o un driver rovinano Windows non c\'è un punto a cui tornare. Sui PC gestiti è una scelta del reparto informatico.',
    });
    return;
  }
  if (r.read !== 'ok') return;
  if (!r.count) {
    add({
      id: 'pc.restore',
      metric: 'pc.restore',
      category: 'pc',
      title: 'Punti di ripristino',
      value: 'nessuno',
      severity: 'warn',
      verdict:
        'Non c\'è nessun punto di ripristino: probabilmente la protezione del sistema è spenta sul disco di sistema. Con un punto di ripristino si torna indietro in pochi minuti dopo un aggiornamento, un driver o un programma che rovinano Windows, senza toccare i documenti.',
      actions: ['enable-system-protection'],
    });
    return;
  }
  // Senza la data dell'ultimo punto (campo facoltativo) si dice solo quanti sono.
  const newest = r.newest && !isNaN(Date.parse(r.newest)) ? r.newest : undefined;
  const age = newest ? (now - Date.parse(newest)) / DAY : 0;
  const sev: Severity = age > 30 ? 'info' : 'ok';
  add({
    id: 'pc.restore',
    metric: 'pc.restore',
    category: 'pc',
    title: 'Punti di ripristino',
    value: newest ? `${r.count}, l'ultimo il ${dateIt(newest)}` : String(r.count),
    numeric: r.count,
    severity: sev,
    verdict:
      sev === 'ok'
        ? `${num(r.count, 'punto di ripristino', 'punti di ripristino')}${newest ? `, l'ultimo ${on(newest, 'il')}` : ''}: se Windows si rovina dopo un aggiornamento o un driver, si può tornare indietro.`
        : `L'ultimo punto di ripristino risale ${on(newest!, 'al')}: Windows ne crea di solito prima degli aggiornamenti, quindi la protezione potrebbe essere stata spenta o lo spazio riservato essere troppo poco.`,
    actions: sev === 'ok' ? [] : ['enable-system-protection'],
  });
}

function analyzeBackup(pc: PcData, now: number, add: Add) {
  const b = pc.backup;
  if (!b || pc.os?.server) return;
  const ib = b.imageBackup;
  const od = b.oneDrive ?? [];
  const lastOk = ib?.lastSuccess ? Date.parse(ib.lastSuccess) : NaN;
  const lastKo = ib?.lastFailure ? Date.parse(ib.lastFailure) : NaN;
  let sev: Severity;
  let value: string;
  let verdict: string;
  let actions: string[] = [];
  const odNames = od.map((f) => (f === 'desktop' ? 'Desktop' : f === 'documents' ? 'Documenti' : 'Immagini'));
  const odText = od.length ? (od.length === 1 ? ` La cartella ${odNames[0]} è sincronizzata con OneDrive.` : ` Le cartelle ${odNames.join(', ')} sono sincronizzate con OneDrive.`) : '';
  if (!isNaN(lastKo) && (isNaN(lastOk) || lastKo > lastOk)) {
    sev = 'warn';
    value = `ultimo backup non riuscito, ${dateIt(ib!.lastFailure!)}`;
    verdict = `L'ultimo backup di Backup e ripristino di Windows non è riuscito ${on(ib!.lastFailure!, 'il')}${!isNaN(lastOk) ? `; l'ultimo riuscito risale ${on(ib!.lastSuccess!, 'al')}` : ', e negli ultimi 90 giorni nessuno è riuscito'}. Cause frequenti: disco di backup scollegato o pieno.${odText}`;
    actions = ['backup-files'];
  } else if (!isNaN(lastOk)) {
    sev = now - lastOk > 30 * DAY ? 'info' : 'ok';
    value = `ultimo backup ${dateIt(ib!.lastSuccess!)}`;
    verdict = `L'ultimo backup di Backup e ripristino di Windows è riuscito ${on(ib!.lastSuccess!, 'il')}.${sev === 'info' ? ' È passato più di un mese: controlla che il disco di backup sia collegato.' : ''}${odText}`;
    actions = sev === 'ok' ? [] : ['backup-files'];
  } else if (od.length) {
    sev = 'info';
    value = 'cartelle in OneDrive';
    verdict = `${odText.trim()} La sincronizzazione protegge dalla perdita del PC, ma non è un backup completo: un file cancellato o cifrato da un ransomware cambia anche nel cloud (si recupera dal Cestino o dalla cronologia delle versioni di OneDrive, entro i limiti del servizio).`;
    actions = ['backup-files'];
  } else if (ib && ib.read !== 'ok') {
    // Senza il registro di Backup e ripristino non si può dire che manchi un backup.
    sev = 'unknown';
    value = 'non letto';
    verdict = `Lo storico di Backup e ripristino di Windows non è stato letto${ib.read === 'denied' ? ' (servono i privilegi di amministratore)' : ''}, e nessuna cartella risulta sincronizzata con OneDrive: Polaris non può dire se esiste un backup.`;
  } else {
    sev = 'info';
    value = 'nessun backup trovato';
    verdict =
      'Polaris non ha trovato backup fatti con Backup e ripristino di Windows né cartelle sincronizzate con OneDrive. Cronologia file e i programmi di altri produttori non vengono controllati: se usi uno di questi, un NAS o un servizio cloud va bene così; altrimenti i documenti esistono solo su questo disco.';
    actions = ['backup-files'];
  }
  add({ id: 'pc.backup', metric: 'pc.backup', category: 'security', title: 'Backup dei dati', value, severity: sev, verdict, actions });
}

function analyzeAccounts(scan: Scan, pc: PcData, add: Add) {
  const a = pc.accounts;
  if (!a || !a.local) return;
  const enabled = a.local.filter((x) => x.enabled);
  const builtin = enabled.filter((x) => x.kind === 'builtin-admin');
  const guest = enabled.filter((x) => x.kind === 'guest');
  const noPwd = enabled.filter((x) => x.passwordNotRequired && x.kind !== 'guest');
  const admins = a.admins?.localEnabled ?? enabled.filter((x) => x.admin).length;
  const corp = !!scan.agent.domain;
  const server = !!pc.os?.server;
  const issues: string[] = [];
  let sev = 'ok' as Severity;
  const raise = (s: Severity) => {
    const rank: Record<Severity, number> = { unknown: 0, ok: 1, info: 2, warn: 3, crit: 4 };
    if (rank[s] > rank[sev]) sev = s;
  };
  if (guest.length) {
    issues.push('l\'account Guest (ospite) è attivo: chiunque può accedere senza password');
    raise('warn');
  }
  if (builtin.length && !server) {
    issues.push('l\'account Administrator integrato è attivo: è il primo che si prova ad attaccare e su molti PC ha una password debole o mai cambiata');
    raise('warn');
  }
  if (noPwd.length) {
    issues.push(`${num(noPwd.length, 'account attivo può', 'account attivi possono')} non avere una password (Windows non la richiede)`);
    raise('warn');
  }
  if (admins >= 4) {
    issues.push(`${admins} account locali sono amministratori`);
    raise('warn');
  } else if (admins === 3) {
    issues.push('3 account locali sono amministratori');
    raise('info');
  }
  const currentAdmin = a.currentIsAdmin === true && !a.local.some((x) => x.current && x.kind === 'builtin-admin');
  if (currentAdmin && !issues.length) {
    issues.push('lavori con un account amministratore: un programma malevolo aperto per sbaglio ottiene più facilmente il controllo del PC');
    raise('info');
  }
  if (corp && sev === 'warn') sev = 'info';
  const actions: string[] = [];
  if (guest.length || builtin.length || noPwd.length || admins >= 3) actions.push('secure-local-accounts');
  if (currentAdmin) actions.push('use-standard-account');
  add({
    id: 'pc.accounts',
    metric: 'pc.accounts',
    category: 'security',
    title: 'Account locali',
    value: `${num(enabled.length, 'account attivo', 'account attivi')}, ${num(admins, 'amministratore', 'amministratori')}`,
    numeric: enabled.length,
    severity: sev,
    verdict: issues.length
      ? `${issues.join('; ').charAt(0).toUpperCase()}${issues.join('; ').slice(1)}.` + (corp ? ' Il PC è in un dominio: le regole sugli account possono arrivare dal server dell\'organizzazione.' : '') + ' Polaris legge le impostazioni degli account e non prova password: non può dire se una password è debole.'
      : `Nessun account ospite o predefinito attivo e ${admins <= 1 ? 'un solo amministratore locale' : `${admins} amministratori locali`}. Polaris non prova password: non può dire se una password è debole.`,
    actions,
  });
}

function analyzeAccess(pc: PcData, add: Add) {
  const ac = pc.access;
  if (!ac) return;
  const portable = isPortable(pc);
  if (ac.autologon?.enabled) {
    const pw = !!ac.autologon.passwordInRegistry;
    add({
      id: 'pc.autologon',
      metric: 'pc.autologon',
      category: 'security',
      title: 'Accesso automatico',
      value: pw ? 'attivo, password nel registro' : 'attivo',
      severity: pw ? 'crit' : 'warn',
      verdict:
        'All\'avvio Windows entra da solo nell\'account, senza chiedere la password: chiunque accenda il PC ne usa i dati e i programmi.' +
        (pw
          ? ' La password è scritta in chiaro nel registro di Windows (Polaris ne controlla solo la presenza, non la legge): la può leggere qualunque utente del PC, e anche da un altro computer della rete se il servizio Registro remoto è raggiungibile.'
          : '') +
        (portable ? ' Su un portatile il rischio è maggiore.' : ''),
      actions: ['disable-autologon'],
    });
  }
  const rdp = ac.rdp;
  if (rdp?.enabled && !isHome(pc.os?.edition)) {
    add({
      id: 'pc.rdp',
      metric: 'pc.rdp',
      category: 'security',
      title: 'Desktop remoto',
      value: `attivo${rdp.nla ? ', con autenticazione di rete (NLA)' : ', SENZA autenticazione di rete'}${rdp.port && rdp.port !== 3389 ? `, porta ${rdp.port}` : ''}`,
      severity: rdp.nla ? 'info' : 'crit',
      verdict: rdp.nla
        ? `Desktop remoto è attivo${rdp.byPolicy ? ' (dai criteri di gruppo)' : ''} con l'autenticazione a livello di rete. Va usato solo dalla rete locale o attraverso una VPN: esposto su Internet è tra i servizi più attaccati.`
        : 'Desktop remoto è attivo senza l\'autenticazione a livello di rete (NLA): la schermata di accesso è raggiungibile prima di qualunque verifica, e alcune vulnerabilità gravi di Desktop remoto si sfruttano proprio così.',
      actions: ['secure-remote-desktop'],
    });
  }
  const u = ac.uac;
  if (u) {
    const sev: Severity = !u.enabled ? 'crit' : u.consentAdmin === 0 ? 'warn' : !u.secureDesktop ? 'info' : 'ok';
    add({
      id: 'pc.uac',
      metric: 'pc.uac',
      category: 'security',
      title: 'Controllo dell\'account utente',
      value: !u.enabled ? 'disattivato' : u.consentAdmin === 0 ? 'attivo, senza conferme' : !u.secureDesktop ? 'attivo, conferma sul desktop normale' : 'attivo',
      severity: sev,
      verdict:
        sev === 'crit'
          ? 'Il Controllo dell\'account utente è disattivato: ogni programma avviato da un amministratore ha subito il controllo completo del PC, e molte protezioni di Windows (comprese le app moderne) non funzionano come previsto.'
          : sev === 'warn'
            ? 'Gli amministratori diventano amministratori senza nessuna conferma: un programma malevolo ottiene i privilegi senza che nessuno se ne accorga.'
            : sev === 'info'
              ? 'Le richieste di conferma compaiono sul desktop normale invece che sul desktop protetto, dove nessun programma può cliccare al posto dell\'utente.'
              : 'Windows chiede conferma prima delle modifiche che richiedono l\'amministratore, sul desktop protetto.',
      actions: sev === 'ok' ? [] : ['enable-uac'],
    });
  }
  const l = ac.lock;
  if (l) {
    // Il blocco più breve tra quello dei criteri e lo screen saver con password.
    const policySec = l.inactivitySec || 0;
    const saverSec = l.saverActive && l.saverSecure && l.saverSec ? l.saverSec : 0;
    const sec = policySec && saverSec ? Math.min(policySec, saverSec) : policySec || saverSec;
    const how = sec === policySec ? ' (criteri di sicurezza)' : ' (screen saver con richiesta della password)';
    const after = sec < 60 ? num(sec, 'secondo', 'secondi') : num(Math.round(sec / 60), 'minuto', 'minuti');
    if (!sec) {
      add({
        id: 'pc.lock',
        metric: 'pc.lock',
        category: 'security',
        title: 'Blocco automatico dello schermo',
        value: 'non impostato',
        severity: 'info',
        verdict:
          'Né i criteri né lo screen saver bloccano lo schermo dopo qualche minuto di inattività: se ti allontani senza bloccarlo (Windows+L), chi passa usa il PC con il tuo account. Polaris non vede il blocco al risveglio dalla sospensione: se il PC va in sospensione e chiede la password, lo schermo è comunque protetto dopo quel tempo.',
        actions: ['set-screen-lock'],
      });
    } else if (sec > 900) {
      add({
        id: 'pc.lock',
        metric: 'pc.lock',
        category: 'security',
        title: 'Blocco automatico dello schermo',
        value: `dopo ${after} (oltre i 15 consigliati)`,
        severity: 'info',
        verdict: `Lo schermo si blocca da solo dopo ${after} di inattività${how}: è un tempo lungo, in cui chi passa può usare il PC con il tuo account. Conviene non superare i 15 minuti.`,
        actions: ['set-screen-lock'],
      });
    } else {
      add({
        id: 'pc.lock',
        metric: 'pc.lock',
        category: 'security',
        title: 'Blocco automatico dello schermo',
        value: `dopo ${after}`,
        severity: 'ok',
        verdict: `Lo schermo si blocca da solo dopo ${after} di inattività${how}.`,
      });
    }
  }
}

/** Giudizi su cifratura, ripristino, backup, account e accessi. */
export function analyzeProtection(scan: Scan, add: Add) {
  const pc = scan.pc;
  if (!pc) return;
  const now = Date.parse(scan.agent.startedAt) || Date.now();
  analyzeEncryption(scan, pc, add);
  analyzeRestore(pc, now, add);
  analyzeBackup(pc, now, add);
  analyzeAccounts(scan, pc, add);
  analyzeAccess(pc, add);
}
