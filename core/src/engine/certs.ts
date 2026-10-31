import { thousands } from './fmt';
import { dateIt } from './pc';
import type { CertResult, CertTrust, Finding, Scan, Severity } from './types';

// Certificati dei servizi interni: l'agente legge, su richiesta, il
// certificato TLS dei servizi indicati dall'utente (gestionale, PACS, NAS,
// pannello del router, posta) e come lo valuta Windows su questo PC; qui si
// trasforma ogni risultato in un giudizio. Le soglie sono le stesse della
// voce "infra.cert" della knowledge base. Gira anche in goja: niente Intl.

/** Problema: certificato scaduto o con al più 7 giorni di validità. */
export const CERT_CRIT_DAYS = 7;
/**
 * Attenzione: al più 30 giorni, o un terzo della durata se è minore (Let's
 * Encrypt consiglia di rinnovare quando resta un terzo della durata). Non
 * esiste una soglia standard: sono valori prudenti.
 */
export const CERT_WARN_DAYS = 30;
export type CertExpiry = 'expired' | 'crit' | 'warn' | 'ok';

/**
 * Stato della scadenza: scaduto; Problema entro 7 giorni; Attenzione entro
 * min(30, durata/3) giorni. Per un certificato che dura una settimana o meno
 * vuol dire essere sempre in allarme: è voluto, Polaris non sa se si rinnova
 * da solo.
 */
export function certExpiry(daysLeft: number, lifetimeDays?: number): CertExpiry {
  if (daysLeft < 0) return 'expired';
  if (daysLeft <= CERT_CRIT_DAYS) return 'crit';
  if (daysLeft <= certWarnDays(lifetimeDays)) return 'warn';
  return 'ok';
}

/** Giorni entro cui il certificato è "in scadenza" (Attenzione), dato il periodo di validità. */
export function certWarnDays(lifetimeDays?: number): number {
  return lifetimeDays && lifetimeDays > 0 ? Math.min(CERT_WARN_DAYS, lifetimeDays / 3) : CERT_WARN_DAYS;
}

/** "scade tra 12 giorni", "scade entro un giorno", "scaduto da 3 giorni". */
export function certExpiryText(daysLeft: number): string {
  if (daysLeft < -1) return `scaduto da ${thousands(-daysLeft)} giorni`;
  if (daysLeft < 0) return 'scaduto';
  if (daysLeft === 0) return 'scade entro un giorno';
  if (daysLeft === 1) return 'scade tra 1 giorno';
  if (daysLeft < 730) return `scade tra ${thousands(daysLeft)} giorni`;
  return `scade tra ${Math.floor(daysLeft / 365)} anni`;
}

/** Attendibilità come la riporta Windows su questo PC, per esteso. */
export const CERT_TRUST_TEXT: Record<CertTrust, string> = {
  trusted: 'attendibile su questo PC',
  'untrusted-root': 'emittente non riconosciuto da questo PC',
  'partial-chain': 'catena incompleta: manca un certificato intermedio',
  'invalid-signature': 'firma non valida',
  'wrong-usage': 'non valido per i server TLS',
  distrusted: 'bloccato da Windows su questo PC',
  revoked: 'revocato',
  '': 'non verificata',
};

const TRUST_SHORT: Record<CertTrust, string> = {
  trusted: 'attendibile',
  'untrusted-root': 'CA non riconosciuta',
  'partial-chain': 'catena incompleta',
  'invalid-signature': 'firma non valida',
  'wrong-usage': 'uso non valido',
  distrusted: 'bloccato da Windows',
  revoked: 'revocato',
  '': 'attendibilità non verificata',
};

/** Chi l'ha emesso, in breve: "autofirmato" o il nome dell'emittente. */
export function certIssuer(r: CertResult): string {
  if (r.selfSigned) return 'autofirmato';
  return r.issuer || r.issuerOrg || 'emittente senza nome';
}

/** Attendibilità in breve, con "autofirmato" al posto dell'emittente sconosciuto. */
export function certTrustShort(r: CertResult): string {
  const trust = r.trust ?? '';
  if (r.selfSigned) return trust === 'trusted' ? 'autofirmato, attendibile' : 'autofirmato';
  return TRUST_SHORT[trust] ?? TRUST_SHORT[''];
}

/** Al massimo 20 servizi per controllo, come nell'agente. */
export const CERT_MAX_TARGETS = 20;

const SCHEME_PORT: { [scheme: string]: number } = { ldaps: 636, smtps: 465, imaps: 993 };
const URL_RE = /^([a-z][a-z0-9+.-]*):\/\/(?:[^@/?#]*@)?(\[[^\]]*\]|[^:/?#]*)(?::(\d*))?(?:[/?#].*)?$/i;

/**
 * Normalizza un servizio come fa l'agente: "nas.local", "192.168.1.10:8443",
 * "https://pacs.local:8443/viewer", "[fd00::5]:636". La porta nel nome o
 * nell'indirizzo prevale su quella indicata a parte; senza porta vale 443
 * (636, 465 e 993 per ldaps://, smtps:// e imaps://).
 */
export function certNormalize(host: string, port?: number): { host: string; port: number } | { error: string } {
  let h = host.trim();
  let p = port || 0;
  if (h.indexOf('://') >= 0) {
    const m = URL_RE.exec(h);
    if (!m || !m[2] || m[2] === '[]') return { error: 'indirizzo non valido' };
    h = m[2];
    if (m[3]) p = Number(m[3]);
    else if (!p) p = SCHEME_PORT[m[1].toLowerCase()] || 443;
  } else {
    const m = /^\[([^\]]*)\]:(\d+)$/.exec(h) || /^([^:]*):(\d+)$/.exec(h);
    if (m) {
      h = m[1];
      p = Number(m[2]);
    }
  }
  h = h.replace(/^\[/, '').replace(/\]$/, '');
  if (!p) p = 443;
  if (!h || h.length > 253 || /[\s/\\@]/.test(h)) return { error: 'indirizzo o nome mancante o non valido' };
  if (!(p >= 1 && p <= 65535) || Math.floor(p) !== p) return { error: `porta ${p} non valida` };
  return { host: h, port: p };
}

/** Il servizio come l'ha indicato l'utente: "nas.local:5001". */
export function certWhere(r: Pick<CertResult, 'host' | 'port'>): string {
  const h = r.host || '';
  const host = h.indexOf(':') >= 0 ? `[${h}]` : h;
  return `${host}:${r.port || 443}`;
}

export interface CertIssue {
  id: string;
  severity: Severity;
  /** Etichetta breve per elenchi e tabelle. */
  short: string;
  /** Frase per il giudizio. */
  text: string;
  action?: string;
}

const RANK: Record<Severity, number> = { unknown: 0, ok: 1, info: 2, warn: 3, crit: 4 };
const isIp = (h: string) => /^[0-9.]+$/.test(h) || h.indexOf(':') >= 0;

/**
 * Che cosa c'è da sapere su un certificato, dal più grave: problemi (crit),
 * avvisi (warn) e note (info). Un servizio non controllato ha solo l'errore.
 */
export function certIssues(r: CertResult): CertIssue[] {
  if (!r.ok) return [{ id: 'failed', severity: 'unknown', short: 'non controllato', text: `Controllo non riuscito: ${r.error || 'nessun certificato ricevuto'}.` }];
  const out: CertIssue[] = [];
  const date = r.notAfter ? dateIt(r.notAfter) : '';
  const trust = r.trust ?? '';
  const tls = r.tlsVersion || 'TLS';
  const names = [...(r.dnsNames ?? []), ...(r.ips ?? [])];

  const exp = certExpiry(r.daysLeft, r.lifetimeDays);
  if (exp === 'expired')
    out.push({
      id: 'expired',
      severity: 'crit',
      short: 'scaduto',
      text: `Il certificato è scaduto${date ? ` il ${date}` : ''}: browser e programmi mostrano un errore o rifiutano la connessione.`,
      action: 'renew-certificate',
    });
  else if (exp === 'crit' || exp === 'warn')
    out.push({
      id: 'expiring',
      severity: exp,
      short: certExpiryText(r.daysLeft),
      text: `Il certificato ${r.daysLeft === 0 ? 'scade entro un giorno' : `scade tra ${r.daysLeft === 1 ? '1 giorno' : `${thousands(r.daysLeft)} giorni`}`}${date ? ` (il ${date})` : ''}: ${exp === 'crit' ? 'rinnovalo subito' : 'pianifica il rinnovo'}.`,
      action: 'renew-certificate',
    });

  if (r.legacyOnly)
    out.push({
      id: 'legacy-only',
      severity: 'crit',
      short: 'solo TLS 1.0/1.1',
      text: `Il servizio offre solo ${tls}: TLS 1.0 e 1.1 sono dismessi (RFC 8996) e non vanno più negoziati (RFC 9325); i browser attuali non li accettano più.`,
      action: 'disable-legacy-tls',
    });
  if (trust === 'invalid-signature')
    out.push({
      id: 'invalid-signature',
      severity: 'crit',
      short: 'firma non valida',
      text: 'Windows segnala che la firma del certificato o della sua catena non è valida: il certificato può essere danneggiato o non essere quello originale. Non accettarlo finché l\'amministratore del servizio non l\'ha verificato.',
      action: 'reissue-certificate-san',
    });
  if (trust === 'distrusted')
    out.push({
      id: 'distrusted',
      severity: 'crit',
      short: 'bloccato da Windows',
      text: 'Il certificato o il suo emittente è tra quelli che Windows su questo PC tratta come non attendibili: il servizio va dotato di un altro certificato.',
      action: 'reissue-certificate-san',
    });
  if (trust === 'revoked')
    out.push({
      id: 'revoked',
      severity: 'crit',
      short: 'revocato',
      text: 'Dalle informazioni già presenti su questo PC il certificato risulta revocato da chi l\'ha emesso: va sostituito.',
      action: 'reissue-certificate-san',
    });

  if (r.cnOnly)
    out.push({
      id: 'cn-only',
      severity: 'warn',
      short: 'solo Common Name',
      text: 'Il certificato indica il nome solo nel Common Name, senza nomi alternativi (SAN): Chrome non accetta più questi certificati dalla versione 58 e la RFC 9525 non ammette il Common Name per identificare un servizio.',
      action: 'reissue-certificate-san',
    });
  else if (!r.nameMatch)
    out.push({
      id: 'name-mismatch',
      severity: 'warn',
      short: 'nome non corrispondente',
      text: `${isIp(r.host) ? 'L\'indirizzo' : 'Il nome'} ${r.host} non è tra quelli del certificato${names.length ? ` (${names.slice(0, 4).join(', ')}${names.length > 4 ? '…' : ''})` : ''}: il browser mostra un avviso anche se il certificato è attendibile.`,
      action: 'reissue-certificate-san',
    });
  if (r.weakSig)
    out.push({
      id: 'weak-signature',
      severity: 'warn',
      short: 'firma SHA-1 o MD5',
      text: `Il certificato è firmato con ${r.sigAlg || 'SHA-1 o MD5'}: SHA-1 e MD5 non vanno più usati per le firme (RFC 9325).`,
      action: 'reissue-certificate-san',
    });
  if (r.keyType === 'RSA' && r.keyBits && r.keyBits < 2048)
    out.push({
      id: 'weak-key',
      severity: 'warn',
      short: `RSA ${r.keyBits} bit`,
      text: `La chiave RSA ha ${r.keyBits} bit: il minimo è 2048 (RFC 9325).`,
      action: 'reissue-certificate-san',
    });
  if (r.legacyToo && !r.legacyOnly)
    out.push({
      id: 'legacy-too',
      severity: 'warn',
      short: 'accetta TLS 1.0/1.1',
      text: `Il servizio usa ${tls} ma accetta ancora TLS 1.0 o 1.1, versioni dismesse (RFC 8996) che non vanno più negoziate (RFC 9325): i client vecchi possono ancora collegarsi così.`,
      action: 'disable-legacy-tls',
    });
  if (trust === 'partial-chain')
    out.push({
      id: 'partial-chain',
      severity: 'warn',
      short: 'catena incompleta',
      text: 'Con i soli certificati presenti su questo PC la catena non arriva a un\'autorità radice: di solito il servizio non invia il certificato intermedio, e i programmi che non lo trovano altrove rifiutano la connessione.',
      action: 'reissue-certificate-san',
    });
  if (trust === 'untrusted-root' && !r.selfSigned)
    out.push({
      id: 'unknown-ca',
      severity: 'warn',
      short: 'CA non riconosciuta',
      text: `Il certificato è emesso da ${certIssuer(r)}, un'autorità che questo PC non riconosce: se è la CA interna della struttura va distribuita ai PC; se non sai chi l'ha emesso, chiedilo all'amministratore del servizio. Una CA pubblica mai usata su questo PC può risultare non riconosciuta, perché il controllo non scarica nulla.`,
      action: 'trust-internal-ca',
    });
  if (trust === 'wrong-usage')
    out.push({
      id: 'wrong-usage',
      severity: 'warn',
      short: 'uso non valido',
      text: 'Il certificato non è autorizzato per l\'autenticazione di un server TLS: i client possono rifiutarlo.',
      action: 'reissue-certificate-san',
    });

  if (r.selfSigned && trust !== 'trusted')
    out.push({
      id: 'self-signed',
      severity: 'info',
      short: 'autofirmato',
      text: `Il certificato è autofirmato${trust ? ' e questo PC non lo considera attendibile' : ''}. Su NAS, router, PACS e programmi di gestione è normale: le CA pubbliche non possono rilasciare certificati per nomi interni o indirizzi privati. Va bene se i PC lo considerano attendibile per scelta, dopo averne verificato l'impronta; non va bene se gli utenti si abituano ad accettare l'avviso del browser.`,
      action: 'trust-internal-ca',
    });
  if (r.clientCert)
    out.push({
      id: 'client-cert',
      severity: 'info',
      short: 'chiede un certificato client',
      text: 'Il servizio chiede un certificato anche al client (TLS reciproco): per un PACS con DICOM su TLS è previsto, perché lo standard chiede ai server di supportare l\'autenticazione reciproca; per altri servizi verifica con il fornitore che sia voluto.',
    });
  return out.sort((a, b) => RANK[b.severity] - RANK[a.severity]);
}

/** Gravità complessiva di un certificato: la peggiore tra quelle trovate, "ok" se non c'è nulla. */
export function certSeverity(r: CertResult): Severity {
  if (!r.ok) return 'unknown';
  return certIssues(r).reduce<Severity>((s, i) => (RANK[i.severity] > RANK[s] ? i.severity : s), 'ok');
}

/** "scade tra 12 giorni · TLS 1.3 · autofirmato" */
export function certValue(r: CertResult): string {
  if (!r.ok) return 'non controllato';
  return [certExpiryText(r.daysLeft), `${r.tlsVersion || 'TLS'}${r.starttls ? ' (STARTTLS)' : ''}`, certTrustShort(r)].join(' · ');
}

/** Riga riassuntiva per il rapporto di testo: "scade il 12/11/2026 (12 g), TLS 1.3, autofirmato". */
export function certSummary(r: CertResult): string {
  if (!r.ok) return `non controllato: ${r.error || 'nessun certificato'}`;
  const date = r.notAfter ? dateIt(r.notAfter) : '?';
  const days = r.daysLeft < 0 ? 'scaduto' : `${thousands(r.daysLeft)} g`;
  return `${r.daysLeft < 0 ? 'scaduto il' : 'scade il'} ${date}${r.daysLeft < 0 ? '' : ` (${days})`}, ${r.tlsVersion || 'TLS'}, ${certTrustShort(r)}`;
}

/** Il servizio con la sua etichetta: "NAS (nas.local:5001)". */
export function certTarget(r: CertResult): string {
  const where = certWhere(r);
  if (!r.label) return where;
  return /\)$/.test(r.label) ? `${r.label}, ${where}` : `${r.label} (${where})`;
}

/** Che cosa provare quando il controllo non riesce, in base all'errore dell'agente e alla porta. */
export function certFailHint(error?: string, port?: number): string {
  const e = (error || '').toLowerCase();
  if (e.indexOf('porta chiusa') >= 0 || e.indexOf('non usa tls') >= 0)
    return (port || 443) === 443
      ? ' Verifica la porta: il pannello cifrato di molti dispositivi non usa la 443 ma un\'altra porta, per esempio 8443.'
      : ' Verifica la porta nel manuale o nel pannello del dispositivo.';
  if (e.indexOf('non risolto') >= 0) return ' Controlla il nome o indica direttamente l\'indirizzo IP del servizio.';
  if (e.indexOf('non ha risposto') >= 0)
    return ' Le cause possibili: il servizio è spento, un firewall blocca la connessione, oppure su quella porta risponde un servizio che non usa TLS e resta in attesa. Le verifiche di raggiungibilità aiutano a capire se la porta è aperta.';
  return '';
}

/** Un giudizio per ogni servizio controllato, con identificativo stabile ricavato da nome e porta. */
export function analyzeCerts(scan: Scan, add: (f: Omit<Finding, 'actions'> & { actions?: string[] }) => void) {
  const results = scan.infra?.certs?.results ?? [];
  const seen: { [id: string]: number } = {};
  for (const r of results) {
    const base = `infra.cert.${certWhere(r).toLowerCase()}`;
    seen[base] = (seen[base] || 0) + 1;
    const id = seen[base] > 1 ? `${base}#${seen[base]}` : base;
    const issues = certIssues(r);
    const severity = certSeverity(r);
    const where = `${certWhere(r)}${r.ip && r.ip !== r.host ? ` (${r.ip})` : ''}`;
    let verdict: string;
    if (!r.ok)
      verdict = `Controllo non riuscito su ${where}: ${(r.error || 'nessun certificato ricevuto').replace(/\.$/, '')}.${certFailHint(r.error, r.port)}`;
    else {
      const trust = r.trust ?? '';
      const who = r.selfSigned
        ? trust === 'trusted'
          ? 'autofirmato, considerato attendibile su questo PC'
          : 'autofirmato'
        : `emesso da ${certIssuer(r)}${trust === 'trusted' ? ', attendibile su questo PC' : trust === '' ? ', attendibilità non verificata' : ''}`;
      const facts = [
        r.notAfter ? `valido fino al ${dateIt(r.notAfter)}${r.lifetimeDays ? ` (durata ${thousands(r.lifetimeDays)} giorni)` : ''}` : '',
        who,
        `${r.tlsVersion || 'TLS'}${r.starttls ? ' dopo STARTTLS' : ''}`,
      ].filter(Boolean);
      const fine =
        trust === ''
          ? 'Certificato valido, con una versione di TLS attuale; l\'attendibilità su questo PC non è stata verificata.'
          : 'Certificato valido e attendibile su questo PC, con una versione di TLS attuale: nulla da fare fino al rinnovo.';
      verdict = `${issues.length ? issues.map((i) => i.text).join(' ') : fine} ${where}: ${facts.join('; ')}.`;
    }
    const actions: string[] = [];
    for (const i of issues) if (i.action && actions.indexOf(i.action) < 0) actions.push(i.action);
    add({
      id,
      metric: 'infra.cert',
      category: 'infra',
      title: `Certificato · ${r.label || certWhere(r)}`,
      value: certValue(r),
      ...(r.ok ? { numeric: r.daysLeft } : {}),
      severity,
      verdict,
      actions,
    });
  }
}
