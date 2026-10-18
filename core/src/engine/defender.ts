import { more, num } from './fmt';
import type { Finding, PcData, Severity, Threat, ThreatSeverity, ThreatStatus } from './types';

// Microsoft Defender: minacce della cronologia e stato della protezione
// (protezione da manomissioni, ultime scansioni). Lo stato generale
// dell'antivirus resta il giudizio "pc.av", qui non si ripete.

type Add = (f: Omit<Finding, 'actions'> & { actions?: string[] }) => void;

const DAY = 86400000;

export const THREAT_SEVERITY: Record<ThreatSeverity, string> = { low: 'bassa', moderate: 'media', high: 'alta', severe: 'grave', unknown: 'non indicata' };
export const THREAT_STATUS: Record<ThreatStatus, string> = {
  detected: 'rilevata, da risolvere',
  cleaned: 'ripulita',
  quarantined: 'in quarantena',
  removed: 'rimossa',
  allowed: 'consentita',
  blocked: 'bloccata',
  failed: 'azione non riuscita',
  unknown: 'stato sconosciuto',
};

/** Minaccia ancora da gestire: attiva, solo rilevata o con un'azione fallita. */
export const unresolved = (t: Threat) => !!t.active || t.status === 'detected' || t.status === 'failed';

const names = (list: Threat[], n = 3) =>
  list
    .slice(0, n)
    .map((t) => `${t.name} (${THREAT_SEVERITY[t.severity]})`)
    .join(', ') + more(list.length, Math.min(n, list.length));

export function analyzeDefender(pc: PcData, now: number, add: Add) {
  const list = pc.threats;
  if (list) {
    const open = list.filter(unresolved);
    const allowed = list.filter((t) => t.status === 'allowed' && !unresolved(t));
    const recent = list.filter((t) => {
      const d = Date.parse(t.detected ?? '');
      return !isNaN(d) && now - d <= 30 * DAY;
    });
    const sev: Severity = open.length ? 'crit' : allowed.length ? 'warn' : recent.length ? 'info' : 'ok';
    add({
      id: 'pc.threats',
      metric: 'pc.threats',
      category: 'security',
      title: 'Minacce rilevate da Defender',
      value: open.length
        ? num(open.length, 'da risolvere', 'da risolvere')
        : allowed.length
          ? num(allowed.length, 'consentita', 'consentite')
          : recent.length
            ? `${num(recent.length, 'bloccata', 'bloccate')} in 30 giorni`
            : 'nessuna',
      numeric: open.length,
      severity: sev,
      verdict:
        sev === 'crit'
          ? `Defender ha rilevato ${num(open.length, 'minaccia non ancora risolta', 'minacce non ancora risolte')}: ${names(open)}. La minaccia è ancora attiva o l'azione automatica non è riuscita: va gestita subito.`
          : sev === 'warn'
            ? `${names(allowed)}: ${allowed.length === 1 ? 'consentita' : 'consentite'} manualmente in Defender. Se non sei sicuro che sia innocua, rimuovi l'eccezione e lascia che Defender la metta in quarantena.`
            : sev === 'info'
              ? `Negli ultimi 30 giorni Defender ha intercettato ${num(recent.length, 'minaccia', 'minacce')}: ${names(recent)}. Sono in quarantena o rimosse: la protezione ha funzionato. Se si ripetono, cerca la fonte (download, allegati, chiavette).`
              : list.length
                ? 'Nella cronologia di Defender ci sono solo minacce più vecchie di 30 giorni, già risolte.'
                : 'Nessuna minaccia nella cronologia di Microsoft Defender.',
      actions: sev === 'crit' || sev === 'warn' ? ['remove-threats'] : [],
    });
  }

  const d = pc.defender;
  if (d && d.mode === 'normal') {
    const issues: string[] = [];
    let sev: Severity = 'ok';
    if (!d.realTime && !pc.antivirus) {
      sev = 'warn';
      issues.push('La protezione in tempo reale è disattivata: file e allegati non vengono controllati mentre li apri.');
    }
    if (d.tamperProtected === false) {
      if (sev === 'ok') sev = 'info';
      issues.push('La protezione da manomissioni è disattivata: un malware potrebbe spegnere Defender o cambiarne le impostazioni. Sui PC aziendali può gestirla l\'amministratore.');
    }
    const last = Math.min(d.quickScanAgeDays ?? Infinity, d.fullScanAgeDays ?? Infinity);
    if (last > 14) {
      if (sev === 'ok') sev = 'info';
      issues.push(
        last === Infinity
          ? 'Non risulta alcuna scansione completata: di solito Defender ne esegue una durante la manutenzione automatica, quando il PC è acceso e inattivo. Si avvia anche dalla sezione Computer di Polaris.'
          : `L'ultima scansione risale a ${num(last, 'giorno', 'giorni')} fa: di solito Defender ne esegue una durante la manutenzione automatica, quando il PC è acceso e inattivo. Si avvia anche dalla sezione Computer di Polaris.`,
      );
    }
    const scanText = last === Infinity ? 'nessuna scansione' : last === 0 ? 'scansione oggi' : `ultima scansione ${num(last, 'giorno', 'giorni')} fa`;
    add({
      id: 'pc.defender',
      metric: 'pc.defender',
      category: 'security',
      title: 'Microsoft Defender',
      value: [d.tamperProtected === undefined ? '' : `manomissioni ${d.tamperProtected ? 'bloccate' : 'non bloccate'}`, scanText].filter(Boolean).join(' · '),
      severity: sev,
      verdict: issues.length
        ? issues.join(' ')
        : `Defender è l'antivirus attivo, con protezione da manomissioni${d.tamperProtected === undefined ? ' (stato non riportato)' : ''} e scansioni regolari.`,
      actions: issues.length ? ['defender-protection'] : [],
    });
  }
}
