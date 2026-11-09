import { more, num } from './fmt';
import type { Finding, Printer, Scan, Severity } from './types';

// Stampanti e servizio di stampa (spooler), come Stampanti e scanner: stato
// delle stampanti, lavori fermi in coda, servizio fermo. Dei lavori Polaris
// conosce solo stato e età: mai titoli dei documenti o nomi di chi stampa.
// Gira anche in goja: niente Intl.

/** Stati di una stampante, in italiano. */
export const PRINTER_FLAG: Record<string, string> = {
  paused: 'in pausa',
  error: 'in errore',
  'pending-deletion': 'in eliminazione',
  'paper-jam': 'carta inceppata',
  'paper-out': 'carta esaurita',
  'paper-problem': 'problema con la carta',
  offline: 'non in linea',
  'output-bin-full': 'vassoio di uscita pieno',
  'not-available': 'non disponibile',
  'toner-low': 'toner o inchiostro in esaurimento',
  'no-toner': 'toner o inchiostro esaurito',
  'user-intervention': 'richiede un intervento',
  'out-of-memory': 'memoria della stampante piena',
  'door-open': 'sportello aperto',
  'server-unknown': 'server di stampa sconosciuto',
  'power-save': 'in risparmio energetico',
};

/** Stati che impediscono di stampare. */
const BLOCKING = ['paused', 'error', 'paper-jam', 'paper-out', 'paper-problem', 'offline', 'not-available', 'no-toner', 'user-intervention', 'door-open', 'out-of-memory'];

export const printerProblems = (p: Printer) => (p.flags ?? []).filter((f) => BLOCKING.indexOf(f) >= 0);
export const isRealPrinter = (p: Printer) => p.kind !== 'virtual';

/** Stato di una stampante in una riga: "in errore, carta esaurita · 2 lavori fermi". */
export function printerText(p: Printer): string {
  const parts = (p.flags ?? []).filter((f) => f !== 'power-save').map((f) => PRINTER_FLAG[f] ?? f);
  if (p.workOffline) parts.push('impostata per lavorare non in linea');
  if (p.stuck) parts.push(num(p.stuck, 'lavoro fermo', 'lavori fermi'));
  if (p.jobErrors) parts.push(num(p.jobErrors, 'lavoro in errore', 'lavori in errore'));
  if (!parts.length) return p.jobs ? `pronta, ${num(p.jobs, 'lavoro', 'lavori')} in coda` : 'pronta';
  return parts.join(', ');
}

type Add = (f: Omit<Finding, 'actions'> & { actions?: string[] }) => void;

/** Giudizio su stampanti e servizio di stampa. */
export function analyzePrinting(scan: Scan, add: Add) {
  const pr = scan.pc?.printing;
  if (!pr) return;
  const sp = pr.spooler;
  const real = (pr.printers ?? []).filter(isRealPrinter);
  if (sp && (sp.start === 'disabled' || !sp.running)) {
    add({
      id: 'pc.printers',
      metric: 'pc.printers',
      category: 'pc',
      title: 'Stampanti',
      value: sp.start === 'disabled' ? 'servizio di stampa disattivato' : 'servizio di stampa fermo',
      severity: real.length || pr.connections ? 'warn' : 'info',
      verdict:
        sp.start === 'disabled'
          ? 'Il servizio di stampa (spooler) è disattivato: il PC non può stampare. Su alcuni PC lo si disattiva di proposito per sicurezza, quando non si stampa mai.'
          : 'Il servizio di stampa (spooler) non è in esecuzione: finché non riparte non si stampa. Succede quando un driver di stampa lo fa cadere.',
      actions: ['restart-spooler'],
    });
    return;
  }
  if (!real.length) return;
  const broken = real.filter((p) => printerProblems(p).length || p.workOffline);
  const stuck = real.filter((p) => p.stuck || p.jobErrors);
  const low = real.filter((p) => (p.flags ?? []).indexOf('toner-low') >= 0);
  const def = real.filter((p) => p.default)[0];
  let sev: Severity = 'ok';
  if (low.length) sev = 'info';
  if (broken.length || stuck.length) sev = 'warn';
  const list = [...broken, ...stuck.filter((p) => broken.indexOf(p) < 0), ...low.filter((p) => broken.indexOf(p) < 0 && stuck.indexOf(p) < 0)];
  const actions: string[] = [];
  if (broken.some((p) => p.workOffline || (p.flags ?? []).indexOf('offline') >= 0 || (p.flags ?? []).indexOf('paused') >= 0)) actions.push('printer-online');
  if (stuck.length) actions.push('clear-print-queue');
  add({
    id: 'pc.printers',
    metric: 'pc.printers',
    category: 'pc',
    title: 'Stampanti',
    value: sev === 'ok' ? `${num(real.length, 'stampante pronta', 'stampanti pronte')}` : `${num(broken.length + stuck.filter((p) => broken.indexOf(p) < 0).length || low.length, 'stampante da controllare', 'stampanti da controllare')}`,
    numeric: real.length,
    severity: sev,
    verdict:
      sev === 'ok'
        ? `Le stampanti installate sono pronte${def ? `; quella predefinita è ${def.name}` : ''}.${pr.connections ? ` Ci sono anche ${num(pr.connections, 'stampante condivisa', 'stampanti condivise')} da altri computer, di cui Polaris non legge lo stato.` : ''}`
        : list
            .slice(0, 3)
            .map((p) => `${p.name}${p.default ? ' (predefinita)' : ''}: ${printerText(p)}`)
            .join('; ') +
          more(list.length, 3) +
          '.' +
          (list.some((p) => (p.flags ?? []).some((f) => ['paper-jam', 'paper-out', 'paper-problem', 'no-toner', 'door-open', 'output-bin-full'].indexOf(f) >= 0))
            ? ' Controlla carta, toner, sportelli e vassoi della stampante.'
            : '') +
          ' Lo stato è quello che il servizio di stampa conosce: una stampante di rete spenta può risultare pronta finché non le si manda un lavoro.',
    actions,
  });
}
