import { crashDrivers } from './crash';
import type { Action, ActionStep, Scan, Step } from './types';

// Passi delle azioni adattati al PC analizzato: Windows 11 e Windows 10 hanno
// percorsi e nomi diversi in Impostazioni, e Polaris conosce la versione dal
// rapporto. Senza la versione (rapporti senza dati del PC, demo della rete)
// si mostrano entrambe. Stile ES2015, come il resto del motore (goja).

export type WinMajor = 10 | 11;

/** Versione principale di Windows del PC analizzato, se il rapporto la dice. */
export function windowsMajor(scan: Scan | null | undefined): WinMajor | undefined {
  const os = scan && scan.pc && scan.pc.os;
  if (!os) return undefined;
  if (os.server) return undefined; // Windows Server ha un'altra interfaccia: niente percorsi su misura
  if (typeof os.build === 'number' && os.build > 0) return os.build >= 22000 ? 11 : 10;
  if (/windows 11/i.test(os.name)) return 11;
  if (/windows 10/i.test(os.name)) return 10;
  return undefined;
}

/** Un passo sempre nella forma completa. */
export function asStep(s: Step): ActionStep {
  return typeof s === 'string' ? { text: s } : s;
}

/** I passi da mostrare per quella versione di Windows (senza versione: tutti). */
export function stepsFor(a: Action, win?: WinMajor): ActionStep[] {
  const out: ActionStep[] = [];
  for (const raw of a.steps) {
    const s = asStep(raw);
    if (s.only && win && s.only !== win) continue;
    out.push(s);
  }
  return out;
}

/** Il testo del passo per quella versione; senza versione, con la variante di Windows 10 tra parentesi. */
export function stepText(s: Step, win?: WinMajor): string {
  const x = asStep(s);
  if (!x.win10) return x.text;
  if (win === 10) return x.win10;
  if (win === 11) return x.text;
  return `${x.text} (Windows 10: ${x.win10})`;
}

/** Valori del rapporto che completano i comandi dei passi. */
export interface StepVars {
  /** Driver ricorrente nelle schermate blu, solo se è un semplice nome di file .sys. */
  driver?: string;
}

/** Segnaposto mostrato quando il rapporto non indica un driver utilizzabile. */
export const DRIVER_PLACEHOLDER = 'nome-del-file.sys';

// Il nome finisce in un comando che l'utente incolla nel Prompt dei comandi: un
// rapporto importato potrebbe contenere un nome costruito per aggiungere altri
// comandi (& | > ...). Si accettano solo lettere, cifre, punto, trattino e
// trattino basso, come nei nomi dei driver.
const SAFE_DRIVER = /^[A-Za-z0-9_.-]{1,64}\.sys$/i;

/** I valori del rapporto per i comandi dei passi. */
export function stepVars(scan: Scan | null | undefined): StepVars {
  const c = scan && scan.pc && scan.pc.crashes;
  const top = crashDrivers(c || undefined)[0];
  return top && SAFE_DRIVER.test(top.label) ? { driver: top.label } : {};
}

/** Il comando del passo con i valori del rapporto; senza un valore resta il segnaposto da sostituire. */
export function stepCmd(s: Step, vars?: StepVars): string | undefined {
  const x = asStep(s);
  if (!x.cmd) return undefined;
  return x.cmd.split('{driver}').join(vars && vars.driver ? vars.driver : DRIVER_PLACEHOLDER);
}

/**
 * Riga di testo completa di un passo, per il rapporto e il catalogo: testo,
 * comando e avvertenze. Con cmd: false il comando resta fuori, per scriverlo su
 * una riga sua (andando a capo non si potrebbe più copiare).
 */
export function stepLine(s: Step, win?: WinMajor, vars?: StepVars, opts?: { cmd?: boolean }): string {
  const x = asStep(s);
  let line = stepText(x, win);
  if (x.cmd && !(opts && opts.cmd === false)) line += ` Comando: ${stepCmd(x, vars)}`;
  const notes: string[] = [];
  if (x.admin) notes.push('serve l\'amministratore');
  if (x.where === 'router') notes.push('sul router');
  if (x.where === 'device') notes.push('sul dispositivo');
  if (x.only && !win) notes.push(`solo Windows ${x.only}`);
  return notes.length ? `${line} [${notes.join(', ')}]` : line;
}

/** Tutto il testo dei passi (anche le varianti di Windows 10 e i comandi), per la ricerca e i controlli. */
export function stepsText(a: Action): string {
  const parts: string[] = [];
  for (const raw of a.steps) {
    const s = asStep(raw);
    parts.push(s.text);
    if (s.win10) parts.push(s.win10);
    if (s.cmd) parts.push(s.cmd);
  }
  if (a.check) parts.push(a.check);
  return parts.join(' ');
}

/** Gli strumenti che i passi dell'azione aprono, senza ripetizioni, nell'ordine dei passi. */
export function stepOpens(a: Action): string[] {
  const out: string[] = [];
  for (const raw of a.steps) {
    const s = asStep(raw);
    if (s.open && out.indexOf(s.open) < 0) out.push(s.open);
  }
  return out;
}
