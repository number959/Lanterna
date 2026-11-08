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

/** Riga di testo completa di un passo, per il rapporto e il documento: testo, comando e avvertenze. */
export function stepLine(s: Step, win?: WinMajor): string {
  const x = asStep(s);
  let line = stepText(x, win);
  if (x.cmd) line += ` Comando: ${x.cmd}`;
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
