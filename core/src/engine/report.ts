import { ACTIONS } from './kb/actions';
import { METRICS } from './kb/metrics';
import type { Analysis, Finding, Scan, Severity } from './types';

// Rapporto testuale, usato dalla riga di comando e dall'esportazione .txt.
// Testo UTF-8: Go scrive sulla console di Windows in Unicode (WriteConsoleW)
// e i file salvati hanno il BOM, quindi gli accenti si leggono ovunque.

const TAG: Record<Severity, string> = { ok: '[ OK ]', info: '[INFO]', warn: '[ !! ]', crit: '[CRIT]', unknown: '[ ?? ]' };

function wrap(text: string, width: number, indent: string): string {
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let line = '';
  for (const w of words) {
    if ((line + ' ' + w).trim().length > width) {
      lines.push(line);
      line = w;
    } else line = (line ? line + ' ' : '') + w;
  }
  if (line) lines.push(line);
  return lines.map((l) => indent + l).join('\n');
}

function bar(score: number, width = 30): string {
  const n = Math.round((score / 100) * width);
  return '[' + '#'.repeat(n) + '.'.repeat(width - n) + ']';
}

export function renderText(scan: Scan, a: Analysis, opts: { verbose?: boolean; width?: number } = {}): string {
  const W = opts.width ?? 78;
  const out: string[] = [];
  const hr = '='.repeat(W);
  out.push(hr);
  out.push(' LANterna - rapporto di diagnostica di rete');
  out.push(` ${scan.agent.host ?? ''}  ${scan.agent.os ?? scan.agent.platform}  ${scan.agent.startedAt}  (${Math.round(scan.agent.durationMs / 100) / 10} s)`);
  out.push(hr);
  out.push('');
  out.push(` Punteggio complessivo: ${a.score}/100  ${bar(a.score)}  ${a.grade.toUpperCase()}`);
  out.push(wrap(a.headline, W - 2, ' '));
  out.push('');
  for (const c of a.categories) {
    if (c.score === null) continue;
    out.push(`   ${c.label.padEnd(14)} ${String(c.score).padStart(3)}  ${bar(c.score, 20)}  ${c.counts.crit ? `${c.counts.crit} ${c.counts.crit === 1 ? 'critico' : 'critici'}  ` : ''}${c.counts.warn ? `${c.counts.warn} ${c.counts.warn === 1 ? 'avviso' : 'avvisi'}` : ''}`);
  }
  const byCat = new Map<string, Finding[]>();
  for (const f of a.findings) byCat.set(f.category, [...(byCat.get(f.category) ?? []), f]);
  for (const c of a.categories) {
    const fs = byCat.get(c.category);
    if (!fs) continue;
    out.push('');
    out.push('-'.repeat(W));
    out.push(` ${c.label.toUpperCase()}`);
    out.push('-'.repeat(W));
    for (const f of fs) {
      out.push(` ${TAG[f.severity]} ${f.title}: ${f.value}`);
      out.push(wrap(f.verdict, W - 9, '        '));
      if (opts.verbose) {
        const m = METRICS[f.metric];
        if (m) {
          out.push(wrap('Cos\'è: ' + m.what, W - 9, '        '));
          if (m.scale) for (const s of m.scale) out.push(wrap(`${TAG[s.severity]} ${s.range}: ${s.meaning}`, W - 11, '          '));
        }
      }
    }
  }
  if (a.channels.length) {
    out.push('');
    out.push('-'.repeat(W));
    out.push(' CANALI WI-FI');
    out.push('-'.repeat(W));
    for (const ch of a.channels) {
      out.push(` ${ch.band.replace('.', ',')} GHz: attuale ${ch.current ?? '-'}, consigliato ${ch.recommended ?? 'automatico'}`);
      out.push(wrap(ch.note, W - 9, '        '));
    }
  }
  if (a.plan.length) {
    out.push('');
    out.push(hr);
    out.push(' PIANO D\'AZIONE (in ordine di priorità)');
    out.push(hr);
    a.plan.forEach((p, i) => {
      const act = ACTIONS[p.action.id];
      out.push(` ${String(i + 1).padStart(2)}. ${TAG[p.severity]} ${act.title}`);
      out.push(wrap(`impatto ${act.impact}, difficoltà ${act.effort}; risolve: ${p.findings.join(', ')}`, W - 9, '        '));
      if (opts.verbose) {
        out.push(wrap(act.why, W - 9, '        '));
        act.steps.forEach((s, j) => out.push(wrap(`${j + 1}) ${s}`, W - 11, '          ')));
      }
    });
  }
  if (scan.errors.length) {
    out.push('');
    out.push(' Misure non riuscite:');
    for (const e of scan.errors) out.push(wrap(`- ${e.probe}: ${e.message}`, W - 4, '   '));
  }
  out.push('');
  return out.join('\n');
}
