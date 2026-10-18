import { ACTIONS } from './kb/actions';
import { scoreAssessment } from './kb/assessment';
import { METRICS } from './kb/metrics';
import { dateIt } from './pc';
import type { Analysis, EventKind, Finding, ReachResult, Scan, Severity } from './types';

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

/** Come wrap, ma con rientro diverso per la prima riga e per le successive. */
function hang(text: string, width: number, first: string, rest: string): string {
  const lines = wrap(text, width - first.length, '').split('\n');
  if (lines.length === 1) return first + lines[0];
  const tail = wrap(lines.slice(1).join(' '), width - rest.length, rest);
  return `${first}${lines[0]}\n${tail}`;
}

function bar(score: number, width = 30): string {
  const n = Math.round((score / 100) * width);
  return '[' + '#'.repeat(n) + '.'.repeat(width - n) + ']';
}

const cut = (s: string, n: number) => (s.length > n ? s.slice(0, n - 1) + '…' : s).padEnd(n);

const REACH_TEXT: Record<ReachResult['status'], string> = {
  open: 'porta aperta',
  closed: 'porta chiusa',
  filtered: 'nessuna risposta',
  reply: 'risponde al ping',
  noreply: 'nessuna risposta',
  unresolved: 'nome non risolto',
  refused: 'non verificata',
  error: 'errore',
};

function reachTag(r: ReachResult): string {
  if (r.status === 'refused' || r.status === 'error' || (r.expect === 'isolated' && r.status === 'unresolved')) return TAG.unknown;
  if (r.ok) return r.expect === 'reachable' && (r.rttMs ?? 0) > 100 ? TAG.warn : TAG.ok;
  return r.expect === 'isolated' && r.status === 'closed' ? TAG.warn : TAG.crit;
}

/** Dettagli che non entrano nei giudizi: elenco dei dispositivi, esiti delle verifiche, aree dell'autovalutazione. */
function infraDetails(scan: Scan, out: string[], W: number, verbose: boolean) {
  const inf = scan.infra;
  if (!inf || (!inf.inventory && !inf.reach?.results.length && !inf.assessment)) return;
  out.push('');
  out.push('-'.repeat(W));
  out.push(' INFRASTRUTTURA: DETTAGLI');
  out.push('-'.repeat(W));
  const inv = inf.inventory;
  if (inv) {
    out.push(wrap(`Inventario ${inv.subnet}${inv.adapter ? ` (${inv.adapter})` : ''}: ${inv.hosts.length} indirizzi in uso, ${inv.startedAt}`, W - 2, ' '));
    if (verbose) {
      for (const h of inv.hosts) {
        const note = [h.self ? 'questo PC' : '', h.gateway ? 'gateway' : '', h.randomMac ? 'MAC casuale' : '', h.rttMs === undefined && !h.self ? 'solo ARP' : '']
          .filter(Boolean)
          .join(', ');
        out.push(`   ${h.ip.padEnd(15)} ${(h.mac ?? '-').padEnd(17)} ${cut(h.name || h.netbios || '-', 21)} ${note}`.trimEnd());
      }
    }
  }
  const rs = inf.reach?.results ?? [];
  if (rs.length) {
    out.push('');
    out.push(wrap(`Verifiche di raggiungibilità${inf.reach?.from ? ` da ${inf.reach.from}` : ''}, ${inf.reach?.startedAt ?? ''}`, W - 2, ' '));
    for (const r of rs) {
      const target = `${r.label ? `${r.label} ` : ''}${r.host}${r.port ? `:${r.port}` : ''}`;
      const res = `${REACH_TEXT[r.status]}${r.rttMs !== undefined && (r.status === 'open' || r.status === 'reply') ? `, ${Math.round(r.rttMs)} ms` : ''}`;
      out.push(` ${reachTag(r)} ${cut(target, 38)} ${r.expect === 'isolated' ? 'isolata ' : 'risponde'}  ${res}`.trimEnd());
    }
  }
  if (inf.assessment) {
    out.push('');
    out.push(' Autovalutazione (dichiarata, non misurata)');
    for (const s of scoreAssessment(inf.assessment.answers)) {
      out.push(`   ${s.area.title.padEnd(26)} ${s.score === null ? '  -' : String(s.score).padStart(3)}  ${s.score === null ? '' : bar(s.score, 20)}`.trimEnd());
      if (verbose) for (const g of s.gaps) out.push(wrap(`- ${g.q.short}${g.answer === 'partial' ? ' (in parte)' : ''}`, W - 9, '        '));
    }
  }
}

const n1 = (v: number) => v.toFixed(v < 10 ? 1 : 0).replace('.', ',');
const MEDIA: Record<string, string> = { hdd: 'HDD', ssd: 'SSD', scm: 'SCM', unknown: '?' };
const HEALTH: Record<string, string> = { healthy: 'integro', warning: 'guasto previsto', unhealthy: 'guasto', unknown: 'stato ignoto' };
const EVENT_TEXT: Record<EventKind, string> = {
  'unexpected-shutdown': 'spegnimento imprevisto',
  bugcheck: 'schermata blu',
  'disk-error': 'errore del disco',
  'disk-retry': 'operazione ripetuta',
  filesystem: 'file system danneggiato',
  'storage-reset': 'reset del controller',
  'whea-fatal': 'errore hardware grave',
  'whea-corrected': 'errore hardware corretto',
};
const LOCATION: Record<string, string> = { user: 'utente', machine: 'computer', machine32: 'computer (32 bit)', 'user-folder': 'cartella utente', 'common-folder': 'cartella comune' };

/** Dettagli del computer che non entrano nei giudizi: dischi, volumi, avvio, processi, eventi, test. */
function pcDetails(scan: Scan, out: string[], W: number, verbose: boolean) {
  const pc = scan.pc;
  if (!pc) return;
  out.push('');
  out.push('-'.repeat(W));
  out.push(' COMPUTER: DETTAGLI');
  out.push('-'.repeat(W));
  const os = pc.os;
  if (os) {
    const up = os.uptimeSec !== undefined ? `, acceso da ${n1(os.uptimeSec / 86400)} giorni` : '';
    out.push(wrap(`${os.name}${os.version ? ` ${os.version}` : ''}${os.build ? ` (build ${os.build}${os.ubr ? `.${os.ubr}` : ''})` : ''}${os.arch ? `, ${os.arch}` : ''}${up}`, W - 2, ' '));
  }
  if (pc.cpu) {
    const cores = pc.cpu.cores ? `${pc.cpu.cores} core / ${pc.cpu.threads ?? '?'} thread` : pc.cpu.threads ? `${pc.cpu.threads} thread` : '';
    out.push(wrap(`Processore: ${pc.cpu.name}${cores ? `, ${cores}` : ''}${pc.cpu.loadPct !== undefined ? `, carico ${Math.round(pc.cpu.loadPct)} %` : ''}`, W - 2, ' '));
  }
  if (pc.memory) out.push(` Memoria: ${n1(pc.memory.totalMB / 1024)} GB, liberi ${n1(pc.memory.availableMB / 1024)} GB`);
  for (const g of pc.gpus ?? []) out.push(wrap(`Video: ${g.name}${g.driverVersion ? `, driver ${g.driverVersion}` : ''}${g.driverDate ? ` del ${dateIt(g.driverDate)}` : ''}`, W - 2, ' '));
  if (pc.disks?.length) {
    out.push('');
    out.push(' Dischi');
    for (const d of pc.disks) {
      const r = d.reliability;
      const extra = [r?.temperatureC !== undefined ? `${Math.round(r.temperatureC)} °C` : '', r?.wearPct !== undefined && d.media !== 'hdd' ? `usura ${Math.round(r.wearPct)} %` : '', r?.powerOnHours !== undefined ? `${r.powerOnHours} ore` : '']
        .filter(Boolean)
        .join(', ');
      out.push(
        hang(
          `${(d.id ?? '-').padEnd(3)}${cut(d.name, 26)} ${`${MEDIA[d.media]} ${d.bus ?? ''}`.trim().padEnd(10)} ${`${Math.round(d.sizeGB)} GB`.padStart(8)}  ${HEALTH[d.health ?? 'unknown']}${extra ? `, ${extra}` : ''}${d.system ? ' (Windows)' : ''}`,
          W,
          '   ',
          '      ',
        ),
      );
    }
  }
  if (pc.volumes?.length) {
    out.push(' Volumi');
    for (const v of pc.volumes) {
      const pct = v.sizeGB ? Math.round((100 * v.freeGB) / v.sizeGB) : 0;
      out.push(`   ${v.letter.padEnd(4)}${(v.fs ?? '').padEnd(6)}${`${Math.round(v.sizeGB)} GB`.padStart(8)}  liberi ${n1(v.freeGB)} GB (${pct} %)${v.disk !== undefined ? `, disco ${v.disk}` : ''}${v.kind === 'removable' ? ', rimovibile' : ''}`);
    }
  }
  if (pc.startup) {
    const on = pc.startup.filter((x) => x.enabled);
    out.push('');
    out.push(` Programmi all'avvio: ${on.length} attivi, ${pc.startup.length - on.length} disattivati`);
    if (verbose) for (const x of pc.startup) out.push(`   ${x.enabled ? '+' : '-'} ${cut(x.name, 30)} ${LOCATION[x.location] ?? x.location}`.trimEnd());
  }
  if (pc.processes?.length) {
    out.push(' Processi più pesanti (misurati a fine analisi)');
    for (const p of pc.processes.slice(0, verbose ? 16 : 6))
      out.push(`   ${cut(`${p.name}${p.count > 1 ? ` (${p.count})` : ''}`, 34)} ${p.cpuPct !== undefined ? `${n1(p.cpuPct)} %`.padStart(7) : '      -'}  ${`${Math.round(p.memoryMB)} MB`.padStart(8)}`);
  }
  if (pc.eventsDays) {
    out.push(` Eventi rilevanti negli ultimi ${pc.eventsDays} giorni: ${pc.events?.length ? '' : 'nessuno'}`.trimEnd());
    for (const e of pc.events ?? [])
      out.push(wrap(`${dateIt(e.last)}  ${e.source} ${e.id}  x${e.count}  ${EVENT_TEXT[e.kind]}${e.detail ? `: ${e.detail}` : ''}`, W - 4, '   '));
  }
  const b = pc.bench;
  if (b?.cpu || b?.disk?.length) {
    out.push('');
    out.push(' Test di velocità');
    if (b.cpu)
      out.push(wrap(`Processore (${dateIt(b.cpu.startedAt)}): un thread ${n1(b.cpu.singleMBs)} MB/s, ${b.cpu.threads} thread ${n1(b.cpu.multiMBs)} MB/s di punta e ${n1(b.cpu.sustainedMBs)} MB/s alla fine`, W - 4, '   '));
    for (const d of b.disk ?? [])
      out.push(wrap(`Unità ${d.drive} (${dateIt(d.startedAt)}, file di ${d.fileMB} MB): sequenziale ${n1(d.seqReadMBs)} MB/s in lettura e ${n1(d.seqWriteMBs)} in scrittura; casuale 4K ${n1(d.rndReadMBs)} MB/s (${Math.round(d.rndReadIops)} IOPS) in lettura e ${n1(d.rndWriteMBs)} MB/s in scrittura`, W - 4, '   '));
  }
  for (const n of pc.notes ?? []) out.push(wrap(`Nota: ${n}`, W - 2, ' '));
}

export function renderText(scan: Scan, a: Analysis, opts: { verbose?: boolean; width?: number } = {}): string {
  const W = opts.width ?? 78;
  const out: string[] = [];
  const hr = '='.repeat(W);
  out.push(hr);
  out.push(` STARNET Polaris - rapporto di diagnostica ${scan.pc ? 'di PC e rete' : 'di rete'}`);
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
      out.push(hang(`${TAG[f.severity]} ${f.title}: ${f.value}`, W, ' ', '        '));
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
  infraDetails(scan, out, W, !!opts.verbose);
  pcDetails(scan, out, W, !!opts.verbose);
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
