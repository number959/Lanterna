import { BRAND_CYAN, BRAND_NAVY, CYAN_FRAME, CYAN_STAR, FRAME, LETTERS, LOGO_VIEWBOX, STAR_LEFT, STAR_RIGHT } from '../ui/brand-paths';
import { ENGINE_VERSION } from './analyze';
import { THREAT_SEVERITY, THREAT_STATUS } from './defender';
import { fmt, thousands } from './fmt';
import { cacheText, channelMode, coreLayout, cpuVendor, memVendor, moduleText } from './hardware';
import { dateIt } from './pc';
import { attrState, bytesText, diskStatus, isFlashDisk, smartId, smartName, smartRaw } from './smart';
import { pctText, sizeText, SPACE_CATEGORY_LABEL, SPACE_HINTS, SPACE_RISK_LABEL, unattributedBytes } from './space';
import type { Analysis, EventKind, Finding, Scan, Severity } from './types';

// Documento stampabile ed esportabile sullo stato del PC (e della rete): HTML
// autonomo in formato A4, con gli stessi giudizi del programma. Lo usano
// l'interfaccia (anteprima, stampa o PDF, file .html) e la riga di comando
// (polaris-cli report --html). Tutti gli stili sono sotto .pdoc, così il
// documento si può anche inserire nella pagina dell'interfaccia per stamparlo.
// Non contiene numeri di serie, indirizzi MAC, l'indirizzo IP pubblico né
// percorsi personali. Gira anche in goja: niente Intl, solo ES2015.

export interface DocOptions {
  /** Versione dell'agente o dell'interfaccia che genera il documento. */
  version?: string;
  /** Data e ora di creazione, già formattate da chi chiama. */
  generated?: string;
}

const SEV: Record<Severity, { label: string; mark: string }> = {
  crit: { label: 'Critico', mark: '✕' },
  warn: { label: 'Attenzione', mark: '!' },
  info: { label: 'Info', mark: 'i' },
  ok: { label: 'OK', mark: '✓' },
  unknown: { label: 'Non misurato', mark: '?' },
};
const GRADE_SEV: Record<Analysis['grade'], Severity> = { ottima: 'ok', buona: 'ok', discreta: 'warn', critica: 'crit' };
const MEDIA: Record<string, string> = { hdd: 'HDD', ssd: 'SSD', scm: 'SCM', unknown: '' };
const CHASSIS: Record<string, string> = { desktop: 'computer fisso', laptop: 'portatile', workstation: 'workstation', server: 'server', tablet: 'tablet', other: '' };
const EVENT: Record<EventKind, string> = {
  'unexpected-shutdown': 'Spegnimento imprevisto',
  bugcheck: 'Schermata blu',
  'disk-error': 'Errore del disco',
  'disk-retry': 'Operazione ripetuta sul disco',
  filesystem: 'File system danneggiato',
  'storage-reset': 'Reset del controller',
  'whea-fatal': 'Errore hardware grave',
  'whea-corrected': 'Errore hardware corretto',
};

const esc = (s: unknown) =>
  String(s === undefined || s === null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

// Indirizzi MAC e IP pubblici restano fuori dal documento, che si consegna e si stampa.
const MAC = /\b[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}\b/gi;
const IPV4 = /\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g;
const RESOLVERS = ['1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4', '9.9.9.9', '149.112.112.112'];
function scrub(s: string): string {
  return s.replace(MAC, '[MAC]').replace(IPV4, (m: string, a: string, b: string, c: string, d: string) => {
    const o = [a, b, c, d].map(Number);
    if (o.some((x) => x > 255)) return m; // un numero di versione, non un indirizzo
    const priv = o[0] === 10 || o[0] === 127 || (o[0] === 172 && o[1] >= 16 && o[1] <= 31) || (o[0] === 192 && o[1] === 168) || (o[0] === 169 && o[1] === 254) || (o[0] === 100 && o[1] >= 64 && o[1] <= 127);
    return priv || RESOLVERS.indexOf(m) >= 0 ? m : '[IP pubblico]';
  });
}
const t = (s: unknown) => esc(scrub(String(s === undefined || s === null ? '' : s)));

const sev = (s: Severity) => `<span class="pd-sev pd-${s}"><b aria-hidden="true">${SEV[s].mark}</b> ${SEV[s].label}</span>`;
const n1 = (v: number) => fmt(v, v < 10 ? 1 : 0);
const gb = (v: number) => (v >= 1000 ? `${fmt(v / 1000, 1)} TB` : `${Math.round(v)} GB`);

/** Data e ora locali registrate dall'agente ("2026-10-19T09:41:00+02:00"). */
function when(iso: string): string {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/.exec(iso);
  return m ? `${m[3]}/${m[2]}/${m[1]} alle ${m[4]}:${m[5]}` : dateIt(iso);
}

function rows(pairs: [string, string | undefined, Finding?][]): string {
  return pairs
    .filter(([, v, f]) => v || f)
    .map(([k, v, f]) => `<tr><th scope="row">${esc(k)}</th><td>${v ? t(v) : t(f?.value)}</td><td class="pd-c">${f ? sev(f.severity) : ''}</td></tr>`)
    .join('');
}

function logo(): string {
  // Logo a colori sul fondo chiaro della pagina, nelle proporzioni originali e senza effetti.
  return (
    `<svg class="pd-logo" viewBox="${LOGO_VIEWBOX}" role="img" aria-label="STARNET"><defs>` +
    `<clipPath id="pd-f"><path d="${FRAME}" clip-rule="evenodd"/></clipPath><clipPath id="pd-s"><path d="${STAR_RIGHT}" clip-rule="evenodd"/></clipPath></defs>` +
    `<path fill="${BRAND_NAVY}" fill-rule="evenodd" d="${FRAME}"/><polygon fill="${BRAND_CYAN}" points="${CYAN_FRAME}" clip-path="url(#pd-f)"/>` +
    `<path fill="${BRAND_NAVY}" fill-rule="evenodd" d="${STAR_LEFT}"/><path fill="${BRAND_NAVY}" fill-rule="evenodd" d="${STAR_RIGHT}"/>` +
    `<polygon fill="${BRAND_CYAN}" points="${CYAN_STAR}" clip-path="url(#pd-s)"/>` +
    LETTERS.map((d) => `<path fill="${BRAND_NAVY}" fill-rule="evenodd" d="${d}"/>`).join('') +
    `</svg>`
  );
}

function scoreHex(score: number, s: Severity): string {
  const hex = 'M60 8 105.03 34V86L60 112 14.97 86V34Z';
  return (
    `<div class="pd-score pd-${s}"><svg viewBox="0 0 120 120" aria-hidden="true">` +
    `<path d="${hex}" class="pd-track"/><path d="${hex}" class="pd-fill" pathLength="100" stroke-dasharray="${Math.max(0, Math.min(100, score))} 100"/></svg>` +
    `<span class="pd-score-n"><b>${score}</b><small>/100</small></span></div>`
  );
}

export function documentParts(scan: Scan, a: Analysis, opts: DocOptions = {}): { title: string; css: string; body: string } {
  const pc = scan.pc;
  const f = (id: string) => a.findings.find((x) => x.id === id);
  const host = scan.agent.host || 'questo computer';
  const title = `${pc ? 'Stato del computer' : 'Stato della rete'} · ${host} · ${dateIt(scan.agent.startedAt)}`;
  const out: string[] = [];

  out.push(
    `<div class="pd-head"><div class="pd-brand">${logo()}<span>Polaris</span></div>` +
      `<div class="pd-title"><h1>${pc ? 'Stato del computer' : 'Stato della rete'}</h1>` +
      `<p>${esc(host)}${scan.agent.os ? ` · ${esc(scan.agent.os)}` : ''} · analisi del ${esc(when(scan.agent.startedAt))}${scan.agent.elevated ? ' · da amministratore' : ''}</p></div></div>`,
  );

  // Riepilogo: punteggio, frase di sintesi e aree.
  const cats = a.categories.filter((c) => c.score !== null);
  out.push(
    `<section class="pd-summary">${scoreHex(a.score, GRADE_SEV[a.grade])}<div><p class="pd-grade">Situazione ${esc(a.grade)}</p><p class="pd-headline">${t(a.headline)}</p>` +
      `<table class="pd-cats"><tbody>${cats
        .map(
          (c) =>
            `<tr><th scope="row">${esc(c.label)}</th><td class="pd-barcell"><span class="pd-bar pd-${c.worst}"><i style="width:${c.score}%"></i></span></td><td class="pd-num">${c.score}</td><td class="pd-counts">${[
              c.counts.crit ? `${c.counts.crit} ${c.counts.crit === 1 ? 'critico' : 'critici'}` : '',
              c.counts.warn ? `${c.counts.warn} ${c.counts.warn === 1 ? 'avviso' : 'avvisi'}` : '',
            ]
              .filter(Boolean)
              .join(' · ')}</td></tr>`,
        )
        .join('')}</tbody></table></div></section>`,
  );

  // Da sistemare per primo.
  const top = a.plan.slice(0, 5);
  out.push(
    `<section><h2>Da sistemare per primo</h2>${
      top.length
        ? `<ol class="pd-top">${top.map((p) => `<li>${sev(p.severity)} <b>${esc(p.action.title)}</b><span>${esc(p.action.why)}</span></li>`).join('')}</ol>`
        : '<p class="pd-muted">Nessuna azione necessaria: tutto è nella norma.</p>'
    }</section>`,
  );

  if (pc) {
    const os = pc.os;
    const hw = pc.hardware;
    const sys = rows([
      ['Computer', hw ? [[hw.vendor, hw.model].filter(Boolean).join(' '), hw.chassis ? CHASSIS[hw.chassis] : ''].filter(Boolean).join(', ') : undefined],
      ['Windows', os ? `${os.name}${os.version ? ` ${os.version}` : ''}${os.build ? ` (build ${os.build}${os.ubr ? `.${os.ubr}` : ''})` : ''}` : undefined, f('pc.os')],
      ['Processore', pc.cpu ? `${pc.cpu.name}${pc.cpu.cores ? `, ${pc.cpu.cores} core / ${pc.cpu.threads ?? '?'} thread` : ''}` : undefined, f('pc.cpuload')],
      ['Memoria', pc.memory ? `${n1(pc.memory.totalMB / 1024)} GB, in uso ${Math.round(100 - (100 * pc.memory.availableMB) / Math.max(1, pc.memory.totalMB))} %` : undefined, f('pc.ram') ?? f('pc.ramuse')],
      ['Canali della memoria', undefined, f('pc.ram.channel')],
      ['Acceso da', os?.uptimeSec !== undefined ? `${n1(os.uptimeSec / 86400)} giorni` : undefined, f('pc.uptime')],
      ['Aggiornamenti', pc.updates?.lastInstalled ? `ultimo il ${dateIt(pc.updates.lastInstalled)}${pc.updates.lastKB ? ` (${pc.updates.lastKB})` : ''}` : undefined, f('pc.updates')],
      ['Riavvio in sospeso', pc.updates ? (pc.updates.pendingReboot ? 'sì' : 'no') : undefined, f('pc.reboot')],
      ['Programmi all\'avvio', pc.startup ? `${pc.startup.filter((x) => x.enabled).length} attivi` : undefined, f('pc.startup')],
      ['Batteria', undefined, f('pc.battery')],
      ['Alimentazione', undefined, f('pc.power')],
    ]);
    const d = pc.defender;
    const secRows = rows([
      ['Antivirus', pc.antivirus ? pc.antivirus.map((x) => `${x.name}${x.enabled ? '' : ' (disattivato)'}`).join(', ') || 'nessuno registrato' : undefined, f('pc.av')],
      [
        'Microsoft Defender',
        d ? `${d.mode === 'passive' ? 'modalità passiva' : d.realTime ? 'protezione in tempo reale attiva' : 'protezione in tempo reale disattivata'}${d.tamperProtected === undefined ? '' : `, manomissioni ${d.tamperProtected ? 'bloccate' : 'non bloccate'}`}` : undefined,
        f('pc.defender'),
      ],
      ['Firme antivirus', d?.signatureVersion ? `${d.signatureVersion}${d.signatureUpdated ? ` del ${dateIt(d.signatureUpdated)}` : ''}` : undefined],
      ['Ultima scansione', d ? `rapida: ${d.quickScanEnd ? dateIt(d.quickScanEnd) : 'mai'}; completa: ${d.fullScanEnd ? dateIt(d.fullScanEnd) : 'mai'}` : undefined],
      ['Minacce', pc.threats ? (pc.threats.length ? `${pc.threats.length} nella cronologia` : 'nessuna nella cronologia') : undefined, f('pc.threats')],
      ['Firewall di Windows', undefined, f('sec.firewall')],
      ['Secure Boot', hw?.secureBoot === undefined ? undefined : hw.secureBoot ? 'attivo' : 'disattivato', f('pc.secureboot')],
      ['TPM', hw?.tpm === undefined ? undefined : hw.tpm ? `versione ${hw.tpm}` : 'non presente', f('pc.tpm')],
      ['Requisiti di Windows 11', undefined, f('pc.win11')],
    ]);
    out.push(
      `<section class="pd-two"><div><h2>Sistema</h2><table class="pd-kv"><tbody>${sys}</tbody></table></div>` +
        `<div><h2>Sicurezza</h2><table class="pd-kv"><tbody>${secRows}</tbody></table></div></section>`,
    );

    // Dischi, come il riquadro di CrystalDiskInfo, e spazio per volume.
    const disks = (pc.disks ?? []).filter((x) => x.sizeGB > 0);
    if (disks.length || pc.volumes?.length) {
      const drows = disks
        .map((x) => {
          const st = diskStatus(x);
          const flash = isFlashDisk(x);
          const notes: string[] = [];
          for (const at of x.smart ?? []) {
            const state = attrState(at);
            if (state === 'fail' || state === 'caution') notes.push(`${smartId(at.id)} ${smartName(at.id, flash)}: ${state === 'fail' ? `${at.current} (soglia ${at.threshold})` : smartRaw(at)}`);
          }
          if (x.nvme) {
            notes.push(`riserva ${x.nvme.availableSparePct} %, scritti ${bytesText(x.nvme.dataWrittenGB)}, ${thousands(x.nvme.unsafeShutdowns)} spegnimenti non sicuri`);
            if (x.nvme.mediaErrors) notes.push(`${thousands(x.nvme.mediaErrors)} errori di integrità`);
          }
          if (!notes.length && st.signals[0]) notes.push(st.signals[0].text);
          const kind = [x.media === 'ssd' && x.bus === 'NVMe' ? 'SSD NVMe' : MEDIA[x.media], x.media === 'ssd' && x.bus === 'NVMe' ? '' : x.bus].filter(Boolean).join(' ');
          return (
            `<tr><td><b>${t(x.name)}</b>${x.system ? '<span class="pd-muted"> · Windows</span>' : ''}</td><td>${esc(kind)}</td><td class="pd-num">${gb(x.sizeGB)}</td>` +
            `<td>${sev(st.severity === 'info' ? 'ok' : st.severity)} ${st.severity === 'unknown' ? '' : `<span class="pd-muted">${esc(st.label)}</span>`}</td>` +
            `<td class="pd-num">${st.temperatureC !== undefined ? `${Math.round(st.temperatureC)} °C` : '—'}</td>` +
            `<td class="pd-num">${st.lifePct !== undefined ? `${Math.round(st.lifePct)} %` : '—'}</td>` +
            `<td class="pd-num">${st.powerOnHours !== undefined ? thousands(st.powerOnHours) : '—'}</td><td class="pd-small">${t(notes.join('; '))}</td></tr>`
          );
        })
        .join('');
      const vrows = (pc.volumes ?? [])
        .filter((v) => v.sizeGB > 0)
        .map((v) => {
          const used = Math.round(100 - (100 * v.freeGB) / v.sizeGB);
          const fs = f(`pc.space.${v.letter.replace(':', '')}`);
          return `<tr><td><b>${esc(v.letter)}</b>${v.label ? ` ${t(v.label)}` : ''}</td><td>${esc(v.fs ?? '')}</td><td class="pd-num">${gb(v.sizeGB)}</td><td class="pd-num">${n1(v.freeGB)} GB</td><td class="pd-barcell"><span class="pd-bar pd-${fs?.severity ?? 'ok'}"><i style="width:${used}%"></i></span></td><td>${fs ? sev(fs.severity) : ''}</td></tr>`;
        })
        .join('');
      out.push(
        `<section><h2>Dischi e spazio</h2>${
          drows
            ? `<table class="pd-table"><thead><tr><th>Disco</th><th>Tipo</th><th class="pd-num">Capacità</th><th>Stato</th><th class="pd-num">Temp.</th><th class="pd-num">Vita SSD</th><th class="pd-num">Ore</th><th>Da sapere</th></tr></thead><tbody>${drows}</tbody></table>`
            : ''
        }${
          vrows
            ? `<table class="pd-table pd-vol"><thead><tr><th>Volume</th><th>File system</th><th class="pd-num">Capacità</th><th class="pd-num">Libero</th><th>Occupato</th><th><span class="pd-sr">Giudizio</span></th></tr></thead><tbody>${vrows}</tbody></table>`
            : ''
        }${disks.some((x) => (x.smart ?? []).length || x.nvme) ? '' : '<p class="pd-muted pd-small">Gli attributi SMART si leggono avviando Polaris come amministratore.</p>'}</section>`,
      );
    }
  }

  // Valutazione completa, per area.
  const byCat: { [k: string]: Finding[] } = {};
  for (const x of a.findings) (byCat[x.category] = byCat[x.category] || []).push(x);
  out.push(
    `<section class="pd-findings"><h2>Valutazione completa</h2>${a.categories
      .filter((c) => byCat[c.category])
      .map(
        (c) =>
          `<h3>${esc(c.label)}</h3><table class="pd-table"><tbody>${byCat[c.category]
            // I giudizi positivi stanno su una riga: la spiegazione serve per ciò che va guardato.
            .map((x) => `<tr><td class="pd-c">${sev(x.severity)}</td><td><b>${t(x.title)}</b>: ${t(x.value)}${x.severity === 'ok' ? '' : `<br><span class="pd-small">${t(x.verdict)}</span>`}</td></tr>`)
            .join('')}</tbody></table>`,
      )
      .join('')}</section>`,
  );

  if (pc?.hardware) {
    const hw = pc.hardware;
    const c = hw.cpu;
    const b = hw.board;
    const mods = hw.memory?.modules ?? [];
    const mode = channelMode(hw.memory);
    const tech = rows([
      ['Processore', c ? [c.family ? `${cpuVendor(c.vendor)} famiglia ${c.family} modello ${c.model} stepping ${c.stepping}` : '', [coreLayout(c), c.threads ? `${c.threads} thread` : ''].filter(Boolean).join(', '), c.socket ? `zoccolo ${c.socket}` : ''].filter(Boolean).join('; ') : undefined],
      ['Cache', c?.caches?.length ? c.caches.map((x) => cacheText(x).replace(': ', ' ')).join('; ') : undefined],
      ['Scheda madre', b ? [[b.vendor, b.product, b.version].filter(Boolean).join(' '), b.biosVersion ? `BIOS ${[b.biosVendor, b.biosVersion].filter(Boolean).join(' ')}${b.biosDate ? ` del ${dateIt(b.biosDate)}` : ''}` : ''].filter(Boolean).join('; ') : undefined],
      ['Firmware', [hw.firmware === 'uefi' ? 'UEFI' : hw.firmware === 'bios' ? 'BIOS legacy' : '', hw.hypervisor ? 'hypervisor attivo' : ''].filter(Boolean).join(', ') || undefined],
      ['Memoria', mods.length ? `${mods.length} ${mods.length === 1 ? 'modulo' : 'moduli'}${hw.memory?.slots ? ` su ${hw.memory.slots} slot` : ''}${mode === 'single' || mode === 'same-channel' ? ', canale singolo' : mode === 'multi' ? ', dual channel' : ''}` : undefined],
      ...mods.map((m): [string, string] => [m.slot || m.bank || 'Modulo', `${moduleText(m)}${memVendor(m.vendor) || m.part ? `, ${[memVendor(m.vendor), m.part].filter(Boolean).join(' ')}` : ''}`]),
      ...(pc.gpus ?? []).map((g): [string, string] => ['Video', `${g.name}${g.vramMB ? `, ${g.vramMB >= 1024 ? `${n1(g.vramMB / 1024)} GB` : `${g.vramMB} MB`}` : ''}${g.width && g.height ? `, schermo ${g.width}×${g.height}${g.refreshHz ? ` a ${g.refreshHz} Hz` : ''}` : ''}${g.driverDate ? `, driver del ${dateIt(g.driverDate)}` : ''}`]),
    ]);
    out.push(`<section><h2>Scheda tecnica</h2><table class="pd-kv pd-tech"><tbody>${tech}</tbody></table></section>`);
  }

  if (pc?.eventsDays) {
    const ev = pc.events ?? [];
    out.push(
      `<section><h2>Stabilità: eventi degli ultimi ${pc.eventsDays} giorni</h2>${
        ev.length
          ? `<table class="pd-table"><thead><tr><th>Ultima volta</th><th>Evento</th><th>Origine e codice</th><th class="pd-num">Volte</th><th>Dettaglio</th></tr></thead><tbody>${ev
              .map((e) => `<tr><td>${dateIt(e.last)}</td><td>${esc(EVENT[e.kind])}</td><td>${t(e.source)} ${e.id}</td><td class="pd-num">${e.count}</td><td class="pd-small">${t(e.detail ?? '')}</td></tr>`)
              .join('')}</tbody></table>`
          : '<p class="pd-muted">Nessuno spegnimento imprevisto, schermata blu o errore hardware e di disco nel periodo.</p>'
      }${
        pc.threats && pc.threats.length
          ? `<h3>Minacce nella cronologia di Defender</h3><table class="pd-table"><tbody>${pc.threats
              .slice(0, 10)
              .map((x) => `<tr><td>${x.detected ? dateIt(x.detected) : '—'}</td><td><b>${t(x.name)}</b></td><td>gravità ${esc(THREAT_SEVERITY[x.severity])}</td><td>${esc(THREAT_STATUS[x.status])}${x.active ? ', ancora attiva' : ''}</td></tr>`)
              .join('')}</tbody></table>`
          : ''
      }</section>`,
    );
  }

  const bench = pc?.bench;
  if (bench?.cpu || bench?.disk?.length) {
    const parts: string[] = [];
    if (bench.cpu)
      parts.push(
        `<p>Processore, ${dateIt(bench.cpu.startedAt)}: un thread ${n1(bench.cpu.singleMBs)} MB/s; ${bench.cpu.threads} thread ${n1(bench.cpu.multiMBs)} MB/s di punta e ${n1(bench.cpu.sustainedMBs)} MB/s alla fine.</p>`,
      );
    for (const dk of bench.disk ?? []) {
      const r = (v?: number) => (v === undefined ? '—' : `${n1(v)}`);
      parts.push(
        `<table class="pd-table pd-bench"><caption>Unità ${esc(dk.drive)}, ${dateIt(dk.startedAt)}, file di ${dk.fileMB} MB (MB/s)</caption><thead><tr><th>Profilo</th><th class="pd-num">Lettura</th><th class="pd-num">Scrittura</th></tr></thead><tbody>` +
          (dk.seqQ8ReadMBs !== undefined ? `<tr><td>SEQ1M Q8T1</td><td class="pd-num">${r(dk.seqQ8ReadMBs)}</td><td class="pd-num">${r(dk.seqQ8WriteMBs)}</td></tr>` : '') +
          `<tr><td>SEQ1M Q1T1</td><td class="pd-num">${r(dk.seqReadMBs)}</td><td class="pd-num">${r(dk.seqWriteMBs)}</td></tr>` +
          (dk.rndQ32ReadMBs !== undefined ? `<tr><td>RND4K Q32T1</td><td class="pd-num">${r(dk.rndQ32ReadMBs)}</td><td class="pd-num">${r(dk.rndQ32WriteMBs)}</td></tr>` : '') +
          `<tr><td>RND4K Q1T1</td><td class="pd-num">${r(dk.rndReadMBs)}</td><td class="pd-num">${r(dk.rndWriteMBs)}</td></tr></tbody></table>`,
      );
    }
    out.push(`<section><h2>Test di velocità</h2>${parts.join('')}</section>`);
  }

  // Cosa occupa spazio: totali, categorie e cartelle note di Windows. Niente
  // nomi di file o di cartelle personali: il documento si consegna.
  const spaces = pc?.space ?? [];
  if (spaces.length) {
    const parts = spaces.map((r) => {
      const cats = (r.categories ?? []).filter((c) => c.alloc > 0).slice(0, 6);
      const hints = (r.hints ?? []).filter((h) => h.alloc >= 1e8);
      const un = unattributedBytes(r);
      const note = [
        r.linkedBytes ? `${sizeText(r.linkedBytes)} di collegamenti fisici contati una volta` : '',
        r.cloudFiles ? `${thousands(r.cloudFiles)} file solo online esclusi` : '',
        r.denied ? `${thousands(r.denied)} cartelle non leggibili` : '',
        r.errors ? `${thousands(r.errors)} ${r.errors === 1 ? 'cartella non letta' : 'cartelle non lette'} per errori del disco` : '',
        un > 0 ? `${sizeText(un)} non attribuiti a file leggibili` : '',
      ].filter(Boolean);
      return (
        `<h3>Unità ${esc(r.drive)}, analisi del ${dateIt(r.startedAt)}${r.partial ? ' (interrotta: valori parziali)' : ''}</h3>` +
        `<p>${sizeText(r.allocBytes)} in ${thousands(r.files)} file e ${thousands(r.dirs)} cartelle${r.totalBytes > 0 ? `; liberi ${sizeText(r.freeBytes)} su ${sizeText(r.totalBytes)}` : ''}.${note.length ? ` <span class="pd-small">${esc(note.join('; '))}.</span>` : ''}</p>` +
        (cats.length ? `<p class="pd-small">Per tipo: ${cats.map((c) => `${esc(SPACE_CATEGORY_LABEL[c.id] ?? c.id)} ${sizeText(c.alloc)} (${pctText(c.alloc, r.allocBytes)})`).join(', ')}.</p>` : '') +
        (hints.length
          ? `<table class="pd-table"><thead><tr><th>Cartella o file noto</th><th class="pd-num">Spazio</th><th>Cosa fare</th></tr></thead><tbody>${hints
              .map((h) => `<tr><td>${esc(SPACE_HINTS[h.id]?.label ?? h.id)}</td><td class="pd-num">${sizeText(h.alloc)}</td><td>${esc(SPACE_HINTS[h.id] ? SPACE_RISK_LABEL[SPACE_HINTS[h.id].risk] : '')}</td></tr>`)
              .join('')}</tbody></table>`
          : '')
      );
    });
    out.push(`<section><h2>Cosa occupa spazio</h2>${parts.join('')}</section>`);
  }

  // Piano d'azione con le caselle da spuntare a mano.
  if (a.plan.length)
    out.push(
      `<section class="pd-plan"><h2>Piano d'azione</h2><table class="pd-table"><thead><tr><th class="pd-c">Fatto</th><th>#</th><th>Azione</th><th>Gravità</th><th>Impatto</th><th>Difficoltà</th></tr></thead><tbody>${a.plan
        .map(
          (p, i) =>
            `<tr><td class="pd-c"><span class="pd-box" aria-hidden="true"></span></td><td class="pd-num">${i + 1}</td><td><b>${esc(p.action.title)}</b><br><span class="pd-small">risolve: ${t(p.findings.join(', '))}</span></td><td>${sev(p.severity)}</td><td>${esc(p.action.impact)}</td><td>${esc(p.action.effort)}</td></tr>`,
        )
        .join('')}</tbody></table></section>`,
    );

  out.push(
    `<section class="pd-sign"><h2>Note e firma</h2><div class="pd-notes"><span></span><span></span><span></span><span></span></div>` +
      `<div class="pd-signrow"><div>Intervento di<span></span></div><div>Data<span></span></div><div>Firma<span></span></div></div></section>`,
  );

  out.push(
    `<div class="pd-foot">Generato da STARNET Polaris${opts.version ? ` ${esc(opts.version)}` : ''} (motore di analisi ${ENGINE_VERSION})${opts.generated ? ` il ${esc(opts.generated)}` : ''}. ` +
      `Il documento descrive il ${pc ? 'computer' : 'collegamento'} al momento dell'analisi. Non contiene numeri di serie, indirizzi MAC, l'indirizzo IP pubblico né percorsi personali. ` +
      `Date di fine supporto di Windows e soglie dei test sono indicative: verificale sulle fonti ufficiali.</div>`,
  );

  return { title, css: DOC_CSS, body: out.join('') };
}

/** Documento HTML autonomo, da aprire nel browser, stampare o salvare in PDF. */
export function renderDocument(scan: Scan, a: Analysis, opts: DocOptions = {}): string {
  const p = documentParts(scan, a, opts);
  return `<!doctype html><html lang="it"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${esc(p.title)}</title><style>${p.css}</style></head><body class="pdoc-page"><main class="pdoc">${p.body}</main></body></html>`;
}

const DOC_CSS = `@page{size:A4;margin:13mm 12mm 15mm}
.pdoc-page{margin:0;background:#e9eef5}
.pdoc{--navy:#022D62;--cyan:#00B9FE;--ink:#14213d;--muted:#55657d;--line:#d6dee9;--soft:#f3f6fa;--ok:#18794e;--info:#1f5fae;--warn:#8a5300;--crit:#b42318;--unknown:#55657d;
box-sizing:border-box;max-width:210mm;margin:0 auto;padding:14mm 12mm;background:#fff;color:var(--ink);font:10pt/1.45 "Segoe UI",Inter,system-ui,-apple-system,Roboto,Arial,sans-serif;-webkit-print-color-adjust:exact;print-color-adjust:exact}
.pdoc *{box-sizing:border-box}
.pdoc h1,.pdoc h2,.pdoc h3{font-family:inherit;font-stretch:normal}
.pdoc th,.pdoc td{font:inherit;color:inherit;background:none;position:static;white-space:normal;text-transform:none;letter-spacing:normal}
.pdoc tr:last-child td{border-bottom:1px solid var(--line)}
.pdoc h1{margin:0;font-size:19pt;line-height:1.15;color:var(--navy);letter-spacing:-.01em}
.pdoc h2{margin:16px 0 7px;padding-bottom:3px;font-size:11.5pt;color:var(--navy);border-bottom:1.5px solid var(--line);break-after:avoid}
.pdoc h3{margin:10px 0 4px;font-size:9.5pt;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;break-after:avoid}
.pdoc p{margin:4px 0}
.pdoc .pd-summary,.pdoc .pd-sign,.pdoc .pd-bench{break-inside:avoid}
.pdoc .pd-head{display:flex;align-items:center;gap:18px;padding-bottom:12px;margin-bottom:6px;border-bottom:3px solid var(--navy)}
.pdoc .pd-brand{display:flex;flex-direction:column;align-items:center;gap:2px;padding:4px 6px}
.pdoc .pd-logo{width:76px;height:auto;display:block}
.pdoc .pd-brand span{font-size:7.5pt;font-weight:700;letter-spacing:.32em;text-transform:uppercase;color:var(--navy)}
.pdoc .pd-title p{color:var(--muted);font-size:9.5pt}
.pdoc .pd-summary{display:flex;gap:18px;align-items:center;margin:12px 0 4px;padding:12px 14px;background:var(--soft);border:1px solid var(--line);border-radius:10px}
.pdoc .pd-score{position:relative;width:104px;height:104px;flex:none}
.pdoc .pd-score svg{width:100%;height:100%;display:block}
.pdoc .pd-score path{fill:none;stroke-width:10;stroke-linejoin:round}
.pdoc .pd-track{stroke:#dfe6ef}
.pdoc .pd-fill{stroke:currentColor}
.pdoc .pd-score-n{position:absolute;inset:0;display:flex;align-items:baseline;justify-content:center;padding-top:36px;color:var(--ink)}
.pdoc .pd-score-n b{font-size:25pt;line-height:1}
.pdoc .pd-score-n small{font-size:9pt;color:var(--muted)}
.pdoc .pd-score.pd-ok{color:var(--ok)}.pdoc .pd-score.pd-warn{color:var(--warn)}.pdoc .pd-score.pd-crit{color:var(--crit)}
.pdoc .pd-grade{font-size:8.5pt;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}
.pdoc .pd-headline{font-size:11pt;font-weight:600;margin:2px 0 8px}
.pdoc table{width:100%;border-collapse:collapse;font-size:inherit}
.pdoc th,.pdoc td{padding:3.5px 6px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line)}
.pdoc thead th{font-size:7.8pt;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);border-bottom:1.5px solid var(--line)}
.pdoc tr{break-inside:avoid}
.pdoc caption{caption-side:top;text-align:left;font-size:9pt;color:var(--muted);padding:4px 0}
.pdoc .pd-cats th{font-weight:600;width:28%;border:0;padding:2px 6px 2px 0}
.pdoc .pd-cats td{border:0;padding:2px 6px}
.pdoc .pd-barcell{width:34%;vertical-align:middle}
.pdoc .pd-bar{display:block;height:7px;border-radius:4px;background:#e2e8f0;overflow:hidden}
.pdoc .pd-bar i{display:block;height:100%;background:var(--ok)}
.pdoc .pd-bar.pd-warn i{background:var(--warn)}.pdoc .pd-bar.pd-crit i{background:var(--crit)}.pdoc .pd-bar.pd-info i{background:var(--info)}
.pdoc .pd-num{text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums}
.pdoc .pd-counts{color:var(--muted);font-size:8.5pt;white-space:nowrap}
.pdoc .pd-c{width:1%;white-space:nowrap}
.pdoc .pd-sev{display:inline-flex;align-items:center;gap:4px;padding:0 6px;border:1px solid currentColor;border-radius:4px;font-size:7.8pt;font-weight:700;line-height:15px;white-space:nowrap}
.pdoc .pd-sev b{font-size:8pt}
.pdoc .pd-sev.pd-ok{color:var(--ok)}.pdoc .pd-sev.pd-info{color:var(--info)}.pdoc .pd-sev.pd-warn{color:var(--warn)}.pdoc .pd-sev.pd-crit{color:var(--crit)}.pdoc .pd-sev.pd-unknown{color:var(--unknown)}
.pdoc .pd-top{margin:0;padding-left:20px}
.pdoc .pd-top li{margin:0 0 6px;break-inside:avoid}
.pdoc .pd-top li span:last-child{display:block;color:var(--muted);font-size:9pt}
.pdoc .pd-two{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.pdoc .pd-kv th{width:34%;font-weight:600;color:var(--muted)}
.pdoc .pd-tech th{width:22%}
.pdoc .pd-table td{font-size:9pt}
.pdoc .pd-vol{margin-top:8px}
.pdoc .pd-small{font-size:8.3pt;color:var(--muted)}
.pdoc .pd-muted{color:var(--muted)}
.pdoc .pd-box{display:inline-block;width:12px;height:12px;border:1.4px solid var(--ink);border-radius:2px}
.pdoc .pd-notes span{display:block;height:24px;border-bottom:1px solid #9aa8bb}
.pdoc .pd-signrow{display:grid;grid-template-columns:1.4fr 1fr 1.4fr;gap:16px;margin-top:14px;font-size:8.5pt;color:var(--muted)}
.pdoc .pd-signrow span{display:block;height:26px;border-bottom:1px solid var(--ink)}
.pdoc .pd-foot{margin-top:18px;padding-top:8px;border-top:1px solid var(--line);font-size:7.8pt;color:var(--muted)}
.pdoc .pd-sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
@media screen and (max-width:640px){.pdoc{padding:16px;font-size:9pt}.pdoc .pd-two{grid-template-columns:1fr}.pdoc .pd-summary{flex-direction:column;align-items:flex-start}.pdoc th,.pdoc td{padding:3px 4px}}
@media print{.pdoc-page{background:#fff}.pdoc{max-width:none;margin:0;padding:0}}`;
