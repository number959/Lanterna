import { BookOpenText, ListTree, RefreshCw, ShieldAlert, TriangleAlert } from 'lucide-react';
import { m } from 'motion/react';
import { useMemo, useState } from 'react';
import { fileSeverity, folderLabel, isLookalike, listeners, signatureLabel, userWritable } from '../engine';
import type { ConnSummary, ListenPort, ProcessDetail, ProcessesData, Scan, Severity } from '../engine';
import { isKernelProc } from '../engine';
import { readProcesses } from './api';
import { readError } from './errors';
import { SevIcon, Stat, TableWrap, fmtNum, useOpenGuide, useToast } from './components';
import type { CrashTargetRef } from './crashes';
import { rise, spring } from './motion';
import type { ViewProps } from './views';

// Processi in esecuzione, come Process Explorer e TCPView ma leggibili da chi
// non è esperto: file e informazioni di versione, firma digitale, cartella,
// tipo di account (mai il nome), porte in ascolto e connessioni contate per
// destinazione (mai gli indirizzi). Polaris legge soltanto: non chiude
// processi e non chiude connessioni. I giudizi sono quelli del motore
// (engine/procs.ts): qui si mostrano gli stessi fatti, riga per riga.

/** Righe mostrate prima di "Mostra tutti". */
export const PROCS_SHOWN = 60;

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

/** Tipo di account del processo, per categoria: il nome non lo legge nessuno. */
const OWNER: Record<NonNullable<ProcessDetail['owner']>, string> = { self: 'Tu', system: 'Sistema', other: 'Altro account', unknown: 'Non leggibile' };

export function ownerText(p: ProcessDetail): string {
  if (!p.owner) return p.access === 'none' ? 'Non leggibile' : '—';
  return `${OWNER[p.owner]}${p.elevated && p.owner === 'self' ? ', come amministratore' : ''}`;
}

/**
 * Firma del processo con il tono: gli stessi criteri dei giudizi, più i casi
 * senza file. Un processo che non si apre anche con Polaris da
 * amministratore è protetto da Windows (o di un altro account, senza il
 * privilegio di debug che Polaris non chiede): «senza amministratore»
 * sarebbe falso.
 */
export function procSignature(p: ProcessDetail, elevated = false): { text: string; tone: Severity } {
  if (p.access === 'none') return { text: elevated ? 'Non apribile: processo protetto da Windows' : 'Non apribile senza amministratore', tone: 'unknown' };
  const f = p.file;
  if (!f || !f.path) return isKernelProc(p) ? { text: 'Nucleo di Windows: nessun file da verificare', tone: 'info' } : { text: 'File non letto', tone: 'unknown' };
  if (f.missing) return { text: 'File non più presente', tone: 'unknown' };
  const l = signatureLabel(f.signature);
  const sev = fileSeverity(f);
  if (f.signature && f.signature.status === 'unsigned' && userWritable(f.folder)) return { text: 'Nessuna firma, in una cartella che un utente può scrivere', tone: sev };
  return { text: l.text, tone: sev === 'unknown' ? l.tone : sev };
}

/** Errore di una lettura dal vivo in italiano (in ./errors, comune con il confronto di Windows 11). */
export { readError };

const SCOPE: Record<ListenPort['scope'], string> = { all: 'tutte le reti', local: 'solo questo PC', specific: 'una rete' };

/** Porte in ascolto: "TCP 8200 (tutte le reti), UDP 1900 (tutte le reti)". */
export function listenText(ls?: ListenPort[]): string {
  const seen: string[] = [];
  const out: string[] = [];
  for (const l of ls ?? []) {
    const k = `${l.proto}${l.port}${l.scope}`;
    if (seen.indexOf(k) >= 0) continue;
    seen.push(k);
    out.push(`${l.proto.toUpperCase()} ${l.port} (${SCOPE[l.scope]})`);
  }
  return out.join(', ');
}

/** Connessioni per destinazione: "2 verso Internet, 1 in rete locale". */
export function connText(c?: ConnSummary): string {
  if (!c) return '';
  return [c.internet ? `${c.internet} verso Internet` : '', c.lan ? `${c.lan} in rete locale` : '', c.local ? `${c.local} su questo PC` : ''].filter(Boolean).join(', ');
}

/** Porte remote più usate: "porta 443" o "porte 443 (12), 80 (2)". */
export function remotePortsText(c?: ConnSummary): string {
  const ps = c?.remotePorts ?? [];
  if (!ps.length) return '';
  if (ps.length === 1) return `porta ${ps[0].port}`;
  return `porte ${ps.map((p) => `${p.port} (${p.count})`).join(', ')}`;
}

const connTotal = (c?: ConnSummary) => (c ? (c.internet ?? 0) + (c.lan ?? 0) + (c.local ?? 0) : 0);

/** In ascolto da altri dispositivi (non solo da questo PC). */
const listensOut = (p: ProcessDetail) => (p.listen ?? []).some((l) => l.scope !== 'local');

export interface ProcCheck {
  sev: Severity;
  /** Perché il processo è da controllare, in breve; vuoto se non lo è. */
  why: string[];
}

const RANK: Record<Severity, number> = { unknown: 0, ok: 1, info: 2, warn: 3, crit: 4 };

/**
 * Da controllare: firma grave o da guardare, senza firma in una cartella che
 * un utente può scrivere, nome di un programma di Windows fuori posto, in
 * ascolto su tutte le reti senza firma valida o da una cartella che un
 * utente può scrivere (come i giudizi). I processi di Polaris non si
 * giudicano.
 */
export function procCheck(p: ProcessDetail, riskyListen: number[]): ProcCheck {
  if (p.polaris) return { sev: 'ok', why: [] };
  const why: string[] = [];
  let sev: Severity = 'ok';
  const fs = p.file && p.file.signature ? fileSeverity(p.file) : 'unknown';
  if (fs === 'crit' || fs === 'warn') {
    sev = fs;
    const s = p.file!.signature!;
    why.push(s.status === 'unsigned' ? 'senza firma in una cartella che un utente può scrivere' : fs === 'crit' ? 'firma alterata o revocata' : 'firma da guardare');
  }
  if (isLookalike(p)) {
    if (RANK.warn > RANK[sev]) sev = 'warn';
    why.push('nome di un programma di Windows fuori dalla cartella di sistema');
  }
  if (riskyListen.indexOf(p.pid) >= 0) {
    if (RANK.warn > RANK[sev]) sev = 'warn';
    why.push('in ascolto su tutte le reti');
  }
  return { sev, why };
}

export type ProcFilter = 'all' | 'check' | 'listen';
export type ProcSortKey = 'name' | 'sig' | 'folder' | 'owner' | 'net' | 'mem' | 'cpu';

export interface ProcRow {
  p: ProcessDetail;
  check: ProcCheck;
  /** Profondità nell'albero (0 senza albero). */
  depth: number;
  /** Mostrato solo come antenato di un processo che corrisponde alla ricerca o al filtro. */
  ctx?: boolean;
  /** Processo da cui è partito (nell'albero). */
  parent?: ProcessDetail;
}

export interface ProcView {
  query: string;
  filter: ProcFilter;
  sort: { k: ProcSortKey; dir: 1 | -1 };
  tree: boolean;
}

const OWNER_ORDER: Record<string, number> = { self: 0, other: 1, system: 2, unknown: 3 };

function sortValue(r: ProcRow, k: ProcSortKey): number | string {
  const p = r.p;
  switch (k) {
    case 'name':
      return p.name.toLowerCase();
    case 'sig':
      // Prima i più gravi, poi i non verificati.
      return -(RANK[procSignature(p).tone] * 10 + RANK[r.check.sev]);
    case 'folder':
      return p.file?.folder ? folderLabel(p.file.folder).toLowerCase() : '~';
    case 'owner':
      return p.owner ? OWNER_ORDER[p.owner] : 9;
    case 'net':
      return (p.listen?.length ?? 0) * 1000 + connTotal(p.conns);
    case 'mem':
      return p.memoryMB ?? -1;
    case 'cpu':
      return p.cpuPct ?? -1;
  }
}

function compare(k: ProcSortKey, dir: 1 | -1) {
  return (a: ProcRow, b: ProcRow) => {
    const va = sortValue(a, k);
    const vb = sortValue(b, k);
    const c = va < vb ? -1 : va > vb ? 1 : 0;
    return c * dir || a.p.name.localeCompare(b.p.name, 'it') || a.p.pid - b.p.pid;
  };
}

/** Il processo padre, se è ancora quello: un padre avviato dopo il figlio è un PID riusato. */
function parentIn(p: ProcessDetail, byPid: { [pid: number]: ProcessDetail }): ProcessDetail | undefined {
  if (p.parentPid === undefined || p.parentPid === p.pid) return undefined;
  const q = byPid[p.parentPid];
  if (!q) return undefined;
  if (q.started && p.started && q.started > p.started) return undefined;
  return q;
}

const matches = (p: ProcessDetail, q: string) =>
  !q || [p.name, p.file?.description, p.file?.company, ...(p.services ?? [])].some((x) => !!x && x.toLowerCase().indexOf(q) >= 0);

/**
 * Righe della tabella: ricerca, filtro, ordinamento e, a richiesta, albero
 * padre-figlio (con gli antenati dei processi trovati, mostrati come
 * contesto).
 */
export function procRows(scan: Scan, v: ProcView): ProcRow[] {
  const data = scan.pc?.procs;
  if (!data) return [];
  const risky = listeners(scan)
    .filter((l) => l.risky)
    .map((l) => l.proc.pid);
  const q = v.query.trim().toLowerCase();
  const all: ProcRow[] = data.items.map((p) => ({ p, check: procCheck(p, risky), depth: 0 }));
  const keep = (r: ProcRow) => matches(r.p, q) && (v.filter === 'all' || (v.filter === 'check' ? r.check.why.length > 0 : listensOut(r.p)));
  const cmp = compare(v.sort.k, v.sort.dir);
  if (!v.tree) return all.filter(keep).sort(cmp);

  const byPid: { [pid: number]: ProcessDetail } = {};
  for (const r of all) byPid[r.p.pid] = r.p;
  const rowOf: { [pid: number]: ProcRow } = {};
  for (const r of all) rowOf[r.p.pid] = r;
  // Processi trovati più i loro antenati.
  const shown: { [pid: number]: boolean } = {};
  for (const r of all) {
    if (!keep(r)) continue;
    shown[r.p.pid] = true;
    // Corrisponde al filtro: mai contesto, anche se la risalita da un figlio venuto prima l'aveva segnato così.
    r.ctx = false;
    let up = parentIn(r.p, byPid);
    for (let guard = 0; up && guard < 64 && !shown[up.pid]; guard++) {
      shown[up.pid] = true;
      rowOf[up.pid].ctx = !keep(rowOf[up.pid]);
      up = parentIn(up, byPid);
    }
  }
  const children: { [pid: number]: ProcRow[] } = {};
  const roots: ProcRow[] = [];
  for (const r of all) {
    if (!shown[r.p.pid]) continue;
    const par = parentIn(r.p, byPid);
    if (par && shown[par.pid]) {
      r.parent = par;
      (children[par.pid] = children[par.pid] ?? []).push(r);
    } else roots.push(r);
  }
  // Due processi che si indicano a vicenda come padre (PID riusati, ore di
  // avvio non lette) non hanno radice: sparirebbero dall'albero con i loro
  // discendenti. Ogni riga mostrata ma non raggiunta diventa una radice.
  const reach: { [pid: number]: boolean } = {};
  const mark = (r: ProcRow) => {
    if (reach[r.p.pid]) return;
    reach[r.p.pid] = true;
    for (const c of children[r.p.pid] ?? []) mark(c);
  };
  roots.forEach(mark);
  for (const r of all) {
    if (!shown[r.p.pid] || reach[r.p.pid]) continue;
    r.parent = undefined;
    roots.push(r);
    mark(r);
  }
  const out: ProcRow[] = [];
  const done: { [pid: number]: boolean } = {};
  const walk = (list: ProcRow[], depth: number) => {
    for (const r of list.sort(cmp)) {
      if (done[r.p.pid]) continue;
      done[r.p.pid] = true;
      r.depth = depth;
      out.push(r);
      if (children[r.p.pid]) walk(children[r.p.pid], depth + 1);
    }
  };
  walk(roots, 0);
  return out;
}

const memText = (mb?: number) => (mb === undefined ? '—' : mb >= 1024 ? `${fmtNum(mb / 1024, 1)} GB` : `${Math.round(mb)} MB`);
const cpuText = (v?: number) => (v === undefined ? '—' : `${fmtNum(v, v < 10 ? 1 : 0)} %`);

const whenText = (iso?: string) => {
  if (!iso) return '';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString('it-IT', { dateStyle: 'short', timeStyle: 'short' });
};

/** Il PC e l'analisi su cui è partita una nuova lettura dei processi: si unisce solo a quelli (come le schermate blu). */
export type ProcsTargetRef = CrashTargetRef;

const COLS: { k: ProcSortKey; label: string; first: 1 | -1 }[] = [
  { k: 'name', label: 'Processo', first: 1 },
  { k: 'sig', label: 'Firma', first: 1 },
  { k: 'folder', label: 'Cartella', first: 1 },
  { k: 'owner', label: 'Utente', first: 1 },
  { k: 'net', label: 'Rete', first: -1 },
  { k: 'mem', label: 'Memoria', first: -1 },
  { k: 'cpu', label: 'CPU', first: -1 },
];

function Row({ r, tree, elevated }: { r: ProcRow; tree: boolean; elevated: boolean }) {
  const p = r.p;
  const sig = procSignature(p, elevated);
  const f = p.file;
  const listen = listenText(p.listen);
  const conns = connText(p.conns);
  const ports = remotePortsText(p.conns);
  const desc = [f?.description, f?.company].filter((x, i, a) => !!x && a.indexOf(x) === i).join(' · ');
  return (
    <tr className={[p.polaris ? 'proc-polaris' : '', r.ctx ? 'proc-ctx' : ''].filter(Boolean).join(' ') || undefined} data-sev={r.check.why.length ? r.check.sev : undefined}>
      <td className="proc-name" style={tree ? { paddingLeft: 14 + r.depth * 18 } : undefined}>
        <span className="proc-title">
          {tree && r.depth > 0 && (
            <span className="proc-branch" aria-hidden>
              └
            </span>
          )}
          <b>{p.name}</b>
          <span className="mono faint">PID {p.pid}</span>
          {tree && r.parent && <span className="sr-only">, avviato da {r.parent.name}</span>}
        </span>
        {desc && <span className="faint proc-desc">{desc}</span>}
        {(p.polaris || r.check.why.length > 0 || (p.services ?? []).length > 0 || p.arch === 'x86' || p.arch === 'x64-on-arm64' || r.ctx) && (
          <span className="proc-tags">
            {p.polaris && <span className="tag accent">STARNET Polaris: escluso dai giudizi</span>}
            {r.check.why.length > 0 && (
              <span className={`sev ${r.check.sev}`}>
                <SevIcon sev={r.check.sev} size={13} />
                da controllare: {r.check.why.join(', ')}
              </span>
            )}
            {(p.services ?? []).length > 0 && (
              <span className="tag" title={p.services!.join(', ')}>
                {p.services!.length === 1 ? `servizio ${p.services![0]}` : `${p.services!.length} servizi: ${p.services!.slice(0, 3).join(', ')}${p.services!.length > 3 ? '…' : ''}`}
              </span>
            )}
            {p.arch === 'x86' && <span className="tag">32 bit</span>}
            {p.arch === 'x64-on-arm64' && <span className="tag">x64 emulato su ARM</span>}
            {r.ctx && <span className="tag">mostrato come contesto</span>}
          </span>
        )}
      </td>
      <td className="proc-sig">
        <span className={`c-${sig.tone}`}>
          <SevIcon sev={sig.tone} size={14} />
          <span>{sig.text}</span>
        </span>
      </td>
      <td className="proc-folder">
        {f?.path ? (
          <>
            <span>{folderLabel(f.folder)}</span>
            <span className="mono faint" title={f.path}>
              {f.path}
            </span>
          </>
        ) : (
          <span className="faint">—</span>
        )}
      </td>
      <td>{ownerText(p)}</td>
      <td className="proc-net">
        {listen || conns ? (
          <>
            {listen && <span>in ascolto: {listen}</span>}
            {conns && (
              <span>
                {conns}
                {ports && <span className="faint"> · {ports}</span>}
              </span>
            )}
          </>
        ) : (
          <span className="faint">—</span>
        )}
      </td>
      <td className="mono num">{memText(p.memoryMB)}</td>
      <td className="mono num">{cpuText(p.cpuPct)}</td>
    </tr>
  );
}

/**
 * Elenco dei processi con firma e connessioni. "Aggiorna" chiede una lettura
 * nuova all'agente (GET /api/processes), che sostituisce quella del
 * rapporto solo se è ancora lo stesso PC e la stessa analisi.
 */
export function ProcsCard({ scan, live, source, addProcs }: Pick<ViewProps, 'scan' | 'live' | 'source' | 'addProcs'>) {
  const toast = useToast();
  const openGuide = useOpenGuide();
  const data: ProcessesData | undefined = scan.pc?.procs;
  const anyCpu = !!data && data.items.some((p) => p.cpuPct !== undefined);
  const [state, setView] = useState<ProcView>({ query: '', filter: 'all', sort: { k: anyCpu ? 'cpu' : 'mem', dir: -1 }, tree: false });
  // Dopo una lettura dal vivo la CPU non c'è: l'ordine per CPU diventa quello per memoria.
  const view = useMemo<ProcView>(() => (state.sort.k === 'cpu' && !anyCpu ? { ...state, sort: { k: 'mem', dir: -1 } } : state), [state, anyCpu]);
  const [all, setAll] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const rows = useMemo(() => procRows(scan, view), [scan, view]);
  const counts = useMemo(() => {
    const base = procRows(scan, { query: '', filter: 'all', sort: { k: 'name', dir: 1 }, tree: false });
    return {
      total: base.length,
      check: base.filter((r) => r.check.why.length > 0).length,
      // Il caso più grave tra quelli da controllare: una firma alterata è critica, non solo da controllare.
      sev: base.reduce<Severity>((s, r) => (r.check.why.length && RANK[r.check.sev] > RANK[s] ? r.check.sev : s), 'ok'),
      listen: base.filter((r) => listensOut(r.p)).length,
      polaris: base.filter((r) => r.p.polaris).length,
    };
  }, [scan]);
  const canRead = live && source === 'agent';

  const refresh = () => {
    const target: ProcsTargetRef = { host: scan.agent.host, startedAt: scan.agent.startedAt };
    setBusy(true);
    setError(null);
    readProcesses()
      .then(
        (r) => {
          if (!addProcs(r, target)) return;
          toast(`Processi aggiornati · ${plural(r.items.length, 'processo', 'processi')}`, 'ok');
        },
        (e) => setError(readError(e)),
      )
      .finally(() => setBusy(false));
  };

  const th = (c: (typeof COLS)[number]) => {
    const on = view.sort.k === c.k;
    return (
      <th key={c.k} aria-sort={on ? (view.sort.dir === 1 ? 'ascending' : 'descending') : 'none'} className={c.k === 'mem' || c.k === 'cpu' ? 'num' : undefined}>
        <button onClick={() => setView({ ...view, sort: { k: c.k, dir: on ? ((-view.sort.dir) as 1 | -1) : c.first } })}>
          {c.label}
          <m.span animate={{ opacity: on ? 1 : 0, rotate: view.sort.dir === 1 ? 180 : 0 }} transition={spring.snappy} style={{ display: 'inline-block' }} aria-hidden>
            ▼
          </m.span>
        </button>
      </th>
    );
  };

  const shown = all ? rows : rows.slice(0, PROCS_SHOWN);
  const loadPct = scan.pc?.cpu?.loadPct;

  return (
    <m.section variants={rise} className="card procs-card">
      <div className="card-head">
        <h2 className="disk-title">
          <ListTree size={19} aria-hidden /> Processi in esecuzione
        </h2>
        <span className="sub">
          {data ? `letti il ${whenText(data.at)}` : 'come Process Explorer e TCPView'}
          {anyCpu && loadPct !== undefined ? ` · processore al ${fmtNum(loadPct)} % durante la misura` : ''}
        </span>
        <span className="spacer" />
        {canRead && (
          <button className="btn small" onClick={refresh} disabled={busy}>
            <RefreshCw size={15} className={busy ? 'spin' : undefined} aria-hidden />
            {busy ? 'Lettura in corso…' : data ? 'Aggiorna' : 'Leggi i processi'}
          </button>
        )}
      </div>

      {!data && (
        <div className="notice">
          <TriangleAlert size={18} aria-hidden />
          <span>
            Questo rapporto non contiene l'elenco dei processi con la firma digitale: è stato creato con una versione precedente di Polaris oppure la lettura
            non è riuscita.{canRead ? ' Puoi leggerli ora.' : ''}
          </span>
        </div>
      )}

      {data && (
        <>
          <div className="stats procs-stats">
            <Stat k="Processi" v={String(counts.total)} />
            <Stat k="Da controllare" v={String(counts.check)} sev={counts.sev} />
            <Stat k="In ascolto sulla rete" v={data.connsRead ? String(counts.listen) : 'non letto'} sev={data.connsRead ? undefined : 'unknown'} />
            <Stat k="Non leggibili" v={String(data.unreadable ?? 0)} sev={data.unreadable && !data.elevated ? 'unknown' : undefined} />
          </div>

          {!!data.unreadable && !data.elevated && (
            <div className="notice" style={{ marginTop: 12 }}>
              <ShieldAlert size={18} aria-hidden />
              <span>
                {plural(data.unreadable, 'processo di un altro account non si apre', 'processi di altri account non si aprono')} senza i permessi di
                amministratore: se ne conoscono il nome, le porte e i servizi, non il file né la firma. Per verificarli tutti avvia Polaris come
                amministratore e ripeti l'analisi.
              </span>
            </div>
          )}
          {/* connsRead falso non arriva nel JSON (omitempty): assente vuol dire non letto. */}
          {(data.partial || !data.connsRead) && (
            <div className="notice" style={{ marginTop: 12 }}>
              <TriangleAlert size={18} aria-hidden />
              <span>
                {data.partial ? 'La lettura non è finita in tempo: l\'elenco o le firme possono essere incompleti. ' : ''}
                {!data.connsRead ? 'Le tabelle delle connessioni non si sono potute leggere: porte e connessioni non sono indicate.' : ''}
              </span>
            </div>
          )}

          <div className="inv-toolbar procs-toolbar">
            <input
              className="field"
              type="search"
              placeholder="Cerca un processo o un servizio"
              aria-label="Cerca un processo o un servizio"
              value={view.query}
              onChange={(e) => setView({ ...view, query: e.target.value })}
            />
            <div className="chips-row" role="group" aria-label="Mostra i processi">
              {(
                [
                  ['all', `Tutti (${counts.total})`],
                  ['check', `Solo da controllare (${counts.check})`],
                  ['listen', `In ascolto sulla rete (${data.connsRead ? counts.listen : 'non letto'})`],
                ] as [ProcFilter, string][]
              ).map(([id, label]) => (
                <button key={id} className="chip" aria-pressed={view.filter === id} onClick={() => setView({ ...view, filter: id })}>
                  {label}
                </button>
              ))}
            </div>
            <button className="chip proc-tree-toggle" role="switch" aria-checked={view.tree} onClick={() => setView({ ...view, tree: !view.tree })}>
              <ListTree size={14} aria-hidden /> Albero dei processi
            </button>
          </div>
          <p className="sr-only" aria-live="polite">
            {all || rows.length <= PROCS_SHOWN ? plural(rows.length, 'processo mostrato', 'processi mostrati') : `${PROCS_SHOWN} di ${rows.length} processi mostrati`}
          </p>

          {rows.length ? (
            <TableWrap label="Processi in esecuzione">
              <table className="pc-table procs-table">
                <thead>
                  <tr>{COLS.map(th)}</tr>
                </thead>
                <tbody>
                  {shown.map((r) => (
                    <Row key={r.p.pid} r={r} tree={view.tree} elevated={!!data.elevated} />
                  ))}
                </tbody>
              </table>
            </TableWrap>
          ) : (
            <p className="muted">
              {view.filter === 'check' && !view.query
                ? 'Nessun processo da controllare tra quelli letti.'
                : view.filter === 'listen' && !view.query
                  ? data.connsRead
                    ? 'Nessun processo in ascolto da altri dispositivi.'
                    : 'Le connessioni non sono state lette: non si sa quali processi sono in ascolto.'
                  : 'Nessun processo corrisponde alla ricerca.'}
            </p>
          )}
          {rows.length > PROCS_SHOWN && (
            <button className="link-btn" onClick={() => setAll(!all)} aria-expanded={all} style={{ marginTop: 10 }}>
              {all ? 'Mostra solo i primi' : `Mostra tutti i ${rows.length} processi`}
            </button>
          )}
          {!anyCpu && (
            <p className="faint card-foot">
              Il carico del processore di ogni processo si misura solo durante l'analisi: in questa lettura non c'è (la colonna CPU resta vuota).
            </p>
          )}
        </>
      )}

      {error && (
        <div className="notice alert" role="alert" style={{ marginTop: 12 }}>
          <TriangleAlert size={18} aria-hidden />
          <span>Lettura non riuscita: {error}</span>
        </div>
      )}

      <div className="crash-actions">
        {openGuide && (
          <button className="link-btn" onClick={() => openGuide('processi-firme')}>
            <BookOpenText size={15} aria-hidden /> Come leggere firme, cartelle e connessioni
          </button>
        )}
      </div>
      <p className="faint card-foot">
        {source === 'demo'
          ? 'Dati dimostrativi: nella demo l\'elenco non si aggiorna dal vivo. '
          : source === 'file'
            ? 'Rapporto importato: l\'elenco è quello del momento dell\'analisi. '
            : ''}
        Polaris legge soltanto: non chiude processi né connessioni. La firma si verifica senza Internet, quindi la revoca dei certificati non è controllata
        online; descrizione e produttore li scrive chi ha creato il file e non sono una prova. Dell'account si indica solo il tipo, mai il nome; delle
        connessioni solo quante sono e verso dove (questo PC, rete locale, Internet), mai gli indirizzi.
        {counts.polaris === 1
          ? ' Il processo di STARNET Polaris è escluso dai giudizi.'
          : counts.polaris > 1
            ? ` I ${counts.polaris} processi di STARNET Polaris (l'agente e la sua finestra) sono esclusi dai giudizi.`
            : ''}
      </p>
    </m.section>
  );
}
