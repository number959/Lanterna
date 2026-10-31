import {
  ChevronRight,
  CircleStop,
  CloudOff,
  ExternalLink,
  FileStack,
  FolderSearch,
  FolderTree,
  Lock,
  Map as MapIcon,
  Play,
  ShieldCheck,
  TriangleAlert,
} from 'lucide-react';
import { AnimatePresence, m, useReducedMotion } from 'motion/react';
import { useEffect, useMemo, useRef, useState } from 'react';
import type { CSSProperties } from 'react';
import { pctText, reclaimableBytes, sizeText, SPACE_CATEGORY_LABEL, SPACE_HINTS, SPACE_RISK_LABEL, unattributedBytes } from '../engine';
import type { Scan, SpaceHint, SpaceNode, SpaceReport, SpaceRisk } from '../engine';
import { simulatedSpace } from '../demo/space';
import { Anim, HexLoader } from './anim';
import { openSpaceItem, runSpace, spaceStatus, stopSpace } from './api';
import type { SpaceState } from './api';
import { fmtNum, Segmented, Stat, TableWrap, useOpenGuide, useToast } from './components';
import { useWidth } from './hooks';
import { ease, spring } from './motion';
import { squarify } from './treemap';
import type { Rect } from './treemap';
import type { ViewProps } from './views';

// "Cosa occupa spazio", sul modello di WizTree: l'agente legge l'elenco di
// file e cartelle di un'unità (non il contenuto) e qui si esplora il
// risultato con una mappa a riquadri, la tabella delle cartelle, i file più
// grandi, i tipi di file e le cartelle note di Windows con il modo sicuro di
// recuperare spazio. Polaris non cancella nulla. Senza agente l'analisi è
// simulata sui dati dimostrativi e dichiarata come tale.

const thousands = (n: number) => String(Math.round(n)).replace(/\B(?=(\d{3})+(?!\d))/g, '.');
const when = (iso?: string) => {
  if (!iso) return '';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString('it-IT', { dateStyle: 'short', timeStyle: 'short' });
};
const day = (iso?: string) => {
  if (!iso) return '';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? '' : d.toLocaleDateString('it-IT', { day: '2-digit', month: '2-digit', year: 'numeric' });
};
/** Durata dell'analisi: si arrotonda prima ai secondi, così non esce mai "2 min 60 s". */
export const seconds = (ms: number) => {
  if (ms < 1000) return 'meno di un secondo';
  const s = Math.round(ms / 1000);
  return s < 120 ? `${s} s` : `${Math.floor(s / 60)} min ${s % 60} s`;
};

// ---------------------------------------------------------------- Analisi in corso

export interface SpaceRun {
  drive: string;
  dirs: number;
  files: number;
  alloc: number;
  elapsedMs: number;
}

/** PC su cui è partita un'analisi: reale (agente) o simulata (demo). */
export interface SpaceTarget {
  host?: string;
  live: boolean;
}

/**
 * L'analisi riguarda il rapporto mostrato: stesso PC, e dati dell'agente per
 * un'analisi reale o demo per una simulata. Un rapporto importato non riceve
 * mai analisi.
 */
export const sameSpaceTarget = (t: SpaceTarget | undefined, scan: Scan | null | undefined, source: 'agent' | 'demo' | 'file') =>
  !!t && !!scan && source === (t.live ? 'agent' : 'demo') && t.host === scan.agent.host;

/** Spazio occupato su un'unità secondo l'analisi del PC: riferimento per la barra di avanzamento. */
const usedOf = (scan: Scan, drive: string) => {
  const v = scan.pc?.volumes?.find((x) => x.letter.toUpperCase() === drive.toUpperCase());
  return v ? Math.max(0, v.sizeGB - v.freeGB) * 1e9 : 0;
};

interface SpaceJob {
  /** Avanzamento dell'analisi in corso. */
  run: SpaceRun | null;
  /** Unità dell'analisi in corso o dell'ultima finita: la scheda la segue anche dopo essere stata rimontata. */
  drive?: string;
  /** PC e modo (reale o simulata) dell'analisi in corso o dell'ultima finita. */
  target?: SpaceTarget;
  /** Occupato dell'unità analizzata, preso all'avvio. */
  used?: number;
  /** Errore dell'ultima analisi. */
  error?: string;
}

// L'analisi continua anche se si cambia sezione: lo stato (e l'esito) vive
// fuori dal componente, così la scheda rimontata li ritrova.
let spaceJob: SpaceJob = { run: null };
let spacePromise: Promise<unknown> | null = null;
let spaceCancel: (() => void) | null = null;
const jobListeners = new Set<(j: SpaceJob) => void>();

function publish(patch: Partial<SpaceJob>) {
  spaceJob = { ...spaceJob, ...patch };
  for (const l of jobListeners) l(spaceJob);
}

function useSpaceJob(): SpaceJob {
  const [job, setJob] = useState<SpaceJob>(spaceJob);
  useEffect(() => {
    jobListeners.add(setJob);
    setJob(spaceJob);
    return () => {
      jobListeners.delete(setJob);
    };
  }, []);
  return job;
}

/** Analisi dello spazio in corso (anche per disattivare i test di velocità nel frattempo). */
export function useSpaceRun(): SpaceRun | null {
  return useSpaceJob().run;
}

/** Simulazione per la demo: l'avanzamento sale in un paio di secondi fino ai totali dell'analisi preparata. */
function simulateSpace(scan: Scan, drive: string): Promise<{ report: SpaceReport; error?: string }> {
  const report = simulatedSpace(scan, drive);
  return new Promise((resolve, reject) => {
    const steps = 30;
    let i = 0;
    let timer = 0;
    spaceCancel = () => {
      window.clearTimeout(timer);
      reject(new Error('Analisi interrotta'));
    };
    const tick = () => {
      i++;
      // Le cartelle grandi arrivano prima: la curva sale veloce e poi rallenta.
      const f = 1 - (1 - i / steps) ** 2;
      publish({ run: { drive, dirs: Math.round(report.dirs * f), files: Math.round(report.files * f), alloc: Math.round(report.allocBytes * f), elapsedMs: i * 80 } });
      if (i >= steps) resolve({ report });
      else timer = window.setTimeout(tick, 80);
    };
    tick();
  });
}

/**
 * Avvia (o riprende) l'analisi per il PC `target`. L'esito non passa dalla
 * scheda che l'ha avviata, che nel frattempo può essere stata smontata:
 * unità ed errore restano nello stato del modulo e App unisce il risultato
 * solo se mostra ancora lo stesso PC.
 */
function startSpace(target: SpaceTarget, scan: Scan, drive: string, addSpace: ViewProps['addSpace'], toast: ReturnType<typeof useToast>, resume = false) {
  if (spacePromise) return;
  publish({ run: { drive, dirs: 0, files: 0, alloc: 0, elapsedMs: 0 }, drive, target, used: usedOf(scan, drive), error: undefined });
  const p = target.live
    ? runSpace(
        drive,
        (st: SpaceState) => {
          const g = st.progress;
          if (st.running) publish({ run: { drive: st.drive ?? drive, dirs: g?.dirs ?? 0, files: g?.files ?? 0, alloc: g?.alloc ?? 0, elapsedMs: g?.elapsedMs ?? 0 } });
        },
        { resume },
      )
    : simulateSpace(scan, drive);
  spacePromise = p;
  p.then(
    ({ report: r, error: warning }) => {
      publish({ drive: r.drive });
      // Se ora si guarda un altro rapporto App non unisce il risultato e lo dice.
      if (!addSpace(r, target)) return;
      if (r.partial) toast(warning ?? `Analisi di ${r.drive} interrotta: valori parziali`, 'warn');
      else toast(`Analisi di ${r.drive} completata`, 'ok', 'complete');
    },
    (e) => {
      const msg = e instanceof Error ? e.message : String(e);
      publish({ error: msg });
      if (/interrott/i.test(msg)) toast('Analisi interrotta', 'ok', 'tap');
      else toast(`Analisi non riuscita: ${msg}`, 'error');
    },
  ).finally(() => {
    spacePromise = null;
    spaceCancel = null;
    publish({ run: null });
  });
}

// ---------------------------------------------------------------- Scheda

export function SpaceCard({ scan, live, source, addSpace }: ViewProps) {
  const toast = useToast();
  const openGuide = useOpenGuide();
  const job = useSpaceJob();
  const run = job.run;
  // L'analisi in corso (o l'ultima finita) è di questo rapporto.
  const mine = sameSpaceTarget(job.target, scan, source);
  const vols = (scan.pc?.volumes ?? []).filter((v) => v.sizeGB > 0 && (v.kind === 'fixed' || v.kind === 'removable'));
  const reports = scan.pc?.space ?? [];
  const [drive, setDrive] = useState(() => (mine && job.drive) || reports[0]?.drive || (vols.find((v) => v.system) ?? vols[0])?.letter || 'C:');
  const report = reports.find((r) => r.drive.toUpperCase() === drive.toUpperCase());
  const readOnly = source === 'file';
  // In un rapporto importato si sceglie solo tra le unità analizzate.
  const choices = [...new Set([...(readOnly ? [] : vols.map((v) => v.letter.toUpperCase())), ...reports.map((r) => r.drive.toUpperCase())])].sort();
  if (!choices.includes(drive.toUpperCase())) choices.unshift(drive.toUpperCase());

  // La scheda segue l'unità dell'analisi in corso o appena finita, anche se è
  // stata rimontata mentre l'analisi andava avanti.
  useEffect(() => {
    if (mine && job.drive) setDrive(job.drive);
  }, [mine, job.drive]);

  // Un'analisi avviata prima (anche da un'altra finestra) si riprende; una già
  // finita (pagina ricaricata, rapporto cambiato nel frattempo) si recupera dall'agente.
  useEffect(() => {
    if (!live || spacePromise) return;
    let alive = true;
    const target: SpaceTarget = { host: scan.agent.host, live: true };
    spaceStatus()
      .then((st) => {
        if (!alive) return;
        const res = st.result;
        if (st.running && st.drive) startSpace(target, scan, st.drive, addSpace, toast, true);
        else if (!st.running && res && !reports.some((r) => r.drive.toUpperCase() === res.drive.toUpperCase() && r.startedAt === res.startedAt)) addSpace(res, target);
      })
      .catch(() => undefined);
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [live]);

  const start = () => startSpace({ host: scan.agent.host, live }, scan, drive, addSpace, toast);
  // Si interrompe con il modo dell'analisi in corso, non con quello del rapporto mostrato ora.
  const stop = () => {
    if (spaceJob.target?.live) stopSpace().catch((e) => toast(`Interruzione non riuscita: ${e instanceof Error ? e.message : e}`, 'error'));
    else spaceCancel?.();
  };
  const running = !!run;
  const error = mine && !running ? job.error : undefined;

  return (
    <>
      {readOnly ? (
        <div className="notice" style={{ marginBottom: 14 }}>
          <TriangleAlert size={18} aria-hidden />
          <span>Rapporto importato: qui si consultano le analisi salvate. Le analisi si eseguono dall'agente, sul PC da analizzare.</span>
        </div>
      ) : (
        !live && (
          <div className="notice" style={{ marginBottom: 14 }}>
            <TriangleAlert size={18} aria-hidden />
            <span>
              Senza agente l'analisi è <b>simulata</b> sui dati dimostrativi: serve a vedere come funziona.
            </span>
          </div>
        )
      )}
      <m.section className="card space-card" initial={false}>
        <div className="card-head">
          <h2 className="disk-title">
            <Anim kind="pulse" on={running}>
              <FolderSearch size={19} />
            </Anim>{' '}
            <span>Cosa occupa spazio</span>
          </h2>
          <span className="sub">{report ? `${report.drive} · ${when(report.startedAt)} · letta in ${seconds(report.durationMs)}` : 'da qualche secondo a qualche minuto'}</span>
        </div>
        <p className="muted bench-desc">
          Legge l'elenco di file e cartelle con lo spazio che occupano, senza aprirli e senza cancellare nulla, come WizTree. I file di Windows con più nomi (per
          esempio in WinSxS) si contano una volta sola; i file solo online di OneDrive non si scaricano.
          {openGuide && (
            <>
              {' '}
              <button className="link-btn" onClick={() => openGuide('spazio-disco')}>
                Come liberare spazio senza rischi
              </button>
            </>
          )}
        </p>
        {(!readOnly || choices.length > 1) && (
          <div className="space-controls">
            <label className="bench-drive">
              <span>Unità</span>
              <select className="field" value={drive.toUpperCase()} onChange={(e) => setDrive(e.target.value)} disabled={running && !readOnly}>
                {choices.map((c) => {
                  const v = vols.find((x) => x.letter.toUpperCase() === c);
                  return (
                    <option key={c} value={c}>
                      {c}
                      {v ? ` ${v.label ? `${v.label} · ` : ''}${thousands(v.sizeGB)} GB, liberi ${v.freeGB < 10 ? fmtNum(v.freeGB, 1) : thousands(v.freeGB)} GB` : ''}
                    </option>
                  );
                })}
              </select>
            </label>
            {!readOnly && (
              <button className="btn primary" disabled={running} onClick={start}>
                <Play size={16} className="nudge" aria-hidden /> {running ? 'Analisi in corso…' : report ? "Ripeti l'analisi" : live ? 'Analizza' : "Simula l'analisi"}
              </button>
            )}
          </div>
        )}
        {/* Annuncia solo l'avvio: la fine la annuncia il messaggio temporaneo (anch'esso letto dai lettori di schermo). */}
        <p className="sr-only" aria-live="polite">
          {run ? `Analisi di ${run.drive} avviata` : ''}
        </p>
        <AnimatePresence initial={false}>{run && <SpaceProgressBox run={run} totalBytes={job.used ?? 0} onStop={stop} />}</AnimatePresence>
        {error && (
          <p className="space-error" role="alert">
            <TriangleAlert size={15} aria-hidden /> {error}
          </p>
        )}
        {report && <SpaceResult key={`${report.drive}-${report.startedAt}`} report={report} canOpen={live && source === 'agent'} elevated={scan.agent.elevated} />}
        {!report && !running && readOnly && <p className="muted">Questo rapporto non contiene analisi dello spazio.</p>}
      </m.section>
    </>
  );
}

function SpaceProgressBox({ run, totalBytes, onStop }: { run: SpaceRun; totalBytes: number; onStop: () => void }) {
  // L'occupato dell'unità analizzata è un buon riferimento per la barra (i file non leggibili la lasciano un po' indietro).
  const done = totalBytes > 0 ? Math.min(0.99, run.alloc / totalBytes) : undefined;
  // Letto a richiesta dal lettore di schermo: i contatori cambiano di continuo e non vanno annunciati.
  const valueText = `${done === undefined ? '' : `${Math.round(done * 100)} %, `}${sizeText(run.alloc)} in ${thousands(run.files)} file`;
  return (
    <m.div
      key="progress"
      initial={{ height: 0, opacity: 0 }}
      animate={{ height: 'auto', opacity: 1, transition: { height: spring.smooth, opacity: { duration: 0.25 } } }}
      exit={{ height: 0, opacity: 0, transition: { duration: 0.25, ease: ease.inOut } }}
      style={{ overflow: 'hidden' }}
    >
      <div className="bench-live">
        <div
          className={`progress ${done === undefined ? 'indeterminate' : 'live'}`}
          role="progressbar"
          aria-label={`Avanzamento dell'analisi di ${run.drive}`}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={done === undefined ? undefined : Math.round(done * 100)}
          aria-valuetext={valueText}
        >
          {done === undefined ? <i /> : <m.i initial={false} animate={{ scaleX: done }} transition={spring.gentle} />}
        </div>
        <div className="bench-live-row">
          <span className="faint space-live">
            <HexLoader size={16} /> {run.drive} · {thousands(run.dirs)} cartelle, {thousands(run.files)} file, {sizeText(run.alloc)}
          </span>
          <button className="btn small" onClick={onStop}>
            <CircleStop size={15} aria-hidden /> Interrompi
          </button>
        </div>
      </div>
    </m.div>
  );
}

// ---------------------------------------------------------------- Risultato

type Tab = 'folders' | 'files' | 'types' | 'hints';

function trail(root: SpaceNode, id: number): SpaceNode[] {
  if (root.id === id) return [root];
  for (const c of root.children ?? []) {
    const t = trail(c, id);
    if (t.length) return [root, ...t];
  }
  return [];
}

function SpaceResult({ report: r, canOpen, elevated }: { report: SpaceReport; canOpen: boolean; elevated?: boolean }) {
  const toast = useToast();
  const [tab, setTab] = useState<Tab>('folders');
  const [cur, setCur] = useState(r.tree?.id ?? 0);
  const path = useMemo(() => (r.tree ? trail(r.tree, cur) : []), [r.tree, cur]);
  const node = path[path.length - 1] ?? r.tree;
  const used = r.totalBytes - r.freeBytes;
  const unattr = unattributedBytes(r);
  const reclaim = reclaimableBytes(r);
  const hints = r.hints ?? [];
  // Cambiando cartella l'elemento attivato sparisce (riquadro, riga, briciola):
  // il cursore va sul nome della cartella mostrata, mai alla prima apertura.
  const curRef = useRef<HTMLElement>(null);
  const focusAfterNav = useRef(false);
  useEffect(() => {
    if (!focusAfterNav.current) return;
    focusAfterNav.current = false;
    curRef.current?.focus();
  }, [cur, tab]);

  // L'agente risponde solo se l'identificativo è della sua ultima analisi di quest'unità.
  const open = (id: number, file = false) =>
    openSpaceItem(r.drive, id, file, r.startedAt).catch((e) => toast(e instanceof Error ? e.message : String(e), 'error'));
  const pick = (id: number) => {
    focusAfterNav.current = true;
    setCur(id);
  };
  const show = (id: number) => {
    focusAfterNav.current = true;
    setCur(id);
    setTab('folders');
  };

  return (
    <div className="space-result">
      {r.partial && (
        <div className="notice warn" style={{ margin: '4px 0 14px' }}>
          <TriangleAlert size={18} aria-hidden />
          <span>Analisi interrotta prima della fine: i valori sono parziali.</span>
        </div>
      )}
      {r.totalBytes > 0 && <DriveBar r={r} unattr={unattr} />}
      <div className="stats space-stats">
        <Stat k="Occupato dai file" v={sizeText(r.allocBytes)} />
        <Stat k="Libero" v={r.totalBytes > 0 ? `${sizeText(r.freeBytes)} (${pctText(r.freeBytes, r.totalBytes)})` : '—'} sev={r.totalBytes > 0 && r.freeBytes / r.totalBytes < 0.1 ? 'warn' : undefined} />
        <Stat k="File" v={thousands(r.files)} />
        <Stat k="Cartelle" v={thousands(r.dirs)} />
        {reclaim > 0 && <Stat k="Si libera con Windows" v={`circa ${sizeText(reclaim)}`} sev="ok" />}
      </div>
      <SpaceNotes r={r} unattr={unattr} used={used} elevated={elevated} />

      <div className="space-tabs">
        <Segmented<Tab>
          value={tab}
          onChange={setTab}
          label="Vista dell'analisi"
          options={[
            { id: 'folders', label: 'Cartelle' },
            { id: 'files', label: 'File più grandi' },
            { id: 'types', label: 'Tipi di file' },
            { id: 'hints', label: `Cartelle note${hints.length ? ` (${hints.length})` : ''}` },
          ]}
        />
      </div>
      <div role="tabpanel" aria-label={tab === 'folders' ? 'Cartelle' : tab === 'files' ? 'File più grandi' : tab === 'types' ? 'Tipi di file' : 'Cartelle note'}>
        {tab === 'folders' && r.tree && node && (
          <>
            <nav className="space-crumbs" aria-label="Cartella mostrata">
              {path.map((n, i) => (
                <span key={n.id} className="space-crumb">
                  {i > 0 && <ChevronRight size={14} aria-hidden />}
                  {i === path.length - 1 ? (
                    <b ref={curRef} tabIndex={-1} aria-current="location">
                      {n.name}
                    </b>
                  ) : (
                    <button className="link-btn" onClick={() => pick(n.id)}>
                      {n.name}
                    </button>
                  )}
                </span>
              ))}
              <span className="faint space-crumb-size">
                {sizeText(node.alloc)}
                {node !== r.tree ? ` · ${pctText(node.alloc, r.allocBytes)} del totale` : ''}
              </span>
            </nav>
            <Treemap node={node} total={r.allocBytes} onPick={pick} />
            <FolderTable node={node} canOpen={canOpen} onPick={pick} onOpen={open} />
          </>
        )}
        {tab === 'files' && <FilesTable r={r} canOpen={canOpen} onOpen={open} />}
        {tab === 'types' && <TypesView r={r} />}
        {tab === 'hints' && <HintsView r={r} canOpen={canOpen} onShow={show} onOpen={open} />}
      </div>
    </div>
  );
}

/**
 * Parti della barra dell'unità: occupato dai file letti, occupato ma non
 * attribuito, libero. In un'analisi interrotta l'occupato non ancora letto ha
 * una parte sua, altrimenti sembrerebbe spazio libero.
 */
export function driveParts(r: SpaceReport, unattr: number) {
  const files = Math.min(r.allocBytes, r.totalBytes);
  return [
    { k: 'files', label: 'File letti', v: files, cls: 'db-files' },
    { k: 'other', label: 'Non attribuito', v: unattr, cls: 'db-other' },
    { k: 'unread', label: 'Non letto', v: r.partial ? Math.max(0, r.totalBytes - r.freeBytes - files) : 0, cls: 'db-unread' },
    { k: 'free', label: 'Libero', v: r.freeBytes, cls: 'db-free' },
  ].filter((p) => p.v > 0);
}

function DriveBar({ r, unattr }: { r: SpaceReport; unattr: number }) {
  const reduce = useReducedMotion();
  const parts = driveParts(r, unattr);
  return (
    <figure className="space-drive" aria-label={`Unità ${r.drive}, ${parts.map((p) => `${p.label.toLowerCase()} ${sizeText(p.v)}`).join(', ')}, su ${sizeText(r.totalBytes)}`}>
      <div className="db-bar" aria-hidden>
        {parts.map((p, i) => (
          <m.span
            key={p.k}
            className={p.cls}
            style={{ flexGrow: p.v / r.totalBytes }}
            initial={reduce ? false : { opacity: 0, scaleX: 0.6 }}
            animate={{ opacity: 1, scaleX: 1 }}
            transition={{ ...spring.gentle, delay: reduce ? 0 : 0.05 + i * 0.08 }}
            title={`${p.label}: ${sizeText(p.v)} (${pctText(p.v, r.totalBytes)})`}
          />
        ))}
      </div>
      <figcaption className="db-legend">
        {parts.map((p) => (
          <span key={p.k}>
            <i className={p.cls} aria-hidden /> {p.label} <b>{sizeText(p.v)}</b>
          </span>
        ))}
        <span className="faint">su {sizeText(r.totalBytes)}{r.fs ? ` · ${r.fs}` : ''}</span>
      </figcaption>
    </figure>
  );
}

/**
 * Note sotto la barra. Il consiglio di avviare Polaris come amministratore
 * vale solo se non lo è (elevated === false): da amministratore restano
 * chiuse le cartelle riservate al sistema, perché l'agente non usa i
 * privilegi di backup.
 */
export function spaceNotes(r: SpaceReport, unattr: number, used: number, elevated?: boolean): { icon: typeof Lock; text: string }[] {
  const notes: { icon: typeof Lock; text: string }[] = [];
  if (r.linkedBytes)
    notes.push({ icon: ShieldCheck, text: `${sizeText(r.linkedBytes)} di file di Windows con più nomi (collegamenti fisici, come tra WinSxS e System32) contati una volta sola: Esplora file li conta più volte.` });
  if (r.cloudFiles)
    notes.push({ icon: CloudOff, text: `${thousands(r.cloudFiles)} file solo online (${sizeText(r.cloudBytes ?? 0)} nel cloud): non occupano spazio su questo disco e non sono stati scaricati.` });
  if (r.denied)
    notes.push({
      icon: Lock,
      text: `${thousands(r.denied)} ${r.denied === 1 ? 'cartella non leggibile' : 'cartelle non leggibili'} con i permessi attuali${r.deniedPaths?.length ? ` (per esempio ${r.deniedPaths.slice(0, 2).join(', ')})` : ''}${
        elevated === false ? ': avviando Polaris come amministratore se ne leggono di più.' : elevated ? ': sono cartelle riservate al sistema.' : '.'
      }`,
    });
  if (r.errors)
    notes.push({ icon: TriangleAlert, text: `${thousands(r.errors)} ${r.errors === 1 ? 'cartella non letta' : 'cartelle non lette'} per errori del disco o del file system.` });
  if (unattr > 0)
    notes.push({
      icon: FileStack,
      text: `${sizeText(unattr)} (${pctText(unattr, used)} dell'occupato) non risultano nei file leggibili: cartelle protette, punti di ripristino e copie shadow, metadati del file system.`,
    });
  return notes;
}

function SpaceNotes({ r, unattr, used, elevated }: { r: SpaceReport; unattr: number; used: number; elevated?: boolean }) {
  const notes = spaceNotes(r, unattr, used, elevated);
  if (!notes.length) return null;
  return (
    <ul className="space-notes">
      {notes.map((n, i) => (
        <li key={i}>
          <n.icon size={15} aria-hidden /> <span>{n.text}</span>
        </li>
      ))}
    </ul>
  );
}

// ---------------------------------------------------------------- Mappa a riquadri

interface Item {
  key: string;
  label: string;
  value: number;
  node?: SpaceNode;
  /** "own": file nella cartella stessa; "more": sottocartelle piccole riassunte. */
  kind: 'dir' | 'own' | 'more';
  files?: number;
}

function itemsOf(n: SpaceNode): Item[] {
  const out: Item[] = (n.children ?? []).map((c) => ({ key: `d${c.id}`, label: c.name, value: c.alloc, node: c, kind: 'dir' as const, files: c.files }));
  if ((n.ownAlloc ?? 0) > 0) out.push({ key: `o${n.id}`, label: 'File nella cartella', value: n.ownAlloc!, kind: 'own', files: n.ownFiles });
  if (n.more && n.more.alloc > 0) out.push({ key: `m${n.id}`, label: `Altre ${thousands(n.more.dirs)} cartelle`, value: n.more.alloc, kind: 'more' });
  return out.sort((a, b) => b.value - a.value);
}

/**
 * Cartella da mostrare dentro un riquadro: se quasi tutto lo spazio sta in
 * una sola sottocartella (Users > profilo, Windows.old > Windows) si scende
 * fino a dove il contenuto si divide davvero.
 */
function through(n: SpaceNode): SpaceNode {
  let cur = n;
  for (let i = 0; i < 4; i++) {
    const c = cur.children?.[0];
    if (!c || !c.children?.length || c.alloc < cur.alloc * 0.9) break;
    cur = c;
  }
  return cur;
}

/** Arrotonda ai pixel e lascia 2 px di spazio tra i riquadri. */
const snap = (r: Rect, gap = 2): Rect => {
  const x0 = Math.round(r.x);
  const y0 = Math.round(r.y);
  const x1 = Math.round(r.x + r.w);
  const y1 = Math.round(r.y + r.h);
  return { x: x0 + gap / 2, y: y0 + gap / 2, w: Math.max(0, x1 - x0 - gap), h: Math.max(0, y1 - y0 - gap) };
};
const box = (r: Rect): CSSProperties => ({ left: r.x, top: r.y, width: r.w, height: r.h });

interface Tip {
  item: Item;
  rect: Rect;
}

function Treemap({ node, total, onPick }: { node: SpaceNode; total: number; onPick: (id: number) => void }) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const reduce = useReducedMotion();
  const [tip, setTip] = useState<Tip | null>(null);
  const height = width > 0 ? Math.round(Math.min(380, Math.max(220, width * 0.5))) : 300;
  const items = useMemo(() => itemsOf(node), [node]);
  const tiles = useMemo(() => (width > 0 ? squarify(items.map((it) => ({ value: it.value, item: it })), { x: 0, y: 0, w: width, h: height }) : []), [items, width, height]);
  useEffect(() => setTip(null), [node]);
  const label = `Mappa delle cartelle in ${node.name}: ${items
    .slice(0, 5)
    .map((it) => `${it.label} ${sizeText(it.value)}`)
    .join(', ')}${items.length > 5 ? ` e altre ${items.length - 5} voci` : ''}. La tabella sotto riporta tutti i valori.`;

  return (
    <div className="treemap-wrap">
      {/* Il contenitore misurato resta lo stesso; cambia (e si anima) solo il contenuto. */}
      <div ref={ref} className="treemap" style={{ height }} role="group" aria-label={label} onMouseLeave={() => setTip(null)}>
        <m.div
          key={node.id}
          className="treemap-layer"
          initial={reduce ? false : { opacity: 0, scale: 0.985 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.3, ease: ease.out }}
        >
        {tiles.map(({ item, rect }) => {
          const r = snap(rect);
          if (r.w < 2 || r.h < 2) return null;
          const big = r.w >= 64 && r.h >= 34;
          const drill = item.kind === 'dir' && !!item.node?.children?.length;
          // Il secondo livello serve solo se la cartella si divide in più voci.
          const split = item.kind === 'dir' && item.node && r.w >= 90 && r.h >= 70 ? itemsOf(through(item.node)) : [];
          const inner = split.length > 1 ? split : [];
          // Nei riquadri stretti nome e dimensione vanno su due righe; negli altri
          // restano su una (il nome si accorcia) per non finire sopra le sottocartelle.
          const head = r.w < 150 ? 44 : 30;
          const subs = inner.length ? squarify(inner.map((it) => ({ value: it.value, item: it })), { x: 3, y: head, w: r.w - 6, h: r.h - head - 3 }) : [];
          const content = (
            <>
              {subs.map(({ item: s, rect: sr }) => {
                const q = snap(sr, 2);
                if (q.w < 3 || q.h < 3) return null;
                return (
                  <span
                    key={s.key}
                    className={`tm-sub tm-${s.kind}`}
                    style={box(q)}
                    onMouseEnter={(e) => {
                      e.stopPropagation();
                      setTip({ item: s, rect: { x: r.x + q.x, y: r.y + q.y, w: q.w, h: q.h } });
                    }}
                    onClick={(e) => {
                      if (s.kind === 'dir' && s.node) {
                        e.stopPropagation();
                        onPick(s.node.id);
                      }
                    }}
                  >
                    {q.w >= 70 && q.h >= 22 && <span className="tm-sub-label">{s.label}</span>}
                  </span>
                );
              })}
              {big && (
                <span className={`tm-label${head === 30 ? ' one' : ''}`}>
                  <span className="tm-name">
                    {item.node?.denied && <Lock size={11} aria-hidden />} {item.label}
                  </span>
                  <span className="tm-size">{sizeText(item.value)}</span>
                </span>
              )}
            </>
          );
          const common = {
            className: `tm-tile tm-${item.kind}${drill ? ' tm-drill' : ''}`,
            style: box(r),
            onMouseEnter: () => setTip({ item, rect: r }),
          };
          return drill ? (
            <button
              key={item.key}
              {...common}
              onClick={() => onPick(item.node!.id)}
              onFocus={() => setTip({ item, rect: r })}
              onBlur={() => setTip(null)}
              aria-label={`${item.label}, ${sizeText(item.value)}, ${pctText(item.value, node.alloc)}: apri la cartella`}
            >
              {content}
            </button>
          ) : (
            <span key={item.key} {...common} aria-hidden>
              {content}
            </span>
          );
        })}
        </m.div>
      </div>
      {tip && width > 0 && <TreemapTip tip={tip} parent={node} total={total} width={width} height={height} />}
    </div>
  );
}

function TreemapTip({ tip, parent, total, width, height }: { tip: Tip; parent: SpaceNode; total: number; width: number; height: number }) {
  const { item, rect } = tip;
  const w = Math.min(260, width - 8);
  // Sotto il riquadro se c'è posto, altrimenti sopra, altrimenti sopra il
  // riquadro stesso (riquadri alti quanto la mappa).
  const room = 100;
  const left = Math.max(4, Math.min(rect.x + 8, width - w - 4));
  const style: CSSProperties =
    rect.y + rect.h + room < height
      ? { left, top: rect.y + rect.h - 6, width: w }
      : rect.y > room
        ? { left, bottom: height - rect.y - 6, width: w }
        : { left, top: rect.y + 34, width: w };
  const n = item.node;
  return (
    <div className="treemap-tip" style={style} aria-hidden>
      <b>{item.label}</b>
      {n && n.path !== item.label && <span className="mono faint">{n.path}</span>}
      <span>
        {sizeText(item.value)} · {pctText(item.value, parent.alloc)} di {parent.name}
        {total > 0 && parent.alloc !== total ? ` · ${pctText(item.value, total)} del totale` : ''}
      </span>
      {item.files !== undefined && (
        <span className="faint">
          {thousands(item.files)} file{n?.dirs ? `, ${thousands(n.dirs)} cartelle` : ''}
          {n?.denied ? ' · in parte non leggibile' : ''}
        </span>
      )}
      {item.kind === 'more' && <span className="faint">Cartelle piccole riassunte in una voce.</span>}
    </div>
  );
}

// ---------------------------------------------------------------- Tabelle

function Bar({ v, max }: { v: number; max: number }) {
  return (
    <span className="space-bar" aria-hidden>
      <i style={{ transform: `scaleX(${max > 0 ? Math.max(0.004, v / max) : 0})` }} />
    </span>
  );
}

function FolderTable({ node, canOpen, onPick, onOpen }: { node: SpaceNode; canOpen: boolean; onPick: (id: number) => void; onOpen: (id: number) => void }) {
  const items = itemsOf(node);
  const max = items[0]?.value ?? 0;
  return (
    <TableWrap label={`Cartelle in ${node.name}`}>
      <table className="pc-table space-table">
        <thead>
          <tr>
            <th scope="col">Cartella</th>
            <th scope="col">Spazio</th>
            <th scope="col" className="num">
              Quota
            </th>
            <th scope="col" className="num">
              File
            </th>
            {canOpen && (
              <th scope="col">
                <span className="sr-only">Azioni</span>
              </th>
            )}
          </tr>
        </thead>
        <tbody>
          {items.map((it) => (
            <tr key={it.key} className={it.kind !== 'dir' ? 'space-pseudo' : undefined}>
              <td className="space-name">
                {it.kind === 'dir' && it.node?.children?.length ? (
                  <button className="link-btn" onClick={() => onPick(it.node!.id)}>
                    <FolderTree size={14} aria-hidden /> {it.label}
                  </button>
                ) : (
                  <span>{it.label}</span>
                )}
                {it.node?.denied && (
                  <span className="tag" title="Alcune sottocartelle non sono leggibili con i permessi attuali">
                    <Lock size={11} aria-hidden /> {it.value > 0 ? 'in parte non leggibile' : 'non leggibile'}
                  </span>
                )}
              </td>
              <td>
                <span className="space-size">
                  <Bar v={it.value} max={max} />
                  <span className="mono">{sizeText(it.value)}</span>
                </span>
              </td>
              <td className="mono num">{pctText(it.value, node.alloc)}</td>
              <td className="mono num">{it.files !== undefined ? thousands(it.files) : '—'}</td>
              {canOpen && (
                <td>
                  {it.kind === 'dir' && it.node ? (
                    <button className="btn small" onClick={() => onOpen(it.node!.id)} aria-label={`Apri ${it.label} in Esplora file`}>
                      <ExternalLink size={14} aria-hidden /> Apri
                    </button>
                  ) : it.kind === 'own' ? (
                    <button className="btn small" onClick={() => onOpen(node.id)} aria-label={`Apri ${node.name} in Esplora file`}>
                      <ExternalLink size={14} aria-hidden /> Apri
                    </button>
                  ) : null}
                </td>
              )}
            </tr>
          ))}
          {!items.length && (
            <tr>
              <td colSpan={canOpen ? 5 : 4} className="muted">
                Cartella vuota.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </TableWrap>
  );
}

function FilesTable({ r, canOpen, onOpen }: { r: SpaceReport; canOpen: boolean; onOpen: (id: number, file: boolean) => void }) {
  const files = r.topFiles ?? [];
  const [all, setAll] = useState(false);
  const shown = all ? files : files.slice(0, 25);
  const max = files[0]?.alloc ?? 0;
  if (!files.length) return <p className="muted">Nessun file letto.</p>;
  return (
    <>
      <TableWrap label="File più grandi">
        <table className="pc-table space-table">
          <thead>
            <tr>
              <th scope="col">File</th>
              <th scope="col">Spazio</th>
              <th scope="col">Modificato</th>
              {canOpen && (
                <th scope="col">
                  <span className="sr-only">Azioni</span>
                </th>
              )}
            </tr>
          </thead>
          <tbody>
            {shown.map((f) => {
              const cut = f.path.lastIndexOf('\\');
              return (
                <tr key={f.id}>
                  <td className="space-file" title={f.path}>
                    <b>{f.path.slice(cut + 1)}</b>
                    <span className="mono faint">{f.path.slice(0, cut + 1)}</span>
                    {f.cloud && <span className="tag">solo online</span>}
                  </td>
                  <td>
                    <span className="space-size">
                      <Bar v={f.alloc} max={max} />
                      <span className="mono">{sizeText(f.alloc)}</span>
                    </span>
                  </td>
                  <td className="faint">{day(f.modified)}</td>
                  {canOpen && (
                    <td>
                      <button className="btn small" onClick={() => onOpen(f.id, true)} aria-label={`Mostra ${f.path.slice(cut + 1)} in Esplora file`}>
                        <ExternalLink size={14} aria-hidden /> Mostra
                      </button>
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </table>
      </TableWrap>
      {files.length > 25 && (
        <p className="card-foot">
          <button className="link-btn" onClick={() => setAll(!all)}>
            {all ? 'Mostra i primi 25' : `Mostra tutti i ${files.length}`}
          </button>
        </p>
      )}
    </>
  );
}

const extLabel = (id: string) => (id === '' ? '(senza estensione)' : id);

function TypesView({ r }: { r: SpaceReport }) {
  const cats = r.categories ?? [];
  const types = r.types ?? [];
  const max = cats[0]?.alloc ?? 0;
  return (
    <div className="grid cols-2 space-types">
      <div>
        <h3 className="space-h3">Per categoria</h3>
        <ul className="space-cats">
          {cats.map((c) => (
            <li key={c.id}>
              <span className="sc-name">{SPACE_CATEGORY_LABEL[c.id] ?? c.id}</span>
              <Bar v={c.alloc} max={max} />
              <span className="mono sc-size">{sizeText(c.alloc)}</span>
              <span className="mono faint sc-pct">{pctText(c.alloc, r.allocBytes)}</span>
            </li>
          ))}
        </ul>
        <p className="faint card-foot">"Altro" raccoglie le estensioni meno comuni e i file di programmi e giochi con formati propri.</p>
      </div>
      <div>
        <h3 className="space-h3">Estensioni che occupano di più</h3>
        <TableWrap label="Estensioni che occupano di più">
          <table className="pc-table space-table">
            <thead>
              <tr>
                <th scope="col">Tipo</th>
                <th scope="col" className="num">
                  Spazio
                </th>
                <th scope="col" className="num">
                  File
                </th>
              </tr>
            </thead>
            <tbody>
              {types.slice(0, 15).map((t) => (
                <tr key={t.id}>
                  <td className="mono">{extLabel(t.id)}</td>
                  <td className="mono num">{sizeText(t.alloc)}</td>
                  <td className="mono num">{thousands(t.files)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      </div>
    </div>
  );
}

const RISK_ORDER: SpaceRisk[] = ['tool', 'app', 'review', 'setting', 'keep'];
const RISK_INTRO: Record<SpaceRisk, string> = {
  tool: 'Si liberano con gli strumenti di Windows indicati, senza cancellare cartelle a mano.',
  app: 'Si svuotano dal programma che le usa (per esempio il browser), non cancellando le cartelle.',
  review: 'Sono dati tuoi: decidi tu cosa tenere.',
  setting: 'Si riducono cambiando un\'impostazione.',
  keep: 'Servono a Windows e ai programmi o sono gestite da Windows: non vanno cancellate a mano.',
};

function HintsView({ r, canOpen, onShow, onOpen }: { r: SpaceReport; canOpen: boolean; onShow: (id: number) => void; onOpen: (id: number) => void }) {
  const hints = r.hints ?? [];
  if (!hints.length) return <p className="muted">Nessuna cartella nota di Windows in quest'analisi.</p>;
  const groups = RISK_ORDER.map((risk) => ({ risk, list: hints.filter((h) => (SPACE_HINTS[h.id]?.risk ?? 'review') === risk) })).filter((g) => g.list.length);
  return (
    <div className="space-hints">
      <p className="faint space-hints-note">
        Indicazioni generali per Windows 10 e 11: nomi di menu e voci possono cambiare con gli aggiornamenti. Polaris non cancella nulla.
      </p>
      {groups.map((g) => (
        <section key={g.risk} className="space-hint-group" aria-label={SPACE_RISK_LABEL[g.risk]}>
          <div className="space-hint-head">
            <h3 className="space-h3">
              <span className={`tag risk-${g.risk}`}>{SPACE_RISK_LABEL[g.risk]}</span>
            </h3>
            <p className="faint">{RISK_INTRO[g.risk]}</p>
          </div>
          {g.list.map((h) => (
            <HintRow key={h.id} h={h} total={r.allocBytes} canOpen={canOpen} onShow={onShow} onOpen={onOpen} />
          ))}
        </section>
      ))}
    </div>
  );
}

function HintRow({ h, total, canOpen, onShow, onOpen }: { h: SpaceHint; total: number; canOpen: boolean; onShow: (id: number) => void; onOpen: (id: number) => void }) {
  const info = SPACE_HINTS[h.id];
  return (
    <article className="space-hint">
      <div className="sh-head">
        <b>{info?.label ?? h.id}</b>
        <span className="mono">{sizeText(h.alloc)}</span>
        <span className="faint">
          {pctText(h.alloc, total)}
          {h.files ? ` · ${thousands(h.files)} file` : ''}
        </span>
      </div>
      {h.path && <div className="mono faint sh-path">{h.path}</div>}
      {info && (
        <>
          <p>{info.what}</p>
          <p>
            <b>Come fare:</b> {info.how}
          </p>
        </>
      )}
      {h.nodeId !== undefined && (
        <div className="chip-actions">
          <button className="btn small" onClick={() => onShow(h.nodeId!)}>
            <MapIcon size={14} aria-hidden /> Mostra nella mappa
          </button>
          {canOpen && (
            <button className="btn small" onClick={() => onOpen(h.nodeId!)}>
              <ExternalLink size={14} aria-hidden /> Apri in Esplora file
            </button>
          )}
        </div>
      )}
    </article>
  );
}
