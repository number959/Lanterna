import { Check, Circle, CircleStop, ExternalLink, Gauge, Play, TriangleAlert } from 'lucide-react';
import { AnimatePresence, m } from 'motion/react';
import { Fragment, useEffect, useId, useRef, useState } from 'react';
import type { KeyboardEvent as ReactKeyboardEvent, ReactNode, RefObject } from 'react';
import { createPortal } from 'react-dom';
import { BLOAT_LABEL, mbpsText, primaryAdapter, SPEED_LEGAL_NOTE, speedBloat, speedBytes, speedCaveats, speedErr, speedMs, speedWhere } from '../engine';
import type { Scan, SpeedDir, SpeedServer, SpeedTest } from '../engine';
import { simulatedSpeed } from '../demo/simulate';
import { HexLoader } from './anim';
import { runSpeed, speedStatus, stopSpeed } from './api';
import type { SpeedState } from './api';
import { fmtNum, SevIcon, useOpenGuide, useToast } from './components';
import { ease, rise, spring } from './motion';
import type { ViewProps } from './views';

// Velocità di Internet con Measurement Lab (M-Lab, ndt7): l'agente misura
// download, upload e latenza a riposo e sotto carico, solo su richiesta e
// dopo il consenso, chiesto prima di OGNI test (M-Lab pubblica il risultato
// con l'indirizzo IP pubblico). Senza agente il test è simulato sui dati
// dimostrativi, senza traffico e quindi senza consenso, e lo si dichiara.

// ---------------------------------------------------------------- Consenso

/** Lo stesso testo dell'agente (windows/internal/speedtest/consent.go): un test lo confronta. */
export const CONSENT_TITLE = 'Test di velocità di Internet';
export const PRIVACY_URL = 'https://www.measurementlab.net/privacy/';
export const AUP_URL = 'https://www.measurementlab.net/aup/';
export const CONSENT_CHECK = 'Ho letto e accetto che il risultato e il mio indirizzo IP vengano pubblicati da M-Lab';
export const CONSENT_TEXT: string[] = [
  'Il test dura circa 30 secondi. Polaris misura prima la latenza, poi scarica e invia dati per circa 20 secondi verso un server di Measurement Lab (M-Lab), un progetto senza scopo di lucro, scelto vicino a te (di solito in Italia).',
  'Il test può consumare molti dati: fino a circa 250 MB in download e 250 MB in upload. Evitalo su connessioni a consumo o sull\'hotspot del telefono.',
  'M-Lab registra e pubblica per sempre, in un archivio aperto e senza restrizioni, il risultato del test insieme all\'indirizzo IP pubblico della tua connessione, alla data e all\'ora e al nome del programma (STARNET Polaris). Non riceve il tuo nome né altri dati del computer; dall\'indirizzo IP si può risalire in modo approssimativo alla zona e all\'operatore.',
  'Se la connessione ha un indirizzo IP fisso (studi, aziende, strutture sanitarie), il risultato resta pubblico e collegato a quell\'indirizzo: verifica che le regole interne lo consentano.',
  `Titolare di questi dati è M-Lab: informativa su ${PRIVACY_URL} e regole d'uso su ${AUP_URL}. Polaris non salva e non stampa il tuo indirizzo IP nei referti. Il test non è adatto a minori di 16 anni.`,
];
const LINKS: [string, string][] = [
  [PRIVACY_URL, 'informativa sulla privacy di M-Lab'],
  [AUP_URL, 'regole d\'uso di M-Lab'],
];

/** Il testo con gli indirizzi di M-Lab trasformati in collegamenti che si aprono a parte. */
function linkify(text: string): ReactNode[] {
  const out: ReactNode[] = [];
  let rest = text;
  for (;;) {
    let at = -1;
    let hit: [string, string] | undefined;
    for (const l of LINKS) {
      const i = rest.indexOf(l[0]);
      if (i >= 0 && (at < 0 || i < at)) {
        at = i;
        hit = l;
      }
    }
    if (!hit) break;
    out.push(rest.slice(0, at));
    out.push(
      <a key={out.length} href={hit[0]} target="_blank" rel="noreferrer noopener">
        {hit[0].replace(/^https:\/\//, '')}
        <span className="sr-only"> ({hit[1]}, si apre in una nuova finestra)</span>
      </a>,
    );
    rest = rest.slice(at + hit[0].length);
  }
  out.push(rest);
  return out;
}

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * Finestra del consenso: modale, con il fuoco intrappolato, Esc che chiude e
 * il fuoco che torna dove era. "Avvia il test" si abilita solo con la casella
 * spuntata, e la casella è vuota a ogni apertura: il consenso vale per un test.
 */
export function ConsentDialog({ onCancel, onAccept }: { onCancel: () => void; onAccept: () => void }) {
  const [checked, setChecked] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  const title = useRef<HTMLHeadingElement>(null);
  const id = useId();

  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    // Il resto della pagina diventa inerte: né il mouse né la tastiera né i
    // lettori di schermo lo raggiungono finché la finestra è aperta.
    const root = document.getElementById('root');
    root?.setAttribute('inert', '');
    document.documentElement.classList.add('pdoc-open');
    title.current?.focus();
    return () => {
      root?.removeAttribute('inert');
      document.documentElement.classList.remove('pdoc-open');
      prev?.focus();
    };
  }, []);

  const onKeyDown = (e: ReactKeyboardEvent) => {
    if (e.key === 'Escape') {
      e.stopPropagation();
      onCancel();
      return;
    }
    if (e.key !== 'Tab' || !box.current) return;
    const items = Array.from(box.current.querySelectorAll<HTMLElement>(FOCUSABLE));
    if (!items.length) return;
    const first = items[0];
    const last = items[items.length - 1];
    const active = document.activeElement;
    if (e.shiftKey && (active === first || active === title.current || !box.current.contains(active))) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && (active === last || !box.current.contains(active))) {
      e.preventDefault();
      first.focus();
    }
  };

  return createPortal(
    <div className="pdoc-portal speed-portal" onKeyDown={onKeyDown}>
      <m.div className="pdoc-backdrop" initial={{ opacity: 0 }} animate={{ opacity: 1 }} onClick={onCancel} aria-hidden="true" />
      <m.div
        ref={box}
        className="speed-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby={`${id}-title`}
        initial={{ opacity: 0, y: 18, scale: 0.98 }}
        animate={{ opacity: 1, y: 0, scale: 1, transition: spring.smooth }}
      >
        <h2 id={`${id}-title`} ref={title} tabIndex={-1}>
          <Gauge size={20} aria-hidden /> {CONSENT_TITLE}
        </h2>
        <div className="speed-consent">
          {CONSENT_TEXT.map((p, i) => (
            <p key={i}>{linkify(p)}</p>
          ))}
        </div>
        <label className="speed-check">
          <input type="checkbox" checked={checked} onChange={(e) => setChecked(e.target.checked)} />
          <span>{CONSENT_CHECK}</span>
        </label>
        <div className="speed-dialog-actions">
          <span id={`${id}-hint`} className="faint">
            {checked ? 'Il consenso vale solo per questo test.' : 'Spunta la casella per avviare il test.'}
          </span>
          <span className="spacer" />
          <button className="btn" onClick={onCancel}>
            Annulla
          </button>
          <button className="btn primary" disabled={!checked} aria-describedby={`${id}-hint`} onClick={onAccept}>
            <Play size={16} aria-hidden /> Avvia il test
          </button>
        </div>
      </m.div>
    </div>,
    document.body,
  );
}

// ---------------------------------------------------------------- Test in corso

export type SpeedPhase = 'locate' | 'idle' | 'download' | 'upload';

export const PHASES: { id: SpeedPhase; label: string }[] = [
  { id: 'locate', label: 'Scelta del server' },
  { id: 'idle', label: 'Latenza a riposo' },
  { id: 'download', label: 'Download' },
  { id: 'upload', label: 'Upload' },
];
const phaseLabel = (p: SpeedPhase) => PHASES.find((x) => x.id === p)?.label ?? '';

/** PC e rete su cui è partito un test: si unisce solo al rapporto dello stesso PC, della stessa rete e della stessa origine. */
export interface SpeedTargetRef {
  live: boolean;
  host?: string;
  gateway?: string;
}

/**
 * Il test riguarda il rapporto mostrato: stesso PC, stesso gateway, e dati
 * dell'agente per un test reale o demo per uno simulato. Un rapporto
 * importato non riceve mai test.
 */
export const sameSpeedTarget = (t: SpeedTargetRef | undefined, scan: Scan | null | undefined, source: 'agent' | 'demo' | 'file') =>
  !!t && !!scan && source === (t.live ? 'agent' : 'demo') && t.host === scan.agent.host && t.gateway === scan.gateway?.ip;

export interface SpeedRun {
  phase: SpeedPhase;
  mbps?: number;
  latencyMs?: number;
  elapsedMs: number;
  phaseMs?: number;
  server?: SpeedServer;
}

interface SpeedJob {
  run: SpeedRun | null;
  target?: SpeedTargetRef;
  error?: string;
  /** Quando l'agente accetta il prossimo test (ms), e quanti test restano oggi. */
  nextAt?: number;
  left?: number;
}

// Il test continua anche se si cambia sezione: lo stato vive fuori dal
// componente, così la scheda rimontata lo ritrova.
let speedJob: SpeedJob = { run: null };
let speedPromise: Promise<unknown> | null = null;
let simCancel: (() => void) | null = null;
let restoreTried = false;
const listeners = new Set<(j: SpeedJob) => void>();

function publish(patch: Partial<SpeedJob>) {
  speedJob = { ...speedJob, ...patch };
  for (const l of listeners) l(speedJob);
}

function useSpeedJob(): SpeedJob {
  const [job, setJob] = useState<SpeedJob>(speedJob);
  useEffect(() => {
    listeners.add(setJob);
    setJob(speedJob);
    return () => {
      listeners.delete(setJob);
    };
  }, []);
  return job;
}

/** Stato dell'agente: avanzamento, attesa prima del prossimo test, test rimasti oggi. */
function applyState(st: SpeedState) {
  const patch: Partial<SpeedJob> = { nextAt: st.waitSec ? Date.now() + st.waitSec * 1000 : undefined, left: st.left };
  const g = st.progress;
  if (st.running && g) patch.run = { phase: g.phase, mbps: g.mbps, latencyMs: g.latencyMs, elapsedMs: g.elapsedMs, phaseMs: g.phaseMs, server: g.server };
  publish(patch);
}

/** Simulazione per la demo: le fasi in circa 8 secondi, senza traffico in rete. */
function simulate(scan: Scan): Promise<SpeedTest> {
  const r = simulatedSpeed(scan);
  const plan: [SpeedPhase, number][] = [
    ['locate', 500],
    ['idle', 1500],
    ['download', 3000],
    ['upload', 3000],
  ];
  return new Promise((resolve, reject) => {
    let timer = 0;
    let step = 0;
    let t0 = Date.now();
    simCancel = () => {
      window.clearTimeout(timer);
      reject(new Error('Test interrotto'));
    };
    const tick = () => {
      const [phase, dur] = plan[step];
      const el = Date.now() - t0;
      const f = Math.min(1, el / dur);
      const dir: SpeedDir | undefined = phase === 'download' ? r.download : phase === 'upload' ? r.upload : undefined;
      // La velocità sale nei primi istanti e poi oscilla poco attorno al valore finale.
      const mbps = dir ? Math.round(dir.mbps * Math.min(1, 0.25 + f * 2.2) * (1 + Math.sin(el / 170) * 0.03) * 10) / 10 : undefined;
      const idle = r.idle?.medianMs ?? 20;
      const lat = phase === 'idle' ? idle : dir?.latency?.medianMs;
      publish({ run: { phase, mbps, latencyMs: lat !== undefined ? Math.round(lat * (1 + Math.sin(el / 230) * 0.08) * 10) / 10 : undefined, elapsedMs: el, phaseMs: dur, server: phase === 'download' || phase === 'upload' ? r.server : undefined } });
      if (el >= dur) {
        step++;
        t0 = Date.now();
        if (step >= plan.length) {
          resolve({ ...r, startedAt: new Date().toISOString() });
          return;
        }
      }
      timer = window.setTimeout(tick, 150);
    };
    tick();
  });
}

/**
 * Avvia (o riprende) il test. L'esito non passa dalla scheda che l'ha
 * avviato, che nel frattempo può essere stata smontata: App lo unisce solo
 * se mostra ancora lo stesso PC e la stessa rete.
 */
function startSpeed(target: SpeedTargetRef, scan: Scan, addSpeed: ViewProps['addSpeed'], toast: ReturnType<typeof useToast>, resume = false) {
  if (speedPromise) return;
  publish({ run: { phase: 'locate', elapsedMs: 0 }, target, error: undefined });
  const p = target.live ? runSpeed(applyState, { resume }) : simulate(scan);
  speedPromise = p;
  p.then(
    (r) => {
      if (!addSpeed(r, target)) return;
      const d = r.download;
      toast(d ? `Test di velocità completato · ${mbpsText(d.mbps)} in download${r.upload?.mbps ? `, ${mbpsText(r.upload.mbps)} in upload` : ''}` : 'Test di velocità completato', 'ok', 'complete');
    },
    (e) => {
      const msg = e instanceof Error ? e.message : String(e);
      publish({ error: msg });
      if (/interrott/i.test(msg)) toast('Test interrotto', 'ok', 'tap');
      else toast(`Test non riuscito: ${msg}`, 'error');
      // Dopo un rifiuto (troppo presto) si aggiorna l'attesa mostrata.
      if (target.live) speedStatus().then(applyState).catch(() => undefined);
    },
  ).finally(() => {
    speedPromise = null;
    simCancel = null;
    publish({ run: null });
  });
}

/** "1 min 20 s", "45 s". */
export function waitText(sec: number): string {
  if (sec < 60) return `${sec} s`;
  return sec % 60 ? `${Math.floor(sec / 60)} min ${sec % 60} s` : `${sec / 60} min`;
}

/** Ora corrente che si aggiorna ogni `every` ms (0 = ferma). */
function useNow(every: number): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!every) return;
    setNow(Date.now());
    const t = window.setInterval(() => setNow(Date.now()), every);
    return () => window.clearInterval(t);
  }, [every]);
  return now;
}

const when = (iso?: string) => {
  if (!iso) return '';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString('it-IT', { dateStyle: 'short', timeStyle: 'short' });
};

// ---------------------------------------------------------------- Scheda

export function SpeedCard({ scan, live, source, addSpeed }: ViewProps) {
  const toast = useToast();
  const openGuide = useOpenGuide();
  const job = useSpeedJob();
  // Il test in corso (o l'ultimo finito) è di questo rapporto.
  const mine = sameSpeedTarget(job.target, scan, source);
  const run = mine ? job.run : null;
  const busy = !!job.run;
  const result = scan.internet?.speed;
  const readOnly = source === 'file';
  const [asking, setAsking] = useState(false);
  const [focusStop, setFocusStop] = useState(false);
  const resultHead = useRef<HTMLHeadingElement>(null);
  // L'orologio gira solo finché c'è un'attesa da mostrare.
  const now = useNow(live && job.nextAt && job.nextAt > Date.now() ? 1000 : 0);
  const waitSec = live && job.nextAt ? Math.max(0, Math.ceil((job.nextAt - now) / 1000)) : 0;
  const error = mine && !busy ? job.error : undefined;
  const wifi = primaryAdapter(scan)?.kind === 'wifi';

  // Un test avviato prima (anche da un'altra finestra) si riprende; uno già
  // finito dopo il caricamento della pagina si recupera una volta dall'agente.
  useEffect(() => {
    if (!live || speedPromise) return;
    let alive = true;
    const target: SpeedTargetRef = { live: true, host: scan.agent.host, gateway: scan.gateway?.ip };
    speedStatus()
      .then((st) => {
        if (!alive) return;
        applyState(st);
        if (st.running) startSpeed(target, scan, addSpeed, toast, true);
        else if (!restoreTried && st.result && st.result.startedAt !== scan.internet?.speed?.startedAt) addSpeed(st.result, target, true);
        restoreTried = true;
      })
      .catch(() => undefined);
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [live]);

  // A test finito il fuoco va sull'esito, invece di perdersi con il pulsante "Interrompi".
  const wasRunning = useRef(false);
  useEffect(() => {
    if (wasRunning.current && !run && focusStop) {
      resultHead.current?.focus();
      setFocusStop(false);
    }
    wasRunning.current = !!run;
  }, [run, focusStop]);

  const begin = () => {
    setFocusStop(true);
    startSpeed({ live, host: scan.agent.host, gateway: scan.gateway?.ip }, scan, addSpeed, toast);
  };
  const start = () => {
    if (live) setAsking(true);
    else begin();
  };
  // Si interrompe con il modo del test in corso, non con quello del rapporto mostrato ora.
  const stop = () => {
    if (speedJob.target?.live) stopSpeed().catch((e) => toast(`Interruzione non riuscita: ${e instanceof Error ? e.message : e}`, 'error'));
    else simCancel?.();
  };

  return (
    <m.section variants={rise} className="card speed-card" style={{ marginTop: 16 }} aria-labelledby="speed-title">
      <div className="card-head">
        <h2 id="speed-title" className="disk-title">
          <Gauge size={19} aria-hidden /> <span>Velocità di Internet</span>
        </h2>
        <span className="sub">{result ? `M-Lab · ${speedWhere(result.server)} · ${when(result.startedAt)}` : 'circa 30 secondi, solo su richiesta'}</span>
      </div>
      <p className="muted bench-desc">
        Misura download, upload e latenza, a riposo e con la linea piena, verso un server di Measurement Lab (M-Lab), un progetto senza scopo di lucro. Il test
        parte solo quando lo avvii e chiede ogni volta il consenso: M-Lab pubblica il risultato con l'indirizzo IP pubblico della connessione.
        {openGuide && (
          <>
            {' '}
            <button className="link-btn" onClick={() => openGuide('velocita-internet')}>
              Che cosa misura e che cosa no
            </button>
          </>
        )}
      </p>
      {readOnly ? (
        <div className="notice" style={{ marginBottom: 14 }}>
          <TriangleAlert size={18} aria-hidden />
          <span>Rapporto importato: qui si consulta il test fatto allora. Il test si esegue dall'agente, sul PC e nella rete da misurare.</span>
        </div>
      ) : (
        !live && (
          <div className="notice" style={{ marginBottom: 14 }}>
            <TriangleAlert size={18} aria-hidden />
            <span>
              Senza agente il test è <b>simulato</b> sui dati dimostrativi: nessun traffico in rete e nessun dato inviato a M-Lab, per questo non chiede il consenso.
            </span>
          </div>
        )
      )}
      {!readOnly && (
        <div className="speed-controls">
          <button className="btn primary" disabled={busy || waitSec > 0} onClick={start} aria-describedby={waitSec > 0 && !busy ? 'speed-wait' : undefined}>
            <Play size={16} className="nudge" aria-hidden /> {busy ? 'Test in corso…' : live ? (result ? 'Ripeti il test…' : 'Avvia il test…') : 'Simula il test'}
          </button>
          {waitSec > 0 && !busy && (
            <span id="speed-wait" className="faint">
              Il prossimo test si può avviare tra {waitText(waitSec)}: Polaris ne consente uno ogni due minuti e dieci al giorno, per non pesare sui server di M-Lab.
            </span>
          )}
          {live && !waitSec && job.left !== undefined && job.left <= 3 && (
            <span className="faint">{job.left ? `Test ancora possibili oggi: ${job.left}.` : 'Per oggi sono già stati fatti tutti i test consentiti.'}</span>
          )}
        </div>
      )}
      {/* Annuncia solo le fasi: velocità e latenza cambiano di continuo e non vanno lette. */}
      <p className="sr-only" aria-live="polite">
        {run ? `Test di velocità: ${phaseLabel(run.phase)}` : ''}
      </p>
      <AnimatePresence initial={false}>{run && <SpeedProgressBox run={run} onStop={stop} autoFocus={focusStop} />}</AnimatePresence>
      {error && (
        <p className="space-error" role="alert">
          <TriangleAlert size={15} aria-hidden /> {error}
        </p>
      )}
      {result && <SpeedResult r={result} wifi={wifi} headRef={resultHead} />}
      {!result && readOnly && <p className="muted">Questo rapporto non contiene un test di velocità.</p>}
      {asking && (
        <ConsentDialog
          onCancel={() => setAsking(false)}
          onAccept={() => {
            setAsking(false);
            begin();
          }}
        />
      )}
    </m.section>
  );
}

function SpeedProgressBox({ run, onStop, autoFocus }: { run: SpeedRun; onStop: () => void; autoFocus: boolean }) {
  const stopRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (autoFocus) stopRef.current?.focus();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const at = PHASES.findIndex((p) => p.id === run.phase);
  const done = run.phaseMs ? Math.min(1, run.elapsedMs / run.phaseMs) : undefined;
  const transfer = run.phase === 'download' || run.phase === 'upload';
  return (
    <m.div
      key="progress"
      initial={{ height: 0, opacity: 0 }}
      animate={{ height: 'auto', opacity: 1, transition: { height: spring.smooth, opacity: { duration: 0.25 } } }}
      exit={{ height: 0, opacity: 0, transition: { duration: 0.25, ease: ease.inOut } }}
      style={{ overflow: 'hidden' }}
    >
      <div className="bench-live speed-live">
        <ol className="speed-steps" aria-label="Fasi del test">
          {PHASES.map((p, i) => {
            const state = i < at ? 'done' : i === at ? 'current' : 'todo';
            return (
              <li key={p.id} data-state={state} aria-current={state === 'current' ? 'step' : undefined}>
                {state === 'done' ? <Check size={15} aria-hidden /> : state === 'current' ? <HexLoader size={15} /> : <Circle size={13} aria-hidden />}
                <span>{p.label}</span>
                <span className="sr-only">{state === 'done' ? ' (fatta)' : state === 'current' ? ' (in corso)' : ' (da fare)'}</span>
              </li>
            );
          })}
        </ol>
        <div className="speed-now">
          <span className="speed-big">
            {transfer ? (run.mbps !== undefined ? mbpsText(run.mbps) : '…') : run.phase === 'idle' && run.latencyMs !== undefined ? speedMs(run.latencyMs) : '…'}
          </span>
          <span className="faint">
            {transfer
              ? `${run.phase === 'download' ? 'in download' : 'in upload'}${run.latencyMs !== undefined ? ` · latenza ${speedMs(run.latencyMs)}` : ''}${run.server ? ` · ${speedWhere(run.server)}` : ''}`
              : run.phase === 'idle'
                ? 'latenza a riposo, con la linea libera'
                : 'M-Lab sceglie un server vicino'}
          </span>
        </div>
        <div
          className={`progress ${done === undefined ? 'indeterminate' : 'live'}`}
          role="progressbar"
          aria-label={`Avanzamento della fase: ${phaseLabel(run.phase)}`}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={done === undefined ? undefined : Math.round(done * 100)}
        >
          {done === undefined ? <i /> : <m.i initial={false} animate={{ scaleX: done }} transition={spring.gentle} />}
        </div>
        <div className="bench-live-row">
          <span className="faint">Non usare la rete durante il test: altri trasferimenti abbassano il risultato.</span>
          <button ref={stopRef} className="btn small" onClick={onStop}>
            <CircleStop size={15} aria-hidden /> Interrompi
          </button>
        </div>
      </div>
    </m.div>
  );
}

// ---------------------------------------------------------------- Esito

function SpeedResult({ r, wifi, headRef }: { r: SpeedTest; wifi: boolean; headRef: RefObject<HTMLHeadingElement> }) {
  const b = speedBloat(r);
  const d = r.download;
  const u = r.upload;
  const caveats = speedCaveats(r, wifi);
  const ok = (x?: SpeedDir) => !!x && x.bytes > 0 && x.mbps > 0;
  const loaded = (x?: SpeedDir) =>
    x?.latency?.medianMs !== undefined
      ? `${speedMs(x.latency.medianMs)}${x.bloatMs !== undefined ? ` (+${speedMs(x.bloatMs)}; 95° percentile +${speedMs(x.bloatP95Ms ?? x.bloatMs)})` : ''}${x.latency.sent > x.latency.received ? `, ${x.latency.sent - x.latency.received} sonde su ${x.latency.sent} senza risposta` : ''}`
      : '—';
  return (
    <div className="speed-result">
      <h3 ref={headRef} tabIndex={-1}>
        Esito{r.simulated ? ' · simulazione' : ''}
      </h3>
      <div className="stats speed-stats">
        <div className="stat">
          <div className="k">Download</div>
          <div className="v">{ok(d) ? mbpsText(d!.mbps) : 'non misurato'}</div>
        </div>
        <div className="stat">
          <div className="k">Upload</div>
          <div className="v">{ok(u) ? mbpsText(u!.mbps) : 'non misurato'}</div>
        </div>
        <div className="stat">
          <div className="k">Latenza a riposo</div>
          <div className="v">{r.idle?.medianMs !== undefined ? speedMs(r.idle.medianMs) : '—'}</div>
        </div>
        <div className="stat">
          <div className="k">Latenza sotto carico</div>
          <div className="v speed-bloat">
            <span className={`sev ${b.severity}`}>
              <SevIcon sev={b.severity} size={14} />
              {BLOAT_LABEL[b.severity]}
            </span>
            {b.worst !== undefined && (
              <span className="speed-sub">
                +{speedMs(b.worst)} {b.dir === 'upload' ? 'in upload' : 'in download'}
              </span>
            )}
          </div>
        </div>
        <div className="stat">
          <div className="k">Server M-Lab</div>
          <div className="v speed-server">{speedWhere(r.server)}</div>
        </div>
      </div>
      <dl className="speed-facts">
        <div>
          <dt>Latenza durante il download</dt>
          <dd>{loaded(d)}</dd>
        </div>
        <div>
          <dt>Latenza durante l'upload</dt>
          <dd>{loaded(u)}</dd>
        </div>
        <div>
          <dt>Dati trasferiti</dt>
          <dd>
            {[ok(d) ? `${speedBytes(d!.bytes)} in download${d!.capped ? ' (limite di 250 MB)' : ''}` : '', ok(u) ? `${speedBytes(u!.bytes)} in upload${u!.capped ? ' (limite di 250 MB)' : ''}` : '']
              .filter(Boolean)
              .join(', ') || '—'}
          </dd>
        </div>
        <div>
          <dt>Sonde di latenza</dt>
          <dd>
            {r.probeMethod === 'tcp' ? 'connessioni TCP (ping bloccati)' : r.probeMethod === 'icmp' ? 'ping' : 'nessuna risposta'}
            {r.probe && r.probeMethod ? <span className="mono"> → {r.probe}</span> : null}
          </dd>
        </div>
        {d?.minRttMs !== undefined && (
          <div>
            <dt>Andata e ritorno minimo verso il server</dt>
            <dd>{speedMs(d.minRttMs)}</dd>
          </div>
        )}
        {d?.retransPct !== undefined && (
          <div>
            <dt>Dati ritrasmessi in download</dt>
            <dd>{fmtNum(d.retransPct, 1)} %</dd>
          </div>
        )}
      </dl>
      {[d?.error && `Download: ${speedErr(d.error)}.`, u?.error && `Upload: ${ok(u) ? '' : 'non riuscito, '}${speedErr(u.error)}.`].filter(Boolean).map((e) => (
        <p key={String(e)} className="speed-warn">
          <TriangleAlert size={15} aria-hidden /> {e}
        </p>
      ))}
      {caveats.length > 0 && (
        <ul className="speed-notes">
          {caveats.map((c) => (
            <li key={c}>{c}</li>
          ))}
        </ul>
      )}
      <div className="notice speed-legal">
        <TriangleAlert size={18} aria-hidden />
        <span>
          {SPEED_LEGAL_NOTE.split('www.misurainternet.it').map((part, i, all) => (
            <Fragment key={i}>
              {part}
              {i < all.length - 1 && (
                <a href="https://www.misurainternet.it/" target="_blank" rel="noreferrer noopener">
                  www.misurainternet.it
                  <ExternalLink size={12} aria-hidden style={{ marginLeft: 3, verticalAlign: '-1px' }} />
                  <span className="sr-only"> (si apre in una nuova finestra)</span>
                </a>
              )}
            </Fragment>
          ))}
        </span>
      </div>
    </div>
  );
}
