import { CircleStop, LocateFixed, MapPinned, Plus, Trash2, TriangleAlert } from 'lucide-react';
import { AnimatePresence, m } from 'motion/react';
import { useEffect, useId, useMemo, useRef, useState } from 'react';
import type { FormEvent, ReactNode } from 'react';
import {
  bandText,
  dbmText,
  gatewayText,
  radioText,
  roomKey,
  rssiSeverity,
  rssiWord,
  surveyAliases,
  surveyRooms,
  SURVEY_MAX_ROOM,
  SURVEY_SECONDS,
} from '../engine';
import type { RoomResult, Scan, Severity, SurveyAliases, SurveySample, WifiSurvey } from '../engine';
import { simulatedSample } from '../demo/survey';
import { runSurvey, stopSurvey, surveyStatus } from './api';
import type { SurveyState } from './api';
import { HexLoader } from './anim';
import { fmtNum, SevIcon, useOpenGuide, useToast } from './components';
import { ease, spring } from './motion';
import type { ViewProps } from './views';

// Mappa del Wi-Fi per stanza: l'utente va in ogni stanza, scrive il nome del
// locale e preme "Misura qui"; l'agente misura per circa 15 secondi segnale,
// access point e ping al router, poi fa una scansione. Le stanze si ordinano
// dalla più debole. Senza agente la misura è simulata e dichiarata come tale;
// un rapporto importato si consulta e basta.

/** Rete e PC su cui è partita una misura: si unisce solo al rapporto della stessa rete e della stessa origine. */
export interface SurveyTargetRef {
  live: boolean;
  host?: string;
  gateway?: string;
}

/**
 * La misura riguarda il rapporto mostrato: stesso PC, stesso gateway, dati
 * Wi-Fi presenti, e dati dell'agente per una misura reale o demo per una
 * simulata. Un rapporto importato non riceve mai misure.
 */
export const sameSurveyTarget = (t: SurveyTargetRef | undefined, scan: Scan | null | undefined, source: 'agent' | 'demo' | 'file') =>
  !!t && !!scan && !!scan.wifi && source === (t.live ? 'agent' : 'demo') && t.host === scan.agent.host && t.gateway === scan.gateway?.ip;

/** Il nome come lo salva l'agente: spazi in eccesso tolti. */
export const cleanRoom = (name: string) => name.trim().replace(/\s+/g, ' ');

/** Lo stesso controllo dell'agente: da 1 a 40 caratteri, senza caratteri di controllo. */
export function roomNameError(name: string): string | undefined {
  const n = cleanRoom(name);
  if (!n) return 'Scrivi il nome della stanza, per esempio Soggiorno o Ambulatorio 2.';
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f-\u009f]/.test(n)) return 'Il nome contiene caratteri non validi.';
  if (Array.from(n).length > SURVEY_MAX_ROOM) return `Al massimo ${SURVEY_MAX_ROOM} caratteri.`;
  return undefined;
}

/** Aggiunge una misura alla sua stanza (stesso nome senza badare a maiuscole e spazi) o crea la stanza. */
export function mergeSample(survey: WifiSurvey | undefined, s: SurveySample): WifiSurvey {
  const rooms = (survey?.rooms ?? []).slice();
  const i = rooms.findIndex((r) => roomKey(r.name) === roomKey(s.room));
  if (i >= 0) rooms[i] = { ...rooms[i], samples: rooms[i].samples.filter((x) => x.startedAt !== s.startedAt).concat(s) };
  else rooms.push({ name: cleanRoom(s.room), samples: [s] });
  return { rooms };
}

/** Toglie una stanza, o un solo punto se si indica quando è stato misurato. */
export function removeFromSurvey(survey: WifiSurvey | undefined, name: string, startedAt?: string): WifiSurvey | undefined {
  const rooms = (survey?.rooms ?? [])
    .map((r) => (roomKey(r.name) !== roomKey(name) ? r : startedAt ? { ...r, samples: r.samples.filter((x) => x.startedAt !== startedAt) } : { ...r, samples: [] }))
    .filter((r) => r.samples.length > 0);
  return rooms.length ? { rooms } : undefined;
}

/** Etichette della gravità per stanza: icona e testo, mai solo il colore. */
export const ROOM_SEV_TEXT: Record<Severity, string> = {
  ok: 'a posto',
  info: 'da sapere',
  warn: 'da migliorare',
  crit: 'problema',
  unknown: 'non misurata',
};

// ---------------------------------------------------------------- Misura in corso

export interface SurveyRun {
  room: string;
  seconds: number;
  phase: 'misura' | 'scansione';
  elapsedMs: number;
  rssi: number[];
  dbm?: number;
  pings: number;
  replies: number;
  roams: number;
}

interface SurveyJob {
  run: SurveyRun | null;
  /** Rete e modo (reale o simulata) della misura in corso o dell'ultima finita. */
  target?: SurveyTargetRef;
  error?: string;
}

// La misura continua anche se si cambia sezione: lo stato vive fuori dalla
// scheda, che rimontata lo ritrova. L'esito lo unisce App, solo se mostra
// ancora la stessa rete.
let surveyJob: SurveyJob = { run: null };
let surveyPromise: Promise<unknown> | null = null;
let surveyCancel: (() => void) | null = null;
const jobListeners = new Set<(j: SurveyJob) => void>();

function publish(patch: Partial<SurveyJob>) {
  surveyJob = { ...surveyJob, ...patch };
  for (const l of jobListeners) l(surveyJob);
}

function useSurveyJob(): SurveyJob {
  const [job, setJob] = useState<SurveyJob>(surveyJob);
  useEffect(() => {
    jobListeners.add(setJob);
    setJob(surveyJob);
    return () => {
      jobListeners.delete(setJob);
    };
  }, []);
  return job;
}

/** Chiave del salvataggio locale della mappa: per PC e rete (solo con l'agente). */
const storeKey = (t: SurveyTargetRef) => `polaris.wifimap.${t.host ?? 'pc'}.${t.gateway ?? 'senza-gateway'}`;

function readStored(key: string): WifiSurvey | undefined {
  try {
    const v = JSON.parse(localStorage.getItem(key) ?? 'null') as WifiSurvey | null;
    return v && Array.isArray(v.rooms) && v.rooms.length ? v : undefined;
  } catch {
    return undefined;
  }
}

function writeStored(key: string, survey?: WifiSurvey) {
  try {
    if (survey?.rooms.length) localStorage.setItem(key, JSON.stringify(survey));
    else localStorage.removeItem(key);
  } catch {
    // memoria del browser non disponibile: la mappa resta nel rapporto
  }
}

/** Misura simulata per la demo: secondi accelerati, poi la scansione. */
function simulate(scan: Scan, room: string, seconds: number, withScan: boolean): Promise<SurveySample> {
  const sample = simulatedSample(scan, room, seconds, withScan);
  return new Promise((resolve, reject) => {
    let i = 0;
    let timer = 0;
    surveyCancel = () => {
      window.clearTimeout(timer);
      reject(new Error('misura interrotta'));
    };
    const pings = sample.gateway && !sample.gateway.skipped ? sample.gateway.sent / seconds : 0;
    const tick = () => {
      i++;
      if (i <= seconds) {
        const rssi = sample.rssi.slice(0, i);
        publish({
          run: {
            room,
            seconds,
            phase: 'misura',
            elapsedMs: i * 1000,
            rssi,
            dbm: rssi[i - 1],
            pings: Math.round(pings * i),
            replies: Math.round(pings * i * (sample.gateway ? sample.gateway.received / Math.max(1, sample.gateway.sent) : 0)),
            roams: sample.roams.filter((r) => r.atMs <= i * 1000).length,
          },
        });
        timer = window.setTimeout(tick, 220);
      } else if (i === seconds + 1 && withScan) {
        publish({ run: { ...surveyJob.run!, phase: 'scansione' } });
        timer = window.setTimeout(tick, 700);
      } else resolve(sample);
    };
    tick();
  });
}

/**
 * Avvia (o riprende) una misura. L'esito non passa dalla scheda, che nel
 * frattempo può essere stata smontata: App lo unisce solo se mostra ancora
 * la stessa rete.
 */
function startSurvey(
  target: SurveyTargetRef,
  scan: Scan,
  req: { room: string; seconds: number; scan: boolean },
  addSurvey: ViewProps['addSurvey'],
  toast: ReturnType<typeof useToast>,
  resume = false,
) {
  if (surveyPromise) return;
  publish({ run: { room: req.room, seconds: req.seconds, phase: 'misura', elapsedMs: 0, rssi: [], pings: 0, replies: 0, roams: 0 }, target, error: undefined });
  const p = target.live
    ? runSurvey(
        req,
        (st: SurveyState) => {
          const g = st.progress;
          if (st.running && g)
            publish({
              run: { room: st.room ?? req.room, seconds: g.seconds, phase: g.phase, elapsedMs: g.elapsedMs, rssi: g.rssi ?? [], dbm: g.dbm, pings: g.pings, replies: g.replies, roams: g.roams },
            });
        },
        { resume },
      )
    : simulate(scan, req.room, req.seconds, req.scan);
  surveyPromise = p;
  p.then(
    (s) => {
      if (target.live) writeStored(storeKey(target), mergeSample(readStored(storeKey(target)), s));
      if (!addSurvey(s, target)) return;
      toast(`Misura di «${s.room}» completata · ${dbmText(s.medianDbm)} dBm, ${rssiWord(s.medianDbm)}`, 'ok', 'complete');
    },
    (e) => {
      const msg = e instanceof Error ? e.message : String(e);
      publish({ error: msg });
      if (/interrott/i.test(msg)) toast('Misura interrotta', 'ok', 'tap');
      else toast(`Misura non riuscita: ${msg}`, 'error');
    },
  ).finally(() => {
    surveyPromise = null;
    surveyCancel = null;
    publish({ run: null });
  });
}

/** Misura del Wi-Fi in corso (per disattivare nel frattempo ciò che la falserebbe). */
export function useSurveyRun(): SurveyRun | null {
  return useSurveyJob().run;
}

// ---------------------------------------------------------------- Scheda

export function WifiMapCard({ scan, analysis, go, live, source, addSurvey, setSurvey }: ViewProps) {
  const toast = useToast();
  const openGuide = useOpenGuide();
  const job = useSurveyJob();
  const run = job.run;
  const readOnly = source === 'file';
  const target: SurveyTargetRef = { live, host: scan.agent.host, gateway: scan.gateway?.ip };
  const mine = sameSurveyTarget(job.target, scan, source);
  const survey = scan.wifi?.survey;
  const alias = useMemo(() => surveyAliases(survey), [survey]);
  const rooms = useMemo(() => surveyRooms(survey, alias), [survey, alias]);
  const [room, setRoom] = useState('');
  const [seconds, setSeconds] = useState(SURVEY_SECONDS);
  const [withScan, setWithScan] = useState(true);
  const [touched, setTouched] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const ids = useId();
  const err = touched ? roomNameError(room) : undefined;

  // Con l'agente la mappa si conserva sul PC, per rete: sopravvive a un
  // riavvio dell'interfaccia. Le misure nuove le salva la misura stessa,
  // anche a scheda chiusa; qui si salvano le stanze tolte.
  const key = storeKey(target);
  const restored = useRef(false);
  useEffect(() => {
    if (source !== 'agent') return;
    if (!restored.current) {
      restored.current = true;
      if (!survey) {
        const saved = readStored(key);
        if (saved) {
          setSurvey(saved);
          return;
        }
      }
    }
    writeStored(key, survey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [source, key, survey]);

  // Una misura avviata prima (pagina ricaricata, altra finestra) si riprende.
  useEffect(() => {
    if (!live || surveyPromise) return;
    let alive = true;
    surveyStatus()
      .then((st) => {
        if (alive && st.running && st.room) startSurvey({ live: true, host: scan.agent.host, gateway: scan.gateway?.ip }, scan, { room: st.room, seconds: st.progress?.seconds ?? SURVEY_SECONDS, scan: true }, addSurvey, toast, true);
      })
      .catch(() => undefined);
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [live]);

  const start = (e?: FormEvent) => {
    e?.preventDefault();
    setTouched(true);
    const problem = roomNameError(room);
    if (problem) {
      inputRef.current?.focus();
      return;
    }
    if (surveyPromise) return;
    startSurvey(target, scan, { room: cleanRoom(room), seconds, scan: withScan }, addSurvey, toast);
  };
  // Si interrompe con il modo della misura in corso, non con quello del rapporto mostrato ora.
  const stop = () => {
    if (surveyJob.target?.live) stopSurvey().catch((e) => toast(`Interruzione non riuscita: ${e instanceof Error ? e.message : e}`, 'error'));
    else surveyCancel?.();
  };
  const another = (name: string) => {
    setRoom(name);
    setTouched(false);
    inputRef.current?.focus();
    inputRef.current?.scrollIntoView({ block: 'center', behavior: 'smooth' });
    toast(`Spostati nel nuovo punto di «${name}» e premi Misura qui`, 'ok', 'tap');
  };
  const removeRoom = (name: string, startedAt?: string) => {
    setSurvey(removeFromSurvey(survey, name, startedAt));
    toast(startedAt ? `Punto di «${name}» rimosso` : `Stanza «${name}» rimossa`, 'ok', 'tap');
  };

  // Che cosa fare: le azioni del piano che vengono dalle stanze, con la
  // gravità della stanza peggiore che le richiede.
  const roomOf = (fid: string) => rooms.find((r) => r.id === fid);
  const RANK: Record<Severity, number> = { unknown: 0, ok: 1, info: 2, warn: 3, crit: 4 };
  const plan = analysis.plan
    .filter((p) => p.findings.some((f) => f.indexOf('wifi.room.') === 0))
    .map((p) => {
      const mine = p.findings.map(roomOf).filter((r): r is RoomResult => !!r);
      const severity = mine.reduce<Severity>((acc, r) => (RANK[r.severity] > RANK[acc] ? r.severity : acc), 'ok');
      return { action: p.action, severity, names: mine.map((r) => r.room.name) };
    })
    .sort((a, b) => RANK[b.severity] - RANK[a.severity])
    .slice(0, 5);
  const ssids = Array.from(new Set(rooms.flatMap((r) => r.room.samples.map((s) => s.ssid))));
  const error = mine && !run ? job.error : undefined;

  return (
    <m.section className="card wifimap-card" initial={false}>
      <div className="card-head">
        <h2 className="wifimap-title">
          <MapPinned size={19} aria-hidden /> <span>Mappa del Wi-Fi per stanza</span>
        </h2>
        <span className="sub">{rooms.length ? `${rooms.length} ${rooms.length === 1 ? 'stanza' : 'stanze'} · misure fatte con questo PC` : 'circa 15 secondi per stanza'}</span>
      </div>
      <p className="muted wifimap-desc">
        Vai nelle stanze in cui si lavora, scrivi il nome del locale e premi Misura qui: per circa 15 secondi Polaris legge il segnale che il PC riceve e
        l'access point a cui è collegato, manda un ping al router ogni 200 ms (solo se ha un indirizzo privato) e alla fine fa una scansione delle reti. I valori
        valgono per questo PC: un altro dispositivo, con altre antenne, riceve in modo diverso.
        {openGuide && (
          <>
            {' '}
            <button className="link-btn" onClick={() => openGuide('wifi-stanza-per-stanza')}>
              Come si misura e come si legge
            </button>
          </>
        )}
      </p>

      {readOnly ? (
        <div className="notice">
          <TriangleAlert size={18} aria-hidden />
          <span>Rapporto importato: qui si consultano le stanze misurate allora. Le misure si fanno con l'agente, nel posto da misurare.</span>
        </div>
      ) : (
        <>
          {!live && (
            <div className="notice" style={{ marginBottom: 12 }}>
              <TriangleAlert size={18} aria-hidden />
              <span>
                Senza agente la misura è <b>simulata</b> sui dati dimostrativi, con i secondi accelerati: serve a vedere come funziona.
              </span>
            </div>
          )}
          <div className="wifimap-before">
            <h3>Prima di ogni misura</h3>
            <ol>
              <li>Mettiti dove si lavora davvero: scrivania, letto, poltrona, bancone.</li>
              <li>Portatile aperto sul piano di lavoro, con lo schermo nella stessa posizione in ogni stanza.</li>
              <li>Resta fermo fino alla fine della misura.</li>
              <li>Collega l'alimentatore, se puoi.</li>
            </ol>
          </div>
          <form className="wifimap-form" onSubmit={start} noValidate>
            <div className="wifimap-field">
              <label htmlFor={`${ids}-room`}>Nome della stanza</label>
              <input
                ref={inputRef}
                id={`${ids}-room`}
                className="field"
                value={room}
                maxLength={SURVEY_MAX_ROOM}
                placeholder="Soggiorno, Ambulatorio 2, Sala d'attesa…"
                autoComplete="off"
                list={`${ids}-rooms`}
                aria-invalid={!!err}
                aria-describedby={`${ids}-hint${err ? ` ${ids}-err` : ''}`}
                onChange={(e) => setRoom(e.target.value)}
              />
              <datalist id={`${ids}-rooms`}>
                {rooms.map((r) => (
                  <option key={r.id} value={r.room.name} />
                ))}
              </datalist>
              <span id={`${ids}-hint`} className="wifimap-hint">
                Usa nomi di luogo, non di persone. Al massimo {SURVEY_MAX_ROOM} caratteri.
              </span>
              {err && (
                <span id={`${ids}-err`} className="reach-err">
                  {err}
                </span>
              )}
            </div>
            <label className="wifimap-secs">
              <span>Durata</span>
              <select className="field" value={seconds} onChange={(e) => setSeconds(Number(e.target.value))} disabled={!!run}>
                {[10, 15, 20].map((n) => (
                  <option key={n} value={n}>
                    {n} secondi
                  </option>
                ))}
              </select>
            </label>
            <label className="consent wifimap-scan">
              <input type="checkbox" checked={withScan} onChange={(e) => setWithScan(e.target.checked)} disabled={!!run} />
              <span>Alla fine, una scansione delle reti (circa 4 secondi)</span>
            </label>
            <button type="submit" className="btn primary" disabled={!!run}>
              <LocateFixed size={16} aria-hidden /> {run ? 'Misura in corso…' : live ? 'Misura qui' : 'Simula la misura qui'}
            </button>
          </form>
          <p className="faint wifimap-note">
            Mentre Polaris legge il Wi-Fi, Windows mostra l'icona della posizione nella barra delle applicazioni: è normale. Su Windows 11 24H2 e successivi
            servono i permessi di posizione.
          </p>
          {/* Annuncia solo l'avvio: la fine la annuncia il messaggio temporaneo. */}
          <p className="sr-only" aria-live="polite">
            {run && mine ? `Misura in «${run.room}» avviata: resta fermo per ${run.seconds} secondi.` : ''}
          </p>
          <AnimatePresence initial={false}>{run && <SurveyProgressBox key="progress" run={run} onStop={stop} />}</AnimatePresence>
          {error && (
            <p className="space-error" role="alert">
              <TriangleAlert size={15} aria-hidden /> {error}
            </p>
          )}
        </>
      )}

      {rooms.length ? (
        <div className="wifimap-results">
          <h3>Stanze, dalla più debole alla più forte</h3>
          {ssids.length > 1 && (
            <p className="notice warn" style={{ marginTop: 0 }}>
              <TriangleAlert size={18} aria-hidden />
              <span>Le misure non sono tutte sulla stessa rete ({ssids.join(', ')}): confronta solo le stanze della stessa rete.</span>
            </p>
          )}
          <ol className="wifimap-list">
            {rooms.map((r) => (
              <RoomItem key={r.id} r={r} alias={alias} readOnly={readOnly} busy={!!run} onAnother={another} onRemove={removeRoom} />
            ))}
          </ol>
          {plan.length > 0 && (
            <div className="wifimap-plan">
              <h3>Che cosa fare</h3>
              <ul>
                {plan.map((p) => {
                  const names = p.names;
                  return (
                    <li key={p.action.id}>
                      <span className={`sev ${p.severity}`}>
                        <SevIcon sev={p.severity} size={13} />
                        <span className="sr-only">{ROOM_SEV_TEXT[p.severity]}: </span>
                      </span>
                      <span>
                        <button className="link-btn" onClick={() => go('plan', p.action.id)}>
                          {p.action.title}
                        </button>
                        {names.length > 0 && <span className="faint"> · {names.join(', ')}</span>}
                      </span>
                    </li>
                  );
                })}
              </ul>
            </div>
          )}
          <p className="faint wifimap-note">
            Muri in cemento e solai pesano molto, di più a 5 e 6 GHz; i forni a microonde disturbano i 2,4 GHz. Le reti dei vicini compaiono solo come numeri, e
            nei rapporti esportati gli access point diventano AP A, AP B.
          </p>
        </div>
      ) : (
        !run && <p className="empty wifimap-empty">{readOnly ? 'Questo rapporto non contiene misure per stanza.' : 'Nessuna stanza misurata: comincia da quella in cui il Wi-Fi va peggio.'}</p>
      )}
    </m.section>
  );
}

/** Posizione in percentuale di un valore in dBm sulla scala da -90 a -40. */
const pos = (dbm: number) => Math.max(0, Math.min(100, ((dbm + 90) / 50) * 100));

function SurveyProgressBox({ run, onStop }: { run: SurveyRun; onStop: () => void }) {
  const scanning = run.phase === 'scansione';
  const done = Math.min(run.seconds, Math.round(run.elapsedMs / 1000));
  const sev = run.dbm !== undefined ? rssiSeverity(run.dbm) : 'unknown';
  const valueText = scanning ? 'scansione delle reti' : `${done} secondi su ${run.seconds}${run.dbm !== undefined ? `, segnale ${run.dbm} dBm` : ''}`;
  return (
    <m.div
      initial={{ height: 0, opacity: 0 }}
      animate={{ height: 'auto', opacity: 1, transition: { height: spring.smooth, opacity: { duration: 0.25 } } }}
      exit={{ height: 0, opacity: 0, transition: { duration: 0.25, ease: ease.inOut } }}
      style={{ overflow: 'hidden' }}
    >
      <div className="bench-live wifimap-live">
        <div
          className={`progress ${scanning ? 'indeterminate' : 'live'}`}
          role="progressbar"
          aria-label={`Misura in «${run.room}»`}
          aria-valuemin={0}
          aria-valuemax={run.seconds}
          aria-valuenow={scanning ? undefined : done}
          aria-valuetext={valueText}
        >
          {scanning ? <i /> : <m.i initial={false} animate={{ scaleX: done / run.seconds }} transition={spring.gentle} />}
        </div>
        <div className="wifimap-now">
          <span className="wifimap-dbm">
            <b>{run.dbm !== undefined ? run.dbm : '—'}</b> dBm
          </span>
          {run.dbm !== undefined && (
            <span className={`sev ${sev}`}>
              <SevIcon sev={sev} size={13} />
              {rssiWord(run.dbm)}
            </span>
          )}
          <span className="wifimap-bars" aria-hidden="true">
            {Array.from({ length: run.seconds }, (_, i) => {
              const v = run.rssi[i];
              return <i key={i} className={v === undefined ? 'wait' : rssiSeverity(v)} style={{ height: v === undefined ? undefined : `${Math.max(12, pos(v))}%` }} />;
            })}
          </span>
        </div>
        <div className="bench-live-row">
          <span className="faint space-live">
            <HexLoader size={16} /> {run.room} · {scanning ? 'scansione delle reti…' : `${done}/${run.seconds} s`}
            {run.pings > 0 ? ` · router: ${run.replies} risposte su ${run.pings} ping` : ''}
            {run.roams > 0 ? ` · ${run.roams} ${run.roams === 1 ? 'cambio' : 'cambi'} di access point` : ''}
          </span>
          <button className="btn small" onClick={onStop}>
            <CircleStop size={15} aria-hidden /> Interrompi
          </button>
        </div>
      </div>
    </m.div>
  );
}

const when = (iso: string) => {
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString('it-IT', { dateStyle: 'short', timeStyle: 'short' });
};

function SignalScale({ s }: { s: SurveySample }) {
  // Scala da -90 a -40 dBm con le soglie: solo visiva, i valori sono scritti accanto.
  return (
    <span className="wifimap-scale" aria-hidden="true">
      <span className="zone crit" style={{ width: `${pos(-80)}%` }} />
      <span className="zone warn" style={{ width: `${pos(-72) - pos(-80)}%` }} />
      <span className="zone info" style={{ width: `${pos(-67) - pos(-72)}%` }} />
      <span className="zone ok" style={{ width: `${100 - pos(-67)}%` }} />
      <span className="range" style={{ left: `${pos(s.minDbm)}%`, width: `${Math.max(1, pos(s.maxDbm) - pos(s.minDbm))}%` }} />
      <span className="dot" style={{ left: `${pos(s.medianDbm)}%` }} />
    </span>
  );
}

function RoomItem({
  r,
  alias,
  readOnly,
  busy,
  onAnother,
  onRemove,
}: {
  r: RoomResult;
  alias: SurveyAliases;
  readOnly: boolean;
  busy: boolean;
  onAnother: (name: string) => void;
  onRemove: (name: string, startedAt?: string) => void;
}) {
  const s = r.worst;
  const n = r.room.samples.length;
  const notes = r.issues.filter((i) => i.id !== 'signal');
  const name = r.room.name;
  return (
    <li className="wifimap-room" data-sev={r.severity}>
      <div className="wifimap-room-head">
        <span className="wifimap-room-name">
          <strong>{name}</strong>
          <span className="faint">
            {n > 1 ? `${n} punti, conta il peggiore · ` : ''}
            {when(s.startedAt)}
          </span>
        </span>
        <span className="wifimap-room-dbm">
          <b>{dbmText(s.medianDbm)}</b> dBm · {rssiWord(s.medianDbm)}
        </span>
        <span className={`sev ${r.severity}`}>
          <SevIcon sev={r.severity} size={14} />
          {ROOM_SEV_TEXT[r.severity]}
        </span>
      </div>
      <SignalScale s={s} />
      {notes.length > 0 && (
        <ul className="cert-notes" aria-label={`Da sapere su ${name}`}>
          {notes.map((x) => (
            <li key={x.id} className={`sev ${x.severity}`}>
              <SevIcon sev={x.severity} size={13} />
              <span className="sr-only">{ROOM_SEV_TEXT[x.severity]}: </span>
              {x.short}
            </li>
          ))}
        </ul>
      )}
      <details className="wifimap-details">
        <summary>Dettagli{n > 1 ? ` dei ${n} punti` : ''}</summary>
        {r.room.samples.map((x, i) => (
          <SampleFacts key={x.startedAt} s={x} alias={alias} label={n > 1 ? `Punto ${i + 1}${x === s ? ', il peggiore' : ''}` : undefined}>
            {!readOnly && n > 1 && (
              <button className="btn small" onClick={() => onRemove(name, x.startedAt)} disabled={busy}>
                <Trash2 size={14} aria-hidden /> Rimuovi questo punto
              </button>
            )}
          </SampleFacts>
        ))}
        {r.issues.length > 0 && (
          <div className="wifimap-why">
            <h4>Perché</h4>
            <ul>
              {r.issues.map((x) => (
                <li key={x.id}>{x.text}</li>
              ))}
            </ul>
          </div>
        )}
      </details>
      {!readOnly && (
        <div className="wifimap-room-actions">
          <button className="btn small" onClick={() => onAnother(name)} disabled={busy}>
            <Plus size={14} aria-hidden /> Misura un altro punto<span className="sr-only"> di {name}</span>
          </button>
          <button className="btn small" onClick={() => onRemove(name)} disabled={busy}>
            <Trash2 size={14} aria-hidden /> Rimuovi la stanza<span className="sr-only"> {name}</span>
          </button>
        </div>
      )}
    </li>
  );
}

function SampleFacts({ s, alias, label, children }: { s: SurveySample; alias: SurveyAliases; label?: string; children?: ReactNode }) {
  const g = s.gateway;
  const sc = s.scan;
  const nb = sc?.neighbors;
  const ap = (b: string) => (
    <>
      <span className="mono">{b}</span> <span className="faint">({alias(b)})</span>
    </>
  );
  return (
    <div className="wifimap-sample">
      {label && <h4>{label}</h4>}
      <dl className="cert-facts">
        <div>
          <dt>Segnale</dt>
          <dd>
            mediana {dbmText(s.medianDbm)} dBm, minimo {s.minDbm}, cali (10° percentile) {s.p10Dbm}, escursione {s.spreadDb} dB · {s.rssi.length} letture in{' '}
            {s.seconds} s{s.stuck ? ' · valori fermi' : ''}
          </dd>
        </div>
        <div>
          <dt>Radio</dt>
          <dd>
            {[radioText(s), s.phy].filter(Boolean).join(' · ') || '—'}
            {s.rxMbps || s.txMbps ? (
              <span className="faint">
                {' '}
                · ricezione {s.rxMbps ?? '—'} Mbit/s, trasmissione {s.txMbps ?? '—'} Mbit/s
              </span>
            ) : null}
          </dd>
        </div>
        <div>
          <dt>Access point</dt>
          <dd>
            {s.roams.length === 0 ? (
              s.bssids[0] ? (
                <>
                  {ap(s.bssids[0])}, nessun cambio durante la misura
                </>
              ) : (
                '—'
              )
            ) : (
              <>
                {s.roams.length} {s.roams.length === 1 ? 'cambio' : 'cambi'} da fermo:{' '}
                {s.roams.map((x, i) => (
                  <span key={i}>
                    {i > 0 ? '; ' : ''}
                    al secondo {Math.round(x.atMs / 1000)} da {alias(x.from)} a {alias(x.to)}
                  </span>
                ))}
                <span className="faint"> ({s.bssids.map((b) => `${alias(b)} = ${b}`).join(', ')})</span>
              </>
            )}
          </dd>
        </div>
        <div>
          <dt>Router</dt>
          <dd>
            {g ? (
              g.skipped || g.error ? (
                gatewayText(s)
              ) : (
                <>
                  {g.target ? <span className="mono">{g.target}</span> : null}
                  {g.target ? ': ' : ''}persi {g.sent - g.received} su {g.sent} ({fmtNum(g.lossPct, 1)} %)
                  {g.medianMs !== undefined ? `, tempo ${fmtNum(g.medianMs, 1)} ms (95° percentile ${fmtNum(g.p95Ms ?? g.medianMs, 1)} ms)` : ''}
                  {g.jitterMs !== undefined ? `, jitter ${fmtNum(g.jitterMs, 1)} ms` : ''}
                </>
              )
            ) : (
              '—'
            )}
          </dd>
        </div>
        {sc && (
          <div className="wide">
            <dt>Scansione dopo la misura</dt>
            <dd>
              {[
                sc.connectedDbm !== undefined ? `rete collegata a ${sc.connectedDbm} dBm` : '',
                sc.utilizationPct !== undefined ? `canale occupato al ${sc.utilizationPct} %${sc.stations !== undefined ? ` con ${sc.stations} dispositivi` : ''} (dichiarato dall'access point)` : '',
              ]
                .filter(Boolean)
                .join(' · ')}
              {(sc.alternatives ?? []).map((a) => (
                <span key={a.bssid} className="wifimap-alt">
                  Altro access point della stessa rete: {bandText(a.band)} canale {a.channel}, {a.rssiDbm} dBm, {ap(a.bssid)}
                </span>
              ))}
              {nb && (
                <span className="wifimap-alt">
                  Reti dei vicini: {nb.visible} visibili, {nb.cochannel} sullo stesso canale
                  {nb.cochannel > 0 ? ` (${nb.strong} ${nb.strong === 1 ? 'forte' : 'forti'}${nb.strongestDbm !== undefined ? `, la più forte a ${nb.strongestDbm} dBm` : ''}${nb.channels?.length ? `; canali ${nb.channels.join(', ')}` : ''})` : ''}
                </span>
              )}
              {sc.stale > 0 && <span className="wifimap-alt faint">{sc.stale} reti sentite più di 10 secondi prima non considerate.</span>}
              {sc.error && <span className="wifimap-alt faint">{sc.error}</span>}
            </dd>
          </div>
        )}
        {s.notes?.length ? (
          <div className="wide">
            <dt>Note</dt>
            <dd>{s.notes.join(' ')}</dd>
          </div>
        ) : null}
      </dl>
      {children}
    </div>
  );
}
