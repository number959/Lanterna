import { AlertTriangle, ArrowLeftRight, Check, ChevronDown, ChevronLeft, ChevronRight, Info, Pause, Play, RotateCcw, Waypoints, X } from 'lucide-react';
import { useReducedMotion } from 'motion/react';
import { memo, useEffect, useId, useMemo, useRef, useState } from 'react';
import type { CSSProperties, KeyboardEvent as ReactKeyboardEvent } from 'react';
import { buildNetworkMap, KIND_LABEL, packetTime, trafficScenarios, trafficSize } from '../engine';
import type { Analysis, DeviceKind, MapNode, NetworkMap, PacketProto, Scan, TrafficPacket, TrafficScenario, TrafficStep } from '../engine';
import { BrandSymbol } from './brand';
import { DeviceArt } from './deviceart';
import { useWidth } from './hooks';
import { IsoDevice, isoTop } from './isoart';
import {
  advance,
  along,
  breachNode,
  briefOf,
  bubbleBox,
  bubbleW,
  CAM_MS,
  CHAR_W,
  clip,
  frameScene,
  groundLines,
  isoScene,
  lanes,
  lerpCamera,
  NARROW_BELOW,
  packetNote,
  progressOf,
  reachOf,
  revealed,
  sceneCamera,
  stageHeight,
  timeline,
  toScreen,
  trailOf,
  typedTarget,
} from './trafficlayout';
import type { Camera, Entry, IsoInfo, IsoScene, Pt } from './trafficlayout';
import './traffic.css';

// "Il traffico passo passo": le scene ricostruite dal motore (traffic.ts) con
// gli indirizzi e i tempi di questa analisi. Vista della rete in prospettiva
// isometrica: all'inizio c'è solo il PC, i dispositivi compaiono quando il
// primo pacchetto va verso di loro e la telecamera allarga l'inquadratura; i
// pacchetti viaggiano sulle corsie (andata e ritorno) con la loro etichetta.
// Poi la vista a sequenza, i dettagli del passo e la tabella dei pacchetti
// come in un analizzatore di rete. Con "riduci movimento" niente si muove:
// la telecamera salta e i pacchetti compaiono già arrivati. Nessun pacchetto
// viene davvero inviato.

/** Colori dei protocolli: chiari, con il testo scuro sopra (contrasto ≥ 7:1). */
export const PROTO_COLOR: Record<PacketProto, string> = {
  DNS: '#7cb0ff',
  DHCP: '#c9adff',
  TCP: '#5fe3a8',
  TLS: '#4fd6ee',
  HTTP: '#ffd166',
  ICMP: '#ffa8bf',
  IPP: '#ffb766',
};

/** Gruppi delle scene, per i filtri sopra l'elenco. */
const CAT_OF: Record<string, 'rete' | 'app' | 'sicurezza'> = { web: 'app', print: 'app', dhcp: 'rete', ping: 'rete', trace: 'rete', services: 'sicurezza' };
const CAT_LABEL = { tutte: 'Tutte', rete: 'Rete', app: 'Applicazioni', sicurezza: 'Sicurezza' } as const;
type Cat = keyof typeof CAT_LABEL;

export function TrafficExplorer({ scan, analysis }: { scan: Scan; analysis: Analysis }) {
  const map = useMemo(() => buildNetworkMap(scan, analysis), [scan, analysis]);
  const scenarios = useMemo(() => trafficScenarios(map, scan), [map, scan]);
  if (!scenarios.length) return <p className="muted">Servono i dati di un'analisi della rete per ricostruire il traffico.</p>;
  return <Explorer map={map} scenarios={scenarios} />;
}

function Explorer({ map, scenarios }: { map: NetworkMap; scenarios: TrafficScenario[] }) {
  const reduce = useReducedMotion();
  const uid = useId();
  const byId = useMemo(() => new Map(map.nodes.map((n) => [n.id, n])), [map]);
  const [sid, setSid] = useState(scenarios[0]?.id ?? '');
  const sc = scenarios.find((s) => s.id === sid) ?? scenarios[0];
  const [view, setView] = useState<'rete' | 'sequenza'>('rete');
  const [speed, setSpeed] = useState(1);
  const [playing, setPlaying] = useState(false);
  const [cur, setCur] = useState({ i: 0, t: 0 });
  const [cat, setCat] = useState<Cat>('tutte');
  const [seen, setSeen] = useState<string[]>([]);
  const [stageRef, stageW] = useWidth<HTMLDivElement>();
  const tableRef = useRef<HTMLDivElement>(null);
  const listRef = useRef<HTMLUListElement>(null);

  const entries = useMemo<Entry[]>(() => (sc ? timeline(sc) : []), [sc]);
  const w = Math.max(300, Math.floor(stageW) || 0);
  const narrow = w < NARROW_BELOW;
  const scene = useMemo(() => (sc ? isoScene(sc, (id) => byId.has(id), entries, narrow) : undefined), [sc, byId, entries, narrow]);
  const h = scene ? stageHeight(scene, w) : 300;

  // Riproduzione: un fotogramma alla volta. La posizione corrente sta anche in
  // un riferimento, così il ciclo non riparte a ogni render.
  const live = useRef({ entries, speed, cur });
  live.current = { entries, speed, cur };
  useEffect(() => {
    if (!playing) return;
    let raf = 0;
    let last = performance.now();
    const tick = (now: number) => {
      const dt = Math.min(100, now - last);
      last = now;
      const { entries: es, speed: sp, cur: c } = live.current;
      const r = advance(es, c, dt, sp);
      live.current.cur = r.cur;
      setCur(r.cur);
      if (r.done) setPlaying(false);
      else raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [playing]);

  // Una nuova analisi riparte dall'inizio della scena.
  useEffect(() => {
    setCur({ i: 0, t: 0 });
    setPlaying(false);
  }, [scenarios]);

  const entry = entries[Math.min(cur.i, entries.length - 1)];
  const stepIdx = entry?.si ?? 0;
  const pkt = entry?.p;
  const packets = useMemo(() => (sc ? sc.steps.flatMap((s) => s.packets) : []), [sc]);
  const before = sc ? sc.steps.slice(0, stepIdx).reduce((n, s) => n + s.packets.length, 0) : 0;
  const sentUpTo = pkt ? pkt.no : before;

  // La riga del pacchetto in corso resta visibile nella tabella, senza muovere la pagina.
  useEffect(() => {
    const wrap = tableRef.current;
    const row = wrap?.querySelector<HTMLTableRowElement>('tr.cur');
    if (!wrap || !row) return;
    const bottom = row.offsetTop + row.offsetHeight;
    if (bottom > wrap.scrollTop + wrap.clientHeight) wrap.scrollTop = bottom - wrap.clientHeight;
    else if (row.offsetTop < wrap.scrollTop + 30) wrap.scrollTop = Math.max(0, row.offsetTop - 30);
  }, [sentUpTo]);

  // Anche il passo in corso resta visibile nell'elenco, che scorre da solo.
  useEffect(() => {
    const list = listRef.current;
    const btn = list?.querySelector<HTMLElement>('.tx-step.on');
    if (!list || !btn || list.scrollHeight <= list.clientHeight) return;
    const top = btn.getBoundingClientRect().top - list.getBoundingClientRect().top + list.scrollTop;
    if (top + btn.offsetHeight > list.scrollTop + list.clientHeight) list.scrollTop = top + btn.offsetHeight - list.clientHeight + 4;
    else if (top < list.scrollTop) list.scrollTop = Math.max(0, top - 4);
  }, [stepIdx, sid]);

  const ended = cur.i >= entries.length - 1 && cur.t >= 1;
  // Le scene viste fino in fondo, per l'avanzamento in alto.
  useEffect(() => {
    if (ended && sc && seen.indexOf(sc.id) < 0) setSeen((v) => [...v, sc.id]);
  }, [ended, sc, seen]);

  if (!sc || !scene) return <p className="muted">Servono i dati di un'analisi della rete per ricostruire il traffico.</p>;

  const step = sc.steps[stepIdx];
  const prog = reduce ? (pkt ? 1 : 0) : progressOf(entry, cur.t);
  const started = cur.i > 0 || cur.t > 0;
  const node = (id: string) => byId.get(id);
  // All'inizio della scena del browser l'indirizzo del sito si scrive nel fumetto sopra il PC.
  const site = stepIdx === 0 ? typedTarget(sc) : undefined;
  const typed = reduce || cur.i > 0 || (!playing && cur.t === 0) ? 1 : Math.min(1, cur.t * 1.6);

  const pick = (id: string) => {
    setSid(id);
    setCur({ i: 0, t: 0 });
    setPlaying(false);
  };
  const goStep = (si: number) => {
    const i = entries.findIndex((e) => e.si === si);
    if (i >= 0) setCur({ i, t: 0 });
  };
  const toggle = () => {
    if (ended) {
      setCur({ i: 0, t: 0 });
      setPlaying(true);
    } else setPlaying((p) => !p);
  };
  const onKey = (e: ReactKeyboardEvent) => {
    if ((e.target as HTMLElement).tagName === 'SELECT' || e.altKey || e.ctrlKey || e.metaKey) return;
    if (e.key === 'ArrowRight' && stepIdx < sc.steps.length - 1) {
      e.preventDefault();
      goStep(stepIdx + 1);
    } else if (e.key === 'ArrowLeft' && stepIdx > 0) {
      e.preventDefault();
      goStep(stepIdx - 1);
    }
  };
  const endNode = pkt ? node(pkt.hops[reachOf(pkt)]) : undefined;
  const note = pkt ? packetNote(pkt) : undefined;
  const nameOf = (n: MapNode | undefined, fallback: string) => (n ? (n.self ? 'Questo PC' : n.label) : fallback);

  return (
    <div className="tx">
      <p className="sr-only" aria-live="polite" aria-atomic="true">
        {`${sc.title}, passo ${stepIdx + 1} di ${sc.steps.length}: ${step.title}`}
      </p>
      <div className="tx-top">
        <div className="tx-brand">
          <BrandSymbol size={26} />
          <span>
            <b>Polaris</b>
            <span>traffico passo passo</span>
          </span>
        </div>
        <div className="tx-now">
          <span className="tx-h">In corso</span>
          <b>{sc.title}</b>
          <span>
            Passo {stepIdx + 1}/{sc.steps.length} · {step.title}
          </span>
        </div>
        <div className="tx-prog">
          <span className="tx-prog-h">
            <span className="tx-h">Scene viste</span>
            <b>
              {seen.length}/{scenarios.length}
            </b>
          </span>
          <span className="tx-bar" aria-hidden>
            <i style={{ width: `${(100 * seen.length) / scenarios.length}%` }} />
          </span>
        </div>
      </div>
      <div className="tx-grid">
        {/* Scene e passi */}
        <div className="tx-side">
          <div className="tx-h" id={`${uid}-scenes`}>
            Scene
          </div>
          <div className="tx-cats" role="group" aria-label="Tipo di scena">
            {(['tutte', 'rete', 'app', 'sicurezza'] as const).map((c) => {
              const n = c === 'tutte' ? scenarios.length : scenarios.filter((x) => CAT_OF[x.id] === c).length;
              if (!n) return null;
              return (
                <button type="button" key={c} aria-pressed={cat === c} className={cat === c ? 'on' : ''} onClick={() => setCat(c)}>
                  {CAT_LABEL[c]} <b>{n}</b>
                </button>
              );
            })}
          </div>
          <ul className="tx-scenes" ref={listRef} aria-labelledby={`${uid}-scenes`}>
            {scenarios
              .filter((x) => cat === 'tutte' || CAT_OF[x.id] === cat)
              .map((s) => {
                const on = s.id === sc.id;
                const done = seen.indexOf(s.id) >= 0;
                return (
                  <li key={s.id}>
                    <button type="button" className={`tx-scene${on ? ' on' : ''}`} aria-expanded={on} aria-current={on ? 'true' : undefined} onClick={() => pick(s.id)}>
                      <span className={`tx-sdot${done ? ' done' : on ? ' cur' : ''}`} aria-hidden />
                      <span className="tx-scene-txt">
                        <span className="tx-scene-t">{s.title}</span>
                        <span className="tx-scene-s">{s.subtitle}</span>
                      </span>
                      {on ? <ChevronDown size={15} aria-hidden /> : <ChevronRight size={15} aria-hidden />}
                    </button>
                    {on && (
                      <ol className="tx-steps" aria-label={`Passi di «${s.title}»`}>
                        {s.steps.map((st, i) => {
                          const sdone = i < stepIdx || (ended && i === stepIdx);
                          return (
                            <li key={st.id}>
                              <button type="button" className={`tx-step${i === stepIdx ? ' on' : ''}`} onClick={() => goStep(i)} aria-current={i === stepIdx ? 'step' : undefined}>
                                <span className={`tx-dot${sdone ? ' done' : i === stepIdx ? ' cur' : ''}`} aria-hidden>
                                  {sdone ? <Check size={11} strokeWidth={3} /> : i + 1}
                                </span>
                                <span className="tx-step-txt">
                                  <span className="tx-step-t">{st.title}</span>
                                  <span className="tx-step-s">{st.subtitle}</span>
                                </span>
                              </button>
                            </li>
                          );
                        })}
                      </ol>
                    )}
                  </li>
                );
              })}
          </ul>
        </div>

        {/* Palco */}
        <div className="tx-stage" onKeyDown={onKey}>
          <div className="tx-stage-h">
            <div className="tx-views" role="group" aria-label="Vista">
              <button type="button" aria-pressed={view === 'rete'} className={view === 'rete' ? 'on' : ''} onClick={() => setView('rete')}>
                <Waypoints size={13} aria-hidden /> Rete
              </button>
              <button type="button" aria-pressed={view === 'sequenza'} className={view === 'sequenza' ? 'on' : ''} onClick={() => setView('sequenza')}>
                <ArrowLeftRight size={13} aria-hidden /> Sequenza
              </button>
            </div>
            <span className="tx-clock mono" aria-hidden>
              {pkt ? `${packetTime(pkt.t)} · ${pkt.no}/${packets.length}` : `${sentUpTo}/${packets.length}`}
            </span>
          </div>
          <div className={`tx-canvas${view === 'rete' ? ' iso' : ''}`} ref={stageRef}>
            {view === 'rete' ? (
              <IsoView sc={sc} scene={scene} node={node} entries={entries} at={Math.min(cur.i, entries.length - 1)} pkt={pkt} prog={prog} w={w} h={h} site={site} typed={typed} reduce={!!reduce} />
            ) : (
              <SequenceView step={step} pkt={pkt} prog={prog} node={node} width={w} />
            )}
          </div>
          <div className="tx-controls">
            <label className="tx-speed">
              <span className="sr-only">Velocità</span>
              <select value={speed} onChange={(e) => setSpeed(Number(e.target.value))}>
                <option value={0.5}>0,5×</option>
                <option value={1}>1×</option>
                <option value={2}>2×</option>
              </select>
            </label>
            <button type="button" className="tx-btn" onClick={() => stepIdx > 0 && goStep(stepIdx - 1)} aria-disabled={stepIdx === 0} aria-label="Passo precedente">
              <ChevronLeft size={17} aria-hidden />
            </button>
            <button type="button" className="tx-btn primary" onClick={toggle}>
              {playing ? <Pause size={15} aria-hidden /> : ended ? <RotateCcw size={15} aria-hidden /> : <Play size={15} aria-hidden />}
              {playing ? 'Pausa' : ended ? 'Di nuovo' : started ? 'Riprendi' : 'Riproduci'}
            </button>
            <button type="button" className="tx-btn" onClick={() => stepIdx < sc.steps.length - 1 && goStep(stepIdx + 1)} aria-disabled={stepIdx >= sc.steps.length - 1} aria-label="Passo successivo">
              <ChevronRight size={17} aria-hidden />
            </button>
            <button
              type="button"
              className="tx-btn"
              onClick={() => {
                setCur({ i: 0, t: 0 });
                setPlaying(false);
              }}
              aria-disabled={!started}
              aria-label="Ricomincia dall'inizio"
            >
              <RotateCcw size={15} aria-hidden />
            </button>
            <span className="tx-keys" aria-hidden>
              ← → passi
            </span>
          </div>
        </div>

        {/* Dettagli del passo */}
        <div className="tx-detail">
          <div className="tx-h">
            Passo {stepIdx + 1} di {sc.steps.length}
          </div>
          <h3 className="tx-title">{step.title}</h3>
          <p className="tx-sub">{step.subtitle}</p>
          <p className="tx-text">{step.detail}</p>
          {pkt && (
            <div className="tx-pkt" style={{ borderColor: PROTO_COLOR[pkt.proto] }}>
              <div className="tx-pkt-h">
                <span className="tx-chip" style={{ background: PROTO_COLOR[pkt.proto] }}>
                  {pkt.label}
                </span>
                <span className="tx-pkt-dir">
                  {clip(nameOf(node(pkt.hops[0]), pkt.src), 18)} → {clip(nameOf(endNode, pkt.dst), 18)}
                </span>
              </div>
              <div className="tx-pkt-info mono">{pkt.info}</div>
              <div className="tx-pkt-meta">
                Pacchetto {pkt.no} di {packets.length} · {pkt.proto} · {trafficSize(pkt.size)}
                {note && (
                  <span className={`tx-stop ${note.sev}`}>
                    {pkt.stopAt !== undefined ? <X size={12} strokeWidth={3} aria-hidden /> : <AlertTriangle size={12} strokeWidth={2.6} aria-hidden />} {note.text}
                  </span>
                )}
              </div>
            </div>
          )}
          {step.fields.length > 0 && (
            <dl className="tx-fields">
              {step.fields.map((f) => (
                <div key={f.k}>
                  <dt>{f.k}</dt>
                  <dd>{f.v}</dd>
                </div>
              ))}
            </dl>
          )}
        </div>

        {/* Pacchetti */}
        <div className="tx-table">
          <div className="tx-table-h">
            <span className="tx-h">Pacchetti</span>
            <span className="tx-legend">
              {[...new Set(packets.map((p) => p.proto))].map((pr) => (
                <span key={pr}>
                  <i style={{ background: PROTO_COLOR[pr] }} aria-hidden /> {pr}
                </span>
              ))}
            </span>
          </div>
          <div className="tx-table-wrap" ref={tableRef} tabIndex={0} role="region" aria-label="Pacchetti della scena">
            <table>
              <caption className="sr-only">Pacchetti di «{sc.title}» fino al passo in corso</caption>
              <thead>
                <tr>
                  <th scope="col">N.</th>
                  <th scope="col">Tempo</th>
                  <th scope="col">Origine</th>
                  <th scope="col">Destinazione</th>
                  <th scope="col">Protocollo</th>
                  <th scope="col">Informazioni</th>
                  <th scope="col">Dim.</th>
                </tr>
              </thead>
              <tbody>
                {packets
                  .filter((p) => p.no <= sentUpTo)
                  .map((p) => (
                    <tr key={p.no} className={p === pkt ? 'cur' : undefined} aria-current={p === pkt ? 'true' : undefined}>
                      <td>
                        <span className="tx-num" style={{ background: PROTO_COLOR[p.proto] }}>
                          {p.no}
                        </span>
                      </td>
                      <td className="mono">{packetTime(p.t)}</td>
                      <td className="mono">{p.src}</td>
                      <td className="mono">{p.dst}</td>
                      <td>{p.proto}</td>
                      <td className="tx-info">
                        {p.info}
                        {packetNote(p) && (
                          <>
                            {' · '}
                            <span className={`tx-stop ${packetNote(p)!.sev}`}>{packetNote(p)!.text}</span>
                          </>
                        )}
                      </td>
                      <td className="mono">{trafficSize(p.size)}</td>
                    </tr>
                  ))}
                {sentUpTo === 0 && (
                  <tr>
                    <td colSpan={7} className="tx-empty">
                      I pacchetti compaiono qui man mano che la scena va avanti.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
      <p className="tx-note">
        <Info size={14} aria-hidden />
        <span>
          Ricostruzione didattica: indirizzi e tempi vengono da questa analisi (router, DNS, Internet, verifiche); i pacchetti sono quelli che il protocollo
          prevede, con le dimensioni tipiche. Polaris non registra il traffico del PC e per questa scena non invia nulla.
        </span>
      </p>
    </div>
  );
}

/** Seconda riga dell'etichetta: l'indirizzo, oppure il tipo se dice qualcosa di più del nome. */
function subOf(n: MapNode): string {
  if (n.ip) return n.ip;
  return KIND_LABEL[n.kind] !== n.label ? KIND_LABEL[n.kind] : '';
}

const pairKey = (a: string, b: string) => (a < b ? `${a}|${b}` : `${b}|${a}`);
const pathD = (pts: Pt[]) => pts.map((p, i) => `${i ? 'L' : 'M'}${p.x.toFixed(1)} ${p.y.toFixed(1)}`).join(' ');

/** Il disegno non cambia mentre la telecamera si muove: si ridisegna solo se cambia il tipo. */
const IsoGlyph = memo(function IsoGlyph({ kind }: { kind: DeviceKind }) {
  return <IsoDevice kind={kind} />;
});

/**
 * La telecamera va verso l'inquadratura voluta in CAM_MS, con partenza e
 * arrivo morbidi; se l'inquadratura cambia a metà riparte da dove si trova.
 * Con "riduci movimento", e quando cambia la scena, salta subito.
 */
function useCamera(target: Camera, w: number, h: number, reduce: boolean, reset: string): Camera {
  const [cam, setCam] = useState(target);
  const now = useRef(target);
  const last = useRef(reset);
  const stale = last.current !== reset;
  useEffect(() => {
    const from = now.current;
    const jump = reduce || last.current !== reset;
    last.current = reset;
    if (jump || (Math.abs(from.k - target.k) < 1e-3 && Math.hypot(from.x - target.x, from.y - target.y) < 0.5)) {
      now.current = target;
      setCam(target);
      return;
    }
    const t0 = performance.now();
    let raf = 0;
    const tick = (t: number) => {
      const f = Math.min(1, (t - t0) / CAM_MS);
      const c = lerpCamera(from, target, w, h, f);
      now.current = c;
      setCam(c);
      if (f < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target, w, h, reduce, reset]);
  return reduce || stale ? target : cam;
}

function IsoView({
  sc,
  scene,
  node,
  entries,
  at,
  pkt,
  prog,
  w,
  h,
  site,
  typed,
  reduce,
}: {
  sc: TrafficScenario;
  scene: IsoScene;
  node: (id: string) => MapNode | undefined;
  entries: Entry[];
  at: number;
  pkt?: TrafficPacket;
  prog: number;
  w: number;
  h: number;
  site?: string;
  typed: number;
  reduce: boolean;
}) {
  const end = pkt ? reachOf(pkt) : -1;
  const hopAt = pkt ? prog * Math.max(1, end) : 0;
  // In scena: i nodi già raggiunti e quelli verso cui va il pacchetto in corso, nell'ordine della disposizione.
  const ids = [...scene.places.keys()].filter((id) => node(id) && revealed(scene, id, at, hopAt));
  const info = (id: string): IsoInfo => {
    const n = node(id)!;
    return { name: n.self ? 'Questo PC' : n.label, sub: subOf(n), top: isoTop(n.kind) };
  };
  const bubble = site && scene.root && ids.indexOf(scene.root) >= 0 ? { id: scene.root, text: site } : undefined;
  const key = `${ids.join(',')}|${bubble ? bubble.text : ''}`;
  // L'inquadratura cambia solo quando compare (o sparisce) qualcosa.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const target = useMemo(() => sceneCamera(scene, ids, info, w, h, bubble), [scene, key, w, h]);
  const cam = useCamera(target, w, h, reduce, sc.id);
  const placed = frameScene(scene, ids, info, cam);
  const s = cam.k * 0.95;

  // Collegamenti: le coppie di nodi vicini nei pacchetti fin qui, orientate dal nodo più vicino al PC.
  const pairs = new Map<string, [string, string]>();
  for (const e of entries.slice(0, at + 1)) {
    const p = e.p;
    if (!p) continue;
    for (let i = 1; i < p.hops.length; i++) {
      const a = p.hops[i - 1];
      const b = p.hops[i];
      if (a === b || !placed.has(a) || !placed.has(b)) continue;
      const k = pairKey(a, b);
      if (!pairs.has(k)) pairs.set(k, scene.parent.get(a) === b ? [b, a] : [a, b]);
    }
  }
  const off = Math.max(3, 5.5 * cam.k);
  const shrink = 36 * s + 4;
  const lift = (p: Pt): Pt => ({ x: p.x, y: p.y - 3 * s });
  const geo = new Map<string, { a: string; b: string; out: Pt[]; back: Pt[] }>();
  for (const [k, [a, b]] of pairs) {
    const mid = (scene.via.get(`${a}>${b}`) ?? []).map((q) => lift(toScreen(cam, q)));
    geo.set(k, { a, b, ...lanes([lift(placed.get(a)!.p), ...mid, lift(placed.get(b)!.p)], off, shrink, shrink) });
  }
  /** La corsia per andare da a a b. */
  const laneFor = (a: string, b: string): Pt[] | undefined => {
    const g = geo.get(pairKey(a, b));
    return g ? (g.a === a ? g.out : g.back) : undefined;
  };

  // Tratti già percorsi (o in corso) dal pacchetto e nodi già raggiunti.
  const active = new Set<string>();
  const reached = new Set<string>();
  const routes: Pt[][] = [];
  if (pkt) {
    reached.add(pkt.hops[0]);
    for (let i = 1; i <= end; i++) {
      const r = laneFor(pkt.hops[i - 1], pkt.hops[i]);
      if (r) routes.push(r);
      if (hopAt > i - 1 || (i === 1 && hopAt >= 0)) active.add(`${pkt.hops[i - 1]}>${pkt.hops[i]}`);
      if (hopAt >= i - 1e-6) reached.add(pkt.hops[i]);
    }
  }
  const color = pkt ? PROTO_COLOR[pkt.proto] : undefined;
  const showPacket = !!pkt && end > 0 && routes.length === end;
  const names = sc.lanes
    .map((l) => node(l))
    .filter((n): n is MapNode => !!n)
    .map((n) => (n.self ? 'questo PC' : n.label));
  const byDepth = [...placed.entries()].sort((x, y) => x[1].p.y - y[1].p.y);
  const arrow = (pts: Pt[], cls: string, style?: CSSProperties) => {
    const p0 = pts[pts.length - 2];
    const p1 = pts[pts.length - 1];
    const len = Math.hypot(p1.x - p0.x, p1.y - p0.y) || 1;
    const ux = (p1.x - p0.x) / len;
    const uy = (p1.y - p0.y) / len;
    const a = 7;
    return (
      <path
        d={`M${p1.x.toFixed(1)} ${p1.y.toFixed(1)} L${(p1.x - ux * a - uy * a * 0.55).toFixed(1)} ${(p1.y - uy * a + ux * a * 0.55).toFixed(1)} L${(p1.x - ux * a + uy * a * 0.55).toFixed(1)} ${(p1.y - uy * a - ux * a * 0.55).toFixed(1)} Z`}
        className={cls}
        style={style}
      />
    );
  };

  return (
    <svg className="tx-svg" viewBox={`0 0 ${w} ${h}`} width={w} height={h} role="img" aria-label={`Rete della scena «${sc.title}»: ${names.join(', ')}`}>
      <g className="tx-ground" aria-hidden>
        {groundLines(cam, w, h).map(([a, b], i) => (
          <line key={i} x1={a.x.toFixed(1)} y1={a.y.toFixed(1)} x2={b.x.toFixed(1)} y2={b.y.toFixed(1)} />
        ))}
      </g>
      {[...geo.entries()].map(([k, g]) => {
        const onOut = active.has(`${g.a}>${g.b}`);
        const onBack = active.has(`${g.b}>${g.a}`);
        const line = (on: boolean) => (on ? { stroke: color } : undefined);
        const head = (on: boolean) => (on ? { fill: color } : undefined);
        return (
          <g key={k} className="tx-lanes">
            <path d={pathD(g.out)} className={`tx-lane${onOut ? ' on' : ''}`} style={line(onOut)} />
            {arrow(g.out, `tx-arrow${onOut ? ' on' : ''}`, head(onOut))}
            <path d={pathD(g.back)} className={`tx-lane${onBack ? ' on' : ''}`} style={line(onBack)} />
            {arrow(g.back, `tx-arrow${onBack ? ' on' : ''}`, head(onBack))}
          </g>
        );
      })}
      {byDepth.map(([id, pl]) => {
        const n = node(id)!;
        const nf = info(id);
        const L = pl.label;
        const anchor = pl.side === 'left' ? 'end' : pl.side === 'right' ? 'start' : 'middle';
        const tx = (pl.side === 'left' ? L.x1 : pl.side === 'right' ? L.x0 : pl.p.x) - pl.p.x;
        const ty = L.y0 - pl.p.y;
        const sub = clip(nf.sub, pl.chars);
        return (
          <g key={id} transform={`translate(${pl.p.x.toFixed(1)} ${pl.p.y.toFixed(1)})`} className={`tx-node${reached.has(id) ? ' on' : ''}${n.self ? ' self' : ''}`}>
            <g className="tx-in">
              <g className="tx-glyph" transform={`scale(${pl.s.toFixed(3)})`}>
                <IsoGlyph kind={n.kind} />
              </g>
              <text x={tx} y={ty + 11} textAnchor={anchor} className="tx-node-name">
                {clip(nf.name, pl.chars)}
              </text>
              {sub && (
                <text x={tx} y={ty + 25} textAnchor={anchor} className="tx-node-ip">
                  {sub}
                </text>
              )}
            </g>
          </g>
        );
      })}
      {bubble && placed.get(bubble.id) && <TypingBubble p={placed.get(bubble.id)!.p} s={s} top={info(bubble.id).top} text={bubble.text} typed={typed} />}
      {showPacket && pkt && <PacketMark pkt={pkt} routes={routes} prog={prog} w={w} placed={placed} />}
    </svg>
  );
}

/** Il fumetto sopra il PC, con il globo e l'indirizzo che si scrive lettera per lettera. */
function TypingBubble({ p, s, top, text, typed }: { p: Pt; s: number; top: number; text: string; typed: number }) {
  const b = bubbleBox(p, s, top, text);
  const shown = text.slice(0, Math.ceil(text.length * typed));
  const gx = b.x0 + 14;
  const gy = (b.y0 + b.y1) / 2;
  return (
    <g className="tx-bubble" aria-hidden>
      <line x1={b.x0 + bubbleW(text) / 2 + 18} y1={b.y1} x2={p.x} y2={b.y1 + 9} className="tx-bubble-l" />
      <rect x={b.x0} y={b.y0} width={b.x1 - b.x0} height={b.y1 - b.y0} rx={3} className="tx-bubble-r" />
      <circle cx={gx} cy={gy} r={5.5} className="tx-bubble-g" />
      <path d={`M${gx - 5.5} ${gy} H${gx + 5.5} M${gx} ${gy - 5.5} Q${gx - 3.5} ${gy} ${gx} ${gy + 5.5} Q${gx + 3.5} ${gy} ${gx} ${gy - 5.5}`} className="tx-bubble-g" />
      <text x={b.x0 + 26} y={b.y0 + 16} className="tx-bubble-t">
        {shown}
        {typed < 1 && <tspan className="tx-caret">▌</tspan>}
      </text>
    </g>
  );
}

function PacketMark({ pkt, routes, prog, w, placed }: { pkt: TrafficPacket; routes: Pt[][]; prog: number; w: number; placed: Map<string, { p: Pt; s: number }> }) {
  const end = reachOf(pkt);
  const p = along(routes, prog);
  const trail = trailOf(routes, prog);
  const color = PROTO_COLOR[pkt.proto];
  // Etichetta del protocollo e, sotto, la riga breve del pacchetto ("A? www.esempio.it").
  const brief = briefOf(pkt);
  const lw = pkt.label.length * 7.2 + 14;
  const bw = brief.length * 6.4 + 14;
  const cw = Math.max(lw, bw);
  const mark = (id: string) => {
    const q = placed.get(id);
    return q ? { x: q.p.x - 34 * q.s - 6, y: q.p.y - 14 * q.s } : undefined;
  };
  const stopAt = prog >= 1 && pkt.stopAt !== undefined ? mark(pkt.hops[end]) : undefined;
  // Passato da una zona che doveva essere isolata: un segnale rosso sul dispositivo isolato.
  const alarm = prog >= 1 && pkt.breach ? mark(breachNode(pkt)) : undefined;
  const cx = Math.min(w - cw - 6, Math.max(6, p.x - lw / 2));
  const cy = Math.max(4, p.y - 58);
  const sev = pkt.sev ?? 'warn';
  return (
    <g className="tx-packet" pointerEvents="none">
      {trail.length > 1 && <path d={pathD(trail)} className="tx-trail" style={{ stroke: color }} />}
      {stopAt && (
        <g className={`tx-x ${sev}`} transform={`translate(${stopAt.x.toFixed(1)} ${stopAt.y.toFixed(1)})`}>
          <circle r="11" />
          <path d="M-4.5 -4.5 L4.5 4.5 M4.5 -4.5 L-4.5 4.5" />
        </g>
      )}
      {alarm && (
        <g className="tx-x crit" transform={`translate(${alarm.x.toFixed(1)} ${alarm.y.toFixed(1)})`}>
          <circle r="11" />
          <path d="M0 -5.5 V1.5 M0 5 V5.2" />
        </g>
      )}
      <circle cx={p.x} cy={p.y} r={10} fill={color} opacity={0.2} />
      <circle cx={p.x} cy={p.y} r={4.8} fill={color} />
      <line x1={p.x} y1={p.y - 6} x2={p.x} y2={cy + 37} className="tx-chip-l" style={{ stroke: color }} />
      <g transform={`translate(${cx.toFixed(1)} ${cy.toFixed(1)})`}>
        <rect width={lw} height={18} rx={3} fill={color} />
        <text x={lw / 2} y={12.8} textAnchor="middle" className="tx-chip-t">
          {pkt.label}
        </text>
        <rect y={20} width={bw} height={17} rx={3} className="tx-chip-b" style={{ stroke: color }} />
        <text x={7} y={32} className="tx-chip-i">
          {brief}
        </text>
      </g>
    </g>
  );
}

function SequenceView({ step, pkt, prog, node, width }: { step: TrafficStep; pkt?: TrafficPacket; prog: number; node: (id: string) => MapNode | undefined; width: number }) {
  const lanes: string[] = [];
  for (const p of step.packets) for (const hp of p.hops) if (lanes.indexOf(hp) < 0 && node(hp)) lanes.push(hp);
  const w = Math.max(300, width);
  const n = lanes.length;
  if (!n) {
    return (
      <svg className="tx-svg" viewBox={`0 0 ${w} 250`} width={w} height={250} role="img" aria-label={`Passo «${step.title}»: nessun pacchetto`}>
        <text x={w / 2} y={125} textAnchor="middle" className="tx-seq-empty">
          {w < 540 ? 'Nessun pacchetto in questo passo.' : 'In questo passo non partono pacchetti: leggi i dettagli a fianco.'}
        </text>
      </svg>
    );
  }
  const mx = w < 540 ? 46 : 84;
  const gap = n > 1 ? (w - 2 * mx) / (n - 1) : w;
  const x = (id: string) => (n === 1 ? w / 2 : mx + lanes.indexOf(id) * gap);
  const chars = Math.max(5, Math.floor((gap - 10) / CHAR_W));
  const ROW = 52;
  const TOP = 112;
  const h = Math.max(250, TOP + step.packets.length * ROW + 10);
  const curIdx = pkt ? step.packets.indexOf(pkt) : -1;
  return (
    <svg className="tx-svg" viewBox={`0 0 ${w} ${h}`} width={w} height={h} role="img" aria-label={`Sequenza del passo «${step.title}»`}>
      {lanes.map((id) => {
        const nd = node(id)!;
        return (
          <g key={id} className={`tx-node${nd.self ? ' self' : ''}`}>
            <g className="tx-glyph">
              <DeviceArt kind={nd.kind} x={x(id)} y={34} scale={0.52} />
            </g>
            <text x={x(id)} y={70} textAnchor="middle" className="tx-node-name">
              {clip(nd.self ? 'Questo PC' : nd.label, chars)}
            </text>
            <line x1={x(id)} x2={x(id)} y1={82} y2={h - 8} className="tx-life" />
          </g>
        );
      })}
      {step.packets.map((p, k) => {
        if (curIdx < 0 || k > curIdx) return null;
        const end = reachOf(p);
        const a = x(p.hops[0]);
        const b = x(p.hops[end]);
        const y = TOP + k * ROW;
        const frac = k === curIdx ? prog : 1;
        const color = PROTO_COLOR[p.proto];
        const room = Math.floor((Math.abs(b - a) - 16) / CHAR_W);
        const info = room - p.label.length - 2 > 8 ? clip(p.info, room - p.label.length - 2) : '';
        return (
          <g key={p.no}>
            <line x1={a} y1={y} x2={a + (b - a) * frac} y2={y + 12 * frac} stroke={color} strokeWidth={2.2} strokeLinecap="round" />
            {p.hops.slice(1, end).map((hp) => {
              const f = b === a ? 0 : (x(hp) - a) / (b - a);
              return f <= frac ? <circle key={hp} cx={x(hp)} cy={y + 12 * f} r={3.2} fill={color} /> : null;
            })}
            {frac >= 1 && p.stopAt === undefined && <path d={`M${b} ${y + 12} l${b >= a ? -9 : 9} -4.5 l0 9 z`} fill={color} />}
            {frac >= 1 && p.breach && (
              <g className="tx-x crit" transform={`translate(${x(breachNode(p)) + (p.dir === 'response' ? (b >= a ? 18 : -18) : b >= a ? -22 : 22)} ${p.dir === 'response' ? y + 4 : y + 12})`}>
                <circle r="8" />
                <path d="M0 -4 V1 M0 3.8 V4" />
              </g>
            )}
            {frac >= 1 && p.stopAt !== undefined && (
              <g className={`tx-x ${p.sev ?? 'warn'}`} transform={`translate(${b} ${y + 12})`}>
                <circle r="9" />
                <path d="M-3.6 -3.6 L3.6 3.6 M3.6 -3.6 L-3.6 3.6" />
              </g>
            )}
            <text x={(a + b) / 2} y={y - 8} textAnchor="middle" className="tx-seq-l">
              <tspan fill={color} className="tx-seq-b">
                {p.label}
              </tspan>
              {info && <tspan dx={7}>{info}</tspan>}
            </text>
          </g>
        );
      })}
    </svg>
  );
}
