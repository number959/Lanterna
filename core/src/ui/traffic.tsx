import { AlertTriangle, ArrowLeftRight, Check, ChevronLeft, ChevronRight, Info, Pause, Play, RotateCcw, Waypoints, X } from 'lucide-react';
import { useReducedMotion } from 'motion/react';
import { useEffect, useId, useMemo, useRef, useState } from 'react';
import type { KeyboardEvent as ReactKeyboardEvent } from 'react';
import { buildNetworkMap, KIND_LABEL, packetTime, trafficScenarios, trafficSize } from '../engine';
import type { Analysis, MapNode, NetworkMap, PacketProto, Scan, TrafficPacket, TrafficScenario, TrafficStep } from '../engine';
import { DeviceArt } from './deviceart';
import { useWidth } from './hooks';
import { advance, along, CHAR_W, clip, packetNote, progressOf, reachOf, route, stageLayout, timeline } from './trafficlayout';
import type { Entry, Pt, StageLayout } from './trafficlayout';
import './traffic.css';

// "Il traffico passo passo": le scene ricostruite dal motore (traffic.ts) con
// gli indirizzi e i tempi di questa analisi. Vista della rete con i
// dispositivi disegnati a linee e i pacchetti che viaggiano con la loro
// etichetta, vista a sequenza, dettagli del passo e tabella dei pacchetti come
// in un analizzatore di rete. Con "riduci movimento" i pacchetti non si
// muovono: compaiono già arrivati. Nessun pacchetto viene davvero inviato.

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
  const [stageRef, stageW] = useWidth<HTMLDivElement>();
  const tableRef = useRef<HTMLDivElement>(null);
  const stepsRef = useRef<HTMLOListElement>(null);

  const entries = useMemo<Entry[]>(() => (sc ? timeline(sc) : []), [sc]);
  const layout = useMemo(() => (sc ? stageLayout(sc, (id) => byId.has(id), stageW) : undefined), [sc, byId, stageW]);

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

  // Anche il passo in corso resta visibile nell'elenco dei passi, che scorre da solo.
  useEffect(() => {
    const list = stepsRef.current;
    const btn = list?.querySelector<HTMLElement>('.tx-step.on');
    if (!list || !btn || list.scrollHeight <= list.clientHeight) return;
    const top = btn.getBoundingClientRect().top - list.getBoundingClientRect().top + list.scrollTop;
    if (top + btn.offsetHeight > list.scrollTop + list.clientHeight) list.scrollTop = top + btn.offsetHeight - list.clientHeight + 4;
    else if (top < list.scrollTop) list.scrollTop = Math.max(0, top - 4);
  }, [stepIdx, sid]);

  if (!sc || !layout) return <p className="muted">Servono i dati di un'analisi della rete per ricostruire il traffico.</p>;

  const step = sc.steps[stepIdx];
  const prog = reduce ? (pkt ? 1 : 0) : progressOf(entry, cur.t);
  const ended = cur.i >= entries.length - 1 && cur.t >= 1;
  const started = cur.i > 0 || cur.t > 0;
  const node = (id: string) => byId.get(id);

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
      <div className="tx-grid">
        {/* Scene e passi */}
        <div className="tx-side">
          <div className="tx-h" id={`${uid}-scenes`}>
            Scene
          </div>
          <ul className="tx-scenes" aria-labelledby={`${uid}-scenes`}>
            {scenarios.map((s) => (
              <li key={s.id}>
                <button type="button" className={`tx-scene${s.id === sc.id ? ' on' : ''}`} aria-pressed={s.id === sc.id} onClick={() => pick(s.id)}>
                  <span className="tx-scene-t">{s.title}</span>
                  <span className="tx-scene-s">{s.subtitle}</span>
                </button>
              </li>
            ))}
          </ul>
          <div className="tx-h tx-steps-h" id={`${uid}-steps`}>
            Passi
          </div>
          <ol className="tx-steps" ref={stepsRef} aria-labelledby={`${uid}-steps`}>
            {sc.steps.map((st, i) => {
              const done = i < stepIdx || (ended && i === stepIdx);
              return (
                <li key={st.id}>
                  <button type="button" className={`tx-step${i === stepIdx ? ' on' : ''}`} onClick={() => goStep(i)} aria-current={i === stepIdx ? 'step' : undefined}>
                    <span className={`tx-dot${done ? ' done' : i === stepIdx ? ' cur' : ''}`} aria-hidden>
                      {done ? <Check size={11} strokeWidth={3} /> : i + 1}
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
          <div className="tx-canvas" ref={stageRef}>
            {view === 'rete' ? (
              <NetworkView sc={sc} layout={layout} node={node} pkt={pkt} prog={prog} packets={packets} />
            ) : (
              <SequenceView step={step} pkt={pkt} prog={prog} node={node} width={layout.w} />
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
            <button type="button" className="tx-btn" onClick={() => goStep(stepIdx - 1)} disabled={stepIdx === 0} aria-label="Passo precedente">
              <ChevronLeft size={17} aria-hidden />
            </button>
            <button type="button" className="tx-btn primary" onClick={toggle}>
              {playing ? <Pause size={15} aria-hidden /> : ended ? <RotateCcw size={15} aria-hidden /> : <Play size={15} aria-hidden />}
              {playing ? 'Pausa' : ended ? 'Di nuovo' : started ? 'Riprendi' : 'Riproduci'}
            </button>
            <button type="button" className="tx-btn" onClick={() => goStep(stepIdx + 1)} disabled={stepIdx >= sc.steps.length - 1} aria-label="Passo successivo">
              <ChevronRight size={17} aria-hidden />
            </button>
            <button
              type="button"
              className="tx-btn"
              onClick={() => {
                setCur({ i: 0, t: 0 });
                setPlaying(false);
              }}
              disabled={!started}
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

function NetworkView({ sc, layout, node, pkt, prog, packets }: { sc: TrafficScenario; layout: StageLayout; node: (id: string) => MapNode | undefined; pkt?: TrafficPacket; prog: number; packets: TrafficPacket[] }) {
  const { w, h, slots, vertical } = layout;
  // Collegamenti: ogni coppia di nodi vicini in almeno un pacchetto della scena,
  // orientata dal nodo più vicino al PC (così i rami partono dalla linea comune).
  const edges = new Map<string, [string, string]>();
  for (const p of packets) {
    for (let i = 1; i < p.hops.length; i++) {
      const a = p.hops[i - 1];
      const b = p.hops[i];
      if (a === b || !slots.has(a) || !slots.has(b)) continue;
      const k = pairKey(a, b);
      if (!edges.has(k)) edges.set(k, layout.parent.get(a) === b ? [b, a] : [a, b]);
    }
  }
  // Tratti già percorsi dal pacchetto in corso e nodi raggiunti.
  const end = pkt ? reachOf(pkt) : -1;
  const at = pkt ? prog * Math.max(1, end) : -1;
  const traveled = new Set<string>();
  const reached = new Set<string>();
  if (pkt) {
    reached.add(pkt.hops[0]);
    for (let i = 1; i <= end; i++) {
      if (at > i - 1 || (i === 1 && at >= 0)) traveled.add(pairKey(pkt.hops[i - 1], pkt.hops[i]));
      if (at >= i - 1e-6) reached.add(pkt.hops[i]);
    }
  }
  const color = pkt ? PROTO_COLOR[pkt.proto] : undefined;
  const pathD = (pts: Pt[]) => pts.map((p, i) => `${i ? 'L' : 'M'}${p.x.toFixed(1)} ${p.y.toFixed(1)}`).join(' ');
  const names = sc.lanes
    .map((l) => node(l))
    .filter((n): n is MapNode => !!n)
    .map((n) => (n.self ? 'questo PC' : n.label));
  const list = [...edges.entries()].sort(([a], [b]) => Number(traveled.has(a)) - Number(traveled.has(b)));
  return (
    <svg className="tx-svg" viewBox={`0 0 ${w} ${h}`} width={w} height={h} role="img" aria-label={`Rete della scena «${sc.title}»: ${names.join(', ')}`}>
      {list.map(([k, [a, b]]) => {
        const on = traveled.has(k);
        return <path key={k} d={pathD(route(layout, a, b))} className={`tx-edge${on ? ' on' : ''}`} style={on ? { stroke: color } : undefined} />;
      })}
      {sc.lanes.map((id) => {
        const n = node(id);
        const s = slots.get(id);
        if (!n || !s) return null;
        const on = reached.has(id);
        const name = clip(n.self ? 'Questo PC' : n.label, s.chars);
        const sub = clip(subOf(n), s.chars);
        const tx = s.x + 32 * (s.s / 0.74) + 2;
        return (
          <g key={id} className={`tx-node${on ? ' on' : ''}${n.self ? ' self' : ''}`}>
            <g className="tx-glyph">
              <DeviceArt kind={n.kind} x={s.x} y={s.right ? s.y : s.y - 6} scale={s.s} />
            </g>
            {s.right ? (
              <>
                <text x={tx} y={s.y - 1} className="tx-node-name">
                  {name}
                </text>
                {sub && (
                  <text x={tx} y={s.y + 13} className="tx-node-ip">
                    {sub}
                  </text>
                )}
              </>
            ) : (
              <>
                <text x={s.x} y={s.y + 36} textAnchor="middle" className="tx-node-name">
                  {name}
                </text>
                {sub && (
                  <text x={s.x} y={s.y + 50} textAnchor="middle" className="tx-node-ip">
                    {sub}
                  </text>
                )}
              </>
            )}
          </g>
        );
      })}
      {pkt && <PacketMark pkt={pkt} layout={layout} prog={prog} vertical={vertical} />}
    </svg>
  );
}

function PacketMark({ pkt, layout, prog, vertical }: { pkt: TrafficPacket; layout: StageLayout; prog: number; vertical: boolean }) {
  const end = reachOf(pkt);
  const routes: Pt[][] = [];
  for (let i = 1; i <= end; i++) routes.push(route(layout, pkt.hops[i - 1], pkt.hops[i]));
  const p = along(routes, prog);
  const color = PROTO_COLOR[pkt.proto];
  const cw = pkt.label.length * 7.2 + 16;
  const stopAt = prog >= 1 && pkt.stopAt !== undefined ? layout.slots.get(pkt.hops[end]) : undefined;
  // Passato anche se non dovrebbe: un segnale rosso sul nodo dove arriva.
  const alarm = prog >= 1 && pkt.stopAt === undefined && pkt.sev === 'crit' ? layout.slots.get(pkt.hops[end]) : undefined;
  // Etichetta sopra il pacchetto; sullo schermo stretto, a destra.
  const cx = vertical ? Math.min(layout.w - cw - 4, p.x + 22) : Math.min(layout.w - cw - 6, Math.max(6, p.x - cw / 2));
  const cy = vertical ? p.y - 36 : p.y - 44;
  const sev = pkt.sev ?? 'warn';
  return (
    <g className="tx-packet" pointerEvents="none">
      {stopAt && (
        <g className={`tx-x ${sev}`} transform={`translate(${stopAt.x - 30} ${stopAt.y + (stopAt.right ? 16 : 10)})`}>
          <circle r="11" />
          <path d="M-4.5 -4.5 L4.5 4.5 M4.5 -4.5 L-4.5 4.5" />
        </g>
      )}
      {alarm && (
        <g className="tx-x crit" transform={`translate(${alarm.x - 30} ${alarm.y + (alarm.right ? 16 : 10)})`}>
          <circle r="11" />
          <path d="M0 -5.5 V1.5 M0 5 V5.2" />
        </g>
      )}
      <circle cx={p.x} cy={p.y} r={10} fill={color} opacity={0.2} />
      <circle cx={p.x} cy={p.y} r={4.8} fill={color} />
      <g transform={`translate(${cx} ${cy})`}>
        <rect width={cw} height={18} rx={4} fill={color} />
        <text x={cw / 2} y={12.8} textAnchor="middle" className="tx-chip-t">
          {pkt.label}
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
            {frac >= 1 && p.stopAt === undefined && p.sev === 'crit' && (
              <g className="tx-x crit" transform={`translate(${b + (b >= a ? -22 : 22)} ${y + 12})`}>
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
