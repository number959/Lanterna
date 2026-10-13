import {
  Cable,
  Check,
  Globe,
  Lock,
  Network,
  Route,
  Router,
  Server,
  Shield,
  Signpost,
  TriangleAlert,
  Users,
  Wifi,
  type LucideIcon,
} from 'lucide-react';
import { AnimatePresence, m, useReducedMotion } from 'motion/react';
import type { Progress } from './api';
import { BrandSymbol, hexPath } from './brand';
import { AnimatedNumber } from './components';
import { useFx } from './fx';
import { ease, spring } from './motion';

// Schermata di analisi: al centro il simbolo STARNET dentro una cornice
// esagonale che si completa con l'avanzamento, come il tratto ciano del
// marchio. Ogni sonda è una stella in orbita: si accende quando la misura
// parte e, finita, si collega alla precedente formando una costellazione.
// Tutto è guidato dall'avanzamento reale restituito dall'agente.

const ICONS: Record<string, LucideIcon> = {
  adapters: Network,
  wifi: Wifi,
  gateway: Router,
  router: Server,
  internet: Globe,
  trace: Route,
  dns: Signpost,
  web: Lock,
  upnp: Cable,
  firewall: Shield,
  lan: Users,
};

const C = 200; // centro del disegno (viewBox 400×400)
const ORBIT = 152;
const CORE = 66; // raggio della cornice esagonale attorno al simbolo

export function ScanOrbit({ progress, connecting }: { progress: Progress | null; connecting?: boolean }) {
  const reduce = useReducedMotion();
  const { lite } = useFx();
  const steps = progress?.steps ?? [];
  const n = steps.length || 11;
  const finished = (s: { state: string }) => s.state === 'done' || s.state === 'error';
  const done = steps.filter(finished).length;
  const pct = steps.length ? Math.round((100 * done) / steps.length) : 0;
  const current = steps.find((s) => s.state === 'running');
  const pos = (i: number) => {
    const a = -Math.PI / 2 + (i * 2 * Math.PI) / n;
    return { x: C + ORBIT * Math.cos(a), y: C + ORBIT * Math.sin(a), a };
  };
  return (
    <div className="scan" role="status" aria-live="polite" aria-busy="true">
      <div className="scan-orbit">
        <m.div
          className="scan-sweep"
          animate={reduce ? undefined : { rotate: 360 }}
          transition={{ duration: 3.6, repeat: Infinity, ease: 'linear' }}
        />
        <svg viewBox="0 0 400 400" aria-hidden="true">
          {/* Esagoni concentrici che ruotano piano in versi opposti. */}
          {[ORBIT + 30, ORBIT - 44].map((r, i) => (
            <m.path
              key={r}
              d={hexPath(C, C, r)}
              fill="none"
              stroke="var(--line-strong)"
              strokeWidth={1}
              strokeDasharray={i === 0 ? '14 12' : '2 9'}
              style={{ originX: '50%', originY: '50%', transformBox: 'view-box' }}
              animate={reduce ? undefined : { rotate: i ? -360 : 360 }}
              transition={{ duration: 90 + i * 30, repeat: Infinity, ease: 'linear' }}
            />
          ))}
          <circle cx={C} cy={C} r={ORBIT} fill="none" stroke="var(--line)" strokeWidth={1} />

          {/* Impulsi esagonali che partono dal centro. */}
          {!reduce &&
            [0, 1, 2].map((i) => (
              <m.path
                key={`w${i}`}
                d={hexPath(C, C, CORE + 6)}
                fill="none"
                stroke="var(--accent)"
                strokeWidth={1.5}
                style={{ originX: '50%', originY: '50%', transformBox: 'view-box' }}
                initial={{ scale: 1, opacity: 0.5 }}
                animate={{ scale: 2.25, opacity: 0 }}
                transition={{ duration: 3.6, repeat: Infinity, delay: i * 1.2, ease: ease.out }}
              />
            ))}

          {/* Costellazione: ogni sonda conclusa si collega alla precedente. */}
          {steps.map((s, i) => {
            if (i === 0) return null;
            const a = pos(i - 1);
            const b = pos(i);
            const lit = finished(s) && finished(steps[i - 1]);
            return (
              <m.line
                key={`k${s.id}`}
                x1={a.x}
                y1={a.y}
                x2={b.x}
                y2={b.y}
                stroke="var(--accent)"
                strokeWidth={1.3}
                strokeLinecap="round"
                initial={{ pathLength: 0, opacity: 0 }}
                animate={{ pathLength: lit ? 1 : 0, opacity: lit ? 0.55 : 0 }}
                transition={{ duration: 0.7, ease: ease.out }}
              />
            );
          })}

          {/* Fasci tra il centro e le sonde in corso o concluse. */}
          {steps.map((s, i) => {
            const p = pos(i);
            const lit = s.state !== 'pending';
            return (
              <m.line
                key={`b${s.id}`}
                x1={C + (CORE + 14) * Math.cos(p.a)}
                y1={C + (CORE + 14) * Math.sin(p.a)}
                x2={C + (ORBIT - 25) * Math.cos(p.a)}
                y2={C + (ORBIT - 25) * Math.sin(p.a)}
                stroke={s.state === 'error' ? 'var(--warn)' : s.state === 'running' ? 'var(--accent)' : 'var(--ok)'}
                strokeWidth={s.state === 'running' ? 2 : 1.2}
                strokeLinecap="round"
                initial={{ pathLength: 0, opacity: 0 }}
                animate={{ pathLength: lit ? 1 : 0, opacity: lit ? (s.state === 'running' ? 0.9 : 0.35) : 0 }}
                transition={{ duration: 0.6, ease: ease.out }}
              />
            );
          })}

          {/* Cornice esagonale che si completa dal vertice alto in senso orario. */}
          <path d={hexPath(C, C, CORE)} fill="var(--surface)" stroke="var(--line-strong)" strokeWidth={1} />
          <path d={hexPath(C, C, CORE + 8)} fill="none" stroke="var(--surface-3)" strokeWidth={6} strokeLinejoin="round" />
          <m.path
            d={hexPath(C, C, CORE + 8)}
            fill="none"
            stroke="var(--accent)"
            strokeWidth={6}
            strokeLinejoin="round"
            strokeLinecap="round"
            initial={{ pathLength: 0 }}
            animate={{ pathLength: steps.length ? done / steps.length : 0.03 }}
            transition={spring.gentle}
          />
          <BrandSymbol x={C - 46} y={C - 46} size={92} intro delay={0.1} />

          {/* Sonde in orbita. */}
          {steps.map((s, i) => {
            const p = pos(i);
            const I = ICONS[s.id] ?? Globe;
            const color =
              s.state === 'done' ? 'var(--ok)' : s.state === 'error' ? 'var(--warn)' : s.state === 'running' ? 'var(--accent)' : 'var(--text-3)';
            return (
              <g key={s.id} transform={`translate(${p.x} ${p.y})`}>
                {s.state === 'running' && !reduce && (
                  <m.path
                    d={hexPath(0, 0, 22)}
                    fill="none"
                    stroke="var(--accent)"
                    strokeWidth={2}
                    initial={{ scale: 1, opacity: 0.8 }}
                    animate={{ scale: 1.6, opacity: 0 }}
                    transition={{ duration: 1.3, repeat: Infinity, ease: ease.out }}
                  />
                )}
                <m.g initial={false} animate={{ scale: s.state === 'running' ? 1.14 : 1 }} transition={spring.snappy}>
                  <m.path
                    d={hexPath(0, 0, 22)}
                    fill="var(--surface)"
                    strokeWidth={s.state === 'pending' ? 1 : 2}
                    strokeLinejoin="round"
                    initial={false}
                    animate={{ stroke: color }}
                    transition={{ duration: 0.35 }}
                    style={{ filter: !lite && (s.state === 'done' || s.state === 'running') ? `drop-shadow(0 0 7px ${color})` : 'none' }}
                  />
                  <g transform="translate(-10 -10)" style={{ color }}>
                    <I size={20} strokeWidth={1.8} />
                  </g>
                  <AnimatePresence>
                    {finished(s) && (
                      // La posizione sta nel <g> esterno: la scala animata di Motion
                      // diventa una trasformazione CSS che sostituirebbe l'attributo.
                      <g key="badge" transform="translate(16 -16)">
                        <m.g initial={{ scale: 0, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0, opacity: 0 }} transition={spring.snappy}>
                          <circle r={8.5} fill={s.state === 'done' ? 'var(--ok)' : 'var(--warn)'} />
                          <g transform="translate(-5.5 -5.5)" style={{ color: 'var(--surface)' }}>
                            {s.state === 'done' ? <Check size={11} strokeWidth={3.2} /> : <TriangleAlert size={11} strokeWidth={2.6} />}
                          </g>
                        </m.g>
                      </g>
                    )}
                  </AnimatePresence>
                </m.g>
              </g>
            );
          })}
        </svg>
      </div>

      <h2 className="scan-title">{connecting ? 'Collegamento all’agente…' : 'Analisi della rete in corso'}</h2>
      <div className="scan-current">
        <AnimatePresence mode="wait" initial={false}>
          <m.span
            key={current?.id ?? (steps.length ? 'end' : 'start')}
            style={{ display: 'inline-block' }}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            transition={{ duration: 0.28, ease: ease.out }}
          >
            {current ? current.label : steps.length ? 'Ultimi controlli…' : 'Preparazione delle sonde…'}
          </m.span>
        </AnimatePresence>
      </div>
      <p className="scan-sub">
        {steps.length ? (
          <>
            <AnimatedNumber value={pct} suffix=" %" /> · {done} di {steps.length} misure · circa mezzo minuto in tutto
          </>
        ) : (
          'Non scollegarti dalla rete durante l’analisi.'
        )}
      </p>

      {steps.length > 0 && (
        <div className="step-list">
          {steps.map((s) => {
            const I = ICONS[s.id] ?? Globe;
            return (
              <m.div key={s.id} data-state={s.state} layout transition={spring.smooth}>
                <I size={15} aria-hidden />
                <span style={{ flex: 1 }}>{s.label}</span>
                <AnimatePresence mode="popLayout" initial={false}>
                  {s.state === 'done' && (
                    <m.span key="ok" className="c-ok" initial={{ scale: 0 }} animate={{ scale: 1 }} exit={{ scale: 0 }} transition={spring.snappy} style={{ display: 'flex' }}>
                      <Check size={15} aria-label="completata" />
                    </m.span>
                  )}
                  {s.state === 'error' && (
                    <m.span key="err" className="c-warn" initial={{ scale: 0 }} animate={{ scale: 1 }} exit={{ scale: 0 }} transition={spring.snappy} style={{ display: 'flex' }}>
                      <TriangleAlert size={15} aria-label="non riuscita" />
                    </m.span>
                  )}
                </AnimatePresence>
              </m.div>
            );
          })}
        </div>
      )}
    </div>
  );
}
