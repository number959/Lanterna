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
import { useId } from 'react';
import type { Progress } from './api';
import { AnimatedNumber, Logo } from './components';
import { useFx } from './fx';
import { ease, spring } from './motion';

// Schermata di analisi: ogni sonda è un nodo in orbita attorno alla lanterna.
// Il nodo pulsa mentre la misura è in corso e si accende quando termina; il
// fascio di luce verso il centro si traccia nello stesso momento. Tutto è
// guidato dall'avanzamento reale restituito dall'agente.

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
const ORBIT = 150;
const ORB = 54;

export function ScanOrbit({ progress, connecting }: { progress: Progress | null; connecting?: boolean }) {
  const reduce = useReducedMotion();
  const { lite } = useFx();
  const gid = useId();
  const steps = progress?.steps ?? [];
  const n = steps.length || 11;
  const done = steps.filter((s) => s.state === 'done' || s.state === 'error').length;
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
          transition={{ duration: 3.2, repeat: Infinity, ease: 'linear' }}
        />
        <svg viewBox="0 0 400 400" aria-hidden="true">
          <defs>
            <radialGradient id={`${gid}-orb`} cx="50%" cy="45%" r="60%">
              <stop offset="0" stopColor="#fff3c4" stopOpacity="0.95" />
              <stop offset="0.35" stopColor="#ffb547" stopOpacity="0.9" />
              <stop offset="1" stopColor="#ff8a3d" stopOpacity="0.05" />
            </radialGradient>
            <filter id={`${gid}-glow`} x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="8" />
            </filter>
          </defs>

          {/* Anelli concentrici che ruotano lentamente in versi opposti. */}
          {[ORBIT, ORBIT - 46, ORBIT + 28].map((r, i) => (
            <m.circle
              key={r}
              cx={C}
              cy={C}
              r={r}
              fill="none"
              stroke="var(--line-strong)"
              strokeWidth={i === 0 ? 1.2 : 1}
              strokeDasharray={i === 0 ? '2 7' : i === 1 ? '1 10' : '18 14'}
              style={{ originX: '50%', originY: '50%', transformBox: 'view-box' }}
              animate={reduce ? undefined : { rotate: i % 2 ? -360 : 360 }}
              transition={{ duration: 60 + i * 25, repeat: Infinity, ease: 'linear' }}
            />
          ))}

          {/* Onde di luce che partono dalla lanterna. */}
          {!reduce &&
            [0, 1, 2].map((i) => (
              <m.circle
                key={`w${i}`}
                cx={C}
                cy={C}
                r={ORB}
                fill="none"
                stroke="var(--accent)"
                strokeWidth={1.5}
                initial={{ r: ORB, opacity: 0.55 }}
                animate={{ r: ORBIT + 40, opacity: 0 }}
                transition={{ duration: 3.6, repeat: Infinity, delay: i * 1.2, ease: ease.out }}
              />
            ))}

          {/* Fasci tra la lanterna e le sonde. */}
          {steps.map((s, i) => {
            const p = pos(i);
            const lit = s.state === 'done' || s.state === 'running' || s.state === 'error';
            const x0 = C + (ORB + 22) * Math.cos(p.a);
            const y0 = C + (ORB + 22) * Math.sin(p.a);
            const x1 = C + (ORBIT - 24) * Math.cos(p.a);
            const y1 = C + (ORBIT - 24) * Math.sin(p.a);
            return (
              <m.line
                key={`b${s.id}`}
                x1={x0}
                y1={y0}
                x2={x1}
                y2={y1}
                stroke={s.state === 'error' ? 'var(--warn)' : s.state === 'running' ? 'var(--accent)' : 'var(--ok)'}
                strokeWidth={s.state === 'running' ? 2 : 1.4}
                strokeLinecap="round"
                initial={{ pathLength: 0, opacity: 0 }}
                animate={{ pathLength: lit ? 1 : 0, opacity: lit ? (s.state === 'running' ? 0.9 : 0.5) : 0 }}
                transition={{ duration: 0.6, ease: ease.out }}
              />
            );
          })}

          {/* Lanterna centrale con anello di avanzamento. */}
          <m.circle
            cx={C}
            cy={C}
            r={ORB + 10}
            fill={`url(#${gid}-orb)`}
            className="orb-glow"
            filter={`url(#${gid}-glow)`}
            style={{ originX: '50%', originY: '50%', transformBox: 'view-box' }}
            animate={reduce ? undefined : { scale: [0.94, 1.06, 0.94], opacity: [0.65, 1, 0.65] }}
            transition={{ duration: 2.4, repeat: Infinity, ease: 'easeInOut' }}
          />
          <circle cx={C} cy={C} r={ORB} fill="var(--surface)" stroke="var(--line-strong)" />
          <circle cx={C} cy={C} r={ORB + 16} fill="none" stroke="var(--surface-3)" strokeWidth={4} />
          <g transform={`rotate(-90 ${C} ${C})`}>
            <m.circle
              cx={C}
              cy={C}
              r={ORB + 16}
              fill="none"
              stroke="var(--accent)"
              strokeWidth={4}
              strokeLinecap="round"
              initial={{ pathLength: 0 }}
              animate={{ pathLength: steps.length ? done / steps.length : 0.04 }}
              transition={spring.gentle}
            />
          </g>
          {/* Logo ingrandito 1,4 volte con la fiamma (16,19) esattamente al centro del bagliore. */}
          <g transform={`translate(${C - 16 * 1.4} ${C - 19 * 1.4}) scale(1.4)`} style={{ color: 'var(--text)' }}>
            <Logo size={32} busy />
          </g>

          {/* Sonde in orbita. */}
          {steps.map((s, i) => {
            const p = pos(i);
            const I = ICONS[s.id] ?? Globe;
            const color =
              s.state === 'done' ? 'var(--ok)' : s.state === 'error' ? 'var(--warn)' : s.state === 'running' ? 'var(--accent)' : 'var(--text-3)';
            return (
              <g key={s.id} transform={`translate(${p.x} ${p.y})`}>
                {s.state === 'running' && !reduce && (
                  <m.circle
                    r={20}
                    fill="none"
                    stroke="var(--accent)"
                    strokeWidth={2}
                    initial={{ r: 20, opacity: 0.8 }}
                    animate={{ r: 34, opacity: 0 }}
                    transition={{ duration: 1.3, repeat: Infinity, ease: ease.out }}
                  />
                )}
                <m.g
                  initial={false}
                  animate={{ scale: s.state === 'running' ? 1.14 : 1 }}
                  transition={spring.snappy}
                >
                  <m.circle
                    r={21}
                    fill="var(--surface)"
                    strokeWidth={s.state === 'pending' ? 1 : 2}
                    initial={false}
                    animate={{ stroke: color }}
                    transition={{ duration: 0.35 }}
                    style={{ filter: !lite && (s.state === 'done' || s.state === 'running') ? `drop-shadow(0 0 8px ${color})` : 'none' }}
                  />
                  <g transform="translate(-10 -10)" style={{ color }}>
                    <I size={20} strokeWidth={1.8} />
                  </g>
                  <AnimatePresence>
                    {(s.state === 'done' || s.state === 'error') && (
                      // La posizione sta nel <g> esterno: la scala animata di Motion
                      // diventa una trasformazione CSS che sostituirebbe l'attributo.
                      <g key="badge" transform="translate(15 -15)">
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
              <m.div
                key={s.id}
                data-state={s.state}
                layout
                transition={spring.smooth}
              >
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
