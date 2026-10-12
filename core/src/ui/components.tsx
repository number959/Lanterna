import {
  ArrowRight,
  CircleCheck,
  CircleHelp,
  ChevronDown,
  Info,
  OctagonX,
  TriangleAlert,
  type LucideIcon,
  type LucideProps,
} from 'lucide-react';
import { AnimatePresence, m, useReducedMotion, useSpring, useTransform } from 'motion/react';
import { createContext, useCallback, useContext, useEffect, useId, useRef, useState } from 'react';
import type { KeyboardEvent, PointerEvent, ReactNode } from 'react';
import { ACTIONS, METRICS } from '../engine';
import type { Finding, Severity } from '../engine';
import { ease, rise, spring } from './motion';

export const SEV_LABEL: Record<Severity, string> = {
  ok: 'Ok',
  info: 'Info',
  warn: 'Da migliorare',
  crit: 'Critico',
  unknown: 'Non misurato',
};

const SEV_ICON: Record<Severity, LucideIcon> = {
  ok: CircleCheck,
  info: Info,
  warn: TriangleAlert,
  crit: OctagonX,
  unknown: CircleHelp,
};

export function SevIcon({ sev, size = 16, ...rest }: { sev: Severity; size?: number } & LucideProps) {
  const I = SEV_ICON[sev];
  return <I size={size} strokeWidth={2.1} aria-hidden {...rest} />;
}

export function SevBadge({ sev }: { sev: Severity }) {
  return (
    <span className={`sev ${sev}`}>
      <SevIcon sev={sev} size={14} />
      {SEV_LABEL[sev]}
    </span>
  );
}

export const sevColor = (s: Severity) => `var(--${s})`;

export const fmtNum = (v: number, decimals = 0) => v.toFixed(decimals).replace('.', ',');

/** Numero che si assesta sul valore con una molla; con movimento ridotto salta subito al valore. */
export function AnimatedNumber({ value, decimals = 0, suffix = '' }: { value: number; decimals?: number; suffix?: string }) {
  const reduce = useReducedMotion();
  const mv = useSpring(reduce ? value : 0, { stiffness: 70, damping: 18, mass: 1 });
  const text = useTransform(mv, (v) => fmtNum(v, decimals) + suffix);
  useEffect(() => {
    if (reduce) mv.jump(value);
    else mv.set(value);
  }, [value, reduce, mv]);
  return <m.span>{text}</m.span>;
}

/** Logo: una lanterna la cui fiamma è un'antenna; durante l'analisi le onde pulsano. */
export function Logo({ size = 30, busy: busyProp = false }: { size?: number; busy?: boolean }) {
  const gid = useId();
  // Con "riduci movimento" il logo resta fermo anche durante l'analisi.
  const reduce = useReducedMotion();
  const busy = busyProp && !reduce;
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      <defs>
        <radialGradient id={gid} cx="50%" cy="60%" r="60%">
          <stop offset="0" stopColor="#fff3c4" />
          <stop offset="0.5" stopColor="#ffb547" />
          <stop offset="1" stopColor="#ff8a3d" />
        </radialGradient>
      </defs>
      <path d="M12 4h8M16 2v2" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
      <path d="M9 8h14l-1.5 16h-11z" fill="none" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" />
      <path d="M8 27h16" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" />
      <m.circle
        cx="16"
        cy="19"
        r="2.2"
        fill={`url(#${gid})`}
        animate={busy ? { scale: [1, 1.25, 1] } : { scale: 1 }}
        transition={busy ? { duration: 1.4, repeat: Infinity, ease: 'easeInOut' } : spring.snappy}
      />
      {[0, 1].map((i) => (
        <m.path
          key={i}
          d={i === 0 ? 'M12.6 15.6a4.8 4.8 0 016.8 0' : 'M10.6 13.3a7.6 7.6 0 0110.8 0'}
          fill="none"
          stroke="#ffb547"
          strokeWidth="1.8"
          strokeLinecap="round"
          animate={busy ? { opacity: [0.25, 1, 0.25] } : { opacity: 1 }}
          transition={busy ? { duration: 1.4, repeat: Infinity, delay: i * 0.25, ease: 'easeInOut' } : { duration: 0.3 }}
        />
      ))}
    </svg>
  );
}

const scoreColor = (s: number) => (s >= 85 ? 'var(--ok)' : s >= 70 ? 'var(--info)' : s >= 50 ? 'var(--warn)' : 'var(--crit)');

/** Anello del punteggio: si riempie con una molla, con alone e numero che sale. */
export function ScoreRing({ score, size = 200 }: { score: number; size?: number }) {
  const gid = useId();
  const reduce = useReducedMotion();
  const r = size / 2 - 14;
  const color = scoreColor(score);
  const ticks = Array.from({ length: 60 }, (_, i) => i);
  return (
    <div className="ring-wrap" style={{ width: size, height: size }} role="img" aria-label={`Punteggio ${score} su 100`}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <defs>
          <linearGradient id={`${gid}-g`} x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stopColor={color} stopOpacity="0.55" />
            <stop offset="1" stopColor={color} />
          </linearGradient>
          <filter id={`${gid}-b`} x="-30%" y="-30%" width="160%" height="160%">
            <feGaussianBlur stdDeviation="6" />
          </filter>
        </defs>
        {ticks.map((i) => {
          const a = (i / 60) * Math.PI * 2 - Math.PI / 2;
          const r1 = r + 9;
          const r2 = r + (i % 5 === 0 ? 4 : 6);
          return (
            <line
              key={i}
              x1={size / 2 + r1 * Math.cos(a)}
              y1={size / 2 + r1 * Math.sin(a)}
              x2={size / 2 + r2 * Math.cos(a)}
              y2={size / 2 + r2 * Math.sin(a)}
              stroke="var(--line-strong)"
              strokeWidth={i % 5 === 0 ? 1.6 : 1}
            />
          );
        })}
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--surface-3)" strokeWidth="12" />
        <g transform={`rotate(-90 ${size / 2} ${size / 2})`}>
          <m.circle
            cx={size / 2}
            cy={size / 2}
            r={r}
            fill="none"
            stroke={color}
            strokeWidth="12"
            strokeLinecap="round"
            className="ring-glow"
            filter={`url(#${gid}-b)`}
            initial={{ pathLength: reduce ? score / 100 : 0, opacity: 0.5 }}
            animate={{ pathLength: score / 100, opacity: 0.5 }}
            transition={{ ...spring.gentle, delay: 0.15 }}
          />
          <m.circle
            cx={size / 2}
            cy={size / 2}
            r={r}
            fill="none"
            stroke={`url(#${gid}-g)`}
            strokeWidth="12"
            strokeLinecap="round"
            initial={{ pathLength: reduce ? score / 100 : 0 }}
            animate={{ pathLength: score / 100 }}
            transition={{ ...spring.gentle, delay: 0.15 }}
          />
        </g>
      </svg>
      <div className="ring-num" aria-hidden="true">
        <div>
          <strong>
            <AnimatedNumber value={score} />
          </strong>
          <span className="of">su 100</span>
        </div>
      </div>
    </div>
  );
}

/** Aggiunge l'effetto luce che segue il puntatore (classe .spot) senza ri-renderizzare. */
export function spotHandlers() {
  return {
    onPointerMove: (e: PointerEvent<HTMLElement>) => {
      const r = e.currentTarget.getBoundingClientRect();
      e.currentTarget.style.setProperty('--mx', `${e.clientX - r.left}px`);
      e.currentTarget.style.setProperty('--my', `${e.clientY - r.top}px`);
    },
  };
}

/** Scheda di un valore misurato: verdetto sempre visibile, spiegazione completa che si apre. */
export function FindingCard({ f, onAction }: { f: Finding; onAction?: (id: string) => void }) {
  const [open, setOpen] = useState(false);
  const m_ = METRICS[f.metric];
  const bodyId = useId();
  return (
    <m.article className="finding" data-sev={f.severity} variants={rise}>
      <button className="finding-head" aria-expanded={open} aria-controls={bodyId} onClick={() => setOpen(!open)}>
        <span className="sev-dot" title={SEV_LABEL[f.severity]}>
          <SevIcon sev={f.severity} size={18} />
          <span className="sr-only">{SEV_LABEL[f.severity]}</span>
        </span>
        <span>
          <span className="finding-title">{f.title}</span>
          <span className="finding-verdict">{f.verdict}</span>
        </span>
        <span className="finding-value">{f.value}</span>
        <m.span className="chev" animate={{ rotate: open ? 180 : 0 }} transition={spring.snappy}>
          <ChevronDown size={18} aria-hidden />
        </m.span>
      </button>
      <AnimatePresence initial={false}>
        {open && m_ && (
          <m.div
            key="body"
            id={bodyId}
            role="region"
            aria-label={`Dettagli: ${f.title}`}
            className="finding-body"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1, transition: { height: spring.smooth, opacity: { duration: 0.25, delay: 0.05 } } }}
            exit={{ height: 0, opacity: 0, transition: { height: { duration: 0.28, ease: ease.inOut }, opacity: { duration: 0.15 } } }}
          >
            <m.div
              className="finding-inner"
              initial="hidden"
              animate="show"
              variants={{ hidden: {}, show: { transition: { staggerChildren: 0.05, delayChildren: 0.06 } } }}
            >
              <m.div className="kb-block" variants={rise}>
                <h3>Cos'è</h3>
                <p>{m_.what}</p>
              </m.div>
              {m_.scale && (
                <m.div className="kb-block" variants={rise}>
                  <h3>Come si legge</h3>
                  <div className="scale">
                    {m_.scale.map((s) => (
                      <div key={s.range} className={`scale-row ${s.severity === f.severity ? 'here' : ''}`}>
                        <span className={`range c-${s.severity}`}>
                          <SevIcon sev={s.severity} size={14} />
                          {s.range}
                        </span>
                        <span className="muted">{s.meaning}</span>
                      </div>
                    ))}
                  </div>
                </m.div>
              )}
              <m.div className="kb-block" variants={rise}>
                <h3>Perché conta</h3>
                <p>{m_.why}</p>
              </m.div>
              {m_.limits && (
                <m.div className="kb-block" variants={rise}>
                  <h3>Limiti della misura</h3>
                  <p>{m_.limits}</p>
                </m.div>
              )}
              {f.actions.length > 0 && (
                <m.div className="kb-block" variants={rise}>
                  <h3>Cosa fare</h3>
                  <div className="chip-actions">
                    {f.actions.map((a) => (
                      <button key={a} className="btn small" onClick={() => onAction?.(a)}>
                        {ACTIONS[a].title}
                        <ArrowRight className="arrow" size={15} aria-hidden />
                      </button>
                    ))}
                  </div>
                </m.div>
              )}
            </m.div>
          </m.div>
        )}
      </AnimatePresence>
    </m.article>
  );
}

export function FindingList({ findings, onAction, empty }: { findings: Finding[]; onAction?: (id: string) => void; empty?: string }) {
  if (!findings.length) return <div className="empty">{empty ?? 'Nessun dato per questa sezione.'}</div>;
  return (
    <m.div className="findings" variants={{ hidden: {}, show: { transition: { staggerChildren: 0.04 } } }}>
      {findings.map((f) => (
        <FindingCard key={f.id} f={f} onAction={onAction} />
      ))}
    </m.div>
  );
}

/** Contenitore scorrevole delle tabelle: raggiungibile e scorrevole anche da tastiera. */
export function TableWrap({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="table-wrap" tabIndex={0} role="region" aria-label={label}>
      {children}
    </div>
  );
}

export function Stat({ k, v, sev, children }: { k: string; v?: string; sev?: Severity; children?: ReactNode }) {
  return (
    <div className="stat">
      <div className="k">{k}</div>
      <div className={`v ${sev ? `c-${sev}` : ''}`}>{children ?? v}</div>
    </div>
  );
}

/**
 * Interruttore a segmenti accessibile (role tablist, frecce sinistra/destra,
 * Home/Fine) con un indicatore che scivola sotto la voce scelta.
 */
export function Segmented<T extends string>({ value, options, onChange, label }: { value: T; options: { id: T; label: ReactNode }[]; onChange: (v: T) => void; label: string }) {
  const layoutId = useId();
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const onKey = (e: KeyboardEvent, i: number) => {
    let next = -1;
    if (e.key === 'ArrowRight') next = (i + 1) % options.length;
    else if (e.key === 'ArrowLeft') next = (i - 1 + options.length) % options.length;
    else if (e.key === 'Home') next = 0;
    else if (e.key === 'End') next = options.length - 1;
    if (next < 0) return;
    e.preventDefault();
    onChange(options[next].id);
    refs.current[next]?.focus();
  };
  return (
    <div className="seg" role="tablist" aria-label={label}>
      {options.map((o, i) => {
        const on = o.id === value;
        return (
          <button
            key={o.id}
            ref={(el) => {
              refs.current[i] = el;
            }}
            role="tab"
            aria-selected={on}
            tabIndex={on ? 0 : -1}
            onClick={() => onChange(o.id)}
            onKeyDown={(e) => onKey(e, i)}
          >
            {on && <m.span layoutId={`seg-${layoutId}`} className="seg-pill" transition={spring.snappy} />}
            {o.label}
          </button>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------- Avvisi temporanei

interface Toast {
  id: number;
  text: string;
  kind: 'ok' | 'error';
}

const ToastCtx = createContext<(text: string, kind?: 'ok' | 'error') => void>(() => undefined);
export const useToast = () => useContext(ToastCtx);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [list, setList] = useState<Toast[]>([]);
  const seq = useRef(0);
  const push = useCallback((text: string, kind: 'ok' | 'error' = 'ok') => {
    const id = ++seq.current;
    setList((l) => [...l.slice(-2), { id, text, kind }]);
    setTimeout(() => setList((l) => l.filter((t) => t.id !== id)), 3600);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        <AnimatePresence initial={false}>
          {list.map((t) => (
            <m.div
              key={t.id}
              layout
              className={`toast ${t.kind}`}
              initial={{ opacity: 0, y: 18, scale: 0.96 }}
              animate={{ opacity: 1, y: 0, scale: 1, transition: spring.smooth }}
              exit={{ opacity: 0, x: 24, transition: { duration: 0.2, ease: ease.inOut } }}
            >
              {t.kind === 'error' ? <OctagonX size={18} aria-hidden /> : <CircleCheck size={18} aria-hidden />}
              {t.text}
            </m.div>
          ))}
        </AnimatePresence>
      </div>
    </ToastCtx.Provider>
  );
}
