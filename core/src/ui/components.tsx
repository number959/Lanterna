import {
  ArrowRight,
  BookOpenText,
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
import { guidesForMetric } from '../guides';
import { ease, rise, spring, stagger } from './motion';
import { play } from './sound';
import type { Cue } from './sound';

/** Apre una guida da qualunque punto dell'interfaccia (lo fornisce la shell). */
export const GuideLinkContext = createContext<((id: string) => void) | null>(null);
export const useOpenGuide = () => useContext(GuideLinkContext);

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
  const openGuide = useOpenGuide();
  const guides = guidesForMetric(f.metric).slice(0, 3);
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
              {openGuide && guides.length > 0 && (
                <m.div className="kb-block" variants={rise}>
                  <h3>Approfondisci</h3>
                  <div className="chip-actions">
                    {guides.map((g) => (
                      <button key={g.id} className="btn small" onClick={() => openGuide(g.id)}>
                        <BookOpenText size={14} aria-hidden />
                        {g.title}
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
    <m.div className="findings" variants={{ hidden: {}, show: { transition: { staggerChildren: stagger(findings.length, 0.04) } } }}>
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

type ToastKind = 'ok' | 'warn' | 'error';

interface Toast {
  id: number;
  text: string;
  kind: ToastKind;
}

// Ogni messaggio ha il suo suono (se i suoni sono accesi): di norma quello del
// tipo di messaggio, oppure uno scelto da chi lo mostra.
const TOAST_CUE: Record<ToastKind, Cue> = { ok: 'success', warn: 'warn', error: 'error' };

const ToastCtx = createContext<(text: string, kind?: ToastKind, cue?: Cue) => void>(() => undefined);
export const useToast = () => useContext(ToastCtx);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [list, setList] = useState<Toast[]>([]);
  const seq = useRef(0);
  const push = useCallback((text: string, kind: ToastKind = 'ok', cue?: Cue) => {
    play(cue ?? TOAST_CUE[kind]);
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
              {t.kind === 'error' ? <OctagonX size={18} aria-hidden /> : t.kind === 'warn' ? <TriangleAlert size={18} aria-hidden /> : <CircleCheck size={18} aria-hidden />}
              {t.text}
            </m.div>
          ))}
        </AnimatePresence>
      </div>
    </ToastCtx.Provider>
  );
}
