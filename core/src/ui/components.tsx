import { useId, useState } from 'react';
import { ACTIONS, METRICS } from '../engine';
import type { Finding, Severity } from '../engine';
import { useCountUp } from './hooks';

export const SEV_LABEL: Record<Severity, string> = {
  ok: 'Ok',
  info: 'Info',
  warn: 'Da migliorare',
  crit: 'Critico',
  unknown: 'Non misurato',
};

export function SevIcon({ sev, size = 16 }: { sev: Severity; size?: number }) {
  const p = { width: size, height: size, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: 2.4, strokeLinecap: 'round' as const, strokeLinejoin: 'round' as const, 'aria-hidden': true };
  switch (sev) {
    case 'ok':
      return (<svg {...p}><circle cx="12" cy="12" r="9.5" /><path d="M7.5 12.5l3 3 6-6.5" /></svg>);
    case 'info':
      return (<svg {...p}><circle cx="12" cy="12" r="9.5" /><path d="M12 11v6M12 7.5v.01" /></svg>);
    case 'warn':
      return (<svg {...p}><path d="M12 3.5l9.5 16.5h-19z" /><path d="M12 10v4.5M12 17.5v.01" /></svg>);
    case 'crit':
      return (<svg {...p}><path d="M8 3h8l5 5v8l-5 5H8l-5-5V8z" /><path d="M9 9l6 6M15 9l-6 6" /></svg>);
    default:
      return (<svg {...p}><circle cx="12" cy="12" r="9.5" /><path d="M9.5 9.5a2.5 2.5 0 114 2c-1 .6-1.5 1.2-1.5 2.3M12 17v.01" /></svg>);
  }
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

export function Icon({ name, size = 18 }: { name: string; size?: number }) {
  const p = { width: size, height: size, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: 2, strokeLinecap: 'round' as const, strokeLinejoin: 'round' as const, 'aria-hidden': true };
  const paths: Record<string, JSX.Element> = {
    home: <><path d="M3 11l9-7 9 7" /><path d="M5 10v10h14V10" /></>,
    wifi: <><path d="M2 8.8a15 15 0 0120 0" /><path d="M5 12.5a10 10 0 0114 0" /><path d="M8.5 16a5 5 0 017 0" /><path d="M12 19.5v.01" /></>,
    lan: <><rect x="9" y="2.5" width="6" height="5" rx="1" /><rect x="2.5" y="16.5" width="6" height="5" rx="1" /><rect x="15.5" y="16.5" width="6" height="5" rx="1" /><path d="M12 7.5v4.5M5.5 16.5V12h13v4.5" /></>,
    globe: <><circle cx="12" cy="12" r="9.5" /><path d="M2.5 12h19M12 2.5c3 3.2 3 15.8 0 19M12 2.5c-3 3.2-3 15.8 0 19" /></>,
    router: <><rect x="2.5" y="13" width="19" height="7" rx="2" /><path d="M6.5 16.5h.01M10 16.5h.01M8 9.5a5.5 5.5 0 018 0M5 6.5a10 10 0 0114 0" /></>,
    plan: <><path d="M9 6h11M9 12h11M9 18h11" /><path d="M4 6l1 1 2-2M4 12l1 1 2-2M4 18l1 1 2-2" /></>,
    pulse: <><path d="M2.5 12h4l2.5-6 4 12 2.5-6h6" /></>,
    book: <><path d="M4 4.5A2.5 2.5 0 016.5 2H20v17H6.5A2.5 2.5 0 004 21.5z" /><path d="M4 19.5A2.5 2.5 0 016.5 17H20" /></>,
    refresh: <><path d="M20.5 11A8.5 8.5 0 105 17.5" /><path d="M20.5 4v7h-7" /></>,
    download: <><path d="M12 3v12M7 10l5 5 5-5" /><path d="M4 20h16" /></>,
    upload: <><path d="M12 21V9M7 14l5-5 5 5" /><path d="M4 4h16" /></>,
    chevron: <path d="M6 9l6 6 6-6" />,
    sun: <><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" /></>,
    moon: <path d="M20 14.5A8 8 0 019.5 4a8 8 0 1010.5 10.5z" />,
    shield: <><path d="M12 2.5l8 3v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10v-6z" /></>,
  };
  return <svg {...p}>{paths[name]}</svg>;
}

export function Logo({ size = 30 }: { size?: number }) {
  // Una lanterna stilizzata la cui fiamma è un'antenna Wi-Fi.
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      <defs>
        <radialGradient id="lg-flame" cx="50%" cy="60%" r="60%">
          <stop offset="0" stopColor="#fff3c4" />
          <stop offset="0.5" stopColor="#ffb547" />
          <stop offset="1" stopColor="#ff8a3d" />
        </radialGradient>
      </defs>
      <path d="M12 4h8M16 2v2" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
      <path d="M9 8h14l-1.5 16h-11z" fill="none" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" />
      <path d="M8 27h16" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" />
      <circle cx="16" cy="19" r="2.2" fill="url(#lg-flame)" />
      <path d="M12.6 15.6a4.8 4.8 0 016.8 0M10.6 13.3a7.6 7.6 0 0110.8 0" fill="none" stroke="#ffb547" strokeWidth="1.8" strokeLinecap="round" />
    </svg>
  );
}

export function ScoreRing({ score, size = 190 }: { score: number; size?: number }) {
  const v = useCountUp(score);
  const r = size / 2 - 12;
  const c = 2 * Math.PI * r;
  const color = score >= 85 ? 'var(--ok)' : score >= 70 ? 'var(--info)' : score >= 50 ? 'var(--warn)' : 'var(--crit)';
  const gid = useId();
  return (
    <div className="ring-wrap" style={{ width: size, height: size }} role="img" aria-label={`Punteggio ${score} su 100`}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <defs>
          <filter id={gid}>
            <feGaussianBlur stdDeviation="5" />
          </filter>
        </defs>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--surface-3)" strokeWidth="12" />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={c * (1 - v / 100)}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
          filter={`url(#${gid})`}
          opacity="0.55"
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={c * (1 - v / 100)}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
        />
      </svg>
      <div className="ring-num" aria-hidden="true">
        <div>
          <strong className="mono">{v}</strong>
          <span>su 100</span>
        </div>
      </div>
    </div>
  );
}

/** Scheda di un valore misurato: verdetto sempre visibile, spiegazione completa espandibile. */
export function FindingCard({ f, i = 0, onAction }: { f: Finding; i?: number; onAction?: (id: string) => void }) {
  const [open, setOpen] = useState(false);
  const m = METRICS[f.metric];
  const bodyId = useId();
  return (
    <article className="finding reveal" data-sev={f.severity} data-open={open} style={{ ['--i' as string]: i }}>
      <button className="finding-head" aria-expanded={open} aria-controls={bodyId} onClick={() => setOpen(!open)}>
        <span className={`c-${f.severity}`} title={SEV_LABEL[f.severity]}>
          <SevIcon sev={f.severity} size={22} />
          <span className="sr-only">{SEV_LABEL[f.severity]}</span>
        </span>
        <span>
          <div className="finding-title">{f.title}</div>
          <div className="finding-verdict">{f.verdict}</div>
        </span>
        <span className="finding-value">{f.value}</span>
        <span className="chev"><Icon name="chevron" /></span>
      </button>
      <div className="finding-body" id={bodyId} role="region" aria-label={`Dettagli: ${f.title}`}>
        <div>
          {open && m && (
            <div className="finding-inner">
              <div className="kb-block">
                <h4>Cos'è</h4>
                <p>{m.what}</p>
              </div>
              {m.scale && (
                <div className="kb-block">
                  <h4>Come si legge</h4>
                  <div className="scale">
                    {m.scale.map((s) => (
                      <div key={s.range} className={`scale-row ${s.severity === f.severity ? 'here' : ''}`}>
                        <span className={`c-${s.severity}`} style={{ display: 'flex', gap: 6, alignItems: 'center', fontWeight: 600 }}>
                          <SevIcon sev={s.severity} size={14} />
                          {s.range}
                        </span>
                        <span className="muted">{s.meaning}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              <div className="kb-block">
                <h4>Perché conta</h4>
                <p>{m.why}</p>
              </div>
              {m.limits && (
                <div className="kb-block">
                  <h4>Limiti della misura</h4>
                  <p>{m.limits}</p>
                </div>
              )}
              {f.actions.length > 0 && (
                <div className="kb-block">
                  <h4>Cosa fare</h4>
                  <div className="chip-actions">
                    {f.actions.map((a) => (
                      <button key={a} className="btn small" onClick={() => onAction?.(a)}>
                        {ACTIONS[a].title} →
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </article>
  );
}

export function FindingList({ findings, onAction, empty }: { findings: Finding[]; onAction?: (id: string) => void; empty?: string }) {
  if (!findings.length) return <div className="empty">{empty ?? 'Nessun dato per questa sezione.'}</div>;
  return (
    <div className="findings">
      {findings.map((f, i) => (
        <FindingCard key={f.id} f={f} i={i} onAction={onAction} />
      ))}
    </div>
  );
}

export function Stat({ k, v, sev }: { k: string; v: string; sev?: Severity }) {
  return (
    <div className="stat">
      <div className="k">{k}</div>
      <div className={`v ${sev ? `c-${sev}` : ''}`}>{v}</div>
    </div>
  );
}
