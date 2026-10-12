import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { analyze, ENGINE_VERSION, renderText } from '../engine';
import type { Scan, Severity } from '../engine';
import { demoScan } from '../demo/sample';
import { agentInfo, download, isScan, lastScan, runScan } from './api';
import type { AgentInfo, Progress } from './api';
import { Icon, Logo, sevColor } from './components';
import { useLocalState } from './hooks';
import { GuideView, InternetView, LanView, MonitorView, Overview, PlanView, RouterView, WifiView } from './views';
import type { View, ViewProps } from './views';

type Source = 'agent' | 'demo' | 'file';

const NAV: { id: View; label: string; icon: string; cats?: string[] }[] = [
  { id: 'overview', label: 'Panoramica', icon: 'home' },
  { id: 'wifi', label: 'Wi-Fi', icon: 'wifi', cats: ['wifi'] },
  { id: 'lan', label: 'Rete locale', icon: 'lan', cats: ['lan'] },
  { id: 'internet', label: 'Internet e DNS', icon: 'globe', cats: ['internet', 'dns'] },
  { id: 'router', label: 'Router e sicurezza', icon: 'router', cats: ['router', 'security'] },
  { id: 'plan', label: "Piano d'azione", icon: 'plan' },
  { id: 'monitor', label: 'Monitor', icon: 'pulse' },
  { id: 'guide', label: 'Guida', icon: 'book' },
];

const RANK: Record<Severity, number> = { unknown: 0, ok: 1, info: 2, warn: 3, crit: 4 };

function Scanning({ progress }: { progress: Progress | null }) {
  const blips = useMemo(() => Array.from({ length: 6 }, (_, i) => ({ left: 20 + ((i * 37) % 60), top: 18 + ((i * 53) % 64), delay: i * 0.4 })), []);
  return (
    <div className="scanning" role="status" aria-live="polite">
      <div className="radar">
        {blips.map((b, i) => (
          <span key={i} className="blip" style={{ left: `${b.left}%`, top: `${b.top}%`, animationDelay: `${b.delay}s` }} />
        ))}
      </div>
      <div>
        <h2 style={{ margin: '0 0 6px' }}>Analisi della rete in corso…</h2>
        <p className="muted" style={{ margin: 0 }}>Serve circa mezzo minuto. Non scollegarti dalla rete.</p>
      </div>
      {progress && (
        <div className="step-list">
          {progress.steps.map((s) => (
            <div key={s.id} className={s.state === 'running' ? 'on' : s.state === 'done' ? 'faint' : s.state === 'error' ? 'c-warn' : ''}>
              {s.state === 'done' ? '✓' : s.state === 'running' ? '◉' : s.state === 'error' ? '!' : '○'} {s.label}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function App() {
  const [agent, setAgent] = useState<AgentInfo | null | undefined>(undefined);
  const [scan, setScan] = useState<Scan | null>(null);
  const [source, setSource] = useState<Source>('demo');
  const [view, setView] = useState<View>('overview');
  const [focus, setFocus] = useState<string | undefined>();
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<Progress | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [theme, setTheme] = useLocalState<'auto' | 'dark' | 'light'>('lanterna.theme', 'auto');
  const fileRef = useRef<HTMLInputElement>(null);
  const mainRef = useRef<HTMLElement>(null);

  useEffect(() => {
    if (theme === 'auto') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', theme);
  }, [theme]);

  const scanNow = useCallback(async () => {
    setBusy(true);
    setError(null);
    setProgress(null);
    try {
      const s = await runScan(setProgress);
      setScan(s);
      setSource('agent');
      setView('overview');
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    (async () => {
      const info = await agentInfo();
      setAgent(info);
      if (!info) {
        setScan(demoScan);
        setSource('demo');
        return;
      }
      try {
        const s = await lastScan();
        if (s) {
          setScan(s);
          setSource('agent');
        } else await scanNow();
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
    })();
  }, [scanNow]);

  const analysis = useMemo(() => (scan ? analyze(scan) : null), [scan]);

  const go = useCallback((v: View, f?: string) => {
    setView(v);
    setFocus(f);
    if (!f) mainRef.current?.scrollTo?.({ top: 0 });
    if (!f) window.scrollTo({ top: 0, behavior: 'smooth' });
  }, []);

  const onImport = async (file: File) => {
    try {
      const data = JSON.parse(await file.text());
      if (!isScan(data)) throw new Error('il file non è un rapporto di LANterna');
      setScan(data);
      setSource('file');
      setError(null);
      go('overview');
    } catch (e) {
      setError(`Importazione non riuscita: ${e instanceof Error ? e.message : e}`);
    }
  };

  const stamp = scan ? scan.agent.startedAt.replace(/[:T]/g, '-').slice(0, 16) : '';
  const navDot = (cats?: string[]) => {
    if (!cats || !analysis) return undefined;
    let worst: Severity = 'ok';
    for (const c of analysis.categories) if (cats.includes(c.category) && RANK[c.worst] > RANK[worst]) worst = c.worst;
    return worst === 'crit' || worst === 'warn' ? worst : undefined;
  };
  const current = NAV.find((n) => n.id === view)!;
  const props: ViewProps | null = scan && analysis ? { scan, analysis, go, focus, live: source === 'agent' && !!agent } : null;

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand"><Logo /> <span>LAN<b>terna</b></span></div>
        <nav className="nav" aria-label="Sezioni">
          {NAV.map((n) => {
            const dot = navDot(n.cats);
            return (
              <button key={n.id} aria-current={view === n.id ? 'page' : undefined} onClick={() => go(n.id)}>
                <Icon name={n.icon} /> {n.label}
                {dot && <span className="dot" style={{ background: sevColor(dot) }} aria-label={dot === 'crit' ? 'problemi critici' : 'avvisi'} />}
              </button>
            );
          })}
        </nav>
        <div className="sidebar-foot">
          {agent ? `Agente ${agent.platform} v${agent.version}` : 'Nessun agente collegato'}
          <br />
          Motore v{ENGINE_VERSION}
        </div>
      </aside>

      <main className="main" ref={mainRef}>
        <header className="topbar">
          <h1>{current.label}</h1>
          {scan && (
            <span className={`source ${source === 'demo' ? 'demo' : ''}`}>
              {source === 'demo' ? 'DEMO · dati dimostrativi' : source === 'file' ? `File importato · ${scan.agent.host ?? ''}` : `${scan.agent.host ?? 'questo PC'}`}
              {' · '}
              {new Date(scan.agent.startedAt).toLocaleString('it-IT', { dateStyle: 'short', timeStyle: 'short' })}
            </span>
          )}
          <span className="spacer" />
          {agent && (
            <button className="btn primary" onClick={scanNow} disabled={busy}>
              <Icon name="refresh" /> <span className="btn-label">{busy ? 'Analisi…' : 'Nuova analisi'}</span>
            </button>
          )}
          {scan && analysis && (
            <>
              <button className="btn" onClick={() => download(`lanterna-${stamp}.json`, JSON.stringify(scan, null, 2), 'application/json')} title="Salva i dati grezzi: potrai riaprirli o confrontarli" aria-label="Esporta JSON">
                <Icon name="download" /> <span className="btn-label">JSON</span>
              </button>
              <button className="btn" onClick={() => download(`lanterna-${stamp}.txt`, renderText(scan, analysis, { verbose: true }), 'text/plain;charset=utf-8')} title="Rapporto leggibile da allegare a una segnalazione" aria-label="Esporta rapporto di testo">
                <Icon name="download" /> <span className="btn-label">Rapporto</span>
              </button>
            </>
          )}
          <button className="btn" onClick={() => fileRef.current?.click()} title="Apri un rapporto JSON salvato (anche da Android o ESP32)" aria-label="Importa rapporto JSON">
            <Icon name="upload" /> <span className="btn-label">Importa</span>
          </button>
          <input ref={fileRef} type="file" accept="application/json,.json" hidden onChange={(e) => { const f = e.target.files?.[0]; if (f) onImport(f); e.target.value = ''; }} />
          <button className="btn icon-btn" onClick={() => setTheme(theme === 'dark' ? 'light' : theme === 'light' ? 'auto' : 'dark')} aria-label={`Tema: ${theme}`} title={`Tema: ${theme === 'auto' ? 'automatico' : theme === 'dark' ? 'scuro' : 'chiaro'}`}>
            <Icon name={theme === 'light' ? 'sun' : 'moon'} />
          </button>
        </header>

        {error && <div className="notice" role="alert" style={{ borderColor: 'var(--crit)', marginBottom: 16 }}>{error}</div>}
        {source === 'demo' && agent === null && view !== 'monitor' && (
          <div className="notice" style={{ marginBottom: 16 }}>
            Stai guardando una <b>rete dimostrativa</b>. Per analizzare la tua rete avvia <span className="mono">LANterna.exe</span> su Windows,
            oppure importa un rapporto JSON.
          </div>
        )}

        {busy ? <Scanning progress={progress} /> : props ? (
          <div key={view + (scan?.agent.startedAt ?? '')}>
            {view === 'overview' && <Overview {...props} />}
            {view === 'wifi' && <WifiView {...props} />}
            {view === 'lan' && <LanView {...props} />}
            {view === 'internet' && <InternetView {...props} />}
            {view === 'router' && <RouterView {...props} />}
            {view === 'plan' && <PlanView {...props} />}
            {view === 'monitor' && <MonitorView {...props} />}
            {view === 'guide' && <GuideView {...props} />}
          </div>
        ) : agent === undefined ? <Scanning progress={null} /> : null}
      </main>
    </div>
  );
}
