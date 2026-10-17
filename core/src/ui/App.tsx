import {
  Activity,
  BookOpen,
  Building2,
  FileJson,
  FileText,
  Globe,
  Info,
  LayoutDashboard,
  ListChecks,
  Moon,
  Network,
  OctagonX,
  RefreshCw,
  Router,
  Sun,
  SunMoon,
  Upload,
  Wifi,
  type LucideIcon,
} from 'lucide-react';
import { AnimatePresence, LazyMotion, MotionConfig, domMax, m, useReducedMotion, useScroll, useTransform } from 'motion/react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { MouseEvent, ReactNode } from 'react';
import { analyze, ENGINE_VERSION, primaryAdapter, renderText } from '../engine';
import type { AnswerValue, InfraData, Scan, Severity } from '../engine';
import { clinicScan } from '../demo/clinic';
import { demoScan } from '../demo/sample';
import { agentInfo, download, isScan, lastScan, runScan } from './api';
import type { AgentInfo, Progress } from './api';
import { BrandLogo, BrandSymbol } from './brand';
import { GuideLinkContext, Segmented, ToastProvider, useToast } from './components';
import { setFxPref, useFx } from './fx';
import { useLocalState } from './hooks';
import { InfraView } from './infra';
import { useMonitor } from './monitor';
import { ease, page, spring } from './motion';
import { ScanOrbit } from './scan';
import { useTheme } from './theme';
import type { ThemePref } from './theme';
import { GuideView } from './guides';
import { InternetView, LanView, MonitorView, Overview, PlanView, RouterView, WifiView } from './views';
import type { AssessmentState, GatewayMacChange, View, ViewProps } from './views';

type Source = 'agent' | 'demo' | 'file';
type DemoKind = 'home' | 'clinic';
const DEMOS: Record<DemoKind, Scan> = { home: demoScan, clinic: clinicScan };

const NAV: { id: View; label: string; short: string; icon: LucideIcon; cats?: string[] }[] = [
  { id: 'overview', label: 'Panoramica', short: 'Sintesi', icon: LayoutDashboard },
  { id: 'wifi', label: 'Wi-Fi', short: 'Wi-Fi', icon: Wifi, cats: ['wifi'] },
  { id: 'lan', label: 'Rete locale', short: 'LAN', icon: Network, cats: ['lan'] },
  { id: 'internet', label: 'Internet e DNS', short: 'Internet', icon: Globe, cats: ['internet', 'dns'] },
  { id: 'router', label: 'Router e sicurezza', short: 'Router', icon: Router, cats: ['router', 'security'] },
  { id: 'infra', label: 'Infrastruttura', short: 'Infra', icon: Building2, cats: ['infra'] },
  { id: 'plan', label: "Piano d'azione", short: 'Piano', icon: ListChecks },
  { id: 'monitor', label: 'Monitor', short: 'Monitor', icon: Activity },
  { id: 'guide', label: 'Guida', short: 'Guida', icon: BookOpen },
];

const RANK: Record<Severity, number> = { unknown: 0, ok: 1, info: 2, warn: 3, crit: 4 };

const THEME_NEXT: Record<ThemePref, ThemePref> = { auto: 'dark', dark: 'light', light: 'auto' };
const THEME_LABEL: Record<ThemePref, string> = { auto: 'automatico', dark: 'scuro', light: 'chiaro' };
const THEME_ICON: Record<ThemePref, LucideIcon> = { auto: SunMoon, dark: Moon, light: Sun };

/** Le scorciatoie da tastiera non devono scattare mentre si scrive. */
const typing = (t: EventTarget | null) =>
  t instanceof HTMLElement && (t.isContentEditable || t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT');

/** Mette il cursore nella ricerca della guida appena la pagina è montata. */
function focusSearch() {
  const t0 = performance.now();
  const attempt = () => {
    const el = document.querySelector<HTMLInputElement>('[data-search]');
    if (el) el.focus();
    else if (performance.now() - t0 < 1500) requestAnimationFrame(attempt);
  };
  requestAnimationFrame(attempt);
}

/**
 * Confronta il MAC del router con quello dell'ultima analisi reale fatta su
 * questo PC per la stessa rete. Il ricordo si aggiorna solo con un'analisi più
 * recente, così riaprire la stessa analisi mostra di nuovo l'eventuale cambio.
 */
function gatewayMacMemory(scan: Scan): GatewayMacChange | undefined {
  const gw = scan.gateway;
  if (!gw?.mac) return undefined;
  const net = scan.wifi?.connected?.ssid ?? primaryAdapter(scan)?.name ?? '';
  const key = `polaris.gwmac.${gw.ip}.${net}`;
  const at = scan.agent.startedAt;
  try {
    const rec = JSON.parse(localStorage.getItem(key) ?? 'null') as { mac: string; at: string; prevMac?: string; prevAt?: string } | null;
    const changed = (r: typeof rec) => (r?.prevMac && r.prevAt && r.prevMac !== r.mac ? { prev: r.prevMac, prevAt: r.prevAt, now: r.mac } : undefined);
    if (rec && rec.at === at) return changed(rec);
    if (rec && rec.at > at) return undefined; // analisi più vecchia riaperta: niente confronto
    const next = { mac: gw.mac, at, ...(rec ? { prevMac: rec.mac, prevAt: rec.at } : {}) };
    localStorage.setItem(key, JSON.stringify(next));
    return changed(next);
  } catch {
    return undefined;
  }
}

/** Avviso che si apre e si chiude in altezza invece di spostare il contenuto a scatti. */
function Collapse({ children }: { children: ReactNode }) {
  return (
    <m.div
      initial={{ height: 0, opacity: 0 }}
      animate={{ height: 'auto', opacity: 1, transition: { height: spring.smooth, opacity: { duration: 0.3, delay: 0.05 } } }}
      exit={{ height: 0, opacity: 0, transition: { height: { duration: 0.28, ease: ease.inOut }, opacity: { duration: 0.15 } } }}
      style={{ overflow: 'hidden' }}
    >
      <div style={{ paddingBottom: 16 }}>{children}</div>
    </m.div>
  );
}

export default function App() {
  // LazyMotion "strict" impedisce di usare per sbaglio i componenti motion.*
  // completi; MotionConfig applica "riduci movimento" del sistema a tutte le
  // animazioni di trasformazione e layout.
  return (
    <LazyMotion features={domMax} strict>
      <MotionConfig reducedMotion="user">
        <ToastProvider>
          <Shell />
        </ToastProvider>
      </MotionConfig>
    </LazyMotion>
  );
}

function Shell() {
  const toast = useToast();
  const reduce = useReducedMotion();
  const [agent, setAgent] = useState<AgentInfo | null | undefined>(undefined);
  const [scan, setScan] = useState<Scan | null>(null);
  const [source, setSource] = useState<Source>('demo');
  const [view, setView] = useState<View>('overview');
  const [focus, setFocus] = useState<string | undefined>();
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<Progress | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [slow, setSlow] = useState(false);
  const [demoKind, setDemoKind] = useLocalState<DemoKind>('polaris.demo', 'home');
  const [theme, setTheme] = useTheme();
  const fx = useFx();
  const fileRef = useRef<HTMLInputElement>(null);
  const viewRef = useRef(view);
  const focusRef = useRef<string | undefined>(undefined);
  const { scrollY } = useScroll();
  const barOpacity = useTransform(scrollY, [0, 48], [0, 1]);

  // La schermata "collegamento all'agente" compare solo se la risposta tarda:
  // senza agente (demo) l'interfaccia parte subito senza lampi.
  useEffect(() => {
    const t = setTimeout(() => setSlow(true), 350);
    return () => clearTimeout(t);
  }, []);

  const scanNow = useCallback(async () => {
    setBusy(true);
    setError(null);
    setProgress(null);
    try {
      const s = await runScan(setProgress);
      // Inventario e verifiche della stessa rete restano validi: si conservano (con la loro data).
      setScan((prev) => (prev && !s.infra && prev.infra && prev.gateway?.ip === s.gateway?.ip && prev.agent.platform === s.agent.platform ? { ...s, infra: { ...prev.infra, assessment: undefined } } : s));
      setSource('agent');
      viewRef.current = 'overview';
      focusRef.current = undefined;
      setView('overview');
      setFocus(undefined);
      toast('Analisi completata');
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setError(msg);
      toast(`Analisi non riuscita: ${msg}`, 'error');
    } finally {
      setBusy(false);
    }
  }, [toast]);

  useEffect(() => {
    (async () => {
      const info = await agentInfo();
      setAgent(info);
      if (!info) {
        setScan(DEMOS[demoKind] ?? demoScan);
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
    // Solo all'avvio: la scelta della demo si cambia poi con il selettore.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanNow]);

  // Autovalutazione: le risposte restano sul PC, separate per contesto (demo o rete aziendale).
  const assessKey = scan ? `polaris.assessment.${source === 'demo' ? `demo-${scan.agent.host ?? ''}` : scan.agent.domain || scan.agent.host || 'pc'}` : 'polaris.assessment.none';
  const [answers, setAnswers] = useLocalState<Record<string, AnswerValue>>(assessKey, {});
  const fileAssessment = source === 'file' ? scan?.infra?.assessment : undefined;
  const assessment = useMemo<AssessmentState>(
    () => ({
      answers: fileAssessment?.answers ?? answers,
      readOnly: !!fileAssessment,
      set: (id, v) => {
        const next = { ...answers };
        if (v) next[id] = v;
        else delete next[id];
        setAnswers(next);
      },
      reset: () => setAnswers({}),
    }),
    [answers, setAnswers, fileAssessment],
  );
  // Il rapporto (analisi, JSON, testo) contiene anche l'autovalutazione, se compilata.
  const effective = useMemo<Scan | null>(() => {
    if (!scan || fileAssessment) return scan;
    const has = Object.keys(answers).length > 0;
    if (!has && !scan.infra?.assessment) return scan;
    const infra: InfraData = { ...scan.infra };
    if (has) infra.assessment = { answers, updatedAt: new Date().toISOString() };
    else delete infra.assessment;
    return { ...scan, infra };
  }, [scan, answers, fileAssessment]);
  const setInfra = useCallback((patch: Partial<InfraData>) => setScan((s) => (s ? { ...s, infra: { ...s.infra, ...patch } } : s)), []);

  const analysis = useMemo(() => (effective ? analyze(effective) : null), [effective]);
  const live = source === 'agent' && !!agent;
  // Il monitor misura la rete attuale: reale se l'agente è collegato, anche mentre si guarda un rapporto importato.
  const monitor = useMonitor(!!agent);
  const gwMacChange = useMemo(() => (scan && source === 'agent' ? gatewayMacMemory(scan) : undefined), [scan, source]);

  const go = useCallback(
    (v: View, f?: string) => {
      // Stessa sezione: si torna solo in cima. Sezione diversa: lo scorrimento
      // avviene a pagina uscita (onExitComplete), così non si vede saltare.
      if (v === viewRef.current && !f) window.scrollTo({ top: 0, behavior: reduce ? 'auto' : 'smooth' });
      viewRef.current = v;
      focusRef.current = f;
      setView(v);
      setFocus(f);
    },
    [reduce],
  );

  const openGuide = useCallback((id: string) => go('guide', `g:${id}`), [go]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.ctrlKey || e.metaKey || e.altKey || typing(e.target)) return;
      if (e.key >= '1' && e.key <= '9') {
        e.preventDefault();
        go(NAV[Number(e.key) - 1].id);
      } else if (e.key === '/') {
        e.preventDefault();
        go('guide');
        focusSearch();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [go]);

  const current = NAV.find((n) => n.id === view)!;
  useEffect(() => {
    document.title = `${current.label} · STARNET Polaris`;
  }, [current]);

  const onImport = async (file: File) => {
    try {
      let data: unknown;
      try {
        data = JSON.parse(await file.text());
      } catch {
        throw new Error('il file non contiene JSON valido');
      }
      if (!isScan(data)) throw new Error('il file non è un rapporto di STARNET Polaris');
      setScan(data);
      setSource('file');
      setError(null);
      go('overview');
      toast(`Rapporto importato${data.agent.host ? ` · ${data.agent.host}` : ''}`);
    } catch (e) {
      toast(`Importazione non riuscita: ${e instanceof Error ? e.message : e}`, 'error');
    }
  };

  const stamp = scan ? scan.agent.startedAt.replace(/[:T]/g, '-').slice(0, 16) : '';
  const save = (name: string, content: string, type: string) => {
    download(name, content, type);
    toast(`Download avviato · ${name}`);
  };
  const onTheme = (e: MouseEvent<HTMLButtonElement>) => {
    const r = e.currentTarget.getBoundingClientRect();
    setTheme(THEME_NEXT[theme], { x: r.left + r.width / 2, y: r.top + r.height / 2 });
  };
  const navDot = (cats?: string[]) => {
    if (!cats || !analysis) return undefined;
    let worst: Severity = 'ok';
    for (const c of analysis.categories) if (cats.includes(c.category) && RANK[c.worst] > RANK[worst]) worst = c.worst;
    return worst === 'crit' || worst === 'warn' ? worst : undefined;
  };
  const scanning = busy || (agent === undefined && slow);
  const props: ViewProps | null =
    effective && analysis ? { scan: effective, analysis, go, focus, live, source, setInfra, assessment, monitor, gwMacChange } : null;
  const pickDemo = (k: DemoKind) => {
    setDemoKind(k);
    setScan(DEMOS[k]);
    setSource('demo');
    setError(null);
  };
  const ThemeIcon = THEME_ICON[theme];

  return (
    <GuideLinkContext.Provider value={openGuide}>
      <a className="skip-link" href="#main">Vai al contenuto</a>
      <div className="backdrop" aria-hidden="true">
        <div className="glow g1" />
        <div className="glow g2" />
        <div className="glow g3" />
        <div className="hexgrid" />
        {[1, 2, 3, 4, 5, 6].map((i) => (
          <span key={i} className={`spark s${i}`} />
        ))}
      </div>

      <div className="app">
        <aside className="sidebar">
          {/* Logo completo nella versione del tema (bianco sui fondi scuri, a colori sui chiari) e nome del prodotto. */}
          <div className="brand">
            <BrandLogo width={112} intro title="STARNET" />
            <span className="brand-product">Polaris</span>
          </div>
          <nav className="nav" aria-label="Sezioni">
            {NAV.map((n, i) => {
              const dot = navDot(n.cats);
              const on = view === n.id;
              const I = n.icon;
              return (
                <button key={n.id} className="nav-item" aria-current={on ? 'page' : undefined} onClick={() => go(n.id)} title={`${n.label} (tasto ${i + 1})`}>
                  {on && <m.span layoutId="nav-pill" className="nav-pill" transition={spring.snappy} />}
                  <I size={18} strokeWidth={on ? 2.2 : 1.9} aria-hidden />
                  <span className="nav-label">{n.label}</span>
                  <span className="nav-short" aria-hidden="true">{n.short}</span>
                  {dot && <span className={`dot ${dot}`} role="img" aria-label={dot === 'crit' ? 'problemi critici' : 'avvisi'} />}
                  {n.id === 'monitor' && monitor.running && !on && <span className="dot live" role="img" aria-label="monitor attivo" />}
                </button>
              );
            })}
          </nav>
          <div className="sidebar-foot">
            <span>{agent ? `Agente ${agent.platform} v${agent.version}` : 'Nessun agente collegato'}</span>
            <span>Motore v{ENGINE_VERSION}</span>
            <span className="keys">
              <kbd>1</kbd>–<kbd>9</kbd> sezioni · <kbd>/</kbd> cerca
            </span>
            <button
              className="fx-toggle"
              role="switch"
              aria-checked={fx.lite}
              onClick={() => setFxPref(fx.lite ? 'full' : 'lite')}
              title="Toglie sfocature, trasparenze e bagliori animati: utile su macchine virtuali, in desktop remoto o su PC senza accelerazione grafica"
            >
              <span className="track" aria-hidden="true">
                <m.span className="thumb" layout transition={spring.snappy} />
              </span>
              Grafica leggera{fx.auto ? ' (automatica)' : ''}
            </button>
          </div>
        </aside>

        <main id="main" className="main" tabIndex={-1}>
          <header className="topbar">
            <m.div className="topbar-bg" style={{ opacity: barOpacity }} aria-hidden="true" />
            {/* Su mobile la barra laterale diventa la barra in basso: il simbolo resta qui. */}
            <span className="mobile-mark" aria-hidden="true">
              <BrandSymbol size={30} />
            </span>
            <AnimatePresence mode="wait" initial={false}>
              <m.h1
                key={view}
                className="page-title"
                initial={{ opacity: 0, y: 10, ...(fx.lite ? {} : { filter: 'blur(4px)' }) }}
                animate={{ opacity: 1, y: 0, ...(fx.lite ? {} : { filter: 'blur(0px)' }), transition: { duration: 0.32, ease: ease.out } }}
                exit={{ opacity: 0, y: -8, ...(fx.lite ? {} : { filter: 'blur(4px)' }), transition: { duration: 0.14, ease: ease.inOut } }}
              >
                {current.label}
              </m.h1>
            </AnimatePresence>
            {scan && (
              <span className={`source ${source}`}>
                {source === 'file' ? <FileJson size={13} aria-hidden /> : <span className="live" aria-hidden />}
                {source === 'demo' ? 'DEMO · dati dimostrativi' : source === 'file' ? `File importato · ${scan.agent.host ?? ''}` : `${scan.agent.host ?? 'questo PC'}`}
                {' · '}
                {new Date(scan.agent.startedAt).toLocaleString('it-IT', { dateStyle: 'short', timeStyle: 'short' })}
              </span>
            )}
            <span className="spacer" />
            <div className="actions">
              {agent && (
                <button className="btn primary" onClick={scanNow} disabled={busy} aria-label={busy ? 'Analisi in corso' : 'Nuova analisi'}>
                  <RefreshCw size={16} className={busy ? 'spin' : undefined} aria-hidden />
                  <span className="btn-label">{busy ? 'Analisi…' : 'Nuova analisi'}</span>
                </button>
              )}
              {scan && analysis && (
                <>
                  <button
                    className="btn"
                    onClick={() => save(`polaris-${stamp}.json`, JSON.stringify(effective ?? scan, null, 2), 'application/json')}
                    title="Salva i dati grezzi: potrai riaprirli o confrontarli"
                    aria-label="Esporta JSON"
                  >
                    <FileJson size={16} aria-hidden /> <span className="btn-label">JSON</span>
                  </button>
                  <button
                    className="btn"
                    onClick={() => save(`polaris-${stamp}.txt`, renderText(effective ?? scan, analysis, { verbose: true }), 'text/plain;charset=utf-8')}
                    title="Rapporto leggibile da allegare a una segnalazione"
                    aria-label="Esporta rapporto di testo"
                  >
                    <FileText size={16} aria-hidden /> <span className="btn-label">Rapporto</span>
                  </button>
                </>
              )}
              <button className="btn" onClick={() => fileRef.current?.click()} title="Apri un rapporto JSON salvato (anche da Android o ESP32)" aria-label="Importa rapporto JSON">
                <Upload size={16} aria-hidden /> <span className="btn-label">Importa</span>
              </button>
              <input
                ref={fileRef}
                type="file"
                accept="application/json,.json"
                hidden
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) onImport(f);
                  e.target.value = '';
                }}
              />
              <button className="btn icon" onClick={onTheme} aria-label={`Tema ${THEME_LABEL[theme]}: passa a ${THEME_LABEL[THEME_NEXT[theme]]}`} title={`Tema: ${THEME_LABEL[theme]}`}>
                <AnimatePresence mode="popLayout" initial={false}>
                  <m.span
                    key={theme}
                    style={{ display: 'flex' }}
                    initial={{ rotate: -90, scale: 0.4, opacity: 0 }}
                    animate={{ rotate: 0, scale: 1, opacity: 1 }}
                    exit={{ rotate: 90, scale: 0.4, opacity: 0 }}
                    transition={spring.snappy}
                  >
                    <ThemeIcon size={17} aria-hidden />
                  </m.span>
                </AnimatePresence>
              </button>
            </div>
          </header>

          <AnimatePresence initial={false}>
            {error && (
              <Collapse key="error">
                <div className="notice alert" role="alert">
                  <OctagonX size={18} aria-hidden />
                  <span>{error}</span>
                </div>
              </Collapse>
            )}
            {source === 'demo' && agent === null && view !== 'monitor' && (
              <Collapse key="demo">
                <div className="notice">
                  <Info size={18} aria-hidden />
                  <span>
                    Stai guardando una <b>rete dimostrativa</b>. Per analizzare la tua rete avvia <span className="mono">Polaris.exe</span> su
                    Windows, oppure importa un rapporto JSON.
                  </span>
                  <span className="demo-pick">
                    <Segmented<DemoKind>
                      label="Rete dimostrativa"
                      value={demoKind}
                      onChange={pickDemo}
                      options={[
                        { id: 'home', label: 'Casa' },
                        { id: 'clinic', label: 'Clinica' },
                      ]}
                    />
                  </span>
                </div>
              </Collapse>
            )}
          </AnimatePresence>

          <AnimatePresence
            mode="wait"
            onExitComplete={() => {
              if (!focusRef.current) window.scrollTo({ top: 0 });
            }}
          >
            {scanning ? (
              <m.div
                key="scan"
                initial={{ opacity: 0, scale: 0.97 }}
                animate={{ opacity: 1, scale: 1, transition: { duration: 0.5, ease: ease.out } }}
                exit={{ opacity: 0, scale: 1.03, transition: { duration: 0.25, ease: ease.inOut } }}
              >
                <ScanOrbit progress={busy ? progress : null} connecting={!busy} />
              </m.div>
            ) : props ? (
              <m.div key={`${view}|${source}|${props.scan.agent.startedAt}`} variants={page} initial="hidden" animate="show" exit="exit">
                {view === 'overview' && <Overview {...props} />}
                {view === 'wifi' && <WifiView {...props} />}
                {view === 'lan' && <LanView {...props} />}
                {view === 'internet' && <InternetView {...props} />}
                {view === 'router' && <RouterView {...props} />}
                {view === 'infra' && <InfraView {...props} />}
                {view === 'plan' && <PlanView {...props} />}
                {view === 'monitor' && <MonitorView {...props} />}
                {view === 'guide' && <GuideView {...props} />}
              </m.div>
            ) : null}
          </AnimatePresence>
        </main>
      </div>
    </GuideLinkContext.Provider>
  );
}
