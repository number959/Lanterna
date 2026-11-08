import { AppWindow, ClipboardCopy, Monitor, PackageSearch, Router, ShieldAlert, Smartphone } from 'lucide-react';
import { m } from 'motion/react';
import { useCallback, useMemo } from 'react';
import { asStep, stepText, windowsMajor } from '../engine';
import type { Action, ActionStep, Scan, WinMajor } from '../engine';
import { ACTION_APPS, ROUTER_PANEL, TOOLS, WINDOWS_TOOLS } from '../tools';
import type { ToolView } from '../tools';
import { openTool } from './api';
import { useToast } from './components';
import { useLocalState } from './hooks';
import { spring } from './motion';
import { ToolCard, useOpenTool, useTools } from './toolbox';
import type { View } from './views';

// Passi guidati del piano d'azione: per ogni passo il testo per la versione di
// Windows del PC analizzato, il pulsante che apre la pagina giusta di Windows
// (o il pannello del router), il comando da copiare e le avvertenze; una
// spunta per passo, che resta sul PC. Polaris non esegue nulla da solo: apre
// le pagine e copia i comandi, le modifiche le fa chi usa il PC.

/** Indirizzo IPv4 privato o link-local: solo per questi si offre il pannello del router. */
export function privateIPv4(ip?: string): boolean {
  if (!ip) return false;
  const m4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m4) return false;
  const [a, b] = [Number(m4[1]), Number(m4[2])];
  if ([m4[1], m4[2], m4[3], m4[4]].some((x) => Number(x) > 255)) return false;
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254);
}

/** Una pagina di Windows si offre solo se esiste nella versione del PC (o se la versione non è nota). */
export function toolFor(id: string | undefined, win?: WinMajor) {
  if (!id || id === ROUTER_PANEL) return undefined;
  const w = WINDOWS_TOOLS.find((x) => x.id === id);
  if (!w) return undefined;
  if (w.win && win && w.win !== win) return undefined;
  return w;
}

function StepCheck({ checked, onChange, label }: { checked: boolean; onChange: () => void; label: string }) {
  return (
    <button className="check small" role="checkbox" aria-checked={checked} aria-label={label} onClick={onChange}>
      <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden>
        <rect className="box" x="1.5" y="1.5" width="21" height="21" rx="7" />
        <m.path className="tick" d="M7 12.5l3.4 3.4L17.5 8.6" initial={false} animate={{ pathLength: checked ? 1 : 0, opacity: checked ? 1 : 0 }} transition={spring.snappy} />
      </svg>
    </button>
  );
}

function useCopy() {
  const toast = useToast();
  return useCallback(
    (text: string) => {
      const done = () => toast('Comando copiato: incollalo nel Terminale', 'ok', 'tap');
      const fail = () => toast('Copia non riuscita: seleziona il comando e copialo a mano', 'warn');
      try {
        if (navigator.clipboard?.writeText) navigator.clipboard.writeText(text).then(done, fail);
        else fail();
      } catch {
        fail();
      }
    },
    [toast],
  );
}

function StepBody({ s, win, live, scan }: { s: ActionStep; win?: WinMajor; live: boolean; scan: Scan }) {
  const toast = useToast();
  const copy = useCopy();
  const tool = toolFor(s.open, win);
  const gw = scan.gateway?.ip;
  const router = s.open === ROUTER_PANEL;
  const openWin = (id: string, name: string) =>
    openTool(id, 'app')
      .then(() => toast(`${name} aperto`, 'ok', 'open'))
      .catch((e) => toast(e instanceof Error ? e.message : String(e), 'error'));
  const openRouter = () =>
    openTool(ROUTER_PANEL, 'site')
      .then(() => toast('Pannello del router aperto nel browser', 'ok', 'open'))
      .catch((e) => toast(e instanceof Error ? e.message : String(e), 'error'));
  return (
    <div className="plan-step-body">
      <span className="plan-step-text">{stepText(s, win)}</span>
      {(s.admin || s.where || (s.only && !win)) && (
        <span className="plan-step-tags">
          {s.admin && (
            <span className="tag warn-soft">
              <ShieldAlert size={12} aria-hidden /> serve l&apos;amministratore
            </span>
          )}
          {s.where === 'router' && (
            <span className="tag">
              <Router size={12} aria-hidden /> sul router
            </span>
          )}
          {s.where === 'device' && (
            <span className="tag">
              <Smartphone size={12} aria-hidden /> sul dispositivo
            </span>
          )}
          {s.only && !win && (
            <span className="tag">
              <Monitor size={12} aria-hidden /> solo Windows {s.only}
            </span>
          )}
        </span>
      )}
      {s.cmd && (
        <span className="plan-cmd">
          <code>{s.cmd}</code>
          <button className="btn small" onClick={() => copy(s.cmd!)} aria-label={`Copia il comando ${s.cmd}`}>
            <ClipboardCopy size={14} aria-hidden /> Copia
          </button>
        </span>
      )}
      {tool && live && (
        <span className="chip-actions plan-step-open">
          <button className="btn small primary-soft" onClick={() => openWin(tool.id, tool.name)}>
            <AppWindow size={14} aria-hidden /> Apri {tool.name}
          </button>
        </span>
      )}
      {router &&
        (live && privateIPv4(gw) ? (
          <span className="chip-actions plan-step-open">
            <button className="btn small primary-soft" onClick={openRouter}>
              <Router size={14} aria-hidden /> Apri il pannello del router
            </button>
          </span>
        ) : gw && privateIPv4(gw) ? (
          <span className="faint plan-step-note">
            Pannello del router: <code>{scan.gateway?.web?.https ? 'https' : 'http'}://{gw}</code> nel browser
            {scan.agent.platform === 'demo' ? ' (nella demo il router è immaginario)' : ''}.
          </span>
        ) : null)}
    </div>
  );
}

/** I passi di un'azione, guidati per la versione di Windows del PC analizzato. */
export function PlanSteps({ action, scan, live }: { action: Action; scan: Scan; live: boolean }) {
  const win = windowsMajor(scan);
  const key = `polaris.steps.${scan.agent.host ?? 'demo'}`;
  const [done, setDone] = useLocalState<Record<string, number[]>>(key, {});
  const mine = done[action.id] ?? [];
  const toggle = (i: number) => {
    const next = mine.includes(i) ? mine.filter((x) => x !== i) : [...mine, i];
    setDone({ ...done, [action.id]: next });
  };
  const steps = useMemo(
    () =>
      action.steps
        .map((raw, i) => ({ s: asStep(raw), i }))
        .filter(({ s }) => !(s.only && win && s.only !== win)),
    [action, win],
  );
  const anyWin = steps.some(({ s }) => !!s.win10 || !!s.open || !!s.only);
  return (
    <>
      {anyWin && (
        <p className="faint plan-win">
          {win
            ? `Passi per Windows ${win}, la versione di questo PC${live ? '' : ' secondo il rapporto'}.`
            : 'Dove Windows 10 è diverso, il percorso è tra parentesi.'}
          {!live && steps.some(({ s }) => !!s.open) ? ' Con Polaris avviato su Windows i pulsanti aprono direttamente le pagine indicate.' : ''}
        </p>
      )}
      <ol className="steps guided">
        {steps.map(({ s, i }, n) => {
          const checked = mine.includes(i);
          return (
            <li key={i} className={checked ? 'done' : undefined}>
              <StepCheck checked={checked} onChange={() => toggle(i)} label={`Passo ${n + 1} fatto`} />
              <StepBody s={s} win={win} live={live} scan={scan} />
            </li>
          );
        })}
      </ol>
    </>
  );
}

/** I programmi della cassetta utili per l'azione, con lo stato e il pulsante per aprirli o scaricarli. */
export function PlanApps({ action, live, go }: { action: Action; live: boolean; go: (v: View, focus?: string) => void }) {
  const found = useTools(live);
  const open = useOpenTool();
  const apps = (ACTION_APPS[action.id] ?? []).map((id) => TOOLS.find((t) => t.id === id)).filter((t): t is (typeof TOOLS)[number] => !!t);
  if (!apps.length) return null;
  return (
    <div className="plan-apps">
      <p className="plan-apps-title">
        <PackageSearch size={14} aria-hidden /> <span>Programmi utili per questa azione</span>
      </p>
      <div className="plan-apps-grid">
        {apps.map((t) => (
          <ToolCard key={t.id} t={t} found={found} live={live} onOpen={open} compact onGo={(v: ToolView) => go(v)} />
        ))}
      </div>
    </div>
  );
}
