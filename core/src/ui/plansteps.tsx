import { AppWindow, ClipboardCopy, Monitor, PackageSearch, Router, ShieldAlert, Smartphone } from 'lucide-react';
import { m } from 'motion/react';
import { useCallback, useId, useMemo } from 'react';
import { asStep, stepCmd, stepText, stepVars, windowsMajor } from '../engine';
import type { Action, ActionStep, Scan, StepVars, WinMajor } from '../engine';
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

// Un ottetto senza zeri iniziali: "010" per i browser è ottale (8), quindi un
// indirizzo diverso da quello mostrato.
const OCTET = '(0|[1-9]\\d{0,2})';
const IPV4 = new RegExp(`^${OCTET}\\.${OCTET}\\.${OCTET}\\.${OCTET}$`);

/** Indirizzo IPv4 privato o link-local: solo per questi si offre il pannello del router. */
export function privateIPv4(ip?: string): boolean {
  if (!ip) return false;
  const m4 = IPV4.exec(ip);
  if (!m4) return false;
  const o = [m4[1], m4[2], m4[3], m4[4]].map(Number);
  if (o.some((x) => x > 255)) return false;
  const [a, b] = o;
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254);
}

/** Nota in cima al piano: quale Windows seguono i passi e con i nomi di quale versione. */
export function planWinNote(win?: WinMajor, live = true): string {
  const tail = 'con altri aggiornamenti possono cambiare leggermente.';
  const whose = live ? 'la versione di questo PC' : 'la versione del PC analizzato';
  if (win === 10) return `I passi seguono Windows 10, ${whose}, con i nomi di menu e pulsanti di Windows 10 22H2: ${tail}`;
  if (win === 11) return `I passi seguono Windows 11, ${whose}, con i nomi di menu e pulsanti di Windows 11 24H2: ${tail}`;
  return `I passi seguono Windows 11 e, dove cambia, Windows 10, con i nomi di menu e pulsanti delle versioni 24H2 e 22H2: ${tail}`;
}

/** Una pagina di Windows si offre solo se esiste nella versione del PC (o se la versione non è nota). */
export function toolFor(id: string | undefined, win?: WinMajor) {
  if (!id || id === ROUTER_PANEL) return undefined;
  const w = WINDOWS_TOOLS.find((x) => x.id === id);
  if (!w) return undefined;
  if (w.win && win && w.win !== win) return undefined;
  return w;
}

/**
 * Firma dei passi di un'azione: le spunte si salvano per posizione del passo,
 * quindi valgono solo per gli stessi passi. Se una versione successiva cambia
 * i passi dell'azione, le spunte vecchie non finiscono sul passo sbagliato.
 */
export function stepsSig(a: Action): string {
  const s = JSON.stringify(a.steps);
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h * 33) ^ s.charCodeAt(i)) >>> 0;
  return h.toString(36);
}

/** Dove restano le spunte dei passi di un'azione: una chiave per PC e per azione. */
export const stepsKey = (host: string | undefined, actionId: string) => `polaris.steps.${host ?? 'demo'}.${actionId}`;

function StepCheck({ checked, onChange, label, describedBy }: { checked: boolean; onChange: () => void; label: string; describedBy: string }) {
  return (
    <button className="check small" role="checkbox" aria-checked={checked} aria-label={label} aria-describedby={describedBy} onClick={onChange}>
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
      const done = () => toast('Comando copiato: incollalo nel Prompt dei comandi con Ctrl+V e premi Invio', 'ok', 'tap');
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

// Come aprire il Prompt dei comandi: la stessa strada su Windows 10 e 11 (il nome
// della voce del menu Start per il Terminale cambia tra le versioni). Tra
// virgolette solo ciò che si scrive e le etichette confermate.
export const CMD_HOW = 'Nel Prompt dei comandi: cerca "cmd" nel menu Start e apri il Prompt dei comandi.';
export const CMD_HOW_ADMIN =
  'Nel Prompt dei comandi come amministratore: cerca "cmd" nel menu Start, fai clic con il tasto destro sul Prompt dei comandi e scegli "Esegui come amministratore", poi "Sì".';

function StepBody({ s, win, live, scan, vars, textId }: { s: ActionStep; win?: WinMajor; live: boolean; scan: Scan; vars: StepVars; textId: string }) {
  const toast = useToast();
  const copy = useCopy();
  const tool = toolFor(s.open, win);
  const gw = scan.gateway?.ip;
  const https = !!scan.gateway?.web?.https;
  const router = s.open === ROUTER_PANEL;
  const cmd = stepCmd(s, vars);
  const openWin = (id: string, name: string) =>
    openTool(id, 'app')
      .then(() => toast(`${name} aperto`, 'ok', 'open'))
      .catch((e) => toast(e instanceof Error ? e.message : String(e), 'error'));
  // Quasi tutti i router usano in https un certificato autofirmato: il browser
  // avvisa. Si dice che cosa controllare, senza insegnare a ignorare gli avvisi.
  const openRouter = () =>
    openTool(ROUTER_PANEL, 'site')
      .then(() =>
        toast(
          https
            ? `Pannello del router aperto nel browser. Se il browser avvisa per il certificato, prosegui solo se l'indirizzo è https://${gw}: molti router usano un certificato proprio.`
            : 'Pannello del router aperto nel browser',
          'ok',
          'open',
        ),
      )
      .catch((e) => toast(e instanceof Error ? e.message : String(e), 'error'));
  return (
    <div className="plan-step-body">
      <span className="plan-step-text" id={textId}>
        {stepText(s, win)}
      </span>
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
      {cmd && (
        <>
          <span className="plan-cmd">
            <code>{cmd}</code>
            <button className="btn small" onClick={() => copy(cmd)} aria-label={`Copia il comando ${cmd}`}>
              <ClipboardCopy size={14} aria-hidden /> Copia
            </button>
          </span>
          <span className="faint plan-step-note">{s.admin ? CMD_HOW_ADMIN : CMD_HOW}</span>
        </>
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
            Pannello del router: <code>{https ? 'https' : 'http'}://{gw}</code> nel browser
            {scan.agent.platform === 'demo' ? ' (nella demo il router è immaginario)' : ''}.
          </span>
        ) : null)}
    </div>
  );
}

interface SavedSteps {
  /** Firma dei passi a cui si riferiscono le spunte (stepsSig). */
  v: string;
  /** Posizioni dei passi fatti, nell'elenco completo dell'azione. */
  done: number[];
}

/** I passi di un'azione, guidati per la versione di Windows del PC analizzato. */
export function PlanSteps({ action, scan, live }: { action: Action; scan: Scan; live: boolean }) {
  const win = windowsMajor(scan);
  const vars = useMemo(() => stepVars(scan), [scan]);
  const sig = useMemo(() => stepsSig(action), [action]);
  const uid = useId();
  // Una chiave per azione: ogni azione del piano ha il suo elenco, e scrivendo
  // non si toccano le spunte delle altre.
  const [saved, setSaved] = useLocalState<SavedSteps | null>(stepsKey(scan.agent.host, action.id), null);
  const mine = saved && saved.v === sig && Array.isArray(saved.done) ? saved.done : [];
  const toggle = (i: number) => {
    const next = mine.includes(i) ? mine.filter((x) => x !== i) : [...mine, i];
    setSaved({ v: sig, done: next });
  };
  const steps = useMemo(
    () =>
      action.steps
        .map((raw, i) => ({ s: asStep(raw), i }))
        .filter(({ s }) => !(s.only && win && s.only !== win)),
    [action, win],
  );
  // L'intestazione serve solo se c'è qualcosa da fare in Windows (non per le azioni tutte sul router).
  const anyWin = steps.some(({ s }) => !!s.win10 || (!!s.open && s.open !== ROUTER_PANEL) || !!s.only);
  return (
    <>
      {anyWin && (
        <p className="faint plan-win">
          {win ? `Passi per Windows ${win}, ${live ? 'la versione di questo PC' : 'la versione del PC analizzato'}.` : 'Dove Windows 10 è diverso, il percorso è tra parentesi.'}
          {!live && steps.some(({ s }) => !!s.open) ? ' Con Polaris avviato su Windows i pulsanti aprono direttamente le pagine indicate.' : ''}
        </p>
      )}
      <ol className="steps guided">
        {steps.map(({ s, i }, n) => {
          const checked = mine.includes(i);
          const textId = `${uid}-s${i}`;
          return (
            <li key={i} className={checked ? 'done' : undefined}>
              <StepCheck checked={checked} onChange={() => toggle(i)} label={`Passo ${n + 1} fatto`} describedBy={textId} />
              <StepBody s={s} win={win} live={live} scan={scan} vars={vars} textId={textId} />
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
