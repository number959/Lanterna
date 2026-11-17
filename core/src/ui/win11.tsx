import { BookOpenText, CircleCheck, CircleHelp, CircleMinus, CircleX, Globe, MonitorCheck, TriangleAlert } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { m } from 'motion/react';
import { useState, useSyncExternalStore } from 'react';
import { dateIt, WIN11_STATUS_LABEL, win11CpuRule, win11Requirements } from '../engine';
import type { PcData, Scan, Severity, Win11CPUCheck, Win11Status } from '../engine';
import { checkWin11Cpus } from './api';
import { SevIcon, useOpenGuide, useToast } from './components';
import { rise } from './motion';
import type { ViewProps } from './views';

// Requisiti di Windows 11, come Controllo integrità PC: una riga per
// requisito dal motore (engine/win11.ts), con lo stato a icona e a parole.
// In fondo, su richiesta, il confronto del processore con l'elenco
// ufficiale di Microsoft: il PC scarica la pagina da learn.microsoft.com, la
// legge e la scarta (POST /api/win11/cpus). Polaris non incorpora gli
// elenchi, che non hanno una licenza che ne permetta la copia. Nella demo
// l'esito è simulato con le regole di Polaris e dichiarato.

/** Il PC e l'analisi su cui è partito il confronto: agente per un controllo vero, demo per uno simulato. */
export interface Win11TargetRef {
  host?: string;
  startedAt: string;
  live: boolean;
}

/**
 * L'esito si unisce solo al rapporto su cui è partito il confronto: stesso
 * PC e stessa analisi, dall'agente (o dalla demo per l'esito simulato); mai a
 * un rapporto importato.
 */
export const sameWin11Target = (t: Win11TargetRef | undefined, scan: Scan | null | undefined, source: 'agent' | 'demo' | 'file') =>
  !!t && !!scan && source === (t.live ? 'agent' : 'demo') && t.host === scan.agent.host && t.startedAt === scan.agent.startedAt;

/** Fonte dell'esito simulato nella demo. */
export const DEMO_LIST_SOURCE = 'simulazione della demo';

/** Esito simulato per la demo, dalle regole di Polaris: nessuna pagina letta. */
export function simulatedWin11List(pc: PcData, at = new Date().toISOString()): Win11CPUCheck {
  const name = pc.cpu?.name ?? '';
  const amd = /\bAMD\b|Ryzen|Athlon|EPYC/i.test(name);
  const rule = win11CpuRule(name);
  const result: Win11CPUCheck['result'] = !rule ? 'unknown' : rule.result === 'listed' ? 'listed' : rule.result === 'notListed' || rule.result === 'newer' ? 'notListed' : 'unknown';
  return {
    at,
    source: DEMO_LIST_SOURCE,
    version: amd ? '24H2' : '25H2',
    kind: amd ? 'model' : 'series',
    result,
    ...(result === 'listed' && rule?.series ? { match: rule.series } : {}),
    ...(name ? { cpu: name } : {}),
    ...(result === 'unknown' ? { error: 'nella demo il processore non corrisponde alle regole di Polaris' } : {}),
  };
}

// Il confronto può durare fino a mezzo minuto: lo stato vive fuori da React,
// così cambiando sezione e tornando il pulsante resta occupato.
let running = false;
const subs = new Set<() => void>();
const setRunning = (v: boolean) => {
  running = v;
  subs.forEach((f) => f());
};
const subscribe = (f: () => void) => {
  subs.add(f);
  return () => subs.delete(f);
};
const useRunning = () => useSyncExternalStore(subscribe, () => running, () => running);

const STATUS_ICON: Record<Win11Status, LucideIcon> = { ok: CircleCheck, fail: CircleX, unknown: CircleHelp, na: CircleMinus };
const STATUS_TONE: Record<Win11Status, string> = { ok: 'c-ok', fail: 'c-warn', unknown: 'c-unknown', na: 'faint' };

const whenText = (iso?: string) => {
  if (!iso) return '';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString('it-IT', { dateStyle: 'short', timeStyle: 'short' });
};

const hostOf = (src: string) => {
  const m_ = /^https?:\/\/([^/]+)/i.exec(src);
  return m_ ? m_[1] : '';
};

/** Esito del confronto in una frase, con il tono. */
export function listResultText(l: Win11CPUCheck): { text: string; sev: Severity } {
  const which = `per Windows 11 ${l.version}${l.kind === 'model' ? ' (elenco per modello)' : ' (elenco per serie)'}`;
  if (l.result === 'listed') return { text: `Il processore è nell'elenco ufficiale Microsoft ${which}${l.match ? `: ${l.match}` : ''}.`, sev: 'ok' };
  if (l.result === 'notListed')
    return {
      text: `Il processore non compare nell'elenco ufficiale Microsoft ${which}. Gli elenchi sono pensati per i PC nuovi e Microsoft considera supportate anche le generazioni uscite dopo: la verifica definitiva è Controllo integrità PC.`,
      sev: 'warn',
    };
  return { text: `Confronto non concluso: da verificare con Controllo integrità PC${l.error ? ` (${l.error})` : ''}.`, sev: 'unknown' };
}

function ListResult({ l }: { l: Win11CPUCheck }) {
  const r = listResultText(l);
  const demo = l.source === DEMO_LIST_SOURCE;
  const host = hostOf(l.source);
  return (
    <div className="w11-result" data-sev={r.sev}>
      <p>
        <span className={`c-${r.sev}`}>
          <SevIcon sev={r.sev} size={16} />
        </span>{' '}
        {r.text}
      </p>
      <p className="faint">
        {demo ? 'Esito simulato nella demo: nessuna pagina è stata letta' : `Pagina letta da ${host || l.source}`}
        {l.at ? ` il ${whenText(l.at)}` : ''}
        {l.rows ? ` · ${l.rows} righe nell'elenco` : ''}
        {l.cpu ? ` · processore confrontato: ${l.cpu}` : ''}.
      </p>
    </div>
  );
}

/** Requisiti di Windows 11 come Controllo integrità PC, con il confronto su richiesta con l'elenco ufficiale. */
export function Win11Card({ scan, analysis, live, source, addWin11List }: Pick<ViewProps, 'scan' | 'analysis' | 'live' | 'source' | 'addWin11List'>) {
  const toast = useToast();
  const openGuide = useOpenGuide();
  const busy = useRunning();
  const [error, setError] = useState<string | null>(null);
  const reqs = win11Requirements(scan);
  const pc = scan.pc;
  if (!pc || !reqs.length) return null;
  const f = analysis.findings.find((x) => x.id === 'pc.win11');
  const win10 = !!pc.os && /^Windows 10/.test(pc.os.name);
  const list = pc.win11List;
  const canCheck = (live && source === 'agent') || source === 'demo';

  const check = () => {
    const target: Win11TargetRef = { host: scan.agent.host, startedAt: scan.agent.startedAt, live: source === 'agent' };
    setRunning(true);
    setError(null);
    const p: Promise<Win11CPUCheck> =
      source === 'agent' ? checkWin11Cpus() : new Promise((res) => setTimeout(() => res(simulatedWin11List(pc)), 900));
    p.then(
      (r) => {
        if (!addWin11List(r, target)) return;
        if (r.result === 'listed') toast('Processore trovato nell\'elenco ufficiale Microsoft', 'ok');
        else if (r.result === 'notListed') toast('Processore non presente nell\'elenco ufficiale Microsoft', 'warn');
        else toast('Confronto con l\'elenco ufficiale non concluso: da verificare', 'warn');
      },
      (e) => setError(e instanceof Error ? e.message : String(e)),
    ).finally(() => setRunning(false));
  };

  return (
    <m.section variants={rise} className="card win11-card">
      <div className="card-head">
        <h2 className="disk-title">
          <MonitorCheck size={19} aria-hidden /> Requisiti di Windows 11
        </h2>
        <span className="sub">come Controllo integrità PC</span>
        <span className="spacer" />
        {f && (
          <span className={`sev ${f.severity}`}>
            <SevIcon sev={f.severity} size={14} />
            {f.value}
          </span>
        )}
      </div>
      <p className="muted" style={{ marginTop: 0 }}>
        {win10
          ? 'Per passare a Windows 11 il PC deve rispettare tutti questi requisiti. Polaris li controlla con i dati letti durante l\'analisi; la verifica ufficiale resta quella dell\'app Controllo integrità PC.'
          : 'Windows 11 è già installato: ecco se il PC rispetta i requisiti. Secondo Microsoft un PC installato senza i requisiti non ha garanzia di ricevere gli aggiornamenti, compresi quelli di sicurezza.'}
      </p>

      <ul className="w11-list" aria-label="Requisiti di Windows 11">
        {reqs.map((r) => {
          const I = STATUS_ICON[r.status];
          return (
            <li key={r.id} className="w11-row" data-status={r.status}>
              <span className={`w11-ico ${STATUS_TONE[r.status]}`}>
                <I size={20} strokeWidth={2.1} aria-hidden />
              </span>
              <div className="w11-body">
                <div className="w11-head">
                  <b>{r.label}</b>
                  <span className={`w11-status ${STATUS_TONE[r.status]}`}>{WIN11_STATUS_LABEL[r.status]}</span>
                </div>
                <span className="mono w11-value">{r.value}</span>
                {r.detail && <p className="faint w11-detail">{r.detail}</p>}
              </div>
            </li>
          );
        })}
      </ul>

      <div className="w11-official">
        <h3 className="dev-h">
          <Globe size={16} aria-hidden /> Elenco ufficiale dei processori supportati
        </h3>
        {list ? (
          <ListResult l={list} />
        ) : (
          <p className="muted">
            {canCheck
              ? 'Non ancora controllato. Polaris non contiene gli elenchi di Microsoft: si leggono dal sito solo se lo chiedi.'
              : 'Questo rapporto non contiene il confronto con l\'elenco ufficiale.'}
          </p>
        )}
        {error && (
          <div className="notice alert" role="alert" style={{ margin: '10px 0' }}>
            <TriangleAlert size={18} aria-hidden />
            <span>Confronto non riuscito: {error}</span>
          </div>
        )}
        {canCheck && (
          <div className="w11-check">
            <button className="btn small" onClick={check} disabled={busy} aria-describedby="w11-check-note">
              <Globe size={15} className={busy ? 'spin' : undefined} aria-hidden />
              {busy ? 'Lettura dell\'elenco in corso…' : list ? 'Controlla di nuovo nell\'elenco ufficiale Microsoft' : 'Controlla nell\'elenco ufficiale Microsoft'}
            </button>
            <p id="w11-check-note" className="faint">
              {source === 'demo'
                ? 'Nella demo l\'esito è simulato con le regole di Polaris: nessuna pagina viene letta e non serve Internet.'
                : 'Solo quando premi il pulsante, questo PC scarica da learn.microsoft.com la pagina di Microsoft con l\'elenco dei processori del produttore del tuo processore, la legge e confronta il nome del processore. La pagina non viene salvata: resta solo l\'esito, che entra nel rapporto. Serve Internet.'}
            </p>
          </div>
        )}
        {source === 'file' && list && <p className="faint">Rapporto importato: l'esito è quello salvato con il rapporto.</p>}
      </div>

      <div className="crash-actions">
        {openGuide && (
          <button className="link-btn" onClick={() => openGuide('requisiti-windows-11')}>
            <BookOpenText size={15} aria-hidden /> Come si leggono i requisiti
          </button>
        )}
      </div>
      <p className="faint card-foot">
        Gli elenchi di Microsoft sono pensati per i produttori di PC nuovi e cambiano a ogni versione: un processore assente non è per forza escluso, e
        Windows Update decide con famiglia, modello e stepping, non con il nome. Controllo integrità PC non controlla scheda video e schermo; Polaris
        non verifica DirectX 12.{pc.win11?.appraiser?.at ? ` Verdetto di Windows Update calcolato il ${dateIt(pc.win11.appraiser.at.slice(0, 10))}.` : ''}
      </p>
    </m.section>
  );
}
