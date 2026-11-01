import { BookOpenText, MonitorX, RefreshCw, ShieldAlert, TriangleAlert } from 'lucide-react';
import { m } from 'motion/react';
import { useState } from 'react';
import { bugcheckInfo, CRASH_DUMP_TYPE, CRASH_LIMITED, crashRead, crashSetting, culpritHow, lastBugcheckEvent, noCulpritText, parseBugcheckEvent, sizeText } from '../engine';
import type { BugcheckInfo, CrashData, CrashDump, Scan, Severity } from '../engine';
import { readCrashes } from './api';
import { SevIcon, useOpenGuide, useToast } from './components';
import { rise } from './motion';
import type { ViewProps } from './views';

// Schermate blu, come BlueScreenView: l'agente legge durante l'analisi i
// minidump (da amministratore) e le impostazioni dei dump; senza privilegi
// restano il codice e i parametri dell'evento 1001. Polaris legge soltanto:
// non cambia impostazioni e non sposta file.

/** Il PC e l'analisi su cui è partita una nuova lettura. */
export interface CrashTargetRef {
  host?: string;
  startedAt: string;
}

/**
 * Una nuova lettura si unisce solo al rapporto dell'agente dello stesso PC e
 * della stessa analisi: mai a una demo o a un rapporto importato.
 */
export const sameCrashTarget = (t: CrashTargetRef | undefined, scan: Scan | null | undefined, source: 'agent' | 'demo' | 'file') =>
  !!t && !!scan && source === 'agent' && t.host === scan.agent.host && t.startedAt === scan.agent.startedAt;

/** Minidump mostrati prima di "Mostra tutti". */
export const CRASH_SHOWN = 6;

const whenText = (iso?: string) => {
  if (!iso) return '';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString('it-IT', { dateStyle: 'short', timeStyle: 'short' });
};
const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

/** Gravità e testo del riquadro di un file: icona e parola, mai solo il colore. */
export function crashBadge(d: CrashDump): { sev: Severity; label: string } {
  if (d.error) return { sev: 'unknown', label: 'file non letto' };
  if (!crashRead(d)) return { sev: 'unknown', label: 'codice non scritto' };
  if (bugcheckInfo(d.code).family === 'manual') return { sev: 'info', label: 'arresto provocato' };
  return { sev: 'warn', label: 'schermata blu' };
}

function Params({ params, label }: { params?: string[]; label: string }) {
  const ps = params && params.length ? params : [];
  if (!ps.length) return <span className="faint">non scritti</span>;
  return (
    <ol className="crash-plist" aria-label={label}>
      {ps.map((p, i) => (
        <li key={i}>
          <span className="faint">P{i + 1}</span> <code className="mono">{p || '—'}</code>
        </li>
      ))}
    </ol>
  );
}

function CodeLine({ info }: { info: BugcheckInfo }) {
  return (
    <>
      <p className="crash-code">
        <code className="mono">{info.code || '—'}</code>
        <b>{info.name ?? 'codice non presente nell\'elenco di Polaris'}</b>
      </p>
      <p className="crash-meaning">
        {info.meaning ? `${cap(info.meaning)}.` : 'Cercalo nella documentazione Microsoft dei codici di arresto (Bug Check Code Reference).'}
      </p>
    </>
  );
}

function CrashItem({ d, title }: { d: CrashDump; title?: string }) {
  const info = bugcheckInfo(d.code);
  const badge = crashBadge(d);
  const when = d.time ? whenText(d.time) : d.modified ? `${whenText(d.modified)} (data del file)` : 'data non scritta nel file';
  const p = d.probable;
  const others = (d.stack ?? []).filter((x) => !p || x.toLowerCase() !== p.driver.toLowerCase());
  return (
    <li className="cert-item crash-item" data-sev={badge.sev}>
      <div className="cert-head">
        <span className="cert-name">
          <strong>{title ?? when}</strong>
          <span className="mono faint">{title ? `${d.file} · ${when}` : d.file}</span>
        </span>
        <span className={`sev ${badge.sev}`}>
          <SevIcon sev={badge.sev} size={14} />
          {badge.label}
        </span>
      </div>
      {d.error ? (
        <p className="cert-fail">Non letto: {d.error}.</p>
      ) : (
        <>
          {info.code ? <CodeLine info={info} /> : <p className="crash-meaning">Codice non scritto nel file.</p>}
          <dl className="cert-facts">
            <div>
              <dt>Driver indicato (indizio)</dt>
              <dd>
                {p ? (
                  <>
                    <b className="mono">{p.driver}</b>{' '}
                    <span className="faint">
                      {culpritHow(p)}
                      {p.unloaded ? ', già scaricato al momento dell\'arresto' : ''}
                    </span>
                  </>
                ) : (
                  noCulpritText(d)
                )}
              </dd>
            </div>
            {others.length > 0 && (
              <div>
                <dt>Altri moduli nello stack</dt>
                <dd className="mono">{others.join(', ')}</dd>
              </div>
            )}
            <div>
              <dt>File</dt>
              <dd>
                {CRASH_DUMP_TYPE[d.dumpType ?? 'unknown']} · {sizeText(d.size)}
                {d.build ? ` · build ${d.build}` : ''}
                {d.machine ? ` · ${d.machine}` : ''}
              </dd>
            </div>
            {d.limited && (
              <div>
                <dt>Lettura</dt>
                <dd>{cap(CRASH_LIMITED[d.limited])}</dd>
              </div>
            )}
            <div className="crash-params">
              <dt>Parametri</dt>
              <dd>
                <Params params={d.params} label={`Parametri di ${d.file}`} />
              </dd>
            </div>
          </dl>
        </>
      )}
    </li>
  );
}

function Settings({ c }: { c: CrashData }) {
  const s = c.settings;
  const off = s?.dumpEnabled === 0;
  const yes = (b?: boolean) => (b === undefined ? 'non letto' : b ? 'sì' : 'no');
  return (
    <dl className="cert-facts crash-settings">
      <div>
        <dt>Salvataggio dopo una schermata blu</dt>
        <dd>
          {off ? (
            <span className="sev warn">
              <SevIcon sev="warn" size={14} />
              nessun file: le prossime non lasceranno un file da esaminare
            </span>
          ) : (
            cap(crashSetting(s))
          )}
        </dd>
      </div>
      <div>
        <dt>Cartella dei minidump</dt>
        <dd className="mono">{s?.minidumpDir ?? (s ? '%SystemRoot%\\Minidump' : 'non letta')}</dd>
      </div>
      <div>
        <dt>Riavvio automatico</dt>
        <dd>{yes(s?.autoReboot)}</dd>
      </div>
      <div>
        <dt>Evento nel registro di sistema</dt>
        <dd>{yes(s?.logEvent)}</dd>
      </div>
    </dl>
  );
}

export function CrashesCard({ scan, live, source, addCrashes }: ViewProps) {
  const toast = useToast();
  const openGuide = useOpenGuide();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [all, setAll] = useState(false);
  const pc = scan.pc;
  const c = pc?.crashes;
  const ev = lastBugcheckEvent(pc?.events);
  const evData = parseBugcheckEvent(ev?.detail);
  const dumps = c?.dumps ?? [];
  const read = dumps.filter(crashRead);
  const shown = all ? dumps : dumps.slice(0, CRASH_SHOWN);
  const canRead = live && source === 'agent';
  // Lettura fermata dall'agente prima di leggere un file (tempo scaduto): o
  // prima di arrivare alla cartella (nessuna impostazione), o dopo averla
  // elencata (total > 0 ma nessun file letto).
  const unfinished = !!c && !!c.partial && !dumps.length;

  const refresh = () => {
    const target: CrashTargetRef = { host: scan.agent.host, startedAt: scan.agent.startedAt };
    setBusy(true);
    setError(null);
    readCrashes()
      .then(
        (r) => {
          if (!addCrashes(r, target)) return;
          const n = r.dumps.filter(crashRead).length;
          if (r.needsAdmin && !n) toast('File delle schermate blu non leggibili: serve avviare Polaris come amministratore', 'warn');
          else toast(n ? `Schermate blu rilette · ${n} ${n === 1 ? 'file' : 'file'}` : 'Schermate blu rilette · nessun file', 'ok');
        },
        (e) => setError(e instanceof Error ? e.message : String(e)),
      )
      .finally(() => setBusy(false));
  };

  return (
    <m.section variants={rise} className="card crash-card">
      <div className="card-head">
        <h2 className="disk-title">
          <MonitorX size={19} aria-hidden /> File delle schermate blu
        </h2>
        <span className="sub">minidump letti da Polaris, come BlueScreenView</span>
      </div>
      <p className="muted" style={{ marginTop: 0 }}>
        Dopo una schermata blu Windows salva un file con il codice di arresto e lo stato del sistema. Polaris lo legge senza programmi esterni e indica il
        driver sospetto: un indizio, non una certezza.
      </p>

      {!c && (
        <div className="notice">
          <TriangleAlert size={18} aria-hidden />
          <span>
            Questo rapporto non contiene la lettura dei file delle schermate blu: è stato creato con una versione precedente di Polaris oppure la lettura
            non è riuscita.{canRead ? ' Puoi leggerli ora.' : ''}
          </span>
        </div>
      )}

      {unfinished && (
        <div className="notice">
          <TriangleAlert size={18} aria-hidden />
          <span>
            {c!.folder === 'ok' && c!.total > 0
              ? `Nella cartella dei minidump ci sono ${c!.total} file, ma la lettura non è finita in tempo durante l'analisi.`
              : "La lettura dei file delle schermate blu non è finita in tempo durante l'analisi."}
            {canRead ? ' Puoi leggerli ora.' : ''}
          </span>
        </div>
      )}

      {c?.needsAdmin && (
        <div className="notice warn crash-admin">
          <ShieldAlert size={18} aria-hidden />
          <span>
            <b>Per leggere i file delle schermate blu serve avviare Polaris come amministratore.</b> Chiudi Polaris, fai clic con il tasto destro su Polaris e
            scegli "Esegui come amministratore", poi ripeti l'analisi.{evData ? ' Intanto, qui sotto, ciò che dice il registro eventi.' : ''}
          </span>
        </div>
      )}

      {ev && evData && (!c || !read.length) && (
        <div className="crash-event">
          <h3>Dal registro eventi</h3>
          <p className="faint crash-event-when">
            Evento 1001 (BugCheck) del {whenText(ev.last)}
            {ev.count > 1 ? `, l'ultimo di ${ev.count}` : ''}
            {pc?.eventsDays ? ` negli ultimi ${pc.eventsDays} giorni` : ''}
          </p>
          <CodeLine info={bugcheckInfo(evData.code)} />
          <dl className="cert-facts">
            <div className="crash-params">
              <dt>Parametri</dt>
              <dd>
                <Params params={evData.params} label="Parametri dell'evento 1001" />
              </dd>
            </div>
          </dl>
        </div>
      )}

      {c && !(unfinished && !c.folder) && <Settings c={c} />}

      {c && !c.needsAdmin && !unfinished && !dumps.length && (
        <p className="crash-empty">
          {c.folder === 'error' ? <SevIcon sev="unknown" size={16} className="c-unknown" /> : <SevIcon sev="ok" size={16} className="c-ok" />}
          <span>
            {c.folder === 'missing'
              ? 'Nessun file di schermata blu: la cartella dei minidump non esiste, quindi Windows non ne ha salvati (o sono stati cancellati).'
              : c.folder === 'error'
                ? 'Nessun file letto: la cartella dei minidump non si è potuta leggere.'
                : 'Nessun file di schermata blu nella cartella dei minidump.'}
          </span>
        </p>
      )}

      {dumps.length > 0 && (
        <div style={{ marginTop: 18 }}>
          <h3>
            Minidump · {c!.total} {c!.total === 1 ? 'file' : 'file'}
            {c!.total > dumps.length ? `, letti i ${dumps.length} più recenti` : ''}
            {c!.partial ? ' · lettura interrotta' : ''}
          </h3>
          <ul className="cert-list crash-list" aria-label="File delle schermate blu, dal più recente">
            {shown.map((d, i) => (
              <CrashItem key={`${d.file}-${i}`} d={d} />
            ))}
          </ul>
          {dumps.length > CRASH_SHOWN && (
            <button className="btn small" onClick={() => setAll(!all)} aria-expanded={all}>
              {all ? 'Mostra solo i più recenti' : `Mostra tutti (${dumps.length})`}
            </button>
          )}
        </div>
      )}

      {c?.memoryDump && (
        <ul className="cert-list crash-list" aria-label="Dump della memoria" style={{ marginTop: 14 }}>
          <CrashItem d={c.memoryDump} title="Dump della memoria (MEMORY.DMP)" />
        </ul>
      )}

      {error && (
        <div className="notice alert" role="alert" style={{ marginTop: 12 }}>
          <TriangleAlert size={18} aria-hidden />
          <span>Lettura non riuscita: {error}</span>
        </div>
      )}

      <div className="crash-actions">
        {canRead && (
          <button className="btn small" onClick={refresh} disabled={busy}>
            <RefreshCw size={15} className={busy ? 'spin' : undefined} aria-hidden />
            {busy ? 'Lettura in corso…' : c && !unfinished ? 'Rileggi i file' : 'Leggi i file'}
          </button>
        )}
        {openGuide && (
          <button className="link-btn" onClick={() => openGuide('minidump-schermate-blu')}>
            <BookOpenText size={15} aria-hidden /> Come leggere i minidump
          </button>
        )}
      </div>
      <p className="faint card-foot">
        {dumps.length > 0 || c?.memoryDump
          ? 'Il driver indicato è un indizio: Polaris non usa i simboli di debug e non ricostruisce lo stack completo come WinDbg. '
          : ''}
        Polaris legge soltanto: non cambia le impostazioni e non sposta né cancella i file. Date e ore nel fuso orario di questo dispositivo.
      </p>
    </m.section>
  );
}
