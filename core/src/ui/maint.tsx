import { AppWindow, HardDrive, MemoryStick, RefreshCw } from 'lucide-react';
import { m } from 'motion/react';
import { dateIt, failedUpdates, lastQualityUpdate, memDiagPending, wuErrorText } from '../engine';
import type { PcData, ServiceState, Severity, UpdateEntry, Volume } from '../engine';
import { openTool } from './api';
import { SevIcon, TableWrap, useToast } from './components';
import { rise } from './motion';

// Aggiornamenti e controlli di Windows: cronologia di Windows Update con i
// codici spiegati, esito di Diagnostica memoria, file system da controllare.
// Solo letture: le correzioni si fanno da Windows Update, Servizi e chkdsk.

const RESULT: Record<UpdateEntry['result'], [string, Severity]> = {
  succeeded: ['installato', 'ok'],
  succeededWithErrors: ['installato con errori', 'info'],
  failed: ['non riuscito', 'warn'],
  aborted: ['interrotto', 'info'],
  inProgress: ['in corso', 'info'],
  notStarted: ['non iniziato', 'info'],
};
const KIND: Record<UpdateEntry['kind'], string> = { quality: 'aggiornamento', feature: 'nuova versione', driver: 'driver', definition: 'firme di Defender', other: 'altro' };
const START: Record<ServiceState['start'], string> = { auto: 'automatico', delayed: 'automatico (ritardato)', manual: 'manuale', disabled: 'disattivato', unknown: 'non letto' };
const HEALTH: Record<NonNullable<Volume['health']>, [string, Severity]> = {
  healthy: ['sano', 'ok'],
  scan: ['da analizzare', 'info'],
  spotfix: ['serve una correzione rapida', 'warn'],
  repair: ['serve una riparazione completa', 'crit'],
};

function OpenButton({ tool, label, done, live }: { tool: string; label: string; done: string; live: boolean }) {
  const toast = useToast();
  if (!live) return null;
  const open = () =>
    openTool(tool, 'app')
      .then(() => toast(done, 'ok', 'open'))
      .catch((e) => toast(e instanceof Error ? e.message : String(e), 'error'));
  return (
    <button className="btn small" onClick={open}>
      <AppWindow size={15} aria-hidden /> Apri {label}
    </button>
  );
}

function UpdatesPart({ pc, now, live }: { pc: PcData; now: number; live: boolean }) {
  const u = pc.updates;
  if (!u) return <p className="muted">Lo stato degli aggiornamenti non è stato letto.</p>;
  const last = lastQualityUpdate(u, now);
  const failed = failedUpdates(u.history, now);
  const open = failed.filter((f) => !f.resolved);
  const wu = u.service?.wu;
  const rows = (u.history ?? []).filter((e) => e.kind !== 'definition').slice(0, 8);
  return (
    <>
      <dl className="kv hw-kv">
        <dt>Ultimo aggiornamento installato</dt>
        <dd>{last ? `${dateIt(last.date)}${last.kb ? `, ${last.kb}` : ''}` : 'non letto'}</dd>
        <dt>Non riusciti negli ultimi 30 giorni</dt>
        <dd className={open.length ? 'c-warn' : 'c-ok'}>
          <SevIcon sev={open.length ? 'warn' : 'ok'} size={14} /> {open.length ? `${open.length} ancora da installare` : failed.length ? `nessuno (${failed.length} ${failed.length === 1 ? 'risolto' : 'risolti'} in seguito)` : 'nessuno'}
        </dd>
        <dt>Servizio Windows Update</dt>
        <dd className={wu?.start === 'disabled' ? 'c-crit' : undefined}>
          {wu ? `avvio ${START[wu.start]}${wu.running ? ', in esecuzione' : ''}` : 'non letto'}
          {u.policy?.managed ? ' · gestito dall\'organizzazione' : u.policy?.noAutoUpdate ? ' · aggiornamenti automatici spenti dai criteri' : ''}
        </dd>
        {u.pendingReboot && (
          <>
            <dt>Riavvio in sospeso</dt>
            <dd className="c-info">{(u.rebootReasons ?? []).join(', ') || 'sì'}</dd>
          </>
        )}
      </dl>
      {open.length > 0 && (
        <ul className="maint-fails">
          {open.slice(0, 4).map((f, i) => (
            <li key={i}>
              <b>{f.entry.kb || f.entry.title}</b>, {dateIt(f.entry.date)}: errore {wuErrorText(f.entry.hresult)}
            </li>
          ))}
        </ul>
      )}
      {rows.length > 0 && (
        <TableWrap label="Cronologia di Windows Update, senza le firme di Defender">
          <table className="pc-table">
            <thead>
              <tr>
                <th>Data</th>
                <th>Aggiornamento</th>
                <th>Esito</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((e, i) => (
                <tr key={`${e.date}-${i}`}>
                  <td className="mono">{dateIt(e.date)}</td>
                  <td>
                    {e.title}
                    <span className="faint" style={{ display: 'block' }}>
                      {KIND[e.kind]}
                      {e.operation === 'uninstall' ? ', disinstallazione' : ''}
                    </span>
                  </td>
                  <td className={`c-${RESULT[e.result][1]}`}>
                    {RESULT[e.result][0]}
                    {e.hresult && <span className="mono" style={{ display: 'block' }}>{e.hresult}</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
      {u.history === null || u.history === undefined ? (
        <p className="faint card-foot">
          La cronologia di Windows Update non è stata letta{u.historyError ? ` (errore ${wuErrorText(u.historyError)})` : ''}: la data viene dall'elenco degli aggiornamenti installati.
        </p>
      ) : null}
      <div className="maint-actions">
        <OpenButton tool="windows-update-history" label="la cronologia degli aggiornamenti" done="Cronologia degli aggiornamenti aperta" live={live} />
      </div>
    </>
  );
}

// Stessa logica del motore (memDiagPending): un giorno di margine prima di dire
// che il test pianificato non è partito.
function MemDiagPart({ pc, live, now }: { pc: PcData; live: boolean; now: number }) {
  const md = pc.memDiag;
  const last = md?.results[0];
  let sev: Severity = 'unknown';
  let text = 'Il registro di sistema non è stato letto.';
  if (md) {
    const sched = md.lastScheduled ? Date.parse(md.lastScheduled) : NaN;
    const newer = !isNaN(sched) && (!last || sched > Date.parse(last.time));
    if (last?.errors) {
      sev = 'crit';
      text = `Errori hardware trovati il ${dateIt(last.time)}: un modulo di RAM è guasto.`;
    } else if (memDiagPending(md, now)) {
      sev = 'info';
      text = `Test pianificato il ${dateIt(md.lastScheduled!)}, ma l'esito non è registrato: non è partito o è stato interrotto.`;
    } else if (newer) {
      text = `Test pianificato il ${dateIt(md.lastScheduled!)}: parte al prossimo riavvio.${last ? ` Ultimo esito, il ${dateIt(last.time)}: nessun errore.` : ''}`;
    } else if (last) {
      sev = 'ok';
      text = `Ultimo test il ${dateIt(last.time)}: nessun errore.`;
    } else {
      text = `Nessun test registrato nell'ultimo anno.`;
    }
  }
  return (
    <div className="maint-row">
      <span className={`c-${sev}`} style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
        <SevIcon sev={sev} size={15} /> {text}
      </span>
      <span className="spacer" />
      <OpenButton tool="memory-diagnostic" label="Diagnostica memoria Windows" done="Diagnostica memoria Windows aperta" live={live} />
    </div>
  );
}

function FsPart({ pc }: { pc: PcData }) {
  const vols = pc.volumes ?? [];
  const boots = (pc.fsChecks ?? []).filter((c) => c.source === 'wininit');
  if (!vols.length) return null;
  return (
    <>
      <TableWrap label="Stato del file system dei volumi">
        <table className="pc-table">
          <thead>
            <tr>
              <th>Unità</th>
              <th>Da controllare al riavvio</th>
              <th>Stato secondo Windows</th>
            </tr>
          </thead>
          <tbody>
            {vols.map((v) => (
              <tr key={v.letter}>
                <td className="mono">
                  {v.letter}
                  <span className="faint"> {v.kind === 'removable' ? 'rimovibile' : v.system ? 'sistema' : ''}</span>
                </td>
                <td className={v.dirty ? (v.kind === 'removable' ? 'c-info' : 'c-warn') : undefined}>{v.dirty === undefined ? 'non verificabile' : v.dirty ? 'sì' : 'no'}</td>
                <td className={v.health ? `c-${HEALTH[v.health][1]}` : undefined}>{v.health ? HEALTH[v.health][0] : 'non letto'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableWrap>
      <p className="faint card-foot">
        {pc.fsChecks === null || pc.fsChecks === undefined
          ? 'I controlli all\'avvio non sono stati letti.'
          : boots.length
            ? `Controlli del disco all'avvio negli ultimi 30 giorni: ${boots.length}, l'ultimo il ${dateIt(boots[0].time)}${boots[0].drive ? ` su ${boots[0].drive}` : ''}.`
            : 'Nessun controllo del disco all\'avvio negli ultimi 30 giorni.'}{' '}
        Senza amministratore Windows può non rispondere sullo stato da controllare.
      </p>
    </>
  );
}

export function MaintCard({ pc, live, now }: { pc: PcData; live: boolean; now: number }) {
  return (
    <m.section variants={rise} className="card maint-card">
      <div className="card-head">
        <h2 className="disk-title">
          <RefreshCw size={19} aria-hidden /> Aggiornamenti e controlli di Windows
        </h2>
        <span className="sub">Windows Update, test della memoria, file system</span>
      </div>
      <h3 className="dev-h">Windows Update</h3>
      <UpdatesPart pc={pc} now={now} live={live} />
      <h3 className="dev-h">
        <MemoryStick size={16} aria-hidden /> Test della memoria (Diagnostica memoria Windows)
      </h3>
      <MemDiagPart pc={pc} live={live} now={now} />
      <h3 className="dev-h">
        <HardDrive size={16} aria-hidden /> File system
      </h3>
      <FsPart pc={pc} />
      <p className="faint card-foot">
        I significati dei codici di Windows Update vengono dalle pagine Microsoft; i codici non in elenco sono mostrati senza spiegazione. Un test della memoria senza
        errori esclude i guasti evidenti, non quelli intermittenti.
      </p>
    </m.section>
  );
}
