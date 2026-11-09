import { AppWindow, MonitorCog, ShieldCheck } from 'lucide-react';
import { m } from 'motion/react';
import { Fragment, useState } from 'react';
import { dateIt, deviceClassText, deviceProblemDetail, deviceProblemText, deviceSeverity, driverText, symbolicDate, thirdPartyDrivers } from '../engine';
import type { DeviceInfo, DevicesData, PcData, Severity } from '../engine';
import { SevIcon, TableWrap, useToast } from './components';
import { openTool } from './api';
import { rise } from './motion';

// Dispositivi e driver, come Gestione dispositivi: i problemi con il codice
// del riquadro Stato dispositivo, i driver di terze parti dal più vecchio e
// la verifica delle firme. Polaris legge e basta: le correzioni si fanno in
// Gestione dispositivi, con il pulsante che la apre.

/** Driver di terze parti mostrati prima di "Mostra tutti". */
export const DRIVERS_SHOWN = 8;

const SEV_WORD: Record<Severity, string> = { crit: 'grave', warn: 'da risolvere', info: 'da controllare', ok: 'funziona', unknown: 'non letto' };

function ageText(date?: string, now = Date.now()): { text: string; old: boolean } | null {
  if (!date) return null;
  if (symbolicDate(date)) return { text: 'data simbolica', old: false };
  const t = Date.parse(date + 'T00:00:00Z');
  if (isNaN(t)) return null;
  const years = Math.floor((now - t) / (365.25 * 86400000));
  return { text: years < 1 ? 'meno di un anno' : years === 1 ? '1 anno' : `${years} anni`, old: years >= 5 };
}

function ProblemRow({ d }: { d: DeviceInfo }) {
  const sev = deviceSeverity(d);
  return (
    <tr>
      <td>
        <span className={`c-${sev}`} style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
          <SevIcon sev={sev} size={15} /> {SEV_WORD[sev]}
        </span>
      </td>
      <td>
        <b>{d.name}</b>
        <span className="faint" style={{ display: 'block' }}>
          {deviceClassText(d.class)}
          {d.hardwareId ? (
            <>
              {' · '}
              <span className="mono">{d.hardwareId}</span>
            </>
          ) : null}
        </span>
      </td>
      <td>
        <b>{deviceProblemText(d.problem ?? 0)}</b>
        <span className="faint" style={{ display: 'block' }}>
          {deviceProblemDetail(d)}
        </span>
      </td>
      <td className="faint">{d.driver ? driverText(d.driver) : 'nessun driver'}</td>
    </tr>
  );
}

function DriversTable({ dev, now }: { dev: DevicesData; now: number }) {
  const [all, setAll] = useState(false);
  const pkgs = thirdPartyDrivers(dev);
  if (!pkgs.length) return <p className="muted">Nessun driver di terze parti: tutti i dispositivi usano driver inclusi in Windows.</p>;
  const rows = all ? pkgs : pkgs.slice(0, DRIVERS_SHOWN);
  return (
    <>
      <TableWrap label="Driver di terze parti, dal più vecchio">
        <table className="pc-table">
          <thead>
            <tr>
              <th>Driver</th>
              <th>Data</th>
              <th>Usato da</th>
              <th>File</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((p) => {
              const age = ageText(p.date, now);
              return (
                <tr key={p.inf}>
                  <td>
                    <b>{p.provider || 'produttore non indicato'}</b>
                    {p.version && <span className="mono faint" style={{ display: 'block' }}>{p.version}</span>}
                  </td>
                  <td>
                    {p.date ? dateIt(p.date) : '—'}
                    {age && <span className={`tag${age.old ? ' warn-soft' : ''}`} style={{ marginLeft: 6 }}>{age.text}</span>}
                  </td>
                  <td>
                    {p.devices
                      .slice(0, 2)
                      .map((d) => d.name)
                      .join('; ')}
                    {p.devices.length > 2 && <span className="faint"> e altri {p.devices.length - 2}</span>}
                    <span className="faint" style={{ display: 'block' }}>
                      {p.classes.join(', ')}
                    </span>
                  </td>
                  <td className="mono faint">
                    {p.inf}
                    {p.file && <span style={{ display: 'block' }}>{p.file}</span>}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </TableWrap>
      {pkgs.length > DRIVERS_SHOWN && (
        <button className="link-btn" onClick={() => setAll(!all)} aria-expanded={all}>
          {all ? 'Mostra solo i più vecchi' : `Mostra tutti i ${pkgs.length} driver`}
        </button>
      )}
    </>
  );
}

function Signing({ dev, pc }: { dev: DevicesData; pc: PcData }) {
  const ci = dev.codeIntegrity;
  if (!ci) return <p className="faint">Windows non ha comunicato lo stato della verifica delle firme dei driver.</p>;
  const x86 = /^x86$/i.test(pc.os?.arch ?? '');
  const bad: Severity = x86 ? 'warn' : 'crit';
  const rows: [string, string, Severity][] = [
    ['Verifica delle firme in kernel', ci.enabled ? 'attiva' : 'spenta', ci.enabled ? 'ok' : bad],
    ['Modalità test', ci.testSigning ? 'attiva: accetta driver firmati con qualunque certificato' : 'spenta', ci.testSigning ? bad : 'ok'],
    ['Debug del kernel', ci.debugMode ? 'attivo' : 'spento', ci.debugMode ? bad : 'ok'],
    ['Integrità della memoria (Isolamento core)', ci.hvci ? 'attiva' : 'spenta', ci.hvci ? 'ok' : 'info'],
  ];
  return (
    <dl className="kv hw-kv">
      {rows.map(([k, v, s]) => (
        <Fragment key={k}>
          <dt>{k}</dt>
          <dd className={`c-${s}`}>
            <SevIcon sev={s} size={14} /> {v}
          </dd>
        </Fragment>
      ))}
    </dl>
  );
}

export function DevicesCard({ pc, live, now }: { pc: PcData; live: boolean; now: number }) {
  const toast = useToast();
  const dev = pc.devices;
  if (!dev) return null;
  const problems = dev.items.filter((d) => d.problem);
  const rank: Record<Severity, number> = { crit: 0, warn: 1, info: 2, ok: 3, unknown: 4 };
  problems.sort((a, b) => rank[deviceSeverity(a)] - rank[deviceSeverity(b)]);
  const open = () =>
    openTool('device-manager', 'app')
      .then(() => toast('Gestione dispositivi aperta', 'ok', 'open'))
      .catch((e) => toast(e instanceof Error ? e.message : String(e), 'error'));
  return (
    <m.section variants={rise} className="card devices-card">
      <div className="card-head">
        <h2 className="disk-title">
          <MonitorCog size={19} aria-hidden /> Gestione dispositivi
        </h2>
        <span className="sub">
          {dev.total} dispositivi presenti{problems.length ? `, ${problems.length} con problemi` : ', nessun problema'}
        </span>
        <span className="spacer" />
        {live && (
          <button className="btn small" onClick={open}>
            <AppWindow size={15} aria-hidden /> Apri Gestione dispositivi
          </button>
        )}
      </div>
      <h3 className="dev-h">Dispositivi con problemi</h3>
      {problems.length ? (
        <TableWrap label="Dispositivi con problemi">
          <table className="pc-table">
            <thead>
              <tr>
                <th>Stato</th>
                <th>Dispositivo</th>
                <th>Problema</th>
                <th>Driver</th>
              </tr>
            </thead>
            <tbody>
              {problems.map((d, i) => (
                <ProblemRow key={`${d.name}-${i}`} d={d} />
              ))}
            </tbody>
          </table>
        </TableWrap>
      ) : (
        <p className="muted" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <SevIcon sev="ok" size={16} className="c-ok" /> Nessun dispositivo segnala problemi: in Gestione dispositivi non ci sarebbero punti esclamativi.
        </p>
      )}
      <h3 className="dev-h">Driver di terze parti, dal più vecchio</h3>
      <DriversTable dev={dev} now={now} />
      <p className="faint card-foot">
        I driver inclusi in Windows hanno tutti la data 21/06/2006: è una scelta di Microsoft per non scavalcare quelli dei produttori, non vuol dire che siano
        vecchi, e Polaris non li valuta per età. La data dei driver di terze parti è quella dichiarata dal produttore.
      </p>
      <h3 className="dev-h">
        <ShieldCheck size={16} aria-hidden /> Firma dei driver
      </h3>
      <Signing dev={dev} pc={pc} />
      <p className="faint card-foot">
        Lettura in sola lettura con le API di Windows, uguale con e senza amministratore. I nomi dei dispositivi Bluetooth abbinati, dei telefoni, delle
        stampanti e dei dispositivi di rete sono sostituiti da nomi generici; non vengono letti numeri di serie. Per un controllo a mano: <span className="mono">pnputil /enum-devices /problem</span>
        {dev.partial ? '. La lettura non è finita in tempo: l\'elenco può essere incompleto.' : '.'}
      </p>
    </m.section>
  );
}
