import { AppWindow, KeyRound, Lock, Printer as PrinterIcon, UserRound } from 'lucide-react';
import { m } from 'motion/react';
import { Fragment } from 'react';
import { dateIt, ENC_PROTECTOR, encText, isRealPrinter, printerProblems, printerText } from '../engine';
import type { Finding, PcData, Severity } from '../engine';
import { openTool } from './api';
import { SevIcon, TableWrap, useToast } from './components';
import { rise } from './motion';

// Protezione dei dati e degli accessi (cifratura, ripristino, backup,
// account, accesso automatico, Desktop remoto, Controllo dell'account
// utente, blocco dello schermo) e stampanti. I giudizi vengono dal motore;
// qui solo la presentazione. Nessun nome di account, nessuna password, mai la
// chiave di ripristino.

function OpenButton({ tool, label, done, live }: { tool: string; label: string; done: string; live: boolean }) {
  const toast = useToast();
  if (!live) return null;
  const open = () =>
    openTool(tool, 'app')
      .then(() => toast(done, 'ok', 'open'))
      .catch((e) => toast(e instanceof Error ? e.message : String(e), 'error'));
  return (
    <button className="btn small" onClick={open}>
      <AppWindow size={15} aria-hidden /> {label}
    </button>
  );
}

function Row({ k, f, fallback }: { k: string; f?: Finding; fallback?: string }) {
  if (!f && !fallback) return null;
  const sev: Severity = f?.severity ?? 'unknown';
  return (
    <Fragment>
      <dt>{k}</dt>
      <dd className={f ? `c-${sev}` : undefined}>
        {f && <SevIcon sev={sev} size={14} />} {f ? f.value : fallback}
      </dd>
    </Fragment>
  );
}

export function ProtectionCard({ pc, findings, live }: { pc: PcData; findings: Finding[]; live: boolean }) {
  const f = (id: string) => findings.find((x) => x.id === id);
  const enc = pc.encryption;
  const os = (enc?.volumes ?? []).filter((v) => v.kind === 'os')[0];
  const others = (enc?.volumes ?? []).filter((v) => v.kind !== 'os');
  const rp = pc.backup?.restorePoints;
  const ib = pc.backup?.imageBackup;
  const acc = pc.accounts;
  const ac = pc.access;
  if (!enc && !pc.backup && !acc && !ac) return null;
  return (
    <m.section variants={rise} className="card protect-card">
      <div className="card-head">
        <h2 className="disk-title">
          <Lock size={19} aria-hidden /> Protezione dei dati e degli accessi
        </h2>
        <span className="sub">cifratura, ripristino, backup, account e accesso al PC</span>
      </div>
      <h3 className="dev-h">
        <KeyRound size={16} aria-hidden /> Cifratura e copie dei dati
      </h3>
      <dl className="kv hw-kv">
        <Row k="Cifratura del disco di sistema" f={f('pc.encryption')} fallback={enc ? (enc.read === 'absent' ? 'BitLocker non presente' : 'non letta') : undefined} />
        {os?.protectors && os.protectors.length > 0 && (
          <>
            <dt>Protezioni della chiave</dt>
            <dd>
              {os.protectors.map((p) => ENC_PROTECTOR[p] ?? p).join(', ')}
              {os.recoveryKeyId ? ` · identificativo della chiave di ripristino ${os.recoveryKeyId}…` : ''}
            </dd>
          </>
        )}
        {others.length > 0 && (
          <>
            <dt>Altri dischi</dt>
            <dd>{others.map((v) => `${v.letter} ${encText(v)}`).join(' · ')}</dd>
          </>
        )}
        <Row k="Punti di ripristino" f={f('pc.restore')} fallback={rp && rp.read === 'denied' ? 'si leggono da amministratore' : undefined} />
        <Row k="Backup" f={f('pc.backup')} />
        {ib?.lastSuccess && (
          <>
            <dt>Backup e ripristino di Windows</dt>
            <dd>
              ultimo riuscito il {dateIt(ib.lastSuccess)}
              {ib.lastFailure ? `, ultimo non riuscito il ${dateIt(ib.lastFailure)}` : ''}
            </dd>
          </>
        )}
      </dl>
      <h3 className="dev-h">
        <UserRound size={16} aria-hidden /> Account e accesso al PC
      </h3>
      <dl className="kv hw-kv">
        <Row k="Account locali" f={f('pc.accounts')} />
        {acc?.local && (
          <>
            <dt>Account predefiniti</dt>
            <dd>
              Administrator integrato {acc.local.some((x) => x.kind === 'builtin-admin' && x.enabled) ? 'attivo' : 'disattivato'} · Guest{' '}
              {acc.local.some((x) => x.kind === 'guest' && x.enabled) ? 'attivo' : 'disattivato'}
            </dd>
          </>
        )}
        <Row k="Accesso automatico" f={f('pc.autologon')} fallback={ac?.autologon ? 'non attivo' : undefined} />
        <Row k="Desktop remoto" f={f('pc.rdp')} fallback={ac?.rdp ? 'non attivo' : undefined} />
        <Row k="Controllo dell'account utente" f={f('pc.uac')} />
        <Row k="Blocco automatico dello schermo" f={f('pc.lock')} />
      </dl>
      <div className="maint-actions">
        <OpenButton tool="device-encryption" label="Apri la crittografia del dispositivo" done="Crittografia del dispositivo aperta" live={live} />
        <OpenButton tool="uac-settings" label="Apri il Controllo dell'account utente" done="Controllo dell'account utente aperto" live={live} />
      </div>
      <p className="faint card-foot">
        Polaris legge le impostazioni di Windows: non prova password, non tenta accessi e non legge mai la chiave di ripristino; i nomi degli account non finiscono nei
        rapporti. Lo stato di BitLocker e i punti di ripristino si leggono solo da amministratore. Non vede i backup fatti con altri programmi o su un NAS.
      </p>
    </m.section>
  );
}

export function PrintersCard({ pc, live }: { pc: PcData; live: boolean }) {
  const pr = pc.printing;
  if (!pr) return null;
  const list = pr.printers ?? [];
  const real = list.filter(isRealPrinter);
  const sp = pr.spooler;
  return (
    <m.section variants={rise} className="card printers-card">
      <div className="card-head">
        <h2 className="disk-title">
          <PrinterIcon size={19} aria-hidden /> Stampanti
        </h2>
        <span className="sub">
          servizio di stampa {sp ? (sp.running ? 'in esecuzione' : sp.start === 'disabled' ? 'disattivato' : 'fermo') : 'non letto'}
          {pr.connections ? ` · ${pr.connections === 1 ? 'una condivisa' : `${pr.connections} condivise`} da altri computer` : ''}
        </span>
        <span className="spacer" />
        <OpenButton tool="printers" label="Apri Stampanti e scanner" done="Stampanti e scanner aperto" live={live} />
      </div>
      {pr.printers === null ? (
        <p className="muted">Le stampanti non sono state lette: il servizio di stampa non risponde.</p>
      ) : list.length === 0 ? (
        <p className="muted">Nessuna stampante installata.</p>
      ) : (
        <TableWrap label="Stampanti installate">
          <table className="pc-table">
            <thead>
              <tr>
                <th>Stampante</th>
                <th>Tipo</th>
                <th>Stato</th>
                <th>Coda</th>
              </tr>
            </thead>
            <tbody>
              {[...real, ...list.filter((p) => !isRealPrinter(p))].map((p) => {
                const bad = printerProblems(p).length > 0 || p.workOffline || !!p.stuck || !!p.jobErrors;
                const sev: Severity = !isRealPrinter(p) ? 'info' : bad ? 'warn' : (p.flags ?? []).indexOf('toner-low') >= 0 ? 'info' : 'ok';
                return (
                  <tr key={p.name}>
                    <td>
                      <b>{p.name}</b>
                      {p.default && <span className="tag accent" style={{ marginLeft: 6 }}>predefinita</span>}
                      {p.driver && <span className="faint" style={{ display: 'block' }}>{p.driver}</span>}
                    </td>
                    <td>{p.kind === 'tcp' ? 'di rete (TCP/IP)' : p.kind === 'wsd' ? 'di rete (WSD)' : p.kind === 'usb' ? 'USB' : p.kind === 'virtual' ? 'virtuale' : 'altro'}</td>
                    <td className={isRealPrinter(p) ? `c-${sev}` : 'faint'}>
                      {isRealPrinter(p) && <SevIcon sev={sev} size={14} />} {printerText(p)}
                    </td>
                    <td>
                      {p.jobs || '—'}
                      {p.oldestMin ? <span className="faint" style={{ display: 'block' }}>il più vecchio da {p.oldestMin} min</span> : null}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </TableWrap>
      )}
      <p className="faint card-foot">
        Lo stato è quello che conosce il servizio di stampa di Windows: una stampante di rete spenta può risultare pronta finché non le si manda un lavoro. Polaris non legge
        mai i titoli dei documenti né i nomi di chi stampa.
      </p>
    </m.section>
  );
}
