import { Activity, AppWindow, Timer } from 'lucide-react';
import { m } from 'motion/react';
import { appHint, bootSample, bootSeverity, bootTypical, dateIt, failText, msText, reliabilityFalling, reliabilitySeverity, SLOW_KIND } from '../engine';
import type { PcData, Reliability, Severity } from '../engine';
import { openTool } from './api';
import { SevIcon, TableWrap, useToast } from './components';
import { rise } from './motion';

// Avvio e affidabilità, come "Impatto di avvio" di Gestione attività e
// Monitoraggio affidabilità: durata dell'avvio misurata da Windows, i
// componenti che la allungano, i programmi che si chiudono da soli e
// l'indice di stabilità. I valori mancanti sono "non misurato", mai zero.

const fmt1 = (v: number) => v.toFixed(1).replace('.', ',');

function Sparkline({ r }: { r: Reliability }) {
  const s = r.series ?? [];
  if (s.length < 2) return null;
  const w = 220;
  const h = 48;
  const pts = s.map((p, i) => [(i / (s.length - 1)) * (w - 4) + 2, h - 2 - (p.index / 10) * (h - 4)] as [number, number]);
  const min = Math.min(...s.map((p) => p.index));
  const max = Math.max(...s.map((p) => p.index));
  return (
    <svg className="rel-spark" viewBox={`0 0 ${w} ${h}`} width={w} height={h} role="img" aria-label={`Indice degli ultimi ${s.length} giorni: da ${fmt1(min)} a ${fmt1(max)}, ultimo ${fmt1(s[s.length - 1].index)}`}>
      <line x1="2" x2={w - 2} y1={h - 2 - 0.8 * (h - 4)} y2={h - 2 - 0.8 * (h - 4)} className="rel-spark-band" />
      <polyline points={pts.map((p) => p.join(',')).join(' ')} fill="none" className="rel-spark-line" />
      <circle cx={pts[pts.length - 1][0]} cy={pts[pts.length - 1][1]} r="3" className="rel-spark-dot" />
    </svg>
  );
}

/** Gravità della durata di un avvio, a parole: il colore da solo non basta. */
const BOOT_WORD: Record<Severity, string> = { ok: 'nella norma', info: 'un po\' lento', warn: 'lento', crit: 'molto lento', unknown: 'non valutato' };

function BootPart({ pc }: { pc: PcData }) {
  const b = pc.boot!;
  const sample = bootSample(b);
  const typical = bootTypical(b);
  const sev: Severity = bootSeverity(typical);
  const last = sample[0];
  const fast = pc.os?.fastStartup === true;
  if (!typical)
    return (
      <p className="muted">
        Durata dell'avvio non misurata:{' '}
        {b.channel === 'denied'
          ? 'il registro con le misure non è leggibile da questo account.'
          : b.channel === 'missing' || b.channel === 'error'
            ? 'il registro con le misure non è disponibile.'
            : `Windows non l'ha registrata negli ultimi ${b.days} giorni. Succede su molti PC con le versioni recenti di Windows${fast ? ' e con Avvio rapido attivo, perché l\'accensione è un ripristino dall\'ibernazione' : ''}.`}
      </p>
    );
  const main = last.mainPathMs ?? 0;
  const post = last.postBootMs ?? 0;
  const tot = Math.max(main + post, 1);
  return (
    <>
      <div className="boot-head">
        <span className={`boot-big c-${sev}`}>
          <SevIcon sev={sev} size={18} /> {msText(typical)}
        </span>
        <span className="faint">mediana degli ultimi {sample.length === 1 ? 'avvio misurato' : `${sample.length} avvii misurati`}</span>
      </div>
      {main + post > 0 && (
        <div className="boot-split" role="img" aria-label={`Ultimo avvio misurato: ${msText(main)} fino al desktop, ${msText(post)} dopo l'accesso`}>
          <span className="boot-main" style={{ width: `${(main / tot) * 100}%` }}>
            fino al desktop {msText(main)}
          </span>
          <span className="boot-post" style={{ width: `${(post / tot) * 100}%` }}>
            dopo l'accesso {msText(post)}
          </span>
        </div>
      )}
      <p className="faint boot-note">
        Ultimo avvio misurato del {dateIt(last.time)}, senza contare i riavvii dopo un aggiornamento
        {last.startupApps ? `, con ${last.startupApps === 1 ? 'un programma' : `${last.startupApps} programmi`} all'avvio` : ''}.
        {b.firmwareMs !== undefined ? ` Firmware prima di Windows (Ultimo tempo BIOS): ${msText(b.firmwareMs)}.` : ''}
        {b.shutdowns?.[0] ? ` Ultimo spegnimento: ${msText(b.shutdowns[0].totalMs)}.` : ''}
      </p>
      <TableWrap label="Ultimi avvii misurati da Windows">
        <table className="pc-table">
          <thead>
            <tr>
              <th>Data</th>
              <th>Totale</th>
              <th>Fino al desktop</th>
              <th>Dopo l'accesso</th>
            </tr>
          </thead>
          <tbody>
            {(b.boots ?? []).slice(0, 6).map((r, i) => (
              <tr key={`${r.time}-${i}`}>
                <td className="mono">
                  {dateIt(r.time)}
                  {r.afterUpdate && (
                    <span className="tag" style={{ marginLeft: 6 }}>
                      dopo un aggiornamento
                    </span>
                  )}
                </td>
                {/* position: relative tiene il testo per i lettori di schermo dentro la tabella che scorre. */}
                <td className={`c-${bootSeverity(r.totalMs)}`} style={{ position: 'relative' }}>
                  <SevIcon sev={bootSeverity(r.totalMs)} size={13} /> {msText(r.totalMs)}
                  <span className="sr-only">, {BOOT_WORD[bootSeverity(r.totalMs)]}</span>
                </td>
                <td>{r.mainPathMs ? msText(r.mainPathMs) : '—'}</td>
                <td>{r.postBootMs ? msText(r.postBootMs) : '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableWrap>
    </>
  );
}

function SlowPart({ pc }: { pc: PcData }) {
  const slow = pc.boot?.slow ?? [];
  if (!slow.length) return <p className="muted">Windows non ha segnalato componenti lenti negli ultimi {pc.boot?.days ?? 90} giorni.</p>;
  return (
    <TableWrap label="Componenti segnalati da Windows come lenti">
      <table className="pc-table">
        <thead>
          <tr>
            <th>Componente</th>
            <th>Tipo</th>
            <th>Ritardo</th>
            <th>Volte</th>
            <th>Ultima volta</th>
          </tr>
        </thead>
        <tbody>
          {slow.slice(0, 10).map((s, i) => (
            <tr key={`${s.name}-${i}`}>
              <td>
                <b>{s.friendly || s.name}</b>
                {s.friendly && <span className="mono faint" style={{ display: 'block' }}>{s.name}</span>}
              </td>
              <td>
                {SLOW_KIND[s.kind] ?? s.kind}
                {s.phase === 'shutdown' ? ', allo spegnimento' : ''}
              </td>
              <td>{s.degradationMs ? `+${msText(s.degradationMs)}` : '—'}</td>
              <td className={s.count >= 3 ? 'c-warn' : undefined} style={{ position: 'relative' }}>
                {s.count >= 3 && <SevIcon sev="warn" size={13} />} {s.count}
                {s.count >= 3 && <span className="sr-only">, si ripete spesso</span>}
              </td>
              <td className="mono">{dateIt(s.last)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </TableWrap>
  );
}

function AppsPart({ pc }: { pc: PcData }) {
  const d = pc.apps!;
  if (d.channel !== 'ok') return <p className="muted">Il registro Applicazione non è stato letto{d.channel === 'denied' ? ': non è leggibile da questo account' : ''}.</p>;
  if (!d.apps.length)
    return (
      <p className="muted" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <SevIcon sev="ok" size={16} className="c-ok" /> Nessun programma si è chiuso da solo o bloccato negli ultimi {d.days} giorni.
      </p>
    );
  return (
    <>
      <TableWrap label="Programmi che si sono chiusi da soli o bloccati">
        <table className="pc-table">
          <thead>
            <tr>
              <th>Programma</th>
              <th>Arresti</th>
              <th>Blocchi</th>
              <th>Ultima volta</th>
              <th>Indizi</th>
            </tr>
          </thead>
          <tbody>
            {d.apps.slice(0, 10).map((a) => (
              <tr key={a.app}>
                <td>
                  <b>{a.app}</b>
                  <span className="faint" style={{ display: 'block' }}>
                    {[a.version, a.system ? 'di Windows' : '', a.store ? 'app dello Store' : '', a.userFolder ? 'installato nella cartella dell\'utente' : ''].filter(Boolean).join(' · ')}
                  </span>
                </td>
                <td>{a.crashes || '—'}</td>
                <td>{a.hangs || '—'}</td>
                <td className="mono">{dateIt(a.last)}</td>
                <td className="faint">{appHint(a) || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableWrap>
      <p className="faint card-foot">
        In totale {failText(d)} in {d.days} giorni.
        {d.wer?.disabled || d.wer?.loggingDisabled ? ' La Segnalazione errori di Windows è disattivata: alcuni arresti possono mancare.' : ''}
        {d.wer?.localDumps ? ' Sono attivi i dump locali dei programmi: i file si accumulano nella cartella CrashDumps.' : ''}
      </p>
    </>
  );
}

function ReliabilityPart({ pc, live }: { pc: PcData; live: boolean }) {
  const toast = useToast();
  const r = pc.reliability!;
  const open = () =>
    openTool('reliability', 'app')
      .then(() => toast('Monitoraggio affidabilità aperto', 'ok', 'open'))
      .catch((e) => toast(e instanceof Error ? e.message : String(e), 'error'));
  const btn = live && (
    <button className="btn small" onClick={open}>
      <AppWindow size={15} aria-hidden /> Apri Monitoraggio affidabilità
    </button>
  );
  if (!r.available || r.index === undefined)
    return (
      <div className="rel-row">
        <p className="muted">
          Indice non disponibile:{' '}
          {r.reason === 'disabled'
            ? 'la raccolta dei dati è disattivata nel registro di Windows.'
            : pc.os?.server
              ? 'su Windows Server è disattivato per impostazione predefinita.'
              : r.reason === 'error'
                ? 'Windows non ha risposto alla lettura.'
                : 'Windows non l\'ha ancora calcolato negli ultimi 30 giorni.'}
        </p>
        {btn}
      </div>
    );
  const sev = reliabilitySeverity(r.index);
  return (
    <div className="rel-row">
      <span className={`boot-big c-${sev}`}>
        <SevIcon sev={sev} size={18} /> {fmt1(r.index)} <span className="faint rel-of">su 10</span>
      </span>
      <Sparkline r={r} />
      <span className="faint">
        {r.indexAt ? `calcolato il ${dateIt(r.indexAt)}` : ''}
        {reliabilityFalling(r) ? ' · in calo rispetto alla settimana prima' : ''}
      </span>
      <span className="spacer" />
      {btn}
    </div>
  );
}

export function StabilityCard({ pc, live }: { pc: PcData; live: boolean }) {
  if (!pc.boot && !pc.apps && !pc.reliability) return null;
  return (
    <m.section variants={rise} className="card stability-card">
      <div className="card-head">
        <h2 className="disk-title">
          <Timer size={19} aria-hidden /> Avvio e affidabilità
        </h2>
        <span className="sub">misure di Windows: avvii, programmi che si chiudono, indice di stabilità</span>
      </div>
      {pc.boot && (
        <>
          <h3 className="dev-h">Durata dell'avvio</h3>
          <BootPart pc={pc} />
          <h3 className="dev-h">Componenti segnalati come lenti</h3>
          <SlowPart pc={pc} />
        </>
      )}
      {pc.apps && (
        <>
          <h3 className="dev-h">Programmi che si chiudono da soli</h3>
          <AppsPart pc={pc} />
        </>
      )}
      {pc.reliability && (
        <>
          <h3 className="dev-h">
            <Activity size={16} aria-hidden /> Indice di stabilità (Monitoraggio affidabilità)
          </h3>
          <ReliabilityPart pc={pc} live={live} />
          <p className="faint card-foot">
            L'indice lo calcola Windows con una formula non pubblicata, dando più peso ai problemi recenti: Polaris lo riporta così com'è.
          </p>
        </>
      )}
      <p className="faint card-foot">
        Letture in sola lettura dai registri eventi di Windows. Dei programmi Polaris mostra solo il nome del file, mai il percorso; non legge identificativi dei
        processi né dei rapporti inviati a Microsoft.
      </p>
    </m.section>
  );
}
