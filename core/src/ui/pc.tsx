import {
  BookOpenText,
  CircleStop,
  Cpu,
  Eye,
  Gauge as GaugeIcon,
  HardDrive,
  History,
  Lock,
  Monitor,
  Play,
  ScrollText,
  Trash2,
  TriangleAlert,
  Usb,
} from 'lucide-react';
import { AnimatePresence, m, useReducedMotion } from 'motion/react';
import { Fragment, useEffect, useState } from 'react';
import { BUGCHECKS, STATUS_LABEL, attrState, bytesText, dateIt, diskStatus, isFlashDisk, smartId, smartName, smartRaw } from '../engine';
import type { AttrState, CpuBench, DiskBench, EventGroup, EventKind, Finding, NVMeHealth, PcData, PhysicalDisk, Scan, Severity, StartupItem, Volume } from '../engine';
import { simulatedCpuBench, simulatedDiskBench } from '../demo/simulate';
import { guideById } from '../guides';
import { benchStatus, runBench, stopBench } from './api';
import type { BenchRequest } from './api';
import { FindingList, SevIcon, Stat, TableWrap, fmtNum, sevColor, useOpenGuide, useToast } from './components';
import { useWidth } from './hooks';
import { cascade, ease, rise, spring } from './motion';
import { Section } from './views';
import type { ViewProps } from './views';

// Sezione Computer: lo stato del PC da cui parte l'analisi. Tutto ciò che si
// vede è letto in sola lettura durante l'analisi; i test di velocità partono
// solo su richiesta e, senza agente, sono simulati e dichiarati come tali.

const PC_GUIDES = ['pc-come-funziona', 'dischi-hdd-ssd', 'salute-dischi-smart', 'test-velocita', 'pc-lento-metodo'];

const gb = (v: number) => `${fmtNum(v, v < 10 ? 1 : 0)} GB`;
const mbs = (v: number) => `${fmtNum(v, v < 10 ? 1 : 0)} MB/s`;
const thousands = (n: number) => String(Math.round(n)).replace(/\B(?=(\d{3})+(?!\d))/g, '.');
const when = (iso?: string) => {
  if (!iso) return '';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString('it-IT', { dateStyle: 'short', timeStyle: 'short' });
};
/** Nome del processore senza marchi e frequenza: "Intel Core i5-1135G7". */
export const shortCpu = (name: string) =>
  name
    .replace(/\((R|TM)\)/gi, '')
    .replace(/\b\d+(th|st|nd|rd) Gen\b/i, '')
    .replace(/\bCPU\b/, '')
    .replace(/\s*@.*$/, '')
    .replace(/\s+/g, ' ')
    .trim();
const isFlash = (d: PhysicalDisk) => d.media === 'ssd' || d.media === 'scm';
const isUsbDisk = (d?: PhysicalDisk) => !!d && /usb/i.test(d.bus ?? '');
const MEDIA: Record<PhysicalDisk['media'], string> = { ssd: 'SSD', hdd: 'Disco meccanico (HDD)', scm: 'Memoria persistente', unknown: 'Tipo non dichiarato' };

export function PcView(props: ViewProps) {
  const { scan, analysis: a, go } = props;
  const pc = scan.pc;
  const findings = a.findings.filter((f) => f.id.startsWith('pc.'));
  return (
    <>
      <PcIntro scan={scan} />

      {!pc && (
        <m.div variants={rise} className="notice" style={{ marginTop: 16 }}>
          <TriangleAlert size={18} aria-hidden />
          <span>
            Questo rapporto non contiene i dati del computer: è stato creato con una versione precedente di Polaris o da una sonda che non li raccoglie.
          </span>
        </m.div>
      )}
      {pc?.notes && pc.notes.length > 0 && (
        <m.div variants={rise} className="notice" style={{ marginTop: 16 }}>
          <TriangleAlert size={18} aria-hidden />
          <ul style={{ margin: 0, paddingLeft: 18 }}>
            {pc.notes.map((n, i) => (
              <li key={i}>{n}</li>
            ))}
          </ul>
        </m.div>
      )}

      {findings.length > 0 && (
        <Section title="Valutazione">
          <FindingList findings={findings} onAction={(id) => go('plan', id)} />
        </Section>
      )}

      {pc && ((pc.disks?.length ?? 0) > 0 || (pc.volumes?.length ?? 0) > 0) && (
        <Section title="Dischi e spazio">
          <DisksGrid pc={pc} findings={a.findings} elevated={scan.agent.elevated} />
        </Section>
      )}

      <Section title="Test di velocità">
        <BenchCard {...props} />
      </Section>

      {pc && (pc.startup || pc.processes) && (
        <Section title="Avvio e processi">
          <m.div className="grid cols-2" variants={cascade(0.06)}>
            {pc.startup && <StartupCard items={pc.startup} />}
            {pc.processes && <ProcessesCard pc={pc} />}
          </m.div>
        </Section>
      )}

      {pc?.eventsDays ? (
        <Section title={`Eventi degli ultimi ${pc.eventsDays} giorni`}>
          <EventsCard pc={pc} />
        </Section>
      ) : null}

      {pc && (
        <Section title="Dettagli del sistema">
          <SystemDetails pc={pc} />
        </Section>
      )}
    </>
  );
}

function PcIntro({ scan }: { scan: Scan }) {
  const openGuide = useOpenGuide();
  const pc = scan.pc;
  const os = pc?.os;
  const guides = PC_GUIDES.map(guideById).filter((g) => g !== undefined);
  const parts = [
    os ? `${os.name}${os.version ? ` ${os.version}` : ''}` : '',
    pc?.cpu?.name ? shortCpu(pc.cpu.name) : '',
    pc?.memory ? `${gb(pc.memory.totalMB / 1024)} di RAM` : '',
    pc?.disks?.find((d) => d.system) ? `${MEDIA[pc.disks.find((d) => d.system)!.media].replace(' (HDD)', '')} di sistema` : '',
  ].filter(Boolean);
  return (
    <m.section variants={rise} className="card infra-intro">
      <span className="infra-mark" aria-hidden>
        <Monitor size={26} />
      </span>
      <div style={{ minWidth: 0 }}>
        <h2>{scan.agent.host ?? 'Questo computer'}</h2>
        <p className="muted">{parts.length ? parts.join(' · ') : 'Dati del computer non disponibili.'}</p>
        <ul className="infra-rules" aria-label="Come vengono raccolti i dati">
          <li>
            <Eye size={14} aria-hidden /> Solo letture, nessuna impostazione modificata
          </li>
          <li>
            <Lock size={14} aria-hidden /> I dati restano sul PC
          </li>
          <li>
            <GaugeIcon size={14} aria-hidden /> Test di velocità solo su richiesta
          </li>
        </ul>
        {openGuide && guides.length > 0 && (
          <p className="plan-guides">
            <BookOpenText size={14} aria-hidden />
            <span>Approfondisci:</span>
            {guides.map((g) => (
              <button key={g.id} className="link-btn" onClick={() => openGuide(g.id)}>
                {g.title}
              </button>
            ))}
          </p>
        )}
      </div>
    </m.section>
  );
}

// ---------------------------------------------------------------- Dischi

function Gauge({ label, value, frac, marks, sev, sub }: { label: string; value: string; frac: number; marks: number[]; sev: Severity; sub?: string }) {
  const reduce = useReducedMotion();
  return (
    <div className="dgauge">
      <div className="dgauge-head">
        <span>{label}</span>
        <b className={`mono c-${sev}`}>{value}</b>
      </div>
      <span className="meter dgauge-meter" role="img" aria-label={`${label}: ${value}`}>
        <m.i
          style={{ background: sevColor(sev) }}
          initial={{ scaleX: reduce ? Math.min(1, frac) : 0 }}
          animate={{ scaleX: Math.max(0.02, Math.min(1, frac)) }}
          transition={spring.gentle}
        />
        {marks.map((x) => (
          <span key={x} className="mark" style={{ left: `${x * 100}%` }} />
        ))}
      </span>
      {sub && <span className="dgauge-sub">{sub}</span>}
    </div>
  );
}

function VolumeBar({ v, finding }: { v: Volume; finding?: Finding }) {
  const reduce = useReducedMotion();
  const used = v.sizeGB > 0 ? 1 - v.freeGB / v.sizeGB : 0;
  const sev: Severity = finding?.severity ?? (v.kind === 'removable' ? 'unknown' : 'ok');
  return (
    <div className="vol">
      <div className="vol-head">
        <b className="mono">{v.letter}</b>
        <span className="vol-name">
          {v.label || (v.system ? 'Windows' : 'Volume')}
          {v.fs ? ` · ${v.fs}` : ''}
          {v.kind === 'removable' ? ' · rimovibile' : ''}
        </span>
        <span className={`mono vol-free c-${sev === 'ok' || sev === 'unknown' ? 'unknown' : sev}`}>
          {gb(v.freeGB)} liberi su {gb(v.sizeGB)}
        </span>
      </div>
      <span className="meter vol-meter" role="img" aria-label={`${v.letter} occupato al ${Math.round(used * 100)} %`}>
        <m.i style={{ background: sev === 'ok' || sev === 'unknown' ? 'linear-gradient(90deg, var(--primary-b), var(--primary-a))' : sevColor(sev) }} initial={{ scaleX: reduce ? used : 0 }} animate={{ scaleX: used }} transition={spring.gentle} />
      </span>
    </div>
  );
}

function DisksGrid({ pc, findings, elevated }: { pc: PcData; findings: Finding[]; elevated?: boolean }) {
  const disks = (pc.disks ?? []).filter((d) => d.sizeGB > 0);
  const volFinding = (v: Volume) => findings.find((f) => f.id === `pc.space.${v.letter.replace(':', '')}`);
  const orphan = (pc.volumes ?? []).filter((v) => !disks.some((d) => d.id !== undefined && d.id === v.disk));
  return (
    <m.div className="grid cols-2" variants={cascade(0.06)}>
      {disks.map((d, i) => (
        <DiskCard key={d.id ?? i} d={d} finding={findings.find((f) => f.id === `pc.disk.${d.id ?? i}`)} vols={(pc.volumes ?? []).filter((v) => v.disk === d.id)} volFinding={volFinding} elevated={elevated} />
      ))}
      {orphan.length > 0 && (
        <m.section variants={rise} className="card">
          <div className="card-head">
            <h2 className="disk-title">
              <HardDrive size={19} aria-hidden /> {disks.length ? 'Altre unità' : 'Unità'}
            </h2>
          </div>
          {orphan.map((v) => (
            <VolumeBar key={v.letter} v={v} finding={volFinding(v)} />
          ))}
        </m.section>
      )}
    </m.div>
  );
}

function DiskCard({ d, finding, vols, volFinding, elevated }: { d: PhysicalDisk; finding?: Finding; vols: Volume[]; volFinding: (v: Volume) => Finding | undefined; elevated?: boolean }) {
  const sev: Severity = finding?.severity ?? 'unknown';
  const r = d.reliability;
  const nv = d.nvme;
  const st = diskStatus(d);
  const flash = isFlashDisk(d);
  const temp = st.temperatureC;
  const tempSev: Severity = temp === undefined ? 'unknown' : flash ? (temp >= 80 ? 'crit' : temp >= 70 ? 'warn' : 'ok') : temp >= 60 ? 'crit' : temp >= 55 ? 'warn' : 'ok';
  const wear = st.wearPct;
  const wearSev: Severity = wear === undefined ? 'unknown' : wear >= 90 ? 'crit' : wear >= 70 ? 'warn' : 'ok';
  const uncorrected = r && (r.readUncorrected !== undefined || r.writeUncorrected !== undefined) ? (r.readUncorrected ?? 0) + (r.writeUncorrected ?? 0) : undefined;
  const hasData = !!r || !!nv || (d.smart ?? []).length > 0;
  const Icon = isUsbDisk(d) ? Usb : HardDrive;
  return (
    <m.section variants={rise} className="card disk-card" style={{ ['--disk-tint' as string]: sevColor(sev) }}>
      <div className="card-head">
        <h2 className="disk-title">
          <Icon size={19} aria-hidden /> <span>{d.name}</span>
        </h2>
        <span className="spacer" />
        <span className={`sev ${sev}`} title="Stato secondo Windows e i dati SMART, come in CrystalDiskInfo">
          <SevIcon sev={sev} size={14} />
          {STATUS_LABEL[sev]}
          {st.lifePct !== undefined && <span className="mono">{fmtNum(st.lifePct)} %</span>}
        </span>
      </div>
      <div className="chips-row">
        <span className="tag accent">{MEDIA[d.media]}</span>
        {d.bus && <span className="tag">{d.bus}</span>}
        <span className="tag">{gb(d.sizeGB)}</span>
        {d.spindleRpm ? <span className="tag">{thousands(d.spindleRpm)} giri/min</span> : null}
        {d.system && <span className="tag">Windows</span>}
      </div>
      {hasData ? (
        <>
          {(temp !== undefined || wear !== undefined) && (
            <div className="dgauges">
              {temp !== undefined && (
                <Gauge
                  label="Temperatura"
                  value={`${fmtNum(temp)} °C`}
                  frac={temp / (flash ? 90 : 70)}
                  marks={flash ? [70 / 90, 80 / 90] : [55 / 70, 60 / 70]}
                  sev={tempSev}
                  sub={r?.temperatureMaxC ? `Massima registrata ${fmtNum(r.temperatureMaxC)} °C` : undefined}
                />
              )}
              {wear !== undefined && (
                <Gauge
                  label="Usura"
                  value={`${fmtNum(wear)} %`}
                  frac={Math.min(wear, 100) / 100}
                  marks={[0.7, 0.9]}
                  sev={wearSev}
                  sub={`Vita residua stimata ${fmtNum(st.lifePct ?? 0)} %`}
                />
              )}
            </div>
          )}
          <dl className="kv disk-kv">
            {st.powerOnHours !== undefined && (
              <>
                <dt>Ore di accensione</dt>
                <dd>
                  {thousands(st.powerOnHours)} ({fmtNum(st.powerOnHours / 8760, 1)} anni continuativi)
                </dd>
              </>
            )}
            {st.powerCycles !== undefined && (
              <>
                <dt>Accensioni</dt>
                <dd>{thousands(st.powerCycles)}</dd>
              </>
            )}
            {nv && (
              <>
                <dt>Dati scritti / letti</dt>
                <dd>
                  {bytesText(nv.dataWrittenGB)} / {bytesText(nv.dataReadGB)}
                </dd>
              </>
            )}
            {uncorrected !== undefined && (
              <>
                <dt>Errori non correggibili</dt>
                <dd className={uncorrected ? 'c-warn' : undefined}>{uncorrected}</dd>
              </>
            )}
            {r?.readErrors !== undefined && (
              <>
                <dt>Errori di lettura registrati</dt>
                <dd>{thousands(r.readErrors)}</dd>
              </>
            )}
            {r?.startStopCycles !== undefined && (
              <>
                <dt>Avvii del motore</dt>
                <dd>{thousands(r.startStopCycles)}</dd>
              </>
            )}
            {r?.loadUnloadCycles !== undefined && (
              <>
                <dt>Parcheggi della testina</dt>
                <dd>{thousands(r.loadUnloadCycles)}</dd>
              </>
            )}
            {d.firmware && (
              <>
                <dt>Firmware</dt>
                <dd>{d.firmware}</dd>
              </>
            )}
          </dl>
          {nv && <NVMeLog nv={nv} />}
          {(d.smart ?? []).length > 0 && <SmartTable d={d} />}
        </>
      ) : (
        <p className="faint disk-hint">
          {elevated === false
            ? 'Temperatura, usura ed errori (dati SMART) compaiono avviando Polaris come amministratore: clic destro su Polaris.exe > Esegui come amministratore.'
            : 'Il disco non espone i dati SMART (succede con molti box USB e controller RAID).'}
        </p>
      )}
      {vols.length > 0 && (
        <div className="vols">
          {vols.map((v) => (
            <VolumeBar key={v.letter} v={v} finding={volFinding(v)} />
          ))}
        </div>
      )}
    </m.section>
  );
}

const ATTR_CLASS: Record<AttrState, string> = { fail: 'c-crit', past: 'c-info', caution: 'c-warn', ok: '' };
const ATTR_LABEL: Record<AttrState, string> = { fail: 'alla soglia di guasto o sotto', past: 'in passato alla soglia di guasto', caution: 'conteggio da tenere d\'occhio', ok: '' };

const stateSev = (s: AttrState): Severity => (s === 'fail' ? 'crit' : s === 'caution' ? 'warn' : 'info');

/**
 * Attributi SMART con le stesse colonne di CrystalDiskInfo. Nelle schede
 * strette (telefono) la tabella diventa un elenco: sei colonne non ci stanno
 * e lo scorrimento laterale nasconderebbe proprio soglia e dato grezzo.
 */
function SmartTable({ d }: { d: PhysicalDisk }) {
  const attrs = d.smart ?? [];
  const flash = isFlashDisk(d);
  const flagged = attrs.filter((a) => attrState(a) !== 'ok').length;
  const [ref, width] = useWidth<HTMLDetailsElement>();
  const narrow = width > 0 && width < 460;
  return (
    <details ref={ref} className="smart-box" open={flagged > 0 || undefined}>
      <summary>
        <ScrollText size={15} aria-hidden /> Attributi SMART ({attrs.length})
        {flagged > 0 && <span className="tag smart-flag">{flagged} da guardare</span>}
      </summary>
      {narrow ? (
        <ul className="smart-list" aria-label={`Attributi SMART di ${d.name}`}>
          {attrs.map((a) => {
            const state = attrState(a);
            return (
              <li key={a.id} className={state !== 'ok' ? `smart-${state}` : undefined}>
                <div className={`smart-li-head ${ATTR_CLASS[state]}`}>
                  <span className="mono">{smartId(a.id)}</span>
                  <span>
                    {state !== 'ok' && <SevIcon sev={stateSev(state)} size={13} />} {smartName(a.id, flash)}
                    {state !== 'ok' && <span className="sr-only"> ({ATTR_LABEL[state]})</span>}
                  </span>
                </div>
                <div className="smart-li-vals mono">
                  <span>attuale {a.current}</span>
                  <span>peggiore {a.worst}</span>
                  <span>soglia {a.threshold ?? '-'}</span>
                  <span>grezzo {smartRaw(a)}</span>
                </div>
              </li>
            );
          })}
        </ul>
      ) : (
        <TableWrap label={`Attributi SMART di ${d.name}`}>
          <table className="smart-table">
            <thead>
              <tr>
                <th scope="col">ID</th>
                <th scope="col">Attributo</th>
                <th scope="col" className="num">
                  Attuale
                </th>
                <th scope="col" className="num">
                  Peggiore
                </th>
                <th scope="col" className="num">
                  Soglia
                </th>
                <th scope="col">Dato grezzo</th>
              </tr>
            </thead>
            <tbody>
              {attrs.map((a) => {
                const state = attrState(a);
                return (
                  <tr key={a.id} className={state !== 'ok' ? `smart-${state}` : undefined}>
                    <td className="mono">{smartId(a.id)}</td>
                    <td className={`name ${ATTR_CLASS[state]}`}>
                      {state !== 'ok' && <SevIcon sev={stateSev(state)} size={13} />} {smartName(a.id, flash)}
                      {state !== 'ok' && <span className="sr-only"> ({ATTR_LABEL[state]})</span>}
                    </td>
                    <td className="mono num">{a.current}</td>
                    <td className="mono num">{a.worst}</td>
                    <td className="mono num">{a.threshold ?? '-'}</td>
                    <td className="mono">{smartRaw(a)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </TableWrap>
      )}
      <p className="faint smart-note">
        Attuale e peggiore sono valori normalizzati dal produttore (di solito partono da 100 o 200 e scendono con il degrado): l&apos;attributo è guasto quando scende alla soglia.
        Il dato grezzo è in esadecimale quando il suo formato dipende dal produttore.
      </p>
    </details>
  );
}

const NVME_WARN = ['riserva sotto soglia', 'temperatura fuori limite', 'affidabilità degradata', 'sola lettura', 'backup della memoria volatile guasto', 'memoria persistente in sola lettura'];

/** Registro di salute NVMe completo, come la scheda di CrystalDiskInfo per i dischi NVMe. */
function NVMeLog({ nv }: { nv: NVMeHealth }) {
  const warns = NVME_WARN.filter((_, i) => nv.criticalWarning & (1 << i));
  const rows: [string, string, Severity?][] = [
    ['Avviso critico', warns.length ? warns.join(', ') : 'nessuno', warns.length ? 'crit' : undefined],
    ['Riserva disponibile', `${nv.availableSparePct} % (soglia ${nv.spareThresholdPct} %)`, nv.spareThresholdPct > 0 && nv.availableSparePct < nv.spareThresholdPct ? 'crit' : undefined],
    ['Durata consumata', `${nv.percentageUsed} %`, nv.percentageUsed >= 90 ? 'crit' : nv.percentageUsed >= 70 ? 'warn' : undefined],
    ['Dati scritti', bytesText(nv.dataWrittenGB)],
    ['Dati letti', bytesText(nv.dataReadGB)],
    ['Accensioni', thousands(nv.powerCycles)],
    ['Ore di accensione', thousands(nv.powerOnHours)],
    ['Spegnimenti non sicuri', thousands(nv.unsafeShutdowns)],
    ['Errori di integrità dei dati', thousands(nv.mediaErrors), nv.mediaErrors > 0 ? 'warn' : undefined],
    ['Voci nel registro errori', thousands(nv.errorLogEntries)],
    ['Minuti oltre la temperatura di avviso', thousands(nv.warningTempMinutes)],
    ['Minuti oltre la temperatura critica', thousands(nv.criticalTempMinutes), nv.criticalTempMinutes > 0 ? 'info' : undefined],
  ];
  return (
    <details className="smart-box" open={warns.length > 0 || nv.mediaErrors > 0 || undefined}>
      <summary>
        <ScrollText size={15} aria-hidden /> Registro di salute NVMe
      </summary>
      <dl className="kv disk-kv smart-kv">
        {rows.map(([k, v, s]) => (
          <Fragment key={k}>
            <dt>{k}</dt>
            <dd className={s ? `c-${s}` : undefined}>{v}</dd>
          </Fragment>
        ))}
      </dl>
      <p className="faint smart-note">
        Le voci nel registro errori contano anche eventi innocui (comandi non supportati inviati dal sistema): da sole non indicano un guasto.
      </p>
    </details>
  );
}

// ---------------------------------------------------------------- Test di velocità

type BenchKind = 'cpu' | 'disk';
interface BenchRun {
  kind: BenchKind;
  drive?: string;
  phase: string;
  done: number;
  value?: number;
  samples?: number[];
}

const PHASE_LABEL: Record<string, string> = {
  start: 'Avvio',
  load: 'Carico attuale del processore',
  single: 'Un thread',
  multi: 'Tutti i thread',
  'seq-write': 'Scrittura sequenziale',
  'seq-read': 'Lettura sequenziale',
  'rnd-read': 'Lettura casuale 4K',
  'rnd-write': 'Scrittura casuale 4K',
  done: 'Fine',
};

// Il test continua anche se si cambia pagina: lo stato vive a livello di
// modulo e le schede che si montano ne seguono l'avanzamento.
let benchPromise: Promise<CpuBench | DiskBench> | null = null;
let benchLast: BenchRun | null = null;
let benchCancel: (() => void) | null = null;
const benchListeners = new Set<(r: BenchRun | null) => void>();
const publishBench = (r: BenchRun | null) => {
  benchLast = r;
  benchListeners.forEach((f) => f(r));
};

function simulateBench(scan: Scan, req: BenchRequest): Promise<CpuBench | DiskBench> {
  const result = req.kind === 'cpu' ? simulatedCpuBench(scan) : simulatedDiskBench(scan, req.drive);
  const drive = req.kind === 'disk' ? req.drive : undefined;
  return new Promise((resolve, reject) => {
    const t0 = performance.now();
    let timer = 0;
    benchCancel = () => {
      clearTimeout(timer);
      reject(new Error('test interrotto'));
    };
    const step = () => {
      const t = performance.now() - t0;
      if (req.kind === 'cpu') {
        const c = result as CpuBench;
        const samples = c.samples ?? [];
        if (t < 400) publishBench({ kind: 'cpu', phase: 'load', done: t / 6000 });
        else if (t < 1600) publishBench({ kind: 'cpu', phase: 'single', done: t / 6000, value: c.singleMBs * Math.min(1, (t - 400) / 500) });
        else if (t < 6000) {
          const n = Math.min(samples.length, Math.floor((t - 1600) / 220));
          publishBench({ kind: 'cpu', phase: 'multi', done: t / 6000, value: n ? samples[n - 1] : undefined, samples: samples.slice(0, n) });
        } else return resolve(result);
      } else {
        const d = result as DiskBench;
        const phases: [string, number][] = [
          ['seq-write', d.seqWriteMBs],
          ['seq-read', d.seqReadMBs],
          ['rnd-read', d.rndReadMBs],
          ['rnd-write', d.rndWriteMBs],
        ];
        const i = Math.floor(t / 1200);
        if (i >= phases.length) return resolve(result);
        const wobble = 1 + Math.sin(t / 90) * 0.03;
        publishBench({ kind: 'disk', drive, phase: phases[i][0], done: t / 4800, value: phases[i][1] * wobble });
      }
      timer = window.setTimeout(step, 80);
    };
    step();
  });
}

function startBench(live: boolean, scan: Scan, req: BenchRequest, done: (r: CpuBench | DiskBench, kind: BenchKind) => void, fail: (e: Error) => void, resume = false) {
  if (benchPromise) return;
  const drive = req.kind === 'disk' ? req.drive : undefined;
  publishBench({ kind: req.kind, drive, phase: 'start', done: 0 });
  benchPromise = live
    ? runBench(
        req,
        (st) => {
          if (st.progress) publishBench({ kind: req.kind, drive: st.drive ?? drive, phase: st.progress.phase, done: st.progress.done, value: st.progress.value, samples: st.progress.samples });
        },
        { resume },
      )
    : simulateBench(scan, req);
  benchPromise
    .then(
      (r) => done(r, req.kind),
      (e) => fail(e instanceof Error ? e : new Error(String(e))),
    )
    .finally(() => {
      benchPromise = null;
      benchCancel = null;
      publishBench(null);
    });
}

// Cronologia dei test sul PC: serve a confrontare "prima e dopo" (pulizia,
// sostituzione del disco, nuovo piano di alimentazione).
interface BenchHistory {
  cpu: CpuBench[];
  disk: DiskBench[];
}
const EMPTY_HISTORY: BenchHistory = { cpu: [], disk: [] };
const histListeners = new Set<() => void>();
function readHistory(key: string): BenchHistory {
  try {
    const h = JSON.parse(localStorage.getItem(key) ?? 'null') as BenchHistory | null;
    return h && Array.isArray(h.cpu) && Array.isArray(h.disk) ? h : EMPTY_HISTORY;
  } catch {
    return EMPTY_HISTORY;
  }
}
function writeHistory(key: string, h: BenchHistory) {
  try {
    localStorage.setItem(key, JSON.stringify(h));
  } catch {
    // archiviazione non disponibile: la cronologia resta solo nella sessione
  }
  histListeners.forEach((f) => f());
}
function pushHistory(key: string, r: { cpu?: CpuBench; disk?: DiskBench }) {
  const h = readHistory(key);
  writeHistory(key, {
    cpu: r.cpu ? [r.cpu, ...h.cpu].slice(0, 8) : h.cpu,
    disk: r.disk ? [r.disk, ...h.disk].slice(0, 24) : h.disk,
  });
}
function useHistory(key: string): BenchHistory {
  const [h, setH] = useState(() => readHistory(key));
  useEffect(() => {
    const f = () => setH(readHistory(key));
    f();
    histListeners.add(f);
    return () => {
      histListeners.delete(f);
    };
  }, [key]);
  return h;
}

function SamplesChart({ samples, total = 20, label }: { samples: number[]; total?: number; label: string }) {
  const max = Math.max(1, ...samples);
  const peak = Math.max(0, ...samples.slice(0, Math.ceil(total / 2)));
  return (
    <div className="samples" role="img" aria-label={label}>
      {Array.from({ length: Math.max(total, samples.length) }, (_, i) => {
        const v = samples[i];
        const ratio = v !== undefined && peak > 0 ? v / peak : 1;
        const sev: Severity = ratio < 0.8 ? 'warn' : ratio < 0.9 ? 'info' : 'ok';
        return (
          <span key={i} className="s-col">
            {v !== undefined && (
              <m.i
                style={{ background: sev === 'ok' ? 'linear-gradient(180deg, var(--primary-a), var(--primary-b))' : sevColor(sev) }}
                initial={{ scaleY: 0 }}
                animate={{ scaleY: v / max }}
                transition={spring.snappy}
                title={`${i + 1}° secondo: ${mbs(v)}`}
              />
            )}
          </span>
        );
      })}
    </div>
  );
}

function BenchProgress({ run, onStop }: { run: BenchRun; onStop: () => void }) {
  return (
    <m.div
      key="progress"
      initial={{ height: 0, opacity: 0 }}
      animate={{ height: 'auto', opacity: 1, transition: { height: spring.smooth, opacity: { duration: 0.25 } } }}
      exit={{ height: 0, opacity: 0, transition: { duration: 0.25, ease: ease.inOut } }}
      style={{ overflow: 'hidden' }}
    >
      <div className="bench-live">
        <div className="progress" role="progressbar" aria-label="Avanzamento del test" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(run.done * 100)}>
          <m.i initial={false} animate={{ scaleX: Math.min(1, run.done) }} transition={spring.gentle} />
        </div>
        <div className="bench-live-row">
          <span className="faint" aria-live="polite">
            {PHASE_LABEL[run.phase] ?? run.phase}
            {run.value !== undefined && run.value > 0 ? ` · ${mbs(run.value)}` : ''}
          </span>
          <button className="btn small" onClick={onStop}>
            <CircleStop size={15} aria-hidden /> Interrompi
          </button>
        </div>
        {run.kind === 'cpu' && run.phase === 'multi' && <SamplesChart samples={run.samples ?? []} label="Velocità secondo per secondo con tutti i thread" />}
      </div>
    </m.div>
  );
}

function BenchCard({ scan, live, source, analysis, addBench }: ViewProps) {
  const toast = useToast();
  const [run, setRun] = useState<BenchRun | null>(benchLast);
  const [error, setError] = useState<string | null>(null);
  const [consent, setConsent] = useState(false);
  const vols = (scan.pc?.volumes ?? []).filter((v) => v.sizeGB > 0);
  const [drive, setDrive] = useState(() => (vols.find((v) => v.system) ?? vols[0])?.letter ?? 'C:');
  const histKey = `polaris.bench.${source === 'demo' ? `demo-${scan.agent.host ?? ''}` : scan.agent.host ?? 'pc'}`;
  const hist = useHistory(histKey);
  const bench = scan.pc?.bench;
  const readOnly = source === 'file';

  useEffect(() => {
    benchListeners.add(setRun);
    return () => {
      benchListeners.delete(setRun);
    };
  }, []);

  const done = (r: CpuBench | DiskBench, kind: BenchKind) => {
    const patch = kind === 'cpu' ? { cpu: r as CpuBench } : { disk: r as DiskBench };
    addBench(patch);
    pushHistory(histKey, patch);
    toast(kind === 'cpu' ? 'Test del processore completato' : `Test dell'unità ${(r as DiskBench).drive} completato`);
  };
  const fail = (e: Error) => {
    setError(e.message);
    if (/interrott/i.test(e.message)) toast('Test interrotto');
    else toast(`Test non riuscito: ${e.message}`, 'error');
  };

  // Un test avviato prima (anche da un'altra finestra) si riprende invece di ripartire.
  useEffect(() => {
    if (!live || benchPromise) return;
    let alive = true;
    benchStatus()
      .then((st) => {
        if (!alive || !st.running || !st.kind) return;
        const req: BenchRequest = st.kind === 'cpu' ? { kind: 'cpu' } : { kind: 'disk', drive: st.drive ?? 'C:', confirm: true };
        startBench(true, scan, req, done, fail, true);
      })
      .catch(() => undefined);
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [live]);

  const start = (req: BenchRequest) => {
    setError(null);
    startBench(live, scan, req, done, fail);
  };
  const stop = () => {
    if (live) stopBench().catch((e) => toast(`Interruzione non riuscita: ${e instanceof Error ? e.message : e}`, 'error'));
    else benchCancel?.();
  };

  const cpu = bench?.cpu;
  const cpuFinding = analysis.findings.find((f) => f.id === 'pc.cpubench');
  const diskRes = bench?.disk?.find((d) => d.drive.toUpperCase() === drive.toUpperCase());
  const diskFinding = analysis.findings.find((f) => f.id === `pc.diskbench.${drive.replace(':', '')}`);
  const vol = vols.find((v) => v.letter === drive);
  const volDisk = scan.pc?.disks?.find((d) => d.id !== undefined && d.id === vol?.disk);
  const lowSpace = vol ? vol.freeGB < 2.2 : false;
  const busy = !!run;
  const cpuHist = hist.cpu.filter((h) => h.startedAt !== cpu?.startedAt).slice(0, 4);
  const diskHist = hist.disk.filter((h) => h.drive.toUpperCase() === drive.toUpperCase() && h.startedAt !== diskRes?.startedAt).slice(0, 4);

  return (
    <>
      {readOnly ? (
        <div className="notice" style={{ marginBottom: 14 }}>
          <TriangleAlert size={18} aria-hidden />
          <span>Rapporto importato: qui si consultano i test salvati. I test si eseguono dall'agente, sul PC da analizzare.</span>
        </div>
      ) : (
        !live && (
          <div className="notice" style={{ marginBottom: 14 }}>
            <TriangleAlert size={18} aria-hidden />
            <span>
              Senza agente i test sono <b>simulati</b> sui dati dimostrativi: servono a vedere come funzionano.
            </span>
          </div>
        )
      )}
      <m.div className="grid cols-2" variants={cascade(0.06)}>
        <m.section variants={rise} className="card bench-panel">
          <div className="card-head">
            <h2 className="disk-title">
              <Cpu size={19} aria-hidden /> Processore
            </h2>
            <span className="sub">circa 25 secondi</span>
            <span className="spacer" />
            {cpuFinding && (
              <span className={`sev ${cpuFinding.severity}`}>
                <SevIcon sev={cpuFinding.severity} size={14} />
                {cpuFinding.severity === 'ok' ? 'Stabile' : cpuFinding.severity === 'info' ? 'Lieve calo' : 'Limitato'}
              </span>
            )}
          </div>
          <p className="muted bench-desc">
            Comprime dati in memoria con un thread e poi con tutti, campionando ogni secondo: misura la velocità e se cala quando il processore scalda. Non scrive
            nulla su disco. Chiudi i programmi pesanti prima di avviarlo.
          </p>
          {!readOnly && (
            <div className="infra-start">
              <button className="btn primary" disabled={busy} onClick={() => start({ kind: 'cpu' })}>
                <Play size={16} aria-hidden /> {run?.kind === 'cpu' ? 'Test in corso…' : cpu ? 'Ripeti il test' : live ? 'Avvia il test' : 'Simula il test'}
              </button>
            </div>
          )}
          <AnimatePresence initial={false}>{run?.kind === 'cpu' && <BenchProgress run={run} onStop={stop} />}</AnimatePresence>
          {cpu && (
            <div className="bench-result">
              <div className="stats">
                <Stat k="Un thread" v={mbs(cpu.singleMBs)} />
                <Stat k={`${cpu.threads} thread, punta`} v={mbs(cpu.multiMBs)} />
                <Stat k="Alla fine" v={mbs(cpu.sustainedMBs)} sev={cpu.sustainedMBs / cpu.multiMBs < 0.8 ? 'warn' : cpu.sustainedMBs / cpu.multiMBs < 0.9 ? 'info' : undefined} />
                <Stat k="Con tutti i thread" v={`${fmtNum(cpu.multiMBs / Math.max(cpu.singleMBs, 0.1), 1)}×`} />
              </div>
              {cpu.samples && cpu.samples.length > 1 && (
                <>
                  <SamplesChart samples={cpu.samples} total={cpu.samples.length} label="Velocità secondo per secondo con tutti i thread" />
                  <p className="faint bench-axis">
                    <span>Secondo per secondo con tutti i thread</span>
                    <span>{when(cpu.startedAt)}{cpu.onAC === false ? ' · a batteria' : ''}</span>
                  </p>
                </>
              )}
            </div>
          )}
          {cpuHist.length > 0 && (
            <BenchHistoryList
              rows={cpuHist.map((h) => ({ at: h.startedAt, text: `${mbs(h.singleMBs)} · ${mbs(h.multiMBs)} · alla fine ${mbs(h.sustainedMBs)}` }))}
              onClear={() => writeHistory(histKey, { ...readHistory(histKey), cpu: cpu ? [cpu] : [] })}
            />
          )}
        </m.section>

        <m.section variants={rise} className="card bench-panel">
          <div className="card-head">
            <h2 className="disk-title">
              <HardDrive size={19} aria-hidden /> Disco
            </h2>
            <span className="sub">fino a 35 secondi</span>
            <span className="spacer" />
            {diskFinding && (
              <span className={`sev ${diskFinding.severity}`}>
                <SevIcon sev={diskFinding.severity} size={14} />
                {diskFinding.severity === 'ok' ? 'Nella norma' : diskFinding.severity === 'info' ? 'Lento' : 'Sotto la norma'}
              </span>
            )}
          </div>
          <p className="muted bench-desc">
            Scrive e rilegge un file temporaneo fino a 1 GB senza cache di Windows, in sequenza e in punti casuali (4 KB), e lo cancella alla fine, anche se il test
            si interrompe.
          </p>
          {vols.length > 0 && (
            <label className="bench-drive">
              <span>Unità</span>
              <select className="field" value={drive} onChange={(e) => setDrive(e.target.value)} disabled={busy}>
                {vols.map((v) => {
                  const d = scan.pc?.disks?.find((x) => x.id !== undefined && x.id === v.disk);
                  return (
                    <option key={v.letter} value={v.letter}>
                      {v.letter} {v.label || (v.system ? 'Windows' : '')} · {d ? `${d.media === 'hdd' ? 'HDD' : d.media === 'ssd' ? 'SSD' : 'unità'}${d.bus ? ` ${d.bus}` : ''}` : v.kind === 'removable' ? 'rimovibile' : 'disco'} · {gb(v.freeGB)} liberi
                    </option>
                  );
                })}
              </select>
            </label>
          )}
          {!readOnly && (
            <div className="infra-start">
              <label className="consent">
                <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} disabled={busy} />
                <span>
                  Va bene scrivere su {drive} un file temporaneo fino a 1 GB, cancellato alla fine.
                  {volDisk && isFlash(volDisk) ? ' Su un SSD è un consumo trascurabile.' : ''}
                </span>
              </label>
              <button className="btn primary" disabled={busy || !consent || lowSpace} onClick={() => start({ kind: 'disk', drive, confirm: true })}>
                <Play size={16} aria-hidden /> {run?.kind === 'disk' ? 'Test in corso…' : diskRes ? 'Ripeti il test' : live ? 'Avvia il test' : 'Simula il test'}
              </button>
              {lowSpace && <span className="faint" style={{ fontSize: 13 }}>Servono almeno 2 GB liberi su {drive}.</span>}
            </div>
          )}
          <AnimatePresence initial={false}>{run?.kind === 'disk' && <BenchProgress run={run} onStop={stop} />}</AnimatePresence>
          {diskRes && (
            <div className="bench-result">
              <div className="stats">
                <Stat k="Lettura sequenziale" v={mbs(diskRes.seqReadMBs)} />
                <Stat k="Scrittura sequenziale" v={mbs(diskRes.seqWriteMBs)} />
                <Stat k="Lettura casuale 4K">
                  {mbs(diskRes.rndReadMBs)}
                  <span className="sub">{thousands(diskRes.rndReadIops)} IOPS</span>
                </Stat>
                <Stat k="Scrittura casuale 4K">
                  {mbs(diskRes.rndWriteMBs)}
                  <span className="sub">{thousands(diskRes.rndWriteIops)} IOPS</span>
                </Stat>
              </div>
              <p className="faint bench-axis">
                <span>
                  File di {diskRes.fileMB} MB{diskRes.note ? ` · ${diskRes.note}` : ''}
                </span>
                <span>{when(diskRes.startedAt)}</span>
              </p>
            </div>
          )}
          {diskHist.length > 0 && (
            <BenchHistoryList
              rows={diskHist.map((h) => ({ at: h.startedAt, text: `lettura ${mbs(h.seqReadMBs)} · scrittura ${mbs(h.seqWriteMBs)} · 4K ${mbs(h.rndReadMBs)}` }))}
              onClear={() => {
                const h = readHistory(histKey);
                writeHistory(histKey, { ...h, disk: h.disk.filter((x) => x.drive.toUpperCase() !== drive.toUpperCase() || x.startedAt === diskRes?.startedAt) });
              }}
            />
          )}
        </m.section>
      </m.div>
      {error && (
        <div className={`notice ${/interrott/i.test(error) ? '' : 'alert'}`} role="alert" style={{ marginTop: 14 }}>
          <TriangleAlert size={18} aria-hidden />
          <span>{/interrott/i.test(error) ? 'Test interrotto: il file temporaneo, se c\'era, è stato cancellato.' : error}</span>
        </div>
      )}
    </>
  );
}

function BenchHistoryList({ rows, onClear }: { rows: { at: string; text: string }[]; onClear: () => void }) {
  return (
    <div className="bench-hist">
      <div className="bench-hist-head">
        <History size={14} aria-hidden /> Prove precedenti su questo PC
        <span className="spacer" />
        <button className="link-btn" onClick={onClear}>
          <Trash2 size={13} aria-hidden /> Cancella
        </button>
      </div>
      <ul>
        {rows.map((r) => (
          <li key={r.at}>
            <span className="faint">{when(r.at)}</span>
            <span className="mono">{r.text}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

// ---------------------------------------------------------------- Avvio e processi

const LOCATION: Record<StartupItem['location'], string> = {
  user: 'Registro, utente',
  machine: 'Registro, computer',
  machine32: 'Registro, programmi a 32 bit',
  'user-folder': 'Esecuzione automatica, utente',
  'common-folder': 'Esecuzione automatica, tutti',
};

function StartupCard({ items }: { items: StartupItem[] }) {
  const openGuide = useOpenGuide();
  const rows = [...items].sort((a, b) => Number(b.enabled) - Number(a.enabled) || a.name.localeCompare(b.name, 'it'));
  const on = items.filter((i) => i.enabled).length;
  return (
    <m.section variants={rise} className="card">
      <div className="card-head">
        <h2>Programmi all'avvio</h2>
        <span className="sub">
          {on} attivi{items.length > on ? `, ${items.length - on} disattivati` : ''}
        </span>
      </div>
      {rows.length ? (
        <TableWrap label="Programmi all'avvio">
          <table className="pc-table">
            <thead>
              <tr>
                <th>Programma</th>
                <th>Stato</th>
                <th>Avviato da</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((s, i) => (
                <tr key={`${s.location}-${s.name}-${i}`} className={s.enabled ? undefined : 'off'}>
                  <td className="cmd" title={s.command}>
                    <b>{s.name}</b>
                    {s.command && <span className="mono faint">{s.command}</span>}
                  </td>
                  <td>{s.enabled ? <span className="tag accent">attivo</span> : <span className="tag">disattivato</span>}</td>
                  <td className="faint">{LOCATION[s.location] ?? s.location}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      ) : (
        <p className="muted">Nessun programma all'avvio nelle chiavi Run e nelle cartelle di esecuzione automatica.</p>
      )}
      <p className="faint card-foot">
        Si disattivano da Gestione attività &gt; App di avvio, senza disinstallarli.{' '}
        {openGuide && (
          <button className="link-btn" onClick={() => openGuide('avvio-processi')}>
            Cosa disattivare
          </button>
        )}
      </p>
    </m.section>
  );
}

function ProcessesCard({ pc }: { pc: PcData }) {
  const reduce = useReducedMotion();
  const list = pc.processes ?? [];
  const maxMem = Math.max(1, ...list.map((p) => p.memoryMB));
  const maxCpu = Math.max(1, ...list.map((p) => p.cpuPct ?? 0));
  const totalMB = pc.memory?.totalMB;
  return (
    <m.section variants={rise} className="card">
      <div className="card-head">
        <h2>Processi più pesanti</h2>
        {pc.cpu?.loadPct !== undefined && <span className="sub">processore al {fmtNum(pc.cpu.loadPct)} % durante la misura</span>}
      </div>
      {list.length ? (
        <TableWrap label="Processi più pesanti">
          <table className="pc-table">
            <thead>
              <tr>
                <th>Processo</th>
                <th>CPU</th>
                <th>Memoria</th>
              </tr>
            </thead>
            <tbody>
              {list.map((p) => (
                <tr key={p.name}>
                  <td>
                    <b>{p.name}</b>
                    {p.count > 1 && <span className="faint"> ×{p.count}</span>}
                  </td>
                  <td className="bar-cell">
                    <span className="mono">{p.cpuPct === undefined ? '—' : `${fmtNum(p.cpuPct, p.cpuPct < 10 ? 1 : 0)} %`}</span>
                    <span className="minibar">
                      <m.i initial={{ scaleX: reduce ? (p.cpuPct ?? 0) / maxCpu : 0 }} animate={{ scaleX: (p.cpuPct ?? 0) / maxCpu }} transition={spring.gentle} />
                    </span>
                  </td>
                  <td className="bar-cell">
                    <span className="mono" title={totalMB ? `${fmtNum((100 * p.memoryMB) / totalMB)} % della RAM` : undefined}>
                      {p.memoryMB >= 1024 ? gb(p.memoryMB / 1024) : `${Math.round(p.memoryMB)} MB`}
                    </span>
                    <span className="minibar">
                      <m.i initial={{ scaleX: reduce ? p.memoryMB / maxMem : 0 }} animate={{ scaleX: p.memoryMB / maxMem }} transition={spring.gentle} />
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      ) : (
        <p className="muted">Processi non misurati.</p>
      )}
      <p className="faint card-foot">
        Misurati per un secondo e mezzo a fine analisi; i processi con lo stesso nome sono sommati. msedgewebview2.exe comprende anche la finestra di Polaris.
      </p>
    </m.section>
  );
}

// ---------------------------------------------------------------- Eventi

const EVENT_LABEL: Record<EventKind, string> = {
  'unexpected-shutdown': 'Spegnimento imprevisto',
  bugcheck: 'Schermata blu',
  'disk-error': 'Errore del disco',
  'disk-retry': 'Operazione ripetuta sul disco',
  filesystem: 'File system danneggiato',
  'storage-reset': 'Reset del controller',
  'whea-fatal': 'Errore hardware grave',
  'whea-corrected': 'Errore hardware corretto',
};
const EVENT_SEV: Record<EventKind, Severity> = {
  'unexpected-shutdown': 'warn',
  bugcheck: 'crit',
  'disk-error': 'crit',
  'disk-retry': 'warn',
  filesystem: 'crit',
  'storage-reset': 'warn',
  'whea-fatal': 'crit',
  'whea-corrected': 'info',
};

function eventDetail(e: EventGroup, pc: PcData): string {
  if (!e.detail) return '';
  if (e.kind === 'bugcheck') {
    const m0 = /0x[0-9a-f]+/i.exec(e.detail);
    if (m0) {
      const code = '0x' + ('00000000' + m0[0].slice(2).toLowerCase()).slice(-8);
      const b = BUGCHECKS[code];
      return b ? `${code} ${b[0]}: ${b[1]}` : code;
    }
  }
  const hd = /harddisk(\d+)/i.exec(e.detail);
  if (hd) {
    const d = pc.disks?.find((x) => x.id === hd[1]);
    return d ? `Disco ${hd[1]}: ${d.name}${isUsbDisk(d) ? ' (USB)' : ''}` : `Disco ${hd[1]}`;
  }
  return e.detail;
}

function EventsCard({ pc }: { pc: PcData }) {
  const openGuide = useOpenGuide();
  const ev = pc.events ?? [];
  return (
    <m.section variants={rise} className="card">
      <div className="card-head">
        <h2 className="disk-title">
          <ScrollText size={19} aria-hidden /> Registro di sistema
        </h2>
        <span className="sub">spegnimenti, schermate blu, errori di disco e hardware</span>
      </div>
      {ev.length === 0 ? (
        <p className="muted" style={{ display: 'flex', alignItems: 'center', gap: 8, margin: 0 }}>
          <SevIcon sev="ok" size={16} className="c-ok" /> Nessun evento rilevante negli ultimi {pc.eventsDays} giorni.
        </p>
      ) : (
        <TableWrap label="Eventi rilevanti del registro di sistema">
          <table className="pc-table">
            <thead>
              <tr>
                <th>Ultima volta</th>
                <th>Evento</th>
                <th>Volte</th>
                <th>Dettaglio</th>
              </tr>
            </thead>
            <tbody>
              {ev.map((e, i) => (
                <tr key={`${e.source}-${e.id}-${i}`}>
                  <td className="mono">{dateIt(e.last)}</td>
                  <td>
                    <span className={`c-${EVENT_SEV[e.kind]}`} style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                      <SevIcon sev={EVENT_SEV[e.kind]} size={14} /> {EVENT_LABEL[e.kind]}
                    </span>
                    <span className="mono faint ev-src">
                      {e.source} {e.id}
                    </span>
                  </td>
                  <td className="mono">{e.count}</td>
                  <td className="wrap">{eventDetail(e, pc)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
      <p className="faint card-foot">
        Gli stessi eventi si consultano in Visualizzatore eventi &gt; Registri di Windows &gt; Sistema.{' '}
        {openGuide && (
          <button className="link-btn" onClick={() => openGuide('registro-eventi')}>
            Come leggerli
          </button>
        )}
      </p>
    </m.section>
  );
}

// ---------------------------------------------------------------- Dettagli

const PLAN: Record<string, string> = { balanced: 'Bilanciato', high: 'Prestazioni elevate', saver: 'Risparmio energia', ultimate: 'Prestazioni ottimali', custom: 'Personalizzato' };

function SystemDetails({ pc }: { pc: PcData }) {
  const os = pc.os;
  const b = pc.battery;
  const health = b?.designMWh && b.fullMWh ? Math.min(100, (100 * b.fullMWh) / b.designMWh) : undefined;
  const avs = pc.antivirus;
  return (
    <m.div className="grid cols-2" variants={cascade(0.06)}>
      <m.section variants={rise} className="card">
        <div className="card-head">
          <h2>Windows e hardware</h2>
        </div>
        <dl className="kv">
          {os && (
            <>
              <dt>Sistema</dt>
              <dd>
                {os.name}
                {os.version ? ` ${os.version}` : ''}
                {os.build ? ` (build ${os.build}${os.ubr ? `.${os.ubr}` : ''})` : ''}
              </dd>
              {os.edition && (
                <>
                  <dt>Edizione</dt>
                  <dd>{os.edition}</dd>
                </>
              )}
              {os.arch && (
                <>
                  <dt>Architettura</dt>
                  <dd>{os.arch}</dd>
                </>
              )}
              {os.installDate && (
                <>
                  <dt>Installato</dt>
                  <dd>{dateIt(os.installDate)}</dd>
                </>
              )}
              {os.bootTime && (
                <>
                  <dt>Ultimo avvio</dt>
                  <dd>{when(os.bootTime)}</dd>
                </>
              )}
              {os.fastStartup !== undefined && (
                <>
                  <dt>Avvio rapido</dt>
                  <dd>{os.fastStartup ? 'attivo' : 'disattivato'}</dd>
                </>
              )}
            </>
          )}
          {pc.cpu && (
            <>
              <dt>Processore</dt>
              <dd>{shortCpu(pc.cpu.name)}</dd>
              {(pc.cpu.cores || pc.cpu.threads) && (
                <>
                  <dt>Core e thread</dt>
                  <dd>
                    {pc.cpu.cores ? `${pc.cpu.cores} core, ` : ''}
                    {pc.cpu.threads ?? '?'} thread{pc.cpu.maxMhz ? `, ${fmtNum(pc.cpu.maxMhz / 1000, 1)} GHz di base` : ''}
                  </dd>
                </>
              )}
            </>
          )}
          {pc.memory && (
            <>
              <dt>Memoria</dt>
              <dd>
                {gb(pc.memory.totalMB / 1024)}, liberi {gb(pc.memory.availableMB / 1024)}
                {pc.memory.commitLimitMB ? ` · impegnati ${gb((pc.memory.commitMB ?? 0) / 1024)} su ${gb(pc.memory.commitLimitMB / 1024)}` : ''}
              </dd>
            </>
          )}
          {(pc.gpus ?? []).map((g, i) => (
            <Fragment key={i}>
              <dt>Scheda video</dt>
              <dd>
                {g.name}
                {g.driverVersion ? ` · driver ${g.driverVersion}` : ''}
                {g.driverDate ? ` del ${dateIt(g.driverDate)}` : ''}
              </dd>
            </Fragment>
          ))}
        </dl>
      </m.section>
      <m.section variants={rise} className="card">
        <div className="card-head">
          <h2>Alimentazione e sicurezza</h2>
        </div>
        <dl className="kv">
          {pc.power && (
            <>
              <dt>Piano</dt>
              <dd>{pc.power.plan || (pc.power.planKind ? PLAN[pc.power.planKind] : '—')}</dd>
              <dt>Alimentazione</dt>
              <dd>
                {pc.power.onAC === undefined ? 'non nota' : pc.power.onAC ? 'collegato alla corrente' : 'a batteria'}
                {pc.power.batterySaver ? ' · risparmio batteria attivo' : ''}
              </dd>
            </>
          )}
          {b && (
            <>
              <dt>Batteria</dt>
              <dd>
                {b.chargePct !== undefined ? `carica al ${b.chargePct} %` : ''}
                {health !== undefined ? `${b.chargePct !== undefined ? ' · ' : ''}salute ${fmtNum(health)} %` : ''}
                {b.cycles ? ` · ${thousands(b.cycles)} cicli` : ''}
              </dd>
            </>
          )}
          {avs && (
            <>
              <dt>Antivirus</dt>
              <dd>
                {avs.length
                  ? avs.map((a) => `${a.name}: ${a.enabled ? (a.upToDate === false ? 'attivo, non aggiornato' : 'attivo') : 'disattivato'}`).join(' · ')
                  : 'nessuno registrato'}
              </dd>
            </>
          )}
          {pc.updates && (
            <>
              <dt>Ultimo aggiornamento</dt>
              <dd>
                {pc.updates.lastInstalled ? dateIt(pc.updates.lastInstalled) : 'non rilevato'}
                {pc.updates.lastKB ? ` · ${pc.updates.lastKB}` : ''}
              </dd>
              <dt>Riavvio in sospeso</dt>
              <dd>{pc.updates.pendingReboot ? `sì (${(pc.updates.rebootReasons ?? []).join(', ') || 'motivo non indicato'})` : 'no'}</dd>
            </>
          )}
        </dl>
      </m.section>
    </m.div>
  );
}
