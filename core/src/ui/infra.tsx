import {
  BookOpenText,
  Building2,
  ChevronDown,
  ClipboardCheck,
  FileSpreadsheet,
  ListPlus,
  Lock,
  Plus,
  Radar,
  RotateCcw,
  ScanSearch,
  ShieldCheck,
  Trash2,
  TriangleAlert,
  Unplug,
  Waypoints,
} from 'lucide-react';
import { AnimatePresence, m } from 'motion/react';
import { useEffect, useMemo, useRef, useState } from 'react';
import type { KeyboardEvent } from 'react';
import { ASSESS_QUESTIONS, scoreAssessment } from '../engine';
import type { AnswerValue, AssessAreaId, Inventory, InventoryHost, ReachExpect, ReachResult, ReachTarget, Scan, Severity } from '../engine';
import { simulatedInventory, simulatedReach } from '../demo/simulate';
import { guideById } from '../guides';
import { download, inventoryStatus, runInventory, runReach } from './api';
import type { InventoryProgress } from './api';
import { FindingList, SevIcon, Stat, TableWrap, fmtNum, sevColor, useOpenGuide, useToast } from './components';
import { useLocalState } from './hooks';
import { toCsv } from './monitor';
import { cascade, ease, rise, spring } from './motion';
import { Section } from './views';
import type { ViewProps } from './views';

// Sezione Infrastruttura: gli strumenti per le reti complesse. Inventario e
// verifiche contattano altri dispositivi, quindi partono solo su richiesta
// esplicita; senza agente (demo) sono simulati e dichiarati come tali.

const fmtMs = (v?: number) => (v === undefined ? '—' : v < 1 ? '<1 ms' : `${fmtNum(v, v < 10 ? 1 : 0)} ms`);
const fmtWhen = (iso?: string) => {
  if (!iso) return '';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString('it-IT', { dateStyle: 'short', timeStyle: 'short' });
};

export function InfraView(props: ViewProps) {
  const { analysis: a, go } = props;
  const openGuide = useOpenGuide();
  const findings = a.findings.filter((f) => f.category === 'infra');
  const guides = ['inventario-documentazione', 'segmentazione', 'analisi-reti-grandi'].map(guideById).filter((g) => g !== undefined);
  return (
    <>
      <m.section variants={rise} className="card infra-intro">
        <span className="infra-mark" aria-hidden>
          <Building2 size={26} />
        </span>
        <div style={{ minWidth: 0 }}>
          <h2>Strumenti per reti complesse</h2>
          <p className="muted">
            Inventario della sottorete, test di segmentazione, verifica dei servizi critici e autovalutazione delle misure organizzative: le analisi che servono
            in uno studio, in un'azienda o in una struttura sanitaria. Ripetile da ogni zona della rete ed esporta ogni volta il rapporto.
          </p>
          <ul className="infra-rules" aria-label="Regole di sicurezza delle analisi">
            <li>
              <Lock size={14} aria-hidden /> Solo su tua richiesta
            </li>
            <li>
              <ShieldCheck size={14} aria-hidden /> Solo indirizzi privati
            </li>
            <li>
              <Waypoints size={14} aria-hidden /> Ritmo prudente
            </li>
            <li>
              <Unplug size={14} aria-hidden /> Nessuna scansione di porte
            </li>
          </ul>
          {openGuide && (
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

      {findings.length > 0 && (
        <Section title="Valutazione">
          <FindingList findings={findings} onAction={(id) => go('plan', id)} />
        </Section>
      )}

      <Section title="Inventario della sottorete">
        <InventoryCard {...props} />
      </Section>

      <Section title="Segmentazione e servizi critici">
        <ReachCard {...props} />
      </Section>

      <Section title="Autovalutazione">
        <AssessmentCard {...props} />
      </Section>
    </>
  );
}

// ---------------------------------------------------------------- Inventario

type Phase = { phase: string; done: number; total: number };

// L'inventario continua anche se si cambia pagina: lo stato vive a livello di
// modulo e le schede che si montano si limitano a seguirne l'avanzamento.
let running: Promise<Inventory> | null = null;
let lastPhase: Phase | null = null;
const listeners = new Set<(p: Phase | null) => void>();
const publish = (p: Phase | null) => {
  lastPhase = p;
  listeners.forEach((f) => f(p));
};

function simulateRun(scan: Scan): Promise<Inventory> {
  const result = simulatedInventory(scan);
  const total = Math.min(result.scanned, 1022);
  const names = result.hosts.length;
  return new Promise((resolve) => {
    const t0 = performance.now();
    const step = () => {
      const t = performance.now() - t0;
      if (t < 2600) publish({ phase: 'ping', done: Math.round((total * t) / 2600), total });
      else if (t < 3500) publish({ phase: 'nomi', done: Math.round((names * (t - 2600)) / 900), total: names });
      else return resolve(result);
      setTimeout(step, 80);
    };
    step();
  });
}

function startInventory(live: boolean, scan: Scan, resume: boolean, onDone: (inv: Inventory) => void, onError: (e: Error) => void) {
  if (running) return;
  publish({ phase: 'ping', done: 0, total: 0 });
  running = live ? runInventory((p: InventoryProgress) => publish({ phase: p.phase ?? 'ping', done: p.done, total: p.total }), { resume }) : simulateRun(scan);
  running
    .then(onDone, (e) => onError(e instanceof Error ? e : new Error(String(e))))
    .finally(() => {
      running = null;
      publish(null);
    });
}

type HostFilter = 'all' | 'unnamed' | 'random' | 'arp';

function hostNote(h: InventoryHost): string {
  return [h.self && 'questo PC', h.gateway && 'gateway', h.randomMac && 'MAC casuale o virtuale', h.rttMs === undefined && !h.self && 'visto solo tramite ARP']
    .filter(Boolean)
    .join(' · ');
}

function inventoryCsv(inv: Inventory): string {
  return toCsv([
    ['ip', 'nome_dns', 'netbios', 'mac', 'mac_casuale', 'ping_ms', 'note'],
    ...inv.hosts.map((h) => [h.ip, h.name, h.netbios, h.mac, h.randomMac ? 'sì' : '', h.rttMs, hostNote(h)]),
  ]);
}

function InventoryCard({ scan, live, source, setInfra }: ViewProps) {
  const toast = useToast();
  const inv = scan.infra?.inventory;
  const [authorized, setAuthorized] = useState(false);
  const [phase, setPhase] = useState<Phase | null>(lastPhase);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<HostFilter>('all');
  const [query, setQuery] = useState('');

  useEffect(() => {
    listeners.add(setPhase);
    return () => {
      listeners.delete(setPhase);
    };
  }, []);

  const done = (r: Inventory) => {
    setInfra({ inventory: r });
    toast(`Inventario completato · ${r.hosts.filter((h) => !h.self).length} dispositivi`);
  };
  const fail = (e: Error) => {
    setError(e.message);
    toast(`Inventario non riuscito: ${e.message}`, 'error');
  };

  // Un inventario avviato prima (anche da un'altra finestra) si riprende invece di ripartire.
  useEffect(() => {
    if (!live || running) return;
    let alive = true;
    inventoryStatus()
      .then((p) => {
        if (alive && p.running) startInventory(true, scan, true, done, fail);
      })
      .catch(() => undefined);
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [live]);

  const start = () => {
    setError(null);
    startInventory(live, scan, false, done, fail);
  };

  const others = inv?.hosts.filter((h) => !h.self) ?? [];
  const q = query.trim().toLowerCase();
  const rows = (inv?.hosts ?? []).filter((h) => {
    if (filter === 'unnamed' && (h.name || h.netbios || h.self)) return false;
    if (filter === 'random' && !h.randomMac) return false;
    if (filter === 'arp' && (h.rttMs !== undefined || h.self)) return false;
    return !q || [h.ip, h.name, h.netbios, h.mac].some((v) => v?.toLowerCase().includes(q));
  });
  const counts = {
    ping: others.filter((h) => h.rttMs !== undefined).length,
    arp: others.filter((h) => h.rttMs === undefined).length,
    unnamed: others.filter((h) => !h.name && !h.netbios).length,
    random: others.filter((h) => h.randomMac).length,
  };
  const pct = phase && phase.total ? Math.min(1, phase.done / phase.total) : 0;

  return (
    <m.section variants={rise} className="card">
      <div className="card-head">
        <h2 style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
          <ScanSearch size={19} aria-hidden /> Dispositivi della sottorete
        </h2>
        {inv && (
          <span className="sub mono">
            {inv.subnet} · {fmtWhen(inv.startedAt)}
          </span>
        )}
        <span className="spacer" />
        {inv && (
          <button
            className="btn small"
            onClick={() => download(`polaris-inventario-${inv.subnet.replace(/[/.]/g, '-')}.csv`, inventoryCsv(inv), 'text/csv;charset=utf-8')}
          >
            <FileSpreadsheet size={15} aria-hidden /> Esporta CSV
          </button>
        )}
      </div>

      <p className="muted" style={{ marginTop: 0 }}>
        Un ping a ogni indirizzo della sottorete del PC, circa trenta al secondo, poi la tabella ARP e i nomi da DNS e NetBIOS dei soli dispositivi trovati.
        Nessuna connessione verso le porte dei dispositivi. Le sottoreti più ampie di /22 vengono esaminate solo nel blocco /24 del PC.
      </p>

      {source === 'file' ? (
        <div className="notice">
          <TriangleAlert size={18} aria-hidden />
          <span>Rapporto importato: qui si consultano i risultati salvati. L'inventario si esegue dall'agente, sulla rete a cui è collegato il PC.</span>
        </div>
      ) : (
        <>
          {!live && (
            <div className="notice" style={{ marginBottom: 14 }}>
              <TriangleAlert size={18} aria-hidden />
              <span>
                Senza agente l'inventario è <b>simulato</b> sui dati dimostrativi: serve a vedere come funziona.
              </span>
            </div>
          )}

          <div className="infra-start">
            <label className="consent">
              <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} disabled={!!phase} />
              <span>Sono autorizzato ad analizzare questa rete e, se ci sono dispositivi medicali, l'attività è concordata con l'ingegneria clinica.</span>
            </label>
            <button className="btn primary" onClick={start} disabled={!authorized || !!phase} aria-describedby="inv-hint">
              <Radar size={16} className={phase ? 'spin' : undefined} aria-hidden />
              {phase ? 'Inventario in corso…' : inv ? "Ripeti l'inventario" : live ? "Avvia l'inventario" : "Simula l'inventario"}
            </button>
            <span id="inv-hint" className="faint" style={{ fontSize: 13 }}>
              {authorized ? 'Una sottorete /24 richiede circa dieci secondi.' : "Conferma l'autorizzazione per avviare."}
            </span>
          </div>
        </>
      )}

      <AnimatePresence initial={false}>
        {phase && (
          <m.div
            key="progress"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1, transition: { height: spring.smooth, opacity: { duration: 0.25 } } }}
            exit={{ height: 0, opacity: 0, transition: { duration: 0.25, ease: ease.inOut } }}
            style={{ overflow: 'hidden' }}
          >
            <div className="infra-progress">
              <div
                className="progress live"
                role="progressbar"
                aria-label="Avanzamento dell'inventario"
                aria-valuemin={0}
                aria-valuemax={phase.total || 1}
                aria-valuenow={phase.done}
              >
                <m.i initial={false} animate={{ scaleX: pct }} transition={spring.gentle} />
              </div>
              <span className="faint mono" aria-live="polite">
                {phase.phase === 'nomi' ? 'Nomi dei dispositivi' : 'Ping degli indirizzi'} · {phase.done}/{phase.total || '…'}
              </span>
            </div>
          </m.div>
        )}
      </AnimatePresence>

      {error && (
        <div className="notice alert" role="alert" style={{ marginTop: 14 }}>
          <TriangleAlert size={18} aria-hidden />
          <span>{error}</span>
        </div>
      )}

      {inv && (
        <>
          <div className="stats" style={{ marginTop: 18 }}>
            <Stat k="Dispositivi" v={String(others.length)} />
            <Stat k="Rispondono al ping" v={String(counts.ping)} />
            <Stat k="Solo ARP" v={String(counts.arp)} />
            <Stat k="Senza nome" v={String(counts.unnamed)} sev={counts.unnamed ? 'warn' : 'ok'} />
            <Stat k="MAC casuali o virtuali" v={String(counts.random)} />
            <Stat k="Durata" v={`${fmtNum(inv.durationMs / 1000, 1)} s`} />
          </div>
          {inv.note && (
            <p className="notice" style={{ marginTop: 12 }}>
              <TriangleAlert size={18} aria-hidden />
              <span>{inv.note}</span>
            </p>
          )}
          <div className="inv-toolbar">
            <input
              className="field"
              type="search"
              placeholder="Filtra per indirizzo, nome o MAC"
              aria-label="Filtra i dispositivi"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            <div className="chips-row" role="group" aria-label="Mostra">
              {(
                [
                  ['all', `Tutti (${inv.hosts.length})`],
                  ['unnamed', `Senza nome (${counts.unnamed})`],
                  ['random', `MAC casuale (${counts.random})`],
                  ['arp', `Solo ARP (${counts.arp})`],
                ] as [HostFilter, string][]
              ).map(([id, label]) => (
                <button key={id} className="chip" aria-pressed={filter === id} onClick={() => setFilter(id)}>
                  {label}
                </button>
              ))}
            </div>
          </div>
          <TableWrap label="Dispositivi trovati">
            <table>
              <thead>
                <tr>
                  <th>Indirizzo</th>
                  <th>Nome DNS</th>
                  <th>NetBIOS</th>
                  <th>MAC</th>
                  <th>Ping</th>
                  <th>Note</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((h) => (
                  <tr key={h.ip} className={h.self ? 'mine' : ''}>
                    <td className="mono">{h.ip}</td>
                    <td>{h.name ?? <span className="faint">—</span>}</td>
                    <td className="mono">{h.netbios ?? <span className="faint">—</span>}</td>
                    <td className="mono faint">{h.mac ?? '—'}</td>
                    <td className="mono">{h.rttMs !== undefined ? fmtMs(h.rttMs) : <span className="faint">—</span>}</td>
                    <td className="faint wrap">{hostNote(h)}</td>
                  </tr>
                ))}
                {!rows.length && (
                  <tr>
                    <td colSpan={6} className="faint" style={{ textAlign: 'center', padding: 20 }}>
                      Nessun dispositivo corrisponde al filtro.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </TableWrap>
          <p className="faint" style={{ fontSize: 13, marginBottom: 0 }}>
            Il produttore si ricava dai primi tre byte del MAC con gli elenchi pubblici dell'IEEE; i MAC casuali non lo indicano.
          </p>
        </>
      )}
    </m.section>
  );
}

// ---------------------------------------------------------------- Verifiche di raggiungibilità

interface Row {
  key: number;
  label: string;
  host: string;
  port: string;
  expect: ReachExpect;
}

const EXAMPLES: Omit<Row, 'key' | 'host'>[] = [
  { label: 'Cartella clinica (HTTPS)', port: '443', expect: 'reachable' },
  { label: 'PACS (DICOM)', port: '104', expect: 'reachable' },
  { label: 'Integrazione HL7 (MLLP)', port: '2575', expect: 'reachable' },
  { label: 'Controller di dominio (LDAP)', port: '389', expect: 'reachable' },
  { label: 'DNS interno', port: '53', expect: 'reachable' },
  { label: 'Rete dei dispositivi medicali', port: '', expect: 'isolated' },
  { label: 'Gestione degli apparati (SSH)', port: '22', expect: 'isolated' },
  { label: 'Telecamere (RTSP)', port: '554', expect: 'isolated' },
];

const HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$|^[0-9a-f:]+$/i;
const MAX_TARGETS = 64;

function rowError(r: Row): string | null {
  const host = r.host.trim();
  if (!host) return 'indica un indirizzo o un nome';
  if (host.length > 253 || !HOST_RE.test(host)) return 'indirizzo o nome non valido';
  if (r.port.trim()) {
    const p = Number(r.port);
    if (!Number.isInteger(p) || p < 1 || p > 65535) return 'porta tra 1 e 65535, o vuota per il ping';
  }
  return null;
}

const STATUS_TEXT: Record<ReachResult['status'], string> = {
  open: 'porta aperta',
  closed: 'porta chiusa (rifiuto)',
  filtered: 'nessuna risposta',
  reply: 'risponde al ping',
  noreply: 'non risponde al ping',
  unresolved: 'nome non risolto',
  refused: 'non verificata',
  error: 'errore',
};

function resultSev(r: ReachResult): Severity {
  if (r.status === 'refused' || r.status === 'error' || (r.expect === 'isolated' && r.status === 'unresolved')) return 'unknown';
  if (r.ok) return r.expect === 'reachable' && (r.rttMs ?? 0) > 100 ? 'warn' : 'ok';
  return r.expect === 'isolated' && r.status === 'closed' ? 'warn' : 'crit';
}

function ReachCard({ scan, live, source, setInfra }: ViewProps) {
  const toast = useToast();
  const reach = scan.infra?.reach;
  // Le destinazioni dipendono dalla zona: si ricordano per rete (gateway), separate dalla demo.
  const storeKey = `polaris.reach.${live ? (scan.gateway?.ip ?? 'senza-gateway') : `demo-${scan.agent.host ?? ''}`}`;
  const initial = useMemo<ReachTarget[]>(() => reach?.results.map(({ label, host, port, expect }) => ({ label, host, port, expect })) ?? [], [reach]);
  const [saved, setSaved] = useLocalState<ReachTarget[] | null>(storeKey, null);
  const seq = useRef(0);
  const toRows = (ts: ReachTarget[]): Row[] =>
    ts.map((t) => ({ key: ++seq.current, label: t.label ?? '', host: t.host, port: t.port ? String(t.port) : '', expect: t.expect }));
  const [rows, setRowsState] = useState<Row[]>(() => toRows(saved ?? initial));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [touched, setTouched] = useState(false);

  const setRows = (next: Row[]) => {
    setRowsState(next);
    setSaved(
      next.map((r) => ({
        ...(r.label.trim() ? { label: r.label.trim() } : {}),
        host: r.host.trim(),
        ...(r.port.trim() ? { port: Number(r.port) } : {}),
        expect: r.expect,
      })),
    );
  };
  const update = (key: number, patch: Partial<Row>) => setRows(rows.map((r) => (r.key === key ? { ...r, ...patch } : r)));
  const errors = rows.map(rowError);
  const invalid = errors.some(Boolean);
  const canRun = rows.length > 0 && rows.length <= MAX_TARGETS && !invalid && !busy;

  const run = async () => {
    setTouched(true);
    if (!canRun) return;
    setBusy(true);
    setError(null);
    const targets: ReachTarget[] = rows.map((r) => ({
      ...(r.label.trim() ? { label: r.label.trim() } : {}),
      host: r.host.trim(),
      ...(r.port.trim() ? { port: Number(r.port) } : {}),
      expect: r.expect,
    }));
    try {
      const res = live
        ? await runReach(targets)
        : await new Promise<ReturnType<typeof simulatedReach>>((ok) => setTimeout(() => ok(simulatedReach(scan, targets)), 900));
      setInfra({ reach: res });
      const bad = res.results.filter((r) => !r.ok).length;
      toast(bad ? `Verifiche completate · ${bad} da controllare` : 'Verifiche completate · tutto come previsto');
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setError(msg);
      toast(`Verifiche non riuscite: ${msg}`, 'error');
    } finally {
      setBusy(false);
    }
  };

  const okCount = reach?.results.filter((r) => r.ok).length ?? 0;
  return (
    <m.section variants={rise} className="card">
      <div className="card-head">
        <h2 style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
          <ShieldCheck size={19} aria-hidden /> Che cosa deve rispondere da questa rete
        </h2>
      </div>
      <p className="muted" style={{ marginTop: 0 }}>
        Indica i servizi che da qui <b>devono rispondere</b> (cartella clinica, PACS, DNS, controller di dominio) e le zone che <b>devono restare isolate</b>{' '}
        (rete dei dispositivi medicali, gestione degli apparati, telecamere, ospiti). Per ogni destinazione: una connessione TCP alla porta indicata, oppure due
        ping se la porta è vuota. Solo indirizzi privati, al massimo {MAX_TARGETS} destinazioni, quattro alla volta.
      </p>

      {source === 'file' ? (
        <div className="notice">
          <TriangleAlert size={18} aria-hidden />
          <span>Rapporto importato: qui si consultano gli esiti salvati. Le verifiche si eseguono dall'agente, dalla zona di rete in cui si trova il PC.</span>
        </div>
      ) : (
        <>
          <div className="reach-list" role={rows.length ? 'list' : undefined} aria-label={rows.length ? 'Destinazioni da verificare' : undefined}>
            <AnimatePresence initial={false}>
              {rows.map((r, i) => {
                const err = touched || r.host ? errors[i] : null;
                return (
                  <m.div
                    key={r.key}
                    role="listitem"
                    className="reach-row"
                    layout="position"
                    initial={{ opacity: 0, y: -6 }}
                    animate={{ opacity: 1, y: 0, transition: { duration: 0.3, ease: ease.out } }}
                    exit={{ opacity: 0, x: 16, transition: { duration: 0.18, ease: ease.inOut } }}
                  >
                    <input
                      className="field"
                      aria-label={`Etichetta della destinazione ${i + 1}`}
                      placeholder="Etichetta (facoltativa)"
                      value={r.label}
                      onChange={(e) => update(r.key, { label: e.target.value })}
                    />
                    <input
                      className="field mono"
                      aria-label={`Indirizzo o nome della destinazione ${i + 1}`}
                      aria-invalid={!!err}
                      aria-describedby={err ? `reach-err-${r.key}` : undefined}
                      placeholder="10.20.50.20 o pacs.clinica.local"
                      value={r.host}
                      onChange={(e) => update(r.key, { host: e.target.value })}
                      spellCheck={false}
                    />
                    <input
                      className="field mono port"
                      aria-label={`Porta della destinazione ${i + 1} (vuota per il ping)`}
                      inputMode="numeric"
                      placeholder="porta"
                      value={r.port}
                      onChange={(e) => update(r.key, { port: e.target.value.replace(/[^0-9]/g, '').slice(0, 5) })}
                    />
                    <select
                      className="field"
                      aria-label={`Attesa per la destinazione ${i + 1}`}
                      value={r.expect}
                      onChange={(e) => update(r.key, { expect: e.target.value as ReachExpect })}
                    >
                      <option value="reachable">deve rispondere</option>
                      <option value="isolated">deve essere isolata</option>
                    </select>
                    <button
                      className="btn small icon"
                      aria-label={`Rimuovi la destinazione ${i + 1}`}
                      title="Rimuovi"
                      onClick={() => setRows(rows.filter((x) => x.key !== r.key))}
                    >
                      <Trash2 size={15} aria-hidden />
                    </button>
                    {err && (
                      <span id={`reach-err-${r.key}`} className="reach-err">
                        {err}
                      </span>
                    )}
                  </m.div>
                );
              })}
            </AnimatePresence>
          </div>
          {!rows.length && (
            <div className="empty" style={{ padding: 20 }}>
              Nessuna destinazione: aggiungine una o parti dagli esempi.
            </div>
          )}

          <div className="reach-actions">
            <button
              className="btn small"
              onClick={() => setRows([...rows, { key: ++seq.current, label: '', host: '', port: '', expect: 'reachable' }])}
              disabled={rows.length >= MAX_TARGETS}
            >
              <Plus size={15} aria-hidden /> Aggiungi destinazione
            </button>
            <button
              className="btn small"
              onClick={() =>
                setRows(
                  [...rows, ...EXAMPLES.filter((x) => !rows.some((r) => r.label === x.label)).map((x) => ({ ...x, host: '', key: ++seq.current }))].slice(
                    0,
                    MAX_TARGETS,
                  ),
                )
              }
            >
              <ListPlus size={15} aria-hidden /> Esempi per strutture sanitarie
            </button>
            <span className="spacer" />
            <button className="btn primary" onClick={run} disabled={busy || !rows.length}>
              <Radar size={16} className={busy ? 'spin' : undefined} aria-hidden />
              {busy ? 'Verifica in corso…' : live ? 'Esegui le verifiche' : 'Simula le verifiche'}
            </button>
          </div>
          {touched && invalid && (
            <p className="reach-err" role="alert">
              Completa o correggi le destinazioni evidenziate.
            </p>
          )}
          {error && (
            <div className="notice alert" role="alert" style={{ marginTop: 12 }}>
              <TriangleAlert size={18} aria-hidden />
              <span>{error}</span>
            </div>
          )}
        </>
      )}

      {reach && reach.results.length > 0 && (
        <div style={{ marginTop: 20 }}>
          <h3>
            Esito · {okCount}/{reach.results.length} come previsto · {fmtWhen(reach.startedAt)}
            {reach.from ? ` · da ${reach.from}` : ''}
            {!live ? ' · simulazione' : ''}
          </h3>
          <TableWrap label="Esito delle verifiche">
            <table>
              <thead>
                <tr>
                  <th>Destinazione</th>
                  <th>Attesa</th>
                  <th>Esito</th>
                  <th>Tempo</th>
                  <th>Giudizio</th>
                </tr>
              </thead>
              <tbody>
                {reach.results.map((r, i) => {
                  const sev = resultSev(r);
                  return (
                    <tr key={i}>
                      <td>
                        {r.label && <div>{r.label}</div>}
                        <div className="mono faint" style={{ fontSize: 13 }}>
                          {r.host}
                          {r.port ? `:${r.port}` : ' (ping)'}
                          {r.ip && r.ip !== r.host ? ` → ${r.ip}` : ''}
                        </div>
                      </td>
                      <td>{r.expect === 'reachable' ? 'deve rispondere' : 'deve essere isolata'}</td>
                      <td title={r.error}>{STATUS_TEXT[r.status]}</td>
                      <td className="mono">
                        {r.rttMs !== undefined && (r.status === 'open' || r.status === 'reply' || r.status === 'closed') ? fmtMs(r.rttMs) : '—'}
                      </td>
                      <td>
                        <span className={`sev ${sev}`}>
                          <SevIcon sev={sev} size={14} />
                          {sev === 'ok'
                            ? 'come previsto'
                            : sev === 'unknown'
                              ? 'non verificata'
                              : r.expect === 'isolated'
                                ? sev === 'crit'
                                  ? 'non isolata'
                                  : 'da verificare'
                                : sev === 'warn'
                                  ? 'lenta'
                                  : 'non raggiungibile'}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </TableWrap>
        </div>
      )}
    </m.section>
  );
}

// ---------------------------------------------------------------- Autovalutazione

const CHOICES: { id: AnswerValue; label: string }[] = [
  { id: 'yes', label: 'Sì' },
  { id: 'partial', label: 'In parte' },
  { id: 'no', label: 'No' },
  { id: 'na', label: 'Non applicabile' },
];

/** Gruppo di opzioni (radio) con frecce, Home e Fine; un secondo clic sulla scelta la annulla. */
function Choice({ value, onChange, label, disabled }: { value?: AnswerValue; onChange: (v?: AnswerValue) => void; label: string; disabled?: boolean }) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const current = CHOICES.findIndex((c) => c.id === value);
  const onKey = (e: KeyboardEvent, i: number) => {
    let next = -1;
    if (e.key === 'ArrowRight' || e.key === 'ArrowDown') next = (i + 1) % CHOICES.length;
    else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') next = (i - 1 + CHOICES.length) % CHOICES.length;
    else if (e.key === 'Home') next = 0;
    else if (e.key === 'End') next = CHOICES.length - 1;
    if (next < 0) return;
    e.preventDefault();
    onChange(CHOICES[next].id);
    refs.current[next]?.focus();
  };
  return (
    <div className="choice" role="radiogroup" aria-label={label}>
      {CHOICES.map((c, i) => {
        const on = c.id === value;
        return (
          <button
            key={c.id}
            ref={(el) => {
              refs.current[i] = el;
            }}
            role="radio"
            aria-checked={on}
            tabIndex={on || (current < 0 && i === 0) ? 0 : -1}
            disabled={disabled}
            data-v={c.id}
            onClick={() => onChange(on ? undefined : c.id)}
            onKeyDown={(e) => onKey(e, i)}
          >
            {c.label}
          </button>
        );
      })}
    </div>
  );
}

const scoreSev = (s: number): Severity => (s >= 80 ? 'ok' : s >= 50 ? 'warn' : 'crit');

function AssessmentCard({ assessment, go }: ViewProps) {
  const openGuide = useOpenGuide();
  const [open, setOpen] = useState<AssessAreaId | null>('segmentazione');
  const [confirm, setConfirm] = useState(false);
  const scores = useMemo(() => scoreAssessment(assessment.answers), [assessment.answers]);
  const answered = ASSESS_QUESTIONS.filter((q) => assessment.answers[q.id]).length;
  useEffect(() => {
    if (!confirm) return;
    const t = setTimeout(() => setConfirm(false), 4000);
    return () => clearTimeout(t);
  }, [confirm]);

  return (
    <m.section variants={rise} className="card">
      <div className="card-head">
        <h2 style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
          <ClipboardCheck size={19} aria-hidden /> Misure organizzative
        </h2>
        <span className="sub">
          {answered} di {ASSESS_QUESTIONS.length} risposte
        </span>
        <span className="spacer" />
        {answered > 0 && (
          <button className="btn small" onClick={() => go('plan')}>
            Vedi il piano
          </button>
        )}
        {answered > 0 && !assessment.readOnly && (
          <button
            className="btn small"
            onClick={() => {
              if (!confirm) return setConfirm(true);
              assessment.reset();
              setConfirm(false);
            }}
          >
            <RotateCcw size={15} aria-hidden /> {confirm ? 'Conferma: azzera tutto' : 'Azzera'}
          </button>
        )}
      </div>
      <p className="muted" style={{ marginTop: 0 }}>
        Ciò che una misura di rete non vede: segmentazione, dispositivi medicali, accessi dei fornitori, backup, continuità e gestione degli incidenti. Le
        risposte restano su questo PC ed entrano nel rapporto esportato; ogni "no" o "in parte" aggiunge al piano l'azione che manca. È una dichiarazione, non
        una verifica: non sostituisce un audit.
      </p>
      {assessment.readOnly && (
        <div className="notice" style={{ marginBottom: 14 }}>
          <TriangleAlert size={18} aria-hidden />
          <span>Risposte del rapporto importato: si possono consultare ma non modificare.</span>
        </div>
      )}
      <m.div className="assess" variants={cascade(0.04)}>
        {scores.map((s) => {
          const isOpen = open === s.area.id;
          const qs = ASSESS_QUESTIONS.filter((q) => q.area === s.area.id);
          const guide = guideById(s.area.guide);
          const sev = s.score === null ? 'unknown' : scoreSev(s.score);
          return (
            <m.div key={s.area.id} className="assess-area" data-open={isOpen} variants={rise}>
              <button className="assess-head" aria-expanded={isOpen} aria-controls={`area-${s.area.id}`} onClick={() => setOpen(isOpen ? null : s.area.id)}>
                <span className="assess-title">
                  <strong>{s.area.title}</strong>
                  <span className="faint">{s.area.summary}</span>
                </span>
                <span className="assess-score" style={{ ['--c' as string]: sevColor(sev) }}>
                  <span className="mono">{s.score === null ? '—' : s.score}</span>
                  <span className="meter" aria-hidden>
                    <m.i initial={false} animate={{ scaleX: (s.score ?? 0) / 100 }} transition={spring.gentle} style={{ background: 'var(--c)' }} />
                  </span>
                  <span className="faint">
                    {s.answered + qs.filter((q) => assessment.answers[q.id] === 'na').length}/{s.total}
                  </span>
                </span>
                <m.span className="chev" animate={{ rotate: isOpen ? 180 : 0 }} transition={spring.snappy} aria-hidden>
                  <ChevronDown size={18} />
                </m.span>
              </button>
              <AnimatePresence initial={false}>
                {isOpen && (
                  <m.div
                    id={`area-${s.area.id}`}
                    key="body"
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: 'auto', opacity: 1, transition: { height: spring.smooth, opacity: { duration: 0.25, delay: 0.05 } } }}
                    exit={{ height: 0, opacity: 0, transition: { height: { duration: 0.28, ease: ease.inOut }, opacity: { duration: 0.15 } } }}
                    style={{ overflow: 'hidden' }}
                  >
                    <ol className="assess-qs">
                      {qs.map((q) => (
                        <li key={q.id} data-answer={assessment.answers[q.id] ?? ''}>
                          <span className="q-text">
                            {q.text}
                            {q.weight === 3 && (
                              <span className="tag" title="Pesa di più nel punteggio">
                                essenziale
                              </span>
                            )}
                          </span>
                          <Choice label={q.text} value={assessment.answers[q.id]} disabled={assessment.readOnly} onChange={(v) => assessment.set(q.id, v)} />
                        </li>
                      ))}
                    </ol>
                    {openGuide && guide && (
                      <p className="plan-guides assess-foot">
                        <BookOpenText size={14} aria-hidden />
                        <span>Approfondisci:</span>
                        <button className="link-btn" onClick={() => openGuide(guide.id)}>
                          {guide.title}
                        </button>
                      </p>
                    )}
                  </m.div>
                )}
              </AnimatePresence>
            </m.div>
          );
        })}
      </m.div>
      <p className="faint" style={{ fontSize: 13, marginBottom: 0 }}>
        Aree e domande riprendono le guide della biblioteca; i riferimenti normativi citati vanno verificati sui testi ufficiali.
      </p>
    </m.section>
  );
}
