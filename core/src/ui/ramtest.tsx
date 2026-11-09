import { CircleStop, MemoryStick, Play } from 'lucide-react';
import { m } from 'motion/react';
import { useEffect, useState } from 'react';
import { ramTestSeverity } from '../engine';
import type { RamTest, Scan, Severity } from '../engine';
import { benchStatus, runRamTest, stopBench } from './api';
import type { RamRequest } from './api';
import { Segmented, SevIcon, TableWrap, useToast } from './components';
import { rise, spring } from './motion';
import type { ViewProps } from './views';

// Test della RAM con Windows acceso, come HCI MemTest: solo su richiesta,
// con conferma, interrompibile. Prova la memoria libera; quella usata da
// Windows si prova con Memtest86+ da chiavetta (nella cassetta).

type Preset = RamRequest['preset'];
const PRESET: { id: Preset; label: string; min: number }[] = [
  { id: 'quick', label: 'Rapido, 3 minuti', min: 3 },
  { id: 'standard', label: 'Standard, 10 minuti', min: 10 },
  { id: 'long', label: 'Lungo, 30 minuti', min: 30 },
];

export const RAM_TEST_NAME: Record<string, string> = {
  'own-address': 'Indirizzo in ogni cella',
  'mi-01': 'Inversioni con zeri e uni',
  'mi-random': 'Inversioni con uno schema casuale',
  'random-seq': 'Sequenza casuale',
  'mi-walk8': 'Inversioni con un bit acceso per byte',
  modulo20: 'Schema ogni 20 celle',
  'block-move': 'Spostamento di blocchi',
  'bit-fade': 'Decadimento dei bit (memoria ferma)',
  done: 'Fine',
};

interface RamRun {
  preset: Preset;
  done: number;
  phase: string;
  pass?: number;
  errors?: number;
  value?: number;
}

// Lo stato vive a livello di modulo: il test continua anche cambiando pagina.
let ramPromise: Promise<RamTest> | null = null;
let ramLast: RamRun | null = null;
let ramCancel: (() => void) | null = null;
const listeners = new Set<(r: RamRun | null) => void>();
const publish = (r: RamRun | null) => {
  ramLast = r;
  listeners.forEach((f) => f(r));
};

/** Simulazione per la demo: un test pulito, accelerato. */
export function simulatedRamTest(scan: Scan, preset: Preset): RamTest {
  const total = scan.pc?.memory?.totalMB ?? 8192;
  const avail = scan.pc?.memory?.availableMB ?? Math.round(total / 2);
  const tested = Math.max(256, avail - Math.max(1024, Math.round(total / 8)));
  const min = PRESET.find((p) => p.id === preset)!.min;
  return {
    startedAt: new Date().toISOString(),
    durationMs: min * 60000,
    preset,
    plannedSec: min * 60,
    stop: 'time',
    totalMB: total,
    availableMB: avail,
    testedMB: tested,
    lockedMB: tested,
    threads: scan.pc?.cpu?.threads ?? 8,
    passes: min,
    mbs: 9800,
    tests: Object.keys(RAM_TEST_NAME)
      .filter((k) => k !== 'done' && (k !== 'bit-fade' || preset === 'long'))
      .map((name) => ({ name, runs: name === 'bit-fade' ? 1 : min, errors: 0 })),
    errors: 0,
  };
}

function simulate(scan: Scan, preset: Preset): Promise<RamTest> {
  const result = simulatedRamTest(scan, preset);
  const names = Object.keys(RAM_TEST_NAME).filter((k) => k !== 'done' && k !== 'bit-fade');
  return new Promise((resolve, reject) => {
    const t0 = performance.now();
    let timer = 0;
    ramCancel = () => {
      clearTimeout(timer);
      reject(new Error('test interrotto'));
    };
    const step = () => {
      const t = performance.now() - t0;
      if (t >= 6000) return resolve(result);
      publish({ preset, done: t / 6000, phase: names[Math.floor(t / 300) % names.length], pass: Math.floor(t / 2100) + 1, errors: 0, value: 9800 + Math.sin(t / 200) * 300 });
      timer = window.setTimeout(step, 100);
    };
    step();
  });
}

function useRamRun(): RamRun | null {
  const [run, setRun] = useState<RamRun | null>(ramLast);
  useEffect(() => {
    listeners.add(setRun);
    // Un avanzamento pubblicato tra il primo disegno e l'iscrizione non va perso.
    setRun(ramLast);
    return () => {
      listeners.delete(setRun);
    };
  }, []);
  return run;
}

const errorsText = (n: number) => `${n} ${n === 1 ? 'errore' : 'errori'}`;

/** Messaggio di fine test: un test interrotto o fermato non è "finito". */
function endMessage(r: RamTest): string {
  const how = r.stop === 'cancelled' ? 'interrotto' : r.stop === 'low-memory' ? 'fermato per poca memoria libera' : 'finito';
  if (r.errors) return `Test della RAM ${how}: ${errorsText(r.errors)} ${r.errors === 1 ? 'trovato' : 'trovati'}`;
  return how === 'finito' ? 'Test della RAM finito: nessun errore' : `Test della RAM ${how}: nessun errore nella parte provata`;
}

const gb = (mb: number) => `${(mb / 1024).toFixed(mb < 10240 ? 1 : 0).replace('.', ',')} GB`;

function Result({ r }: { r: RamTest }) {
  const sev: Severity = ramTestSeverity(r);
  const pct = r.totalMB ? Math.round((r.testedMB / r.totalMB) * 100) : 0;
  return (
    <div className="ram-result">
      <p className={`ram-verdict c-${sev}`}>
        <SevIcon sev={sev} size={18} />{' '}
        {r.errors
          ? `${r.errors} ${r.errors === 1 ? 'errore trovato' : 'errori trovati'} su ${gb(r.testedMB)}`
          : `Nessun errore su ${gb(r.testedMB)} (${pct} % della RAM), ${r.passes} ${r.passes === 1 ? 'passaggio completo' : 'passaggi completi'}`}
      </p>
      <p className="faint">
        Test del {new Date(r.startedAt).toLocaleString('it-IT', { dateStyle: 'short', timeStyle: 'short' })}, {r.threads} thread
        {r.lockedMB < r.testedMB ? `; bloccati in RAM solo ${gb(r.lockedMB)}: esito meno affidabile` : ''}
        {r.stop === 'cancelled' ? '; interrotto' : r.stop === 'low-memory' ? '; fermato perché Windows aveva poca memoria libera' : ''}
        {r.onAC === false ? '; a batteria' : ''}.
      </p>
      {r.errorSamples && r.errorSamples.length > 0 && (
        <TableWrap label="Errori trovati nel test della RAM">
          <table className="pc-table">
            <thead>
              <tr>
                <th>Prova</th>
                <th>Passaggio</th>
                <th>Posizione nel blocco</th>
                <th>Atteso</th>
                <th>Letto</th>
              </tr>
            </thead>
            <tbody>
              {r.errorSamples.map((e, i) => (
                <tr key={i}>
                  <td>{RAM_TEST_NAME[e.test] ?? e.test}</td>
                  <td>{e.pass + 1}</td>
                  <td className="mono">{e.offsetMB.toFixed(1).replace('.', ',')} MB</td>
                  <td className="mono">{e.expected}</td>
                  <td className="mono">{e.actual}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
      {r.badBits && <p className="faint">Bit trovati diversi: <span className="mono">{r.badBits}</span>. La posizione è nel blocco di memoria del test: non indica il modulo né lo slot.</p>}
    </div>
  );
}

export function RamTestCard({ scan, live, source, addBench }: ViewProps) {
  const toast = useToast();
  const run = useRamRun();
  const [preset, setPreset] = useState<Preset>('quick');
  const [consent, setConsent] = useState(false);
  const last = scan.pc?.bench?.ram;
  const busy = !!run;
  const canRun = live || source === 'demo';
  const total = scan.pc?.memory?.totalMB;
  const avail = scan.pc?.memory?.availableMB;
  const reserve = total ? Math.max(1024, Math.round(total / 8)) : 1024;
  const testMB = avail !== undefined ? Math.max(0, avail - reserve) : undefined;
  const lowMem = testMB !== undefined && testMB < 256;
  const min = PRESET.find((p) => p.id === preset)!.min;

  // Il risultato va al rapporto mostrato quando il test è partito.
  const start = (resume = false) => {
    if (ramPromise) return;
    const target = { host: scan.agent.host, live };
    publish({ preset, done: 0, phase: 'start' });
    ramPromise = live
      ? runRamTest(
          { kind: 'ram', preset, confirm: true },
          (st) => {
            const p = st.progress;
            if (p && st.kind === 'ram') publish({ preset, done: p.done, phase: p.phase, pass: p.pass, errors: p.errors, value: p.value });
          },
          { resume },
        )
      : simulate(scan, preset);
    ramPromise
      .then((r) => {
        if (addBench({ ram: r }, target)) toast(endMessage(r), r.errors ? 'warn' : 'ok', 'complete');
      })
      .catch((e) => {
        const msg = e instanceof Error ? e.message : String(e);
        if (/interrott/i.test(msg)) toast('Test della RAM interrotto', 'ok', 'tap');
        else toast(`Test della RAM non riuscito: ${msg}`, 'error');
      })
      .finally(() => {
        ramPromise = null;
        ramCancel = null;
        publish(null);
      });
  };

  // Un test della RAM avviato prima (anche da un'altra finestra, o prima di
  // ricaricare la pagina) si riprende invece di andare perso.
  useEffect(() => {
    if (!live || ramPromise) return;
    let alive = true;
    benchStatus()
      .then((st) => {
        if (alive && st.running && st.kind === 'ram') start(true);
      })
      .catch(() => undefined);
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [live]);
  const stop = () => {
    if (ramCancel) ramCancel();
    else stopBench().catch(() => undefined);
  };

  return (
    <m.section variants={rise} className="card ram-card">
      <div className="card-head">
        <h2 className="disk-title">
          <MemoryStick size={19} aria-hidden /> Test della RAM con Windows acceso
        </h2>
        <span className="sub">come HCI MemTest: solo la memoria libera, su richiesta</span>
      </div>
      <p className="muted">
        Scrive e rilegge sequenze di bit nella memoria libera, tenuta bloccata in RAM. La memoria usata da Windows e dai programmi aperti non si può provare da Windows:
        per quella serve Memtest86+ da chiavetta, nella cassetta degli attrezzi.
      </p>
      {!canRun ? (
        <p className="faint">Il test si avvia solo con Polaris in esecuzione su questo PC.</p>
      ) : busy && run ? (
        <div className="bench-live">
          <div className="progress live" role="progressbar" aria-label="Avanzamento del test della RAM" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(run.done * 100)}>
            <m.i initial={false} animate={{ scaleX: Math.min(1, run.done) }} transition={spring.gentle} />
          </div>
          <div className="bench-live-row">
            <span className="faint" aria-live="polite">
              {run.phase === 'start' ? 'Riservo la memoria…' : `Passaggio ${run.pass ?? 1} · ${RAM_TEST_NAME[run.phase] ?? run.phase}`}
              {run.errors ? ` · ${errorsText(run.errors)}` : run.phase !== 'start' ? ' · nessun errore finora' : ''}
            </span>
            <button className="btn small" onClick={stop}>
              <CircleStop size={15} aria-hidden /> Interrompi
            </button>
          </div>
        </div>
      ) : (
        <>
          <Segmented value={preset} options={PRESET.map((p) => ({ id: p.id, label: p.label }))} onChange={setPreset} label="Durata del test della RAM" />
          <label className="consent">
            <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} />{' '}
            {testMB !== undefined && total
              ? `Il test occupa circa ${gb(testMB)} di RAM (${Math.round((testMB / total) * 100)} % del totale) e tutti i processori per ${min} minuti: il computer sarà lento. Ho chiuso i programmi che non servono e collegato l'alimentatore.`
              : `Il test occupa la memoria libera e tutti i processori per ${min} minuti: il computer sarà lento. Ho chiuso i programmi che non servono e collegato l'alimentatore.`}
          </label>
          {lowMem && <p className="c-warn">Memoria libera insufficiente per un test utile: chiudi qualche programma e ripeti l'analisi.</p>}
          <button className="btn primary" disabled={!consent || lowMem} onClick={() => start()}>
            <Play size={15} aria-hidden /> Avvia il test della RAM
          </button>
          <p className="faint card-foot">Puoi interromperlo quando vuoi; se un altro programma ha bisogno di memoria il test si ferma da solo.</p>
        </>
      )}
      {last && !busy && <Result r={last} />}
    </m.section>
  );
}
