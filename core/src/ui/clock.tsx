import { Pause, Play, RotateCw, TriangleAlert } from 'lucide-react';
import { useEffect, useState } from 'react';
import type { CSSProperties } from 'react';
import type { PcData } from '../engine';
import { HexLoader } from './anim';
import { cpuClock } from './api';
import type { CpuClockSample } from './api';
import { LiveChart } from './charts';
import type { ViewProps } from './views';

// Velocità dei core in tempo reale (il "Core Speed" di CPU-Z). Con l'agente
// una lettura al secondo dai contatori delle prestazioni di Windows, gli
// stessi di Gestione attività; nella demo valori simulati e dichiarati. Si
// misura solo mentre il riquadro è visibile e la finestra in primo piano.

const HISTORY = 60;

export interface ClockState {
  sample?: CpuClockSample;
  /** Media dei core al secondo (null: lettura non riuscita). */
  history: (number | null)[];
  /** Il core più veloce visto in questa sessione. */
  peak: number;
  tick: number;
  error?: string;
}

/** Numero pseudocasuale ripetibile in [0, 1) da due interi. */
function noise(a: number, b: number): number {
  const x = Math.sin(a * 12.9898 + b * 78.233) * 43758.5453;
  return x - Math.floor(x);
}

/**
 * Lettura simulata per la demo: un'attività che sale e scende lentamente,
 * core più o meno impegnati, turbo fino a circa 1,6 volte la base.
 */
export function simulateClock(base: number, threads: number, t: number): CpuClockSample {
  const wave = 0.5 + 0.5 * Math.sin(t / 7);
  const cores = Array.from({ length: Math.max(1, threads) }, (_, i) => {
    const r = noise(t, i);
    const load = Math.round(100 * Math.min(1, wave * r * 1.3));
    const mhz = Math.round(base * (0.62 + 0.98 * wave * (0.45 + 0.55 * r)));
    return { id: `0,${i}`, mhz, loadPct: load };
  });
  const mhz = Math.round(cores.reduce((s, c) => s + c.mhz, 0) / cores.length);
  const loadPct = Math.round(cores.reduce((s, c) => s + c.loadPct, 0) / cores.length);
  return { mhz, maxMhz: Math.max(...cores.map((c) => c.mhz)), baseMhz: base, perfPct: Math.round((100 * mhz) / base), loadPct, cores, at: new Date().toISOString() };
}

/** Aggiunge una lettura allo stato: storico degli ultimi 60 secondi e massimo della sessione. */
export function pushSample(s: ClockState, smp: CpuClockSample): ClockState {
  return { sample: smp, history: [...s.history, smp.mhz].slice(-HISTORY), peak: Math.max(s.peak, smp.maxMhz), tick: s.tick + 1 };
}

type Mode = 'live' | 'demo' | 'off';

function useCpuClock(mode: Mode, paused: boolean, base: number, threads: number, retry: number): ClockState {
  const [state, setState] = useState<ClockState>({ history: [], peak: 0, tick: 0 });
  useEffect(() => {
    if (mode === 'off' || paused) return;
    let alive = true;
    let busy = false;
    let t = 0;
    let ctl: AbortController | undefined;
    const step = async () => {
      if (busy || document.visibilityState !== 'visible') return;
      busy = true;
      try {
        ctl = new AbortController();
        const smp = mode === 'live' ? await cpuClock(ctl.signal) : simulateClock(base, threads, t++);
        if (alive) setState((s) => pushSample(s, smp));
      } catch (e) {
        if (!alive) return;
        // Dopo un errore ci si ferma: il pulsante Riprova riparte.
        clearInterval(id);
        setState((s) => ({ ...s, error: e instanceof Error ? e.message : String(e) }));
      } finally {
        busy = false;
      }
    };
    const id = setInterval(step, 1000);
    setState((s) => ({ ...s, error: undefined }));
    step();
    return () => {
      alive = false;
      clearInterval(id);
      ctl?.abort();
    };
  }, [mode, paused, base, threads, retry]);
  return state;
}

const ghz = (mhz: number) => (mhz / 1000).toLocaleString('it-IT', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const num = (v: number, d = 0) => v.toLocaleString('it-IT', { minimumFractionDigits: d, maximumFractionDigits: d });

export function CoreClock({ pc, live, source }: { pc: PcData; live: boolean; source: ViewProps['source'] }) {
  const mode: Mode = live ? 'live' : source === 'demo' ? 'demo' : 'off';
  const [paused, setPaused] = useState(false);
  const [retry, setRetry] = useState(0);
  const cpu = pc.hardware?.cpu;
  const base = pc.cpu?.maxMhz || 2900;
  const threads = cpu?.threads || pc.cpu?.threads || 8;
  const st = useCpuClock(mode, paused, base, threads, retry);
  const bus = cpu?.busMhz;

  if (mode === 'off') {
    return (
      <div className="hw-block clock">
        <h3>Velocità dei core in tempo reale</h3>
        <p className="faint clock-note">Si misura dal vivo solo con l&apos;agente sul PC: un rapporto importato non la contiene.</p>
      </div>
    );
  }
  const smp = st.sample;
  const scale = Math.max(st.peak, (smp?.baseMhz || base) * 1.25, smp?.maxMhz ?? 0);
  const coreMhz = (smp?.cores ?? []).map((c) => c.mhz).filter((v) => v > 0);
  return (
    <div className="hw-block clock" role="group" aria-label="Velocità dei core in tempo reale">
      <div className="clock-head">
        <span className={`live-dot${paused || st.error ? ' off' : ''}`} aria-hidden="true" />
        <h3>Velocità dei core in tempo reale</h3>
        {mode === 'demo' && <span className="tag">simulata</span>}
        <span className="spacer" />
        {!st.error && (
          <button className="btn small icon" onClick={() => setPaused((p) => !p)} aria-pressed={paused} aria-label="Pausa della misura" title={paused ? 'Riprendi' : 'Metti in pausa'}>
            {paused ? <Play size={15} aria-hidden /> : <Pause size={15} aria-hidden />}
          </button>
        )}
      </div>
      {st.error ? (
        <div className="tool-problem clock-error">
          <TriangleAlert size={14} aria-hidden />
          <span>
            Misura non disponibile: {st.error}.{' '}
            <button className="link-btn" onClick={() => setRetry((r) => r + 1)}>
              <RotateCw size={13} aria-hidden /> Riprova
            </button>
          </span>
        </div>
      ) : !smp ? (
        <p className="clock-wait">
          <HexLoader size={18} label="Prima lettura in corso" /> Prima lettura…
        </p>
      ) : (
        <>
          <div className="clock-main">
            <p className="clock-big">
              <b>{ghz(smp.mhz)}</b> <span>GHz</span>
              <small>
                media dei core{smp.perfPct ? ` · ${num(smp.perfPct)} % della base` : ''}
                {smp.perfPct > 102 ? ' (turbo)' : ''}
              </small>
            </p>
            <dl className="kv hw-kv clock-kv">
              <dt>Core più veloce</dt>
              <dd>{ghz(smp.maxMhz)} GHz</dd>
              <dt>Frequenza di base</dt>
              <dd>{ghz(smp.baseMhz || base)} GHz</dd>
              <dt>Massima in questa sessione</dt>
              <dd>{ghz(st.peak)} GHz</dd>
              {bus ? (
                <>
                  <dt>Bus e moltiplicatore</dt>
                  <dd>
                    {bus} MHz × {num(smp.mhz / bus, 1)} (nominale)
                  </dd>
                </>
              ) : null}
              <dt>Carico medio</dt>
              <dd>{num(smp.loadPct)} %</dd>
            </dl>
          </div>
          <LiveChart
            series={[{ label: 'media dei core in MHz', color: 'var(--accent)', samples: st.history }]}
            tick={st.tick}
            maxPoints={HISTORY}
            height={140}
            unit="MHz"
            label="Velocità dei core negli ultimi 60 secondi"
          />
          {coreMhz.length > 0 && (
            <div
              className="clock-cores"
              style={{ '--n': smp.cores.length } as CSSProperties}
              role="img"
              aria-label={`${smp.cores.length} processori logici, da ${ghz(Math.min(...coreMhz))} a ${ghz(Math.max(...coreMhz))} GHz`}
            >
              {smp.cores.map((c, i) => (
                <span key={c.id} title={`Processore ${i}: ${ghz(c.mhz)} GHz, carico ${num(c.loadPct)} %`}>
                  <i style={{ height: `${Math.max(4, Math.min(100, (100 * c.mhz) / scale))}%` }} />
                </span>
              ))}
            </div>
          )}
        </>
      )}
      <p className="faint clock-note">
        Come in Gestione attività: Windows ricava la frequenza effettiva dai contatori del processore. Sopra il 100 % della base il processore è in
        turbo; molto sotto risparmia energia, oppure lo frenano temperatura o alimentazione. Bus e moltiplicatore sono valori nominali dichiarati dal
        firmware: CPU-Z li misura con un driver in kernel, che Polaris non usa.
      </p>
    </div>
  );
}
