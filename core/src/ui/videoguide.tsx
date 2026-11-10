import { ChevronLeft, ChevronRight, Clapperboard, FileText, Pause, Play, RotateCcw, Volume2, VolumeX } from 'lucide-react';
import { m, useReducedMotion } from 'motion/react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { KeyboardEvent as ReactKeyboardEvent } from 'react';
import { analyze } from '../engine';
import { clinicScan } from '../demo/clinic';
import { demoScan } from '../demo/sample';
import { videoById } from '../guides';
import type { VideoGuide } from '../guides';
import { Diagram } from './diagrams';
import { NetMap } from './netmap';

// Videoguide: scene animate con la narrazione letta dalla voce italiana di
// Windows (Microsoft Elsa) attraverso la sintesi vocale del sistema, sul PC.
// Si usano solo le voci installate sul computer (localService): le voci
// "online" di alcuni browser manderebbero il testo a un servizio esterno.
// Ogni frase è anche un sottotitolo; senza una voce italiana, o con l'audio
// spento, la guida procede con i soli sottotitoli al ritmo di lettura.

const PREF_KEY = 'polaris.video';
const RATES = [
  { v: 0.85, label: 'Lenta' },
  { v: 1, label: 'Normale' },
  { v: 1.15, label: 'Veloce' },
];

interface Prefs {
  voice?: string;
  rate: number;
  muted: boolean;
  transcript: boolean;
}

function readPrefs(): Prefs {
  try {
    const v = JSON.parse(localStorage.getItem(PREF_KEY) ?? '{}') as Partial<Prefs>;
    return { voice: v.voice, rate: typeof v.rate === 'number' ? v.rate : 1, muted: !!v.muted, transcript: !!v.transcript };
  } catch {
    return { rate: 1, muted: false, transcript: false };
  }
}

function savePrefs(p: Prefs) {
  try {
    localStorage.setItem(PREF_KEY, JSON.stringify(p));
  } catch {
    /* archiviazione non disponibile */
  }
}

const synth = (): SpeechSynthesis | undefined => (typeof window !== 'undefined' && 'speechSynthesis' in window ? window.speechSynthesis : undefined);

/** Voci italiane installate sul PC; Elsa per prima. */
export function italianVoices(all: SpeechSynthesisVoice[]): SpeechSynthesisVoice[] {
  const it = all.filter((v) => /^it([-_]|$)/i.test(v.lang) && v.localService);
  return it.sort((a, b) => Number(/elsa/i.test(b.name)) - Number(/elsa/i.test(a.name)) || a.name.localeCompare(b.name));
}

function useVoices(): SpeechSynthesisVoice[] {
  const [voices, setVoices] = useState<SpeechSynthesisVoice[]>(() => italianVoices(synth()?.getVoices() ?? []));
  useEffect(() => {
    const s = synth();
    if (!s) return;
    const load = () => setVoices(italianVoices(s.getVoices()));
    load();
    s.addEventListener?.('voiceschanged', load);
    return () => s.removeEventListener?.('voiceschanged', load);
  }, []);
  return voices;
}

/** Tempo di lettura di una frase senza voce: circa 14 caratteri al secondo, almeno 2,4 secondi. */
export const readingMs = (text: string, rate = 1) => Math.max(2400, (text.length / 14) * 1000) / rate;

/** Durata stimata della videoguida in minuti, arrotondata. */
export function videoMinutes(v: VideoGuide): number {
  const ms = v.scenes.reduce((a, s) => a + s.narration.reduce((b, t) => b + readingMs(t) + 350, 0), 0);
  return Math.max(1, Math.round(ms / 60000));
}

const flat = (v: VideoGuide) => v.scenes.flatMap((s, si) => s.narration.map((t, ti) => ({ si, ti, t })));

export function VideoPlayer({ video }: { video: VideoGuide }) {
  const reduce = useReducedMotion();
  const voices = useVoices();
  const [prefs, setPrefs] = useState<Prefs>(readPrefs);
  const [pos, setPos] = useState(0); // indice della frase in tutta la guida
  const [playing, setPlaying] = useState(false);
  const [ended, setEnded] = useState(false);
  const lines = useMemo(() => flat(video), [video]);
  const cur = lines[Math.min(pos, lines.length - 1)];
  const scene = video.scenes[cur.si];
  const voice = voices.find((v) => v.voiceURI === prefs.voice) ?? voices[0];
  const speaking = !prefs.muted && !!voice && !!synth();
  const timer = useRef<number | undefined>(undefined);
  const token = useRef(0);
  const scans = useMemo(() => ({ casa: { scan: demoScan, a: analyze(demoScan) }, clinica: { scan: clinicScan, a: analyze(clinicScan) } }), []);

  const update = (p: Partial<Prefs>) =>
    setPrefs((cur) => {
      const n = { ...cur, ...p };
      savePrefs(n);
      return n;
    });

  const stopAll = useCallback(() => {
    token.current++;
    window.clearTimeout(timer.current);
    synth()?.cancel();
  }, []);

  // Lettura della frase corrente; alla fine si passa alla successiva.
  useEffect(() => {
    if (!playing) return;
    const my = ++token.current;
    const next = () => {
      if (token.current !== my) return;
      if (pos + 1 < lines.length) setPos(pos + 1);
      else {
        setPlaying(false);
        setEnded(true);
      }
    };
    const text = lines[pos].t;
    if (speaking && voice) {
      const s = synth()!;
      s.cancel();
      const u = new SpeechSynthesisUtterance(text);
      u.voice = voice;
      u.lang = voice.lang || 'it-IT';
      u.rate = prefs.rate;
      u.onend = () => {
        timer.current = window.setTimeout(next, 350);
      };
      // Una voce che non parte non deve bloccare la guida: si prosegue a tempo.
      u.onerror = () => {
        timer.current = window.setTimeout(next, readingMs(text, prefs.rate));
      };
      // Chromium a volte ignora una lettura chiesta subito dopo cancel().
      timer.current = window.setTimeout(() => {
        if (token.current === my) s.speak(u);
      }, 60);
    } else {
      timer.current = window.setTimeout(next, readingMs(text, prefs.rate));
    }
    return () => {
      window.clearTimeout(timer.current);
    };
  }, [playing, pos, speaking, voice, prefs.rate, lines]);

  useEffect(() => stopAll, [stopAll]);

  const play = () => {
    if (ended) {
      setPos(0);
      setEnded(false);
    }
    setPlaying(true);
  };
  const pause = () => {
    stopAll();
    setPlaying(false);
  };
  const goScene = (si: number) => {
    stopAll();
    setEnded(false);
    setPos(lines.findIndex((l) => l.si === si));
  };
  const onKey = (e: ReactKeyboardEvent) => {
    if (e.target !== e.currentTarget) return;
    if (e.key === ' ' || e.key === 'k') {
      e.preventDefault();
      if (playing) pause();
      else play();
    } else if (e.key === 'ArrowRight' && cur.si + 1 < video.scenes.length) goScene(cur.si + 1);
    else if (e.key === 'ArrowLeft' && cur.si > 0) goScene(cur.si - 1);
  };

  const pct = ((pos + (ended ? 1 : 0)) / lines.length) * 100;
  const noVoice = !synth() || voices.length === 0;

  return (
    <div className="vg" tabIndex={0} onKeyDown={onKey} role="region" aria-label={`Videoguida: ${video.title}`}>
      <div className="vg-stage">
        <m.div key={`${cur.si}`} className="vg-visual" initial={reduce ? false : { opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35 }}>
          {scene.diagram ? (
            <Diagram id={scene.diagram} caption={scene.title} />
          ) : scene.map ? (
            <div className="vg-map">
              <NetMap scan={scans[scene.map].scan} analysis={scans[scene.map].a} height={360} compact />
            </div>
          ) : null}
        </m.div>
        <p className="vg-caption" aria-live="polite">
          <span className="vg-scene">
            {cur.si + 1}/{video.scenes.length} · {scene.title}
          </span>
          {cur.t}
        </p>
      </div>
      <div className="vg-progress" role="progressbar" aria-label="Avanzamento della videoguida" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(pct)}>
        <i style={{ width: `${pct}%` }} />
      </div>
      <div className="vg-controls">
        <button className="btn small icon" onClick={() => goScene(Math.max(0, cur.si - 1))} disabled={cur.si === 0} aria-label="Scena precedente">
          <ChevronLeft size={17} aria-hidden />
        </button>
        {playing ? (
          <button className="btn small primary" onClick={pause} aria-label="Pausa">
            <Pause size={16} aria-hidden /> Pausa
          </button>
        ) : (
          <button className="btn small primary" onClick={play} aria-label={ended ? 'Guarda di nuovo' : pos ? 'Riprendi' : 'Guarda la videoguida'}>
            {ended ? <RotateCcw size={16} aria-hidden /> : <Play size={16} aria-hidden />} {ended ? 'Di nuovo' : pos ? 'Riprendi' : 'Guarda'}
          </button>
        )}
        <button className="btn small icon" onClick={() => goScene(Math.min(video.scenes.length - 1, cur.si + 1))} disabled={cur.si + 1 >= video.scenes.length} aria-label="Scena successiva">
          <ChevronRight size={17} aria-hidden />
        </button>
        <span className="spacer" />
        <button className="btn small icon" onClick={() => update({ muted: !prefs.muted })} aria-pressed={prefs.muted} aria-label={prefs.muted ? 'Riattiva la voce' : 'Solo sottotitoli'} title={prefs.muted ? 'Riattiva la voce' : 'Solo sottotitoli'} disabled={noVoice}>
          {prefs.muted || noVoice ? <VolumeX size={16} aria-hidden /> : <Volume2 size={16} aria-hidden />}
        </button>
        {voices.length > 1 && (
          <label className="vg-select">
            <span className="sr-only">Voce</span>
            <select value={voice?.voiceURI} onChange={(e) => update({ voice: e.target.value })}>
              {voices.map((v) => (
                <option key={v.voiceURI} value={v.voiceURI}>
                  {v.name.replace(/^Microsoft /, '').replace(/ - .*$/, '')}
                </option>
              ))}
            </select>
          </label>
        )}
        <label className="vg-select">
          <span className="sr-only">Velocità della voce</span>
          <select value={prefs.rate} onChange={(e) => update({ rate: Number(e.target.value) })}>
            {RATES.map((r) => (
              <option key={r.v} value={r.v}>
                {r.label}
              </option>
            ))}
          </select>
        </label>
        <button className={`btn small${prefs.transcript ? ' on' : ''}`} onClick={() => update({ transcript: !prefs.transcript })} aria-pressed={prefs.transcript}>
          <FileText size={15} aria-hidden /> Testo
        </button>
      </div>
      <ol className="vg-chapters" aria-label="Scene">
        {video.scenes.map((s, i) => (
          <li key={s.title}>
            <button className={i === cur.si ? 'on' : ''} aria-current={i === cur.si ? 'step' : undefined} onClick={() => goScene(i)}>
              {i + 1}. {s.title}
            </button>
          </li>
        ))}
      </ol>
      {noVoice ? (
        <p className="faint vg-note">
          Su questo computer non c&apos;è una voce italiana per la lettura: la videoguida procede con i sottotitoli. Su Windows la voce italiana si chiama Microsoft
          Elsa; se manca, si aggiunge dalle impostazioni della voce di Windows.
        </p>
      ) : (
        <p className="faint vg-note">
          Voce: {voice?.name.replace(/ - .*$/, '')}, letta da Windows su questo PC. Barra spaziatrice per pausa e ripresa, frecce per cambiare scena.
        </p>
      )}
      {prefs.transcript && (
        <div className="vg-transcript">
          {video.scenes.map((s, i) => (
            <section key={s.title}>
              <h4>
                {i + 1}. {s.title}
              </h4>
              <p>{s.narration.join(' ')}</p>
            </section>
          ))}
        </div>
      )}
    </div>
  );
}

/** Videoguida dentro una guida: copertina con titolo e durata, il lettore si apre al clic. */
export function VideoBlock({ id }: { id: string }) {
  const v = videoById(id);
  const [open, setOpen] = useState(false);
  if (!v) return null;
  if (open) return <VideoPlayer video={v} />;
  return (
    <button className="vg-poster" onClick={() => setOpen(true)}>
      <span className="vg-poster-icon" aria-hidden>
        <Clapperboard size={22} />
      </span>
      <span className="vg-poster-text">
        <b>Videoguida: {v.title}</b>
        <span className="faint">
          {v.summary} · {v.scenes.length} scene, circa {videoMinutes(v)} {videoMinutes(v) === 1 ? 'minuto' : 'minuti'}, con la voce italiana di Windows
        </span>
      </span>
      <Play size={18} aria-hidden />
    </button>
  );
}
