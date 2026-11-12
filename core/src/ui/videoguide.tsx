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
import { allRecorded, clipOf, VOCE } from './narrazione';
import { NetMap } from './netmap';

// Videoguide: scene animate con la narrazione in italiano. La voce è una
// registrazione inclusa nel programma, una per frase, generata una volta con
// una voce neurale (scripts/narrazione): non dipende dalle voci installate sul
// PC e durante l'ascolto nulla esce dal computer. In alternativa si può
// scegliere una voce italiana di Windows (sintesi vocale del sistema, solo
// voci installate, localService: le voci "online" di alcuni browser
// manderebbero il testo a un servizio esterno). Ogni frase è anche un
// sottotitolo; con l'audio spento, o se una registrazione non parte, la guida
// procede con i soli sottotitoli al ritmo di lettura.

const PREF_KEY = 'polaris.video';
const RATES = [
  { v: 0.85, label: 'Lenta' },
  { v: 1, label: 'Normale' },
  { v: 1.15, label: 'Veloce' },
];

/** Valore del selettore della voce per la narrazione registrata. */
const REC = 'registrata';

interface Prefs {
  /** Voce di Windows scelta al posto della registrazione (voiceURI). */
  voice?: string;
  /** Da dove viene la voce: la registrazione inclusa (predefinita) o la sintesi di Windows. */
  source?: 'rec' | 'sys';
  rate: number;
  muted: boolean;
  transcript: boolean;
}

function readPrefs(): Prefs {
  try {
    const v = JSON.parse(localStorage.getItem(PREF_KEY) ?? '{}') as Partial<Prefs>;
    return { voice: v.voice, source: v.source === 'sys' ? 'sys' : 'rec', rate: typeof v.rate === 'number' ? v.rate : 1, muted: !!v.muted, transcript: !!v.transcript };
  } catch {
    return { source: 'rec', rate: 1, muted: false, transcript: false };
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

/**
 * Le voci italiane di Windows e se l'elenco è arrivato: il browser lo consegna
 * poco dopo l'apertura della pagina, e la prima richiesta può tornare vuota.
 * Dopo un secondo si smette di aspettare: su quel PC voci italiane non ce ne sono.
 */
function useVoices(): [SpeechSynthesisVoice[], boolean] {
  const [voices, setVoices] = useState<SpeechSynthesisVoice[]>(() => italianVoices(synth()?.getVoices() ?? []));
  const [waited, setWaited] = useState(false);
  useEffect(() => {
    const s = synth();
    if (!s) return;
    const load = () => setVoices(italianVoices(s.getVoices()));
    load();
    s.addEventListener?.('voiceschanged', load);
    const t = window.setTimeout(() => setWaited(true), 1000);
    return () => {
      s.removeEventListener?.('voiceschanged', load);
      window.clearTimeout(t);
    };
  }, []);
  return [voices, voices.length > 0 || waited || !synth()];
}

/** Tempo di lettura di una frase senza voce: circa 14 caratteri al secondo, almeno 2,4 secondi. */
export const readingMs = (text: string, rate = 1) => Math.max(2400, (text.length / 14) * 1000) / rate;

/** Pausa tra una frase e la successiva. */
const GAP_MS = 350;

/** Durata della videoguida in minuti, arrotondata: dalle registrazioni, o stimata dove mancano. */
export function videoMinutes(v: VideoGuide): number {
  const ms = v.scenes.reduce((a, s) => a + s.narration.reduce((b, t) => b + (clipOf(t)?.ms ?? readingMs(t)) + GAP_MS, 0), 0);
  return Math.max(1, Math.round(ms / 60000));
}

/** La videoguida che sta suonando: se ne parte un'altra nella stessa pagina, questa si ferma. */
let current: (() => void) | null = null;

const flat = (v: VideoGuide) => v.scenes.flatMap((s, si) => s.narration.map((t, ti) => ({ si, ti, t })));

export function VideoPlayer({ video }: { video: VideoGuide }) {
  const reduce = useReducedMotion();
  const [voices, voicesReady] = useVoices();
  const [prefs, setPrefs] = useState<Prefs>(readPrefs);
  const [pos, setPos] = useState(0); // indice della frase in tutta la guida
  const [playing, setPlaying] = useState(false);
  const [ended, setEnded] = useState(false);
  const lines = useMemo(() => flat(video), [video]);
  const cur = lines[Math.min(pos, lines.length - 1)];
  const scene = video.scenes[cur.si];
  const voice = voices.find((v) => v.voiceURI === prefs.voice) ?? voices[0];
  // La registrazione c'è per tutta la guida ed è la voce predefinita.
  const hasRec = useMemo(() => allRecorded(lines.map((l) => l.t)), [lines]);
  const recorded = hasRec && (prefs.source !== 'sys' || !voice || !synth());
  const speaking = !prefs.muted && !recorded && !!voice && !!synth();
  // Chi ha scelto la voce di Windows non deve sentire l'inizio della registrazione mentre l'elenco delle voci arriva.
  const waiting = prefs.source === 'sys' && !prefs.muted && !voicesReady;
  // La voce di Windows conta per la lettura solo quando è lei a leggere: il browser rinnova gli oggetti voce a ogni
  // aggiornamento dell'elenco, e la frase registrata in corso non deve ripartire per questo.
  const voiceRef = useRef(voice);
  voiceRef.current = voice;
  const voiceId = recorded ? '' : (voice?.voiceURI ?? '');
  const audio = useRef<HTMLAudioElement | null>(null);
  const timer = useRef<number | undefined>(undefined);
  const token = useRef(0);
  const [restart, setRestart] = useState(0);
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
    audio.current?.pause();
  }, []);

  const pause = useCallback(() => {
    stopAll();
    setPlaying(false);
  }, [stopAll]);

  // Una narrazione alla volta: con due videoguide aperte nella stessa pagina, quella che parte ferma l'altra.
  useEffect(() => {
    if (!playing) return;
    if (current && current !== pause) current();
    current = pause;
    return () => {
      if (current === pause) current = null;
    };
  }, [playing, pause]);

  // Lettura della frase corrente; alla fine si passa alla successiva.
  useEffect(() => {
    if (!playing || waiting) return;
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
    const clip = !prefs.muted && recorded ? clipOf(text) : undefined;
    if (clip) {
      // Registrazione della frase: alla fine una breve pausa, poi la successiva.
      const a = audio.current ?? (audio.current = new Audio());
      // Può arrivare due volte per lo stesso file (evento di errore e avvio rifiutato): conta una volta sola.
      const timed = () => {
        if (token.current !== my) return;
        window.clearTimeout(timer.current);
        timer.current = window.setTimeout(next, readingMs(text, prefs.rate));
      };
      a.onended = () => {
        if (token.current === my) timer.current = window.setTimeout(next, GAP_MS);
      };
      // Un file che non si carica o che il browser non lascia partire non blocca la guida: si prosegue a tempo.
      a.onerror = timed;
      // Una pausa arrivata da fuori (il tasto multimediale della tastiera, i comandi di Windows) ferma anche la guida:
      // altrimenti resterebbe "in riproduzione" senza suono e senza avanzare. A fine frase l'evento arriva lo stesso,
      // ma lì l'audio risulta finito; dopo un nuovo avvio non risulta più in pausa.
      a.onpause = () => {
        if (token.current === my && a.paused && !a.ended) pause();
      };
      a.src = clip.url;
      // Anche come velocità predefinita: il caricamento di un file nuovo riporta l'elemento a quella.
      a.defaultPlaybackRate = prefs.rate;
      a.playbackRate = prefs.rate;
      const started = a.play();
      if (started && typeof started.catch === 'function')
        started.catch((e: unknown) => {
          // Una pausa o un cambio di frase interrompe l'avvio: non è un errore.
          if ((e as { name?: string } | null)?.name !== 'AbortError') timed();
        });
      // La frase successiva si prepara intanto, così parte senza attese.
      const after = lines[pos + 1] ? clipOf(lines[pos + 1].t) : undefined;
      if (after) {
        const pre = new Audio();
        pre.preload = 'auto';
        pre.src = after.url;
      }
    } else if (speaking && voiceRef.current) {
      const v = voiceRef.current;
      const s = synth()!;
      s.cancel();
      const u = new SpeechSynthesisUtterance(text);
      u.voice = v;
      u.lang = v.lang || 'it-IT';
      u.rate = prefs.rate;
      // Una frase interrotta (pausa, cambio di scena o di voce) non deve
      // toccare il tempo della lettura che l'ha sostituita.
      u.onend = () => {
        if (token.current === my) timer.current = window.setTimeout(next, 350);
      };
      // Una voce che non parte non deve bloccare la guida: si prosegue a tempo.
      u.onerror = () => {
        if (token.current === my) timer.current = window.setTimeout(next, readingMs(text, prefs.rate));
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
      // Silenzio, cambio di voce o di velocità: la frase in corso si ferma subito. Se invece il lettore è già stato
      // fermato (pausa, o un'altra videoguida partita), la voce è già zitta: un secondo arresto, che arriva in
      // ritardo, toglierebbe la parola alla videoguida appena partita, perché la sintesi di Windows è una sola.
      if (token.current === my) synth()?.cancel();
      if (audio.current) {
        audio.current.onended = null;
        audio.current.onerror = null;
        audio.current.onpause = null;
        audio.current.pause();
      }
    };
  }, [playing, waiting, pos, speaking, recorded, prefs.muted, voiceId, prefs.rate, lines, restart, pause]);

  // Dopo una pausa, una ripresa arrivata da fuori (lo stesso tasto multimediale) fa ripartire la guida e non solo
  // l'audio: altrimenti il resto della frase suonerebbe con la guida ferma, e a fine frase resterebbe il silenzio.
  // La frase riparte dall'inizio, come con il pulsante «Riprendi».
  useEffect(() => {
    const a = audio.current;
    if (playing || !a) return;
    const resume = () => {
      // Un avvio chiesto dal lettore stesso fa arrivare l'evento qualche decina di millisecondi dopo: se nel frattempo
      // l'utente ha premuto Pausa, l'audio è già fermo e quell'evento non è una ripresa.
      if (a.paused) return;
      a.pause();
      if (ended) {
        setPos(0);
        setEnded(false);
      }
      setPlaying(true);
    };
    a.addEventListener('play', resume);
    return () => a.removeEventListener('play', resume);
  }, [playing, ended]);

  useEffect(() => stopAll, [stopAll]);

  const play = () => {
    if (ended) {
      setPos(0);
      setEnded(false);
    }
    setPlaying(true);
  };
  const goScene = (si: number) => {
    // Da fermo non c'è nulla da fermare: e la sintesi di Windows è una sola, quindi fermarla toglierebbe la parola
    // a un'altra videoguida che sta leggendo.
    if (playing) stopAll();
    setEnded(false);
    setPos(lines.findIndex((l) => l.si === si));
    // Anche se la scena è quella in corso, la lettura riparte dalla prima frase.
    setRestart((r) => r + 1);
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
  const noVoice = !hasRec && (!synth() || voices.length === 0);
  const sysName = (v: SpeechSynthesisVoice) => v.name.replace(/^Microsoft /, '').replace(/ - .*$/, '');

  return (
    <div className="vg" tabIndex={0} onKeyDown={onKey} role="region" aria-label={`Videoguida: ${video.title}`}>
      <div className="vg-stage">
        <m.div key={`${cur.si}`} className="vg-visual" initial={reduce ? false : { opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35 }}>
          {scene.diagram ? (
            <Diagram id={scene.diagram} caption={scene.title} />
          ) : scene.map ? (
            <div className="vg-map">
              <NetMap scan={scans[scene.map].scan} analysis={scans[scene.map].a} height={360} compact animate={playing} />
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
        <button className="btn small icon" onClick={() => update({ muted: !prefs.muted })} aria-pressed={prefs.muted} aria-label="Solo sottotitoli, senza voce" title="Solo sottotitoli, senza voce" disabled={noVoice}>
          {prefs.muted || noVoice ? <VolumeX size={16} aria-hidden /> : <Volume2 size={16} aria-hidden />}
        </button>
        {(hasRec ? voices.length > 0 : voices.length > 1) && !!synth() && (
          <label className="vg-select">
            <span className="sr-only">Voce</span>
            <select value={recorded ? REC : voice?.voiceURI} onChange={(e) => update(e.target.value === REC ? { source: 'rec' } : { source: 'sys', voice: e.target.value })}>
              {hasRec && <option value={REC}>{VOCE ? `${VOCE.nome} (voce registrata)` : 'Voce registrata'}</option>}
              {voices.map((v) => (
                <option key={v.voiceURI} value={v.voiceURI}>
                  {hasRec ? `Windows: ${sysName(v)}` : sysName(v)}
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
      ) : recorded ? (
        <p className="faint vg-note">
          Voce registrata{VOCE ? ` (${VOCE.nome}, voce sintetica)` : ''}, inclusa nel programma: non serve una voce installata e nulla esce dal computer. Barra
          spaziatrice per pausa e ripresa, frecce per cambiare scena.
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
          {v.summary} · {v.scenes.length} scene, circa {videoMinutes(v)} {videoMinutes(v) === 1 ? 'minuto' : 'minuti'}, con la narrazione in italiano
        </span>
      </span>
      <Play size={18} aria-hidden />
    </button>
  );
}
