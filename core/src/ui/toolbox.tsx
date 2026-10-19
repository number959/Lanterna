import { AppWindow, Check, Download, ExternalLink, PackageCheck, ShieldCheck, Sparkles, Trash2, TriangleAlert, Wrench, X } from 'lucide-react';
import { AnimatePresence, m } from 'motion/react';
import { useCallback, useEffect, useState } from 'react';
import { CATEGORY_LABEL, TOOLS, WINDOWS_TOOLS } from '../tools';
import type { Tool, ToolCategory } from '../tools';
import { Anim, HexLoader, Skeleton } from './anim';
import { cancelFetch, fetchTool, openTool, removeTool, toolsStatus } from './api';
import type { FetchState, PortableState, ToolsState } from './api';
import { Segmented, useToast } from './components';
import { cascade, rise, spring } from './motion';
import type { ViewProps } from './views';

// Cassetta degli attrezzi: gli strumenti di Windows, i programmi inclusi in
// Polaris (CrystalDiskInfo, CrystalDiskMark, BlueScreenView), le versioni
// portable che Polaris scarica dal sito ufficiale con la firma verificata e i
// programmi installati. Con l'agente si apre tutto dal PC analizzato (la
// finestra di Polaris non apre da sola i siti nel browser); senza, restano i link.

type Filter = 'tutti' | ToolCategory;
type Found = Required<Omit<ToolsState, 'fetch'>> & { fetch?: FetchState; loaded: boolean };
type Toast = ReturnType<typeof useToast>;

const EMPTY: Found = { installed: {}, bundled: {}, portable: {}, loaded: false };

// Stato condiviso da cassetta e scorciatoie: una sola richiesta per volta, e
// durante un download l'avanzamento si rilegge ogni 400 ms anche cambiando sezione.
let current: Found = EMPTY;
let shared: { at: number; req: Promise<Found> } | null = null;
const listeners = new Set<(f: Found) => void>();
let polling = false;
let openAfter: { id: string; name: string; toast: Toast } | null = null;

function publish(f: Found) {
  current = f;
  listeners.forEach((l) => l(f));
}

function loadTools(force = false): Promise<Found> {
  if (force || !shared || Date.now() - shared.at > 10_000) {
    const req = toolsStatus().then((st) => {
      const f: Found = { installed: st.installed ?? {}, bundled: st.bundled ?? {}, portable: st.portable ?? {}, fetch: st.fetch, loaded: true };
      publish(f);
      if (f.fetch?.running) pollFetch();
      return f;
    });
    shared = { at: Date.now(), req };
    req.catch(() => {
      shared = null;
    });
  }
  return shared.req;
}

function pollFetch() {
  if (polling) return;
  polling = true;
  const tick = () => {
    loadTools(true)
      .then((f) => {
        if (f.fetch?.running) {
          setTimeout(tick, 400);
          return;
        }
        polling = false;
        const after = openAfter;
        openAfter = null;
        if (!after || f.fetch?.tool !== after.id) return;
        if (f.fetch.error) {
          after.toast(`${after.name}: ${f.fetch.error}`, 'error');
          return;
        }
        const p = f.portable[after.id];
        after.toast(`${after.name} scaricato e verificato${p?.signer ? `: firma di ${p.signer}` : ''}`);
        openTool(after.id, 'app')
          .then(() => after.toast(`${after.name} aperto`))
          .catch((e) => after.toast(e instanceof Error ? e.message : String(e), 'error'));
      })
      .catch(() => {
        polling = false;
      });
  };
  tick();
}

/** Programmi installati, inclusi e scaricati, letti dall'agente. */
export function useTools(live: boolean): Found {
  const [found, setFound] = useState<Found>(current);
  useEffect(() => {
    if (!live) return;
    listeners.add(setFound);
    loadTools().catch(() => setFound((f) => ({ ...f, loaded: true })));
    return () => {
      listeners.delete(setFound);
    };
  }, [live]);
  return live ? found : EMPTY;
}

export function useOpenTool() {
  const toast = useToast();
  return useCallback(
    (tool: string, target: 'app' | 'site', name: string) =>
      openTool(tool, target)
        .then(() => toast(target === 'site' ? `Sito di ${name} aperto nel browser` : `${name} aperto`))
        .catch((e) => toast(e instanceof Error ? e.message : String(e), 'error')),
    [toast],
  );
}

const mb = (bytes: number) => (bytes / 1e6).toLocaleString('it-IT', { maximumFractionDigits: bytes < 1e7 ? 1 : 0 });

export function Toolbox({ live, source }: Pick<ViewProps, 'live' | 'source'>) {
  const found = useTools(live);
  const open = useOpenTool();
  const [filter, setFilter] = useState<Filter>('tutti');
  const readOnly = source === 'file';

  const cats = (Object.keys(CATEGORY_LABEL) as ToolCategory[]).filter((c) => TOOLS.some((t) => t.category === c));
  const list = TOOLS.filter((t) => filter === 'tutti' || t.category === filter);

  return (
    <>
      <m.div variants={rise} className="notice" style={{ marginBottom: 14 }}>
        <Wrench size={18} aria-hidden />
        <span>
          Gli strumenti di Windows si aprono da qui. CrystalDiskInfo, CrystalDiskMark e BlueScreenView sono inclusi in Polaris: copie originali del
          produttore, verificate con l&apos;impronta SHA-256, che si aprono con un clic. Gli altri programmi non si possono ridistribuire: con{' '}
          <b>Scarica e apri</b> Polaris ne prende la versione portable dal sito ufficiale e la avvia solo se è firmata dal produttore. Quelli già installati
          li riconosce e li apre. Siti, licenze e firme verificati il 19/10/2026: le condizioni d&apos;uso restano quelle dei produttori.
        </span>
      </m.div>

      <m.section variants={rise} className="card">
        <div className="card-head">
          <h2 className="disk-title">
            <AppWindow size={19} aria-hidden /> Strumenti di Windows
          </h2>
        </div>
        {!live && <p className="faint tool-hint">{readOnly ? 'Rapporto importato: gli strumenti si aprono dal PC dove gira l\'agente.' : 'Nella demo gli strumenti non si aprono: serve l\'agente su Windows.'}</p>}
        <m.ul className="wintools" variants={cascade(0.02)}>
          {WINDOWS_TOOLS.map((w) => (
            <m.li key={w.id} variants={rise}>
              <button className="wintool" disabled={!live} onClick={() => open(w.id, 'app', w.name)}>
                <b>{w.name}</b>
                <span>{w.what}</span>
              </button>
            </m.li>
          ))}
        </m.ul>
      </m.section>

      <div className="toolbox-filter">
        <Segmented<Filter>
          label="Categoria dei programmi"
          value={filter}
          onChange={setFilter}
          options={[{ id: 'tutti', label: 'Tutti' }, ...cats.map((c) => ({ id: c, label: CATEGORY_LABEL[c] }))]}
        />
      </div>
      <m.div className="grid cols-2 toolbox-grid" variants={cascade(0.04)} key={filter} initial="hidden" animate="show">
        {list.map((t) => (
          <ToolCard key={t.id} t={t} found={found} live={live} onOpen={open} />
        ))}
      </m.div>
    </>
  );
}

function ToolCard({ t, found, live, onOpen }: { t: Tool; found: Found; live: boolean; onOpen: (tool: string, target: 'app' | 'site', name: string) => Promise<void> }) {
  const toast = useToast();
  const [confirm, setConfirm] = useState(false);
  const [opening, setOpening] = useState(false);
  const installed = found.installed[t.id];
  const bundled = found.bundled[t.id];
  const dl: PortableState | undefined = found.portable[t.id];
  const included = !!bundled && !bundled.problem;
  const ready = !!dl && !dl.problem;
  const fetch = found.fetch;
  const fetching = !!fetch?.running && fetch.tool === t.id;
  const busyElsewhere = !!fetch?.running && fetch.tool !== t.id;
  const canOpen = live && (included || ready || !!installed);
  const loading = live && !found.loaded;

  const doOpen = () => {
    setOpening(true);
    onOpen(t.id, 'app', t.name).finally(() => setOpening(false));
  };
  const startFetch = () => {
    setConfirm(false);
    openAfter = { id: t.id, name: t.name, toast };
    fetchTool(t.id)
      .then(() => {
        publish({ ...current, fetch: { running: true, tool: t.id, done: 0, total: -1 } });
        pollFetch();
      })
      .catch((e) => {
        openAfter = null;
        toast(e instanceof Error ? e.message : String(e), 'error');
      });
  };
  const remove = () =>
    removeTool(t.id)
      .then(() => {
        toast(`Copia scaricata di ${t.name} eliminata`);
        return loadTools(true);
      })
      .catch((e) => toast(e instanceof Error ? e.message : String(e), 'error'));

  return (
    <m.section variants={rise} className="card tool-card">
      <div className="card-head">
        <h2 className="tool-title">
          {t.name}
          <span className="faint">{t.vendor}</span>
        </h2>
        <span className="spacer" />
        <span className="tool-badges">
          {loading && (t.included || t.portable || t.installs) && <Skeleton w={118} h={22} r={11} />}
          {included && (
            <span className="sev ok">
              <Anim kind="pop">
                <PackageCheck size={13} />
              </Anim>{' '}
              Incluso in Polaris {bundled.version}
            </span>
          )}
          {bundled?.problem && (
            <span className="sev warn">
              <TriangleAlert size={13} aria-hidden /> Copia inclusa alterata
            </span>
          )}
          {ready && (
            <span className={`sev ${dl.expired ? 'warn' : 'ok'}`} title={dl.date ? `Scaricato il ${new Date(dl.date).toLocaleDateString('it-IT')}` : undefined}>
              <Anim kind="pop">{dl.expired ? <TriangleAlert size={13} /> : <ShieldCheck size={13} />}</Anim> {dl.expired ? 'Scaduto: riscaricalo' : `Pronto${dl.version ? ` ${dl.version}` : ''}`}
            </span>
          )}
          {dl?.problem && (
            <span className="sev warn">
              <TriangleAlert size={13} aria-hidden /> Copia scaricata alterata
            </span>
          )}
          {installed && (
            <span className="sev ok">
              <Anim kind="pop">
                <Check size={13} />
              </Anim>{' '}
              Installato{installed.version ? ` ${installed.version}` : ''}
            </span>
          )}
        </span>
      </div>
      <div className="chips-row">
        <span className="tag accent">{CATEGORY_LABEL[t.category]}</span>
        {!live && t.included && <span className="tag">Incluso nel pacchetto di Polaris ({t.included})</span>}
        {!live && t.portable && <span className="tag">Versione portable dal sito ufficiale</span>}
      </div>
      <p className="tool-what">{t.what}</p>
      <p className="faint tool-license">Licenza: {t.license}</p>
      {t.polaris && (
        <p className="tool-polaris">
          <Sparkles size={14} aria-hidden /> <span>{t.polaris}</span>
        </p>
      )}
      {t.note && <p className="faint tool-note">{t.note}</p>}
      {ready && dl.signer && (
        <p className="faint tool-note">
          Scaricato da {t.portable?.from}
          {dl.date ? ` il ${new Date(dl.date).toLocaleDateString('it-IT')}` : ''}; firma digitale di {dl.signer}, verificata a ogni avvio.
        </p>
      )}
      {bundled?.problem && (
        <p className="tool-problem">
          <TriangleAlert size={14} aria-hidden />
          <span>Copia inclusa: {bundled.problem}. Riscarica il pacchetto di Polaris dalla fonte originale.</span>
        </p>
      )}
      {dl?.problem && (
        <p className="tool-problem">
          <TriangleAlert size={14} aria-hidden />
          <span>Copia scaricata: {dl.problem}.</span>
        </p>
      )}

      <AnimatePresence initial={false}>
        {fetching && fetch && <FetchProgress key="fetch" t={t} fetch={fetch} />}
        {confirm && !fetching && t.portable && (
          <m.div
            key="confirm"
            className="notice tool-confirm"
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto', transition: spring.smooth }}
            exit={{ opacity: 0, height: 0, transition: { duration: 0.18 } }}
          >
            <Anim kind="draw">
              <ShieldCheck size={18} />
            </Anim>
            <span>
              Polaris scarica la versione portable di {t.name}
              {t.portable.version ? ` ${t.portable.version}` : ''} da <b>{t.portable.from}</b> (circa {t.portable.mb.toLocaleString('it-IT')} MB), controlla che sia
              firmata da <b>{t.portable.signer}</b> e la apre. Il programma resta su questo PC, in %LOCALAPPDATA%\STARNET Polaris\strumenti. Condizioni
              d&apos;uso: {t.portable.terms}.
            </span>
            <span className="chip-actions">
              <button className="btn primary small" onClick={startFetch}>
                <Download size={15} className="nudge" aria-hidden /> Scarica e apri
              </button>
              <button className="btn small" onClick={() => setConfirm(false)}>
                Annulla
              </button>
            </span>
          </m.div>
        )}
      </AnimatePresence>

      <div className="chip-actions">
        {canOpen && !(ready && dl.expired && !included && !installed) && (
          <button className="btn primary small" onClick={doOpen} disabled={opening || fetching} aria-label={`Apri ${t.name}`} title={included ? `Avvia la copia inclusa in Polaris (${bundled.version})` : ready ? 'Verifica la firma e avvia la copia scaricata' : 'Avvia la versione installata su questo PC'}>
            {opening ? <HexLoader size={15} /> : <AppWindow size={15} aria-hidden />} {opening ? (ready && !included ? 'Verifica della firma…' : 'Apertura…') : 'Apri'}
          </button>
        )}
        {live && t.portable && !included && !fetching && !confirm && (!ready || dl.expired) && (
          <button className="btn small primary-soft" onClick={() => setConfirm((c) => !c)} disabled={busyElsewhere} aria-expanded={confirm} title={busyElsewhere ? 'Attendi la fine dell\'altro download' : undefined}>
            <Download size={15} className="nudge" aria-hidden /> {dl ? 'Riscarica' : 'Scarica e apri'}
          </button>
        )}
        {live ? (
          <button className="btn small" onClick={() => onOpen(t.id, 'site', t.name)} aria-label={`Sito ufficiale di ${t.name}`}>
            <ExternalLink size={15} className="nudge" aria-hidden /> Sito ufficiale
          </button>
        ) : (
          <a className="btn small" href={t.site} target="_blank" rel="noopener noreferrer" aria-label={`Sito ufficiale di ${t.name} (si apre in una nuova scheda)`}>
            <ExternalLink size={15} className="nudge" aria-hidden /> Sito ufficiale
          </a>
        )}
        {live && dl && !fetching && (
          <button className="btn small icon" onClick={remove} aria-label={`Elimina la copia scaricata di ${t.name}`} title="Elimina la copia scaricata">
            <Trash2 size={15} aria-hidden />
          </button>
        )}
      </div>
    </m.section>
  );
}

function FetchProgress({ t, fetch }: { t: Tool; fetch: FetchState }) {
  const toast = useToast();
  const pct = fetch.total > 0 ? Math.min(100, (100 * fetch.done) / fetch.total) : undefined;
  const verifying = pct !== undefined && pct >= 100;
  return (
    <m.div
      className="tool-fetch"
      initial={{ opacity: 0, height: 0 }}
      animate={{ opacity: 1, height: 'auto', transition: spring.smooth }}
      exit={{ opacity: 0, height: 0, transition: { duration: 0.2 } }}
    >
      <div className="tool-fetch-row">
        {verifying ? (
          <HexLoader size={18} />
        ) : (
          <Anim kind="bounce">
            <Download size={17} />
          </Anim>
        )}
        <span aria-live="polite">
          {verifying ? (
            <>Verifica della firma di {t.portable?.signer}…</>
          ) : (
            <>
              Scaricamento da {t.portable?.from}: {mb(fetch.done)}
              {fetch.total > 0 ? ` di ${mb(fetch.total)}` : ''} MB
            </>
          )}
        </span>
        <span className="spacer" />
        {!verifying && (
          <button
            className="btn small icon"
            onClick={() => cancelFetch().catch((e) => toast(e instanceof Error ? e.message : String(e), 'error'))}
            aria-label={`Interrompi il download di ${t.name}`}
            title="Interrompi"
          >
            <X size={15} aria-hidden />
          </button>
        )}
      </div>
      <div
        className={`progress live${pct === undefined ? ' indeterminate' : ''}`}
        role="progressbar"
        aria-label={`Download di ${t.name}`}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={pct === undefined ? undefined : Math.round(pct)}
      >
        <m.i initial={false} animate={{ width: pct === undefined ? '35%' : `${pct}%` }} transition={spring.gentle} />
      </div>
    </m.div>
  );
}

/** Scorciatoia verso un programma della cassetta, solo se con l'agente si può aprire. */
export function ToolShortcut({ id, live, text }: { id: string; live: boolean; text: string }) {
  const found = useTools(live);
  const open = useOpenTool();
  const t = TOOLS.find((x) => x.id === id);
  const inc = found.bundled[id];
  const included = !!inc && !inc.problem;
  if (!live || !t || (!included && !found.installed[id])) return null;
  return (
    <m.div className="tool-shortcut" initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}>
      <Anim kind="draw">
        <PackageCheck size={18} />
      </Anim>
      <span>
        <b>{t.name}</b> {text}
        {included ? ` · incluso in Polaris ${inc.version}` : ' · installato su questo PC'}
      </span>
      <button className="btn small" onClick={() => open(id, 'app', t.name)}>
        <AppWindow size={15} aria-hidden /> Apri {t.name}
      </button>
    </m.div>
  );
}
