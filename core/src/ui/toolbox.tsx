import { AppWindow, Check, ExternalLink, PackageCheck, Sparkles, TriangleAlert, Wrench } from 'lucide-react';
import { m } from 'motion/react';
import { useCallback, useEffect, useState } from 'react';
import { CATEGORY_LABEL, TOOLS, WINDOWS_TOOLS } from '../tools';
import type { Tool, ToolCategory } from '../tools';
import { openTool, toolsStatus } from './api';
import type { ToolsState } from './api';
import { Segmented, useToast } from './components';
import { cascade, rise } from './motion';
import type { ViewProps } from './views';

// Cassetta degli attrezzi: gli strumenti di Windows, i programmi inclusi in
// Polaris (CrystalDiskInfo e CrystalDiskMark) e i programmi gratuiti più noti.
// Con l'agente gli strumenti si aprono dal PC analizzato (la finestra di
// Polaris non apre da sola i siti nel browser); senza agente restano i link.

type Filter = 'tutti' | ToolCategory;
type Found = Required<ToolsState>;

const EMPTY: Found = { installed: {}, bundled: {} };

// Una sola richiesta per le schede che si aprono insieme (cassetta e scorciatoie).
let shared: { at: number; req: Promise<Found> } | null = null;
function loadTools(): Promise<Found> {
  if (!shared || Date.now() - shared.at > 10_000) {
    const req = toolsStatus().then((st) => ({ installed: st.installed ?? {}, bundled: st.bundled ?? {} }));
    shared = { at: Date.now(), req };
    req.catch(() => {
      shared = null;
    });
  }
  return shared.req;
}

/** Programmi installati e inclusi nel pacchetto, letti dall'agente. */
export function useTools(live: boolean): Found {
  const [found, setFound] = useState<Found>(EMPTY);
  useEffect(() => {
    if (!live) return;
    let alive = true;
    loadTools()
      .then((f) => alive && setFound(f))
      .catch(() => undefined);
    return () => {
      alive = false;
    };
  }, [live]);
  return found;
}

export function useOpenTool() {
  const toast = useToast();
  return useCallback(
    (tool: string, target: 'app' | 'site', name: string) => {
      openTool(tool, target)
        .then(() => toast(target === 'site' ? `Sito di ${name} aperto nel browser` : `${name} aperto`))
        .catch((e) => toast(e instanceof Error ? e.message : String(e), 'error'));
    },
    [toast],
  );
}

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
          Gli strumenti di Windows si aprono da qui. CrystalDiskInfo e CrystalDiskMark sono inclusi in Polaris: sono le copie originali del produttore (open source,
          licenza MIT), verificate con l'impronta SHA-256, e si aprono con un clic senza installare nulla. Gli altri programmi non sono inclusi, perché le loro
          licenze non lo permettono o non lo rendono opportuno: si scaricano dal sito ufficiale, e quelli già installati Polaris li riconosce e li apre. Siti e
          licenze verificati il 19/10/2026: controllali comunque prima di installare.
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
          <ToolCard key={t.id} t={t} installed={found.installed[t.id]} bundled={found.bundled[t.id]} live={live} onOpen={open} />
        ))}
      </m.div>
    </>
  );
}

function ToolCard({
  t,
  installed,
  bundled,
  live,
  onOpen,
}: {
  t: Tool;
  installed?: { version?: string };
  bundled?: { version: string; problem?: string };
  live: boolean;
  onOpen: (tool: string, target: 'app' | 'site', name: string) => void;
}) {
  const included = bundled && !bundled.problem;
  return (
    <m.section variants={rise} className="card tool-card">
      <div className="card-head">
        <h2 className="tool-title">
          {t.name}
          <span className="faint">{t.vendor}</span>
        </h2>
        <span className="spacer" />
        <span className="tool-badges">
          {included && (
            <span className="sev ok">
              <PackageCheck size={13} aria-hidden /> Incluso in Polaris {bundled.version}
            </span>
          )}
          {bundled?.problem && (
            <span className="sev warn">
              <TriangleAlert size={13} aria-hidden /> Copia inclusa alterata
            </span>
          )}
          {installed && (
            <span className="sev ok">
              <Check size={13} aria-hidden /> Installato{installed.version ? ` ${installed.version}` : ''}
            </span>
          )}
        </span>
      </div>
      <div className="chips-row">
        <span className="tag accent">{CATEGORY_LABEL[t.category]}</span>
        {!live && t.included && <span className="tag">Incluso nel pacchetto di Polaris ({t.included})</span>}
      </div>
      <p className="tool-what">{t.what}</p>
      <p className="faint tool-license">Licenza: {t.license}</p>
      {t.polaris && (
        <p className="tool-polaris">
          <Sparkles size={14} aria-hidden /> <span>{t.polaris}</span>
        </p>
      )}
      {t.note && <p className="faint tool-note">{t.note}</p>}
      {bundled?.problem && (
        <p className="tool-problem">
          <TriangleAlert size={14} aria-hidden />
          <span>Copia inclusa: {bundled.problem}. Riscarica il pacchetto di Polaris dalla fonte originale.</span>
        </p>
      )}
      <div className="chip-actions">
        {live && (included || installed) && (
          <button
            className="btn primary small"
            onClick={() => onOpen(t.id, 'app', t.name)}
            aria-label={`Apri ${t.name}`}
            title={included ? `Avvia la copia inclusa in Polaris (${bundled.version})` : 'Avvia la versione installata su questo PC'}
          >
            <AppWindow size={15} aria-hidden /> Apri
          </button>
        )}
        {live ? (
          <button className="btn small" onClick={() => onOpen(t.id, 'site', t.name)} aria-label={`Sito ufficiale di ${t.name}`}>
            <ExternalLink size={15} aria-hidden /> Sito ufficiale
          </button>
        ) : (
          <a className="btn small" href={t.site} target="_blank" rel="noopener noreferrer" aria-label={`Sito ufficiale di ${t.name} (si apre in una nuova scheda)`}>
            <ExternalLink size={15} aria-hidden /> Sito ufficiale
          </a>
        )}
      </div>
    </m.section>
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
      <PackageCheck size={18} aria-hidden />
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
