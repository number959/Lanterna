import { AppWindow, Check, ExternalLink, Sparkles, Wrench } from 'lucide-react';
import { m } from 'motion/react';
import { useEffect, useState } from 'react';
import { CATEGORY_LABEL, TOOLS, WINDOWS_TOOLS } from '../tools';
import type { Tool, ToolCategory } from '../tools';
import { openTool, toolsStatus } from './api';
import type { ToolsState } from './api';
import { Segmented, useToast } from './components';
import { cascade, rise } from './motion';
import type { ViewProps } from './views';

// Cassetta degli attrezzi: gli strumenti di Windows e i programmi gratuiti più
// noti. Con l'agente gli strumenti si aprono dal PC analizzato (la finestra di
// Polaris non apre da sola i siti nel browser); senza agente restano i link.

type Filter = 'tutti' | ToolCategory;

export function Toolbox({ live, source }: Pick<ViewProps, 'live' | 'source'>) {
  const toast = useToast();
  const [installed, setInstalled] = useState<ToolsState['installed']>({});
  const [filter, setFilter] = useState<Filter>('tutti');
  const readOnly = source === 'file';

  useEffect(() => {
    if (!live) return;
    let alive = true;
    toolsStatus()
      .then((st) => alive && setInstalled(st.installed ?? {}))
      .catch(() => undefined);
    return () => {
      alive = false;
    };
  }, [live]);

  const open = (tool: string, target: 'app' | 'site', name: string) => {
    openTool(tool, target)
      .then(() => toast(target === 'site' ? `Sito di ${name} aperto nel browser` : `${name} aperto`))
      .catch((e) => toast(e instanceof Error ? e.message : String(e), 'error'));
  };

  const cats = (Object.keys(CATEGORY_LABEL) as ToolCategory[]).filter((c) => TOOLS.some((t) => t.category === c));
  const list = TOOLS.filter((t) => filter === 'tutti' || t.category === filter);

  return (
    <>
      <m.div variants={rise} className="notice" style={{ marginBottom: 14 }}>
        <Wrench size={18} aria-hidden />
        <span>
          Gli strumenti di Windows si aprono da qui. I programmi gratuiti non sono inclusi in Polaris, perché le loro licenze non lo permettono o non lo rendono
          opportuno: si scaricano dal sito ufficiale, e quelli già installati Polaris li riconosce e li apre. Siti e licenze verificati il 18/10/2026: controllali
          comunque prima di installare.
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
          <ToolCard key={t.id} t={t} installed={installed[t.id]} live={live} onOpen={open} />
        ))}
      </m.div>
    </>
  );
}

function ToolCard({ t, installed, live, onOpen }: { t: Tool; installed?: { version?: string }; live: boolean; onOpen: (tool: string, target: 'app' | 'site', name: string) => void }) {
  return (
    <m.section variants={rise} className="card tool-card">
      <div className="card-head">
        <h2 className="tool-title">
          {t.name}
          <span className="faint">{t.vendor}</span>
        </h2>
        <span className="spacer" />
        {installed && (
          <span className="sev ok">
            <Check size={13} aria-hidden /> Installato{installed.version ? ` ${installed.version}` : ''}
          </span>
        )}
      </div>
      <div className="chips-row">
        <span className="tag accent">{CATEGORY_LABEL[t.category]}</span>
      </div>
      <p className="tool-what">{t.what}</p>
      <p className="faint tool-license">Licenza: {t.license}</p>
      {t.polaris && (
        <p className="tool-polaris">
          <Sparkles size={14} aria-hidden /> <span>{t.polaris}</span>
        </p>
      )}
      {t.note && <p className="faint tool-note">{t.note}</p>}
      <div className="chip-actions">
        {installed && live && (
          <button className="btn primary small" onClick={() => onOpen(t.id, 'app', t.name)} aria-label={`Apri ${t.name}`}>
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
