import { Download, FileText, Printer, X } from 'lucide-react';
import { m } from 'motion/react';
import { useEffect, useMemo, useRef } from 'react';
import { createPortal } from 'react-dom';
import { documentParts, renderDocument } from '../engine';
import type { Analysis, Scan } from '../engine';
import { Anim } from './anim';
import { ease, spring } from './motion';

// Anteprima del documento stampabile sullo stato del PC. "Stampa o salva PDF"
// stampa solo il documento (la classe pdoc-printing nasconde il resto della
// pagina, vedi styles.css); "Scarica HTML" salva il file autonomo, che si apre
// in qualunque browser.

export function DocumentPreview({
  scan,
  analysis,
  version,
  onClose,
  onSave,
}: {
  scan: Scan;
  analysis: Analysis;
  version?: string;
  onClose: () => void;
  onSave: (name: string, content: string, type: string) => void;
}) {
  const generated = useMemo(() => new Date().toLocaleString('it-IT', { dateStyle: 'short', timeStyle: 'short' }).replace(', ', ' alle '), []);
  const parts = useMemo(() => documentParts(scan, analysis, { version, generated }), [scan, analysis, version, generated]);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    ref.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    document.documentElement.classList.add('pdoc-open');
    return () => {
      window.removeEventListener('keydown', onKey);
      document.documentElement.classList.remove('pdoc-open', 'pdoc-printing');
      prev?.focus();
    };
  }, [onClose]);

  const print = () => {
    const root = document.documentElement;
    root.classList.add('pdoc-printing');
    window.addEventListener('afterprint', () => root.classList.remove('pdoc-printing'), { once: true });
    window.print();
  };
  const file = `stato-${scan.pc ? 'pc' : 'rete'}-${(scan.agent.host || 'polaris').replace(/[^\w.-]+/g, '_')}-${scan.agent.startedAt.slice(0, 10)}.html`;

  return createPortal(
    <div className="pdoc-portal">
      <m.div className="pdoc-backdrop" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={onClose} aria-hidden="true" />
      <m.div
        ref={ref}
        className="pdoc-modal"
        role="dialog"
        aria-modal="true"
        aria-label={parts.title}
        tabIndex={-1}
        initial={{ opacity: 0, y: 28, scale: 0.98 }}
        animate={{ opacity: 1, y: 0, scale: 1, transition: spring.smooth }}
        exit={{ opacity: 0, y: 18, scale: 0.99, transition: { duration: 0.18, ease: ease.inOut } }}
      >
        <div className="pdoc-toolbar">
          <Anim kind="draw">
            <FileText size={18} />
          </Anim>
          <b>Documento sullo stato del {scan.pc ? 'computer' : 'collegamento'}</b>
          <span className="spacer" />
          <span className="pdoc-actions">
            <button className="btn primary small" onClick={print}>
              <Printer size={15} aria-hidden /> Stampa o salva PDF
            </button>
            <button className="btn small" onClick={() => onSave(file, renderDocument(scan, analysis, { version, generated }), 'text/html;charset=utf-8')}>
              <Download size={15} className="nudge" aria-hidden /> Scarica HTML
            </button>
          </span>
          <button className="btn small icon" onClick={onClose} aria-label="Chiudi l'anteprima">
            <X size={16} aria-hidden />
          </button>
        </div>
        <div className="pdoc-scroll" tabIndex={0} role="region" aria-label="Anteprima del documento">
          <style>{parts.css}</style>
          <m.div
            className="pdoc pdoc-sheet"
            initial={{ opacity: 0, y: 14 }}
            animate={{ opacity: 1, y: 0, transition: { duration: 0.45, ease: ease.out, delay: 0.08 } }}
            dangerouslySetInnerHTML={{ __html: parts.body }}
          />
        </div>
      </m.div>
    </div>,
    document.body,
  );
}
