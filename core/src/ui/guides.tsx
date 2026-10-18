import {
  ArrowLeft,
  ArrowRight,
  BookOpenText,
  CircleCheckBig,
  Clock,
  Copy,
  Gauge,
  Lightbulb,
  ListTree,
  Network,
  ScanSearch,
  Search,
  Stethoscope,
  TriangleAlert,
} from 'lucide-react';
import { AnimatePresence, m, useReducedMotion } from 'motion/react';
import { Fragment, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { ACTIONS, CATEGORY_LABELS, METRIC_LIST } from '../engine';
import type { Analysis, Category, Finding } from '../engine';
import {
  CHAPTERS,
  GLOSSARY,
  GUIDES,
  chapterOf,
  fold,
  guideById,
  guidesForAction,
  guidesForMetric,
  guidesOf,
  headingsOf,
  neighbours,
  parseInline,
  readingMinutes,
  search,
} from '../guides';
import type { Block, Guide, GlossaryTerm, Level, NoteKind, SearchHit } from '../guides';
import { Segmented, SevIcon, TableWrap, spotHandlers, useToast } from './components';
import { Diagram } from './diagrams';
import { useLocalState } from './hooks';
import { ease, spring } from './motion';
import type { ViewProps } from './views';

// Centro guide: biblioteca di articoli, lettore con indice, glossario e
// riferimento delle misure. Si raggiunge da qualunque punto con
// go('guide', 'g:<id-guida>'), 't:<termine>', 'm:<metrica>' o 'a:<azione>'.

type Tab = 'guide' | 'glossario' | 'misure';

interface Route {
  tab: Tab;
  article?: string;
  term?: string;
  metric?: string;
  action?: string;
}

function parseFocus(f?: string): Route {
  if (!f) return { tab: 'guide' };
  const k = f.slice(0, 2);
  const v = f.slice(2);
  if (k === 'g:' && guideById(v)) return { tab: 'guide', article: v };
  if (k === 't:') return { tab: 'glossario', term: v };
  if (k === 'm:') return { tab: 'misure', metric: v };
  if (k === 'a:') return { tab: 'misure', action: v };
  if (f === 'tab:glossario') return { tab: 'glossario' };
  if (f === 'tab:misure') return { tab: 'misure' };
  return { tab: 'guide' };
}

const same = (a: Route, b: Route) => a.tab === b.tab && a.article === b.article && a.term === b.term && a.metric === b.metric && a.action === b.action;

const LEVEL: Record<Level, string> = { base: 'Base', intermedio: 'Intermedio', avanzato: 'Avanzato' };
const NOTE: Record<NoteKind, { icon: typeof Lightbulb; title: string }> = {
  tip: { icon: Lightbulb, title: 'Consiglio' },
  warn: { icon: TriangleAlert, title: 'Attenzione' },
  clinic: { icon: Stethoscope, title: 'In una struttura sanitaria' },
};

const termAnchor = (t: string) => `gl-${fold(t).replace(/[^a-z0-9]+/g, '-')}`;

/** Ingresso dei pannelli interni (biblioteca, articolo, glossario...). */
const panel = {
  initial: { opacity: 0, y: 12 },
  animate: { opacity: 1, y: 0, transition: { duration: 0.42, ease: ease.out } },
  exit: { opacity: 0, y: -6, transition: { duration: 0.14, ease: ease.inOut } },
};

// ------------------------------------------------------------------ testo

/** Testo con il markup delle guide: grassetto, codice e collegamenti ad altre guide. */
export function Rich({ text, onOpen }: { text: string; onOpen: (id: string) => void }) {
  return (
    <>
      {parseInline(text).map((x, i) =>
        x.t === 'text' ? (
          <Fragment key={i}>{x.s}</Fragment>
        ) : x.t === 'b' ? (
          <strong key={i}>{x.s}</strong>
        ) : x.t === 'code' ? (
          <code key={i}>{x.s}</code>
        ) : (
          <a
            key={i}
            className="glink"
            href={`#guida-${x.id}`}
            onClick={(e) => {
              e.preventDefault();
              onOpen(x.id);
            }}
          >
            {x.s}
          </a>
        ),
      )}
    </>
  );
}

/** Evidenzia nel testo le parole cercate (confronto senza accenti né maiuscole). */
function Hl({ text, toks }: { text: string; toks: string[] }) {
  const f = fold(text);
  const r: [number, number][] = [];
  for (const t of toks) {
    for (let i = f.indexOf(t); i >= 0; i = f.indexOf(t, i + t.length)) r.push([i, i + t.length]);
  }
  if (!r.length) return <>{text}</>;
  r.sort((a, b) => a[0] - b[0]);
  const merged: [number, number][] = [];
  for (const x of r) {
    const last = merged[merged.length - 1];
    if (last && x[0] <= last[1]) last[1] = Math.max(last[1], x[1]);
    else merged.push([...x]);
  }
  const out: ReactNode[] = [];
  let at = 0;
  merged.forEach(([s, e], i) => {
    if (s > at) out.push(text.slice(at, s));
    out.push(<mark key={i}>{text.slice(s, e)}</mark>);
    at = e;
  });
  if (at < text.length) out.push(text.slice(at));
  return <>{out}</>;
}

function CodeBlock({ text, caption }: { text: string; caption?: string }) {
  const toast = useToast();
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      toast('Comandi copiati negli appunti');
    } catch {
      toast('Copia non riuscita: seleziona il testo e usa Ctrl+C', 'error');
    }
  };
  return (
    <figure className="code-block">
      {caption && <figcaption>{caption}</figcaption>}
      <pre tabIndex={0} aria-label={caption ?? 'Comandi'}>
        <code>{text}</code>
      </pre>
      <button className="btn small copy" onClick={copy} aria-label={`Copia: ${caption ?? 'comandi'}`} title="Copia">
        <Copy size={14} aria-hidden />
      </button>
    </figure>
  );
}

function BlockView({ b, sec, onOpen }: { b: Block; sec?: number; onOpen: (id: string) => void }) {
  switch (b.t) {
    case 'p':
      return (
        <p>
          <Rich text={b.text} onOpen={onOpen} />
        </p>
      );
    case 'h':
      return (
        <h3 id={`sez-${sec}`} data-sec={sec} tabIndex={-1}>
          {b.text}
        </h3>
      );
    case 'list': {
      const items = b.items.map((it, i) => (
        <li key={i}>
          <Rich text={it} onOpen={onOpen} />
        </li>
      ));
      return b.ordered ? <ol className="olist">{items}</ol> : <ul className="ulist">{items}</ul>;
    }
    case 'table':
      return (
        <figure className="prose-table">
          {b.caption && <figcaption>{b.caption}</figcaption>}
          <TableWrap label={b.caption ?? b.head.join(', ')}>
            <table>
              <thead>
                <tr>
                  {b.head.map((h) => (
                    <th key={h} scope="col">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {b.rows.map((r, i) => (
                  <tr key={i}>
                    {r.map((c, j) => (
                      <td key={j}>
                        <Rich text={c} onOpen={onOpen} />
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        </figure>
      );
    case 'note': {
      const n = NOTE[b.kind];
      const I = n.icon;
      return (
        <aside className={`callout ${b.kind}`} aria-label={b.title ?? n.title}>
          <span className="callout-icon">
            <I size={17} aria-hidden />
          </span>
          <div>
            <strong className="callout-title">{b.title ?? n.title}</strong>
            <p>
              <Rich text={b.text} onOpen={onOpen} />
            </p>
          </div>
        </aside>
      );
    }
    case 'code':
      return <CodeBlock text={b.text} caption={b.caption} />;
    case 'diagram':
      return <Diagram id={b.id} caption={b.caption} />;
  }
}

// ------------------------------------------------------------------ biblioteca

function LevelTag({ level }: { level: Level }) {
  return <span className={`lvl ${level}`}>{LEVEL[level]}</span>;
}

function GuideCard({ g, read, onOpen }: { g: Guide; read: boolean; onOpen: (id: string) => void }) {
  return (
    <m.button
      className="guide-card spot"
      onClick={() => onOpen(g.id)}
      {...spotHandlers()}
      variants={{ hidden: { opacity: 0, y: 10 }, show: { opacity: 1, y: 0, transition: { duration: 0.45, ease: ease.out } } }}
      whileTap={{ scale: 0.985 }}
    >
      <span className="gc-meta">
        <LevelTag level={g.level} />
        <span className="gc-min">
          <Clock size={12.5} aria-hidden /> {readingMinutes(g)} min
        </span>
        {read && (
          <span className="gc-read" title="Già letta">
            <CircleCheckBig size={15} aria-hidden />
            <span className="sr-only">già letta</span>
          </span>
        )}
      </span>
      <span className="gc-title">{g.title}</span>
      <span className="gc-sum">{g.summary}</span>
    </m.button>
  );
}

function LibraryHome({ read, last, onOpen }: { read: string[]; last?: string; onOpen: (id: string) => void }) {
  const done = GUIDES.filter((g) => read.includes(g.id)).length;
  const resume = last ? guideById(last) : undefined;
  return (
    <m.div {...panel}>
      <section className="card lib-hero">
        <div>
          <h2 className="lib-title">Biblioteca di PC e rete</h2>
          <p className="muted lib-sub">
            {GUIDES.length} guide in {CHAPTERS.length} capitoli, dall'uso del programma al computer, dalle basi della rete fino alle strutture sanitarie, e{' '}
            {GLOSSARY.length} voci di glossario. Tutto è incluso nel programma e si consulta anche senza connessione.
          </p>
          <div className="lib-paths">
            <button className="btn primary" onClick={() => onOpen(resume?.id ?? 'primi-passi')}>
              <BookOpenText size={17} aria-hidden /> {resume ? `Continua: ${resume.title}` : 'Come si usa'}
            </button>
            <button className="btn" onClick={() => onOpen('pc-lento-metodo')}>
              <Gauge size={17} aria-hidden /> PC lento
            </button>
            <button className="btn" onClick={() => onOpen('come-funziona-una-rete')}>
              <Network size={17} aria-hidden /> Basi della rete
            </button>
            <button className="btn" onClick={() => onOpen('rete-clinica-architettura')}>
              <Stethoscope size={17} aria-hidden /> Percorso per cliniche
            </button>
            <button className="btn" onClick={() => onOpen('metodo-diagnosi')}>
              <ScanSearch size={17} aria-hidden /> Metodo di diagnosi
            </button>
          </div>
        </div>
        <div className="lib-progress" aria-label={`${done} guide lette su ${GUIDES.length}`}>
          <span className="lp-num">
            {done}
            <small>/{GUIDES.length}</small>
          </span>
          <span className="lp-label">guide lette</span>
          <span className="meter" aria-hidden>
            <m.i initial={{ scaleX: 0 }} animate={{ scaleX: done / GUIDES.length }} transition={spring.gentle} />
          </span>
        </div>
      </section>
      {CHAPTERS.map((c, i) => (
        <section key={c.id} className="chapter">
          <h2 className="section-title">
            <span className="ch-num">{i + 1}</span>
            {c.title}
          </h2>
          <p className="muted chapter-sum">{c.summary}</p>
          <m.div className="guide-grid" initial="hidden" whileInView="show" viewport={{ once: true, amount: 0.1 }} variants={{ hidden: {}, show: { transition: { staggerChildren: 0.035 } } }}>
            {guidesOf(c.id).map((g) => (
              <GuideCard key={g.id} g={g} read={read.includes(g.id)} onOpen={onOpen} />
            ))}
          </m.div>
        </section>
      ))}
    </m.div>
  );
}

// ------------------------------------------------------------------ lettore

function Reader({ g, analysis, onOpen, onBack, backLabel, onMetric, onAction }: {
  g: Guide;
  analysis: Analysis;
  onOpen: (id: string) => void;
  onBack: () => void;
  backLabel: string;
  onMetric: (id: string) => void;
  onAction: (id: string) => void;
}) {
  const reduce = useReducedMotion();
  const ch = chapterOf(g.chapter);
  const heads = headingsOf(g);
  const { prev, next } = neighbours(g.id);
  const [active, setActive] = useState(-1);
  const secOf = useMemo(() => {
    let n = -1;
    return g.blocks.map((b) => (b.t === 'h' ? ++n : undefined));
  }, [g]);

  // Sezione attiva nell'indice: l'ultimo titolo passato sotto la barra in alto.
  useEffect(() => {
    let raf = 0;
    const onScroll = () => {
      cancelAnimationFrame(raf);
      raf = requestAnimationFrame(() => {
        const hs = document.querySelectorAll<HTMLElement>('.prose h3[data-sec]');
        let cur = -1;
        hs.forEach((h, i) => {
          if (h.getBoundingClientRect().top < 140) cur = i;
        });
        setActive(cur);
      });
    };
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener('scroll', onScroll);
    };
  }, [g.id]);

  const jump = (i: number) => {
    const el = document.getElementById(`sez-${i}`);
    if (!el) return;
    el.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'start' });
    el.focus({ preventScroll: true });
  };

  const measured = new Map<string, Finding>();
  for (const f of analysis.findings) if (!measured.has(f.metric)) measured.set(f.metric, f);
  const metrics = (g.metrics ?? []).filter((id) => METRIC_LIST.some((mm) => mm.id === id));
  const planIds = new Set(analysis.plan.map((p) => p.action.id));
  const others = guidesOf(g.chapter).filter((x) => x.id !== g.id);

  return (
    <m.div className="reader" {...panel}>
      <article className="article" aria-labelledby="article-title">
        <nav className="crumbs" aria-label="Percorso">
          <button className="link-btn" onClick={onBack}>
            <ArrowLeft size={15} aria-hidden /> {backLabel}
          </button>
          <span aria-hidden="true">/</span>
          <span>{ch.title}</span>
        </nav>
        <header className="article-head">
          <h2 id="article-title" className="article-title">{g.title}</h2>
          <p className="lead">{g.summary}</p>
          <div className="article-meta">
            <LevelTag level={g.level} />
            <span className="tag">
              <Clock size={12.5} aria-hidden /> {readingMinutes(g)} min di lettura
            </span>
          </div>
        </header>
        {heads.length > 2 && (
          <details className="toc-inline">
            <summary>
              <ListTree size={16} aria-hidden /> In questa guida
            </summary>
            <ol>
              {heads.map((h, i) => (
                <li key={i}>
                  <a href={`#sez-${i}`} onClick={(e) => { e.preventDefault(); jump(i); }}>{h}</a>
                </li>
              ))}
            </ol>
          </details>
        )}
        <div className="prose">
          {g.blocks.map((b, i) => (
            <BlockView key={i} b={b} sec={secOf[i]} onOpen={onOpen} />
          ))}
        </div>

        {(metrics.length > 0 || (g.actions ?? []).length > 0) && (
          <section className="related" aria-labelledby="rel-title">
            <h3 id="rel-title">Nella tua rete</h3>
            {metrics.length > 0 && (
              <div className="rel-list">
                {metrics.map((id) => {
                  const mm = METRIC_LIST.find((x) => x.id === id)!;
                  const f = measured.get(id);
                  return (
                    <button key={id} className="rel-item" onClick={() => onMetric(id)}>
                      <span className="rel-k">{mm.label}</span>
                      {f ? (
                        <span className={`sev ${f.severity}`}>
                          <SevIcon sev={f.severity} size={13} />
                          {f.value}
                        </span>
                      ) : (
                        <span className="faint rel-none">non misurato</span>
                      )}
                    </button>
                  );
                })}
              </div>
            )}
            {(g.actions ?? []).length > 0 && (
              <div className="rel-actions">
                {(g.actions ?? []).filter((id) => ACTIONS[id]).map((id) => (
                  <button key={id} className="btn small" onClick={() => onAction(id)}>
                    {ACTIONS[id].title}
                    {planIds.has(id) && <span className="tag accent">nel tuo piano</span>}
                    <ArrowRight className="arrow" size={14} aria-hidden />
                  </button>
                ))}
              </div>
            )}
          </section>
        )}

        <nav className="article-nav" aria-label="Altre guide">
          {prev ? (
            <button className="an-btn" onClick={() => onOpen(prev.id)}>
              <span className="an-k"><ArrowLeft size={14} aria-hidden /> Precedente</span>
              <span className="an-t">{prev.title}</span>
            </button>
          ) : <span />}
          {next ? (
            <button className="an-btn next" onClick={() => onOpen(next.id)}>
              <span className="an-k">Successiva <ArrowRight size={14} aria-hidden /></span>
              <span className="an-t">{next.title}</span>
            </button>
          ) : <span />}
        </nav>
      </article>

      <aside className="article-aside" aria-label="Indice e guide del capitolo">
        {heads.length > 0 && (
          <div className="toc">
            <h3>In questa guida</h3>
            <ol>
              {heads.map((h, i) => (
                <li key={i}>
                  <a href={`#sez-${i}`} aria-current={active === i ? 'location' : undefined} onClick={(e) => { e.preventDefault(); jump(i); }}>
                    {active === i && <m.span layoutId="toc-pill" className="toc-pill" transition={spring.snappy} />}
                    {h}
                  </a>
                </li>
              ))}
            </ol>
          </div>
        )}
        {others.length > 0 && (
          <div className="toc others">
            <h3>{ch.title}</h3>
            <ul>
              {others.map((x) => (
                <li key={x.id}>
                  <a href={`#guida-${x.id}`} onClick={(e) => { e.preventDefault(); onOpen(x.id); }}>{x.title}</a>
                </li>
              ))}
            </ul>
          </div>
        )}
      </aside>
    </m.div>
  );
}

// ------------------------------------------------------------------ glossario

function GlossaryView({ term, onOpen }: { term?: string; onOpen: (id: string) => void }) {
  const reduce = useReducedMotion();
  const groups = useMemo(() => {
    const map = new Map<string, GlossaryTerm[]>();
    for (const t of GLOSSARY) {
      const c = fold(t.term)[0];
      const k = /[a-z]/.test(c) ? c.toUpperCase() : '#';
      map.set(k, [...(map.get(k) ?? []), t]);
    }
    return [...map.entries()].sort((a, b) => (a[0] === '#' ? -1 : b[0] === '#' ? 1 : a[0].localeCompare(b[0])));
  }, []);
  const target = term ? GLOSSARY.find((t) => fold(t.term) === fold(term)) : undefined;
  useEffect(() => {
    if (!target) return;
    const id = setTimeout(() => {
      const el = document.getElementById(termAnchor(target.term));
      el?.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'center' });
      el?.focus({ preventScroll: true });
    }, 420);
    return () => clearTimeout(id);
  }, [target, reduce]);
  const go = (k: string) => document.getElementById(`gl-lettera-${k}`)?.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'start' });
  return (
    <m.div {...panel}>
      <nav className="letters" aria-label="Iniziali">
        {groups.map(([k]) => (
          <a key={k} href={`#gl-lettera-${k}`} onClick={(e) => { e.preventDefault(); go(k); }}>
            {k === '#' ? '0–9' : k}
          </a>
        ))}
      </nav>
      {groups.map(([k, terms]) => (
        <section key={k} id={`gl-lettera-${k}`} className="gl-group" aria-label={k === '#' ? 'Numeri' : `Lettera ${k}`}>
          <h2 className="gl-letter" aria-hidden="true">{k === '#' ? '0–9' : k}</h2>
          <dl className="gl-list">
            {terms.map((t) => {
              const gd = t.guide ? guideById(t.guide) : undefined;
              return (
                <div key={t.term} id={termAnchor(t.term)} tabIndex={-1} className={`gl-item ${target === t ? 'focused' : ''}`}>
                  <dt>
                    <span className="gl-term">{t.term}</span>
                    {t.full && <span className="gl-full">{t.full}</span>}
                  </dt>
                  <dd>
                    {t.def}
                    {gd && (
                      <a className="glink gl-more" href={`#guida-${gd.id}`} onClick={(e) => { e.preventDefault(); onOpen(gd.id); }}>
                        {gd.title}
                      </a>
                    )}
                  </dd>
                </div>
              );
            })}
          </dl>
        </section>
      ))}
    </m.div>
  );
}

// ------------------------------------------------------------------ misure e azioni

function Reference({ analysis: a, metric, action, onOpen }: { analysis: Analysis; metric?: string; action?: string; onOpen: (id: string) => void }) {
  const reduce = useReducedMotion();
  const measured = new Map<string, Finding>();
  for (const f of a.findings) if (!measured.has(f.metric)) measured.set(f.metric, f);
  const cats = Object.keys(CATEGORY_LABELS) as Category[];
  const target = metric ? `m-${metric}` : action ? `a-${action}` : undefined;
  useEffect(() => {
    if (!target) return;
    const id = setTimeout(() => {
      const el = document.getElementById(target);
      el?.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'center' });
      el?.focus({ preventScroll: true });
    }, 420);
    return () => clearTimeout(id);
  }, [target, reduce]);
  const guideLinks = (gs: Guide[]) =>
    gs.length > 0 && (
      <p className="ref-guides">
        <BookOpenText size={14} aria-hidden />
        {gs.slice(0, 3).map((x, i) => (
          <Fragment key={x.id}>
            {i > 0 && ' · '}
            <a className="glink" href={`#guida-${x.id}`} onClick={(e) => { e.preventDefault(); onOpen(x.id); }}>{x.title}</a>
          </Fragment>
        ))}
      </p>
    );
  return (
    <m.div {...panel}>
      <p className="muted ref-intro">
        Ogni valore che STARNET Polaris misura, con le soglie usate per giudicarlo, e tutte le azioni correttive del piano. I valori della tua rete
        sono evidenziati.
      </p>
      {cats.map((c) => {
        const ms = METRIC_LIST.filter((mm) => mm.category === c);
        if (!ms.length) return null;
        return (
          <div key={c}>
            <h2 className="section-title">{CATEGORY_LABELS[c]}</h2>
            <div className="grid cols-2">
              {ms.map((mm) => {
                const f = measured.get(mm.id);
                return (
                  <section key={mm.id} id={`m-${mm.id}`} tabIndex={-1} className={`card ref-card ${target === `m-${mm.id}` ? 'focused' : ''}`}>
                    <div className="card-head">
                      <h2>{mm.label}</h2>
                      <span className="spacer" />
                      {f && <span className={`sev ${f.severity}`} title="valore misurato nella tua rete"><SevIcon sev={f.severity} size={14} />{f.value}</span>}
                    </div>
                    <p className="muted" style={{ marginTop: 0 }}>{mm.what}</p>
                    {mm.scale && (
                      <div className="scale" style={{ margin: '10px 0' }}>
                        {mm.scale.map((s) => (
                          <div key={s.range} className={`scale-row ${f?.severity === s.severity ? 'here' : ''}`} style={f?.severity === s.severity ? { ['--sev-bg' as string]: `var(--${s.severity}-bg)` } : undefined}>
                            <span className={`range c-${s.severity}`}><SevIcon sev={s.severity} size={14} />{s.range}</span>
                            <span className="muted">{s.meaning}</span>
                          </div>
                        ))}
                      </div>
                    )}
                    <p style={{ marginBottom: 0 }}><b>Perché conta.</b> <span className="muted">{mm.why}</span></p>
                    {mm.limits && <p className="faint" style={{ fontSize: 13.5, marginBottom: 0 }}><b>Limiti:</b> {mm.limits}</p>}
                    {guideLinks(guidesForMetric(mm.id))}
                  </section>
                );
              })}
            </div>
          </div>
        );
      })}
      <h2 className="section-title">Tutte le azioni correttive</h2>
      <div className="grid cols-2">
        {Object.values(ACTIONS).map((x) => (
          <details key={x.id} id={`a-${x.id}`} tabIndex={-1} className={`card ${target === `a-${x.id}` ? 'focused' : ''}`} open={target === `a-${x.id}` ? true : undefined}>
            <summary>
              <ArrowRight size={16} className="c-ok" aria-hidden /> {x.title}
            </summary>
            <p className="muted">{x.why}</p>
            <ol className="steps">{x.steps.map((s, i) => <li key={i}>{s}</li>)}</ol>
            {guideLinks(guidesForAction(x.id))}
          </details>
        ))}
      </div>
    </m.div>
  );
}

// ------------------------------------------------------------------ ricerca

type Hit = SearchHit | { kind: 'metric'; id: string; label: string; text: string; score: number } | { kind: 'action'; id: string; label: string; text: string; score: number };

function tokensOf(q: string) {
  return fold(q)
    .split(/[\s,;:!?()"']+/)
    .filter((t) => t.length >= 2 || /\d/.test(t));
}

function searchAll(q: string): Hit[] {
  const toks = tokensOf(q);
  const out: Hit[] = search(q, 40);
  const score = (title: string, hay: string) => {
    const ft = fold(title);
    const fh = fold(hay);
    let s = 0;
    for (const t of toks) {
      if (ft.includes(t)) s += 9;
      else if (fh.includes(t)) s += 1.5;
      else return 0;
    }
    return s;
  };
  for (const mm of METRIC_LIST) {
    const s = score(mm.label, [mm.what, mm.why, mm.limits ?? '', ...(mm.scale ?? []).map((x) => `${x.range} ${x.meaning}`)].join(' '));
    if (s) out.push({ kind: 'metric', id: mm.id, label: mm.label, text: mm.what, score: s });
  }
  for (const x of Object.values(ACTIONS)) {
    const s = score(x.title, [x.why, ...x.steps].join(' '));
    if (s) out.push({ kind: 'action', id: x.id, label: x.title, text: x.why, score: s });
  }
  return out.sort((a, b) => b.score - a.score).slice(0, 40);
}

function Results({ q, hits, onPick }: { q: string; hits: Hit[]; onPick: (h: Hit) => void }) {
  const toks = tokensOf(q);
  return (
    <m.div {...panel}>
      <p className="muted results-count" role="status">
        {hits.length ? `${hits.length === 40 ? 'Primi 40' : hits.length} risultati per «${q.trim()}»` : `Nessun risultato per «${q.trim()}». Prova con un sinonimo o una sigla (per esempio «Wi-Fi», «802.1X», «PACS»).`}
      </p>
      <ul className="results" id="guide-results">
        {hits.map((h) => {
          const key = h.kind === 'guide' ? `g${h.guide.id}` : h.kind === 'term' ? `t${h.term.term}` : `${h.kind}${h.id}`;
          const kind = h.kind === 'guide' ? chapterOf(h.guide.chapter).title : h.kind === 'term' ? 'Glossario' : h.kind === 'metric' ? 'Misura' : 'Azione';
          const title = h.kind === 'guide' ? h.guide.title : h.kind === 'term' ? h.term.term + (h.term.full ? ` · ${h.term.full}` : '') : h.label;
          const text = h.kind === 'guide' ? (h.snippet ?? h.guide.summary) : h.kind === 'term' ? h.term.def : h.text;
          return (
            <li key={key}>
              <button className="result" onClick={() => onPick(h)}>
                <span className={`r-kind ${h.kind}`}>{kind}</span>
                <span className="r-title"><Hl text={title} toks={toks} /></span>
                <span className="r-text"><Hl text={text} toks={toks} /></span>
              </button>
            </li>
          );
        })}
      </ul>
    </m.div>
  );
}

// ------------------------------------------------------------------ vista

export function GuideView({ analysis, focus, go }: ViewProps) {
  const [route, setRoute] = useState<Route>(() => parseFocus(focus));
  const [q, setQ] = useState('');
  const [read, setRead] = useLocalState<string[]>('polaris.guide.read', []);
  const [last, setLast] = useLocalState<string | undefined>('polaris.guide.last', undefined);
  const history = useRef<Route[]>([]);

  useEffect(() => {
    const r = parseFocus(focus);
    setRoute((cur) => (same(cur, r) ? cur : r));
    history.current = [];
  }, [focus]);

  useEffect(() => {
    const id = route.article;
    if (!id) return;
    if (!read.includes(id)) setRead([...read, id]);
    if (last !== id) setLast(id);
  }, [route.article]);

  const navigate = (r: Route) => {
    if (same(r, route)) return;
    history.current.push(route);
    setRoute(r);
    setQ('');
    window.scrollTo({ top: 0 });
  };
  const openGuide = (id: string) => navigate({ tab: 'guide', article: id });
  const back = () => {
    setRoute(history.current.pop() ?? { tab: 'guide' });
    window.scrollTo({ top: 0 });
  };
  const hits = useMemo(() => (q.trim() ? searchAll(q) : null), [q]);
  const pick = (h: Hit) => {
    if (h.kind === 'guide') navigate({ tab: 'guide', article: h.guide.id });
    else if (h.kind === 'term') navigate({ tab: 'glossario', term: h.term.term });
    else if (h.kind === 'metric') navigate({ tab: 'misure', metric: h.id });
    else navigate({ tab: 'misure', action: h.id });
  };
  const planIds = new Set(analysis.plan.map((p) => p.action.id));
  const article = route.tab === 'guide' && route.article ? guideById(route.article) : undefined;
  const prevRoute = history.current[history.current.length - 1];
  const backLabel = prevRoute && (prevRoute.article || prevRoute.tab !== 'guide') ? 'Indietro' : 'Biblioteca';

  let body: ReactNode;
  if (hits) body = <Results key="results" q={q} hits={hits} onPick={pick} />;
  else if (article)
    body = (
      <Reader
        key={`g:${article.id}`}
        g={article}
        analysis={analysis}
        onOpen={openGuide}
        onBack={back}
        backLabel={backLabel}
        onMetric={(id) => navigate({ tab: 'misure', metric: id })}
        onAction={(id) => (planIds.has(id) ? go('plan', id) : navigate({ tab: 'misure', action: id }))}
      />
    );
  else if (route.tab === 'guide') body = <LibraryHome key="lib" read={read} last={last} onOpen={openGuide} />;
  else if (route.tab === 'glossario') body = <GlossaryView key="glo" term={route.term} onOpen={openGuide} />;
  else body = <Reference key="ref" analysis={analysis} metric={route.metric} action={route.action} onOpen={openGuide} />;

  return (
    <>
      <m.div className="guide-bar" variants={{ hidden: { opacity: 0, y: 14 }, show: { opacity: 1, y: 0, transition: { duration: 0.55, ease: ease.out } } }}>
        <div className="search-wrap">
          <Search size={18} aria-hidden />
          <input
            className="search"
            type="search"
            placeholder="Cerca in guide, glossario e misure: VLAN, DICOM, roaming, dBm…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && hits?.length) pick(hits[0]);
              else if (e.key === 'Escape') setQ('');
            }}
            aria-label="Cerca nella guida"
            aria-controls={hits ? 'guide-results' : undefined}
            data-search
          />
        </div>
        <Segmented
          value={route.tab}
          label="Sezioni della guida"
          onChange={(t) => navigate({ tab: t })}
          options={[
            { id: 'guide', label: `Guide · ${GUIDES.length}` },
            { id: 'glossario', label: `Glossario · ${GLOSSARY.length}` },
            { id: 'misure', label: 'Misure e azioni' },
          ]}
        />
      </m.div>
      <AnimatePresence mode="wait" initial={false}>
        {body}
      </AnimatePresence>
    </>
  );
}
