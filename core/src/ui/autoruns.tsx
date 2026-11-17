import { AppWindow, ArrowRight, BookOpenText, Rocket, ShieldAlert, TriangleAlert } from 'lucide-react';
import { m } from 'motion/react';
import { useState } from 'react';
import {
  accountLabel,
  autorunCounts,
  autorunIssues,
  browserLabel,
  categoryLabel,
  categoryLower,
  categoryShort,
  consumerLabel,
  entryFile,
  fileName,
  fileSeverity,
  folderLabel,
  interpretedInline,
  runAsLabel,
  signatureLabel,
  sourceLabel,
  startLabel,
  triggerLabel,
  userWritable,
} from '../engine';
import type { AutorunCategory, AutorunEntry, AutorunIssue, AutorunsData, Scan, Severity } from '../engine';
import { openTool } from './api';
import { Segmented, SevIcon, TableWrap, useOpenGuide, useToast } from './components';
import { rise } from './motion';
import type { ViewProps } from './views';

// Avvio automatico, come Autoruns: tutto ciò che parte da solo oltre alle
// chiavi Run (attività pianificate, servizi, driver, sottoscrizioni WMI,
// estensioni dei browser, Winlogon e gli altri punti di Windows). L'agente
// elenca le voci non di Microsoft, quelle con il file mancante e quelle in
// cartelle che un utente può scrivere; le voci di Windows firmate da
// Microsoft si contano soltanto. Polaris legge e basta: nessun pulsante
// disattiva o cancella;
// per agire ci sono i passi del piano d'azione e i programmi (Autoruns,
// App di avvio di Windows).

export type AutorunTab = 'logon' | 'tasks' | 'services' | 'drivers' | 'wmi' | 'browser' | 'other';

export const AUTORUN_TABS: { id: AutorunTab; label: string; cats: AutorunCategory[] }[] = [
  { id: 'logon', label: 'Accesso', cats: ['logon'] },
  { id: 'tasks', label: 'Attività pianificate', cats: ['tasks'] },
  { id: 'services', label: 'Servizi', cats: ['services'] },
  { id: 'drivers', label: 'Driver', cats: ['drivers'] },
  { id: 'wmi', label: 'WMI', cats: ['wmi'] },
  { id: 'browser', label: 'Browser', cats: ['browser'] },
  { id: 'other', label: 'Altro', cats: ['winlogon', 'hijacks', 'lsa', 'print', 'network'] },
];

/** Voci mostrate per categoria prima di "Mostra tutte". */
export const AUTORUNS_SHOWN = 25;

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

const RANK: Record<Severity, number> = { unknown: 0, ok: 1, info: 2, warn: 3, crit: 4 };

/** Gravità di una voce da controllare, a parole: il colore da solo non basta. */
const ISSUE_WORD: Record<Severity, string> = { crit: 'da controllare subito', warn: 'da controllare', info: 'da conoscere', ok: 'in regola', unknown: 'da verificare' };

const SCOPE: Record<NonNullable<AutorunEntry['scope']>, string> = { machine: 'tutti gli utenti', machine32: 'tutti gli utenti, programma a 32 bit', user: 'questo utente' };

/** Tipo di voce, come lo scrive l'agente (Kind in windows/internal/autoruns). */
const KIND: Record<string, string> = {
  run: 'chiave Run',
  runonce: 'chiave RunOnce',
  runonceex: 'chiave RunOnceEx',
  policyrun: 'chiave Run dei criteri',
  load: 'valore load di Windows',
  folder: 'cartella Esecuzione automatica',
  shell: 'Shell di Winlogon',
  userinit: 'Userinit di Winlogon',
  ifeo: 'debugger IFEO',
  silentexit: 'SilentProcessExit',
  bootexecute: 'BootExecute',
  appinit: 'AppInit_DLLs',
  printmon: 'monitor di stampa',
  printproc: 'processore di stampa',
  'lsa-auth': 'pacchetto di autenticazione (LSA)',
  'lsa-security': 'pacchetto di sicurezza (LSA)',
  'lsa-notify': 'notifica delle password (LSA)',
  netprovider: 'provider di rete',
};

const whenText = (iso?: string) => {
  if (!iso) return '';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString('it-IT', { dateStyle: 'short', timeStyle: 'short' });
};

/**
 * Firma del file che conta per la voce, con il tono; undefined se la voce non
 * ha file (estensioni, WMI). Per un file mancante il tono è quello del
 * giudizio sulla voce (issueSev): avviso solo per servizi e driver attivi.
 */
export function entrySignature(e: AutorunEntry, issueSev?: Severity): { text: string; tone: Severity } | undefined {
  if (interpretedInline(e)) return { text: `Comando eseguito da ${fileName(e.file?.path)}: la firma di Microsoft di questo programma di Windows non dice nulla su ciò che esegue`, tone: 'info' };
  const f = entryFile(e);
  if (!f) return undefined;
  if (f.missing) return { text: 'File mancante', tone: issueSev ?? 'unknown' };
  const l = signatureLabel(f.signature);
  const sev = fileSeverity(f);
  if (f.signature && f.signature.status === 'unsigned' && userWritable(f.folder)) return { text: 'Nessuna firma, in una cartella che un utente può scrivere', tone: sev };
  return { text: l.text, tone: sev === 'unknown' ? l.tone : sev };
}

/** Dettagli propri della categoria, in breve. */
export function entryDetails(e: AutorunEntry): string[] {
  const out: string[] = [];
  const push = (s: string | undefined | false) => {
    if (s) out.push(s);
  };
  switch (e.category) {
    case 'tasks':
      if (e.triggers?.length) push(`parte ${e.triggers.map(triggerLabel).join(', ')}`);
      if (e.runAs) push(`gira come ${runAsLabel(e.runAs)}${e.highest ? ', con i privilegi più alti' : ''}`);
      else if (e.highest) push('con i privilegi più alti');
      if (e.hidden) push('attività nascosta');
      if (e.lastRun) push(`ultima esecuzione ${whenText(e.lastRun)}${e.lastResult ? (/^0x0+$/i.test(e.lastResult) || e.lastResult === '0' ? ', riuscita' : `, esito ${e.lastResult}`) : ''}`);
      else push('mai eseguita');
      if (e.nextRun) push(`prossima ${whenText(e.nextRun)}`);
      if (e.authorMicrosoft) push('autore dichiarato: Microsoft');
      break;
    case 'services':
    case 'drivers':
      push(e.start && `avvio ${startLabel(e.start)}`);
      // Account non letto: si dice, non si presume LocalSystem (i driver non hanno account).
      push(e.account ? `account ${accountLabel(e.account)}` : e.category === 'services' && 'account non letto');
      if (e.unquoted) push(`percorso con spazi senza virgolette${e.interceptors ? `: ${plural(e.interceptors, 'file intercettore esiste', 'file intercettori esistono')}` : ''}`);
      break;
    case 'wmi':
      push(consumerLabel(e.consumer));
      // bound falso non arriva nel JSON (omitempty): l'agente lo legge sempre, assente vuol dire non collegata.
      push(e.bound ? 'collegata a un evento' : 'non collegata a un evento');
      push(e.namespace && `spazio ${e.namespace}`);
      break;
    case 'browser':
      push(`${browserLabel(e.browser)}${e.profile ? `, profilo ${e.profile}` : ''}`);
      push(sourceLabel(e.source));
      push(e.allSites && 'può leggere e modificare tutti i siti');
      push(e.version && `versione ${e.version}`);
      break;
    default:
      push(e.kind && (KIND[e.kind] ?? e.kind));
      push(e.scope && SCOPE[e.scope]);
  }
  const f = entryFile(e);
  if (f?.description || f?.company) push([f.description, f.company].filter((x, i, a) => !!x && a.indexOf(x) === i).join(' · '));
  return out;
}

/** Stato della voce: attiva o disattivata, e in esecuzione per servizi e driver. */
export function entryState(e: AutorunEntry): { text: string; on: boolean } {
  if (!e.enabled) return { text: e.start === 'disabled' ? 'disabilitato' : 'disattivata', on: false };
  // running falso non arriva nel JSON (omitempty): l'agente legge sempre lo stato dei servizi, assente vuol dire fermo.
  if (e.category === 'services' || e.category === 'drivers') return { text: e.running ? 'in esecuzione' : 'fermo', on: true };
  return { text: 'attiva', on: true };
}

export interface TabCount {
  listed: number;
  total: number;
  microsoft: number;
  issues: number;
  denied: AutorunCategory[];
}

/** Conteggi per scheda: voci elencate, totale, voci di Microsoft non elencate, voci da controllare, categorie negate. */
export function tabCounts(scan: Scan, issues: AutorunIssue[]): Record<AutorunTab, TabCount> {
  const data = scan.pc?.autoruns;
  const counts = autorunCounts(scan);
  const out = {} as Record<AutorunTab, TabCount>;
  for (const t of AUTORUN_TABS) {
    const c: TabCount = { listed: 0, total: 0, microsoft: 0, issues: 0, denied: [] };
    for (const cat of t.cats) {
      const listed = (data?.entries ?? []).filter((e) => e.category === cat).length;
      const n = counts.find((x) => x.category === cat);
      c.listed += listed;
      c.total += n ? Math.max(n.total, listed) : listed;
      c.microsoft += n ? n.microsoft : 0;
      c.issues += issues.filter((x) => x.entry.category === cat).length;
      if ((data?.denied ?? []).indexOf(cat) >= 0) c.denied.push(cat);
    }
    out[t.id] = c;
  }
  return out;
}

/** Voci di Windows firmate da Microsoft, contate e non elencate. */
export const microsoftTotal = (scan: Scan) => autorunCounts(scan).reduce((t, c) => t + c.microsoft, 0);

function IssueList({ issues }: { issues: AutorunIssue[] }) {
  return (
    <ul className="cert-list ar-issues" aria-label="Voci da controllare">
      {issues.map((x, i) => {
        const e = x.entry;
        const f = entryFile(e);
        const where = e.command || f?.path || (e.category === 'browser' ? `${browserLabel(e.browser)}${e.extId ? ` · ${e.extId}` : ''}` : e.location);
        return (
          <li key={`${e.category}-${e.name}-${i}`} className="cert-item" data-sev={x.severity}>
            <div className="cert-head">
              <span className="cert-name">
                <strong>{e.name}</strong>
                <span className="faint">{categoryShort(e.category)}</span>
              </span>
              <span className={`sev ${x.severity}`}>
                <SevIcon sev={x.severity} size={14} />
                {ISSUE_WORD[x.severity]}
              </span>
            </div>
            <p className="ar-why">{x.why.charAt(0).toUpperCase() + x.why.slice(1)}.</p>
            {where && <p className="mono faint ar-where">{where}</p>}
          </li>
        );
      })}
    </ul>
  );
}

function EntriesTable({ cat, entries, flagged }: { cat: AutorunCategory; entries: AutorunEntry[]; flagged: Map<AutorunEntry, AutorunIssue> }) {
  const [all, setAll] = useState(false);
  const rows = [...entries].sort((a, b) => {
    const ia = flagged.get(a);
    const ib = flagged.get(b);
    return (ib ? RANK[ib.severity] : 0) - (ia ? RANK[ia.severity] : 0) || Number(b.enabled) - Number(a.enabled) || a.name.localeCompare(b.name, 'it');
  });
  const shown = all ? rows : rows.slice(0, AUTORUNS_SHOWN);
  const ext = cat === 'browser';
  return (
    <>
      <TableWrap label={categoryLabel(cat)}>
        <table className="pc-table ar-table">
          <thead>
            <tr>
              <th>{ext ? 'Estensione' : 'Voce'}</th>
              <th>{ext ? 'Identificativo' : 'Comando o file'}</th>
              <th>{ext ? 'Origine' : 'Firma'}</th>
              <th>Stato</th>
              <th>Dettagli</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((e, i) => {
              const issue = flagged.get(e);
              const sig = entrySignature(e, issue?.severity);
              const f = entryFile(e);
              const st = entryState(e);
              const det = entryDetails(e);
              return (
                <tr key={`${e.name}-${i}`} className={e.enabled ? undefined : 'off'} data-sev={issue?.severity}>
                  <td className="ar-name">
                    <b>{e.name}</b>
                    {issue && (
                      <span className={`sev ${issue.severity}`}>
                        <SevIcon sev={issue.severity} size={13} />
                        {ISSUE_WORD[issue.severity]}
                      </span>
                    )}
                    {e.location && !ext && <span className="mono faint ar-loc">{e.location}</span>}
                  </td>
                  <td className="cmd">
                    {ext ? (
                      <span className="mono faint">{e.extId ?? '—'}</span>
                    ) : (
                      <>
                        <span className="mono" title={e.command || f?.path}>
                          {e.command || f?.path || '—'}
                        </span>
                        {e.target?.path && <span className="faint ar-target">esegue {e.target.path}</span>}
                      </>
                    )}
                  </td>
                  <td className="proc-sig">
                    {ext ? (
                      <span>{sourceLabel(e.source)}</span>
                    ) : sig ? (
                      <>
                        <span className={`c-${sig.tone}`}>
                          <SevIcon sev={sig.tone} size={14} />
                          <span>{sig.text}</span>
                        </span>
                        {f?.folder && !f.missing && <span className="faint ar-folder">{folderLabel(f.folder)}</span>}
                      </>
                    ) : (
                      <span className="faint">—</span>
                    )}
                  </td>
                  <td>{st.on ? <span className="tag accent">{st.text}</span> : <span className="tag">{st.text}</span>}</td>
                  <td className="ar-details">{det.length ? det.join(' · ') : <span className="faint">—</span>}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </TableWrap>
      {rows.length > AUTORUNS_SHOWN && (
        <button className="link-btn" onClick={() => setAll(!all)} aria-expanded={all} style={{ marginTop: 8 }}>
          {all ? 'Mostra solo le prime' : `Mostra tutte le ${rows.length} voci`}
        </button>
      )}
    </>
  );
}

function CategoryPart({ data, cat, flagged, scan, showTitle }: { data: AutorunsData; cat: AutorunCategory; flagged: Map<AutorunEntry, AutorunIssue>; scan: Scan; showTitle: boolean }) {
  const entries = data.entries.filter((e) => e.category === cat);
  const n = autorunCounts(scan).find((c) => c.category === cat);
  const total = n ? Math.max(n.total, entries.length) : entries.length;
  const ms = n?.microsoft ?? 0;
  // Nelle estensioni il totale dell'agente comprende i componenti interni del browser, che non si elencano.
  const hidden = cat === 'browser' ? Math.max(0, total - ms - entries.length) : 0;
  const denied = (data.denied ?? []).indexOf(cat) >= 0;
  if (!showTitle && !entries.length && !total && !denied) return <p className="muted">Nessuna voce in questa categoria.</p>;
  if (showTitle && !entries.length && !total && !denied) return null;
  return (
    <div className="ar-cat">
      {showTitle && <h3 className="dev-h">{categoryLabel(cat)}</h3>}
      <p className="faint ar-count">
        {total
          ? `${plural(total, 'voce', 'voci')} in tutto${ms ? `: ${ms} di Windows firmate da Microsoft, non elencate` : ''}${entries.length ? `${ms ? ';' : ':'} ${plural(entries.length, 'elencata qui', 'elencate qui')}` : ''}${hidden ? `${ms || entries.length ? ';' : ':'} ${plural(hidden, 'componente interno del browser, non elencato', 'componenti interni del browser, non elencati')}` : ''}.`
          : 'Nessuna voce letta.'}
      </p>
      {denied && (
        <div className="notice" style={{ margin: '8px 0 10px' }}>
          <ShieldAlert size={18} aria-hidden />
          {data.elevated ? (
            <span>
              Alcune voci di questa categoria non si sono potute leggere nemmeno da amministratore (protette)
              {cat === 'tasks' ? ': da guardare in Utilità di pianificazione.' : ': da verificare.'}
            </span>
          ) : (
            <span>
              Senza i permessi di amministratore questa categoria si legge solo in parte: il resto è da verificare avviando Polaris come
              amministratore.
            </span>
          )}
        </div>
      )}
      {entries.length > 0 && <EntriesTable cat={cat} entries={entries} flagged={flagged} />}
    </div>
  );
}

/**
 * Avvio automatico come Autoruns: in cima le voci da controllare (quelle dei
 * giudizi), poi le schede per categoria con i conteggi.
 */
export function AutorunsCard({ scan, analysis, live, source, go, initialTab }: Pick<ViewProps, 'scan' | 'analysis' | 'live' | 'source' | 'go'> & { initialTab?: AutorunTab }) {
  const toast = useToast();
  const openGuide = useOpenGuide();
  const data = scan.pc?.autoruns;
  const issues = data ? autorunIssues(scan).sort((a, b) => RANK[b.severity] - RANK[a.severity]) : [];
  const counts = tabCounts(scan, issues);
  const firstTab = AUTORUN_TABS.find((t) => counts[t.id].issues) ?? AUTORUN_TABS.find((t) => counts[t.id].listed) ?? AUTORUN_TABS[0];
  const [tab, setTab] = useState<AutorunTab>(initialTab ?? firstTab.id);
  const [allIssues, setAllIssues] = useState(false);
  if (!data) return null;
  const flagged = new Map<AutorunEntry, AutorunIssue>();
  for (const x of issues) if (!flagged.has(x.entry)) flagged.set(x.entry, x);
  const ms = microsoftTotal(scan);
  const current = AUTORUN_TABS.find((t) => t.id === tab)!;
  const denied = data.denied ?? [];
  // Il passo da cui partire nel piano: la prima azione del giudizio più grave sull'avvio automatico.
  const fs = analysis.findings.filter((f) => f.id.startsWith('pc.autoruns.') && f.actions.length).sort((a, b) => RANK[b.severity] - RANK[a.severity]);
  const planAction = fs.length ? fs[0].actions[0] : undefined;
  const openStartup = () =>
    openTool('startup-apps', 'app')
      .then(() => toast('App di avvio aperte', 'ok', 'open'))
      .catch((e) => toast(e instanceof Error ? e.message : String(e), 'error'));
  const worrying = issues.filter((x) => x.severity === 'warn' || x.severity === 'crit');

  return (
    <m.section variants={rise} className="card autoruns-card">
      <div className="card-head">
        <h2 className="disk-title">
          <Rocket size={19} aria-hidden /> Avvio automatico
        </h2>
        <span className="sub">tutto ciò che parte da solo, come Autoruns</span>
      </div>
      <p className="muted" style={{ marginTop: 0 }}>
        {ms > 0
          ? `Le voci di Windows firmate da Microsoft non si elencano: sono ${ms}. `
          : 'Le voci di Windows firmate da Microsoft non si elencano. '}
        Qui sotto ci sono le altre: programmi di altri produttori, voci con il file mancante e quelle che partono da cartelle che un utente può
        scrivere. I componenti interni dei browser si contano soltanto.
      </p>

      {denied.length > 0 && (
        <div className="notice" style={{ marginBottom: 12 }}>
          <ShieldAlert size={18} aria-hidden />
          {data.elevated ? (
            <span>
              Anche da amministratore {denied.length === 1 ? 'una categoria si legge' : 'alcune categorie si leggono'} solo in parte (
              {denied.map(categoryLower).join(', ')}): alcune voci sono protette e non si sono potute leggere. Il resto non va considerato in regola
              {denied.indexOf('tasks') >= 0 ? ': le attività sono da guardare in Utilità di pianificazione.' : '.'}
            </span>
          ) : (
            <span>
              Senza i permessi di amministratore {denied.length === 1 ? 'una categoria si legge' : 'alcune categorie si leggono'} solo in parte (
              {denied.map(categoryLower).join(', ')}): il resto è da verificare avviando Polaris come amministratore, non va considerato in regola.
            </span>
          )}
        </div>
      )}
      {data.partial && (
        <div className="notice" style={{ marginBottom: 12 }}>
          <TriangleAlert size={18} aria-hidden />
          <span>La lettura non è finita in tempo durante l'analisi: l'elenco può essere incompleto.</span>
        </div>
      )}

      <h3 className="dev-h">Voci da controllare</h3>
      {issues.length ? (
        <>
          <p className="faint ar-count">
            {worrying.length
              ? `${plural(worrying.length, 'voce da controllare', 'voci da controllare')}${issues.length > worrying.length ? `, ${plural(issues.length - worrying.length, 'altra da conoscere', 'altre da conoscere')}` : ''}.`
              : `${plural(issues.length, 'voce da conoscere', 'voci da conoscere')}, nessuna con segnali gravi.`}{' '}
            Nessuna è per forza un pericolo: va riconosciuta.
          </p>
          {/* Prima le voci da controllare; quelle solo da conoscere su richiesta, se ce ne sono di più gravi. */}
          <IssueList issues={worrying.length && !allIssues ? worrying : issues} />
          {worrying.length > 0 && issues.length > worrying.length && (
            <button className="link-btn" onClick={() => setAllIssues(!allIssues)} aria-expanded={allIssues}>
              {allIssues ? 'Mostra solo le voci da controllare' : `Mostra anche ${issues.length - worrying.length === 1 ? 'la voce' : `le ${issues.length - worrying.length} voci`} da conoscere`}
            </button>
          )}
        </>
      ) : (
        <p className="muted" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <SevIcon sev={denied.length ? 'unknown' : 'ok'} size={16} className={denied.length ? 'c-unknown' : 'c-ok'} />
          {denied.length ? 'Nessuna voce da controllare tra quelle lette; le categorie lette solo in parte restano da verificare.' : 'Nessuna voce da controllare tra quelle lette.'}
        </p>
      )}

      <h3 className="dev-h">Per categoria</h3>
      <div className="ar-tabs">
        <Segmented<AutorunTab>
          label="Categorie dell'avvio automatico"
          value={tab}
          onChange={setTab}
          options={AUTORUN_TABS.map((t) => ({
            id: t.id,
            label: (
              <>
                {t.label} <span className="ar-tab-n">{counts[t.id].listed}</span>
                {counts[t.id].issues > 0 && <span className="sr-only">, {plural(counts[t.id].issues, 'da controllare', 'da controllare')}</span>}
                {counts[t.id].denied.length > 0 && <span className="sr-only">, letta solo in parte</span>}
              </>
            ),
          }))}
        />
      </div>
      <div role="tabpanel" aria-label={current.label} className="ar-panel">
        {current.cats.map((c) => (
          <CategoryPart key={c} data={data} cat={c} flagged={flagged} scan={scan} showTitle={current.cats.length > 1} />
        ))}
        {current.cats.length > 1 && !counts[current.id].total && !counts[current.id].denied.length && (
          <p className="muted">Nessuna voce letta in Winlogon, nei dirottamenti noti, nei pacchetti di sicurezza, nella stampa e nei provider di rete.</p>
        )}
      </div>

      <div className="crash-actions">
        {planAction && (
          <button className="btn small" onClick={() => go('plan', planAction)}>
            Passi nel piano d'azione <ArrowRight size={15} aria-hidden />
          </button>
        )}
        {live && source === 'agent' && (
          <button className="btn small" onClick={openStartup}>
            <AppWindow size={15} aria-hidden /> Apri App di avvio
          </button>
        )}
        {openGuide && (
          <button className="link-btn" onClick={() => openGuide('avvio-automatico')}>
            <BookOpenText size={15} aria-hidden /> Come leggere l'avvio automatico
          </button>
        )}
      </div>
      <p className="faint card-foot">
        Polaris legge soltanto: non disattiva e non cancella nessuna voce. I programmi all'avvio si disattivano da Gestione attività &gt; App di avvio;
        servizi, attività pianificate, driver ed estensioni con Autoruns, con l'Utilità di pianificazione o dal browser, seguendo i passi del piano
        d'azione. La firma si verifica senza Internet (revoca dei certificati non controllata online). Dei profili dei browser si indica solo il numero,
        mai il nome; dell'account solo il tipo.
      </p>
    </m.section>
  );
}
