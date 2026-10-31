import { Copy, FileBadge, Lightbulb, Plus, Radar, Trash2, TriangleAlert } from 'lucide-react';
import { AnimatePresence, m } from 'motion/react';
import { useEffect, useMemo, useRef, useState } from 'react';
import { CERT_MAX_TARGETS, CERT_TRUST_TEXT, certExpiryText, certFailHint, certIssues, certNormalize, certSeverity, certWhere, dateIt } from '../engine';
import type { CertData, CertResult, CertTarget, Scan, Severity } from '../engine';
import { simulatedCerts } from '../demo/simulate';
import { lastCerts, runCerts } from './api';
import { SevIcon, thousands, useToast } from './components';
import { useLocalState } from './hooks';
import { ease, rise } from './motion';
import type { ViewProps } from './views';

// Certificati dei servizi interni: l'utente indica i servizi della rete
// locale (gestionale, PACS, NAS, pannello del router, posta) e l'agente ne
// legge il certificato TLS, senza inviare dati. Senza agente il controllo è
// simulato e dichiarato come tale; un rapporto importato si consulta e basta.

/** Porte con TLS diretto (più SMTP con STARTTLS) da proporre nel campo della porta. */
export const CERT_PORTS: { port: number; label: string }[] = [
  { port: 443, label: 'HTTPS' },
  { port: 8443, label: 'HTTPS alternativo' },
  { port: 636, label: 'LDAPS, controller di dominio' },
  { port: 3269, label: 'LDAPS, catalogo globale' },
  { port: 465, label: 'SMTPS, invio della posta' },
  { port: 587, label: 'SMTP con STARTTLS, invio della posta' },
  { port: 25, label: 'SMTP con STARTTLS, tra server di posta' },
  { port: 993, label: 'IMAPS, posta in arrivo' },
  { port: 995, label: 'POP3S, posta in arrivo' },
  { port: 990, label: 'FTPS' },
  { port: 2762, label: 'DICOM su TLS' },
  { port: 8883, label: 'MQTT su TLS' },
];
const TLS_PORTS = new Set(CERT_PORTS.map((p) => p.port));

/** Chiave di confronto di un servizio: nome in minuscolo e porta effettiva. */
export function certKey(t: { host: string; port?: number }): string {
  const n = certNormalize(t.host, t.port);
  return 'error' in n ? t.host.trim().toLowerCase() : `${n.host.toLowerCase()}:${n.port}`;
}

/**
 * Servizi da proporre: il pannello del router o del gateway (sulla porta
 * HTTPS che l'analisi ha visto aperta o non ha controllato) e i servizi delle
 * verifiche di raggiungibilità che rispondono su una porta con TLS.
 */
export function certSuggestions(scan: Scan): CertTarget[] {
  const out: CertTarget[] = [];
  const gw = scan.gateway;
  if (gw?.ip) {
    const open = (p: number) => gw.ports?.find((x) => x.port === p)?.open;
    const port = open(443) || gw.web?.https ? 443 : open(8443) ? 8443 : open(443) === undefined ? 443 : open(8443) === undefined ? 8443 : undefined;
    if (port) out.push({ label: scan.agent.domain ? 'Gestione del gateway' : 'Pannello del router', host: gw.ip, port });
  }
  for (const r of scan.infra?.reach?.results ?? []) {
    if (r.expect === 'reachable' && r.status === 'open' && r.port && TLS_PORTS.has(r.port)) out.push({ ...(r.label ? { label: r.label } : {}), host: r.host, port: r.port });
  }
  return out.filter((t, i) => out.findIndex((x) => certKey(x) === certKey(t)) === i);
}

export interface CertRowCheck {
  /** Errore da mostrare sul campo del nome (o dell'indirizzo https://). */
  hostError?: string;
  /** Errore da mostrare sul campo della porta. */
  portError?: string;
  /** Il servizio come lo controlla l'agente, quando è diverso da come è scritto. */
  effective?: string;
  note?: string;
}

const RDP_ERROR = 'il Desktop remoto (3389) non usa TLS diretto: per ora non si controlla';

/**
 * Controlla una riga prima di inviarla: lo stesso controllo dell'agente, più
 * qualche nota utile. Ogni errore sta sul campo che lo causa, così chi usa un
 * lettore di schermo lo sente sul campo giusto.
 */
export function certRowCheck(host: string, port: string): CertRowCheck {
  const h = host.trim();
  const p = port.trim() ? Number(port) : undefined;
  const portError = p !== undefined && (!Number.isInteger(p) || p < 1 || p > 65535) ? 'porta tra 1 e 65535, o vuota per 443' : p === 3389 ? RDP_ERROR : undefined;
  if (!h) return { hostError: 'indica un nome, un indirizzo IP o un indirizzo https://', ...(portError ? { portError } : {}) };
  if (portError) return { portError };
  const n = certNormalize(h, p);
  if ('error' in n) return { hostError: n.error };
  // La porta 3389 può arrivare anche da un indirizzo come https://pc-01:3389.
  if (n.port === 3389) return { hostError: RDP_ERROR };
  const where = certWhere(n);
  const note = n.port === 25 || n.port === 587 ? 'Posta SMTP: il controllo passa a TLS con STARTTLS.' : undefined;
  return { ...(where !== `${h}:${p ?? 443}` ? { effective: where } : {}), ...(note ? { note } : {}) };
}

/** Rete su cui è partito un controllo: si unisce solo al rapporto della stessa rete e della stessa origine. */
export interface CertTargetRef {
  live: boolean;
  host?: string;
  gateway?: string;
}

/**
 * Il controllo riguarda il rapporto mostrato: stesso PC, stesso gateway, e
 * dati dell'agente per un controllo reale o demo per uno simulato. Un
 * rapporto importato non riceve mai controlli.
 */
export const sameCertTarget = (t: CertTargetRef | undefined, scan: Scan | null | undefined, source: 'agent' | 'demo' | 'file') =>
  !!t && !!scan && source === (t.live ? 'agent' : 'demo') && t.host === scan.agent.host && t.gateway === scan.gateway?.ip;

/** Etichette della gravità per ogni servizio: icona e testo, mai solo il colore. */
const SEV_TEXT: Record<Severity, string> = {
  ok: 'valido',
  info: 'da sapere',
  warn: 'da sistemare',
  crit: 'problema',
  unknown: 'non controllato',
};

/** Impronta a coppie di cifre, come la mostrano i browser: "AB:CD:…". */
export const fingerprintText = (fp: string) => (fp.match(/.{1,2}/g) ?? []).join(':');

interface Row {
  key: number;
  label: string;
  host: string;
  port: string;
}

const toTarget = (r: Row): CertTarget => ({
  ...(r.label.trim() ? { label: r.label.trim() } : {}),
  host: r.host.trim(),
  ...(r.port.trim() ? { port: Number(r.port) } : {}),
});

// Il controllo può durare fino a due minuti e continua anche se si cambia
// pagina: lo stato (in corso, ultimo errore) vive a livello di modulo e le
// schede che si montano lo seguono.
interface CertJob {
  busy: boolean;
  error: string | null;
}
let running: Promise<CertData> | null = null;
let job: CertJob = { busy: false, error: null };
const jobListeners = new Set<(j: CertJob) => void>();
const publishJob = (patch: Partial<CertJob>) => {
  job = { ...job, ...patch };
  jobListeners.forEach((f) => f(job));
};
// L'ultimo controllo fatto dall'agente si recupera una volta sola, all'apertura.
let restoreTried = false;

export function CertsCard({ scan, live, source, addCerts }: ViewProps) {
  const toast = useToast();
  const certs = scan.infra?.certs;
  // I servizi dipendono dalla rete: si ricordano per rete (gateway), separati dalla demo.
  const storeKey = `polaris.certs.${live ? (scan.gateway?.ip ?? 'senza-gateway') : `demo-${scan.agent.host ?? ''}`}`;
  const fromResults = useMemo<CertTarget[] | null>(
    () => (certs?.results?.length ? certs.results.map(({ label, host, port }) => ({ ...(label ? { label } : {}), host, port })) : null),
    [certs],
  );
  const [saved, setSaved] = useLocalState<CertTarget[] | null>(storeKey, null);
  const seq = useRef(0);
  const toRows = (ts: CertTarget[]): Row[] => ts.map((t) => ({ key: ++seq.current, label: t.label ?? '', host: t.host, port: t.port ? String(t.port) : '' }));
  const [rows, setRowsState] = useState<Row[]>(() => toRows(saved ?? fromResults ?? certSuggestions(scan)));
  const [{ busy, error }, setJob] = useState<CertJob>(job);
  const [touched, setTouched] = useState(false);

  useEffect(() => {
    jobListeners.add(setJob);
    setJob(job);
    return () => {
      jobListeners.delete(setJob);
    };
  }, []);

  useEffect(() => {
    if (!live || certs || restoreTried) return;
    restoreTried = true;
    const target: CertTargetRef = { live: true, host: scan.agent.host, gateway: scan.gateway?.ip };
    lastCerts()
      .then((d) => {
        if (d?.results?.length) addCerts(d, target, true);
      })
      .catch(() => undefined);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [live]);

  const setRows = (next: Row[]) => {
    setRowsState(next);
    setSaved(next.map(toTarget));
  };
  const update = (key: number, patch: Partial<Row>) => setRows(rows.map((r) => (r.key === key ? { ...r, ...patch } : r)));
  const checks = rows.map((r) => certRowCheck(r.host, r.port));
  const invalid = checks.some((c) => c.hostError || c.portError);
  const canRun = rows.length > 0 && rows.length <= CERT_MAX_TARGETS && !invalid && !busy;
  const suggestions = certSuggestions(scan).filter((s) => !rows.some((r) => certKey(toTarget(r)) === certKey(s)));

  const run = () => {
    setTouched(true);
    if (!canRun) return;
    const targets = rows.map(toTarget);
    const target: CertTargetRef = { live, host: scan.agent.host, gateway: scan.gateway?.ip };
    running = live ? runCerts(targets) : new Promise<CertData>((ok) => setTimeout(() => ok(simulatedCerts(scan, targets)), 1200));
    publishJob({ busy: true, error: null });
    running
      .then(
        (res) => {
          if (!addCerts(res, target)) return;
          const sevs = res.results.map(certSeverity);
          const bad = sevs.filter((s) => s === 'crit' || s === 'warn').length;
          const failed = sevs.filter((s) => s === 'unknown').length;
          const tail = failed ? `, ${failed} non ${failed === 1 ? 'controllato' : 'controllati'}` : '';
          if (bad) toast(`Certificati controllati · ${bad} da sistemare${tail}`, 'warn');
          else if (failed) toast(`Certificati controllati${tail}`, 'warn');
          else toast('Certificati controllati · nessun problema', 'ok', 'complete');
        },
        (e) => {
          const msg = e instanceof Error ? e.message : String(e);
          publishJob({ error: msg });
          toast(`Controllo non riuscito: ${msg}`, 'error');
        },
      )
      .finally(() => {
        running = null;
        publishJob({ busy: false });
      });
  };

  const counts = (certs?.results ?? []).reduce<Record<Severity, number>>(
    (acc, r) => {
      acc[certSeverity(r)]++;
      return acc;
    },
    { ok: 0, info: 0, warn: 0, crit: 0, unknown: 0 },
  );

  return (
    <m.section variants={rise} className="card certs-card">
      <div className="card-head">
        <h2 style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
          <FileBadge size={19} aria-hidden /> Servizi con connessione cifrata
        </h2>
      </div>
      <p className="muted" style={{ marginTop: 0 }}>
        Indica i servizi della rete locale che usano una connessione cifrata (gestionale, PACS, NAS, pannello del router, posta): Polaris si collega, legge il
        certificato durante la negoziazione TLS e chiude, senza inviare dati né credenziali. Vedi scadenza, nomi, emittente, versione di TLS e se questo PC lo
        considera attendibile. Solo indirizzi privati, al massimo {CERT_MAX_TARGETS} servizi; la revoca non si controlla.
      </p>

      {source === 'file' ? (
        <div className="notice">
          <TriangleAlert size={18} aria-hidden />
          <span>Rapporto importato: qui si consultano i certificati controllati allora. Il controllo si esegue dall'agente, dalla rete in cui si trova il PC.</span>
        </div>
      ) : (
        <>
          {!live && (
            <div className="notice" style={{ marginBottom: 4 }}>
              <TriangleAlert size={18} aria-hidden />
              <span>
                Senza agente il controllo è <b>simulato</b> sui dati dimostrativi: serve a vedere come funziona.
              </span>
            </div>
          )}
          <datalist id="cert-ports">
            {CERT_PORTS.map((p) => (
              <option key={p.port} value={p.port}>
                {p.label}
              </option>
            ))}
          </datalist>
          <div className="reach-list" role={rows.length ? 'list' : undefined} aria-label={rows.length ? 'Servizi da controllare' : undefined}>
            <AnimatePresence initial={false}>
              {rows.map((r, i) => {
                const c = checks[i];
                const hostErr = touched || r.host ? c.hostError : undefined;
                const portErr = c.portError;
                const hint = hostErr || portErr ? undefined : [c.effective ? `Si controlla ${c.effective}.` : '', c.note ?? ''].filter(Boolean).join(' ');
                const hostDesc = hostErr ? `cert-err-${r.key}` : hint ? `cert-hint-${r.key}` : undefined;
                return (
                  <m.div
                    key={r.key}
                    role="listitem"
                    className="reach-row cert-row"
                    layout="position"
                    initial={{ opacity: 0, y: -6 }}
                    animate={{ opacity: 1, y: 0, transition: { duration: 0.3, ease: ease.out } }}
                    exit={{ opacity: 0, x: 16, transition: { duration: 0.18, ease: ease.inOut } }}
                  >
                    <input
                      className="field"
                      aria-label={`Etichetta del servizio ${i + 1}`}
                      placeholder="Etichetta (facoltativa)"
                      value={r.label}
                      onChange={(e) => update(r.key, { label: e.target.value })}
                    />
                    <input
                      className="field mono"
                      aria-label={`Nome, indirizzo o URL del servizio ${i + 1}`}
                      aria-invalid={!!hostErr}
                      aria-describedby={hostDesc}
                      placeholder="nas.studio.local o https://10.0.0.5:8443"
                      value={r.host}
                      onChange={(e) => update(r.key, { host: e.target.value })}
                      spellCheck={false}
                      autoCapitalize="off"
                      autoCorrect="off"
                    />
                    <input
                      className="field mono port"
                      aria-label={`Porta del servizio ${i + 1} (vuota per 443)`}
                      inputMode="numeric"
                      aria-invalid={!!portErr}
                      aria-describedby={portErr ? `cert-perr-${r.key}` : undefined}
                      list="cert-ports"
                      placeholder="443"
                      value={r.port}
                      onChange={(e) => update(r.key, { port: e.target.value.replace(/[^0-9]/g, '').slice(0, 5) })}
                    />
                    <button className="btn small icon" aria-label={`Rimuovi il servizio ${i + 1}`} title="Rimuovi" onClick={() => setRows(rows.filter((x) => x.key !== r.key))}>
                      <Trash2 size={15} aria-hidden />
                    </button>
                    {hostErr && (
                      <span id={`cert-err-${r.key}`} className="reach-err">
                        {hostErr}
                      </span>
                    )}
                    {portErr && (
                      <span id={`cert-perr-${r.key}`} className="reach-err">
                        {portErr}
                      </span>
                    )}
                    {hint && (
                      <span id={`cert-hint-${r.key}`} className="cert-hint">
                        {hint}
                      </span>
                    )}
                  </m.div>
                );
              })}
            </AnimatePresence>
          </div>
          {!rows.length && (
            <div className="empty" style={{ padding: 20 }}>
              Nessun servizio: aggiungine uno o parti dai suggerimenti.
            </div>
          )}

          <div className="reach-actions">
            <button className="btn small" onClick={() => setRows([...rows, { key: ++seq.current, label: '', host: '', port: '' }])} disabled={rows.length >= CERT_MAX_TARGETS}>
              <Plus size={15} aria-hidden /> Aggiungi servizio
            </button>
            {suggestions.length > 0 && (
              <button className="btn small" onClick={() => setRows([...rows, ...toRows(suggestions)].slice(0, CERT_MAX_TARGETS))} disabled={rows.length >= CERT_MAX_TARGETS}>
                <Lightbulb size={15} aria-hidden /> Aggiungi i suggerimenti ({suggestions.length})
              </button>
            )}
            <span className="spacer" />
            <button className="btn primary" onClick={run} disabled={busy || !rows.length}>
              <Radar size={16} className={busy ? 'spin' : undefined} aria-hidden />
              {busy ? 'Controllo in corso…' : live ? 'Controlla i certificati' : 'Simula il controllo'}
            </button>
          </div>
          <p className="faint" style={{ fontSize: 13, margin: '8px 0 0' }}>
            Suggerimenti: il pannello del router e i servizi delle verifiche che rispondono su una porta cifrata. Il controllo dura qualche secondo per servizio,
            al massimo due minuti.
          </p>
          {touched && invalid && (
            <p className="reach-err" role="alert">
              Completa o correggi i servizi evidenziati.
            </p>
          )}
          {error && (
            <div className="notice alert" role="alert" style={{ marginTop: 12 }}>
              <TriangleAlert size={18} aria-hidden />
              <span>{error}</span>
            </div>
          )}
        </>
      )}

      {certs?.results?.length ? (
        <div style={{ marginTop: 20 }}>
          <h3>
            Esito · {certs.results.length} {certs.results.length === 1 ? 'servizio' : 'servizi'}
            {counts.crit ? ` · ${counts.crit} con problemi` : ''}
            {counts.warn ? ` · ${counts.warn} da sistemare` : ''} · {fmtWhen(certs.checkedAt)}
            {!live && source !== 'file' ? ' · simulazione' : ''}
          </h3>
          <ul className="cert-list">
            {certs.results.map((r, i) => (
              <CertItem key={`${certKey(r)}-${i}`} r={r} />
            ))}
          </ul>
          <p className="faint" style={{ fontSize: 13, marginBottom: 0 }}>
            Attendibilità come la vede Windows su questo PC e per questo utente, con i soli certificati già presenti: il controllo non scarica nulla. Prima di
            rendere attendibile un certificato, confronta l'impronta con quella che ti dà l'amministratore del dispositivo.
          </p>
        </div>
      ) : null}
    </m.section>
  );
}

const fmtWhen = (iso?: string) => {
  if (!iso) return '';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString('it-IT', { dateStyle: 'short', timeStyle: 'short' });
};

function CertItem({ r }: { r: CertResult }) {
  const toast = useToast();
  const sev = certSeverity(r);
  const issues = certIssues(r).filter((x) => x.id !== 'failed');
  const names = [...(r.dnsNames ?? []), ...(r.ips ?? [])];
  const where = certWhere(r);
  const name = r.label || where;
  const copy = async () => {
    if (!r.fingerprint) return;
    try {
      await navigator.clipboard.writeText(fingerprintText(r.fingerprint));
      toast('Impronta copiata negli appunti');
    } catch {
      toast("Copia non riuscita: seleziona l'impronta e usa Ctrl+C", 'error');
    }
  };
  const trust = r.trust ?? '';
  return (
    <li className="cert-item" data-sev={sev}>
      <div className="cert-head">
        <span className="cert-name">
          <strong>{name}</strong>
          <span className="mono faint">
            {r.label ? where : ''}
            {r.ip && r.ip !== r.host ? `${r.label ? ' ' : ''}→ ${r.ip}` : ''}
          </span>
        </span>
        <span className={`sev ${sev}`}>
          <SevIcon sev={sev} size={14} />
          {SEV_TEXT[sev]}
        </span>
      </div>
      {!r.ok ? (
        <p className="cert-fail">
          Controllo non riuscito: {r.error || 'nessun certificato ricevuto'}.{certFailHint(r.error, r.port)}
        </p>
      ) : (
        <>
          {issues.length > 0 && (
            <ul className="cert-notes" aria-label={`Da sapere su ${name}`}>
              {issues.map((x) => (
                <li key={x.id} className={`sev ${x.severity}`}>
                  <SevIcon sev={x.severity} size={13} />
                  <span className="sr-only">{SEV_TEXT[x.severity]}: </span>
                  {x.short}
                </li>
              ))}
            </ul>
          )}
          <dl className="cert-facts">
            <div>
              <dt>Scadenza</dt>
              <dd>
                {certExpiryText(r.daysLeft)}
                {r.notAfter ? `, il ${dateIt(r.notAfter)}` : ''}
                {r.lifetimeDays ? <span className="faint"> · durata {thousands(r.lifetimeDays)} giorni</span> : null}
              </dd>
            </div>
            <div>
              <dt>Emittente</dt>
              <dd>{r.selfSigned ? 'autofirmato (emesso dal servizio stesso)' : [r.issuer, r.issuerOrg && r.issuerOrg !== r.issuer ? r.issuerOrg : ''].filter(Boolean).join(', ') || '—'}</dd>
            </div>
            <div>
              <dt>Nomi</dt>
              <dd className="mono">{names.length ? names.join(', ') : r.subject ? `${r.subject} (solo Common Name)` : '—'}</dd>
            </div>
            <div>
              <dt>Connessione</dt>
              <dd>
                {r.tlsVersion || 'TLS'}
                {r.starttls ? ' dopo STARTTLS' : ''}
                {r.cipher ? <span className="mono faint"> · {r.cipher}</span> : null}
              </dd>
            </div>
            <div>
              <dt>Chiave e firma</dt>
              <dd>
                {[r.keyType && `${r.keyType}${r.keyBits ? ` ${r.keyBits} bit` : ''}`, r.sigAlg].filter(Boolean).join(' · ') || '—'}
              </dd>
            </div>
            <div>
              <dt>Su questo PC</dt>
              <dd>{r.selfSigned && trust === 'trusted' ? 'attendibile (autofirmato, aggiunto ai certificati attendibili di questo PC)' : CERT_TRUST_TEXT[trust] ?? CERT_TRUST_TEXT['']}</dd>
            </div>
            {r.fingerprint && (
              <div className="cert-fp">
                <dt>Impronta SHA-256</dt>
                <dd>
                  <code className="mono">{fingerprintText(r.fingerprint)}</code>
                  <button className="btn small icon" onClick={copy} aria-label={`Copia l'impronta SHA-256 di ${name}`} title="Copia l'impronta">
                    <Copy size={14} aria-hidden />
                  </button>
                </dd>
              </div>
            )}
          </dl>
        </>
      )}
    </li>
  );
}
