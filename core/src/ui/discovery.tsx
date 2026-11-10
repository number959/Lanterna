import { Building2, Cable, ChevronDown, KeyRound, Layers, ListChecks, Network, Radar, Square, TriangleAlert, Wifi } from 'lucide-react';
import { AnimatePresence, m } from 'motion/react';
import { useEffect, useMemo, useRef, useState } from 'react';
import { buildNetworkMap, discoveredNets, netLabel, netsWithoutTargets, parseCidr, segmentationTargets, switchPort } from '../engine';
import type { ADSubnets, DiscoveredNet, InfraData, Inventory, L2Discovery, Scan, SnmpResult } from '../engine';
import { simulatedAD, simulatedL2, simulatedRemoteInventory, simulatedSnmp } from '../demo/discovery';
import { discoverStatus, listenSwitch, readADSubnets, readSnmp, runInventory, stopListen } from './api';
import type { SnmpCreds } from './api';
import type { CertTargetRef } from './certs';
import { Stat, TableWrap, useToast } from './components';
import { ease, rise, spring } from './motion';
import { proposeReach } from './reachbus';
import type { ViewProps } from './views';
import './discovery.css';

// Scheda "Reti e VLAN" della sezione Infrastruttura: le altre reti senza
// doverle scrivere. Quello che il PC sa già (rotte, server DNS e DHCP, reti
// Wi-Fi degli stessi access point) è sempre presente; tre letture partono
// solo su richiesta: l'ascolto passivo degli annunci dello switch, le
// sottoreti di Active Directory e la lettura SNMP in sola lettura con le
// credenziali del tecnico, che non vengono mai salvate. Senza agente le
// letture sono simulate e dichiarate come tali.

const L2_SECONDS = 61;
const MAX_SAVED = 16;

// Le letture continuano anche se si cambia pagina: lo stato vive a livello di
// modulo e le schede che si montano ne seguono l'avanzamento.
interface Jobs {
  l2?: { elapsed: number; seconds: number };
  ad?: boolean;
  snmp?: { target: string; step?: string };
  inv?: { subnet: string; phase: string; done: number; total: number };
}
let jobs: Jobs = {};
const subs = new Set<(j: Jobs) => void>();
const setJobs = (patch: Partial<Jobs>) => {
  jobs = { ...jobs, ...patch };
  subs.forEach((f) => f(jobs));
};
function useJobs(): Jobs {
  const [j, set] = useState(jobs);
  useEffect(() => {
    subs.add(set);
    set(jobs);
    return () => {
      subs.delete(set);
    };
  }, []);
  return j;
}


const L2_READ: Record<string, string> = {
  none: 'Nessun annuncio in un minuto: lo switch non è gestito, oppure LLDP e CDP sono spenti sulle porte degli utenti. Anche un telefono IP o un piccolo switch tra il PC e la presa li fermano.',
  nowired: 'Nessuna scheda cablata collegata: gli annunci dello switch arrivano solo con il cavo.',
  admin: 'Serve Polaris avviato come amministratore: la cattura degli annunci usa un componente di Windows riservato agli amministratori.',
  unsupported: 'La cattura dei pacchetti di Windows non è disponibile su questo sistema.',
};

const AD_READ: Record<string, string> = {
  nodomain: 'Il PC non fa parte di un dominio Active Directory: nessuna sottorete da leggere.',
  unreachable: 'Il controller di dominio non risponde: il PC è fuori dalla rete dell\'organizzazione?',
  denied: 'Accesso negato alla configurazione del dominio.',
};

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
function privateIp(s: string): boolean {
  const m4 = IPV4.exec(s.trim());
  if (!m4 || m4.slice(1).some((x) => Number(x) > 255)) return false;
  const [a, b] = [Number(m4[1]), Number(m4[2])];
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

const speed = (mbps?: number) => (mbps === undefined ? undefined : mbps >= 1000 ? `${String(mbps / 1000).replace('.', ',')} Gb/s` : `${mbps} Mb/s`);

/** Rete su cui si può fare l'inventario attraverso il router: privata, da /22 a /30, non quella del PC. */
function inventoriable(n: DiscoveredNet): boolean {
  const c = parseCidr(n.prefix);
  return !!c && !n.local && !n.contains && c.prefix >= 22 && c.prefix <= 30 && privateIp(n.prefix!.split('/')[0]);
}

export function DiscoveryCard({ scan, live, source, mergeInfra }: ViewProps) {
  const toast = useToast();
  const j = useJobs();
  const disc = scan.infra?.discovery;
  const nets = useMemo(() => discoveredNets(scan), [scan]);
  const sp = useMemo(() => switchPort(scan), [scan]);
  const wifiZones = useMemo(() => buildNetworkMap(scan).segments.filter((s) => s.kind === 'wifi'), [scan]);
  const missing = netsWithoutTargets(nets);
  const [authorized, setAuthorized] = useState(false);
  const [errors, setErrors] = useState<{ l2?: string; ad?: string; snmp?: string; inv?: string }>({});
  const fileOnly = source === 'file';

  // Rete su cui parte una lettura: il risultato si unisce solo al rapporto della stessa rete.
  const targetOf = (): CertTargetRef => ({ live, host: scan.agent.host, gateway: scan.gateway?.ip });
  const merge = (start: CertTargetRef, patch: (i: InfraData) => Partial<InfraData>, what: string): boolean => mergeInfra(patch, start, what);
  const fail = (k: keyof typeof errors, e: unknown) => {
    const msg = e instanceof Error ? e.message : String(e);
    setErrors((x) => ({ ...x, [k]: msg }));
    toast(msg, 'error');
  };

  // ------------------------------------------------ ascolto degli switch
  const startL2 = (resume = false) => {
    if (jobs.l2) return;
    setErrors((x) => ({ ...x, l2: undefined }));
    const start = targetOf();
    setJobs({ l2: { elapsed: 0, seconds: L2_SECONDS } });
    const done = (r: L2Discovery) => {
      // Un ascolto non riuscito non dice nulla della rete: resta l'esito precedente.
      if (r.read === 'admin' || r.read === 'nowired' || r.read === 'unsupported' || r.read === 'error') {
        fail('l2', new Error(r.error ?? L2_READ[r.read] ?? 'Ascolto non riuscito.'));
        return;
      }
      if (merge(start, (i) => ({ discovery: { ...i.discovery, l2: r } }), 'Ascolto dello switch'))
        toast(r.read === 'ok' ? 'Annunci dello switch ricevuti' : 'Ascolto finito', r.read === 'ok' ? 'ok' : undefined, r.read === 'ok' ? 'complete' : undefined);
    };
    const p: Promise<L2Discovery> = live
      ? listenSwitch(L2_SECONDS, (st) => setJobs({ l2: { elapsed: st.elapsed ?? 0, seconds: st.seconds ?? L2_SECONDS } }), { resume })
      : new Promise((ok) => {
          // Simulazione accelerata: un minuto di ascolto in cinque secondi.
          const t0 = performance.now();
          const tick = () => {
            const t = performance.now() - t0;
            if (t >= 5000) return ok(simulatedL2(scan));
            setJobs({ l2: { elapsed: Math.round((L2_SECONDS * t) / 5000), seconds: L2_SECONDS } });
            setTimeout(tick, 200);
          };
          tick();
        });
    p.then(done, (e) => fail('l2', e)).finally(() => setJobs({ l2: undefined }));
  };

  // ----------------------------------------- sottoreti di Active Directory
  const startAD = () => {
    if (jobs.ad) return;
    setErrors((x) => ({ ...x, ad: undefined }));
    const start = targetOf();
    setJobs({ ad: true });
    const p: Promise<ADSubnets> = live ? readADSubnets() : new Promise((ok) => setTimeout(() => ok(simulatedAD(scan)), 900));
    p.then((r) => {
      if (merge(start, (i) => ({ discovery: { ...i.discovery, ad: r } }), 'Lettura di Active Directory') && r.read === 'ok')
        toast(`${r.subnets?.length ?? 0} sottoreti da Active Directory`, 'ok', 'complete');
    }, (e) => fail('ad', e)).finally(() => setJobs({ ad: undefined }));
  };

  // ------------------------------------------------------- lettura SNMP
  const startSnmp = (target: string, creds: SnmpCreds) => {
    if (jobs.snmp) return;
    setErrors((x) => ({ ...x, snmp: undefined }));
    const start = targetOf();
    setJobs({ snmp: { target } });
    const def = creds.version === '2c' && /^(public|private)$/i.test((creds.community ?? '').trim());
    const p: Promise<SnmpResult> = live
      ? readSnmp(target, creds, (st) => setJobs({ snmp: { target, step: st.step } }))
      : new Promise((ok, ko) =>
          setTimeout(() => {
            try {
              ok(simulatedSnmp(scan, target, def));
            } catch (e) {
              ko(e);
            }
          }, 1600),
        );
    p.then((r) => {
      if (merge(start, (i) => ({ discovery: { ...i.discovery, snmp: [r, ...(i.discovery?.snmp ?? []).filter((x) => x.target !== r.target)].slice(0, MAX_SAVED) } }), 'Lettura SNMP'))
        toast(`Lettura SNMP di ${r.system?.name ?? r.target} completata`, 'ok', 'complete');
    }, (e) => fail('snmp', e)).finally(() => setJobs({ snmp: undefined }));
  };

  // --------------------------------- inventario attraverso il router
  const startInv = (subnet: string) => {
    if (jobs.inv) return;
    setErrors((x) => ({ ...x, inv: undefined }));
    const start = targetOf();
    setJobs({ inv: { subnet, phase: 'ping', done: 0, total: 0 } });
    const p: Promise<Inventory> = live
      ? runInventory((st) => setJobs({ inv: { subnet, phase: st.phase ?? 'ping', done: st.done, total: st.total } }), { subnet })
      : new Promise((ok) => {
          const t0 = performance.now();
          const tick = () => {
            const t = performance.now() - t0;
            if (t >= 2600) return ok(simulatedRemoteInventory(scan, subnet));
            setJobs({ inv: { subnet, phase: 'ping', done: Math.round((254 * t) / 2600), total: 254 } });
            setTimeout(tick, 120);
          };
          tick();
        });
    p.then((r) => {
      if (merge(start, (i) => ({ remote: [r, ...(i.remote ?? []).filter((x) => x.subnet !== r.subnet)].slice(0, MAX_SAVED) }), 'Inventario'))
        toast(`Inventario di ${r.subnet} · ${r.hosts.length} ${r.hosts.length === 1 ? 'dispositivo' : 'dispositivi'}`, 'ok', 'complete');
    }, (e) => fail('inv', e)).finally(() => setJobs({ inv: undefined }));
  };

  // Un ascolto o una lettura avviati prima (anche da un'altra finestra) si riprendono.
  useEffect(() => {
    if (!live) return;
    let alive = true;
    discoverStatus<L2Discovery>('l2')
      .then((st) => {
        if (alive && st.running && !jobs.l2) startL2(true);
      })
      .catch(() => undefined);
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [live]);

  const propose = () => {
    const t = segmentationTargets(scan, nets);
    if (!t.length) {
      toast('Nessun dispositivo noto nelle altre reti: fai prima l\'inventario di una rete o la lettura SNMP del router', 'warn');
      return;
    }
    proposeReach(t);
  };

  const others = nets.filter((n) => !n.local);
  const vlans = nets.filter((n) => n.vlan).length;
  const sources = new Set(nets.flatMap((n) => n.sources.map((s) => s.replace(/ \(.*\)$/, '')))).size;

  return (
    <m.section variants={rise} className="card disc-card">
      <div className="card-head">
        <h2 style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
          <Layers size={19} aria-hidden /> Le altre reti, senza doverle scrivere
        </h2>
      </div>
      <p className="muted" style={{ marginTop: 0 }}>
        Polaris unisce ciò che il PC sa già (rotte, server DNS e DHCP, reti Wi-Fi degli stessi access point) con tre letture che partono solo su tua richiesta.
        Nessuna scansione a tappeto: l'inventario di un'altra rete parte solo su tua richiesta, una sottorete alla volta e senza porte. Ogni rete riporta la fonte da cui
        risulta.
      </p>

      {fileOnly ? (
        <div className="notice">
          <TriangleAlert size={18} aria-hidden />
          <span>Rapporto importato: qui si consultano le reti salvate. Ascolto, letture e inventari si eseguono dall'agente, sulla rete del PC.</span>
        </div>
      ) : (
        !live && (
          <div className="notice" style={{ marginBottom: 14 }}>
            <TriangleAlert size={18} aria-hidden />
            <span>
              Senza agente le letture sono <b>simulate</b> sui dati dimostrativi, per vedere come funzionano.
            </span>
          </div>
        )
      )}

      <div className="disc-tools">
        <L2Tool scan={scan} live={live} disabled={fileOnly} job={j.l2} error={errors.l2} onStart={() => startL2()} sp={sp} l2={disc?.l2} />
        <ADTool scan={scan} live={live} disabled={fileOnly} busy={!!j.ad} error={errors.ad} onStart={startAD} ad={disc?.ad} />
        <SnmpTool scan={scan} live={live} disabled={fileOnly} authorized={authorized} job={j.snmp} error={errors.snmp} onStart={startSnmp} results={disc?.snmp ?? []} />
      </div>

      {!fileOnly && (
        <label className="consent disc-consent">
          <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
          <span>
            Sono autorizzato ad analizzare queste reti e a interrogare i loro apparati; per le reti dei dispositivi medicali l'attività è concordata con
            l'ingegneria clinica. Serve per la lettura SNMP e per l'inventario delle altre reti.
          </span>
        </label>
      )}

      <div className="stats" style={{ marginTop: 18 }}>
        <Stat k="Reti note" v={String(nets.length)} />
        <Stat k="VLAN" v={String(vlans)} />
        <Stat k="Fonti" v={String(sources)} />
        <Stat k="Da esplorare" v={String(missing.length)} sev={missing.length ? 'warn' : undefined} />
      </div>

      <NetsTable nets={nets} canInventory={!fileOnly && authorized} job={j.inv} onInventory={startInv} remote={scan.infra?.remote ?? []} />
      {errors.inv && (
        <div className="notice alert" role="alert" style={{ marginTop: 12 }}>
          <TriangleAlert size={18} aria-hidden />
          <span>{errors.inv}</span>
        </div>
      )}

      {wifiZones.length > 0 && (
        <p className="disc-wifi">
          <Wifi size={15} aria-hidden />
          <span>
            Reti Wi-Fi trasmesse dagli stessi access point, di solito VLAN separate:{' '}
            {wifiZones.map((z, i) => (
              <span key={z.id}>
                {i ? ', ' : ''}
                <b>{z.label.replace(/^Wi-Fi «(.*)»$/, '$1')}</b>
              </span>
            ))}
            .
          </span>
        </p>
      )}

      {others.length > 0 && !fileOnly && (
        <div className="disc-propose">
          <button className="btn primary" onClick={propose}>
            <ListChecks size={16} aria-hidden /> Usa nel test di segmentazione
          </button>
          <span className="faint" style={{ fontSize: 13 }}>
            Propone fino a due dispositivi noti per rete, da verificare come "deve essere isolata", e i server DNS come "deve rispondere". Le interfacce dei router
            non si propongono: spesso rispondono anche quando l'isolamento funziona. Rivedi l'elenco prima di avviare.
            {missing.length > 0 &&
              ` Per ${missing.length === 1 ? 'una rete' : `${missing.length} reti`} non si conosce ancora nessun dispositivo: fai l'inventario della rete o la lettura SNMP del router.`}
          </span>
        </div>
      )}
    </m.section>
  );
}

// ---------------------------------------------------------------- strumenti

function Progress({ label, value, max, text }: { label: string; value: number; max: number; text: string }) {
  return (
    <div className="infra-progress">
      <div className="progress live" role="progressbar" aria-label={label} aria-valuemin={0} aria-valuemax={max || 1} aria-valuenow={value}>
        <m.i initial={false} animate={{ scaleX: max ? Math.min(1, value / max) : 0 }} transition={spring.gentle} />
      </div>
      <span className="faint mono" aria-live="polite">
        {text}
      </span>
    </div>
  );
}

function L2Tool({
  scan,
  live,
  disabled,
  job,
  error,
  onStart,
  sp,
  l2,
}: {
  scan: Scan;
  live: boolean;
  disabled: boolean;
  job?: { elapsed: number; seconds: number };
  error?: string;
  onStart: () => void;
  sp: ReturnType<typeof switchPort>;
  l2?: L2Discovery;
}) {
  const wired = scan.adapters.some((a) => a.kind === 'ethernet' && a.up && a.ipv4.length > 0);
  const elevated = scan.agent.elevated;
  const dtp = l2?.read === 'ok' ? l2.dtp?.[0] : undefined;
  const stp = l2?.read === 'ok' ? (l2.stp?.find((s) => s.format === 'ieee') ?? l2.stp?.[0]) : undefined;
  return (
    <div className="disc-tool">
      <h3>
        <Cable size={17} aria-hidden /> Annunci dello switch
      </h3>
      <p className="faint">
        Per circa un minuto Polaris ascolta ciò che lo switch annuncia alla porta del PC (LLDP, CDP, DTP, Spanning Tree): switch, porta, VLAN. Non trasmette nulla.
        Serve il cavo e l'avvio come amministratore.
      </p>
      {live && !disabled && (!wired || elevated === false) && (
        <p className="disc-hint">
          <TriangleAlert size={14} aria-hidden />
          {!wired ? 'Nessuna scheda cablata collegata: collega il cavo prima di ascoltare.' : 'Polaris non è avviato come amministratore: l\'ascolto non potrà partire.'}
        </p>
      )}
      {!disabled && (
        <div className="disc-actions">
          <button className="btn" onClick={onStart} disabled={!!job}>
            <Radar size={16} className={job ? 'spin' : undefined} aria-hidden />
            {job ? 'Ascolto in corso…' : live ? 'Ascolta lo switch' : "Simula l'ascolto"}
          </button>
          {job && live && (
            <button className="btn small" onClick={() => stopListen().catch(() => undefined)}>
              <Square size={13} aria-hidden /> Interrompi
            </button>
          )}
        </div>
      )}
      <AnimatePresence initial={false}>
        {job && (
          <m.div key="p" initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0, transition: { duration: 0.2, ease: ease.inOut } }} style={{ overflow: 'hidden' }}>
            <Progress label="Avanzamento dell'ascolto" value={job.elapsed} max={job.seconds} text={`${Math.min(job.elapsed, job.seconds)} di ${job.seconds} s`} />
          </m.div>
        )}
      </AnimatePresence>
      {error && <p className="disc-error" role="alert">{error}</p>}
      {l2 && l2.read !== 'ok' && <p className="disc-result muted">{l2.error ?? L2_READ[l2.read] ?? 'Ascolto non riuscito.'}</p>}
      {sp && (
        <dl className="disc-dl">
          <dt>Switch</dt>
          <dd>
            <b>{sp.name}</b>
          </dd>
          {sp.model && (
            <>
              <dt>Modello</dt>
              <dd className="faint">{sp.model}</dd>
            </>
          )}
          <dt>Porta</dt>
          <dd className="mono">{sp.port ?? '—'}</dd>
          {sp.vlan !== undefined && (
            <>
              <dt>VLAN della porta</dt>
              <dd>
                {sp.vlan}
                {sp.vlans.find((v) => v.id === sp.vlan)?.name && <span className="faint"> · {sp.vlans.find((v) => v.id === sp.vlan)!.name}</span>}
              </dd>
            </>
          )}
          {sp.voiceVlan !== undefined && (
            <>
              <dt>VLAN della voce</dt>
              <dd>{sp.voiceVlan}</dd>
            </>
          )}
          {(sp.speedMbps || sp.duplex) && (
            <>
              <dt>Collegamento</dt>
              <dd>{[speed(sp.speedMbps), sp.duplex && (sp.duplex === 'full' ? 'full duplex' : 'half duplex')].filter(Boolean).join(', ')}</dd>
            </>
          )}
          {sp.mgmt && (
            <>
              <dt>Gestione</dt>
              <dd className="mono">{sp.mgmt}</dd>
            </>
          )}
          {dtp && (
            <>
              <dt>DTP</dt>
              <dd className={dtp.operStatus === 'trunk' || dtp.adminStatus === 'auto' || dtp.adminStatus === 'desirable' ? 'disc-warn' : undefined}>
                attivo{dtp.adminStatus ? `, modalità ${dtp.adminStatus}` : ''}
                {dtp.operStatus ? `, porta ${dtp.operStatus === 'trunk' ? 'in trunk' : 'di accesso'}` : ''}
              </dd>
            </>
          )}
          {stp && (
            <>
              <dt>Spanning Tree</dt>
              <dd>
                {stp.protocol.toUpperCase()}, radice {stp.rootMac}, priorità {stp.rootPriority}
                {stp.rootPriority === 32768 && <span className="disc-warn"> (predefinita)</span>}
              </dd>
            </>
          )}
          {l2 && l2.counts.eapol > 0 && (
            <>
              <dt>802.1X</dt>
              <dd>la porta chiede l'autenticazione</dd>
            </>
          )}
        </dl>
      )}
    </div>
  );
}

function ADTool({
  scan,
  live,
  disabled,
  busy,
  error,
  onStart,
  ad,
}: {
  scan: Scan;
  live: boolean;
  disabled: boolean;
  busy: boolean;
  error?: string;
  onStart: () => void;
  ad?: ADSubnets;
}) {
  const domain = scan.agent.domain;
  const sites = new Set((ad?.subnets ?? []).map((s) => s.site).filter(Boolean)).size;
  return (
    <div className="disc-tool">
      <h3>
        <Building2 size={17} aria-hidden /> Active Directory
      </h3>
      <p className="faint">Le sottoreti che gli amministratori hanno registrato in Siti e servizi, sede per sede. Solo per i PC in un dominio: una lettura al controller di dominio.</p>
      {!disabled && (
        <div className="disc-actions">
          <button className="btn" onClick={onStart} disabled={busy || !domain}>
            <Network size={16} className={busy ? 'spin' : undefined} aria-hidden />
            {busy ? 'Lettura in corso…' : live ? 'Leggi Active Directory' : 'Simula la lettura'}
          </button>
          {!domain && <span className="faint" style={{ fontSize: 13 }}>Il PC non è in un dominio.</span>}
        </div>
      )}
      {error && <p className="disc-error" role="alert">{error}</p>}
      {ad && ad.read !== 'ok' && <p className="disc-result muted">{ad.error ?? AD_READ[ad.read] ?? 'Lettura non riuscita.'}</p>}
      {ad?.read === 'ok' && (
        <p className="disc-result">
          <b>{ad.subnets?.length ?? 0}</b> {(ad.subnets?.length ?? 0) === 1 ? 'sottorete' : 'sottoreti'}
          {sites ? ` in ${sites} ${sites === 1 ? 'sito' : 'siti'}` : ''}
          {ad.subnets?.length ? `: ${ad.subnets.slice(0, 4).map((s) => s.prefix + (s.site ? ` (${s.site})` : '')).join(', ')}${ad.subnets.length > 4 ? '…' : ''}` : ''}
        </p>
      )}
    </div>
  );
}

const AUTHS = ['SHA256', 'SHA', 'SHA384', 'SHA512', 'SHA224', 'MD5'];

function SnmpTool({
  scan,
  live,
  disabled,
  authorized,
  job,
  error,
  onStart,
  results,
}: {
  scan: Scan;
  live: boolean;
  disabled: boolean;
  authorized: boolean;
  job?: { target: string; step?: string };
  error?: string;
  onStart: (target: string, creds: SnmpCreds) => void;
  results: SnmpResult[];
}) {
  // Indirizzi da proporre: gateway, indirizzi di gestione annunciati dallo switch e dai vicini LLDP letti.
  const suggestions = useMemo(() => {
    const out: string[] = [];
    const add = (ip?: string) => {
      if (ip && privateIp(ip) && out.indexOf(ip) < 0) out.push(ip);
    };
    add(scan.gateway?.ip);
    const l2 = scan.infra?.discovery?.l2;
    for (const n of l2?.lldp ?? []) n.managementAddresses?.forEach(add);
    for (const n of l2?.cdp ?? []) n.managementAddresses?.forEach(add);
    for (const r of results) for (const n of r.lldpNeighbors) add(n.mgmtIp);
    return out.slice(0, 8);
  }, [scan, results]);
  const [target, setTarget] = useState(suggestions[0] ?? '');
  const [version, setVersion] = useState<'3' | '2c'>('3');
  const [community, setCommunity] = useState('');
  const [user, setUser] = useState('');
  const [auth, setAuth] = useState('SHA256');
  const [authPass, setAuthPass] = useState('');
  const [priv, setPriv] = useState('AES');
  const [privPass, setPrivPass] = useState('');
  const [open, setOpen] = useState<string | null>(null);
  const targetRef = useRef(target);
  targetRef.current = target;

  const problem = !privateIp(target)
    ? 'indica l\'indirizzo IPv4 privato del router o dello switch'
    : version === '2c'
      ? !community.trim()
        ? 'scrivi la community'
        : null
      : !user.trim()
        ? 'scrivi l\'utente SNMPv3'
        : auth && authPass.length < 8
          ? 'la password di autenticazione deve avere almeno 8 caratteri'
          : auth && priv && privPass.length < 8
            ? 'la password di cifratura deve avere almeno 8 caratteri'
            : null;
  const submit = () => {
    if (problem || !authorized) return;
    const creds: SnmpCreds =
      version === '2c'
        ? { version, community }
        : { version, user, ...(auth ? { auth, authPass } : {}), ...(auth && priv ? { priv, privPass } : {}) };
    onStart(target.trim(), creds);
  };
  const id = 'snmp-form';
  return (
    <div className="disc-tool">
      <h3>
        <KeyRound size={17} aria-hidden /> SNMP in sola lettura
      </h3>
      <p className="faint">
        Chiedi a un router o a uno switch, con le tue credenziali, VLAN, reti, vicini e tabelle. Una richiesta alla volta, al solo indirizzo indicato. Le credenziali
        non vengono salvate né mostrate nei rapporti.
      </p>
      {!disabled && (
        <form
          className="disc-form"
          id={id}
          autoComplete="off"
          onSubmit={(e) => {
            e.preventDefault();
            submit();
          }}
        >
          <label>
            <span>Indirizzo</span>
            <input className="field mono" list={`${id}-ips`} value={target} onChange={(e) => setTarget(e.target.value)} placeholder="10.0.0.2" spellCheck={false} inputMode="decimal" />
            <datalist id={`${id}-ips`}>
              {suggestions.map((s) => (
                <option key={s} value={s} />
              ))}
            </datalist>
          </label>
          <label>
            <span>Versione</span>
            <select className="field" value={version} onChange={(e) => setVersion(e.target.value as '3' | '2c')}>
              <option value="3">SNMPv3</option>
              <option value="2c">SNMPv2c</option>
            </select>
          </label>
          {version === '2c' ? (
            <label className="wide">
              <span>Community</span>
              <input className="field" type="password" autoComplete="off" value={community} onChange={(e) => setCommunity(e.target.value)} />
            </label>
          ) : (
            <>
              <label className="wide">
                <span>Utente</span>
                <input className="field" type="password" autoComplete="off" value={user} onChange={(e) => setUser(e.target.value)} />
              </label>
              <label>
                <span>Autenticazione</span>
                <select
                  className="field"
                  value={auth}
                  onChange={(e) => {
                    setAuth(e.target.value);
                    // Senza autenticazione SNMPv3 non ammette la cifratura.
                    if (!e.target.value) setPriv('');
                  }}
                >
                  {AUTHS.map((a) => (
                    <option key={a} value={a}>
                      {a === 'SHA' ? 'SHA-1' : a === 'MD5' ? 'MD5 (superato)' : a.replace('SHA', 'SHA-')}
                    </option>
                  ))}
                  <option value="">nessuna</option>
                </select>
              </label>
              {auth && (
                <label>
                  <span>Password di autenticazione</span>
                  <input className="field" type="password" autoComplete="off" value={authPass} onChange={(e) => setAuthPass(e.target.value)} />
                </label>
              )}
              <label>
                <span>Cifratura</span>
                <select className="field" value={priv} onChange={(e) => setPriv(e.target.value)} disabled={!auth}>
                  <option value="AES">AES-128</option>
                  <option value="DES">DES (superato)</option>
                  <option value="">nessuna</option>
                </select>
              </label>
              {auth && priv && (
                <label>
                  <span>Password di cifratura</span>
                  <input className="field" type="password" autoComplete="off" value={privPass} onChange={(e) => setPrivPass(e.target.value)} />
                </label>
              )}
            </>
          )}
          <div className="disc-actions wide">
            <button className="btn" type="submit" disabled={!!job || !!problem || !authorized}>
              <KeyRound size={16} className={job ? 'spin' : undefined} aria-hidden />
              {job ? 'Lettura in corso…' : live ? 'Leggi via SNMP' : 'Simula la lettura'}
            </button>
            <span className="faint" style={{ fontSize: 13 }} aria-live="polite">
              {job ? `${job.target}${job.step ? ` · ${job.step}` : ''}` : !authorized ? 'Conferma l\'autorizzazione qui sotto.' : (problem ?? '')}
            </span>
          </div>
        </form>
      )}
      {error && <p className="disc-error" role="alert">{error}</p>}
      {results.length > 0 && (
        <ul className="disc-snmp">
          {results.map((r) => {
            const nets = r.interfaces.reduce((t, i) => t + i.ips.length, 0);
            const isOpen = open === r.target;
            return (
              <li key={r.target}>
                <button className="disc-snmp-head" aria-expanded={isOpen} onClick={() => setOpen(isOpen ? null : r.target)}>
                  <span>
                    <b>{r.system?.name ?? r.target}</b> <span className="mono faint">{r.target}</span>
                  </span>
                  <span className={`disc-chip ${r.defaultCommunity ? 'crit' : r.version === '2c' || r.warnings?.length ? 'warn' : 'ok'}`}>SNMPv{r.version}</span>
                  <span className="faint">
                    {r.vlans.length} VLAN · {nets} {nets === 1 ? 'rete' : 'reti'} · {r.lldpNeighbors.length} {r.lldpNeighbors.length === 1 ? 'vicino' : 'vicini'}
                  </span>
                  <ChevronDown size={15} aria-hidden className={isOpen ? 'flip' : undefined} />
                </button>
                {isOpen && <SnmpDetails r={r} />}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

const STATE_TEXT: Record<string, string> = { ok: 'letta', partial: 'letta in parte', absent: 'non gestita', error: 'errore', skipped: 'non letta', '': '—' };

function SnmpDetails({ r }: { r: SnmpResult }) {
  const sections: [string, SnmpResult['sections']['system']][] = [
    ['Dati del dispositivo', r.sections.system],
    ['Interfacce', r.sections.interfaces],
    ['VLAN', r.sections.vlans],
    ['Vicini LLDP', r.sections.lldp],
    ['Tabella ARP', r.sections.arp],
    ['MAC per porta', r.sections.fdb],
  ];
  return (
    <div className="disc-snmp-body">
      {r.system?.descr && <p className="faint">{r.system.descr}</p>}
      {r.defaultCommunity && <p className="disc-warn">Il dispositivo accetta una community predefinita: chiunque nella rete può leggerne la configurazione.</p>}
      {r.warnings?.map((w) => (
        <p key={w} className="disc-warn">
          {w}
        </p>
      ))}
      {r.vlans.length > 0 && (
        <p>
          <b>VLAN:</b> {r.vlans.map((v) => `${v.id}${v.name ? ` ${v.name}` : ''}`).join(', ')}
        </p>
      )}
      {r.interfaces.some((i) => i.ips.length) && (
        <p>
          <b>Reti:</b>{' '}
          {r.interfaces
            .flatMap((i) => i.ips.map((ip) => `${ip.subnet ?? ip.ip}${i.vlanId ? ` (VLAN ${i.vlanId})` : ''}`))
            .join(', ')}
        </p>
      )}
      {r.lldpNeighbors.length > 0 && (
        <p>
          <b>Vicini LLDP:</b> {r.lldpNeighbors.map((n) => `${n.localPort ?? n.localPortNum} → ${n.sysName ?? n.chassisId ?? '?'}${n.mgmtIp ? ` (${n.mgmtIp})` : ''}`).join('; ')}
        </p>
      )}
      <p className="faint">
        Tabella ARP: {r.arp.length} righe · MAC per porta: {r.fdb.length} righe · {r.requests} richieste in {String(Math.round(r.durationMs / 100) / 10).replace('.', ',')} s
      </p>
      <ul className="disc-sections">
        {sections.map(([k, st]) => (
          <li key={k}>
            <span>{k}</span>
            <span className={`faint${st.state === 'error' ? ' disc-warn' : ''}`}>
              {STATE_TEXT[st.state] ?? st.state}
              {st.note ? ` · ${st.note}` : ''}
            </span>
          </li>
        ))}
      </ul>
      {r.stopped && <p className="disc-warn">Lettura fermata prima della fine: {r.stopped}</p>}
    </div>
  );
}

// ---------------------------------------------------------------- elenco delle reti

function NetsTable({
  nets,
  canInventory,
  job,
  onInventory,
  remote,
}: {
  nets: DiscoveredNet[];
  canInventory: boolean;
  job?: { subnet: string; phase: string; done: number; total: number };
  onInventory: (subnet: string) => void;
  remote: Inventory[];
}) {
  return (
    <TableWrap label="Reti note">
      <table className="disc-table">
        <thead>
          <tr>
            <th>Rete</th>
            <th>Indirizzi</th>
            <th>Fonti</th>
            <th>Dispositivi noti</th>
            <th>
              <span className="sr-only">Azioni</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {nets.map((n) => {
            const inv = n.prefix ? remote.find((r) => r.subnet === n.prefix) : undefined;
            const running = job && job.subnet === n.prefix;
            return (
              <tr key={n.key} className={n.local ? 'mine' : ''}>
                <td>
                  <b>{n.vlan || n.name ? netLabel(n) : n.prefix}</b>
                  <span className="disc-badges">
                    {n.local && <span className="disc-chip ok">questo PC</span>}
                    {n.voice && <span className="disc-chip">voce</span>}
                    {n.site && <span className="disc-chip">sito {n.site}</span>}
                    {n.guessed && <span className="disc-chip">/24 presunta</span>}
                    {!!n.contains && <span className="disc-chip">comprende {n.contains} reti</span>}
                  </span>
                </td>
                <td className="mono">{n.prefix ?? <span className="faint">sottorete non nota</span>}</td>
                <td className="faint wrap">{n.sources.join(', ')}</td>
                <td className="wrap">
                  {n.hosts.length || n.servers.length ? (
                    <>
                      {n.hosts.length > 0 && `${n.hosts.length} ${n.hosts.length === 1 ? 'dispositivo' : 'dispositivi'}`}
                      {n.servers.length > 0 && `${n.hosts.length ? ' · ' : ''}${n.servers.length} server`}
                      {n.routers.length > 0 && <span className="faint"> · router {n.routers.slice(0, 2).join(', ')}</span>}
                    </>
                  ) : n.routers.length ? (
                    <span className="faint">router {n.routers.slice(0, 2).join(', ')}</span>
                  ) : (
                    <span className="faint">—</span>
                  )}
                  {inv && <span className="faint"> · inventario: {inv.hosts.length} rispondono</span>}
                </td>
                <td>
                  {inventoriable(n) &&
                    (running ? (
                      <span className="faint mono" aria-live="polite">
                        {job!.done}/{job!.total || '…'}
                      </span>
                    ) : (
                      <button
                        className="btn small"
                        onClick={() => onInventory(n.prefix!)}
                        disabled={!canInventory || !!job}
                        title={canInventory ? `Inventario di ${n.prefix} attraverso il router` : 'Conferma prima l\'autorizzazione'}
                      >
                        <Radar size={14} aria-hidden /> {inv ? 'Ripeti' : 'Inventario'}
                      </button>
                    ))}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </TableWrap>
  );
}
