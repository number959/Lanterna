import {
  ArrowRight,
  BookOpen,
  BookOpenText,
  ExternalLink,
  Globe,
  ListChecks,
  Network,
  Pause,
  Play,
  RotateCcw,
  Router,
  Shield,
  TriangleAlert,
  Wifi,
  type LucideIcon,
} from 'lucide-react';
import { AnimatePresence, m, useReducedMotion } from 'motion/react';
import { useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { phyLabel, primaryAdapter } from '../engine';
import type { Analysis, Band, Bss, Category, Scan, Severity } from '../engine';
import { ping } from './api';
import { ChannelLoad, HBars, LatencyChart, LiveChart, SpectrumChart } from './charts';
import { HexGauge } from './brand';
import { guidesForAction } from '../guides';
import { AnimatedNumber, FindingList, Segmented, SevBadge, SevIcon, Stat, TableWrap, fmtNum, sevColor, spotHandlers, useOpenGuide } from './components';
import { useFx } from './fx';
import { useLocalState } from './hooks';
import { cascade, ease, rise, spring } from './motion';

export type View = 'overview' | 'wifi' | 'lan' | 'internet' | 'router' | 'plan' | 'monitor' | 'guide';

export interface ViewProps {
  scan: Scan;
  analysis: Analysis;
  go: (v: View, focus?: string) => void;
  focus?: string;
  live: boolean;
}

const byCat = (a: Analysis, ...cats: Category[]) => a.findings.filter((f) => cats.includes(f.category));
const CAT_VIEW: Record<Category, View> = { wifi: 'wifi', lan: 'lan', internet: 'internet', dns: 'internet', router: 'router', security: 'router' };
const CAT_ICON: Record<Category, LucideIcon> = { wifi: Wifi, lan: Network, internet: Globe, dns: Globe, router: Router, security: Shield };
const fmtMs = (v?: number) => (v === undefined ? '—' : v < 1 ? '<1 ms' : `${fmtNum(v, v < 10 ? 1 : 0)} ms`);
const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <m.section variants={rise}>
      <h2 className="section-title">{title}</h2>
      {children}
    </m.section>
  );
}

// ---------------------------------------------------------------- Panoramica

/** Titolo che si "accende" parola per parola (il testo completo resta leggibile dagli screen reader). */
function Headline({ text }: { text: string }) {
  const { lite } = useFx();
  const words = text.split(' ');
  return (
    <p className="headline">
      <span className="sr-only">{text}</span>
      <m.span aria-hidden initial="hidden" animate="show" variants={cascade(0.022, 0.25)}>
        {words.map((w, i) => (
          <m.span
            key={i}
            className="w"
            variants={{
              // Con la grafica leggera niente sfocatura: un filtro per parola costa molto senza GPU.
              hidden: lite ? { opacity: 0, y: 8 } : { opacity: 0, y: 8, filter: 'blur(3px)' },
              show: lite
                ? { opacity: 1, y: 0, transition: { duration: 0.5, ease: ease.out } }
                : { opacity: 1, y: 0, filter: 'blur(0px)', transition: { duration: 0.5, ease: ease.out } },
            }}
          >
            {i < words.length - 1 ? `${w} ` : w}
          </m.span>
        ))}
      </m.span>
    </p>
  );
}

const scoreSev = (s: number): Severity => (s >= 85 ? 'ok' : s >= 70 ? 'info' : s >= 50 ? 'warn' : 'crit');

export function Overview({ scan, analysis: a, go }: ViewProps) {
  const reduce = useReducedMotion();
  const top = a.findings.filter((f) => f.severity === 'crit' || f.severity === 'warn').slice(0, 5);
  const n = (s: Severity) => a.findings.filter((f) => f.severity === s).length;
  const sev = scoreSev(a.score);
  return (
    <>
      <m.section variants={rise} className="card hero" style={{ ['--hero-tint' as string]: sevColor(sev) }}>
        <HexGauge score={a.score} />
        <div>
          <div className={`grade c-${sev}`}>
            <SevIcon sev={sev} size={15} /> Salute della rete: {a.grade}
          </div>
          <Headline text={a.headline} />
          <div className="hero-counts">
            {n('crit') > 0 && <span className="sev crit"><SevIcon sev="crit" size={14} />{plural(n('crit'), 'critico', 'critici')}</span>}
            {n('warn') > 0 && <span className="sev warn"><SevIcon sev="warn" size={14} />{plural(n('warn'), 'avviso', 'avvisi')}</span>}
            <span className="sev ok"><SevIcon sev="ok" size={14} />{plural(n('ok'), 'valore ok', 'valori ok')}</span>
          </div>
          <div className="hero-actions">
            {a.plan.length > 0 && (
              <button className="btn primary" onClick={() => go('plan')}>
                <ListChecks size={17} aria-hidden /> Vedi il piano d'azione ({a.plan.length})
              </button>
            )}
            <button className="btn" onClick={() => go('guide', 'tab:misure')}>
              <BookOpen size={17} aria-hidden /> Come leggere i valori
            </button>
          </div>
        </div>
      </m.section>

      <Section title="Aree analizzate">
        <m.div className="tiles" variants={cascade(0.05)}>
          {a.categories.map((c, i) => {
            const I = CAT_ICON[c.category];
            return (
              <m.button
                key={c.category}
                className="tile spot"
                variants={rise}
                whileHover={reduce ? undefined : { y: -4 }}
                whileTap={{ scale: 0.98 }}
                transition={spring.snappy}
                onClick={() => go(CAT_VIEW[c.category])}
                aria-label={`${c.label}: ${c.score ?? 'non misurato'}${c.score === null ? '' : ' su 100'}`}
                {...spotHandlers()}
              >
                <span className="t-label">
                  <I size={16} aria-hidden /> {c.label}
                  <span className={`end c-${c.worst}`}><SevIcon sev={c.worst} size={16} /></span>
                </span>
                <span className="t-score">{c.score === null ? '—' : <AnimatedNumber value={c.score} />}</span>
                <span className="meter">
                  <m.i
                    style={{ background: sevColor(c.worst === 'unknown' ? 'unknown' : c.worst) }}
                    initial={{ scaleX: 0 }}
                    animate={{ scaleX: (c.score ?? 0) / 100 }}
                    transition={{ ...spring.gentle, delay: reduce ? 0 : 0.35 + i * 0.06 }}
                  />
                </span>
                <span className="t-foot">
                  {c.score === null
                    ? 'non misurato'
                    : [c.counts.crit && plural(c.counts.crit, 'critico', 'critici'), c.counts.warn && plural(c.counts.warn, 'avviso', 'avvisi')]
                        .filter(Boolean)
                        .join(' · ') || 'tutto ok'}
                </span>
              </m.button>
            );
          })}
        </m.div>
      </Section>

      {top.length > 0 && (
        <Section title="Problemi principali">
          <FindingList findings={top} onAction={(id) => go('plan', id)} />
        </Section>
      )}

      {a.plan.length > 0 && (
        <Section title="Da dove cominciare">
          <m.div className="steps-grid" variants={cascade(0.06)}>
            {a.plan.slice(0, 3).map((p, i) => (
              <m.button
                key={p.action.id}
                className="tile spot step-card"
                variants={rise}
                whileHover={reduce ? undefined : { y: -4 }}
                whileTap={{ scale: 0.98 }}
                transition={spring.snappy}
                onClick={() => go('plan', p.action.id)}
                {...spotHandlers()}
              >
                <span className="t-label">
                  <span className="n">0{i + 1}</span>
                  <span className={`end c-${p.severity}`}><SevIcon sev={p.severity} size={16} /></span>
                </span>
                <span className="title">{p.action.title}</span>
                <span className="t-foot" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  Impatto {p.action.impact} · difficoltà {p.action.effort}
                  <ArrowRight size={14} style={{ marginLeft: 'auto' }} aria-hidden />
                </span>
              </m.button>
            ))}
          </m.div>
        </Section>
      )}

      {scan.errors.length > 0 && (
        <Section title="Misure non riuscite">
          <div className="notice">
            <TriangleAlert size={18} aria-hidden />
            <ul style={{ margin: 0, paddingLeft: 18 }}>
              {scan.errors.map((e, i) => (
                <li key={i}><b>{e.probe}</b>: {e.message}</li>
              ))}
            </ul>
          </div>
        </Section>
      )}
    </>
  );
}

// ---------------------------------------------------------------- Wi-Fi

type SortKey = 'ssid' | 'rssiDbm' | 'channel' | 'band' | 'widthMhz';

function NetworksTable({ nets, mySsid }: { nets: Bss[]; mySsid?: string }) {
  const [sort, setSort] = useState<{ k: SortKey; dir: 1 | -1 }>({ k: 'rssiDbm', dir: -1 });
  const rows = [...nets].sort((a, b) => {
    const va = a[sort.k] as string | number;
    const vb = b[sort.k] as string | number;
    return (va < vb ? -1 : va > vb ? 1 : 0) * sort.dir;
  });
  const th = (k: SortKey, label: string) => (
    <th aria-sort={sort.k === k ? (sort.dir === 1 ? 'ascending' : 'descending') : 'none'}>
      <button onClick={() => setSort({ k, dir: sort.k === k ? ((-sort.dir) as 1 | -1) : k === 'ssid' ? 1 : -1 })}>
        {label}
        <m.span animate={{ opacity: sort.k === k ? 1 : 0, rotate: sort.dir === 1 ? 180 : 0 }} transition={spring.snappy} style={{ display: 'inline-block' }} aria-hidden>
          ▼
        </m.span>
      </button>
    </th>
  );
  const secSev = (b: Bss): Severity => {
    const p = b.security?.protocol;
    if (!p || p === 'unknown') return 'unknown';
    if (p === 'open' || p === 'wep' || p === 'wpa') return 'crit';
    if (b.security?.pairwise.includes('TKIP')) return 'warn';
    return 'ok';
  };
  const sigSev = (r: number): Severity => (r >= -67 ? 'ok' : r >= -75 ? 'warn' : 'crit');
  return (
    <TableWrap label="Reti Wi-Fi visibili">
      <table>
        <thead>
          <tr>
            {th('ssid', 'Rete')}
            {th('rssiDbm', 'Segnale')}
            {th('band', 'Banda')}
            {th('channel', 'Canale')}
            {th('widthMhz', 'Larghezza')}
            <th>Standard</th>
            <th>Sicurezza</th>
            <th>Carico</th>
            <th>BSSID</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((b) => (
            <tr key={b.bssid} className={b.ssid === mySsid ? 'mine' : ''}>
              <td style={{ fontWeight: b.ssid === mySsid ? 650 : 400 }}>
                {b.ssid || <span className="faint">(nascosta)</span>} {b.connected && <span className="tag accent">collegato</span>}
              </td>
              <td className={`mono c-${sigSev(b.rssiDbm)}`}>{b.rssiDbm} dBm</td>
              <td>{b.band.replace('.', ',')} GHz</td>
              <td className="mono">{b.channel}</td>
              <td className="mono">{b.widthMhz ? `${b.widthMhz} MHz` : '—'}</td>
              <td>{phyLabel(b.phy, b.band)}</td>
              <td className={`c-${secSev(b)}`}>
                {b.security ? `${b.security.protocol.toUpperCase()}${b.security.pairwise.includes('TKIP') ? ' (TKIP)' : ''}${b.security.wps ? ' · WPS' : ''}` : '—'}
              </td>
              <td className="mono">{b.bssLoad ? `${b.bssLoad.utilizationPct} % · ${b.bssLoad.stations} disp.` : '—'}</td>
              <td className="mono faint">{b.bssid}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </TableWrap>
  );
}

/** Dove cade il segnale tra -95 e -30 dBm, con le fasce critica/debole/buona. */
function SignalMeter({ rssi }: { rssi: number }) {
  const pct = Math.max(0, Math.min(100, ((rssi + 95) / 65) * 100));
  return (
    <div className="signal-meter" aria-hidden="true">
      <div className="signal-track">
        <m.div className="signal-marker" initial={{ left: '0%' }} animate={{ left: `${pct}%` }} transition={{ ...spring.gentle, delay: 0.3 }} />
      </div>
      <div className="signal-scale">
        {[-95, -75, -67, -50, -30].map((d) => (
          <span key={d} style={{ left: `${((d + 95) / 65) * 100}%` }}>{d === -30 ? '-30 dBm' : d}</span>
        ))}
      </div>
    </div>
  );
}

export function WifiView({ scan, analysis: a, go }: ViewProps) {
  const wifi = scan.wifi;
  const conn = wifi?.connected;
  const me = wifi?.networks.find((b) => b.connected) ?? wifi?.networks.find((b) => b.bssid === conn?.bssid);
  const bands = (['2.4', '5', '6'] as Band[]).filter((b) => wifi?.networks.some((n) => n.band === b));
  const [band, setBand] = useState<Band>(me?.band ?? bands[0] ?? '2.4');
  const advice = a.channels.find((c) => c.band === band);
  const f = (id: string) => a.findings.find((x) => x.id === id);
  if (!wifi) return <m.div variants={rise} className="empty">Questa sonda non ha raccolto dati Wi-Fi.</m.div>;
  const rssi = f('wifi.rssi')?.numeric;
  return (
    <>
      {conn ? (
        <m.section variants={rise} className="card">
          <div className="card-head">
            <h2>Connessione attuale: {conn.ssid}</h2>
            <span className="sub mono">{conn.bssid}</span>
          </div>
          <div className="stats">
            <Stat k="Segnale" v={f('wifi.rssi')?.value ?? '—'} sev={f('wifi.rssi')?.severity} />
            <Stat k="Qualità (Windows)" v={conn.signalQuality !== undefined ? `${conn.signalQuality} %` : '—'} />
            <Stat k="Velocità radio" v={f('wifi.linkrate')?.value ?? '—'} sev={f('wifi.linkrate')?.severity} />
            <Stat k="Banda / canale" v={f('wifi.band')?.value ?? '—'} sev={f('wifi.band')?.severity} />
            <Stat k="Larghezza" v={f('wifi.width')?.value ?? '—'} sev={f('wifi.width')?.severity} />
            <Stat k="Standard" v={phyLabel(conn.phy, me?.band ?? conn.band)} sev={f('wifi.phy')?.severity} />
          </div>
          {rssi !== undefined && <SignalMeter rssi={rssi} />}
        </m.section>
      ) : (
        <m.div variants={rise} className="notice">
          <Wifi size={18} aria-hidden />
          {wifi.error ? `Wi-Fi non disponibile: ${wifi.error}` : 'Il dispositivo non è collegato a una rete Wi-Fi.'}
        </m.div>
      )}

      {bands.length > 0 && (
        <m.section variants={rise} className="card" style={{ marginTop: 16 }}>
          <div className="card-head">
            <h2>Spettro radio</h2>
            <span className="sub">ogni curva è una rete: larga quanto il suo canale, alta quanto il suo segnale</span>
            <span className="spacer" />
            <Segmented label="Banda" value={band} onChange={setBand} options={bands.map((b) => ({ id: b, label: `${b.replace('.', ',')} GHz` }))} />
          </div>
          <AnimatePresence mode="wait" initial={false}>
            <m.div
              key={band}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0, transition: { duration: 0.35, ease: ease.out } }}
              exit={{ opacity: 0, y: -6, transition: { duration: 0.15 } }}
            >
              <SpectrumChart networks={wifi.networks} band={band} mySsid={conn?.ssid} />
              {advice && (
                <div style={{ marginTop: 18 }}>
                  <h3>Interferenza stimata per {band === '5' ? 'blocco da 80 MHz' : 'canale'}</h3>
                  {advice.scores.length > 0 && <ChannelLoad advice={advice} />}
                  <p className="notice" style={{ marginTop: 10, marginBottom: 0 }}>
                    <span>
                      {advice.recommended !== undefined && advice.recommended !== advice.current ? <b>Canale consigliato: {advice.recommended}. </b> : null}
                      {advice.note}
                    </span>
                  </p>
                </div>
              )}
            </m.div>
          </AnimatePresence>
        </m.section>
      )}

      <Section title="Valutazione">
        <FindingList findings={a.findings.filter((x) => x.id.startsWith('wifi.'))} onAction={(id) => go('plan', id)} />
      </Section>

      <Section title={`Reti visibili (${wifi.networks.length})`}>
        <NetworksTable nets={wifi.networks} mySsid={conn?.ssid} />
      </Section>
    </>
  );
}

// ---------------------------------------------------------------- LAN

export function LanView({ scan, analysis: a, go }: ViewProps) {
  const primary = primaryAdapter(scan);
  const g = scan.gateway;
  return (
    <>
      <m.div className="grid cols-2" variants={cascade(0.06)}>
        <m.section variants={rise} className="card">
          <div className="card-head"><h2>Scheda in uso</h2></div>
          {primary ? (
            <dl className="kv">
              <dt>Nome</dt><dd>{primary.name}</dd>
              {primary.description && primary.description !== primary.name && (<><dt>Hardware</dt><dd>{primary.description}</dd></>)}
              <dt>Tipo</dt><dd>{{ wifi: 'Wi-Fi', ethernet: 'Ethernet (cavo)', other: 'altro', virtual: 'virtuale', loopback: 'loopback' }[primary.kind]}</dd>
              <dt>IPv4</dt><dd>{primary.ipv4.join(', ') || '—'}</dd>
              <dt>IPv6</dt><dd>{primary.ipv6.join(', ') || '—'}</dd>
              <dt>Gateway</dt><dd>{primary.gateways.join(', ') || '—'}</dd>
              <dt>DNS</dt><dd>{primary.dns.join(', ') || '—'}</dd>
              <dt>DHCP</dt><dd>{primary.dhcp === undefined ? '—' : primary.dhcp ? 'sì' : 'no (statico)'}</dd>
              <dt>MAC</dt><dd>{primary.mac ?? '—'}</dd>
              {primary.mtu ? (<><dt>MTU</dt><dd>{primary.mtu}</dd></>) : null}
              {primary.linkMbps ? (<><dt>Velocità link</dt><dd>{primary.linkMbps} Mbit/s</dd></>) : null}
            </dl>
          ) : (
            <p className="muted">Nessuna scheda attiva.</p>
          )}
        </m.section>
        <m.section variants={rise} className="card">
          <div className="card-head"><h2>Tratto PC → router</h2></div>
          {g?.ping && g.ping.received > 0 ? (
            <>
              <div className="stats" style={{ marginBottom: 12 }}>
                <Stat k="Media" v={fmtMs(g.ping.avgMs)} sev={a.findings.find((f) => f.id === 'lan.gwlatency')?.severity} />
                <Stat k="Min / max" v={`${fmtMs(g.ping.minMs)} / ${fmtMs(g.ping.maxMs)}`} />
                <Stat k="Jitter" v={fmtMs(g.ping.jitterMs)} sev={a.findings.find((f) => f.id === 'lan.jitter')?.severity} />
                <Stat k="Persi" v={`${g.ping.sent - g.ping.received}/${g.ping.sent}`} sev={a.findings.find((f) => f.id === 'lan.gwloss')?.severity} />
              </div>
              {g.ping.samples && <LatencyChart series={[{ label: 'Router', color: 'var(--accent)', samples: g.ping.samples }]} />}
            </>
          ) : (
            <p className="muted">{g ? 'Il router non ha risposto alle misure dirette.' : 'Nessun gateway misurato.'}</p>
          )}
        </m.section>
      </m.div>

      <Section title="Valutazione">
        <FindingList findings={byCat(a, 'lan')} onAction={(id) => go('plan', id)} />
      </Section>

      <Section title="Tutte le schede di rete">
        <TableWrap label="Schede di rete">
          <table>
            <thead><tr><th>Nome</th><th>Tipo</th><th>Stato</th><th>IPv4</th><th>Gateway</th><th>Velocità</th><th>MAC</th></tr></thead>
            <tbody>
              {scan.adapters.map((ad) => (
                <tr key={ad.name} className={ad === primary ? 'mine' : ''}>
                  <td title={ad.description}>{ad.name}</td>
                  <td>{ad.kind}</td>
                  <td className={ad.up ? 'c-ok' : 'faint'}>{ad.up ? 'attiva' : 'scollegata'}</td>
                  <td className="mono">{ad.ipv4.join(', ') || '—'}</td>
                  <td className="mono">{ad.gateways.join(', ') || '—'}</td>
                  <td className="mono">{ad.linkMbps ? `${ad.linkMbps} Mbit/s` : '—'}</td>
                  <td className="mono faint">{ad.mac ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      </Section>

      {scan.lan && scan.lan.neighbors.length > 0 && (
        <Section title={`Dispositivi visti di recente (${scan.lan.neighbors.length})`}>
          <TableWrap label="Dispositivi visti di recente">
            <table>
              <thead><tr><th>Indirizzo IP</th><th>MAC</th><th>Note</th></tr></thead>
              <tbody>
                {scan.lan.neighbors.map((n) => (
                  <tr key={n.ip}>
                    <td className="mono">{n.ip}</td>
                    <td className="mono">{n.mac ?? '—'}</td>
                    <td className="faint">
                      {n.ip === g?.ip ? 'router' : n.mac && /^.[26ae]/i.test(n.mac) ? 'MAC casuale (privacy): telefono o PC moderno' : ''}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        </Section>
      )}
    </>
  );
}

// ---------------------------------------------------------------- Internet

// Serie dei grafici: il ciano del marchio per la prima, poi tinte ben distinte e adatte a entrambi i temi.
const SERIES_COLORS = ['var(--accent)', 'var(--signal)', 'var(--p1)', 'var(--p4)'];

export function InternetView({ scan, analysis: a, go }: ViewProps) {
  const reduce = useReducedMotion();
  const net = scan.internet;
  const dns = scan.dns;
  const maxRtt = Math.max(1, ...(net?.traceroute ?? []).map((h) => h.rttMs ?? 0));
  return (
    <>
      {net && net.targets.length > 0 && (
        <m.section variants={rise} className="card">
          <div className="card-head"><h2>Latenza verso Internet</h2></div>
          <div className="stats" style={{ marginBottom: 14 }}>
            {net.targets.map((t) => (
              <Stat key={t.target} k={`${t.label ?? t.target} (${t.target})${t.method === 'tcp' ? ' · TCP' : ''}`}>
                {t.received ? (
                  <>
                    {t.avgMs !== undefined && t.avgMs >= 1 ? <AnimatedNumber value={t.avgMs} decimals={t.avgMs < 10 ? 1 : 0} suffix=" ms" /> : fmtMs(t.avgMs)}
                    <span className="sub">
                      {t.sent - t.received} {t.sent - t.received === 1 ? 'perso' : 'persi'} su {t.sent}
                    </span>
                  </>
                ) : (
                  'nessuna risposta'
                )}
              </Stat>
            ))}
          </div>
          <LatencyChart series={net.targets.filter((t) => t.samples).map((t, i) => ({ label: t.label ?? t.target, color: SERIES_COLORS[i % 4], samples: t.samples! }))} />
          <div className="legend">
            {net.targets.map((t, i) => (<span key={t.target}><i style={{ background: SERIES_COLORS[i % 4] }} />{t.label ?? t.target}</span>))}
            <span><i style={{ background: 'var(--crit)', borderRadius: '50%' }} />pacchetto perso</span>
          </div>
        </m.section>
      )}

      <m.div className="grid cols-2" style={{ marginTop: 16 }} variants={cascade(0.06)}>
        {net?.traceroute && (
          <m.section variants={rise} className="card">
            <div className="card-head">
              <h2>Percorso verso {net.traceTarget ?? 'Internet'}</h2>
              <span className="sub">ogni riga è un router attraversato; il primo è il tuo</span>
            </div>
            <div className="hops">
              {net.traceroute.map((h, i) => (
                <div className="hop" key={h.ttl}>
                  <span className="n">{h.ttl}</span>
                  <span className="mono" style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{h.ip ?? <span className="faint">* nessuna risposta</span>}</span>
                  <span className="bar">
                    {h.rttMs !== undefined && (
                      <m.i
                        initial={{ scaleX: reduce ? h.rttMs / maxRtt : 0 }}
                        animate={{ scaleX: h.rttMs / maxRtt }}
                        transition={{ ...spring.gentle, delay: reduce ? 0 : 0.2 + i * 0.08 }}
                      />
                    )}
                  </span>
                  <span className="mono" style={{ textAlign: 'right' }}>{h.rttMs !== undefined ? fmtMs(h.rttMs) : '—'}</span>
                </div>
              ))}
            </div>
          </m.section>
        )}
        {dns && (
          <m.section variants={rise} className="card">
            <div className="card-head">
              <h2>DNS: tempo per tradurre un nome</h2>
              <span className="sub">in evidenza il DNS in uso; più corto è meglio</span>
            </div>
            <HBars
              items={[
                ...dns.system.map((s) => ({ label: `${s.label ?? s.server} (in uso)`, value: s.ok ? s.timeMs ?? null : null, highlight: true, note: s.error })),
                ...dns.public.map((s) => ({ label: `${s.label ?? s.server} ${s.server}`, value: s.ok ? s.timeMs ?? null : null, note: s.error })),
              ]}
            />
          </m.section>
        )}
      </m.div>

      <Section title="Valutazione">
        <FindingList findings={byCat(a, 'internet', 'dns')} onAction={(id) => go('plan', id)} />
      </Section>
    </>
  );
}

// ---------------------------------------------------------------- Router e sicurezza

export function RouterView({ scan, analysis: a, go }: ViewProps) {
  const g = scan.gateway;
  const igd = g?.upnp?.devices.find((d) => /InternetGatewayDevice/i.test(d.deviceType ?? '')) ?? g?.upnp?.devices[0];
  const fwNames = { domain: 'Dominio', private: 'Privata', public: 'Pubblica' };
  return (
    <>
      <m.div className="grid cols-2" variants={cascade(0.06)}>
        <m.section variants={rise} className="card">
          <div className="card-head"><h2>Il tuo router</h2></div>
          {g ? (
            <dl className="kv">
              <dt>Indirizzo</dt>
              <dd>
                <a href={`http://${g.ip}`} target="_blank" rel="noreferrer" style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                  {g.ip} <ExternalLink size={13} aria-hidden />
                </a>
              </dd>
              {g.mac && (<><dt>MAC</dt><dd>{g.mac}</dd></>)}
              {igd?.manufacturer && (<><dt>Produttore</dt><dd>{igd.manufacturer}</dd></>)}
              {igd?.modelName && (<><dt>Modello</dt><dd>{igd.modelName} {igd.modelNumber ?? ''}</dd></>)}
              {g.web?.title && (<><dt>Pannello</dt><dd>{g.web.title}</dd></>)}
              {g.web?.server && (<><dt>Server web</dt><dd>{g.web.server}</dd></>)}
              {g.upnp?.externalIp && (<><dt>IP pubblico</dt><dd>{g.upnp.externalIp}</dd></>)}
            </dl>
          ) : (
            <p className="muted">Nessun gateway rilevato.</p>
          )}
          <p className="faint" style={{ fontSize: 13, marginBottom: 0 }}>STARNET Polaris interroga solo il gateway della rete a cui sei collegato, senza autenticarsi.</p>
        </m.section>
        <m.section variants={rise} className="card">
          <div className="card-head"><h2>Servizi del router</h2></div>
          {g?.ports ? (
            <m.div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }} initial="hidden" animate="show" variants={cascade(0.03, 0.2)}>
              {g.ports.map((p) => {
                const f = a.findings.find((x) => x.id === `router.port.${p.port}`);
                const sev: Severity = p.open ? f?.severity ?? 'info' : 'unknown';
                return (
                  <m.span
                    key={p.port}
                    className={`sev ${sev}`}
                    title={f?.verdict ?? 'chiusa'}
                    variants={{ hidden: { opacity: 0, scale: 0.85 }, show: { opacity: 1, scale: 1, transition: spring.snappy } }}
                  >
                    {p.open ? <SevIcon sev={sev} size={14} /> : null}
                    {p.port} {p.service} {p.open ? 'aperta' : 'chiusa'}
                  </m.span>
                );
              })}
            </m.div>
          ) : (
            <p className="muted">Controllo porte non eseguito.</p>
          )}
          {scan.firewall && (
            <>
              <h3 style={{ marginTop: 20 }}>Firewall di questo PC</h3>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                {scan.firewall.profiles.map((p) => (
                  <span key={p.name} className={`sev ${p.enabled === null ? 'unknown' : p.enabled ? 'ok' : p.active ? 'crit' : 'warn'}`}>
                    <SevIcon sev={p.enabled === null ? 'unknown' : p.enabled ? 'ok' : p.active ? 'crit' : 'warn'} size={14} />
                    {fwNames[p.name]}{p.active ? ' (in uso)' : ''}: {p.enabled === null ? '?' : p.enabled ? 'attivo' : 'disattivato'}
                  </span>
                ))}
              </div>
            </>
          )}
        </m.section>
      </m.div>

      <Section title="Valutazione">
        <FindingList findings={byCat(a, 'router', 'security')} onAction={(id) => go('plan', id)} />
      </Section>

      {g?.upnp && g.upnp.devices.length > 0 && (
        <Section title="Dispositivi UPnP in rete">
          <TableWrap label="Dispositivi UPnP">
            <table>
              <thead><tr><th>Nome</th><th>Produttore</th><th>Modello</th><th>Tipo</th></tr></thead>
              <tbody>
                {g.upnp.devices.map((d, i) => (
                  <tr key={i}>
                    <td>{d.friendlyName ?? '—'}</td>
                    <td>{d.manufacturer ?? '—'}</td>
                    <td>{[d.modelName, d.modelNumber].filter(Boolean).join(' ') || '—'}</td>
                    <td className="faint">{(d.deviceType ?? '').replace('urn:schemas-upnp-org:device:', '')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        </Section>
      )}
    </>
  );
}

// ---------------------------------------------------------------- Piano

/** Casella di spunta disegnata: il segno si traccia con una molla. */
function Check({ checked, onChange, label }: { checked: boolean; onChange: () => void; label: string }) {
  return (
    <button className="check" role="checkbox" aria-checked={checked} onClick={onChange}>
      <svg width="22" height="22" viewBox="0 0 24 24" aria-hidden>
        <rect className="box" x="1.5" y="1.5" width="21" height="21" rx="7" />
        <m.path className="tick" d="M7 12.5l3.4 3.4L17.5 8.6" initial={false} animate={{ pathLength: checked ? 1 : 0, opacity: checked ? 1 : 0 }} transition={spring.snappy} />
        <AnimatePresence>
          {checked && (
            <m.circle
              key="burst"
              cx="12"
              cy="12"
              r="11"
              fill="none"
              stroke="var(--ok)"
              strokeWidth="2"
              initial={{ scale: 0.8, opacity: 0.7 }}
              animate={{ scale: 1.7, opacity: 0 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.6, ease: ease.out }}
              style={{ originX: '50%', originY: '50%', transformBox: 'fill-box' }}
            />
          )}
        </AnimatePresence>
      </svg>
      {label}
    </button>
  );
}

export function PlanView({ analysis: a, focus, scan }: ViewProps) {
  const openGuide = useOpenGuide();
  const key = `polaris.done.${scan.agent.host ?? 'demo'}`;
  const [done, setDone] = useLocalState<string[]>(key, []);
  const titles = useMemo(() => new Map(a.findings.map((f) => [f.id, f])), [a]);
  const refs = useRef(new Map<string, HTMLElement>());
  const reduce = useReducedMotion();
  useEffect(() => {
    if (!focus) return;
    const t = setTimeout(() => {
      const el = refs.current.get(focus);
      el?.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'center' });
      el?.focus({ preventScroll: true });
    }, 450); // dopo l'entrata della pagina
    return () => clearTimeout(t);
  }, [focus, reduce]);
  if (!a.plan.length) return <m.div variants={rise} className="empty">Nessuna azione necessaria: la rete è in ordine.</m.div>;
  const completed = a.plan.filter((p) => done.includes(p.action.id)).length;
  return (
    <>
      <m.section variants={rise} className="card plan-progress">
        <ListChecks size={22} className="c-ok" aria-hidden />
        <div style={{ minWidth: 0 }}>
          <div style={{ fontWeight: 650 }}>
            <AnimatedNumber value={completed} /> di {a.plan.length} azioni completate
          </div>
          <div className="faint" style={{ fontSize: 13 }}>Ordinate per gravità, impatto e facilità. Dopo le modifiche esegui una nuova analisi.</div>
        </div>
        <span className="meter" aria-hidden>
          <m.i initial={false} animate={{ scaleX: completed / a.plan.length }} transition={spring.gentle} />
        </span>
      </m.section>
      <m.div className="stack" style={{ marginTop: 16 }} variants={cascade(0.05)}>
        {a.plan.map((p, i) => {
          const isDone = done.includes(p.action.id);
          const focused = focus === p.action.id;
          return (
            <m.section
              key={p.action.id}
              ref={(el: HTMLElement | null) => {
                if (el) refs.current.set(p.action.id, el);
              }}
              tabIndex={-1}
              className={`card plan-item ${isDone ? 'done' : ''} ${focused ? 'focused' : ''}`}
              data-sev={p.severity}
              variants={rise}
              layout="position"
              transition={spring.smooth}
            >
              <div className="plan-num">{i + 1}</div>
              <div style={{ minWidth: 0 }}>
                <div className="card-head" style={{ marginBottom: 8 }}>
                  <h2>{p.action.title}</h2>
                  <span className="spacer" />
                  <SevBadge sev={p.severity} />
                </div>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  <span className="tag">impatto {p.action.impact}</span>
                  <span className="tag">difficoltà {p.action.effort}</span>
                </div>
                <AnimatePresence initial={false}>
                  {!isDone && (
                    <m.div
                      key="steps"
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: 'auto', opacity: 1, transition: { height: spring.smooth, opacity: { duration: 0.25 } } }}
                      exit={{ height: 0, opacity: 0, transition: { height: { duration: 0.3, ease: ease.inOut }, opacity: { duration: 0.15 } } }}
                      style={{ overflow: 'hidden' }}
                    >
                      <p className="muted" style={{ margin: '12px 0 0' }}>{p.action.why}</p>
                      <ol className="steps">
                        {p.action.steps.map((s, j) => <li key={j}>{s}</li>)}
                      </ol>
                      {openGuide && guidesForAction(p.action.id).length > 0 && (
                        <p className="plan-guides">
                          <BookOpenText size={14} aria-hidden />
                          <span>Approfondisci:</span>
                          {guidesForAction(p.action.id).slice(0, 3).map((g) => (
                            <button key={g.id} className="link-btn" onClick={() => openGuide(g.id)}>{g.title}</button>
                          ))}
                        </p>
                      )}
                    </m.div>
                  )}
                </AnimatePresence>
                <div style={{ display: 'flex', gap: 14, alignItems: 'center', flexWrap: 'wrap', marginTop: 12 }}>
                  <Check checked={isDone} label={isDone ? 'Fatto' : 'Segna come fatto'} onChange={() => setDone(isDone ? done.filter((d) => d !== p.action.id) : [...done, p.action.id])} />
                  <span className="faint" style={{ fontSize: 13 }}>Risolve: {p.findings.map((id) => titles.get(id)?.title ?? id).join(' · ')}</span>
                </div>
              </div>
            </m.section>
          );
        })}
      </m.div>
    </>
  );
}

// ---------------------------------------------------------------- Monitor

const WINDOW = 60;

function summary(xs: (number | null)[]) {
  const ok = xs.filter((v): v is number => v !== null);
  let j = 0;
  for (let i = 1; i < ok.length; i++) j += Math.abs(ok[i] - ok[i - 1]);
  return {
    last: xs.length ? xs[xs.length - 1] : undefined,
    avg: ok.length ? ok.reduce((a, b) => a + b, 0) / ok.length : undefined,
    loss: xs.length ? (100 * (xs.length - ok.length)) / xs.length : 0,
    jitter: ok.length > 1 ? j / (ok.length - 1) : undefined,
  };
}

function MsValue({ v }: { v?: number | null }) {
  if (v === undefined) return <>—</>;
  if (v === null) return <span className="c-crit">perso</span>;
  if (v < 1) return <>&lt;1 ms</>;
  return <AnimatedNumber value={v} decimals={v < 10 ? 1 : 0} suffix=" ms" />;
}

export function MonitorView({ live, scan }: ViewProps) {
  const [running, setRunning] = useState(true);
  const [gw, setGw] = useState<(number | null)[]>([]);
  const [inet, setInet] = useState<(number | null)[]>([]);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    if (!running) return;
    let alive = true;
    let n = 0;
    const push = (set: typeof setGw, v: number | null) => set((xs) => [...xs, v].slice(-WINDOW));
    const id = setInterval(async () => {
      n++;
      let a: number | null;
      let b: number | null;
      if (live) {
        [a, b] = await Promise.all([ping('gateway').catch(() => null), ping('internet').catch(() => null)]);
        if (!alive) return;
      } else {
        // Demo: valori simulati, chiaramente indicati nell'interfaccia.
        const burst = n % 23 > 17;
        a = Math.random() < 0.03 ? null : Math.round((4 + Math.random() * 6 + (burst ? 25 : 0)) * 10) / 10;
        b = Math.random() < 0.02 ? null : Math.round((26 + Math.random() * 9 + (burst ? 40 : 0)) * 10) / 10;
      }
      push(setGw, a);
      push(setInet, b);
      setTick((t) => t + 1);
    }, 1000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [running, live]);
  const sg = summary(gw);
  const si = summary(inet);
  const box = (label: string, s: ReturnType<typeof summary>, color: string) => (
    <m.section variants={rise} className="card" style={{ boxShadow: 'none' }}>
      <h3 style={{ color }}>{label}</h3>
      <div className="stats">
        <Stat k="Ultimo"><MsValue v={s.last} /></Stat>
        <Stat k="Media"><MsValue v={s.avg} /></Stat>
        <Stat k="Jitter"><MsValue v={s.jitter} /></Stat>
        <Stat k="Persi" sev={s.loss > 2 ? 'crit' : s.loss > 0 ? 'warn' : 'ok'}>
          <AnimatedNumber value={s.loss} suffix=" %" />
        </Stat>
      </div>
    </m.section>
  );
  return (
    <>
      <m.section variants={rise} className="card">
        <div className="card-head">
          <h2 style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <AnimatePresence initial={false}>
              {running && <m.span key="dot" className="live-dot" initial={{ scale: 0 }} animate={{ scale: 1 }} exit={{ scale: 0 }} transition={spring.snappy} />}
            </AnimatePresence>
            Monitor in tempo reale
          </h2>
          <span className="sub">
            un ping al secondo verso il router{scan.gateway ? ` (${scan.gateway.ip})` : ''} e verso Internet, ultimi {WINDOW} secondi
          </span>
          <span className="spacer" />
          <button className="btn small" onClick={() => setRunning(!running)} aria-pressed={!running}>
            <AnimatePresence mode="popLayout" initial={false}>
              <m.span key={running ? 'p' : 'r'} style={{ display: 'flex' }} initial={{ rotate: -90, opacity: 0 }} animate={{ rotate: 0, opacity: 1 }} exit={{ rotate: 90, opacity: 0 }} transition={spring.snappy}>
                {running ? <Pause size={15} aria-hidden /> : <Play size={15} aria-hidden />}
              </m.span>
            </AnimatePresence>
            {running ? 'Pausa' : 'Riprendi'}
          </button>
          <button className="btn small" onClick={() => { setGw([]); setInet([]); setTick(0); }}>
            <RotateCcw size={15} aria-hidden /> Azzera
          </button>
        </div>
        {!live && (
          <div className="notice" style={{ marginBottom: 12 }}>
            <TriangleAlert size={18} aria-hidden />
            Modalità demo: i valori sono simulati. Avvia Polaris.exe per misurare la tua rete.
          </div>
        )}
        <LiveChart
          tick={running ? tick : 0}
          maxPoints={WINDOW}
          series={[
            { label: 'Router', color: 'var(--accent)', samples: gw },
            { label: 'Internet', color: 'var(--signal)', samples: inet },
          ]}
        />
        <div className="legend">
          <span><i style={{ background: 'var(--accent)' }} />Router</span>
          <span><i style={{ background: 'var(--signal)' }} />Internet</span>
          <span><i style={{ background: 'var(--crit)' }} />pacchetto perso</span>
        </div>
      </m.section>
      <m.div className="grid cols-2" style={{ marginTop: 16 }} variants={cascade(0.06)}>
        {box('Router', sg, 'var(--accent-text)')}
        {box('Internet', si, 'var(--signal)')}
      </m.div>
      <m.p variants={rise} className="muted" style={{ fontSize: 14 }}>
        Usalo mentre riproduci il problema (una videochiamata che scatta, un gioco a scatti): se i picchi compaiono anche sulla linea del router il
        problema è in casa (Wi-Fi o rete locale); se compaiono solo su quella di Internet è sulla linea o dall'operatore.
      </m.p>
    </>
  );
}
