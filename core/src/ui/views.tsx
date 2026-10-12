import { useEffect, useMemo, useRef, useState } from 'react';
import { ACTIONS, CATEGORY_LABELS, METRIC_LIST, phyLabel, primaryAdapter } from '../engine';
import type { Analysis, Band, Bss, Category, Finding, Scan, Severity } from '../engine';
import { ping } from './api';
import { ChannelLoad, HBars, LatencyChart, SpectrumChart } from './charts';
import { FindingList, Icon, ScoreRing, SevBadge, SevIcon, Stat, sevColor } from './components';
import { useLocalState } from './hooks';

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
const CAT_ICON: Record<Category, string> = { wifi: 'wifi', lan: 'lan', internet: 'globe', dns: 'globe', router: 'router', security: 'shield' };
const fmtMs = (v?: number) => (v === undefined ? '—' : v < 1 ? '<1 ms' : `${Math.round(v * 10) / 10} ms`);

// ---------------------------------------------------------------- Panoramica

export function Overview({ scan, analysis: a, go }: ViewProps) {
  const top = a.findings.filter((f) => f.severity === 'crit' || f.severity === 'warn').slice(0, 5);
  return (
    <>
      <section className="card hero reveal">
        <ScoreRing score={a.score} />
        <div>
          <div className={`grade c-${a.score >= 85 ? 'ok' : a.score >= 70 ? 'info' : a.score >= 50 ? 'warn' : 'crit'}`}>Salute della rete: {a.grade}</div>
          <p className="headline">{a.headline}</p>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            {a.plan.length > 0 && (
              <button className="btn primary" onClick={() => go('plan')}>
                <Icon name="plan" /> Vedi il piano d'azione ({a.plan.length})
              </button>
            )}
            <button className="btn" onClick={() => go('guide')}>
              <Icon name="book" /> Come leggere i valori
            </button>
          </div>
        </div>
      </section>

      <h2 className="section-title">Aree analizzate</h2>
      <div className="tiles">
        {a.categories.map((c, i) => (
          <button key={c.category} className="tile reveal" style={{ ['--i' as string]: i }} onClick={() => go(CAT_VIEW[c.category])}>
            <div className="t-label">
              <Icon name={CAT_ICON[c.category]} size={16} /> {c.label}
              <span style={{ marginLeft: 'auto' }} className={`c-${c.worst}`}><SevIcon sev={c.worst} size={16} /></span>
            </div>
            <div className="t-score mono">{c.score ?? '—'}</div>
            <div className="meter"><i style={{ width: `${c.score ?? 0}%`, background: sevColor(c.worst === 'unknown' ? 'unknown' : c.worst), ['--i' as string]: i }} /></div>
            <div className="faint" style={{ fontSize: 12.5, marginTop: 8 }}>
              {c.score === null
                ? 'non misurato'
                : [c.counts.crit && `${c.counts.crit} ${c.counts.crit === 1 ? 'critico' : 'critici'}`, c.counts.warn && `${c.counts.warn} ${c.counts.warn === 1 ? 'avviso' : 'avvisi'}`]
                    .filter(Boolean)
                    .join(' · ') || 'tutto ok'}
            </div>
          </button>
        ))}
      </div>

      {top.length > 0 && (
        <>
          <h2 className="section-title">Problemi principali</h2>
          <FindingList findings={top} onAction={(id) => go('plan', id)} />
        </>
      )}

      {a.plan.length > 0 && (
        <>
          <h2 className="section-title">Da dove cominciare</h2>
          <div className="grid cols-3">
            {a.plan.slice(0, 3).map((p, i) => (
              <button key={p.action.id} className="tile reveal" style={{ ['--i' as string]: i }} onClick={() => go('plan', p.action.id)}>
                <div className="t-label"><span className={`c-${p.severity}`}><SevIcon sev={p.severity} size={16} /></span> Passo {i + 1}</div>
                <div style={{ fontWeight: 650, margin: '6px 0' }}>{p.action.title}</div>
                <div className="faint" style={{ fontSize: 13 }}>Impatto {p.action.impact} · difficoltà {p.action.effort}</div>
              </button>
            ))}
          </div>
        </>
      )}

      {scan.errors.length > 0 && (
        <>
          <h2 className="section-title">Misure non riuscite</h2>
          <div className="notice">
            <ul className="errors" style={{ margin: 0, paddingLeft: 18 }}>
              {scan.errors.map((e, i) => (
                <li key={i}><b>{e.probe}</b>: {e.message}</li>
              ))}
            </ul>
          </div>
        </>
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
        {label} {sort.k === k ? (sort.dir === 1 ? '▲' : '▼') : ''}
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
    <div className="table-wrap">
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
                {b.ssid || <span className="faint">(nascosta)</span>} {b.connected && <span className="tag">collegato</span>}
              </td>
              <td className={`mono c-${sigSev(b.rssiDbm)}`}>{b.rssiDbm} dBm</td>
              <td>{b.band.replace('.', ',')} GHz</td>
              <td className="mono">{b.channel}</td>
              <td className="mono">{b.widthMhz} MHz</td>
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
  if (!wifi) return <div className="empty">Questa sonda non ha raccolto dati Wi-Fi.</div>;
  return (
    <>
      {conn ? (
        <section className="card reveal">
          <div className="card-head">
            <h2>Connessione attuale: {conn.ssid}</h2>
            <span className="faint mono">{conn.bssid}</span>
          </div>
          <div className="stats">
            <Stat k="Segnale" v={f('wifi.rssi')?.value ?? '—'} sev={f('wifi.rssi')?.severity} />
            <Stat k="Qualità (Windows)" v={conn.signalQuality !== undefined ? `${conn.signalQuality} %` : '—'} />
            <Stat k="Velocità radio" v={f('wifi.linkrate')?.value ?? '—'} sev={f('wifi.linkrate')?.severity} />
            <Stat k="Banda / canale" v={f('wifi.band')?.value ?? '—'} sev={f('wifi.band')?.severity} />
            <Stat k="Larghezza" v={f('wifi.width')?.value ?? '—'} sev={f('wifi.width')?.severity} />
            <Stat k="Standard" v={phyLabel(conn.phy, me?.band ?? conn.band)} sev={f('wifi.phy')?.severity} />
          </div>
        </section>
      ) : (
        <div className="notice">{wifi.error ? `Wi-Fi non disponibile: ${wifi.error}` : 'Il dispositivo non è collegato a una rete Wi-Fi.'}</div>
      )}

      {bands.length > 0 && (
        <section className="card reveal" style={{ ['--i' as string]: 1, marginTop: 16 }}>
          <div className="card-head">
            <h2>Spettro radio</h2>
            <span className="muted" style={{ fontSize: 14 }}>ogni curva è una rete: larga quanto il suo canale, alta quanto il suo segnale</span>
            <span className="spacer" />
            <div className="tabs" role="tablist" aria-label="Banda">
              {bands.map((b) => (
                <button key={b} role="tab" aria-selected={band === b} onClick={() => setBand(b)}>
                  {b.replace('.', ',')} GHz
                </button>
              ))}
            </div>
          </div>
          <SpectrumChart key={band} networks={wifi.networks} band={band} mySsid={conn?.ssid} />
          {advice && (
            <div style={{ marginTop: 18 }}>
              <h3>Interferenza stimata per {band === '5' ? 'blocco da 80 MHz' : 'canale'}</h3>
              {advice.scores.length > 0 && <ChannelLoad key={band} advice={advice} />}
              <p className="notice" style={{ marginTop: 10 }}>
                {advice.recommended !== undefined && advice.recommended !== advice.current ? (
                  <b>Canale consigliato: {advice.recommended}. </b>
                ) : null}
                {advice.note}
              </p>
            </div>
          )}
        </section>
      )}

      <h2 className="section-title">Valutazione</h2>
      <FindingList findings={a.findings.filter((x) => x.id.startsWith('wifi.'))} onAction={(id) => go('plan', id)} />

      <h2 className="section-title">Reti visibili ({wifi.networks.length})</h2>
      <NetworksTable nets={wifi.networks} mySsid={conn?.ssid} />
    </>
  );
}

// ---------------------------------------------------------------- LAN

export function LanView({ scan, analysis: a, go }: ViewProps) {
  const primary = primaryAdapter(scan);
  const g = scan.gateway;
  return (
    <>
      <div className="grid cols-2">
        <section className="card reveal">
          <h2>Scheda in uso</h2>
          {primary ? (
            <dl className="kv" style={{ marginTop: 10 }}>
              <dt>Nome</dt><dd>{primary.name}</dd>
              {primary.description && primary.description !== primary.name && (<><dt>Hardware</dt><dd>{primary.description}</dd></>)}
              <dt>Tipo</dt><dd>{{ wifi: 'Wi-Fi', ethernet: 'Ethernet (cavo)', other: 'altro', virtual: 'virtuale', loopback: 'loopback' }[primary.kind]}</dd>
              <dt>IPv4</dt><dd>{primary.ipv4.join(', ') || '—'}</dd>
              <dt>IPv6</dt><dd>{primary.ipv6.join(', ') || '—'}</dd>
              <dt>Gateway</dt><dd>{primary.gateways.join(', ') || '—'}</dd>
              <dt>DNS</dt><dd>{primary.dns.join(', ') || '—'}</dd>
              <dt>DHCP</dt><dd>{primary.dhcp === undefined ? '—' : primary.dhcp ? 'sì' : 'no (statico)'}</dd>
              <dt>MAC</dt><dd>{primary.mac ?? '—'}</dd>
              {primary.mtu && (<><dt>MTU</dt><dd>{primary.mtu}</dd></>)}
              {primary.linkMbps && (<><dt>Velocità link</dt><dd>{primary.linkMbps} Mbit/s</dd></>)}
            </dl>
          ) : (
            <p className="muted">Nessuna scheda attiva.</p>
          )}
        </section>
        <section className="card reveal" style={{ ['--i' as string]: 1 }}>
          <h2>Tratto PC → router</h2>
          {g?.ping && g.ping.received > 0 ? (
            <>
              <div className="stats" style={{ margin: '10px 0' }}>
                <Stat k="Media" v={fmtMs(g.ping.avgMs)} sev={a.findings.find((f) => f.id === 'lan.gwlatency')?.severity} />
                <Stat k="Min / max" v={`${fmtMs(g.ping.minMs)} / ${fmtMs(g.ping.maxMs)}`} />
                <Stat k="Jitter" v={fmtMs(g.ping.jitterMs)} sev={a.findings.find((f) => f.id === 'lan.jitter')?.severity} />
                <Stat k="Persi" v={`${g.ping.sent - g.ping.received}/${g.ping.sent}`} sev={a.findings.find((f) => f.id === 'lan.gwloss')?.severity} />
              </div>
              {g.ping.samples && <LatencyChart series={[{ label: 'Router', color: 'var(--accent)', samples: g.ping.samples }]} />}
            </>
          ) : (
            <p className="muted">{g ? 'Il router non ha risposto al ping.' : 'Nessun gateway misurato.'}</p>
          )}
        </section>
      </div>

      <h2 className="section-title">Valutazione</h2>
      <FindingList findings={byCat(a, 'lan')} onAction={(id) => go('plan', id)} />

      <h2 className="section-title">Tutte le schede di rete</h2>
      <div className="table-wrap">
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
      </div>

      {scan.lan && scan.lan.neighbors.length > 0 && (
        <>
          <h2 className="section-title">Dispositivi visti di recente ({scan.lan.neighbors.length})</h2>
          <div className="table-wrap">
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
          </div>
        </>
      )}
    </>
  );
}

// ---------------------------------------------------------------- Internet

const SERIES_COLORS = ['var(--info)', 'var(--ok)', '#c792ea', 'var(--accent)'];

export function InternetView({ scan, analysis: a, go }: ViewProps) {
  const net = scan.internet;
  const dns = scan.dns;
  const maxRtt = Math.max(1, ...(net?.traceroute ?? []).map((h) => h.rttMs ?? 0));
  return (
    <>
      {net && net.targets.length > 0 && (
        <section className="card reveal">
          <div className="card-head"><h2>Latenza verso Internet</h2></div>
          <div className="stats" style={{ marginBottom: 12 }}>
            {net.targets.map((t) => (
              <Stat key={t.target} k={`${t.label ?? t.target} (${t.target})`} v={t.received ? `${fmtMs(t.avgMs)} · ${t.sent - t.received} persi` : 'nessuna risposta'} />
            ))}
          </div>
          <LatencyChart series={net.targets.filter((t) => t.samples).map((t, i) => ({ label: t.label ?? t.target, color: SERIES_COLORS[i % 4], samples: t.samples! }))} />
          <div className="legend" style={{ marginTop: 8 }}>
            {net.targets.map((t, i) => (<span key={t.target}><i style={{ background: SERIES_COLORS[i % 4] }} />{t.label ?? t.target}</span>))}
            <span><i style={{ background: 'var(--crit)', borderRadius: '50%' }} />pacchetto perso</span>
          </div>
        </section>
      )}

      <div className="grid cols-2" style={{ marginTop: 16 }}>
        {net?.traceroute && (
          <section className="card reveal" style={{ ['--i' as string]: 1 }}>
            <h2>Percorso verso {net.traceTarget ?? 'Internet'}</h2>
            <p className="muted" style={{ fontSize: 14, marginTop: 0 }}>Ogni riga è un router attraversato. Il primo è il tuo.</p>
            <div className="hops">
              {net.traceroute.map((h, i) => (
                <div className="hop" key={h.ttl} style={{ ['--i' as string]: i }}>
                  <span className="n">{h.ttl}</span>
                  <span className="mono" style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{h.ip ?? <span className="faint">* nessuna risposta</span>}</span>
                  <span className="bar">{h.rttMs !== undefined && <i style={{ width: `${(100 * h.rttMs) / maxRtt}%` }} />}</span>
                  <span className="mono" style={{ textAlign: 'right' }}>{h.rttMs !== undefined ? fmtMs(h.rttMs) : '—'}</span>
                </div>
              ))}
            </div>
          </section>
        )}
        {dns && (
          <section className="card reveal" style={{ ['--i' as string]: 2 }}>
            <h2>DNS: tempo per tradurre un nome</h2>
            <p className="muted" style={{ fontSize: 14, marginTop: 0 }}>In evidenza il DNS che usi ora. Più corto è meglio.</p>
            <HBars
              items={[
                ...dns.system.map((s) => ({ label: `${s.label ?? s.server} (in uso)`, value: s.ok ? s.timeMs ?? null : null, highlight: true, note: s.error })),
                ...dns.public.map((s) => ({ label: `${s.label ?? s.server} ${s.server}`, value: s.ok ? s.timeMs ?? null : null, note: s.error })),
              ]}
            />
          </section>
        )}
      </div>

      <h2 className="section-title">Valutazione</h2>
      <FindingList findings={byCat(a, 'internet', 'dns')} onAction={(id) => go('plan', id)} />
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
      <div className="grid cols-2">
        <section className="card reveal">
          <h2>Il tuo router</h2>
          {g ? (
            <dl className="kv" style={{ marginTop: 10 }}>
              <dt>Indirizzo</dt><dd><a href={`http://${g.ip}`} target="_blank" rel="noreferrer">{g.ip}</a></dd>
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
          <p className="faint" style={{ fontSize: 13, marginBottom: 0 }}>
            LANterna interroga solo il gateway della rete a cui sei collegato, senza autenticarsi.
          </p>
        </section>
        <section className="card reveal" style={{ ['--i' as string]: 1 }}>
          <h2>Servizi del router</h2>
          {g?.ports ? (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 10 }}>
              {g.ports.map((p) => {
                const f = a.findings.find((x) => x.id === `router.port.${p.port}`);
                const sev: Severity = p.open ? f?.severity ?? 'info' : 'ok';
                return (
                  <span key={p.port} className={`sev ${p.open ? sev : 'unknown'}`} title={f?.verdict ?? 'chiusa'}>
                    {p.open ? <SevIcon sev={sev} size={14} /> : null}
                    {p.port} {p.service} {p.open ? 'aperta' : 'chiusa'}
                  </span>
                );
              })}
            </div>
          ) : (
            <p className="muted">Controllo porte non eseguito.</p>
          )}
          {scan.firewall && (
            <>
              <h3 style={{ marginTop: 18 }}>Firewall di questo PC</h3>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                {scan.firewall.profiles.map((p) => (
                  <span key={p.name} className={`sev ${p.enabled === null ? 'unknown' : p.enabled ? 'ok' : p.active ? 'crit' : 'warn'}`}>
                    {fwNames[p.name]}{p.active ? ' (in uso)' : ''}: {p.enabled === null ? '?' : p.enabled ? 'attivo' : 'disattivato'}
                  </span>
                ))}
              </div>
            </>
          )}
        </section>
      </div>

      <h2 className="section-title">Valutazione</h2>
      <FindingList findings={byCat(a, 'router', 'security')} onAction={(id) => go('plan', id)} />

      {g?.upnp && g.upnp.devices.length > 0 && (
        <>
          <h2 className="section-title">Dispositivi UPnP in rete</h2>
          <div className="table-wrap">
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
          </div>
        </>
      )}
    </>
  );
}

// ---------------------------------------------------------------- Piano

export function PlanView({ analysis: a, focus, scan }: ViewProps) {
  const key = `lanterna.done.${scan.agent.host ?? 'demo'}`;
  const [done, setDone] = useLocalState<string[]>(key, []);
  const titles = useMemo(() => new Map(a.findings.map((f) => [f.id, f])), [a]);
  const refs = useRef(new Map<string, HTMLElement>());
  useEffect(() => {
    if (!focus) return;
    const el = refs.current.get(focus);
    el?.scrollIntoView({ behavior: 'smooth', block: 'center' });
    el?.focus({ preventScroll: true });
  }, [focus]);
  if (!a.plan.length) return <div className="empty">Nessuna azione necessaria: la rete è in ordine.</div>;
  return (
    <>
      <p className="muted" style={{ marginTop: 0 }}>
        Le azioni sono ordinate per gravità dei problemi che risolvono, impatto e facilità. Spunta quelle completate, poi esegui una nuova analisi
        per verificare il miglioramento.
      </p>
      <div className="grid">
        {a.plan.map((p, i) => {
          const isDone = done.includes(p.action.id);
          return (
            <section
              key={p.action.id}
              ref={(el) => { if (el) refs.current.set(p.action.id, el); }}
              tabIndex={-1}
              className={`card plan-item reveal ${isDone ? 'done' : ''}`}
              data-sev={p.severity}
              style={{ ['--i' as string]: i, outline: focus === p.action.id ? '2px solid var(--accent)' : undefined }}
            >
              <div className="plan-num">{i + 1}</div>
              <div>
                <div className="card-head" style={{ marginBottom: 6 }}>
                  <h2>{p.action.title}</h2>
                  <span className="spacer" />
                  <SevBadge sev={p.severity} />
                </div>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 8 }}>
                  <span className="tag">impatto {p.action.impact}</span>
                  <span className="tag">difficoltà {p.action.effort}</span>
                </div>
                <p className="muted" style={{ margin: '6px 0' }}>{p.action.why}</p>
                <ol className="steps">
                  {p.action.steps.map((s, j) => <li key={j}>{s}</li>)}
                </ol>
                <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap', marginTop: 12 }}>
                  <label className="check">
                    <input type="checkbox" checked={isDone} onChange={() => setDone(isDone ? done.filter((d) => d !== p.action.id) : [...done, p.action.id])} />
                    Fatto
                  </label>
                  <span className="faint" style={{ fontSize: 13 }}>
                    Risolve: {p.findings.map((id) => titles.get(id)?.title ?? id).join(' · ')}
                  </span>
                </div>
              </div>
            </section>
          );
        })}
      </div>
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

export function MonitorView({ live, scan }: ViewProps) {
  const [running, setRunning] = useState(true);
  const [gw, setGw] = useState<(number | null)[]>([]);
  const [inet, setInet] = useState<(number | null)[]>([]);
  useEffect(() => {
    if (!running) return;
    let alive = true;
    let tick = 0;
    const push = (set: typeof setGw, v: number | null) => set((xs) => [...xs, v].slice(-WINDOW));
    const id = setInterval(async () => {
      tick++;
      if (live) {
        const [a, b] = await Promise.all([ping('gateway').catch(() => null), ping('internet').catch(() => null)]);
        if (!alive) return;
        push(setGw, a);
        push(setInet, b);
      } else {
        // Demo: valori simulati, chiaramente indicati nell'interfaccia.
        const burst = tick % 23 > 17;
        push(setGw, Math.random() < 0.03 ? null : Math.round((4 + Math.random() * 6 + (burst ? 25 : 0)) * 10) / 10);
        push(setInet, Math.random() < 0.02 ? null : Math.round((26 + Math.random() * 9 + (burst ? 40 : 0)) * 10) / 10);
      }
    }, 1000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [running, live]);
  const sg = summary(gw);
  const si = summary(inet);
  const box = (label: string, s: ReturnType<typeof summary>, color: string) => (
    <div className="card" style={{ boxShadow: 'none' }}>
      <h3 style={{ color }}>{label}</h3>
      <div className="stats">
        <Stat k="Ultimo" v={s.last === undefined ? '—' : s.last === null ? 'perso' : fmtMs(s.last)} />
        <Stat k="Media" v={fmtMs(s.avg)} />
        <Stat k="Jitter" v={fmtMs(s.jitter)} />
        <Stat k="Persi" v={`${Math.round(s.loss)} %`} sev={s.loss > 2 ? 'crit' : s.loss > 0 ? 'warn' : 'ok'} />
      </div>
    </div>
  );
  return (
    <>
      <section className="card reveal">
        <div className="card-head">
          <h2>{running ? <span className="live-dot" style={{ marginRight: 8 }} /> : null}Monitor in tempo reale</h2>
          <span className="muted" style={{ fontSize: 14 }}>
            un ping al secondo verso il router{scan.gateway ? ` (${scan.gateway.ip})` : ''} e verso Internet, ultimi {WINDOW} secondi
          </span>
          <span className="spacer" />
          <button className="btn small" onClick={() => setRunning(!running)}>{running ? 'Pausa' : 'Riprendi'}</button>
          <button className="btn small" onClick={() => { setGw([]); setInet([]); }}>Azzera</button>
        </div>
        {!live && <div className="notice" style={{ marginBottom: 12 }}>Modalità demo: i valori sono simulati. Avvia LANterna.exe per misurare la tua rete.</div>}
        <LatencyChart live maxPoints={WINDOW} height={220} series={[{ label: 'Router', color: 'var(--accent)', samples: gw }, { label: 'Internet', color: 'var(--info)', samples: inet }]} />
        <div className="legend" style={{ marginTop: 8 }}>
          <span><i style={{ background: 'var(--accent)' }} />Router</span>
          <span><i style={{ background: 'var(--info)' }} />Internet</span>
          <span><i style={{ background: 'var(--crit)', borderRadius: '50%' }} />pacchetto perso</span>
        </div>
      </section>
      <div className="grid cols-2" style={{ marginTop: 16 }}>
        {box('Router', sg, 'var(--accent)')}
        {box('Internet', si, 'var(--info)')}
      </div>
      <p className="muted" style={{ fontSize: 14 }}>
        Usalo mentre riproduci il problema (una videochiamata che scatta, un gioco che va a scatti): se i picchi compaiono anche sulla linea del
        router il problema è in casa (Wi-Fi o rete locale); se compaiono solo su quella di Internet è sulla linea o dall'operatore.
      </p>
    </>
  );
}

// ---------------------------------------------------------------- Guida

export function GuideView({ analysis: a }: ViewProps) {
  const [q, setQ] = useState('');
  const norm = (s: string) => s.toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '');
  const match = (...xs: (string | undefined)[]) => !q || xs.some((x) => x && norm(x).includes(norm(q)));
  const measured = new Map<string, Finding>();
  for (const f of a.findings) if (!measured.has(f.metric)) measured.set(f.metric, f);
  const cats = Object.keys(CATEGORY_LABELS) as Category[];
  const metrics = METRIC_LIST.filter((m) => match(m.label, m.what, m.why, m.limits, ...(m.scale ?? []).map((s) => s.meaning)));
  const actions = Object.values(ACTIONS).filter((x) => match(x.title, x.why, ...x.steps));
  return (
    <>
      <input className="search" type="search" placeholder="Cerca un termine: dBm, canale, DNS, jitter, UPnP…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Cerca nella guida" />
      {cats.map((c) => {
        const ms = metrics.filter((m) => m.category === c);
        if (!ms.length) return null;
        return (
          <div key={c}>
            <h2 className="section-title">{CATEGORY_LABELS[c]}</h2>
            <div className="grid cols-2">
              {ms.map((m, i) => {
                const f = measured.get(m.id);
                return (
                  <section key={m.id} className="card reveal" style={{ ['--i' as string]: i }}>
                    <div className="card-head">
                      <h2>{m.label}</h2>
                      <span className="spacer" />
                      {f && <span className={`sev ${f.severity}`} title="valore misurato nella tua rete"><SevIcon sev={f.severity} size={14} />{f.value}</span>}
                    </div>
                    <p className="muted" style={{ marginTop: 0 }}>{m.what}</p>
                    {m.scale && (
                      <div className="scale" style={{ margin: '10px 0' }}>
                        {m.scale.map((s) => (
                          <div key={s.range} className={`scale-row ${f?.severity === s.severity ? 'here' : ''}`}>
                            <span className={`c-${s.severity}`} style={{ fontWeight: 600 }}>{s.range}</span>
                            <span className="muted">{s.meaning}</span>
                          </div>
                        ))}
                      </div>
                    )}
                    <p style={{ marginBottom: 0 }}><b>Perché conta.</b> <span className="muted">{m.why}</span></p>
                    {m.limits && <p className="faint" style={{ fontSize: 13.5, marginBottom: 0 }}><b>Limiti:</b> {m.limits}</p>}
                  </section>
                );
              })}
            </div>
          </div>
        );
      })}
      {actions.length > 0 && (
        <>
          <h2 className="section-title">Tutte le azioni correttive</h2>
          <div className="grid cols-2">
            {actions.map((x) => (
              <details key={x.id} className="card">
                <summary style={{ cursor: 'pointer', fontWeight: 650 }}>{x.title}</summary>
                <p className="muted">{x.why}</p>
                <ol className="steps">{x.steps.map((s, i) => <li key={i}>{s}</li>)}</ol>
              </details>
            ))}
          </div>
        </>
      )}
      {!metrics.length && !actions.length && <div className="empty">Nessun risultato per "{q}".</div>}
    </>
  );
}
