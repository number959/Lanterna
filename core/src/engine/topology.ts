import { primaryAdapter } from './adapters';
import { cidrText, inCidr, ipNum, numIp, parseCidr, privateKind } from './cidr';
import type { Cidr } from './cidr';
import { discoveredNets, netLabel, switchPort } from './discovery';
import { classifyHost, KIND_ORDER, nearBssid, vlanIn } from './devicetype';
import type { Confidence, DeviceKind } from './devicetype';
import type { Analysis, InventoryHost, Scan, Severity } from './types';

// Mappa della rete: dai dati del rapporto (inventario, dispositivi visti dal
// PC, gateway, Wi-Fi, traceroute, server DNS e DHCP, verifiche dei servizi)
// costruisce nodi, zone (sottoreti e reti Wi-Fi), collegamenti e i percorsi
// del traffico di questo PC, con le posizioni già calcolate: l'interfaccia la
// disegna e la anima, il documento la può stampare. Un collegamento dedotto
// (per esempio un access point che non risponde all'inventario) è segnato
// come tale. Polaris vede il proprio traffico, non quello degli altri: i
// percorsi dicono da dove passa, non quanto ne passa.
// Gira anche in goja: niente Intl.

export interface MapNode {
  id: string;
  kind: DeviceKind;
  label: string;
  ip?: string;
  mac?: string;
  vendor?: string;
  /** Nomi DNS e NetBIOS. */
  names: string[];
  confidence: Confidence;
  reasons: string[];
  /** Zona di appartenenza; "core" per il gateway e la catena verso Internet. */
  segment: string;
  self?: boolean;
  gateway?: boolean;
  /** Dedotto dai dati, non visto rispondere. */
  inferred?: boolean;
  /** Ruoli nella rete: gateway, DNS, DHCP, Wi-Fi, servizi verificati. */
  roles: string[];
  rttMs?: number;
  sev?: Severity;
  /** Segnali in chiaro (TTL, servizi, UPnP, ruoli NetBIOS). */
  signals: string[];
  x: number;
  y: number;
}

export type SegmentKind = 'local' | 'remote' | 'wifi';

export interface MapSegment {
  id: string;
  label: string;
  subnet?: string;
  vlan?: number;
  kind: SegmentKind;
  /** Come è stata scoperta. */
  sources: string[];
  note?: string;
  x: number;
  y: number;
  w: number;
  h: number;
  /** Lato della dorsale su cui sta la zona. */
  side?: 'left' | 'right' | 'center';
  /** Punto in cui la linea della zona esce verso la dorsale. */
  ex?: number;
  ey?: number;
}

export type LinkKind = 'cable' | 'wifi' | 'routed' | 'internet' | 'lan';

export interface MapLink {
  id: string;
  from: string;
  to: string;
  kind: LinkKind;
  sev?: Severity;
  label?: string;
  inferred?: boolean;
}

export type FlowKind = 'internet' | 'dns' | 'service' | 'blocked';

export interface MapFlow {
  id: string;
  label: string;
  kind: FlowKind;
  /** Nodi attraversati, da questo PC alla destinazione. */
  path: string[];
  sev: Severity;
  note: string;
  rttMs?: number;
}

export interface NetworkMap {
  nodes: MapNode[];
  segments: MapSegment[];
  links: MapLink[];
  flows: MapFlow[];
  width: number;
  height: number;
  notes: string[];
  counts: Partial<Record<DeviceKind, number>>;
  /** I dispositivi vengono dall'inventario (true) o solo dalla tabella ARP del PC. */
  fromInventory: boolean;
  /** Dorsale verticale sotto il gateway: da qui partono i rami verso le zone. */
  backbone?: { x: number; y1: number; y2: number };
}

// ---------------------------------------------------------------- indirizzi

export { cidrText, inCidr, ipNum, parseCidr, privateKind } from './cidr';
export type { Cidr } from './cidr';

const by24 = (ip: string): Cidr => parseCidr(`${ip}/24`)!;

/** Dispositivi scoperti mostrati al massimo in ogni altra rete: gli altri restano nell'elenco. */
const MAX_DISCOVERED = 12;

// ---------------------------------------------------------------- costruzione

const FIREWALL_RE = /firewall|fortigate|fortinet|pfsense|opnsense|sophos|watchguard|sonicwall|palo ?alto|check ?point|untangle|stormshield|zyxel usg|endian/i;

const sevOf = (a: Analysis | undefined, ...ids: string[]): Severity | undefined => {
  const RANK: Record<Severity, number> = { unknown: 0, ok: 1, info: 2, warn: 3, crit: 4 };
  let out: Severity | undefined;
  for (const id of ids) {
    const f = a?.findings.find((x) => x.id === id);
    if (f && (!out || RANK[f.severity] > RANK[out])) out = f.severity;
  }
  return out;
};

const fmtMs = (ms: number) => `${ms < 10 ? Math.round(ms * 10) / 10 : Math.round(ms)} ms`.replace('.', ',');

/** Etichetta breve di un dispositivo: nome, poi produttore e tipo, poi indirizzo. */
function labelOf(h: InventoryHost, kindLabel: string): string {
  const n = (h.name ?? '').split('.')[0] || h.netbios || '';
  if (n) return n;
  if (h.vendor) return `${h.vendor}`;
  return kindLabel;
}

const KIND_SHORT: Record<DeviceKind, string> = {
  internet: 'Internet',
  isp: 'Operatore',
  router: 'Router',
  firewall: 'Firewall',
  switch: 'Switch',
  ap: 'Access point',
  pc: 'PC',
  laptop: 'Portatile',
  server: 'Server',
  vm: 'Macchina virtuale',
  nas: 'NAS',
  printer: 'Stampante',
  phone: 'Telefono',
  tablet: 'Tablet',
  voip: 'Telefono VoIP',
  camera: 'Telecamera',
  tv: 'Multimedia',
  iot: 'Dispositivo IoT',
  medical: 'Medicale',
  unknown: 'Dispositivo',
};

function signalsOf(h: InventoryHost): string[] {
  const out: string[] = [];
  if (h.vendor) out.push(`Produttore (dal MAC): ${h.vendor}`);
  if (h.ttl) out.push(`TTL della risposta: ${h.ttl}`);
  if (h.services?.length) out.push(`Servizi annunciati (mDNS): ${h.services.join(', ')}`);
  if (h.upnp?.length) out.push(`Tipi UPnP: ${h.upnp.map((u) => u.replace(/^urn:/, '')).join(', ')}`);
  if (h.server) out.push(`Si presenta come: ${h.server}`);
  if (h.roles?.length) out.push(`Ruoli NetBIOS: ${h.roles.join(', ')}`);
  if (h.randomMac) out.push('MAC casuale (privacy)');
  return out;
}

/** Costruisce la mappa della rete dal rapporto. */
export function buildNetworkMap(scan: Scan, analysis?: Analysis): NetworkMap {
  const primary = primaryAdapter(scan);
  const local = parseCidr(primary?.ipv4[0]);
  const selfIp = primary?.ipv4[0]?.split('/')[0];
  const gwIp = scan.gateway?.ip ?? primary?.gateways[0];
  const dnsServers = primary?.dns ?? [];
  const dhcpServer = primary?.dhcpServer;
  const bssids = (scan.wifi?.networks ?? []).map((n) => n.bssid);
  const web = scan.gateway?.web;
  const gatewayFirewall = FIREWALL_RE.test(`${web?.title ?? ''} ${web?.server ?? ''}`);
  const inv = scan.infra?.inventory;
  const notes: string[] = [];

  // Ruoli dichiarati dalle verifiche dei servizi critici.
  const roles: Record<string, string> = {};
  const labels: Record<string, string> = {};
  for (const r of scan.infra?.reach?.results ?? []) {
    if (!r.ip || !r.label) continue;
    if (r.expect === 'reachable') roles[r.ip] = `il servizio «${r.label}»`;
    if (!labels[r.ip]) labels[r.ip] = r.label;
  }

  // Scoperta delle reti: VLAN e sottoreti note, capacità e nomi annunciati
  // dai vicini LLDP/CDP (switch, router, access point), per indirizzo.
  const nets = discoveredNets(scan, primary);
  const neighborCaps: Record<string, string[]> = {};
  const neighborNames: Record<string, string> = {};
  const disc = scan.infra?.discovery;
  for (const r of disc?.snmp ?? []) {
    if (r.system?.name) neighborNames[r.target] = r.system.name;
    for (const n of r.lldpNeighbors) {
      if (!n.mgmtIp) continue;
      if (n.capsEnabled?.length) neighborCaps[n.mgmtIp] = n.capsEnabled.map((c) => (c === 'wlanAccessPoint' ? 'wlan-ap' : c));
      if (n.sysName && !neighborNames[n.mgmtIp]) neighborNames[n.mgmtIp] = n.sysName;
    }
  }
  if (disc?.l2?.read === 'ok') {
    for (const n of disc.l2.lldp ?? []) for (const ip of n.managementAddresses ?? []) if (n.capabilities?.length) neighborCaps[ip] = n.capabilities;
    for (const n of disc.l2.cdp ?? []) for (const ip of n.managementAddresses ?? []) if (n.capabilities?.length && !neighborCaps[ip]) neighborCaps[ip] = n.capabilities;
  }

  // Dispositivi: inventario, poi quelli visti dal PC (tabella ARP).
  const hosts = new Map<string, InventoryHost>();
  for (const h of inv?.hosts ?? []) hosts.set(h.ip, { ...h });
  for (const n of scan.lan?.neighbors ?? []) {
    if (!hosts.has(n.ip) && ipNum(n.ip) !== undefined) {
      hosts.set(n.ip, { ip: n.ip, mac: n.mac, randomMac: !!n.mac && /^.[26ae]/i.test(n.mac) });
    }
  }
  if (selfIp && !hosts.has(selfIp)) hosts.set(selfIp, { ip: selfIp, mac: primary?.mac, self: true, name: scan.agent.host });
  if (gwIp && !hosts.has(gwIp)) hosts.set(gwIp, { ip: gwIp, mac: scan.gateway?.mac, gateway: true });
  for (const h of hosts.values()) {
    if (h.ip === selfIp) h.self = true;
    if (h.ip === gwIp) h.gateway = true;
  }
  if (!inv) notes.push('Ci sono solo i dispositivi che il PC ha contattato di recente: l\'inventario della sezione Infrastruttura li trova tutti.');

  const nodes: MapNode[] = [];
  const byIp = new Map<string, MapNode>();
  const nodeOf = (h: InventoryHost, segment: string): MapNode => {
    const g = classifyHost(h, { gatewayIp: gwIp, gatewayFirewall, dnsServers, dhcpServer, bssids, roles, labels, neighborCaps });
    let kind = g.kind;
    let reasons = g.reasons;
    let confidence = g.confidence;
    if (h.self) {
      kind = scan.pc?.battery ? 'laptop' : 'pc';
      reasons = ['è il PC su cui gira Polaris'];
      confidence = 'alta';
    }
    const r: string[] = [];
    if (h.gateway) r.push('Gateway');
    if (dnsServers.indexOf(h.ip) >= 0) r.push('DNS');
    if (dhcpServer === h.ip) r.push('DHCP');
    if (roles[h.ip]) r.push(roles[h.ip].replace(/^il servizio «(.*)»$/, '$1'));
    const n: MapNode = {
      id: `ip:${h.ip}`,
      kind,
      label: h.self ? scan.agent.host || 'Questo PC' : labelOf(h, KIND_SHORT[kind]),
      ip: h.ip,
      mac: h.mac,
      vendor: h.vendor,
      names: [h.name, h.netbios].filter((x): x is string => !!x),
      confidence,
      reasons,
      segment,
      self: h.self,
      gateway: h.gateway,
      roles: r,
      rttMs: h.rttMs,
      signals: signalsOf(h),
      x: 0,
      y: 0,
    };
    nodes.push(n);
    byIp.set(h.ip, n);
    return n;
  };

  const segments: MapSegment[] = [];
  const localSeg: MapSegment = {
    id: 'seg:local',
    label: 'Rete di questo PC',
    subnet: local ? cidrText(local) : undefined,
    kind: 'local',
    sources: [inv ? 'inventario della sottorete' : 'dispositivi visti dal PC'],
    x: 0,
    y: 0,
    w: 0,
    h: 0,
  };
  segments.push(localSeg);

  // Il gateway sta sopra le zone: è il punto in cui passano tutte.
  const gwHost = gwIp ? hosts.get(gwIp) : undefined;
  const gwNode = gwHost ? nodeOf(gwHost, 'core') : undefined;
  const localVlan = vlanIn(gwHost?.name) ?? vlanIn(gwHost?.netbios);
  if (localVlan) {
    localSeg.vlan = localVlan;
    localSeg.sources.push(`numero di VLAN nel nome del gateway (${gwHost?.name ?? gwHost?.netbios})`);
  }

  const localNet = nets.find((n) => n.local);
  if (localNet?.vlan && localNet.vlan !== localSeg.vlan) {
    localSeg.vlan = localNet.vlan;
    localSeg.sources = localSeg.sources.filter((x) => !/^numero di VLAN/.test(x));
  }
  if (localNet?.name) localSeg.label = `Rete di questo PC · ${localNet.name}`;
  for (const x of localNet?.sources ?? []) if (x !== 'rete di questo PC' && localSeg.sources.indexOf(x) < 0) localSeg.sources.push(x);

  // Dispositivi della rete del PC.
  for (const h of hosts.values()) {
    if (h.gateway) continue;
    if (local && !inCidr(h.ip, local) && !h.self) continue;
    nodeOf(h, localSeg.id);
  }

  // Lo switch che annuncia sé stesso alla porta del PC (LLDP o CDP): sta tra
  // il PC e il gateway, se il PC è collegato con il cavo.
  const sp = primary?.kind === 'ethernet' ? switchPort(scan) : undefined;
  let swNode: MapNode | undefined;
  if (sp) {
    const why = `annuncia sé stesso con ${sp.protocol} sulla porta del PC: porta ${sp.port ?? 'non indicata'}${sp.vlan ? `, VLAN ${sp.vlan}` : ''}`;
    const existing = sp.mgmt ? byIp.get(sp.mgmt) : undefined;
    if (existing && existing !== gwNode && !existing.self) {
      swNode = existing;
      swNode.kind = 'switch';
      swNode.confidence = 'alta';
      swNode.reasons = [why, ...swNode.reasons];
    } else {
      swNode = {
        id: `sw:${sp.name}`,
        kind: 'switch',
        label: sp.name.split('.')[0],
        ip: sp.mgmt,
        names: [sp.name],
        confidence: 'alta',
        reasons: [why],
        segment: localSeg.id,
        inferred: true,
        roles: [],
        signals: sp.model ? [sp.model] : [],
        x: 0,
        y: 0,
      };
      nodes.push(swNode);
      // L'indirizzo di gestione appartiene a questo switch: non diventa un altro nodo.
      if (sp.mgmt && !hosts.has(sp.mgmt)) {
        hosts.set(sp.mgmt, { ip: sp.mgmt, name: sp.name });
        byIp.set(sp.mgmt, swNode);
      }
    }
    if (sp.port) swNode.roles.push(`porta ${sp.port}`);
  }

  // Wi-Fi: l'access point a cui è collegato il PC.
  const conn = primary?.kind === 'wifi' ? scan.wifi?.connected : undefined;
  const connBssid = conn?.bssid;
  let apNode: MapNode | undefined;
  if (conn && connBssid) {
    const gwNear = gwNode?.mac && nearBssid(gwNode.mac, [connBssid]);
    if (gwNode && (gwNear || gwNode.mac?.toLowerCase() === connBssid.toLowerCase())) {
      apNode = gwNode;
      gwNode.roles.push(`Wi-Fi «${conn.ssid}»`);
      gwNode.reasons = [...gwNode.reasons, `trasmette anche la rete Wi-Fi «${conn.ssid}» del PC`];
    } else {
      apNode = nodes.find((n) => n.segment === localSeg.id && n.kind === 'ap' && !!n.mac && !!nearBssid(n.mac, [connBssid]));
      if (!apNode) {
        apNode = {
          id: `ap:${conn.bssid}`,
          kind: 'ap',
          label: 'Access point',
          mac: conn.bssid,
          names: [],
          confidence: 'alta',
          reasons: [`il PC è collegato alla rete Wi-Fi «${conn.ssid}» trasmessa da qui (BSSID ${conn.bssid})`],
          segment: localSeg.id,
          inferred: true,
          roles: [],
          signals: [],
          x: 0,
          y: 0,
        };
        nodes.push(apNode);
      }
      apNode.roles.push(`Wi-Fi «${conn.ssid}»`);
    }
  }

  // Altre reti Wi-Fi trasmesse dagli stessi access point: di solito VLAN separate.
  const ownAps = nodes.filter((n) => n.kind === 'ap' || n === apNode).map((n) => n.mac).filter((m): m is string => !!m);
  const ownBssids = conn?.bssid ? [conn.bssid, ...ownAps] : ownAps;
  const otherSsids = new Map<string, string>();
  for (const b of scan.wifi?.networks ?? []) {
    if (b.ssid === conn?.ssid) continue;
    const own = ownBssids.some((x) => x.toLowerCase() === b.bssid.toLowerCase()) || !!nearBssid(b.bssid, ownBssids);
    if (own && !otherSsids.has(b.ssid)) otherSsids.set(b.ssid, b.bssid);
  }
  for (const [ssid] of otherSsids) {
    segments.push({
      id: `seg:wifi:${ssid || 'nascosta'}`,
      label: ssid ? `Wi-Fi «${ssid}»` : 'Rete Wi-Fi nascosta',
      kind: 'wifi',
      sources: ['reti Wi-Fi degli stessi access point'],
      note: ssid
        ? 'Trasmessa dagli stessi access point della rete del PC: di solito è una VLAN separata.'
        : 'Rete senza nome trasmessa dagli stessi access point: spesso è riservata a dispositivi (medicali, telefoni, sensori).',
      x: 0,
      y: 0,
      w: 0,
      h: 0,
    });
  }

  // Altre sottoreti note: prima quelle con il prefisso esatto (rotte del PC),
  // poi i server DNS e DHCP e i servizi verificati, ognuno nella zona più
  // specifica che lo contiene o, se nessuna lo contiene, nella sua /24.
  const remote = new Map<string, { seg: MapSegment; ips: string[]; cidr: Cidr }>();
  const addSegment = (c: Cidr, source: string, extra: Partial<MapSegment> = {}) => {
    const key = cidrText(c);
    if (local && local.net === c.net && local.prefix === c.prefix) {
      if (localSeg.sources.indexOf(source) < 0) localSeg.sources.push(source);
      return undefined;
    }
    let r = remote.get(key);
    if (!r) {
      r = { seg: { id: `seg:${key}`, label: c.prefix < 22 ? `Reti ${key}` : `Rete ${key}`, subnet: key, kind: 'remote', sources: [], x: 0, y: 0, w: 0, h: 0, ...extra }, ips: [], cidr: c };
      remote.set(key, r);
      segments.push(r.seg);
    }
    if (r.seg.sources.indexOf(source) < 0) r.seg.sources.push(source);
    return r;
  };
  for (const rt of scan.lan?.routes ?? []) {
    const c = parseCidr(rt.prefix);
    if (!c || privateKind(numIp(c.net)) !== 'private' || c.prefix < 8) continue;
    addSegment(c, rt.origin === 'dhcp' ? 'rotta ricevuta dal DHCP' : 'tabella di instradamento del PC');
  }
  // Reti scoperte (switch, Active Directory, SNMP, inventari): le zone hanno
  // il numero e il nome della VLAN. Gli aggregati (una /16 che contiene reti
  // già note) e le /24 presunte dai soli server non diventano zone.
  const named = new Set<string>();
  for (const n of nets) {
    if (n.local || !n.prefix || n.contains || n.guessed) continue;
    const c = parseCidr(n.prefix);
    if (!c || privateKind(numIp(c.net)) !== 'private') continue;
    let r: ReturnType<typeof addSegment>;
    for (const x of n.sources) r = addSegment(c, x) ?? r;
    if (!r) continue;
    if (n.vlan) r.seg.vlan = n.vlan;
    if (n.vlan || n.name) r.seg.label = `${netLabel(n)} · ${n.prefix}`;
    else if (n.site) r.seg.label = `Sito ${n.site} · ${n.prefix}`;
    if (n.vlan || n.name || n.site) named.add(r.seg.id);
  }
  const addRemote = (ip: string, source: string) => {
    if (!ip || hosts.has(ip) || ipNum(ip) === undefined || privateKind(ip) !== 'private') return;
    if (local && inCidr(ip, local)) return;
    let best: { seg: MapSegment; ips: string[]; cidr: Cidr } | undefined;
    for (const r of remote.values()) if (inCidr(ip, r.cidr) && (!best || r.cidr.prefix > best.cidr.prefix)) best = r;
    const r = best ?? addSegment(by24(ip), source)!;
    if (r.seg.sources.indexOf(source) < 0) r.seg.sources.push(source);
    if (r.seg.sources.indexOf(source) < 0) r.seg.sources.push(source);
    if (r.ips.indexOf(ip) < 0) {
      r.ips.push(ip);
      hosts.set(ip, { ip });
      nodeOf({ ip }, r.seg.id);
    }
  };
  for (const d of dnsServers) addRemote(d, 'server DNS del PC');
  if (dhcpServer) addRemote(dhcpServer, 'server DHCP del PC');
  for (const r of scan.infra?.reach?.results ?? []) if (r.ip) addRemote(r.ip, r.expect === 'reachable' ? 'servizi critici verificati' : 'test di segmentazione');
  for (const r of remote.values()) {
    const v = r.ips.map((ip) => vlanIn(labels[ip])).find((x) => x !== undefined);
    if (!named.has(r.seg.id)) {
      if (v) r.seg.vlan = v;
      if (r.seg.sources.some((s) => /DNS|DHCP/.test(s))) r.seg.label = `Server · ${r.seg.subnet}`;
      else if (v) r.seg.label = `VLAN ${v} · ${r.seg.subnet}`;
    }
    // Nome dei nodi remoti: il servizio verificato o il ruolo.
    for (const ip of r.ips) {
      const n = byIp.get(ip)!;
      const res = (scan.infra?.reach?.results ?? []).find((x) => x.ip === ip);
      if (res?.label) n.label = res.label;
      else if (n.roles.length) n.label = `Server ${n.roles.join(' e ')}`;
      if (res) {
        n.rttMs = res.rttMs;
        if (res.expect === 'isolated') {
          n.reasons = [...n.reasons, res.ok ? 'dal PC non risponde, come previsto (zona isolata)' : 'risponde dal PC anche se dovrebbe essere isolato'];
          n.sev = res.ok ? 'ok' : 'crit';
        } else n.sev = res.ok ? 'ok' : 'crit';
      }
    }
  }

  // Dispositivi noti nelle altre reti: dagli inventari fatti attraverso il
  // router (con nomi e tempi) e dalla tabella ARP letta via SNMP (con il MAC).
  const remoteInv = new Map<string, InventoryHost>();
  for (const i of scan.infra?.remote ?? []) for (const h of i.hosts) if (!h.self) remoteInv.set(h.ip, h);
  const arpMac = new Map<string, string>();
  for (const r of disc?.snmp ?? []) for (const a of r.arp) if (!arpMac.has(a.ip)) arpMac.set(a.ip, a.mac);
  let hidden = 0;
  for (const n of nets) {
    if (n.local || !n.prefix) continue;
    const r = remote.get(n.prefix);
    if (!r) continue;
    const fresh = n.hosts.filter((ip) => !hosts.has(ip));
    for (const ip of fresh.slice(0, MAX_DISCOVERED)) {
      const known = remoteInv.get(ip);
      const mac = known?.mac ?? arpMac.get(ip);
      const h: InventoryHost = {
        ...(known ?? { ip }),
        ...(mac ? { mac, randomMac: /^.[26ae]/i.test(mac) } : {}),
        ...(!known?.name && neighborNames[ip] ? { name: neighborNames[ip] } : {}),
      };
      hosts.set(ip, h);
      r.ips.push(ip);
      nodeOf(h, r.seg.id);
    }
    hidden += Math.max(0, fresh.length - MAX_DISCOVERED);
  }
  if (hidden) notes.push(`Nelle altre reti ci sono altri ${hidden} dispositivi noti: l'elenco completo è in Infrastruttura, nella scheda Reti e VLAN.`);

  // Catena verso Internet: altri router privati (doppio NAT), operatore, Internet.
  const links: MapLink[] = [];
  const flows: MapFlow[] = [];
  const chain: MapNode[] = [];
  const hops = scan.internet?.traceroute ?? [];
  const gi = gwIp ? hops.findIndex((h) => h.ip === gwIp) : -1;
  const after = hops.slice(gi + 1).filter((h) => h.ip);
  // Un indirizzo privato subito dopo il gateway è un secondo router di casa o
  // dell'ufficio (doppio NAT) se risponde quasi subito; con qualche millisecondo
  // in più sta oltre la linea, cioè nella rete dell'operatore.
  const gwHopRtt = gi >= 0 ? hops[gi].rttMs : undefined;
  const first = after[0];
  const secondRouter =
    first && privateKind(first.ip) === 'private' && first.rttMs !== undefined && gwHopRtt !== undefined && first.rttMs - gwHopRtt < 3 ? first : undefined;
  if (secondRouter) {
    const h = secondRouter;
    const n: MapNode = {
      id: `ip:${h.ip}`,
      kind: 'router',
      label: 'Secondo router',
      ip: h.ip,
      names: [],
      confidence: 'media',
      reasons: ['il traceroute passa da un altro indirizzo privato dopo il gateway: due router in fila (doppio NAT)'],
      segment: 'core',
      inferred: true,
      roles: [],
      rttMs: h.rttMs,
      signals: [],
      x: 0,
      y: 0,
    };
    nodes.push(n);
    chain.push(n);
  }
  let isp: MapNode | undefined;
  let inet: MapNode | undefined;
  if (scan.internet) {
    const pub = after.filter((h) => h !== secondRouter);
    const cg = after.some((h) => privateKind(h.ip) === 'cgnat');
    const priv = pub.some((h) => privateKind(h.ip) === 'private');
    if (pub.length) {
      isp = {
        id: 'isp',
        kind: 'isp',
        label: 'Operatore',
        names: [],
        confidence: 'alta',
        reasons: [
          `${pub.length} ${pub.length === 1 ? 'salto' : 'salti'} del traceroute nella rete dell'operatore` +
            (cg ? ', anche nello spazio condiviso 100.64.0.0/10 (NAT dell\'operatore, CGNAT)' : '') +
            (priv ? '; i primi apparati dell\'operatore hanno indirizzi privati, come succede spesso' : ''),
        ],
        segment: 'core',
        roles: [],
        rttMs: pub[0].rttMs,
        signals: [],
        x: 0,
        y: 0,
      };
      nodes.push(isp);
      chain.push(isp);
    }
    const t0 = scan.internet.targets?.find((t) => t.received > 0 && t.avgMs !== undefined);
    inet = {
      id: 'internet',
      kind: 'internet',
      label: 'Internet',
      names: [],
      confidence: 'alta',
      reasons: t0 && t0.avgMs !== undefined ? [`${t0.label ?? t0.target} risponde in ${fmtMs(t0.avgMs)} di media`] : ['nessuna destinazione su Internet ha risposto'],
      segment: 'core',
      roles: [],
      rttMs: t0?.avgMs,
      sev: sevOf(analysis, 'net.loss', 'net.latency'),
      signals: [],
      x: 0,
      y: 0,
    };
    nodes.push(inet);
    chain.push(inet);
  }

  // Collegamenti.
  const self = nodes.find((n) => n.self);
  const link = (from: MapNode | undefined, to: MapNode | undefined, kind: LinkKind, extra: Partial<MapLink> = {}) => {
    if (!from || !to || from === to) return;
    links.push({ id: `${from.id}>${to.id}`, from: from.id, to: to.id, kind, ...extra });
  };
  const gwRtt = scan.gateway?.ping && scan.gateway.ping.received > 0 ? scan.gateway.ping.avgMs : undefined;
  if (self && swNode) {
    link(self, swNode, 'cable', { label: sp?.port, sev: sevOf(analysis, 'lan.switchport') });
    link(swNode, gwNode, 'cable', { inferred: true, label: gwRtt !== undefined ? fmtMs(gwRtt) : undefined });
  } else if (self && apNode && apNode !== gwNode) {
    link(self, apNode, 'wifi', { sev: sevOf(analysis, 'wifi.rssi'), label: conn?.rssiDbm !== undefined ? `${conn.rssiDbm} dBm` : undefined });
    link(apNode, gwNode, 'cable', { inferred: true });
  } else if (self && gwNode) {
    link(self, gwNode, apNode === gwNode ? 'wifi' : 'cable', {
      sev: sevOf(analysis, 'lan.gwloss', 'lan.gwlatency', apNode === gwNode ? 'wifi.rssi' : 'lan.gwloss'),
      label: gwRtt !== undefined ? fmtMs(gwRtt) : undefined,
    });
  }
  for (const n of nodes) {
    if (n.segment !== localSeg.id || n === self || n === apNode || n === swNode) continue;
    links.push({ id: `${n.id}>lan`, from: n.id, to: localSeg.id, kind: 'lan' });
  }
  for (const s of segments) {
    if (s.kind === 'remote') links.push({ id: `${s.id}>gw`, from: s.id, to: gwNode?.id ?? 'internet', kind: 'routed' });
    if (s.kind === 'wifi') links.push({ id: `${s.id}>ap`, from: s.id, to: apNode?.id ?? gwNode?.id ?? localSeg.id, kind: 'wifi', inferred: true });
  }
  let prev = gwNode;
  for (const c of chain) {
    link(prev, c, c.kind === 'internet' ? 'internet' : 'cable', c.kind === 'internet' ? { sev: c.sev, label: c.rttMs !== undefined ? fmtMs(c.rttMs) : undefined } : {});
    prev = c;
  }

  // Percorsi del traffico di questo PC.
  const toGw: string[] = self ? (swNode ? [self.id, swNode.id] : apNode && apNode !== gwNode ? [self.id, apNode.id] : [self.id]) : [];
  if (gwNode) toGw.push(gwNode.id);
  if (self && inet) {
    flows.push({
      id: 'flow:internet',
      label: 'Verso Internet',
      kind: 'internet',
      path: [...toGw, ...chain.map((c) => c.id)],
      sev: sevOf(analysis, 'net.loss', 'net.latency') ?? 'ok',
      note: inet.rttMs !== undefined ? `Internet risponde in ${fmtMs(inet.rttMs)} di media.` : 'Internet non ha risposto alle misure.',
      rttMs: inet.rttMs,
    });
  }
  const dns = dnsServers.map((d) => byIp.get(d)).find((n): n is MapNode => !!n);
  if (self && dns) {
    const path = dns === gwNode ? toGw : dns.segment === localSeg.id ? [self.id, dns.id] : [...toGw, dns.id];
    flows.push({ id: 'flow:dns', label: 'Risoluzione dei nomi (DNS)', kind: 'dns', path, sev: sevOf(analysis, 'dns.time') ?? 'ok', note: `Il PC chiede i nomi a ${dns.ip}${dns === gwNode ? ', cioè al router' : ''}.` });
  }
  for (const r of scan.infra?.reach?.results ?? []) {
    const n = r.ip ? byIp.get(r.ip) : undefined;
    if (!self || !n) continue;
    const path = n.segment === localSeg.id ? [self.id, n.id] : [...toGw, n.id];
    if (r.expect === 'isolated') {
      flows.push({
        id: `flow:${r.ip}:${r.port ?? 0}`,
        label: r.label ?? r.host,
        kind: 'blocked',
        path,
        sev: r.ok ? 'ok' : 'crit',
        note: r.ok ? 'Bloccato dal firewall o dalle regole tra le zone, come previsto.' : 'Raggiungibile anche se dovrebbe essere isolato: le regole tra le zone vanno riviste.',
      });
    } else {
      flows.push({
        id: `flow:${r.ip}:${r.port ?? 0}`,
        label: r.label ?? r.host,
        kind: 'service',
        path,
        sev: r.ok ? 'ok' : 'crit',
        note: r.ok ? `Risponde${r.rttMs !== undefined ? ` in ${fmtMs(r.rttMs)}` : ''}.` : 'Non risponde: il servizio o le regole di rete vanno controllati.',
        rttMs: r.rttMs,
      });
    }
  }

  notes.push('Le linee animate mostrano da dove passa il traffico di questo PC: Polaris non vede il traffico degli altri dispositivi.');

  const counts: Partial<Record<DeviceKind, number>> = {};
  for (const n of nodes) if (n.kind !== 'internet' && n.kind !== 'isp') counts[n.kind] = (counts[n.kind] ?? 0) + 1;

  const map: NetworkMap = { nodes, segments, links, flows, width: 0, height: 0, notes, counts, fromInventory: !!inv };
  layoutMap(map);
  return map;
}

// ---------------------------------------------------------------- disposizione

/** Larghezza e altezza di una cella della griglia dei dispositivi. */
export const CELL_W = 114;
export const CELL_H = 100;
/** Distanza della linea di raccolta di una zona dal suo bordo superiore. */
export const ZONE_BUS = 30;
const ZONE_PAD = 16;
const ZONE_HEAD = 44;
const ZONE_GAP_Y = 34;
const BB_GAP = 58;
const CORE_STEP = 96;
const MARGIN = 40;

const kindRank = (k: DeviceKind) => {
  const i = KIND_ORDER.indexOf(k);
  return i < 0 ? 99 : i;
};

/**
 * Calcola le posizioni. In alto la catena verso Internet (Internet, operatore,
 * eventuale secondo router, gateway); sotto il gateway una dorsale verticale da
 * cui partono i rami verso le zone, disposte a sinistra e a destra: le linee
 * non attraversano mai una zona. Con una sola zona, la zona sta al centro.
 */
export function layoutMap(map: NetworkMap): void {
  // Prima gli apparati di rete, poi questo PC, poi gli altri per tipo e indirizzo.
  const infra = (n: MapNode) => (n.kind === 'router' || n.kind === 'firewall' || n.kind === 'switch' || n.kind === 'ap' ? 0 : n.self ? 1 : 2);
  const segNodes = (id: string) =>
    map.nodes
      .filter((n) => n.segment === id)
      .sort((a, b) => infra(a) - infra(b) || kindRank(a.kind) - kindRank(b.kind) || (ipNum(a.ip) ?? 0) - (ipNum(b.ip) ?? 0) || a.label.localeCompare(b.label));
  for (const s of map.segments) {
    const n = segNodes(s.id).length;
    const maxCols = s.kind === 'local' ? 8 : 4;
    const cols = s.kind === 'wifi' ? 1 : Math.max(1, Math.min(maxCols, Math.ceil(Math.sqrt(n * (s.kind === 'local' ? 2.6 : 1.6)))));
    const rows = s.kind === 'wifi' ? 1 : Math.max(1, Math.ceil(n / cols));
    s.w = Math.max(s.kind === 'wifi' ? 220 : 240, cols * CELL_W + ZONE_PAD * 2);
    s.h = s.kind === 'wifi' ? 96 : ZONE_HEAD + rows * CELL_H + ZONE_PAD - 8;
  }
  const order = map.segments.slice().sort((a, b) => ['local', 'remote', 'wifi'].indexOf(a.kind) - ['local', 'remote', 'wifi'].indexOf(b.kind));
  const left: MapSegment[] = [];
  const right: MapSegment[] = [];
  let hl = 0;
  let hr = 0;
  for (const s of order) {
    if (s.kind === 'local' || hl <= hr) {
      left.push(s);
      hl += s.h + ZONE_GAP_Y;
    } else {
      right.push(s);
      hr += s.h + ZONE_GAP_Y;
    }
  }
  const single = order.length === 1;
  const leftW = Math.max(0, ...left.map((s) => s.w));
  const rightW = Math.max(0, ...right.map((s) => s.w));
  const cx = single ? MARGIN + Math.max(leftW, 300) / 2 : MARGIN + leftW + BB_GAP;
  const width = single ? MARGIN * 2 + Math.max(leftW, 300) : cx + BB_GAP + Math.max(rightW, 160) + MARGIN;

  // Catena in alto: Internet, operatore, secondo router, gateway.
  const core = map.nodes.filter((n) => n.segment === 'core');
  const chain = ['internet', 'isp'].map((k) => core.find((n) => n.kind === k)).filter((n): n is MapNode => !!n);
  const others = core.filter((n) => n.kind !== 'internet' && n.kind !== 'isp' && !n.gateway);
  const gw = core.find((n) => n.gateway);
  const column = [...chain, ...others, ...(gw ? [gw] : [])];
  let y = 54;
  for (const n of column) {
    n.x = cx;
    n.y = y;
    y += CORE_STEP;
  }
  const top = column.length ? y - CORE_STEP + 78 : MARGIN;

  const place = (s: MapSegment, x: number, yy: number, side: 'left' | 'right' | 'center') => {
    s.x = x;
    s.y = yy;
    s.side = side;
    if (side === 'center') {
      s.ex = cx;
      s.ey = yy;
    } else {
      s.ex = side === 'left' ? x + s.w : x;
      s.ey = yy + ZONE_BUS;
    }
    const ns = segNodes(s.id);
    const cols = Math.max(1, Math.floor((s.w - ZONE_PAD * 2) / CELL_W));
    const used = Math.min(cols, Math.max(1, ns.length));
    const ox = s.x + (s.w - used * CELL_W) / 2;
    ns.forEach((n, i) => {
      n.x = ox + (i % cols) * CELL_W + CELL_W / 2;
      n.y = s.y + ZONE_HEAD + Math.floor(i / cols) * CELL_H + CELL_H / 2 - 10;
    });
  };
  let bottom = top;
  if (single) {
    const s = order[0];
    place(s, cx - s.w / 2, top, 'center');
    bottom = s.y + s.h;
  } else {
    let yl = top;
    for (const s of left) {
      place(s, cx - BB_GAP - s.w, yl, 'left');
      yl += s.h + ZONE_GAP_Y;
    }
    let yr = top;
    for (const s of right) {
      place(s, cx + BB_GAP, yr, 'right');
      yr += s.h + ZONE_GAP_Y;
    }
    bottom = Math.max(yl, yr) - ZONE_GAP_Y;
  }
  map.width = width;
  map.height = bottom + MARGIN;
  map.backbone = { x: cx, y1: gw ? gw.y : top, y2: Math.max(top, ...map.segments.map((s) => s.ey ?? top)) };
}
