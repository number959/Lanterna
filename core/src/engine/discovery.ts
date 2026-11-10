import { primaryAdapter } from './adapters';
import { fmt, more, num, thousands } from './fmt';
import { cidrText, inCidr, ipNum, parseCidr, privateKind } from './cidr';
import type { Cidr } from './cidr';
import type { Adapter, Finding, L2Discovery, ReachTarget, Scan, Severity, SnmpResult } from './types';

// Scoperta delle altre reti e delle VLAN: unisce quello che dicono la tabella
// di instradamento del PC, gli annunci dello switch (LLDP, CDP, Spanning
// Tree), Active Directory, le letture SNMP del tecnico e gli inventari fatti
// attraverso il router in un solo elenco di reti, con la fonte di ogni
// informazione. Da qui partono i giudizi sulla porta dello switch, su DTP,
// sulla VLAN 1, sullo Spanning Tree e sulla configurazione SNMP, e le
// destinazioni proposte per il test di segmentazione.
// Gira anche in goja: niente Intl.

/** Una rete o una VLAN nota, con le fonti che la indicano. */
export interface DiscoveredNet {
  /** Chiave stabile: il prefisso o "vlan:N". */
  key: string;
  /** Rete in notazione CIDR, se nota. */
  prefix?: string;
  /** Numero della VLAN, se noto. */
  vlan?: number;
  /** Nome della VLAN, come lo annunciano lo switch o SNMP. */
  name?: string;
  /** È la rete di questo PC. */
  local?: boolean;
  /** VLAN della voce (telefoni). */
  voice?: boolean;
  /** Sito di Active Directory a cui appartiene la sottorete. */
  site?: string;
  /** Indirizzi di router o switch in questa rete (interfacce lette via SNMP). */
  routers: string[];
  /** Server DNS o DHCP del PC che stanno in questa rete. */
  servers: string[];
  /** Dispositivi noti in questa rete (inventario, tabella ARP via SNMP), senza router e server. */
  hosts: string[];
  /** Da dove viene l'informazione, in italiano. */
  sources: string[];
  /** Prefisso /24 presunto: si conosce solo l'indirizzo di un server. */
  guessed?: boolean;
  /** Il prefisso contiene altre reti note (aggregato, per esempio una /16 di un sito). */
  contains?: number;
}

/** Nome breve di una rete: "VLAN 30 Medicali", "Rete 10.0.5.0/24". */
export function netLabel(n: DiscoveredNet): string {
  if (n.vlan) return `VLAN ${n.vlan}${n.name ? ` ${n.name}` : ''}`;
  if (n.name) return n.name;
  return n.prefix ? `Rete ${n.prefix}` : 'Rete';
}

const pushU = (list: string[], v: string | undefined) => {
  if (v && list.indexOf(v) < 0) list.push(v);
};

const byIp = (a: string, b: string) => (ipNum(a) ?? 0) - (ipNum(b) ?? 0);

/** Ultima lettura dello switch con almeno un annuncio. */
function l2Of(scan: Scan): L2Discovery | undefined {
  const l2 = scan.infra?.discovery?.l2;
  return l2 && l2.read === 'ok' ? l2 : undefined;
}

/** Porta dello switch a cui è collegato il PC, dagli annunci LLDP o CDP. */
export interface SwitchPort {
  /** Nome dello switch (o identificativo dello chassis). */
  name: string;
  port?: string;
  /** VLAN non etichettata della porta (PVID o VLAN nativa). */
  vlan?: number;
  voiceVlan?: number;
  /** VLAN con nome annunciate sulla porta. */
  vlans: { id: number; name?: string }[];
  mgmt?: string;
  model?: string;
  speedMbps?: number;
  duplex?: string;
  mau?: string;
  protocol: 'LLDP' | 'CDP';
  /** Il dispositivo annuncia anche funzioni di router o di access point. */
  capabilities: string[];
  /** Nome della scheda del PC che ha ricevuto l'annuncio. */
  adapter?: string;
}

export function switchPort(scan: Scan): SwitchPort | undefined {
  const l2 = l2Of(scan);
  if (!l2) return undefined;
  const l = (l2.lldp ?? []).find((n) => n.ttl > 0) ?? l2.lldp?.[0];
  const c = l2.cdp?.[0];
  if (l) {
    return {
      name: l.systemName || c?.deviceId || l.chassisId,
      port: l.portId || c?.portId,
      vlan: l.portVlanId ?? c?.nativeVlan,
      voiceVlan: l.voiceVlan ?? c?.voiceVlan,
      vlans: l.vlans ?? [],
      mgmt: l.managementAddresses?.[0] ?? c?.managementAddresses?.[0],
      model: l.systemDescription || c?.platform,
      speedMbps: l.speedMbps,
      duplex: l.duplex ?? c?.duplex,
      mau: l.mau,
      protocol: 'LLDP',
      capabilities: l.capabilities ?? [],
      adapter: l.adapter,
    };
  }
  if (c) {
    return {
      name: c.systemName || c.deviceId,
      port: c.portId,
      vlan: c.nativeVlan,
      voiceVlan: c.voiceVlan,
      vlans: [],
      mgmt: c.managementAddresses?.[0] ?? c.addresses?.[0],
      model: c.platform,
      duplex: c.duplex,
      protocol: 'CDP',
      capabilities: c.capabilities ?? [],
      adapter: c.adapter,
    };
  }
  return undefined;
}

/** VLAN viste negli annunci dello Spanning Tree per VLAN (PVST+): sono quelle che passano sul collegamento. */
function stpVlans(l2: L2Discovery | undefined): number[] {
  const out: number[] = [];
  for (const s of l2?.stp ?? []) if (s.format === 'pvst' && s.vlan && out.indexOf(s.vlan) < 0) out.push(s.vlan);
  return out.sort((a, b) => a - b);
}

const snmpLabel = (r: SnmpResult) => `SNMP ${r.system?.name ?? r.target}`;

/**
 * Tutte le reti e le VLAN note, la rete del PC per prima. Le VLAN di cui non
 * si conosce la sottorete restano voci a sé; quando una fonte collega numero
 * e sottorete (un'interfaccia letta via SNMP) le voci si uniscono.
 */
export function discoveredNets(scan: Scan, primary: Adapter | undefined = primaryAdapter(scan)): DiscoveredNet[] {
  const nets: DiscoveredNet[] = [];
  const byKey = new Map<string, DiscoveredNet>();
  const cidrs = new Map<DiscoveredNet, Cidr>();

  const byPrefix = (c: Cidr, source: string): DiscoveredNet => {
    const key = cidrText(c);
    let n = byKey.get(key);
    if (!n) {
      n = { key, prefix: key, routers: [], servers: [], hosts: [], sources: [] };
      byKey.set(key, n);
      cidrs.set(n, c);
      nets.push(n);
    }
    pushU(n.sources, source);
    return n;
  };
  const byVlan = (id: number, source: string, name?: string): DiscoveredNet => {
    let n = nets.find((x) => x.vlan === id);
    if (!n) {
      n = { key: `vlan:${id}`, vlan: id, routers: [], servers: [], hosts: [], sources: [] };
      byKey.set(n.key, n);
      nets.push(n);
    }
    if (name && !n.name) n.name = name;
    pushU(n.sources, source);
    return n;
  };
  /** Assegna la VLAN a una rete con prefisso, assorbendo l'eventuale voce della sola VLAN. */
  const setVlan = (n: DiscoveredNet, id: number) => {
    if (n.vlan === id) return;
    const only = nets.find((x) => x.vlan === id && !x.prefix);
    if (only) {
      if (!n.name && only.name) n.name = only.name;
      if (only.voice) n.voice = true;
      for (const s of only.sources) pushU(n.sources, s);
      nets.splice(nets.indexOf(only), 1);
      byKey.delete(only.key);
    }
    if (!n.vlan) n.vlan = id;
  };
  /** Rete più specifica che contiene l'indirizzo. */
  const containing = (ip: string): DiscoveredNet | undefined => {
    let best: DiscoveredNet | undefined;
    for (const n of nets) {
      const c = cidrs.get(n);
      if (c && inCidr(ip, c) && (!best || c.prefix > cidrs.get(best)!.prefix)) best = n;
    }
    return best;
  };
  const usable = (c: Cidr | undefined) => !!c && c.prefix >= 8 && c.prefix <= 30 && privateKind(cidrText(c).split('/')[0]) !== 'public';

  // Rete del PC.
  const local = parseCidr(primary?.ipv4[0]);
  if (local) {
    const n = byPrefix(local, 'rete di questo PC');
    n.local = true;
  }
  const wired = primary?.kind === 'ethernet';

  // Annunci dello switch sulla porta del PC.
  const l2 = l2Of(scan);
  const sp = switchPort(scan);
  if (sp) {
    const src = `annunci dello switch (${sp.protocol})`;
    if (sp.vlan) {
      const localNet = nets.find((x) => x.local);
      if (wired && localNet) {
        setVlan(localNet, sp.vlan);
        pushU(localNet.sources, src);
      } else byVlan(sp.vlan, src);
    }
    for (const v of sp.vlans) byVlan(v.id, src, v.name);
    if (sp.voiceVlan) {
      const v = byVlan(sp.voiceVlan, src);
      v.voice = true;
    }
  }
  for (const id of stpVlans(l2)) byVlan(id, 'Spanning Tree per VLAN (PVST+)');

  // Tabella di instradamento del PC.
  for (const rt of scan.lan?.routes ?? []) {
    const c = parseCidr(rt.prefix);
    if (!usable(c)) continue;
    byPrefix(c!, rt.origin === 'dhcp' ? 'rotta ricevuta dal DHCP' : 'tabella di instradamento del PC');
  }

  // Active Directory.
  const ad = scan.infra?.discovery?.ad;
  if (ad?.read === 'ok') {
    for (const s of ad.subnets ?? []) {
      const c = parseCidr(s.prefix);
      if (!usable(c)) continue;
      const n = byPrefix(c!, 'Active Directory');
      if (s.site && !n.site) n.site = s.site;
    }
  }

  // Letture SNMP: reti delle interfacce, VLAN configurate, tabella ARP.
  const snmp = scan.infra?.discovery?.snmp ?? [];
  for (const r of snmp) {
    const src = snmpLabel(r);
    for (const i of r.interfaces) {
      for (const ip of i.ips) {
        const c = parseCidr(ip.subnet);
        if (!usable(c)) continue;
        const n = byPrefix(c!, src);
        pushU(n.routers, ip.ip);
        if (i.vlanId) setVlan(n, i.vlanId);
      }
    }
    for (const v of r.vlans) {
      // La VLAN 1 esiste su ogni switch e le 1002-1005 sono le VLAN di
      // servizio degli switch Cisco: contano solo se usate davvero.
      if (v.id < 1 || v.id > 4094 || (v.id >= 1002 && v.id <= 1005)) continue;
      if (v.id === 1 && !nets.some((x) => x.vlan === 1)) continue;
      const n = byVlan(v.id, src, v.name);
      if (v.name && !n.name) n.name = v.name;
    }
  }
  for (const r of snmp) {
    for (const a of r.arp) {
      const n = containing(a.ip);
      if (n && !n.local && n.routers.indexOf(a.ip) < 0) pushU(n.hosts, a.ip);
    }
  }

  // Inventari di altre sottoreti, fatti attraverso il router.
  for (const inv of scan.infra?.remote ?? []) {
    const c = parseCidr(inv.subnet);
    if (!usable(c)) continue;
    const n = byPrefix(c!, 'inventario attraverso il router');
    for (const h of inv.hosts) if (!h.self) pushU(n.hosts, h.ip);
  }

  // Server DNS e DHCP del PC in altre reti: se nessuna rete nota li contiene,
  // si ipotizza la loro /24.
  const servers: [string, string][] = [];
  for (const d of primary?.dns ?? []) servers.push([d, 'server DNS del PC']);
  if (primary?.dhcpServer) servers.push([primary.dhcpServer, 'server DHCP del PC']);
  for (const [ip, src] of servers) {
    if (ipNum(ip) === undefined || privateKind(ip) !== 'private' || (local && inCidr(ip, local))) continue;
    let n = containing(ip);
    if (!n) {
      n = byPrefix(parseCidr(`${ip}/24`)!, src);
      n.guessed = true;
    }
    pushU(n.sources, src);
    pushU(n.servers, ip);
  }

  for (const n of nets) {
    n.hosts = n.hosts.filter((h) => n.servers.indexOf(h) < 0 && n.routers.indexOf(h) < 0).sort(byIp);
    n.routers.sort(byIp);
    // Un prefisso che ne contiene altri noti (una /16 di Active Directory) è un aggregato.
    const c = cidrs.get(n);
    if (c) {
      const inside = nets.filter((x) => x !== n && cidrs.has(x) && cidrs.get(x)!.prefix > c.prefix && inCidr(x.prefix!.split('/')[0], c)).length;
      if (inside) n.contains = inside;
    }
  }
  return nets.sort((a, b) => {
    if (!!a.local !== !!b.local) return a.local ? -1 : 1;
    if (!!a.vlan !== !!b.vlan) return a.vlan ? -1 : 1;
    if (a.vlan && b.vlan && a.vlan !== b.vlan) return a.vlan - b.vlan;
    const pa = a.prefix ? (ipNum(a.prefix.split('/')[0]) ?? 0) : Infinity;
    const pb = b.prefix ? (ipNum(b.prefix.split('/')[0]) ?? 0) : Infinity;
    return pa - pb;
  });
}

/** Nomi tipici delle reti dei server e dei servizi condivisi. */
const SERVER_NET = /server|\bsrv|\bserv|\bced\b|data ?center|\bdmz\b|\bdati\b/i;

/** Destinazioni per ogni rete al massimo, e in tutto. */
const PER_NET = 2;
const MAX_PREFILL = 32;

/**
 * Destinazioni proposte per il test di segmentazione: per ogni altra rete
 * nota fino a due dispositivi (dall'inventario o dalla tabella ARP letta via
 * SNMP), da verificare come "deve essere isolata"; i server DNS in altre reti
 * come "deve rispondere" sulla porta 53. Le interfacce dei router non si
 * propongono: spesso rispondono al ping anche quando le regole tra le zone
 * funzionano. Il tecnico rivede l'elenco prima di avviare le verifiche.
 */
export function segmentationTargets(scan: Scan, nets: DiscoveredNet[] = discoveredNets(scan)): ReachTarget[] {
  const out: ReachTarget[] = [];
  const seen: string[] = [];
  const add = (t: ReachTarget) => {
    const k = `${t.host}:${t.port ?? 0}`;
    if (out.length >= MAX_PREFILL || seen.indexOf(k) >= 0) return;
    seen.push(k);
    out.push(t);
  };
  const dns = primaryAdapter(scan)?.dns ?? [];
  // Gli indirizzi già verificati come servizi che devono rispondere non si
  // propongono come da isolare, e nemmeno le reti dei server: lì si
  // verificano i servizi (porte) che devono rispondere, non l'isolamento.
  const needed: string[] = [];
  for (const r of scan.infra?.reach?.results ?? []) if (r.expect === 'reachable' && r.ip) needed.push(r.ip);
  for (const n of nets) {
    if (n.local) continue;
    const serverNet = n.servers.length > 0 || SERVER_NET.test(n.name ?? '');
    if (!serverNet) for (const ip of n.hosts.filter((h) => needed.indexOf(h) < 0).slice(0, PER_NET)) add({ label: netLabel(n), host: ip, expect: 'isolated' });
    for (const ip of n.servers) if (dns.indexOf(ip) >= 0) add({ label: `Server DNS (${netLabel(n)})`, host: ip, port: 53, expect: 'reachable' });
  }
  return out;
}

/** Reti note senza dispositivi da proporre: servono inventario o SNMP. */
export function netsWithoutTargets(nets: DiscoveredNet[]): DiscoveredNet[] {
  return nets.filter((n) => !n.local && n.prefix && !n.hosts.length && !n.guessed && !n.contains);
}

// ---------------------------------------------------------------- giudizi

type Add = (f: Omit<Finding, 'actions'> & { actions?: string[] }) => void;

const ADMIN_TEXT: Record<string, string> = {
  desirable: 'cerca attivamente di formare un trunk (dynamic desirable)',
  auto: 'diventa un trunk se l\'altro lato lo chiede (dynamic auto)',
  on: 'è fissata come trunk',
  off: 'è fissata come porta di accesso',
};

const speedText = (mbps: number) => (mbps >= 1000 ? `${fmt(mbps / 1000, mbps % 1000 ? 1 : 0)} Gb/s` : `${mbps} Mb/s`);

/** Priorità predefinita dello Spanning Tree (IEEE 802.1D/802.1Q). */
const STP_DEFAULT_PRIORITY = 32768;

export function analyzeDiscovery(scan: Scan, add: Add, primary: Adapter | undefined = primaryAdapter(scan)) {
  const disc = scan.infra?.discovery;
  const l2 = disc?.l2;

  // Porta dello switch.
  if (l2?.read === 'none') {
    add({
      id: 'lan.switchport',
      metric: 'lan.switchport',
      category: 'infra',
      title: 'Porta dello switch',
      value: 'nessun annuncio',
      severity: 'unknown',
      verdict: `In ${l2.seconds} secondi di ascolto lo switch non ha mandato annunci LLDP o CDP alla porta del PC: è uno switch non gestito, oppure i protocolli di scoperta sono disattivati sulle porte degli utenti (una scelta legittima). Switch, porta e VLAN vanno letti dalla configurazione o via SNMP.`,
    });
  }
  const sp = switchPort(scan);
  if (sp && l2) {
    const half = sp.duplex === 'half';
    const slow = sp.speedMbps !== undefined && sp.speedMbps <= 10;
    const sev: Severity = half || slow ? 'warn' : 'info';
    const parts: string[] = [`Il PC è collegato alla porta ${sp.port ?? 'non indicata'} di ${sp.name}${sp.model ? ` (${sp.model})` : ''}, annunciata con ${sp.protocol}.`];
    if (sp.vlan) parts.push(`La porta mette il PC nella VLAN ${sp.vlan}${sp.vlans.find((v) => v.id === sp.vlan)?.name ? ` (${sp.vlans.find((v) => v.id === sp.vlan)!.name})` : ''} senza etichetta.`);
    if (sp.voiceVlan) parts.push(`Per i telefoni è prevista la VLAN della voce ${sp.voiceVlan}.`);
    if (sp.speedMbps) parts.push(`Lo switch vede il collegamento a ${speedText(sp.speedMbps)}${sp.duplex ? `, ${sp.duplex === 'full' ? 'full duplex' : 'half duplex'}` : ''}${sp.mau ? ` (${sp.mau})` : ''}.`);
    if (half)
      parts.push(
        'Half duplex su un collegamento moderno indica di solito una negoziazione fallita (una delle due parti impostata a mano): rallentamenti ed errori, soprattutto sotto carico.',
      );
    else if (slow) parts.push('10 Mb/s è la velocità di un cavo danneggiato o di una porta impostata a mano: controllali.');
    else if (sp.speedMbps === 100) parts.push('A 100 Mb/s: se PC e switch arrivano a 1 Gb/s, il cavo potrebbe avere solo due coppie collegate o un difetto.');
    if (l2.counts.eapol > 0) parts.push('La porta chiede l\'autenticazione 802.1X: l\'accesso alla rete è controllato.');
    add({
      id: 'lan.switchport',
      metric: 'lan.switchport',
      category: 'infra',
      title: 'Porta dello switch',
      value: [sp.name, sp.port, sp.vlan ? `VLAN ${sp.vlan}` : undefined].filter(Boolean).join(' · '),
      severity: sev,
      numeric: sp.speedMbps,
      verdict: parts.join(' '),
      actions: half || slow ? ['check-duplex'] : [],
    });
  }

  // DTP: la porta del PC negozia il trunk.
  const dtp = l2?.read === 'ok' ? (l2.dtp ?? []) : [];
  if (dtp.length) {
    const d = dtp.find((x) => x.operStatus === 'trunk') ?? dtp.find((x) => x.adminStatus === 'desirable' || x.adminStatus === 'auto') ?? dtp[0];
    const trunk = d.operStatus === 'trunk';
    const dynamic = d.adminStatus === 'desirable' || d.adminStatus === 'auto';
    const sev: Severity = trunk ? 'crit' : dynamic ? 'warn' : 'info';
    add({
      id: 'lan.dtp',
      metric: 'lan.dtp',
      category: 'infra',
      title: 'Negoziazione del trunk (DTP)',
      value: trunk ? 'porta in trunk' : dynamic ? `modalità ${d.adminStatus}` : 'DTP attivo',
      severity: sev,
      verdict: trunk
        ? 'La porta a cui è collegato il PC è un trunk: da qui arrivano le trame di più VLAN. Una postazione non dovrebbe mai stare su un trunk: chiunque si colleghi a questa presa può raggiungere le altre VLAN.'
        : dynamic
          ? `La porta del PC manda annunci DTP e ${ADMIN_TEXT[d.adminStatus!]}: un dispositivo che si finge switch può trasformarla in un trunk e raggiungere tutte le VLAN (VLAN hopping).`
          : `La porta del PC manda annunci DTP${d.adminStatus && ADMIN_TEXT[d.adminStatus] ? ` e ${ADMIN_TEXT[d.adminStatus]}` : ''}: il rischio è basso, ma sulle porte degli utenti la negoziazione va spenta del tutto.`,
      actions: ['disable-dtp'],
    });
  }

  // VLAN 1 per le postazioni.
  const nets = discoveredNets(scan, primary);
  if (sp?.vlan === 1) {
    const others = nets.filter((n) => n.vlan && n.vlan !== 1).length;
    add({
      id: 'lan.vlan1',
      metric: 'lan.vlan1',
      category: 'infra',
      title: 'Postazione nella VLAN 1',
      value: 'VLAN 1',
      severity: others ? 'warn' : 'info',
      verdict: others
        ? `La porta del PC usa la VLAN 1, quella predefinita degli switch, mentre la rete ha anche altre VLAN (${others}): spesso la VLAN 1 porta anche il traffico di gestione degli apparati e i protocolli di controllo. Le postazioni vanno in una VLAN dedicata.`
        : 'La porta del PC usa la VLAN 1, quella predefinita degli switch. In una rete senza altre VLAN è normale; quando si divide la rete in zone, le postazioni vanno spostate in una VLAN dedicata.',
      actions: others ? ['move-off-vlan1'] : [],
    });
  }

  // Spanning Tree.
  const stp = l2?.read === 'ok' ? (l2.stp ?? []) : [];
  if (stp.length) {
    const s = stp.find((x) => x.format === 'ieee') ?? stp[0];
    const defaultRoot = s.rootPriority === STP_DEFAULT_PRIORITY;
    const legacy = s.protocol === 'stp';
    const tc = stp.some((x) => x.topologyChange);
    const isRoot = s.rootMac === s.bridgeMac && s.rootPathCost === 0;
    const proto = s.protocol === 'rstp' ? 'Rapid Spanning Tree (802.1w)' : s.protocol === 'mstp' ? 'Multiple Spanning Tree (802.1s)' : s.protocol === 'stp' ? 'Spanning Tree classico (802.1D)' : 'Spanning Tree';
    const parts = [
      `Sulla porta arrivano annunci ${proto}${s.format === 'pvst' || stp.some((x) => x.format === 'pvst') ? ' anche per VLAN (PVST+)' : ''}.`,
      isRoot
        ? `Lo switch del PC è la radice dell'albero (priorità ${s.rootPriority}).`
        : `La radice dell'albero è il bridge ${s.rootMac} con priorità ${s.rootPriority}${s.rootSysIdExt ? ` (più ${s.rootSysIdExt} di estensione, di solito il numero della VLAN)` : ''}, a costo ${s.rootPathCost} dallo switch del PC.`,
    ];
    if (defaultRoot)
      parts.push('La radice ha la priorità predefinita (32768): è stata scelta dal MAC più basso, cioè a caso. Conviene fissare come radice lo switch centrale, abbassandone la priorità.');
    if (legacy) parts.push('Lo Spanning Tree classico impiega 30-50 secondi a riattivare una porta dopo un guasto: le versioni rapide lo fanno in pochi secondi.');
    if (tc) parts.push('Durante l\'ascolto sono arrivati avvisi di cambio di topologia: se si ripetono spesso, una porta si accende e si spegne o c\'è un anello.');
    add({
      id: 'lan.stp',
      metric: 'lan.stp',
      category: 'infra',
      title: 'Spanning Tree',
      value: `${s.protocol.toUpperCase()} · radice ${s.rootPriority}`,
      severity: 'info',
      verdict: parts.join(' '),
      actions: defaultRoot || legacy ? ['stp-root'] : [],
    });
  }

  // Letture SNMP.
  for (const r of disc?.snmp ?? []) {
    const sev: Severity = r.defaultCommunity ? 'crit' : r.version === '2c' ? 'warn' : r.warnings?.length ? 'warn' : 'ok';
    const nIf = r.interfaces.reduce((t, i) => t + i.ips.length, 0);
    const read = [
      r.vlans.length ? num(r.vlans.length, 'VLAN', 'VLAN') : '',
      nIf ? num(nIf, 'rete', 'reti') : '',
      r.lldpNeighbors.length ? num(r.lldpNeighbors.length, 'vicino LLDP', 'vicini LLDP') : '',
      r.arp.length ? `${thousands(r.arp.length)} righe ARP` : '',
      r.fdb.length ? `${thousands(r.fdb.length)} MAC per porta` : '',
    ].filter(Boolean);
    const who = r.system?.name ? `${r.system.name} (${r.target})` : r.target;
    let verdict = `Letto in sola lettura con SNMPv${r.version}: ${read.length ? read.join(', ') : 'solo i dati generali'}.`;
    if (r.defaultCommunity)
      verdict += ' Il dispositivo accetta una community predefinita ("public" o "private"): chiunque nella rete può leggerne la configurazione, e con "private" spesso anche modificarla.';
    else if (r.version === '2c') verdict += ' SNMPv2c trasmette la community in chiaro: chi osserva il traffico la legge e la riusa.';
    for (const w of r.warnings ?? []) if (r.version === '3') verdict += ` ${w}`;
    if (r.stopped) verdict += ` Lettura fermata prima della fine: ${r.stopped}`;
    add({
      id: `lan.snmp.${r.target}`,
      metric: 'lan.snmp',
      category: 'infra',
      title: `SNMP di ${who}`,
      value: `SNMPv${r.version}${r.defaultCommunity ? ' · community predefinita' : ''}`,
      severity: sev,
      verdict,
      actions: sev === 'ok' ? [] : ['snmp-harden'],
    });
  }

  // Inventari di altre sottoreti.
  for (const inv of scan.infra?.remote ?? []) {
    const others = inv.hosts.filter((h) => !h.self);
    add({
      id: `infra.inventory.${inv.subnet}`,
      metric: 'infra.inventory',
      category: 'infra',
      title: `Inventario di ${inv.subnet}`,
      value: `${others.length} ${others.length === 1 ? 'dispositivo' : 'dispositivi'}`,
      numeric: others.length,
      severity: 'info',
      verdict:
        `Attraverso il router, ${others.length === 1 ? 'un dispositivo della rete risponde' : `${others.length} dispositivi della rete rispondono`} al ping da questo PC.` +
        (others.length
          ? ' Se questa rete dovrebbe essere isolata da quella del PC è già un segnale da verificare con il test di segmentazione.'
          : ' Nessuna risposta: la rete è vuota, oppure le regole tra le zone bloccano il ping da qui.') +
        (inv.note ? ` ${inv.note}` : ''),
      actions: others.length ? ['test-segmentation'] : [],
    });
  }

  // Riepilogo delle reti scoperte.
  const known = nets.filter((n) => !n.local);
  const hasDiscovery = !!(l2?.read === 'ok' || disc?.ad?.read === 'ok' || disc?.snmp?.length || scan.infra?.remote?.length);
  if (hasDiscovery && known.length) {
    const vlans = nets.filter((n) => n.vlan).length;
    const sources: string[] = [];
    for (const n of nets) for (const s of n.sources) if (s !== 'rete di questo PC') pushU(sources, s.replace(/ \(.*\)$/, ''));
    const localNet = nets.find((n) => n.local);
    const list = known.slice(0, 6).map((n) => (n.prefix && n.vlan ? `${netLabel(n)} (${n.prefix})` : n.prefix ?? netLabel(n)));
    const missing = netsWithoutTargets(nets).length;
    add({
      id: 'lan.vlans',
      metric: 'lan.vlans',
      category: 'infra',
      title: 'Reti e VLAN scoperte',
      value: `${num(known.length + (localNet ? 1 : 0), 'rete', 'reti')}${vlans ? ` · ${num(vlans, 'VLAN', 'VLAN')}` : ''}`,
      numeric: known.length,
      severity: 'info',
      verdict:
        `Oltre alla rete del PC${localNet?.prefix ? ` (${localNet.prefix}${localNet.vlan ? `, VLAN ${localNet.vlan}` : ''})` : ''} sono note ${num(known.length, 'altra rete', 'altre reti')}: ${list.join('; ')}${more(known.length, 6)}. ` +
        `Fonti: ${sources.join(', ')}. ` +
        'Il test di segmentazione verifica che da qui passino solo i flussi previsti' +
        (missing ? `; per ${num(missing, 'rete', 'reti')} non si conosce ancora nessun dispositivo da provare (serve l'inventario attraverso il router o la lettura SNMP).` : '.'),
      actions: ['test-segmentation'],
    });
  }
}
