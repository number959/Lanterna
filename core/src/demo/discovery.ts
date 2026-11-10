import type { ADSubnets, DiscoveryData, Inventory, InventoryHost, L2Discovery, Scan, SnmpResult, SnmpStatus } from '../engine/types';

// Scoperta delle reti per le demo: il poliambulatorio ha un firewall che fa
// da router tra le VLAN (letto con SNMPv3), uno switch centrale letto con
// SNMPv2c e un dominio con le sottoreti registrate in Active Directory, anche
// quelle di una seconda sede. L'ascolto degli annunci dello switch e gli
// inventari attraverso il router si simulano su richiesta, sempre dichiarati
// come simulati. Valori plausibili ma inventati.

const ok = (rows: number, source?: string): SnmpStatus => ({ state: 'ok', rows, ...(source ? { source } : {}) });
const absent = (note: string): SnmpStatus => ({ state: 'absent', rows: 0, note });

const svi = (index: number, name: string, vlanId: number, ip: string, prefix = 24) => {
  const parts = ip.split('.');
  const subnet = `${parts[0]}.${parts[1]}.${parts[2]}.0/${prefix}`;
  return { index, name, type: 135, vlanId, ips: [{ ip, mask: '255.255.255.0', prefix, subnet }] };
};

// Dispositivi visti dal firewall nelle VLAN (tabella ARP).
const ARP: [string, string, string?][] = [
  ['10.10.10.10', '00:50:56:9a:10:10', 'VMware'],
  ['10.10.10.11', '00:50:56:9a:10:11', 'VMware'],
  ['10.10.10.25', '00:50:56:9a:10:25', 'VMware'],
  ['10.20.20.31', 'd8:9e:f3:20:31:01', 'Dell'],
  ['10.20.20.32', 'd8:9e:f3:20:32:01', 'Dell'],
  ['10.20.20.40', '3c:2a:f4:20:40:01', 'Brother'],
  ['10.20.40.21', '00:1c:7e:40:21:01', 'Esaote'],
  ['10.20.40.22', '00:1c:7e:40:22:01', 'Esaote'],
  ['10.20.50.10', '00:50:56:9a:50:10', 'VMware'],
  ['10.20.50.20', '00:50:56:9a:50:20', 'VMware'],
  ['10.20.50.30', '00:50:56:9a:50:30', 'VMware'],
  ['10.20.50.40', '00:11:32:50:40:01', 'Synology'],
  ['10.20.60.15', '00:04:a3:60:15:01', 'Microchip Technology'],
  ['10.20.60.16', '00:04:a3:60:16:01', 'Microchip Technology'],
  ['10.20.60.17', '00:04:a3:60:17:01', 'Microchip Technology'],
  ['10.20.70.10', 'bc:ad:28:70:10:01', 'Hikvision'],
  ['10.20.70.11', 'bc:ad:28:70:11:01', 'Hikvision'],
  ['10.20.90.50', '6a:2c:91:90:50:01'],
  ['10.20.90.51', 'ae:41:0b:90:51:01'],
  ['10.20.100.21', '00:04:f2:a1:21:01', 'Polycom'],
  ['10.20.100.22', '00:04:f2:a1:22:01', 'Polycom'],
  ['10.0.0.2', '00:1e:bd:5a:00:01', 'Cisco'],
  ['10.0.0.11', '00:1e:bd:5a:11:00', 'Cisco'],
  ['10.0.0.12', '00:1e:bd:5a:12:00', 'Cisco'],
];

const ifOf = (ip: string) => {
  const third = Number(ip.split('.')[2]);
  return ip.startsWith('10.10.') ? 10 : ip.startsWith('10.0.') ? 999 : third;
};

const firewall: SnmpResult = {
  target: '10.20.30.1',
  version: '3',
  startedAt: '2026-10-14T09:24:10Z',
  durationMs: 4200,
  requests: 38,
  system: { descr: 'FortiGate-100F', objectId: '1.3.6.1.4.1.12356.101.1.1004', name: 'FW-CLINICA', uptimeSec: 3456000 },
  interfaces: [
    svi(10, 'vlan10', 10, '10.10.10.1'),
    svi(20, 'vlan20', 20, '10.20.20.1'),
    svi(30, 'vlan30', 30, '10.20.30.1'),
    svi(40, 'vlan40', 40, '10.20.40.1'),
    svi(50, 'vlan50', 50, '10.20.50.1'),
    svi(60, 'vlan60', 60, '10.20.60.1'),
    svi(70, 'vlan70', 70, '10.20.70.1'),
    svi(90, 'vlan90', 90, '10.20.90.1'),
    svi(100, 'vlan100', 100, '10.20.100.1'),
    svi(999, 'mgmt', 999, '10.0.0.1'),
  ],
  vlans: [],
  lldpNeighbors: [
    { localPortNum: 1, localPort: 'port1', chassisId: '00:1e:bd:5a:00:01', chassisIdType: 'macAddress', portId: 'Gi1/0/1', portIdType: 'interfaceName', sysName: 'SW-CORE', capsEnabled: ['bridge', 'router'], mgmtIp: '10.0.0.2' },
  ],
  arp: ARP.map(([ip, mac, vendor]) => ({ ifIndex: ifOf(ip), ip, mac, ...(vendor ? { vendor } : {}) })),
  fdb: [],
  sections: {
    system: ok(1, 'SNMPv2-MIB'),
    interfaces: ok(10, 'IF-MIB, IP-MIB'),
    vlans: absent('il dispositivo non pubblica le tabelle delle VLAN negli standard letti'),
    lldp: ok(1, 'LLDP-MIB'),
    arp: ok(ARP.length, 'IP-MIB'),
    fdb: absent('un firewall non ha la tabella degli indirizzi MAC per porta'),
  },
};

const coreSwitch: SnmpResult = {
  target: '10.0.0.2',
  version: '2c',
  startedAt: '2026-10-14T09:26:02Z',
  durationMs: 9800,
  requests: 112,
  warnings: ['SNMPv2c trasmette la community in chiaro: chi osserva il traffico può leggerla. Se il dispositivo lo consente, usa SNMPv3 con autenticazione e cifratura.'],
  system: { descr: 'Cisco IOS XE Software, Catalyst L3 Switch Software', objectId: '1.3.6.1.4.1.9.1.2494', name: 'SW-CORE', uptimeSec: 9504000 },
  interfaces: [svi(999, 'Vl999', 999, '10.0.0.2')],
  vlans: [
    { id: 1, name: 'default' },
    { id: 10, name: 'SERVER' },
    { id: 20, name: 'AMMINISTRAZIONE' },
    { id: 30, name: 'AMBULATORI' },
    { id: 40, name: 'DIAGNOSTICA' },
    { id: 50, name: 'SERVER-CLINICI' },
    { id: 60, name: 'MEDICALI' },
    { id: 70, name: 'TELECAMERE' },
    { id: 90, name: 'OSPITI' },
    { id: 100, name: 'VOCE' },
    { id: 999, name: 'GESTIONE' },
  ],
  lldpNeighbors: [
    { localPortNum: 1, localPort: 'Gi1/0/1', chassisId: '00:09:0f:aa:00:01', chassisIdType: 'macAddress', portId: 'port1', portIdType: 'interfaceName', sysName: 'FW-CLINICA', capsEnabled: ['router'], mgmtIp: '10.0.0.1' },
    { localPortNum: 10, localPort: 'Gi1/0/10', chassisId: '00:1e:bd:5a:11:00', chassisIdType: 'macAddress', portId: 'Gi1/1/1', portIdType: 'interfaceName', sysName: 'SW-PIANO1', capsEnabled: ['bridge'], mgmtIp: '10.0.0.11' },
    { localPortNum: 11, localPort: 'Gi1/0/11', chassisId: '00:1e:bd:5a:12:00', chassisIdType: 'macAddress', portId: 'Gi1/1/1', portIdType: 'interfaceName', sysName: 'SW-PIANO2', capsEnabled: ['bridge'], mgmtIp: '10.0.0.12' },
    { localPortNum: 20, localPort: 'Gi1/0/20', chassisId: '00:50:56:9a:00:20', chassisIdType: 'macAddress', portId: 'vmnic2', portIdType: 'interfaceName', sysName: 'esx01', capsEnabled: ['bridge'] },
  ],
  arp: [
    { ifIndex: 999, ip: '10.0.0.1', mac: '00:09:0f:aa:00:01' },
    { ifIndex: 999, ip: '10.0.0.11', mac: '00:1e:bd:5a:11:00' },
    { ifIndex: 999, ip: '10.0.0.12', mac: '00:1e:bd:5a:12:00' },
  ],
  fdb: [
    { mac: '00:09:0f:aa:30:01', port: 'Gi1/0/1', bridgePort: 1, ifIndex: 1, fdbId: 30 },
    { mac: '00:50:56:9a:50:20', port: 'Gi1/0/20', bridgePort: 20, ifIndex: 20, fdbId: 50 },
    { mac: '00:50:56:9a:50:10', port: 'Gi1/0/20', bridgePort: 20, ifIndex: 20, fdbId: 50 },
    { mac: '8c:f8:c5:3a:11:07', port: 'Gi1/0/10', bridgePort: 10, ifIndex: 10, fdbId: 30 },
    { mac: '00:04:a3:60:15:01', port: 'Gi1/0/11', bridgePort: 11, ifIndex: 11, fdbId: 60 },
    { mac: 'bc:ad:28:70:10:01', port: 'Gi1/0/11', bridgePort: 11, ifIndex: 11, fdbId: 70 },
  ],
  sections: {
    system: ok(1, 'SNMPv2-MIB'),
    interfaces: ok(1, 'IF-MIB, IP-MIB'),
    vlans: ok(11, 'CISCO-VTP-MIB'),
    lldp: ok(4, 'LLDP-MIB'),
    arp: ok(3, 'IP-MIB'),
    fdb: ok(6, 'Q-BRIDGE-MIB'),
  },
};

const clinicAD: ADSubnets = {
  read: 'ok',
  subnets: [
    { prefix: '10.10.10.0/24', site: 'Sede' },
    { prefix: '10.20.0.0/16', site: 'Sede' },
    { prefix: '10.30.0.0/16', site: 'Poliambulatorio-Nord' },
  ],
};

/** La scoperta già eseguita dall'utente nella demo del poliambulatorio. */
export const clinicDiscovery: DiscoveryData = { ad: clinicAD, snmp: [firewall, coreSwitch] };

const isClinic = (scan: Scan) => !!scan.agent.domain;
const wiredUp = (scan: Scan) => scan.adapters.some((a) => a.kind === 'ethernet' && a.up && a.ipv4.length > 0);

/**
 * Ascolto simulato degli annunci dello switch. Nel poliambulatorio: lo switch
 * di piano con LLDP, CDP, DTP ancora attivo e Rapid PVST+ con la radice alla
 * priorità predefinita, come se il PC fosse collegato con il cavo alla presa
 * dell'ambulatorio. Altrove: nessun annuncio (switch non gestito) o nessun cavo.
 */
export function simulatedL2(scan: Scan): L2Discovery {
  const counts = { lldp: 0, cdp: 0, dtp: 0, stp: 0, vtp: 0, eapol: 0, other: 0 };
  if (!isClinic(scan)) {
    if (!wiredUp(scan)) return { read: 'nowired', seconds: 0, frames: 0, counts };
    return { read: 'none', seconds: 61, frames: 0, counts, adapters: ['Ethernet'] };
  }
  return {
    read: 'ok',
    seconds: 61,
    frames: 37,
    counts: { lldp: 2, cdp: 1, dtp: 2, stp: 31, vtp: 1, eapol: 0, other: 0 },
    adapters: ['Ethernet'],
    lldp: [
      {
        adapter: 'Ethernet',
        chassisId: '00:1e:bd:5a:11:00',
        chassisIdType: 'mac',
        portId: 'Gi1/0/12',
        portIdType: 'interface-name',
        ttl: 120,
        systemName: 'SW-PIANO1.clinica.local',
        systemDescription: 'Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E4, RELEASE SOFTWARE (fc2)',
        capabilities: ['bridge'],
        capabilitiesSupported: ['bridge', 'router'],
        managementAddresses: ['10.0.0.11'],
        portVlanId: 30,
        vlans: [{ id: 30, name: 'AMBULATORI' }],
        voiceVlan: 100,
        policies: [{ app: 'voice', tagged: true, vlan: 100, priority: 5, dscp: 46 }],
        medClass: 'network',
        mau: '1000BASE-T',
        mauType: 30,
        speedMbps: 1000,
        duplex: 'full',
        autoneg: 'on',
        frames: 2,
      },
    ],
    cdp: [
      {
        adapter: 'Ethernet',
        version: 2,
        ttl: 180,
        deviceId: 'SW-PIANO1.clinica.local',
        portId: 'GigabitEthernet1/0/12',
        platform: 'cisco WS-C2960X-48FPD-L',
        capabilities: ['switch', 'igmp'],
        managementAddresses: ['10.0.0.11'],
        nativeVlan: 30,
        voiceVlan: 100,
        vtpDomain: 'CLINICA',
        duplex: 'full',
        frames: 1,
      },
    ],
    dtp: [{ adapter: 'Ethernet', version: 1, domain: 'CLINICA', operStatus: 'access', adminStatus: 'auto', operType: 'native', adminType: 'negotiated', neighbor: '00:1e:bd:5a:11:0c', frames: 2 }],
    stp: [
      {
        adapter: 'Ethernet',
        format: 'ieee',
        protocol: 'rstp',
        rootPriority: 32768,
        rootSysIdExt: 30,
        rootMac: '00:1e:bd:5a:00:00',
        rootPathCost: 4,
        bridgePriority: 32768,
        bridgeSysIdExt: 30,
        bridgeMac: '00:1e:bd:5a:11:00',
        portPriority: 128,
        portNumber: 12,
        portRole: 'designated',
        messageAge: 1,
        maxAge: 20,
        helloTime: 2,
        forwardDelay: 15,
        frames: 31,
      },
    ],
  };
}

/** Sottoreti di Active Directory simulate: quelle della demo, oppure nessun dominio. */
export function simulatedAD(scan: Scan): ADSubnets {
  return isClinic(scan) ? clinicAD : { read: 'nodomain' };
}

/**
 * Lettura SNMP simulata: i due apparati della demo del poliambulatorio
 * rispondono (con la versione con cui sono configurati); gli altri indirizzi
 * no, come un dispositivo con SNMP spento o con credenziali diverse.
 */
export function simulatedSnmp(scan: Scan, target: string, defaultCommunity: boolean): SnmpResult {
  const known = isClinic(scan) ? [firewall, coreSwitch].find((r) => r.target === target.trim()) : undefined;
  if (!known) throw new Error(`nessuna risposta da ${target.trim()}: SNMP spento, credenziali diverse o un firewall in mezzo (simulato)`);
  return { ...known, startedAt: new Date().toISOString(), ...(defaultCommunity && known.version === '2c' ? { defaultCommunity: true } : {}) };
}

/** Inventario simulato di un'altra sottorete, attraverso il router: i dispositivi noti alla demo in quella rete. */
export function simulatedRemoteInventory(scan: Scan, subnet: string): Inventory {
  const [base, bits] = subnet.split('/');
  const prefix = Number(bits);
  const net = base.split('.').slice(0, prefix >= 24 ? 3 : 2).join('.') + '.';
  const hosts: InventoryHost[] = [];
  const seen = new Set<string>();
  for (const r of scan.infra?.discovery?.snmp ?? [])
    for (const a of r.arp)
      if (a.ip.startsWith(net) && !seen.has(a.ip)) {
        seen.add(a.ip);
        hosts.push({ ip: a.ip, rttMs: 8 + (Number(a.ip.split('.')[3]) % 7) });
      }
  // I dispositivi medicali e le telecamere, isolati, non rispondono al ping dalla rete degli ambulatori.
  const isolated = /^10\.20\.(60|70|90)\./.test(net);
  const toNum = (a: string) => a.split('.').reduce((s, x) => s * 256 + Number(x), 0);
  return {
    subnet,
    adapter: scan.adapters.find((a) => a.up && a.ipv4.length)?.name,
    scanned: Math.pow(2, 32 - prefix) - 2,
    startedAt: new Date().toISOString(),
    durationMs: 9000 + hosts.length * 300,
    hosts: isolated ? [] : hosts.sort((a, b) => toNum(a.ip) - toNum(b.ip)),
  };
}
