import type { Bss, InventoryHost, Roaming, Scan, WifiSecurity } from '../engine/types';
import { pingSamples, stats } from './util';

// Seconda rete dimostrativa: un poliambulatorio con dominio, rete Wi-Fi
// aziendale 802.1X su più access point e reti separate per ospiti,
// dispositivi medicali, telecamere e gestione. Il PC di un ambulatorio è
// collegato a un AP lontano mentre uno più vicino si sente meglio, due AP
// condividono il canale e una radio aperta annuncia il nome della rete del
// personale. L'utente ha già eseguito inventario e verifiche di
// raggiungibilità dalla sezione Infrastruttura. Valori plausibili ma inventati.

const staff: WifiSecurity = { protocol: 'wpa2', akm: ['802.1X'], pairwise: ['CCMP'], group: 'CCMP', pmf: 'capable' };
const guest: WifiSecurity = { protocol: 'owe', akm: ['OWE'], pairwise: ['CCMP'], pmf: 'required' };
const med: WifiSecurity = { protocol: 'wpa2', akm: ['PSK'], pairwise: ['CCMP'], pmf: 'disabled' };
const kv: Roaming = { k: true, v: true, r: false };

// Quattro AP dual band con lo schema di BSSID più comune: il penultimo ottetto
// identifica l'AP, l'ultimo la radio (c = 2,4 GHz, d = 5 GHz) e la rete.
const ap = (n: number, radio: 0 | 1, ssid: number) => `44:48:c1:a0:${(n * 16).toString(16)}:${radio ? 'd' : 'c'}${ssid}`;

const nets: Bss[] = [
  // AP 2, ambulatori lato nord: è quello a cui il PC è collegato, ormai lontano.
  { ssid: 'Clinica-Staff', bssid: ap(2, 1, 0), rssiDbm: -76, freqMhz: 5180, channel: 36, band: '5', widthMhz: 40, centerChannel: 38, phy: '802.11ax', bssLoad: { stations: 31, utilizationPct: 58 }, security: staff, roaming: kv, country: 'IT', connected: true },
  { ssid: 'Clinica-Ospiti', bssid: ap(2, 1, 1), rssiDbm: -77, freqMhz: 5180, channel: 36, band: '5', widthMhz: 40, centerChannel: 38, phy: '802.11ax', security: guest, roaming: { k: true, v: true, r: false }, country: 'IT' },
  { ssid: 'Clinica-Staff', bssid: ap(2, 0, 0), rssiDbm: -70, freqMhz: 2437, channel: 6, band: '2.4', widthMhz: 20, phy: '802.11ax', bssLoad: { stations: 9, utilizationPct: 41 }, security: staff, roaming: kv, country: 'IT' },
  // AP 1, corridoio: il più vicino al PC.
  { ssid: 'Clinica-Staff', bssid: ap(1, 1, 0), rssiDbm: -58, freqMhz: 5260, channel: 52, band: '5', widthMhz: 40, centerChannel: 54, phy: '802.11ax', bssLoad: { stations: 12, utilizationPct: 22 }, security: staff, roaming: kv, country: 'IT' },
  { ssid: 'Clinica-Ospiti', bssid: ap(1, 1, 1), rssiDbm: -58, freqMhz: 5260, channel: 52, band: '5', widthMhz: 40, centerChannel: 54, phy: '802.11ax', security: guest, roaming: { k: true, v: true, r: false }, country: 'IT' },
  { ssid: '', bssid: ap(1, 1, 2), rssiDbm: -59, freqMhz: 5260, channel: 52, band: '5', widthMhz: 40, centerChannel: 54, phy: '802.11ax', security: med, country: 'IT' },
  { ssid: 'Clinica-Staff', bssid: ap(1, 0, 0), rssiDbm: -55, freqMhz: 2412, channel: 1, band: '2.4', widthMhz: 20, phy: '802.11ax', bssLoad: { stations: 6, utilizationPct: 33 }, security: staff, roaming: kv, country: 'IT' },
  // AP 3, sala d'attesa: stesso canale a 5 GHz dell'AP 2.
  { ssid: 'Clinica-Staff', bssid: ap(3, 1, 0), rssiDbm: -68, freqMhz: 5180, channel: 36, band: '5', widthMhz: 40, centerChannel: 38, phy: '802.11ax', bssLoad: { stations: 18, utilizationPct: 47 }, security: staff, roaming: kv, country: 'IT' },
  { ssid: '', bssid: ap(3, 1, 2), rssiDbm: -69, freqMhz: 5180, channel: 36, band: '5', widthMhz: 40, centerChannel: 38, phy: '802.11ax', security: med, country: 'IT' },
  { ssid: 'Clinica-Staff', bssid: ap(3, 0, 0), rssiDbm: -66, freqMhz: 2462, channel: 11, band: '2.4', widthMhz: 20, phy: '802.11ax', security: staff, roaming: kv, country: 'IT' },
  // AP 4, radiologia: configurato diversamente (senza 802.11v).
  { ssid: 'Clinica-Staff', bssid: ap(4, 1, 0), rssiDbm: -81, freqMhz: 5500, channel: 100, band: '5', widthMhz: 40, centerChannel: 102, phy: '802.11ax', security: staff, roaming: { k: true, v: false, r: false }, country: 'IT' },
  { ssid: 'Clinica-Staff', bssid: ap(4, 0, 0), rssiDbm: -79, freqMhz: 2437, channel: 6, band: '2.4', widthMhz: 20, phy: '802.11ax', security: staff, roaming: { k: true, v: false, r: false }, country: 'IT' },
  // Radio estranea con il nome della rete del personale, ma aperta.
  { ssid: 'Clinica-Staff', bssid: 'da:a1:19:6b:22:01', rssiDbm: -71, freqMhz: 2437, channel: 6, band: '2.4', widthMhz: 20, phy: '802.11n', security: { protocol: 'open', akm: [], pairwise: [] } },
  // Vicini.
  { ssid: 'Farmacia-Centrale', bssid: '30:91:8f:3c:4d:5e', rssiDbm: -84, freqMhz: 2462, channel: 11, band: '2.4', widthMhz: 20, phy: '802.11n', security: { protocol: 'wpa2', akm: ['PSK'], pairwise: ['CCMP'], pmf: 'disabled' } },
  { ssid: 'Studio-Dentistico', bssid: '68:a3:78:9a:bc:de', rssiDbm: -83, freqMhz: 5220, channel: 44, band: '5', widthMhz: 20, phy: '802.11ax', security: { protocol: 'wpa3', akm: ['SAE'], pairwise: ['CCMP'], pmf: 'required' } },
  { ssid: 'TIM-81726354', bssid: 'c8:3a:35:11:22:44', rssiDbm: -86, freqMhz: 2412, channel: 1, band: '2.4', widthMhz: 20, phy: '802.11n', security: { protocol: 'wpa2', akm: ['PSK'], pairwise: ['CCMP'], pmf: 'disabled' } },
];

const host = (ip: string, name: string | undefined, netbios: string | undefined, mac: string | undefined, rtt?: number, extra: Partial<InventoryHost> = {}): InventoryHost => ({
  ip,
  ...(mac ? { mac } : {}),
  ...(name ? { name } : {}),
  ...(netbios ? { netbios } : {}),
  ...(rtt !== undefined ? { rttMs: rtt } : {}),
  ...extra,
});

const pcs: InventoryHost[] = [21, 22, 23, 24, 25, 26, 28, 29, 31, 33].map((last, i) => {
  const n = String(i + 1 + (i >= 6 ? 1 : 0)).padStart(2, '0'); // AMB-07 è questo PC
  return host(`10.20.30.${last}`, `amb-${n}.clinica.local`, `AMB-${n}`, `8c:f8:c5:3a:${(0x20 + i).toString(16)}:${(0x10 + i * 7).toString(16)}`, 6 + ((i * 37) % 9));
});

const inventoryHosts: InventoryHost[] = [
  host('10.20.30.1', 'gw-vlan30.clinica.local', undefined, '00:09:0f:aa:30:01', 5.8, { gateway: true }),
  host('10.20.30.10', 'srv-stampa.clinica.local', 'SRV-STAMPA', '00:50:56:9a:41:10', 6.4),
  host('10.20.30.12', 'stampa-piano1.clinica.local', 'NPI3F21C9', '3c:2a:f4:3f:21:c9', 7.9),
  host('10.20.30.15', 'stampa-piano2.clinica.local', 'NPI8A0B14', '3c:2a:f4:8a:0b:14', 8.3),
  ...pcs,
  host('10.20.30.57', 'amb-07.clinica.local', undefined, '8c:f8:c5:3a:11:07', undefined, { self: true }),
  host('10.20.30.64', 'tablet-inf-03.clinica.local', undefined, '5a:1e:77:c0:93:2b', 14.2, { randomMac: true }),
  host('10.20.30.71', undefined, undefined, 'b6:4d:02:e9:15:7c', 18.7, { randomMac: true }),
  host('10.20.30.73', undefined, undefined, '7e:c3:aa:51:08:d6', undefined, { randomMac: true }),
  host('10.20.30.88', 'ecg-cardio-02.clinica.local', 'ECG-CARDIO-02', '00:1b:63:47:8e:02', 9.6),
  host('10.20.30.96', undefined, 'LAB-ANALIZZ', '00:0d:6f:22:9a:41', 11.2),
  host('10.20.30.120', undefined, undefined, '00:80:a3:9d:5e:11'),
  host('10.20.30.140', undefined, undefined, '00:04:a3:5c:21:07', 10.4),
  host('10.20.30.201', 'ap-corridoio.clinica.local', undefined, '44:48:c1:a0:10:b0', 6.1),
  host('10.20.30.202', 'ap-ambulatori.clinica.local', undefined, '44:48:c1:a0:20:b0', 7.0),
];

export const clinicScan: Scan = {
  schema: 1,
  agent: {
    name: 'STARNET Polaris',
    version: 'demo',
    platform: 'demo',
    host: 'AMB-07',
    os: 'Dati dimostrativi · poliambulatorio',
    startedAt: '2026-10-14T09:12:00Z',
    durationMs: 16800,
    domain: 'clinica.local',
  },
  adapters: [
    { name: 'Wi-Fi', description: 'Intel(R) Wi-Fi 6E AX211 160MHz', kind: 'wifi', mac: '8c:f8:c5:3a:11:07', up: true, ipv4: ['10.20.30.57/24'], ipv6: ['fe80::8ef8:c5ff:fe3a:1107/64'], gateways: ['10.20.30.1'], dns: ['10.10.10.10', '10.10.10.11'], dhcp: true, mtu: 1500, linkMbps: 172, dnsSuffix: 'clinica.local', dhcpServer: '10.10.10.10' },
    { name: 'Ethernet', description: 'Intel(R) Ethernet Connection I219-LM', kind: 'ethernet', mac: '8c:f8:c5:3a:11:08', up: false, ipv4: [], ipv6: [], gateways: [], dns: [] },
  ],
  wifi: {
    source: 'demo',
    connected: { interface: 'Wi-Fi', ssid: 'Clinica-Staff', bssid: ap(2, 1, 0), signalQuality: 48, rssiDbm: -76, rxMbps: 172, txMbps: 130, phy: '802.11ax', band: '5', channel: 36, widthMhz: 40, auth: 'WPA2-Enterprise', cipher: 'CCMP' },
    networks: nets,
  },
  gateway: {
    ip: '10.20.30.1',
    mac: '00:09:0f:aa:30:01',
    ping: stats('10.20.30.1', 'Gateway', pingSamples(5, 9, 20)),
    ports: [
      { port: 22, service: 'ssh', open: false },
      { port: 23, service: 'telnet', open: false },
      { port: 53, service: 'dns', open: false },
      { port: 80, service: 'http', open: false },
      { port: 443, service: 'https', open: true },
      { port: 445, service: 'smb', open: false },
      { port: 8443, service: 'https-alt', open: false },
    ],
    upnp: { found: true, igd: false, devices: [{ friendlyName: 'Stampante piano 1', manufacturer: 'Demo Print', modelName: 'LaserJet Demo', deviceType: 'urn:schemas-upnp-org:device:Printer:1' }] },
    web: { server: 'nginx', title: 'Firewall · accesso amministrativo', https: true },
  },
  internet: {
    // Il firewall della clinica blocca i ping verso Internet: misure con connessioni TCP.
    targets: [
      stats('1.1.1.1', 'Cloudflare', pingSamples(13, 9, 20, [], 0.4), 'tcp'),
      stats('8.8.8.8', 'Google', pingSamples(16, 8, 20, [], 1.3), 'tcp'),
      stats('9.9.9.9', 'Quad9', pingSamples(19, 8, 20, [], 2.1), 'tcp'),
    ],
    traceTarget: '1.1.1.1',
    traceroute: [{ ttl: 1, ip: '10.20.30.1', rttMs: 6.2 }, { ttl: 2 }, { ttl: 3 }, { ttl: 4 }, { ttl: 5 }],
    mtu: { mtu: 1500, method: 'ICMP con bit DF' },
    http: [{ url: 'https://www.google.com/generate_204', ok: true, status: 204, timeMs: 188 }],
  },
  dns: {
    system: [
      { server: '10.10.10.10', ok: true, timeMs: 64 },
      { server: '10.10.10.11', ok: true, timeMs: 71 },
    ],
    public: [
      { server: '1.1.1.1', label: 'Cloudflare', ok: true, timeMs: 12 },
      { server: '8.8.8.8', label: 'Google', ok: true, timeMs: 15 },
      { server: '9.9.9.9', label: 'Quad9', ok: true, timeMs: 19 },
    ],
  },
  lan: {
    neighbors: [
      { ip: '10.20.30.1', mac: '00:09:0f:aa:30:01' },
      { ip: '10.20.30.10', mac: '00:50:56:9a:41:10' },
      { ip: '10.20.30.12', mac: '3c:2a:f4:3f:21:c9' },
      { ip: '10.20.30.22', mac: '8c:f8:c5:3a:21:17' },
      { ip: '10.20.30.88', mac: '00:1b:63:47:8e:02' },
    ],
  },
  firewall: {
    source: 'registry',
    profiles: [
      { name: 'domain', enabled: true, active: true },
      { name: 'private', enabled: true },
      { name: 'public', enabled: true },
    ],
  },
  infra: {
    inventory: {
      subnet: '10.20.30.0/24',
      adapter: 'Wi-Fi',
      scanned: 253,
      startedAt: '2026-10-14T09:15:40Z',
      durationMs: 21400,
      hosts: inventoryHosts,
    },
    reach: {
      startedAt: '2026-10-14T09:18:05Z',
      from: '10.20.30.57',
      results: [
        { label: 'Cartella clinica (web)', host: 'ehr.clinica.local', port: 443, expect: 'reachable', ip: '10.20.50.10', status: 'open', rttMs: 9.8, ok: true },
        { label: 'PACS (DICOM)', host: '10.20.50.20', port: 104, expect: 'reachable', ip: '10.20.50.20', status: 'open', rttMs: 11.4, ok: true },
        { label: 'Integrazione HL7', host: '10.20.50.30', port: 2575, expect: 'reachable', ip: '10.20.50.30', status: 'filtered', ok: false },
        { label: 'Controller di dominio (LDAP)', host: 'dc01.clinica.local', port: 389, expect: 'reachable', ip: '10.10.10.10', status: 'open', rttMs: 8.1, ok: true },
        { label: 'DNS interno', host: '10.10.10.11', port: 53, expect: 'reachable', ip: '10.10.10.11', status: 'open', rttMs: 8.6, ok: true },
        { label: 'Pompe infusionali (VLAN 60)', host: '10.20.60.15', expect: 'isolated', ip: '10.20.60.15', status: 'noreply', ok: true },
        { label: 'Telecamere (RTSP)', host: '10.20.70.10', port: 554, expect: 'isolated', ip: '10.20.70.10', status: 'filtered', ok: true },
        { label: 'Gestione switch (SSH)', host: '10.0.0.2', port: 22, expect: 'isolated', ip: '10.0.0.2', status: 'open', rttMs: 10.2, ok: false },
        { label: 'Gateway della rete ospiti', host: '10.20.90.1', expect: 'isolated', ip: '10.20.90.1', status: 'noreply', ok: true },
        { label: 'PACS: condivisione file', host: '10.20.50.20', port: 445, expect: 'isolated', ip: '10.20.50.20', status: 'closed', rttMs: 9.9, ok: false },
      ],
    },
  },
  errors: [],
};
