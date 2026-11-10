import type { Bss, InventoryHost, Scan } from '../engine/types';
import { homePc } from './pc';
import { homeSurvey } from './survey';
import { pingSamples, stats } from './util';

// Scansione dimostrativa: appartamento in condominio, PC portatile collegato
// a 2,4 GHz su un canale intermedio con molti vicini. I valori sono plausibili
// ma inventati; l'interfaccia la mostra con l'etichetta "DEMO".

const sec = (protocol: NonNullable<Bss['security']>['protocol'], extra: Partial<NonNullable<Bss['security']>> = {}) => ({
  protocol,
  akm: protocol === 'wpa3' ? ['SAE'] : protocol === 'wpa2/wpa3' ? ['PSK', 'SAE'] : protocol === 'open' ? [] : ['PSK'],
  pairwise: protocol === 'open' ? [] : ['CCMP'],
  pmf: protocol === 'wpa3' ? ('required' as const) : protocol === 'wpa2/wpa3' ? ('capable' as const) : ('disabled' as const),
  ...extra,
});

const nets: Bss[] = [
  { ssid: 'Casa-Rossi', bssid: 'a4:2b:b0:11:22:33', rssiDbm: -71, freqMhz: 2432, channel: 5, band: '2.4', widthMhz: 40, centerChannel: 7, phy: '802.11n', bssLoad: { stations: 9, utilizationPct: 62 }, security: sec('wpa2', { wps: true }), country: 'IT', connected: true },
  { ssid: 'Casa-Rossi', bssid: 'a4:2b:b0:11:22:34', rssiDbm: -74, freqMhz: 5180, channel: 36, band: '5', widthMhz: 80, centerChannel: 42, phy: '802.11ac', bssLoad: { stations: 2, utilizationPct: 14 }, security: sec('wpa2', { wps: true }), country: 'IT' },
  { ssid: 'TIM-29384756', bssid: '30:91:8f:aa:bb:01', rssiDbm: -62, freqMhz: 2437, channel: 6, band: '2.4', widthMhz: 20, phy: '802.11n', bssLoad: { stations: 5, utilizationPct: 48 }, security: sec('wpa2') },
  { ssid: 'TIM-29384756', bssid: '30:91:8f:aa:bb:02', rssiDbm: -78, freqMhz: 5500, channel: 100, band: '5', widthMhz: 80, centerChannel: 106, phy: '802.11ac', security: sec('wpa2') },
  { ssid: 'Vodafone-A1B2C3', bssid: '84:a1:d1:00:00:10', rssiDbm: -69, freqMhz: 2442, channel: 7, band: '2.4', widthMhz: 20, phy: '802.11ax', security: sec('wpa2/wpa3') },
  { ssid: 'Vodafone-A1B2C3', bssid: '84:a1:d1:00:00:11', rssiDbm: -80, freqMhz: 5220, channel: 44, band: '5', widthMhz: 80, centerChannel: 42, phy: '802.11ax', security: sec('wpa2/wpa3') },
  { ssid: 'FASTWEB-K9X8', bssid: '00:1e:80:12:34:56', rssiDbm: -73, freqMhz: 2412, channel: 1, band: '2.4', widthMhz: 20, phy: '802.11n', security: sec('wpa2') },
  { ssid: 'WindTre-5544', bssid: 'c8:3a:35:99:88:77', rssiDbm: -77, freqMhz: 2462, channel: 11, band: '2.4', widthMhz: 20, phy: '802.11n', security: sec('wpa2') },
  { ssid: 'HP-Print-3F-LaserJet', bssid: 'fa:da:0c:01:02:03', rssiDbm: -66, freqMhz: 2437, channel: 6, band: '2.4', widthMhz: 20, phy: '802.11n', security: sec('open') },
  { ssid: '', bssid: '12:3a:35:99:88:78', rssiDbm: -82, freqMhz: 2462, channel: 11, band: '2.4', widthMhz: 20, phy: '802.11n', security: sec('wpa2') },
  { ssid: 'Iliad-BOX-7F21', bssid: '68:a3:78:44:55:66', rssiDbm: -84, freqMhz: 2427, channel: 4, band: '2.4', widthMhz: 20, phy: '802.11ax', security: sec('wpa3') },
  { ssid: 'Iliad-BOX-7F21', bssid: '68:a3:78:44:55:67', rssiDbm: -86, freqMhz: 5745, channel: 149, band: '5', widthMhz: 80, centerChannel: 155, phy: '802.11ax', security: sec('wpa3') },
  { ssid: 'Condominio-Ospiti', bssid: '9c:c9:eb:10:20:30', rssiDbm: -79, freqMhz: 2452, channel: 9, band: '2.4', widthMhz: 20, phy: '802.11g', security: sec('wep', { akm: [], pairwise: ['WEP'] }) },
];

// Inventario della rete di casa con i segnali per il riconoscimento del tipo.
const homeHosts: InventoryHost[] = [
  { ip: '192.168.1.1', mac: 'a4:2b:b0:11:22:30', gateway: true, rttMs: 3.1, vendor: 'TP-Link', ttl: 64, upnp: ['urn:schemas-upnp-org:device:InternetGatewayDevice:1', 'urn:schemas-wifialliance-org:device:WFADevice:1'], server: 'Linux/2.6.36, UPnP/1.0, Portable SDK for UPnP devices/1.6.19' },
  { ip: '192.168.1.12', mac: 'b8:27:eb:12:34:56', name: 'homeassistant.home', rttMs: 4.2, vendor: 'Raspberry Pi', ttl: 64, services: ['_home-assistant._tcp', '_hap._tcp', '_http._tcp'] },
  { ip: '192.168.1.20', mac: '50:c7:bf:aa:00:01', name: 'RE450.home', rttMs: 5.6, vendor: 'TP-Link', ttl: 64, upnp: ['urn:schemas-wifialliance-org:device:WFADevice:1'] },
  { ip: '192.168.1.27', mac: 'dc:a6:32:00:11:22', name: 'pihole.home', rttMs: 3.9, vendor: 'Raspberry Pi', ttl: 64, services: ['_http._tcp', '_ssh._tcp'] },
  { ip: '192.168.1.34', mac: '3c:58:c2:aa:bb:cc', self: true, name: 'PORTATILE-DEMO', vendor: 'Intel' },
  { ip: '192.168.1.40', mac: '74:da:38:5e:6f:70', name: 'cam-ingresso.home', rttMs: 9.4, vendor: 'Edimax', ttl: 64, services: ['_rtsp._tcp', '_http._tcp'] },
  { ip: '192.168.1.51', mac: '18:b4:30:01:02:03', name: 'Nest-Termostato.home', rttMs: 12.1, vendor: 'Nest Labs', ttl: 64 },
  { ip: '192.168.1.60', mac: '00:11:32:5a:6b:7c', name: 'DiskStation.home', netbios: 'DISKSTATION', rttMs: 2.8, vendor: 'Synology', ttl: 64, services: ['_smb._tcp', '_afpovertcp._tcp', '_http._tcp'], upnp: ['urn:schemas-upnp-org:device:MediaServer:1'], roles: ['file-server'] },
  { ip: '192.168.1.66', mac: '00:80:77:a1:b2:c3', name: 'BRN008077A1B2C3.home', rttMs: 6.7, vendor: 'Brother', ttl: 64, services: ['_ipp._tcp', '_printer._tcp', '_pdl-datastream._tcp', '_uscan._tcp'], upnp: ['urn:schemas-upnp-org:device:Printer:1'] },
  { ip: '192.168.1.72', mac: 'da:a1:19:6b:22:01', randomMac: true, rttMs: 41.5, ttl: 64, services: ['_apple-mobdev2._tcp', '_companion-link._tcp'] },
  { ip: '192.168.1.85', mac: '04:d4:c4:11:22:33', name: 'DESKTOP-SALOTTO.home', netbios: 'DESKTOP-SALOTTO', rttMs: 1.9, vendor: 'ASUSTek', ttl: 128, roles: ['workstation', 'file-server'] },
  { ip: '192.168.1.90', mac: 'a8:23:fe:44:55:66', name: 'LGwebOSTV.home', rttMs: 8.8, vendor: 'LG Electronics', ttl: 64, services: ['_airplay._tcp'], upnp: ['urn:dial-multiscreen-org:service:dial:1', 'urn:schemas-upnp-org:device:MediaRenderer:1'], server: 'WebOS/4.1.0 UPnP/1.0' },
  { ip: '192.168.1.95', mac: 'e8:68:e7:0a:0b:0c', name: 'shellyplug-s-0A0B0C.home', rttMs: 14.0, vendor: 'Espressif', ttl: 255, services: ['_shelly._tcp', '_http._tcp'] },
];

export const demoScan: Scan = {
  schema: 1,
  agent: { name: 'STARNET Polaris', version: 'demo', platform: 'demo', host: 'PORTATILE-DEMO', os: 'Dati dimostrativi', startedAt: '2026-10-12T20:30:00Z', durationMs: 14200 },
  adapters: [
    { name: 'Wi-Fi', description: 'Intel(R) Wi-Fi 6 AX201 160MHz', kind: 'wifi', mac: '3c:58:c2:aa:bb:cc', up: true, ipv4: ['192.168.1.34/24'], ipv6: ['fe80::1c2d:3e4f:5a6b:7c8d/64'], gateways: ['192.168.1.1'], dns: ['192.168.1.1'], dhcp: true, mtu: 1500, linkMbps: 144 },
    { name: 'Ethernet', description: 'Realtek PCIe GbE Family Controller', kind: 'ethernet', mac: '3c:58:c2:aa:bb:cd', up: false, ipv4: [], ipv6: [], gateways: [], dns: [] },
  ],
  wifi: {
    source: 'demo',
    connected: { interface: 'Wi-Fi', ssid: 'Casa-Rossi', bssid: 'a4:2b:b0:11:22:33', signalQuality: 58, rssiDbm: -71, rxMbps: 144, txMbps: 117, phy: '802.11n', band: '2.4', channel: 5, widthMhz: 40, auth: 'WPA2-Personal', cipher: 'CCMP' },
    networks: nets,
    // Mappa del Wi-Fi per stanza già misurata dall'utente.
    survey: homeSurvey,
  },
  gateway: {
    ip: '192.168.1.1',
    mac: 'a4:2b:b0:11:22:30',
    ping: stats('192.168.1.1', 'Router', pingSamples(6, 26, 20, [13])),
    ports: [
      { port: 21, service: 'ftp', open: false },
      { port: 22, service: 'ssh', open: false },
      { port: 23, service: 'telnet', open: true },
      { port: 53, service: 'dns', open: true },
      { port: 80, service: 'http', open: true },
      { port: 443, service: 'https', open: false },
      { port: 445, service: 'smb', open: false },
      { port: 7547, service: 'tr-069', open: false },
      { port: 8080, service: 'http-alt', open: false },
    ],
    upnp: { found: true, igd: true, externalIp: '93.40.12.34', devices: [{ friendlyName: 'Router Casa', manufacturer: 'Demo Networks', modelName: 'DN-2400', modelNumber: 'v2', server: 'Linux/3.4 UPnP/1.0 MiniUPnPd/1.9', deviceType: 'urn:schemas-upnp-org:device:InternetGatewayDevice:1' }, { friendlyName: 'TV Soggiorno', manufacturer: 'Demo TV', deviceType: 'urn:schemas-upnp-org:device:MediaRenderer:1' }] },
    web: { server: 'mini_httpd/1.19', title: 'DN-2400 Login', https: false },
  },
  internet: {
    targets: [
      stats('1.1.1.1', 'Cloudflare', pingSamples(31, 24, 20)),
      stats('8.8.8.8', 'Google', pingSamples(34, 22, 20, [7], 1.1)),
      stats('9.9.9.9', 'Quad9', pingSamples(38, 20, 20, [], 2.3)),
    ],
    traceTarget: '1.1.1.1',
    traceroute: [
      { ttl: 1, ip: '192.168.1.1', rttMs: 9.8 },
      { ttl: 2, ip: '10.4.18.1', rttMs: 21.4 },
      { ttl: 3 },
      { ttl: 4, ip: '93.40.0.17', rttMs: 26.9 },
      { ttl: 5, ip: '93.62.130.5', rttMs: 31.2 },
      { ttl: 6, ip: '162.158.84.1', rttMs: 33.0 },
      { ttl: 7, ip: '1.1.1.1', rttMs: 32.6 },
    ],
    mtu: { mtu: 1492, method: 'ICMP con bit DF' },
    http: [{ url: 'https://www.google.com/generate_204', ok: true, status: 204, timeMs: 212 }],
  },
  dns: {
    system: [{ server: '192.168.1.1', label: 'Router', ok: true, timeMs: 118 }],
    public: [
      { server: '1.1.1.1', label: 'Cloudflare', ok: true, timeMs: 34 },
      { server: '8.8.8.8', label: 'Google', ok: true, timeMs: 41 },
      { server: '9.9.9.9', label: 'Quad9', ok: true, timeMs: 47 },
    ],
  },
  lan: {
    neighbors: [
      { ip: '192.168.1.1', mac: 'a4:2b:b0:11:22:30' },
      { ip: '192.168.1.12', mac: 'b8:27:eb:12:34:56' },
      { ip: '192.168.1.20', mac: '50:c7:bf:aa:00:01' },
      { ip: '192.168.1.27', mac: 'dc:a6:32:00:11:22' },
      { ip: '192.168.1.40', mac: '74:da:38:5e:6f:70' },
      { ip: '192.168.1.51', mac: '18:b4:30:01:02:03' },
    ],
  },
  firewall: {
    source: 'registry',
    profiles: [
      { name: 'domain', enabled: true },
      { name: 'private', enabled: false, active: true },
      { name: 'public', enabled: true },
    ],
  },
  infra: {
    inventory: { subnet: '192.168.1.0/24', adapter: 'Wi-Fi', scanned: 254, startedAt: '2026-10-12T20:33:10Z', durationMs: 11800, hosts: homeHosts },
  },
  pc: homePc,
  errors: [],
};
