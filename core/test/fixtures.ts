import type { Scan } from '../src/engine';

// Scansione minima e sana: ogni test modifica solo ciò che gli interessa.
export function base(): Scan {
  return structuredClone({
    schema: 1,
    agent: { name: 'test', version: '0', platform: 'windows', startedAt: '2026-01-01T00:00:00Z', durationMs: 1000 },
    adapters: [
      { name: 'Wi-Fi', kind: 'wifi', up: true, ipv4: ['192.168.1.10/24'], ipv6: ['2a01:db8::10/64'], gateways: ['192.168.1.1'], dns: ['192.168.1.1'], dhcp: true },
    ],
    wifi: {
      source: 'wlanapi',
      connected: { ssid: 'Casa', bssid: 'aa:aa:aa:aa:aa:01', rxMbps: 866, txMbps: 866, phy: '802.11ac', band: '5', channel: 36 },
      networks: [
        { ssid: 'Casa', bssid: 'aa:aa:aa:aa:aa:01', rssiDbm: -50, freqMhz: 5180, channel: 36, band: '5', widthMhz: 80, centerChannel: 42, phy: '802.11ac', connected: true, security: { protocol: 'wpa2', akm: ['PSK'], pairwise: ['CCMP'], pmf: 'capable' } },
      ],
    },
    gateway: {
      ip: '192.168.1.1',
      ping: { target: '192.168.1.1', sent: 10, received: 10, avgMs: 3, minMs: 2, maxMs: 4, jitterMs: 1 },
      ports: [{ port: 443, service: 'https', open: true }],
      upnp: { found: false, igd: false, devices: [] },
    },
    internet: {
      targets: [{ target: '1.1.1.1', label: 'Cloudflare', sent: 10, received: 10, avgMs: 15, jitterMs: 2 }],
      mtu: { mtu: 1500, method: 'df' },
      http: [{ url: 'https://x', ok: true, timeMs: 120 }],
    },
    dns: { system: [{ server: '192.168.1.1', ok: true, timeMs: 20 }], public: [{ server: '1.1.1.1', label: 'Cloudflare', ok: true, timeMs: 15 }] },
    firewall: { source: 'registry', profiles: [{ name: 'private', enabled: true, active: true }, { name: 'public', enabled: true }] },
    errors: [],
  } satisfies Scan);
}
