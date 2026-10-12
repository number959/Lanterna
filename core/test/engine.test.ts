import { build } from 'esbuild';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { describe, expect, it } from 'vitest';
import { demoScan } from '../src/demo/sample';
import { ACTIONS, adviseChannels, analyze, bandOf, freqToChannel, METRICS, renderText, spectrum } from '../src/engine';
import type { Bss, Scan } from '../src/engine';

// Scansione minima e sana: ogni test modifica solo ciò che gli interessa.
function base(): Scan {
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

const find = (scan: Scan, id: string) => analyze(scan).findings.find((f) => f.id === id);
const me = (s: Scan) => s.wifi!.networks[0];

describe('canali e frequenze', () => {
  it('converte frequenza in canale e banda', () => {
    expect([2412, 2437, 2462, 2472, 2484].map(freqToChannel)).toEqual([1, 6, 11, 13, 14]);
    expect([5180, 5500, 5745, 5825].map(freqToChannel)).toEqual([36, 100, 149, 165]);
    expect([5955, 6115, 5935].map(freqToChannel)).toEqual([1, 33, 2]);
    expect([2437, 5180, 5955].map(bandOf)).toEqual(['2.4', '5', '6']);
  });

  it('calcola lo spettro dei canali larghi', () => {
    expect(spectrum({ band: '2.4', channel: 6, widthMhz: 20 })).toEqual([2427, 2447]);
    // Canale 5 a 40 MHz con secondario sopra: centro sul canale 7.
    expect(spectrum({ band: '2.4', channel: 5, widthMhz: 40, centerChannel: 7 })).toEqual([2422, 2462]);
    expect(spectrum({ band: '5', channel: 36, widthMhz: 80, centerChannel: 42 })).toEqual([5170, 5250]);
  });

  it('consiglia il canale 2,4 GHz meno affollato tra 1, 6 e 11', () => {
    const mk = (ch: number, rssi: number, ssid = 'x' + ch + rssi): Bss => ({ ssid, bssid: `${ch}${rssi}`, rssiDbm: rssi, freqMhz: 2407 + 5 * ch, channel: ch, band: '2.4', widthMhz: 20 });
    const adv = adviseChannels([mk(1, -50), mk(1, -55), mk(6, -60), mk(11, -85), mk(6, -40, 'Casa')], 'Casa');
    const a24 = adv.find((a) => a.band === '2.4')!;
    expect(a24.recommended).toBe(11);
    expect(a24.current).toBe(6);
    expect(a24.scores).toHaveLength(13);
    // La rete "Casa" non viene contata come interferenza a sé stessa.
    expect(a24.scores[5].networks).toBe(1);
  });

  it('a 5 GHz preferisce un blocco non DFS a parità di carico', () => {
    const adv = adviseChannels([], 'Casa').concat(
      adviseChannels([{ ssid: 'Casa', bssid: '1', rssiDbm: -50, freqMhz: 5180, channel: 36, band: '5', widthMhz: 80, centerChannel: 42 }], 'Casa'),
    );
    const a5 = adv.find((a) => a.band === '5')!;
    expect(a5.recommended).toBe(36);
    expect(a5.scores.find((s) => s.channel === 52)?.dfs).toBe(true);
  });
});

describe('Wi-Fi', () => {
  it.each([
    [-50, 'ok'],
    [-67, 'ok'],
    [-68, 'warn'],
    [-75, 'warn'],
    [-76, 'crit'],
  ])('RSSI %i dBm → %s', (rssi, sev) => {
    const s = base();
    me(s).rssiDbm = rssi;
    expect(find(s, 'wifi.rssi')?.severity).toBe(sev);
  });

  it('stima i dBm dalla qualità quando manca la misura diretta', () => {
    const s = base();
    s.wifi!.networks = [];
    s.wifi!.connected!.signalQuality = 60;
    const f = find(s, 'wifi.rssi')!;
    expect(f.numeric).toBe(-70);
    expect(f.value).toContain('stimato');
  });

  it('segnala il 2,4 GHz quando la stessa rete è disponibile a 5 GHz', () => {
    const s = base();
    s.wifi!.networks = [
      { ...me(s), band: '2.4', channel: 6, freqMhz: 2437, widthMhz: 20, centerChannel: undefined },
      { ...me(s), bssid: 'aa:aa:aa:aa:aa:02', connected: false },
    ];
    s.wifi!.connected!.band = '2.4';
    const f = find(s, 'wifi.band')!;
    expect(f.severity).toBe('warn');
    expect(f.actions).toContain('use-5ghz');
  });

  it('segnala canali 2,4 GHz intermedi e larghezza 40 MHz', () => {
    const s = base();
    s.wifi!.networks = [{ ...me(s), band: '2.4', channel: 4, freqMhz: 2427, widthMhz: 40, centerChannel: 6 }];
    expect(find(s, 'wifi.overlap24')?.severity).toBe('warn');
    expect(find(s, 'wifi.width')?.actions).toEqual(['width-24-20']);
  });

  it('conta le reti forti sullo stesso spettro ignorando la propria', () => {
    const s = base();
    const other = (n: number, rssi: number): Bss => ({ ssid: 'Vicino' + n, bssid: 'bb:' + n, rssiDbm: rssi, freqMhz: 5200, channel: 40, band: '5', widthMhz: 20 });
    s.wifi!.networks.push(
      { ...me(s), bssid: 'aa:aa:aa:aa:aa:09', connected: false }, // nodo mesh della stessa rete
      other(1, -60),
      other(2, -70),
      other(3, -88), // debole: non conta come "forte"
    );
    const f = find(s, 'wifi.cochannel')!;
    expect(f.numeric).toBe(2);
    expect(f.value).toBe('2 forti · 3 totali');
    expect(f.severity).toBe('warn');
  });

  it.each([
    ['open', [], 'crit'],
    ['wep', ['WEP'], 'crit'],
    ['wpa2', ['TKIP', 'CCMP'], 'warn'],
    ['wpa2', ['CCMP'], 'ok'],
    ['wpa3', ['CCMP'], 'ok'],
  ] as const)('sicurezza %s %j → %s', (protocol, pairwise, sev) => {
    const s = base();
    me(s).security = { protocol, akm: [], pairwise: [...pairwise] };
    expect(find(s, 'wifi.security')?.severity).toBe(sev);
  });

  it('segnala PMF assente e WPS attivo', () => {
    const s = base();
    me(s).security = { protocol: 'wpa2', akm: ['PSK'], pairwise: ['CCMP'], pmf: 'disabled', wps: true };
    expect(find(s, 'wifi.pmf')?.severity).toBe('warn');
    expect(find(s, 'wifi.wps')?.actions).toEqual(['disable-wps']);
  });

  it('attribuisce lo standard vecchio al PC se il router è più moderno', () => {
    const s = base();
    s.wifi!.connected!.phy = '802.11n';
    me(s).phy = '802.11ax';
    const f = find(s, 'wifi.phy')!;
    expect(f.severity).toBe('warn');
    expect(f.verdict).toContain('scheda Wi-Fi di questo PC');
  });
});

describe('rete locale', () => {
  it('APIPA è critico', () => {
    const s = base();
    s.adapters[0].ipv4 = ['169.254.10.20/16'];
    s.adapters[0].gateways = [];
    delete s.gateway;
    expect(find(s, 'lan.address')?.severity).toBe('crit');
    expect(find(s, 'lan.gateway')?.severity).toBe('crit');
  });

  it('router che ignora il ping ma risponde su altre porte non è un guasto', () => {
    const s = base();
    s.gateway!.ping = { target: '192.168.1.1', sent: 5, received: 0 };
    expect(find(s, 'lan.gwloss')?.severity).toBe('info');
    s.gateway!.ports = [];
    expect(find(s, 'lan.gwloss')?.severity).toBe('crit');
  });

  it('latenza e perdite verso il router', () => {
    const s = base();
    s.gateway!.ping = { target: 'gw', sent: 50, received: 48, avgMs: 35, jitterMs: 12 };
    expect(find(s, 'lan.gwlatency')?.severity).toBe('warn');
    expect(find(s, 'lan.gwloss')?.severity).toBe('crit'); // 4 %
    expect(find(s, 'lan.jitter')?.severity).toBe('warn');
  });

  it('porta Ethernet a 100 Mbit/s', () => {
    const s = base();
    s.adapters.push({ name: 'Ethernet', kind: 'ethernet', up: true, ipv4: ['192.168.1.11/24'], ipv6: [], gateways: [], dns: [], linkMbps: 100 });
    expect(find(s, 'lan.linkspeed.Ethernet')?.actions).toEqual(['check-cable']);
  });
});

describe('Internet e DNS', () => {
  it('distingue latenza causata in casa da quella dell\'operatore', () => {
    const s = base();
    s.internet!.targets[0].avgMs = 90;
    let f = find(s, 'net.latency')!;
    expect(f.severity).toBe('crit');
    expect(f.actions).toContain('contact-isp');
    s.gateway!.ping!.avgMs = 60;
    f = find(s, 'net.latency')!;
    expect(f.actions).toContain('move-closer');
    expect(f.verdict).toContain('in casa');
  });

  it('ping bloccati ma web funzionante non sono "Internet assente"', () => {
    const s = base();
    s.internet!.targets = [{ target: '1.1.1.1', sent: 4, received: 0 }];
    expect(find(s, 'net.latency')?.severity).toBe('info');
    s.internet!.http = [{ url: 'x', ok: false, error: 'timeout' }];
    expect(find(s, 'net.latency')?.severity).toBe('crit');
  });

  it('traceroute: ignora il singolo nodo lento, segnala il salto persistente', () => {
    const s = base();
    s.internet!.traceroute = [
      { ttl: 1, ip: 'a', rttMs: 2 },
      { ttl: 2, ip: 'b', rttMs: 90 }, // lento a rispondere, ma i successivi sono veloci
      { ttl: 3, ip: 'c', rttMs: 12 },
      { ttl: 4, ip: 'd', rttMs: 14 },
    ];
    expect(find(s, 'net.trace')?.severity).toBe('ok');
    s.internet!.traceroute = [
      { ttl: 1, ip: 'a', rttMs: 2 },
      { ttl: 2, ip: 'b', rttMs: 8 },
      { ttl: 3, ip: 'c', rttMs: 70 },
      { ttl: 4, ip: 'd', rttMs: 72 },
    ];
    const f = find(s, 'net.trace')!;
    expect(f.severity).toBe('warn');
    expect(f.verdict).toContain('salto 3');
  });

  it('traceroute che non raggiunge la destinazione è dichiarato parziale', () => {
    const s = base();
    s.internet!.traceTarget = '1.1.1.1';
    s.internet!.traceroute = [{ ttl: 1, ip: '192.168.1.1', rttMs: 1 }, { ttl: 2, ip: '10.0.0.1', rttMs: 9 }, { ttl: 3 }];
    expect(find(s, 'net.trace')?.verdict).toContain('Percorso parziale');
    s.internet!.traceroute.push({ ttl: 4, ip: '1.1.1.1', rttMs: 12 });
    expect(find(s, 'net.trace')?.verdict).toContain('Percorso regolare');
  });

  it('MTU', () => {
    const s = base();
    expect(find(s, 'net.mtu')?.severity).toBe('ok');
    s.internet!.mtu!.mtu = 1492;
    expect(find(s, 'net.mtu')?.verdict).toContain('PPPoE');
    s.internet!.mtu!.mtu = 1300;
    expect(find(s, 'net.mtu')?.severity).toBe('warn');
  });

  it('DNS muto è critico; DNS pubblico molto più veloce viene suggerito', () => {
    const s = base();
    s.dns!.system = [{ server: '192.168.1.1', ok: false, error: 'timeout' }];
    expect(find(s, 'dns.time')?.severity).toBe('crit');
    s.dns!.system = [{ server: '192.168.1.1', ok: true, timeMs: 140 }];
    expect(find(s, 'dns.time')?.severity).toBe('warn');
    expect(find(s, 'dns.compare')?.actions).toEqual(['change-dns']);
  });
});

describe('router e sicurezza', () => {
  it('telnet aperto è critico e va in sicurezza', () => {
    const s = base();
    s.gateway!.ports = [{ port: 23, service: 'telnet', open: true }];
    const f = find(s, 'router.port.23')!;
    expect(f.severity).toBe('crit');
    expect(f.category).toBe('security');
  });

  it('UPnP IGD attivo', () => {
    const s = base();
    s.gateway!.upnp = { found: true, igd: true, devices: [{ modelName: 'X1' }] };
    expect(find(s, 'router.upnp')?.actions).toEqual(['disable-upnp']);
  });

  it('firewall: profilo attivo spento è critico, inattivo è avviso', () => {
    const s = base();
    s.firewall!.profiles = [{ name: 'private', enabled: false, active: true }];
    expect(find(s, 'sec.firewall')?.severity).toBe('crit');
    s.firewall!.profiles = [{ name: 'private', enabled: true, active: true }, { name: 'public', enabled: false }];
    expect(find(s, 'sec.firewall')?.severity).toBe('warn');
  });
});

describe('sintesi', () => {
  it('una rete sana ha punteggio alto e piano vuoto', () => {
    const a = analyze(base());
    expect(a.findings.filter((f) => f.severity === 'warn' || f.severity === 'crit')).toEqual([]);
    expect(a.score).toBeGreaterThanOrEqual(90);
    expect(a.grade).toBe('ottima');
  });

  it('il titolo segnala le misure non riuscite', () => {
    const s = base();
    expect(analyze(s).headline).toBe('Nessun problema rilevato nelle misure eseguite.');
    s.errors = [{ probe: 'Firewall di Windows', message: 'non leggibile' }, { probe: 'UPnP', message: 'x' }];
    expect(analyze(s).headline).toContain('2 misure non sono riuscite');
  });

  it('ogni problema rimanda a voci di knowledge base e azioni esistenti', () => {
    const a = analyze(demoScan);
    for (const f of a.findings) {
      expect(METRICS[f.metric], f.metric).toBeDefined();
      for (const id of f.actions) expect(ACTIONS[id], id).toBeDefined();
    }
  });

  it('il piano unisce le azioni ripetute e mette prima i problemi critici', () => {
    const a = analyze(demoScan);
    const ids = a.plan.map((p) => p.action.id);
    expect(new Set(ids).size).toBe(ids.length);
    const closer = a.plan.find((p) => p.action.id === 'move-closer')!;
    expect(closer.findings.length).toBeGreaterThan(1);
    expect(a.plan[0].severity).toBe('crit');
  });

  it('la demo produce un quadro coerente', () => {
    const a = analyze(demoScan);
    expect(a.score).toBeLessThan(70); // ci sono problemi critici
    const ids = a.findings.map((f) => f.id);
    for (const id of ['wifi.rssi', 'wifi.band', 'wifi.overlap24', 'wifi.width', 'router.port.23', 'router.upnp', 'sec.firewall', 'wifi.wps'])
      expect(ids).toContain(id);
    expect(a.channels.find((c) => c.band === '2.4')?.recommended).toBeTypeOf('number');
  });

  it('rapporto testuale completo', () => {
    const txt = renderText(demoScan, analyze(demoScan), { verbose: true });
    expect(txt).toContain('Punteggio complessivo');
    expect(txt).toContain("PIANO D'AZIONE");
    expect(txt).toContain('[CRIT]');
    for (const line of txt.split('\n')) expect(line.length).toBeLessThanOrEqual(90);
  });
});

describe('bundle per host senza moduli (goja)', () => {
  it('gira come script globale ES2015 e dà lo stesso risultato', async () => {
    const entry = fileURLToPath(new URL('../src/engine/global.ts', import.meta.url));
    const out = await build({ entryPoints: [entry], bundle: true, format: 'iife', target: 'es2015', write: false });
    const code = out.outputFiles[0].text;
    // Nessuna sintassi successiva a ES2015 che goja potrebbe non supportare.
    expect(code).not.toMatch(/\basync\b|\bawait\b/);
    expect(code).not.toMatch(/[\w)\]]\s*\?\?\s*[\w("'[]/); // nullish coalescing
    expect(code).not.toMatch(/[\w)\]]\?\.[\w([]/); // optional chaining
    expect(code).not.toContain('toLocaleString'); // goja non implementa Intl
    const ctx: Record<string, unknown> = {};
    ctx.globalThis = ctx;
    vm.createContext(ctx);
    vm.runInContext(code, ctx);
    const engine = ctx.LanternaEngine as { analyzeJson(s: string): string; reportText(s: string, v: boolean): string };
    const json = JSON.stringify(demoScan);
    expect(JSON.parse(engine.analyzeJson(json))).toEqual(JSON.parse(JSON.stringify(analyze(demoScan))));
    expect(engine.reportText(json, false)).toContain('LANterna');
    expect(readFileSync(entry, 'utf8')).toContain('LanternaEngine');
  });
});
