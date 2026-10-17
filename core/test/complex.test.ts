import { describe, expect, it } from 'vitest';
import { clinicScan } from '../src/demo/clinic';
import { demoScan } from '../src/demo/sample';
import { ACTIONS, adviseChannels, analyze, ASSESS_QUESTIONS, corporateDomain, METRICS, renderText, scoreAssessment } from '../src/engine';
import type { Bss, ReachResult, Scan, WifiSecurity } from '../src/engine';
import { base } from './fixtures';

// Reti complesse: più access point, reti aziendali con dominio, inventario,
// verifiche di raggiungibilità e autovalutazione.

const find = (scan: Scan, id: string) => analyze(scan).findings.find((f) => f.id === id);
const ids = (scan: Scan) => analyze(scan).findings.map((f) => f.id);

const ent: WifiSecurity = { protocol: 'wpa2', akm: ['802.1X'], pairwise: ['CCMP'], pmf: 'capable' };
const radio = (bssid: string, channel: number, rssiDbm: number, extra: Partial<Bss> = {}): Bss => ({
  ssid: 'Azienda',
  bssid,
  rssiDbm,
  channel,
  band: channel > 14 ? '5' : '2.4',
  freqMhz: channel > 14 ? 5000 + channel * 5 : 2407 + channel * 5,
  widthMhz: channel > 14 ? 40 : 20,
  centerChannel: channel > 14 ? channel + 2 : undefined,
  phy: '802.11ax',
  security: ent,
  roaming: { k: true, v: true, r: true },
  ...extra,
});

/** Rete aziendale con tre AP: il PC è collegato al primo. */
function multiAp(nets: Bss[]): Scan {
  const s = base();
  s.wifi!.connected = { ssid: 'Azienda', bssid: nets[0].bssid, rxMbps: 400, txMbps: 400, phy: '802.11ax', band: nets[0].band, channel: nets[0].channel };
  s.wifi!.networks = nets.map((n, i) => ({ ...n, connected: i === 0 }));
  return s;
}

describe('rete con più access point', () => {
  const healthy = () =>
    multiAp([
      radio('00:11:22:33:10:d0', 36, -55),
      radio('00:11:22:33:20:d0', 52, -66),
      radio('00:11:22:33:30:d0', 100, -72),
      radio('00:11:22:33:10:c0', 1, -50),
      radio('00:11:22:33:20:c0', 6, -60),
    ]);

  it('riconosce gli AP della rete senza contare due volte un AP dual band', () => {
    const f = find(healthy(), 'wifi.aps');
    expect(f?.numeric).toBe(3);
    expect(f?.value).toBe('3 AP · 5 radio');
    // Un solo router dual band non è una rete con più AP.
    expect(ids(demoScan)).not.toContain('wifi.aps');
    expect(ids(demoScan)).not.toContain('wifi.roaming');
  });

  it('rete ben progettata: canali diversi, AP migliore, roaming completo, protezione coerente', () => {
    const s = healthy();
    expect(find(s, 'wifi.owncochannel')?.severity).toBe('ok');
    expect(find(s, 'wifi.sticky')?.severity).toBe('ok');
    expect(find(s, 'wifi.roaming')?.severity).toBe('ok');
    expect(find(s, 'wifi.mixedsec')?.severity).toBe('ok');
    expect(find(s, 'wifi.width')?.severity).toBe('ok'); // 40 MHz con più AP è la scelta giusta
    expect(find(s, 'wifi.security')?.value).toContain('WPA2-Enterprise');
    expect(find(s, 'wifi.security')?.verdict).toContain('RADIUS');
  });

  it('segnala due AP della stessa rete sullo stesso canale solo se si ricevono entrambi', () => {
    const s = healthy();
    s.wifi!.networks[1] = { ...s.wifi!.networks[1], channel: 36, freqMhz: 5180, centerChannel: 38 };
    const f = find(s, 'wifi.owncochannel');
    expect(f?.severity).toBe('warn');
    expect(f?.actions).toContain('plan-ap-channels');
    expect(f?.verdict).toContain('compreso quello a cui sei collegato');
    s.wifi!.networks[1].rssiDbm = -85; // troppo debole per disturbare
    expect(find(s, 'wifi.owncochannel')?.severity).toBe('ok');
  });

  it('sticky client: AP debole quando uno della stessa banda si sente molto meglio', () => {
    const s = multiAp([radio('00:11:22:33:10:d0', 36, -77), radio('00:11:22:33:20:d0', 52, -60), radio('00:11:22:33:10:c0', 1, -58)]);
    const f = find(s, 'wifi.sticky');
    expect(f?.severity).toBe('warn');
    expect(f?.numeric).toBe(17);
    expect(f?.actions).toContain('fix-roaming');
    // Il giudizio sul segnale punta all'AP scelto, non alla copertura.
    const rssi = find(s, 'wifi.rssi');
    expect(rssi?.verdict).toContain('il problema è l\'AP scelto');
    expect(rssi?.actions[0]).toBe('fix-roaming');
    expect(rssi?.actions).not.toContain('add-mesh');
    // La radio a 2,4 GHz più forte non conta: le bande non si confrontano.
    const t = multiAp([radio('00:11:22:33:10:d0', 36, -70), radio('00:11:22:33:10:c0', 1, -50), radio('00:11:22:33:20:d0', 52, -72)]);
    expect(find(t, 'wifi.sticky')?.severity).toBe('ok');
  });

  it('roaming: 802.1X senza 802.11r, funzioni diverse tra AP e Mobility Domain diversi', () => {
    const s = healthy();
    for (const n of s.wifi!.networks) n.roaming = { k: true, v: true, r: false };
    let f = find(s, 'wifi.roaming');
    expect(f?.severity).toBe('info');
    expect(f?.value).toBe('k sì · v sì · r no');
    expect(f?.verdict).toContain('autenticazione 802.1X');
    expect(f?.actions).toEqual(['fix-roaming']);
    s.wifi!.networks[2].roaming = { k: true, v: false, r: false };
    expect(find(s, 'wifi.roaming')?.verdict).toContain('Non tutti gli AP');
    for (const n of s.wifi!.networks) n.roaming = { k: true, v: true, r: true, mdid: '1a2b' };
    s.wifi!.networks[2].roaming = { k: true, v: true, r: true, mdid: '3c4d' };
    f = find(s, 'wifi.roaming');
    expect(f?.severity).toBe('info');
    expect(f?.verdict).toContain('Mobility Domain diversi (1a2b, 3c4d)');
  });

  it('AP aperto con il nome di una rete protetta: possibile AP gemello', () => {
    const s = healthy();
    s.wifi!.networks.push(radio('da:a1:19:6b:22:01', 6, -71, { security: { protocol: 'open', akm: [], pairwise: [] }, roaming: undefined, connected: false }));
    const f = find(s, 'wifi.mixedsec');
    expect(f?.severity).toBe('crit');
    expect(f?.category).toBe('security');
    expect(f?.verdict).toContain('da:a1:19:6b:22:01');
    expect(f?.actions).toEqual(['check-rogue-ap']);
    // La radio estranea non entra nel conteggio degli AP né nelle coppie sullo stesso canale.
    expect(find(s, 'wifi.aps')?.numeric).toBe(3);
    expect(find(s, 'wifi.owncochannel')?.severity).toBe('ok');
  });

  it('protezioni diverse ma dello stesso tipo sono solo un avviso di configurazione', () => {
    const s = healthy();
    const psk = (p: WifiSecurity['protocol']): WifiSecurity => ({ protocol: p, akm: p === 'wpa2' ? ['PSK'] : ['PSK', 'SAE'], pairwise: ['CCMP'] });
    s.wifi!.networks.forEach((n, i) => (n.security = psk(i === 2 ? 'wpa2' : 'wpa2/wpa3')));
    expect(find(s, 'wifi.mixedsec')?.severity).toBe('info');
    s.wifi!.networks[2].security = ent; // 802.1X contro password condivisa
    expect(find(s, 'wifi.mixedsec')?.severity).toBe('warn');
  });

  it('le altre reti delle stesse radio non sono vicini da evitare', () => {
    const s = healthy();
    const guest = radio('00:11:22:33:10:d1', 36, -55, { ssid: 'Azienda-Ospiti', security: { protocol: 'owe', akm: ['OWE'], pairwise: ['CCMP'] }, connected: false });
    s.wifi!.networks.push(guest);
    expect(find(s, 'wifi.cochannel')?.numeric).toBe(0);
    const advice = adviseChannels(s.wifi!.networks, 'Azienda').find((c) => c.band === '5')!;
    expect(advice.current).toBe(36);
    expect(advice.recommended).toBe(36);
    // Una rete diversa sullo stesso canale, da un'altra radio, resta un vicino.
    s.wifi!.networks.push({ ...guest, ssid: 'Vicino', bssid: '66:77:88:99:aa:bb' });
    expect(find(s, 'wifi.cochannel')?.numeric).toBe(1);
  });
});

describe('reti aziendali', () => {
  it('riconosce il dominio e non suggerisce di cambiare DNS sul PC', () => {
    const s = base();
    s.agent.domain = 'clinica.local';
    s.dns!.system = [{ server: '10.0.0.10', ok: true, timeMs: 140 }];
    s.dns!.public = [{ server: '1.1.1.1', label: 'Cloudflare', ok: true, timeMs: 15 }];
    const a = analyze(s);
    expect(a.findings.find((f) => f.id === 'lan.domain')?.value).toBe('clinica.local');
    const actions = a.findings.flatMap((f) => f.actions);
    expect(actions).not.toContain('change-dns');
    expect(actions).toContain('internal-dns');
    expect(a.findings.find((f) => f.id === 'dns.compare')?.verdict).toContain('non si cambiano sul PC');
  });

  it('deduce la rete aziendale da suffisso e DNS interni, non dai suffissi domestici', () => {
    const s = base();
    const ad = s.adapters[0];
    ad.dnsSuffix = 'studio.lan';
    expect(corporateDomain(s, ad)).toBeUndefined(); // suffisso domestico
    ad.dnsSuffix = 'fritz.box';
    expect(corporateDomain(s, ad)).toBeUndefined();
    ad.dnsSuffix = 'ospedale.example.it';
    expect(corporateDomain(s, ad)).toBeUndefined(); // il DNS è il router
    ad.dns = ['10.1.1.5', '10.1.1.6'];
    expect(corporateDomain(s, ad)).toEqual({ name: 'ospedale.example.it', joined: false });
    ad.dns = ['8.8.8.8'];
    expect(corporateDomain(s, ad)).toBeUndefined(); // DNS pubblico: nessun DNS interno
  });

  it('indica il server DHCP quando non è il router', () => {
    const s = base();
    s.adapters[0].dhcpServer = '10.0.0.10';
    expect(find(s, 'lan.address')?.verdict).toContain('server DHCP 10.0.0.10');
    s.adapters[0].dhcpServer = '192.168.1.1';
    expect(find(s, 'lan.address')?.verdict).toContain('assegnato dal router');
  });

  it('sottorete molto ampia: possibile rete piatta', () => {
    const s = base();
    expect(ids(s)).not.toContain('lan.subnet');
    s.adapters[0].ipv4 = ['10.20.30.40/16'];
    const f = find(s, 'lan.subnet');
    expect(f?.value).toBe('/16 · 65.534 indirizzi');
    expect(f?.severity).toBe('info');
    expect(f?.actions).toEqual(['plan-segmentation']);
    expect(f?.verdict).toContain('Se ospita insieme PC');
  });

  it('stesso MAC per più indirizzi: avviso se è quello del router', () => {
    const s = base();
    s.lan = { neighbors: [{ ip: '192.168.1.20', mac: 'aa:bb:cc:00:00:01' }, { ip: '192.168.1.21', mac: 'AA-BB-CC-00-00-01' }, { ip: '192.168.1.30', mac: 'ff:ff:ff:ff:ff:ff' }, { ip: '192.168.1.31', mac: 'ff:ff:ff:ff:ff:ff' }] };
    let f = find(s, 'lan.dupmac');
    expect(f?.severity).toBe('info');
    expect(f?.verdict).toContain('aa:bb:cc:00:00:01 → 192.168.1.20, 192.168.1.21');
    s.gateway!.mac = 'de:ad:be:ef:00:01';
    s.lan.neighbors.push({ ip: '192.168.1.1', mac: 'de:ad:be:ef:00:01' }, { ip: '192.168.1.66', mac: 'de:ad:be:ef:00:01' });
    f = find(s, 'lan.dupmac');
    expect(f?.severity).toBe('warn');
    expect(f?.category).toBe('security');
    expect(f?.verdict).toContain('192.168.1.66');
  });
});

describe('infrastruttura', () => {
  const r = (x: Partial<ReachResult> & Pick<ReachResult, 'host' | 'expect' | 'status'>): ReachResult => ({ ok: false, ...x });

  it('senza dati di infrastruttura la categoria non ha punteggio', () => {
    const a = analyze(base());
    expect(a.categories.find((c) => c.category === 'infra')?.score).toBeNull();
  });

  it('inventario: riepilogo, dispositivi senza nome e sottorete quasi piena', () => {
    const s = base();
    s.infra = {
      inventory: {
        subnet: '192.168.1.0/29',
        scanned: 5,
        startedAt: '2026-01-01T00:00:00Z',
        durationMs: 2000,
        hosts: [
          { ip: '192.168.1.1', mac: 'aa:00:00:00:00:01', name: 'router.lan', rttMs: 1, gateway: true },
          { ip: '192.168.1.2', mac: '02:00:00:00:00:02', rttMs: 3, randomMac: true },
          { ip: '192.168.1.3', mac: 'aa:00:00:00:00:03', netbios: 'STAMPANTE' },
          { ip: '192.168.1.4', mac: 'aa:00:00:00:00:04', rttMs: 2 },
          { ip: '192.168.1.5', mac: 'aa:00:00:00:00:05', self: true },
          { ip: '192.168.1.6', mac: 'aa:00:00:00:00:06', name: 'pc.lan', rttMs: 2 },
        ],
      },
    };
    const f = find(s, 'infra.inventory');
    expect(f?.value).toBe('5 dispositivi');
    expect(f?.severity).toBe('warn'); // tutti e 6 gli indirizzi in uso
    expect(f?.verdict).toContain('4 rispondono al ping, 1 è stato visto solo tramite ARP');
    expect(f?.verdict).toContain('2 sono senza nome');
    expect(f?.actions).toEqual(['identify-devices', 'dhcp-capacity']);
    // Una sottorete esaminata solo in parte non può dirsi piena.
    s.infra.inventory!.note = 'esaminato solo il blocco /24';
    expect(find(s, 'infra.inventory')?.severity).toBe('info');
  });

  it('segmentazione: risposta = violazione, rifiuto = da verificare, silenzio = ok', () => {
    const s = base();
    s.infra = { reach: { startedAt: '', results: [r({ host: '10.0.0.2', port: 22, expect: 'isolated', status: 'filtered', ok: true }), r({ host: '10.0.60.1', expect: 'isolated', status: 'noreply', ok: true })] } };
    let f = find(s, 'infra.seg');
    expect(f?.severity).toBe('ok');
    expect(f?.value).toBe('2/2 isolate');
    s.infra.reach!.results.push(r({ label: 'NAS', host: '10.0.50.5', port: 445, expect: 'isolated', status: 'closed' }));
    f = find(s, 'infra.seg');
    expect(f?.severity).toBe('warn');
    expect(f?.verdict).toContain('NAS (10.0.50.5:445)');
    s.infra.reach!.results.push(r({ label: 'Gestione', host: '10.0.0.3', port: 443, expect: 'isolated', status: 'open', rttMs: 2 }));
    f = find(s, 'infra.seg');
    expect(f?.severity).toBe('crit');
    expect(f?.actions).toEqual(['segment-network']);
    expect(f?.verdict).toMatch(/^Raggiungibili da questa rete/);
    // Destinazioni non verificabili non contano come isolate.
    s.infra.reach!.results = [r({ host: 'x.local', expect: 'isolated', status: 'unresolved' })];
    expect(find(s, 'infra.seg')?.severity).toBe('unknown');
  });

  it('servizi critici: irraggiungibile è critico, lento è un avviso', () => {
    const s = base();
    s.infra = { reach: { startedAt: '', results: [r({ label: 'PACS', host: '10.0.50.20', port: 104, expect: 'reachable', status: 'open', rttMs: 4, ok: true })] } };
    expect(find(s, 'infra.services')?.severity).toBe('ok');
    s.infra.reach!.results[0].rttMs = 180;
    expect(find(s, 'infra.services')?.severity).toBe('warn');
    s.infra.reach!.results.push(r({ label: 'HL7', host: '10.0.50.30', port: 2575, expect: 'reachable', status: 'filtered' }));
    const f = find(s, 'infra.services');
    expect(f?.severity).toBe('crit');
    expect(f?.value).toBe('1/2 raggiungibili');
    expect(f?.actions).toEqual(['check-critical-service']);
  });

  it('autovalutazione: punteggio per area, non applicabili esclusi, azioni nel piano', () => {
    const answers = Object.fromEntries(ASSESS_QUESTIONS.filter((q) => q.area === 'backup').map((q) => [q.id, 'yes' as const]));
    answers['bak-offline'] = 'no' as never;
    answers['bak-config'] = 'na' as never;
    const backup = scoreAssessment(answers).find((a) => a.area.id === 'backup')!;
    expect(backup.score).toBe(63); // (2 + 3) su 8 punti applicabili
    expect(backup.gaps.map((g) => g.q.id)).toEqual(['bak-offline']);
    const s = base();
    s.infra = { assessment: { answers } };
    const a = analyze(s);
    const f = a.findings.find((x) => x.id === 'assess.backup');
    expect(f?.severity).toBe('warn');
    expect(f?.verdict).toContain('copia offline o immutabile');
    expect(a.plan.map((p) => p.action.id)).toContain('backup-offline');
    // Le aree senza risposte non compaiono.
    expect(a.findings.some((x) => x.id === 'assess.medicali')).toBe(false);
  });

  it('ogni domanda dell\'autovalutazione porta a un\'azione esistente', () => {
    for (const q of ASSESS_QUESTIONS) expect(ACTIONS[q.action], q.id).toBeDefined();
    expect(new Set(ASSESS_QUESTIONS.map((q) => q.id)).size).toBe(ASSESS_QUESTIONS.length);
  });
});

describe('demo della clinica', () => {
  it('mostra i problemi tipici di una rete sanitaria', () => {
    const a = analyze(clinicScan);
    const sev = (id: string) => a.findings.find((f) => f.id === id)?.severity;
    expect(sev('wifi.mixedsec')).toBe('crit');
    expect(sev('wifi.sticky')).toBe('warn');
    expect(sev('wifi.owncochannel')).toBe('warn');
    expect(sev('infra.seg')).toBe('crit');
    expect(sev('infra.services')).toBe('crit');
    expect(sev('lan.domain')).toBe('info');
    expect(sev('wifi.cochannel')).toBe('ok'); // le reti ospiti e dispositivi degli stessi AP non contano
    expect(a.findings.flatMap((f) => f.actions)).not.toContain('change-dns');
    for (const f of a.findings) {
      expect(METRICS[f.metric], f.metric).toBeDefined();
      for (const id of f.actions) expect(ACTIONS[id], id).toBeDefined();
    }
  });

  it('rapporto con i dettagli dell\'infrastruttura entro 90 colonne', () => {
    const s = structuredClone(clinicScan);
    s.infra!.assessment = { answers: { 'seg-ospiti': 'yes', 'seg-medicali': 'partial', 'bak-offline': 'no' } };
    const txt = renderText(s, analyze(s), { verbose: true });
    expect(txt).toContain('INFRASTRUTTURA: DETTAGLI');
    expect(txt).toContain('Gestione switch (SSH) 10.0.0.2:22');
    expect(txt).toContain('ecg-cardio-02.clinic…');
    expect(txt).toContain('Autovalutazione (dichiarata, non misurata)');
    for (const line of txt.split('\n')) expect(line.length, line).toBeLessThanOrEqual(90);
  });
});
