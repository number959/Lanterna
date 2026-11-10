import { describe, expect, it } from 'vitest';
import { analyze, buildNetworkMap, trafficScenarios } from '../src/engine';
import type { Scan, TrafficScenario } from '../src/engine';
import { clinicScan } from '../src/demo/clinic';
import { demoScan } from '../src/demo/sample';
import { isoTop } from '../src/ui/isoart';
import {
  advance,
  briefOf,
  entryMs,
  frameScene,
  glyphBox,
  HOLD_MS,
  HOLD_STOP_MS,
  isoScene,
  K_MAX,
  lanes,
  lerpCamera,
  NARROW_BELOW,
  packetNote,
  progressOf,
  revealed,
  sceneCamera,
  SEG_MS,
  stageHeight,
  timeline,
  trailOf,
  typedTarget,
} from '../src/ui/trafficlayout';
import type { Box, IsoInfo } from '../src/ui/trafficlayout';

// "Il traffico passo passo": scene ricostruite con gli indirizzi e i tempi
// dell'analisi, pacchetti scartati dove il firewall blocca, scena isometrica
// senza sovrapposizioni su schermo largo e stretto, telecamera, linea del tempo.

const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const scenes = (scan: Scan) => {
  const map = buildNetworkMap(scan, analyze(scan));
  return { map, list: trafficScenarios(map, scan) };
};
const byId = (list: TrafficScenario[], id: string) => list.find((s) => s.id === id)!;

describe('scene ricostruite', () => {
  it('casa e poliambulatorio: le scene che i dati permettono', () => {
    expect(scenes(demoScan).list.map((s) => s.id)).toEqual(['web', 'dhcp', 'ping', 'trace', 'print']);
    expect(scenes(clinicScan).list.map((s) => s.id)).toEqual(['web', 'dhcp', 'ping', 'trace', 'services', 'print']);
  });

  it('pacchetti numerati da 1, strade fatte di nodi vicini della mappa, tempi crescenti nei passi', () => {
    for (const scan of [demoScan, clinicScan]) {
      const { map, list } = scenes(scan);
      const ids = new Set(map.nodes.map((n) => n.id));
      for (const sc of list) {
        const all = sc.steps.flatMap((s) => s.packets);
        expect(all.map((p) => p.no)).toEqual(all.map((_, i) => i + 1));
        for (const p of all) {
          expect(p.hops.length).toBeGreaterThanOrEqual(2);
          for (const h of p.hops) expect(ids.has(h)).toBe(true);
          expect(new Set(p.hops).size).toBe(p.hops.length);
          if (p.stopAt !== undefined) expect(p.stopAt).toBeGreaterThan(0);
          if (p.stopAt !== undefined) expect(p.stopAt).toBeLessThan(p.hops.length);
          expect(p.size).toBeGreaterThan(0);
        }
        for (const s of sc.steps) for (let i = 1; i < s.packets.length; i++) expect(s.packets[i].t).toBeGreaterThanOrEqual(s.packets[i - 1].t);
        expect(sc.lanes[0]).toBe(map.nodes.find((n) => n.self)!.id);
      }
    }
  });

  it('i tempi sono quelli misurati: DNS, andata e ritorno verso Internet, ping al router', () => {
    const { list } = scenes(demoScan);
    const web = byId(list, 'web');
    const dns = web.steps.find((s) => s.id === 'web-dns')!;
    const dnsMs = demoScan.dns!.system.find((d) => d.ok && d.timeMs !== undefined)!.timeMs!;
    expect(dns.packets[1].t - dns.packets[0].t).toBeCloseTo(dnsMs, 1);
    expect(dns.detail).toContain(`${dnsMs} ms`);
    const tcp = web.steps.find((s) => s.id === 'web-tcp')!;
    const rtt = demoScan.internet!.targets.find((t) => t.received > 0 && t.avgMs !== undefined)!.avgMs!;
    expect(tcp.packets[1].t - tcp.packets[0].t).toBeCloseTo(rtt, 0);
    expect(tcp.packets.map((p) => p.label)).toEqual(['SYN', 'SYN-ACK', 'ACK']);
    expect(tcp.packets[1].dir).toBe('response');
    expect(tcp.packets[1].hops).toEqual([...tcp.packets[0].hops].reverse());
    const ping = byId(list, 'ping');
    const samples = demoScan.gateway!.ping!.samples!;
    ping.steps.forEach((s, i) => {
      if (samples[i] === null) expect(s.packets).toHaveLength(1);
      else expect(s.packets[1].t - s.packets[0].t).toBeCloseTo(samples[i]!, 1);
    });
    expect(ping.title).toBe('Ping al router');
    expect(byId(scenes(clinicScan).list, 'ping').title).toBe('Ping al firewall');
  });

  it('sito e pagina dalla verifica HTTPS, con lo stato vero della risposta', () => {
    const scan = clone(demoScan);
    scan.internet!.http = [{ url: 'https://cp.cloudflare.com/generate_204', ok: true, status: 204, timeMs: 180 }];
    const web = byId(scenes(scan).list, 'web');
    expect(web.steps[0].subtitle).toBe('Si apre cp.cloudflare.com');
    const http = web.steps.find((s) => s.id === 'web-http')!;
    expect(http.packets[1].label).toBe('204');
    expect(http.detail).toContain('"204 No Content"');
    expect(http.detail).not.toContain('invece di 204');
    scan.internet!.http = [{ url: 'https://www.google.com/generate_204', ok: true, status: 302, timeMs: 180 }];
    const moved = byId(scenes(scan).list, 'web').steps.find((s) => s.id === 'web-http')!;
    expect(moved.packets[1].label).toBe('302');
    expect(moved.detail).toContain('"302 Found" invece di 204');
    expect(moved.fields.find((f) => f.k === 'Risposta')!.v).toBe('302 Found');
  });

  it('servizi: i pacchetti verso le zone isolate si fermano al firewall; quelli che passano senza dovere sono segnati', () => {
    const { map, list } = scenes(clinicScan);
    const svc = byId(list, 'services');
    const fw = map.nodes.find((n) => n.gateway)!;
    const step = (label: string) => svc.steps.find((s) => s.title.startsWith(label))!;
    // Pompe infusionali: isolate, nessuna risposta, come previsto.
    const pumps = step('Pompe infusionali').packets;
    expect(pumps).toHaveLength(1);
    expect(pumps[0]).toMatchObject({ proto: 'ICMP', sev: 'ok' });
    expect(pumps[0].hops[pumps[0].stopAt!]).toBe(fw.id);
    expect(packetNote(pumps[0])).toEqual({ text: 'bloccato, come previsto', sev: 'ok' });
    // Gestione dello switch: dovrebbe essere isolata ma risponde.
    const sw = step('Gestione switch').packets;
    expect(sw.map((p) => p.label)).toEqual(['SYN', 'SYN-ACK', 'ACK']);
    expect(sw[1].sev).toBe('crit');
    expect(packetNote(sw[1])).toEqual({ text: 'passa, ma non dovrebbe', sev: 'crit' });
    expect(step('Gestione switch').detail).toContain('dovrebbe essere isolato');
    // Integrazione HL7: deve rispondere ma non risponde, con la ritrasmissione.
    const hl7 = step('Integrazione HL7').packets;
    expect(hl7.map((p) => p.info.startsWith('[Ritrasmissione]'))).toEqual([false, true]);
    expect(hl7.every((p) => p.sev === 'crit' && p.stopAt !== undefined)).toBe(true);
    // Cartella clinica: risponde come previsto, nessuna nota.
    const ehr = step('Cartella clinica').packets;
    expect(ehr.map((p) => packetNote(p))).toEqual([undefined, undefined, undefined]);
  });

  it('DHCP con il server in un\'altra rete: il router fa da relay', () => {
    const dhcp = byId(scenes(clinicScan).list, 'dhcp');
    expect(dhcp.steps.map((s) => s.packets[0].label)).toEqual(['DISCOVER', 'OFFER', 'REQUEST', 'ACK']);
    expect(dhcp.steps[0].detail).toContain('relay');
    expect(dhcp.steps[0].packets[0]).toMatchObject({ src: '0.0.0.0', dst: '255.255.255.255' });
    const home = byId(scenes(demoScan).list, 'dhcp');
    expect(home.steps[0].detail).not.toContain('relay');
    expect(home.steps[1].fields[0].v).toContain('(il router)');
  });

  it('traceroute: un passo per salto, i salti muti si fermano senza risposta', () => {
    const trace = byId(scenes(demoScan).list, 'trace');
    const hops = demoScan.internet!.traceroute!;
    expect(trace.steps).toHaveLength(Math.min(10, hops.length));
    trace.steps.forEach((s, i) => {
      expect(s.packets[0].label).toBe(`TTL ${hops[i].ttl}`);
      expect(s.packets.length).toBe(hops[i].ip ? 2 : 1);
      if (!hops[i].ip) expect(packetNote(s.packets[0])!.sev).toBe('warn');
    });
  });

  it('senza dati: nessuna scena, nessun errore', () => {
    const scan = clone(demoScan);
    delete scan.internet;
    delete scan.gateway;
    const ids = scenes(scan).list.map((s) => s.id);
    expect(ids).not.toContain('web');
    expect(ids).not.toContain('ping');
    expect(ids).not.toContain('trace');
    const map = buildNetworkMap(demoScan, analyze(demoScan));
    expect(trafficScenarios({ ...map, nodes: map.nodes.filter((n) => !n.self) }, demoScan)).toEqual([]);
  });
});

describe('esiti veri dell\'analisi (revisione)', () => {
  const allText = (sc: TrafficScenario) => JSON.stringify(sc.steps);

  it('Internet giù: il DNS non risponde e il browser si ferma, senza risposte inventate', () => {
    const scan = clone(demoScan);
    for (const t of scan.internet!.targets) Object.assign(t, { received: 0, avgMs: undefined, minMs: undefined, maxMs: undefined });
    scan.internet!.http = [{ url: 'https://www.google.com/generate_204', ok: false, error: 'context deadline exceeded' }];
    for (const d of scan.dns!.system) Object.assign(d, { ok: false, timeMs: undefined, error: 'timeout' });
    const web = byId(scenes(scan).list, 'web');
    const dns = web.steps.find((s) => s.id === 'web-dns')!;
    expect(dns.packets).toHaveLength(1);
    expect(packetNote(dns.packets[0])).toEqual({ text: 'nessuna risposta', sev: 'crit' });
    expect(web.steps.map((s) => s.id)).toEqual(['web-start', 'web-dns', 'web-stop']);
    expect(allText(web)).not.toMatch(/204|SYN-ACK|ha risposto in/);
  });

  it('il DNS risponde ma la connessione no: il SYN si ferma e non ci sono TLS né HTTP', () => {
    const scan = clone(demoScan);
    scan.internet!.http = [{ url: 'https://www.google.com/generate_204', ok: false, error: 'dial tcp 142.250.180.4:443: i/o timeout' }];
    const web = byId(scenes(scan).list, 'web');
    const tcp = web.steps.find((s) => s.id === 'web-tcp')!;
    expect(tcp.packets.map((p) => p.label)).toEqual(['SYN', 'SYN']);
    expect(tcp.packets.every((p) => p.stopAt !== undefined && p.sev === 'crit')).toBe(true);
    expect(web.steps.find((s) => s.id === 'web-tls')).toBeUndefined();
    expect(web.steps.find((s) => s.id === 'web-http')).toBeUndefined();
  });

  it('proxy con 407, certificato rifiutato, verifica assente', () => {
    const scan = clone(demoScan);
    scan.internet!.http = [{ url: 'https://www.google.com/generate_204', ok: false, status: 407, timeMs: 90 }];
    const h407 = byId(scenes(scan).list, 'web').steps.find((s) => s.id === 'web-http')!;
    expect(h407.packets[1]).toMatchObject({ label: '407', sev: 'warn', note: 'risposta di errore' });
    expect(h407.detail).toContain('proxy');
    scan.internet!.http = [{ url: 'https://www.google.com/generate_204', ok: false, error: 'tls: failed to verify certificate: x509: certificate signed by unknown authority' }];
    const tls = byId(scenes(scan).list, 'web');
    expect(tls.steps.find((s) => s.id === 'web-tls')!.packets.map((p) => p.label)).toEqual(['CLIENT HELLO', 'SERVER HELLO', 'ALERT']);
    expect(tls.steps.find((s) => s.id === 'web-http')).toBeUndefined();
    delete scan.internet!.http;
    const none = byId(scenes(scan).list, 'web').steps.find((s) => s.id === 'web-http')!;
    expect(none.detail).toContain('la verifica HTTPS non c\'è');
    expect(none.fields.find((f) => f.k === 'Risposta')!.v).toContain('non misurata');
  });

  it('ping: ogni richiesta dal suo campione, nessuna risposta inventata, singolare giusto', () => {
    const scan = clone(demoScan);
    scan.gateway!.ping = { ...scan.gateway!.ping!, sent: 4, received: 0, avgMs: undefined, minMs: undefined, maxMs: undefined, samples: [null, null, null, null] };
    const ping = byId(scenes(scan).list, 'ping');
    expect(ping.steps.every((s) => s.packets.length === 1 && s.packets[0].stopAt !== undefined)).toBe(true);
    expect(ping.steps[0].detail).toContain('0 risposte');
    scan.gateway!.ping = { ...scan.gateway!.ping!, sent: 20, received: 1, avgMs: 3, minMs: 3, maxMs: 3, samples: [null, 3, ...Array(18).fill(null)] };
    const one = byId(scenes(scan).list, 'ping');
    expect(one.steps.map((s) => s.packets.length)).toEqual([1, 2, 1]);
    expect(one.steps[0].detail).toContain('1 risposta,');
  });

  it('ping bloccato: il tempo misurato con TCP si mostra come TCP', () => {
    const scan = clone(clinicScan);
    scan.gateway!.ping = { ...scan.gateway!.ping!, method: 'tcp' };
    const ping = byId(scenes(scan).list, 'ping');
    expect(ping.title).toBe('Raggiungere il firewall (TCP)');
    expect(ping.steps[0].packets.every((p) => p.proto === 'TCP')).toBe(true);
    expect(ping.steps[0].detail).toContain('non risponde al ping');
  });

  it('servizi: rifiuto di un servizio necessario, verifiche non eseguite, nessuna verifica nascosta in silenzio', () => {
    const scan = clone(clinicScan);
    const res = scan.infra!.reach!.results;
    const ehr = res.find((r) => r.label === 'Cartella clinica (web)')!;
    Object.assign(ehr, { status: 'closed', ok: false });
    res.push({ label: 'Server sconosciuto', host: 'srv-x.clinica.local', port: 443, expect: 'reachable', status: 'unresolved', ok: false });
    const svc = byId(scenes(scan).list, 'services');
    const step = svc.steps.find((s) => s.title === 'Cartella clinica (web)')!;
    const rst = step.packets.find((p) => p.label === 'RST')!;
    expect(packetNote(rst)).toEqual({ text: 'rifiuta la connessione', sev: 'crit' });
    expect(rst.breach).toBeUndefined();
    const other = svc.steps.find((s) => s.id === 'svc-other')!;
    expect(other.fields.some((f) => f.k.startsWith('Server sconosciuto') && f.v.includes('non verificata'))).toBe(true);
    // Ogni verifica dell'analisi è in un passo o nell'elenco delle altre.
    const listed = svc.steps.filter((s) => s.id !== 'svc-other').length + other.fields.length;
    expect(listed).toBe(res.length);
    const ids = svc.steps.map((s) => s.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('servizi: la stessa destinazione due volte, una zona isolata nella rete del PC', () => {
    const scan = clone(clinicScan);
    const res = scan.infra!.reach!.results;
    res.push({ ...res[0], label: 'Ancora la cartella clinica' });
    res.push({ label: 'Stampante del piano', host: '10.20.30.12', ip: '10.20.30.12', port: 9100, expect: 'isolated', status: 'filtered', ok: true });
    const svc = byId(scenes(scan).list, 'services');
    const ids = svc.steps.map((s) => s.id);
    expect(new Set(ids).size).toBe(ids.length);
    const local = svc.steps.find((s) => s.title === 'Stampante del piano');
    const text = local ? local.detail : svc.steps.find((s) => s.id === 'svc-other')!.fields.map((f) => f.k).join();
    expect(text).toMatch(/stessa rete del PC|Stampante del piano/);
    if (local) expect(local.packets[0].hops[local.packets[0].stopAt!]).toBe('ip:10.20.30.12');
  });

  it('zona isolata nella rete del PC: niente firewall tra le zone nel testo, il pacchetto si ferma al dispositivo', () => {
    const scan = clone(clinicScan);
    scan.infra!.reach!.results = [
      { label: 'Stampante del piano', host: '10.20.30.12', ip: '10.20.30.12', port: 9100, expect: 'isolated', status: 'filtered', ok: true },
      { label: 'Stampante aperta', host: '10.20.30.15', ip: '10.20.30.15', port: 9100, expect: 'isolated', status: 'open', ok: false, rttMs: 4 },
    ];
    const svc = byId(scenes(scan).list, 'services');
    const [blocked, open] = svc.steps;
    expect(blocked.detail).toContain('stessa rete del PC');
    expect(blocked.detail).not.toContain('il firewall o le regole tra le zone scartano');
    expect(blocked.packets[0].hops[blocked.packets[0].stopAt!]).toBe('ip:10.20.30.12');
    expect(open.detail).toContain('non passa dal firewall tra le zone');
    expect(open.packets.find((p) => p.label === 'SYN-ACK')!.breach).toBe(true);
  });

  it('DNS: il primo server IPv4 sulla mappa e il suo tempo, i DNS IPv6 fuori dal DHCP', () => {
    const scan = clone(demoScan);
    const a = scan.adapters.find((x) => x.gateways.includes(scan.gateway!.ip))!;
    a.dns = ['fd00::1', '192.168.1.1'];
    const list = scenes(scan).list;
    const dns = byId(list, 'web').steps.find((s) => s.id === 'web-dns')!;
    expect(dns.packets[0].dst).toBe('192.168.1.1');
    const lease = byId(list, 'dhcp').steps[1].fields.find((f) => f.k === 'DNS')!;
    expect(lease.v).toBe('192.168.1.1');
    // Il tempo è quello del server interrogato, non del primo che ha risposto.
    const clinic = clone(clinicScan);
    const first = clinic.dns!.system.find((d) => d.server === '10.10.10.10')!;
    Object.assign(first, { ok: false, timeMs: undefined, error: 'timeout' });
    const cd = byId(scenes(clinic).list, 'web').steps.find((s) => s.id === 'web-dns')!;
    expect(cd.packets).toHaveLength(1);
    expect(cd.detail).toContain('non ha risposto');
  });

  it('traceroute: i salti muti non arrivano oltre l\'ultimo router noto', () => {
    const { map, list } = scenes(clinicScan);
    const fw = map.nodes.find((n) => n.gateway)!.id;
    const trace = byId(list, 'trace');
    for (const s of trace.steps.slice(1)) {
      const p = s.packets[0];
      expect(p.hops[p.hops.length - 1]).toBe(fw);
    }
    expect(trace.steps[trace.steps.length - 1].detail).toContain('nessun router risponde');
    const scan = clone(demoScan);
    scan.internet!.traceroute = Array.from({ length: 14 }, (_, i) => ({ ttl: i + 1, ip: i === 0 ? '192.168.1.1' : `10.4.${i}.1`, rttMs: 5 + i }));
    const long = byId(scenes(scan).list, 'trace');
    expect(long.steps).toHaveLength(11);
    expect(long.steps[10].detail).toContain('14 salti');
  });

  it('strade senza doppioni: verifica verso il firewall stesso, PC che fa da DNS', () => {
    const scan = clone(clinicScan);
    scan.infra!.reach!.results.push({ label: 'Pannello del firewall', host: '10.20.30.1', ip: '10.20.30.1', port: 443, expect: 'reachable', status: 'open', ok: true, rttMs: 4 });
    const { list } = scenes(scan);
    for (const sc of list) for (const p of sc.steps.flatMap((s) => s.packets)) for (let i = 1; i < p.hops.length; i++) expect(p.hops[i]).not.toBe(p.hops[i - 1]);
    const self = clone(demoScan);
    const a = self.adapters.find((x) => x.gateways.includes(self.gateway!.ip))!;
    a.dns = [a.ipv4[0].split('/')[0]];
    const dns = byId(scenes(self).list, 'web').steps.find((s) => s.id === 'web-dns')!;
    expect(dns.packets).toHaveLength(0);
    expect(dns.subtitle).toBe('Il server DNS è questo PC');
  });

  it('NAT: doppio NAT e CGNAT detti quando la mappa li trova', () => {
    const scan = clone(demoScan);
    scan.internet!.traceroute = [
      { ttl: 1, ip: '192.168.1.1', rttMs: 2 },
      { ttl: 2, ip: '192.168.0.1', rttMs: 3 },
      { ttl: 3, ip: '100.64.12.1', rttMs: 12 },
      { ttl: 4, ip: '1.1.1.1', rttMs: 20 },
    ];
    scan.internet!.traceTarget = '1.1.1.1';
    const tcp = byId(scenes(scan).list, 'web').steps.find((s) => s.id === 'web-tcp')!;
    expect(tcp.detail).toContain('doppio NAT');
    expect(tcp.detail).toContain('CGNAT');
    expect(byId(scenes(demoScan).list, 'web').steps.find((s) => s.id === 'web-tcp')!.detail).not.toMatch(/doppio NAT|CGNAT/);
  });
});

describe('scena isometrica', () => {
  const hit = (a: Box, b: Box) => a.x0 < b.x1 - 0.5 && b.x0 < a.x1 - 0.5 && a.y0 < b.y1 - 0.5 && b.y0 < a.y1 - 0.5;
  const setup = (scan: Scan) => {
    const { map, list } = scenes(scan);
    const nodes = new Map(map.nodes.map((n) => [n.id, n]));
    const info = (id: string): IsoInfo => {
      const n = nodes.get(id)!;
      return { name: n.self ? 'Questo PC' : n.label, sub: n.ip ?? '', top: isoTop(n.kind) };
    };
    return { map, list, nodes, info, has: (id: string) => nodes.has(id) };
  };

  it('tutti i nodi della scena hanno un posto e nessun disegno sta sopra un altro', () => {
    for (const scan of [demoScan, clinicScan]) {
      const { list, info, has } = setup(scan);
      for (const narrow of [false, true])
        for (const sc of list) {
          const scene = isoScene(sc, has, timeline(sc), narrow);
          for (const id of sc.lanes) expect(scene.places.has(id), `${sc.id} ${id}`).toBe(true);
          const boxes = [...scene.places].map(([id, p]) => ({ id, b: glyphBox(p, 0.95, info(id).top) }));
          for (let i = 0; i < boxes.length; i++)
            for (let j = i + 1; j < boxes.length; j++) expect(hit(boxes[i].b, boxes[j].b), `${sc.id} ${narrow ? 'stretto' : 'largo'}: ${boxes[i].id} e ${boxes[j].id}`).toBe(false);
        }
    }
  });

  it('alla fine della scena: tutto dentro il palco, etichette senza sovrapposizioni, indirizzi interi', () => {
    for (const scan of [demoScan, clinicScan]) {
      const { list, info, has } = setup(scan);
      for (const w of [1100, 692, 600, 520, 340, 300]) {
        for (const sc of list) {
          const es = timeline(sc);
          const scene = isoScene(sc, has, es, w < NARROW_BELOW);
          const h = stageHeight(scene, w);
          const ids = [...scene.places.keys()].filter((id) => revealed(scene, id, es.length - 1, Infinity));
          expect(ids.length, sc.id).toBe(scene.places.size);
          const cam = sceneCamera(scene, ids, info, w, h);
          const placed = frameScene(scene, ids, info, cam, w);
          const where = (id: string) => `${sc.id} ${id} a ${w}px`;
          for (const [id, pl] of placed) {
            for (const b of [pl.glyph, pl.label]) {
              expect(b.x0, where(id)).toBeGreaterThanOrEqual(-0.5);
              expect(b.y0, where(id)).toBeGreaterThanOrEqual(-0.5);
              expect(b.x1, where(id)).toBeLessThanOrEqual(w + 0.5);
              expect(b.y1, where(id)).toBeLessThanOrEqual(h + 0.5);
            }
            const ip = info(id).sub;
            if (ip) expect(pl.chars, where(id)).toBeGreaterThanOrEqual(ip.length);
          }
          const all = [...placed];
          for (let i = 0; i < all.length; i++)
            for (let j = 0; j < all.length; j++) {
              if (i === j) continue;
              const [a, pa] = all[i];
              const [b, pb] = all[j];
              if (i < j) expect(hit(pa.label, pb.label), `${sc.id}: etichette di ${a} e ${b} a ${w}px`).toBe(false);
              expect(hit(pa.label, pb.glyph), `${sc.id}: etichetta di ${a} sul disegno di ${b} a ${w}px`).toBe(false);
            }
          // Disegni leggibili: mai più piccoli di un terzo.
          expect(cam.k, `${sc.id} a ${w}px`).toBeGreaterThan(0.33);
          expect(h, `${sc.id} a ${w}px`).toBeLessThanOrEqual(760);
        }
      }
    }
  });

  it('all\'inizio c\'è solo il PC, grande, con il sito che si scrive; poi compare chi riceve il pacchetto', () => {
    const { list, info, has, map } = setup(demoScan);
    const web = byId(list, 'web');
    const es = timeline(web);
    const scene = isoScene(web, has, es);
    const pc = map.nodes.find((n) => n.self)!.id;
    expect(scene.root).toBe(pc);
    const at0 = [...scene.places.keys()].filter((id) => revealed(scene, id, 0, 0));
    expect(at0).toEqual([pc]);
    const site = typedTarget(web)!;
    expect(site).toBe('www.google.com');
    const cam0 = sceneCamera(scene, at0, info, 692, 346, { id: pc, text: site });
    expect(cam0.k).toBe(K_MAX);
    // Il primo pacchetto (la domanda DNS) fa comparire il router appena parte.
    const i1 = es.findIndex((e) => e.p);
    const gw = es[i1].p!.hops[1];
    expect(revealed(scene, gw, i1, 0)).toBe(true);
    expect(revealed(scene, 'internet', i1, 0)).toBe(false);
    const all = [...scene.places.keys()].filter((id) => revealed(scene, id, es.length - 1, Infinity));
    expect(sceneCamera(scene, all, info, 692, 346).k).toBeLessThan(cam0.k);
    expect(typedTarget(byId(list, 'ping'))).toBeUndefined();
  });

  it('la strada verso Internet va a zig-zag: in alto a destra, poi in basso a destra', () => {
    const { list, has, map } = setup(clinicScan);
    const web = byId(list, 'web');
    const scene = isoScene(web, has, timeline(web));
    const main = web.steps.flatMap((s) => s.packets).find((p) => p.hops[p.hops.length - 1] === 'internet')!.hops;
    expect(main[0]).toBe(map.nodes.find((n) => n.self)!.id);
    const P = main.map((id) => scene.places.get(id)!);
    for (let i = 1; i < P.length; i++) {
      expect(P[i].x, main[i]).toBeGreaterThan(P[i - 1].x);
      expect(Math.sign(P[i].y - P[i - 1].y), main[i]).toBe(i % 2 ? -1 : 1);
    }
    // Sullo schermo stretto scende.
    const narrow = isoScene(web, has, timeline(web), true);
    const Q = main.map((id) => narrow.places.get(id)!);
    for (let i = 1; i < Q.length; i++) expect(Q[i].y).toBeGreaterThan(Q[i - 1].y);
    for (const id of main) expect(narrow.sides.get(id)).toBe('right');
  });

  it('servizi della clinica: in colonna, raggiunti da una dorsale comune, etichette a destra', () => {
    const { list, has, map } = setup(clinicScan);
    const svc = byId(list, 'services');
    const scene = isoScene(svc, has, timeline(svc));
    const fw = map.nodes.find((n) => n.gateway)!.id;
    const col = [...scene.parent].filter(([, pa]) => pa === fw).map(([c]) => c);
    expect(col.length).toBeGreaterThanOrEqual(3);
    const xs = new Set(col.map((c) => scene.places.get(c)!.x));
    expect(xs.size).toBe(1);
    const bus = col.map((c) => scene.via.get(`${fw}>${c}`)![0]);
    expect(new Set(bus.map((b) => `${b.x},${b.y}`)).size).toBe(1);
    for (const c of col) expect(scene.sides.get(c)).toBe('right');
  });

  it('corsie: andata e ritorno ai due lati della strada, accorciate alle estremità', () => {
    const r = lanes([{ x: 0, y: 0 }, { x: 100, y: 0 }], 5, 20, 10);
    expect(r.out).toEqual([{ x: 20, y: 5 }, { x: 90, y: 5 }]);
    expect(r.back).toEqual([{ x: 90, y: -5 }, { x: 20, y: -5 }]);
    // Spezzata ad angolo retto: il giunto resta alla stessa distanza dai due tratti.
    const e = lanes([{ x: 0, y: 0 }, { x: 100, y: 0 }, { x: 100, y: 100 }], 4, 0, 0);
    expect(e.out[1].x).toBeCloseTo(96);
    expect(e.out[1].y).toBeCloseTo(4);
    expect(e.back[1].x).toBeCloseTo(104);
    expect(e.back[1].y).toBeCloseTo(-4);
  });

  it('telecamera: parte e arriva dove deve, lo zoom cambia senza scatti', () => {
    const a = { k: 2, x: 100, y: 50 };
    const b = { k: 0.5, x: 300, y: 120 };
    expect(lerpCamera(a, b, 600, 300, 0)).toEqual(a);
    const end = lerpCamera(a, b, 600, 300, 1);
    expect(end.k).toBeCloseTo(b.k);
    expect(end.x).toBeCloseTo(b.x);
    expect(end.y).toBeCloseTo(b.y);
    const mid = lerpCamera(a, b, 600, 300, 0.5);
    expect(mid.k).toBeCloseTo(1);
  });
});

describe('etichette dei pacchetti e scia', () => {
  it('ogni pacchetto ha una riga breve sotto l\'etichetta, come "A? www.google.com"', () => {
    for (const scan of [demoScan, clinicScan]) {
      for (const sc of scenes(scan).list) {
        for (const p of sc.steps.flatMap((s) => s.packets)) {
          const b = briefOf(p);
          expect(b.length, `${sc.id} ${p.label} ${p.info}`).toBeGreaterThan(0);
          expect(b.length, `${sc.id} ${p.label} ${p.info}`).toBeLessThanOrEqual(30);
        }
      }
    }
    const web = byId(scenes(demoScan).list, 'web');
    const all = web.steps.flatMap((s) => s.packets);
    expect(briefOf(all.find((p) => p.label === 'DNS QUERY')!)).toBe('A? www.google.com');
    expect(briefOf(all.find((p) => p.label === 'SYN')!)).toBe('52411 → 443');
    expect(briefOf(all.find((p) => p.label === 'CLIENT HELLO')!)).toBe('SNI=www.google.com');
    expect(briefOf(all.find((p) => p.label === 'GET')!)).toBe('GET /generate_204');
  });

  it('la scia va dal mittente al punto raggiunto', () => {
    const routes = [
      [{ x: 0, y: 0 }, { x: 100, y: 0 }],
      [{ x: 100, y: 0 }, { x: 100, y: 50 }, { x: 200, y: 50 }],
    ];
    expect(trailOf(routes, 0)).toEqual([]);
    expect(trailOf(routes, 0.25)).toEqual([{ x: 0, y: 0 }, { x: 50, y: 0 }]);
    expect(trailOf(routes, 1)).toEqual([{ x: 0, y: 0 }, { x: 100, y: 0 }, { x: 100, y: 50 }, { x: 200, y: 50 }]);
    const mid = trailOf(routes, 0.75);
    expect(mid[mid.length - 1]).toEqual({ x: 125, y: 50 });
  });
});

describe('linea del tempo', () => {
  it('un elemento per pacchetto, una sosta per i passi senza pacchetti, fine con done', () => {
    const web = byId(scenes(demoScan).list, 'web');
    const es = timeline(web);
    expect(es[0]).toEqual({ si: 0 });
    expect(es.filter((e) => e.p)).toHaveLength(web.steps.flatMap((s) => s.packets).length);
    const first = es[1].p!;
    expect(entryMs(es[1])).toBe((first.hops.length - 1) * SEG_MS + HOLD_MS);
    let cur = { i: 0, t: 0 };
    let done = false;
    let frames = 0;
    while (!done && frames < 10000) {
      const r = advance(es, cur, 16, 2);
      cur = r.cur;
      done = r.done;
      frames++;
    }
    expect(done).toBe(true);
    expect(cur).toEqual({ i: es.length - 1, t: 1 });
    expect(advance(es, cur, 16, 1).done).toBe(true);
  });

  it('il pacchetto arriva prima della fine del suo tempo e resta fermo; quello scartato resta di più', () => {
    const svc = byId(scenes(clinicScan).list, 'services');
    const es = timeline(svc);
    const stopped = es.find((e) => e.p?.stopAt !== undefined)!;
    expect(entryMs(stopped)).toBe(stopped.p!.stopAt! * SEG_MS + HOLD_STOP_MS);
    expect(progressOf(stopped, 0)).toBe(0);
    expect(progressOf(stopped, 0.5)).toBeGreaterThan(0.5);
    expect(progressOf(stopped, 0.9)).toBe(1);
    expect(progressOf({ si: 0 }, 0.5)).toBe(0);
  });
});
