import { describe, expect, it } from 'vitest';
import { analyze, buildNetworkMap, trafficScenarios } from '../src/engine';
import type { Scan, TrafficScenario } from '../src/engine';
import { clinicScan } from '../src/demo/clinic';
import { demoScan } from '../src/demo/sample';
import { advance, CHAR_W, entryMs, HOLD_MS, HOLD_STOP_MS, packetNote, progressOf, route, SEG_MS, stageLayout, timeline, VERTICAL_BELOW } from '../src/ui/trafficlayout';

// "Il traffico passo passo": scene ricostruite con gli indirizzi e i tempi
// dell'analisi, pacchetti scartati dove il firewall blocca, disposizione dei
// nodi senza sovrapposizioni su schermo largo e stretto, linea del tempo.

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
    const avg = demoScan.gateway!.ping!.avgMs;
    const first = ping.steps[0].packets;
    expect(first[1].t - first[0].t).toBeCloseTo(avg!, 1);
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
    expect(trace.steps).toHaveLength(Math.min(8, hops.length));
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

describe('disposizione dei nodi', () => {
  const labelBox = (s: ReturnType<typeof stageLayout>['slots'] extends Map<string, infer T> ? T : never, len: number) => {
    const n = Math.min(len, s.chars) * CHAR_W;
    return s.right
      ? [{ x0: s.x - 30 * (s.s / 0.74), x1: s.x + 30 * (s.s / 0.74) + 2 + n, y0: s.y - 24, y1: s.y + 16 }]
      : [{ x0: s.x - Math.max(29, n / 2), x1: s.x + Math.max(29, n / 2), y0: s.y - 31, y1: s.y + 53 }];
  };
  const overlap = (a: { x0: number; x1: number; y0: number; y1: number }, b: { x0: number; x1: number; y0: number; y1: number }) =>
    a.x0 < b.x1 && b.x0 < a.x1 && a.y0 < b.y1 && b.y0 < a.y1;

  it('largo e stretto: tutti i nodi dentro il palco, etichette senza sovrapposizioni', () => {
    for (const scan of [demoScan, clinicScan]) {
      const { map, list } = scenes(scan);
      const nodes = new Map(map.nodes.map((n) => [n.id, n]));
      for (const width of [1100, 760, 600, 390, 320]) {
        for (const sc of list) {
          const L = stageLayout(sc, (id) => nodes.has(id), width);
          expect(L.vertical).toBe(width < VERTICAL_BELOW);
          const boxes: { id: string; b: { x0: number; x1: number; y0: number; y1: number } }[] = [];
          for (const id of sc.lanes) {
            const s = L.slots.get(id)!;
            expect(s, `${sc.id} ${id} ${width}`).toBeDefined();
            const n = nodes.get(id)!;
            const len = Math.max((n.self ? 'Questo PC' : n.label).length, (n.ip ?? '').length);
            for (const b of labelBox(s, len)) {
              expect(b.x0, `${sc.id} ${id} a ${width}px`).toBeGreaterThanOrEqual(0);
              expect(b.x1, `${sc.id} ${id} a ${width}px`).toBeLessThanOrEqual(L.w + 1);
              expect(b.y0).toBeGreaterThanOrEqual(0);
              expect(b.y1).toBeLessThanOrEqual(L.h + 1);
              boxes.push({ id, b });
            }
          }
          for (let i = 0; i < boxes.length; i++)
            for (let j = i + 1; j < boxes.length; j++) expect(overlap(boxes[i].b, boxes[j].b), `${sc.id}: ${boxes[i].id} e ${boxes[j].id} a ${width}px`).toBe(false);
        }
      }
    }
  });

  it('i servizi della clinica in elenco, raggiunti da una linea comune', () => {
    const { map, list } = scenes(clinicScan);
    const nodes = new Map(map.nodes.map((n) => [n.id, n]));
    const svc = byId(list, 'services');
    const fw = map.nodes.find((n) => n.gateway)!.id;
    const target = svc.lanes[svc.lanes.length - 1];
    const wide = stageLayout(svc, (id) => nodes.has(id), 1000);
    expect(wide.slots.get(target)!.right).toBe(true);
    const r = route(wide, fw, target);
    expect(r).toHaveLength(4);
    expect(r[1].x).toBe(r[2].x);
    expect(route(wide, target, fw)).toEqual([...r].reverse());
    const narrow = stageLayout(svc, (id) => nodes.has(id), 360);
    expect(route(narrow, fw, target)).toHaveLength(3);
    // Il resto della strada è dritto.
    const ap = svc.lanes[1];
    expect(route(wide, svc.lanes[0], ap)).toHaveLength(2);
  });

  it('la strada principale è quella verso Internet', () => {
    const { map, list } = scenes(clinicScan);
    const nodes = new Map(map.nodes.map((n) => [n.id, n]));
    const L = stageLayout(byId(list, 'web'), (id) => nodes.has(id), 1000);
    const pc = L.slots.get(map.nodes.find((n) => n.self)!.id)!;
    const inet = L.slots.get('internet')!;
    const dc = L.slots.get(map.nodes.find((n) => n.ip === '10.10.10.10')!.id)!;
    expect(inet.x).toBe(dc.x);
    expect(inet.x).toBeGreaterThan(pc.x);
    expect(inet.y).not.toBe(dc.y);
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
