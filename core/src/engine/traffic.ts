import { primaryAdapter } from './adapters';
import type { MapNode, NetworkMap } from './topology';
import type { Scan } from './types';

// Il traffico passo passo: per alcune azioni comuni (aprire un sito, ricevere
// l'indirizzo, un ping al router, il percorso verso Internet, i servizi
// verificati, una stampa) ricostruisce i pacchetti che il protocollo prevede,
// con gli indirizzi e i tempi misurati da questa analisi. Non è una cattura:
// Polaris non registra il traffico del PC. I tempi sono ricostruiti dai
// valori misurati (router, DNS, Internet) e le dimensioni sono quelle
// tipiche. L'interfaccia anima i pacchetti lungo i nodi della mappa.
// Gira anche in goja: niente Intl.

export type PacketProto = 'DHCP' | 'DNS' | 'ICMP' | 'TCP' | 'TLS' | 'HTTP' | 'IPP';

export interface TrafficPacket {
  /** Numero progressivo nella scena, da 1. */
  no: number;
  /** Istante ricostruito, in millisecondi dall'inizio della scena. */
  t: number;
  /** Nodi della mappa attraversati, dal mittente al destinatario. */
  hops: string[];
  src: string;
  dst: string;
  proto: PacketProto;
  /** Etichetta breve sul pacchetto in movimento ("DNS QUERY"). */
  label: string;
  /** Riga della tabella, come in un analizzatore di rete. */
  info: string;
  /** Dimensione tipica, in byte. */
  size: number;
  dir: 'request' | 'response';
  /** Il pacchetto si ferma al nodo con questo indice di hops (scartato, nessuna risposta). */
  stopAt?: number;
  /** Esito da evidenziare: ok come previsto, crit quando non dovrebbe passare. */
  sev?: 'ok' | 'warn' | 'crit';
}

export interface TrafficStep {
  id: string;
  title: string;
  subtitle: string;
  detail: string;
  fields: { k: string; v: string }[];
  packets: TrafficPacket[];
}

export interface TrafficScenario {
  id: string;
  title: string;
  subtitle: string;
  /** Nodi coinvolti, nell'ordine delle corsie della vista a sequenza. */
  lanes: string[];
  steps: TrafficStep[];
}

const r1 = (n: number) => Math.round(n * 10) / 10;
/** "8,1 ms", "1,2 s". */
export function msText(ms: number): string {
  if (ms >= 1000) return `${(Math.round(ms / 100) / 10).toFixed(1).replace('.', ',')} s`;
  return `${(ms < 10 ? r1(ms).toFixed(1) : String(Math.round(ms))).replace('.', ',')} ms`;
}
/** Istante nella tabella dei pacchetti: "0,024 s". */
export function packetTime(ms: number): string {
  return `${(ms / 1000).toFixed(3).replace('.', ',')} s`;
}
/** "75 B", "4,0 KB". */
export function sizeText(b: number): string {
  return b >= 1000 ? `${(b / 1000).toFixed(1).replace('.', ',')} KB` : `${b} B`;
}

/** Porta del PC per gli esempi: una porta effimera qualunque (Windows usa 49152-65535). */
const EPH = 52411;
/** Sito degli esempi quando l'analisi non ha la verifica HTTPS. */
const SITE = 'www.google.com';

export function trafficScenarios(map: NetworkMap, scan: Scan): TrafficScenario[] {
  const byId = new Map(map.nodes.map((n) => [n.id, n]));
  const self = map.nodes.find((n) => n.self);
  if (!self) return [];
  const gw = map.nodes.find((n) => n.gateway);
  const inet = map.flows.find((f) => f.kind === 'internet');
  const primary = primaryAdapter(scan);
  const pcIp = self.ip ?? primary?.ipv4[0]?.split('/')[0] ?? 'questo PC';
  const toGw = inet && gw ? inet.path.slice(0, inet.path.indexOf(gw.id) + 1) : gw ? [self.id, gw.id] : [self.id];

  // Strada verso un nodo: quella di un percorso già calcolato dalla mappa,
  // altrimenti diretta nella rete del PC o attraverso il gateway.
  const pathTo = (n: MapNode): string[] => {
    const f = map.flows.find((x) => x.path[x.path.length - 1] === n.id);
    if (f) return f.path;
    if (toGw.indexOf(n.id) >= 0) return toGw.slice(0, toGw.indexOf(n.id) + 1);
    if (n.segment === self.segment) return toGw.length > 2 && toGw[1] !== gw?.id ? [self.id, toGw[1], n.id] : [self.id, n.id];
    return [...toGw, n.id];
  };
  const back = (p: string[]) => [...p].reverse();

  // Tempi misurati, con valori prudenti quando mancano.
  const gwMs = scan.gateway?.ping && scan.gateway.ping.received > 0 ? scan.gateway.ping.avgMs : undefined;
  const dnsOk = scan.dns?.system.find((d) => d.ok && d.timeMs !== undefined);
  const inetT = scan.internet?.targets.find((t) => t.received > 0 && t.avgMs !== undefined);
  const inetMs = inetT?.avgMs;
  const http = scan.internet?.http?.find((h) => h.ok && h.timeMs !== undefined);
  const hop1 = gwMs ?? 2;
  const rtt = inetMs ?? 25;
  // Il sito e la pagina sono quelli della verifica HTTPS dell'analisi, se c'è.
  const httpUrl = http ? /^https?:\/\/([^/:?#]+)[^/?#]*(\/[^?#]*)?/i.exec(http.url) : null;
  const site = httpUrl?.[1] ?? SITE;
  const page = httpUrl?.[2] && httpUrl[2] !== '/' ? httpUrl[2] : '/generate_204';
  const gwName = gw?.kind === 'firewall' ? 'firewall' : 'router';
  const code = http?.status ?? 204;
  const reason: Record<number, string> = { 200: 'OK', 204: 'No Content', 301: 'Moved Permanently', 302: 'Found', 307: 'Temporary Redirect', 308: 'Permanent Redirect' };
  const status = reason[code] ? `${code} ${reason[code]}` : String(code);

  const out: TrafficScenario[] = [];
  const lanesOf = (steps: TrafficStep[]): string[] => {
    const l: string[] = [];
    for (const s of steps) for (const p of s.packets) for (const h of p.hops) if (l.indexOf(h) < 0 && byId.has(h)) l.push(h);
    return l;
  };
  const scenario = (id: string, title: string, subtitle: string, steps: TrafficStep[]) => {
    let no = 0;
    for (const s of steps) for (const p of s.packets) p.no = ++no;
    if (no) out.push({ id, title, subtitle, lanes: lanesOf(steps), steps });
  };
  const pk = (p: Omit<TrafficPacket, 'no'>): TrafficPacket => ({ no: 0, ...p, t: r1(p.t) });

  // ------------------------------------------------ aprire un sito web
  if (inet) {
    const dnsIp = primary?.dns[0];
    const dnsNode = dnsIp ? map.nodes.find((n) => n.ip === dnsIp) : undefined;
    const steps: TrafficStep[] = [];
    let t = 0;
    steps.push({
      id: 'web-start',
      title: 'Il browser prepara la richiesta',
      subtitle: `Si apre ${site}`,
      detail: `Prima di collegarsi il PC deve sapere a quale indirizzo si trova ${site}: i nomi servono alle persone, la rete usa gli indirizzi IP. È la stessa verifica che Polaris fa durante l'analisi.`,
      fields: [
        { k: 'Destinazione', v: site },
        { k: 'Protocollo', v: 'HTTPS, porta 443' },
      ],
      packets: [],
    });
    if (dnsNode) {
      const p = pathTo(dnsNode);
      const dMs = dnsOk?.timeMs ?? 20;
      const viaGw = dnsNode === gw;
      steps.push({
        id: 'web-dns',
        title: 'Risoluzione del nome (DNS)',
        subtitle: 'Trova l\'indirizzo del server',
        detail: `Il PC chiede ${viaGw ? `al ${gwName}` : `al server DNS ${dnsIp}`}, che ha ricevuto dal DHCP o dalle impostazioni, l'indirizzo di ${site}. La domanda viaggia in UDP sulla porta 53 e la risposta porta un record A con l'indirizzo IPv4${dnsOk ? `: questo server ha risposto in ${msText(dMs)} durante l'analisi` : ''}.`,
        fields: [
          { k: 'Server DNS', v: `${dnsIp}${viaGw ? ` (il ${gwName})` : ''}` },
          { k: 'Trasporto', v: 'UDP, porta 53' },
          { k: 'Risposta', v: dnsOk ? `in ${msText(dMs)}, misurato` : 'tempo non misurato' },
        ],
        packets: [
          pk({ t, hops: p, src: pcIp, dst: dnsIp!, proto: 'DNS', label: 'DNS QUERY', info: `Standard query A ${site}`, size: 75, dir: 'request' }),
          pk({ t: t + dMs, hops: back(p), src: dnsIp!, dst: pcIp, proto: 'DNS', label: 'DNS RISPOSTA', info: `Standard query response A ${site}`, size: 91, dir: 'response' }),
        ],
      });
      t += dMs + 0.4;
    }
    const ip = site;
    steps.push({
      id: 'web-tcp',
      title: 'Connessione TCP',
      subtitle: 'Stabilisce un collegamento affidabile',
      detail: `Tre pacchetti aprono la connessione (SYN, SYN-ACK, ACK). Escono dal ${gwName}, che sostituisce l'indirizzo privato del PC con quello pubblico della linea (NAT), e attraversano la rete dell'operatore${inetMs !== undefined ? `: un'andata e ritorno verso Internet ha richiesto ${msText(rtt)} di media durante l'analisi` : ''}.`,
      fields: [
        { k: 'Porte', v: `${EPH} → 443 (la porta del PC è scelta da Windows)` },
        { k: 'Andata e ritorno', v: inetMs !== undefined ? `${msText(rtt)}, misurato` : 'non misurato' },
      ],
      packets: [
        pk({ t, hops: inet.path, src: pcIp, dst: ip, proto: 'TCP', label: 'SYN', info: `${EPH} → 443 [SYN] Seq=0`, size: 66, dir: 'request' }),
        pk({ t: t + rtt, hops: back(inet.path), src: ip, dst: pcIp, proto: 'TCP', label: 'SYN-ACK', info: `443 → ${EPH} [SYN, ACK] Seq=0 Ack=1`, size: 66, dir: 'response' }),
        pk({ t: t + rtt + 0.1, hops: inet.path, src: pcIp, dst: ip, proto: 'TCP', label: 'ACK', info: `${EPH} → 443 [ACK] Seq=1 Ack=1`, size: 54, dir: 'request' }),
      ],
    });
    t += rtt + 0.3;
    steps.push({
      id: 'web-tls',
      title: 'Cifratura (TLS 1.3)',
      subtitle: 'Concorda le chiavi e verifica il server',
      detail: 'Il PC propone gli algoritmi e indica il nome del sito (SNI); il server risponde con il suo certificato, che il browser verifica. Da qui in poi tutto viaggia cifrato: il router e l\'operatore vedono gli indirizzi, non il contenuto.',
      fields: [
        { k: 'Versione', v: 'TLS 1.3' },
        { k: 'Certificato', v: 'verificato dal browser' },
      ],
      packets: [
        pk({ t, hops: inet.path, src: pcIp, dst: ip, proto: 'TLS', label: 'CLIENT HELLO', info: `Client Hello (SNI=${site})`, size: 517, dir: 'request' }),
        pk({ t: t + rtt, hops: back(inet.path), src: ip, dst: pcIp, proto: 'TLS', label: 'SERVER HELLO', info: 'Server Hello, certificato e handshake cifrato', size: 4000, dir: 'response' }),
        pk({ t: t + rtt + 0.4, hops: inet.path, src: pcIp, dst: ip, proto: 'TLS', label: 'FINISHED', info: 'Change Cipher Spec, Finished (cifrato)', size: 118, dir: 'request' }),
      ],
    });
    t += rtt + 0.6;
    const total = http?.timeMs;
    const answer = total !== undefined && total > t + rtt ? total : t + rtt + 3;
    steps.push({
      id: 'web-http',
      title: 'Richiesta e risposta HTTP',
      subtitle: 'Il server risponde',
      detail: `Il browser chiede la pagina dentro la connessione cifrata. Polaris chiede proprio ${page}, una pagina vuota fatta per le verifiche, e il server risponde "${status}"${code !== 204 ? ' invece di 204: la risposta può venire da un portale di accesso o da un proxy, da verificare' : ''}${total !== undefined ? `; tutta la sequenza ha richiesto ${msText(total)} durante l'analisi` : ''}.`,
      fields: [
        { k: 'Richiesta', v: `GET ${page}` },
        { k: 'Risposta', v: status },
        { k: 'Tempo totale', v: total !== undefined ? `${msText(total)}, misurato` : 'non misurato' },
      ],
      packets: [
        pk({ t, hops: inet.path, src: pcIp, dst: ip, proto: 'HTTP', label: 'GET', info: `Application Data (GET ${page})`, size: 741, dir: 'request' }),
        pk({ t: answer, hops: back(inet.path), src: ip, dst: pcIp, proto: 'HTTP', label: String(code), info: `Application Data (${status})`, size: 181, dir: 'response' }),
      ],
    });
    scenario('web', 'Aprire un sito web', 'DNS, TCP, TLS e HTTP', steps);
  }

  // ------------------------------------------------ ricevere l'indirizzo (DHCP)
  const dhcpIp = primary?.dhcpServer ?? (primary?.dhcp ? gw?.ip : undefined);
  const dhcpNode = dhcpIp ? map.nodes.find((n) => n.ip === dhcpIp) : undefined;
  if (primary?.dhcp !== false && dhcpNode && dhcpIp) {
    const relay = dhcpNode.segment !== self.segment && dhcpNode !== gw;
    const p = pathTo(dhcpNode);
    const there = relay ? hop1 + 2 : hop1;
    const lease = [
      { k: 'Server DHCP', v: `${dhcpIp}${dhcpNode === gw ? ` (il ${gwName})` : ''}` },
      { k: 'Indirizzo', v: pcIp },
      ...(gw?.ip ? [{ k: 'Gateway', v: gw.ip }] : []),
      ...(primary?.dns.length ? [{ k: 'DNS', v: primary.dns.join(', ') }] : []),
    ];
    const relayText = relay
      ? ` Il server sta in un'altra rete: il router (o lo switch di livello 3) fa da relay, cioè riceve la richiesta in broadcast e la inoltra al server.`
      : '';
    scenario('dhcp', 'Ricevere l\'indirizzo (DHCP)', 'Discover, Offer, Request, ACK', [
      {
        id: 'dhcp-discover',
        title: 'Il PC cerca un server (Discover)',
        subtitle: 'Un messaggio a tutti',
        detail: `Appena collegato, il PC non ha ancora un indirizzo: manda un messaggio a tutta la rete (broadcast) da 0.0.0.0 a 255.255.255.255, in UDP dalla porta 68 alla 67.${relayText}`,
        fields: [{ k: 'Da → a', v: '0.0.0.0 → 255.255.255.255' }, { k: 'Trasporto', v: 'UDP 68 → 67' }],
        packets: [pk({ t: 0, hops: p, src: '0.0.0.0', dst: '255.255.255.255', proto: 'DHCP', label: 'DISCOVER', info: 'DHCP Discover', size: 342, dir: 'request' })],
      },
      {
        id: 'dhcp-offer',
        title: 'Il server propone un indirizzo (Offer)',
        subtitle: 'Indirizzo, maschera, gateway, DNS',
        detail: 'Il server sceglie un indirizzo libero e lo propone con la maschera, il gateway, i server DNS e la durata del prestito (lease).',
        fields: lease,
        packets: [pk({ t: there, hops: back(p), src: dhcpIp, dst: pcIp, proto: 'DHCP', label: 'OFFER', info: `DHCP Offer ${pcIp}`, size: 342, dir: 'response' })],
      },
      {
        id: 'dhcp-request',
        title: 'Il PC accetta (Request)',
        subtitle: 'Di nuovo a tutti',
        detail: 'Il PC chiede formalmente l\'indirizzo proposto, ancora in broadcast: così anche gli altri server DHCP, se ce ne sono, sanno quale offerta ha scelto.',
        fields: [{ k: 'Chiede', v: pcIp }],
        packets: [pk({ t: there + 1, hops: p, src: '0.0.0.0', dst: '255.255.255.255', proto: 'DHCP', label: 'REQUEST', info: `DHCP Request ${pcIp}`, size: 354, dir: 'request' })],
      },
      {
        id: 'dhcp-ack',
        title: 'Il server conferma (ACK)',
        subtitle: 'L\'indirizzo è del PC',
        detail: 'Con la conferma l\'indirizzo è assegnato per la durata del prestito; a metà del tempo il PC chiede di rinnovarlo direttamente al server.',
        fields: lease,
        packets: [pk({ t: 2 * there + 1, hops: back(p), src: dhcpIp, dst: pcIp, proto: 'DHCP', label: 'ACK', info: `DHCP ACK ${pcIp}`, size: 342, dir: 'response' })],
      },
    ]);
  }

  // ------------------------------------------------ ping al router
  const ping = scan.gateway?.ping;
  if (gw?.ip && ping && ping.sent > 0) {
    const p = toGw;
    const lost = ping.received < ping.sent;
    const avg = ping.received > 0 ? ping.avgMs : undefined;
    const steps: TrafficStep[] = [];
    const n = Math.min(3, ping.sent);
    for (let i = 0; i < n; i++) {
      const miss = lost && i === n - 1;
      const t0 = i * 1000;
      const rt = avg ?? 2;
      steps.push({
        id: `ping-${i + 1}`,
        title: `Richiesta di eco ${i + 1}`,
        subtitle: miss ? 'Nessuna risposta' : `Risposta in ${msText(rt)}`,
        detail:
          i === 0
            ? `Un ping manda al router una richiesta ICMP di eco e misura quanto impiega la risposta. Durante l'analisi Polaris ne ha mandate ${ping.sent}: ${ping.received} risposte${avg !== undefined ? `, ${msText(avg)} di media (da ${msText(ping.minMs ?? avg)} a ${msText(ping.maxMs ?? avg)})` : ''}.`
            : miss
              ? `Su ${ping.sent} richieste ${ping.sent - ping.received} ${ping.sent - ping.received === 1 ? 'non ha' : 'non hanno'} avuto risposta durante l'analisi: un segnale Wi-Fi debole, interferenze o un ${gwName} sovraccarico.`
              : 'Le richieste partono una al secondo: la variazione dei tempi tra l\'una e l\'altra è il jitter.',
        fields: [
          { k: 'Destinazione', v: gw.ip },
          { k: 'Tempo medio', v: avg !== undefined ? msText(avg) : 'nessuna risposta' },
          { k: 'Perdita', v: `${Math.round((100 * (ping.sent - ping.received)) / ping.sent)}%` },
        ],
        packets: [
          pk({ t: t0, hops: p, src: pcIp, dst: gw.ip, proto: 'ICMP', label: 'ECHO', info: `Echo (ping) request seq=${i + 1}`, size: 74, dir: 'request', ...(miss ? { stopAt: p.length - 1, sev: 'warn' as const } : {}) }),
          ...(miss ? [] : [pk({ t: t0 + rt, hops: back(p), src: gw.ip, dst: pcIp, proto: 'ICMP', label: 'ECO', info: `Echo (ping) reply seq=${i + 1}`, size: 74, dir: 'response' })]),
        ],
      });
    }
    scenario('ping', `Ping al ${gwName}`, 'ICMP, il tempo di andata e ritorno', steps);
  }

  // ------------------------------------------------ percorso verso Internet
  const hops = scan.internet?.traceroute ?? [];
  if (inet && hops.length && gw) {
    const isp = map.nodes.find((n) => n.kind === 'isp');
    const second = inet.path.find((id) => {
      const n = byId.get(id);
      return n && !n.self && n !== gw && n.kind === 'router';
    });
    const target = scan.internet?.traceTarget ?? 'Internet';
    const steps: TrafficStep[] = [];
    const shown = hops.slice(0, 8);
    shown.forEach((h, i) => {
      const last = h.ip !== undefined && h.ip === target;
      const at = h.ip === gw.ip ? gw.id : second && h.ip === byId.get(second)?.ip ? second : last ? 'internet' : isp?.id ?? 'internet';
      const idx = inet.path.indexOf(at);
      const p = idx >= 0 ? inet.path.slice(0, idx + 1) : inet.path;
      const t0 = i * 300;
      steps.push({
        id: `trace-${h.ttl}`,
        title: `Salto ${h.ttl}${h.ip ? `: ${h.ip}` : ''}`,
        subtitle: h.ip ? (h.rttMs !== undefined ? `risponde in ${msText(h.rttMs)}` : 'risponde') : 'nessuna risposta',
        detail:
          i === 0
            ? `Il traceroute manda pacchetti con un TTL che cresce di uno: ogni router lo diminuisce e, quando arriva a zero, scarta il pacchetto e avvisa il mittente. Così si scopre un router alla volta, il primo è ${h.ip === gw.ip ? 'quello della rete del PC' : 'il primo apparato del percorso'}.`
            : h.ip
              ? last
                ? `La destinazione ${target} risponde direttamente: il percorso è completo.`
                : `Un router della rete dell'operatore${h.rttMs !== undefined ? ` risponde in ${msText(h.rttMs)}` : ''}.`
              : 'Questo router non risponde ai pacchetti scaduti, come capita spesso: il percorso continua comunque.',
        fields: [
          { k: 'TTL', v: String(h.ttl) },
          { k: 'Router', v: h.ip ?? '* (non risponde)' },
          { k: 'Tempo', v: h.rttMs !== undefined ? `${msText(h.rttMs)}, misurato` : '—' },
        ],
        packets: [
          pk({ t: t0, hops: p, src: pcIp, dst: target, proto: 'ICMP', label: `TTL ${h.ttl}`, info: `Echo (ping) request, TTL=${h.ttl}`, size: 106, dir: 'request', ...(h.ip ? {} : { stopAt: p.length - 1, sev: 'warn' as const }) }),
          ...(h.ip
            ? [pk({ t: t0 + (h.rttMs ?? 5), hops: back(p), src: h.ip, dst: pcIp, proto: 'ICMP', label: last ? 'ECO' : 'TTL SCADUTO', info: last ? 'Echo (ping) reply' : 'Time-to-live exceeded', size: last ? 106 : 134, dir: 'response' })]
            : []),
        ],
      });
    });
    scenario('trace', 'Il percorso verso Internet', 'Traceroute, un router alla volta', steps);
  }

  // ------------------------------------------------ servizi verificati e zone isolate
  const reach = (scan.infra?.reach?.results ?? []).filter((r) => r.ip && map.nodes.some((n) => n.ip === r.ip));
  if (reach.length) {
    const steps: TrafficStep[] = [];
    let t = 0;
    for (const r of reach.slice(0, 8)) {
      const n = map.nodes.find((x) => x.ip === r.ip)!;
      const p = pathTo(n);
      const port = r.port;
      const isolated = r.expect === 'isolated';
      const answered = r.status === 'open' || r.status === 'reply';
      const refused = r.status === 'closed';
      const stopAt = gw && p.indexOf(gw.id) >= 0 && n.segment !== self.segment ? p.indexOf(gw.id) : p.length - 1;
      const sev: 'ok' | 'warn' | 'crit' = r.ok ? 'ok' : isolated && refused ? 'warn' : 'crit';
      const rt = r.rttMs ?? hop1 * 2;
      const name = r.label ?? r.host;
      const packets: TrafficPacket[] = [];
      if (port) {
        packets.push(pk({ t, hops: p, src: pcIp, dst: r.ip!, proto: 'TCP', label: 'SYN', info: `${EPH} → ${port} [SYN] Seq=0`, size: 66, dir: 'request', ...(answered || refused ? {} : { stopAt, sev }) }));
        if (answered) {
          packets.push(pk({ t: t + rt, hops: back(p), src: r.ip!, dst: pcIp, proto: 'TCP', label: 'SYN-ACK', info: `${port} → ${EPH} [SYN, ACK] Seq=0 Ack=1`, size: 66, dir: 'response', sev }));
          packets.push(pk({ t: t + rt + 0.1, hops: p, src: pcIp, dst: r.ip!, proto: 'TCP', label: 'ACK', info: `${EPH} → ${port} [ACK] Seq=1 Ack=1`, size: 54, dir: 'request', sev }));
        } else if (refused) {
          packets.push(pk({ t: t + rt, hops: back(p), src: r.ip!, dst: pcIp, proto: 'TCP', label: 'RST', info: `${port} → ${EPH} [RST, ACK]`, size: 54, dir: 'response', sev }));
        } else {
          packets.push(pk({ t: t + 1000, hops: p, src: pcIp, dst: r.ip!, proto: 'TCP', label: 'SYN', info: `[Ritrasmissione] ${EPH} → ${port} [SYN] Seq=0`, size: 66, dir: 'request', stopAt, sev }));
        }
      } else {
        packets.push(pk({ t, hops: p, src: pcIp, dst: r.ip!, proto: 'ICMP', label: 'ECHO', info: 'Echo (ping) request', size: 74, dir: 'request', ...(answered ? {} : { stopAt, sev }) }));
        if (answered) packets.push(pk({ t: t + rt, hops: back(p), src: r.ip!, dst: pcIp, proto: 'ICMP', label: 'ECO', info: 'Echo (ping) reply', size: 74, dir: 'response', sev }));
      }
      const outcome = answered
        ? isolated
          ? `risponde, ma da questa rete dovrebbe essere isolato: le regole tra le zone lasciano passare il traffico`
          : `risponde${r.rttMs !== undefined ? ` in ${msText(r.rttMs)}` : ''}, come previsto`
        : refused
          ? isolated
            ? 'risponde con un rifiuto: il traffico arriva fino all\'host o a un firewall che rifiuta, da verificare'
            : 'rifiuta la connessione: il dispositivo risponde ma il servizio è fermo'
          : isolated
            ? 'non risponde, come previsto: il firewall o le regole tra le zone scartano il pacchetto'
            : 'non risponde: il servizio o le regole di rete vanno controllati';
      steps.push({
        id: `svc-${r.ip}-${port ?? 0}`,
        title: name,
        subtitle: isolated ? 'deve essere isolato' : 'deve rispondere',
        detail: `${port ? `Una connessione TCP alla porta ${port}` : 'Due ping'} verso ${r.ip}: ${outcome}.`,
        fields: [
          { k: 'Destinazione', v: `${r.ip}${port ? `:${port}` : ''}` },
          { k: 'Attesa', v: isolated ? 'isolato' : 'raggiungibile' },
          { k: 'Esito', v: answered ? (port ? 'porta aperta' : 'risponde al ping') : refused ? 'porta chiusa (rifiuto)' : 'nessuna risposta' },
        ],
        packets,
      });
      t += Math.max(rt * 2, 30) + (answered || refused ? 0 : 1000);
    }
    scenario('services', 'Servizi verificati e zone isolate', 'Che cosa passa e che cosa viene bloccato', steps);
  }

  // ------------------------------------------------ stampa
  const printer = map.nodes.find((n) => n.kind === 'printer' && n.segment === self.segment && n.ip);
  if (printer?.ip) {
    const p = pathTo(printer);
    const ipp = printer.signals.some((s) => /_ipp\._tcp|ipp/i.test(s));
    const port = ipp ? 631 : 9100;
    const rt = printer.rttMs ?? hop1;
    scenario('print', 'Stampare un documento', ipp ? 'IPP sulla porta 631' : 'stampa diretta sulla porta 9100', [
      {
        id: 'print-tcp',
        title: 'Connessione alla stampante',
        subtitle: `Porta ${port}`,
        detail: `Il PC apre una connessione TCP con la stampante ${printer.label} (${printer.ip}), nella stessa rete: il traffico non passa dal router${printer.rttMs !== undefined ? `; la stampante ha risposto al ping in ${msText(printer.rttMs)}` : ''}.`,
        fields: [
          { k: 'Stampante', v: `${printer.label} (${printer.ip})` },
          { k: 'Porta', v: `${port} (${ipp ? 'IPP' : 'stampa diretta'})` },
        ],
        packets: [
          pk({ t: 0, hops: p, src: pcIp, dst: printer.ip, proto: 'TCP', label: 'SYN', info: `${EPH} → ${port} [SYN] Seq=0`, size: 66, dir: 'request' }),
          pk({ t: rt, hops: back(p), src: printer.ip, dst: pcIp, proto: 'TCP', label: 'SYN-ACK', info: `${port} → ${EPH} [SYN, ACK]`, size: 66, dir: 'response' }),
          pk({ t: rt + 0.1, hops: p, src: pcIp, dst: printer.ip, proto: 'TCP', label: 'ACK', info: `${EPH} → ${port} [ACK]`, size: 54, dir: 'request' }),
        ],
      },
      {
        id: 'print-job',
        title: ipp ? 'Invio del lavoro (IPP)' : 'Invio del lavoro',
        subtitle: 'Il documento arriva alla stampante',
        detail: ipp
          ? 'Con IPP il PC manda una richiesta Print-Job con il documento già convertito dal driver; la stampante risponde con l\'esito e il numero del lavoro. È un esempio: Polaris non ha mandato stampe.'
          : 'Con la stampa diretta il PC manda i dati del documento così come li prepara il driver. È un esempio: Polaris non ha mandato stampe.',
        fields: [{ k: 'Richiesta', v: ipp ? 'Print-Job' : 'dati di stampa' }],
        packets: [
          pk({ t: rt + 1, hops: p, src: pcIp, dst: printer.ip, proto: ipp ? 'IPP' : 'TCP', label: 'PRINT-JOB', info: ipp ? 'IPP Print-Job (documento)' : `${EPH} → ${port} dati di stampa`, size: 250000, dir: 'request' }),
          pk({ t: rt * 2 + 40, hops: back(p), src: printer.ip, dst: pcIp, proto: ipp ? 'IPP' : 'TCP', label: ipp ? 'OK' : 'ACK', info: ipp ? 'IPP successful-ok' : `${port} → ${EPH} [ACK]`, size: ipp ? 320 : 54, dir: 'response' }),
        ],
      },
    ]);
  }

  return out;
}
