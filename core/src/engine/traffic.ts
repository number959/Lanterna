import { primaryAdapter } from './adapters';
import { privateKind } from './cidr';
import type { MapNode, NetworkMap } from './topology';
import type { HttpCheck, ReachResult, Scan } from './types';

// Il traffico passo passo: per alcune azioni comuni (aprire un sito, ricevere
// l'indirizzo, un ping al router, il percorso verso Internet, i servizi
// verificati, una stampa) ricostruisce i pacchetti che il protocollo prevede,
// con gli indirizzi, i tempi e gli esiti misurati da questa analisi: dove
// l'analisi ha visto un guasto, il pacchetto si ferma lì. Non è una cattura:
// Polaris non registra il traffico del PC. Quando una misura manca la scena
// mostra lo scambio tipico e lo dice ("non misurato"); le dimensioni sono
// quelle tipiche. L'interfaccia anima i pacchetti lungo i nodi della mappa.
// Gira anche in goja: niente Intl.

export type PacketProto = 'DHCP' | 'DNS' | 'ICMP' | 'TCP' | 'TLS' | 'HTTP' | 'IPP';

export interface TrafficPacket {
  /** Numero progressivo nella scena, da 1. */
  no: number;
  /** Istante ricostruito, in millisecondi dall'inizio della scena. */
  t: number;
  /** Nodi della mappa attraversati, dal mittente al destinatario (mai due uguali di seguito). */
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
  /** Esito da evidenziare: ok come previsto, warn da verificare, crit quando qualcosa non va. */
  sev?: 'ok' | 'warn' | 'crit';
  /** Esito in poche parole, accanto al pacchetto e nella tabella. */
  note?: string;
  /** Arriva da (o va verso) una zona che doveva essere isolata. */
  breach?: boolean;
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
/** Salti del traceroute mostrati, uno per passo. */
const MAX_HOPS = 10;
/** Verifiche dei servizi mostrate, una per passo. */
const MAX_SVC = 8;

const isV4 = (ip?: string) => !!ip && /^\d{1,3}(\.\d{1,3}){3}$/.test(ip);
/** Senza nodi ripetuti di seguito. */
const dedup = (p: string[]) => p.filter((id, i) => i === 0 || id !== p[i - 1]);
const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

const REASON: Record<number, string> = {
  200: 'OK',
  204: 'No Content',
  301: 'Moved Permanently',
  302: 'Found',
  307: 'Temporary Redirect',
  308: 'Permanent Redirect',
  403: 'Forbidden',
  404: 'Not Found',
  407: 'Proxy Authentication Required',
  500: 'Internal Server Error',
  502: 'Bad Gateway',
  503: 'Service Unavailable',
  504: 'Gateway Timeout',
};
const statusText = (code: number) => (REASON[code] ? `${code} ${REASON[code]}` : String(code));
/** Errore della verifica, accorciato per i campi del passo. */
const errText = (e?: string) => (e ? (e.length > 140 ? `${e.slice(0, 139)}…` : e) : '');

/** In quale fase si è fermata la verifica HTTPS, dal testo dell'errore. */
function httpFailStage(h: HttpCheck): 'dns' | 'refused' | 'tls' | 'timeout' {
  const e = h.error ?? '';
  if (/no such host|lookup|name resolution|getaddrinfo|dns/i.test(e)) return 'dns';
  if (/refused|reset|rifiutat/i.test(e)) return 'refused';
  if (/tls|x509|certificat|handshake/i.test(e)) return 'tls';
  return 'timeout';
}

export function trafficScenarios(map: NetworkMap, scan: Scan): TrafficScenario[] {
  const byId = new Map(map.nodes.map((n) => [n.id, n]));
  const byIp = (ip?: string) => (ip ? map.nodes.find((n) => n.ip === ip) : undefined);
  const self = map.nodes.find((n) => n.self);
  if (!self) return [];
  const gw = map.nodes.find((n) => n.gateway);
  const primary = primaryAdapter(scan);
  const pcIp = self.ip ?? primary?.ipv4[0]?.split('/')[0] ?? 'questo PC';
  const gwName = gw?.kind === 'firewall' ? 'firewall' : 'router';

  // Strada fino al gateway dai collegamenti della mappa (PC, access point o
  // switch, gateway), e verso Internet dal percorso della mappa.
  const adj = new Map<string, string[]>();
  const add = (a: string, b: string) => {
    const l = adj.get(a);
    if (l) l.push(b);
    else adj.set(a, [b]);
  };
  for (const l of map.links) {
    if (!byId.has(l.from) || !byId.has(l.to)) continue;
    add(l.from, l.to);
    add(l.to, l.from);
  }
  const bfs = (from: string, to: string): string[] | undefined => {
    const prev = new Map<string, string>([[from, '']]);
    const q = [from];
    while (q.length) {
      const c = q.shift()!;
      if (c === to) {
        const p = [c];
        for (let x = prev.get(c)!; x; x = prev.get(x)!) p.unshift(x);
        return p;
      }
      for (const nx of adj.get(c) ?? []) {
        if (prev.has(nx)) continue;
        prev.set(nx, c);
        q.push(nx);
      }
    }
    return undefined;
  };
  const inetFlow = map.flows.find((f) => f.kind === 'internet');
  const inetPath = inetFlow ? dedup(inetFlow.path) : undefined;
  const toGw = gw ? (inetPath && inetPath.indexOf(gw.id) >= 0 ? inetPath.slice(0, inetPath.indexOf(gw.id) + 1) : bfs(self.id, gw.id) ?? [self.id, gw.id]) : [self.id];
  const mid = toGw.length > 2 ? toGw[1] : undefined;
  const pathTo = (n: MapNode): string[] => {
    if (n === self) return [self.id];
    if (toGw.indexOf(n.id) >= 0) return toGw.slice(0, toGw.indexOf(n.id) + 1);
    if (inetPath && inetPath.indexOf(n.id) >= 0) return inetPath.slice(0, inetPath.indexOf(n.id) + 1);
    if (n.segment === self.segment) return mid && mid !== n.id ? [self.id, mid, n.id] : [self.id, n.id];
    return dedup([...toGw, n.id]);
  };
  const back = (p: string[]) => [...p].reverse();

  // Tempi e esiti misurati.
  const ping = scan.gateway?.ping;
  const gwMs = ping && ping.received > 0 ? ping.avgMs : undefined;
  const targets = scan.internet?.targets ?? [];
  const inetT = targets.find((t) => t.received > 0 && t.avgMs !== undefined);
  const inetDown = targets.length > 0 && targets.every((t) => t.received === 0);
  const httpAll = scan.internet?.http ?? [];
  const http = httpAll.find((h) => h.ok) ?? httpAll[0];
  const hop1 = gwMs ?? 2;
  const rtt = inetT?.avgMs ?? 25;

  const out: TrafficScenario[] = [];
  const lanesOf = (steps: TrafficStep[]): string[] => {
    const l: string[] = [];
    for (const s of steps) for (const p of s.packets) for (const h of p.hops) if (l.indexOf(h) < 0 && byId.has(h)) l.push(h);
    return l;
  };
  const scenario = (id: string, title: string, subtitle: string, steps: TrafficStep[]) => {
    let no = 0;
    for (const s of steps) {
      s.packets = s.packets.filter((p) => p.hops.length >= 2);
      for (const p of s.packets) p.no = ++no;
    }
    if (no) out.push({ id, title, subtitle, lanes: lanesOf(steps), steps });
  };
  const pk = (p: Omit<TrafficPacket, 'no'>): TrafficPacket => {
    const hops = dedup(p.hops);
    const q: TrafficPacket = { no: 0, ...p, hops, t: r1(p.t) };
    if (q.stopAt !== undefined) q.stopAt = Math.max(1, Math.min(hops.length - 1, q.stopAt - (p.hops.length - hops.length)));
    return q;
  };

  // ------------------------------------------------ aprire un sito web
  if (inetPath) {
    const m = http ? /^https?:\/\/([^/:?#]+)[^/?#]*(\/[^?#]*)?/i.exec(http.url) : null;
    const site = m?.[1] ?? SITE;
    const page = m?.[2] && m[2] !== '/' ? m[2] : '/generate_204';
    const httpState: 'ok' | 'status' | 'fail' | 'unknown' = !http ? 'unknown' : http.ok ? 'ok' : http.status !== undefined ? 'status' : 'fail';
    const stage = http && httpState === 'fail' ? httpFailStage(http) : undefined;
    const v4 = (primary?.dns ?? []).filter(isV4);
    const dnsIp = v4.find((ip) => byIp(ip)) ?? v4[0];
    const dnsNode = byIp(dnsIp);
    const dnsRes = dnsIp ? scan.dns?.system.find((d) => d.server === dnsIp) : undefined;
    const dnsState: 'ok' | 'fail' | 'unknown' = !dnsRes ? 'unknown' : dnsRes.ok ? 'ok' : 'fail';
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

    // Risoluzione del nome.
    const dnsMs = dnsRes?.timeMs ?? 20;
    if (!dnsIp) {
      steps.push({
        id: 'web-dns',
        title: 'Risoluzione del nome (DNS)',
        subtitle: 'Nessun server DNS IPv4',
        detail: 'Questa scheda non ha un server DNS IPv4: senza un server a cui chiedere, il nome del sito non diventa un indirizzo.',
        fields: [{ k: 'Server DNS', v: 'nessuno (IPv4)' }],
        packets: [],
      });
    } else if (dnsNode === self) {
      steps.push({
        id: 'web-dns',
        title: 'Risoluzione del nome (DNS)',
        subtitle: 'Il server DNS è questo PC',
        detail: 'Il server DNS è questo stesso PC (per esempio un controller di dominio): la domanda resta dentro il computer e non passa dalla rete.',
        fields: [{ k: 'Server DNS', v: `${dnsIp} (questo PC)` }],
        packets: [],
      });
    } else {
      const p = dnsNode ? pathTo(dnsNode) : privateKind(dnsIp) === 'public' ? inetPath : toGw;
      const viaGw = dnsNode === gw;
      const offMap = !dnsNode && privateKind(dnsIp) !== 'public';
      const who = viaGw ? `al ${gwName}` : `al server DNS ${dnsIp}`;
      const result =
        dnsState === 'ok'
          ? `: questo server ha risposto in ${msText(dnsMs)} durante l'analisi`
          : dnsState === 'fail'
            ? `. Durante l'analisi questo server non ha risposto${dnsRes?.error ? ` (${errText(dnsRes.error)})` : ''}: senza la risposta il browser non trova l'indirizzo, a meno che risponda un altro server DNS`
            : ': il tempo di risposta non è stato misurato in questa analisi';
      steps.push({
        id: 'web-dns',
        title: 'Risoluzione del nome (DNS)',
        subtitle: dnsState === 'fail' ? 'Il server DNS non risponde' : 'Trova l\'indirizzo del server',
        detail: `Il PC chiede ${who}, che ha ricevuto dal DHCP o dalle impostazioni, l'indirizzo di ${site}${offMap ? ` (il server sta in un'altra rete che non compare sulla mappa: il pacchetto passa dal ${gwName})` : ''}. La domanda viaggia in UDP sulla porta 53 e la risposta porta un record A con l'indirizzo IPv4${result}.`,
        fields: [
          { k: 'Server DNS', v: `${dnsIp}${viaGw ? ` (il ${gwName})` : ''}` },
          { k: 'Trasporto', v: 'UDP, porta 53' },
          { k: 'Risposta', v: dnsState === 'ok' ? `in ${msText(dnsMs)}, misurato` : dnsState === 'fail' ? 'nessuna, durante l\'analisi' : 'non misurata' },
        ],
        packets: [
          pk({
            t,
            hops: p,
            src: pcIp,
            dst: dnsIp,
            proto: 'DNS',
            label: 'DNS QUERY',
            info: `Standard query A ${site}`,
            size: 75,
            dir: 'request',
            ...(dnsState === 'fail' ? { stopAt: p.length - 1, sev: 'crit' as const, note: 'nessuna risposta' } : {}),
          }),
          ...(dnsState === 'fail'
            ? []
            : [pk({ t: t + dnsMs, hops: back(p), src: dnsIp, dst: pcIp, proto: 'DNS', label: 'DNS RISPOSTA', info: `Standard query response A ${site}`, size: 91, dir: 'response' })]),
        ],
      });
      t += (dnsState === 'fail' ? 2000 : dnsMs) + 0.4;
    }

    const noName = (dnsState === 'fail' && httpState !== 'ok' && httpState !== 'status') || stage === 'dns';
    if (noName) {
      steps.push({
        id: 'web-stop',
        title: 'Il browser si ferma',
        subtitle: 'Senza indirizzo non c\'è connessione',
        detail: `Senza l'indirizzo di ${site} il browser non può aprire la connessione e mostra un errore.${http && httpState === 'fail' ? ` Anche la verifica HTTPS dell'analisi non è riuscita${stage === 'dns' ? ': non ha trovato l\'indirizzo del sito' : ''}.` : ''}`,
        fields: http?.error ? [{ k: 'Errore della verifica', v: errText(http.error) }] : [],
        packets: [],
      });
      scenario('web', 'Aprire un sito web', 'DNS, TCP, TLS e HTTP', steps);
    } else {
      const ip = site;
      // Connessione TCP: riuscita se la verifica HTTPS ha avuto una risposta.
      const second = inetPath.map((id) => byId.get(id)).find((n): n is MapNode => !!n && !n.self && n !== gw && n.kind === 'router');
      const cgnat = (scan.internet?.traceroute ?? []).some((h) => privateKind(h.ip) === 'cgnat');
      const natted = privateKind(pcIp) !== 'public';
      const nat = natted
        ? ` Passano dal ${gwName}${second ? ' e dal secondo router' : ''}; lungo la strada l'indirizzo privato del PC viene sostituito con un indirizzo valido su Internet (NAT)${second ? ', qui probabilmente due volte (doppio NAT)' : ''}${cgnat ? ', e un\'altra volta nella rete dell\'operatore (CGNAT, indirizzi 100.64.0.0/10)' : ''}.`
        : '';
      const rttKnown = inetT !== undefined;
      const rttText = rttKnown ? `: un'andata e ritorno verso Internet ha richiesto ${msText(rtt)} di media durante l'analisi${inetT?.method === 'tcp' ? ' (misurata con TCP: il ping verso Internet è bloccato)' : ''}` : '';
      const gwIdx = gw ? inetPath.indexOf(gw.id) : -1;
      const lostAt = gwIdx > 0 ? gwIdx : inetPath.length - 1;
      const tcpDetail =
        stage === 'timeout'
          ? `Il PC manda il primo pacchetto della connessione (SYN) e lo ripete, ma durante l'analisi non è arrivata risposta${ping && ping.received > 0 ? `: il ${gwName} risponde, il problema è oltre` : ''}${inetDown ? '; anche il ping verso Internet non ha avuto risposta' : ''}.${nat}`
          : stage === 'refused'
            ? `Il PC manda il primo pacchetto della connessione (SYN) e riceve un rifiuto (RST): durante l'analisi la connessione HTTPS è stata rifiutata, da un firewall o da un proxy lungo la strada.${nat}`
            : `Tre pacchetti aprono la connessione (SYN, SYN-ACK, ACK).${nat} Poi attraversano la rete dell'operatore${rttText}.`;
      const tcpPackets =
        stage === 'timeout'
          ? [
              pk({ t, hops: inetPath, src: pcIp, dst: ip, proto: 'TCP', label: 'SYN', info: `${EPH} → 443 [SYN] Seq=0`, size: 66, dir: 'request', stopAt: lostAt, sev: 'crit', note: 'nessuna risposta' }),
              pk({ t: t + 1000, hops: inetPath, src: pcIp, dst: ip, proto: 'TCP', label: 'SYN', info: `[Ritrasmissione] ${EPH} → 443 [SYN] Seq=0`, size: 66, dir: 'request', stopAt: lostAt, sev: 'crit', note: 'nessuna risposta' }),
            ]
          : stage === 'refused'
            ? [
                pk({ t, hops: inetPath, src: pcIp, dst: ip, proto: 'TCP', label: 'SYN', info: `${EPH} → 443 [SYN] Seq=0`, size: 66, dir: 'request' }),
                pk({ t: t + rtt, hops: back(inetPath), src: ip, dst: pcIp, proto: 'TCP', label: 'RST', info: `443 → ${EPH} [RST, ACK]`, size: 54, dir: 'response', sev: 'crit', note: 'connessione rifiutata' }),
              ]
            : [
                pk({ t, hops: inetPath, src: pcIp, dst: ip, proto: 'TCP', label: 'SYN', info: `${EPH} → 443 [SYN] Seq=0`, size: 66, dir: 'request' }),
                pk({ t: t + rtt, hops: back(inetPath), src: ip, dst: pcIp, proto: 'TCP', label: 'SYN-ACK', info: `443 → ${EPH} [SYN, ACK] Seq=0 Ack=1`, size: 66, dir: 'response' }),
                pk({ t: t + rtt + 0.1, hops: inetPath, src: pcIp, dst: ip, proto: 'TCP', label: 'ACK', info: `${EPH} → 443 [ACK] Seq=1 Ack=1`, size: 54, dir: 'request' }),
              ];
      steps.push({
        id: 'web-tcp',
        title: 'Connessione TCP',
        subtitle: stage === 'timeout' ? 'Nessuna risposta' : stage === 'refused' ? 'Connessione rifiutata' : 'Stabilisce un collegamento affidabile',
        detail: tcpDetail,
        fields: [
          { k: 'Porte', v: `${EPH} → 443 (la porta del PC è scelta da Windows)` },
          { k: 'Andata e ritorno', v: rttKnown ? `${msText(rtt)}, misurato` : 'non misurato' },
          ...(stage === 'timeout' || stage === 'refused' ? [{ k: 'Errore della verifica', v: errText(http?.error) || 'nessuna risposta' }] : []),
        ],
        packets: tcpPackets,
      });
      t += stage === 'timeout' ? 3000 : rtt + 0.3;

      if (stage !== 'timeout' && stage !== 'refused') {
        const tlsFail = stage === 'tls';
        steps.push({
          id: 'web-tls',
          title: 'Cifratura (TLS 1.3)',
          subtitle: tlsFail ? 'Il certificato non è accettato' : 'Concorda le chiavi e verifica il server',
          detail: tlsFail
            ? `Il PC propone gli algoritmi e indica il nome del sito (SNI); il server risponde con il suo certificato, ma la verifica non riesce e la connessione si chiude con un avviso (Alert). Durante l'analisi l'errore è stato: ${errText(http?.error)}. Succede con un proxy che ispeziona il traffico, con l'ora del PC sbagliata o con un certificato scaduto.`
            : 'Il PC propone gli algoritmi e indica il nome del sito (SNI); il server risponde con il suo certificato, che il browser verifica. Da qui in poi tutto viaggia cifrato: il router e l\'operatore vedono gli indirizzi, non il contenuto.',
          fields: [
            { k: 'Versione', v: 'TLS 1.3' },
            { k: 'Certificato', v: tlsFail ? 'non accettato durante l\'analisi' : httpState === 'unknown' ? 'verificato dal browser (non misurato)' : 'verificato' },
          ],
          packets: [
            pk({ t, hops: inetPath, src: pcIp, dst: ip, proto: 'TLS', label: 'CLIENT HELLO', info: `Client Hello (SNI=${site})`, size: 517, dir: 'request' }),
            pk({ t: t + rtt, hops: back(inetPath), src: ip, dst: pcIp, proto: 'TLS', label: 'SERVER HELLO', info: 'Server Hello, certificato e handshake cifrato', size: 4000, dir: 'response' }),
            tlsFail
              ? pk({ t: t + rtt + 0.4, hops: inetPath, src: pcIp, dst: ip, proto: 'TLS', label: 'ALERT', info: 'Alert: certificato non valido, connessione chiusa', size: 31, dir: 'request', sev: 'crit', note: 'certificato non accettato' })
              : pk({ t: t + rtt + 0.4, hops: inetPath, src: pcIp, dst: ip, proto: 'TLS', label: 'FINISHED', info: 'Change Cipher Spec, Finished (cifrato)', size: 118, dir: 'request' }),
          ],
        });
        t += rtt + 0.6;

        if (!tlsFail) {
          const total = http?.timeMs;
          const code = http?.status ?? 204;
          const st = statusText(code);
          const answer = total !== undefined && total > t + rtt ? total : t + rtt + 3;
          const known = httpState === 'ok' || httpState === 'status';
          const errorStatus = known && code >= 400;
          const detail = known
            ? `Il browser chiede la pagina dentro la connessione cifrata. Polaris chiede proprio ${page}, una pagina vuota fatta per le verifiche, e ${errorStatus ? 'durante l\'analisi la risposta è stata' : 'il server risponde'} "${st}"${
                errorStatus
                  ? code === 407
                    ? ': un proxy chiede di autenticarsi prima di lasciar passare la richiesta'
                    : ': la richiesta è stata rifiutata, dal server o da un proxy lungo la strada'
                  : code !== 204
                    ? ' invece di 204: la risposta può venire da un portale di accesso o da un proxy, da verificare'
                    : ''
              }${total !== undefined ? `; tutta la sequenza ha richiesto ${msText(total)} durante l'analisi` : ''}.`
            : `Il browser chiede la pagina dentro la connessione cifrata. Una pagina di verifica come ${page} risponde "204 No Content", una risposta vuota; in questa analisi la verifica HTTPS non c'è.`;
          steps.push({
            id: 'web-http',
            title: 'Richiesta e risposta HTTP',
            subtitle: errorStatus ? 'Risposta di errore' : 'Il server risponde',
            detail,
            fields: [
              { k: 'Richiesta', v: `GET ${page}` },
              { k: 'Risposta', v: known ? st : '204 No Content (tipica, non misurata)' },
              { k: 'Tempo totale', v: total !== undefined ? `${msText(total)}, misurato` : 'non misurato' },
            ],
            packets: [
              pk({ t, hops: inetPath, src: pcIp, dst: ip, proto: 'HTTP', label: 'GET', info: `Application Data (GET ${page})`, size: 741, dir: 'request' }),
              pk({
                t: answer,
                hops: back(inetPath),
                src: ip,
                dst: pcIp,
                proto: 'HTTP',
                label: String(code),
                info: `Application Data (${st})`,
                size: 181,
                dir: 'response',
                ...(errorStatus ? { sev: 'warn' as const, note: 'risposta di errore' } : {}),
              }),
            ],
          });
        }
      }
      scenario('web', 'Aprire un sito web', 'DNS, TCP, TLS e HTTP', steps);
    }
  }

  // ------------------------------------------------ ricevere l'indirizzo (DHCP)
  const dhcpIp = primary?.dhcpServer ?? (primary?.dhcp ? gw?.ip : undefined);
  const dhcpNode = byIp(dhcpIp);
  if (primary?.dhcp !== false && dhcpNode && dhcpNode !== self && dhcpIp) {
    const relay = dhcpNode.segment !== self.segment && dhcpNode !== gw;
    const p = pathTo(dhcpNode);
    const there = relay ? hop1 + 2 : hop1;
    const dns4 = (primary?.dns ?? []).filter(isV4);
    const lease = [
      { k: 'Server DHCP', v: `${dhcpIp}${dhcpNode === gw ? ` (il ${gwName})` : ''}` },
      { k: 'Indirizzo', v: pcIp },
      ...(gw?.ip ? [{ k: 'Gateway', v: gw.ip }] : []),
      ...(dns4.length ? [{ k: 'DNS', v: dns4.join(', ') }] : []),
    ];
    const relayText = relay
      ? ` Il server sta in un'altra rete: il ${gwName} (o lo switch di livello 3) fa da relay, cioè riceve la richiesta in broadcast e la inoltra al server.`
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

  // ------------------------------------------------ ping al gateway (o TCP, se il ping è bloccato)
  if (gw?.ip && ping && ping.sent > 0) {
    const p = toGw;
    const tcp = ping.method === 'tcp';
    const port = tcp ? (scan.gateway?.ports ?? []).find((x) => x.open && [80, 443, 53].indexOf(x.port) >= 0)?.port : undefined;
    const samples: (number | null)[] = ping.samples?.length
      ? ping.samples.slice(0, 3)
      : Array.from({ length: Math.min(3, ping.sent) }, (_, i) => (i < ping.received ? ping.avgMs ?? ping.minMs ?? 1 : null));
    const lost = ping.sent - ping.received;
    const answers = plural(ping.received, 'risposta', 'risposte');
    const avg = gwMs;
    const steps: TrafficStep[] = [];
    samples.forEach((s, i) => {
      const t0 = i * 1000;
      const miss = s === null || s === undefined;
      const intro = tcp
        ? `Il ${gwName} non risponde al ping (ICMP), come succede quando un firewall lo blocca: Polaris ha misurato il tempo con una connessione TCP a una porta aperta${port ? ` (la ${port})` : ''}. Durante l'analisi ${plural(ping.sent, 'tentativo', 'tentativi')}, ${answers}${avg !== undefined ? `, ${msText(avg)} di media` : ''}.`
        : `Un ping manda al ${gwName} una richiesta ICMP di eco e misura quanto impiega la risposta. Durante l'analisi Polaris ne ha mandate ${ping.sent}: ${answers}${avg !== undefined ? `, ${msText(avg)} di media (da ${msText(ping.minMs ?? avg)} a ${msText(ping.maxMs ?? avg)})` : ''}.`;
      const why = miss
        ? ping.received === 0
          ? tcp
            ? ` Nessun tentativo ha avuto risposta: durante l'analisi il ${gwName} non era raggiungibile da questo PC.`
            : ` Nessuna richiesta ha avuto risposta: alcuni ${gwName === 'firewall' ? 'firewall' : 'router'} non rispondono al ping per scelta, altrimenti il collegamento non funziona.`
          : ` Questa richiesta non ha avuto risposta: su ${ping.sent} ${lost === 1 ? 'una non ha avuto' : `${lost} non hanno avuto`} risposta. Le cause tipiche sono un segnale Wi-Fi debole, interferenze o un ${gwName} sovraccarico.`
        : i > 0
          ? ' Le richieste partono una al secondo: la variazione dei tempi tra l\'una e l\'altra è il jitter.'
          : '';
      const lostPk = miss ? { stopAt: p.length - 1, sev: 'warn' as const, note: 'nessuna risposta' } : {};
      const req = tcp
        ? pk({ t: t0, hops: p, src: pcIp, dst: gw.ip!, proto: 'TCP', label: 'SYN', info: `${EPH} → ${port ?? '80/443/53'} [SYN] Seq=0`, size: 66, dir: 'request', ...lostPk })
        : pk({ t: t0, hops: p, src: pcIp, dst: gw.ip!, proto: 'ICMP', label: 'ECHO', info: `Echo (ping) request seq=${i + 1}`, size: 74, dir: 'request', ...lostPk });
      const res = miss
        ? []
        : [
            tcp
              ? pk({ t: t0 + (s as number), hops: back(p), src: gw.ip!, dst: pcIp, proto: 'TCP', label: 'SYN-ACK', info: `${port ?? 'porta'} → ${EPH} [SYN, ACK] Seq=0 Ack=1`, size: 66, dir: 'response' })
              : pk({ t: t0 + (s as number), hops: back(p), src: gw.ip!, dst: pcIp, proto: 'ICMP', label: 'ECO', info: `Echo (ping) reply seq=${i + 1}`, size: 74, dir: 'response' }),
          ];
      steps.push({
        id: `ping-${i + 1}`,
        title: tcp ? `Tentativo ${i + 1}` : `Richiesta di eco ${i + 1}`,
        subtitle: miss ? 'Nessuna risposta' : `Risposta in ${msText(s as number)}`,
        detail: `${i === 0 ? intro : ''}${why}`.trim() || `Risposta in ${msText(s as number)}.`,
        fields: [
          { k: 'Destinazione', v: tcp && port ? `${gw.ip}:${port}` : gw.ip! },
          { k: 'Questa risposta', v: miss ? 'nessuna' : `${msText(s as number)}, misurata` },
          { k: 'Perdita', v: `${Math.round((100 * lost) / ping.sent)}%` },
        ],
        packets: [req, ...res],
      });
    });
    scenario('ping', tcp ? `Raggiungere il ${gwName} (TCP)` : `Ping al ${gwName}`, tcp ? 'il ping è bloccato: risponde una porta TCP' : 'ICMP, il tempo di andata e ritorno', steps);
  }

  // ------------------------------------------------ percorso verso Internet
  const hops = scan.internet?.traceroute ?? [];
  if (inetPath && hops.length && gw) {
    const target = scan.internet?.traceTarget ?? 'Internet';
    const last = inetPath.length - 1;
    const gwIdx = inetPath.indexOf(gw.id);
    const second = inetPath.map((id) => byId.get(id)).find((n): n is MapNode => !!n && !n.self && n !== gw && n.kind === 'router');
    const secondIdx = second ? inetPath.indexOf(second.id) : -1;
    const ispIdx = inetPath.indexOf('isp');
    // I router lungo la strada (gateway, secondo router, operatore), Internet escluso.
    const routers = [gwIdx, secondIdx, ispIdx].filter((i) => i > 0 && i < last).sort((a, b) => a - b);
    const byTcp = targets.some((x) => x.method === 'tcp' && x.received > 0);
    const steps: TrafficStep[] = [];
    let lastResp = 0;
    const shown = hops.slice(0, MAX_HOPS);
    shown.forEach((h, i) => {
      const isTarget = h.ip !== undefined && h.ip === target;
      let at: number;
      if (h.ip) {
        at = h.ip === gw.ip ? gwIdx : second && h.ip === second.ip ? secondIdx : isTarget ? last : ispIdx > 0 ? ispIdx : last;
        if (at < 1) at = last;
        lastResp = Math.max(lastResp, at);
      } else {
        // Nessuna risposta: il pacchetto scade al router dopo l'ultimo che ha
        // risposto. Dov'è non si sa: si disegna al più fino al primo router
        // dopo, mai fino a Internet.
        const next = routers.find((r) => r > lastResp);
        at = next ?? (lastResp >= last ? last : Math.max(1, lastResp));
      }
      const p = inetPath.slice(0, at + 1);
      const later = hops.slice(i + 1).some((x) => x.ip);
      const t0 = i * 300;
      const intro =
        i === 0
          ? `Il traceroute manda pacchetti con un TTL che cresce di uno: ogni router lo diminuisce e, quando arriva a zero, scarta il pacchetto e avvisa il mittente. Così si scopre un router alla volta; il primo di solito è il gateway della rete del PC. `
          : '';
      const what = h.ip
        ? isTarget
          ? `La destinazione ${target} risponde direttamente: il percorso è completo.`
          : h.ip === gw.ip
            ? `Il ${gwName} risponde${h.rttMs !== undefined ? ` in ${msText(h.rttMs)}` : ''}.`
            : second && h.ip === second.ip
              ? `Il secondo router risponde${h.rttMs !== undefined ? ` in ${msText(h.rttMs)}` : ''}.`
              : `Un router ${ispIdx > 0 ? 'della rete dell\'operatore' : 'lungo la strada'} risponde${h.rttMs !== undefined ? ` in ${msText(h.rttMs)}` : ''}.`
        : later
          ? 'Questo router non risponde ai pacchetti scaduti, come capita spesso: il percorso continua comunque, un salto successivo risponde.'
          : `Da qui in poi nessun router risponde: ${byTcp ? 'il ping verso Internet è bloccato lungo la strada, e durante l\'analisi Internet ha risposto solo via TCP' : 'i pacchetti ICMP possono essere bloccati da un firewall lungo la strada'}.`;
      steps.push({
        id: `trace-${i}`,
        title: `Salto ${h.ttl}${h.ip ? `: ${h.ip}` : ''}`,
        subtitle: h.ip ? (h.rttMs !== undefined ? `risponde in ${msText(h.rttMs)}` : 'risponde') : 'nessuna risposta',
        detail: `${intro}${what}`,
        fields: [
          { k: 'TTL', v: String(h.ttl) },
          { k: 'Router', v: h.ip ?? '* (non risponde)' },
          { k: 'Tempo', v: h.rttMs !== undefined ? `${msText(h.rttMs)}, misurato` : '—' },
        ],
        packets: [
          pk({ t: t0, hops: p, src: pcIp, dst: target, proto: 'ICMP', label: `TTL ${h.ttl}`, info: `Echo (ping) request, TTL=${h.ttl}`, size: 106, dir: 'request', ...(h.ip ? {} : { stopAt: p.length - 1, sev: 'warn' as const, note: 'nessuna risposta' }) }),
          ...(h.ip
            ? [pk({ t: t0 + (h.rttMs ?? 5), hops: back(p), src: h.ip, dst: pcIp, proto: 'ICMP', label: isTarget ? 'ECO' : 'TTL SCADUTO', info: isTarget ? 'Echo (ping) reply' : 'Time-to-live exceeded', size: isTarget ? 106 : 134, dir: 'response' })]
            : []),
        ],
      });
    });
    if (hops.length > shown.length) {
      const lastHop = hops[hops.length - 1];
      steps.push({
        id: 'trace-more',
        title: 'Gli altri salti',
        subtitle: `${plural(hops.length - shown.length, 'salto', 'salti')} non ${hops.length - shown.length === 1 ? 'mostrato' : 'mostrati'}`,
        detail: `Il traceroute dell'analisi ha ${hops.length} salti: qui sono mostrati i primi ${shown.length}. L'ultimo, il salto ${lastHop.ttl}, ${lastHop.ip ? `è ${lastHop.ip}${lastHop.rttMs !== undefined ? ` e risponde in ${msText(lastHop.rttMs)}` : ''}` : 'non risponde'}.`,
        fields: [{ k: 'Salti in tutto', v: String(hops.length) }],
        packets: [],
      });
    }
    scenario('trace', 'Il percorso verso Internet', 'Traceroute, un router alla volta', steps);
  }

  // ------------------------------------------------ servizi verificati e zone isolate
  const results = scan.infra?.reach?.results ?? [];
  const tested = results.filter((r) => r.status !== 'unresolved' && r.status !== 'refused' && r.status !== 'error');
  const drawable = tested.filter((r) => {
    const n = byIp(r.ip);
    return !!n && n !== self;
  });
  if (drawable.length) {
    // Con troppe verifiche, prima quelle con un esito che non va.
    const ordered = drawable.length > MAX_SVC ? [...drawable.filter((r) => !r.ok), ...drawable.filter((r) => r.ok)] : drawable;
    const shown = ordered.slice(0, MAX_SVC);
    const steps: TrafficStep[] = [];
    let t = 0;
    shown.forEach((r, i) => {
      const n = byIp(r.ip)!;
      const p = pathTo(n);
      const port = r.port;
      const local = n.segment === self.segment;
      const isolated = r.expect === 'isolated';
      const answered = r.status === 'open' || r.status === 'reply';
      const refused = r.status === 'closed';
      const gwAt = gw ? p.indexOf(gw.id) : -1;
      // Senza risposta: verso una zona isolata il pacchetto si ferma al gateway
      // (lo scarta il firewall tra le zone); un servizio che doveva rispondere
      // non risponde, e non si sa dove si perde.
      const stopAt = isolated && !local && gwAt > 0 ? gwAt : p.length - 1;
      const rt = r.rttMs ?? hop1 * 2;
      const name = r.label ?? r.host;
      const packets: TrafficPacket[] = [];
      const lost = isolated ? { stopAt, sev: 'ok' as const, note: 'bloccato, come previsto' } : { stopAt, sev: 'crit' as const, note: 'nessuna risposta' };
      const pass = isolated ? { sev: 'crit' as const, note: 'passa, ma non dovrebbe', breach: true } : { sev: 'ok' as const };
      const rst = isolated ? { sev: 'warn' as const, note: 'rifiutato: arriva fino al dispositivo' } : { sev: 'crit' as const, note: 'rifiuta la connessione' };
      if (port) {
        packets.push(pk({ t, hops: p, src: pcIp, dst: r.ip!, proto: 'TCP', label: 'SYN', info: `${EPH} → ${port} [SYN] Seq=0`, size: 66, dir: 'request', ...(answered || refused ? {} : lost) }));
        if (answered) {
          packets.push(pk({ t: t + rt, hops: back(p), src: r.ip!, dst: pcIp, proto: 'TCP', label: 'SYN-ACK', info: `${port} → ${EPH} [SYN, ACK] Seq=0 Ack=1`, size: 66, dir: 'response', ...pass }));
          packets.push(pk({ t: t + rt + 0.1, hops: p, src: pcIp, dst: r.ip!, proto: 'TCP', label: 'ACK', info: `${EPH} → ${port} [ACK] Seq=1 Ack=1`, size: 54, dir: 'request', ...pass }));
        } else if (refused) {
          packets.push(pk({ t: t + rt, hops: back(p), src: r.ip!, dst: pcIp, proto: 'TCP', label: 'RST', info: `${port} → ${EPH} [RST, ACK]`, size: 54, dir: 'response', ...rst }));
        } else {
          packets.push(pk({ t: t + 1000, hops: p, src: pcIp, dst: r.ip!, proto: 'TCP', label: 'SYN', info: `[Ritrasmissione] ${EPH} → ${port} [SYN] Seq=0`, size: 66, dir: 'request', ...lost }));
        }
      } else {
        packets.push(pk({ t, hops: p, src: pcIp, dst: r.ip!, proto: 'ICMP', label: 'ECHO', info: 'Echo (ping) request', size: 74, dir: 'request', ...(answered ? {} : lost) }));
        if (answered) packets.push(pk({ t: t + rt, hops: back(p), src: r.ip!, dst: pcIp, proto: 'ICMP', label: 'ECO', info: 'Echo (ping) reply', size: 74, dir: 'response', ...pass }));
      }
      const outcome = answered
        ? isolated
          ? local
            ? 'risponde: sta nella stessa rete del PC, dove il traffico non passa dal firewall tra le zone'
            : 'risponde, ma da questa rete dovrebbe essere isolato: le regole tra le zone lasciano passare il traffico'
          : `risponde${r.rttMs !== undefined ? ` in ${msText(r.rttMs)}` : ''}, come previsto`
        : refused
          ? isolated
            ? 'risponde con un rifiuto: il traffico arriva fino al dispositivo, o a un firewall che rifiuta invece di scartare; da verificare'
            : 'rifiuta la connessione: il dispositivo risponde, ma su questa porta il servizio non è attivo o un firewall lo rifiuta'
          : isolated
            ? local
              ? 'non risponde, come previsto; sta nella stessa rete del PC, quindi a bloccarlo non è il firewall tra le zone ma il dispositivo stesso o l\'isolamento dei client dell\'access point'
              : 'non risponde, come previsto: il firewall o le regole tra le zone scartano il pacchetto'
            : 'non risponde: il servizio o le regole di rete vanno controllati';
      steps.push({
        id: `svc-${i}`,
        title: name,
        subtitle: isolated ? 'deve essere isolato' : 'deve rispondere',
        detail: `${port ? `Una connessione TCP alla porta ${port}` : 'Un ping'} verso ${r.ip}: ${outcome}.`,
        fields: [
          { k: 'Destinazione', v: `${r.ip}${port ? `:${port}` : ''}` },
          { k: 'Attesa', v: isolated ? 'isolato' : 'raggiungibile' },
          { k: 'Esito', v: answered ? (port ? 'porta aperta' : 'risponde al ping') : refused ? 'porta chiusa (rifiuto)' : 'nessuna risposta' },
        ],
        packets,
      });
      t += Math.max(rt * 2, 30) + (answered || refused ? 0 : 1000);
    });
    // Le verifiche che non sono nei passi: oltre il limite, senza un nodo sulla mappa, non eseguite.
    const STATUS: Record<string, string> = {
      open: 'porta aperta',
      closed: 'porta chiusa',
      filtered: 'nessuna risposta',
      reply: 'risponde al ping',
      noreply: 'nessuna risposta',
      unresolved: 'nome non risolto',
      refused: 'indirizzo non privato',
      error: 'errore',
    };
    const rest: { r: ReachResult; why: string }[] = [
      ...ordered.slice(MAX_SVC).map((r) => ({ r, why: STATUS[r.status] ?? r.status })),
      ...tested.filter((r) => drawable.indexOf(r) < 0).map((r) => ({ r, why: `${STATUS[r.status] ?? r.status}, non è sulla mappa` })),
      ...results.filter((r) => tested.indexOf(r) < 0).map((r) => ({ r, why: `non verificata: ${STATUS[r.status] ?? r.status}` })),
    ];
    if (rest.length) {
      steps.push({
        id: 'svc-other',
        title: 'Le altre verifiche',
        subtitle: `${plural(rest.length, 'verifica', 'verifiche')} non ${rest.length === 1 ? 'mostrata' : 'mostrate'} qui`,
        detail: `Nei passi ci sono ${shown.length < drawable.length ? `al massimo ${MAX_SVC} verifiche, prima quelle con un esito che non va` : 'le verifiche verso un dispositivo della mappa'}. L'elenco completo, con gli esiti, è nella sezione Infrastruttura.`,
        fields: rest.slice(0, 10).map(({ r, why }) => ({ k: `${r.label ?? r.host}${r.port ? ` (${r.port})` : ''}`, v: `${r.expect === 'isolated' ? 'da isolare' : 'da raggiungere'}: ${why}${r.ok ? '' : ', esito che non va'}` })),
        packets: [],
      });
    }
    scenario('services', 'Servizi verificati e zone isolate', 'Che cosa passa e che cosa viene bloccato', steps);
  }

  // ------------------------------------------------ stampa
  const printer = map.nodes.find((n) => n.kind === 'printer' && n.segment === self.segment && n.ip && n !== self);
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
        detail: `Il PC apre una connessione TCP con la stampante ${printer.label} (${printer.ip}), nella stessa rete: il traffico non passa dal ${gwName}${printer.rttMs !== undefined ? `; la stampante ha risposto al ping in ${msText(printer.rttMs)}` : ''}.`,
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
