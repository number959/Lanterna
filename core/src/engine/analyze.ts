import { ACTIONS } from './kb/actions';
import { scoreAssessment } from './kb/assessment';
import type {
  Adapter,
  Analysis,
  Band,
  Bss,
  Category,
  CategoryScore,
  Finding,
  PingStats,
  PlanItem,
  ReachResult,
  ReachStatus,
  Roaming,
  Scan,
  SecurityProtocol,
  Severity,
  WifiSecurity,
} from './types';
import {
  adviseChannels,
  apCount,
  cochannel,
  overlappingPairs,
  ownRadios,
  phyLabel,
  phyRank,
  qualityToDbm,
  secFamily,
  siblingOf,
  STRONG_NEIGHBOUR_DBM,
} from './wifi';

export const ENGINE_VERSION = '1.1.0';

const SEV_RANK: Record<Severity, number> = { unknown: 0, ok: 1, info: 2, warn: 3, crit: 4 };
const SEV_POINTS: Record<Severity, number | null> = { ok: 100, info: 95, warn: 55, crit: 10, unknown: null };

export const CATEGORY_LABELS: Record<Category, string> = {
  wifi: 'Wi-Fi',
  lan: 'Rete locale',
  internet: 'Internet',
  dns: 'DNS',
  router: 'Router',
  security: 'Sicurezza',
  infra: 'Infrastruttura',
};

// L'infrastruttura conta solo quando l'utente ha eseguito inventario,
// verifiche o autovalutazione: senza dati la categoria non ha punteggio ed
// è esclusa dalla media.
const CATEGORY_WEIGHT: Record<Category, number> = {
  wifi: 0.25,
  lan: 0.2,
  internet: 0.25,
  dns: 0.1,
  router: 0.1,
  security: 0.1,
  infra: 0.15,
};

export function worse(a: Severity, b: Severity): Severity {
  return SEV_RANK[a] >= SEV_RANK[b] ? a : b;
}

// Formattazione numerica senza Intl: il motore gira anche in goja (exe
// Windows), dove toLocaleString ignorerebbe le opzioni.
const fmt = (n: number, d = 0) => n.toFixed(d).replace('.', ',');
const ms = (n: number) => (n < 1 ? '<1 ms' : `${fmt(n, n < 10 ? 1 : 0)} ms`);
const lostText = (lost: number, sent: number) =>
  lost === 1 ? `si è perso 1 pacchetto su ${sent}` : `si sono persi ${lost} pacchetti su ${sent}`;
const pct = (n: number) => `${fmt(n, n > 0 && n < 10 ? 1 : 0)} %`;
const thousands = (n: number) => String(Math.round(n)).replace(/\B(?=(\d{3})+(?!\d))/g, '.');
const unique = <T>(xs: T[]) => xs.filter((x, i) => xs.indexOf(x) === i);
/** Coda per gli elenchi troncati: " (e altri 3)". */
const more = (total: number, shown: number) => (total > shown ? ` (e altri ${total - shown})` : '');
/** Numero seguito dal verbo concordato: "1 risponde", "3 rispondono". */
const num = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;
const bandLabel = (b: Band) => `${b.replace('.', ',')} GHz`;

function isApipa(cidr: string) {
  return cidr.startsWith('169.254.');
}

function isPrivate4(ip: string) {
  const p = ip.split('.').map(Number);
  return p.length === 4 && (p[0] === 10 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168));
}

const PROTO_LABEL: Record<SecurityProtocol, string> = {
  open: 'Aperta (nessuna cifratura)',
  owe: 'Enhanced Open (OWE)',
  wep: 'WEP',
  wpa: 'WPA (TKIP)',
  wpa2: 'WPA2',
  'wpa2/wpa3': 'WPA2/WPA3 mista',
  wpa3: 'WPA3',
  unknown: 'non riconosciuta',
};

/** Nome della protezione, distinguendo le reti con 802.1X ("Enterprise"). */
function secLabel(s: WifiSecurity): string {
  if (secFamily(s) === 'enterprise') {
    if (s.protocol === 'wpa2/wpa3') return 'WPA2/WPA3-Enterprise';
    if (s.protocol === 'wpa2' || s.protocol === 'wpa3') return `${PROTO_LABEL[s.protocol]}-Enterprise`;
  }
  return PROTO_LABEL[s.protocol];
}

// Suffissi DNS assegnati dai router domestici e dagli operatori: non indicano
// una rete aziendale.
const HOME_SUFFIX = /(^|\.)(home|lan|localdomain|station|router|gateway|box|home\.arpa|homenet\.telecomitalia\.it|fastwebnet\.it)$/i;

export interface CorporateDomain {
  name: string;
  /** true = il PC fa parte del dominio; false = dedotto da suffisso e DNS interni. */
  joined: boolean;
}

/**
 * Rete aziendale con dominio: il PC ne fa parte (Active Directory) oppure la
 * connessione riceve un suffisso DNS non domestico e usa solo DNS interni
 * diversi dal router. In questi casi i DNS si gestiscono sui server.
 */
export function corporateDomain(scan: Scan, primary?: Adapter): CorporateDomain | undefined {
  if (scan.agent.domain) return { name: scan.agent.domain, joined: true };
  const sfx = (primary?.dnsSuffix ?? '').trim().replace(/\.$/, '');
  if (!sfx || sfx.toLowerCase() === 'local' || HOME_SUFFIX.test(sfx)) return undefined;
  const gw = scan.gateway?.ip ?? primary?.gateways[0];
  const dns = primary?.dns ?? [];
  if (!dns.length || dns.some((d) => d === gw) || !dns.some(isPrivate4)) return undefined;
  return { name: sfx, joined: false };
}

function lossPct(p: PingStats) {
  return p.sent > 0 ? (100 * (p.sent - p.received)) / p.sent : 0;
}

/** Scheda principale: quella attiva con il gateway, preferendo quella del gateway misurato. */
export function primaryAdapter(scan: Scan): Adapter | undefined {
  const up = scan.adapters.filter((a) => a.up && a.kind !== 'loopback');
  const gw = scan.gateway?.ip;
  return (
    (gw && up.find((a) => a.gateways.includes(gw))) ||
    up.find((a) => a.gateways.length > 0 && a.ipv4.length > 0) ||
    up.find((a) => a.ipv4.length > 0)
  );
}

class Collector {
  findings: Finding[] = [];
  add(f: Omit<Finding, 'actions'> & { actions?: string[] }) {
    const actions = (f.actions ?? []).filter((a) => {
      if (!ACTIONS[a]) throw new Error(`azione sconosciuta: ${a}`);
      return true;
    });
    this.findings.push({ ...f, actions });
  }
}

// ---------------------------------------------------------------- Wi-Fi

function analyzeWifi(scan: Scan, c: Collector, primary?: Adapter) {
  const wifi = scan.wifi;
  if (!wifi) return;
  const conn = wifi.connected;
  if (!conn) {
    if (wifi.error && primary?.kind === 'wifi') {
      c.add({
        id: 'wifi.unavailable',
        metric: 'wifi.rssi',
        category: 'wifi',
        title: 'Dati Wi-Fi non disponibili',
        value: 'n/d',
        severity: 'unknown',
        verdict: `Non è stato possibile leggere lo stato del Wi-Fi: ${wifi.error}.`,
      });
    }
    if (wifi.networks.length) networksFinding(c, wifi.networks);
    return;
  }

  // La riga della rete collegata nella scansione ha i dati più ricchi (dBm reali, IE).
  const me: Bss | undefined =
    wifi.networks.find((b) => b.connected) ??
    wifi.networks.find((b) => conn.bssid && b.bssid.toLowerCase() === conn.bssid.toLowerCase());
  const band = me?.band ?? conn.band;
  const rssi = me?.rssiDbm ?? conn.rssiDbm ?? (conn.signalQuality !== undefined ? qualityToDbm(conn.signalQuality) : undefined);
  const weakSignal = rssi !== undefined && rssi < -67;
  // Con più AP della stessa rete un segnale debole può dipendere dall'AP scelto, non dalla copertura.
  const peer = me ? strongestPeer(me, wifi.networks) : undefined;
  const betterAp = peer && rssi !== undefined && weakSignal && peer.rssiDbm - rssi >= 10 ? peer : undefined;
  const ownOnBand = me ? ownRadios(wifi.networks, me.ssid).filter((b) => b.band === me.band && compatible(b, me)).length : 0;

  if (rssi !== undefined) {
    const sev: Severity = rssi >= -67 ? 'ok' : rssi >= -75 ? 'warn' : 'crit';
    const derived = me?.rssiDbm === undefined && conn.rssiDbm === undefined;
    const verdicts: Record<string, string> = {
      ok:
        rssi >= -55
          ? 'Segnale eccellente: la distanza dal router non è un limite.'
          : 'Segnale buono: sufficiente per streaming 4K, videochiamate e gioco online.',
      warn: 'Segnale debole: la radio usa modulazioni più lente e ritrasmette più spesso. Navigazione ok, ma velocità ridotta e possibili scatti nelle chiamate.',
      crit: 'Segnale molto debole: alto rischio di disconnessioni e lentezza marcata. È la prima cosa da sistemare.',
    };
    c.add({
      id: 'wifi.rssi',
      metric: 'wifi.rssi',
      category: 'wifi',
      title: 'Potenza del segnale',
      value: `${rssi} dBm${derived ? ' (stimato)' : ''}`,
      numeric: rssi,
      severity: sev,
      verdict:
        verdicts[sev] +
        (betterAp ? ` Un altro access point della stessa rete si riceve a ${betterAp.rssiDbm} dBm: il problema è l'AP scelto dal PC, non la copertura.` : '') +
        (derived ? ` Valore stimato dalla qualità ${conn.signalQuality} % riportata da Windows.` : ''),
      actions:
        sev === 'ok'
          ? []
          : betterAp
            ? ['fix-roaming', 'use-ethernet']
            : sev === 'warn'
              ? ['move-closer', 'add-mesh']
              : ['move-closer', 'add-mesh', 'use-ethernet'],
    });
  }

  const rate = Math.max(conn.rxMbps ?? 0, conn.txMbps ?? 0);
  if (rate > 0) {
    const sev: Severity = rate >= 144 ? 'ok' : rate >= 54 ? 'warn' : 'crit';
    const actions: string[] = [];
    if (sev !== 'ok') {
      if (weakSignal) actions.push('move-closer');
      if (band === '2.4') actions.push('use-5ghz');
      if (phyRank(conn.phy) <= 3) actions.push('update-wifi-driver', 'upgrade-router');
      if (!actions.length) actions.push('change-channel-5', 'update-wifi-driver');
    }
    const real = Math.round(rate * 0.6);
    c.add({
      id: 'wifi.linkrate',
      metric: 'wifi.linkrate',
      category: 'wifi',
      title: 'Velocità radio negoziata',
      value: conn.rxMbps && conn.txMbps && conn.rxMbps !== conn.txMbps ? `↓${conn.rxMbps} / ↑${conn.txMbps} Mbit/s` : `${rate} Mbit/s`,
      numeric: rate,
      severity: sev,
      verdict:
        `In pratica puoi aspettarti circa ${real} Mbit/s reali via Wi-Fi. ` +
        (sev === 'ok'
          ? 'Adeguato alla maggior parte delle connessioni Internet.'
          : sev === 'warn'
            ? 'Se la tua linea è più veloce di così, il Wi-Fi è il collo di bottiglia.'
            : 'Valore molto basso: la connessione radio sta lavorando al minimo.'),
      actions,
    });
  }

  if (band) {
    const sameSsidFast = wifi.networks.some((b) => b.ssid === conn.ssid && b.band !== '2.4');
    const otherFast = wifi.networks.some((b) => b.band !== '2.4');
    let sev: Severity = 'ok';
    let verdict = band === '6' ? 'Banda 6 GHz: la più libera e veloce.' : 'Banda 5 GHz: veloce e con molti canali disponibili.';
    if (band === '2.4') {
      if (sameSsidFast) {
        sev = 'warn';
        verdict = `Sei sulla banda 2,4 GHz, ma la rete "${conn.ssid}" è disponibile anche a 5/6 GHz: passando alla banda veloce la velocità può moltiplicarsi.`;
      } else {
        sev = 'info';
        verdict = otherFast
          ? 'Sei sulla banda 2,4 GHz e il tuo router non sembra offrire il 5 GHz in questo punto (altre reti vicine lo usano).'
          : 'Sei sulla banda 2,4 GHz: più portata ma meno velocità e più interferenze.';
      }
    }
    c.add({
      id: 'wifi.band',
      metric: 'wifi.band',
      category: 'wifi',
      title: 'Banda di frequenza',
      value: `${band.replace('.', ',')} GHz${me?.channel || conn.channel ? ` · canale ${me?.channel ?? conn.channel}` : ''}`,
      severity: sev,
      verdict,
      actions: sev === 'warn' ? ['use-5ghz'] : [],
    });
  }

  if (conn.phy) {
    const r = phyRank(conn.phy);
    const apRank = phyRank(me?.phy);
    const sev: Severity = r >= 4 ? 'ok' : r === 3 ? 'warn' : 'crit';
    let verdict = sev === 'ok' ? 'Standard moderno.' : 'Standard datato che limita la velocità massima.';
    let actions: string[] = [];
    if (sev !== 'ok') {
      if (apRank > r) {
        verdict += ` Il router supporta ${phyLabel(me?.phy, band)}: il limite è la scheda Wi-Fi di questo PC.`;
        actions = ['update-wifi-driver', 'upgrade-router'];
      } else {
        verdict += ' Il limite è il router.';
        actions = ['upgrade-router'];
      }
    } else if (apRank > r) {
      verdict += ` Il router arriva fino a ${phyLabel(me?.phy, band)}: una scheda più recente potrebbe andare più veloce.`;
    }
    c.add({
      id: 'wifi.phy',
      metric: 'wifi.phy',
      category: 'wifi',
      title: 'Standard Wi-Fi',
      value: phyLabel(conn.phy, band),
      severity: sev,
      verdict,
      actions,
    });
  }

  const width = me?.widthMhz ?? conn.widthMhz;
  if (width && band) {
    let sev: Severity = 'ok';
    let verdict = `Canale largo ${width} MHz.`;
    let actions: string[] = [];
    if (band === '2.4' && width >= 40) {
      sev = 'warn';
      verdict = 'A 40 MHz sul 2,4 GHz la rete occupa due dei tre canali utili: crea e subisce più interferenze, spesso senza guadagno reale.';
      actions = ['width-24-20'];
    } else if (band === '2.4') {
      verdict = '20 MHz è la scelta corretta sul 2,4 GHz.';
    } else if (width < 80 && ownOnBand > 1) {
      verdict = `Con più access point della stessa rete, canali da ${width} MHz lasciano abbastanza canali per separarli: è la scelta consigliata nelle reti con molti AP.`;
    } else if (width < 80) {
      sev = 'info';
      verdict = `A ${width} MHz la velocità massima è ridotta rispetto agli 80 MHz standard; ha senso solo in ambienti molto affollati.`;
    } else {
      verdict = `${width} MHz: sfrutta bene la banda ${band.replace('.', ',')} GHz.`;
    }
    c.add({ id: 'wifi.width', metric: 'wifi.width', category: 'wifi', title: 'Larghezza di canale', value: `${width} MHz`, numeric: width, severity: sev, verdict, actions });
  }

  if (me) {
    // Le altre reti delle stesse radio (ospiti, dispositivi) non sono vicini da evitare.
    const sibling = siblingOf(wifi.networks, me.ssid);
    const co = cochannel(
      me,
      wifi.networks.filter((b) => !sibling(b)),
    );
    const n = co.strong.length;
    const sev: Severity = n === 0 ? 'ok' : n <= 3 ? 'warn' : 'crit';
    const chAction = me.band === '2.4' ? 'change-channel-24' : 'change-channel-5';
    const names = co.strong
      .slice(0, 3)
      .map((b) => (b.ssid ? `"${b.ssid}"` : 'una rete nascosta') + ` (${b.rssiDbm} dBm)`)
      .join(', ');
    c.add({
      id: 'wifi.cochannel',
      metric: 'wifi.cochannel',
      category: 'wifi',
      title: 'Reti che condividono il tuo canale',
      value: `${n} forti · ${co.all.length} totali`,
      numeric: n,
      severity: sev,
      verdict:
        n === 0
          ? co.all.length
            ? `Ci sono ${co.all.length} reti deboli (sotto ${STRONG_NEIGHBOUR_DBM} dBm) sul tuo spettro: disturbo trascurabile.`
            : 'Nessun\'altra rete trasmette sul tuo canale.'
          : `${n} ${n === 1 ? 'rete forte trasmette' : 'reti forti trasmettono'} sul tuo stesso spettro: ${names}${more(n, 3)}. Il tempo di trasmissione viene diviso con loro.`,
      actions: sev === 'ok' ? [] : me.band === '2.4' ? [chAction, 'use-5ghz'] : [chAction],
    });

    if (me.band === '2.4' && ![1, 6, 11].includes(me.channel)) {
      c.add({
        id: 'wifi.overlap24',
        metric: 'wifi.overlap24',
        category: 'wifi',
        title: 'Canale 2,4 GHz sovrapposto',
        value: `canale ${me.channel}`,
        severity: 'warn',
        verdict: `Il canale ${me.channel} si sovrappone parzialmente a ${me.channel < 6 ? '1 e 6' : me.channel < 11 ? '6 e 11' : '11'}: disturbi e vieni disturbato da entrambi i gruppi di reti.`,
        actions: ['change-channel-24'],
      });
    }

    if (me.bssLoad) {
      const u = me.bssLoad.utilizationPct;
      const sev: Severity = u <= 40 ? 'ok' : u <= 70 ? 'warn' : 'crit';
      c.add({
        id: 'wifi.bssload',
        metric: 'wifi.bssload',
        category: 'wifi',
        title: 'Occupazione del canale',
        value: `${pct(u)} · ${me.bssLoad.stations} dispositivi`,
        numeric: u,
        severity: sev,
        verdict:
          sev === 'ok'
            ? `L'access point segnala il canale libero per la maggior parte del tempo, con ${me.bssLoad.stations} dispositivi collegati.`
            : `L'access point segnala il canale occupato il ${pct(u)} del tempo: ${sev === 'crit' ? 'è saturo' : 'è impegnato'}. Restano poche finestre per trasmettere.`,
        actions: sev === 'ok' ? [] : [me.band === '2.4' ? 'change-channel-24' : 'change-channel-5', 'reduce-load', ...(me.band === '2.4' ? ['use-5ghz'] : [])],
      });
    }
  }

  // Sicurezza della rete collegata.
  const sec = me?.security;
  if (sec) {
    const p = sec.protocol;
    const tkip = sec.pairwise.includes('TKIP');
    const enterprise = secFamily(sec) === 'enterprise';
    const label = secLabel(sec);
    let sev: Severity;
    let verdict: string;
    if (p === 'open' || p === 'wep' || p === 'wpa') {
      sev = 'crit';
      verdict =
        p === 'open'
          ? 'La rete non è cifrata: chiunque nel raggio può collegarsi e leggere il traffico non protetto da HTTPS.'
          : `${label} è violabile in pochi minuti con strumenti liberamente disponibili.`;
    } else if (p === 'owe') {
      sev = 'info';
      verdict = 'Il traffico è cifrato ma chiunque può collegarsi: adatto a reti ospiti, non alla rete principale.';
    } else if (tkip) {
      sev = 'warn';
      verdict = `${label} con TKIP: protocollo deprecato, meno sicuro e che limita la velocità a 54 Mbit/s.`;
    } else if (p === 'unknown') {
      sev = 'unknown';
      verdict = 'Non è stato possibile determinare il tipo di protezione.';
    } else {
      sev = 'ok';
      verdict = enterprise
        ? `${label} (802.1X): ogni utente o dispositivo si autentica con credenziali o certificati propri tramite un server RADIUS, senza una password condivisa. I dispositivi devono verificare il certificato del server.`
        : p === 'wpa2'
          ? 'WPA2 con AES: sicuro, a patto di usare una password lunga e non banale.'
          : `${label}: protezione moderna.`;
    }
    const akm = sec.akm.length ? ` · ${sec.akm.join('/')}` : '';
    const cipher = sec.pairwise.length ? ` · ${sec.pairwise.join('+')}` : '';
    c.add({
      id: 'wifi.security',
      metric: 'wifi.security',
      category: 'security',
      title: 'Protezione della rete Wi-Fi',
      value: `${label}${akm}${cipher}`,
      severity: sev,
      verdict,
      actions: sev === 'crit' || sev === 'warn' ? ['upgrade-security'] : [],
    });

    if (sec.pmf && (p === 'wpa2' || p === 'wpa2/wpa3' || p === 'wpa3')) {
      const sevP: Severity = sec.pmf === 'disabled' ? 'warn' : 'ok';
      c.add({
        id: 'wifi.pmf',
        metric: 'wifi.pmf',
        category: 'security',
        title: 'Protezione frame di gestione',
        value: { disabled: 'assente', capable: 'supportata', required: 'obbligatoria' }[sec.pmf],
        severity: sevP,
        verdict:
          sevP === 'ok'
            ? 'I messaggi di disconnessione sono firmati: non possono essere falsificati.'
            : 'Senza PMF chiunque nel raggio può scollegare i tuoi dispositivi con messaggi falsificati.',
        actions: sevP === 'ok' ? [] : ['enable-pmf'],
      });
    }
    if (sec.wps) {
      c.add({
        id: 'wifi.wps',
        metric: 'wifi.wps',
        category: 'security',
        title: 'WPS',
        value: 'attivo',
        severity: 'warn',
        verdict: 'Il router annuncia il WPS. Se la modalità PIN è attiva, la password Wi-Fi può essere recuperata indipendentemente dalla sua complessità.',
        actions: ['disable-wps'],
      });
    }
  }

  if (me) analyzeOwnNetwork(c, me, wifi.networks);
  networksFinding(c, wifi.networks);
}

// ---------------------------------------------------------------- Rete con più access point

/** Sotto questa soglia una radio non sente più le trasmissioni altrui e non rimanda le proprie. */
const OWN_OVERLAP_DBM = -80;
const ROAM_NAMES: [keyof Pick<Roaming, 'k' | 'v' | 'r'>, string][] = [
  ['k', '802.11k'],
  ['v', '802.11v'],
  ['r', '802.11r'],
];

/** Stessa famiglia di protezione (o sconosciuta): le radio che fanno davvero parte della rete. */
function compatible(a: Bss, b: Bss): boolean {
  const x = secFamily(a.security);
  const y = secFamily(b.security);
  return x === y || x === 'unknown' || y === 'unknown';
}

/** La radio della stessa rete, nella stessa banda, che si riceve meglio di quella collegata. */
function strongestPeer(me: Bss, networks: Bss[]): Bss | undefined {
  const peers = ownRadios(networks, me.ssid).filter((b) => b !== me && b.band === me.band && compatible(b, me));
  return peers.length ? peers.reduce((a, b) => (b.rssiDbm > a.rssiDbm ? b : a)) : undefined;
}

function analyzeOwnNetwork(c: Collector, me: Bss, networks: Bss[]) {
  const radios = ownRadios(networks, me.ssid);
  if (radios.length < 2) return;
  // Le radio con una protezione diversa non sono AP della rete: le valuta il controllo di sicurezza.
  const own = radios.filter((b) => compatible(b, me));
  const aps = apCount(own);
  const fam = secFamily(me.security);
  const bands = (['2.4', '5', '6'] as Band[]).filter((b) => own.some((r) => r.band === b));
  const where = (b: Bss) => `${b.bssid} (${bandLabel(b.band)}, canale ${b.channel}, ${b.rssiDbm} dBm)`;

  if (aps >= 2) {
    const perBand = bands.map((b) => {
      const rs = own.filter((r) => r.band === b);
      const chs = unique(rs.map((r) => r.channel)).sort((x, y) => x - y);
      return `${bandLabel(b)}: ${rs.length} radio su ${chs.length === 1 ? 'canale' : 'canali'} ${chs.join(', ')}`;
    });
    c.add({
      id: 'wifi.aps',
      metric: 'wifi.aps',
      category: 'wifi',
      title: 'Access point della tua rete',
      value: `${aps} AP · ${own.length} radio`,
      numeric: aps,
      severity: 'info',
      verdict: `La rete "${me.ssid}" è annunciata da almeno ${aps} access point ricevuti da qui. ${perBand.join('; ')}. Sei collegato a ${where(me)}.`,
    });
  }

  // AP della stessa rete che si contendono lo stesso spettro in questo punto.
  if (bands.some((b) => own.filter((r) => r.band === b).length > 1)) {
    const pairs = overlappingPairs(own).filter(([a, b]) => a.rssiDbm >= OWN_OVERLAP_DBM && b.rssiDbm >= OWN_OVERLAP_DBM);
    const mine = pairs.some(([a, b]) => a === me || b === me);
    const list =
      pairs
        .slice(0, 3)
        .map(([a, b]) => `${bandLabel(a.band)} canale ${a.channel === b.channel ? a.channel : `${a.channel}/${b.channel}`}: ${a.bssid} a ${a.rssiDbm} dBm e ${b.bssid} a ${b.rssiDbm} dBm`)
        .join('; ') + more(pairs.length, 3);
    c.add({
      id: 'wifi.owncochannel',
      metric: 'wifi.owncochannel',
      category: 'wifi',
      title: 'AP della tua rete sullo stesso canale',
      value: pairs.length ? `${pairs.length} ${pairs.length === 1 ? 'coppia' : 'coppie'}` : 'nessuno',
      numeric: pairs.length,
      severity: pairs.length ? 'warn' : 'ok',
      verdict: pairs.length
        ? `${list}. Dove si ricevono entrambi, questi AP si dividono il tempo di trasmissione come se fossero uno solo${mine ? ', compreso quello a cui sei collegato' : ''}. Nei sistemi mesh collegati via radio è inevitabile; altrimenti conviene assegnare canali diversi.`
        : 'Gli AP della tua rete ricevuti da qui usano canali diversi: non si contendono lo spettro.',
      actions: pairs.length ? ['plan-ap-channels'] : [],
    });
  }

  // Sticky client: agganciato a un AP debole mentre uno della stessa rete, nella stessa banda, si sente molto meglio.
  const best = strongestPeer(me, networks);
  if (best) {
    const gain = best.rssiDbm - me.rssiDbm;
    const sticky = me.rssiDbm < -67 && gain >= 10;
    c.add({
      id: 'wifi.sticky',
      metric: 'wifi.sticky',
      category: 'wifi',
      title: sticky ? 'Collegato a un AP lontano' : 'Scelta dell\'access point',
      value: sticky ? `${gain} dB in più disponibili` : gain > 0 ? `il migliore è ${gain} dB più forte` : 'AP migliore',
      numeric: Math.max(0, gain),
      severity: sticky ? 'warn' : 'ok',
      verdict: sticky
        ? `Il PC è collegato a ${where(me)}, mentre ${where(best)} della stessa rete si riceve molto meglio. È lo "sticky client": il dispositivo resta sull'AP lontano, va più lento e rallenta anche gli altri utenti di quell'AP.`
        : gain > 0
          ? `Un altro AP della rete si riceve ${gain} dB meglio, ma il segnale attuale (${me.rssiDbm} dBm) è adeguato: restare collegati è corretto.`
          : 'Il PC è collegato all\'AP della rete che si riceve meglio in questa banda.',
      actions: sticky ? ['fix-roaming', 'update-wifi-driver'] : [],
    });
  }

  // Roaming assistito: conta solo dove ci sono più AP tra cui passare.
  const r = me.roaming;
  if (aps >= 2 && r) {
    const missing = ROAM_NAMES.filter(([k]) => !r[k]).map(([, n]) => n);
    const present = ROAM_NAMES.filter(([k]) => r[k]).map(([, n]) => n);
    const withData = own.filter((b) => b.roaming);
    const uneven = withData.some((b) => ROAM_NAMES.some(([k]) => b.roaming![k] !== r[k]));
    const mdids = unique(withData.filter((b) => b.roaming!.r && b.roaming!.mdid).map((b) => b.roaming!.mdid as string));
    const why: string[] = [];
    if (!r.k) why.push('senza 802.11k il dispositivo deve cercare da solo gli AP vicini');
    if (!r.v) why.push('senza 802.11v la rete non può indirizzarlo verso l\'AP migliore');
    if (!r.r)
      why.push(
        fam === 'enterprise'
          ? 'senza 802.11r ogni passaggio ripete l\'autenticazione 802.1X con il server RADIUS, che può interrompere chiamate e applicazioni in tempo reale'
          : 'senza 802.11r ogni passaggio ripete lo scambio delle chiavi, con qualche decina di millisecondi di interruzione',
      );
    let verdict = missing.length
      ? `L'AP a cui sei collegato ${present.length ? `annuncia ${present.join(' e ')} ma non ` : 'non annuncia '}${missing.join(', ')}: ${why.join('; ')}.`
      : 'L\'AP a cui sei collegato annuncia 802.11k, 802.11v e 802.11r: i dispositivi compatibili ricevono l\'elenco degli AP vicini, vengono indirizzati verso il migliore e passano dall\'uno all\'altro rapidamente.';
    if (uneven) verdict += ' Non tutti gli AP della rete annunciano le stesse funzioni: tra AP configurati diversamente il roaming non le sfrutta.';
    if (mdids.length > 1) verdict += ` Gli AP con 802.11r usano Mobility Domain diversi (${mdids.join(', ')}): la transizione veloce funziona solo tra AP dello stesso dominio.`;
    const sev: Severity = missing.length || uneven || mdids.length > 1 ? 'info' : 'ok';
    c.add({
      id: 'wifi.roaming',
      metric: 'wifi.roaming',
      category: 'wifi',
      title: 'Roaming assistito',
      value: ROAM_NAMES.map(([k]) => `${k} ${r[k] ? 'sì' : 'no'}`).join(' · '),
      severity: sev,
      verdict,
      actions: sev === 'ok' ? [] : ['fix-roaming'],
    });
  }

  // Stessa rete annunciata con protezioni diverse: AP configurato male o AP gemello.
  const known = radios.filter((b) => secFamily(b.security) !== 'unknown');
  if (known.length >= 2 && fam !== 'unknown' && me.security) {
    const mySec = me.security;
    const weak = (f: string) => f === 'open' || f === 'legacy';
    const oddFam = known.filter((b) => secFamily(b.security) !== fam);
    const oddProto = known.filter((b) => secFamily(b.security) === fam && b.security!.protocol !== mySec.protocol);
    let sev: Severity = 'ok';
    let verdict = `Tutte le ${known.length} radio che annunciano "${me.ssid}" usano la stessa protezione (${secLabel(mySec)}).`;
    if (oddFam.length) {
      sev = !weak(fam) && oddFam.some((b) => weak(secFamily(b.security))) ? 'crit' : 'warn';
      verdict = `La rete "${me.ssid}" è annunciata anche da ${oddFam
        .slice(0, 3)
        .map((b) => `${where(b)} con protezione ${secLabel(b.security!)}`)
        .join('; ')}${more(oddFam.length, 3)}, diversa da quella dell'AP a cui sei collegato (${secLabel(mySec)}). Può essere un access point configurato male o un AP gemello che imita la rete per intercettare chi si collega.`;
    } else if (oddProto.length) {
      sev = 'info';
      verdict = `Gli AP della rete usano varianti diverse della stessa protezione (${unique(known.map((b) => secLabel(b.security!))).join(', ')}): passando da un AP all'altro i dispositivi possono dover ripetere l'autenticazione. Conviene uniformare la configurazione.`;
    }
    if (sev !== 'ok' || aps >= 2) {
      c.add({
        id: 'wifi.mixedsec',
        metric: 'wifi.mixedsec',
        category: 'security',
        title: 'Protezione degli AP della rete',
        value: oddFam.length ? `${oddFam.length} ${oddFam.length === 1 ? 'radio diversa' : 'radio diverse'}` : oddProto.length ? 'varianti diverse' : 'coerente',
        numeric: oddFam.length,
        severity: sev,
        verdict,
        actions: sev === 'crit' || sev === 'warn' ? ['check-rogue-ap'] : [],
      });
    }
  }
}

function networksFinding(c: Collector, nets: Bss[]) {
  const by = (band: string) => nets.filter((b) => b.band === band).length;
  const hidden = nets.filter((b) => !b.ssid).length;
  const insecure = nets.filter((b) => b.security && ['open', 'wep', 'wpa'].includes(b.security.protocol)).length;
  c.add({
    id: 'wifi.networks',
    metric: 'wifi.networks',
    category: 'wifi',
    title: 'Reti visibili',
    value: `${nets.length}`,
    numeric: nets.length,
    severity: 'info',
    verdict:
      `${by('2.4')} a 2,4 GHz, ${by('5')} a 5 GHz${by('6') ? `, ${by('6')} a 6 GHz` : ''}.` +
      (hidden ? ` ${hidden} ${hidden === 1 ? 'nascosta' : 'nascoste'}.` : '') +
      (insecure ? ` ${insecure} con protezione assente o obsoleta: se non sono tue, non collegarti.` : '') +
      (by('2.4') > 15 ? ' Ambiente radio molto affollato sul 2,4 GHz.' : ''),
  });
}

// ---------------------------------------------------------------- LAN

function analyzeLan(scan: Scan, c: Collector, primary?: Adapter, corp?: CorporateDomain) {
  if (!primary) {
    c.add({
      id: 'lan.address',
      metric: 'lan.address',
      category: 'lan',
      title: 'Connessione di rete',
      value: 'nessuna',
      severity: 'crit',
      verdict: 'Nessuna scheda di rete attiva con un indirizzo IP: il PC non è collegato a nessuna rete.',
      actions: ['restart-network', 'check-dhcp'],
    });
    return;
  }
  const v4 = primary.ipv4.filter((a) => !a.startsWith('127.'));
  const apipa = v4.length > 0 && v4.every(isApipa);
  const withGw = scan.adapters.filter((a) => a.up && a.gateways.length > 0);
  const gwIp = scan.gateway?.ip ?? primary.gateways[0];
  const assigned =
    primary.dhcp === false
      ? 'statico'
      : primary.dhcpServer && primary.dhcpServer !== gwIp
        ? `assegnato dal server DHCP ${primary.dhcpServer}`
        : 'assegnato dal router';
  c.add({
    id: 'lan.address',
    metric: 'lan.address',
    category: 'lan',
    title: 'Indirizzo IP',
    value: v4[0] ?? 'nessuno',
    severity: v4.length === 0 || apipa ? 'crit' : 'ok',
    verdict: apipa
      ? 'Indirizzo automatico 169.254.x.x: il router non ha assegnato un indirizzo, quindi il PC non può navigare.'
      : v4.length === 0
        ? 'Nessun indirizzo IPv4 assegnato.'
        : `Indirizzo ${assigned} sulla scheda "${primary.name}"${primary.kind === 'wifi' ? ' (Wi-Fi)' : primary.kind === 'ethernet' ? ' (cavo)' : ''}.`,
    actions: apipa || v4.length === 0 ? ['check-dhcp', 'restart-network'] : [],
  });

  // Sottoreti molto ampie: spesso il segno di una rete piatta, senza zone.
  const prefix = v4.length && !apipa ? Number(v4[0].split('/')[1]) : NaN;
  if (prefix >= 8 && prefix <= 20) {
    const size = Math.pow(2, 32 - prefix) - 2;
    c.add({
      id: 'lan.subnet',
      metric: 'lan.subnet',
      category: 'lan',
      title: 'Ampiezza della sottorete',
      value: `/${prefix} · ${thousands(size)} indirizzi`,
      numeric: prefix,
      severity: 'info',
      verdict: `La sottorete del PC può contenere fino a ${thousands(size)} dispositivi nello stesso dominio di broadcast. Se ospita insieme PC, ospiti, stampanti e dispositivi è una rete piatta: dividerla in zone (VLAN) per funzione circoscrive guasti e infezioni.`,
      actions: ['plan-segmentation'],
    });
  }
  if (!gwIp) {
    c.add({
      id: 'lan.gateway',
      metric: 'lan.gateway',
      category: 'lan',
      title: 'Gateway predefinito',
      value: 'assente',
      severity: 'crit',
      verdict: 'Non c\'è un router configurato: il PC può parlare solo con la rete locale.',
      actions: ['check-dhcp', 'restart-network'],
    });
  } else {
    c.add({
      id: 'lan.gateway',
      metric: 'lan.gateway',
      category: 'lan',
      title: 'Gateway predefinito',
      value: gwIp,
      severity: withGw.length > 1 ? 'info' : 'ok',
      verdict:
        withGw.length > 1
          ? `Ci sono ${withGw.length} schede con un gateway (${withGw.map((a) => a.name).join(', ')}): Windows sceglie la più veloce, ma VPN o connessioni doppie possono causare percorsi inattesi.`
          : 'Il PC sa a quale router inviare il traffico per Internet.',
    });
  }

  const wifiLink = primary.kind === 'wifi';
  const gp = scan.gateway?.ping;
  const conn = scan.wifi?.connected;
  const wifiBand = scan.wifi?.networks.find((b) => b.connected)?.band ?? conn?.band;
  const chAction = wifiBand === '2.4' ? 'change-channel-24' : 'change-channel-5';
  if (gp && gp.sent > 0) {
    const loss = lossPct(gp);
    const otherServices = scan.gateway?.ports?.some((p) => p.open) || scan.gateway?.upnp?.found;
    // Se il traffico verso Internet passa, il router è vivo per definizione: lo inoltra lui.
    const forwards = scan.internet?.targets.some((t) => t.received > 0) || scan.internet?.http?.some((h) => h.ok);
    if (gp.received === 0) {
      c.add({
        id: 'lan.gwloss',
        metric: 'lan.gwloss',
        category: 'lan',
        title: 'Risposta del router al ping',
        value: 'nessuna risposta',
        severity: otherServices || forwards ? 'info' : 'crit',
        verdict: otherServices
          ? 'Il router non risponde al ping ma risponde su altri servizi: è configurato per ignorare i ping, non è un guasto.'
          : forwards
            ? 'Il router non risponde alle misure dirette (ping e connessioni), ma inoltra regolarmente il traffico verso Internet: è configurato per non rispondere. La latenza del tratto locale non è misurabile.'
            : 'Il router non risponde: rete locale interrotta, router bloccato o Wi-Fi scollegato.',
        actions: otherServices || forwards ? [] : ['restart-network'],
      });
    } else {
      const avg = gp.avgMs ?? 0;
      const sevL: Severity = avg <= 20 ? 'ok' : avg <= 50 ? 'warn' : 'crit';
      const local = wifiLink ? ['move-closer', chAction, 'use-ethernet'] : ['check-cable', 'restart-network'];
      c.add({
        id: 'lan.gwlatency',
        metric: 'lan.gwlatency',
        category: 'lan',
        title: 'Latenza verso il router',
        value: ms(avg),
        numeric: avg,
        severity: sevL,
        verdict:
          sevL === 'ok'
            ? wifiLink
              ? 'Tratto Wi-Fi reattivo.'
              : avg > 5
                ? 'Accettabile, ma via cavo ci si aspetterebbe meno di 1-2 ms: router sotto carico?'
                : 'Tratto cablato reattivo, come deve essere.'
            : `Per una rete locale ${ms(avg)} è ${sevL === 'crit' ? 'molto ' : ''}alto: ${wifiLink ? 'il Wi-Fi è disturbato o il segnale è debole' : 'cavo, porta o router hanno un problema'}.`,
        actions: sevL === 'ok' ? [] : local,
      });
      const sevP: Severity = loss === 0 ? 'ok' : loss <= 2 ? 'warn' : 'crit';
      c.add({
        id: 'lan.gwloss',
        metric: 'lan.gwloss',
        category: 'lan',
        title: 'Pacchetti persi verso il router',
        value: `${pct(loss)} (${gp.sent - gp.received}/${gp.sent})`,
        numeric: loss,
        severity: sevP,
        verdict:
          sevP === 'ok'
            ? 'Nessun pacchetto perso nel tratto locale.'
            : `Nel tratto locale ${lostText(gp.sent - gp.received, gp.sent)}: ${wifiLink ? 'tipico di segnale debole o interferenze' : 'possibile cavo o porta difettosi'}.`,
        actions: sevP === 'ok' ? [] : local,
      });
      if (gp.jitterMs !== undefined) {
        const j = gp.jitterMs;
        const sevJ: Severity = j < 10 ? 'ok' : j <= 30 ? 'warn' : 'crit';
        c.add({
          id: 'lan.jitter',
          metric: 'net.jitter',
          category: 'lan',
          title: 'Stabilità verso il router (jitter)',
          value: ms(j),
          numeric: j,
          severity: sevJ,
          verdict: sevJ === 'ok' ? 'Latenza locale stabile.' : 'La latenza locale oscilla molto: tipico di Wi-Fi con interferenze o con molti dispositivi attivi.',
          actions: sevJ === 'ok' ? [] : local,
        });
      }
    }
  }

  for (const a of scan.adapters) {
    if (!a.up || a.kind !== 'ethernet' || !a.linkMbps || a.ipv4.length === 0) continue;
    const s = a.linkMbps;
    const sev: Severity = s >= 1000 ? 'ok' : s >= 100 ? 'warn' : 'crit';
    c.add({
      id: `lan.linkspeed.${a.name}`,
      metric: 'lan.linkspeed',
      category: 'lan',
      title: `Velocità porta "${a.name}"`,
      value: s >= 1000 ? `${fmt(s / 1000, s % 1000 ? 1 : 0)} Gbit/s` : `${s} Mbit/s`,
      numeric: s,
      severity: sev,
      verdict:
        sev === 'ok'
          ? 'Collegamento gigabit: il cavo non è un limite.'
          : `Collegamento a ${s} Mbit/s: limita qualsiasi linea più veloce. Se la scheda e il router sono gigabit, il cavo è il primo sospettato.`,
      actions: sev === 'ok' ? [] : ['check-cable'],
    });
  }

  const global6 = primary.ipv6.filter((a) => /^[23]/.test(a));
  c.add({
    id: 'lan.ipv6',
    metric: 'lan.ipv6',
    category: 'lan',
    title: 'IPv6',
    value: global6.length ? 'attivo' : 'non disponibile',
    severity: global6.length ? 'ok' : 'info',
    verdict: global6.length
      ? `Indirizzo globale ${global6[0].split('/')[0]}: la rete supporta IPv6.`
      : corp
        ? 'Nessun indirizzo IPv6 globale: la rete funziona su IPv4. Nelle reti aziendali l\'adozione di IPv6 è una scelta di progetto, non un problema.'
        : 'Nessun indirizzo IPv6 globale: Internet funziona su IPv4. Non è un problema, ma se l\'operatore lo offre puoi attivarlo nel router.',
  });

  if (scan.lan) {
    const n = scan.lan.neighbors.length;
    c.add({
      id: 'lan.neighbors',
      metric: 'lan.neighbors',
      category: 'lan',
      title: 'Dispositivi visti di recente',
      value: String(n),
      numeric: n,
      severity: 'info',
      verdict: n
        ? `Il PC ha comunicato di recente con ${n === 1 ? 'un dispositivo' : `${n} dispositivi`} della rete. Confrontali con l'elenco del router se sospetti intrusi.`
        : 'Nessun altro dispositivo nella tabella del sistema.',
      actions: n > 15 ? ['separate-iot'] : [],
    });
  }

  if (corp) {
    const sfx = primary.dnsSuffix;
    const dns = primary.dns.join(', ');
    c.add({
      id: 'lan.domain',
      metric: 'lan.domain',
      category: 'lan',
      title: 'Rete aziendale con dominio',
      value: corp.name,
      severity: 'info',
      verdict:
        (corp.joined ? `Il PC fa parte del dominio ${corp.name}` : `La connessione riceve il suffisso DNS ${corp.name} e usa solo DNS interni`) +
        (corp.joined && sfx && sfx.toLowerCase() !== corp.name.toLowerCase() ? ` (suffisso della connessione: ${sfx})` : '') +
        `. Nomi, accessi e criteri dipendono dai server della rete${dns ? `, in particolare dai DNS ${dns}` : ''}: Polaris non suggerisce di sostituirli con DNS pubblici, che non conoscono i nomi interni.`,
    });
  }

  const shared = sharedMacs(scan);
  if (shared.length) {
    const gw = scan.gateway?.ip;
    const gwDup = gw ? shared.find((d) => d.ips.indexOf(gw) >= 0) : undefined;
    const list = shared
      .slice(0, 3)
      .map((d) => `${d.mac} → ${d.ips.join(', ')}`)
      .join('; ');
    c.add({
      id: 'lan.dupmac',
      metric: 'lan.dupmac',
      category: gwDup ? 'security' : 'lan',
      title: 'Stesso MAC per più indirizzi',
      value: `${shared.length} MAC · ${shared.reduce((s, d) => s + d.ips.length, 0)} indirizzi`,
      numeric: shared.length,
      severity: gwDup ? 'warn' : 'info',
      verdict: gwDup
        ? `Il MAC del router (${gwDup.mac}) risponde anche per ${gwDup.ips.filter((ip) => ip !== gw).join(', ')}. Può essere un apparato con più indirizzi o un ripetitore, ma anche un dispositivo che si spaccia per il router per intercettare il traffico (ARP spoofing): va verificato.`
        : `${list}${more(shared.length, 3)}. Di solito è un ripetitore Wi-Fi che traduce gli indirizzi dei dispositivi collegati, un server con più indirizzi o un host di macchine virtuali; se non riconosci il dispositivo, verificalo.`,
      actions: ['check-arp'],
    });
  }
}

/** MAC che compaiono per più indirizzi IPv4 (tabella ARP, inventario e gateway). */
function sharedMacs(scan: Scan): { mac: string; ips: string[] }[] {
  const by: Record<string, string[]> = {};
  const add = (ip?: string, mac?: string) => {
    if (!ip || !mac) return;
    const m = mac.toLowerCase().replace(/-/g, ':');
    if (m === 'ff:ff:ff:ff:ff:ff' || m === '00:00:00:00:00:00' || m.indexOf('01:00:5e') === 0 || m.indexOf('33:33') === 0) return;
    const ips = by[m] || (by[m] = []);
    if (ips.indexOf(ip) < 0) ips.push(ip);
  };
  for (const n of scan.lan?.neighbors ?? []) add(n.ip, n.mac);
  for (const h of scan.infra?.inventory?.hosts ?? []) add(h.ip, h.mac);
  if (scan.gateway) add(scan.gateway.ip, scan.gateway.mac);
  return Object.keys(by)
    .filter((m) => by[m].length > 1)
    .map((m) => ({ mac: m, ips: by[m] }));
}

// ---------------------------------------------------------------- Internet

function analyzeInternet(scan: Scan, c: Collector, primary?: Adapter, corp?: CorporateDomain) {
  const net = scan.internet;
  if (!net) return;
  const gwAvg = scan.gateway?.ping?.received ? scan.gateway.ping.avgMs : undefined;
  const httpOk = net.http?.some((h) => h.ok);
  const answered = net.targets.filter((t) => t.received > 0);

  if (net.targets.length) {
    if (!answered.length) {
      c.add({
        id: 'net.latency',
        metric: 'net.latency',
        category: 'internet',
        title: 'Raggiungibilità di Internet',
        value: 'nessuna risposta',
        severity: httpOk ? 'info' : 'crit',
        verdict: httpOk
          ? 'I server pubblici non rispondono al ping ma il web funziona: la rete (aziendale, hotel o firewall) blocca i ping. Latenza non misurabile.'
          : 'Nessun server pubblico risponde: Internet non è raggiungibile.',
        actions: httpOk ? [] : ['restart-network', 'contact-isp'],
      });
    } else {
      const best = answered.reduce((a, b) => ((a.avgMs ?? 1e9) <= (b.avgMs ?? 1e9) ? a : b));
      const avg = best.avgMs ?? 0;
      const sev: Severity = avg <= 40 ? 'ok' : avg <= 80 ? 'warn' : 'crit';
      const localShare = gwAvg !== undefined ? gwAvg / Math.max(avg, 0.1) : 0;
      const localCause = gwAvg !== undefined && gwAvg > 20 && localShare > 0.4;
      c.add({
        id: 'net.latency',
        metric: 'net.latency',
        category: 'internet',
        title: 'Latenza verso Internet',
        value: ms(avg),
        numeric: avg,
        severity: sev,
        verdict:
          (sev === 'ok'
            ? avg <= 20
              ? 'Latenza ottima, tipica della fibra.'
              : 'Latenza buona.'
            : `Latenza ${sev === 'crit' ? 'alta' : 'discreta'}: si sente nei giochi e nelle videochiamate.`) +
          ` Server più vicino: ${best.label ?? best.target}.` +
          (best.method === 'tcp' ? ' (Misurata con connessioni TCP: i ping sono bloccati in questa rete.)' : '') +
          (gwAvg !== undefined && sev !== 'ok'
            ? localCause
              ? ` Di questi, ${ms(gwAvg)} si accumulano già tra PC e router: il problema è in casa.`
              : ` La rete di casa pesa solo ${ms(gwAvg)}: il ritardo nasce sulla linea o nella rete dell'operatore.`
            : ''),
        actions: sev === 'ok' ? [] : localCause ? ['move-closer', 'use-ethernet'] : ['reduce-load', 'contact-isp'],
      });
      const sent = net.targets.reduce((s, t) => s + t.sent, 0);
      const recv = net.targets.reduce((s, t) => s + t.received, 0);
      const silent = net.targets.filter((t) => t.received === 0).length;
      // Un singolo server che ignora i ping non è perdita di linea: lo si esclude.
      const counted = net.targets.filter((t) => t.received > 0);
      const sentC = counted.reduce((s, t) => s + t.sent, 0);
      const recvC = counted.reduce((s, t) => s + t.received, 0);
      const loss = sentC ? (100 * (sentC - recvC)) / sentC : 0;
      // Il confronto con il router ha senso solo se il router risponde alle misure.
      const gwPing = scan.gateway?.ping;
      const gwLoss = gwPing && gwPing.received > 0 ? lossPct(gwPing) : 0;
      // Con i ping bloccati si misura con connessioni TCP: un tentativo fallito può
      // dipendere dai limiti del server, quindi il giudizio resta prudente.
      const viaTcp = counted.every((t) => t.method === 'tcp');
      let sevL: Severity = loss === 0 ? 'ok' : loss <= 2 ? 'warn' : 'crit';
      if (viaTcp && sevL === 'crit') sevL = 'warn';
      c.add({
        id: 'net.loss',
        metric: 'net.loss',
        category: 'internet',
        title: 'Pacchetti persi verso Internet',
        value: `${pct(loss)} (${sentC - recvC}/${sentC})`,
        numeric: loss,
        severity: sevL,
        verdict:
          (sevL === 'ok' ? 'Nessuna perdita verso Internet.' : `Verso Internet ${lostText(sentC - recvC, sentC)}.`) +
          (sevL !== 'ok' ? (gwLoss > 0 ? ' Anche verso il router ci sono perdite: la causa è (anche) in casa.' : ' Verso il router nessuna perdita: la causa è sulla linea.') : '') +
          (silent && sent !== recv ? ` (${silent} server ignorano i ping e sono esclusi dal calcolo.)` : '') +
          (viaTcp && sevL !== 'ok'
            ? ' Misura fatta con connessioni TCP perché i ping sono bloccati: un tentativo fallito può dipendere dai limiti del server e non solo dalla linea.'
            : ''),
        actions: sevL === 'ok' ? [] : gwLoss > 0 ? ['move-closer', 'use-ethernet'] : ['contact-isp', 'reduce-load'],
      });
      if (best.jitterMs !== undefined) {
        const j = best.jitterMs;
        const sevJ: Severity = j < 10 ? 'ok' : j <= 30 ? 'warn' : 'crit';
        const gwJ = scan.gateway?.ping?.jitterMs;
        const localJ = gwJ !== undefined && gwJ >= j * 0.5;
        c.add({
          id: 'net.jitter',
          metric: 'net.jitter',
          category: 'internet',
          title: 'Stabilità verso Internet (jitter)',
          value: ms(j),
          numeric: j,
          severity: sevJ,
          verdict:
            sevJ === 'ok'
              ? 'Latenza verso Internet stabile.'
              : localJ
                ? `La latenza verso Internet oscilla, ma oscilla già verso il router (${ms(gwJ as number)}): l'instabilità nasce in casa.`
                : 'La latenza verso Internet oscilla mentre verso il router è stabile: tipico di linea congestionata o di download in corso su altri dispositivi.',
          actions: sevJ === 'ok' ? [] : localJ ? ['move-closer', 'use-ethernet', 'reduce-load'] : ['reduce-load', 'contact-isp'],
        });
      }
    }
  }

  if (net.traceroute && net.traceroute.length) {
    const hops = net.traceroute;
    const resp = hops.filter((h) => h.rttMs !== undefined);
    let worst: { at: number; jump: number } | undefined;
    for (let i = 1; i < resp.length; i++) {
      const jump = (resp[i].rttMs ?? 0) - (resp[i - 1].rttMs ?? 0);
      // Il salto conta solo se anche il nodo successivo resta alto:
      // un singolo router lento a rispondere ai traceroute non è un problema.
      const next = resp[i + 1];
      const persistent = !next || (next.rttMs ?? 0) >= (resp[i].rttMs ?? 0) - 10;
      if (jump > 30 && persistent && (!worst || jump > worst.jump)) worst = { at: resp[i].ttl, jump };
    }
    const silent = hops.filter((h) => !h.ip).length;
    const reached = !!net.traceTarget && hops.some((h) => h.ip === net.traceTarget);
    c.add({
      id: 'net.trace',
      metric: 'net.trace',
      category: 'internet',
      title: 'Percorso verso Internet',
      value: `${hops.length} ${hops.length === 1 ? 'salto' : 'salti'}${silent ? ` (${silent} ${silent === 1 ? 'muto' : 'muti'})` : ''}`,
      numeric: hops.length,
      severity: worst ? 'warn' : 'ok',
      verdict: worst
        ? `Al salto ${worst.at} la latenza cresce di ${ms(worst.jump)} e resta alta: lì c'è congestione o una tratta lunga.${worst.at <= 3 ? ' È vicino a casa: probabilmente la linea di accesso.' : ''}`
        : reached
          ? `Percorso regolare verso ${net.traceTarget}: nessun salto anomalo.${silent ? ' I nodi muti ignorano i traceroute: è normale.' : ''}`
          : `Percorso parziale: la destinazione ${net.traceTarget ?? ''} non risponde ai traceroute (spesso filtrati da operatori e firewall). Nei salti misurati nessuna anomalia.`,
      actions: worst ? ['contact-isp'] : [],
    });
  }

  if (net.mtu) {
    const m = net.mtu.mtu;
    const sev: Severity = m >= 1500 ? 'ok' : m >= 1400 ? 'info' : 'warn';
    c.add({
      id: 'net.mtu',
      metric: 'net.mtu',
      category: 'internet',
      title: 'MTU del percorso',
      value: `${m} byte`,
      numeric: m,
      severity: sev,
      verdict:
        sev === 'ok'
          ? 'Valore standard: i pacchetti viaggiano senza frammentazione.'
          : sev === 'info'
            ? m === 1492
              ? 'Valore tipico delle connessioni PPPoE: tutto regolare.'
              : 'Leggermente sotto lo standard: normale con PPPoE o VPN.'
            : 'Insolitamente bassa: se alcuni siti si caricano a metà, la causa può essere questa.',
      actions: sev === 'warn' ? ['fix-mtu'] : [],
    });
  }

  if (net.http && net.http.length) {
    const ok = net.http.filter((h) => h.ok);
    const t = ok.length ? Math.min(...ok.map((h) => h.timeMs ?? 0)) : undefined;
    // Una sola richiesta "a freddo" (DNS, TCP, TLS, risposta): sotto 800 ms è normale.
    const sev: Severity = !ok.length ? 'crit' : (t ?? 0) <= 800 ? 'ok' : 'warn';
    c.add({
      id: 'net.http',
      metric: 'net.http',
      category: 'internet',
      title: 'Navigazione web',
      value: t !== undefined ? ms(t) : 'fallita',
      numeric: t,
      severity: sev,
      verdict: !ok.length
        ? `Nessun sito di prova risponde${net.http[0].error ? ` (${net.http[0].error})` : ''}: possibile assenza di Internet, proxy o pagina di accesso (hotel, aeroporto) da completare.`
        : sev === 'ok'
          ? 'Una richiesta HTTPS completa (DNS, connessione, cifratura, risposta) va a buon fine rapidamente.'
          : 'La navigazione funziona ma è lenta a rispondere.',
      actions: !ok.length ? ['restart-network', 'contact-isp'] : sev === 'warn' ? [corp ? 'internal-dns' : 'change-dns', 'reduce-load'] : [],
    });
  }
  void primary;
}

// ---------------------------------------------------------------- DNS

function analyzeDns(scan: Scan, c: Collector, corp?: CorporateDomain) {
  const d = scan.dns;
  if (!d || (!d.system.length && !d.public.length)) return;
  // Con un dominio i DNS si migliorano sui server: cambiarli sul PC rompe i nomi interni.
  const fixDns = corp ? 'internal-dns' : 'change-dns';
  const sysOk = d.system.filter((s) => s.ok && s.timeMs !== undefined);
  let sysTime: number | undefined;
  if (d.system.length) {
    if (!sysOk.length) {
      c.add({
        id: 'dns.time',
        metric: 'dns.time',
        category: 'dns',
        title: 'DNS configurato',
        value: 'nessuna risposta',
        severity: 'crit',
        verdict:
          `Il server DNS ${d.system.map((s) => s.server).join(', ')} non risponde: i siti non si aprono per nome anche se la connessione funziona.` +
          (corp ? ' In una rete con dominio smettono di funzionare anche accessi, cartelle condivise e criteri.' : ''),
        actions: [fixDns, 'restart-network'],
      });
    } else {
      sysTime = Math.min(...sysOk.map((s) => s.timeMs as number));
      const sev: Severity = sysTime <= 100 ? 'ok' : sysTime <= 250 ? 'warn' : 'crit';
      const best = sysOk.find((s) => s.timeMs === sysTime)!;
      const isRouter = best.server === scan.gateway?.ip;
      c.add({
        id: 'dns.time',
        metric: 'dns.time',
        category: 'dns',
        title: 'Tempo di risposta DNS',
        value: ms(sysTime),
        numeric: sysTime,
        severity: sev,
        verdict:
          (sev === 'ok' ? 'Risoluzione dei nomi rapida.' : 'Risoluzione dei nomi lenta: ogni nuovo sito parte in ritardo.') +
          ` Server: ${best.server}${isRouter ? ' (il router, che inoltra all\'operatore)' : corp ? ' (DNS interno)' : ''}.` +
          (d.system.length > sysOk.length ? ` ${d.system.length - sysOk.length} server configurati non rispondono.` : ''),
        actions: sev === 'ok' ? [] : [fixDns],
      });
    }
  }
  const pubOk = d.public.filter((s) => s.ok && s.timeMs !== undefined);
  if (pubOk.length) {
    const fastest = pubOk.reduce((a, b) => ((a.timeMs as number) <= (b.timeMs as number) ? a : b));
    const gain = sysTime !== undefined ? sysTime - (fastest.timeMs as number) : undefined;
    const better = gain === undefined || gain > 30;
    const name = fastest.label ?? fastest.server;
    c.add({
      id: 'dns.compare',
      metric: 'dns.compare',
      category: 'dns',
      title: 'Confronto con DNS pubblici',
      value: `${name}: ${ms(fastest.timeMs as number)}`,
      numeric: fastest.timeMs,
      severity: better ? 'info' : 'ok',
      verdict:
        gain === undefined
          ? `Il resolver pubblico più veloce da qui è ${name} (${fastest.server}).`
          : !better
            ? 'Il DNS attuale è veloce quanto i migliori resolver pubblici: non serve cambiarlo.'
            : corp
              ? `${name} risponde ${ms(gain)} prima del DNS interno, ma in una rete con dominio i DNS non si cambiano sul PC: i nomi interni smetterebbero di funzionare. Se il DNS interno è lento va potenziato sul server.`
              : `${name} risponde ${ms(gain)} prima del DNS attuale: cambiarlo renderebbe la navigazione più reattiva.`,
      actions: better && gain !== undefined ? [fixDns] : [],
    });
  }
}

// ---------------------------------------------------------------- Router

const PORTS: Record<number, { sev: Severity; name: string; note: string; action?: string }> = {
  21: { sev: 'warn', name: 'FTP', note: 'Condivisione file con password in chiaro.', action: 'close-router-port' },
  22: { sev: 'info', name: 'SSH', note: 'Accesso amministrativo cifrato: ok se lo usi, altrimenti disattivalo.' },
  23: { sev: 'crit', name: 'Telnet', note: 'Accesso amministrativo con password in chiaro, bersaglio classico dei malware per router.', action: 'close-router-port' },
  53: { sev: 'ok', name: 'DNS', note: 'Il router risolve i nomi per la rete: normale.' },
  80: { sev: 'info', name: 'HTTP', note: 'Pannello di gestione non cifrato.' },
  139: { sev: 'warn', name: 'NetBIOS', note: 'Condivisione file Windows legacy.', action: 'close-router-port' },
  443: { sev: 'ok', name: 'HTTPS', note: 'Pannello di gestione cifrato.' },
  445: { sev: 'warn', name: 'SMB', note: 'Condivisione file (disco USB sul router?).', action: 'close-router-port' },
  5000: { sev: 'info', name: 'UPnP/HTTP', note: 'Servizio UPnP o pannello alternativo.' },
  7547: { sev: 'info', name: 'TR-069', note: 'Gestione remota da parte dell\'operatore: normale sui router forniti dall\'operatore.' },
  8080: { sev: 'info', name: 'HTTP alternativo', note: 'Pannello o servizio web secondario.' },
  8443: { sev: 'ok', name: 'HTTPS alternativo', note: 'Pannello cifrato secondario.' },
  49152: { sev: 'info', name: 'UPnP', note: 'Descrittore UPnP del router.' },
};

function analyzeRouter(scan: Scan, c: Collector) {
  const g = scan.gateway;
  if (!g) return;
  if (g.ports) {
    const open = g.ports.filter((p) => p.open);
    if (!open.length) {
      c.add({
        id: 'router.ports',
        metric: 'router.port',
        category: 'router',
        title: 'Servizi esposti dal router',
        value: `0 su ${g.ports.length}`,
        severity: 'ok',
        verdict: 'Nessuno dei servizi controllati risponde: superficie di attacco minima.',
      });
    }
    for (const p of open) {
      const info = PORTS[p.port] ?? { sev: 'info' as Severity, name: p.service, note: 'Servizio non comune: verifica a cosa serve.' };
      c.add({
        id: `router.port.${p.port}`,
        metric: 'router.port',
        category: info.sev === 'crit' || info.sev === 'warn' ? 'security' : 'router',
        title: `Porta ${p.port} · ${info.name}`,
        value: 'aperta',
        numeric: p.port,
        severity: info.sev,
        verdict: info.note,
        actions: info.action ? [info.action] : p.port === 80 && !open.some((o) => o.port === 443 || o.port === 8443) ? ['router-https'] : [],
      });
    }
  }
  if (g.upnp) {
    const u = g.upnp;
    const dev = u.devices.find((d) => d.modelName || d.friendlyName);
    c.add({
      id: 'router.upnp',
      metric: 'router.upnp',
      category: 'router',
      title: 'UPnP',
      value: u.igd ? 'attivo (IGD)' : u.found ? 'dispositivi UPnP presenti' : 'non rilevato',
      severity: u.igd ? 'warn' : u.found ? 'info' : 'ok',
      verdict: u.igd
        ? `Il router${dev?.modelName ? ` ${dev.modelName}` : ''} accetta richieste automatiche di apertura porte.${u.externalIp ? ` Indirizzo pubblico dichiarato: ${u.externalIp}.` : ''} Utile per console e P2P, rischioso se un dispositivo della rete è compromesso.`
        : u.found
          ? `Ci sono dispositivi UPnP in rete (${u.devices.length}: TV, NAS, stampanti...) ma il router non espone il port forwarding automatico.`
          : 'Nessun router UPnP risponde: le porte verso Internet si aprono solo manualmente.',
      actions: u.igd ? ['disable-upnp'] : [],
    });
  }
  if (g.web) {
    const w = g.web;
    c.add({
      id: 'router.web',
      metric: 'router.web',
      category: 'router',
      title: 'Pannello di gestione',
      value: [w.title, w.server].filter(Boolean).join(' · ') || (w.https ? 'HTTPS' : 'HTTP'),
      severity: w.https ? 'ok' : 'info',
      verdict:
        (w.https ? 'Raggiungibile in HTTPS.' : 'Raggiungibile solo in HTTP: la password di amministrazione viaggia in chiaro nella rete locale.') +
        ' Verifica periodicamente che il firmware sia aggiornato.',
      actions: w.https ? ['update-firmware'] : ['router-https', 'update-firmware'],
    });
  }
}

function analyzeFirewall(scan: Scan, c: Collector) {
  const fw = scan.firewall;
  if (!fw || !fw.profiles.length) return;
  const names = { domain: 'Dominio', private: 'Privata', public: 'Pubblica' };
  const off = fw.profiles.filter((p) => p.enabled === false);
  const activeOff = off.filter((p) => p.active);
  const unknown = fw.profiles.every((p) => p.enabled === null);
  const sev: Severity = unknown ? 'unknown' : activeOff.length ? 'crit' : off.length ? 'warn' : 'ok';
  c.add({
    id: 'sec.firewall',
    metric: 'sec.firewall',
    category: 'security',
    title: 'Firewall di Windows',
    value: fw.profiles.map((p) => `${names[p.name]}: ${p.enabled === null ? '?' : p.enabled ? 'on' : 'off'}`).join(' · '),
    severity: sev,
    verdict:
      sev === 'ok'
        ? 'Tutti i profili del firewall sono attivi.'
        : sev === 'unknown'
          ? 'Non è stato possibile leggere lo stato del firewall.'
          : activeOff.length
            ? `Il profilo in uso (${activeOff.map((p) => names[p.name]).join(', ')}) ha il firewall disattivato: il PC è esposto agli altri dispositivi della rete.`
            : `Il firewall è disattivato per: ${off.map((p) => names[p.name]).join(', ')}. Non è il profilo in uso, ma lo diventerà su un'altra rete.`,
    actions: sev === 'crit' || sev === 'warn' ? ['enable-firewall'] : [],
  });
}

// ---------------------------------------------------------------- Infrastruttura

const REACH_LABEL: Record<ReachStatus, string> = {
  open: 'porta aperta',
  closed: 'porta chiusa (rifiuto)',
  filtered: 'nessuna risposta',
  reply: 'risponde al ping',
  noreply: 'non risponde al ping',
  unresolved: 'nome non risolto',
  refused: 'non verificata: indirizzo non privato',
  error: 'errore',
};

const reachTarget = (r: ReachResult) => {
  const where = `${r.host}${r.port ? `:${r.port}` : ''}`;
  if (!r.label) return where;
  // "Gestione switch (SSH), 10.0.0.2:22" invece di due parentesi di fila.
  return /\)$/.test(r.label) ? `${r.label}, ${where}` : `${r.label} (${where})`;
};

/** Oltre questo tempo di apertura della connessione un servizio interno è lento. */
const SLOW_SERVICE_MS = 100;

function analyzeInfra(scan: Scan, c: Collector) {
  const inf = scan.infra;
  if (!inf) return;

  const inv = inf.inventory;
  if (inv) {
    const others = inv.hosts.filter((h) => !h.self);
    const pinged = others.filter((h) => h.rttMs !== undefined).length;
    const named = others.filter((h) => h.name || h.netbios).length;
    const unnamed = others.length - named;
    const random = others.filter((h) => h.randomMac).length;
    const capacity = inv.scanned + 1; // più il PC stesso
    // Sottorete esaminata per intero e quasi piena: il DHCP può esaurire gli indirizzi.
    const full = !inv.note && capacity >= 6 && inv.hosts.length >= 0.85 * capacity;
    c.add({
      id: 'infra.inventory',
      metric: 'infra.inventory',
      category: 'infra',
      title: 'Inventario della sottorete',
      value: `${others.length} ${others.length === 1 ? 'dispositivo' : 'dispositivi'}`,
      numeric: others.length,
      severity: full ? 'warn' : 'info',
      verdict:
        `Nella sottorete ${inv.subnet} ${others.length === 1 ? 'c\'è 1 dispositivo' : `ci sono ${others.length} dispositivi`} oltre a questo PC: ` +
        `${num(pinged, 'risponde', 'rispondono')} al ping, ${num(others.length - pinged, 'è stato visto', 'sono stati visti')} solo tramite ARP. ` +
        `${num(named, 'ha', 'hanno')} un nome (DNS o NetBIOS)${unnamed ? `, ${num(unnamed, 'è senza nome e va identificato', 'sono senza nome e vanno identificati')}` : ''}.` +
        (random ? ` ${num(random, 'usa', 'usano')} un MAC casuale o virtuale: telefoni e PC con indirizzo privato, macchine virtuali.` : '') +
        (full ? ` La sottorete è quasi piena (${inv.hosts.length} indirizzi occupati su ${capacity}): il DHCP rischia di esaurire gli indirizzi.` : '') +
        (inv.note ? ` ${inv.note}` : ''),
      actions: [...(unnamed ? ['identify-devices'] : []), ...(full ? ['dhcp-capacity'] : [])],
    });
  }

  const results = inf.reach?.results ?? [];
  const untestedText = (n: number) =>
    n ? ` ${n === 1 ? 'Una destinazione non è stata verificata' : `${n} destinazioni non sono state verificate`} (nome non risolto, indirizzo non privato o errore).` : '';

  const iso = results.filter((r) => r.expect === 'isolated');
  if (iso.length) {
    const breach = iso.filter((r) => r.status === 'open' || r.status === 'reply');
    const reject = iso.filter((r) => r.status === 'closed');
    const tested = iso.filter((r) => r.status !== 'unresolved' && r.status !== 'refused' && r.status !== 'error');
    const sev: Severity = breach.length ? 'crit' : reject.length ? 'warn' : tested.length ? 'ok' : 'unknown';
    let verdict = '';
    if (breach.length)
      verdict += `Raggiungibili da questa rete, mentre dovrebbero essere isolate: ${breach
        .slice(0, 4)
        .map((r) => `${reachTarget(r)}, ${REACH_LABEL[r.status]}`)
        .join('; ')}${more(breach.length, 4)}.`;
    if (reject.length)
      verdict += `${verdict ? ' ' : ''}Rispondono con un rifiuto, quindi il traffico arriva fino all'host o a un firewall che rifiuta: ${reject
        .slice(0, 4)
        .map(reachTarget)
        .join('; ')}${more(reject.length, 4)}.`;
    if (sev === 'ok')
      verdict += `${tested.length === 1 ? 'La destinazione verificata risulta isolata' : `Le ${tested.length} destinazioni verificate risultano isolate`} da questa rete, come previsto. Ripeti il test da ogni zona e dopo ogni modifica alle regole.`;
    verdict = (verdict + untestedText(iso.length - tested.length)).trim();
    c.add({
      id: 'infra.seg',
      metric: 'infra.seg',
      category: 'infra',
      title: 'Test di segmentazione',
      value: `${iso.filter((r) => r.ok).length}/${iso.length} isolate`,
      numeric: breach.length,
      severity: sev,
      verdict,
      actions: breach.length || reject.length ? ['segment-network'] : [],
    });
  }

  const svc = results.filter((r) => r.expect === 'reachable');
  if (svc.length) {
    const down = svc.filter((r) => r.status === 'filtered' || r.status === 'noreply' || r.status === 'closed' || r.status === 'unresolved');
    const up = svc.filter((r) => r.status === 'open' || r.status === 'reply');
    const slow = up.filter((r) => (r.rttMs ?? 0) > SLOW_SERVICE_MS);
    const times = up.filter((r) => r.rttMs !== undefined).map((r) => r.rttMs as number);
    const worst = times.length ? Math.max(...times) : undefined;
    const sev: Severity = down.length ? 'crit' : slow.length ? 'warn' : up.length ? 'ok' : 'unknown';
    let verdict = '';
    if (down.length)
      verdict += `Non raggiungibili da questa rete: ${down
        .slice(0, 4)
        .map((r) => `${reachTarget(r)}, ${REACH_LABEL[r.status]}`)
        .join('; ')}${more(down.length, 4)}.`;
    if (slow.length) verdict += `${verdict ? ' ' : ''}Lenti a rispondere: ${slow.map((r) => `${reachTarget(r)}, ${ms(r.rttMs as number)}`).join('; ')}.`;
    if (up.length && (down.length || slow.length)) verdict += ` Rispondono regolarmente: ${up.length - slow.length} su ${svc.length}.`;
    if (sev === 'ok')
      verdict += `${up.length === 1 ? 'Il servizio verificato risponde' : `Tutti i ${up.length} servizi verificati rispondono`}${worst !== undefined ? ` (connessione più lenta: ${ms(worst)})` : ''}.`;
    verdict = (verdict + untestedText(svc.length - down.length - up.length)).trim();
    c.add({
      id: 'infra.services',
      metric: 'infra.services',
      category: 'infra',
      title: 'Servizi critici',
      value: `${up.length}/${svc.length} raggiungibili`,
      numeric: worst,
      severity: sev,
      verdict,
      actions: down.length || slow.length ? ['check-critical-service'] : [],
    });
  }

  const asmt = inf.assessment;
  if (asmt) {
    for (const s of scoreAssessment(asmt.answers)) {
      if (s.score === null) continue;
      const sev: Severity = s.score >= 80 ? 'ok' : s.score >= 50 ? 'warn' : 'crit';
      c.add({
        id: `assess.${s.area.id}`,
        metric: 'infra.assessment',
        category: 'infra',
        title: `Autovalutazione · ${s.area.title}`,
        value: `${s.score}/100`,
        numeric: s.score,
        severity: sev,
        verdict:
          (s.gaps.length
            ? `Da completare: ${s.gaps.map((g) => g.q.short + (g.answer === 'partial' ? ' (in parte)' : '')).join('; ')}.`
            : 'Le misure di quest\'area risultano presenti.') +
          (s.open ? ` ${s.open === 1 ? 'Una domanda è' : `${s.open} domande sono`} ancora senza risposta.` : '') +
          ' Valutazione dichiarata, non misurata da Polaris.',
        actions: unique(s.gaps.map((g) => g.q.action)),
      });
    }
  }
}

// ---------------------------------------------------------------- Sintesi

function scoreCategories(findings: Finding[]): CategoryScore[] {
  return (Object.keys(CATEGORY_LABELS) as Category[]).map((cat) => {
    const fs = findings.filter((f) => f.category === cat);
    const counts: Record<Severity, number> = { ok: 0, info: 0, warn: 0, crit: 0, unknown: 0 };
    let worst: Severity = 'unknown';
    const pts: number[] = [];
    for (const f of fs) {
      counts[f.severity]++;
      worst = worse(worst, f.severity);
      const p = SEV_POINTS[f.severity];
      if (p !== null) pts.push(p);
    }
    let score: number | null = pts.length ? pts.reduce((a, b) => a + b, 0) / pts.length : null;
    // Un problema critico non può essere "diluito" da tanti valori buoni.
    if (score !== null && counts.crit) score = Math.min(score, 45);
    else if (score !== null && counts.warn) score = Math.min(score, 80);
    return { category: cat, label: CATEGORY_LABELS[cat], score: score === null ? null : Math.round(score), worst, counts };
  });
}

function buildPlan(findings: Finding[]): PlanItem[] {
  const map = new Map<string, PlanItem>();
  for (const f of findings) {
    if (f.severity !== 'warn' && f.severity !== 'crit' && f.severity !== 'info') continue;
    for (const id of f.actions) {
      const item = map.get(id) ?? { action: ACTIONS[id], severity: 'ok' as Severity, findings: [], priority: 0 };
      item.severity = worse(item.severity, f.severity);
      if (!item.findings.includes(f.id)) item.findings.push(f.id);
      map.set(id, item);
    }
  }
  const impact = { alto: 3, medio: 2, basso: 1 };
  const effort = { facile: 0, media: 1, avanzata: 2 };
  for (const it of map.values()) {
    it.priority =
      SEV_RANK[it.severity] * 100 + impact[it.action.impact] * 10 + Math.min(it.findings.length, 5) * 3 - effort[it.action.effort] * 4;
  }
  // Un'azione che compare solo per un problema "info" è un consiglio, non un'urgenza:
  // resta in fondo al piano.
  return [...map.values()].sort((a, b) => b.priority - a.priority);
}

function headline(score: number, findings: Finding[], cats: CategoryScore[], failed: number): string {
  const crit = findings.filter((f) => f.severity === 'crit');
  const warn = findings.filter((f) => f.severity === 'warn');
  const note = failed ? ` ${failed === 1 ? 'Una misura non è riuscita' : `${failed} misure non sono riuscite`}: quelle aree non sono valutate.` : '';
  if (!crit.length && !warn.length) return `Nessun problema rilevato nelle misure eseguite.${note}`;
  const top = crit[0] ?? warn[0];
  const parts: string[] = [];
  if (crit.length) parts.push(`${crit.length} ${crit.length === 1 ? 'problema critico' : 'problemi critici'}`);
  if (warn.length) parts.push(`${warn.length} ${warn.length === 1 ? 'avviso' : 'avvisi'}`);
  const lead = crit.length ? 'Attenzione' : score >= 70 ? 'Rete in buona salute, ma migliorabile' : 'Rete migliorabile';
  const worstCat = cats.find((c) => c.category === top.category)?.label ?? '';
  return `${lead}: ${parts.join(' e ')}. Il più urgente (${worstCat}): ${top.title.toLowerCase()}, ${top.value}.${note}`;
}

export function analyze(scan: Scan): Analysis {
  const c = new Collector();
  const primary = primaryAdapter(scan);
  const corp = corporateDomain(scan, primary);
  analyzeWifi(scan, c, primary);
  analyzeLan(scan, c, primary, corp);
  analyzeInternet(scan, c, primary, corp);
  analyzeDns(scan, c, corp);
  analyzeRouter(scan, c);
  analyzeFirewall(scan, c);
  analyzeInfra(scan, c);

  const findings = c.findings.sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity]);
  const categories = scoreCategories(findings);
  let wsum = 0;
  let total = 0;
  for (const cat of categories) {
    if (cat.score === null) continue;
    wsum += CATEGORY_WEIGHT[cat.category];
    total += CATEGORY_WEIGHT[cat.category] * cat.score;
  }
  let score = wsum ? Math.round(total / wsum) : 0;
  if (findings.some((f) => f.severity === 'crit')) score = Math.min(score, 69);
  const grade = score >= 85 ? 'ottima' : score >= 70 ? 'buona' : score >= 50 ? 'discreta' : 'critica';
  const mySsid = scan.wifi?.connected?.ssid;
  return {
    engineVersion: ENGINE_VERSION,
    score,
    grade,
    headline: headline(score, findings, categories, scan.errors.length),
    categories,
    findings,
    plan: buildPlan(findings),
    channels: scan.wifi ? adviseChannels(scan.wifi.networks, mySsid) : [],
  };
}
