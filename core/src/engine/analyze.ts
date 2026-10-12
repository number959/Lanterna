import { ACTIONS } from './kb/actions';
import type {
  Adapter,
  Analysis,
  Bss,
  Category,
  CategoryScore,
  Finding,
  PingStats,
  PlanItem,
  Scan,
  Severity,
} from './types';
import { adviseChannels, cochannel, phyLabel, phyRank, qualityToDbm, STRONG_NEIGHBOUR_DBM } from './wifi';

export const ENGINE_VERSION = '1.0.0';

const SEV_RANK: Record<Severity, number> = { unknown: 0, ok: 1, info: 2, warn: 3, crit: 4 };
const SEV_POINTS: Record<Severity, number | null> = { ok: 100, info: 95, warn: 55, crit: 10, unknown: null };

export const CATEGORY_LABELS: Record<Category, string> = {
  wifi: 'Wi-Fi',
  lan: 'Rete locale',
  internet: 'Internet',
  dns: 'DNS',
  router: 'Router',
  security: 'Sicurezza',
};

const CATEGORY_WEIGHT: Record<Category, number> = {
  wifi: 0.25,
  lan: 0.2,
  internet: 0.25,
  dns: 0.1,
  router: 0.1,
  security: 0.1,
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

function isApipa(cidr: string) {
  return cidr.startsWith('169.254.');
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
        (derived ? ` Valore stimato dalla qualità ${conn.signalQuality} % riportata da Windows.` : ''),
      actions: sev === 'ok' ? [] : sev === 'warn' ? ['move-closer', 'add-mesh'] : ['move-closer', 'add-mesh', 'use-ethernet'],
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
          ? 'Adeguato per la maggior parte delle connessioni domestiche.'
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
    } else if (width < 80) {
      sev = 'info';
      verdict = `A ${width} MHz la velocità massima è ridotta rispetto agli 80 MHz standard; ha senso solo in ambienti molto affollati.`;
    } else {
      verdict = `${width} MHz: sfrutta bene la banda ${band.replace('.', ',')} GHz.`;
    }
    c.add({ id: 'wifi.width', metric: 'wifi.width', category: 'wifi', title: 'Larghezza di canale', value: `${width} MHz`, numeric: width, severity: sev, verdict, actions });
  }

  if (me) {
    const co = cochannel(me, wifi.networks);
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
          : `${n} ${n === 1 ? 'rete forte trasmette' : 'reti forti trasmettono'} sul tuo stesso spettro: ${names}${n > 3 ? '…' : ''}. Il tempo di trasmissione viene diviso con loro.`,
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
            ? `Il router segnala il canale libero per la maggior parte del tempo, con ${me.bssLoad.stations} dispositivi collegati.`
            : `Il router segnala il canale occupato il ${pct(u)} del tempo: ${sev === 'crit' ? 'è saturo' : 'è impegnato'}. Restano poche finestre per trasmettere.`,
        actions: sev === 'ok' ? [] : [me.band === '2.4' ? 'change-channel-24' : 'change-channel-5', 'reduce-load', ...(me.band === '2.4' ? ['use-5ghz'] : [])],
      });
    }
  }

  // Sicurezza della rete collegata.
  const sec = me?.security;
  if (sec) {
    const p = sec.protocol;
    const tkip = sec.pairwise.includes('TKIP');
    let sev: Severity;
    let verdict: string;
    const label: Record<string, string> = {
      open: 'Aperta (nessuna cifratura)',
      owe: 'Enhanced Open (OWE)',
      wep: 'WEP',
      wpa: 'WPA (TKIP)',
      wpa2: 'WPA2',
      'wpa2/wpa3': 'WPA2/WPA3 mista',
      wpa3: 'WPA3',
      unknown: 'non riconosciuta',
    };
    if (p === 'open' || p === 'wep' || p === 'wpa') {
      sev = 'crit';
      verdict =
        p === 'open'
          ? 'La rete non è cifrata: chiunque nel raggio può collegarsi e leggere il traffico non protetto da HTTPS.'
          : `${label[p]} è violabile in pochi minuti con strumenti liberamente disponibili.`;
    } else if (p === 'owe') {
      sev = 'info';
      verdict = 'Il traffico è cifrato ma chiunque può collegarsi: adatto a reti ospiti, non alla rete principale.';
    } else if (tkip) {
      sev = 'warn';
      verdict = `${label[p]} con TKIP: protocollo deprecato, meno sicuro e che limita la velocità a 54 Mbit/s.`;
    } else if (p === 'unknown') {
      sev = 'unknown';
      verdict = 'Non è stato possibile determinare il tipo di protezione.';
    } else {
      sev = 'ok';
      verdict = p === 'wpa2' ? 'WPA2 con AES: sicuro, a patto di usare una password lunga e non banale.' : `${label[p]}: protezione moderna.`;
    }
    const akm = sec.akm.length ? ` · ${sec.akm.join('/')}` : '';
    const cipher = sec.pairwise.length ? ` · ${sec.pairwise.join('+')}` : '';
    c.add({
      id: 'wifi.security',
      metric: 'wifi.security',
      category: 'security',
      title: 'Protezione della rete Wi-Fi',
      value: `${label[p]}${akm}${cipher}`,
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

  networksFinding(c, wifi.networks);
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

function analyzeLan(scan: Scan, c: Collector, primary?: Adapter) {
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
        : `Indirizzo ${primary.dhcp === false ? 'statico' : 'assegnato dal router'} sulla scheda "${primary.name}"${primary.kind === 'wifi' ? ' (Wi-Fi)' : primary.kind === 'ethernet' ? ' (cavo)' : ''}.`,
    actions: apipa || v4.length === 0 ? ['check-dhcp', 'restart-network'] : [],
  });

  const withGw = scan.adapters.filter((a) => a.up && a.gateways.length > 0);
  const gwIp = scan.gateway?.ip ?? primary.gateways[0];
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
}

// ---------------------------------------------------------------- Internet

function analyzeInternet(scan: Scan, c: Collector, primary?: Adapter) {
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
      actions: !ok.length ? ['restart-network', 'contact-isp'] : sev === 'warn' ? ['change-dns', 'reduce-load'] : [],
    });
  }
  void primary;
}

// ---------------------------------------------------------------- DNS

function analyzeDns(scan: Scan, c: Collector) {
  const d = scan.dns;
  if (!d || (!d.system.length && !d.public.length)) return;
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
        verdict: `Il server DNS ${d.system.map((s) => s.server).join(', ')} non risponde: i siti non si aprono per nome anche se la connessione funziona.`,
        actions: ['change-dns', 'restart-network'],
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
          ` Server: ${best.server}${isRouter ? ' (il router, che inoltra all\'operatore)' : ''}.` +
          (d.system.length > sysOk.length ? ` ${d.system.length - sysOk.length} server configurati non rispondono.` : ''),
        actions: sev === 'ok' ? [] : ['change-dns'],
      });
    }
  }
  const pubOk = d.public.filter((s) => s.ok && s.timeMs !== undefined);
  if (pubOk.length) {
    const fastest = pubOk.reduce((a, b) => ((a.timeMs as number) <= (b.timeMs as number) ? a : b));
    const gain = sysTime !== undefined ? sysTime - (fastest.timeMs as number) : undefined;
    const better = gain === undefined || gain > 30;
    c.add({
      id: 'dns.compare',
      metric: 'dns.compare',
      category: 'dns',
      title: 'Confronto con DNS pubblici',
      value: `${fastest.label ?? fastest.server}: ${ms(fastest.timeMs as number)}`,
      numeric: fastest.timeMs,
      severity: better ? 'info' : 'ok',
      verdict:
        gain === undefined
          ? `Il resolver pubblico più veloce da qui è ${fastest.label ?? fastest.server} (${fastest.server}).`
          : better
            ? `${fastest.label ?? fastest.server} risponde ${ms(gain)} prima del DNS attuale: cambiarlo renderebbe la navigazione più reattiva.`
            : 'Il DNS attuale è veloce quanto i migliori resolver pubblici: non serve cambiarlo.',
      actions: better && gain !== undefined ? ['change-dns'] : [],
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
  analyzeWifi(scan, c, primary);
  analyzeLan(scan, c, primary);
  analyzeInternet(scan, c, primary);
  analyzeDns(scan, c);
  analyzeRouter(scan, c);
  analyzeFirewall(scan, c);

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
