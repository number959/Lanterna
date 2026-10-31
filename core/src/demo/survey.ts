import { roomKey } from '../engine/survey';
import type { Band, Scan, SurveyAlt, SurveyNeighbors, SurveyPing, SurveyRoam, SurveySample, WifiSurvey } from '../engine/types';
import { cochannel, ownRadios, siblingOf } from '../engine/wifi';

// Mappa del Wi-Fi per stanza nelle reti dimostrative: stanze già misurate
// (casa e poliambulatorio) e la simulazione di una nuova misura, senza
// agente, ricavata in modo deterministico dal nome della stanza. Valori
// plausibili ma inventati; le statistiche si calcolano come nell'agente.

function hash(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

const round1 = (v: number) => Math.round(v * 10) / 10;

/** Serie di letture al secondo attorno alla mediana, con qualche calo: deterministica. */
export function demoSeries(seed: string, median: number, jitter: number, n: number, dip = 0): number[] {
  const h = hash(seed);
  const raw = Array.from({ length: n }, (_, i) => Math.round(jitter * Math.sin(i * 1.7 + (h % 13)) * Math.abs(Math.cos(i * 0.6 + (h % 7)))));
  if (dip) {
    raw[(h >> 3) % n] -= dip;
    raw[(h >> 7) % n] -= Math.round(dip * 0.7);
  }
  const sorted = [...raw].sort((a, b) => a - b);
  const mid = n % 2 ? sorted[(n - 1) / 2] : Math.round((sorted[n / 2 - 1] + sorted[n / 2]) / 2);
  return raw.map((v) => v - mid + median);
}

/** Statistiche come nell'agente: mediana, minimo, massimo, 10° percentile (rango più vicino), escursione. */
export function seriesStats(rssi: number[]) {
  const s = [...rssi].sort((a, b) => a - b);
  const n = s.length;
  const median = n % 2 ? s[(n - 1) / 2] : (s[n / 2 - 1] + s[n / 2]) / 2;
  const p10 = s[Math.max(0, Math.ceil(0.1 * n) - 1)];
  return { medianDbm: median, minDbm: s[0], maxDbm: s[n - 1], p10Dbm: p10, spreadDb: s[n - 1] - s[0], stuck: n >= 5 && s[0] === s[n - 1] ? true : undefined };
}

function ping(target: string, seconds: number, lost: number, medianMs: number, jitterMs: number): SurveyPing {
  const sent = seconds * 5;
  return { target, sent, received: sent - lost, lossPct: round1((100 * lost) / sent), medianMs, p95Ms: round1(medianMs * 2.6 + jitterMs), jitterMs };
}

interface Spec {
  room: string;
  at: string;
  ssid: string;
  bssid: string;
  band: Band;
  channel: number;
  widthMhz: number;
  phy: string;
  median: number;
  jitter: number;
  dip?: number;
  rx: number;
  tx: number;
  gateway: SurveyPing;
  roams?: string[];
  scan?: { util?: number; stations?: number; alternatives: SurveyAlt[]; neighbors: SurveyNeighbors; stale?: number };
}

function sample(p: Spec, seconds = 15): SurveySample {
  const rssi = demoSeries(`${p.room}|${p.at}`, p.median, p.jitter, seconds, p.dip);
  const st = seriesStats(rssi);
  const path = [p.bssid].concat(p.roams ?? []);
  const roams: SurveyRoam[] = [];
  for (let i = 1; i < path.length; i++) roams.push({ atMs: i * 4000, from: path[i - 1], to: path[i], fromDbm: rssi[i * 4 - 1], toDbm: rssi[i * 4] });
  const bssids = path.filter((b, i) => path.indexOf(b) === i);
  return {
    room: p.room,
    startedAt: p.at,
    durationMs: seconds * 1000 + 180,
    seconds,
    ssid: p.ssid,
    band: p.band,
    channel: p.channel,
    widthMhz: p.widthMhz,
    phy: p.phy,
    rssi,
    ...st,
    rxMbps: p.rx,
    txMbps: p.tx,
    bssids,
    roams,
    gateway: p.gateway,
    ...(p.scan
      ? {
          scan: {
            fresh: p.scan.neighbors.visible + p.scan.alternatives.length + 1,
            stale: p.scan.stale ?? 0,
            connectedDbm: Math.round(st.medianDbm),
            ...(p.scan.util !== undefined ? { utilizationPct: p.scan.util, stations: p.scan.stations } : {}),
            alternatives: p.scan.alternatives,
            neighbors: p.scan.neighbors,
          },
        }
      : {}),
  };
}

const strip = <T extends object>(x: T): T => JSON.parse(JSON.stringify(x));

// ---------------------------------------------------------------- Casa

const HOME_24 = 'a4:2b:b0:11:22:33';
const HOME_5 = 'a4:2b:b0:11:22:34';
const HOME_GW = '192.168.1.1';
const home = (p: Omit<Spec, 'ssid'>) => sample({ ssid: 'Casa-Rossi', ...p });
const on24 = { band: '2.4' as Band, channel: 5, widthMhz: 40, phy: '802.11n', bssid: HOME_24 };
const on5 = { band: '5' as Band, channel: 36, widthMhz: 80, phy: '802.11ac', bssid: HOME_5 };

/** Appartamento: soggiorno con il router, studio a due stanze, camera e bagno in fondo al corridoio. */
export const homeSurvey: WifiSurvey = strip({
  rooms: [
    {
      name: 'Soggiorno',
      samples: [
        home({ room: 'Soggiorno', at: '2026-10-12T20:31:10Z', ...on5, median: -52, jitter: 2, rx: 780, tx: 702, gateway: ping(HOME_GW, 15, 0, 2.4, 0.9),
          scan: { util: 14, stations: 2, alternatives: [{ bssid: HOME_24, band: '2.4', channel: 5, rssiDbm: -45 }], neighbors: { visible: 11, cochannel: 1, strong: 0, strongestDbm: -79, channels: [44] } } }),
      ],
    },
    {
      name: 'Studio',
      samples: [
        home({ room: 'Studio', at: '2026-10-12T20:33:40Z', ...on5, median: -64, jitter: 2, rx: 433, tx: 390, gateway: ping(HOME_GW, 15, 0, 3.1, 1.4),
          scan: { util: 16, stations: 2, alternatives: [{ bssid: HOME_24, band: '2.4', channel: 5, rssiDbm: -58 }], neighbors: { visible: 12, cochannel: 1, strong: 0, strongestDbm: -80, channels: [44] } } }),
        home({ room: 'Studio', at: '2026-10-12T20:35:05Z', ...on5, median: -69, jitter: 2, dip: 3, rx: 292, tx: 263, gateway: ping(HOME_GW, 15, 0, 3.6, 1.9),
          scan: { util: 15, stations: 2, alternatives: [{ bssid: HOME_24, band: '2.4', channel: 5, rssiDbm: -61 }], neighbors: { visible: 12, cochannel: 1, strong: 0, strongestDbm: -81, channels: [44] } } }),
      ],
    },
    {
      name: 'Camera',
      samples: [
        home({ room: 'Camera', at: '2026-10-12T20:38:20Z', ...on24, median: -71, jitter: 2, dip: 2, rx: 144, tx: 117, gateway: ping(HOME_GW, 15, 1, 5.2, 8.4),
          scan: { util: 62, stations: 9, alternatives: [{ bssid: HOME_5, band: '5', channel: 36, rssiDbm: -66 }], neighbors: { visible: 10, cochannel: 6, strong: 2, strongestDbm: -62, channels: [6, 7, 9, 11] } } }),
      ],
    },
    {
      name: 'Bagno',
      samples: [
        home({ room: 'Bagno', at: '2026-10-12T20:40:45Z', ...on24, median: -79, jitter: 7, dip: 6, rx: 58, tx: 39, gateway: ping(HOME_GW, 15, 4, 6.1, 14.2),
          scan: { util: 64, stations: 9, alternatives: [{ bssid: HOME_5, band: '5', channel: 36, rssiDbm: -84 }], neighbors: { visible: 8, cochannel: 5, strong: 1, strongestDbm: -71, channels: [6, 7, 11] }, stale: 2 } }),
      ],
    },
  ],
});

// ---------------------------------------------------------------- Poliambulatorio

// Stesso schema di BSSID della demo della clinica: penultimo ottetto = AP, ultimo = radio e rete.
const AP1 = '44:48:c1:a0:10:d0';
const AP2 = '44:48:c1:a0:20:d0';
const AP3 = '44:48:c1:a0:30:d0';
const AP4 = '44:48:c1:a0:40:d0';
const AP4_24 = '44:48:c1:a0:40:c0';
const CL_GW = '10.20.30.1';
const clinic = (p: Omit<Spec, 'ssid' | 'phy' | 'widthMhz'> & { widthMhz?: number }) => sample({ ssid: 'Clinica-Staff', phy: '802.11ax', widthMhz: 40, ...p });

/** Poliambulatorio: accettazione vicino all'AP 1, ambulatori a nord, corridoio verso la radiologia. */
export const clinicSurvey: WifiSurvey = strip({
  rooms: [
    {
      name: 'Accettazione',
      samples: [
        clinic({ room: 'Accettazione', at: '2026-10-14T09:31:00Z', bssid: AP1, band: '5', channel: 52, median: -56, jitter: 2, rx: 573, tx: 516, gateway: ping(CL_GW, 15, 0, 1.8, 0.7),
          scan: { util: 22, stations: 12, alternatives: [{ bssid: AP3, band: '5', channel: 36, rssiDbm: -74 }], neighbors: { visible: 6, cochannel: 0, strong: 0 } } }),
      ],
    },
    {
      name: 'Ambulatorio 1',
      samples: [
        clinic({ room: 'Ambulatorio 1', at: '2026-10-14T09:33:30Z', bssid: AP3, band: '5', channel: 36, median: -62, jitter: 2, rx: 344, tx: 309, gateway: ping(CL_GW, 15, 0, 2.6, 2.2),
          scan: { util: 47, stations: 18, alternatives: [{ bssid: AP2, band: '5', channel: 36, rssiDbm: -73 }], neighbors: { visible: 5, cochannel: 1, strong: 0, strongestDbm: -83, channels: [44] } } }),
      ],
    },
    {
      name: 'Ambulatorio 2',
      samples: [
        clinic({ room: 'Ambulatorio 2', at: '2026-10-14T09:36:10Z', bssid: AP4, band: '5', channel: 100, median: -78, jitter: 3, dip: 3, rx: 86, tx: 51, gateway: ping(CL_GW, 15, 2, 4.4, 9.1),
          scan: { alternatives: [{ bssid: AP3, band: '5', channel: 36, rssiDbm: -67 }, { bssid: AP4_24, band: '2.4', channel: 6, rssiDbm: -71 }], neighbors: { visible: 4, cochannel: 0, strong: 0 } } }),
      ],
    },
    {
      name: "Sala d'attesa",
      samples: [
        clinic({ room: "Sala d'attesa", at: '2026-10-14T09:39:00Z', bssid: AP2, band: '5', channel: 36, median: -70, jitter: 3, rx: 172, tx: 130, roams: [AP3, AP2], gateway: ping(CL_GW, 15, 0, 3.9, 4.6),
          scan: { util: 58, stations: 31, alternatives: [{ bssid: AP3, band: '5', channel: 36, rssiDbm: -69 }], neighbors: { visible: 7, cochannel: 2, strong: 0, strongestDbm: -77, channels: [36, 44] } } }),
      ],
    },
    {
      name: 'Corridoio radiologia',
      samples: [
        clinic({ room: 'Corridoio radiologia', at: '2026-10-14T09:42:20Z', bssid: AP4_24, band: '2.4', channel: 6, widthMhz: 20, median: -83, jitter: 3, dip: 3, rx: 26, tx: 13, gateway: ping(CL_GW, 15, 6, 7.8, 16.5),
          scan: { alternatives: [{ bssid: AP4, band: '5', channel: 100, rssiDbm: -88 }], neighbors: { visible: 3, cochannel: 1, strong: 0, strongestDbm: -79, channels: [6] } } }),
      ],
    },
  ],
});

// ---------------------------------------------------------------- Simulazione

/**
 * Misura simulata per la demo, senza agente: il valore dipende dal nome
 * della stanza (stesso nome, stesso risultato) e dalle reti della demo.
 */
export function simulatedSample(scan: Scan, room: string, seconds = 15, withScan = true, at = new Date()): SurveySample {
  const wifi = scan.wifi;
  const ssid = wifi?.connected?.ssid ?? 'Rete demo';
  const nets = wifi?.networks ?? [];
  const own = ownRadios(nets, ssid);
  const h = hash(roomKey(room));
  const radio = own.length ? own[h % own.length] : undefined;
  const median = -48 - ((h >>> 3) % 36);
  const jitter = 1 + ((h >>> 9) % 4);
  const rssi = demoSeries(`${roomKey(room)}|${seconds}`, median, jitter, seconds, median < -74 ? 4 : 0);
  const st = seriesStats(rssi);
  const bssid = radio?.bssid ?? '02:00:00:00:00:01';
  const others = own.filter((b) => b.bssid !== bssid && b.band === radio?.band);
  const roam = others.length > 0 && h % 5 === 0 ? others[0].bssid : undefined;
  const lost = median < -78 ? 2 + ((h >>> 5) % 5) : median < -70 ? (h >>> 5) % 2 : 0;
  const shift = median - (radio?.rssiDbm ?? median);
  const gw = scan.gateway?.ip;
  const privateGw = !!gw && /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)/.test(gw);
  const out: SurveySample = {
    room,
    startedAt: at.toISOString().replace(/\.\d{3}Z$/, 'Z'),
    durationMs: seconds * 1000 + 150,
    seconds,
    ssid,
    ...(radio ? { band: radio.band, channel: radio.channel, widthMhz: radio.widthMhz } : {}),
    ...(radio?.phy ? { phy: radio.phy } : {}),
    rssi,
    ...st,
    rxMbps: Math.max(6, Math.round(866 * Math.max(0.05, Math.min(1, (median + 85) / 35)))),
    txMbps: Math.max(6, Math.round(780 * Math.max(0.04, Math.min(1, (median + 86) / 36)))),
    bssids: roam ? [bssid, roam] : [bssid],
    roams: roam ? [{ atMs: 7000, from: bssid, to: roam, fromDbm: rssi[6], toDbm: rssi[7] }] : [],
    gateway: privateGw
      ? ping(gw, seconds, lost, round1(2 + ((h >>> 13) % 40) / 10), round1(0.8 + ((h >>> 15) % (median < -72 ? 140 : 40)) / 10))
      : { sent: 0, received: 0, lossPct: 0, skipped: 'il router ha un indirizzo pubblico: per prudenza non si misura' },
  };
  if (!st.stuck) delete out.stuck;
  if (withScan && radio) {
    const shifted = (dbm: number) => Math.max(-92, Math.min(-35, dbm + shift + ((h >>> 11) % 7) - 3));
    const alts: { [band: string]: SurveyAlt } = {};
    for (const b of own) {
      if (b.bssid === bssid) continue;
      const v = shifted(b.rssiDbm);
      if (!alts[b.band] || v > alts[b.band].rssiDbm) alts[b.band] = { bssid: b.bssid, band: b.band, channel: b.channel, rssiDbm: v };
    }
    const sibling = siblingOf(nets, ssid);
    const neighbours = nets.filter((b) => b.ssid !== ssid && !sibling(b)).map((b) => ({ ...b, rssiDbm: shifted(b.rssiDbm) }));
    const co = cochannel({ ...radio, ssid }, neighbours);
    const strongest = co.all.reduce<number | undefined>((m, b) => (m === undefined || b.rssiDbm > m ? b.rssiDbm : m), undefined);
    out.scan = {
      fresh: neighbours.length + own.length,
      stale: 0,
      connectedDbm: Math.round(st.medianDbm),
      ...(radio.bssLoad ? { utilizationPct: radio.bssLoad.utilizationPct, stations: radio.bssLoad.stations } : {}),
      alternatives: Object.keys(alts)
        .map((k) => alts[k])
        .sort((a, b) => b.rssiDbm - a.rssiDbm),
      neighbors: {
        visible: neighbours.length,
        cochannel: co.all.length,
        strong: co.strong.length,
        ...(strongest !== undefined ? { strongestDbm: strongest } : {}),
        channels: co.all.map((b) => b.channel).filter((c, i, a) => a.indexOf(c) === i).sort((a, b) => a - b),
      },
    };
  }
  return out;
}
