import type { Band, Bss, ChannelAdvice, ChannelScore, WifiSecurity } from './types';

// Matematica dei canali Wi-Fi: conversioni frequenza/canale, spettro
// occupato da ogni rete e stima dell'interferenza per scegliere il canale.

export function bandOf(freqMhz: number): Band {
  if (freqMhz < 3000) return '2.4';
  if (freqMhz >= 5925) return '6';
  return '5';
}

export function freqToChannel(freqMhz: number): number {
  if (freqMhz === 2484) return 14;
  if (freqMhz >= 2412 && freqMhz < 2484) return (freqMhz - 2407) / 5;
  if (freqMhz === 5935) return 2;
  if (freqMhz >= 5955) return (freqMhz - 5950) / 5;
  if (freqMhz >= 5000) return (freqMhz - 5000) / 5;
  return 0;
}

export function channelToFreq(channel: number, band: Band): number {
  if (band === '2.4') return channel === 14 ? 2484 : 2407 + channel * 5;
  if (band === '6') return channel === 2 ? 5935 : 5950 + channel * 5;
  return 5000 + channel * 5;
}

/** Intervallo di spettro [lo, hi] in MHz occupato da una rete. */
export function spectrum(b: Pick<Bss, 'band' | 'channel' | 'widthMhz' | 'centerChannel'>): [number, number] {
  const width = b.widthMhz || 20;
  const center = channelToFreq(b.centerChannel ?? b.channel, b.band);
  return [center - width / 2, center + width / 2];
}

function overlapMhz(a: [number, number], b: [number, number]): number {
  return Math.max(0, Math.min(a[1], b[1]) - Math.max(a[0], b[0]));
}

/** Peso di una rete interferente in base alla potenza: 0 a -90 dBm, 1 a -50 dBm o più. */
export function rssiWeight(rssi: number): number {
  return Math.min(1, Math.max(0, (rssi + 90) / 40));
}

/** Soglia sopra la quale una rete vicina è considerata "forte". */
export const STRONG_NEIGHBOUR_DBM = -75;

/**
 * Reti che condividono lo spettro con `mine` (escluse le radio della stessa
 * rete, cioè con lo stesso SSID: un mesh coordina già i suoi nodi).
 */
export function cochannel(mine: Bss, all: Bss[]): { strong: Bss[]; all: Bss[] } {
  const range = spectrum(mine);
  const others = all.filter(
    (b) => b.bssid !== mine.bssid && b.band === mine.band && b.ssid !== mine.ssid && overlapMhz(range, spectrum(b)) > 0,
  );
  return { all: others, strong: others.filter((b) => b.rssiDbm > STRONG_NEIGHBOUR_DBM) };
}

// ---- Reti con più access point

/** Radio che annunciano la stessa rete (stesso SSID, non nascosto). */
export function ownRadios(networks: Bss[], ssid?: string): Bss[] {
  return ssid ? networks.filter((b) => b.ssid === ssid) : [];
}

function macBytes(mac: string): number[] | null {
  const p = mac.split(/[:-]/);
  if (p.length !== 6) return null;
  const b = p.map((x) => parseInt(x, 16));
  return b.some((x) => isNaN(x)) ? null : b;
}

/**
 * Due reti trasmesse dalla stessa radio fisica (più SSID sullo stesso AP):
 * stessa banda e canale e BSSID che differiscono solo nell'ultima cifra
 * esadecimale o solo nel primo ottetto, i due schemi più usati dai produttori.
 */
export function sameRadio(a: Bss, b: Bss): boolean {
  if (a.band !== b.band || a.channel !== b.channel || a.bssid === b.bssid) return false;
  const x = macBytes(a.bssid);
  const y = macBytes(b.bssid);
  if (!x || !y || x[1] !== y[1] || x[2] !== y[2] || x[3] !== y[3] || x[4] !== y[4]) return false;
  return (x[0] === y[0] && (x[5] & 0xf0) === (y[5] & 0xf0)) || x[5] === y[5];
}

/** Altre reti (ospiti, dispositivi...) trasmesse dalle stesse radio della rete `ssid`. */
export function siblingOf(networks: Bss[], ssid?: string): (b: Bss) => boolean {
  const mine = ownRadios(networks, ssid);
  return (b) => b.ssid !== ssid && mine.some((m) => sameRadio(m, b));
}

/**
 * Stima prudente del numero di access point: un AP ha di norma una sola
 * radio per banda, quindi un router dual band (stesso SSID a 2,4 e 5 GHz)
 * conta uno. I BSSID non bastano: ogni produttore li deriva a modo suo.
 */
export function apCount(radios: Bss[]): number {
  const per: Record<Band, number> = { '2.4': 0, '5': 0, '6': 0 };
  for (const r of radios) per[r.band]++;
  return Math.max(per['2.4'], per['5'], per['6']);
}

/** Coppie di radio (della stessa rete) che occupano lo stesso spettro. */
export function overlappingPairs(radios: Bss[]): [Bss, Bss][] {
  const out: [Bss, Bss][] = [];
  for (let i = 0; i < radios.length; i++) {
    for (let j = i + 1; j < radios.length; j++) {
      const a = radios[i];
      const b = radios[j];
      if (a.band === b.band && overlapMhz(spectrum(a), spectrum(b)) > 0) out.push([a, b]);
    }
  }
  return out;
}

export type SecFamily = 'open' | 'legacy' | 'personal' | 'enterprise' | 'unknown';

/** Famiglia di protezione: aperta, obsoleta, a password condivisa o con 802.1X. */
export function secFamily(s?: WifiSecurity): SecFamily {
  if (!s || s.protocol === 'unknown') return 'unknown';
  if (s.protocol === 'open' || s.protocol === 'owe') return 'open';
  if (s.protocol === 'wep' || s.protocol === 'wpa') return 'legacy';
  return s.akm.some((a) => a.indexOf('802.1X') >= 0) ? 'enterprise' : 'personal';
}

/** Indice di carico 0-100 di un intervallo di spettro. */
function loadOf(range: [number, number], others: Bss[]): { load: number; networks: number } {
  let sum = 0;
  let networks = 0;
  const width = range[1] - range[0];
  for (const b of others) {
    const ov = overlapMhz(range, spectrum(b));
    if (ov <= 0) continue;
    networks++;
    let w = rssiWeight(b.rssiDbm) * (ov / width);
    // Se la rete dichiara l'occupazione del canale, pesa di più quando è alta.
    if (b.bssLoad) w *= 0.5 + b.bssLoad.utilizationPct / 100;
    sum += w;
  }
  // Curva di saturazione: 1 rete forte ≈ 40, 3 reti forti ≈ 80.
  return { load: Math.round(100 * (1 - Math.exp(-sum / 2))), networks };
}

const DFS_5 = (ch: number) => ch >= 52 && ch <= 144;

const BLOCKS_5: { first: number; last: number; center: number }[] = [
  { first: 36, last: 48, center: 42 },
  { first: 52, last: 64, center: 58 },
  { first: 100, last: 112, center: 106 },
  { first: 116, last: 128, center: 122 },
  { first: 132, last: 144, center: 138 },
  { first: 149, last: 161, center: 155 },
];

export function adviseChannels(networks: Bss[], mySsid?: string): ChannelAdvice[] {
  const mine = networks.filter((b) => mySsid !== undefined && b.ssid === mySsid);
  // Le altre reti delle stesse radio (ospiti, dispositivi) restano sul canale
  // della rete principale qualunque esso sia: non sono interferenza da evitare.
  const sibling = siblingOf(networks, mySsid);
  const others = networks.filter((b) => !(mySsid !== undefined && b.ssid === mySsid) && !sibling(b));
  // Con più AP della stessa rete il canale di riferimento è quello dell'AP collegato.
  const myOn = (band: Band) => mine.find((b) => b.band === band && b.connected) ?? mine.find((b) => b.band === band);
  const out: ChannelAdvice[] = [];

  // ---- 2,4 GHz: si valutano tutti i canali, si consiglia solo tra 1, 6, 11.
  const n24 = others.filter((b) => b.band === '2.4');
  const my24 = myOn('2.4');
  if (n24.length || my24) {
    const scores: ChannelScore[] = [];
    for (let ch = 1; ch <= 13; ch++) {
      const f = channelToFreq(ch, '2.4');
      scores.push({ channel: ch, label: String(ch), ...loadOf([f - 10, f + 10], n24) });
    }
    const best = [1, 6, 11]
      .map((ch) => scores[ch - 1])
      .sort((a, b) => a.load - b.load || a.channel - b.channel)[0];
    const current = my24?.channel;
    const cur = current ? scores[current - 1] : undefined;
    let note: string;
    let recommended = best.channel;
    if (!current) note = `Se attivi una rete a 2,4 GHz, il canale meno disturbato è il ${best.channel}.`;
    else if (current === best.channel || (cur && cur.load - best.load < 10 && [1, 6, 11].includes(current))) {
      note = `Il canale ${current} è già una buona scelta.`;
      recommended = current;
    } else note = `Passando dal canale ${current} al ${best.channel} l'interferenza stimata scende da ${cur?.load ?? '?'} a ${best.load} su 100.`;
    out.push({ band: '2.4', current, recommended, scores, note });
  }

  // ---- 5 GHz: si valutano i blocchi da 80 MHz.
  const n5 = others.filter((b) => b.band === '5');
  const my5 = myOn('5');
  if (n5.length || my5) {
    const scores: ChannelScore[] = BLOCKS_5.map((blk) => {
      const f = channelToFreq(blk.center, '5');
      return {
        channel: blk.first,
        label: `${blk.first}-${blk.last}`,
        dfs: DFS_5(blk.first),
        ...loadOf([f - 40, f + 40], n5),
      };
    });
    // A parità di carico (scarto < 10) si preferisce 36-48 (sempre disponibile
    // a piena potenza), poi i blocchi DFS, per ultimo 149-161 che in Italia e
    // nell'UE è ammesso solo a bassa potenza.
    const pref = (s: ChannelScore) => (s.channel >= 149 ? 2 : s.dfs ? 1 : 0);
    const best = [...scores].sort((a, b) => {
      const d = a.load - b.load;
      if (Math.abs(d) >= 10) return d;
      return pref(a) - pref(b) || d || a.channel - b.channel;
    })[0];
    const current = my5?.channel;
    const curBlock = current ? scores.find((s) => current >= s.channel && current <= s.channel + 12) : undefined;
    let note: string;
    let recommended = best.channel;
    if (!current) note = `Il blocco meno occupato è ${best.label}.`;
    else if (!curBlock || curBlock === best || curBlock.load - best.load < 15) {
      note = `Il canale ${current} è in un blocco poco affollato: va bene così.`;
      recommended = current;
    } else note = `Il blocco ${curBlock.label} ha interferenza ${curBlock.load}/100; il blocco ${best.label} solo ${best.load}/100.`;
    if (recommended === best.channel && best.dfs)
      note += ' Il blocco consigliato è DFS: il router può doverlo lasciare se rileva un radar meteo.';
    if (recommended === best.channel && best.channel >= 149)
      note += ' Attenzione: in Italia e nell\'UE i canali 149-165 sono ammessi solo a bassa potenza.';
    out.push({ band: '5', current, recommended, scores, note });
  }

  const my6 = myOn('6');
  if (my6 || others.some((b) => b.band === '6')) {
    out.push({
      band: '6',
      current: my6?.channel,
      scores: [],
      note: 'La banda 6 GHz è nuova e quasi sempre libera: il canale automatico del router è la scelta migliore.',
    });
  }
  return out;
}

const WIFI_GEN: Record<string, string> = {
  '802.11be': 'Wi-Fi 7',
  '802.11ax': 'Wi-Fi 6',
  '802.11ac': 'Wi-Fi 5',
  '802.11n': 'Wi-Fi 4',
};

export function phyLabel(phy?: string, band?: Band): string {
  if (!phy) return 'sconosciuto';
  let gen = WIFI_GEN[phy];
  if (phy === '802.11ax' && band === '6') gen = 'Wi-Fi 6E';
  return gen ? `${gen} (${phy})` : phy;
}

/** Rango dello standard: più alto = più moderno. */
export function phyRank(phy?: string): number {
  return ({ '802.11b': 1, '802.11a': 2, '802.11g': 2, '802.11n': 3, '802.11ac': 4, '802.11ax': 5, '802.11be': 6 } as Record<string, number>)[
    phy ?? ''
  ] ?? 0;
}

export function qualityToDbm(q: number): number {
  return Math.round(q / 2 - 100);
}
