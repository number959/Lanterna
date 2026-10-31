import { fmt } from './fmt';
import type { Finding, Scan, Severity, SurveyAlt, SurveyPing, SurveyRoom, SurveySample, WifiSurvey } from './types';

// Mappa del Wi-Fi per stanza: l'utente misura, con questo PC, un punto per
// stanza (o più punti: conta il peggiore) e qui ogni stanza riceve un
// giudizio. Le soglie con fonte sono di Cisco (-67 dBm per la voce), Juniper
// Mist (-72 dBm, copertura predefinita) e Microsoft Teams (perdite sotto
// l'1 % e jitter sotto 30 ms in ogni intervallo di 15 secondi); le altre
// sono scelte di Polaris e la voce "wifi.survey" della knowledge base le
// dichiara come tali. Gira anche in goja: niente Intl né funzioni recenti.

/** Ok: da -67 dBm in su (Cisco, minimo per la voce su Wi-Fi). */
export const SURVEY_OK_DBM = -67;
/** "Ottimo" da -60 dBm (scelta di Polaris; Aruba progetta le celle Wi-Fi 6 tra -55 e -65 dBm). */
export const SURVEY_GREAT_DBM = -60;
/** Info fino a -72 dBm compreso (Juniper Mist, soglia predefinita di copertura). */
export const SURVEY_INFO_DBM = -72;
/** Attenzione fino a -80 dBm compreso, Problema sotto (scelta di Polaris). */
export const SURVEY_CRIT_DBM = -80;
/** Escursione oltre la quale il segnale da fermi è instabile (scelta di Polaris). */
export const SURVEY_SPREAD_DB = 10;
/** Un altro AP della stessa rete e banda più forte di almeno tanto: client "appiccicoso" (scelta di Polaris). */
export const SURVEY_STICKY_DB = 8;
/** Perdite al router: Attenzione oltre l'1 % (Teams), Problema dal 5 % (scelta di Polaris). */
export const SURVEY_LOSS_WARN = 1;
export const SURVEY_LOSS_CRIT = 5;
/** Jitter al router: Attenzione da 10 ms (scelta di Polaris), Problema da 30 ms (Teams, per tutto il percorso). */
export const SURVEY_JITTER_WARN = 10;
export const SURVEY_JITTER_CRIT = 30;
/** Tempo di risposta del router, contato solo insieme a perdite: 20 e 50 ms (scelte di Polaris). */
export const SURVEY_RTT_WARN = 20;
export const SURVEY_RTT_CRIT = 50;
/** Occupazione del canale dichiarata dall'AP (BSS Load) oltre la quale è un avviso (scelta di Polaris). */
export const SURVEY_UTIL_WARN = 50;
/** Vicini "forti" sullo stesso canale: oltre -75 dBm, come nel resto del motore. */
export const SURVEY_STRONG_DBM = -75;
/** Nome della stanza: al massimo 40 caratteri, come nell'agente. */
export const SURVEY_MAX_ROOM = 40;
/** Durata della misura: 15 secondi (da 10 a 20). */
export const SURVEY_SECONDS = 15;

const RANK: Record<Severity, number> = { unknown: 0, ok: 1, info: 2, warn: 3, crit: 4 };
const worse = (a: Severity, b: Severity): Severity => (RANK[b] > RANK[a] ? b : a);

/** Livello del segnale (mediana): ok, info, warn, crit. */
export function rssiSeverity(dbm: number): Severity {
  if (dbm >= SURVEY_OK_DBM) return 'ok';
  if (dbm >= SURVEY_INFO_DBM) return 'info';
  if (dbm >= SURVEY_CRIT_DBM) return 'warn';
  return 'crit';
}

/** Livello dei cali (10° percentile): un livello sotto quello della mediana. */
export function dipSeverity(dbm: number): Severity {
  if (dbm >= SURVEY_INFO_DBM) return 'ok';
  if (dbm >= SURVEY_CRIT_DBM) return 'info';
  return 'warn';
}

/** Il segnale a parole: ottimo, buono, sufficiente, debole, molto debole. */
export function rssiWord(dbm: number): string {
  if (dbm >= SURVEY_GREAT_DBM) return 'ottimo';
  if (dbm >= SURVEY_OK_DBM) return 'buono';
  if (dbm >= SURVEY_INFO_DBM) return 'sufficiente';
  if (dbm >= SURVEY_CRIT_DBM) return 'debole';
  return 'molto debole';
}

/** Che cosa permette: per la scheda e il documento. */
export function rssiMeaning(dbm: number): string {
  if (dbm >= SURVEY_OK_DBM) return 'adatto anche a chiamate e video';
  if (dbm >= SURVEY_INFO_DBM) return 'va bene per navigazione e posta, chiamate e video al limite';
  if (dbm >= SURVEY_CRIT_DBM) return 'navigazione lenta, chiamate che scattano';
  return 'disconnessioni e lentezza marcata';
}

/** dBm come li scrive l'agente: interi, o con un decimale ("-63,5"). */
export const dbmText = (v: number) => (Math.round(v) === v ? String(v) : fmt(v, 1));
/** "2,4 GHz" */
export const bandText = (b?: string) => (b ? `${b.replace('.', ',')} GHz` : '');

/** Alias dei BSSID della propria rete: "AP A", "AP B"... nell'ordine in cui compaiono. */
export type SurveyAliases = (bssid: string) => string;

const MAC = /^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$/i;

/**
 * Gli alias si danno solo ai BSSID: un valore che non lo è (per esempio
 * "AP A" in un rapporto già esportato) resta com'è, così una seconda
 * esportazione non cambia nulla.
 */
export function surveyAliases(survey?: WifiSurvey): SurveyAliases {
  const map: { [bssid: string]: string } = {};
  let n = 0;
  const add = (b?: string) => {
    if (!b || !MAC.test(b)) return;
    const k = b.toLowerCase();
    if (map[k]) return;
    map[k] = n < 26 ? `AP ${String.fromCharCode(65 + n)}` : `AP ${n + 1}`;
    n++;
  };
  for (const r of survey?.rooms ?? [])
    for (const s of r.samples) {
      for (const b of s.bssids) add(b);
      for (const x of s.roams) {
        add(x.from);
        add(x.to);
      }
      for (const a of s.scan?.alternatives ?? []) add(a.bssid);
    }
  return (b: string) => (MAC.test(b) ? map[b.toLowerCase()] || 'AP' : b);
}

/**
 * Nessuna risposta dal router su tutta la serie. Molti router e firewall
 * ignorano i ping, e una VPN può bloccare la rete locale: da sola non è una
 * perdita. I dati di un agente precedente non hanno noReply: vale la stessa
 * regola se la serie non ha errori.
 */
export function routerSilent(g?: SurveyPing): boolean {
  return !!g && !g.skipped && g.sent > 0 && g.received === 0 && (g.noReply === true || !g.error);
}

/** I router che hanno risposto ai ping in almeno una misura della mappa. */
export function pingAnswerers(survey?: WifiSurvey): string[] {
  const out: string[] = [];
  for (const r of survey?.rooms ?? [])
    for (const s of r.samples) {
      const g = s.gateway;
      if (g && g.target && g.received > 0 && out.indexOf(g.target) < 0) out.push(g.target);
    }
  return out;
}

/**
 * La serie di ping misura perdite e tempi: non saltata, senza errori e, se
 * il router non ha mai risposto, solo quando lo stesso router risponde in
 * un'altra misura (allora in quel punto i dati non passano davvero).
 */
export function pingMeasured(g: SurveyPing | undefined, answering: string[] = []): boolean {
  if (!g || g.skipped || g.sent <= 0) return false;
  if (routerSilent(g)) return !!g.target && answering.indexOf(g.target) >= 0;
  return !g.error;
}

export interface SurveyIssue {
  id: string;
  severity: Severity;
  /** Etichetta breve per elenchi. */
  short: string;
  /** Frase per il giudizio. */
  text: string;
  actions: string[];
}

const channelAction = (band?: string) => (band === '2.4' ? 'change-channel-24' : 'change-channel-5');

/** Il miglior altro access point della stessa rete nella banda indicata (o nelle bande indicate). */
function bestAlt(s: SurveySample, bands: string[]): SurveyAlt | undefined {
  let best: SurveyAlt | undefined;
  for (const a of s.scan?.alternatives ?? []) if (bands.indexOf(a.band) >= 0 && (!best || a.rssiDbm > best.rssiDbm)) best = a;
  return best;
}

/**
 * Che cosa c'è da sapere su un punto misurato, dal più grave. `alias`
 * sostituisce i BSSID nei testi (che finiscono nei rapporti); `answering`
 * sono i router che hanno risposto ai ping in altre misure (pingAnswerers).
 */
export function sampleIssues(s: SurveySample, alias: SurveyAliases = () => 'AP', answering: string[] = []): SurveyIssue[] {
  const out: SurveyIssue[] = [];
  const med = s.medianDbm;
  const m = dbmText(med);
  const band = s.band;
  const on24 = band === '2.4';
  const walls = band === '5' || band === '6' ? ' A 5 e 6 GHz muri e solai attenuano più che a 2,4 GHz.' : '';

  const sig = rssiSeverity(med);
  if (sig === 'info')
    out.push({
      id: 'signal',
      severity: 'info',
      short: 'segnale sufficiente',
      text: `Segnale sufficiente (mediana ${m} dBm): ${rssiMeaning(med)}.`,
      actions: ['survey-place-ap'],
    });
  else if (sig === 'warn' || sig === 'crit')
    out.push({
      id: 'signal',
      severity: sig,
      short: `segnale ${rssiWord(med)}`,
      text: `Segnale ${rssiWord(med)} (mediana ${m} dBm): ${rssiMeaning(med)}.${walls}`,
      actions: sig === 'crit' ? ['survey-place-ap', 'add-mesh', 'wired-backhaul'] : ['survey-place-ap', 'add-mesh'],
    });

  // I cali contano un livello meno della mediana, e solo se peggiorano il giudizio.
  const dip = s.stuck ? 'ok' : dipSeverity(s.p10Dbm);
  if (RANK[dip] > RANK[sig])
    out.push({
      id: 'dips',
      severity: dip,
      short: `cali fino a ${s.p10Dbm} dBm`,
      text: `In alcuni secondi il segnale scende a ${s.p10Dbm} dBm (10° percentile; minimo ${s.minDbm} dBm): la connessione rallenta proprio in quei momenti.`,
      actions: ['survey-place-ap'],
    });

  if (s.stuck)
    out.push({
      id: 'stuck',
      severity: 'info',
      short: 'valori fermi',
      text: `Windows ha restituito sempre lo stesso valore (${s.minDbm} dBm): la scheda forse non aggiorna il segnale ogni secondo, quindi cali e instabilità non si possono valutare. Ripeti la misura; se succede ancora, confronta con un altro PC.`,
      actions: [],
    });
  else if (s.spreadDb > SURVEY_SPREAD_DB)
    out.push({
      id: 'unstable',
      severity: 'warn',
      short: 'segnale instabile',
      text: `Da fermo il segnale è variato di ${s.spreadDb} dB (da ${s.minDbm} a ${s.maxDbm} dBm): persone e porte che si muovono, un access point che cambia potenza o un'interferenza${on24 ? ' (forno a microonde, baby monitor, Bluetooth)' : ''}.`,
      actions: on24 ? ['avoid-24-interference', 'use-5ghz'] : ['survey-place-ap'],
    });

  if (s.roams.length) {
    const path = [s.roams[0].from].concat(s.roams.map((r) => r.to)).map(alias).join(' → ');
    out.push({
      id: 'roam',
      severity: 'warn',
      short: s.roams.length === 1 ? 'cambio di access point da fermo' : `${s.roams.length} cambi di access point da fermo`,
      text: `Durante la misura, da fermo, il PC è passato da un access point all'altro (${path}): qui due access point si ricevono in modo simile, oppure il PC cambia troppo facilmente. Ogni passaggio può interrompere per un attimo chiamate e applicazioni.`,
      actions: ['fix-roaming', 'plan-ap-channels'],
    });
  }

  // Client "appiccicoso": un altro AP della stessa rete, nella stessa banda, molto più forte.
  const ref = s.scan?.connectedDbm ?? med;
  const same = band ? bestAlt(s, [band]) : undefined;
  if (same && same.rssiDbm - ref >= SURVEY_STICKY_DB)
    out.push({
      id: 'sticky',
      severity: 'warn',
      short: 'access point più forte disponibile',
      text: `Un altro access point della stessa rete (${alias(same.bssid)}, ${bandText(same.band)} canale ${same.channel}) si riceve a ${same.rssiDbm} dBm, ${Math.round(same.rssiDbm - ref)} dB meglio di quello collegato: il PC resta agganciato all'access point più debole.`,
      actions: ['fix-roaming'],
    });

  // Band steering: sui 2,4 GHz mentre la stessa rete arriva bene a 5 o 6 GHz.
  const fast = on24 ? bestAlt(s, ['5', '6']) : undefined;
  if (fast && fast.rssiDbm >= SURVEY_OK_DBM)
    out.push({
      id: 'band',
      severity: 'info',
      short: 'banda veloce disponibile',
      text: `Il PC usa i 2,4 GHz, ma qui la stessa rete si riceve anche a ${bandText(fast.band)} a ${fast.rssiDbm} dBm: sulla banda più veloce la connessione andrebbe meglio.`,
      actions: ['band-steering', 'use-5ghz'],
    });

  const g = s.gateway;
  if (g && routerSilent(g) && pingMeasured(g, answering))
    out.push({
      id: 'loss',
      severity: 'crit',
      short: 'nessuna risposta dal router',
      text: `Il router non ha risposto a nessuno dei ${g.sent} ping, mentre in altre misure risponde: qui i dati non passano, anche se il PC risulta collegato. Se nel frattempo si è attivata una VPN o un firewall che blocca la rete locale, ripeti la misura senza.`,
      actions: on24 ? ['survey-place-ap', 'avoid-24-interference'] : ['survey-place-ap'],
    });
  else if (g && pingMeasured(g, answering)) {
    const lost = g.sent - g.received;
    if (g.lossPct > SURVEY_LOSS_WARN) {
      const sev: Severity = g.lossPct >= SURVEY_LOSS_CRIT ? 'crit' : 'warn';
      out.push({
        id: 'loss',
        severity: sev,
        short: `perdite al router ${fmt(g.lossPct, g.lossPct < 10 ? 1 : 0)} %`,
        text: `Persi ${lost} ping su ${g.sent} verso il router (${fmt(g.lossPct, 1)} %): ${sev === 'crit' ? 'chiamate e video si interrompono' : 'oltre l\'1 % chiamate e video peggiorano'}. Le perdite rivelano anche un segnale debole nella direzione dal PC all'access point, che la misura in dBm non vede.`,
        actions: on24 ? ['survey-place-ap', 'avoid-24-interference'] : ['survey-place-ap'],
      });
    }
    if (g.jitterMs !== undefined && g.jitterMs >= SURVEY_JITTER_WARN) {
      const sev: Severity = g.jitterMs >= SURVEY_JITTER_CRIT ? 'crit' : 'warn';
      out.push({
        id: 'jitter',
        severity: sev,
        short: `jitter ${fmt(g.jitterMs, 1)} ms`,
        text: `Il tempo di risposta del router varia in media di ${fmt(g.jitterMs, 1)} ms da un ping all'altro: ${sev === 'crit' ? 'basta questo tratto a superare i 30 ms che Microsoft Teams indica per tutto il percorso' : 'le chiamate possono scattare'}. Di solito è il canale affollato o il segnale debole.`,
        actions: on24 ? ['avoid-24-interference', 'reduce-load'] : ['reduce-load', channelAction(band)],
      });
    }
    // Il router risponde ai ping quando può: il tempo conta solo insieme a perdite.
    if (lost > 0 && g.medianMs !== undefined && g.medianMs >= SURVEY_RTT_WARN) {
      const sev: Severity = g.medianMs >= SURVEY_RTT_CRIT ? 'crit' : 'warn';
      out.push({
        id: 'rtt',
        severity: sev,
        short: `router lento (${fmt(g.medianMs, 0)} ms)`,
        text: `Il router risponde in ${fmt(g.medianMs, 0)} ms di mediana e alcuni ping si perdono: nella rete di casa o dell'ufficio il tratto fino al router richiede di solito pochi millisecondi.`,
        actions: ['survey-place-ap', 'reduce-load'],
      });
    }
  }

  const u = s.scan?.utilizationPct;
  if (u !== undefined && u > SURVEY_UTIL_WARN)
    out.push({
      id: 'busy',
      severity: 'warn',
      short: `canale occupato ${u} %`,
      text: `L'access point dichiara il canale occupato il ${u} % del tempo${s.scan?.stations !== undefined ? `, con ${s.scan.stations} dispositivi collegati` : ''}: restano poche occasioni per trasmettere.`,
      actions: [channelAction(band), 'reduce-load'].concat(on24 ? ['use-5ghz'] : []),
    });

  const nb = s.scan?.neighbors;
  if (nb && nb.strong > 0)
    out.push({
      id: 'cochannel',
      severity: 'info',
      short: nb.strong === 1 ? '1 rete vicina forte sul canale' : `${nb.strong} reti vicine forti sul canale`,
      text: `${nb.strong === 1 ? 'Una rete dei vicini forte trasmette' : `${nb.strong} reti dei vicini forti trasmettono`} sullo stesso spettro${nb.strongestDbm !== undefined ? ` (la più forte a ${nb.strongestDbm} dBm)` : ''}: il tempo di trasmissione si divide con loro.`,
      actions: on24 ? ['change-channel-24', 'use-5ghz'] : ['change-channel-5'],
    });

  return out.sort((a, b) => RANK[b.severity] - RANK[a.severity]);
}

/** Gravità di un punto: la peggiore tra quelle trovate, "ok" se non c'è nulla. */
export function sampleSeverity(s: SurveySample, answering: string[] = []): Severity {
  return sampleIssues(s, undefined, answering).reduce<Severity>((acc, i) => worse(acc, i.severity), 'ok');
}

/** Il punto peggiore di una stanza: gravità più alta, poi segnale più basso. */
export function worstSample(room: SurveyRoom, answering: string[] = []): SurveySample | undefined {
  let best: SurveySample | undefined;
  let bestSev: Severity = 'unknown';
  for (const s of room.samples) {
    const sev = sampleSeverity(s, answering);
    if (!best || RANK[sev] > RANK[bestSev] || (sev === bestSev && s.medianDbm < best.medianDbm)) {
      best = s;
      bestSev = sev;
    }
  }
  return best;
}

const ACCENTS: { [c: string]: string } = { à: 'a', á: 'a', â: 'a', ä: 'a', ã: 'a', è: 'e', é: 'e', ê: 'e', ë: 'e', ì: 'i', í: 'i', î: 'i', ï: 'i', ò: 'o', ó: 'o', ô: 'o', ö: 'o', õ: 'o', ù: 'u', ú: 'u', û: 'u', ü: 'u', ç: 'c', ñ: 'n' };

/** Parte stabile dell'identificativo di una stanza: "Sala d'attesa" → "sala-d-attesa". */
export function roomSlug(name: string): string {
  let s = '';
  const low = name.toLowerCase();
  for (let i = 0; i < low.length; i++) {
    const c = low.charAt(i);
    s += ACCENTS[c] || c;
  }
  s = s.replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 32).replace(/-+$/, '');
  return s || 'stanza';
}

/** Chiave per riconoscere la stessa stanza: senza differenze di maiuscole e spazi. */
export const roomKey = (name: string) => name.trim().replace(/\s+/g, ' ').toLowerCase();

export interface RoomResult {
  room: SurveyRoom;
  /** Identificativo del giudizio: "wifi.room.<nome>". */
  id: string;
  worst: SurveySample;
  severity: Severity;
  issues: SurveyIssue[];
  /** I router che rispondono ai ping in almeno una misura (per gatewayText). */
  answering: string[];
}

/** Le stanze con il loro giudizio, dalla più debole alla più forte. */
export function surveyRooms(survey?: WifiSurvey, alias?: SurveyAliases): RoomResult[] {
  const al = alias ?? surveyAliases(survey);
  const answering = pingAnswerers(survey);
  const seen: { [slug: string]: number } = {};
  const out: RoomResult[] = [];
  for (const room of survey?.rooms ?? []) {
    const worst = worstSample(room, answering);
    if (!worst) continue;
    const slug = roomSlug(room.name);
    seen[slug] = (seen[slug] || 0) + 1;
    const issues = sampleIssues(worst, al, answering);
    out.push({
      room,
      id: `wifi.room.${slug}${seen[slug] > 1 ? `-${seen[slug]}` : ''}`,
      worst,
      severity: issues.reduce<Severity>((acc, i) => worse(acc, i.severity), 'ok'),
      issues,
      answering,
    });
  }
  return out.sort((a, b) => RANK[b.severity] - RANK[a.severity] || a.worst.medianDbm - b.worst.medianDbm || (a.room.name < b.room.name ? -1 : 1));
}

/** "-63 dBm · buono" (+ "· 2 punti"). */
export function roomValue(r: RoomResult): string {
  const n = r.room.samples.length;
  return `${dbmText(r.worst.medianDbm)} dBm · ${rssiWord(r.worst.medianDbm)}${n > 1 ? ` · ${n} punti, il peggiore` : ''}`;
}

/** Banda, canale e larghezza in breve: "5 GHz · canale 36 · 80 MHz". */
export function radioText(s: SurveySample): string {
  return [bandText(s.band), s.channel ? `canale ${s.channel}` : '', s.widthMhz ? `${s.widthMhz} MHz` : ''].filter(Boolean).join(' · ');
}

/** Riga del router: "persi 0 su 75 · 3,2 ms · jitter 1,1 ms". */
export function gatewayText(s: SurveySample, answering: string[] = []): string {
  const g = s.gateway;
  if (!g) return '';
  if (g.skipped) return `non misurato: ${g.skipped}`;
  if (!pingMeasured(g, answering)) {
    if (routerSilent(g)) return `nessuna risposta su ${g.sent} ping: il router forse li ignora, perdite e tempi non misurabili`;
    if (g.error) return `non misurato: ${g.error}`;
  }
  return [
    `persi ${g.sent - g.received} su ${g.sent}`,
    g.medianMs !== undefined ? `${fmt(g.medianMs, 1)} ms` : '',
    g.jitterMs !== undefined ? `jitter ${fmt(g.jitterMs, 1)} ms` : '',
  ]
    .filter(Boolean)
    .join(' · ');
}

/** Un giudizio per stanza (id "wifi.room.<nome>"), con il punto peggiore. */
export function analyzeSurvey(scan: Scan, add: (f: Omit<Finding, 'actions'> & { actions?: string[] }) => void) {
  const survey = scan.wifi?.survey;
  if (!survey?.rooms?.length) return;
  for (const r of surveyRooms(survey)) {
    const s = r.worst;
    // Il livello del segnale apre sempre il giudizio, anche quando il problema è altrove.
    const lead = r.issues.some((i) => i.id === 'signal')
      ? []
      : [`Segnale ${rssiWord(s.medianDbm)} (mediana ${dbmText(s.medianDbm)} dBm, cali fino a ${s.p10Dbm} dBm): ${rssiMeaning(s.medianDbm)}.`];
    const estimated = s.estimated ? ['I dBm sono stimati dalla qualità del segnale riportata da Windows: la scheda non li fornisce.'] : [];
    const head = lead.concat(estimated, r.issues.map((i) => i.text)).join(' ');
    const g = s.gateway;
    const facts = [radioText(s), pingMeasured(g, r.answering) || routerSilent(g) ? `router: ${gatewayText(s, r.answering)}` : ''].filter(Boolean).join('; ');
    const where = r.room.samples.length > 1 ? ` Il giudizio è quello del punto peggiore su ${r.room.samples.length}.` : '';
    const actions: string[] = [];
    for (const i of r.issues) for (const a of i.actions) if (actions.indexOf(a) < 0) actions.push(a);
    add({
      id: r.id,
      metric: 'wifi.survey',
      category: 'wifi',
      title: `Stanza · ${r.room.name}`,
      value: roomValue(r),
      numeric: s.medianDbm,
      severity: r.severity,
      verdict: `${head}${facts ? ` ${facts.charAt(0).toUpperCase()}${facts.slice(1)}.` : ''}${where}`,
      actions,
    });
  }
}

/**
 * Copia del rapporto da esportare: nella mappa del Wi-Fi i BSSID della
 * propria rete diventano "AP A", "AP B"... (i nomi delle stanze restano:
 * sono nomi di luogo scelti dall'utente). Le reti dei vicini sono già solo
 * numeri.
 */
export function surveyForExport(scan: Scan): Scan {
  const survey = scan.wifi?.survey;
  if (!scan.wifi || !survey) return scan;
  const al = surveyAliases(survey);
  const rooms = survey.rooms.map((r) => ({
    name: r.name,
    samples: r.samples.map((s) => {
      const copy: SurveySample = JSON.parse(JSON.stringify(s));
      copy.bssids = s.bssids.map(al);
      copy.roams = s.roams.map((x) => ({ ...x, from: al(x.from), to: al(x.to) }));
      if (copy.scan?.alternatives) copy.scan.alternatives = copy.scan.alternatives.map((a) => ({ ...a, bssid: al(a.bssid) }));
      return copy;
    }),
  }));
  return { ...scan, wifi: { ...scan.wifi, survey: { rooms } } };
}
