import { fmt, thousands } from './fmt';
import { dateIt } from './pc';
import type { Adapter, Finding, Scan, Severity, SpeedDir, SpeedServer, SpeedTest } from './types';

// Test di velocità di Internet con Measurement Lab (M-Lab, protocollo ndt7):
// l'agente lo esegue solo su richiesta e dopo il consenso; qui si trasforma
// il risultato in giudizi. Polaris non conosce la velocità del contratto:
// la velocità è sempre un'informazione, mai un problema. Il bufferbloat ha
// soglie scelte da Polaris (P), le stesse della voce "net.bufferbloat" della
// knowledge base. Gira anche in goja: niente Intl, indexOf al posto dei
// metodi più recenti.

/** Bufferbloat, latenza aggiunta mediana (P): sotto 30 ms va bene. */
export const SPEED_BLOAT_WARN_MS = 30;
/** Bufferbloat, latenza aggiunta mediana (P): oltre 100 ms è alto. */
export const SPEED_BLOAT_CRIT_MS = 100;
/** Ritrasmissioni in download da segnalare, solo come informazione (P). */
export const SPEED_RETRANS_INFO_PCT = 5;
/** Oltre questa velocità una sola connessione può restare sotto la linea (2,5-10 Gbit/s). */
export const SPEED_FAST_MBPS = 700;
/** Sonde perse sotto carico oltre cui la coda può essere più lunga di quanto misurato. */
export const SPEED_LOST_NOTE_PCT = 10;

/** Città dei server di M-Lab in italiano (Locate le dà in inglese). */
const CITY_IT: { [en: string]: string } = {
  Milan: 'Milano',
  Rome: 'Roma',
  Turin: 'Torino',
  Naples: 'Napoli',
  Florence: 'Firenze',
  Venice: 'Venezia',
  Genoa: 'Genova',
  Zurich: 'Zurigo',
  Geneva: 'Ginevra',
  Munich: 'Monaco di Baviera',
  Frankfurt: 'Francoforte',
  Paris: 'Parigi',
  Marseille: 'Marsiglia',
  London: 'Londra',
  Lisbon: 'Lisbona',
  Brussels: 'Bruxelles',
  Athens: 'Atene',
  Prague: 'Praga',
  Warsaw: 'Varsavia',
  Copenhagen: 'Copenaghen',
  Stockholm: 'Stoccolma',
};
const COUNTRY_IT: { [code: string]: string } = {
  IT: 'Italia',
  CH: 'Svizzera',
  FR: 'Francia',
  DE: 'Germania',
  AT: 'Austria',
  ES: 'Spagna',
  GB: 'Regno Unito',
  NL: 'Paesi Bassi',
  BE: 'Belgio',
  SI: 'Slovenia',
  HR: 'Croazia',
  GR: 'Grecia',
  PT: 'Portogallo',
};

/** "Milano", oppure la città come la dà M-Lab. */
export function speedCity(s?: SpeedServer): string {
  if (!s || !s.city) return '';
  return CITY_IT[s.city] || s.city;
}

/** "Milano (mil05)", "Parigi, Francia (par05)", "server di M-Lab". */
export function speedWhere(s?: SpeedServer): string {
  const city = speedCity(s);
  const country = s && s.country && s.country !== 'IT' ? COUNTRY_IT[s.country] || s.country : '';
  const place = [city, country].filter(Boolean).join(', ');
  const site = s && s.site ? s.site : '';
  if (!place) return site ? `server di M-Lab ${site}` : 'server di M-Lab';
  return site ? `${place} (${site})` : place;
}

/** "245 Mbit/s", "48,2 Mbit/s", "3,45 Mbit/s", "1,24 Gbit/s". */
export function mbpsText(v: number): string {
  if (v >= 1000) return `${fmt(v / 1000, 2)} Gbit/s`;
  return `${fmt(v, v < 10 ? 2 : v < 100 ? 1 : 0)} Mbit/s`;
}

/** "12 ms", "8,4 ms". */
export function speedMs(v: number): string {
  return `${fmt(v, v < 10 ? 1 : 0)} ms`;
}

/** Dati trasferiti: "306 MB", "1,2 GB". */
export function speedBytes(b: number): string {
  if (b >= 1e9) return `${fmt(b / 1e9, 1)} GB`;
  return `${thousands(b / 1e6)} MB`;
}

/** Gravità del bufferbloat (latenza aggiunta mediana), con le soglie di Polaris (P). */
export function bloatSeverity(ms: number): Severity {
  if (ms < SPEED_BLOAT_WARN_MS) return 'ok';
  if (ms <= SPEED_BLOAT_CRIT_MS) return 'warn';
  return 'crit';
}

/** Come si legge la latenza sotto carico, per icona e testo. */
export const BLOAT_LABEL: { [s: string]: string } = { ok: 'contenuta', warn: 'da migliorare', crit: 'alta', unknown: 'non misurata' };

export interface SpeedBloat {
  /** Latenza aggiunta mediana nel verso peggiore. */
  worst?: number;
  worstP95?: number;
  dir?: 'download' | 'upload';
  severity: Severity;
  /** Sonde senza risposta sotto carico, su quelle inviate. */
  lost: number;
  sent: number;
}

/** Il bufferbloat del test: il verso con più latenza aggiunta decide la gravità. */
export function speedBloat(r: SpeedTest): SpeedBloat {
  const out: SpeedBloat = { severity: 'unknown', lost: 0, sent: 0 };
  const dirs: ['download' | 'upload', SpeedDir | undefined][] = [
    ['download', r.download],
    ['upload', r.upload],
  ];
  for (const [name, d] of dirs) {
    if (!d || !d.latency) continue;
    out.sent += d.latency.sent;
    out.lost += d.latency.sent - d.latency.received;
    if (d.bloatMs === undefined) continue;
    if (out.worst === undefined || d.bloatMs > out.worst) {
      out.worst = d.bloatMs;
      out.worstP95 = d.bloatP95Ms;
      out.dir = name;
    }
  }
  if (out.worst !== undefined) out.severity = bloatSeverity(out.worst);
  return out;
}

const measured = (d?: SpeedDir) => !!d && d.bytes > 0 && d.mbps > 0;

/**
 * Errore di un verso, senza il prefisso "upload non riuscito" e senza
 * indirizzi: l'agente non ne mette, ma un rapporto può arrivare da altrove.
 */
export function speedErr(e?: string): string {
  if (!e) return '';
  return e
    .replace(/^upload non riuscito: /, '')
    .replace(/\[[0-9a-fA-F:.]+\](:\d+)?/g, '[indirizzo]')
    .replace(/\b\d{1,3}(\.\d{1,3}){3}(:\d+)?\b/g, '[indirizzo]');
}

/** "download 245 · upload 48,2 Mbit/s". */
export function speedValue(r: SpeedTest): string {
  const d = r.download;
  const u = r.upload;
  if (!measured(d)) return 'non misurata';
  const num = (v: number) => mbpsText(v).replace(/ [MG]bit\/s$/, '');
  const unit = (v: number) => (v >= 1000 ? 'Gbit/s' : 'Mbit/s');
  if (!measured(u)) return `download ${mbpsText(d!.mbps)}`;
  if (unit(d!.mbps) === unit(u!.mbps)) return `download ${num(d!.mbps)} · upload ${num(u!.mbps)} ${unit(u!.mbps)}`;
  return `download ${mbpsText(d!.mbps)} · upload ${mbpsText(u!.mbps)}`;
}

/** "+26 ms in download · +128 ms in upload". */
export function bloatValue(r: SpeedTest): string {
  const parts: string[] = [];
  if (r.download && r.download.bloatMs !== undefined) parts.push(`+${speedMs(r.download.bloatMs)} in download`);
  if (r.upload && r.upload.bloatMs !== undefined) parts.push(`+${speedMs(r.upload.bloatMs)} in upload`);
  return parts.length ? parts.join(' · ') : 'non misurata';
}

/** Note di metodo che valgono per ogni risultato: Wi-Fi, proxy, linee molto veloci, simulazione. */
export function speedCaveats(r: SpeedTest, wifi: boolean): string[] {
  const out: string[] = [];
  if (r.simulated) out.push('Risultato simulato sui dati dimostrativi: nessuna misura reale.');
  if (wifi) out.push('Il PC era collegato in Wi-Fi: il risultato può dipendere dal Wi-Fi più che dalla linea; per il confronto con il contratto ripeti il test con il cavo.');
  if (r.viaProxy) out.push('Il test è passato dal proxy: misura il percorso attraverso il proxy, non solo la linea.');
  if (r.download && r.download.mbps >= SPEED_FAST_MBPS)
    out.push('Su linee molto veloci (da 2,5 a 10 Gbit/s) una sola connessione dà spesso valori più bassi dei test con più connessioni in parallelo.');
  return out;
}

/** La nota sul valore legale, mostrata accanto a ogni risultato. */
export const SPEED_LEGAL_NOTE =
  'La misura usa una sola connessione verso un server di M-Lab: serve a capire come va la linea, ma non ha valore legale. Per un reclamo all\'operatore o per recedere senza costi serve la misura certificata AGCOM con Ne.Me.Sys. (www.misurainternet.it): PC collegato al modem con il cavo, misure per 24 ore, certificato con i dati dell\'intestatario.';

/**
 * Giudizi del test: la velocità (sempre informazione), la latenza sotto
 * carico (con le soglie di Polaris) e, se alte, le ritrasmissioni.
 */
export function analyzeSpeed(scan: Scan, add: (f: Omit<Finding, 'actions'> & { actions?: string[] }) => void, primary?: Adapter) {
  const r = scan.internet && scan.internet.speed;
  if (!r) return;
  const wifi = !!primary && primary.kind === 'wifi';
  const where = speedWhere(r.server);
  const d = r.download;
  const u = r.upload;
  const sim = r.simulated ? ' (simulazione)' : '';

  if (!measured(d)) {
    add({
      id: 'net.speed',
      metric: 'net.speed',
      category: 'internet',
      title: `Velocità di Internet (M-Lab)${sim}`,
      value: 'non misurata',
      severity: 'unknown',
      verdict: `Il test di velocità non è riuscito${d && d.error ? `: ${speedErr(d.error)}` : ''}.`,
    });
    return;
  }
  const parts = [
    `Misura con il server M-Lab di ${where}${r.startedAt ? `, il ${dateIt(r.startedAt)}` : ''}, una sola connessione per verso:${mbpsText(d!.mbps)} in download${measured(u) ? ` e ${mbpsText(u!.mbps)} in upload` : ''}.`,
  ];
  if (u && !measured(u)) parts.push(`Upload non misurato${u.error ? `: ${speedErr(u.error)}` : ''}.`);
  if (d!.error) parts.push(`Download: ${speedErr(d!.error)}.`);
  if (u && measured(u) && u.error) parts.push(`Upload: ${speedErr(u.error)}.`);
  parts.push(
    'Polaris non conosce la velocità del tuo contratto: confronta il risultato con la velocità minima indicata nell\'offerta, ripetendo il test in orari diversi. Il test non ha valore legale: per un reclamo serve la misura certificata AGCOM (Ne.Me.Sys., su misurainternet.it).',
  );
  const caveats = speedCaveats(r, wifi);
  // Scheda di rete collegata a una velocità vicina al risultato: è lei il limite.
  const link = primary && primary.kind === 'ethernet' ? primary.linkMbps : undefined;
  if (link && d!.mbps >= 0.85 * link)
    caveats.push(`La scheda di rete del PC è collegata a ${thousands(link)} Mbit/s: il risultato è vicino a questo limite, quindi la linea potrebbe andare più veloce (controlla cavo, porta del router e scheda).`);
  add({
    id: 'net.speed',
    metric: 'net.speed',
    category: 'internet',
    title: `Velocità di Internet (M-Lab)${sim}`,
    value: speedValue(r),
    numeric: d!.mbps,
    severity: 'info',
    verdict: parts.concat(caveats).join(' '),
    actions: wifi ? ['speed-compare-contract', 'speed-test-cable'] : ['speed-compare-contract'],
  });

  const b = speedBloat(r);
  if (b.worst !== undefined && r.idle && r.idle.medianMs !== undefined) {
    const idle = speedMs(r.idle.medianMs);
    const worst = `+${speedMs(b.worst)}`;
    const p95 = b.worstP95 !== undefined ? ` (95° percentile +${speedMs(b.worstP95)})` : '';
    const dirText = b.dir === 'upload' ? 'in upload' : 'in download';
    let verdict =
      b.severity === 'ok'
        ? `Con la linea satura la latenza resta contenuta: al massimo ${worst} ${dirText}${p95} rispetto ai ${idle} a riposo. Chiamate e videochiamate reggono anche mentre qualcuno scarica o carica file.`
        : b.severity === 'warn'
          ? `Con la linea satura la latenza sale di ${speedMs(b.worst)} ${dirText}${p95} rispetto ai ${idle} a riposo: si nota nelle videochiamate e nei giochi quando qualcuno scarica o carica file.`
          : `Con la linea satura la latenza sale di ${speedMs(b.worst)} ${dirText}${p95} rispetto ai ${idle} a riposo: chiamate e videochiamate si spezzano quando la linea è piena (backup, aggiornamenti, caricamenti).`;
    if (b.severity !== 'ok')
      verdict += b.dir === 'upload' ? ' La coda si forma di solito nel modem o nel router, nel verso dell\'upload.' : ' La coda si forma nel router, nel modem o presso l\'operatore.';
    if (b.sent > 0 && (100 * b.lost) / b.sent > SPEED_LOST_NOTE_PCT)
      verdict += ` ${b.lost} sonde su ${b.sent} sono rimaste senza risposta durante i trasferimenti: la coda può essere anche più lunga di quanto misurato.`;
    if (wifi && b.severity !== 'ok') verdict += ' Parte della coda può essere nel Wi-Fi: confronta con un test via cavo.';
    if (r.simulated) verdict = `Simulazione. ${verdict}`;
    const actions: string[] = b.severity === 'ok' ? [] : ['enable-sqm', 'reduce-load'];
    if (wifi && b.severity !== 'ok') actions.push('speed-test-cable');
    add({
      id: 'net.bufferbloat',
      metric: 'net.bufferbloat',
      category: 'internet',
      title: `Latenza sotto carico (bufferbloat)${sim}`,
      value: bloatValue(r),
      numeric: b.worst,
      severity: b.severity,
      verdict,
      actions,
    });
  }

  if (d!.retransPct !== undefined && d!.retransPct >= SPEED_RETRANS_INFO_PCT) {
    add({
      id: 'net.speed.retrans',
      metric: 'net.speed.retrans',
      category: 'internet',
      title: `Dati ritrasmessi nel test di velocità${sim}`,
      value: `${fmt(d!.retransPct, 1)} %`,
      numeric: d!.retransPct,
      severity: 'info',
      verdict: `Durante il download il server ha dovuto ritrasmettere il ${fmt(d!.retransPct, 1)} % dei dati. È un'indicazione grossolana delle perdite sul percorso: se si ripete in più test, insieme a perdite o latenza alte nelle altre misure, la linea va fatta controllare; un singolo valore alto non basta.`,
    });
  }
}

/**
 * Righe del rapporto di testo, senza indirizzi IP né identificativi del
 * test. Le avvertenze (Wi-Fi, linee molto veloci) sono già nel giudizio.
 */
export function speedTextLines(r: SpeedTest): string[] {
  const out: string[] = [];
  out.push(`Server M-Lab: ${speedWhere(r.server)}; test del ${r.startedAt ? dateIt(r.startedAt) : '?'}${r.simulated ? ' (simulazione)' : ''}`);
  const dir = (name: string, d?: SpeedDir) => {
    if (!d) return;
    if (!measured(d)) {
      out.push(`${name}: non misurato${d.error ? ` (${speedErr(d.error)})` : ''}`);
      return;
    }
    const lat = d.latency && d.latency.medianMs !== undefined ? `; latenza ${speedMs(d.latency.medianMs)}${d.bloatMs !== undefined ? ` (+${speedMs(d.bloatMs)}, 95° percentile +${speedMs(d.bloatP95Ms || 0)})` : ''}` : '';
    out.push(`${name}: ${mbpsText(d.mbps)}, ${speedBytes(d.bytes)} in ${fmt(d.ms / 1000, 1)} s${d.capped ? ' (limite di 250 MB)' : ''}${lat}`);
    if (d.error) out.push(`${name}: ${speedErr(d.error)}`);
  };
  dir('Download', r.download);
  dir('Upload', r.upload);
  if (r.idle && r.idle.medianMs !== undefined)
    out.push(`Latenza a riposo: ${speedMs(r.idle.medianMs)} (mediana, ${r.probeMethod === 'tcp' ? 'connessioni TCP' : 'ping'} verso ${r.probe || 'un server pubblico'})`);
  const b = speedBloat(r);
  if (b.worst !== undefined) out.push(`Latenza sotto carico: ${BLOAT_LABEL[b.severity]} (soglie di Polaris: sotto ${SPEED_BLOAT_WARN_MS} ms in più va bene, oltre ${SPEED_BLOAT_CRIT_MS} ms è alta)`);
  const d = r.download;
  if (d && d.minRttMs !== undefined) out.push(`Andata e ritorno minimo verso il server: ${speedMs(d.minRttMs)}`);
  if (d && d.retransPct !== undefined) out.push(`Dati ritrasmessi in download: ${fmt(d.retransPct, 1)} %`);
  if (r.viaProxy) out.push('Il test è passato dal proxy: misura il percorso attraverso il proxy.');
  out.push(SPEED_LEGAL_NOTE);
  return out;
}

/** Righe chiave e valore per il documento stampabile. */
export function speedDocRows(r: SpeedTest): [string, string][] {
  const rows: [string, string][] = [];
  const dirRow = (name: string, d?: SpeedDir) => {
    if (!d) return;
    rows.push([name, measured(d) ? `${mbpsText(d.mbps)} (${speedBytes(d.bytes)} in ${fmt(d.ms / 1000, 1)} s${d.capped ? ', limite di 250 MB' : ''})` : `non misurato${d.error ? `: ${speedErr(d.error)}` : ''}`]);
  };
  dirRow('Download', r.download);
  dirRow('Upload', r.upload);
  if (r.idle && r.idle.medianMs !== undefined) rows.push(['Latenza a riposo', `${speedMs(r.idle.medianMs)} (mediana)`]);
  const loaded = (d?: SpeedDir) =>
    d && d.latency && d.latency.medianMs !== undefined ? `${speedMs(d.latency.medianMs)}${d.bloatMs !== undefined ? ` (+${speedMs(d.bloatMs)})` : ''}` : '';
  const ld = loaded(r.download);
  const lu = loaded(r.upload);
  if (ld || lu) rows.push(['Latenza sotto carico', [ld ? `${ld} in download` : '', lu ? `${lu} in upload` : ''].filter(Boolean).join('; ')]);
  rows.push(['Server', `M-Lab, ${speedWhere(r.server)}`]);
  return rows;
}
