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
/**
 * Sonde senza risposta durante i trasferimenti, oltre la quota persa a
 * riposo, da cui il giudizio è almeno "da migliorare" (P): picchi di coda
 * oltre l'attesa delle sonde, anche se la mediana è bassa.
 */
export const SPEED_LOST_NOTE_PCT = 10;
/** Attesa delle sonde di latenza dell'agente, se il risultato non la dice. */
export const SPEED_PROBE_TIMEOUT_MS = 1000;

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

/** Attesa delle sonde del test (ms). */
export const probeWait = (r: SpeedTest) => r.probeTimeoutMs || SPEED_PROBE_TIMEOUT_MS;

/** "1 s", "1,5 s", "800 ms". */
export function waitLabel(ms: number): string {
  return ms >= 1000 ? `${fmt(ms / 1000, ms % 1000 ? 1 : 0)} s` : `${Math.round(ms)} ms`;
}

const least = (b?: boolean) => (b ? 'almeno ' : '');

/** Latenza aggiunta in un verso; atLeast: è un minimo, perché cade su sonde senza risposta. */
export interface DirBloat {
  ms: number;
  p95?: number;
  atLeast: boolean;
  p95AtLeast: boolean;
}

/**
 * Latenza aggiunta in un verso, come la calcola l'agente (che conta le sonde
 * senza risposta come latenza di almeno l'attesa). Per dati senza mediana
 * sotto carico ma con la maggior parte delle sonde senza risposta, mentre a
 * riposo rispondevano, è l'attesa meno la mediana a riposo, come minimo: una
 * coda oltre l'attesa non deve sembrare contenuta.
 */
export function dirBloat(r: SpeedTest, d?: SpeedDir): DirBloat | undefined {
  if (!d) return undefined;
  const l = d.latency;
  if (d.bloatMs !== undefined) return { ms: d.bloatMs, p95: d.bloatP95Ms, atLeast: !!(l && l.medianAtLeast), p95AtLeast: !!(l && l.p95AtLeast) };
  const idle = r.idle;
  if (l && l.sent > 0 && l.received * 2 < l.sent && idle && idle.received > 0 && idle.medianMs !== undefined) {
    const ms = Math.max(0, Math.round((probeWait(r) - idle.medianMs) * 10) / 10);
    return { ms, p95: ms, atLeast: true, p95AtLeast: true };
  }
  return undefined;
}

export interface SpeedBloat {
  /** Latenza aggiunta mediana nel verso peggiore. */
  worst?: number;
  worstP95?: number;
  /** Il valore peggiore (o il suo 95° percentile) è un minimo: cade su sonde senza risposta entro l'attesa. */
  atLeast: boolean;
  p95AtLeast: boolean;
  dir?: 'download' | 'upload';
  severity: Severity;
  /** Sonde senza risposta sotto carico, su quelle inviate. */
  lost: number;
  sent: number;
  /** Sonde senza risposta oltre la quota persa anche a riposo. */
  excess: number;
  /** Giudizio alzato a "da migliorare" per le sonde senza risposta (P), con la mediana sotto 30 ms. */
  raised: boolean;
}

/**
 * Il bufferbloat del test: il verso con più latenza aggiunta decide la
 * gravità (P). Se oltre il 10 % delle sonde resta senza risposta durante i
 * trasferimenti, al netto della quota persa a riposo, il giudizio è almeno
 * "da migliorare": ci sono picchi di coda oltre l'attesa delle sonde.
 */
export function speedBloat(r: SpeedTest): SpeedBloat {
  const out: SpeedBloat = { severity: 'unknown', atLeast: false, p95AtLeast: false, lost: 0, sent: 0, excess: 0, raised: false };
  const dirs: ['download' | 'upload', SpeedDir | undefined][] = [
    ['download', r.download],
    ['upload', r.upload],
  ];
  for (const [name, d] of dirs) {
    if (!d || !d.latency) continue;
    out.sent += d.latency.sent;
    out.lost += d.latency.sent - d.latency.received;
    const b = dirBloat(r, d);
    if (!b) continue;
    if (out.worst === undefined || b.ms > out.worst) {
      out.worst = b.ms;
      out.worstP95 = b.p95;
      out.atLeast = b.atLeast;
      out.p95AtLeast = b.p95AtLeast;
      out.dir = name;
    }
  }
  const idle = r.idle;
  const idleLost = idle && idle.sent > 0 ? (idle.sent - idle.received) / idle.sent : 0;
  out.excess = Math.max(0, out.lost - Math.round(out.sent * idleLost));
  if (out.worst !== undefined) {
    out.severity = bloatSeverity(out.worst);
    if (out.severity === 'ok' && out.sent > 0 && (100 * out.excess) / out.sent > SPEED_LOST_NOTE_PCT) {
      out.severity = 'warn';
      out.raised = true;
    }
  }
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

/** "+26 ms in download · +128 ms in upload", "+15 ms in download · almeno +976 ms in upload". */
export function bloatValue(r: SpeedTest): string {
  const parts: string[] = [];
  const bd = dirBloat(r, r.download);
  const bu = dirBloat(r, r.upload);
  if (bd) parts.push(`${least(bd.atLeast)}+${speedMs(bd.ms)} in download`);
  if (bu) parts.push(`${least(bu.atLeast)}+${speedMs(bu.ms)} in upload`);
  return parts.length ? parts.join(' · ') : 'non misurata';
}

/**
 * Latenza durante un trasferimento, con le sonde senza risposta:
 * "43 ms (+19 ms; 95° percentile +31 ms)", "almeno 1000 ms (almeno +976
 * ms; …), 12 sonde su 12 senza risposta entro 1 s". '' senza sonde.
 */
export function speedLoadedText(r: SpeedTest, d?: SpeedDir): string {
  const l = d && d.latency;
  if (!d || !l || !l.sent) return '';
  const wait = waitLabel(probeWait(r));
  const lost = l.sent > l.received ? `${l.sent - l.received} sonde su ${l.sent} senza risposta entro ${wait}` : '';
  if (l.medianMs === undefined) {
    const b = dirBloat(r, d);
    return b ? `${lost}: almeno +${speedMs(b.ms)} rispetto al riposo` : `non misurata${lost ? `: ${lost}` : ''}`;
  }
  const add =
    d.bloatMs !== undefined
      ? ` (${least(l.medianAtLeast)}+${speedMs(d.bloatMs)}${d.bloatP95Ms !== undefined ? `; 95° percentile ${least(l.p95AtLeast)}+${speedMs(d.bloatP95Ms)}` : ''})`
      : '';
  return `${least(l.medianAtLeast)}${speedMs(l.medianMs)}${add}${lost ? `, ${lost}` : ''}`;
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
    `Misura con il server M-Lab di ${where}${r.startedAt ? `, il ${dateIt(r.startedAt)}` : ''}, una sola connessione per verso: ${mbpsText(d!.mbps)} in download${measured(u) ? ` e ${mbpsText(u!.mbps)} in upload` : ''}.`,
  ];
  if (u && u.server) parts.push(`L'upload è stato misurato su un altro server: ${speedWhere(u.server)}, perché M-Lab non proponeva più quello del download.`);
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
    const wait = waitLabel(probeWait(r));
    const idleLost = r.idle.received < r.idle.sent;
    const worst = `+${speedMs(b.worst)}`;
    const p95 = b.worstP95 !== undefined ? ` (95° percentile ${least(b.p95AtLeast)}+${speedMs(b.worstP95)})` : '';
    const dirText = b.dir === 'upload' ? 'in upload' : 'in download';
    let verdict: string;
    if (b.atLeast)
      // Coda oltre l'attesa delle sonde: la maggior parte non ha avuto risposta.
      verdict = `Con la linea satura la maggior parte delle sonde ${dirText} non ha avuto risposta entro ${wait}, mentre a riposo rispondevano in ${idle}: la latenza aggiunta è di almeno ${speedMs(b.worst)}. La coda supera probabilmente ${wait}, oppure il modem o il router scartano i pacchetti: chiamate e videochiamate si bloccano quando la linea è piena (backup, aggiornamenti, caricamenti).`;
    else if (b.raised)
      verdict = `Con la linea satura la latenza mediana sale di ${speedMs(b.worst)} ${dirText} rispetto ai ${idle} a riposo, ma ${b.excess} sonde su ${b.sent} non hanno avuto risposta entro ${wait}${idleLost ? ' (oltre a quelle perse anche a riposo)' : ', mentre a riposo rispondevano'}: probabilmente ci sono picchi di coda oltre ${wait} (o pacchetti scartati), che disturbano chiamate e videochiamate.`;
    else
      verdict =
        b.severity === 'ok'
          ? `Con la linea satura la latenza resta contenuta: al massimo ${worst} ${dirText}${p95} rispetto ai ${idle} a riposo. Chiamate e videochiamate reggono anche mentre qualcuno scarica o carica file.`
          : b.severity === 'warn'
            ? `Con la linea satura la latenza sale di ${speedMs(b.worst)} ${dirText}${p95} rispetto ai ${idle} a riposo: si nota nelle videochiamate e nei giochi quando qualcuno scarica o carica file.`
            : `Con la linea satura la latenza sale di ${speedMs(b.worst)} ${dirText}${p95} rispetto ai ${idle} a riposo: chiamate e videochiamate si spezzano quando la linea è piena (backup, aggiornamenti, caricamenti).`;
    if (b.severity !== 'ok')
      verdict += b.dir === 'upload' ? ' La coda si forma di solito nel modem o nel router, nel verso dell\'upload.' : ' La coda si forma nel router, nel modem o presso l\'operatore.';
    if (!b.atLeast && !b.raised && b.sent > 0) {
      if ((100 * b.excess) / b.sent > SPEED_LOST_NOTE_PCT)
        verdict += ` ${b.lost} sonde su ${b.sent} non hanno avuto risposta entro ${wait} durante i trasferimenti: nel calcolo contano come latenza di almeno ${wait}${idleLost ? ', tolta la quota persa anche a riposo' : ''}.`;
      else if ((100 * b.lost) / b.sent > SPEED_LOST_NOTE_PCT)
        verdict += ` ${b.lost} sonde su ${b.sent} sono rimaste senza risposta durante i trasferimenti, ma se ne perdevano anche a riposo: indicano perdite sulla linea più che una coda.`;
    }
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
    const loaded = speedLoadedText(r, d);
    out.push(`${name}: ${mbpsText(d.mbps)}, ${speedBytes(d.bytes)} in ${fmt(d.ms / 1000, 1)} s${d.capped ? ' (limite di 250 MB)' : ''}${loaded ? `; latenza ${loaded}` : ''}`);
    if (d.server) out.push(`${name}: su un altro server di M-Lab, ${speedWhere(d.server)}`);
    if (d.error) out.push(`${name}: ${speedErr(d.error)}`);
  };
  dir('Download', r.download);
  dir('Upload', r.upload);
  if (r.idle && r.idle.medianMs !== undefined)
    out.push(`Latenza a riposo: ${speedMs(r.idle.medianMs)} (mediana, ${r.probeMethod === 'tcp' ? 'connessioni TCP' : 'ping'} verso ${r.probe || 'un server pubblico'})`);
  const b = speedBloat(r);
  if (b.worst !== undefined)
    out.push(
      `Latenza sotto carico: ${BLOAT_LABEL[b.severity]}, ${least(b.atLeast)}+${speedMs(b.worst)} ${b.dir === 'upload' ? 'in upload' : 'in download'}${b.raised ? `, ${b.excess} sonde su ${b.sent} senza risposta` : ''} (soglie di Polaris: sotto ${SPEED_BLOAT_WARN_MS} ms in più va bene, oltre ${SPEED_BLOAT_CRIT_MS} ms è alta)`,
    );
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
  const ld = speedLoadedText(r, r.download);
  const lu = speedLoadedText(r, r.upload);
  if (ld || lu) rows.push(['Latenza sotto carico', [ld ? `download: ${ld}` : '', lu ? `upload: ${lu}` : ''].filter(Boolean).join('; ')]);
  const up = r.upload && r.upload.server;
  rows.push(['Server', `M-Lab, ${speedWhere(r.server)}${up ? `; upload: ${speedWhere(up)}` : ''}`]);
  return rows;
}
