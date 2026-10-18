import { fmt, num, thousands } from './fmt';
import type { NVMeHealth, PhysicalDisk, Severity, SmartAttr } from './types';

// Lettura dei dati SMART come in CrystalDiskInfo: nomi degli attributi ATA,
// interpretazione del dato grezzo e stato complessivo del disco (Buono,
// Attenzione, Critico). Le regole seguono quelle diffuse tra gli strumenti
// dedicati: un attributo è "guasto" quando il valore attuale scende alla
// soglia del produttore o sotto (come smartctl); settori riallocati, in
// attesa o non correggibili sono il primo segnale di degrado (come
// CrystalDiskInfo); per i dischi NVMe valgono i bit di avviso critico e la
// riserva definiti dalla specifica.

const RANK: Record<Severity, number> = { unknown: 0, ok: 1, info: 2, warn: 3, crit: 4 };
const worst = (...s: Severity[]) => s.reduce((a, b) => (RANK[b] > RANK[a] ? b : a), 'unknown' as Severity);

/**
 * Nomi degli attributi più diffusi (i nomi generici di smartmontools,
 * tradotti). Alcuni identificativi hanno un significato diverso su SSD: in
 * quel caso vale SSD_NAMES.
 */
const NAMES: Record<number, string> = {
  1: 'Tasso di errori di lettura',
  2: 'Prestazioni di trasferimento',
  3: 'Tempo di avvio della rotazione',
  4: 'Avvii e arresti del motore',
  5: 'Settori riallocati',
  6: 'Margine del canale di lettura',
  7: 'Tasso di errori di posizionamento',
  8: 'Prestazioni di posizionamento',
  9: 'Ore di accensione',
  10: 'Tentativi di avvio della rotazione',
  11: 'Tentativi di ricalibrazione',
  12: 'Cicli di accensione',
  13: 'Tasso di errori di lettura corretti',
  22: 'Livello di elio',
  170: 'Blocchi di riserva disponibili',
  171: 'Errori di programmazione',
  172: 'Errori di cancellazione',
  173: "Livellamento dell'usura",
  174: 'Interruzioni di corrente impreviste',
  177: "Livellamento dell'usura",
  179: 'Blocchi di riserva usati',
  180: 'Blocchi di riserva non usati',
  181: 'Errori di programmazione',
  182: 'Errori di cancellazione',
  183: 'Blocchi difettosi in esercizio',
  184: 'Errori end-to-end',
  187: 'Errori non correggibili segnalati',
  188: 'Comandi scaduti',
  189: 'Scritture con testina troppo alta',
  190: "Temperatura del flusso d'aria",
  191: 'Urti rilevati',
  192: 'Ritrazioni allo spegnimento',
  193: 'Cicli di parcheggio delle testine',
  194: 'Temperatura',
  195: "Errori corretti dall'hardware",
  196: 'Eventi di riallocazione',
  197: 'Settori in attesa di riallocazione',
  198: 'Settori non correggibili',
  199: "Errori CRC dell'interfaccia",
  200: 'Tasso di errori di scrittura',
  201: 'Tasso di errori di lettura software',
  202: 'Errori di indirizzamento dei dati',
  220: 'Spostamento dei piatti',
  222: 'Ore con testine caricate',
  223: 'Tentativi di caricamento delle testine',
  224: 'Attrito di caricamento',
  225: 'Cicli di caricamento',
  226: 'Tempo di caricamento',
  228: 'Ritrazioni allo spegnimento',
  230: 'Ampiezza del segnale delle testine',
  231: 'Temperatura',
  232: 'Riserva disponibile',
  233: 'Indicatore di usura',
  240: 'Ore di volo delle testine',
  241: 'Totale dati scritti',
  242: 'Totale dati letti',
  250: 'Tentativi di rilettura',
  254: 'Cadute libere rilevate',
};
const SSD_NAMES: Record<number, string> = {
  202: 'Vita residua',
  230: 'Protezione della durata',
  231: 'Vita residua',
};

export const isFlashDisk = (d: PhysicalDisk) => d.media === 'ssd' || d.media === 'scm' || !!d.nvme;

/** Nome italiano di un attributo SMART. */
export function smartName(id: number, flash: boolean): string {
  return (flash && SSD_NAMES[id]) || NAMES[id] || 'Specifico del produttore';
}

/** Identificativo nella forma degli strumenti dedicati: due cifre esadecimali. */
export const smartId = (id: number) => (id < 16 ? '0' : '') + id.toString(16).toUpperCase();

const lo32 = (raw: number) => raw % 4294967296;
const lo16 = (raw: number) => raw % 65536;

/** Attributi il cui dato grezzo è un semplice conteggio (nelle cifre basse). */
const COUNTS = [4, 5, 10, 11, 12, 171, 172, 174, 179, 180, 181, 182, 183, 184, 187, 192, 193, 196, 197, 198, 199, 225, 228, 254];

/**
 * Temperatura di un attributo: il byte basso del dato grezzo (gli altri byte,
 * per molti produttori, sono minima e massima). undefined se non plausibile.
 */
function tempOf(a?: SmartAttr): number | undefined {
  if (!a) return undefined;
  const t = a.raw % 256;
  return t > 0 && t < 100 ? t : undefined;
}

/**
 * Dato grezzo leggibile: gradi per le temperature, ore e conteggi in
 * decimale, il resto in esadecimale a 12 cifre come in CrystalDiskInfo (per
 * molti attributi i byte hanno significati diversi secondo il produttore, e un
 * numero decimale enorme trarrebbe in inganno).
 */
export function smartRaw(a: SmartAttr): string {
  if (a.id === 194 || a.id === 190) {
    const t = tempOf(a);
    if (t !== undefined) return `${t} °C`;
  }
  if (a.id === 9 || a.id === 240) return `${thousands(lo32(a.raw))} ore`;
  if (COUNTS.indexOf(a.id) >= 0) return thousands(lo32(a.raw));
  return a.raw.toString(16).toUpperCase().padStart(12, '0');
}

export type AttrState = 'fail' | 'past' | 'caution' | 'ok';

/** Settori riallocati, in attesa, non correggibili ed errori non correggibili. */
const CAUTION: Record<number, [string, string]> = {
  5: ['settore riallocato', 'settori riallocati'],
  197: ['settore in attesa di riallocazione', 'settori in attesa di riallocazione'],
  198: ['settore non correggibile', 'settori non correggibili'],
  187: ['errore non correggibile segnalato', 'errori non correggibili segnalati'],
};

/** Conteggio di un attributo di attenzione; 0 se il valore è un segnaposto (tutti i bit a uno). */
function cautionCount(a: SmartAttr): number {
  return lo32(a.raw) === 4294967295 ? 0 : lo16(a.raw);
}

/**
 * Stato di un attributo: "fail" se il valore attuale è alla soglia o sotto
 * (soglia zero = mai guasto; 254 e 255 non sono soglie reali), "past" se lo è
 * stato il valore peggiore, "caution" per un conteggio di settori diverso da
 * zero.
 */
export function attrState(a: SmartAttr): AttrState {
  const t = a.threshold;
  if (t !== undefined && t > 0 && t < 254) {
    if (a.current <= t) return 'fail';
    if (a.worst <= t) return 'past';
  }
  if (CAUTION[a.id] && cautionCount(a) > 0) return 'caution';
  return 'ok';
}

export interface DiskSignal {
  severity: Severity;
  text: string;
  /** Azioni della knowledge base suggerite da questo segnale. */
  actions: string[];
  /** Segnale dato da Windows (stato del disco) e non dai dati SMART letti. */
  windows?: boolean;
}

const REPLACE = ['backup-replace-disk'];
const CHECK = ['check-disk-errors', 'backup-replace-disk'];

export interface DiskStatus {
  /** ok = Buono, warn = Attenzione, crit = Critico, unknown = nessun dato. */
  severity: Severity;
  label: 'Buono' | 'Attenzione' | 'Critico' | 'Sconosciuto';
  /** Vita residua stimata degli SSD (100 meno l'usura). */
  lifePct?: number;
  wearPct?: number;
  temperatureC?: number;
  powerOnHours?: number;
  powerCycles?: number;
  /** Dati scritti in totale (solo NVMe: per ATA l'unità dipende dal produttore). */
  writtenGB?: number;
  /** Motivi rilevati dai dati SMART, dal più grave. */
  signals: DiskSignal[];
}

export const STATUS_LABEL: Record<Severity, DiskStatus['label']> = {
  ok: 'Buono',
  info: 'Buono',
  warn: 'Attenzione',
  crit: 'Critico',
  unknown: 'Sconosciuto',
};

const NVME_BITS: [number, Severity, string, string[]][] = [
  [0x01, 'crit', 'la riserva di celle di scorta è scesa sotto la soglia del produttore', REPLACE],
  [0x04, 'crit', "il disco segnala un'affidabilità degradata da errori interni o di memoria", REPLACE],
  [0x08, 'crit', 'il disco si è messo in sola lettura per proteggere i dati', REPLACE],
  [0x02, 'warn', 'la temperatura è fuori dai limiti del produttore', ['cool-disk']],
  [0x10, 'warn', 'il sistema di protezione dei dati in caso di blackout è guasto', REPLACE],
  [0x20, 'warn', 'la memoria persistente è in sola lettura', REPLACE],
];

function nvmeSignals(nv: NVMeHealth): DiskSignal[] {
  const out: DiskSignal[] = [];
  for (const [bit, severity, text, actions] of NVME_BITS) if (nv.criticalWarning & bit) out.push({ severity, text: `Avviso critico NVMe: ${text}.`, actions });
  if (!(nv.criticalWarning & 0x01) && nv.spareThresholdPct > 0 && nv.availableSparePct < nv.spareThresholdPct)
    out.push({ severity: 'crit', text: `La riserva di celle è al ${nv.availableSparePct} %, sotto la soglia del ${nv.spareThresholdPct} %.`, actions: REPLACE });
  if (nv.mediaErrors > 0)
    out.push({
      severity: 'warn',
      text: `Ha registrato ${num(nv.mediaErrors, 'errore di integrità dei dati', 'errori di integrità dei dati')}: dati che il disco non è riuscito a leggere correttamente.`,
      actions: CHECK,
    });
  return out;
}

function ataSignals(attrs: SmartAttr[], flash: boolean): DiskSignal[] {
  const out: DiskSignal[] = [];
  for (const a of attrs) {
    const st = attrState(a);
    const name = `${smartId(a.id)} ${smartName(a.id, flash)}`;
    if (st === 'fail') {
      out.push({
        severity: a.flags & 1 ? 'crit' : 'warn',
        text:
          `L'attributo ${name} è a ${a.current}, alla soglia di guasto del produttore (${a.threshold}) o sotto` +
          (a.flags & 1 ? ': per il disco è un segnale di guasto imminente.' : ': è un indicatore di invecchiamento, non di guasto immediato.'),
        actions: REPLACE,
      });
    } else if (st === 'past' && a.flags & 1) {
      out.push({ severity: 'info', text: `L'attributo ${name} in passato è sceso alla soglia di guasto (peggiore ${a.worst}, soglia ${a.threshold}).`, actions: [] });
    }
  }
  const counts: string[] = [];
  for (const id of [5, 197, 198, 187]) {
    const a = attrs.find((x) => x.id === id);
    if (a && attrState(a) !== 'fail' && CAUTION[id] && cautionCount(a) > 0) counts.push(num(cautionCount(a), CAUTION[id][0], CAUTION[id][1]));
  }
  if (counts.length)
    out.push({
      severity: 'warn',
      text: `Il disco ha ${counts.join(', ')}: zone che non si leggono più in modo affidabile. È il primo segnale di degrado, spesso in crescita.`,
      actions: CHECK,
    });
  return out;
}

/** Stato complessivo del disco secondo i dati SMART, come il riquadro di CrystalDiskInfo. */
export function diskStatus(d: PhysicalDisk): DiskStatus {
  const r = d.reliability;
  const nv = d.nvme;
  const attrs = d.smart ?? [];
  const flash = isFlashDisk(d);
  const attr = (id: number) => attrs.find((a) => a.id === id);

  const signals: DiskSignal[] = [];
  if (d.health === 'unhealthy') signals.push({ severity: 'crit', text: 'Windows segnala il disco come guasto.', actions: REPLACE, windows: true });
  else if (d.health === 'warning' || (d.operational ?? []).some((o) => /predictive failure/i.test(o)))
    signals.push({ severity: 'crit', text: 'Il disco prevede un guasto: i suoi controlli interni hanno superato le soglie.', actions: REPLACE, windows: true });
  if (nv) signals.push(...nvmeSignals(nv));
  signals.push(...ataSignals(attrs, flash));

  // I contatori di Windows derivano dagli stessi dati: se gli attributi ATA
  // hanno già segnalato settori o errori non correggibili non si ripetono.
  const ataUncorrected = attrs.some((a) => (a.id === 187 || a.id === 198) && cautionCount(a) > 0);
  const uncorrected = (r?.readUncorrected ?? 0) + (r?.writeUncorrected ?? 0);
  if (uncorrected > 0 && !ataUncorrected)
    signals.push({
      severity: 'warn',
      text: `Ha registrato ${num(uncorrected, 'errore di lettura o scrittura non correggibile', 'errori di lettura o scrittura non correggibili')}: settori illeggibili, primo segnale di degrado.`,
      actions: CHECK,
    });

  const wearRaw = flash ? (r?.wearPct ?? nv?.percentageUsed) : undefined;
  const wear = wearRaw === undefined ? undefined : Math.max(0, wearRaw);
  if (wear !== undefined && wear >= 70)
    signals.push({
      severity: wear >= 90 ? 'crit' : 'warn',
      text: `Ha consumato il ${fmt(wear)} % della durata di scrittura dichiarata dal produttore.`,
      actions: REPLACE,
    });

  const h9 = attr(9);
  const c12 = attr(12);
  const temp = r?.temperatureC ?? nv?.temperatureC ?? tempOf(attr(194)) ?? tempOf(attr(190));
  if (temp !== undefined) {
    const tempSev: Severity = flash ? (temp >= 80 ? 'crit' : temp >= 70 ? 'warn' : 'ok') : temp >= 60 ? 'crit' : temp >= 55 ? 'warn' : 'ok';
    if (tempSev !== 'ok')
      signals.push({
        severity: tempSev,
        text: `Temperatura alta (${fmt(temp)} °C): ${flash ? 'oltre i 70 °C molti SSD rallentano per proteggersi' : 'oltre i 55 °C i dischi meccanici si consumano più in fretta'}.`,
        actions: ['cool-disk'],
      });
  }

  const status: DiskStatus = {
    severity: 'unknown',
    label: 'Sconosciuto',
    wearPct: wear,
    lifePct: wear === undefined ? undefined : Math.max(0, 100 - wear),
    temperatureC: temp,
    powerOnHours: r?.powerOnHours ?? nv?.powerOnHours ?? (h9 ? lo32(h9.raw) : undefined),
    powerCycles: nv?.powerCycles ?? (c12 ? lo32(c12.raw) : undefined),
    writtenGB: nv?.dataWrittenGB,
    // Ordinamento stabile: a parità di gravità resta l'ordine di inserimento.
    signals: signals.map((x, i) => ({ x, i })).sort((a, b) => RANK[b.x.severity] - RANK[a.x.severity] || a.i - b.i).map((e) => e.x),
  };
  const known = d.health === 'healthy' || !!r || !!nv || attrs.length > 0;
  const sev = worst(known ? 'ok' : 'unknown', ...signals.map((s) => s.severity));
  status.severity = sev === 'info' ? 'ok' : sev;
  status.label = STATUS_LABEL[status.severity];
  return status;
}

/** Testo breve per i dati scritti: "18,7 TB", "820 GB". */
export function bytesText(gb: number): string {
  return gb >= 1000 ? `${fmt(gb / 1000, gb >= 100000 ? 0 : 1)} TB` : `${fmt(gb, 0)} GB`;
}
