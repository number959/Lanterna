import { more, num } from './fmt';
import { dateIt } from './pc';
import type { DeviceInfo, DevicesData, Finding, PcData, Scan, Severity } from './types';

// Dispositivi e driver, come Gestione dispositivi: problemi segnalati da
// Windows (i codici del riquadro "Stato dispositivo"), driver di terze parti
// vecchi, verifica delle firme dei driver. L'agente legge i dati con SetupAPI
// e Configuration Manager, senza identificativi d'istanza e senza nomi
// scelti dall'utente. Gira anche in goja: niente Intl.
//
// Significato dei codici: Microsoft Learn, "Device Manager error messages" e
// le pagine CM_PROB_* (learn.microsoft.com/windows-hardware/drivers/install/),
// lette il 9/11/2026. Le spiegazioni in italiano sono di Polaris, non i testi
// esatti di Windows.

/** Codici di Gestione dispositivi: titolo breve e spiegazione. */
export const DEVICE_PROBLEMS: Record<number, [string, string]> = {
  1: ['non configurato', 'Windows non ha configurato il dispositivo, di solito perché manca il driver'],
  3: ['driver danneggiato o risorse insufficienti', 'il driver può essere danneggiato, oppure mancano memoria o altre risorse'],
  10: ['non può essere avviato', 'il driver non è riuscito ad avviare il dispositivo'],
  12: ['risorse insufficienti', 'il dispositivo non trova risorse libere (conflitto con un altro dispositivo)'],
  14: ['serve un riavvio', 'il dispositivo funzionerà solo dopo il riavvio del PC'],
  16: ['risorse non identificate', 'Windows non riesce a identificare tutte le risorse usate dal dispositivo'],
  18: ['driver da reinstallare', 'bisogna reinstallare i driver del dispositivo'],
  19: ['configurazione danneggiata', 'la configurazione del dispositivo nel registro è incompleta o danneggiata, spesso per un filtro lasciato da un programma disinstallato'],
  21: ['in rimozione', 'Windows sta rimuovendo il dispositivo'],
  22: ['disattivato', 'il dispositivo è disattivato in Gestione dispositivi'],
  24: ['assente o incompleto', 'il dispositivo non è presente, non funziona bene o non ha tutti i driver'],
  25: ['configurazione in corso', 'Windows sta ancora configurando il dispositivo'],
  26: ['configurazione in corso', 'Windows sta ancora configurando il dispositivo'],
  28: ['driver non installato', 'i driver del dispositivo non sono installati'],
  29: ['disattivato dal firmware', 'il firmware non ha dato al dispositivo le risorse necessarie: di solito è spento nelle impostazioni del BIOS/UEFI'],
  31: ['driver non caricato', 'Windows non riesce a caricare i driver necessari'],
  32: ['servizio del driver disattivato', 'il servizio del driver è disattivato; un altro driver può svolgere la stessa funzione'],
  33: ['risorse non determinabili', 'Windows non riesce a determinare le risorse richieste dal dispositivo'],
  34: ['impostazioni non determinabili', 'Windows non riesce a determinare le impostazioni del dispositivo'],
  35: ['firmware incompleto', 'il firmware del PC non descrive abbastanza il dispositivo: serve un aggiornamento del BIOS/UEFI'],
  36: ['interrupt non compatibile', 'il dispositivo chiede un tipo di interrupt diverso da quello configurato'],
  37: ['driver non inizializzato', 'Windows non riesce a inizializzare il driver'],
  38: ['driver ancora in memoria', 'una copia precedente del driver è ancora in memoria'],
  39: ['driver danneggiato o mancante', 'Windows non riesce a caricare il driver: è danneggiato, mancante o non compatibile (anche con l\'integrità della memoria)'],
  40: ['servizio del driver danneggiato', 'le informazioni del servizio del driver nel registro mancano o sono sbagliate'],
  41: ['hardware non trovato', 'il driver è stato caricato ma non trova il dispositivo'],
  42: ['dispositivo duplicato', 'nel sistema c\'è già un dispositivo uguale in funzione'],
  43: ['fermato dopo un errore', 'Windows ha fermato il dispositivo perché ha segnalato problemi'],
  44: ['spento da un programma', 'un\'applicazione o un servizio ha spento il dispositivo'],
  47: ['pronto per la rimozione', 'il dispositivo è stato preparato per la rimozione sicura ma è ancora collegato'],
  48: ['driver bloccato', 'il driver è bloccato perché noto per causare problemi a Windows'],
  49: ['registro troppo grande', 'il registro di sistema ha superato la dimensione massima'],
  50: ['proprietà non applicate', 'Windows non è riuscito ad applicare tutte le proprietà del dispositivo'],
  51: ['in attesa di un altro dispositivo', 'il dispositivo aspetta che si avvii un altro dispositivo'],
  52: ['firma del driver non verificata', 'Windows non riesce a verificare la firma digitale del driver e non lo carica'],
  53: ['riservato al debugger', 'il dispositivo è riservato al debugger del kernel'],
  54: ['reimpostazione in corso', 'il dispositivo si sta reimpostando'],
  55: ['bloccato fino all\'accesso', 'il dispositivo non parte finché un utente non accede (protezione DMA del kernel)'],
  56: ['configurazione di classe in corso', 'Windows sta ancora configurando la classe del dispositivo'],
};

/** Stati NTSTATUS frequenti con i problemi dei dispositivi (nomi da ntstatus.h). */
const NTSTATUS_TEXT: Record<string, string> = {
  '0xC0000034': 'oggetto non trovato: spesso un servizio o un filtro mancante',
  '0xC000009A': 'risorse insufficienti',
  '0xC0000428': 'firma del file non valida',
  '0xC0000490': 'nessun driver compatibile trovato',
  '0xC0000491': 'pacchetto del driver non trovato',
  '0xC0000492': 'configurazione del driver non trovata',
  '0xC0000494': 'serve un driver di funzione',
};

/** Codici che si risolvono da soli o con un riavvio. */
const TRANSIENT = [14, 21, 25, 26, 47, 51, 54, 56];
/** Codici di dispositivi spenti di proposito. */
const DISABLED = [22, 32];
/** Classi senza le quali il PC non lavora (video, rete, dischi, controller, tastiera e mouse, audio, chipset). */
const CORE_CLASSES = ['display', 'net', 'diskdrive', 'hdc', 'scsiadapter', 'keyboard', 'mouse', 'media', 'monitor'];

/** Gruppi di Gestione dispositivi, per classe di installazione. */
const CLASS_IT: Record<string, string> = {
  display: 'Schede video',
  net: 'Schede di rete',
  diskdrive: 'Unità disco',
  hdc: 'Controller IDE ATA/ATAPI',
  scsiadapter: 'Controller di archiviazione',
  usb: 'Controller USB',
  usbdevice: 'Dispositivi USB',
  bluetooth: 'Bluetooth',
  media: 'Audio, video e giochi',
  audioendpoint: 'Ingressi e uscite audio',
  keyboard: 'Tastiere',
  mouse: 'Mouse e dispositivi di puntamento',
  hidclass: 'Dispositivi di input (HID)',
  monitor: 'Monitor',
  system: 'Dispositivi di sistema',
  processor: 'Processori',
  softwaredevice: 'Dispositivi software',
  softwarecomponent: 'Componenti software',
  extension: 'Estensioni',
  camera: 'Fotocamere',
  image: 'Dispositivi di imaging',
  printer: 'Stampanti',
  printqueue: 'Code di stampa',
  securitydevices: 'Dispositivi di sicurezza',
  firmware: 'Firmware',
  computer: 'Computer',
  battery: 'Batterie',
  wpd: 'Dispositivi portatili',
  volume: 'Volumi di archiviazione',
  volumesnapshot: 'Copie shadow dei volumi',
  smartcardreader: 'Lettori di smart card',
  biometric: 'Dispositivi biometrici',
  ports: 'Porte (COM e LPT)',
  sensor: 'Sensori',
  ucm: 'Connettori USB',
  memorytechnologydriver: 'Lettori di schede di memoria',
  sdhost: 'Controller host SD',
  net_virtual: 'Schede di rete',
};

/** Nome del gruppo di Gestione dispositivi per una classe ("Altri dispositivi" se manca). */
export function deviceClassText(cls?: string): string {
  if (!cls) return 'Altri dispositivi';
  return CLASS_IT[cls.toLowerCase()] ?? cls;
}

/** "Codice 10: non può essere avviato". */
export function deviceProblemText(code: number): string {
  const p = DEVICE_PROBLEMS[code];
  return `Codice ${code}${p ? `: ${p[0]}` : ''}`;
}

/** Spiegazione completa del problema, con lo stato NTSTATUS se c'è. */
export function deviceProblemDetail(d: DeviceInfo): string {
  const code = d.problem ?? 0;
  const p = DEVICE_PROBLEMS[code];
  const known = d.problemStatus ? NTSTATUS_TEXT[d.problemStatus] : undefined;
  const status = d.problemStatus ? ` (stato ${d.problemStatus}${known ? `, ${known}` : ''})` : '';
  return `${p ? p[1].charAt(0).toUpperCase() + p[1].slice(1) : 'Problema segnalato da Windows'}${status}.`;
}

/** "NVIDIA 31.0.15.3623 del 12/03/2024 (oem42.inf)". */
export function driverText(d?: DeviceInfo['driver']): string {
  if (!d) return '';
  const parts = [d.provider, d.version].filter(Boolean).join(' ');
  const date = d.date && !d.inbox ? ` del ${dateIt(d.date)}` : '';
  const inf = d.inf ? ` (${d.inf})` : '';
  return `${parts || 'driver'}${date}${inf}`;
}

export const isDisabled = (d: DeviceInfo) => DISABLED.indexOf(d.problem ?? 0) >= 0;
export const isTransient = (d: DeviceInfo) => TRANSIENT.indexOf(d.problem ?? 0) >= 0;

/** Gravità di un dispositivo con problemi; 'ok' se non ne ha. */
export function deviceSeverity(d: DeviceInfo): Severity {
  const code = d.problem ?? 0;
  if (!code) return 'ok';
  if (code === 48 || code === 52) return 'crit';
  if (isDisabled(d) || isTransient(d)) return 'info';
  const cls = (d.class ?? '').toLowerCase();
  if (CORE_CLASSES.indexOf(cls) >= 0) return 'crit';
  // I controller USB e i dispositivi del chipset (sul bus PCI) servono a tutto il resto.
  if ((cls === 'usb' || cls === 'system') && d.enumerator === 'PCI') return 'crit';
  return 'warn';
}

const RANK: Record<Severity, number> = { unknown: 0, ok: 1, info: 2, warn: 3, crit: 4 };
const DAY = 86400000;
const YEAR = 365.25 * DAY;

/** Il dispositivo che usa un file di driver (come "nvlddmkm.sys"), se l'agente l'ha visto. */
export function deviceOfDriver(pc: PcData | undefined, file: string): DeviceInfo | undefined {
  const f = file.toLowerCase();
  const items = pc?.devices?.items ?? [];
  // Prima il dispositivo con un problema o con un driver di terze parti.
  const all = items.filter((d) => d.driver?.file === f);
  return all.filter((d) => d.problem || (d.driver && !d.driver.inbox))[0] ?? all[0];
}

/** Driver di terze parti, uno per file INF, con i dispositivi che lo usano. */
export interface DriverPackage {
  inf: string;
  provider?: string;
  version?: string;
  date?: string;
  file?: string;
  classes: string[];
  devices: DeviceInfo[];
}

/** Raggruppa i driver di terze parti per file INF, dal più vecchio. */
export function thirdPartyDrivers(dev?: DevicesData): DriverPackage[] {
  const by: { [inf: string]: DriverPackage } = {};
  const order: string[] = [];
  for (const d of dev?.items ?? []) {
    const drv = d.driver;
    if (!drv || drv.inbox || !drv.inf) continue;
    let p = by[drv.inf];
    if (!p) {
      p = by[drv.inf] = { inf: drv.inf, provider: drv.provider, version: drv.version, date: drv.date, file: drv.file, classes: [], devices: [] };
      order.push(drv.inf);
    }
    p.devices.push(d);
    const c = deviceClassText(d.class);
    if (p.classes.indexOf(c) < 0) p.classes.push(c);
  }
  return order.map((k) => by[k]).sort((a, b) => (a.date ?? '9999') < (b.date ?? '9999') ? -1 : (a.date ?? '9999') > (b.date ?? '9999') ? 1 : a.inf < b.inf ? -1 : 1);
}

/** Classi i cui driver contano per la stabilità, con l'età oltre la quale Polaris li segnala. */
const AGE_CLASSES: Record<string, { info: number; warn?: number }> = {
  net: { info: 5, warn: 8 },
  hdc: { info: 5, warn: 8 },
  scsiadapter: { info: 5, warn: 8 },
  bluetooth: { info: 5 },
  media: { info: 5 },
  system: { info: 5 },
};

/** Pacchetti di terze parti vecchi, con la soglia superata. */
export function oldDrivers(dev: DevicesData | undefined, now: number): { pkg: DriverPackage; years: number; sev: Severity }[] {
  const out: { pkg: DriverPackage; years: number; sev: Severity }[] = [];
  for (const p of thirdPartyDrivers(dev)) {
    if (!p.date) continue;
    const t = Date.parse(p.date + 'T00:00:00Z');
    if (isNaN(t)) continue;
    const years = (now - t) / YEAR;
    let sev: Severity = 'ok';
    for (const d of p.devices) {
      const rule = AGE_CLASSES[(d.class ?? '').toLowerCase()];
      // I driver dei chipset da Microsoft sono di Windows anche se hanno un file oem.
      if (!rule || (/^microsoft/i.test(p.provider ?? '') && (d.class ?? '').toLowerCase() === 'system')) continue;
      const s: Severity = rule.warn && years >= rule.warn ? 'warn' : years >= rule.info ? 'info' : 'ok';
      if (RANK[s] > RANK[sev]) sev = s;
    }
    if (sev !== 'ok') out.push({ pkg: p, years, sev });
  }
  return out;
}

type Add = (f: Omit<Finding, 'actions'> & { actions?: string[] }) => void;

const nameList = (ds: DeviceInfo[], n: number) =>
  ds
    .slice(0, n)
    .map((d) => `${d.name} (${deviceProblemText(d.problem ?? 0).toLowerCase()})`)
    .join('; ') + more(ds.length, n);

/** Giudizi su dispositivi e driver. */
export function analyzeDevices(scan: Scan, add: Add) {
  const pc = scan.pc;
  const dev = pc?.devices;
  if (!pc || !dev) return;
  const now = Date.parse(scan.agent.startedAt) || Date.now();
  const problems = dev.items.filter((d) => d.problem);
  const hard = problems.filter((d) => !isDisabled(d) && !isTransient(d));
  const transient = problems.filter(isTransient);
  const disabled = problems.filter(isDisabled);
  let sev: Severity = 'ok';
  for (const d of problems) if (RANK[deviceSeverity(d)] > RANK[sev]) sev = deviceSeverity(d);
  if (hard.length >= 3 && RANK[sev] < RANK.warn) sev = 'warn';
  const value = problems.length
    ? `${num(problems.length, 'dispositivo con problemi', 'dispositivi con problemi')} su ${dev.total}`
    : `${dev.total} dispositivi, nessun problema`;
  let verdict: string;
  if (hard.length) {
    const first = hard[0];
    verdict =
      `Gestione dispositivi segnala: ${nameList(hard, 4)}. ${first.name}: ${deviceProblemDetail(first)}` +
      (hard.some((d) => d.problem === 52)
        ? ' Un driver senza firma valida viene rifiutato da Windows: serve la versione firmata del produttore.'
        : '') +
      (hard.some((d) => d.problem === 28) ? ' Per un driver non installato cerca prima negli aggiornamenti facoltativi di Windows, poi sul sito del produttore.' : '') +
      (transient.length ? ` Altri ${transient.length} si sistemano con un riavvio.` : '') +
      (disabled.length ? ` ${num(disabled.length, 'dispositivo è disattivato', 'dispositivi sono disattivati')} di proposito.` : '');
  } else if (transient.length) {
    verdict = `${nameList(transient, 4)}: Windows sta finendo di configurar${transient.length === 1 ? 'lo' : 'li'} o aspetta un riavvio. Riavvia il PC e ripeti l'analisi.`;
  } else if (disabled.length) {
    verdict = `Nessun guasto. ${disabled.length === 1 ? 'È disattivato' : 'Sono disattivati'} in Gestione dispositivi: ${disabled
      .slice(0, 4)
      .map((d) => d.name)
      .join('; ')}${more(disabled.length, 4)}. Se non è voluto, riattiva${disabled.length === 1 ? 'lo' : 'li'}.`;
  } else {
    verdict = 'Nessun dispositivo segnala problemi: in Gestione dispositivi non ci sono punti esclamativi.';
  }
  if (dev.partial) verdict += ' La lettura non è finita in tempo: l\'elenco può essere incompleto.';
  const actions: string[] = [];
  if (hard.length) actions.push('fix-device');
  if (transient.length) actions.push('restart-pc');
  if (disabled.length) actions.push('enable-device');
  add({ id: 'pc.devices', metric: 'pc.devices', category: 'pc', title: 'Dispositivi', value, numeric: problems.length, severity: sev, verdict, actions });

  // Firma dei driver: su Windows a 64 bit il kernel accetta solo driver firmati, a meno di modalità test o debug.
  const ci = dev.codeIntegrity;
  const x86 = /^x86$/i.test(pc.os?.arch ?? '');
  if (ci) {
    const off = !ci.enabled || ci.testSigning || ci.debugMode;
    const s: Severity = off ? (x86 ? 'warn' : 'crit') : 'ok';
    const why = [
      !ci.enabled ? 'la verifica delle firme dei driver è spenta' : '',
      ci.testSigning ? 'è attiva la modalità test, che accetta driver firmati con qualunque certificato (sul desktop compare la scritta Modalità test)' : '',
      ci.debugMode ? 'è attivo il debug del kernel, che consente codice non firmato' : '',
    ].filter(Boolean);
    add({
      id: 'pc.drivers.signing',
      metric: 'pc.drivers.signing',
      category: 'pc',
      title: 'Firma dei driver',
      value: off ? (ci.testSigning ? 'Modalità test attiva' : ci.debugMode ? 'Debug del kernel attivo' : 'Verifica spenta') : `Verificata${ci.hvci ? ', integrità della memoria attiva' : ''}`,
      severity: s,
      verdict: off
        ? `Windows sta caricando driver senza le garanzie normali: ${why.join('; ')}. È il modo in cui si installano driver non firmati, compresi cheat e software malevolo: se non l'hai fatto di proposito per sviluppare un driver, va spento.`
        : `Windows carica in kernel solo driver con una firma valida${ci.hvci ? ' e l\'integrità della memoria (Isolamento core) è attiva' : ''}: i driver avviati sono firmati.`,
      actions: off ? ['disable-test-signing'] : [],
    });
  }

  const old = oldDrivers(dev, now);
  if (old.length) {
    const s: Severity = old.some((o) => o.sev === 'warn') ? 'warn' : 'info';
    const list = old
      .slice(0, 4)
      .map((o) => `${o.pkg.devices[0].name} (${[o.pkg.provider, o.pkg.version].filter(Boolean).join(' ')}, del ${dateIt(o.pkg.date!)})`)
      .join('; ');
    add({
      id: 'pc.drivers.old',
      metric: 'pc.drivers.old',
      category: 'pc',
      title: 'Driver di terze parti vecchi',
      value: `${num(old.length, 'driver', 'driver')} con più di ${Math.floor(Math.min(...old.map((o) => o.years)))} anni`,
      numeric: old.length,
      severity: s,
      verdict:
        `${list}${more(old.length, 4)}. ` +
        (s === 'warn'
          ? 'Driver di rete o dei dischi così vecchi lavorano in kernel a ogni operazione e sono tra i primi sospettati di blocchi e schermate blu: cerca la versione aggiornata.'
          : 'Non è per forza un problema (alcuni produttori non aggiornano più i driver che funzionano), ma una versione recente corregge spesso difetti di stabilità e sicurezza.') +
        ' La data è quella dichiarata dal produttore; i driver inclusi in Windows non sono valutati per età.',
      actions: ['update-drivers'],
    });
  }
}
