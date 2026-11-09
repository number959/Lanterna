import { fmt, more, num } from './fmt';
import { dateIt, on } from './pc';
import type { AppFailure, AppFailures, BootPerf, BootRecord, Finding, PcData, Reliability, Scan, Severity } from './types';

// Avvio, programmi che si chiudono da soli e indice di stabilità, come
// "Impatto di avvio" di Gestione attività e Monitoraggio affidabilità.
// L'agente legge il registro Diagnostics-Performance (eventi 100-110 e
// 200-203), il registro Applicazione (1000, 1001, 1002) e WMI
// (Win32_ReliabilityStabilityMetrics). Le soglie sono scelte di Polaris:
// Microsoft non ne pubblica. Gira anche in goja: niente Intl.

/** Soglie della durata dell'avvio (mediana degli ultimi avvii), in ms. */
export const BOOT_WARN_MS = 60000;
export const BOOT_CRIT_MS = 180000;
/** Soglie del tempo del firmware prima di Windows, in ms. */
export const FIRMWARE_INFO_MS = 15000;
export const FIRMWARE_WARN_MS = 45000;
/** Soglie dello spegnimento, in ms. */
export const SHUTDOWN_INFO_MS = 60000;
export const SHUTDOWN_WARN_MS = 180000;
/** Arresti e blocchi in 30 giorni oltre i quali Polaris avvisa. */
export const APPS_WARN = 5;
/** Arresti dello stesso programma che, con l'ultimo da meno di 7 giorni, rendono il problema critico. */
export const APP_CRIT = 10;

/** "1 min 32 s", "48 s", "3,2 s". */
export function msText(ms: number): string {
  const s = ms / 1000;
  if (s < 10) return `${fmt(s, 1)} s`;
  if (s < 60) return `${Math.round(s)} s`;
  const m = Math.floor(s / 60);
  const r = Math.round(s - m * 60);
  return r ? `${m} min ${r} s` : `${m} min`;
}

const median = (xs: number[]) => {
  const v = xs.slice().sort((a, b) => a - b);
  const n = v.length;
  return n ? (n % 2 ? v[(n - 1) / 2] : (v[n / 2 - 1] + v[n / 2]) / 2) : 0;
};

/**
 * Gli avvii che contano per il giudizio: gli ultimi 5, senza i riavvii dopo
 * un aggiornamento (più lunghi per natura) se ce ne sono altri.
 */
export function bootSample(b?: BootPerf): BootRecord[] {
  const all = (b?.boots ?? []).filter((r) => r.totalMs > 0);
  const normal = all.filter((r) => !r.afterUpdate);
  return (normal.length ? normal : all).slice(0, 5);
}

/** Durata tipica dell'avvio (mediana del campione), 0 se non misurata. */
export const bootTypical = (b?: BootPerf) => median(bootSample(b).map((r) => r.totalMs));

export function bootSeverity(ms: number): Severity {
  if (!ms) return 'unknown';
  return ms > BOOT_CRIT_MS ? 'crit' : ms >= BOOT_WARN_MS ? 'warn' : 'ok';
}

/** Tipo di componente lento, in italiano. */
export const SLOW_KIND: Record<string, string> = {
  app: 'programma',
  driver: 'driver',
  service: 'servizio',
  core: 'componente di Windows',
  prefetch: 'ottimizzazione dell\'avvio',
  policy: 'criteri di gruppo',
  device: 'dispositivo',
  session: 'avvio della sessione',
};

/** Codici di eccezione frequenti negli arresti dei programmi (ntstatus.h e documentazione Microsoft). */
export const EXCEPTION_TEXT: Record<string, string> = {
  '0xc0000005': 'accesso a una zona di memoria non valida',
  '0xc0000006': 'errore nel leggere dal disco o dalla rete una parte del programma',
  '0xc000001d': 'istruzione non valida per il processore',
  '0xc00000fd': 'stack esaurito (ricorsione infinita)',
  '0xc0000374': 'memoria del programma (heap) danneggiata',
  '0xc0000409': 'controllo di sicurezza fallito (buffer sovrascritto)',
  '0xc0000417': 'parametro non valido passato a una funzione di sistema',
  '0xe0434352': 'eccezione .NET non gestita',
  '0x80000003': 'punto di interruzione (il programma si è fermato da solo)',
};

/** Moduli di Windows che compaiono spesso negli arresti senza esserne la causa. */
const VICTIM_MODULES = ['ntdll.dll', 'kernelbase.dll', 'kernel32.dll', 'ucrtbase.dll', 'msvcrt.dll'];
/** Eseguibili di Windows che, se si chiudono spesso, fanno pensare a file di sistema danneggiati. */
const SYSTEM_APPS = ['explorer.exe', 'svchost.exe', 'dwm.exe', 'runtimebroker.exe', 'searchhost.exe', 'startmenuexperiencehost.exe', 'shellexperiencehost.exe', 'sihost.exe', 'ctfmon.exe', 'lsass.exe', 'winlogon.exe', 'csrss.exe'];

/** "3 arresti e 1 blocco". */
export function failText(a: { crashes: number; hangs: number }): string {
  const parts: string[] = [];
  if (a.crashes) parts.push(num(a.crashes, 'arresto', 'arresti'));
  if (a.hangs) parts.push(num(a.hangs, 'blocco', 'blocchi'));
  return parts.join(' e ') || 'nessuno';
}

/** Il modulo e il codice più frequenti di un programma, spiegati. */
export function appHint(a: AppFailure): string {
  const mod = a.modules?.[0];
  const exc = a.exceptions?.[0];
  const parts: string[] = [];
  if (mod) parts.push(`modulo ${mod.name}${VICTIM_MODULES.indexOf(mod.name.toLowerCase()) >= 0 ? ' (di Windows: spesso è dove l\'errore si manifesta, non la causa)' : ''}`);
  if (exc) parts.push(`codice ${exc.name}${EXCEPTION_TEXT[exc.name] ? `, ${EXCEPTION_TEXT[exc.name]}` : ''}`);
  return parts.join('; ');
}

const isSystemApp = (a: AppFailure) => !!a.system || SYSTEM_APPS.indexOf(a.app.toLowerCase()) >= 0;

const DAY = 86400000;

type Add = (f: Omit<Finding, 'actions'> & { actions?: string[] }) => void;

function analyzeBoot(pc: PcData, add: Add) {
  const b = pc.boot;
  if (!b) return;
  const sample = bootSample(b);
  const typical = bootTypical(b);
  const fast = pc.os?.fastStartup === true;
  const fastNote = fast
    ? ' Con Avvio rapido attivo, l\'accensione dopo lo spegnimento è un ripristino dall\'ibernazione e Windows misura solo gli avvii completi, come i riavvii.'
    : '';
  if (!typical) {
    const why =
      b.channel === 'denied'
        ? 'il registro con le misure dell\'avvio non è leggibile da questo account'
        : b.channel === 'missing'
          ? 'il registro con le misure dell\'avvio non c\'è su questo PC'
          : b.channel === 'error'
            ? 'la lettura del registro con le misure dell\'avvio non è riuscita'
            : `Windows non ha registrato la durata dell'avvio negli ultimi ${b.days} giorni (succede su molti PC con le versioni recenti di Windows)`;
    add({
      id: 'pc.boot',
      metric: 'pc.boot',
      category: 'pc',
      title: 'Durata dell\'avvio',
      value: 'non misurata',
      severity: 'unknown',
      verdict: `Durata dell'avvio non disponibile: ${why}.${fastNote}`,
    });
  } else {
    const sev = bootSeverity(typical);
    const last = sample[0];
    const heavyPost = !!last.postBootMs && last.postBootMs > 30000 && last.postBootMs > last.totalMs / 2;
    const heavyMain = !!last.mainPathMs && last.mainPathMs > 60000;
    const sysDisk = (pc.disks ?? []).find((d) => d.system);
    const hdd = sysDisk?.media === 'hdd';
    let verdict =
      `Mediana degli ultimi ${num(sample.length, 'avvio misurato', 'avvii misurati')}: ${msText(typical)}` +
      (last.mainPathMs ? `; l'ultimo, ${on(last.time, 'il')}, ${msText(last.mainPathMs)} fino al desktop e ${msText(last.postBootMs ?? 0)} per i programmi all'avvio` : '') +
      '.';
    if (sev === 'ok') verdict += ' Un tempo normale per un PC con disco SSD.';
    else {
      if (heavyPost) verdict += ` La parte più lunga viene dopo l'accesso: i programmi all'avvio${last.startupApps ? ` (Windows ne ha contati ${last.startupApps})` : ''}.`;
      if (heavyMain) verdict += hdd ? ' Anche il caricamento di Windows è lento: il disco di sistema è meccanico.' : ' Anche il caricamento di Windows è lento: driver, servizi o il disco.';
      if (!heavyPost && !heavyMain) verdict += ' Controlla i programmi all\'avvio e i componenti segnalati come lenti.';
    }
    const actions: string[] = [];
    if (sev !== 'ok') {
      actions.push('trim-startup');
      if (hdd) actions.push('upgrade-ssd');
    }
    add({
      id: 'pc.boot',
      metric: 'pc.boot',
      category: 'pc',
      title: 'Durata dell\'avvio',
      value: msText(typical),
      numeric: Math.round(typical / 1000),
      severity: sev,
      verdict: verdict + fastNote,
      actions,
    });
  }

  const slow = b.slow ?? [];
  if (slow.length) {
    const many = slow.filter((s) => s.count >= 3);
    const sev: Severity = many.length ? 'warn' : 'info';
    const list = slow
      .slice(0, 3)
      .map((s) => `${s.friendly || s.name} (${SLOW_KIND[s.kind] ?? s.kind}${s.phase === 'shutdown' ? ' allo spegnimento' : ''}, ${s.degradationMs ? `+${msText(s.degradationMs)}, ` : ''}${num(s.count, 'volta', 'volte')})`)
      .join('; ');
    const hasApps = slow.some((s) => s.kind === 'app' || s.kind === 'service');
    const hasDrivers = slow.some((s) => s.kind === 'driver' || s.kind === 'device');
    add({
      id: 'pc.boot.slow',
      metric: 'pc.boot.slow',
      category: 'pc',
      title: 'Componenti che rallentano avvio e spegnimento',
      value: num(slow.length, 'componente segnalato', 'componenti segnalati'),
      numeric: slow.length,
      severity: sev,
      verdict:
        `Negli ultimi ${b.days} giorni Windows ha segnalato come più lenti del solito: ${list}${more(slow.length, 3)}.` +
        (many.length ? ' Quelli segnalati più volte rallentano ogni avvio: aggiornali o, se non servono, toglili dall\'avvio.' : ' Segnalazioni occasionali possono dipendere da aggiornamenti in corso.'),
      actions: [...(hasApps ? ['trim-startup'] : []), ...(hasDrivers ? ['update-drivers'] : [])],
    });
  }

  if (b.firmwareMs !== undefined && b.firmwareMs > FIRMWARE_INFO_MS) {
    const sev: Severity = b.firmwareMs > FIRMWARE_WARN_MS ? 'warn' : 'info';
    add({
      id: 'pc.boot.firmware',
      metric: 'pc.boot.firmware',
      category: 'pc',
      title: 'Tempo del firmware all\'accensione',
      value: msText(b.firmwareMs),
      numeric: Math.round(b.firmwareMs / 1000),
      severity: sev,
      verdict: `Prima ancora che parta Windows, il firmware del PC (BIOS/UEFI) impiega ${msText(b.firmwareMs)}: di solito bastano pochi secondi. Cause frequenti: avvio dalla rete attivo, dischi o chiavette controllati prima di quello di sistema, controlli completi della memoria a ogni accensione, firmware da aggiornare.`,
      actions: ['check-firmware-boot'],
    });
  }

  const sd = b.shutdowns?.[0];
  if (sd && sd.totalMs > SHUTDOWN_INFO_MS) {
    const sev: Severity = sd.totalMs > SHUTDOWN_WARN_MS ? 'warn' : 'info';
    const svc = slow.filter((s) => s.phase === 'shutdown').map((s) => s.friendly || s.name);
    add({
      id: 'pc.boot.shutdown',
      metric: 'pc.boot.shutdown',
      category: 'pc',
      title: 'Durata dello spegnimento',
      value: msText(sd.totalMs),
      numeric: Math.round(sd.totalMs / 1000),
      severity: sev,
      verdict:
        `L'ultimo spegnimento misurato, ${on(sd.time, 'il')}, è durato ${msText(sd.totalMs)}.` +
        (svc.length ? ` Windows ha segnalato come lenti a chiudersi: ${svc.slice(0, 3).join(', ')}.` : ' Di solito lo rallentano programmi o servizi che non si chiudono, o aggiornamenti da installare.'),
      actions: svc.length ? ['trim-startup'] : ['update-windows'],
    });
  }
}

function analyzeApps(pc: PcData, now: number, add: Add) {
  const d: AppFailures | undefined = pc.apps;
  if (!d) return;
  if (d.channel !== 'ok') {
    add({
      id: 'pc.apps',
      metric: 'pc.apps',
      category: 'pc',
      title: 'Programmi che si chiudono da soli',
      value: 'non letto',
      severity: 'unknown',
      verdict: d.channel === 'denied' ? 'Il registro Applicazione non è leggibile da questo account.' : 'La lettura del registro Applicazione non è riuscita.',
    });
    return;
  }
  const total = d.crashes + d.hangs;
  const top = d.apps.slice(0, 3);
  const hot = d.apps.filter((a) => a.crashes + a.hangs >= APP_CRIT && now - Date.parse(a.last) <= 7 * DAY);
  const sev: Severity = total === 0 ? 'ok' : hot.length ? 'crit' : total >= APPS_WARN ? 'warn' : 'info';
  const sysRepeat = d.apps.filter((a) => isSystemApp(a) && a.crashes + a.hangs >= 3);
  const werOff = !!(d.wer?.disabled || d.wer?.loggingDisabled);
  let verdict: string;
  if (!total) verdict = `Nessun programma si è chiuso da solo o bloccato negli ultimi ${d.days} giorni.`;
  else {
    verdict =
      `Negli ultimi ${d.days} giorni ${failText(d)}: ` +
      top.map((a) => `${a.app} (${failText(a)}, l'ultima volta il ${dateIt(a.last)})`).join('; ') +
      more(d.apps.length, 3) +
      '.';
    const hint = appHint(top[0]);
    if (hint) verdict += ` Per ${top[0].app}: ${hint}.`;
    if (hot.length) verdict += ` ${hot[0].app} si è chiuso ${hot[0].crashes + hot[0].hangs} volte, l'ultima negli ultimi 7 giorni: è un problema in corso.`;
    if (sysRepeat.length) verdict += ` Si chiudono spesso anche componenti di Windows (${sysRepeat.map((a) => a.app).join(', ')}): possibile danno ai file di sistema o un programma che si aggancia a Windows (antivirus, temi, estensioni).`;
  }
  if (werOff) verdict += ' La Segnalazione errori di Windows è disattivata: il conteggio viene dal registro eventi e può essere incompleto.';
  const actions: string[] = [];
  if (total) actions.push('update-app');
  if (sysRepeat.length) actions.push('repair-windows');
  add({
    id: 'pc.apps',
    metric: 'pc.apps',
    category: 'pc',
    title: 'Programmi che si chiudono da soli',
    value: total ? `${failText(d)} in ${d.days} giorni` : 'nessuno',
    numeric: total,
    severity: sev,
    verdict,
    actions,
  });
}

/** Media dell'indice in una finestra di giorni prima della data indicata. */
function windowAvg(series: { date: string; index: number }[], end: number, days: number): number | undefined {
  const xs = series.filter((p) => {
    const t = Date.parse(p.date + 'T12:00:00Z');
    return t <= end && t > end - days * DAY;
  });
  return xs.length ? xs.reduce((s, p) => s + p.index, 0) / xs.length : undefined;
}

export function reliabilitySeverity(index: number): Severity {
  return index >= 8 ? 'ok' : index >= 5 ? 'info' : index >= 3 ? 'warn' : 'crit';
}

/** Tendenza dell'indice: true se la media degli ultimi 7 giorni è scesa di almeno 2 punti rispetto ai 7 precedenti. */
export function reliabilityFalling(r?: Reliability): boolean {
  const s = r?.series ?? [];
  if (s.length < 4) return false;
  const end = Date.parse(s[s.length - 1].date + 'T12:00:00Z');
  const a = windowAvg(s, end, 7);
  const b = windowAvg(s, end - 7 * DAY, 7);
  return a !== undefined && b !== undefined && b - a >= 2;
}

function analyzeReliability(pc: PcData, now: number, add: Add) {
  const r = pc.reliability;
  if (!r) return;
  if (!r.available || r.index === undefined) {
    const server = !!pc.os?.server;
    const why =
      r.reason === 'disabled'
        ? 'la raccolta dei dati è disattivata nel registro di Windows (valore WMIEnable)'
        : server
          ? 'su Windows Server è disattivato per impostazione predefinita'
          : r.reason === 'error'
            ? 'Windows non ha risposto alla lettura'
            : 'Windows non ha ancora calcolato l\'indice negli ultimi 30 giorni (l\'attività pianificata che lo calcola può essere disattivata)';
    add({
      id: 'pc.reliability',
      metric: 'pc.reliability',
      category: 'pc',
      title: 'Indice di stabilità',
      value: 'non disponibile',
      severity: server || r.reason === 'disabled' ? 'info' : 'unknown',
      verdict: `L'indice di stabilità di Monitoraggio affidabilità non è disponibile: ${why}.`,
    });
    return;
  }
  const sev = reliabilitySeverity(r.index);
  const falling = reliabilityFalling(r);
  const recs = r.records ?? [];
  const updFail = recs.filter((g) => g.category === 'update-failed').reduce((s, g) => s + g.count, 0);
  const instFail = recs.filter((g) => g.category === 'install-failed').reduce((s, g) => s + g.count, 0);
  const stale = r.indexAt && now - Date.parse(r.indexAt) > 2 * DAY;
  let verdict =
    `Windows valuta la stabilità del PC ${fmt(r.index, 1)} su 10` +
    (r.indexAt ? `, ${on(r.indexAt, 'il')}` : '') +
    (sev === 'ok' ? ': pochi problemi negli ultimi giorni.' : sev === 'info' ? ': qualche arresto o errore negli ultimi giorni.' : ': molti arresti, blocchi o errori di Windows negli ultimi giorni.');
  if (falling) verdict += ' L\'indice è in calo rispetto alla settimana precedente.';
  if (updFail) verdict += ` Nello stesso periodo Monitoraggio affidabilità registra ${num(updFail, 'aggiornamento non riuscito', 'aggiornamenti non riusciti')}.`;
  if (instFail) verdict += ` E ${num(instFail, 'installazione non riuscita', 'installazioni non riuscite')}.`;
  if (stale) verdict += ` Il valore non è aggiornato: l'ultimo calcolo risale ${on(r.indexAt!, 'al')}.`;
  verdict += ' L\'indice lo calcola Windows con una formula non pubblicata (i problemi recenti pesano di più): Polaris lo riporta così com\'è e lo legge a fasce.';
  const actions: string[] = [];
  if (sev !== 'ok') actions.push('review-reliability');
  if (updFail) actions.push('update-windows');
  add({
    id: 'pc.reliability',
    metric: 'pc.reliability',
    category: 'pc',
    title: 'Indice di stabilità',
    value: `${fmt(r.index, 1)} su 10${falling ? ', in calo' : ''}`,
    numeric: r.index,
    severity: falling && sev === 'ok' ? 'info' : sev,
    verdict,
    actions,
  });
}

/** Giudizi su avvio, programmi che si chiudono da soli e indice di stabilità. */
export function analyzeStability(scan: Scan, add: Add) {
  const pc = scan.pc;
  if (!pc) return;
  const now = Date.parse(scan.agent.startedAt) || Date.now();
  analyzeBoot(pc, add);
  analyzeApps(pc, now, add);
  analyzeReliability(pc, now, add);
}
