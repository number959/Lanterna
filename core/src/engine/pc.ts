import { fmt, more, num, thousands } from './fmt';
import { bytesText, diskStatus, isFlashDisk } from './smart';
import type { DiskBench, EventGroup, EventKind, Finding, PcData, PhysicalDisk, PlanKind, Scan, Severity } from './types';

// Analisi del computer: sistema e supporto di Windows, memoria, dischi e loro
// salute, spazio, avvio, eventi del registro di sistema, sicurezza, batteria,
// alimentazione e test di velocità. Le soglie sono le stesse spiegate nella
// knowledge base (kb/metrics.ts, voci "pc.*").

type Add = (f: Omit<Finding, 'actions'> & { actions?: string[] }) => void;

const DAY = 86400000;
const RANK: Record<Severity, number> = { unknown: 0, ok: 1, info: 2, warn: 3, crit: 4 };
const worst = (...s: Severity[]) => s.reduce((a, b) => (RANK[b] > RANK[a] ? b : a), 'unknown' as Severity);

const pad2 = (n: number) => (n < 10 ? '0' : '') + n;
/** Data in formato italiano (GG/MM/AAAA) da una stringa ISO; '' se non valida. */
export function dateIt(iso: string): string {
  const t = Date.parse(iso.length === 10 ? iso + 'T00:00:00Z' : iso);
  if (isNaN(t)) return '';
  const d = new Date(t);
  return `${pad2(d.getUTCDate())}/${pad2(d.getUTCMonth() + 1)}/${d.getUTCFullYear()}`;
}

const MONTHS = ['gennaio', 'febbraio', 'marzo', 'aprile', 'maggio', 'giugno', 'luglio', 'agosto', 'settembre', 'ottobre', 'novembre', 'dicembre'];
/**
 * Data in parole con la preposizione giusta: on('2026-10-08', 'il') dà
 * "l'8 ottobre 2026", on('2025-10-14', 'dal') "dal 14 ottobre 2025",
 * on('2026-11-01', 'al') "al 1° novembre 2026".
 */
export function on(iso: string, prep: 'il' | 'dal' | 'al'): string {
  const t = Date.parse(iso.length === 10 ? iso + 'T00:00:00Z' : iso);
  if (isNaN(t)) return '';
  const d = new Date(t);
  const day = d.getUTCDate();
  const text = `${day === 1 ? '1°' : day} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}`;
  const elide = day === 8 || day === 11;
  const p = prep === 'il' ? (elide ? "l'" : 'il ') : prep === 'dal' ? (elide ? "dall'" : 'dal ') : elide ? "all'" : 'al ';
  return p + text;
}

const gbText = (gb: number) => `${fmt(gb, gb < 10 ? 1 : 0)} GB`;
const mbs = (v: number) => `${fmt(v, v < 10 ? 1 : 0)} MB/s`;

// ---------------------------------------------------------------- Windows

/**
 * Fine del supporto delle versioni di Windows 11 (aggiornamenti mensili di
 * sicurezza), per Home/Pro (24 mesi) ed Enterprise/Education (36 mesi).
 * Date pubblicate da Microsoft e note a metà 2026: vanno verificate sul sito
 * del ciclo di vita, perché Microsoft può modificarle.
 */
export const WIN11_EOS: Record<string, { home: string; ent: string }> = {
  '21H2': { home: '2023-10-10', ent: '2024-10-08' },
  '22H2': { home: '2024-10-08', ent: '2025-10-14' },
  '23H2': { home: '2025-11-11', ent: '2026-11-10' },
  '24H2': { home: '2026-10-13', ent: '2027-10-12' },
  '25H2': { home: '2027-10-12', ent: '2028-10-10' },
};
const WIN11_BUILD: Record<number, string> = { 22000: '21H2', 22621: '22H2', 22631: '23H2', 26100: '24H2', 26200: '25H2' };
/** Windows 10: fine del supporto e del programma ESU per i privati. */
export const WIN10_EOS = '2025-10-14';
export const WIN10_ESU_CONSUMER = '2026-10-13';

const isLtsc = (edition = '') => /^(Enterprise|IoTEnterprise)SN?$/i.test(edition);
const isHome = (edition = '') => /^Core/i.test(edition);
const isEntEdu = (edition = '') => /^(Enterprise|Education|IoTEnterprise)/i.test(edition) && !isLtsc(edition);

function analyzeOs(pc: PcData, now: number, add: Add) {
  const os = pc.os;
  if (!os) return;
  const build = os.build ?? 0;
  const version = os.version || (build >= 22000 ? WIN11_BUILD[build] : undefined);
  const value = `${os.name}${version ? ` ${version}` : ''}${build ? ` (build ${build}${os.ubr ? `.${os.ubr}` : ''})` : ''}`;
  let sev: Severity = 'ok';
  let verdict = '';
  let actions: string[] = [];
  const day = (iso: string) => Date.parse(iso + 'T00:00:00Z');
  if (os.server) {
    sev = 'info';
    verdict = 'Windows Server ha un ciclo di vita proprio, legato alla versione: verifica la data di fine supporto sul sito Microsoft.';
  } else if (build && build < 10240) {
    sev = 'crit';
    verdict = 'Versione di Windows non più supportata da anni: non riceve aggiornamenti di sicurezza e molti programmi non la supportano più.';
    actions = ['upgrade-windows'];
  } else if (isLtsc(os.edition)) {
    sev = 'info';
    verdict = 'Edizione LTSC (supporto a lungo termine): riceve aggiornamenti di sicurezza per più anni senza nuove funzioni. Verifica la data di fine supporto della tua edizione sul sito Microsoft.';
  } else if (build >= 10240 && build < 22000) {
    // Windows 10: supporto terminato; ESU per i privati fino al 13/10/2026, per le aziende a pagamento fino a tre anni.
    const ended = now >= day(WIN10_EOS);
    const esuOver = now >= day(WIN10_ESU_CONSUMER);
    if (!ended) {
      sev = 'info';
      verdict = `Il supporto di Windows 10 termina ${on(WIN10_EOS, 'il')}: pianifica il passaggio a Windows 11.`;
    } else if (isHome(os.edition) && esuOver) {
      sev = 'crit';
      verdict = `Windows 10 Home non riceve più aggiornamenti di sicurezza: il supporto è terminato ${on(WIN10_EOS, 'il')} e il programma ESU per i privati ${on(WIN10_ESU_CONSUMER, 'il')}. Ogni vulnerabilità scoperta da allora resta aperta.`;
    } else {
      sev = 'warn';
      verdict =
        `Il supporto di Windows 10 è terminato ${on(WIN10_EOS, 'il')}: gli aggiornamenti di sicurezza arrivano solo con il programma ESU ` +
        `(per i privati fino ${on(WIN10_ESU_CONSUMER, 'al')}, per aziende e organizzazioni a pagamento fino a tre anni). Se l'ultimo aggiornamento installato è recente il PC è probabilmente iscritto all'ESU; in ogni caso va pianificato il passaggio a Windows 11.`;
    }
    actions = ['upgrade-windows'];
  } else if (version && WIN11_EOS[version]) {
    const eos = WIN11_EOS[version][isEntEdu(os.edition) ? 'ent' : 'home'];
    const left = Math.ceil((day(eos) - now) / DAY);
    if (left <= 0) {
      sev = 'warn';
      verdict = `La versione ${version} di Windows 11 non riceve più aggiornamenti di sicurezza ${on(eos, 'dal')}: installa l'aggiornamento di funzionalità più recente da Windows Update.`;
      actions = ['upgrade-windows'];
    } else if (left <= 60) {
      sev = 'info';
      verdict = `La versione ${version} riceve aggiornamenti fino ${on(eos, 'al')} (${left === 1 ? 'manca un giorno' : `mancano ${left} giorni`}): installa per tempo l'aggiornamento di funzionalità più recente.`;
      actions = ['upgrade-windows'];
    } else {
      verdict = `Versione supportata: riceve aggiornamenti di sicurezza fino ${on(eos, 'al')}.`;
    }
  } else if (build >= 22000) {
    sev = 'info';
    verdict = 'Versione di Windows 11 recente, non ancora nel calendario di Polaris: verifica la data di fine supporto sul sito Microsoft.';
  } else {
    sev = 'unknown';
    verdict = 'Versione di Windows non riconosciuta.';
  }
  add({ id: 'pc.os', metric: 'pc.os', category: 'pc', title: 'Sistema operativo', value, severity: sev, verdict, actions });
}

function analyzeUptime(pc: PcData, add: Add) {
  const os = pc.os;
  if (os?.uptimeSec !== undefined) {
    const days = os.uptimeSec / 86400;
    const sev: Severity = days > 30 ? 'warn' : days > 7 ? 'info' : 'ok';
    const hours = Math.round(os.uptimeSec / 3600);
    const value = days >= 1 ? `${fmt(days, days < 10 ? 1 : 0)} giorni` : num(hours, 'ora', 'ore');
    add({
      id: 'pc.uptime',
      metric: 'pc.uptime',
      category: 'pc',
      title: 'Tempo dall\'ultimo riavvio',
      value,
      numeric: days,
      severity: sev,
      verdict:
        (sev === 'ok'
          ? 'Il computer è stato riavviato di recente.'
          : `Il computer non viene riavviato da ${value}: un riavvio completa gli aggiornamenti, libera la memoria e rimette in ordine driver e servizi bloccati.`) +
        (os.fastStartup && sev !== 'ok' ? ' Con l\'avvio rapido attivo, "Arresta il sistema" non azzera questo tempo: per ripartire da zero serve "Riavvia".' : ''),
      actions: sev === 'ok' ? [] : ['restart-pc'],
    });
  }
  const u = pc.updates;
  if (u) {
    const reasons = u.rebootReasons ?? [];
    const updates = reasons.some((r) => /Windows Update|componenti/i.test(r));
    add({
      id: 'pc.reboot',
      metric: 'pc.reboot',
      category: 'pc',
      title: 'Riavvio in sospeso',
      value: u.pendingReboot ? reasons.join(', ') || 'sì' : 'no',
      severity: !u.pendingReboot ? 'ok' : updates ? 'warn' : 'info',
      verdict: !u.pendingReboot
        ? 'Nessuna operazione in attesa di riavvio.'
        : updates
          ? 'Windows ha installato aggiornamenti che diventano effettivi solo dopo il riavvio: fino ad allora le correzioni di sicurezza non sono attive e il sistema può comportarsi in modo instabile.'
          : 'Alcuni file verranno sostituiti al prossimo riavvio (di solito dopo l\'installazione o la rimozione di un programma).',
      actions: u.pendingReboot ? ['restart-pc'] : [],
    });
  }
}

// ---------------------------------------------------------------- Memoria e processore

function topBy<T>(xs: T[], key: (x: T) => number | undefined, n: number, min: number): T[] {
  return xs
    .filter((x) => (key(x) ?? -1) >= min)
    .sort((a, b) => (key(b) ?? 0) - (key(a) ?? 0))
    .slice(0, n);
}

/** La finestra di Polaris usa WebView2: i suoi processi compaiono nell'elenco. */
const procName = (n: string) => (/^msedgewebview2\.exe$/i.test(n) ? `${n} (anche la finestra di Polaris)` : n);

function analyzeMemory(pc: PcData, add: Add) {
  const m = pc.memory;
  if (m && m.totalMB > 0) {
    const gb = m.totalMB / 1024;
    // Il totale visto da Windows esclude la memoria riservata alla grafica integrata: 8 GB installati possono apparire come 7,7.
    const sev: Severity = gb < 3 ? 'crit' : gb < 7 ? 'warn' : 'ok';
    add({
      id: 'pc.ram',
      metric: 'pc.ram',
      category: 'pc',
      title: 'Memoria installata (RAM)',
      value: gbText(gb),
      numeric: gb,
      severity: sev,
      verdict:
        sev === 'crit'
          ? 'Memoria insufficiente per Windows 10 e 11: il sistema usa continuamente il disco al posto della RAM e tutto rallenta.'
          : sev === 'warn'
            ? 'Basta per un uso leggero, ma browser con molte schede, Office e videochiamate insieme la esauriscono: a quel punto Windows usa il disco e il PC rallenta.'
            : gb < 15
              ? 'Adeguata per il lavoro d\'ufficio; per fotoritocco, sviluppo o molte applicazioni insieme servono 16 GB.'
              : 'Ampia per l\'uso d\'ufficio e per molte applicazioni insieme.',
      actions: sev === 'ok' ? [] : ['add-ram'],
    });
    const availPct = (100 * m.availableMB) / m.totalMB;
    const commitPct = m.commitLimitMB ? (100 * (m.commitMB ?? 0)) / m.commitLimitMB : undefined;
    const usage: Severity = availPct < 10 || (commitPct ?? 0) > 90 ? 'warn' : availPct < 20 ? 'info' : 'ok';
    const heavy = topBy(pc.processes ?? [], (p) => p.memoryMB, 3, 200).map((p) => `${procName(p.name)} ${gbText(p.memoryMB / 1024)}`);
    add({
      id: 'pc.ramuse',
      metric: 'pc.ramuse',
      category: 'pc',
      title: 'Memoria in uso',
      value: `${fmt(100 - availPct)} % in uso, ${gbText(m.availableMB / 1024)} liberi`,
      numeric: 100 - availPct,
      severity: usage,
      verdict:
        (usage === 'ok'
          ? 'C\'è memoria libera a sufficienza.'
          : usage === 'info'
            ? 'Memoria piuttosto occupata: con un altro programma pesante Windows inizierà a usare il disco.'
            : 'Memoria quasi esaurita: Windows sposta dati sul disco (paginazione) e i programmi rallentano o si bloccano.') +
        (commitPct !== undefined && commitPct > 90 ? ` La memoria impegnata è al ${fmt(commitPct)} % del limite (RAM più file di paging).` : '') +
        (heavy.length && usage !== 'ok' ? ` Usano più memoria: ${heavy.join(', ')}.` : ''),
      actions: usage === 'warn' ? (gb < 15 ? ['close-heavy-apps', 'add-ram'] : ['close-heavy-apps']) : [],
    });
  }
  const load = pc.cpu?.loadPct;
  if (load !== undefined) {
    const sev: Severity = load >= 80 ? 'warn' : load >= 50 ? 'info' : 'ok';
    const busy = topBy(pc.processes ?? [], (p) => p.cpuPct, 3, 5).map((p) => `${procName(p.name)} ${fmt(p.cpuPct ?? 0)} %`);
    add({
      id: 'pc.cpuload',
      metric: 'pc.cpuload',
      category: 'pc',
      title: 'Carico del processore',
      value: `${fmt(load)} %`,
      numeric: load,
      severity: sev,
      verdict:
        (sev === 'ok'
          ? load < 25
            ? 'Il processore era quasi libero durante la misura.'
            : 'Il processore lavorava ma aveva ancora capacità libera durante la misura.'
          : sev === 'info'
            ? 'Il processore era piuttosto occupato durante la misura.'
            : 'Il processore era quasi saturo: i programmi rispondono in ritardo.') +
        (busy.length ? ` Più attivi: ${busy.join(', ')}.` : '') +
        (sev !== 'ok' ? ' È una misura di un secondo e mezzo: se il valore resta alto anche ripetendo l\'analisi, individua il programma in Gestione attività.' : ''),
      actions: sev === 'warn' ? ['close-heavy-apps'] : [],
    });
  }
}

// ---------------------------------------------------------------- Dischi

const MEDIA_LABEL: Record<PhysicalDisk['media'], string> = { hdd: 'disco meccanico', ssd: 'SSD', scm: 'memoria persistente (SCM)', unknown: '' };
const isFlash = isFlashDisk;
const isUsb = (d?: PhysicalDisk) => !!d && /usb/i.test(d.bus ?? '');

function diskTitle(d: PhysicalDisk): string {
  if (d.system) return 'Salute del disco di sistema';
  return `Salute del disco${d.id !== undefined ? ` ${d.id}` : ''}${isUsb(d) ? ' (USB)' : ''}`;
}

function analyzeDisks(scan: Scan, pc: PcData, add: Add) {
  const disks = (pc.disks ?? []).filter((d) => d.sizeGB > 0);
  disks.forEach((d, i) => {
    const r = d.reliability;
    const st = diskStatus(d);
    const flash = isFlashDisk(d);
    const hasSmart = !!r || !!d.nvme || (d.smart ?? []).length > 0;

    const parts = [`${d.name}: ${st.label}${st.lifePct !== undefined ? ` ${fmt(st.lifePct)} %` : ''}`];
    if (st.temperatureC !== undefined) parts.push(`${fmt(st.temperatureC)} °C`);
    if (st.powerOnHours !== undefined) parts.push(`${thousands(st.powerOnHours)} ore`);

    const what = [MEDIA_LABEL[d.media], d.bus, `da ${gbText(d.sizeGB)}`].filter(Boolean).join(' ');
    const v: string[] = [];
    if (d.health === 'unhealthy')
      v.push(`Windows segnala il disco come guasto (${what}): copia subito altrove i dati importanti, potrebbe smettere di funzionare in qualsiasi momento.`);
    else if (st.signals.some((x) => x.windows))
      v.push(`Il disco prevede un guasto (${what}): i suoi controlli interni (SMART) hanno superato le soglie. Copia subito i dati e programma la sostituzione.`);
    else if (d.health === 'healthy') v.push(`Windows considera il disco integro (${what}).`);
    else if (hasSmart) v.push(`Windows non riporta lo stato del disco (${what}), ma i dati SMART sono leggibili.`);
    else v.push(`Windows non riporta lo stato del disco (${what}).`);
    for (const x of st.signals) if (!x.windows) v.push(x.text);
    if (st.wearPct !== undefined && st.wearPct < 70) v.push(`Usura ${fmt(st.wearPct)} % della durata dichiarata.`);
    if (d.nvme) {
      const nv = d.nvme;
      const extra = [`${bytesText(nv.dataWrittenGB)} scritti in totale`];
      if (nv.unsafeShutdowns > 0) extra.push(num(nv.unsafeShutdowns, 'spegnimento non sicuro', 'spegnimenti non sicuri'));
      v.push(`Registro NVMe: ${extra.join(', ')}.`);
    }
    const crc = (d.smart ?? []).find((a) => a.id === 199);
    if (crc && crc.raw % 4294967296 > 0)
      v.push(`L'interfaccia ha registrato ${num(crc.raw % 4294967296, 'errore', 'errori')} di trasmissione (CRC): di solito dipendono dal cavo SATA o dal connettore, non dal disco; se il numero cresce, sostituisci il cavo.`);
    if (!flash && (st.powerOnHours ?? 0) > 40000) v.push(`Con ${thousands(st.powerOnHours!)} ore di funzionamento (oltre 4 anni continuativi) è un disco anziano: tieni aggiornato il backup.`);
    if (!hasSmart && st.severity !== 'crit')
      v.push(
        scan.agent.elevated === false
          ? 'Temperatura, usura ed errori (dati SMART) si leggono avviando Polaris come amministratore.'
          : 'Il disco non espone i dati SMART (succede con molti box USB e controller RAID).',
      );

    const actions: string[] = [];
    for (const x of st.signals) for (const a of x.actions) if (actions.indexOf(a) < 0) actions.push(a);
    add({
      id: `pc.disk.${d.id ?? i}`,
      metric: 'pc.disk.health',
      category: 'pc',
      title: diskTitle(d),
      value: parts.join(' · '),
      numeric: st.wearPct,
      severity: st.severity,
      verdict: v.join(' '),
      actions,
    });
  });

  const sys = disks.find((d) => d.system);
  if (sys && sys.media !== 'unknown') {
    const hdd = sys.media === 'hdd';
    add({
      id: 'pc.systemdisk',
      metric: 'pc.systemdisk',
      category: 'pc',
      title: 'Disco di Windows',
      value: hdd ? `disco meccanico${sys.spindleRpm ? `, ${thousands(sys.spindleRpm)} giri/min` : ''}` : `SSD${sys.bus ? ` ${sys.bus}` : ''}`,
      severity: hdd ? 'warn' : 'ok',
      verdict: hdd
        ? 'Windows e i programmi sono su un disco meccanico: le letture sparse, che dominano avvio, aggiornamenti e apertura dei programmi, sono decine di volte più lente che su un SSD. È la causa più comune di un PC lento.'
        : 'Windows è su un SSD: avvio e apertura dei programmi non sono limitati dal disco.',
      actions: hdd ? ['upgrade-ssd'] : [],
    });
  }

  for (const vol of pc.volumes ?? []) {
    if (vol.kind !== 'fixed' || vol.sizeGB < 1) continue;
    const pctFree = (100 * vol.freeGB) / vol.sizeGB;
    const sev: Severity = vol.system
      ? vol.freeGB < 5 || pctFree < 5
        ? 'crit'
        : vol.freeGB < 15 || pctFree < 10
          ? 'warn'
          : 'ok'
      : pctFree < 5
        ? 'warn'
        : pctFree < 10
          ? 'info'
          : 'ok';
    const disk = disks.find((d) => d.id !== undefined && d.id === vol.disk);
    add({
      id: `pc.space.${vol.letter.replace(':', '')}`,
      metric: 'pc.space',
      category: 'pc',
      title: `Spazio libero (${vol.letter}${vol.system ? ', Windows' : ''})`,
      value: `${gbText(vol.freeGB)} su ${gbText(vol.sizeGB)} (${fmt(pctFree)} %)`,
      numeric: pctFree,
      severity: sev,
      verdict:
        (sev === 'ok'
          ? 'Spazio sufficiente.'
          : vol.system
            ? sev === 'crit'
              ? 'Spazio quasi esaurito sull\'unità di Windows: aggiornamenti che non si installano, programmi che si bloccano, file temporanei e di paging senza posto.'
              : 'Spazio scarso sull\'unità di Windows: gli aggiornamenti di funzionalità richiedono circa 20 GB liberi e il sistema rallenta quando l\'unità è quasi piena.'
            : 'Unità quasi piena: i nuovi file non troveranno posto.') +
        (sev !== 'ok' && disk && isFlash(disk) ? ' Un SSD quasi pieno è anche più lento in scrittura, perché ha meno spazio per riorganizzare i dati.' : ''),
      actions: sev === 'ok' ? [] : ['free-disk-space'],
    });
  }
}

// ---------------------------------------------------------------- Avvio

function analyzeStartup(pc: PcData, add: Add) {
  if (!pc.startup) return;
  const on = pc.startup.filter((s) => s.enabled);
  const off = pc.startup.length - on.length;
  const sev: Severity = on.length > 15 ? 'warn' : on.length > 8 ? 'info' : 'ok';
  add({
    id: 'pc.startup',
    metric: 'pc.startup',
    category: 'pc',
    title: 'Programmi all\'avvio',
    value: `${on.length} attivi${off ? `, ${off} disattivati` : ''}`,
    numeric: on.length,
    severity: sev,
    verdict:
      sev === 'ok'
        ? 'Pochi programmi partono con Windows.'
        : `${num(on.length, 'programma parte', 'programmi partono')} a ogni accesso e allungano l'avvio: ${on
            .slice(0, 5)
            .map((s) => s.name)
            .join(', ')}${more(on.length, 5)}. Disattiva quelli che non servono subito: non occorre disinstallarli.`,
    actions: sev === 'ok' ? [] : ['trim-startup'],
  });
}

// ---------------------------------------------------------------- Eventi

/** Codici di arresto più frequenti (schermate blu) e loro significato. */
export const BUGCHECKS: Record<string, [string, string]> = {
  '0x0000000a': ['IRQL_NOT_LESS_OR_EQUAL', 'un driver ha usato memoria non valida'],
  '0x0000001a': ['MEMORY_MANAGEMENT', 'errore nella gestione della memoria: RAM difettosa o driver'],
  '0x0000001e': ['KMODE_EXCEPTION_NOT_HANDLED', 'eccezione in un driver'],
  '0x0000003b': ['SYSTEM_SERVICE_EXCEPTION', 'eccezione in un servizio di sistema o in un driver'],
  '0x00000050': ['PAGE_FAULT_IN_NONPAGED_AREA', 'accesso a memoria non valida: driver, RAM o disco'],
  '0x0000007a': ['KERNEL_DATA_INPAGE_ERROR', 'dati non letti dal disco: disco, cavo o controller'],
  '0x0000007e': ['SYSTEM_THREAD_EXCEPTION_NOT_HANDLED', 'eccezione in un driver'],
  '0x0000009f': ['DRIVER_POWER_STATE_FAILURE', 'un driver non gestisce sospensione o risveglio'],
  '0x000000d1': ['DRIVER_IRQL_NOT_LESS_OR_EQUAL', 'un driver (spesso di rete) ha usato memoria non valida'],
  '0x000000ef': ['CRITICAL_PROCESS_DIED', 'si è fermato un processo essenziale di Windows'],
  '0x000000f4': ['CRITICAL_OBJECT_TERMINATION', 'si è fermato un processo essenziale: spesso il disco'],
  '0x00000116': ['VIDEO_TDR_FAILURE', 'la scheda video non risponde: driver video o surriscaldamento'],
  '0x00000124': ['WHEA_UNCORRECTABLE_ERROR', 'errore hardware: processore, RAM, alimentazione o temperature'],
  '0x00000133': ['DPC_WATCHDOG_VIOLATION', 'un driver o un dispositivo non risponde in tempo (spesso disco o firmware dell\'SSD)'],
  '0x00000139': ['KERNEL_SECURITY_CHECK_FAILURE', 'struttura dati danneggiata: driver o RAM'],
  '0x0000013a': ['KERNEL_MODE_HEAP_CORRUPTION', 'memoria del sistema danneggiata da un driver'],
  '0x00000154': ['UNEXPECTED_STORE_EXCEPTION', 'errore nella memoria compressa: spesso il disco'],
};

const bugcheckCode = (detail?: string) => {
  const m = /0x[0-9a-f]+/i.exec(detail ?? '');
  if (!m) return undefined;
  const hex = m[0].slice(2).toLowerCase();
  return '0x' + ('00000000' + hex).slice(-8);
};

function analyzeEvents(pc: PcData, add: Add) {
  const days = pc.eventsDays;
  if (!days) return;
  const ev = pc.events ?? [];
  const of = (...k: EventKind[]) => ev.filter((e) => k.indexOf(e.kind) >= 0);
  const total = (es: EventGroup[]) => es.reduce((a, e) => a + e.count, 0);
  const last = (es: EventGroup[]) => es.map((e) => e.last).sort().pop() ?? '';
  const period = `negli ultimi ${days} giorni`;

  // Kernel-Power 41 ed EventLog 6008 descrivono lo stesso episodio: non si sommano.
  const sd = of('unexpected-shutdown');
  const shutdowns = Math.max(total(sd.filter((e) => e.id === 41)), total(sd.filter((e) => e.id !== 41)));
  const bsod = of('bugcheck');
  const nBsod = total(bsod);
  add({
    id: 'pc.events.shutdown',
    metric: 'pc.events.shutdown',
    category: 'pc',
    title: 'Spegnimenti imprevisti',
    value: shutdowns ? `${shutdowns} in ${days} giorni` : 'nessuno',
    numeric: shutdowns,
    severity: shutdowns >= 3 ? 'warn' : shutdowns ? 'info' : 'ok',
    verdict: shutdowns
      ? `${num(shutdowns, 'spegnimento non regolare', 'spegnimenti non regolari')} ${period}, l'ultimo ${on(last(sd), 'il')}: mancanza di corrente, pulsante tenuto premuto, blocco del sistema, surriscaldamento o alimentazione difettosa.` +
        (nBsod ? ' Alcuni possono coincidere con le schermate blu indicate sotto.' : '')
      : `Nessuno spegnimento non regolare ${period}.`,
    actions: shutdowns ? ['check-power-supply'] : [],
  });

  const codes: string[] = [];
  for (const e of bsod) {
    const c = bugcheckCode(e.detail);
    if (c && codes.indexOf(c) < 0) codes.push(c);
  }
  const named = codes.map((c) => (BUGCHECKS[c] ? `${c} ${BUGCHECKS[c][0]} (${BUGCHECKS[c][1]})` : c));
  const hw = codes.some((c) => c === '0x00000124' || c === '0x0000001a');
  add({
    id: 'pc.events.bsod',
    metric: 'pc.events.bsod',
    category: 'pc',
    title: 'Schermate blu',
    value: nBsod ? `${nBsod} in ${days} giorni` : 'nessuna',
    numeric: nBsod,
    severity: nBsod >= 2 ? 'crit' : nBsod ? 'warn' : 'ok',
    verdict: nBsod
      ? `Windows si è arrestato con un errore ${nBsod === 1 ? 'una volta' : `${nBsod} volte`} ${period}, l'ultima ${on(last(bsod), 'il')}.` +
        (named.length ? ` Codic${named.length === 1 ? 'e' : 'i'}: ${named.join('; ')}.` : '')
      : `Nessun arresto con schermata blu ${period}.`,
    actions: nBsod ? (hw ? ['diagnose-bsod', 'check-hardware'] : ['diagnose-bsod']) : [],
  });

  // Errori di disco e file system, con l'unità coinvolta quando l'evento la indica.
  const disks = pc.disks ?? [];
  const diskOf = (e: EventGroup) => {
    const m = /harddisk(\d+)/i.exec(e.detail ?? '');
    return m ? disks.find((d) => d.id === m[1]) : undefined;
  };
  const storage = of('disk-error', 'filesystem', 'disk-retry', 'storage-reset');
  const internal = storage.filter((e) => !isUsb(diskOf(e)));
  const errors = internal.filter((e) => e.kind === 'disk-error' || e.kind === 'filesystem');
  const soft = internal.filter((e) => e.kind === 'disk-retry' || e.kind === 'storage-reset');
  const usbOnly = storage.length > 0 && internal.length === 0;
  const sev: Severity = total(errors) >= 20 ? 'crit' : errors.length ? 'warn' : total(soft) >= 10 ? 'warn' : storage.length ? 'info' : 'ok';
  const describe = (e: EventGroup) => {
    const d = diskOf(e);
    const where = d ? ` (${d.name}${isUsb(d) ? ', USB' : ''})` : /^[a-z]:$/i.test(e.detail ?? '') ? ` (${e.detail!.toUpperCase()})` : '';
    const what: Record<string, [string, string]> = {
      'disk-error': ['errore del disco', 'errori del disco'],
      filesystem: ['danno al file system', 'danni al file system'],
      'disk-retry': ['operazione ripetuta', 'operazioni ripetute'],
      'storage-reset': ['reset del controller per mancata risposta', 'reset del controller per mancata risposta'],
    };
    return `${num(e.count, what[e.kind][0], what[e.kind][1])}${where}`;
  };
  add({
    id: 'pc.events.disk',
    metric: 'pc.events.disk',
    category: 'pc',
    title: 'Errori di disco nel registro',
    value: storage.length ? `${total(storage)} eventi in ${days} giorni` : 'nessuno',
    numeric: total(storage),
    severity: sev,
    verdict: storage.length
      ? `${period.charAt(0).toUpperCase() + period.slice(1)}: ${storage.slice(0, 4).map(describe).join('; ')}${more(storage.length, 4)}.` +
        (usbOnly
          ? ' Riguardano solo unità USB: capita quando si scollegano senza "Rimozione sicura" o con cavi e porte difettosi.'
          : errors.length
            ? ' Errori su un disco interno sono un segnale serio: verifica il disco e tieni aggiornato il backup.'
            : ' Operazioni ripetute e reset indicano un disco che a volte non risponde in tempo: cavo, alimentazione, driver o firmware.')
      : `Nessun errore di disco o di file system ${period}.`,
    actions: sev === 'ok' ? [] : errors.length && !usbOnly ? ['check-disk-errors', 'backup-replace-disk'] : ['check-disk-errors'],
  });

  const fatal = total(of('whea-fatal'));
  const corrected = total(of('whea-corrected'));
  add({
    id: 'pc.events.whea',
    metric: 'pc.events.whea',
    category: 'pc',
    title: 'Errori hardware (WHEA)',
    value: fatal || corrected ? [fatal ? `${fatal} gravi` : '', corrected ? `${corrected} corretti` : ''].filter(Boolean).join(', ') : 'nessuno',
    numeric: fatal + corrected,
    severity: fatal ? 'crit' : corrected >= 10 ? 'warn' : corrected ? 'info' : 'ok',
    verdict: fatal
      ? `Il processore o la scheda madre hanno segnalato ${num(fatal, 'errore hardware grave', 'errori hardware gravi')} ${period}: possibile causa di blocchi e schermate blu.`
      : corrected
        ? `${num(corrected, 'errore hardware corretto', 'errori hardware corretti')} ${period}: l'hardware li ha recuperati da solo. Pochi sono normali su alcune piattaforme; molti indicano un componente (RAM, processore, scheda PCIe) al limite.`
        : `Nessun errore hardware segnalato ${period}.`,
    actions: fatal || corrected >= 10 ? ['check-hardware'] : [],
  });
}

// ---------------------------------------------------------------- Sicurezza

function analyzeSecurity(pc: PcData, now: number, add: Add) {
  const avs = pc.antivirus;
  if (avs) {
    const on = avs.filter((a) => a.enabled);
    const fresh = on.filter((a) => a.upToDate !== false);
    const sev: Severity = !on.length ? 'crit' : !fresh.length ? 'warn' : 'ok';
    const offNames = avs.filter((a) => !a.enabled).map((a) => a.name);
    add({
      id: 'pc.av',
      metric: 'pc.av',
      category: 'security',
      title: 'Antivirus',
      value: on.length ? on.map((a) => a.name).join(', ') : avs.length ? `${avs[0].name}: disattivato` : 'nessuno',
      severity: sev,
      verdict:
        sev === 'crit'
          ? avs.length
            ? 'La protezione antivirus in tempo reale è disattivata: file e allegati non vengono controllati.'
            : 'Nessun antivirus attivo risulta al Centro sicurezza di Windows: file e allegati non vengono controllati.'
          : sev === 'warn'
            ? 'L\'antivirus è attivo ma le definizioni non sono aggiornate: non riconosce le minacce recenti.'
            : 'Protezione in tempo reale attiva e aggiornata.' +
              (offNames.length ? ` ${offNames.join(', ')} risulta disattivato: è normale quando è attivo un altro antivirus.` : ''),
      actions: sev === 'crit' ? ['enable-antivirus'] : sev === 'warn' ? ['update-antivirus'] : [],
    });
  }
  const u = pc.updates;
  const t = u?.lastInstalled ? Date.parse(u.lastInstalled + 'T00:00:00Z') : NaN;
  // Una data nel futuro è un errore di lettura (formato regionale): si ignora.
  if (u?.lastInstalled && !isNaN(t) && t <= now + DAY) {
    const days = Math.max(0, Math.floor((now - t) / DAY));
    const sev: Severity = days > 60 ? 'warn' : days > 35 ? 'info' : 'ok';
    add({
      id: 'pc.updates',
      metric: 'pc.updates',
      category: 'security',
      title: 'Ultimo aggiornamento di Windows',
      value: `${dateIt(u.lastInstalled)} (${days === 0 ? 'oggi' : num(days, 'giorno fa', 'giorni fa')})${u.lastKB ? `, ${u.lastKB}` : ''}`,
      numeric: days,
      severity: sev,
      verdict:
        sev === 'ok'
          ? 'Windows Update installa regolarmente gli aggiornamenti (Microsoft pubblica quelli di sicurezza ogni mese, il secondo martedì).'
          : sev === 'info'
            ? 'L\'ultimo aggiornamento risale a più di un mese fa: controlla Windows Update.'
            : 'Nessun aggiornamento da oltre due mesi: Windows Update potrebbe essere bloccato o disattivato, e il PC resta esposto alle vulnerabilità corrette nel frattempo.',
      actions: sev === 'ok' ? [] : ['update-windows'],
    });
  }
}

// ---------------------------------------------------------------- Batteria, alimentazione, video

const PLAN_LABEL: Record<PlanKind, string> = {
  balanced: 'Bilanciato',
  high: 'Prestazioni elevate',
  saver: 'Risparmio energia',
  ultimate: 'Prestazioni ottimali',
  custom: 'Personalizzato',
};

function analyzePower(pc: PcData, now: number, add: Add) {
  const b = pc.battery;
  if (b?.designMWh && b.fullMWh) {
    const health = Math.min(100, (100 * b.fullMWh) / b.designMWh);
    const sev: Severity = health < 50 ? 'warn' : health < 80 ? 'info' : 'ok';
    add({
      id: 'pc.battery',
      metric: 'pc.battery',
      category: 'pc',
      title: 'Salute della batteria',
      value: `${fmt(health)} % della capacità originale${b.cycles ? `, ${thousands(b.cycles)} cicli` : ''}`,
      numeric: health,
      severity: sev,
      verdict:
        sev === 'ok'
          ? 'La batteria conserva gran parte della capacità originale.'
          : sev === 'info'
            ? `La batteria si è consumata: a piena carica dura circa il ${fmt(health)} % rispetto a quando era nuova. È normale dopo qualche anno.`
            : `La batteria conserva meno della metà della capacità: autonomia molto ridotta e possibili spegnimenti improvvisi sotto carico.`,
      actions: sev === 'ok' ? [] : ['replace-battery'],
    });
  }
  const p = pc.power;
  if (p?.planKind) {
    const onAC = p.onAC !== false;
    const sev: Severity = p.planKind === 'saver' && onAC ? 'warn' : (p.planKind === 'high' || p.planKind === 'ultimate') && p.onAC === false ? 'info' : 'ok';
    add({
      id: 'pc.power',
      metric: 'pc.power',
      category: 'pc',
      title: 'Piano di alimentazione',
      value: `${p.plan || PLAN_LABEL[p.planKind]}${p.hasBattery ? (p.onAC === false ? ' · a batteria' : ' · alimentatore collegato') : ''}${p.batterySaver ? ' · risparmio batteria attivo' : ''}`,
      severity: sev,
      verdict:
        sev === 'warn'
          ? 'Il piano "Risparmio energia" limita il processore anche con l\'alimentazione collegata: il PC è più lento senza un vero vantaggio.'
          : sev === 'info'
            ? 'Piano ad alte prestazioni mentre il PC va a batteria: l\'autonomia si riduce.'
            : p.planKind === 'balanced'
              ? 'Piano bilanciato: il processore accelera quando serve e risparmia quando è inattivo. È la scelta consigliata.'
              : 'Piano di alimentazione adatto all\'uso attuale.',
      actions: sev === 'warn' ? ['power-plan'] : [],
    });
  }
  const gpus = (pc.gpus ?? []).filter((g) => !/remote display|hyper-v|virtual|mirror|indirect display|parsec|citrix|vmware|virtualbox/i.test(g.name));
  if (gpus.length) {
    const basic = gpus.filter((g) => /microsoft basic display|standard vga|vga compatible/i.test(g.name));
    const real = gpus.filter((g) => basic.indexOf(g) < 0);
    const old = real.filter((g) => g.driverDate && now - Date.parse(g.driverDate + 'T00:00:00Z') > 3 * 365 * DAY);
    const sev: Severity = basic.length && !real.length ? 'warn' : old.length ? 'info' : 'ok';
    add({
      id: 'pc.gpu',
      metric: 'pc.gpu',
      category: 'pc',
      title: 'Scheda video e driver',
      value: gpus.map((g) => `${g.name}${g.driverDate ? ` (driver del ${dateIt(g.driverDate)})` : ''}`).join(' · '),
      severity: sev,
      verdict:
        sev === 'warn'
          ? 'Windows usa il driver video di base: niente accelerazione grafica, risoluzione e luminosità limitate, video che scattano. Manca il driver del produttore.'
          : sev === 'info'
            ? `Il driver di ${old.map((g) => g.name).join(', ')} ha più di tre anni: un driver recente corregge problemi di stabilità, consumo e compatibilità.`
            : 'Driver video del produttore installato.',
      actions: sev === 'ok' ? [] : ['update-gpu-driver'],
    });
  }
}

// ---------------------------------------------------------------- Test di velocità

function analyzeBench(pc: PcData, add: Add) {
  const c = pc.bench?.cpu;
  if (c && c.multiMBs > 0) {
    const ratio = c.sustainedMBs / c.multiMBs;
    const scale = c.singleMBs > 0 ? c.multiMBs / c.singleMBs : 0;
    const throttle: Severity = ratio < 0.8 ? 'warn' : ratio < 0.9 ? 'info' : 'ok';
    const poorScale = c.threads >= 4 && scale > 0 && scale < 1.5;
    const sev = worst(throttle, poorScale ? 'warn' : 'ok');
    const v: string[] = [];
    if (throttle === 'ok') v.push(`Prestazioni stabili per tutta la prova: alla fine il processore rende il ${fmt(Math.min(ratio, 1) * 100)} % della punta.`);
    else v.push(`Dopo i primi secondi la velocità cala del ${fmt((1 - ratio) * 100)} %: il processore rallenta per il calore o per i limiti di potenza.`);
    if (poorScale) v.push(`Con ${c.threads} thread va solo ${fmt(scale, 1)} volte più veloce che con uno: qualcosa lo limita (piano di risparmio energia, calore, altri programmi o limiti della macchina virtuale).`);
    else if (scale > 0) v.push(`Con tutti i ${c.threads} thread è ${fmt(scale, 1)} volte più veloce che con uno.`);
    if (c.onAC === false) v.push('Prova eseguita a batteria: molti portatili limitano il processore senza alimentatore.');
    if ((c.loadBeforePct ?? 0) > 25) v.push(`Prima della prova il processore era già occupato al ${fmt(c.loadBeforePct!)} %: i valori possono risultare più bassi.`);
    v.push('I MB/s servono a confrontare il PC con sé stesso nel tempo o con altri PC provati con Polaris, non con i punteggi di altri programmi.');
    const actions: string[] = [];
    if (throttle !== 'ok') actions.push('cool-cpu');
    if (poorScale) actions.push('power-plan', 'close-heavy-apps');
    add({
      id: 'pc.cpubench',
      metric: 'pc.cpubench',
      category: 'pc',
      title: 'Velocità del processore',
      value: `${mbs(c.singleMBs)} su un thread · ${mbs(c.multiMBs)} con ${c.threads}`,
      numeric: c.multiMBs,
      severity: sev,
      verdict: v.join(' '),
      actions,
    });
  }
  for (const b of pc.bench?.disk ?? []) diskBench(pc, b, add);
}

function diskBench(pc: PcData, b: DiskBench, add: Add) {
  const vol = (pc.volumes ?? []).find((v) => v.letter.toUpperCase() === b.drive.toUpperCase());
  const disk = vol?.disk !== undefined ? (pc.disks ?? []).find((d) => d.id === vol.disk) : undefined;
  const nvme = /nvme/i.test(disk?.bus ?? '');
  const removable = vol?.kind === 'removable' || isUsb(disk);
  let sev: Severity = 'ok';
  let expect = '';
  const actions: string[] = [];
  if (removable) {
    sev = b.seqWriteMBs < 10 ? 'info' : 'ok';
    expect =
      sev === 'info'
        ? 'Unità esterna lenta in scrittura (meno di 10 MB/s): tipico delle chiavette economiche o delle porte USB 2.0.'
        : 'Unità esterna: la velocità dipende anche dalla porta USB e dal cavo.';
  } else if (disk && isFlash(disk)) {
    const minSeq = nvme ? 500 : 200;
    if (b.seqReadMBs < minSeq || b.rndReadMBs < 10) {
      sev = 'warn';
      actions.push('check-disk-errors', 'cool-disk');
      if (vol && vol.freeGB / vol.sizeGB < 0.1) actions.unshift('free-disk-space');
    }
    expect = nvme
      ? 'In questa prova un SSD NVMe in salute legge in sequenza indicativamente oltre 1.000 MB/s e in modo casuale 4K oltre 30 MB/s.'
      : 'In questa prova un SSD SATA in salute legge in sequenza indicativamente 400-550 MB/s e in modo casuale 4K oltre 20 MB/s.';
    // Con 8 richieste in coda il limite è l'interfaccia: valori molto bassi
    // indicano un collegamento più lento di quello che il disco supporta.
    const q8 = b.seqQ8ReadMBs;
    if (q8 !== undefined && sev === 'ok') {
      if (nvme && q8 < 1000) {
        sev = 'info';
        expect += ` Con 8 richieste in coda legge solo ${mbs(q8)}: gli NVMe arrivano di solito a 1.500-7.000 MB/s. Può dipendere da uno slot M.2 con meno linee PCIe, da un disco molto caldo o da un modello economico.`;
      } else if (!nvme && q8 < 300) {
        sev = 'info';
        expect += ` Con 8 richieste in coda legge solo ${mbs(q8)}: un SSD SATA arriva a circa 550 MB/s. Valori vicini a 250-280 MB/s indicano una porta SATA a 3 Gbit/s o il controller in modalità IDE invece di AHCI.`;
      }
    }
  } else if (disk?.media === 'hdd') {
    if (b.seqReadMBs < 50 || b.rndReadMBs < 0.2) {
      sev = 'warn';
      actions.push('check-disk-errors');
    }
    actions.push('upgrade-ssd');
    expect =
      'Un disco meccanico legge in sequenza indicativamente 80-250 MB/s, ma in modo casuale 4K solo 0,5-2 MB/s: è questo a renderlo lento con Windows, che legge di continuo piccoli file sparsi.';
  } else {
    expect = 'Tipo di disco non noto: confronta i valori con le prove successive.';
  }
  add({
    id: `pc.diskbench.${b.drive.replace(':', '')}`,
    metric: 'pc.diskbench',
    category: 'pc',
    title: `Velocità del disco (${b.drive})`,
    value:
      b.seqQ8ReadMBs !== undefined
        ? `sequenziale ${mbs(b.seqQ8ReadMBs)} · casuale 4K ${mbs(b.rndReadMBs)}`
        : `lettura ${mbs(b.seqReadMBs)}, scrittura ${mbs(b.seqWriteMBs)} · casuale 4K ${mbs(b.rndReadMBs)}`,
    numeric: b.seqReadMBs,
    severity: sev,
    verdict:
      (sev === 'warn' ? 'Velocità inferiore a quella tipica di questo tipo di unità. ' : '') +
      expect +
      (sev === 'warn' && disk && isFlash(disk) ? ' Cause frequenti: unità quasi piena, surriscaldamento, driver del controller, degrado.' : '') +
      (b.note ? ` ${b.note}` : ''),
    actions: sev === 'warn' ? actions.filter((a, i) => actions.indexOf(a) === i) : [],
  });
}

export function analyzePc(scan: Scan, add: Add) {
  const pc = scan.pc;
  if (!pc) return;
  const now = Date.parse(scan.agent.startedAt) || Date.now();
  analyzeOs(pc, now, add);
  analyzeUptime(pc, add);
  analyzeMemory(pc, add);
  analyzeDisks(scan, pc, add);
  analyzeStartup(pc, add);
  analyzeEvents(pc, add);
  analyzeSecurity(pc, now, add);
  analyzePower(pc, now, add);
  analyzeBench(pc, add);
}
