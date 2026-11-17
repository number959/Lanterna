import { cpuNameClean } from './codenames';
import { fmt, num } from './fmt';
import type { Finding, PcData, PcGpu, Scan, Severity } from './types';

// Requisiti di Windows 11, come Controllo integrità PC: processore, memoria,
// disco, firmware UEFI, Secure Boot, TPM 2.0, scheda video, schermo e le
// istruzioni chieste dalla versione 24H2. Valgono sui PC con Windows 10
// (aggiornabile o no) e su quelli con Windows 11 già installato (hardware
// supportato o no). Ricerca del 17/11/2026, fonti:
// - Microsoft Learn, «Windows 11 requirements» (14/7/2026) e il PDF
//   «Minimum Hardware Requirements for Windows 11» (2021): 1 GHz, 2 core,
//   64 bit; 4 GB; 64 GB; DirectX 12 con driver WDDM 2.0; UEFI, Secure Boot
//   capable; TPM 2.0; schermo 720p oltre 9" con 8 bit per canale (escluso il
//   PC fisso); aggiornamento diretto da Windows 10 2004 o successivo;
// - Configuration Manager, «Manage Windows 11 readiness dashboard»: i motivi
//   di blocco di Windows Update (Tpm, UefiSecureBoot, Memory, CPU, CpuFms,
//   SModeState, SystemDriveSize): conta la dimensione del disco di sistema;
// - support.microsoft.com, «Installing Windows 11 on devices that don't meet
//   minimum system requirements»: questi PC «aren't guaranteed to receive
//   updates, including but not limited to security updates»;
// - POPCNT e SSE4.2 per la 24H2: solo stampa specializzata, nessuna pagina
//   Microsoft letta;
// - elenchi dei processori supportati (21H2, 22H2, 24H2, 25H2): Intel per
//   serie, AMD per modello fino alla 24H2 e per serie nella 25H2, Qualcomm per
//   modello e serie. Le pagine non hanno una licenza che ne permetta la copia:
//   Polaris NON le incorpora. Le regole qui sotto sono scritte dal progetto e
//   ricavate dalle serie (fatti), con quattro esiti onesti e mai un «non
//   supportato» certo; vale anche la regola di Microsoft: «Subsequently
//   released and future generations of processors which meet the same
//   principles will be considered as supported, even if not explicitly
//   listed». L'esito vero lo dà Windows (CpuFms, famiglia, modello e
//   stepping), che non pubblica la sua tabella: per questo c'è Controllo
//   integrità PC. Se l'utente ha fatto leggere l'elenco ufficiale dal suo PC
//   (pc.win11List), un processore nell'elenco è confermato; uno assente
//   resta giudicato con le regole (tabella in win11Cpu), perché l'elenco di
//   una sola versione non comprende tutti i modelli: l'assenza da sola non
//   dà mai «non rispettato».

type Add = (f: Omit<Finding, 'actions'> & { actions?: string[] }) => void;

export type Win11CpuResult = 'listed' | 'newer' | 'notListed' | 'unknown';

export const WIN11_CPU_LABEL: Record<Win11CpuResult, string> = {
  listed: 'nella generazione supportata',
  newer: 'più recente degli elenchi: probabilmente supportato',
  // Mai «non supportato»: lo dice con certezza solo Windows (CpuFms).
  notListed: 'generazione anteriore a quelle elencate',
  unknown: 'da verificare con Controllo integrità PC',
};

/** Etichetta del pulsante che avvia il confronto con l'elenco ufficiale (scheda e azione check-win11-cpu). */
export const WIN11_CHECK_BUTTON = 'Controlla nell\'elenco ufficiale Microsoft';

export interface Win11CpuVerdict {
  result: Win11CpuResult;
  /** Serie o generazione riconosciuta ("Core i5 di 11ª generazione"). */
  series?: string;
  detail: string;
  /** Da dove viene l'esito: elenco ufficiale letto dal PC, regole del progetto, nessuna. */
  source: 'list' | 'rules' | 'none';
}

interface Rule {
  result: Win11CpuResult;
  series?: string;
  note?: string;
}

const listed = (series: string, note?: string): Rule => ({ result: 'listed', series, note });
const newer = (series: string, note?: string): Rule => ({ result: 'newer', series, note });
const notListed = (series: string, note?: string): Rule => ({ result: 'notListed', series, note });
const unknown = (series?: string, note?: string): Rule => ({ result: 'unknown', series, note });

// Criterio unico per le serie tolte dagli elenchi recenti: se la serie è solo
// negli elenchi fino alla 22H2 (Core X 7000X, 9000X e 10000X, Xeon W-2100,
// W-2200 e W-3100, primi Snapdragon) l'esito è «da verificare»; se è ancora
// negli elenchi per modello della 24H2 (Ryzen 2000, EPYC 7002) è «nella
// generazione supportata», con la nota.
const OLD_LISTS = 'presente negli elenchi Microsoft fino alla 22H2, non in quelli successivi';
const MODEL_LISTS = 'negli elenchi per modello fino alla 24H2, non nella 25H2';

function intelRule(n: string): Rule | undefined {
  let m: RegExpExecArray | null;
  if (/\bCore\s*2\b|\bCore\s+(?:Duo|Solo)\b|\bPentium\s+(?:4|D|M|Dual)\b|\bCeleron\s+(?:M|D)\b/i.test(n)) return notListed('processore anteriore ai Core di 2ª generazione');
  if ((m = /\bCore\s*Ultra\s*X?[3579]\s+(\d)\d{2}/i.exec(n))) {
    const s = +m[1];
    return s <= 3 ? listed(`Core Ultra (serie ${s})`) : newer(`Core Ultra (serie ${s})`);
  }
  if (/\bi3-N3\d{2}\b/i.test(n)) return listed('Core i3 serie N300');
  if ((m = /\bi([3579])-(\d{4,5})([A-Z]{0,2}\d?)\b/i.exec(n))) {
    const d = m[2];
    const suf = m[3].toUpperCase();
    const gen = d.length === 5 || d[0] === '1' ? +d.slice(0, 2) : +d[0];
    const series = `Core i${m[1]} di ${gen}ª generazione`;
    if (/^7820HQ$/i.test(d + suf)) return unknown(series, 'Microsoft lo ammette solo su alcuni sistemi indicati per modello');
    // Core X (7000X, 9000X, 10000X): serie solo negli elenchi fino alla 22H2,
    // come gli Xeon W-2100 e W-2200 della stessa generazione.
    if (suf === 'X' || suf === 'XE') return unknown(`Core X serie ${gen}000X`, OLD_LISTS);
    if (gen >= 8 && gen <= 14) return listed(series);
    if (gen > 14) return newer(series);
    return notListed(series);
  }
  if (/\bi[3579][- ](?:M )?\d{3}[A-Z]{0,2}\b/i.test(n)) return notListed('Core di 1ª generazione');
  if (/\bm3-8\d{3}Y\b/i.test(n)) return listed('Core m di 8ª generazione');
  if (/\bm[357]-?\d?Y\d{2}\b|\bCore M\b|\bM-5Y\d{2}\b/i.test(n)) return notListed('Core m di 6ª o 7ª generazione');
  if ((m = /\bCore\s+([3579])\s+(N)?(\d)\d{2}[A-Z]*\b/i.exec(n))) {
    if (m[2]) return newer('Core serie N (Twin Lake)');
    const s = +m[3];
    return s <= 2 ? listed(`Core (serie ${s})`) : newer(`Core (serie ${s})`);
  }
  if (/\bU300E?\b/i.test(n)) return listed('Intel U300');
  if ((m = /\bIntel\s+(?:Processor\s+)?N(\d{2,3})\b/i.exec(n))) {
    const v = +m[1];
    if (v === 100 || v === 200) return listed(`Intel N${v}`);
    if (v === 95 || v === 97) return listed('Intel serie N90', 'attribuzione alla serie N90 fatta da Polaris');
    if (v === 150 || v === 250) return newer(`Intel N${v} (Twin Lake)`);
    return unknown(`Intel N${v}`);
  }
  if (/\bIntel\s+(?:Processor\s+)?300T?\b/i.test(n)) return listed('Intel 300 per desktop');
  if (/\bCeleron\b/i.test(n)) {
    if ((m = /\b([GJN])(\d)\d{3}[A-Z]*\b/i.exec(n))) {
      const l = m[1].toUpperCase();
      const g = +m[2];
      const s = `Celeron ${l}${g}000`;
      if (l === 'G') return g >= 4 ? listed(s) : notListed(s);
      if (l === 'J') return g === 4 ? listed(s) : g >= 6 ? unknown(s) : notListed(s);
      return g === 4 || g === 5 ? listed(s) : g >= 6 ? unknown(s) : notListed(s);
    }
    if ((m = /\b(\d)\d{3}[A-Z]*\b/.exec(n))) {
      const g = +m[1];
      if (g === 3) return unknown('Celeron serie 3000', 'la serie Celeron 3000 comprende anche modelli di 7ª generazione');
      return g >= 4 ? listed(`Celeron serie ${g}000`) : notListed(`Celeron serie ${g}000`);
    }
    return unknown('Celeron');
  }
  if (/\bPentium\b/i.test(n)) {
    if ((m = /\b([JN])(\d)\d{3}\b/i.exec(n))) {
      const l = m[1].toUpperCase();
      const g = +m[2];
      const s = `Pentium ${l}${g}000`;
      if (g === 5) return l === 'J' ? listed(s) : unknown(s, 'la serie Pentium Silver N5000 non compare negli elenchi Microsoft');
      if (g === 6) return l === 'N' ? listed(s) : unknown(s);
      return notListed(s);
    }
    if ((m = /\bG(\d)\d{3}[A-Z]*\b/i.exec(n))) return +m[1] >= 5 ? listed(`Pentium Gold G${m[1]}000`) : notListed(`Pentium G${m[1]}000`);
    if ((m = /\b(\d)\d{3}([UY])\b/i.exec(n))) {
      const g = +m[1];
      if (g === 4) return unknown(`Pentium serie 4000${m[2].toUpperCase()}`, 'la serie Pentium Gold 4000U/4000Y comprende anche modelli di 7ª generazione');
      return g >= 5 ? listed(`Pentium Gold serie ${g}000`) : notListed(`Pentium serie ${g}000`);
    }
    if ((m = /\b([5-8])\d{3}\b/.exec(n))) return listed(`Pentium serie ${m[1]}000`);
    return unknown('Pentium');
  }
  if (/\bAtom\b/i.test(n)) {
    if (/\bx7\d{3}[A-Z]*\b/i.test(n)) return listed('Atom x7000');
    if (/\bx6\d{3}/i.test(n)) return unknown('Atom x6000');
    if (/\bx[57]-[EZ]\d{4}\b|\bZ\d{4}\b|\b[ND]\d{3}\b/i.test(n)) return notListed('Atom anteriore alla serie x7000');
    return unknown('Atom');
  }
  if (/\bXeon\b/i.test(n)) {
    if ((m = /\b(?:Platinum|Gold|Silver|Bronze)\s*(\d)(\d)\d{2}/i.exec(n))) {
      const g = +m[2];
      if (g >= 1 && g <= 5) return listed(`Xeon Scalable di ${g}ª generazione`);
      return newer(`Xeon Scalable (${m[1]}${m[2]}00)`);
    }
    if ((m = /\bw[3579]-(\d)(\d)\d{2}/i.exec(n))) {
      const s = m[1] + m[2];
      return ['24', '25', '34', '35'].indexOf(s) >= 0 ? listed(`Xeon W-${s}00`) : unknown(`Xeon W-${s}00`);
    }
    if ((m = /\bW-(\d{4,5})[A-Z]*\b/i.exec(n))) {
      const d = m[1];
      if (d.length === 5) return d.slice(0, 2) === '10' || d.slice(0, 2) === '11' ? listed(`Xeon W-${d.slice(0, 2)}000M`) : unknown('Xeon W');
      const s = d.slice(0, 2);
      if (['12', '13', '24', '25', '33', '34', '35'].indexOf(s) >= 0) return listed(`Xeon W-${s}00`);
      if (['21', '22', '31'].indexOf(s) >= 0) return unknown(`Xeon W-${s}00`, OLD_LISTS);
      return unknown(`Xeon W-${s}00`);
    }
    if ((m = /\bE-2(\d)\d{2}/i.exec(n))) return +m[1] >= 1 && +m[1] <= 4 ? listed(`Xeon E-2${m[1]}00`) : newer(`Xeon E-2${m[1]}00`);
    if ((m = /\bD-(\d)(\d)\d{2}/i.exec(n))) {
      const s = m[1] + m[2];
      return ['17', '18', '27', '28'].indexOf(s) >= 0 ? listed(`Xeon D-${s}00`) : notListed(`Xeon D-${s}00`);
    }
    if (/\bE[357]-\d{4}/i.test(n)) return notListed('Xeon E3, E5 o E7');
    if (/\b6\d{3}[PE]\b/.test(n)) return newer('Xeon 6');
    if (/\bXeon\s+6\d{2}X?\b/i.test(n)) return listed('Xeon 600 per workstation');
    if (/\b[XLEW]\d{4}\b|\b[357]\d{3}\b/.test(n)) return notListed('Xeon anteriore agli Scalable');
    return unknown('Xeon');
  }
  return undefined;
}

function amdRule(n: string): Rule | undefined {
  let m: RegExpExecArray | null;
  if ((m = /\bEPYC\s*(\d)[0-9A-Z][0-9A-Z](\d)/i.exec(n))) {
    const s = +m[1];
    const g = +m[2];
    const series = `EPYC ${s}00${g}`;
    if (s === 7) return g === 1 ? notListed(series) : g === 2 ? listed(series, MODEL_LISTS) : g === 3 ? listed(series) : newer(series);
    if (s === 9 || s === 4) return g === 4 || g === 5 ? listed(series) : g > 5 ? newer(series) : unknown(series);
    if (s === 8) return g === 4 ? listed(series) : g > 4 ? newer(series) : unknown(series);
    if (s === 3) return g === 1 ? notListed(series) : unknown(series);
    return unknown(series);
  }
  if ((m = /\bThreadripper\s+(?:PRO\s+)?(\d)\d{3}/i.exec(n))) {
    const s = +m[1];
    const series = `Threadripper ${s}000`;
    if (s <= 2) return notListed(series);
    return [3, 5, 7, 9].indexOf(s) >= 0 ? listed(series) : unknown(series);
  }
  if (/\bRyzen\s+(?:AI\s+)?Z[12]\b/i.test(n)) return listed('Ryzen Z1/Z2');
  if ((m = /\bRyzen\s+AI\s+(?:Max\+?\s+)?(?:[3579]\s+)?(?:PRO\s+)?(?:HX\s+)?(\d)\d{2}\b/i.exec(n))) {
    const s = +m[1];
    return s === 3 ? listed('Ryzen AI 300') : s > 3 ? newer(`Ryzen AI ${s}00`) : unknown('Ryzen AI');
  }
  if ((m = /\bRyzen\s+[3579]\s+(?:PRO\s+)?(\d)(\d{3})([A-Z]*)/i.exec(n))) {
    const s = +m[1];
    const suf = m[3].toUpperCase();
    const series = `Ryzen ${s}000`;
    if (s === 1) return notListed(series);
    if (s === 2) return /[GUH]/.test(suf) ? notListed('Ryzen 2000 con grafica integrata') : listed(series, MODEL_LISTS);
    return listed(series);
  }
  if ((m = /\bRyzen\s+[3579]\s+(?:PRO\s+)?([12])\d{2}\b/i.exec(n))) return listed(`Ryzen ${m[1]}00`);
  if (/\bAthlon\b/i.test(n)) {
    if ((m = /\bAthlon\s+(?:(?:Gold|Silver|PRO)\s+)*(\d)(\d{2,3})[A-Z]*\b/i.exec(n))) {
      const g = +m[1];
      if (g === 2 && m[2].length === 2) return notListed('Athlon 200 (Raven Ridge)');
      if (g === 3 || g === 4 || g === 7) return listed(`Athlon ${g}${m[2].length === 2 ? '00' : '000'}`);
    }
    return notListed('Athlon anteriore alla serie 3000');
  }
  if (/\bAMD\s+30[12][05]e\b/i.test(n)) return listed('AMD 3015e/3020e');
  if (/\b(?:A\d{1,2}(?:-PRO)?-\d{4}|FX-\d{4}|E\d?-\d{4})|\bPhenom\b|\bSempron\b|\bOpteron\b|\bTurion\b/i.test(n)) return notListed('processore AMD anteriore ai Ryzen');
  return undefined;
}

function qualcommRule(n: string): Rule | undefined {
  if (!/Snapdragon|Qualcomm|\bX[12][EP]?-\d|\bSQ[123]\b/i.test(n)) return undefined;
  if (/\bX[12][EP]?\b|\bX[12][EP]?-\d|Snapdragon X\b|X Elite|X Plus/i.test(n)) return listed('Snapdragon X');
  if (/\b8cx Gen ?[23]\b|\bSQ[123]\b|\b7c\+ ?Gen ?3\b/i.test(n)) return listed('Snapdragon 8cx Gen 2/3, 7c+ Gen 3 o Microsoft SQ');
  if (/\b8cx\b|\b850\b|\b7c\b|\b8c\b/i.test(n)) return unknown('Snapdragon', OLD_LISTS);
  return unknown('Snapdragon');
}

/** Regole del progetto sul nome commerciale del processore (undefined: nome non riconosciuto). */
export function win11CpuRule(name?: string): Rule | undefined {
  const n = cpuNameClean(name);
  if (!n) return undefined;
  return qualcommRule(n) || (/\bAMD\b|\bRyzen\b|\bEPYC\b|\bAthlon\b/i.test(n) ? amdRule(n) : intelRule(n));
}

/**
 * Processore e generazione supportata, dall'elenco ufficiale letto dal PC
 * (pc.win11List) e dalle regole del progetto. L'elenco è quello OEM di una
 * sola versione (AMD per modello 24H2, Intel e Qualcomm per serie 25H2):
 * «notListed» vuol dire «non è in quell'elenco», mai «non supportato».
 *
 *   elenco      regola                   esito       fonte   requisito
 *   listed      qualsiasi                listed      list    rispettato
 *   notListed   newer                    newer       rules   rispettato
 *   notListed   listed senza nota        listed      rules   rispettato
 *   notListed   listed con nota          unknown     list    da verificare
 *   notListed   notListed                notListed   list    non rispettato
 *   notListed   unknown o nessuna        unknown     list    da verificare
 *   unknown     qualsiasi                (regola)    rules   (dalla regola)
 *   nessuno     nessuna                  unknown     none    da verificare
 *
 * Una regola «listed» senza nota dice che la serie è negli elenchi più
 * recenti (25H2 per serie): l'elenco per modello della 24H2 e quello di una
 * sola versione non comprendono i modelli usciti dopo né quelli dimenticati
 * (Ryzen 9000, Ryzen AI 300, Ryzen 7 8845HS). Una regola con nota (serie
 * solo negli elenchi di versioni precedenti, o negli elenchi per modello)
 * non basta contro l'assenza dal modello: da verificare.
 */
export function win11Cpu(pc: PcData): Win11CpuVerdict {
  const rule = win11CpuRule(pc.cpu && pc.cpu.name);
  const list = pc.win11List;
  // Nel dettaglio basta «da verificare»: il rimando a Controllo integrità PC lo aggiunge la riga del requisito.
  const ruleText = (r: Rule) => `${r.series ? `${r.series}: ` : ''}${r.result === 'unknown' ? 'da verificare' : WIN11_CPU_LABEL[r.result]}${r.note ? ` (${r.note})` : ''}`;
  // Nella demo l'esito è simulato: nessuna pagina letta (la fonte non è un indirizzo).
  const read = list && /^https?:\/\//i.test(list.source || '') ? 'letto su richiesta da questo PC' : 'esito simulato nella demo, nessuna pagina letta';
  if (list && list.result === 'listed')
    return { result: 'listed', series: list.match, source: 'list', detail: `Nell'elenco ufficiale Microsoft dei processori supportati per la versione ${list.version}${list.match ? ` (${list.match})` : ''}, ${read}.` };
  if (list && list.result === 'notListed') {
    const absent = `Non compare nell'elenco ufficiale Microsoft per la versione ${list.version} (${list.kind === 'model' ? 'per modello' : 'per serie'}, ${read})`;
    if (rule && rule.result === 'newer')
      return {
        result: 'newer',
        series: rule.series,
        source: 'rules',
        detail: `${absent}, ma è di una generazione successiva: Microsoft considera supportate anche le generazioni uscite dopo gli elenchi, se rispettano gli stessi principi.`,
      };
    if (rule && rule.result === 'listed' && !rule.note)
      return {
        result: 'listed',
        series: rule.series,
        source: 'rules',
        detail: `${absent}, ma secondo le regole di Polaris è in una serie o generazione degli elenchi Microsoft più recenti: ${ruleText(rule)}. Gli elenchi sono scritti per i PC nuovi, cambiano a ogni versione e non comprendono tutti i modelli.`,
      };
    if (rule && rule.result === 'notListed')
      return {
        result: 'notListed',
        series: rule.series,
        source: 'list',
        detail: `${absent}, e le regole di Polaris lo collocano in una generazione anteriore a quelle elencate${rule.series ? ` (${rule.series})` : ''}.`,
      };
    // Regola incerta, con nota o assente (anche «AMD Eng Sample», «AMD Custom APU»): mai «non rispettato».
    return {
      result: 'unknown',
      series: rule && rule.series,
      source: 'list',
      detail: `${absent}, ma le regole di Polaris non lo escludono${rule ? `: ${ruleText(rule)}` : ''}. Gli elenchi cambiano a ogni versione e non comprendono tutti i modelli: l'assenza da sola non basta per escluderlo.`,
    };
  }
  if (rule)
    return {
      result: rule.result,
      series: rule.series,
      source: 'rules',
      detail: `${ruleText(rule)}. Regole di Polaris ricavate dalle serie degli elenchi Microsoft, che Polaris non incorpora.`,
    };
  return { result: 'unknown', source: 'none', detail: 'Il nome del processore non corrisponde alle regole di Polaris.' };
}

export type Win11Status = 'ok' | 'fail' | 'unknown' | 'na';

export interface Win11Req {
  id: 'cpu' | 'cpu-gen' | 'ram' | 'disk' | 'uefi' | 'secureboot' | 'tpm' | 'gpu' | 'display' | 'instr' | 'appraiser' | 'os';
  label: string;
  status: Win11Status;
  value: string;
  detail?: string;
}

/** Nome breve di ogni requisito, per le frasi dei giudizi. */
const REQ_SHORT: Record<Win11Req['id'], string> = {
  cpu: 'processore a 64 bit con almeno 2 core e 1 GHz',
  'cpu-gen': 'generazione del processore',
  ram: 'almeno 4 GB di RAM',
  disk: 'disco di sistema da 64 GB',
  uefi: 'firmware UEFI',
  secureboot: 'Secure Boot',
  tpm: 'TPM 2.0',
  gpu: 'scheda video con driver WDDM 2.0',
  display: 'schermo integrato',
  instr: 'istruzioni POPCNT e SSE4.2',
  appraiser: 'verdetto di Windows Update',
  os: 'Windows 10 versione 2004 o successiva',
};

export const WIN11_STATUS_LABEL: Record<Win11Status, string> = { ok: 'rispettato', fail: 'non rispettato', unknown: 'da verificare', na: 'non si applica' };

/** Motivi di blocco di Windows Update (Configuration Manager, readiness dashboard), in italiano; chiavi in minuscolo. */
const APPRAISER_REASON: Record<string, string> = {
  cpufms: 'processore non nella generazione approvata',
  cpu: 'meno di 2 core o meno di 1 GHz',
  tpm: 'TPM 2.0 assente',
  uefisecureboot: 'Secure Boot non supportato',
  memory: 'meno di 4 GB di RAM',
  ram: 'meno di 4 GB di RAM',
  systemdrivesize: 'disco di sistema sotto i 64 GB',
  smodestate: 'modalità S',
};

/** Versione del modello dei driver video: 2000 → "2.0", 3100 → "3.1". */
export const wddmText = (w: number) => `${Math.floor(w / 1000)}.${Math.floor((w % 1000) / 100)}`;

const isBasicGpu = (g: PcGpu) => /basic (?:display|render)|hyper-v video|remote display|indirect display/i.test(g.name);

const isWin10 = (pc: PcData) => !!pc.os && /^Windows 10/.test(pc.os.name) && !pc.os.server;
const isWin11 = (pc: PcData) => !!pc.os && /^Windows 11/.test(pc.os.name) && !pc.os.server;

/**
 * Requisiti di Windows 11 per la scheda dell'interfaccia, uno per riga. Vuoto
 * sui server e sui PC che non hanno Windows 10 o 11.
 */
export function win11Requirements(scan: Scan): Win11Req[] {
  const pc = scan.pc;
  if (!pc || !(isWin10(pc) || isWin11(pc))) return [];
  const hw = pc.hardware || {};
  const os = pc.os!;
  const w11 = pc.win11 || {};
  const out: Win11Req[] = [];
  const arch = (os.arch || '').toLowerCase();
  const arm = arch === 'arm64';

  // Processore: 64 bit, 2 core, 1 GHz.
  const cores = (pc.cpu && pc.cpu.cores) || (hw.cpu && hw.cpu.cores);
  const mhz = pc.cpu && pc.cpu.maxMhz;
  const bits64 = arch === 'x64' || arch === 'amd64' || arm;
  const parts = [cores ? num(cores, 'core', 'core') : '', mhz ? `${fmt(mhz / 1000, 1)} GHz` : '', bits64 ? '64 bit' : arch === 'x86' ? 'Windows a 32 bit' : ''].filter(Boolean);
  out.push({
    id: 'cpu',
    label: 'Processore a 64 bit, almeno 2 core e 1 GHz',
    status: (cores !== undefined && cores < 2) || (mhz !== undefined && mhz < 1000) ? 'fail' : bits64 && cores && mhz ? 'ok' : 'unknown',
    value: parts.join(', ') || 'non letto',
    detail: arch === 'x86' ? 'Windows è a 32 bit: il processore può essere comunque a 64 bit, da verificare.' : undefined,
  });

  const cpu = win11Cpu(pc);
  // Da verificare per l'assenza dall'elenco letto: la riga lo dice, con la versione dell'elenco.
  const fromList = cpu.result === 'unknown' && cpu.source === 'list' && pc.win11List ? `non nell'elenco Microsoft ${pc.win11List.version}: da verificare` : '';
  out.push({
    id: 'cpu-gen',
    label: 'Generazione del processore supportata',
    status: cpu.result === 'listed' || cpu.result === 'newer' ? 'ok' : cpu.result === 'notListed' ? 'fail' : 'unknown',
    value: `${cpu.series ? `${cpu.series}, ` : ''}${fromList || WIN11_CPU_LABEL[cpu.result]}`,
    detail: `${cpu.detail} La verifica definitiva è Controllo integrità PC.`,
  });

  // Memoria: 4 GB. La RAM installata (SMBIOS) prima di quella vista da Windows, che esclude la parte riservata.
  const mem = pc.memory;
  if (mem && mem.installedMB) {
    out.push({ id: 'ram', label: 'Memoria di almeno 4 GB', status: mem.installedMB >= 4096 ? 'ok' : 'fail', value: `${fmt(mem.installedMB / 1024, mem.installedMB % 1024 ? 1 : 0)} GB installati` });
  } else if (mem) {
    out.push({
      id: 'ram',
      label: 'Memoria di almeno 4 GB',
      status: mem.totalMB >= 3800 ? 'ok' : mem.totalMB >= 3072 ? 'unknown' : 'fail',
      value: `${fmt(mem.totalMB / 1024, 1)} GB visti da Windows`,
      detail: mem.totalMB < 3800 && mem.totalMB >= 3072 ? 'Una parte della RAM può essere riservata alla grafica integrata: la quantità installata non è stata letta.' : undefined,
    });
  } else out.push({ id: 'ram', label: 'Memoria di almeno 4 GB', status: 'unknown', value: 'non letta' });

  // Disco di sistema: conta la dimensione, non lo spazio libero.
  const sys = (pc.volumes || []).find((v) => v.system);
  out.push({
    id: 'disk',
    label: 'Disco di sistema di almeno 64 GB',
    status: !sys ? 'unknown' : sys.sizeGB >= 64 ? 'ok' : sys.sizeGB >= 55 ? 'unknown' : 'fail',
    value: sys ? `${Math.round(sys.sizeGB)} GB (${sys.letter})` : 'non letto',
    detail: sys && sys.sizeGB < 64 && sys.sizeGB >= 55 ? 'Al limite: Windows misura i dischi in unità binarie, un disco da 64 GB risulta di circa 59 GB.' : undefined,
  });

  out.push({
    id: 'uefi',
    label: 'Firmware UEFI',
    status: hw.firmware === 'uefi' ? 'ok' : hw.firmware === 'bios' ? 'fail' : 'unknown',
    value: hw.firmware === 'uefi' ? 'UEFI' : hw.firmware === 'bios' ? 'BIOS legacy' : 'non letto',
    detail: hw.firmware === 'bios' ? 'Il passaggio a UEFI richiede di convertire il disco (MBR2GPT): con un backup, meglio da un tecnico.' : undefined,
  });

  // Secure Boot: basta che il PC lo supporti; spento, lo si sa solo da amministratore.
  let sb: Win11Req;
  if (hw.firmware === 'bios') sb = { id: 'secureboot', label: 'Secure Boot supportato', status: 'fail', value: 'non disponibile con il BIOS legacy' };
  else if (hw.secureBoot === true) sb = { id: 'secureboot', label: 'Secure Boot supportato', status: 'ok', value: 'attivo' };
  else if (w11.secureBootCapable === true) sb = { id: 'secureboot', label: 'Secure Boot supportato', status: 'ok', value: 'supportato ma spento', detail: 'Va attivato nelle impostazioni del firmware: protegge l\'avvio.' };
  else if (w11.secureBootCapable === false) sb = { id: 'secureboot', label: 'Secure Boot supportato', status: 'fail', value: 'non supportato' };
  else if (hw.secureBoot === false)
    sb = { id: 'secureboot', label: 'Secure Boot supportato', status: 'unknown', value: 'spento: probabilmente attivabile', detail: 'Se il PC lo supporta si sa solo avviando Polaris come amministratore: da verificare nelle impostazioni del firmware.' };
  else sb = { id: 'secureboot', label: 'Secure Boot supportato', status: 'unknown', value: 'non letto' };
  out.push(sb);

  // TPM 2.0: la funzione documentata (Tbsi_GetDeviceInfo) prima dei dispositivi di sicurezza.
  const tpm = w11.tpmVersion !== undefined ? w11.tpmVersion : hw.tpm;
  out.push({
    id: 'tpm',
    label: 'TPM 2.0',
    status: tpm === '2.0' ? 'ok' : tpm === undefined || tpm === '?' ? 'unknown' : 'fail',
    value: tpm === undefined ? 'non letto' : tpm === '' ? 'nessun TPM attivo' : tpm === '?' ? 'versione non riportata' : `TPM ${tpm}`,
    detail: tpm === '' ? 'Molti processori lo integrano (Intel PTT, AMD fTPM) ma spento: si attiva nel firmware.' : undefined,
  });

  // Scheda video: WDDM 2.0 dal driver; DirectX 12 non si verifica (servirebbe caricare il driver video nell'agente).
  const gpus = (pc.gpus || []).filter((g) => !isBasicGpu(g));
  const withWddm = gpus.filter((g) => g.wddm);
  const best = withWddm.reduce((a, g) => Math.max(a, g.wddm || 0), 0);
  out.push({
    id: 'gpu',
    label: 'Scheda video DirectX 12 con driver WDDM 2.0',
    status: best >= 2000 ? 'ok' : withWddm.length ? 'fail' : 'unknown',
    value: best ? `WDDM ${wddmText(best)}` : gpus.length ? 'modello del driver non letto' : (pc.gpus || []).length ? 'solo una scheda video di base' : 'non letta',
    detail: 'DirectX 12 non è verificato da Polaris. Controllo integrità PC non controlla scheda video e schermo.',
  });

  // Schermo: solo quelli integrati; sui PC fissi il requisito non si applica.
  const inner = (hw.displays || []).filter((d) => d.internal);
  const desk = hw.chassis === 'desktop' || hw.chassis === 'workstation' || hw.chassis === 'server';
  if (!inner.length && (desk || (hw.displays || []).length)) {
    out.push({ id: 'display', label: 'Schermo integrato oltre 9 pollici, 720p, 8 bit per colore', status: 'na', value: 'non si applica ai PC fissi e agli schermi esterni' });
  } else if (!inner.length) {
    out.push({ id: 'display', label: 'Schermo integrato oltre 9 pollici, 720p, 8 bit per colore', status: 'unknown', value: 'non letto' });
  } else {
    const d = inner[0];
    // La risoluzione nativa (modalità preferita dichiarata dallo schermo) decide. Senza, quella in
    // uso basta solo per dire «sì»: un portatile duplicato su un proiettore a 800×600 ha un
    // pannello che può arrivare a 1080p, quindi sotto le 720 righe resta da verificare.
    const cur = d.width && d.height ? Math.min(d.width, d.height) : undefined;
    const nat = d.nativeWidth && d.nativeHeight ? Math.min(d.nativeWidth, d.nativeHeight) : undefined;
    const fail = (d.diagonalIn !== undefined && d.diagonalIn < 9) || (nat !== undefined && nat < 720);
    const lowInUse = nat === undefined && cur !== undefined && cur < 720;
    const unsure = d.diagonalIn === undefined || (nat === undefined && cur === undefined) || lowInUse || d.bitsPerColor === undefined || d.bitsPerColor < 8;
    const inUse = d.width && d.height ? `${d.width}×${d.height}` : '';
    const res = nat !== undefined ? `${d.nativeWidth}×${d.nativeHeight}${inUse && inUse !== `${d.nativeWidth}×${d.nativeHeight}` ? ` (in uso ${inUse})` : ''}` : inUse;
    out.push({
      id: 'display',
      label: 'Schermo integrato oltre 9 pollici, 720p, 8 bit per colore',
      status: fail ? 'fail' : unsure ? 'unknown' : 'ok',
      value: [d.diagonalIn ? `${fmt(d.diagonalIn, 1)}"` : '', res, d.bitsPerColor ? `${d.bitsPerColor} bit per colore` : ''].filter(Boolean).join(', ') || 'non letto',
      detail:
        d.bitsPerColor !== undefined && d.bitsPerColor < 8
          ? 'Con meno di 8 bit per colore Microsoft ammette 6 bit con il dithering: da verificare.'
          : nat !== undefined
            ? 'Risoluzione nativa: la modalità preferita che lo schermo dichiara a Windows.'
            : lowInUse
              ? 'La risoluzione letta è quella in uso durante l\'analisi (per esempio con lo schermo duplicato su un proiettore): lo schermo può arrivare a 720p o più, da verificare.'
              : 'La risoluzione è quella in uso durante l\'analisi, non per forza quella massima dello schermo.',
    });
  }

  // POPCNT e SSE4.2: la versione 24H2 non si installa senza (dalla stampa, non da Microsoft).
  const feats = (hw.cpu && hw.cpu.features) || [];
  out.push({
    id: 'instr',
    label: 'Istruzioni POPCNT e SSE4.2 (dalla 24H2)',
    status: arm ? 'na' : !feats.length ? 'unknown' : feats.indexOf('POPCNT') >= 0 && feats.indexOf('SSE4.2') >= 0 ? 'ok' : 'fail',
    value: arm ? 'non si applica ai processori ARM' : !feats.length ? 'non lette' : feats.indexOf('POPCNT') >= 0 && feats.indexOf('SSE4.2') >= 0 ? 'presenti' : 'mancanti',
    detail: arm ? undefined : 'Requisito riportato dalla stampa specializzata, non da una pagina Microsoft.',
  });

  // Indizio: il verdetto che Windows Update ha già calcolato (chiave non documentata).
  const ap = w11.appraiser;
  if (ap && (ap.verdict || (ap.reasons && ap.reasons.length))) {
    // I motivi si cercano senza badare alle maiuscole: la grafia di Windows non è documentata ovunque.
    const reasonText = (r: string) => (Object.prototype.hasOwnProperty.call(APPRAISER_REASON, r.toLowerCase()) ? APPRAISER_REASON[r.toLowerCase()] : r);
    const reasons = (ap.reasons || []).map(reasonText).filter((r, i, a) => a.indexOf(r) === i);
    // Configuration Manager: Orange e Yellow non riguardano l'hardware (app o driver da aggiornare, app da disinstallare).
    const verdict =
      ap.verdict === 'green'
        ? 'aggiornabile'
        : ap.verdict === 'red'
          ? 'bloccato'
          : ap.verdict === 'orange'
            ? 'con avvertenze (app o driver da aggiornare)'
            : ap.verdict === 'yellow'
              ? 'con avvertenze (app da disinstallare)'
              : 'non indicato';
    out.push({
      id: 'appraiser',
      label: 'Verdetto di Windows Update (indizio)',
      status: ap.verdict === 'green' ? 'ok' : ap.verdict === 'red' ? 'fail' : 'unknown',
      value: `${verdict}${ap.target ? ` alla ${ap.target}` : ''}${reasons.length ? `: ${reasons.join(', ')}` : ''}`,
      detail: 'Dal controllo di compatibilità di Windows Update, letto da una chiave del registro che Microsoft non documenta: è un indizio, non una prova.',
    });
  }

  if (isWin10(pc)) {
    const build = os.build;
    out.push({
      id: 'os',
      label: 'Windows 10 versione 2004 o successiva',
      status: build === undefined ? 'unknown' : build >= 19041 ? 'ok' : 'fail',
      value: build === undefined ? 'non letta' : `build ${build}${os.version ? ` (${os.version})` : ''}`,
    });
  }
  return out;
}

/** Giudizio pc.win11: su Windows 10 se il PC è aggiornabile, su Windows 11 se l'hardware è supportato. */
export function analyzeWin11(scan: Scan, add: Add) {
  const pc = scan.pc;
  if (!pc || !pc.hardware) return;
  const reqs = win11Requirements(scan);
  if (!reqs.length) return;
  const core = reqs.filter((r) => r.id !== 'appraiser');
  const fail = core.filter((r) => r.status === 'fail');
  const unsure = core.filter((r) => r.status === 'unknown');
  const ap = reqs.find((r) => r.id === 'appraiser');
  const cpu = reqs.find((r) => r.id === 'cpu-gen')!;
  const hw = pc.hardware;
  const list = (rs: Win11Req[]) => rs.map((r) => `${REQ_SHORT[r.id]} (${r.value})`).join('; ');
  // Schermo e scheda video: requisiti che Microsoft indica, ma che né Windows Update (motivi di
  // blocco: Tpm, UefiSecureBoot, Memory, CPU, CpuFms, SModeState, SystemDriveSize) né Controllo
  // integrità PC controllano. Mancano anche su PC venduti con Windows 11 (console portatili da
  // 7"): solo informazione, mai la frase sugli aggiornamenti non garantiti.
  const soft = fail.filter((r) => r.id === 'display' || r.id === 'gpu');
  const hard = fail.filter((r) => r.id !== 'display' && r.id !== 'gpu');
  const softText = soft.length
    ? `${list(soft)}. ${soft.length > 1 ? 'Sono requisiti' : 'È un requisito'} che Microsoft indica, ma che né Windows Update né Controllo integrità PC controllano, e non ${soft.length > 1 ? 'bloccano' : 'blocca'} gli aggiornamenti.`
    : '';
  const actions: string[] = [];
  if ([...fail, ...unsure].some((r) => r.id === 'tpm' || r.id === 'uefi' || r.id === 'secureboot') || (hw.secureBoot === false && hw.firmware === 'uefi')) actions.push('firmware-security');
  if (cpu.status !== 'ok') actions.push('check-win11-cpu');
  const sb = reqs.find((r) => r.id === 'secureboot');
  const sbOff = sb && sb.status === 'ok' && hw.secureBoot === false ? ' Secure Boot è supportato ma spento: va attivato nel firmware.' : '';
  const apText = ap ? ` Windows Update, come indizio, lo considera ${ap.status === 'ok' ? 'aggiornabile' : ap.status === 'fail' ? 'non aggiornabile' : 'da verificare'}${ap.status === 'fail' && ap.value.indexOf(':') > 0 ? ` (${ap.value.slice(ap.value.indexOf(':') + 2)})` : ''}.` : '';
  const unsureText = unsure.length ? ` Da verificare: ${list(unsure)}.` : '';

  if (isWin10(pc)) {
    actions.push('upgrade-windows');
    const sev: Severity = hard.length ? 'warn' : 'info';
    add({
      id: 'pc.win11',
      metric: 'pc.win11',
      category: 'pc',
      title: 'Requisiti di Windows 11',
      value: fail.length
        ? num(fail.length, 'requisito mancante', 'requisiti mancanti')
        : unsure.length
          ? num(unsure.length, 'requisito da verificare', 'requisiti da verificare')
          : 'aggiornabile secondo i requisiti verificabili',
      severity: sev,
      // Il rimando a Controllo integrità PC è già nel dettaglio del processore: una volta sola.
      verdict:
        (hard.length
          ? `Il PC non rispetta questi requisiti di Windows 11: ${list(hard)}.`
          : soft.length
            ? 'Il PC rispetta i requisiti di Windows 11 che Windows Update controlla.'
            : 'Il PC rispetta i requisiti di Windows 11 verificabili da qui.') +
        (soft.length ? ` Non rispettato: ${softText}` : '') +
        unsureText +
        sbOff +
        apText +
        ` Processore: ${cpu.detail}`,
      actions,
    });
    return;
  }
  // Windows 11 già installato.
  const sev: Severity = hard.length ? 'warn' : soft.length || unsure.length ? 'info' : 'ok';
  add({
    id: 'pc.win11',
    metric: 'pc.win11',
    category: 'pc',
    title: 'Requisiti di Windows 11',
    value: fail.length ? num(fail.length, 'requisito non rispettato', 'requisiti non rispettati') : unsure.length ? num(unsure.length, 'requisito da verificare', 'requisiti da verificare') : 'rispettati',
    severity: sev,
    verdict: hard.length
      ? `Windows 11 è installato su un PC che non rispetta questi requisiti: ${list(hard)}. Secondo Microsoft i PC installati senza i requisiti non hanno garanzia di ricevere aggiornamenti, compresi quelli di sicurezza, e non hanno assistenza; sul desktop può comparire una filigrana.${soft.length ? ` Non rispettato anche: ${softText}` : ''}${unsureText}${sbOff}${apText}`
      : soft.length
        ? `I requisiti che Windows Update controlla sono rispettati. Non rispettato: ${softText}${unsureText}${sbOff}${apText}`
        : unsure.length
          ? `I requisiti verificabili sono rispettati; da verificare: ${list(unsure)}.${sbOff}${apText}`
          : `Il PC rispetta i requisiti di Windows 11 verificabili da qui.${sbOff}`,
    actions: sev === 'ok' ? [] : actions,
  });
}
