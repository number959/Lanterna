import { fmt, num, thousands } from './fmt';
import type { Finding, HwCache, HwCpu, HwMemory, HwModule, PcData, Severity } from './types';

// Scheda tecnica del computer, come in CPU-Z: giudizi su memoria (canali e
// velocità), avvio protetto, TPM e requisiti di Windows 11, più le funzioni
// di formattazione usate da interfaccia e rapporto.

type Add = (f: Omit<Finding, 'actions'> & { actions?: string[] }) => void;

/** Produttori di memoria indicati con il codice JEDEC invece che per nome. */
const JEDEC: Record<string, string> = {
  '80CE': 'Samsung',
  CE00: 'Samsung',
  '80AD': 'SK hynix',
  AD00: 'SK hynix',
  '802C': 'Micron',
  '2C00': 'Micron',
  '0198': 'Kingston',
  '9801': 'Kingston',
  '859B': 'Crucial',
  '9B05': 'Crucial',
  '04CD': 'G.Skill',
  CD04: 'G.Skill',
  '029E': 'Corsair',
  '9E02': 'Corsair',
};

/** Nome del produttore di un modulo: i codici JEDEC diventano nomi. */
export function memVendor(v?: string): string {
  if (!v) return '';
  const hex = v.replace(/\s/g, '').toUpperCase();
  if (/^[0-9A-F]{4,16}$/.test(hex)) {
    for (const k of Object.keys(JEDEC)) if (hex.startsWith(k)) return JEDEC[k];
    return '';
  }
  return v;
}

/** Lettera del canale di memoria ricavata dalle etichette dello slot; undefined se non deducibile. */
export function channelOf(m: HwModule): string | undefined {
  for (const s of [m.bank ?? '', m.slot ?? '']) {
    const c = /channel\s*([a-h])\b/i.exec(s) ?? /dimm[\s_-]?([a-h])[\s_-]?\d/i.exec(s) ?? /^dimm\s+([a-h])$/i.exec(s.trim());
    if (c) return c[1].toUpperCase();
  }
  return undefined;
}

export type ChannelMode = 'single' | 'same-channel' | 'multi' | 'soldered' | 'unknown';

/**
 * Configurazione dei canali di memoria. Si giudica solo la memoria a moduli
 * (DIMM, SODIMM): quella saldata (LPDDR) è organizzata dal produttore e
 * Windows la descrive in modi molto diversi.
 */
export function channelMode(mem?: HwMemory): ChannelMode {
  const mods = mem?.modules ?? [];
  if (!mods.length) return 'unknown';
  if (mods.some((m) => !m.form || /^LP/i.test(m.type ?? ''))) return 'soldered';
  if (mods.length === 1) return 'single';
  const ch = mods.map(channelOf);
  if (ch.some((c) => c === undefined)) return 'unknown';
  return new Set(ch).size === 1 ? 'same-channel' : 'multi';
}

/** Core per classe di efficienza: "6 P + 8 E", "8 core". */
export function coreLayout(cpu?: HwCpu): string {
  const cls = cpu?.coreClasses ?? [];
  if (cls.length >= 2) {
    const names = cls.length === 2 ? ['P', 'E'] : ['P', 'E', 'LP-E'];
    return cls.map((n, i) => `${n} ${names[i] ?? `classe ${i + 1}`}`).join(' + ');
  }
  return cpu?.cores ? `${cpu.cores} core` : '';
}

/** KB o MB con i decimali necessari: 48 KB, 1,25 MB, 18 MB. */
function kb(k: number): string {
  if (k < 1024) return `${k} KB`;
  const v = k / 1024;
  return `${fmt(v, v % 1 === 0 ? 0 : (v * 10) % 1 === 0 ? 1 : 2)} MB`;
}
const KIND: Record<HwCache['kind'], string> = { data: 'dati', instruction: 'istruzioni', unified: '' };

/** Riga di una cache come in CPU-Z: "L1 dati: 8 × 48 KB, 12 vie". */
export function cacheText(c: HwCache): string {
  const name = `L${c.level}${KIND[c.kind] ? ` ${KIND[c.kind]}` : ''}`;
  return `${name}: ${c.count > 1 ? `${c.count} × ` : ''}${kb(c.sizeKB)}${c.ways ? `, ${c.ways} vie` : ''}`;
}

/** Modulo in breve: "8 GB DDR4 SODIMM, 3200 MT/s (lavora a 2666)". */
export function moduleText(m: HwModule): string {
  const speed = m.speedMTs ? `, ${m.speedMTs} MT/s${m.configuredMTs && m.configuredMTs !== m.speedMTs ? ` (lavora a ${m.configuredMTs})` : ''}` : '';
  return `${fmt(m.sizeGB, m.sizeGB % 1 ? 1 : 0)} GB${m.type ? ` ${m.type}` : ''}${m.form ? ` ${m.form}` : ''}${speed}`;
}

const VENDOR_NAME: Record<string, string> = { GenuineIntel: 'Intel', AuthenticAMD: 'AMD' };
export const cpuVendor = (v?: string) => (v ? VENDOR_NAME[v] ?? v : '');

export function analyzeHardware(pc: PcData, add: Add) {
  const hw = pc.hardware;
  if (!hw) return;
  const mem = hw.memory;
  const mods = mem?.modules ?? [];

  // Canali di memoria.
  const mode = channelMode(mem);
  if (mode === 'single' || mode === 'same-channel' || mode === 'multi') {
    const free = mem?.slots ? mem.slots - mods.length : undefined;
    const what = mods.map(moduleText);
    let sev: Severity = 'ok';
    let verdict: string;
    if (mode === 'single') {
      if (mem?.slots === 1) {
        verdict = `C'è un solo modulo di memoria (${what[0]}) e il PC ha un solo slot: la RAM lavora in canale singolo per come è costruito il computer.`;
      } else {
        sev = 'info';
        verdict =
          `C'è un solo modulo di memoria (${what[0]}): la RAM lavora in canale singolo, con metà della banda disponibile. ` +
          'Con la grafica integrata la differenza si sente (video, giochi, più schermi); con i programmi d\'ufficio è contenuta. ' +
          (free && free > 0 ? `Aggiungendo un modulo identico in uno ${free === 1 ? 'slot libero' : 'degli slot liberi'} si attiva il dual channel.` : 'Aggiungendo un modulo identico si attiva il dual channel.');
      }
    } else if (mode === 'same-channel') {
      sev = 'warn';
      verdict =
        `I ${mods.length} moduli di memoria risultano sullo stesso canale (${mods.map((m) => m.slot || m.bank).join(', ')}): la RAM lavora in canale singolo. ` +
        'Di solito basta spostare un modulo nello slot del secondo canale indicato dal manuale della scheda madre (per esempio A2 e B2).';
    } else {
      verdict = `Memoria su più canali (${mods.length} moduli): la banda è quella prevista.`;
    }
    add({
      id: 'pc.ram.channel',
      metric: 'pc.ram.channel',
      category: 'pc',
      title: 'Canali della memoria',
      value: mode === 'multi' ? 'dual channel o superiore' : 'canale singolo',
      severity: sev,
      verdict,
      actions: sev === 'ok' ? [] : ['dual-channel'],
    });
  }

  // Velocità della memoria.
  const slow = mods.filter((m) => m.speedMTs && m.configuredMTs && m.configuredMTs < m.speedMTs * 0.9);
  const mixed = new Set(mods.map((m) => `${m.sizeGB}|${m.speedMTs}|${m.part ?? ''}`)).size > 1;
  if (mods.some((m) => m.configuredMTs)) {
    const conf = Math.min(...mods.map((m) => m.configuredMTs || Infinity));
    const rated = Math.min(...mods.map((m) => m.speedMTs || Infinity));
    let verdict =
      slow.length > 0
        ? `La memoria lavora a ${thousands(conf)} MT/s, sotto i ${thousands(rated)} MT/s dichiarati dai moduli. Spesso è il massimo supportato dal processore o dalla scheda madre, e in quel caso è normale; su un PC fisso può dipendere dalle impostazioni della memoria nel BIOS.`
        : `La memoria lavora a ${thousands(conf)} MT/s, la velocità dichiarata dai moduli.`;
    if (mixed) verdict += ' I moduli sono diversi tra loro: lavorano tutti alla velocità del più lento e il dual channel può non attivarsi del tutto.';
    add({
      id: 'pc.ram.speed',
      metric: 'pc.ram.speed',
      category: 'pc',
      title: 'Velocità della memoria',
      value: `${thousands(conf)} MT/s${slow.length ? ` su ${thousands(rated)}` : ''}`,
      numeric: conf,
      severity: slow.length || mixed ? 'info' : 'ok',
      verdict,
    });
  }

  // Avvio protetto (Secure Boot).
  if (hw.firmware === 'bios' || hw.secureBoot !== undefined) {
    const legacy = hw.firmware === 'bios';
    const on = hw.secureBoot === true && !legacy;
    add({
      id: 'pc.secureboot',
      metric: 'pc.secureboot',
      category: 'security',
      title: 'Avvio protetto (Secure Boot)',
      value: legacy ? 'avvio BIOS legacy' : on ? 'attivo' : 'disattivato',
      severity: on ? 'ok' : legacy ? 'info' : 'warn',
      verdict: on
        ? 'Secure Boot è attivo: all\'accensione il firmware avvia solo un sistema firmato, e un malware che prova a caricarsi prima di Windows viene bloccato.'
        : legacy
          ? 'Windows si avvia in modalità BIOS legacy: Secure Boot non è disponibile e Windows 11 richiede l\'avvio UEFI. Il passaggio richiede di convertire il disco (MBR2GPT) e cambiare modalità nel firmware: va fatto con un backup e, se possibile, da un tecnico.'
          : 'Secure Boot è disattivato: all\'accensione il firmware non verifica che il sistema sia autentico, e un malware che si carica prima di Windows (bootkit) non verrebbe bloccato. Si attiva nelle impostazioni del firmware.',
      actions: on ? [] : ['firmware-security'],
    });
  }

  // Chip di sicurezza TPM.
  if (hw.tpm !== undefined) {
    const v = hw.tpm;
    const ok = v === '2.0';
    add({
      id: 'pc.tpm',
      metric: 'pc.tpm',
      category: 'security',
      title: 'Chip di sicurezza (TPM)',
      value: v ? `TPM ${v === '?' ? '' : v}`.trim() : 'non trovato',
      severity: ok ? 'ok' : 'info',
      verdict: ok
        ? 'TPM 2.0 presente: custodisce le chiavi di BitLocker e di Windows Hello ed è uno dei requisiti di Windows 11.'
        : v
          ? `C'è un TPM ${v === '?' ? 'di versione non riportata' : v}: Windows 11 richiede la versione 2.0.`
          : 'Windows non vede alcun TPM. Molti PC dal 2016 in poi lo hanno integrato nel processore (Intel PTT, AMD fTPM) ma disattivato: si attiva nelle impostazioni del firmware.',
      actions: ok ? [] : ['firmware-security'],
    });
  }

  // Requisiti di Windows 11 sui PC ancora con Windows 10.
  const os = pc.os;
  if (os && !os.server && /^Windows 10/.test(os.name)) {
    const sys = (pc.volumes ?? []).find((v) => v.system);
    const feats = hw.cpu?.features;
    const checks: [string, boolean | undefined][] = [
      ['TPM 2.0', hw.tpm === undefined ? undefined : hw.tpm === '2.0'],
      ['avvio UEFI (necessario per Secure Boot)', hw.firmware === undefined ? undefined : hw.firmware === 'uefi'],
      ['almeno 4 GB di RAM', pc.memory ? pc.memory.totalMB >= 3800 : undefined],
      ['almeno 64 GB sul disco di sistema', sys ? sys.sizeGB >= 64 : undefined],
      ['istruzioni POPCNT e SSE4.2 (dalla versione 24H2)', feats?.length ? feats.includes('POPCNT') && feats.includes('SSE4.2') : undefined],
    ];
    const missing = checks.filter(([, ok]) => ok === false).map(([k]) => k);
    const met = checks.filter(([, ok]) => ok === true).map(([k]) => k);
    add({
      id: 'pc.win11',
      metric: 'pc.win11',
      category: 'pc',
      title: 'Requisiti di Windows 11',
      value: missing.length ? `${num(missing.length, 'requisito mancante', 'requisiti mancanti')}` : `${met.length} su ${checks.length} verificati`,
      severity: missing.length ? 'warn' : 'info',
      verdict:
        (missing.length
          ? `Il PC non rispetta questi requisiti di Windows 11: ${missing.join('; ')}.`
          : `Il PC rispetta i requisiti verificabili da qui: ${met.join(', ')}.`) +
        (hw.secureBoot === false && hw.firmware === 'uefi' ? ' Secure Boot va attivato.' : '') +
        ' Resta da verificare il processore, che deve essere nell\'elenco Microsoft (in genere Intel dall\'8ª generazione e AMD Ryzen dalla serie 2000): lo controlla l\'app Controllo integrità PC.',
      actions: missing.some((k) => /TPM|UEFI/.test(k)) ? ['firmware-security', 'upgrade-windows'] : ['upgrade-windows'],
    });
  }
}
