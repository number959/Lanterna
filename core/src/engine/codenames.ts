import type { HwCpu } from './types';

// Nome in codice del processore, come lo mostra CPU-Z: dalla famiglia, dal
// modello e dallo stepping che Windows scrive nel registro (Identifier, in
// decimale: "Intel64 Family 6 Model 140 Stepping 1") e, nei casi ambigui, dal
// nome commerciale (ProcessorNameString). Le tabelle sono del progetto: righe
// scritte a mano a partire da fatti (numeri e nomi) pubblicati nelle fonti
// citate gruppo per gruppo, senza copiare codice né commenti. Gli anni sono
// indicativi (annunci e commenti di libcpuid, non fonti primarie). Ricerca del
// 17/11/2026.
//
// Fonti e licenze:
// - ICSV: Intel Affected Processor List, CSV ufficiale di Intel
//   (github.com/intel/Intel-affected-processor-list, licenza 0BSD), versione
//   del 4/9/2026 e versioni precedenti dello stesso file (marzo 2024, agosto
//   2025), perché Intel toglie le CPU a fine assistenza;
// - SDM4: Intel SDM vol. 4, 335592-093US (settembre 2026), tabella 2-1;
// - LNX: Linux arch/x86/include/asm/intel-family.h e arch/x86/kernel/cpu/amd.c
//   (torvalds/linux al 17/11/2026, GPL-2.0), solo come riscontro di fatti;
// - ILL: illumos-gate usr/src/uts/intel/os/cpuid_subr.c, tabella amd_revmap
//   (CDDL-1.0), solo come riscontro di fatti;
// - LCPU: libcpuid recog_intel.c e recog_amd.c (BSD-2-Clause, Copyright 2008
//   Veselin Georgiev): gli schemi dei nomi commerciali usati per i casi
//   ambigui derivano da lì (avviso in THIRD_PARTY_NOTICES.md);
// - CPUTYPE: Linux arch/arm64/include/asm/cputype.h, per i core Qualcomm.
// Un modello che non è in tabella resta senza nome: mai un nome indovinato.

export interface CodeName {
  /** Nome in codice ("Tiger Lake-U"), o la famiglia se il modello preciso non è in tabella. */
  name: string;
  /** Anno indicativo di uscita. */
  year?: number;
  /** Fascia: portatili, desktop, server... */
  segment?: string;
  /** Riga incerta o caso ambiguo senza un nome commerciale che lo risolva: da verificare. */
  uncertain?: boolean;
}

type Pick = (n: string, cpu: HwCpu) => Partial<CodeName> | undefined;

interface Row {
  /** Famiglia come la scrive Windows (decimale). */
  f: number;
  /** Intervallo dei modelli (decimale, come Windows), estremi compresi. */
  m: [number, number];
  /** Stepping ammessi; assente = tutti. */
  s?: number[];
  name: string;
  year?: number;
  segment?: string;
  uncertain?: boolean;
  /** Caso ambiguo risolto dal nome commerciale. */
  pick?: Pick;
}

const one = (m: number): [number, number] => [m, m];

/** Nome commerciale senza marchi registrati, "CPU", frequenza e spazi doppi. */
export function cpuNameClean(name?: string): string {
  return (name || '')
    .replace(/\((?:R|TM|C)\)|®|™|​/gi, ' ')
    .replace(/\bCPU\b/g, ' ')
    .replace(/@\s*[\d.,]+\s*[GM]Hz/i, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

// Suffissi dei processori Intel per portatili: U, Y, H, HX, HK, HQ, G1-G7, P, V.
const MOBILE = /\d{3,5}(?:HX|HK|HQ|HS|H|U|Y|P|V|G\d)\b/;
const isXeon = (n: string) => /\bXeon\b/i.test(n);
const isCoreX = (n: string) => /\bi[79]-\d{4,5}X[E]?\b/i.test(n);

// ---------------------------------------------------------------- Intel

const INTEL: Row[] = [
  // Prima del 2015 (LNX: SANDYBRIDGE, IVYBRIDGE, HASWELL, BROADWELL).
  { f: 6, m: one(0x2a), name: 'Sandy Bridge', year: 2011, segment: 'desktop e portatili' },
  { f: 6, m: one(0x2d), name: 'Sandy Bridge-E/EP', year: 2011, segment: 'server e workstation' },
  { f: 6, m: one(0x3a), name: 'Ivy Bridge', year: 2012, segment: 'desktop e portatili' },
  { f: 6, m: one(0x3e), name: 'Ivy Bridge-E/EP', year: 2013, segment: 'server e workstation' },
  { f: 6, m: one(0x3c), name: 'Haswell', year: 2013, segment: 'desktop e portatili' },
  { f: 6, m: one(0x45), name: 'Haswell-ULT', year: 2013, segment: 'portatili' },
  { f: 6, m: one(0x46), name: 'Haswell (Crystal Well)', year: 2013, segment: 'desktop e portatili' },
  { f: 6, m: one(0x3d), name: 'Broadwell', year: 2015, segment: 'portatili' },
  { f: 6, m: one(0x47), name: 'Broadwell (H, grafica Iris Pro)', year: 2015, segment: 'desktop e portatili' },
  // Server e fascia alta (ICSV: Haswell Server EP/EX, Broadwell Server, Broadwell DE; LNX).
  {
    f: 6,
    m: one(0x3f),
    name: 'Haswell-EP/EX',
    year: 2014,
    segment: 'server',
    pick: (n) => (/\bi7-5\d{3}/i.test(n) ? { name: 'Haswell-E', segment: 'desktop di fascia alta' } : undefined),
  },
  {
    f: 6,
    m: one(0x4f),
    name: 'Broadwell-EP/EX',
    year: 2016,
    segment: 'server',
    pick: (n) => (/\bi7-6[89]\d{2}/i.test(n) ? { name: 'Broadwell-E', segment: 'desktop di fascia alta' } : undefined),
  },
  { f: 6, m: one(0x56), name: 'Broadwell-DE (Xeon D-1500)', year: 2015, segment: 'server' },
  // Skylake (ICSV 506E3; SDM4; LNX SKYLAKE_L e SKYLAKE).
  { f: 6, m: one(0x4e), name: 'Skylake-U/Y', year: 2015, segment: 'portatili' },
  {
    f: 6,
    m: one(0x5e),
    name: 'Skylake',
    year: 2015,
    segment: 'desktop e portatili',
    pick: (n) => (/\bE3-\d{4}/i.test(n) ? { name: 'Skylake (Xeon E3 v5)', segment: 'server e workstation' } : MOBILE.test(n) ? { name: 'Skylake-H', segment: 'portatili' } : n ? { name: 'Skylake-S', segment: 'desktop' } : undefined),
  },
  // Famiglia Xeon Scalable sul modello 0x55: Skylake-SP (stepping 3-4),
  // Cascade Lake (5-7) e Cooper Lake (11). ICSV 50653, 50654, 50656, 50657,
  // 5065B; LNX (CASCADELAKE_X s:7, COOPERLAKE_X s:11).
  {
    f: 6,
    m: one(0x55),
    s: [0, 1, 2, 3, 4],
    name: 'Skylake-SP (Xeon Scalable 1ª gen.)',
    year: 2017,
    segment: 'server',
    pick: (n) => (isCoreX(n) ? { name: 'Skylake-X', segment: 'desktop di fascia alta' } : /\bW-21\d{2}/i.test(n) ? { name: 'Skylake-W', segment: 'workstation' } : undefined),
  },
  {
    f: 6,
    m: one(0x55),
    s: [5, 6, 7],
    name: 'Cascade Lake (Xeon Scalable 2ª gen.)',
    year: 2019,
    segment: 'server',
    pick: (n) => (isCoreX(n) ? { name: 'Cascade Lake-X', segment: 'desktop di fascia alta' } : /\bW-22\d{2}/i.test(n) ? { name: 'Cascade Lake-W', segment: 'workstation' } : undefined),
  },
  { f: 6, m: one(0x55), s: [10, 11], name: 'Cooper Lake (Xeon Scalable 3ª gen.)', year: 2020, segment: 'server' },
  { f: 6, m: one(0x55), name: 'Skylake-SP o Cascade Lake (Xeon Scalable)', segment: 'server', uncertain: true },
  // Ice Lake (ICSV 706E5, 606A6, 606C1; SDM4; LNX). 0x7D solo in LNX: riga incerta.
  { f: 6, m: one(0x7e), name: 'Ice Lake-U/Y', year: 2019, segment: 'portatili' },
  { f: 6, m: one(0x7d), name: 'Ice Lake', year: 2019, uncertain: true },
  {
    f: 6,
    m: one(0x6a),
    name: 'Ice Lake-SP (Xeon Scalable 3ª gen.)',
    year: 2021,
    segment: 'server',
    pick: (n) => (/\bW-33\d{2}/i.test(n) ? { name: 'Ice Lake-W', segment: 'workstation' } : undefined),
  },
  { f: 6, m: one(0x6c), name: 'Ice Lake-D (Xeon D-1700/2700)', year: 2022, segment: 'server' },
  { f: 6, m: one(0x66), name: 'Cannon Lake-U', year: 2018, segment: 'portatili' },
  // Modello 0x8E: lo stepping non basta (ICSV 806E9, 806EA, 806EB, 806EC e
  // versioni precedenti; LNX AMBERLAKE_L, COFFEELAKE_L, WHISKEYLAKE_L).
  // Decide il numero del modello nel nome, con gli schemi di LCPU.
  {
    f: 6,
    m: one(0x8e),
    s: [9],
    name: 'Kaby Lake-U/Y o Amber Lake-Y',
    year: 2016,
    segment: 'portatili',
    uncertain: true,
    pick: (n) =>
      /\b(?:i[357]|m3)-8\d{3}Y\b/i.test(n)
        ? { name: 'Amber Lake-Y', year: 2018, uncertain: false }
        : /\b(?:i[357]-7\d{3}[UY]|m3-7Y\d{2}|i[357]-7Y\d{2})\b/i.test(n)
          ? { name: n.match(/Y\d{2}\b|\d{4}Y\b/) ? 'Kaby Lake-Y' : 'Kaby Lake-U', uncertain: false }
          : undefined,
  },
  {
    f: 6,
    m: one(0x8e),
    s: [10],
    name: 'Kaby Lake-R o Coffee Lake-U',
    year: 2017,
    segment: 'portatili',
    uncertain: true,
    pick: (n) =>
      /\bi[357]-8\d{2}9U\b|\bi3-8109U\b/i.test(n)
        ? { name: 'Coffee Lake-U', year: 2018, uncertain: false }
        : /\bi[357]-8\d{2}0U\b/i.test(n)
          ? { name: 'Kaby Lake-R', uncertain: false }
          : undefined,
  },
  { f: 6, m: one(0x8e), s: [11], name: 'Whiskey Lake-U', year: 2018, segment: 'portatili' },
  {
    f: 6,
    m: one(0x8e),
    s: [12],
    name: 'Whiskey Lake-U, Comet Lake-U o Amber Lake-Y',
    year: 2019,
    segment: 'portatili',
    uncertain: true,
    pick: (n) =>
      /\b(?:i[357]|m3)-(?:10\d{3}|8\d{3})Y\b/i.test(n)
        ? { name: 'Amber Lake-Y', uncertain: false }
        : /\bi[357]-10\d{3}U\b/i.test(n)
          ? { name: 'Comet Lake-U', uncertain: false }
          : /\bi[357]-8\d{2}5U\b|\b[456]\d{2}5U\b/i.test(n)
            ? { name: 'Whiskey Lake-U', year: 2018, uncertain: false }
            : undefined,
  },
  { f: 6, m: one(0x8e), name: 'Kaby Lake, Coffee Lake, Whiskey Lake o Comet Lake (famiglia Skylake)', segment: 'portatili', uncertain: true },
  // Modello 0x9E (ICSV 906E9, 906EA, 906EB, 906EC, 906ED e versioni
  // precedenti: Kaby Lake S/H/G/X, Coffee Lake S/H; LNX COFFEELAKE s:10-13).
  {
    f: 6,
    m: one(0x9e),
    s: [9],
    name: 'Kaby Lake',
    year: 2017,
    segment: 'desktop e portatili',
    pick: (n) =>
      /\bE3-\d{4}/i.test(n)
        ? { name: 'Kaby Lake (Xeon E3 v6)', segment: 'server e workstation' }
        : /\d{4}G\b/.test(n)
          ? { name: 'Kaby Lake-G', segment: 'portatili' }
          : /\d{4}X\b/.test(n)
            ? { name: 'Kaby Lake-X', segment: 'desktop di fascia alta' }
            : MOBILE.test(n)
              ? { name: 'Kaby Lake-H', segment: 'portatili' }
              : n
                ? { name: 'Kaby Lake-S', segment: 'desktop' }
                : undefined,
  },
  {
    f: 6,
    m: one(0x9e),
    s: [10, 11, 12, 13],
    name: 'Coffee Lake',
    year: 2018,
    segment: 'desktop e portatili',
    pick: (n, c) => {
      const refresh = /\bi[3579]-9\d{3}/i.test(n) || (c.stepping === 13 && /\bE-22\d{2}/i.test(n));
      const base = refresh ? 'Coffee Lake Refresh' : 'Coffee Lake';
      if (isXeon(n)) return { name: `${base} (Xeon E)`, segment: 'server e workstation', year: refresh ? 2019 : 2018 };
      if (MOBILE.test(n)) return { name: `${base}-H`, segment: 'portatili', year: refresh ? 2019 : 2018 };
      return n ? { name: `${base}-S`, segment: 'desktop', year: refresh ? 2018 : 2017 } : undefined;
    },
  },
  { f: 6, m: one(0x9e), name: 'Kaby Lake o Coffee Lake (famiglia Skylake)', uncertain: true },
  // Comet Lake (ICSV A0652, A0653, A0655, A0660, A0661).
  {
    f: 6,
    m: one(0xa5),
    name: 'Comet Lake',
    year: 2020,
    segment: 'desktop e portatili',
    pick: (n, c) => (isXeon(n) ? { name: 'Comet Lake (Xeon W-1200)', segment: 'workstation' } : c.stepping === 2 || MOBILE.test(n) ? { name: 'Comet Lake-H', segment: 'portatili' } : { name: 'Comet Lake-S', segment: 'desktop' }),
  },
  { f: 6, m: one(0xa6), name: 'Comet Lake-U', year: 2019, segment: 'portatili' },
  // Rocket Lake, Tiger Lake, Lakefield (ICSV A0671, 806C1, 806C2, 806D1; SDM4; LNX).
  { f: 6, m: one(0xa7), name: 'Rocket Lake', year: 2021, segment: 'desktop', pick: (n) => (isXeon(n) ? { name: 'Rocket Lake (Xeon)', segment: 'server e workstation' } : undefined) },
  { f: 6, m: one(0x8c), s: [1], name: 'Tiger Lake-U', year: 2020, segment: 'portatili' },
  { f: 6, m: one(0x8c), s: [2], name: 'Tiger Lake-U Refresh / H35', year: 2021, segment: 'portatili' },
  { f: 6, m: one(0x8c), name: 'Tiger Lake-U', year: 2020, segment: 'portatili' },
  { f: 6, m: one(0x8d), name: 'Tiger Lake-H', year: 2021, segment: 'portatili', pick: (n) => (isXeon(n) ? { name: 'Tiger Lake-H (Xeon W-11000M)', segment: 'workstation mobili' } : undefined) },
  { f: 6, m: one(0x8a), name: 'Lakefield', year: 2020, segment: 'portatili', uncertain: true },
  // Alder Lake e Raptor Lake (ICSV 90672, 90675, 906A3, 906A4, B0671,
  // B06A2/3/8, B06F2/5; SDM4; LNX). Gli stessi valori non ibridi con il nome
  // Xeon sono Catlow (Xeon E-2400, server).
  {
    f: 6,
    m: one(0x97),
    name: 'Alder Lake-S',
    year: 2021,
    segment: 'desktop',
    pick: (n) => (isXeon(n) ? { name: 'Catlow (Xeon E)', segment: 'server', year: 2023 } : /\d{4,5}HX\b/.test(n) ? { name: 'Alder Lake-HX', segment: 'portatili', year: 2022 } : undefined),
  },
  { f: 6, m: one(0x9a), s: [3], name: 'Alder Lake-P/H', year: 2022, segment: 'portatili' },
  { f: 6, m: one(0x9a), s: [4], name: 'Alder Lake-U', year: 2022, segment: 'portatili' },
  { f: 6, m: one(0x9a), name: 'Alder Lake-P', year: 2022, segment: 'portatili' },
  {
    f: 6,
    m: one(0xb7),
    name: 'Raptor Lake-S',
    year: 2022,
    segment: 'desktop',
    pick: (n) =>
      isXeon(n)
        ? { name: 'Catlow (Xeon E-2400)', segment: 'server', year: 2023 }
        : /\d{5}HX\b/.test(n)
          ? { name: 'Raptor Lake-HX', segment: 'portatili', year: 2023 }
          : /\bi[3579]-14\d{3}/i.test(n)
            ? { name: 'Raptor Lake-S Refresh', year: 2023 }
            : undefined,
  },
  {
    f: 6,
    m: one(0xba),
    name: 'Raptor Lake-P/H/U',
    year: 2023,
    segment: 'portatili',
    pick: (n) => (/\bCore [357] [12]\d{2}[UH]\b/i.test(n) ? { name: 'Raptor Lake Refresh (Core serie 1-2)', year: 2024 } : undefined),
  },
  { f: 6, m: one(0xbf), name: 'Raptor Lake-S', year: 2023 },
  { f: 6, m: one(0xd7), name: 'Bartlett Lake', year: 2025, segment: 'embedded' },
  // Core Ultra (ICSV A06A4, C0662, C0664, C0652, B0650, B06D1, C06C2/3,
  // D0651; SDM4; LNX). 0xAC e 0xE5 solo in LNX: righe incerte.
  { f: 6, m: one(0xaa), name: 'Meteor Lake', year: 2023, segment: 'portatili' },
  { f: 6, m: one(0xac), name: 'Meteor Lake', year: 2023, uncertain: true },
  { f: 6, m: one(0xc6), name: 'Arrow Lake-S', year: 2024, segment: 'desktop', pick: (n) => (/\d{3}HX\b/.test(n) ? { name: 'Arrow Lake-HX', segment: 'portatili', year: 2025 } : undefined) },
  { f: 6, m: one(0xc5), name: 'Arrow Lake-H', year: 2025, segment: 'portatili' },
  { f: 6, m: one(0xb5), name: 'Arrow Lake-U', year: 2025, segment: 'portatili' },
  { f: 6, m: one(0xbd), name: 'Lunar Lake', year: 2024, segment: 'portatili' },
  { f: 6, m: one(0xcc), name: 'Panther Lake', year: 2026, segment: 'portatili' },
  { f: 6, m: one(0xe5), name: 'Panther Lake', segment: 'embedded', uncertain: true },
  { f: 6, m: one(0xd5), name: 'Wildcat Lake', year: 2026, segment: 'portatili' },
  // Xeon recenti (ICSV 806F5-8, C06F2, A06D1, A06E1, A06F3, B0664, D06D1; LNX).
  { f: 6, m: one(0x8f), name: 'Sapphire Rapids (Xeon Scalable 4ª gen.)', year: 2023, segment: 'server', pick: (n) => (/\bw[3579]-[23]4\d{2}/i.test(n) || /\bW-[23]4\d{2}/i.test(n) ? { name: 'Sapphire Rapids (Xeon W)', segment: 'workstation' } : undefined) },
  { f: 6, m: one(0xcf), name: 'Emerald Rapids (Xeon Scalable 5ª gen.)', year: 2023, segment: 'server' },
  { f: 6, m: one(0xad), name: 'Granite Rapids (Xeon 6 con core P)', year: 2024, segment: 'server' },
  { f: 6, m: one(0xae), name: 'Granite Rapids-D', year: 2025, segment: 'server' },
  { f: 6, m: one(0xaf), name: 'Sierra Forest (Xeon 6 con core E)', year: 2024, segment: 'server' },
  { f: 6, m: one(0xdd), name: 'Clearwater Forest', segment: 'server' },
  { f: 6, m: one(0xb6), name: 'Grand Ridge', segment: 'server' },
  // Atom, Celeron, Pentium Silver, serie N (ICSV 506CA, 706A1, 706A8, 906C0,
  // 90660/1, B06E0, 506F1, 80665; SDM4; LNX ATOM_*).
  { f: 6, m: one(0x37), name: 'Bay Trail', year: 2013, segment: 'tablet e PC economici' },
  { f: 6, m: one(0x4c), name: 'Cherry Trail / Braswell', year: 2015, segment: 'tablet e PC economici' },
  { f: 6, m: one(0x5c), name: 'Apollo Lake', year: 2016, segment: 'PC economici' },
  { f: 6, m: one(0x5f), name: 'Denverton (Atom C3000)', year: 2017, segment: 'server' },
  { f: 6, m: one(0x7a), name: 'Gemini Lake', year: 2017, segment: 'PC economici' },
  { f: 6, m: one(0x9c), name: 'Jasper Lake', year: 2021, segment: 'PC economici' },
  { f: 6, m: one(0x96), name: 'Elkhart Lake', year: 2021, segment: 'embedded' },
  { f: 6, m: one(0x86), name: 'Snow Ridge (Jacobsville)', segment: 'server' },
  {
    f: 6,
    m: one(0xbe),
    name: 'Alder Lake-N',
    year: 2023,
    segment: 'PC economici',
    pick: (n) => (/\bN[12]50\b|\bN3[5-9]\d\b|\bCore 3 N\d{3}\b/i.test(n) && !/\bi3-N3/i.test(n) ? { name: 'Twin Lake', year: 2025 } : undefined),
  },
  // Famiglie nuove solo in LNX (INTEL_NOVALAKE, INTEL_DIAMONDRAPIDS_X): righe incerte.
  { f: 18, m: one(0x01), name: 'Nova Lake-S', segment: 'desktop', uncertain: true },
  { f: 18, m: one(0x03), name: 'Nova Lake-L', segment: 'portatili', uncertain: true },
  { f: 19, m: one(0x01), name: 'Diamond Rapids', segment: 'server', uncertain: true },
];

// ---------------------------------------------------------------- AMD
// Famiglie in decimale come le scrive Windows: 21 = 15h, 22 = 16h, 23 = 17h,
// 25 = 19h, 26 = 1Ah. AMD non pubblica una tabella dei Ryzen: i nomi vengono
// da ILL (sigle di revisione), LCPU e Linux (amd.c, k10temp.c); dove lo stesso
// modello vale per più prodotti decide il nome commerciale.

const has = (re: RegExp) => (n: string) => re.test(n);
const EPYC = has(/\bEPYC\b/i);
const TR = has(/\bThreadripper\b/i);

const AMD: Row[] = [
  // 15h e 16h (ILL: OR, TN, KV, CZ, ST, KB, ML).
  { f: 21, m: [0x00, 0x0f], name: 'Bulldozer/Piledriver (Orochi)', year: 2011, segment: 'desktop e server' },
  { f: 21, m: [0x10, 0x1f], name: 'Trinity/Richland', year: 2012, segment: 'desktop e portatili' },
  { f: 21, m: [0x30, 0x3f], name: 'Kaveri/Godavari', year: 2014, segment: 'desktop e portatili' },
  { f: 21, m: [0x60, 0x6f], name: 'Carrizo/Bristol Ridge', year: 2015, segment: 'desktop e portatili' },
  { f: 21, m: [0x70, 0x7f], name: 'Stoney Ridge', year: 2016, segment: 'portatili' },
  { f: 22, m: [0x00, 0x0f], name: 'Kabini', year: 2013, segment: 'portatili e PC economici' },
  { f: 22, m: [0x30, 0x3f], name: 'Beema/Mullins', year: 2014, segment: 'portatili e PC economici' },
  // 17h, Zen, Zen+ e Zen 2 (ILL ZP, PiR, RV, PCO, RV2X, SSP, RN, LCN, MTS; LCPU; k10temp).
  {
    f: 23,
    m: one(0x01),
    name: 'Summit Ridge',
    year: 2017,
    segment: 'desktop',
    pick: (n) => (EPYC(n) ? { name: 'Naples (EPYC 7001)', segment: 'server' } : TR(n) ? { name: 'Whitehaven (Threadripper 1000)', segment: 'desktop di fascia alta' } : undefined),
  },
  { f: 23, m: one(0x08), name: 'Pinnacle Ridge', year: 2018, segment: 'desktop', pick: (n) => (TR(n) ? { name: 'Colfax (Threadripper 2000)', segment: 'desktop di fascia alta' } : undefined) },
  { f: 23, m: one(0x11), name: 'Raven Ridge', year: 2018, segment: 'desktop e portatili' },
  { f: 23, m: one(0x18), name: 'Picasso', year: 2019, segment: 'desktop e portatili' },
  { f: 23, m: one(0x20), name: 'Dali', year: 2020, segment: 'portatili economici' },
  {
    f: 23,
    m: one(0x31),
    name: 'Rome o Castle Peak',
    year: 2019,
    uncertain: true,
    pick: (n) => (EPYC(n) ? { name: 'Rome (EPYC 7002)', segment: 'server', uncertain: false } : TR(n) ? { name: 'Castle Peak (Threadripper 3000)', segment: 'desktop di fascia alta', uncertain: false } : undefined),
  },
  { f: 23, m: one(0x60), name: 'Renoir', year: 2020, segment: 'desktop e portatili' },
  { f: 23, m: one(0x68), name: 'Lucienne', year: 2021, segment: 'portatili' },
  { f: 23, m: one(0x71), name: 'Matisse', year: 2019, segment: 'desktop' },
  { f: 23, m: [0x90, 0x91], name: 'Van Gogh', year: 2022, segment: 'console portatili' },
  { f: 23, m: one(0xa0), name: 'Mendocino', year: 2022, segment: 'portatili' },
  // 19h, Zen 3 e Zen 4 (ILL GN, RS, VMR, RMB, CZN, RPL, PHX, PHX2, HPT2, RSDN; LCPU; k10temp; Linux amd.c).
  {
    f: 25,
    m: [0x00, 0x0f],
    name: 'Milan (EPYC 7003)',
    year: 2021,
    segment: 'server',
    pick: (n, c) => (c.model === 0x08 && TR(n) ? { name: 'Chagall (Threadripper PRO 5000)', year: 2022, segment: 'workstation' } : undefined),
  },
  {
    f: 25,
    m: [0x10, 0x1f],
    name: 'Genoa (EPYC 9004)',
    year: 2022,
    segment: 'server',
    pick: (n, c) => (c.model === 0x18 && TR(n) ? { name: 'Storm Peak (Threadripper 7000)', year: 2023, segment: 'desktop di fascia alta e workstation' } : undefined),
  },
  { f: 25, m: [0x20, 0x2f], name: 'Vermeer', year: 2020, segment: 'desktop' },
  { f: 25, m: [0x40, 0x4f], name: 'Rembrandt', year: 2022, segment: 'portatili', pick: (n) => (/\b7\d35[HU]/i.test(n) ? { name: 'Rembrandt-R', year: 2023 } : undefined) },
  {
    f: 25,
    m: [0x50, 0x5f],
    name: 'Cezanne',
    year: 2021,
    segment: 'desktop e portatili',
    pick: (n) => (/\b5\d25U\b/i.test(n) ? { name: 'Barcelo', year: 2022, segment: 'portatili' } : /\b7\d30U\b/i.test(n) ? { name: 'Barcelo-R', year: 2023, segment: 'portatili', uncertain: true } : undefined),
  },
  {
    f: 25,
    m: [0x60, 0x6f],
    name: 'Raphael',
    year: 2022,
    segment: 'desktop',
    pick: (n) => (/\b7\d45HX/i.test(n) ? { name: 'Dragon Range', year: 2023, segment: 'portatili' } : EPYC(n) ? { name: 'Raphael (EPYC 4004)', year: 2024, segment: 'server' } : undefined),
  },
  { f: 25, m: one(0x74), name: 'Phoenix', year: 2023, segment: 'portatili' },
  {
    f: 25,
    m: one(0x75),
    name: 'Phoenix o Hawk Point',
    year: 2024,
    uncertain: true,
    pick: (n) => (/\b8\d00(?:G|GE|F)\b/i.test(n) ? { name: 'Phoenix', segment: 'desktop', uncertain: false } : /\b8\d4[05](?:U|H|HS)\b/i.test(n) ? { name: 'Hawk Point', segment: 'portatili', uncertain: false } : undefined),
  },
  { f: 25, m: one(0x78), name: 'Phoenix 2', year: 2023, segment: 'portatili' },
  { f: 25, m: one(0x7c), name: 'Hawk Point 2', year: 2024, segment: 'portatili', uncertain: true },
  {
    f: 25,
    m: [0xa0, 0xaf],
    name: 'Bergamo (EPYC 9004 con core Zen 4c)',
    year: 2023,
    segment: 'server',
    pick: (n) => (/\bEPYC 8\d{2}4/i.test(n) ? { name: 'Siena (EPYC 8004)', uncertain: true } : undefined),
  },
  // 1Ah, Zen 5 (ILL BRH, BRHD, SHP, STX, GNR, KRK, KRK2, STXH; LCPU).
  {
    f: 26,
    m: [0x00, 0x0f],
    name: 'Turin (EPYC 9005)',
    year: 2024,
    segment: 'server',
    pick: (n, c) => (c.model === 0x08 && TR(n) ? { name: 'Shimada Peak (Threadripper 9000)', year: 2025, segment: 'desktop di fascia alta e workstation' } : undefined),
  },
  { f: 26, m: [0x10, 0x1f], name: 'Turin Dense (EPYC 9005 con core Zen 5c)', year: 2024, segment: 'server' },
  { f: 26, m: [0x20, 0x2f], name: 'Strix Point', year: 2024, segment: 'portatili' },
  {
    f: 26,
    m: [0x40, 0x4f],
    name: 'Granite Ridge',
    year: 2024,
    segment: 'desktop',
    pick: (n) => (/\b9\d55HX/i.test(n) ? { name: 'Fire Range', year: 2025, segment: 'portatili', uncertain: true } : EPYC(n) ? { name: 'Granite Ridge (EPYC 4005)', year: 2025, segment: 'server' } : undefined),
  },
  { f: 26, m: one(0x68), name: 'Krackan Point 2', year: 2025, segment: 'portatili', uncertain: true },
  { f: 26, m: [0x60, 0x6f], name: 'Krackan Point', year: 2025, segment: 'portatili' },
  { f: 26, m: [0x70, 0x77], name: 'Strix Halo', year: 2025, segment: 'portatili e mini PC' },
];

/** Architettura Zen per intervallo di modelli (Linux amd.c), quando il modello preciso non è in tabella. */
function zenOf(f: number, m: number): string | undefined {
  const inR = (lo: number, hi: number) => m >= lo && m <= hi;
  if (f === 23) {
    if (inR(0x00, 0x2f) || inR(0x50, 0x5f)) return 'Zen';
    if (inR(0x30, 0x4f) || inR(0x60, 0x7f) || inR(0x90, 0x91) || inR(0xa0, 0xaf)) return 'Zen 2';
  }
  if (f === 25) {
    if (inR(0x00, 0x0f) || inR(0x20, 0x5f)) return 'Zen 3';
    if (inR(0x10, 0x1f) || inR(0x60, 0xaf)) return 'Zen 4';
  }
  if (f === 26) {
    if (inR(0x00, 0x2f) || inR(0x40, 0x4f) || inR(0x60, 0x7f) || inR(0xd0, 0xd7)) return 'Zen 5';
    if (inR(0x50, 0x5f) || inR(0x80, 0xaf) || inR(0xc0, 0xcf) || inR(0xd8, 0xef)) return 'Zen 6';
  }
  return undefined;
}

// ---------------------------------------------------------------- Qualcomm
// Su Windows ARM64 il registro non dà famiglia e modello nel formato x86:
// decide il nome commerciale (CPUTYPE: core Oryon = implementatore 0x51, part
// 0x001; nomi X1E/X1P/X1 dagli elenchi Microsoft dei processori Qualcomm e
// dalle pagine Qualcomm). Snapdragon X2 non compare in CPUTYPE: senza anno.

const QUALCOMM: { re: RegExp; c: CodeName }[] = [
  { re: /\bX2E\b|X2 Elite/i, c: { name: 'Snapdragon X2 Elite (core Oryon)', segment: 'portatili' } },
  { re: /\bX2P\b|X2 Plus/i, c: { name: 'Snapdragon X2 Plus (core Oryon)', segment: 'portatili' } },
  { re: /\bX1E-?\d{2}-?\d{3}\b|X Elite/i, c: { name: 'Snapdragon X Elite (core Oryon)', year: 2024, segment: 'portatili' } },
  { re: /\bX1P-?\d{2}-?\d{3}\b|X Plus/i, c: { name: 'Snapdragon X Plus (core Oryon)', year: 2024, segment: 'portatili' } },
  { re: /\bX1-?26-?100\b|Snapdragon X\b/i, c: { name: 'Snapdragon X (core Oryon)', year: 2024, segment: 'portatili' } },
  { re: /\b8cx Gen ?3\b|\bSQ3\b/i, c: { name: 'Snapdragon 8cx Gen 3', year: 2022, segment: 'portatili' } },
  { re: /\b8cx Gen ?2\b|\bSQ2\b/i, c: { name: 'Snapdragon 8cx Gen 2', year: 2020, segment: 'portatili' } },
  { re: /\b8cx\b|\bSQ1\b/i, c: { name: 'Snapdragon 8cx', year: 2019, segment: 'portatili' } },
  { re: /\b7c\+? ?Gen ?3\b/i, c: { name: 'Snapdragon 7c+ Gen 3', year: 2022, segment: 'portatili economici' } },
  { re: /\b7c\b/i, c: { name: 'Snapdragon 7c', year: 2019, segment: 'portatili economici' } },
];

function fromRows(rows: Row[], f: number, m: number, s: number | undefined, n: string, cpu: HwCpu): CodeName | undefined {
  for (const r of rows) {
    if (r.f !== f || m < r.m[0] || m > r.m[1]) continue;
    if (r.s && (s === undefined || r.s.indexOf(s) < 0)) continue;
    const out: CodeName = { name: r.name };
    if (r.year) out.year = r.year;
    if (r.segment) out.segment = r.segment;
    if (r.uncertain) out.uncertain = true;
    const p = r.pick && n ? r.pick(n, cpu) : undefined;
    if (p) {
      if (p.name) out.name = p.name;
      if (p.year) out.year = p.year;
      if (p.segment) out.segment = p.segment;
      if (p.uncertain !== undefined) out.uncertain = p.uncertain;
    }
    if (!out.uncertain) delete out.uncertain;
    return out;
  }
  return undefined;
}

/**
 * Nome in codice del processore. `name` è il nome commerciale (pc.cpu.name)
 * e serve per i casi ambigui; senza, quei casi restano "da verificare".
 * undefined se il processore non è in tabella.
 */
export function codeName(cpu: HwCpu | undefined, name?: string): CodeName | undefined {
  const n = cpuNameClean(name);
  // ARM64 (Snapdragon): solo dal nome commerciale.
  if (/Snapdragon|Qualcomm|\bX1[EP]?-\d|\bX2[EP]\b|\bSQ[123]\b/i.test(n)) {
    for (const q of QUALCOMM) if (q.re.test(n)) return { ...q.c };
    return undefined;
  }
  if (!cpu || cpu.family === undefined || cpu.model === undefined) return undefined;
  const vendor = cpu.vendor || (/\bIntel\b/i.test(n) ? 'GenuineIntel' : /\bAMD\b/i.test(n) ? 'AuthenticAMD' : '');
  const f = cpu.family;
  const m = cpu.model;
  if (vendor === 'GenuineIntel') return fromRows(INTEL, f, m, cpu.stepping, n, cpu);
  if (vendor === 'AuthenticAMD') {
    const r = fromRows(AMD, f, m, cpu.stepping, n, cpu);
    if (r) return r;
    const zen = zenOf(f, m);
    return zen ? { name: `${zen}, nome in codice non in tabella`, uncertain: true } : undefined;
  }
  return undefined;
}

/** Riga per scheda tecnica, rapporto e documento: "Tiger Lake-U (2020, portatili)". */
export function codeNameText(c?: CodeName): string {
  if (!c) return '';
  const extra = [c.year ? String(c.year) : '', c.segment || ''].filter(Boolean).join(', ');
  return `${c.name}${extra ? ` (${extra})` : ''}${c.uncertain ? ', da verificare' : ''}`;
}
