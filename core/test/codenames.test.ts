import { describe, expect, it } from 'vitest';
import { codeName, codeNameText, cpuNameClean } from '../src/engine';
import type { HwCpu } from '../src/engine';

// Nome in codice del processore: i casi della ricerca del 17/11/2026, compresi
// quelli ambigui (stesso modello e stepping per prodotti diversi) e i
// processori dei server, come quelli delle macchine della CI su Azure.

const intel = (model: number, stepping?: number): HwCpu => ({ vendor: 'GenuineIntel', family: 6, model, stepping });
const amd = (family: number, model: number, stepping?: number): HwCpu => ({ vendor: 'AuthenticAMD', family, model, stepping });
const nameOf = (cpu: HwCpu, n?: string) => codeName(cpu, n)?.name;

describe('nome in codice: Intel', () => {
  it('i casi del repository e della ricerca', () => {
    expect(codeName(intel(140, 1), '11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz')).toEqual({ name: 'Tiger Lake-U', year: 2020, segment: 'portatili' });
    expect(nameOf(intel(151, 5), '12th Gen Intel(R) Core(TM) i5-12500T')).toBe('Alder Lake-S');
    expect(nameOf(intel(154, 3))).toBe('Alder Lake-P/H');
    expect(nameOf(intel(154, 4))).toBe('Alder Lake-U');
    expect(nameOf(intel(183, 1), '13th Gen Intel(R) Core(TM) i9-13980HX')).toBe('Raptor Lake-HX');
    expect(nameOf(intel(183, 1), 'Intel(R) Core(TM) i7-14700K')).toBe('Raptor Lake-S Refresh');
    expect(nameOf(intel(170, 4), 'Intel(R) Core(TM) Ultra 7 155H')).toBe('Meteor Lake');
    expect(nameOf(intel(189, 1), 'Intel(R) Core(TM) Ultra 7 258V')).toBe('Lunar Lake');
    expect(nameOf(intel(198, 2), 'Intel(R) Core(TM) Ultra 9 285K')).toBe('Arrow Lake-S');
    expect(nameOf(intel(204, 2))).toBe('Panther Lake');
  });

  it('modello 0x8E: decide il numero nel nome, senza nome resta da verificare', () => {
    expect(nameOf(intel(142, 9), 'Intel(R) Core(TM) i5-8200Y CPU @ 1.30GHz')).toBe('Amber Lake-Y');
    expect(nameOf(intel(142, 9), 'Intel(R) Core(TM) i5-7200U CPU @ 2.50GHz')).toBe('Kaby Lake-U');
    expect(nameOf(intel(142, 9), 'Intel(R) Core(TM) m3-7Y30 CPU @ 1.00GHz')).toBe('Kaby Lake-Y');
    expect(codeName(intel(142, 9))).toMatchObject({ name: 'Kaby Lake-U/Y o Amber Lake-Y', uncertain: true });
    expect(nameOf(intel(142, 10), 'Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz')).toBe('Kaby Lake-R');
    expect(nameOf(intel(142, 10), 'Intel(R) Core(TM) i5-8259U CPU @ 2.30GHz')).toBe('Coffee Lake-U');
    expect(nameOf(intel(142, 10), 'Intel(R) Core(TM) i3-8109U CPU @ 3.00GHz')).toBe('Coffee Lake-U');
    expect(nameOf(intel(142, 11), 'Intel(R) Core(TM) i7-8565U CPU @ 1.80GHz')).toBe('Whiskey Lake-U');
    expect(nameOf(intel(142, 12), 'Intel(R) Core(TM) i5-10210U CPU @ 1.60GHz')).toBe('Comet Lake-U');
    expect(nameOf(intel(142, 12), 'Intel(R) Core(TM) i7-10510Y CPU @ 1.20GHz')).toBe('Amber Lake-Y');
    expect(nameOf(intel(142, 12), 'Intel(R) Core(TM) i5-8365U CPU @ 1.60GHz')).toBe('Whiskey Lake-U');
    expect(codeName(intel(142))).toMatchObject({ uncertain: true }); // senza stepping
  });

  it('modello 0x9E: Kaby Lake S/H/G/X e Coffee Lake, con il Refresh della 9ª generazione', () => {
    expect(codeName(intel(158, 9), 'Intel(R) Core(TM) i7-7700HQ CPU @ 2.80GHz')).toMatchObject({ name: 'Kaby Lake-H', segment: 'portatili' });
    expect(codeName(intel(158, 9), 'Intel(R) Core(TM) i7-7700K CPU @ 4.20GHz')).toMatchObject({ name: 'Kaby Lake-S', segment: 'desktop' });
    expect(nameOf(intel(158, 9), 'Intel(R) Core(TM) i7-8809G CPU @ 3.10GHz')).toBe('Kaby Lake-G');
    expect(nameOf(intel(158, 9), 'Intel(R) Xeon(R) CPU E3-1230 v6 @ 3.50GHz')).toBe('Kaby Lake (Xeon E3 v6)');
    expect(nameOf(intel(158, 10), 'Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz')).toBe('Coffee Lake-H');
    expect(nameOf(intel(158, 12), 'Intel(R) Core(TM) i9-9900K CPU @ 3.60GHz')).toBe('Coffee Lake Refresh-S');
    expect(nameOf(intel(158, 13), 'Intel(R) Xeon(R) E-2236 CPU @ 3.40GHz')).toBe('Coffee Lake Refresh (Xeon E)');
    expect(codeName(intel(158))).toMatchObject({ name: 'Kaby Lake o Coffee Lake (famiglia Skylake)', uncertain: true });
  });

  it('serie N: Alder Lake-N e Twin Lake', () => {
    expect(nameOf(intel(190, 0), 'Intel(R) N100')).toBe('Alder Lake-N');
    expect(nameOf(intel(190, 0), 'Intel(R) Core(TM) i3-N305')).toBe('Alder Lake-N');
    expect(nameOf(intel(190, 0), 'Intel(R) N150')).toBe('Twin Lake');
    expect(nameOf(intel(190, 0), 'Intel(R) Core(TM) 3 N355')).toBe('Twin Lake');
  });

  it('Xeon dei server, come le macchine su Azure', () => {
    expect(nameOf(intel(85, 7), 'Intel(R) Xeon(R) Platinum 8272CL CPU @ 2.60GHz')).toBe('Cascade Lake (Xeon Scalable 2ª gen.)');
    expect(nameOf(intel(85, 4), 'Intel(R) Xeon(R) Platinum 8171M CPU @ 2.60GHz')).toBe('Skylake-SP (Xeon Scalable 1ª gen.)');
    expect(nameOf(intel(85, 4), 'Intel(R) Core(TM) i9-7900X CPU @ 3.30GHz')).toBe('Skylake-X');
    expect(nameOf(intel(85, 11))).toBe('Cooper Lake (Xeon Scalable 3ª gen.)');
    expect(codeName(intel(106, 6), 'Intel(R) Xeon(R) Platinum 8370C CPU @ 2.80GHz')).toEqual({ name: 'Ice Lake-SP (Xeon Scalable 3ª gen.)', year: 2021, segment: 'server' });
    expect(nameOf(intel(143, 8), 'Intel(R) Xeon(R) Platinum 8480C')).toBe('Sapphire Rapids (Xeon Scalable 4ª gen.)');
    expect(nameOf(intel(207, 2), 'INTEL(R) XEON(R) PLATINUM 8573C')).toBe('Emerald Rapids (Xeon Scalable 5ª gen.)');
    expect(nameOf(intel(173, 1))).toBe('Granite Rapids (Xeon 6 con core P)');
    expect(nameOf(intel(175, 3))).toBe('Sierra Forest (Xeon 6 con core E)');
    expect(nameOf(intel(79, 1), 'Intel(R) Xeon(R) CPU E5-2673 v4 @ 2.30GHz')).toBe('Broadwell-EP/EX');
    expect(nameOf(intel(63, 2), 'Intel(R) Xeon(R) CPU E5-2673 v3 @ 2.40GHz')).toBe('Haswell-EP/EX');
    expect(nameOf(intel(151, 5), 'Intel(R) Xeon(R) E-2488')).toBe('Catlow (Xeon E)');
  });

  it('modelli non in tabella e righe incerte', () => {
    expect(codeName(intel(0x99, 0))).toBeUndefined();
    expect(codeName({ vendor: 'GenuineIntel' })).toBeUndefined();
    expect(codeName(undefined, 'Intel(R) Core(TM) i5-1135G7')).toBeUndefined();
    expect(codeName({ vendor: 'GenuineIntel', family: 18, model: 1, stepping: 0 })).toMatchObject({ name: 'Nova Lake-S', uncertain: true });
    // Senza il produttore, lo dice il nome.
    expect(nameOf({ family: 6, model: 140, stepping: 1 }, 'Intel(R) Core(TM) i5-1135G7')).toBe('Tiger Lake-U');
  });
});

describe('nome in codice: AMD', () => {
  it('Ryzen per i PC', () => {
    expect(codeName(amd(25, 33, 2), 'AMD Ryzen 7 5800X 8-Core Processor')).toEqual({ name: 'Vermeer', year: 2020, segment: 'desktop' });
    expect(nameOf(amd(23, 8, 2), 'AMD Ryzen 5 2600 Six-Core Processor')).toBe('Pinnacle Ridge');
    expect(nameOf(amd(23, 1, 1), 'AMD Ryzen 7 1700 Eight-Core Processor')).toBe('Summit Ridge');
    expect(nameOf(amd(23, 24, 1), 'AMD Ryzen 5 3500U with Radeon Vega Mobile Gfx')).toBe('Picasso');
    expect(nameOf(amd(23, 113, 0), 'AMD Ryzen 9 3900X 12-Core Processor')).toBe('Matisse');
    expect(nameOf(amd(25, 68, 1), 'AMD Ryzen 7 6800U with Radeon Graphics')).toBe('Rembrandt');
    expect(nameOf(amd(25, 68, 1), 'AMD Ryzen 5 7535HS with Radeon Graphics')).toBe('Rembrandt-R');
    expect(nameOf(amd(25, 80, 0), 'AMD Ryzen 7 5800H with Radeon Graphics')).toBe('Cezanne');
    expect(nameOf(amd(25, 80, 0), 'AMD Ryzen 5 5625U with Radeon Graphics')).toBe('Barcelo');
    expect(nameOf(amd(25, 97, 2), 'AMD Ryzen 9 7950X 16-Core Processor')).toBe('Raphael');
    expect(nameOf(amd(25, 97, 2), 'AMD Ryzen 9 7945HX with Radeon Graphics')).toBe('Dragon Range');
    expect(nameOf(amd(25, 117, 2), 'AMD Ryzen 7 8700G w/ Radeon 780M Graphics')).toBe('Phoenix');
    expect(nameOf(amd(25, 117, 2), 'AMD Ryzen 7 8840U w/ Radeon 780M Graphics')).toBe('Hawk Point');
    expect(codeName(amd(25, 117, 2))).toMatchObject({ name: 'Phoenix o Hawk Point', uncertain: true });
    expect(nameOf(amd(26, 68, 0), 'AMD Ryzen 9 9950X 16-Core Processor')).toBe('Granite Ridge');
    expect(nameOf(amd(26, 36, 0), 'AMD Ryzen AI 9 HX 370 w/ Radeon 890M')).toBe('Strix Point');
    expect(nameOf(amd(26, 112, 0), 'AMD RYZEN AI MAX+ 395 w/ Radeon 8060S')).toBe('Strix Halo');
  });

  it('EPYC e Threadripper, come le macchine della CI su Azure', () => {
    expect(codeName(amd(25, 1, 1), 'AMD EPYC 7763 64-Core Processor')).toEqual({ name: 'Milan (EPYC 7003)', year: 2021, segment: 'server' });
    expect(nameOf(amd(23, 49, 0), 'AMD EPYC 7452 32-Core Processor')).toBe('Rome (EPYC 7002)');
    expect(nameOf(amd(23, 49, 0), 'AMD Ryzen Threadripper 3970X 32-Core Processor')).toBe('Castle Peak (Threadripper 3000)');
    expect(codeName(amd(23, 49, 0))).toMatchObject({ name: 'Rome o Castle Peak', uncertain: true });
    expect(nameOf(amd(23, 1, 2), 'AMD EPYC 7601 32-Core Processor')).toBe('Naples (EPYC 7001)');
    expect(nameOf(amd(25, 17, 1), 'AMD EPYC 9654 96-Core Processor')).toBe('Genoa (EPYC 9004)');
    expect(nameOf(amd(25, 24, 1), 'AMD Ryzen Threadripper 7980X 64-Cores')).toBe('Storm Peak (Threadripper 7000)');
    expect(nameOf(amd(25, 160, 2), 'AMD EPYC 9754 128-Core Processor')).toBe('Bergamo (EPYC 9004 con core Zen 4c)');
    expect(nameOf(amd(26, 2, 1), 'AMD EPYC 9755 128-Core Processor')).toBe('Turin (EPYC 9005)');
    expect(nameOf(amd(26, 17, 0), 'AMD EPYC 9965 192-Core Processor')).toBe('Turin Dense (EPYC 9005 con core Zen 5c)');
    expect(nameOf(amd(25, 97, 2), 'AMD EPYC 4564P 16-Core Processor')).toBe('Raphael (EPYC 4004)');
  });

  it('modello fuori tabella: solo l\'architettura Zen, da verificare', () => {
    expect(codeName(amd(26, 0x50, 0))).toEqual({ name: 'Zen 6, nome in codice non in tabella', uncertain: true });
    expect(codeName(amd(25, 0x2f, 0))).toMatchObject({ name: 'Vermeer' }); // intervallo 20-2F
    expect(codeName(amd(27, 1, 0))).toBeUndefined();
  });
});

describe('nome in codice: Qualcomm (ARM64, dal nome commerciale)', () => {
  it('Snapdragon X e 8cx', () => {
    expect(codeName(undefined, 'Snapdragon(R) X Elite - X1E78100 - Qualcomm(R) Oryon(TM) CPU')).toEqual({ name: 'Snapdragon X Elite (core Oryon)', year: 2024, segment: 'portatili' });
    expect(nameOf({}, 'Snapdragon(R) X Plus - X1P64100 - Qualcomm(R) Oryon(TM) CPU')).toBe('Snapdragon X Plus (core Oryon)');
    expect(nameOf({}, 'Snapdragon (TM) 8cx Gen 3 @ 3.0 GHz')).toBe('Snapdragon 8cx Gen 3');
    expect(nameOf({}, 'Microsoft SQ3 @ 3.0 GHz')).toBe('Snapdragon 8cx Gen 3');
    expect(codeName({}, 'Snapdragon (TM) X2 Elite')?.year).toBeUndefined(); // part number sconosciuto
  });
});

describe('nome in codice: testi', () => {
  it('nome pulito e riga per la scheda tecnica', () => {
    expect(cpuNameClean('Intel(R) Core(TM) i7 CPU         860  @ 2.80GHz')).toBe('Intel Core i7 860');
    expect(cpuNameClean('AMD Ryzen™ 7 5800X®')).toBe('AMD Ryzen 7 5800X');
    expect(codeNameText({ name: 'Tiger Lake-U', year: 2020, segment: 'portatili' })).toBe('Tiger Lake-U (2020, portatili)');
    expect(codeNameText({ name: 'Rome o Castle Peak', year: 2019, uncertain: true })).toBe('Rome o Castle Peak (2019), da verificare');
    expect(codeNameText(undefined)).toBe('');
  });
});
