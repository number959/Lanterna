import { describe, expect, it } from 'vitest';
import { analyze, chipsetName, chipsetText, documentParts, renderText } from '../src/engine';
import type { Hardware, PciFunc } from '../src/engine';
import { clinicScan } from '../src/demo/clinic';
import { demoScan } from '../src/demo/sample';

// Chipset dagli ID PCI: Intel per modello (datasheet e pci.ids), AMD per
// serie con le ambiguità dichiarate, PCH integrato, macchine virtuali, ARM.

const intel = (device: string, rev?: string): PciFunc => ({ vendor: '8086', device, rev, class: '0601' });
const amd = (...devices: string[]): PciFunc[] => devices.map((device) => ({ vendor: '1022', device }));
const hw = (chipset: PciFunc[], extra: Hardware = {}): Hardware => ({ ...extra, chipset });

describe('chipset Intel', () => {
  it('modello esatto dalle schede tecniche', () => {
    const c = chipsetName(hw([intel('7A06', '11')]));
    expect(c).toEqual({ name: 'Intel B760', detail: 'serie 700, Raptor Lake PCH-S, ID 8086:7A06, rev. 11' });
    expect(chipsetName(hw([intel('7a84')]))?.name).toBe('Intel Z690'); // minuscole dagli hardware ID
    expect(chipsetName(hw([intel('A145')]))?.name).toBe('Intel Z170');
    expect(chipsetName(hw([intel('7F04')]))?.name).toBe('Intel Z890');
    expect(chipsetName(hw([intel('0685')]))?.name).toBe('Intel Z490');
  });

  it('righe solo da pci.ids: da verificare', () => {
    expect(chipsetName(hw([intel('4387')]))).toMatchObject({ name: 'Intel B560', uncertain: true });
    expect(chipsetName(hw([intel('8C50')]))).toMatchObject({ name: 'Intel B85', uncertain: true });
    expect(chipsetName(hw([intel('A1C3')]))).toMatchObject({ name: 'Intel C624', uncertain: true });
  });

  it('PCH integrato nel processore e SoC dei portatili', () => {
    expect(chipsetName(hw([intel('A082', '20')]))).toEqual({ name: 'PCH integrato nel processore', detail: 'Tiger Lake-LP UP3, serie 500 nel package, Tiger Lake, ID 8086:A082, rev. 20' });
    expect(chipsetName(hw([intel('0284')]))?.name).toBe('PCH integrato nel processore');
    expect(chipsetName(hw([intel('7E01')]))).toMatchObject({ name: 'PCH integrato nel processore', uncertain: true });
  });

  it('modello sconosciuto: la serie dall\'intervallo, poi solo l\'ID', () => {
    expect(chipsetName(hw([intel('7A1F')]))).toMatchObject({ name: 'chipset Intel serie 700', uncertain: true });
    expect(chipsetName(hw([intel('1234')]))).toEqual({ name: 'chipset Intel non in tabella', detail: 'ID 8086:1234', uncertain: true });
    expect(chipsetName(hw([{ vendor: '8086', device: '1234', class: '0C05' }]))).toBeUndefined();
  });
});

describe('chipset AMD', () => {
  it('serie 800 prima della regola dei due 43F4', () => {
    expect(chipsetName(hw(amd('790E', '43F4', '43F4', '43FC')))?.name).toBe('serie 800 (X870E, X870 o B850)');
    expect(chipsetName(hw(amd('43FD')))).toMatchObject({ uncertain: true });
  });

  it('serie 600: A620 riconoscibile, B650 o X670 solo come probabilità', () => {
    expect(chipsetName(hw(amd('790E', '43FA')))?.name).toBe('AMD A620');
    expect(chipsetName(hw(amd('43F4', '43F4', '43F7')))).toMatchObject({ name: 'serie 600 (probabilmente X670 o X670E)', uncertain: true });
    expect(chipsetName(hw(amd('43F4', '43F6')))).toMatchObject({ name: 'serie 600 (probabilmente B650 o B650E)', uncertain: true });
    expect(chipsetName(hw(amd('43F7')))?.name).toBe('serie 600 (B650 o X670)');
    expect(chipsetName(hw(amd('43F9')))).toMatchObject({ name: 'serie 600', uncertain: true });
  });

  it('serie 500, X570, 400 e 300', () => {
    expect(chipsetName(hw(amd('43E9', '43EC')))?.name).toBe('AMD A520');
    expect(chipsetName(hw(amd('43E9', '43EE')))?.name).toBe('AMD B550');
    expect(chipsetName(hw(amd('57AD', '149C')))?.name).toBe('AMD X570 (o X570S)');
    // Famiglia 23 modello 0x31: Threadripper 3000 (TRX40) o PRO 3000WX (WRX80, ThinkStation P620): decide lo zoccolo.
    expect(chipsetName(hw(amd('57AD'), { cpu: { vendor: 'AuthenticAMD', family: 23, model: 0x31 } }))).toMatchObject({ name: 'AMD TRX40 o WRX80', uncertain: true });
    expect(chipsetName(hw(amd('57AD'), { cpu: { vendor: 'AuthenticAMD', family: 23, model: 0x31, socket: 'sWRX8' } }))).toMatchObject({ name: 'AMD WRX80', uncertain: true });
    expect(chipsetName(hw(amd('57AD'), { cpu: { vendor: 'AuthenticAMD', family: 23, model: 0x31, socket: 'sTRX4' } }))).toMatchObject({ name: 'AMD TRX40', uncertain: true });
    expect(chipsetName(hw(amd('43C8')))).toMatchObject({ name: 'serie 400 (X470 o B450)', uncertain: true });
    expect(chipsetName(hw(amd('43B8')))?.name).toBe('AMD A320');
    expect(chipsetName(hw(amd('43B9')))?.name).toBe('AMD X370');
    expect(chipsetName(hw(amd('43BA')))?.name).toBe('AMD X399');
    expect(chipsetName(hw(amd('43BB')))).toMatchObject({ name: 'serie 300 (probabilmente B350)', uncertain: true });
  });

  it('solo FCH: nessun chipset separato', () => {
    const c = chipsetName(hw(amd('790E', '790B')));
    expect(c?.name).toBe('nessun chipset separato');
    expect(c?.uncertain).toBeUndefined();
  });
});

describe('chipset: casi particolari', () => {
  it('macchina virtuale: chipset emulato, mai un chipset vero', () => {
    expect(chipsetName(hw([{ vendor: '8086', device: '7192', class: '0600' }, intel('7110')]))?.name).toBe('chipset emulato (macchina virtuale)');
    expect(chipsetName(hw([{ vendor: '1414', device: '5353' }], { vendor: 'Microsoft Corporation', model: 'Virtual Machine' }))?.name).toBe('chipset emulato (macchina virtuale)');
  });

  it('ARM64: nessun chipset separato; senza dati: niente', () => {
    expect(chipsetName({ cpu: { vendor: 'Qualcomm Technologies Inc' } })?.name).toBe('nessun chipset separato');
    expect(chipsetName({})).toBeUndefined();
    expect(chipsetName(undefined)).toBeUndefined();
  });

  it('testo, rapporto e documento delle demo', () => {
    expect(chipsetText({ name: 'Intel Q670', detail: 'serie 600', uncertain: true })).toBe('Intel Q670 · serie 600 · da verificare');
    expect(chipsetText(undefined)).toBe('');
    const home = renderText(demoScan, analyze(demoScan));
    expect(home).toContain('Chipset: PCH integrato nel processore');
    const clinic = documentParts(clinicScan, analyze(clinicScan)).body;
    expect(clinic).toContain('Intel Q670');
  });
});
