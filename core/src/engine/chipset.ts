import type { Hardware, PciFunc } from './types';

// Nome del chipset dagli ID PCI che l'agente esporta (solo produttore,
// dispositivo, revisione e classe: mai l'ID d'istanza). Tabelle del progetto,
// scritte a mano da fatti pubblicati; ricerca del 17/11/2026.
//
// Intel: il dato giusto è il Device ID della funzione PCH D31:F0 (controller
// LPC/eSPI, classe 0601). Fonti, per serie: datasheet Intel 332690-007EN
// (serie 100), 335192-003 (200), 337347-009 (300), 620854 rev. 003 (400),
// 648364 rev. 005 (600), 743835 rev. 005 (700, EDC), 833778 rev. 003 (800),
// 332995-004EN, 337867-006, 615170-001, 631119-007 e 763122 rev. 001 (PCH
// nel package del processore). Le righe senza datasheet vengono da pci.ids
// (versione 2026.11.16, BSD-3-Clause, Copyright Martin Mares e Albert Pool:
// avviso in THIRD_PARTY_NOTICES.md) e sono segnate come da verificare.
//
// AMD non pubblica i datasheet dei chipset. Il bridge FCH (1022:790E, SMBus
// 790B) sta nel processore e non identifica nulla; il chipset separato delle
// schede AM4/AM5 (Promontory) si riconosce solo per serie dai suoi ID USB,
// SATA e bridge (pci.ids 2026.11.16; Linux xhci-pci.c per 43B9-43BC). La «E»
// di X670E/B650E/X870E non si distingue mai; per la serie 800 gli ID si
// controllano prima della regola dei due 43F4 della serie 600.

export interface ChipsetName {
  /** "Intel Z790", "PCH integrato nel processore", "serie 600 (B650 o X670)". */
  name: string;
  /** Serie, famiglia del PCH e ID PCI. */
  detail?: string;
  /** Riga solo da pci.ids, serie riconosciuta per intervallo o modello non distinguibile: da verificare. */
  uncertain?: boolean;
}

type Kind = 'pch' | 'onpkg' | 'soc';

interface IntelRow {
  /** Nome del chipset ("Z790") o della piattaforma per i PCH integrati. */
  name: string;
  serie: string;
  kind: Kind;
  /** Solo pci.ids, nessun datasheet letto. */
  ids?: boolean;
}

const pch = (serie: string, list: string, ids?: boolean): Record<string, IntelRow> => {
  const out: Record<string, IntelRow> = {};
  for (const pair of list.split(' ')) {
    const [dev, name] = pair.split('=');
    out[dev] = { name, serie, kind: 'pch', ids };
  }
  return out;
};

const INTEL: Record<string, IntelRow> = {
  // Serie 6-9 (2011-2014): solo pci.ids.
  ...pch('serie 6, Cougar Point', '1C44=Z68 1C46=P67 1C4A=H67 1C4C=Q65 1C4E=Q67 1C50=B65 1C5C=H61 1C49=HM65 1C4B=HM67 1C4F=QM67 1C47=UM67 1C4D=QS67 1C52=C202 1C54=C204 1C56=C206', true),
  ...pch('serie 7, Panther Point', '1E44=Z77 1E46=Z75 1E47=Q77 1E48=Q75 1E49=B75 1E4A=H77 1E53=C216 1E55=QM77 1E56=QS77 1E57=HM77 1E59=HM76 1E5D=HM75 1E5E=HM70 1E5F=NM70', true),
  ...pch('serie 8, Lynx Point', '8C44=Z87 8C46=Z85 8C4A=H87 8C4C=Q85 8C4E=Q87 8C50=B85 8C5C=H81 8C49=HM86 8C4B=HM87 8C4F=QM87 8C52=C222 8C54=C224 8C56=C226', true),
  ...pch('serie 9, Wildcat Point', '8CC3=HM97 8CC4=Z97 8CC5=QM97 8CC6=H97', true),
  // Serie 100 (Sunrise Point-H): Intel 332690-007EN, tabella 2-1.
  ...pch('serie 100, Sunrise Point-H', 'A143=H110 A144=H170 A145=Z170 A146=Q170 A147=Q150 A148=B150 A149=C236 A14A=C232 A14D=QM170 A14E=HM170 A150=CM236 A152=HM175 A153=QM175 A154=CM238'),
  // Serie 200: Intel 335192-003; C422 solo pci.ids.
  ...pch('serie 200, Union Point', 'A2C4=H270 A2C5=Z270 A2C6=Q270 A2C7=Q250 A2C8=B250 A2C9=Z370 A2D2=X299'),
  ...pch('serie 200, Union Point', 'A2D3=C422', true),
  // Serie 300 (Cannon Point-H): Intel 337347-009, tabella 2-1; Q360 solo pci.ids.
  ...pch('serie 300, Cannon Point-H', 'A303=H310 A304=H370 A305=Z390 A306=Q370 A308=B360 A309=C246 A30A=C242 A30C=QM370 A30D=HM370 A30E=CM246'),
  ...pch('serie 300, Cannon Point-H', 'A307=Q360', true),
  // Serie 400 (Comet Lake PCH-H): Intel 620854 rev. 003, tabella 7; B460 e H410 (Comet Lake-V) solo pci.ids.
  ...pch('serie 400, Comet Lake PCH-H', '0684=H470 0685=Z490 0687=Q470 068C=QM480 068D=HM470 068E=WM490 0697=W480'),
  ...pch('serie 400, Comet Lake PCH-V', 'A3C8=B460 A3DA=H410', true),
  // Serie 500 (Tiger Lake PCH-H): solo pci.ids, datasheet non letto.
  ...pch('serie 500, Tiger Lake PCH-H', '4384=Q570 4385=Z590 4386=H570 4387=B560 4388=H510 4389=WM590 438A=QM580 438B=HM570 438C=C252 438D=C256 438F=W580', true),
  // Serie 600 (Alder Lake PCH-S): Intel 648364 rev. 005.
  ...pch('serie 600, Alder Lake PCH-S', '7A83=Q670 7A84=Z690 7A85=H670 7A86=B660 7A87=H610 7A88=W680 7A8C=HM670 7A8D=WM690'),
  // Serie 700: Intel 743835 rev. 005 (W790 7A8A come scritto da Intel).
  ...pch('serie 700, Raptor Lake PCH-S', '7A04=Z790 7A05=H770 7A06=B760 7A0C=HM770 7A0D=WM790 7A13=C266 7A14=C262 7A8A=W790'),
  // Serie 800: Intel 833778 rev. 003, tabella 12.
  ...pch('serie 800', '7F03=Q870 7F04=Z890 7F06=B860 7F07=H810 7F08=W880 7F0C=HM870 7F0D=WM880'),
  // Chipset per server e workstation: solo pci.ids.
  ...pch('serie C600, X99', '8D44=C610/X99 8D47=C610/X99', true),
  ...pch('serie C620, Lewisburg', 'A1C1=C621 A1C2=C622 A1C3=C624 A1C4=C625 A1C5=C626 A1C6=C627 A1C7=C628 A1CA=C629 A242=C624 A243=C627 A244=C621 A245=C627 A246=C628', true),
  ...pch('serie C740, Emmitsburg', '1B81=C741', true),
  // PCH nel package del processore (portatili).
  '9D43': { name: 'Sunrise Point-LP U', serie: 'serie 100 nel package, Skylake-U/Y', kind: 'onpkg' },
  '9D46': { name: 'Sunrise Point-LP Y', serie: 'serie 100 nel package, Skylake-U/Y', kind: 'onpkg' },
  '9D48': { name: 'Sunrise Point-LP U', serie: 'serie 100 nel package, Skylake-U/Y', kind: 'onpkg' },
  '9D4E': { name: 'Sunrise Point-LP', serie: 'serie 200 nel package, Kaby Lake-U/Y/R', kind: 'onpkg', ids: true },
  '9D50': { name: 'Sunrise Point-LP', serie: 'serie 200 nel package, Kaby Lake-U/Y/R', kind: 'onpkg', ids: true },
  '9D56': { name: 'Sunrise Point-LP', serie: 'serie 200 nel package, Kaby Lake-U/Y/R', kind: 'onpkg', ids: true },
  '9D58': { name: 'Sunrise Point-LP', serie: 'serie 200 nel package, Kaby Lake-U/Y/R', kind: 'onpkg', ids: true },
  '9D84': { name: 'Cannon Point-LP', serie: 'serie 300 nel package, Whiskey Lake, Coffee Lake-U', kind: 'onpkg' },
  '0284': { name: 'Comet Lake PCH-LP Premium-U', serie: 'serie 400 nel package, Comet Lake-U', kind: 'onpkg' },
  '0285': { name: 'Comet Lake PCH-LP Mainstream/Base-U', serie: 'serie 400 nel package, Comet Lake-U', kind: 'onpkg' },
  '3482': { name: 'Ice Lake-LP', serie: 'serie 495 nel package, Ice Lake', kind: 'onpkg', ids: true },
  A082: { name: 'Tiger Lake-LP UP3', serie: 'serie 500 nel package, Tiger Lake', kind: 'onpkg' },
  A087: { name: 'Tiger Lake-LP UP4', serie: 'serie 500 nel package, Tiger Lake', kind: 'onpkg' },
  '5181': { name: 'Alder Lake PCH-P', serie: 'serie 600 nel package, Alder Lake-P', kind: 'onpkg', ids: true },
  '5182': { name: 'Alder Lake PCH-P', serie: 'serie 600 nel package, Alder Lake-P', kind: 'onpkg', ids: true },
  '5187': { name: 'Alder Lake PCH-P', serie: 'serie 600 nel package, Alder Lake-P', kind: 'onpkg', ids: true },
  '519D': { name: 'Raptor Lake PCH-P', serie: 'serie 700 nel package, Raptor Lake-P', kind: 'onpkg' },
  // SoC senza chipset separato: solo pci.ids.
  '5AE8': { name: 'Apollo Lake', serie: 'SoC', kind: 'soc', ids: true },
  '31E8': { name: 'Gemini Lake', serie: 'SoC', kind: 'soc', ids: true },
  '4D87': { name: 'Jasper Lake', serie: 'SoC', kind: 'soc', ids: true },
  '4B00': { name: 'Elkhart Lake', serie: 'SoC', kind: 'soc', ids: true },
  '5481': { name: 'Alder Lake-N', serie: 'SoC', kind: 'soc', ids: true },
  '7E01': { name: 'Meteor Lake-P', serie: 'SoC', kind: 'soc', ids: true },
  '7E02': { name: 'Meteor Lake-H', serie: 'SoC', kind: 'soc', ids: true },
  A806: { name: 'Lunar Lake', serie: 'SoC', kind: 'soc', ids: true },
  A807: { name: 'Lunar Lake', serie: 'SoC', kind: 'soc', ids: true },
  '7702': { name: 'Arrow Lake-H', serie: 'SoC', kind: 'soc', ids: true },
  '7730': { name: 'Arrow Lake-H', serie: 'SoC', kind: 'soc', ids: true },
  AE10: { name: 'Arrow Lake-HX', serie: 'SoC, eSPI diretto', kind: 'soc', ids: true },
  E300: { name: 'Panther Lake', serie: 'SoC, Core Ultra serie 3', kind: 'soc', ids: true },
  E302: { name: 'Panther Lake', serie: 'SoC, Core Ultra serie 3', kind: 'soc', ids: true },
  E31F: { name: 'Panther Lake', serie: 'SoC, Core Ultra serie 3', kind: 'soc', ids: true },
  E400: { name: 'Panther Lake', serie: 'SoC, Core Ultra serie 3', kind: 'soc', ids: true },
  E402: { name: 'Panther Lake', serie: 'SoC, Core Ultra serie 3', kind: 'soc', ids: true },
  E41F: { name: 'Panther Lake', serie: 'SoC, Core Ultra serie 3', kind: 'soc', ids: true },
  '5795': { name: 'Xeon 6', serie: 'SoC, Xeon 6 con core P', kind: 'soc', ids: true },
};

/** Serie per intervallo di Device ID, per un modello non in tabella (datasheet citati sopra). */
const INTEL_RANGES: [number, number, string][] = [
  [0x1c40, 0x1c5f, 'serie 6'],
  [0x1e40, 0x1e5f, 'serie 7'],
  [0x8c40, 0x8c5f, 'serie 8'],
  [0x8cc0, 0x8ccf, 'serie 9'],
  [0xa140, 0xa15f, 'serie 100'],
  [0xa2c0, 0xa2cf, 'serie 200'],
  [0xa300, 0xa31f, 'serie 300'],
  [0x0680, 0x069f, 'serie 400'],
  [0x4380, 0x439f, 'serie 500'],
  [0x7a80, 0x7a9f, 'serie 600'],
  [0x7a00, 0x7a1f, 'serie 700'],
  [0x7f00, 0x7f1f, 'serie 800'],
];

/** Chipset emulati dagli hypervisor (Intel 440FX/440BX e PIIX3/PIIX4, pci.ids). */
const VIRTUAL = ['1237', '7000', '7110', '7113', '7190', '7192'];

const hex = (s?: string) => (s || '').toUpperCase().replace(/^0X/, '');
const idText = (f: PciFunc) => `ID ${hex(f.vendor)}:${hex(f.device)}${f.rev ? `, rev. ${hex(f.rev)}` : ''}`;

function intelChipset(funcs: PciFunc[]): ChipsetName | undefined {
  for (const f of funcs) {
    const row = INTEL[hex(f.device)];
    if (!row) continue;
    const unc = row.ids ? { uncertain: true } : {};
    if (row.kind === 'pch') return { name: `Intel ${row.name}`, detail: `${row.serie}, ${idText(f)}`, ...unc };
    return { name: 'PCH integrato nel processore', detail: `${row.name}, ${row.serie}, ${idText(f)}`, ...unc };
  }
  // Un bridge LPC/eSPI Intel non in tabella: la serie dall'intervallo, se c'è.
  for (const f of funcs) {
    const d = parseInt(hex(f.device), 16);
    if (!(d >= 0)) continue;
    for (const [lo, hi, serie] of INTEL_RANGES) {
      if (d >= lo && d <= hi) return { name: `chipset Intel ${serie}`, detail: `modello non in tabella, ${idText(f)}`, uncertain: true };
    }
  }
  const lpc = funcs.find((f) => hex(f.class) === '0601');
  return lpc ? { name: 'chipset Intel non in tabella', detail: idText(lpc), uncertain: true } : undefined;
}

function amdChipset(funcs: PciFunc[], hw: Hardware): ChipsetName | undefined {
  const ids = funcs.map((f) => hex(f.device));
  const any = (...list: string[]) => list.some((x) => ids.indexOf(x) >= 0);
  const count = (x: string) => ids.filter((d) => d === x).length;
  const promontory = 'chipset separato Promontory';
  // Serie 800 prima della regola dei due 43F4: se le schede 800 espongano anche 43F4 non è verificato.
  if (any('43FC', '43FD')) return { name: 'serie 800 (X870E, X870 o B850)', detail: `${promontory}; il modello preciso non si distingue dagli ID`, uncertain: true };
  if (any('43FA')) return { name: 'AMD A620', detail: `${promontory}, serie 600` };
  if (any('43F9')) return { name: 'serie 600', detail: `${promontory}; l'ID 43F9 non corrisponde a un modello noto`, uncertain: true };
  if (any('43F4', '43F5', '43F6', '43F7')) {
    const up = count('43F4');
    if (up >= 2) return { name: 'serie 600 (probabilmente X670 o X670E)', detail: `${promontory}: due chip in cascata`, uncertain: true };
    if (up === 1) return { name: 'serie 600 (probabilmente B650 o B650E)', detail: `${promontory}: un solo chip`, uncertain: true };
    return { name: 'serie 600 (B650 o X670)', detail: promontory, uncertain: true };
  }
  if (any('43EC')) return { name: 'AMD A520', detail: `${promontory}, serie 500` };
  if (any('43E9', '43EA', '43EB', '43EE')) return { name: 'AMD B550', detail: `${promontory}, serie 500` };
  if (any('57AD', '57A3', '57A4')) {
    // Lo stesso chip fa da TRX40 e WRX80 con i Threadripper.
    const c = hw.cpu;
    // Famiglia 23 modello 0x31 sono sia i Threadripper 3000 (TRX40) sia i
    // Threadripper PRO 3000WX (Castle Peak, WRX80): decide lo zoccolo
    // dichiarato dal firmware, se c'è.
    if (c && c.family === 23 && c.model === 0x31) {
      const socket = (c.socket || '').toUpperCase();
      if (/WRX8/.test(socket)) return { name: 'AMD WRX80', detail: 'chipset separato derivato dal die di Matisse, zoccolo sWRX8', uncertain: true };
      if (/TRX4/.test(socket)) return { name: 'AMD TRX40', detail: 'chipset separato derivato dal die di Matisse, zoccolo sTRX4', uncertain: true };
      return { name: 'AMD TRX40 o WRX80', detail: 'chipset separato derivato dal die di Matisse; WRX80 con i Threadripper PRO 3000WX', uncertain: true };
    }
    if (c && c.family === 25 && c.model === 0x08) return { name: 'AMD WRX80', detail: 'chipset separato derivato dal die di Matisse', uncertain: true };
    return { name: 'AMD X570 (o X570S)', detail: 'chipset separato derivato dal die di Matisse' };
  }
  if (any('43C6', '43C7', '43C8', '43D5')) return { name: 'serie 400 (X470 o B450)', detail: `${promontory}; il modello preciso non si distingue dagli ID`, uncertain: true };
  if (any('43B1', '43B6', '43BA')) return { name: 'AMD X399', detail: `${promontory}, serie 300` };
  if (any('43B8', '43BC')) return { name: 'AMD A320', detail: `${promontory}, serie 300` };
  if (any('43B0', '43B5', '43B9')) return { name: 'AMD X370', detail: `${promontory}, serie 300` };
  if (any('43B4', '43B7', '43BB')) return { name: 'serie 300 (probabilmente B350)', detail: promontory, uncertain: true };
  if (any('790E', '790B')) return { name: 'nessun chipset separato', detail: 'le funzioni del chipset (FCH) sono integrate nel processore: tipico di portatili, mini PC e schede A300/X300' };
  return undefined;
}

/** Il PC è una macchina virtuale riconoscibile dal modello dichiarato dal firmware. */
const isVirtualModel = (hw: Hardware) => /virtual machine|vmware|virtualbox|\bkvm\b|qemu|hvm domu|parallels/i.test(`${hw.vendor || ''} ${hw.model || ''}`);

/**
 * Nome del chipset per la scheda tecnica; undefined se l'agente non ha
 * esportato funzioni PCI riconoscibili.
 */
export function chipsetName(hw: Hardware | undefined): ChipsetName | undefined {
  if (!hw) return undefined;
  const vendor = (hw.cpu && hw.cpu.vendor) || '';
  // ARM64 (Snapdragon): niente chipset separato, e le tabelle x86 non valgono.
  if (/qualcomm|\barm\b/i.test(vendor)) return { name: 'nessun chipset separato', detail: 'sui processori ARM le funzioni del chipset sono integrate nel processore' };
  const funcs = hw.chipset || [];
  if (!funcs.length) return undefined;
  const intel = funcs.filter((f) => hex(f.vendor) === '8086');
  const amd = funcs.filter((f) => hex(f.vendor) === '1022');
  if (intel.some((f) => VIRTUAL.indexOf(hex(f.device)) >= 0) || (isVirtualModel(hw) && !amd.length && !intel.some((f) => INTEL[hex(f.device)])))
    return { name: 'chipset emulato (macchina virtuale)', detail: 'l\'hypervisor presenta un chipset Intel 440BX/PIIX4 emulato: non è un chipset fisico' };
  if (intel.length) {
    const r = intelChipset(intel);
    if (r) return r;
  }
  if (amd.length) return amdChipset(amd, hw);
  return undefined;
}

/** Riga per scheda tecnica, rapporto e documento: "Intel Z790 · serie 700, PCH Raptor Lake-S, ID 8086:7A04". */
export function chipsetText(c?: ChipsetName): string {
  if (!c) return '';
  return `${c.name}${c.detail ? ` · ${c.detail}` : ''}${c.uncertain ? ' · da verificare' : ''}`;
}
