import { describe, expect, it } from 'vitest';
import { ACTIONS, analyze, documentParts, METRICS, renderText, WIN11_CPU_LABEL, win11Cpu, win11CpuRule, win11Requirements } from '../src/engine';
import type { PcData, Scan, Win11CPUCheck, Win11Req } from '../src/engine';
import { WIN11_CHECK_BUTTON } from '../src/engine/win11';
import { clinicScan } from '../src/demo/clinic';
import { demoScan } from '../src/demo/sample';
import { guideById } from '../src/guides';

// Requisiti di Windows 11: regole del progetto sulla generazione del processore
// (mai un «non supportato» certo), ogni requisito come Controllo integrità PC,
// giudizio su Windows 10 e su Windows 11 già installato.

const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const resultOf = (name: string) => win11CpuRule(name)?.result;

describe('generazione del processore: regole del progetto', () => {
  it('Intel Core per generazione, con le eccezioni dichiarate', () => {
    expect(resultOf('Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz')).toBe('listed');
    expect(resultOf('11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz')).toBe('listed');
    expect(resultOf('12th Gen Intel(R) Core(TM) i5-12500T')).toBe('listed');
    expect(resultOf('13th Gen Intel(R) Core(TM) i7-1355U')).toBe('listed');
    expect(resultOf('Intel(R) Core(TM) i9-14900K')).toBe('listed');
    expect(win11CpuRule('Intel(R) Core(TM) i7-7700HQ CPU @ 2.80GHz')).toEqual({ result: 'notListed', series: 'Core i7 di 7ª generazione', note: undefined });
    expect(resultOf('Intel(R) Core(TM) i7-7820HQ CPU @ 2.90GHz')).toBe('unknown'); // solo alcuni sistemi
    expect(resultOf('Intel(R) Core(TM) i7-7740X CPU @ 4.30GHz')).toBe('unknown'); // Core X solo fino alla 22H2
    // Criterio unico: le serie solo negli elenchi fino alla 22H2 (Core X, Xeon W-2100/2200/3100) sono da verificare.
    expect(win11CpuRule('Intel(R) Core(TM) i9-10900X CPU @ 3.70GHz')).toMatchObject({ result: 'unknown', series: 'Core X serie 10000X', note: expect.stringContaining('fino alla 22H2') });
    expect(resultOf('Intel(R) Core(TM) i9-9900X CPU @ 3.50GHz')).toBe('unknown');
    expect(win11CpuRule('Intel(R) Xeon(R) W-2295 CPU @ 3.00GHz')).toMatchObject({ result: 'unknown', note: expect.stringContaining('fino alla 22H2') });
    expect(resultOf('Intel(R) Core(TM) i7 CPU         860  @ 2.80GHz')).toBe('notListed');
    expect(resultOf('Intel(R) Core(TM)2 Duo CPU     E8400  @ 3.00GHz')).toBe('notListed');
    expect(resultOf('Intel(R) Core(TM) m3-8100Y CPU @ 1.10GHz')).toBe('listed');
    expect(resultOf('Intel(R) Core(TM) m3-7Y30 CPU @ 1.00GHz')).toBe('notListed');
  });

  it('Core Ultra, Core serie 1-2, serie N', () => {
    expect(resultOf('Intel(R) Core(TM) Ultra 7 155H')).toBe('listed');
    expect(resultOf('Intel(R) Core(TM) Ultra 9 285K')).toBe('listed');
    expect(resultOf('Intel(R) Core(TM) Ultra 5 445H')).toBe('newer');
    expect(resultOf('Intel(R) Core(TM) 5 120U')).toBe('listed');
    expect(resultOf('Intel(R) Core(TM) 7 250H')).toBe('listed');
    expect(resultOf('Intel(R) Core(TM) 3 N355')).toBe('newer');
    expect(resultOf('Intel(R) Core(TM) i3-N305')).toBe('listed');
    expect(resultOf('Intel(R) N100')).toBe('listed');
    expect(win11CpuRule('Intel(R) N97')).toMatchObject({ result: 'listed', note: 'attribuzione alla serie N90 fatta da Polaris' });
    expect(resultOf('Intel(R) N150')).toBe('newer');
    expect(resultOf('Intel(R) N50')).toBe('unknown');
  });

  it('Celeron, Pentium e Atom: le serie troppo ampie restano da verificare', () => {
    expect(resultOf('Intel(R) Celeron(R) N4020 CPU @ 1.10GHz')).toBe('listed');
    expect(resultOf('Intel(R) Celeron(R) N5105 @ 2.00GHz')).toBe('listed');
    expect(resultOf('Intel(R) Celeron(R) CPU N3350 @ 1.10GHz')).toBe('notListed');
    expect(resultOf('Intel(R) Celeron(R) CPU 3865U @ 1.80GHz')).toBe('unknown');
    expect(resultOf('Intel(R) Celeron(R) 7305')).toBe('listed');
    expect(resultOf('Intel(R) Celeron(R) G4900 CPU @ 3.10GHz')).toBe('listed');
    expect(resultOf('Intel(R) Celeron(R) G3930 CPU @ 2.90GHz')).toBe('notListed');
    expect(resultOf('Intel(R) Celeron(R) J4125 CPU @ 2.00GHz')).toBe('listed');
    expect(resultOf('Intel(R) Pentium(R) Silver N5000 CPU @ 1.10GHz')).toBe('unknown');
    expect(resultOf('Intel(R) Pentium(R) Silver J5005 CPU @ 1.50GHz')).toBe('listed');
    expect(resultOf('Intel(R) Pentium(R) CPU 4415U @ 2.30GHz')).toBe('unknown');
    expect(resultOf('Intel(R) Pentium(R) Gold G5400 CPU @ 3.70GHz')).toBe('listed');
    expect(resultOf('Intel(R) Pentium(R) CPU G4560 @ 3.50GHz')).toBe('notListed');
    expect(resultOf('Intel(R) Pentium(R) Gold 7505 @ 2.00GHz')).toBe('listed');
    expect(resultOf('Intel(R) Atom(TM) x7425E')).toBe('listed');
    expect(resultOf('Intel(R) Atom(TM) x5-Z8350 CPU @ 1.44GHz')).toBe('notListed');
  });

  it('Xeon, anche quelli delle macchine della CI', () => {
    expect(win11CpuRule('Intel(R) Xeon(R) Platinum 8272CL CPU @ 2.60GHz')).toMatchObject({ result: 'listed', series: 'Xeon Scalable di 2ª generazione' });
    expect(resultOf('Intel(R) Xeon(R) Platinum 8370C CPU @ 2.80GHz')).toBe('listed');
    expect(resultOf('Intel(R) Xeon(R) Platinum 8171M CPU @ 2.60GHz')).toBe('listed');
    expect(resultOf('Intel(R) Xeon(R) CPU E5-2673 v4 @ 2.30GHz')).toBe('notListed');
    expect(resultOf('Intel(R) Xeon(R) 6980P')).toBe('newer');
    expect(resultOf('Intel(R) Xeon(R) W-2245 CPU @ 3.90GHz')).toBe('unknown');
    expect(resultOf('Intel(R) Xeon(R) W-1250 CPU @ 3.30GHz')).toBe('listed');
    expect(resultOf('Intel(R) Xeon(R) w5-2455X')).toBe('listed');
    expect(resultOf('Intel(R) Xeon(R) E-2236 CPU @ 3.40GHz')).toBe('listed');
    expect(resultOf('Intel(R) Xeon(R) CPU D-1541 @ 2.10GHz')).toBe('notListed');
  });

  it('AMD e Qualcomm', () => {
    expect(resultOf('AMD Ryzen 5 2600 Six-Core Processor')).toBe('listed');
    expect(resultOf('AMD Ryzen 5 2400G with Radeon Vega Graphics')).toBe('notListed');
    expect(resultOf('AMD Ryzen 7 1700 Eight-Core Processor')).toBe('notListed');
    expect(resultOf('AMD Ryzen 5 3500U with Radeon Vega Mobile Gfx')).toBe('listed');
    expect(resultOf('AMD Ryzen 9 9950X 16-Core Processor')).toBe('listed');
    expect(resultOf('AMD Ryzen 7 260 w/ Radeon 780M Graphics')).toBe('listed');
    expect(resultOf('AMD Ryzen AI 9 HX 370 w/ Radeon 890M')).toBe('listed');
    expect(resultOf('AMD Ryzen Threadripper 2950X 16-Core Processor')).toBe('notListed');
    expect(resultOf('AMD Ryzen Threadripper PRO 3995WX 64-Cores')).toBe('listed');
    expect(resultOf('AMD EPYC 7763 64-Core Processor')).toBe('listed');
    expect(resultOf('AMD EPYC 7601 32-Core Processor')).toBe('notListed');
    expect(win11CpuRule('AMD EPYC 7F52 16-Core Processor')).toMatchObject({ result: 'listed', series: 'EPYC 7002' });
    expect(resultOf('AMD EPYC 9655 96-Core Processor')).toBe('listed');
    expect(resultOf('AMD Athlon 200GE with Radeon Vega Graphics')).toBe('notListed');
    expect(resultOf('AMD Athlon Silver 3050U with Radeon Graphics')).toBe('listed');
    expect(resultOf('AMD A10-9600P RADEON R5, 10 COMPUTE CORES 4C+6G')).toBe('notListed');
    expect(resultOf('AMD 3020e with Radeon Graphics')).toBe('listed');
    expect(resultOf('Snapdragon(R) X Elite - X1E78100 - Qualcomm(R) Oryon(TM) CPU')).toBe('listed');
    expect(resultOf('Microsoft SQ1 @ 3.0 GHz')).toBe('listed');
    expect(resultOf('Snapdragon (TM) 8cx @ 2.84 GHz')).toBe('unknown');
  });

  it('nome sconosciuto: nessuna regola, esito da verificare', () => {
    expect(win11CpuRule('CPU di prova')).toBeUndefined();
    expect(win11CpuRule('')).toBeUndefined();
    expect(win11Cpu({ cpu: { name: 'CPU di prova' } })).toMatchObject({ result: 'unknown', source: 'none' });
  });

  it('l\'elenco ufficiale letto dal PC: «nell\'elenco» conferma, l\'assenza si unisce alle regole', () => {
    const list = (result: 'listed' | 'notListed' | 'unknown', name: string, version = '25H2', kind: 'model' | 'series' = 'series'): PcData => ({
      cpu: { name },
      win11List: { at: '2026-11-17T10:00:00Z', source: 'https://learn.microsoft.com/', version, kind, result, match: result === 'listed' ? 'Intel Core i5 (8th Generation)' : undefined },
    });
    const amd = (result: 'listed' | 'notListed' | 'unknown', name: string) => list(result, name, '24H2', 'model');
    expect(win11Cpu(list('listed', 'Intel(R) Core(TM) i5-8250U'))).toMatchObject({ result: 'listed', source: 'list' });
    // Assente dall'elenco e anteriore secondo le regole: l'unico «non rispettato».
    expect(win11Cpu(list('notListed', 'Intel(R) Core(TM) i5-7200U'))).toMatchObject({ result: 'notListed', source: 'list' });
    expect(win11Cpu(amd('notListed', 'AMD Ryzen 7 1700 Eight-Core Processor'))).toMatchObject({ result: 'notListed', source: 'list' });
    // Una generazione uscita dopo l'elenco resta «più recente».
    expect(win11Cpu(list('notListed', 'Intel(R) Core(TM) Ultra 5 445H'))).toMatchObject({ result: 'newer', source: 'rules' });
    expect(win11Cpu(list('notListed', 'Intel(R) N150'))).toMatchObject({ result: 'newer', source: 'rules' });
    // Processori attuali assenti dall'elenco AMD per modello della 24H2 o dall'elenco Intel 25H2: le regole li danno supportati.
    for (const n of ['AMD Ryzen 9 9950X 16-Core Processor', 'AMD Ryzen AI 9 HX 370 w/ Radeon 890M', 'AMD Ryzen 7 8845HS w/ Radeon 780M Graphics', 'AMD Ryzen Threadripper 3970X 32-Core Processor', 'AMD Ryzen 7 260 w/ Radeon 780M Graphics'])
      expect(win11Cpu(amd('notListed', n)), n).toMatchObject({ result: 'listed', source: 'rules' });
    expect(win11Cpu(list('notListed', 'Intel(R) Pentium(R) Gold G6400 CPU @ 4.00GHz'))).toMatchObject({ result: 'listed', source: 'rules' });
    // Il dettaglio non dice che la serie è negli elenchi più recenti (la serie Pentium Gold G6000 non c'è): lo dicono le regole.
    expect(win11Cpu(list('notListed', 'Intel(R) Pentium(R) Gold G6400 CPU @ 4.00GHz')).detail).toContain('le regole di Polaris lo collocano nella generazione supportata (Pentium Gold G6000)');
    // Athlon 300/3000/4000 e AMD 3015e/3020e: Microsoft li elenca solo per modello (24H2), la 25H2 per serie non li ha.
    expect(win11CpuRule('AMD Athlon Silver 3050U with Radeon Graphics')).toMatchObject({ result: 'listed', note: expect.stringContaining('per modello') });
    expect(win11CpuRule('AMD 3020e with Radeon Graphics')).toMatchObject({ result: 'listed', note: expect.stringContaining('per modello') });
    expect(win11CpuRule('AMD Athlon Gold 7220U')).toMatchObject({ result: 'listed', note: undefined });
    for (const n of ['AMD Athlon PRO 3145U Mobile Processor with Radeon Graphics', 'AMD Athlon Gold PRO 4150GE with Radeon Graphics', 'AMD 3015e with Radeon Graphics'])
      expect(win11Cpu(amd('notListed', n)), n).toMatchObject({ result: 'unknown', source: 'list' });
    expect(win11Cpu(amd('notListed', 'AMD EPYC 7302 16-Core Processor')).detail).toContain('non lo escludono (EPYC 7002, negli elenchi per modello fino alla 24H2, non nella 25H2)');
    // Serie solo negli elenchi vecchi, serie con nota, nomi sconosciuti: da verificare, mai «non rispettato».
    for (const p of [
      list('notListed', 'Intel(R) Core(TM) i9-10900X CPU @ 3.70GHz'),
      list('notListed', 'Intel(R) Core(TM) i9-10980XE CPU @ 3.00GHz'),
      list('notListed', 'Intel(R) Core(TM) i7-9800X CPU @ 3.80GHz'),
      list('notListed', 'Intel(R) Xeon(R) W-2295 CPU @ 3.00GHz'),
      list('notListed', 'Intel(R) Xeon(R) W-2133 CPU @ 3.60GHz'),
      amd('notListed', 'AMD Ryzen 5 2600 Six-Core Processor'),
      amd('notListed', 'AMD Eng Sample: 100-000000163_43/29_Y'),
      amd('notListed', 'AMD Custom APU 0405'),
      list('notListed', 'Intel(R) N50'),
    ]) {
      const v = win11Cpu(p);
      expect(v, p.cpu!.name).toMatchObject({ result: 'unknown', source: 'list' });
      expect(v.detail, p.cpu!.name).toContain('Non compare nell\'elenco ufficiale Microsoft');
    }
    expect(win11Cpu(list('unknown', 'Intel(R) Core(TM) i5-8250U'))).toMatchObject({ result: 'listed', source: 'rules' });
    for (const k of Object.keys(WIN11_CPU_LABEL)) expect(WIN11_CPU_LABEL[k as keyof typeof WIN11_CPU_LABEL].length).toBeGreaterThan(5);
    // Mai «non supportato» nelle etichette.
    for (const v of Object.values(WIN11_CPU_LABEL)) expect(v).not.toMatch(/non supportat/);
  });

  it('con l\'elenco letto, il requisito non diventa mai «non rispettato» per un processore supportato secondo le regole', () => {
    const notListed: Win11CPUCheck = { at: '2026-11-17T10:00:00Z', source: 'https://learn.microsoft.com/x', version: '24H2', kind: 'model', result: 'notListed', rows: 399 };
    const s = goodScan();
    s.pc!.win11List = notListed;
    for (const name of ['AMD Ryzen 9 9950X 16-Core Processor', 'AMD Ryzen AI 9 HX 370 w/ Radeon 890M']) {
      s.pc!.cpu!.name = name;
      expect(req(s, 'cpu-gen')?.status, name).toBe('ok');
      expect(win11Of(s)?.severity, name).toBe('ok');
    }
    s.pc!.win11List = { ...notListed, version: '25H2', kind: 'series' };
    for (const name of ['Intel(R) Core(TM) i9-10900X CPU @ 3.70GHz', 'Intel(R) Xeon(R) W-2295 CPU @ 3.00GHz']) {
      s.pc!.cpu!.name = name;
      const r = req(s, 'cpu-gen');
      expect(r?.status, name).toBe('unknown');
      expect(r?.value, name).toContain('non nell\'elenco Microsoft 25H2: da verificare');
      const f = win11Of(s);
      expect(f?.severity, name).toBe('info');
      expect(f?.verdict, name).not.toContain('garanzia di ricevere aggiornamenti');
    }
    s.pc!.cpu!.name = 'Intel(R) Core(TM) i5-7200U CPU @ 2.50GHz';
    expect(req(s, 'cpu-gen')).toMatchObject({ status: 'fail', value: 'Core i5 di 7ª generazione, generazione anteriore a quelle elencate' });
  });

  it('esito simulato della demo: il dettaglio non dichiara una lettura', () => {
    const pc: PcData = { cpu: { name: 'Intel(R) Core(TM) i5-8250U' }, win11List: { at: '2026-11-17T10:00:00Z', source: 'simulazione della demo', version: '25H2', kind: 'series', result: 'listed', match: 'Core i5 di 8ª generazione' } };
    expect(win11Cpu(pc).detail).not.toContain('letto su richiesta');
    expect(win11Cpu(pc).detail).toContain('esito simulato nella demo');
    pc.win11List = { ...pc.win11List!, result: 'notListed', match: undefined };
    pc.cpu!.name = 'Intel(R) Core(TM) i5-7200U';
    expect(win11Cpu(pc).detail).toContain('esito simulato nella demo');
  });
});

/** Un PC con Windows 10 o 11 che rispetta tutti i requisiti. */
function goodScan(os = 'Windows 11 Pro', build = 26100): Scan {
  const s = clone(demoScan);
  const pc = s.pc!;
  pc.os = { name: os, version: '24H2', build, arch: 'x64' };
  pc.win11 = { tpmVersion: '2.0' };
  return s;
}
const req = (s: Scan, id: Win11Req['id']) => win11Requirements(s).find((r) => r.id === id);
const win11Of = (s: Scan) => analyze(s).findings.find((f) => f.id === 'pc.win11');

describe('requisiti di Windows 11, uno per riga', () => {
  it('tutti i requisiti su un PC adatto; la riga della versione solo su Windows 10', () => {
    const r = win11Requirements(goodScan());
    expect(r.map((x) => x.id)).toEqual(['cpu', 'cpu-gen', 'ram', 'disk', 'uefi', 'secureboot', 'tpm', 'gpu', 'display', 'instr']);
    expect(r.every((x) => x.status === 'ok')).toBe(true);
    expect(req(goodScan('Windows 10 Pro', 19045), 'os')).toMatchObject({ status: 'ok', value: 'build 19045 (24H2)' });
    expect(req(goodScan('Windows 10 Pro', 18363), 'os')?.status).toBe('fail');
  });

  it('niente requisiti sui server e sui sistemi diversi da Windows 10 e 11', () => {
    const s = goodScan('Windows Server 2022 Datacenter', 20348);
    s.pc!.os!.server = true;
    expect(win11Requirements(s)).toEqual([]);
    expect(win11Of(s)).toBeUndefined();
    expect(win11Requirements(goodScan('Windows 8.1 Pro', 9600))).toEqual([]);
  });

  it('memoria: la RAM installata prima di quella vista da Windows', () => {
    const s = goodScan();
    s.pc!.memory = { totalMB: 3700, availableMB: 1000, installedMB: 4096 };
    expect(req(s, 'ram')).toMatchObject({ status: 'ok', value: '4 GB installati' });
    s.pc!.memory = { totalMB: 3500, availableMB: 1000 };
    expect(req(s, 'ram')?.status).toBe('unknown');
    s.pc!.memory = { totalMB: 2048, availableMB: 1000 };
    expect(req(s, 'ram')?.status).toBe('fail');
  });

  it('TPM: la funzione del servizio TPM prima dei dispositivi di sicurezza', () => {
    const s = goodScan();
    s.pc!.win11 = { tpmVersion: '' };
    expect(req(s, 'tpm')).toMatchObject({ status: 'fail', value: 'nessun TPM attivo' });
    s.pc!.win11 = {};
    s.pc!.hardware!.tpm = '1.2';
    expect(req(s, 'tpm')).toMatchObject({ status: 'fail', value: 'TPM 1.2' });
    delete s.pc!.hardware!.tpm;
    expect(req(s, 'tpm')?.status).toBe('unknown');
  });

  it('Secure Boot: basta che sia supportato; spento senza amministratore è da verificare', () => {
    const s = goodScan();
    s.pc!.hardware!.secureBoot = false;
    expect(req(s, 'secureboot')).toMatchObject({ status: 'unknown', value: 'spento: probabilmente attivabile' });
    s.pc!.win11 = { tpmVersion: '2.0', secureBootCapable: true };
    expect(req(s, 'secureboot')).toMatchObject({ status: 'ok', value: 'supportato ma spento' });
    expect(win11Of(s)?.verdict).toContain('Secure Boot è supportato ma spento');
    s.pc!.win11 = { secureBootCapable: false };
    expect(req(s, 'secureboot')?.status).toBe('fail');
    s.pc!.hardware!.firmware = 'bios';
    expect(req(s, 'secureboot')?.status).toBe('fail');
    expect(req(s, 'uefi')).toMatchObject({ status: 'fail', value: 'BIOS legacy' });
  });

  it('scheda video: WDDM dal driver, DirectX 12 dichiarato non verificato', () => {
    const s = goodScan();
    expect(req(s, 'gpu')).toMatchObject({ status: 'ok', value: 'WDDM 2.9' });
    expect(req(s, 'gpu')?.detail).toContain('DirectX 12 non è verificato');
    s.pc!.gpus = [{ name: 'Acme Graphics', wddm: 1300 }];
    expect(req(s, 'gpu')?.status).toBe('fail');
    s.pc!.gpus = [{ name: 'Microsoft Basic Display Adapter', wddm: 1300 }];
    expect(req(s, 'gpu')).toMatchObject({ status: 'unknown', value: 'solo una scheda video di base' });
  });

  it('schermo: solo quelli integrati, non si applica ai PC fissi', () => {
    const s = goodScan();
    s.pc!.hardware!.displays = [{ width: 1280, height: 800, diagonalIn: 8, bitsPerColor: 8, internal: true }];
    expect(req(s, 'display')?.status).toBe('fail');
    // Pannello da 15,6" usato a 800×600 (duplicato su un proiettore): senza la risoluzione nativa è da verificare, non «non rispettato».
    s.pc!.hardware!.displays = [{ width: 800, height: 600, diagonalIn: 15.6, bitsPerColor: 8, internal: true }];
    expect(req(s, 'display')?.status).toBe('unknown');
    expect(req(s, 'display')?.detail).toContain('da verificare');
    // Con la risoluzione nativa letta decide quella.
    s.pc!.hardware!.displays = [{ width: 800, height: 600, nativeWidth: 1920, nativeHeight: 1080, diagonalIn: 15.6, bitsPerColor: 8, internal: true }];
    expect(req(s, 'display')).toMatchObject({ status: 'ok', value: '15,6", 1920×1080 (in uso 800×600), 8 bit per colore' });
    s.pc!.hardware!.displays = [{ width: 1024, height: 600, nativeWidth: 1024, nativeHeight: 600, diagonalIn: 10.1, bitsPerColor: 8, internal: true }];
    expect(req(s, 'display')).toMatchObject({ status: 'fail', value: '10,1", 1024×600, 8 bit per colore' });
    s.pc!.hardware!.displays = [{ width: 1366, height: 768, diagonalIn: 11.6, bitsPerColor: 6, internal: true }];
    expect(req(s, 'display')?.status).toBe('unknown');
    s.pc!.hardware!.displays = [{ width: 1920, height: 1080, diagonalIn: 27 }];
    expect(req(s, 'display')?.status).toBe('na');
    delete s.pc!.hardware!.displays;
    s.pc!.hardware!.chassis = 'desktop';
    expect(req(s, 'display')?.status).toBe('na');
  });

  it('istruzioni della 24H2 (dalla stampa, non da Microsoft); ARM64 escluso', () => {
    const s = goodScan();
    expect(req(s, 'instr')?.detail).toContain('non da una pagina Microsoft');
    s.pc!.hardware!.cpu!.features = ['SSE2', 'SSE4.1'];
    expect(req(s, 'instr')?.status).toBe('fail');
    s.pc!.os!.arch = 'arm64';
    expect(req(s, 'instr')?.status).toBe('na');
  });

  it('verdetto di Windows Update: arancione con avvertenze, motivi senza badare alle maiuscole', () => {
    const s = goodScan('Windows 10 Pro', 19045);
    s.pc!.win11 = { tpmVersion: '2.0', appraiser: { target: '25H2', verdict: 'orange' } };
    expect(req(s, 'appraiser')).toMatchObject({ status: 'unknown', value: 'con avvertenze (app o driver da aggiornare) alla 25H2' });
    s.pc!.win11 = { tpmVersion: '2.0', appraiser: { target: '25H2', verdict: 'red', reasons: ['TPM', 'UEFISecureBoot', 'cpufms', 'constructor'] } };
    expect(req(s, 'appraiser')?.value).toBe('bloccato alla 25H2: TPM 2.0 assente, Secure Boot non supportato, processore non nella generazione approvata, constructor');
  });

  it('verdetto di Windows Update come indizio, con i motivi tradotti', () => {
    const s = goodScan('Windows 10 Pro', 19045);
    s.pc!.win11 = { tpmVersion: '2.0', appraiser: { target: '25H2', verdict: 'red', reasons: ['CpuFms', 'Tpm'] } };
    const r = req(s, 'appraiser');
    expect(r?.status).toBe('fail');
    expect(r?.value).toBe('bloccato alla 25H2: processore non nella generazione approvata, TPM 2.0 assente');
    expect(r?.detail).toContain('indizio');
    // L'indizio non conta tra i requisiti mancanti, ma si dice.
    const f = win11Of(s);
    expect(f?.severity).toBe('info');
    expect(f?.verdict).toContain('Windows Update, come indizio, lo considera non aggiornabile');
  });
});

describe('giudizio pc.win11', () => {
  it('Windows 10: aggiornabile, da verificare o con requisiti mancanti', () => {
    const ok = win11Of(goodScan('Windows 10 Pro', 19045));
    expect(ok).toMatchObject({ severity: 'info', value: 'aggiornabile secondo i requisiti verificabili', actions: ['upgrade-windows'] });
    const old = goodScan('Windows 10 Pro', 19045);
    old.pc!.cpu!.name = 'Intel(R) Core(TM) i7-7700HQ CPU @ 2.80GHz';
    old.pc!.win11 = { tpmVersion: '' };
    const f = win11Of(old);
    expect(f?.severity).toBe('warn');
    expect(f?.value).toBe('2 requisiti mancanti');
    expect(f?.verdict).toContain('generazione del processore (Core i7 di 7ª generazione, generazione anteriore a quelle elencate)');
    expect(f?.actions).toEqual(['firmware-security', 'check-win11-cpu', 'upgrade-windows']);
  });

  it('Windows 10: il rimando a Controllo integrità PC compare una volta sola', () => {
    const f = win11Of(goodScan('Windows 10 Pro', 19045));
    expect(f?.verdict.split('Controllo integrità PC').length).toBe(2);
    const s = goodScan('Windows 10 Pro', 19045);
    s.pc!.win11List = { at: '2026-11-17T10:00:00Z', source: 'https://learn.microsoft.com/x', version: '25H2', kind: 'series', result: 'listed', match: '11th Generation Core i5 Processors', rows: 87 };
    expect(win11Of(s)?.verdict.split('Controllo integrità PC').length).toBe(2);
  });

  it('schermo o scheda video sotto i requisiti: solo informazione, mai aggiornamenti non garantiti', () => {
    // Console portatile da 7" venduta con Windows 11 (ROG Ally, MSI Claw).
    const s = goodScan();
    s.pc!.hardware!.displays = [{ diagonalIn: 7, width: 1920, height: 1080, bitsPerColor: 8, internal: true }];
    let f = win11Of(s);
    expect(f?.severity).toBe('info');
    expect(f?.value).toBe('1 requisito non rispettato');
    expect(f?.verdict).not.toContain('garanzia di ricevere aggiornamenti');
    expect(f?.verdict).toContain('né Windows Update né Controllo integrità PC');
    s.pc!.gpus = [{ name: 'Acme Graphics', wddm: 1300 }];
    expect(win11Of(s)?.severity).toBe('info');
    // Su Windows 10 lo stesso: informazione, non avviso.
    const w10 = goodScan('Windows 10 Pro', 19045);
    w10.pc!.hardware!.displays = [{ diagonalIn: 7, width: 1920, height: 1080, bitsPerColor: 8, internal: true }];
    f = win11Of(w10);
    expect(f?.severity).toBe('info');
    expect(f?.verdict).toContain('rispetta i requisiti di Windows 11 che Windows Update controlla.');
    expect(f?.verdict).toContain('non blocca l\'aggiornamento a Windows 11');
    // Con un requisito controllato da Windows Update ancora da verificare (TPM non letto) non si dice «rispettati» senza riserve.
    w10.pc!.win11 = {};
    delete w10.pc!.hardware!.tpm;
    f = win11Of(w10);
    expect(f?.verdict).toContain('che Windows Update controlla, tra quelli verificabili da qui. Non rispettato: schermo integrato');
    expect(f?.verdict).toContain('Da verificare: TPM 2.0 (non letto)');
    const w11u = goodScan();
    w11u.pc!.hardware!.displays = [{ diagonalIn: 7, width: 1920, height: 1080, bitsPerColor: 8, internal: true }];
    w11u.pc!.win11 = {};
    delete w11u.pc!.hardware!.tpm;
    expect(win11Of(w11u)?.verdict).toMatch(/^I requisiti verificabili che Windows Update controlla sono rispettati\. Non rispettato: schermo integrato .* non blocca gli aggiornamenti\. Da verificare: TPM 2\.0 \(non letto\)\./);
    // Su Windows 10 con un requisito vero mancante: avviso, e lo schermo «anche».
    w10.pc!.cpu!.name = 'Intel(R) Core(TM) i5-7200U CPU @ 2.50GHz';
    f = win11Of(w10);
    expect(f?.severity).toBe('warn');
    expect(f?.verdict).toContain('. Non rispettato anche: schermo integrato');
    // Con un requisito vero mancante resta l'avviso, e lo schermo si dice a parte.
    s.pc!.cpu!.name = 'Intel(R) Core(TM) i5-7200U CPU @ 2.50GHz';
    f = win11Of(s);
    expect(f?.severity).toBe('warn');
    expect(f?.verdict).toContain('garanzia di ricevere aggiornamenti');
    expect(f?.verdict).toContain('Non rispettato anche: scheda video con driver WDDM 2.0 (WDDM 1.3); schermo integrato (7,0", 1920×1080, 8 bit per colore). Sono requisiti che Microsoft indica');
  });

  it('Windows 11 su hardware non supportato: aggiornamenti non garantiti', () => {
    const s = goodScan();
    s.pc!.cpu!.name = 'Intel(R) Core(TM) i5-7200U CPU @ 2.50GHz';
    const f = win11Of(s);
    expect(f?.severity).toBe('warn');
    expect(f?.value).toBe('1 requisito non rispettato');
    expect(f?.verdict).toContain('non hanno garanzia di ricevere aggiornamenti');
    expect(f?.actions).toEqual(['check-win11-cpu']);
    expect(win11Of(goodScan())).toMatchObject({ severity: 'ok', value: 'rispettati', actions: [] });
  });

  it('mai «non supportato» per un processore sconosciuto', () => {
    const s = goodScan();
    s.pc!.cpu!.name = 'Genuine Intel(R) CPU 0000 @ 2.00GHz';
    const f = win11Of(s);
    expect(f?.severity).toBe('info');
    expect(f?.value).toBe('1 requisito da verificare');
    expect(f?.actions).toContain('check-win11-cpu');
  });

  it('demo: portatile di casa a posto, ambulatorio con Secure Boot da verificare', () => {
    expect(win11Of(demoScan)?.severity).toBe('ok');
    const c = win11Of(clinicScan);
    expect(c?.severity).toBe('info');
    expect(c?.verdict).toContain('Secure Boot (spento: probabilmente attivabile)');
    expect(c?.verdict).toContain('lo considera aggiornabile');
  });

  it('knowledge base, azioni, guida, rapporto e documento', () => {
    expect(METRICS['pc.win11'].limits).toContain('non sono incorporati');
    expect(METRICS['pc.win11'].limits).not.toMatch(/generazione non supportata/);
    expect((METRICS['pc.win11'].scale || []).map((x) => x.range).join(' ')).toContain('schermo o scheda video');
    expect(ACTIONS['check-win11-cpu']).toBeDefined();
    // L'azione cita il pulsante della scheda con la sua etichetta esatta.
    expect(ACTIONS['check-win11-cpu'].steps.map((x) => (typeof x === 'string' ? x : x.text)).join(' ')).toContain(`«${WIN11_CHECK_BUTTON}»`);
    const guide = JSON.stringify(guideById('requisiti-windows-11'));
    expect(guide).toContain(WIN11_CPU_LABEL.notListed);
    expect(guide).not.toMatch(/generazione non supportata/);
    // Tabella degli esiti come quella di win11Cpu: l'assenza dall'elenco letto dà «da verificare» solo con le serie elencate per modello o senza regola.
    expect(guide).not.toContain('che le regole non escludono');
    expect(guide).toContain('che le regole mettono in una serie elencata solo modello per modello (Ryzen 2000, Athlon 3000, EPYC 7002) o non riconoscono');
    expect(guideById('requisiti-windows-11')?.metrics).toContain('pc.win11');
    const txt = renderText(clinicScan, analyze(clinicScan));
    expect(txt).toContain(' Requisiti di Windows 11');
    expect(txt).toContain('[ ?? ] Secure Boot supportato: spento: probabilmente attivabile');
    expect(txt).toContain('[ -- ] Schermo integrato');
    const doc = documentParts(clinicScan, analyze(clinicScan)).body;
    expect(doc).toContain('<h2>Requisiti di Windows 11</h2>');
    expect(doc).toContain('non incorpora gli elenchi dei processori');
    expect(doc).toContain('valutata con regole proprie');
    // Con l'esito dall'elenco letto su richiesta, la nota lo dice.
    const s = clone(clinicScan);
    s.pc!.win11List = { at: '2026-11-17T10:00:00Z', source: 'https://learn.microsoft.com/x', version: '25H2', kind: 'series', result: 'listed', match: '12th Generation Core i5 Processors', rows: 87 };
    const doc2 = documentParts(s, analyze(s)).body;
    expect(doc2).toContain('confrontata con l\'elenco ufficiale (versione 25H2) letto su richiesta da questo PC');
    expect(doc2).not.toContain('valutata con regole proprie');
  });
});
