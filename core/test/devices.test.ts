import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import {
  ACTIONS,
  analyze,
  DEVICE_PROBLEMS,
  deviceClassText,
  deviceOfDriver,
  deviceProblemDetail,
  deviceProblemText,
  deviceSeverity,
  documentParts,
  driverText,
  METRICS,
  oldDrivers,
  renderText,
  thirdPartyDrivers,
} from '../src/engine';
import type { DeviceInfo, Finding, Scan } from '../src/engine';
import { clinicScan } from '../src/demo/clinic';
import { demoScan } from '../src/demo/sample';
import { guideById } from '../src/guides';
import { DevicesCard } from '../src/ui/devices';

// Dispositivi e driver: gravità per codice e classe, driver vecchi e di
// Windows, firma dei driver, collegamento con le schermate blu, demo,
// documento e scheda dell'interfaccia.

const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const find = (s: Scan, id: string): Finding | undefined => analyze(s).findings.find((f) => f.id === id);
const dev = (patch: Partial<DeviceInfo>): DeviceInfo => ({ name: 'Dispositivo di prova', ...patch });

describe('gravità dei problemi dei dispositivi', () => {
  it('distingue classi essenziali, secondarie, disattivati e codici temporanei', () => {
    expect(deviceSeverity(dev({}))).toBe('ok');
    expect(deviceSeverity(dev({ class: 'Net', problem: 10 }))).toBe('crit');
    expect(deviceSeverity(dev({ class: 'Display', problem: 43 }))).toBe('crit');
    expect(deviceSeverity(dev({ class: 'USB', enumerator: 'PCI', problem: 10 }))).toBe('crit');
    expect(deviceSeverity(dev({ class: 'USB', enumerator: 'USB', problem: 43 }))).toBe('warn');
    expect(deviceSeverity(dev({ class: 'SmartCardReader', problem: 43 }))).toBe('warn');
    expect(deviceSeverity(dev({ problem: 28 }))).toBe('warn');
    expect(deviceSeverity(dev({ class: 'Printer', problem: 52 }))).toBe('crit');
    expect(deviceSeverity(dev({ class: 'Net', problem: 22 }))).toBe('info');
    expect(deviceSeverity(dev({ class: 'Net', problem: 14 }))).toBe('info');
  });

  it('spiega codice e stato', () => {
    expect(deviceProblemText(28)).toBe('Codice 28: driver non installato');
    expect(deviceProblemText(99)).toBe('Codice 99');
    expect(deviceProblemDetail(dev({ problem: 28, problemStatus: '0xC0000490' }))).toBe(
      'I driver del dispositivo non sono installati (stato 0xC0000490, nessun driver compatibile trovato).',
    );
    expect(deviceProblemDetail(dev({ problem: 10, problemStatus: '0xC0001234' }))).toContain('(stato 0xC0001234)');
    expect(deviceClassText('Net')).toBe('Schede di rete');
    expect(deviceClassText(undefined)).toBe('Altri dispositivi');
    expect(deviceClassText('NuovaClasse')).toBe('NuovaClasse');
    expect(driverText({ provider: 'Microsoft', version: '10.0.1', date: '2006-06-21', inf: 'bth.inf', inbox: true })).toBe('Microsoft 10.0.1 (bth.inf)');
    expect(driverText({ provider: 'Acme', version: '1.0', date: '2020-11-05', inf: 'oem1.inf' })).toBe('Acme 1.0 del 05/11/2020 (oem1.inf)');
    for (const code of Object.keys(DEVICE_PROBLEMS)) expect(DEVICE_PROBLEMS[Number(code)][1]).not.toMatch(/\.$/);
  });
});

describe('demo e giudizi', () => {
  it('casa: dispositivo senza driver, Bluetooth disattivato, driver vecchi, driver Wi-Fi delle schermate blu', () => {
    const s = clone(demoScan);
    const d = find(s, 'pc.devices')!;
    expect(d.severity).toBe('warn');
    expect(d.value).toMatch(/^2 dispositivi con problemi su \d+$/);
    expect(d.verdict).toContain('Dispositivo sconosciuto (codice 28: driver non installato)');
    expect(d.verdict).toContain('1 dispositivo è disattivato');
    expect(d.actions).toEqual(['fix-device', 'enable-device']);
    const old = find(s, 'pc.drivers.old')!;
    expect(old.severity).toBe('info');
    expect(old.numeric).toBe(4);
    expect(old.verdict).toContain('Intel(R) Serial IO I2C Host Controller - A0E8');
    expect(find(s, 'pc.drivers.signing')!.severity).toBe('ok');
    // Il driver ricorrente delle schermate blu è collegato alla scheda Wi-Fi.
    const crash = find(s, 'pc.crash.driver')!;
    expect(crash.verdict).toContain('È il driver di Acme Wireless AX 160MHz (schede di rete): Acme 22.40.0.7 del 05/11/2020 (oem18.inf).');
    // Un pacchetto usato da due dispositivi compare una volta sola.
    const pk = thirdPartyDrivers(s.pc!.devices).filter((p) => p.inf === 'oem5.inf');
    expect(pk).toHaveLength(1);
    expect(pk[0].devices).toHaveLength(2);
    expect(thirdPartyDrivers(s.pc!.devices)[0].date).toBe('2020-05-14');
  });

  it('clinica: lettore di smart card fermato dopo un errore, integrità della memoria attiva', () => {
    const s = clone(clinicScan);
    const d = find(s, 'pc.devices')!;
    expect(d.severity).toBe('warn');
    expect(d.verdict).toContain('Acme USB Smart Card Reader (codice 43: fermato dopo un errore)');
    expect(find(s, 'pc.drivers.old')).toBeUndefined();
    expect(find(s, 'pc.drivers.signing')!.value).toBe('Verificata, integrità della memoria attiva');
  });

  it('modalità test: critica a 64 bit, da migliorare a 32 bit', () => {
    const s = clone(demoScan);
    s.pc!.devices!.codeIntegrity = { options: 0x3, enabled: true, testSigning: true };
    const f = find(s, 'pc.drivers.signing')!;
    expect(f.severity).toBe('crit');
    expect(f.value).toBe('Modalità test attiva');
    expect(f.actions).toEqual(['disable-test-signing']);
    s.pc!.os!.arch = 'x86';
    expect(find(s, 'pc.drivers.signing')!.severity).toBe('warn');
    delete s.pc!.devices!.codeIntegrity;
    expect(find(s, 'pc.drivers.signing')).toBeUndefined();
  });

  it('nessun problema, solo codici temporanei, tre problemi secondari', () => {
    const s = clone(demoScan);
    s.pc!.devices!.items = s.pc!.devices!.items.filter((d) => !d.problem);
    let f = find(s, 'pc.devices')!;
    expect(f.severity).toBe('ok');
    expect(f.verdict).toContain('non ci sono punti esclamativi');
    s.pc!.devices!.items.push(dev({ name: 'Scheda di prova', class: 'Net', problem: 14 }));
    f = find(s, 'pc.devices')!;
    expect(f.severity).toBe('info');
    expect(f.actions).toEqual(['restart-pc']);
    s.pc!.devices!.items = [1, 2, 3].map((i) => dev({ name: `Lettore ${i}`, class: 'Image', problem: 10 }));
    expect(find(s, 'pc.devices')!.severity).toBe('warn');
  });

  it('età dei driver: le soglie per classe, mai i driver di Windows', () => {
    const now = Date.parse('2026-10-12T00:00:00Z');
    const d = (cls: string, date: string, inf: string, provider = 'Acme') => dev({ class: cls, driver: { provider, version: '1', date, inf, inbox: !/^oem/.test(inf) } });
    const data = { total: 5, problems: 0, items: [d('Net', '2017-01-01', 'oem1.inf'), d('Net', '2006-06-21', 'netwtw.inf'), d('Printer', '2010-01-01', 'oem2.inf'), d('MEDIA', '2022-01-01', 'oem3.inf'), d('System', '2015-01-01', 'oem4.inf', 'Microsoft')] };
    const old = oldDrivers(data, now);
    expect(old.map((o) => [o.pkg.inf, o.sev])).toEqual([['oem1.inf', 'warn']]);
  });

  it('collega un file di driver al dispositivo, preferendo quello con un problema o di terze parti', () => {
    const s = clone(demoScan);
    expect(deviceOfDriver(s.pc, 'ACMEWLAN.SYS')!.name).toBe('Acme Wireless AX 160MHz');
    expect(deviceOfDriver(s.pc, 'nessuno.sys')).toBeUndefined();
    expect(deviceOfDriver(undefined, 'x.sys')).toBeUndefined();
  });
});

describe('catalogo, guida, documento e interfaccia', () => {
  it('le voci di conoscenza e le azioni esistono e la guida le spiega', () => {
    for (const id of ['pc.devices', 'pc.drivers.signing', 'pc.drivers.old']) expect(METRICS[id], id).toBeTruthy();
    for (const id of ['fix-device', 'enable-device', 'disable-test-signing', 'update-drivers']) expect(ACTIONS[id], id).toBeTruthy();
    const g = guideById('dispositivi-driver')!;
    expect(g.metrics).toEqual(['pc.devices', 'pc.drivers.signing', 'pc.drivers.old']);
    const table = g.blocks.find((b) => b.t === 'table' && b.caption === 'Codici di Gestione dispositivi');
    expect(table && table.t === 'table' ? table.rows.length : 0).toBe(Object.keys(DEVICE_PROBLEMS).length);
  });

  it('il documento e il rapporto di testo riportano problemi, driver vecchi e firma', () => {
    const s = clone(demoScan);
    const html = documentParts(s, analyze(s)).body;
    expect(html).toContain('<h2>Dispositivi e driver</h2>');
    expect(html).toContain('Codice 28: driver non installato');
    expect(html).toContain('Driver di terze parti con più di 5 anni');
    expect(html).toContain('Firma dei driver: verifica attiva; integrità della memoria spenta.');
    const text = renderText(s, analyze(s));
    expect(text).toContain('Dispositivi');
  });

  it('la scheda mostra problemi, driver dal più vecchio e firma, con i nomi generici', () => {
    const s = clone(demoScan);
    const html = renderToStaticMarkup(createElement(DevicesCard, { pc: s.pc!, live: false, now: Date.parse(s.agent.startedAt) }));
    expect(html).toContain('Gestione dispositivi');
    expect(html).toContain('Codice 28: driver non installato');
    expect(html).toContain('Dispositivo Bluetooth');
    expect(html).not.toContain('Apri Gestione dispositivi');
    expect(html.indexOf('2020-05-14'.split('-').reverse().join('/'))).toBeLessThan(html.indexOf('12/01/2021'));
    expect(html).not.toContain('Mostra tutti i');
    const many = clone(s.pc!);
    for (let i = 0; i < 5; i++) many.devices!.items.push(dev({ name: `Extra ${i}`, class: 'System', driver: { provider: 'Acme', version: '1', date: '2025-01-01', inf: `oem${90 + i}.inf` } }));
    expect(renderToStaticMarkup(createElement(DevicesCard, { pc: many, live: false, now: 0 }))).toContain('Mostra tutti i 11 driver');
    const clinic = clone(clinicScan);
    const live = renderToStaticMarkup(createElement(DevicesCard, { pc: clinic.pc!, live: true, now: Date.parse(clinic.agent.startedAt) }));
    expect(live).toContain('Apri Gestione dispositivi');
    expect(live).not.toContain('Mostra tutti i');
    const none = clone(s.pc!);
    delete none.devices;
    expect(renderToStaticMarkup(createElement(DevicesCard, { pc: none, live: false, now: 0 }))).toBe('');
  });
});
