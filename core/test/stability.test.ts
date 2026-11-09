import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import {
  ACTIONS,
  analyze,
  appHint,
  bootSample,
  bootSeverity,
  bootTypical,
  documentParts,
  failText,
  METRICS,
  msText,
  reliabilityFalling,
  reliabilitySeverity,
} from '../src/engine';
import type { Finding, Scan } from '../src/engine';
import { clinicScan } from '../src/demo/clinic';
import { demoScan } from '../src/demo/sample';
import { guideById } from '../src/guides';
import { StabilityCard } from '../src/ui/stability';

// Avvio, programmi che si chiudono da soli e indice di stabilità: soglie,
// casi senza misura, demo, documento e scheda.

const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const find = (s: Scan, id: string): Finding | undefined => analyze(s).findings.find((f) => f.id === id);

describe('durata dell\'avvio', () => {
  it('formatta i tempi e applica le soglie', () => {
    expect(msText(3200)).toBe('3,2 s');
    expect(msText(48000)).toBe('48 s');
    expect(msText(92400)).toBe('1 min 32 s');
    expect(msText(120000)).toBe('2 min');
    expect(bootSeverity(0)).toBe('unknown');
    expect(bootSeverity(59999)).toBe('ok');
    expect(bootSeverity(60000)).toBe('warn');
    expect(bootSeverity(180001)).toBe('crit');
  });

  it('usa la mediana degli ultimi 5 avvii senza i riavvii dopo un aggiornamento', () => {
    const s = clone(demoScan);
    const b = s.pc!.boot!;
    expect(bootSample(b).map((r) => r.totalMs)).toEqual([118400, 104800, 97100, 99600]);
    expect(bootTypical(b)).toBe((99600 + 104800) / 2);
    b.boots = [{ time: '2026-10-01T08:00:00Z', totalMs: 200000, afterUpdate: true }];
    expect(bootSample(b)).toHaveLength(1);
  });

  it('casa: avvio lento dopo il desktop, servizio segnalato più volte', () => {
    const s = clone(demoScan);
    const f = find(s, 'pc.boot')!;
    expect(f.severity).toBe('warn');
    expect(f.value).toBe('1 min 42 s');
    expect(f.verdict).toContain('La parte più lunga viene dopo l\'accesso: i programmi all\'avvio (Windows ne ha contati 14).');
    expect(f.verdict).toContain('Avvio rapido attivo');
    expect(f.actions).toEqual(['trim-startup']);
    const slow = find(s, 'pc.boot.slow')!;
    expect(slow.severity).toBe('warn');
    expect(slow.verdict).toContain('Acme Update Service (servizio, +17 s, 4 volte)');
    expect(find(s, 'pc.boot.firmware')).toBeUndefined();
    expect(find(s, 'pc.boot.shutdown')).toBeUndefined();
  });

  it('senza misure: non misurata, con il motivo', () => {
    const s = clone(demoScan);
    s.pc!.boot!.boots = [];
    let f = find(s, 'pc.boot')!;
    expect(f.severity).toBe('unknown');
    expect(f.value).toBe('non misurata');
    expect(f.verdict).toContain('Windows non ha registrato la durata dell\'avvio negli ultimi 90 giorni');
    s.pc!.boot!.channel = 'denied';
    f = find(s, 'pc.boot')!;
    expect(f.verdict).toContain('non è leggibile da questo account');
  });

  it('firmware e spegnimento lenti', () => {
    const s = clone(demoScan);
    s.pc!.boot!.firmwareMs = 52000;
    s.pc!.boot!.shutdowns = [{ time: '2026-10-10T18:00:00Z', totalMs: 200000 }];
    expect(find(s, 'pc.boot.firmware')!.severity).toBe('warn');
    const sd = find(s, 'pc.boot.shutdown')!;
    expect(sd.severity).toBe('warn');
    expect(sd.value).toBe('3 min 20 s');
    s.pc!.boot!.firmwareMs = 20000;
    expect(find(s, 'pc.boot.firmware')!.severity).toBe('info');
  });
});

describe('programmi che si chiudono da soli', () => {
  it('casa: un programma si chiude spesso, l\'ultima volta il giorno prima', () => {
    const s = clone(demoScan);
    const f = find(s, 'pc.apps')!;
    expect(f.severity).toBe('crit');
    expect(f.value).toBe('9 arresti e 3 blocchi in 30 giorni');
    expect(f.verdict).toContain('AcmePhotoStudio.exe (8 arresti e 2 blocchi, l\'ultima volta il 11/10/2026)');
    expect(f.verdict).toContain('modulo acmegpufx.dll; codice 0xc0000005, accesso a una zona di memoria non valida');
    expect(f.actions).toEqual(['update-app']);
  });

  it('nessun arresto, registro non leggibile, componenti di Windows e segnalazione errori spenta', () => {
    const c = clone(clinicScan);
    expect(find(c, 'pc.apps')!.severity).toBe('ok');
    const s = clone(demoScan);
    s.pc!.apps!.channel = 'denied';
    expect(find(s, 'pc.apps')!.severity).toBe('unknown');
    const x = clone(demoScan);
    x.pc!.apps!.apps.push({ app: 'explorer.exe', crashes: 3, hangs: 0, last: '2026-10-01T10:00:00Z', system: true });
    x.pc!.apps!.wer = { disabled: true };
    const f = find(x, 'pc.apps')!;
    expect(f.actions).toEqual(['update-app', 'repair-windows']);
    expect(f.verdict).toContain('Si chiudono spesso anche componenti di Windows (explorer.exe)');
    expect(f.verdict).toContain('La Segnalazione errori di Windows è disattivata');
  });

  it('spiega i moduli di Windows come probabili vittime', () => {
    expect(appHint({ app: 'a.exe', crashes: 1, hangs: 0, last: '', modules: [{ name: 'ntdll.dll', count: 1 }] })).toContain('spesso è dove l\'errore si manifesta, non la causa');
    expect(appHint({ app: 'a.exe', crashes: 1, hangs: 0, last: '' })).toBe('');
    expect(failText({ crashes: 1, hangs: 1 })).toBe('1 arresto e 1 blocco');
    expect(failText({ crashes: 0, hangs: 0 })).toBe('nessuno');
  });
});

describe('indice di stabilità', () => {
  it('fasce e tendenza', () => {
    expect(reliabilitySeverity(8)).toBe('ok');
    expect(reliabilitySeverity(7.9)).toBe('info');
    expect(reliabilitySeverity(4.9)).toBe('warn');
    expect(reliabilitySeverity(2.9)).toBe('crit');
    expect(reliabilityFalling(clone(demoScan).pc!.reliability)).toBe(true);
    expect(reliabilityFalling(clone(clinicScan).pc!.reliability)).toBe(false);
  });

  it('casa: 4,2 in calo, con gli aggiornamenti non riusciti; clinica: 9,1', () => {
    const f = find(clone(demoScan), 'pc.reliability')!;
    expect(f.severity).toBe('warn');
    expect(f.value).toBe('4,2 su 10, in calo');
    expect(f.verdict).toContain('3 aggiornamenti non riusciti');
    expect(f.actions).toEqual(['review-reliability', 'update-windows']);
    const c = find(clone(clinicScan), 'pc.reliability')!;
    expect(c.severity).toBe('ok');
    expect(c.value).toBe('9,1 su 10');
  });

  it('non disponibile: informazione su Windows Server o se disattivato, altrimenti non misurato', () => {
    const s = clone(demoScan);
    s.pc!.reliability = { available: false, reason: 'no-data' };
    expect(find(s, 'pc.reliability')!.severity).toBe('unknown');
    s.pc!.reliability = { available: false, reason: 'disabled', wmiEnabled: false };
    expect(find(s, 'pc.reliability')!.severity).toBe('info');
    s.pc!.reliability = { available: false, reason: 'no-data' };
    s.pc!.os!.server = true;
    const f = find(s, 'pc.reliability')!;
    expect(f.severity).toBe('info');
    expect(f.verdict).toContain('su Windows Server è disattivato');
  });
});

describe('catalogo, guida, documento e scheda', () => {
  it('voci, azioni e guida', () => {
    for (const id of ['pc.boot', 'pc.boot.slow', 'pc.boot.firmware', 'pc.boot.shutdown', 'pc.apps', 'pc.reliability']) expect(METRICS[id], id).toBeTruthy();
    for (const id of ['update-app', 'repair-windows', 'check-firmware-boot', 'review-reliability']) expect(ACTIONS[id], id).toBeTruthy();
    expect(guideById('avvio-affidabilita')!.metrics).toContain('pc.reliability');
  });

  it('il documento riporta avvio, programmi e indice', () => {
    const s = clone(demoScan);
    const html = documentParts(s, analyze(s)).body;
    expect(html).toContain('<h2>Avvio e affidabilità</h2>');
    expect(html).toContain('<b>1 min 42 s</b>');
    expect(html).toContain('AcmePhotoStudio.exe');
    expect(html).toContain('<b>4,2 su 10</b>');
  });

  it('la scheda mostra i quattro blocchi e il pulsante solo con l\'agente', () => {
    const s = clone(demoScan);
    const html = renderToStaticMarkup(createElement(StabilityCard, { pc: s.pc!, live: false }));
    expect(html).toContain('Durata dell&#x27;avvio');
    expect(html).toContain('Acme Update Service');
    expect(html).toContain('AcmePhotoStudio.exe');
    expect(html).toContain('4,2');
    expect(html).toContain('dopo un aggiornamento');
    expect(html).not.toContain('Apri Monitoraggio affidabilità');
    const live = renderToStaticMarkup(createElement(StabilityCard, { pc: clone(clinicScan).pc!, live: true }));
    expect(live).toContain('Apri Monitoraggio affidabilità');
    expect(live).toContain('Nessun programma si è chiuso da solo');
    const none = clone(s.pc!);
    delete none.boot;
    delete none.apps;
    delete none.reliability;
    expect(renderToStaticMarkup(createElement(StabilityCard, { pc: none, live: false }))).toBe('');
  });
});
