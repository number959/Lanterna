import { describe, expect, it } from 'vitest';
import { analyze, deviceSeverity, documentParts, failedUpdates, lastQualityUpdate, msText, oldDrivers, symbolicDate, wuErrorText } from '../src/engine';
import type { DeviceInfo, DevicesData, Finding, Scan, UpdateEntry } from '../src/engine';
import { clinicScan } from '../src/demo/clinic';
import { demoScan } from '../src/demo/sample';

// Correzioni della revisione indipendente della 0.12.0: ogni caso riproduce
// un difetto trovato (falso negativo, testo sbagliato, eccezione) e ne
// fissa il comportamento corretto.

const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const find = (s: Scan, id: string): Finding | undefined => analyze(s).findings.find((f) => f.id === id);
const entry = (p: Partial<UpdateEntry>): UpdateEntry => ({ title: 'Aggiornamento (KB5000001)', kb: 'KB5000001', kind: 'quality', operation: 'install', result: 'succeeded', date: '2026-10-01T03:00:00Z', ...p });
const NOW = Date.parse('2026-10-12T20:30:00Z');

describe('ultimo aggiornamento di Windows', () => {
  it('lo strumento di rimozione malware e gli aggiornamenti di altri prodotti non contano', () => {
    const u = {
      pendingReboot: false,
      history: [
        entry({ title: 'Windows Malicious Software Removal Tool x64 - v5.130 (KB890830)', kb: 'KB890830', date: '2026-10-08T03:00:00Z' }),
        entry({ title: '2026-10 Aggiornamento cumulativo per .NET Framework 3.5 e 4.8.1 (KB5066000)', kb: 'KB5066000', date: '2026-10-07T03:00:00Z' }),
        entry({ title: '2025-06 Aggiornamento cumulativo per Windows 11 (KB5060000)', kb: 'KB5060000', date: '2025-06-11T03:00:00Z' }),
      ],
    };
    expect(lastQualityUpdate(u, NOW)).toEqual({ date: '2025-06-11T03:00:00Z', kb: 'KB5060000' });
  });

  it('una data nel futuro (formato regionale sbagliato) non nasconde quelle valide', () => {
    const u = { pendingReboot: false, lastInstalled: '2027-09-10', lastKB: 'KB1', history: [entry({ date: '2026-10-01T03:00:00Z', kb: 'KB2' })] };
    expect(lastQualityUpdate(u, NOW)).toEqual({ date: '2026-10-01T03:00:00Z', kb: 'KB2' });
    const s = clone(demoScan);
    s.agent.startedAt = '2026-10-12T20:30:00Z';
    s.pc!.updates = u;
    expect(find(s, 'pc.updates')?.value).toContain('KB2');
  });
});

describe('aggiornamenti non riusciti', () => {
  it('un cumulativo fallito e poi sostituito da quello del mese dopo è risolto', () => {
    const h = [
      entry({ title: '2026-10 Aggiornamento cumulativo per Windows 11 Version 24H2 per sistemi basati su x64 (KB5066835)', kb: 'KB5066835', date: '2026-10-10T03:00:00Z' }),
      entry({ title: '2026-09 Aggiornamento cumulativo per Windows 11 Version 24H2 per sistemi basati su x64 (KB5065426)', kb: 'KB5065426', result: 'failed', hresult: '0x800F081F', date: '2026-09-20T03:00:00Z' }),
    ];
    expect(failedUpdates(h, NOW)).toEqual([{ entry: h[1], resolved: true }]);
  });

  it('i driver rifiutati con 0x80070103 non contano', () => {
    const h = [entry({ title: 'Acme - Net - 22.40.0.7', kb: undefined, kind: 'driver', result: 'failed', hresult: '0x80070103', date: '2026-10-05T03:00:00Z' })];
    expect(failedUpdates(h, NOW)).toEqual([]);
    expect(wuErrorText('0x80070103')).toContain('ERROR_NO_MORE_ITEMS');
  });

  it('nomi Microsoft dei codici di Configurazione', () => {
    expect(wuErrorText('0xC1900101')).toContain('MOSETUP_E_SETUP_PLATFORM');
    expect(wuErrorText('0xC190020E')).toContain('MOSETUP_E_INSTALLDISKSPACE_BLOCK');
  });
});

describe('documento', () => {
  it('le versioni dei driver non diventano indirizzi IP pubblici', () => {
    const body = documentParts(demoScan, analyze(demoScan)).body;
    expect(body).toContain('Acme 22.40.0.7');
    expect(body).not.toMatch(/Acme \[IP pubblico\]/);
  });
});

describe('dispositivi e driver', () => {
  const drv = (date: string): DevicesData => ({
    total: 1,
    problems: 0,
    items: [{ name: 'Intel(R) SMBus - A0A3', class: 'System', enumerator: 'PCI', driver: { provider: 'INTEL', version: '10.1.37.6', date, inf: 'oem7.inf' } }],
  });

  it('la data simbolica 18/07/1968 dei driver Intel del chipset non vale come età', () => {
    expect(symbolicDate('1968-07-18')).toBe(true);
    expect(symbolicDate('2016-03-01')).toBe(false);
    expect(oldDrivers(drv('1968-07-18'), NOW)).toEqual([]);
    expect(oldDrivers(drv('2016-03-01'), NOW).length).toBe(1);
  });

  it('una scheda di rete virtuale con un problema non è grave come una vera', () => {
    const virt: DeviceInfo = { name: 'WAN Miniport (IP)', class: 'Net', enumerator: 'ROOT', problem: 10 };
    expect(deviceSeverity(virt)).toBe('warn');
    expect(deviceSeverity({ ...virt, name: 'Acme Ethernet', enumerator: 'PCI' })).toBe('crit');
  });
});

describe('porte USB', () => {
  it('un dispositivo non riconosciuto già contato tra i dispositivi (codice 43) non pesa due volte', () => {
    const s = clone(demoScan);
    s.pc!.usb = {
      read: 'ok',
      controllers: [{ name: 'x', kind: 'xhci', hub: { kind: 'root', portCount: 2, ports: [{ index: 1, status: 'failed-enumeration' }] } }],
    };
    s.pc!.devices!.items = s.pc!.devices!.items.filter((d) => d.problem !== 43);
    const alone = find(s, 'pc.usb.ports')!;
    expect(alone.severity).toBe('warn');
    expect(alone.verdict).not.toContain('dove è già contato');
    s.pc!.devices!.items.push({ name: 'Dispositivo USB sconosciuto (richiesta del descrittore non riuscita)', class: 'USB', enumerator: 'USB', problem: 43 });
    const both = find(s, 'pc.usb.ports')!;
    expect(both.severity).toBe('info');
    expect(both.verdict).toContain('dove è già contato');
  });
});

describe('errori del file system su unità rimovibili', () => {
  it('una chiavetta (E:, rimovibile) non viene presentata come disco interno', () => {
    const s = clone(demoScan);
    s.pc!.eventsDays = 30;
    s.pc!.events = [
      { kind: 'filesystem', source: 'Ntfs', id: 55, count: 2, last: '2026-10-08T10:03:44Z', detail: 'E:' },
      { kind: 'fs-flush', source: 'Ntfs', id: 140, count: 1, last: '2026-10-08T10:04:00Z', detail: 'E:' },
    ];
    const f = find(s, 'pc.events.disk')!;
    expect(f.verdict).toContain('unità USB o rimovibili');
    expect(f.verdict).not.toContain('disco interno');
    expect(f.actions).not.toContain('backup-replace-disk');
  });
});

describe('protezione e accessi', () => {
  it('blocco dello schermo dopo 30 minuti: c\'è, ma oltre i 15 consigliati', () => {
    const s = clone(clinicScan);
    s.pc!.access = { ...s.pc!.access, lock: { inactivitySec: 1800 } };
    const f = find(s, 'pc.lock')!;
    expect(f.severity).toBe('info');
    expect(f.value).toBe('dopo 30 minuti (oltre i 15 consigliati)');
    s.pc!.access!.lock = { inactivitySec: 60 };
    expect(find(s, 'pc.lock')!.value).toBe('dopo 1 minuto');
  });

  it('backup non letti: nessun giudizio "nessun backup"', () => {
    const s = clone(demoScan);
    s.pc!.os = { ...s.pc!.os!, server: false };
    s.pc!.backup = { imageBackup: { read: 'denied', days: 90 }, oneDrive: [] };
    const f = find(s, 'pc.backup')!;
    expect(f.severity).toBe('unknown');
    expect(f.value).toBe('non letto');
  });

  it('punti di ripristino senza la data dell\'ultimo: niente eccezioni', () => {
    const s = clone(demoScan);
    s.pc!.os = { ...s.pc!.os!, server: false };
    s.pc!.backup = { restorePoints: { read: 'ok', count: 3 } };
    const f = find(s, 'pc.restore')!;
    expect(f.value).toBe('3');
    expect(f.severity).toBe('ok');
  });
});

describe('testi', () => {
  it('le durate arrotondano prima i secondi totali', () => {
    expect(msText(119600)).toBe('2 min');
    expect(msText(179700)).toBe('3 min');
    expect(msText(95000)).toBe('1 min 35 s');
  });

  it('niente doppi due punti né plurali con 1 nei giudizi delle demo', () => {
    for (const s of [demoScan, clinicScan]) {
      for (const f of analyze(s).findings) {
        expect(f.verdict, f.id).not.toMatch(/[A-Z]::/);
        expect(`${f.value} ${f.verdict}`, f.id).not.toMatch(/\b1 (errori|volte|passaggi|minuti|controlli|porte|programmi)\b/);
      }
    }
  });
});
