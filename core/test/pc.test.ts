import { describe, expect, it } from 'vitest';
import { clinicScan } from '../src/demo/clinic';
import { demoScan } from '../src/demo/sample';
import { analyze, renderText } from '../src/engine';
import type { PcData, Scan } from '../src/engine';
import { on } from '../src/engine/pc';
import { cacheText, channelMode, coreLayout, memVendor } from '../src/engine/hardware';
import { attrState, diskStatus, smartName, smartRaw } from '../src/engine/smart';
import type { DefenderInfo, Hardware, HwModule, NVMeHealth, SmartAttr, Threat } from '../src/engine/types';
import { base } from './fixtures';

// Scansione sana con un computer in ordine: ogni test cambia solo ciò che verifica.
function healthyPc(): PcData {
  return {
    os: { name: 'Windows 11 Pro', version: '25H2', build: 26200, ubr: 6899, edition: 'Professional', uptimeSec: 2 * 86400, fastStartup: true },
    cpu: { name: 'CPU di prova', cores: 8, threads: 16, loadPct: 12 },
    memory: { totalMB: 16000, availableMB: 9000, commitMB: 9000, commitLimitMB: 20000 },
    gpus: [{ name: 'Scheda video', driverVersion: '1.0', driverDate: '2026-03-01' }],
    disks: [{ id: '0', name: 'SSD di prova', media: 'ssd', bus: 'NVMe', sizeGB: 1000, health: 'healthy', system: true }],
    volumes: [{ letter: 'C:', kind: 'fixed', sizeGB: 1000, freeGB: 500, system: true, disk: '0' }],
    power: { planKind: 'balanced', onAC: true },
    startup: [{ name: 'SecurityHealth', location: 'machine', enabled: true }],
    events: [],
    eventsDays: 30,
    antivirus: [{ name: 'Microsoft Defender Antivirus', enabled: true, upToDate: true }],
    updates: { lastInstalled: '2026-09-25', pendingReboot: false },
  };
}

function scanWith(pc: PcData, date = '2026-10-15T10:00:00Z'): Scan {
  const s = base();
  s.agent.startedAt = date;
  s.pc = pc;
  return s;
}

const run = (pc: PcData, date?: string) => analyze(scanWith(pc, date));
const find = (pc: PcData, id: string, date?: string) => run(pc, date).findings.find((f) => f.id === id);
const sevOf = (pc: PcData, id: string, date?: string) => find(pc, id, date)?.severity;
const edit = (fn: (p: PcData) => void) => {
  const p = healthyPc();
  fn(p);
  return p;
};

describe('computer: sistema operativo', () => {
  it('un PC in ordine non genera avvisi', () => {
    const a = run(healthyPc());
    const pc = a.findings.filter((f) => f.id.startsWith('pc.'));
    expect(pc.length).toBeGreaterThan(10);
    expect(pc.filter((f) => f.severity !== 'ok').map((f) => f.id)).toEqual([]);
    expect(a.categories.find((c) => c.category === 'pc')?.score).toBe(100);
  });

  it.each([
    ['Windows 11 Home', '23H2', 22631, 'Core', '2026-10-15', 'warn'],
    ['Windows 11 Home', '24H2', 26100, 'Core', '2026-09-01', 'info'],
    ['Windows 11 Home', '24H2', 26100, 'Core', '2026-10-15', 'warn'],
    ['Windows 11 Enterprise', '24H2', 26100, 'Enterprise', '2026-10-15', 'ok'],
    ['Windows 11 Education', '23H2', 22631, 'Education', '2026-10-01', 'info'],
    ['Windows 11 Pro', '25H2', 26200, 'Professional', '2026-10-15', 'ok'],
    ['Windows 10 Pro', '22H2', 19045, 'Professional', '2026-10-15', 'warn'],
    ['Windows 10 Home', '22H2', 19045, 'Core', '2026-06-01', 'warn'],
    ['Windows 10 Home', '22H2', 19045, 'Core', '2026-10-15', 'crit'],
    ['Windows 10 Enterprise LTSC 2021', '21H2', 19044, 'EnterpriseS', '2026-10-15', 'info'],
    ['Windows 8.1', '', 9600, 'Core', '2026-10-15', 'crit'],
    ['Windows 11 Pro', '26H2', 26300, 'Professional', '2026-10-15', 'info'],
  ])('%s %s (%s) il %s → %s', (name, version, build, edition, date, sev) => {
    const p = edit((x) => (x.os = { name, version: version || undefined, build, edition }));
    expect(sevOf(p, 'pc.os', `${date}T12:00:00Z`)).toBe(sev);
  });

  it('ricava la versione dalla build quando manca', () => {
    const f = find(edit((x) => (x.os = { name: 'Windows 11 Pro', build: 22631, edition: 'Professional' })), 'pc.os');
    expect(f?.value).toContain('23H2');
    expect(f?.verdict).toContain("dall'11 novembre 2025");
  });

  it('Windows Server: da verificare, senza calendario', () => {
    expect(sevOf(edit((x) => (x.os = { name: 'Windows Server 2022 Standard', build: 20348, server: true })), 'pc.os')).toBe('info');
  });

  it('scrive le date con le preposizioni giuste', () => {
    expect(on('2026-10-08', 'il')).toBe("l'8 ottobre 2026");
    expect(on('2025-11-11', 'dal')).toBe("dall'11 novembre 2025");
    expect(on('2026-11-01', 'al')).toBe('al 1° novembre 2026');
    expect(on('2025-10-14', 'il')).toBe('il 14 ottobre 2025');
  });
});

describe('computer: riavvio, memoria, processore', () => {
  it.each([
    [3, 'ok'],
    [8, 'info'],
    [31, 'warn'],
  ])('acceso da %i giorni → %s', (days, sev) => {
    expect(sevOf(edit((x) => (x.os!.uptimeSec = days * 86400)), 'pc.uptime')).toBe(sev);
  });

  it('con l\'avvio rapido spiega che serve "Riavvia"', () => {
    expect(find(edit((x) => (x.os!.uptimeSec = 40 * 86400)), 'pc.uptime')?.verdict).toContain('Riavvia');
  });

  it('riavvio in sospeso per aggiornamenti: avviso', () => {
    const p = edit((x) => (x.updates = { lastInstalled: '2026-10-10', pendingReboot: true, rebootReasons: ['Windows Update'] }));
    const f = find(p, 'pc.reboot');
    expect(f?.severity).toBe('warn');
    expect(f?.actions).toEqual(['restart-pc']);
    const files = edit((x) => (x.updates = { lastInstalled: '2026-10-10', pendingReboot: true, rebootReasons: ['file da sostituire al riavvio'] }));
    expect(sevOf(files, 'pc.reboot')).toBe('info');
  });

  it.each([
    [2048, 'crit'],
    [3900, 'warn'],
    [6100, 'warn'],
    [7800, 'ok'],
    [32000, 'ok'],
  ])('RAM %i MB → %s', (mb, sev) => {
    expect(sevOf(edit((x) => (x.memory = { totalMB: mb, availableMB: mb / 2 })), 'pc.ram')).toBe(sev);
  });

  it('memoria quasi esaurita o impegno oltre il 90 %: avviso con i processi più pesanti', () => {
    const p = edit((x) => {
      x.memory = { totalMB: 8000, availableMB: 600 };
      x.processes = [{ name: 'chrome.exe', count: 20, cpuPct: 3, memoryMB: 2500 }];
    });
    const f = find(p, 'pc.ramuse');
    expect(f?.severity).toBe('warn');
    expect(f?.verdict).toContain('chrome.exe');
    expect(f?.actions).toEqual(['close-heavy-apps', 'add-ram']);
    expect(sevOf(edit((x) => (x.memory = { totalMB: 16000, availableMB: 8000, commitMB: 19000, commitLimitMB: 20000 })), 'pc.ramuse')).toBe('warn');
    expect(sevOf(edit((x) => (x.memory = { totalMB: 16000, availableMB: 2500 })), 'pc.ramuse')).toBe('info');
  });

  it.each([
    [30, 'ok'],
    [60, 'info'],
    [85, 'warn'],
  ])('carico %i %% → %s', (load, sev) => {
    expect(sevOf(edit((x) => (x.cpu!.loadPct = load)), 'pc.cpuload')).toBe(sev);
  });

  it('descrive il carico in modo coerente con il valore', () => {
    expect(find(edit((x) => (x.cpu!.loadPct = 10)), 'pc.cpuload')?.verdict).toContain('quasi libero');
    expect(find(edit((x) => (x.cpu!.loadPct = 43)), 'pc.cpuload')?.verdict).toContain('capacità libera');
  });

  it('riconosce i processi della finestra di Polaris', () => {
    const p = edit((x) => {
      x.cpu!.loadPct = 70;
      x.processes = [{ name: 'msedgewebview2.exe', count: 6, cpuPct: 20, memoryMB: 300 }];
    });
    expect(find(p, 'pc.cpuload')?.verdict).toContain('anche la finestra di Polaris');
  });
});

describe('computer: dischi', () => {
  it('disco guasto o con guasto previsto: critico, prima azione salvare i dati', () => {
    for (const d of [
      { health: 'unhealthy' as const },
      { health: 'warning' as const },
      { health: 'healthy' as const, operational: ['Predictive Failure'] },
    ]) {
      const f = find(edit((x) => Object.assign(x.disks![0], d)), 'pc.disk.0');
      expect(f?.severity).toBe('crit');
      expect(f?.actions[0]).toBe('backup-replace-disk');
    }
  });

  it('errori non correggibili, usura e temperatura', () => {
    const rel = (r: object, media: 'ssd' | 'hdd' = 'ssd') =>
      sevOf(
        edit((x) => {
          x.disks![0].media = media;
          x.disks![0].reliability = r;
        }),
        'pc.disk.0',
      );
    expect(rel({ readUncorrected: 3 })).toBe('warn');
    expect(rel({ wearPct: 69 })).toBe('ok');
    expect(rel({ wearPct: 75 })).toBe('warn');
    expect(rel({ wearPct: 92 })).toBe('crit');
    expect(rel({ wearPct: 95 }, 'hdd')).toBe('ok'); // l'usura conta solo per gli SSD
    expect(rel({ temperatureC: 72 })).toBe('warn');
    expect(rel({ temperatureC: 81 })).toBe('crit');
    expect(rel({ temperatureC: 56 }, 'hdd')).toBe('warn');
    expect(rel({ temperatureC: 61 }, 'hdd')).toBe('crit');
  });

  it('senza dati SMART suggerisce di avviare come amministratore', () => {
    const s = scanWith(healthyPc());
    s.agent.elevated = false;
    const f = analyze(s).findings.find((x) => x.id === 'pc.disk.0');
    expect(f?.severity).toBe('ok');
    expect(f?.verdict).toContain('amministratore');
  });

  it('dati SMART presenti: niente invito ad avviare come amministratore', () => {
    const p = edit((x) => (x.disks![0].nvme = nvme()));
    const s = scanWith(p);
    s.agent.elevated = false;
    const f = analyze(s).findings.find((x) => x.id === 'pc.disk.0');
    expect(f?.verdict).not.toContain('amministratore');
    expect(f?.value).toContain('Buono 97 %');
  });

  it('Windows su un disco meccanico: avviso con il passaggio a SSD', () => {
    const f = find(edit((x) => (x.disks![0].media = 'hdd')), 'pc.systemdisk');
    expect(f?.severity).toBe('warn');
    expect(f?.actions).toEqual(['upgrade-ssd']);
  });

  it.each([
    [true, 1000, 4, 'crit'],
    [true, 1000, 40, 'crit'],
    [true, 1000, 90, 'warn'],
    [true, 100, 12, 'warn'],
    [true, 256, 60, 'ok'],
    [false, 1000, 70, 'info'],
    [false, 1000, 40, 'warn'],
  ])('spazio: sistema=%s, %i GB con %i GB liberi → %s', (system, size, free, sev) => {
    const p = edit((x) => (x.volumes = [{ letter: system ? 'C:' : 'D:', kind: 'fixed', sizeGB: size, freeGB: free, system }]));
    expect(sevOf(p, `pc.space.${system ? 'C' : 'D'}`)).toBe(sev);
  });

  it('le unità rimovibili non vengono giudicate per lo spazio', () => {
    const p = edit((x) => x.volumes!.push({ letter: 'E:', kind: 'removable', sizeGB: 32, freeGB: 0.1 }));
    expect(find(p, 'pc.space.E')).toBeUndefined();
  });
});

describe('computer: avvio ed eventi', () => {
  it.each([
    [8, 'ok'],
    [12, 'info'],
    [16, 'warn'],
  ])('%i programmi all\'avvio → %s', (n, sev) => {
    const p = edit((x) => (x.startup = Array.from({ length: n + 2 }, (_, i) => ({ name: `p${i}`, location: 'user' as const, enabled: i < n }))));
    expect(sevOf(p, 'pc.startup')).toBe(sev);
  });

  it('Kernel-Power 41 ed EventLog 6008 dello stesso episodio non si sommano', () => {
    const p = edit((x) => {
      x.events = [
        { kind: 'unexpected-shutdown', source: 'Microsoft-Windows-Kernel-Power', id: 41, count: 2, last: '2026-10-03T07:41:12Z' },
        { kind: 'unexpected-shutdown', source: 'EventLog', id: 6008, count: 2, last: '2026-10-03T07:41:40Z' },
      ];
    });
    const f = find(p, 'pc.events.shutdown');
    expect(f?.value).toBe('2 in 30 giorni');
    expect(f?.severity).toBe('info');
    expect(f?.verdict).toContain('il 3 ottobre 2026');
  });

  it('schermate blu: codice spiegato, ripetute = critico', () => {
    const p = edit((x) => {
      x.events = [{ kind: 'bugcheck', source: 'Microsoft-Windows-WER-SystemErrorReporting', id: 1001, count: 2, last: '2026-10-01T10:00:00Z', detail: '0x00000124 (0x0, 0x1)' }];
    });
    const f = find(p, 'pc.events.bsod');
    expect(f?.severity).toBe('crit');
    expect(f?.verdict).toContain('WHEA_UNCORRECTABLE_ERROR');
    expect(f?.actions).toEqual(['diagnose-bsod', 'check-hardware']);
  });

  it('errori di disco: unità USB, disco interno, molti errori', () => {
    const withEvents = (events: PcData['events'], usb = false) =>
      find(
        edit((x) => {
          x.events = events;
          x.disks!.push({ id: '1', name: 'Chiavetta', media: 'unknown', bus: usb ? 'USB' : 'SATA', sizeGB: 32 });
        }),
        'pc.events.disk',
      );
    const usbOnly = withEvents([{ kind: 'disk-retry', source: 'disk', id: 153, count: 30, last: '2026-10-09T18:00:00Z', detail: '\\Device\\Harddisk1\\DR1' }], true);
    expect(usbOnly?.severity).toBe('info');
    expect(usbOnly?.verdict).toContain('Rimozione sicura');
    const internal = withEvents([{ kind: 'disk-error', source: 'disk', id: 7, count: 3, last: '2026-10-09T18:00:00Z', detail: '\\Device\\Harddisk1\\DR1' }]);
    expect(internal?.severity).toBe('warn');
    expect(internal?.actions).toEqual(['check-disk-errors', 'backup-replace-disk']);
    expect(withEvents([{ kind: 'disk-error', source: 'disk', id: 7, count: 25, last: '2026-10-09T18:00:00Z' }])?.severity).toBe('crit');
  });

  it('errori hardware WHEA', () => {
    const w = (events: PcData['events']) => sevOf(edit((x) => (x.events = events)), 'pc.events.whea');
    expect(w([{ kind: 'whea-corrected', source: 'Microsoft-Windows-WHEA-Logger', id: 19, count: 3, last: '2026-10-01T00:00:00Z' }])).toBe('info');
    expect(w([{ kind: 'whea-corrected', source: 'Microsoft-Windows-WHEA-Logger', id: 19, count: 12, last: '2026-10-01T00:00:00Z' }])).toBe('warn');
    expect(w([{ kind: 'whea-fatal', source: 'Microsoft-Windows-WHEA-Logger', id: 18, count: 1, last: '2026-10-01T00:00:00Z' }])).toBe('crit');
  });

  it('registro non letto: nessun giudizio sugli eventi', () => {
    const a = run(edit((x) => (x.eventsDays = undefined)));
    expect(a.findings.filter((f) => f.id.startsWith('pc.events.'))).toEqual([]);
  });
});

describe('computer: sicurezza, batteria, alimentazione, video', () => {
  it('antivirus', () => {
    const av = (list: PcData['antivirus']) => find(edit((x) => (x.antivirus = list)), 'pc.av');
    expect(av(null)).toBeUndefined();
    expect(av([])?.severity).toBe('crit');
    expect(av([{ name: 'Defender', enabled: false, upToDate: true }])?.severity).toBe('crit');
    expect(av([{ name: 'Defender', enabled: true, upToDate: false }])?.severity).toBe('warn');
    const other = av([
      { name: 'Altro antivirus', enabled: true, upToDate: true },
      { name: 'Windows Defender', enabled: false, upToDate: true },
    ]);
    expect(other?.severity).toBe('ok');
    expect(other?.category).toBe('security');
    expect(other?.verdict).toContain('è normale');
  });

  it('aggiornamenti: soglie e date impossibili', () => {
    const up = (d: string) => find(edit((x) => (x.updates = { lastInstalled: d, pendingReboot: false })), 'pc.updates');
    expect(up('2026-10-01')?.severity).toBe('ok');
    expect(up('2026-09-01')?.severity).toBe('info');
    expect(up('2026-07-01')?.severity).toBe('warn');
    expect(up('2026-12-10')).toBeUndefined(); // data nel futuro: formato regionale letto male
  });

  it('batteria e piano di alimentazione', () => {
    expect(sevOf(edit((x) => (x.battery = { designMWh: 50000, fullMWh: 47000 })), 'pc.battery')).toBe('ok');
    expect(sevOf(edit((x) => (x.battery = { designMWh: 50000, fullMWh: 35000 })), 'pc.battery')).toBe('info');
    expect(sevOf(edit((x) => (x.battery = { designMWh: 50000, fullMWh: 20000 })), 'pc.battery')).toBe('warn');
    expect(sevOf(edit((x) => (x.power = { planKind: 'saver', onAC: true, hasBattery: true })), 'pc.power')).toBe('warn');
    expect(sevOf(edit((x) => (x.power = { planKind: 'saver', onAC: false, hasBattery: true })), 'pc.power')).toBe('ok');
    expect(sevOf(edit((x) => (x.power = { planKind: 'high', onAC: false, hasBattery: true })), 'pc.power')).toBe('info');
  });

  it('driver video', () => {
    expect(sevOf(edit((x) => (x.gpus = [{ name: 'Microsoft Basic Display Adapter' }])), 'pc.gpu')).toBe('warn');
    expect(sevOf(edit((x) => (x.gpus = [{ name: 'Scheda video', driverDate: '2021-01-10' }])), 'pc.gpu')).toBe('info');
    expect(find(edit((x) => (x.gpus = [{ name: 'Microsoft Hyper-V Video', driverDate: '2006-06-21' }])), 'pc.gpu')).toBeUndefined();
  });
});

describe('computer: test di velocità', () => {
  const cpu = (single: number, multi: number, sustained: number, threads = 8) =>
    find(edit((x) => (x.bench = { cpu: { startedAt: '2026-10-15T10:05:00Z', threads, singleMBs: single, multiMBs: multi, sustainedMBs: sustained, durationMs: 23000 } })), 'pc.cpubench');

  it('processore stabile, che rallenta o che non usa i core', () => {
    expect(cpu(40, 240, 236)?.severity).toBe('ok');
    expect(cpu(40, 240, 210)?.severity).toBe('info');
    const hot = cpu(40, 240, 150);
    expect(hot?.severity).toBe('warn');
    expect(hot?.actions).toContain('cool-cpu');
    const capped = cpu(40, 50, 50);
    expect(capped?.severity).toBe('warn');
    expect(capped?.actions).toEqual(['power-plan', 'close-heavy-apps']);
  });

  const disk = (media: 'ssd' | 'hdd', bus: string, seq: number, rnd: number, kind: 'fixed' | 'removable' = 'fixed', write = 300) =>
    find(
      edit((x) => {
        x.disks = [{ id: '0', name: 'Unità', media, bus, sizeGB: 500, health: 'healthy', system: true }];
        x.volumes = [{ letter: 'C:', kind, sizeGB: 500, freeGB: 300, system: true, disk: '0' }];
        x.bench = { disk: [{ startedAt: '2026-10-15T10:05:00Z', drive: 'C:', fileMB: 1024, seqReadMBs: seq, seqWriteMBs: write, rndReadMBs: rnd, rndReadIops: rnd * 244, rndWriteMBs: rnd, rndWriteIops: rnd * 244, durationMs: 30000 }] };
      }),
      'pc.diskbench.C',
    );

  it('confronta la velocità con quella tipica del tipo di unità', () => {
    expect(disk('ssd', 'NVMe', 2400, 55)?.severity).toBe('ok');
    expect(disk('ssd', 'NVMe', 380, 30)?.severity).toBe('warn');
    expect(disk('ssd', 'SATA', 380, 30)?.severity).toBe('ok');
    expect(disk('ssd', 'SATA', 520, 6)?.severity).toBe('warn');
    expect(disk('hdd', 'SATA', 140, 0.9)?.severity).toBe('ok');
    expect(disk('hdd', 'SATA', 35, 0.9)?.severity).toBe('warn');
    expect(disk('ssd', 'USB', 30, 2, 'removable', 6)?.severity).toBe('info');
  });

  it('test del disco con il profilo CrystalDiskMark: collegamento lento e valori nel rapporto', () => {
    const prof = (bus: string, q8: number) =>
      find(
        edit((x) => {
          x.disks = [{ id: '0', name: 'Unità', media: 'ssd', bus, sizeGB: 500, health: 'healthy', system: true }];
          x.volumes = [{ letter: 'C:', kind: 'fixed', sizeGB: 500, freeGB: 300, system: true, disk: '0' }];
          x.bench = {
            disk: [
              {
                startedAt: '2026-10-15T10:05:00Z', drive: 'C:', fileMB: 1024, seqReadMBs: 520, seqWriteMBs: 480, rndReadMBs: 35, rndReadIops: 8545, rndWriteMBs: 90, rndWriteIops: 21972,
                seqQ8ReadMBs: q8, seqQ8WriteMBs: 500, rndQ32ReadMBs: 380, rndQ32ReadIops: 92773, rndQ32WriteMBs: 300, rndQ32WriteIops: 73242, durationMs: 40000,
              },
            ],
          };
        }),
        'pc.diskbench.C',
      );
    expect(prof('SATA', 560)?.severity).toBe('ok');
    // SATA vicino ai 280 MB/s: porta a 3 Gbit/s o modalità IDE.
    const sata2 = prof('SATA', 275);
    expect(sata2?.severity).toBe('info');
    expect(sata2?.verdict).toContain('AHCI');
    expect(prof('NVMe', 3400)?.severity).toBe('ok');
    expect(prof('NVMe', 850)?.verdict).toContain('linee PCIe');
    expect(prof('NVMe', 3400)?.value).toBe('sequenziale 3400 MB/s · casuale 4K 35 MB/s');
  });

  it('rapporto testuale con la tabella del profilo', () => {
    const s = scanWith(
      edit((x) => {
        x.bench = {
          disk: [
            {
              startedAt: '2026-10-15T10:05:00Z', drive: 'C:', fileMB: 1024, seqReadMBs: 2870, seqWriteMBs: 1410, rndReadMBs: 58.6, rndReadIops: 14307, rndWriteMBs: 152, rndWriteIops: 37109,
              seqQ8ReadMBs: 3480, seqQ8WriteMBs: 3050, rndQ32ReadMBs: 610, rndQ32ReadIops: 148926, rndQ32WriteMBs: 420, rndQ32WriteIops: 102539, durationMs: 33000,
            },
          ],
        };
      }),
    );
    const t = renderText(s, analyze(s));
    expect(t).toContain('SEQ1M Q8T1 (sequenziale, 8 in coda)');
    expect(t).toMatch(/RND4K Q32T1 \(casuale 4K, 32 in coda\)\s+610 MB\/s\s+420 MB\/s/);
  });
});

describe('computer: sintesi e rapporto', () => {
  it('la categoria Computer pesa nel punteggio e il titolo parla di PC e rete', () => {
    const ok = run(healthyPc());
    expect(ok.categories.map((c) => c.category)).toContain('pc');
    const warn = run(edit((x) => (x.power = { planKind: 'saver', onAC: true })));
    expect(warn.headline).toMatch(/^PC e rete/);
    expect(warn.score).toBeLessThan(ok.score);
    // Senza dati del computer il testo resta quello della sola rete.
    const s = base();
    s.dns!.system[0].timeMs = 180;
    expect(analyze(s).headline).toMatch(/^Rete/);
  });

  it('un disco che sta per guastarsi è il problema più urgente e la prima azione', () => {
    const a = analyze(clinicScan);
    expect(a.headline).toContain('Il più urgente (Computer): salute del disco 1');
    expect(a.plan[0].action.id).toBe('backup-replace-disk');
  });

  it('le demo hanno i dati del computer e i giudizi attesi', () => {
    const home = analyze(demoScan);
    const sev = (id: string) => home.findings.find((f) => f.id === id)?.severity;
    expect(sev('pc.space.C')).toBe('crit');
    expect(sev('pc.os')).toBe('warn');
    expect(sev('pc.power')).toBe('warn');
    expect(sev('pc.av')).toBe('ok');
    const clinic = analyze(clinicScan).findings;
    expect(clinic.find((f) => f.id === 'pc.disk.1')?.severity).toBe('crit');
    expect(clinic.find((f) => f.id === 'pc.events.disk')?.verdict).toContain('(D:)');
  });

  it('il rapporto testuale riporta i dettagli del computer', () => {
    const t = renderText(clinicScan, analyze(clinicScan), { verbose: true });
    expect(t).toContain('rapporto di diagnostica di PC e rete');
    expect(t).toContain('COMPUTER: DETTAGLI');
    expect(t).toContain('ST1000DM010-2EP102');
    expect(t).toContain('guasto previsto');
    expect(t).toContain('FirmaDigitale');
  });
});

const nvme = (o: Partial<NVMeHealth> = {}): NVMeHealth => ({
  criticalWarning: 0,
  temperatureC: 38,
  availableSparePct: 100,
  spareThresholdPct: 10,
  percentageUsed: 3,
  dataReadGB: 6321,
  dataWrittenGB: 5056.8,
  powerCycles: 1234,
  powerOnHours: 5120,
  unsafeShutdowns: 37,
  mediaErrors: 0,
  errorLogEntries: 12,
  warningTempMinutes: 0,
  criticalTempMinutes: 0,
  ...o,
});
const at = (id: number, current: number, worst: number, threshold: number | undefined, raw: number, flags = 0x32): SmartAttr => ({ id, flags, current, worst, threshold, raw });

describe('computer: dati SMART (stile CrystalDiskInfo)', () => {
  // Disco SATA meccanico non di sistema, senza contatori di Windows: conta solo SMART.
  const sata = (attrs: SmartAttr[]) =>
    find(
      edit((x) => {
        x.disks![0] = { id: '0', name: 'Disco SATA', media: 'hdd', bus: 'SATA', sizeGB: 1000, health: 'healthy', smart: attrs };
      }),
      'pc.disk.0',
    );

  it('attributo di pre-guasto alla soglia o sotto: critico, come smartctl', () => {
    const f = sata([at(0x05, 10, 10, 10, 1500, 0x33), at(0x09, 80, 80, 0, 20000)]);
    expect(f?.severity).toBe('crit');
    expect(f?.actions[0]).toBe('backup-replace-disk');
    expect(f?.verdict).toContain('05 Settori riallocati');
    expect(f?.value).toContain('Critico');
    expect(f?.value).toContain('20.000 ore');
  });

  it('attributo di invecchiamento sotto soglia: solo avviso', () => {
    expect(sata([at(0xc1, 30, 30, 40, 600000, 0x32)])?.severity).toBe('warn');
  });

  it('settori riallocati, in attesa e non correggibili: attenzione con controllo e backup', () => {
    const f = sata([at(0x05, 100, 100, 10, 8, 0x33), at(0xc5, 100, 100, 0, 2), at(0xc6, 100, 100, 0, 0)]);
    expect(f?.severity).toBe('warn');
    expect(f?.verdict).toContain('8 settori riallocati, 2 settori in attesa di riallocazione');
    expect(f?.actions).toEqual(['check-disk-errors', 'backup-replace-disk']);
    expect(f?.value).toContain('Attenzione');
  });

  it('soglie zero, segnaposto e soglie non reali non danno falsi allarmi', () => {
    const f = sata([at(0x05, 100, 100, 0, 0xffffffff, 0x33), at(0x01, 1, 1, 0, 0), at(0x03, 90, 90, 255, 0, 0x03), at(0xc6, 100, 100, undefined, 0)]);
    expect(f?.severity).toBe('ok');
    expect(f?.value).toContain('Buono');
  });

  it('valore peggiore sotto soglia in passato: nota senza cambiare lo stato', () => {
    const f = sata([at(0x07, 60, 40, 45, 0, 0x0f)]);
    expect(f?.severity).toBe('ok');
    expect(f?.verdict).toContain('in passato');
  });

  it('errori CRC: spiegati come problema di cavo, non del disco', () => {
    const f = sata([at(0xc7, 200, 200, 0, 31, 0x3e)]);
    expect(f?.severity).toBe('ok');
    expect(f?.verdict).toContain('cavo SATA');
  });

  const nv = (o: Partial<NVMeHealth>) =>
    find(
      edit((x) => {
        x.disks![0].nvme = nvme(o);
      }),
      'pc.disk.0',
    );

  it('NVMe: bit di avviso critico, riserva, errori, usura e temperatura', () => {
    expect(nv({})?.severity).toBe('ok');
    expect(nv({ criticalWarning: 0x01 })?.severity).toBe('crit');
    expect(nv({ criticalWarning: 0x08 })?.verdict).toContain('sola lettura');
    const hot = nv({ criticalWarning: 0x02 });
    expect(hot?.severity).toBe('warn');
    expect(hot?.actions).toContain('cool-disk');
    expect(nv({ availableSparePct: 5, spareThresholdPct: 10 })?.severity).toBe('crit');
    expect(nv({ mediaErrors: 3 })?.verdict).toContain('3 errori di integrità');
    expect(nv({ percentageUsed: 95 })?.severity).toBe('crit');
    expect(nv({ percentageUsed: 140 })?.value).toContain('Critico 0 %');
    expect(nv({ temperatureC: 74 })?.severity).toBe('warn');
    expect(nv({ unsafeShutdowns: 37 })?.verdict).toContain('37 spegnimenti non sicuri');
    expect(nv({ dataWrittenGB: 18730.2 })?.verdict).toContain('18,7 TB scritti');
  });

  it('stato complessivo: etichette, vita residua e fonti dei valori', () => {
    const base = { id: '0', name: 'D', media: 'ssd' as const, sizeGB: 500 };
    expect(diskStatus({ ...base }).label).toBe('Sconosciuto');
    const ok = diskStatus({ ...base, nvme: nvme() });
    expect([ok.label, ok.lifePct, ok.temperatureC, ok.powerOnHours, ok.powerCycles, ok.writtenGB]).toEqual(['Buono', 97, 38, 5120, 1234, 5056.8]);
    // I contatori di Windows hanno la precedenza; la temperatura ATA viene dal byte basso.
    const sataSsd = diskStatus({ ...base, reliability: { wearPct: 12 }, smart: [at(0xc2, 35, 50, 0, 0x110000001f), at(0x09, 99, 99, 0, 0x100000000 + 700)] });
    expect([sataSsd.lifePct, sataSsd.temperatureC, sataSsd.powerOnHours]).toEqual([88, 31, 700]);
    expect(diskStatus({ ...base, media: 'hdd', smart: [at(0x05, 5, 5, 10, 1, 0x33)] }).label).toBe('Critico');
    expect(diskStatus({ ...base, media: 'hdd', smart: [at(0xc5, 100, 100, 0, 1)] }).label).toBe('Attenzione');
  });

  it('nomi e dati grezzi leggibili', () => {
    expect(smartName(0x05, false)).toBe('Settori riallocati');
    expect(smartName(0xe7, true)).toBe('Vita residua');
    expect(smartName(0xe7, false)).toBe('Temperatura');
    expect(smartName(0x99, false)).toBe('Specifico del produttore');
    expect(smartRaw(at(0xc2, 44, 53, 0, 0x110000002c))).toBe('44 °C');
    expect(smartRaw(at(0x09, 57, 57, 0, 38120))).toBe('38.120 ore');
    expect(smartRaw(at(0x05, 8, 8, 10, 3824))).toBe('3.824');
    expect(smartRaw(at(0x01, 72, 64, 6, 0x0d4c77b2))).toBe('00000D4C77B2');
    expect(attrState(at(0x05, 10, 10, 10, 0))).toBe('fail');
    expect(attrState(at(0x05, 11, 10, 10, 0))).toBe('past');
    expect(attrState(at(0xc5, 100, 100, 0, 3))).toBe('caution');
  });

  it('demo: il disco dati dell\'ambulatorio è critico per SMART, il portatile ha il registro NVMe', () => {
    const clinic = analyze(clinicScan).findings;
    const d1 = clinic.find((f) => f.id === 'pc.disk.1');
    expect(d1?.verdict).toContain('05 Settori riallocati');
    expect(d1?.verdict).toContain('48 settori in attesa');
    // Gli errori non correggibili di Windows non si ripetono dopo quelli SMART.
    expect(d1?.verdict).not.toContain('errori di lettura o scrittura non correggibili');
    const home = analyze(demoScan).findings.find((f) => f.id === 'pc.disk.0');
    expect(home?.value).toContain('Buono 82 %');
    expect(home?.verdict).toContain('96 spegnimenti non sicuri');
  });
});

const mod = (slot: string, o: Partial<HwModule> = {}): HwModule => ({ slot, sizeGB: 8, type: 'DDR4', form: 'SODIMM', speedMTs: 3200, configuredMTs: 3200, part: 'X', ...o });

describe('computer: scheda tecnica (stile CPU-Z)', () => {
  const hwPc = (hw: Hardware, os?: Partial<PcData['os']>) =>
    edit((x) => {
      x.hardware = hw;
      if (os) x.os = { ...x.os!, ...os };
    });

  it('canali della memoria: un modulo, slot sbagliati, dual channel, memoria saldata', () => {
    const single = find(hwPc({ memory: { slots: 2, modules: [mod('ChannelA-DIMM0')] } }), 'pc.ram.channel');
    expect(single?.severity).toBe('info');
    expect(single?.actions).toEqual(['dual-channel']);
    expect(single?.verdict).toContain('slot libero');
    expect(sevOf(hwPc({ memory: { slots: 1, modules: [mod('DIMM 0')] } }), 'pc.ram.channel')).toBe('ok');
    const same = find(hwPc({ memory: { slots: 4, modules: [mod('DIMM_A1', { form: 'DIMM' }), mod('DIMM_A2', { form: 'DIMM' })] } }), 'pc.ram.channel');
    expect(same?.severity).toBe('warn');
    expect(same?.verdict).toContain('DIMM_A1, DIMM_A2');
    expect(sevOf(hwPc({ memory: { modules: [mod('ChannelA-DIMM0'), mod('ChannelB-DIMM0')] } }), 'pc.ram.channel')).toBe('ok');
    // Canale nell'etichetta del banco (schede AMD) e "DIMM A/B" (portatili).
    expect(channelMode({ modules: [mod('DIMM 0', { bank: 'P0 CHANNEL A' }), mod('DIMM 1', { bank: 'P0 CHANNEL B' })] })).toBe('multi');
    expect(channelMode({ modules: [mod('DIMM A'), mod('DIMM B')] })).toBe('multi');
    // Senza etichette utili o con memoria saldata: nessun giudizio.
    expect(find(hwPc({ memory: { modules: [mod('Bottom-Slot 1(left)'), mod('Bottom-Slot 2(right)')] } }), 'pc.ram.channel')).toBeUndefined();
    expect(find(hwPc({ memory: { modules: [mod('Controller0-ChannelA', { type: 'LPDDR5', form: undefined })] } }), 'pc.ram.channel')).toBeUndefined();
  });

  it('velocità della memoria e moduli diversi', () => {
    const slow = find(hwPc({ memory: { modules: [mod('ChannelA-DIMM0', { configuredMTs: 2666 }), mod('ChannelB-DIMM0', { configuredMTs: 2666 })] } }), 'pc.ram.speed');
    expect(slow?.severity).toBe('info');
    expect(slow?.value).toBe('2.666 MT/s su 3.200');
    expect(sevOf(hwPc({ memory: { modules: [mod('ChannelA-DIMM0'), mod('ChannelB-DIMM0')] } }), 'pc.ram.speed')).toBe('ok');
    const mixed = find(hwPc({ memory: { modules: [mod('ChannelA-DIMM0'), mod('ChannelB-DIMM0', { sizeGB: 4, part: 'Y' })] } }), 'pc.ram.speed');
    expect(mixed?.severity).toBe('info');
    expect(mixed?.verdict).toContain('diversi tra loro');
  });

  it('Secure Boot e TPM', () => {
    const off = find(hwPc({ firmware: 'uefi', secureBoot: false }), 'pc.secureboot');
    expect([off?.severity, off?.category, off?.actions[0]]).toEqual(['warn', 'security', 'firmware-security']);
    expect(sevOf(hwPc({ firmware: 'uefi', secureBoot: true }), 'pc.secureboot')).toBe('ok');
    expect(find(hwPc({ firmware: 'bios' }), 'pc.secureboot')?.verdict).toContain('MBR2GPT');
    expect(find(hwPc({ firmware: 'uefi' }), 'pc.secureboot')).toBeUndefined();
    expect(sevOf(hwPc({ tpm: '2.0' }), 'pc.tpm')).toBe('ok');
    expect(find(hwPc({ tpm: '' }), 'pc.tpm')?.verdict).toContain('Intel PTT');
    expect(find(hwPc({ tpm: '1.2' }), 'pc.tpm')?.value).toBe('TPM 1.2');
    expect(find(hwPc({}), 'pc.tpm')).toBeUndefined();
  });

  it('requisiti di Windows 11 solo sui PC con Windows 10', () => {
    const win10 = { name: 'Windows 10 Pro', version: '22H2', build: 19045 };
    const good: Hardware = { firmware: 'uefi', secureBoot: true, tpm: '2.0', cpu: { features: ['SSE4.2', 'POPCNT'] } };
    const ok = find(hwPc(good, win10), 'pc.win11');
    expect(ok?.severity).toBe('info');
    expect(ok?.verdict).toContain('Controllo integrità PC');
    const bad = find(hwPc({ firmware: 'bios', tpm: '', cpu: { features: ['SSE2'] } }, win10), 'pc.win11');
    expect(bad?.severity).toBe('warn');
    expect(bad?.verdict).toContain('TPM 2.0; avvio UEFI');
    expect(bad?.verdict).toContain('POPCNT');
    expect(bad?.actions).toEqual(['firmware-security', 'upgrade-windows']);
    expect(find(hwPc(good), 'pc.win11')).toBeUndefined(); // Windows 11
  });

  it('formattazione: core P/E, cache, produttori JEDEC', () => {
    expect(coreLayout({ coreClasses: [8, 16] })).toBe('8 P + 16 E');
    expect(coreLayout({ coreClasses: [4, 8, 2] })).toBe('4 P + 8 E + 2 LP-E');
    expect(coreLayout({ coreClasses: [6], cores: 6 })).toBe('6 core');
    expect(cacheText({ level: 1, kind: 'data', sizeKB: 48, count: 8, ways: 12 })).toBe('L1 dati: 8 × 48 KB, 12 vie');
    expect(cacheText({ level: 3, kind: 'unified', sizeKB: 18432, count: 1, ways: 12 })).toBe('L3: 18 MB, 12 vie');
    expect(cacheText({ level: 2, kind: 'unified', sizeKB: 1280, count: 6 })).toBe('L2: 6 × 1,25 MB');
    expect(cacheText({ level: 2, kind: 'unified', sizeKB: 1536, count: 1 })).toBe('L2: 1,5 MB');
    expect(memVendor('80AD000080AD')).toBe('SK hynix');
    expect(memVendor('Kingston')).toBe('Kingston');
    expect(memVendor('00000000')).toBe('');
  });

  it('demo: portatile in canale singolo, ambulatorio con Secure Boot spento', () => {
    const home = analyze(demoScan).findings;
    expect(home.find((f) => f.id === 'pc.ram.channel')?.severity).toBe('info');
    expect(home.find((f) => f.id === 'pc.win11')).toBeUndefined();
    const clinic = analyze(clinicScan).findings;
    expect(clinic.find((f) => f.id === 'pc.secureboot')?.severity).toBe('warn');
    expect(clinic.find((f) => f.id === 'pc.win11')?.severity).toBe('info');
    expect(clinic.find((f) => f.id === 'pc.ram.channel')?.severity).toBe('ok');
  });
});

describe('computer: Microsoft Defender', () => {
  const t = (o: Partial<Threat> = {}): Threat => ({ name: 'Trojan:Win32/Wacatac.B!ml', severity: 'severe', status: 'quarantined', detected: '2026-10-10T09:00:00Z', ...o });
  const withThreats = (threats: Threat[] | null) => edit((x) => (x.threats = threats));

  it('cronologia delle minacce: attive, consentite, recenti, vecchie, nessuna', () => {
    const active = find(withThreats([t({ status: 'failed', active: true }), t({ name: 'PUA:Win32/Presenoker', severity: 'low' })]), 'pc.threats');
    expect([active?.severity, active?.category, active?.actions[0]]).toEqual(['crit', 'security', 'remove-threats']);
    expect(active?.verdict).toContain('Trojan:Win32/Wacatac.B!ml (grave)');
    expect(active?.value).toBe('1 da risolvere');
    expect(sevOf(withThreats([t({ status: 'detected' })]), 'pc.threats')).toBe('crit');
    expect(sevOf(withThreats([t({ status: 'allowed' })]), 'pc.threats')).toBe('warn');
    const recent = find(withThreats([t(), t({ name: 'PUA:Win32/Presenoker', severity: 'low', status: 'removed' })]), 'pc.threats');
    expect(recent?.severity).toBe('info');
    expect(recent?.value).toBe('2 bloccate in 30 giorni');
    expect(find(withThreats([t({ detected: '2026-07-01T09:00:00Z' })]), 'pc.threats')?.verdict).toContain('più vecchie di 30 giorni');
    expect(find(withThreats([]), 'pc.threats')?.severity).toBe('ok');
    expect(find(withThreats(null), 'pc.threats')).toBeUndefined();
  });

  it('protezione da manomissioni e ultime scansioni, solo se Defender è l\'antivirus attivo', () => {
    const def = (o: Partial<DefenderInfo>) => edit((x) => (x.defender = { mode: 'normal', enabled: true, realTime: true, tamperProtected: true, quickScanAgeDays: 2, ...o }));
    expect(sevOf(def({}), 'pc.defender')).toBe('ok');
    const tamper = find(def({ tamperProtected: false }), 'pc.defender');
    expect([tamper?.severity, tamper?.actions[0]]).toEqual(['info', 'defender-protection']);
    expect(find(def({ quickScanAgeDays: undefined }), 'pc.defender')?.verdict).toContain('Non risulta alcuna scansione');
    expect(find(def({ quickScanAgeDays: 40, fullScanAgeDays: 20 }), 'pc.defender')?.verdict).toContain('20 giorni fa');
    // Tempo reale spento: lo segnala già il giudizio sull'antivirus, qui solo se il Centro sicurezza non è leggibile.
    expect(sevOf(def({ realTime: false }), 'pc.defender')).toBe('ok');
    const unread = def({ realTime: false });
    unread.antivirus = null;
    expect(sevOf(unread, 'pc.defender')).toBe('warn');
    expect(find(def({ mode: 'passive' }), 'pc.defender')).toBeUndefined();
  });

  it('demo: il portatile ha una minaccia bloccata, l\'ambulatorio usa un antivirus aziendale', () => {
    const home = analyze(demoScan).findings;
    expect(home.find((f) => f.id === 'pc.threats')?.severity).toBe('info');
    expect(home.find((f) => f.id === 'pc.defender')?.severity).toBe('ok');
    const clinic = analyze(clinicScan).findings;
    expect(clinic.find((f) => f.id === 'pc.threats')?.severity).toBe('ok');
    expect(clinic.find((f) => f.id === 'pc.defender')).toBeUndefined();
  });
});
