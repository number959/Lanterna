import { describe, expect, it } from 'vitest';
import { clinicScan } from '../src/demo/clinic';
import { demoScan } from '../src/demo/sample';
import { analyze, renderText } from '../src/engine';
import type { PcData, Scan } from '../src/engine';
import { on } from '../src/engine/pc';
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
