import { describe, expect, it } from 'vitest';
import { demoScan } from '../src/demo/sample';
import { clinicScan } from '../src/demo/clinic';
import { emptySensors, fmtSensor, levelOf, nextAlerts, pushSnapshot, resetStats, sensorsCsv, simulateSensors } from '../src/ui/sensors';
import type { SensorsState } from '../src/ui/sensors';
import type { SensorSnapshot } from '../src/ui/api';

const snap = (at: number, temp: number, extra = true): SensorSnapshot => ({
  at: new Date(Date.UTC(2026, 9, 30, 9, 0, at)).toISOString(),
  groups: [
    {
      id: 'gpu.x',
      kind: 'gpu',
      name: 'GPU "Prova"',
      sensors: [
        { id: 'gpu.x.temp', label: 'Temperatura', value: temp, unit: '°C', warn: 83, crit: 93 },
        ...(extra ? [{ id: 'gpu.x.fan', label: 'Ventola', value: 1500 + at, unit: 'giri/min' }] : []),
      ],
    },
    { id: 'battery.0', kind: 'battery', name: '=Batteria', sensors: [{ id: 'battery.0.charge', label: 'Carica', value: 50 - at, unit: '%', warn: 20, crit: 10, below: true }] },
  ],
  missing: ['niente CPU'],
});

describe('monitor dei sensori', () => {
  it('tiene attuale, minimo, massimo, media, grafici e registro', () => {
    let s: SensorsState = emptySensors();
    s = pushSnapshot(s, snap(0, 60));
    s = pushSnapshot(s, snap(1, 70.5, false));
    s = pushSnapshot(s, snap(2, 65));
    const t = s.stats['gpu.x.temp'];
    expect([t.cur, t.min, t.max, t.n]).toEqual([65, 60, 70.5, 3]);
    expect(t.sum / t.n).toBeCloseTo(65.17, 2);
    // La ventola manca nella seconda lettura: buco nel grafico, statistiche invariate.
    expect(s.stats['gpu.x.fan'].hist).toEqual([1500, null, 1502]);
    expect(s.stats['gpu.x.fan'].n).toBe(2);
    expect(s.order).toEqual(['gpu.x.temp', 'gpu.x.fan', 'battery.0.charge']);
    expect(s.log).toHaveLength(3);
    expect(s.tick).toBe(3);
    expect(s.missing).toEqual(['niente CPU']);
    expect(s.since).toBe(snap(0, 0).at);
    // Il registro si ferma al massimo indicato.
    let r = emptySensors();
    for (let i = 0; i < 12; i++) r = pushSnapshot(r, snap(i, 50), 5);
    expect(r.log).toHaveLength(5);
    expect(r.stats['gpu.x.temp'].hist.length).toBeLessThanOrEqual(120);
    // Azzerare riparte dall'ultimo valore.
    const z = resetStats(s);
    expect([z.stats['gpu.x.temp'].min, z.stats['gpu.x.temp'].max, z.stats['gpu.x.temp'].n]).toEqual([65, 65, 1]);
    expect(z.since).toBe(s.at);
    expect(z.log).toHaveLength(3);
  });

  it('valuta le soglie verso l\'alto e verso il basso', () => {
    const temp = { warn: 83, crit: 93 };
    expect([levelOf(temp, 82.9), levelOf(temp, 83), levelOf(temp, 95)]).toEqual(['ok', 'warn', 'crit']);
    const charge = { warn: 20, crit: 10, below: true };
    expect([levelOf(charge, 50), levelOf(charge, 19), levelOf(charge, 5)]).toEqual(['ok', 'warn', 'crit']);
    expect(levelOf({}, 1e9)).toBe('ok');
  });

  it('avvisa una volta e si riarma solo con un margine', () => {
    let s = pushSnapshot(emptySensors(), snap(0, 80));
    let a = nextAlerts({}, s);
    expect(a.fire).toEqual([]);
    s = pushSnapshot(s, snap(1, 84));
    a = nextAlerts(a.armed, s);
    expect(a.fire).toHaveLength(1);
    expect(a.fire[0].level).toBe('warn');
    expect(a.fire[0].text).toBe('Attenzione: GPU "Prova", temperatura 84,0 °C');
    // Oscilla appena sotto la soglia: nessun nuovo avviso.
    s = pushSnapshot(s, snap(2, 82));
    a = nextAlerts(a.armed, s);
    s = pushSnapshot(s, snap(3, 84));
    a = nextAlerts(a.armed, s);
    expect(a.fire).toEqual([]);
    // Allarme: avviso anche se era già in attenzione.
    s = pushSnapshot(s, snap(4, 94));
    a = nextAlerts(a.armed, s);
    expect(a.fire.map((f) => f.level)).toEqual(['crit']);
    // Torna sotto di almeno 2 °C: si riarma.
    s = pushSnapshot(s, snap(5, 80));
    a = nextAlerts(a.armed, s);
    expect(a.armed['gpu.x.temp']).toBe('ok');
    s = pushSnapshot(s, snap(6, 85));
    expect(nextAlerts(a.armed, s).fire).toHaveLength(1);
    // Fuori dalle temperature si avvisa solo per l'allarme: la carica al 19 % no, al 9 % sì.
    let b = emptySensors();
    b = pushSnapshot(b, snap(31, 50));
    let ab = nextAlerts({}, b);
    expect(ab.fire).toEqual([]);
    b = pushSnapshot(b, snap(41, 50));
    ab = nextAlerts(ab.armed, b);
    expect(ab.fire.map((f) => f.text)).toEqual(['Allarme: =Batteria, carica 9,0 %']);
  });

  it('formatta i valori in italiano', () => {
    expect(fmtSensor(3600, 'MHz')).toBe('3.600 MHz');
    expect(fmtSensor(12.17, 'V')).toBe('12,17 V');
    expect(fmtSensor(15000, '/s')).toBe('15.000 /s');
    expect(fmtSensor(64.53, '°C')).toBe('64,5 °C');
    expect(fmtSensor(0.875, 'V')).toBe('0,875 V');
    expect(fmtSensor(1.234, 'MB/s')).toBe('1,23 MB/s');
    expect(fmtSensor(212, '')).toBe('212');
    expect(fmtSensor(-8.25, 'W')).toBe('-8,3 W');
  });

  it('esporta il registro in CSV per Excel in italiano', () => {
    let s = emptySensors();
    s = pushSnapshot(s, snap(0, 60.5));
    s = pushSnapshot(s, snap(1, 61, false));
    const csv = sensorsCsv(s);
    expect(csv.charCodeAt(0)).toBe(0xfeff);
    const lines = csv.slice(1).split('\r\n');
    expect(lines[0]).toBe('Data e ora;"GPU ""Prova"" - Temperatura [°C]";"GPU ""Prova"" - Ventola [giri/min]";\'=Batteria - Carica [%]');
    expect(lines[1]).toMatch(/^\d{4}-\d\d-\d\d \d\d:\d\d:00;60,5;1500;50$/);
    expect(lines[2]).toMatch(/:01;61;;49$/);
    expect(lines[3]).toBe('');
  });

  it('simula sensori coerenti con i PC dimostrativi', () => {
    const home = simulateSensors(demoScan, 30);
    const ids = home.groups.map((g) => g.id);
    expect(ids).toEqual(expect.arrayContaining(['cpu', 'thermal', 'memory', 'disk.0', 'disk.1', 'battery.0', 'system']));
    expect(home.groups.find((g) => g.kind === 'gpu')?.name).toBe('Intel(R) Iris(R) Xe Graphics');
    expect(home.groups.find((g) => g.id === 'cpu')!.sensors.filter((x) => x.id.endsWith('.clock') && x.id.startsWith('cpu.core.'))).toHaveLength(8);
    // La chiavetta USB non ha temperatura; l'SSD sì, con le soglie dei dischi a stato solido.
    const d0 = home.groups.find((g) => g.id === 'disk.0')!;
    expect(d0.sensors.find((x) => x.id === 'disk.0.temp')).toMatchObject({ warn: 70, crit: 80 });
    expect(home.groups.find((g) => g.id === 'disk.1')!.sensors.some((x) => x.unit === '°C')).toBe(false);
    expect(home.missing!.some((m) => m.startsWith('Temperatura e frequenze di Intel(R) Iris(R) Xe Graphics:'))).toBe(true);
    expect(home.missing!.some((m) => m.includes('HWiNFO'))).toBe(true);
    // Il PC dell'ambulatorio è un fisso: niente zone termiche né batteria.
    const clinic = simulateSensors(clinicScan, 30);
    expect(clinic.groups.some((g) => g.kind === 'thermal' || g.kind === 'battery')).toBe(false);
    expect(clinic.missing!.some((m) => m.startsWith('Zone termiche'))).toBe(true);
    expect(clinic.groups.find((g) => g.id === 'disk.1')!.sensors.find((x) => x.unit === '°C')).toMatchObject({ warn: 55, crit: 60 });
    // Ripetibile e plausibile.
    expect(simulateSensors(demoScan, 7)).toEqual(simulateSensors(demoScan, 7));
    for (let t = 0; t < 120; t++) {
      for (const g of simulateSensors(demoScan, t).groups) {
        for (const x of g.sensors) {
          expect(Number.isFinite(x.value)).toBe(true);
          // Le prestazioni rispetto alla base superano 100 in turbo.
          if (x.unit === '%' && x.id !== 'cpu.perf') {
            expect(x.value).toBeGreaterThanOrEqual(0);
            expect(x.value).toBeLessThanOrEqual(100);
          }
        }
      }
    }
    // Il portatile, scaldandosi, limita il processore.
    const hot = Array.from({ length: 120 }, (_, t) => simulateSensors(demoScan, t)).find((s) => s.groups.find((g) => g.id === 'cpu')!.sensors.find((x) => x.id === 'cpu.limit')!.value < 95);
    expect(hot).toBeDefined();
  });
});

describe('monitor dei sensori: casi limite', () => {
  const at = (sec: number) => new Date(Date.UTC(2026, 9, 30, 9, 0, sec)).toISOString();
  const one = (sec: number, v: number, unit = 'ms', warn = 100, crit = 500): SensorSnapshot => ({
    at: at(sec),
    groups: [{ id: 'disk.0', kind: 'disk', name: 'Disco 0', sensors: [{ id: 'disk.0.latency', label: 'Tempo di risposta medio', value: v, unit, warn, crit }] }],
  });

  it('segna le pause come interruzioni e scarta le letture ripetute', () => {
    let s = pushSnapshot(emptySensors(), one(0, 5));
    s = pushSnapshot(s, one(1, 6));
    const same = pushSnapshot(s, one(1, 6));
    expect(same).toBe(s);
    // Dieci secondi di pausa: nove buchi, poi il valore.
    s = pushSnapshot(s, one(11, 7));
    expect(s.stats['disk.0.latency'].hist).toEqual([5, 6, null, null, null, null, null, null, null, null, null, 7]);
    // Un ritardo normale (fino a 2,5 s) non crea buchi.
    s = pushSnapshot(s, one(13, 8));
    expect(s.stats['disk.0.latency'].hist.slice(-2)).toEqual([7, 8]);
    expect(s.stats['disk.0.latency'].n).toBe(4);
  });

  it('non ripete l\'allarme del tempo di risposta a ogni oscillazione', () => {
    let s = emptySensors();
    let armed = {};
    let fired = 0;
    [520, 480, 510, 495, 530, 499, 501].forEach((v, i) => {
      s = pushSnapshot(s, one(i, v));
      const a = nextAlerts(armed, s);
      armed = a.armed;
      fired += a.fire.length;
    });
    expect(fired).toBe(1);
    // Rientrato sotto 425 ms (il 15 % sotto 500) si riarma.
    s = pushSnapshot(s, one(10, 400));
    armed = nextAlerts(armed, s).armed;
    s = pushSnapshot(s, one(11, 520));
    expect(nextAlerts(armed, s).fire).toHaveLength(1);
  });

  it('mostra prima gli allarmi e rinvia gli avvisi in eccesso', () => {
    const snap: SensorSnapshot = {
      at: at(0),
      groups: [
        { id: 'thermal', kind: 'thermal', name: 'Zone termiche ACPI', sensors: [
          { id: 'tz.a', label: 'Zona TZ00', value: 88, unit: '°C', warn: 85, crit: 95 },
          { id: 'tz.b', label: 'Zona TZ01', value: 87, unit: '°C', warn: 85, crit: 95 },
        ] },
        { id: 'battery.0', kind: 'battery', name: 'Batteria', sensors: [{ id: 'b', label: 'Carica', value: 8, unit: '%', warn: 20, crit: 10, below: true }] },
      ],
    };
    const s = pushSnapshot(emptySensors(), snap);
    const a = nextAlerts({}, s);
    expect(a.fire.map((f) => f.id)).toEqual(['b', 'tz.a']);
    // La seconda zona arriva alla lettura dopo, la batteria non si ripete.
    const s2 = pushSnapshot(s, { ...snap, at: at(1) });
    expect(nextAlerts(a.armed, s2).fire.map((f) => f.id)).toEqual(['tz.b']);
  });

  it('nella demo il portatile si scalda solo nel primo minuto', () => {
    const warn = (t: number) => simulateSensors(demoScan, t).groups.find((g) => g.id === 'thermal')!.sensors[0].value >= 85;
    expect(Array.from({ length: 56 }, (_, t) => t).some(warn)).toBe(true);
    expect(Array.from({ length: 600 }, (_, t) => t + 56).some(warn)).toBe(false);
  });
});
