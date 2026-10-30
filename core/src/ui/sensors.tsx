import {
  Activity,
  BatteryMedium,
  ChevronDown,
  Cpu,
  Download,
  Eye,
  EyeOff,
  Gpu,
  HardDrive,
  MemoryStick,
  Network,
  Pause,
  Play,
  RotateCcw,
  RotateCw,
  Thermometer,
  TriangleAlert,
} from 'lucide-react';
import { m } from 'motion/react';
import { Fragment, useEffect, useRef, useState } from 'react';
import type { LucideIcon } from 'lucide-react';
import type { Scan } from '../engine';
import { HexLoader } from './anim';
import { download, readSensors } from './api';
import type { SensorGroup, SensorKind, SensorReading, SensorSnapshot } from './api';
import { LiveChart } from './charts';
import { TableWrap, useToast } from './components';
import { useLocalState } from './hooks';
import { rise } from './motion';
import type { ViewProps } from './views';

// Monitor dei sensori sul modello della finestra "Sensors" di HWiNFO: per ogni
// sensore il valore attuale, il minimo, il massimo e la media della sessione,
// un grafico a richiesta, gli avvisi quando si superano le soglie e il
// registro in CSV. Con l'agente una lettura al secondo di ciò che Windows
// espone senza driver; nella demo valori simulati e dichiarati. Si legge
// solo mentre la sezione è aperta e la finestra in primo piano: i valori
// raccolti restano se si cambia sezione e si torna.

/** Secondi di storia per i grafici dei singoli sensori. */
const HIST = 120;
/** Letture tenute per il CSV: un'ora a una lettura al secondo. */
export const MAX_LOG = 3600;

export interface SensorStat {
  id: string;
  groupId: string;
  group: string;
  label: string;
  unit: string;
  warn?: number;
  crit?: number;
  below?: boolean;
  detail?: boolean;
  cur: number;
  min: number;
  max: number;
  sum: number;
  n: number;
  /** Ultimi valori per il grafico (null: sensore assente in quella lettura). */
  hist: (number | null)[];
}

export interface SensorsState {
  stats: Record<string, SensorStat>;
  /** Ordine di prima comparsa (colonne del CSV). */
  order: string[];
  /** Struttura dell'ultima lettura. */
  groups: { id: string; kind: SensorKind; name: string; sub?: string; ids: string[] }[];
  log: { at: string; vals: Record<string, number> }[];
  tick: number;
  missing: string[];
  at?: string;
  /** Inizio del calcolo di minimo, massimo e media. */
  since?: string;
}

export const emptySensors = (): SensorsState => ({ stats: {}, order: [], groups: [], log: [], tick: 0, missing: [] });

/** Aggiunge una lettura: aggiorna attuale, minimo, massimo, media, grafici e registro. */
export function pushSnapshot(s: SensorsState, snap: SensorSnapshot, maxLog = MAX_LOG): SensorsState {
  const stats = { ...s.stats };
  const order = [...s.order];
  const seen = new Set<string>();
  const vals: Record<string, number> = {};
  for (const g of snap.groups) {
    for (const x of g.sensors) {
      if (!Number.isFinite(x.value) || seen.has(x.id)) continue;
      seen.add(x.id);
      vals[x.id] = x.value;
      const p = stats[x.id];
      const meta = { groupId: g.id, group: g.name, label: x.label, unit: x.unit, warn: x.warn, crit: x.crit, below: x.below, detail: x.detail };
      if (!p) {
        order.push(x.id);
        stats[x.id] = { id: x.id, ...meta, cur: x.value, min: x.value, max: x.value, sum: x.value, n: 1, hist: [x.value] };
      } else {
        stats[x.id] = { ...p, ...meta, cur: x.value, min: Math.min(p.min, x.value), max: Math.max(p.max, x.value), sum: p.sum + x.value, n: p.n + 1, hist: [...p.hist, x.value].slice(-HIST) };
      }
    }
  }
  for (const id of order) {
    if (!seen.has(id)) {
      const p = stats[id];
      stats[id] = { ...p, hist: [...p.hist, null].slice(-HIST) };
    }
  }
  return {
    stats,
    order,
    groups: snap.groups.map((g) => ({ id: g.id, kind: g.kind, name: g.name, sub: g.sub, ids: g.sensors.filter((x) => Number.isFinite(x.value)).map((x) => x.id) })),
    log: [...s.log, { at: snap.at, vals }].slice(-maxLog),
    tick: s.tick + 1,
    missing: snap.missing ?? [],
    at: snap.at,
    since: s.since ?? snap.at,
  };
}

/** Azzera minimo, massimo e media dall'ultima lettura (come il pulsante di HWiNFO); grafici e registro restano. */
export function resetStats(s: SensorsState): SensorsState {
  const stats: Record<string, SensorStat> = {};
  for (const [id, x] of Object.entries(s.stats)) stats[id] = { ...x, min: x.cur, max: x.cur, sum: x.cur, n: 1 };
  return { ...s, stats, since: s.at };
}

export type Level = 'ok' | 'warn' | 'crit';
const RANK: Record<Level, number> = { ok: 0, warn: 1, crit: 2 };

/** Livello di un valore rispetto alle soglie del sensore. */
export function levelOf(x: Pick<SensorReading, 'warn' | 'crit' | 'below'>, v: number): Level {
  const over = (t?: number) => t !== undefined && (x.below ? v < t : v >= t);
  return over(x.crit) ? 'crit' : over(x.warn) ? 'warn' : 'ok';
}

/** Margine per riarmare un avviso: il valore deve tornare oltre la soglia di questo tanto. */
const hysteresis = (unit: string) => (unit === '°C' ? 2 : unit === '%' ? 3 : 0);

export interface SensorAlert {
  id: string;
  level: Level;
  text: string;
}

/**
 * Avvisi da mostrare: quando un sensore entra in allarme o una temperatura
 * supera la soglia di attenzione. Ogni avviso si ripete solo dopo che il
 * valore è tornato sotto la soglia con un margine, per non insistere a ogni
 * oscillazione. Restituisce anche lo stato aggiornato degli avvisi.
 */
export function nextAlerts(armed: Record<string, Level>, s: SensorsState): { armed: Record<string, Level>; fire: SensorAlert[] } {
  const out = { ...armed };
  const fire: SensorAlert[] = [];
  for (const g of s.groups) {
    for (const id of g.ids) {
      const x = s.stats[id];
      if (!x) continue;
      const lvl = levelOf(x, x.cur);
      const prev = out[id] ?? 'ok';
      if (RANK[lvl] > RANK[prev]) {
        out[id] = lvl;
        if (lvl === 'crit' || x.unit === '°C') {
          fire.push({ id, level: lvl, text: `${lvl === 'crit' ? 'Allarme' : 'Attenzione'}: ${x.group}, ${x.label.toLowerCase()} ${fmtSensor(x.cur, x.unit)}` });
        }
      } else if (RANK[lvl] < RANK[prev]) {
        // Si riarma solo con il margine: il livello calcolato con la soglia spostata deve essere più basso.
        const h = hysteresis(x.unit) * (x.below ? 1 : -1);
        const relaxed = levelOf({ warn: x.warn === undefined ? undefined : x.warn + h, crit: x.crit === undefined ? undefined : x.crit + h, below: x.below }, x.cur);
        if (RANK[relaxed] < RANK[prev]) out[id] = relaxed;
      }
    }
  }
  return { armed: out, fire };
}

const DECIMALS: Record<string, number> = { '%': 1, MHz: 0, '°C': 1, W: 1, V: 3, 'MB/s': 1, 'Mbit/s': 1, ms: 1, GB: 2, MB: 0, Wh: 1, 'giri/min': 0, '/s': 0, ore: 1, '': 0 };

/** Valore con l'unità, in italiano. */
export function fmtSensor(v: number, unit: string): string {
  let d = DECIMALS[unit] ?? 1;
  if ((unit === 'MB/s' || unit === 'Mbit/s') && Math.abs(v) < 10) d = 2;
  // Tensioni: tre decimali per la scheda video (sotto il volt), due per la batteria.
  if (unit === 'V' && Math.abs(v) >= 5) d = 2;
  const s = v.toLocaleString('it-IT', { minimumFractionDigits: d, maximumFractionDigits: d, useGrouping: true });
  return unit ? `${s} ${unit}` : s;
}

const csvNum = (v: number) => String(v).replace('.', ',');
const csvText = (s: string) => {
  let t = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
  if (/[;"\n\r]/.test(t)) t = `"${t.replace(/"/g, '""')}"`;
  return t;
};
const pad = (n: number) => String(n).padStart(2, '0');
const localStamp = (iso: string) => {
  const d = new Date(iso);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
};

/**
 * Registro in CSV come quello di polaris-cli sensors --csv: una riga per
 * lettura, una colonna per sensore, punto e virgola e virgola decimale (Excel
 * in italiano), con la marca UTF-8 iniziale.
 */
export function sensorsCsv(s: SensorsState): string {
  const head = ['Data e ora', ...s.order.map((id) => {
    const x = s.stats[id];
    return csvText(`${x.group} - ${x.label}${x.unit ? ` [${x.unit}]` : ''}`);
  })];
  const rows = s.log.map((r) => [localStamp(r.at), ...s.order.map((id) => (id in r.vals ? csvNum(r.vals[id]) : ''))].join(';'));
  return String.fromCharCode(0xfeff) + [head.join(';'), ...rows].join('\r\n') + '\r\n';
}

// ---------------------------------------------------------------- simulazione per la demo

/** Numero pseudocasuale ripetibile in [0, 1) da due interi. */
function noise(a: number, b: number): number {
  const x = Math.sin(a * 12.9898 + b * 78.233) * 43758.5453;
  return x - Math.floor(x);
}
const r1 = (v: number, d = 1) => Math.round(v * 10 ** d) / 10 ** d;

/**
 * Lettura simulata e plausibile per i PC dimostrativi: un carico che sale e
 * scende, il portatile che si scalda e limita il processore, la grafica
 * integrata senza telemetria del driver, come accade davvero.
 */
export function simulateSensors(scan: Scan, t: number, now = Date.UTC(2026, 9, 30, 9, 0, 0) + t * 1000): SensorSnapshot {
  const pc = scan.pc;
  const laptop = pc?.hardware?.chassis === 'laptop' || !!pc?.power?.hasBattery;
  const wave = 0.5 + 0.5 * Math.sin(t / 9);
  const groups: SensorGroup[] = [];
  const missing: string[] = [];
  // Processore
  const threads = pc?.hardware?.cpu?.threads || pc?.cpu?.threads || 8;
  const base = pc?.cpu?.maxMhz || 2400;
  const tz = laptop ? 46 + 42 * wave + 3 * noise(t, 99) : undefined;
  const passive = tz !== undefined && tz > 82 ? Math.max(70, 100 - (tz - 82) * 4) : 100;
  const cores = Array.from({ length: threads }, (_, i) => {
    const r = noise(t, i);
    const load = Math.min(100, 100 * wave * r * 1.3);
    const mhz = base * Math.min(1.75, 0.55 + 1.2 * wave * (0.45 + 0.55 * r)) * (passive / 100);
    return { load, mhz };
  });
  const usage = cores.reduce((a, c) => a + c.load, 0) / threads;
  const avg = cores.reduce((a, c) => a + c.mhz, 0) / threads;
  const pkg = (laptop ? 3 : 5) + (laptop ? 25 : 30) * (usage / 100) + noise(t, 50);
  const cpu: SensorReading[] = [
    { id: 'cpu.usage', label: 'Utilizzo totale', value: r1(usage), unit: '%' },
    { id: 'cpu.utility', label: 'Utilità (come Gestione attività)', value: r1(Math.min(100, (usage * avg) / base)), unit: '%' },
    { id: 'cpu.clock', label: 'Frequenza effettiva media', value: Math.round(avg), unit: 'MHz' },
    { id: 'cpu.maxclock', label: 'Core più veloce', value: Math.round(Math.max(...cores.map((c) => c.mhz))), unit: 'MHz' },
    { id: 'cpu.perf', label: 'Prestazioni rispetto alla base', value: Math.round((100 * avg) / base), unit: '%' },
    { id: 'cpu.limit', label: 'Limite di prestazioni', value: Math.round(passive), unit: '%', warn: 95, below: true },
    { id: 'cpu.power.rapl-package0-pkg', label: 'Potenza del processore (package)', value: r1(pkg), unit: 'W' },
    { id: 'cpu.power.rapl-package0-pp0', label: 'Potenza dei core', value: r1(pkg * 0.62), unit: 'W' },
    { id: 'cpu.power.rapl-package0-pp1', label: 'Potenza della grafica integrata', value: r1(0.4 + 2.5 * noise(t, 51)), unit: 'W' },
    { id: 'cpu.c1', label: 'Tempo nello stato C1', value: r1(8 + 10 * noise(t, 60)), unit: '%', detail: true },
    { id: 'cpu.c2', label: 'Tempo nello stato C2', value: r1(Math.max(0, 70 - usage) * 0.3), unit: '%', detail: true },
    { id: 'cpu.c3', label: 'Tempo nello stato C3', value: r1(Math.max(0, 80 - usage) * 0.5), unit: '%', detail: true },
    { id: 'cpu.interrupt', label: 'Tempo per gli interrupt', value: r1(0.2 + 0.6 * noise(t, 61)), unit: '%', detail: true },
    { id: 'cpu.dpc', label: 'Tempo per le DPC', value: r1(0.1 + 0.4 * noise(t, 62)), unit: '%', detail: true },
    ...cores.flatMap((c, i) => [
      { id: `cpu.core.0,${i}.clock`, label: `Processore logico ${i}: frequenza`, value: Math.round(c.mhz), unit: 'MHz', detail: true },
      { id: `cpu.core.0,${i}.usage`, label: `Processore logico ${i}: utilizzo`, value: r1(c.load), unit: '%', detail: true },
    ]),
  ];
  groups.push({ id: 'cpu', kind: 'cpu', name: pc?.cpu?.name ?? 'Processore', sensors: cpu });
  if (tz !== undefined) {
    groups.push({
      id: 'thermal',
      kind: 'thermal',
      name: 'Zone termiche ACPI',
      sub: 'dichiarate dal firmware',
      sensors: [
        { id: 'tz.tz-tz00.temp', label: 'Zona TZ00', value: r1(tz), unit: '°C', warn: 85, crit: 95 },
        { id: 'tz.tz-tz00.passive', label: 'Zona TZ00: limite per il calore', value: Math.round(passive), unit: '%', warn: 100, below: true, detail: true },
      ],
    });
  } else {
    missing.push('Zone termiche: il firmware di questo PC non ne dichiara a Windows.');
  }
  // Scheda video integrata: utilizzo e memoria dai contatori, nessuna telemetria dal driver.
  (pc?.gpus ?? []).slice(0, 1).forEach((g) => {
    const id = 'gpu.0x00000000_0x0000d1b8';
    const use = 4 + 22 * noise(t, 70) * wave;
    groups.push({
      id,
      kind: 'gpu',
      name: g.name,
      sensors: [
        { id: `${id}.usage`, label: 'Utilizzo', value: r1(use), unit: '%' },
        { id: `${id}.dedicated`, label: 'Memoria dedicata in uso', value: 0, unit: 'MB' },
        { id: `${id}.shared`, label: 'Memoria condivisa in uso', value: Math.round(380 + 160 * wave), unit: 'MB' },
        { id: `${id}.engine.3d`, label: 'Motore 3D', value: r1(use), unit: '%' },
        { id: `${id}.engine.copy`, label: 'Copia', value: r1(1.5 * noise(t, 71)), unit: '%', detail: true },
        { id: `${id}.engine.videodecode`, label: 'Decodifica video', value: r1(12 * noise(t, 72)), unit: '%', detail: true },
      ],
    });
    missing.push('Temperatura e frequenze della scheda video: il driver non le fornisce a Windows (servono un driver WDDM 2.4 o successivo e il supporto del produttore).');
  });
  // Memoria
  if (pc?.memory) {
    const total = pc.memory.totalMB / 1024;
    const used = Math.min(total, total - pc.memory.availableMB / 1024 + 0.25 * Math.sin(t / 5));
    const limit = (pc.memory.commitLimitMB ?? pc.memory.totalMB * 1.5) / 1024;
    const commit = Math.min(limit, (pc.memory.commitMB ?? pc.memory.totalMB) / 1024 + 0.3 * Math.sin(t / 6));
    groups.push({
      id: 'memory',
      kind: 'memory',
      name: 'Memoria',
      sub: `${r1(total)} GB utilizzabili`.replace('.', ','),
      sensors: [
        { id: 'mem.load', label: 'Memoria fisica in uso', value: Math.round((100 * used) / total), unit: '%', warn: 85, crit: 95 },
        { id: 'mem.used', label: 'Memoria fisica usata', value: r1(used, 2), unit: 'GB' },
        { id: 'mem.avail', label: 'Memoria fisica disponibile', value: r1(total - used, 2), unit: 'GB' },
        { id: 'mem.commit', label: 'Memoria impegnata', value: r1(commit, 2), unit: 'GB' },
        { id: 'mem.commitload', label: 'Memoria impegnata sul limite', value: Math.round((100 * commit) / limit), unit: '%', warn: 85, crit: 95 },
        { id: 'mem.pagefile', label: 'File di paging usato', value: r1(18 + 6 * wave), unit: '%' },
        { id: 'mem.pages', label: 'Pagine lette o scritte su disco', value: Math.round(40 * noise(t, 80) * wave), unit: '/s', detail: true },
      ],
    });
  }
  // Dischi
  (pc?.disks ?? []).forEach((d, i) => {
    const id = d.id ?? String(i);
    const flash = d.media === 'ssd' || d.media === 'scm';
    const temp = d.nvme?.temperatureC ?? d.reliability?.temperatureC;
    const act = Math.min(100, (d.system ? 35 : 6) * wave * (0.3 + noise(t, 90 + i)));
    const letters = (pc?.volumes ?? []).filter((v) => v.disk === id && v.letter).map((v) => v.letter).join(' ');
    const sensors: SensorReading[] = [];
    if (temp !== undefined) {
      const [warn, crit] = flash ? [70, 80] : [55, 60];
      sensors.push({ id: `disk.${id}.temp`, label: 'Temperatura', value: Math.round(temp + 3 * wave), unit: '°C', warn, crit });
    }
    sensors.push(
      { id: `disk.${id}.activity`, label: 'Attività', value: r1(act), unit: '%' },
      { id: `disk.${id}.read`, label: 'Lettura', value: r1((flash ? 9 : 2.5) * act * noise(t, 92 + i), 2), unit: 'MB/s' },
      { id: `disk.${id}.write`, label: 'Scrittura', value: r1((flash ? 3 : 1) * act * noise(t, 94 + i), 2), unit: 'MB/s' },
      { id: `disk.${id}.latency`, label: 'Tempo di risposta medio', value: r1(flash ? 0.2 + 0.6 * noise(t, 96 + i) : 6 + 14 * noise(t, 96 + i)), unit: 'ms', warn: 100, crit: 500 },
      { id: `disk.${id}.queue`, label: 'Richieste in coda', value: Math.round(2 * noise(t, 98 + i) * wave), unit: '', detail: true },
    );
    groups.push({ id: `disk.${id}`, kind: 'disk', name: `Disco ${id}: ${d.name}`, sub: letters || undefined, sensors });
  });
  // Rete
  scan.adapters
    .filter((a) => a.up && (a.kind === 'wifi' || a.kind === 'ethernet'))
    .forEach((a, i) => {
      const name = (a.description ?? a.name).replace(/\(/g, '[').replace(/\)/g, ']');
      const id = `net.${name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')}`;
      groups.push({
        id,
        kind: 'network',
        name,
        sensors: [
          { id: `${id}.rx`, label: 'Ricezione', value: r1(0.05 + 18 * wave * noise(t, 110 + i), 3), unit: 'Mbit/s' },
          { id: `${id}.tx`, label: 'Invio', value: r1(0.02 + 2 * wave * noise(t, 112 + i), 3), unit: 'Mbit/s' },
          { id: `${id}.link`, label: 'Velocità del collegamento', value: a.linkMbps ?? 0, unit: 'Mbit/s', detail: true },
        ],
      });
    });
  // Batteria
  const b = pc?.battery;
  if (b && pc?.power?.hasBattery) {
    const full = (b.fullMWh ?? 40000) / 1000;
    const design = b.designMWh ? b.designMWh / 1000 : undefined;
    const onAC = pc.power.onAC !== false;
    const charge = Math.min(100, (b.chargePct ?? 60) + (onAC ? t / 40 : -t / 60));
    const sensors: SensorReading[] = [
      { id: 'battery.0.charge', label: 'Carica', value: Math.round(Math.max(0, charge)), unit: '%', warn: 20, crit: 10, below: true },
      { id: 'battery.0.capacity', label: 'Energia residua', value: r1((full * Math.max(0, charge)) / 100), unit: 'Wh' },
      { id: 'battery.0.rate', label: 'Potenza (positiva in carica, negativa in scarica)', value: r1(onAC ? (charge < 100 ? 18 - 6 * noise(t, 120) : 0) : -(6 + 8 * wave)), unit: 'W' },
      { id: 'battery.0.voltage', label: 'Tensione', value: r1(11.4 + 1.2 * (charge / 100), 2), unit: 'V' },
    ];
    if (design) sensors.push({ id: 'battery.0.health', label: 'Salute (capacità rispetto a quella originale)', value: Math.round((100 * full) / design), unit: '%', warn: 50, below: true });
    groups.push({ id: 'battery.0', kind: 'battery', name: 'Batteria', sub: onAC ? (charge < 100 ? 'in carica' : 'alimentatore collegato') : 'a batteria', sensors });
  }
  // Sistema
  const procs = 150 + Math.round((pc?.processes ?? []).reduce((a, p) => a + p.count, 0) + 4 * noise(t, 130));
  groups.push({
    id: 'system',
    kind: 'system',
    name: 'Sistema',
    sensors: [
      { id: 'sys.processes', label: 'Processi', value: procs, unit: '' },
      { id: 'sys.threads', label: 'Thread', value: procs * 13 + Math.round(40 * noise(t, 131)), unit: '' },
      { id: 'sys.ctx', label: 'Cambi di contesto', value: Math.round(9000 + 30000 * wave * noise(t, 132)), unit: '/s', detail: true },
      { id: 'sys.queue', label: 'Thread in attesa del processore', value: Math.round(3 * noise(t, 133) * wave), unit: '', detail: true },
      { id: 'sys.uptime', label: "Tempo dall'avvio", value: r1(((pc?.os?.uptimeSec ?? 7200) + t) / 3600), unit: 'ore' },
    ],
  });
  missing.push("Temperature, tensioni e ventole del processore e della scheda madre: Windows non le espone senza un driver in kernel, che Polaris non usa. Per queste c'è HWiNFO nella Cassetta degli attrezzi.");
  return { at: new Date(now).toISOString(), groups, missing };
}

// ---------------------------------------------------------------- interfaccia

const ICONS: Record<SensorKind, LucideIcon> = { cpu: Cpu, thermal: Thermometer, gpu: Gpu, memory: MemoryStick, disk: HardDrive, network: Network, battery: BatteryMedium, system: Activity };

type Mode = 'live' | 'demo' | 'off';

/** Sessioni conservate tra un cambio di sezione e l'altro, per sorgente. */
const sessions = new Map<string, SensorsState>();

function useSensorSession(mode: Mode, scan: Scan, paused: boolean, retry: number) {
  const key = `${mode}|${scan.agent.startedAt}|${scan.agent.host ?? ''}`;
  const [state, setState] = useState<SensorsState>(() => sessions.get(key) ?? emptySensors());
  const [error, setError] = useState<string>();
  const toast = useToast();
  const armed = useRef<Record<string, Level>>({});
  useEffect(() => {
    setState(sessions.get(key) ?? emptySensors());
    armed.current = {};
  }, [key]);
  useEffect(() => {
    if (mode === 'off' || paused) return;
    let alive = true;
    let busy = false;
    let ctl: AbortController | undefined;
    let t = sessions.get(key)?.tick ?? 0;
    const step = async () => {
      if (busy || document.visibilityState !== 'visible') return;
      busy = true;
      try {
        ctl = new AbortController();
        const snap = mode === 'live' ? await readSensors(ctl.signal) : simulateSensors(scan, t++, Date.now());
        if (!alive) return;
        const next = pushSnapshot(sessions.get(key) ?? emptySensors(), snap);
        sessions.set(key, next);
        setState(next);
        const a = nextAlerts(armed.current, next);
        armed.current = a.armed;
        for (const f of a.fire.slice(0, 2)) toast(f.text, f.level === 'crit' ? 'error' : 'warn', 'alert');
      } catch (e) {
        if (!alive) return;
        // Dopo un errore ci si ferma: il pulsante Riprova riparte.
        clearInterval(id);
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        busy = false;
      }
    };
    const id = setInterval(step, 1000);
    setError(undefined);
    step();
    return () => {
      alive = false;
      clearInterval(id);
      ctl?.abort();
    };
  }, [mode, paused, retry, key, scan, toast]);
  const reset = () => {
    const cur = sessions.get(key);
    if (!cur) return;
    const next = resetStats(cur);
    sessions.set(key, next);
    setState(next);
  };
  return { state, error, reset };
}

const timeIt = (iso?: string) => (iso ? new Date(iso).toLocaleTimeString('it-IT', { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '');

function SummaryTiles({ s }: { s: SensorsState }) {
  const cur = (id: string) => s.stats[id];
  const present = new Set(s.groups.flatMap((g) => g.ids));
  const live = Object.values(s.stats).filter((x) => present.has(x.id));
  const tiles: { k: string; v: string; sub?: string; lvl: Level }[] = [];
  const usage = cur('cpu.usage');
  if (usage && present.has(usage.id)) {
    const clock = cur('cpu.clock');
    const ghz = clock && present.has(clock.id) ? (clock.cur / 1000).toLocaleString('it-IT', { minimumFractionDigits: 2, maximumFractionDigits: 2 }) : '';
    tiles.push({ k: 'Processore', v: fmtSensor(usage.cur, '%'), sub: ghz ? `${ghz} GHz di media` : undefined, lvl: 'ok' });
  }
  const pkg = live.find((x) => x.id.startsWith('cpu.power.') && x.label.includes('package'));
  if (pkg) tiles.push({ k: 'Consumo del processore', v: fmtSensor(pkg.cur, pkg.unit), sub: `massimo ${fmtSensor(pkg.max, pkg.unit)}`, lvl: 'ok' });
  const temps = live.filter((x) => x.unit === '°C').sort((a, b) => b.cur - a.cur);
  if (temps.length) {
    const t = temps[0];
    tiles.push({ k: 'Temperatura più alta', v: fmtSensor(t.cur, t.unit), sub: `${t.group}${t.label === 'Temperatura' ? '' : `, ${t.label}`}`, lvl: levelOf(t, t.cur) });
  }
  const mem = cur('mem.load');
  if (mem && present.has(mem.id)) {
    const used = cur('mem.used');
    tiles.push({ k: 'Memoria in uso', v: fmtSensor(mem.cur, '%'), sub: used ? fmtSensor(used.cur, 'GB') : undefined, lvl: levelOf(mem, mem.cur) });
  }
  const gpu = live.filter((x) => x.id.startsWith('gpu.') && x.id.endsWith('.usage')).sort((a, b) => b.cur - a.cur)[0];
  if (gpu) tiles.push({ k: 'Scheda video', v: fmtSensor(gpu.cur, '%'), sub: gpu.group, lvl: 'ok' });
  const disk = live.filter((x) => x.id.startsWith('disk.') && x.id.endsWith('.activity')).sort((a, b) => b.cur - a.cur)[0];
  if (disk) tiles.push({ k: 'Disco più attivo', v: fmtSensor(disk.cur, '%'), sub: disk.group, lvl: 'ok' });
  return (
    <div className="stats sensors-summary">
      {tiles.map((x) => (
        <div key={x.k} className="stat">
          <div className="k">{x.k}</div>
          <div className={`v ${x.lvl === 'ok' ? '' : `c-${x.lvl}`}`}>{x.v}</div>
          {x.sub && <span className="sub">{x.sub}</span>}
        </div>
      ))}
    </div>
  );
}

function GroupTable({ g, s, detail, tick }: { g: SensorsState['groups'][number]; s: SensorsState; detail: boolean; tick: number }) {
  const [open, setOpen] = useState(true);
  const [charts, setCharts] = useState<Set<string>>(new Set());
  const Icon = ICONS[g.kind] ?? Activity;
  const rows = g.ids.map((id) => s.stats[id]).filter((x): x is SensorStat => !!x);
  const shown = rows.filter((x) => detail || !x.detail);
  const hidden = rows.length - shown.length;
  const tableId = `sensors-${g.id.replace(/[^a-z0-9]+/gi, '-')}`;
  const toggle = (id: string) =>
    setCharts((c) => {
      const n = new Set(c);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });
  return (
    <div className="sensor-group">
      <h3 className="sensor-group-head">
        <button className="link-btn" aria-expanded={open} aria-controls={tableId} onClick={() => setOpen((o) => !o)}>
          <ChevronDown size={15} aria-hidden className={open ? 'chev open' : 'chev'} />
          <Icon size={15} aria-hidden />
          <span>{g.name}</span>
        </button>
        {g.sub && <span className="faint">{g.sub}</span>}
      </h3>
      <div id={tableId} hidden={!open}>
        {open && (
          <TableWrap label={`Sensori: ${g.name}`}>
            <table className="sensor-table">
              <thead>
                <tr>
                  <th scope="col">Sensore</th>
                  <th scope="col" className="num">
                    Attuale
                  </th>
                  <th scope="col" className="num">
                    Minimo
                  </th>
                  <th scope="col" className="num">
                    Massimo
                  </th>
                  <th scope="col" className="num">
                    Media
                  </th>
                </tr>
              </thead>
              <tbody>
                {shown.map((x) => {
                  const lvl = levelOf(x, x.cur);
                  const chartId = `${tableId}-${x.id.replace(/[^a-z0-9]+/gi, '-')}`;
                  const exp = charts.has(x.id);
                  // Il grafico parte da zero: la potenza della batteria in scarica è negativa e si mostra in valore assoluto.
                  const neg = x.hist.some((v) => v !== null && v < 0);
                  return (
                    <Fragment key={x.id}>
                      <tr className={lvl === 'ok' ? undefined : `lvl-${lvl}`}>
                        <th scope="row">
                          <button className="sensor-name" aria-expanded={exp} aria-controls={exp ? chartId : undefined} onClick={() => toggle(x.id)} title={exp ? 'Nascondi il grafico' : 'Mostra il grafico'}>
                            {lvl !== 'ok' && <TriangleAlert size={13} aria-hidden className={`c-${lvl}`} />}
                            {x.label}
                          </button>
                        </th>
                        <td className={`num mono${lvl === 'ok' ? '' : ` c-${lvl}`}`}>{fmtSensor(x.cur, x.unit)}</td>
                        <td className="num mono">{fmtSensor(x.min, x.unit)}</td>
                        <td className="num mono">{fmtSensor(x.max, x.unit)}</td>
                        <td className="num mono">{fmtSensor(x.sum / x.n, x.unit)}</td>
                      </tr>
                      {exp && (
                        <tr className="sensor-chart-row">
                          <td colSpan={5} id={chartId}>
                            <LiveChart
                              series={[{ label: x.label, color: 'var(--accent)', samples: neg ? x.hist.map((v) => (v === null ? null : Math.abs(v))) : x.hist }]}
                              tick={tick}
                              maxPoints={HIST}
                              height={150}
                              unit={x.unit === 'giri/min' ? 'g/min' : x.unit}
                              floor={0}
                              fixedMax={x.unit === '%' ? 100 : undefined}
                              label={`${g.name}, ${x.label}${neg ? ' in valore assoluto' : ''}, ultimi ${HIST} secondi`}
                            />
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </TableWrap>
        )}
        {hidden > 0 && (
          <p className="faint sensor-hidden">
            {hidden === 1 ? '1 riga di dettaglio nascosta' : `${hidden} righe di dettaglio nascoste`}: si vedono con il pulsante Dettagli.
          </p>
        )}
      </div>
    </div>
  );
}

export function SensorsCard({ scan, live, source }: { scan: Scan; live: boolean; source: ViewProps['source'] }) {
  const mode: Mode = live ? 'live' : source === 'demo' ? 'demo' : 'off';
  const [paused, setPaused] = useState(false);
  const [retry, setRetry] = useState(0);
  const [detail, setDetail] = useLocalState<boolean>('polaris.sensors.detail', false);
  const { state: s, error, reset } = useSensorSession(mode, scan, paused, retry);

  if (mode === 'off') {
    return (
      <m.section variants={rise} className="card sensors-card">
        <div className="card-head">
          <h2>Sensori in tempo reale</h2>
        </div>
        <p className="faint" style={{ margin: 0 }}>
          I sensori si leggono dal vivo solo con l&apos;agente sul PC: un rapporto importato non li contiene.
        </p>
      </m.section>
    );
  }
  const exportCsv = () => {
    const d = new Date();
    const pad2 = (n: number) => String(n).padStart(2, '0');
    download(`polaris-sensori-${d.getFullYear()}${pad2(d.getMonth() + 1)}${pad2(d.getDate())}-${pad2(d.getHours())}${pad2(d.getMinutes())}.csv`, sensorsCsv(s), 'text/csv;charset=utf-8');
  };
  return (
    <m.section variants={rise} className="card sensors-card">
      <div className="card-head sensors-head">
        <span className={`live-dot${paused || error ? ' off' : ''}`} aria-hidden="true" />
        <h2>Sensori in tempo reale</h2>
        {mode === 'demo' && <span className="tag">simulati</span>}
        <span className="spacer" />
        <div className="sensors-actions">
          <button className="btn small" onClick={() => setPaused((p) => !p)} aria-pressed={paused} disabled={!!error}>
            {paused ? <Play size={15} aria-hidden /> : <Pause size={15} aria-hidden />} Pausa
          </button>
          <button className="btn small" onClick={reset} disabled={s.tick === 0}>
            <RotateCcw size={15} aria-hidden /> Azzera minimi e massimi
          </button>
          <button className="btn small" onClick={() => setDetail(!detail)} aria-pressed={detail}>
            {detail ? <EyeOff size={15} aria-hidden /> : <Eye size={15} aria-hidden />} Dettagli
          </button>
          <button className="btn small" onClick={exportCsv} disabled={s.log.length === 0}>
            <Download size={15} aria-hidden /> Esporta CSV
          </button>
        </div>
      </div>
      {error && (
        <div className="tool-problem clock-error">
          <TriangleAlert size={14} aria-hidden />
          <span>
            Lettura non disponibile: {error}.{' '}
            <button className="link-btn" onClick={() => setRetry((r) => r + 1)}>
              <RotateCw size={13} aria-hidden /> Riprova
            </button>
          </span>
        </div>
      )}
      {s.tick === 0 ? (
        !error && (
          <p className="clock-wait">
            <HexLoader size={18} label="Prima lettura in corso" /> Prima lettura…
          </p>
        )
      ) : (
        <>
          <SummaryTiles s={s} />
          <p className="faint sensors-since">
            Minimo, massimo e media dalle {timeIt(s.since)} · {s.log.length === 1 ? '1 lettura' : `${s.log.length} letture`} nel registro (al massimo un&apos;ora) · tocca un
            sensore per il suo grafico
          </p>
          {s.groups.map((g) => (
            <GroupTable key={g.id} g={g} s={s} detail={detail} tick={s.tick} />
          ))}
        </>
      )}
      {s.missing.length > 0 && (
        <div className="hw-block sensors-missing">
          <h3>Cosa non si legge su questo PC</h3>
          <ul>
            {s.missing.map((x) => (
              <li key={x}>{x}</li>
            ))}
          </ul>
        </div>
      )}
      <p className="faint clock-note">
        Come HWiNFO, ma senza driver: Polaris legge i contatori delle prestazioni di Windows (gli stessi di Gestione attività), i dati che il driver video
        fornisce a Windows, lo stato della batteria e, ogni 30 secondi, la temperatura dei dischi dai dati SMART. Le zone termiche sono dichiarate dal
        firmware e non sempre seguono il processore.
      </p>
    </m.section>
  );
}
