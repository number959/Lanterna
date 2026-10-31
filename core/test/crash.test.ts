import { build } from 'esbuild';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { describe, expect, it } from 'vitest';
import {
  ACTIONS,
  analyze,
  BUGCHECKS,
  BUGCHECKS_MORE,
  bugcheckInfo,
  bugcheckText,
  crashCode,
  crashCodes,
  crashDrivers,
  crashSummary,
  documentParts,
  lastBugcheckEvent,
  METRICS,
  parseBugcheckEvent,
  renderText,
} from '../src/engine';
import type { CrashData, CrashDump, EventGroup, Finding, PcData, Scan } from '../src/engine';
import { clinicScan } from '../src/demo/clinic';
import { demoScan } from '../src/demo/sample';
import { ACTION_TOOLS } from '../src/tools';
import { crashBadge, noCulpritText, sameCrashTarget } from '../src/ui/crashes';
import { GLOSSARY, guideById } from '../src/guides';

// Schermate blu dai minidump: giudizi del motore senza doppioni rispetto a
// pc.events.bsod, demo, documento e rapporto senza percorsi, motore in goja.

const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));

const dump = (patch: Partial<CrashDump>): CrashDump => ({
  file: '101026-1000-01.dmp',
  size: 600000,
  time: '2026-10-10T10:00:00Z',
  code: '0x000000d1',
  params: ['0x0000000000000010', '0x0000000000000002', '0x0000000000000000', '0xfffff8045b6a2c3e'],
  bits: 64,
  machine: 'x64',
  build: 26100,
  dumpType: 'triage',
  drivers: 200,
  ...patch,
});

const bsodEvent = (count: number, detail = '0x000000d1 (0x0000000000000010, 0x0000000000000002, 0x0000000000000000, 0xfffff8045b6a2c3e)'): EventGroup => ({
  kind: 'bugcheck',
  source: 'Microsoft-Windows-WER-SystemErrorReporting',
  id: 1001,
  count,
  last: '2026-10-10T10:00:00Z',
  detail,
});

function scanWith(crashes: CrashData | undefined, events: EventGroup[] = [], startedAt = '2026-10-15T09:00:00Z'): Scan {
  const pc: PcData = { events, eventsDays: 30, ...(crashes ? { crashes } : {}) };
  return {
    schema: 1,
    agent: { name: 'STARNET Polaris', version: 'test', platform: 'windows', host: 'PC-PROVA', startedAt, durationMs: 1000 },
    adapters: [],
    pc,
    errors: [],
  };
}

const data = (dumps: CrashDump[], patch: Partial<CrashData> = {}): CrashData => ({
  readAt: '2026-10-15T09:00:00Z',
  settings: { dumpEnabled: 7, minidumpDir: '%SystemRoot%\\Minidump', autoReboot: true, logEvent: true },
  folder: 'ok',
  total: dumps.length,
  dumps,
  ...patch,
});

const crashFindings = (s: Scan): Finding[] => analyze(s).findings.filter((f) => f.id.indexOf('pc.crash') === 0);
const byId = (s: Scan, id: string) => analyze(s).findings.find((f) => f.id === id);

describe('codici di arresto', () => {
  it('normalizza i codici e riconosce nomi e famiglie', () => {
    expect(crashCode('0xD1')).toBe('0x000000d1');
    expect(crashCode('0x1000007E')).toBe('0x1000007e');
    expect(crashCode('d1')).toBe('');
    expect(crashCode('0x123456789')).toBe('');
    expect(bugcheckInfo('0xd1')).toMatchObject({ name: 'DRIVER_IRQL_NOT_LESS_OR_EQUAL', family: 'driver' });
    expect(bugcheckInfo('0x0000001A')).toMatchObject({ name: 'MEMORY_MANAGEMENT', family: 'memory' });
    expect(bugcheckInfo('0x7a').family).toBe('disk');
    expect(bugcheckInfo('0x124').family).toBe('hardware');
    expect(bugcheckInfo('0xe2').family).toBe('manual');
    expect(bugcheckText('0x00abcdef')).toBe('0x00abcdef (non è nell\'elenco di Polaris)');
    expect(bugcheckText(undefined)).toBe('codice non scritto nel file');
    // Nessun codice compare due volte con nomi diversi.
    for (const k of Object.keys(BUGCHECKS_MORE)) expect(BUGCHECKS[k], k).toBeUndefined();
  });

  it('legge codice e parametri dall\'evento 1001', () => {
    const e = parseBugcheckEvent('0x0000009F (0x0000000000000003, 0xffffe50c3c7a5060, 0xfffff8045b67f7b0, 0xffffe50c4a3c9010)');
    expect(e).toEqual({ code: '0x0000009f', params: ['0x0000000000000003', '0xffffe50c3c7a5060', '0xfffff8045b67f7b0', '0xffffe50c4a3c9010'] });
    expect(parseBugcheckEvent('0x0000009f')).toEqual({ code: '0x0000009f', params: [] });
    expect(parseBugcheckEvent('nessun codice')).toBeUndefined();
    const last = lastBugcheckEvent([bsodEvent(1), { ...bsodEvent(2), last: '2026-10-12T00:00:00Z' }, { kind: 'disk-error', source: 'disk', id: 7, count: 1, last: '2026-10-14T00:00:00Z' }]);
    expect(last?.last).toBe('2026-10-12T00:00:00Z');
  });

  it('ha gli stessi nomi ufficiali della riga di comando (windows/internal/crash/names.go)', () => {
    const src = readFileSync(fileURLToPath(new URL('../../windows/internal/crash/names.go', import.meta.url)), 'utf8');
    const go: Record<string, string> = {};
    for (const m of src.matchAll(/0x([0-9A-F]{8}):\s*"([A-Z0-9_]+)"/g)) go['0x' + m[1].toLowerCase()] = m[2];
    const ts: Record<string, string> = {};
    for (const [k, v] of Object.entries({ ...BUGCHECKS, ...BUGCHECKS_MORE })) ts[k] = v[0];
    expect(Object.keys(go).length).toBeGreaterThan(40);
    expect(go).toEqual(ts);
  });
});

describe('giudizi', () => {
  it('casa: driver ricorrente, senza un secondo conteggio delle schermate blu', () => {
    const a = analyze(demoScan);
    const bsod = a.findings.filter((f) => f.metric === 'pc.events.bsod');
    expect(bsod).toHaveLength(1);
    expect(bsod[0].value).toBe('1 in 30 giorni');
    const crash = a.findings.filter((f) => f.id.indexOf('pc.crash') === 0);
    expect(crash.map((f) => f.id)).toEqual(['pc.crash.driver']);
    const f = crash[0];
    expect(f.severity).toBe('warn');
    expect(f.value).toBe('acmewlan.sys: 3 su 4');
    expect(f.verdict).toContain('dal 14 agosto 2026 al 27 settembre 2026');
    expect(f.verdict).toContain('indizio, non una certezza');
    expect(f.actions).toEqual(['update-crash-driver', 'diagnose-bsod']);
    // Gli identificativi restano unici.
    const ids = a.findings.map((x) => x.id);
    expect(new Set(ids).size).toBe(ids.length);
    // L'azione sul driver entra nel piano.
    expect(a.plan.some((p) => p.action.id === 'update-crash-driver' && p.findings.indexOf('pc.crash.driver') >= 0)).toBe(true);
  });

  it('una ripetizione vecchia di oltre 30 giorni è solo un\'informazione', () => {
    const s = clone(demoScan);
    s.agent.startedAt = '2026-12-20T10:00:00Z';
    expect(byId(s, 'pc.crash.driver')?.severity).toBe('info');
    expect(byId(s, 'pc.crash.driver')?.verdict).toContain('più di 30 giorni');
  });

  it('un solo minidump per driver non basta; il kernel non è mai un driver ricorrente', () => {
    const one = data([dump({ probable: { driver: 'acmenet.sys', method: 'param', param: 4 } }), dump({ code: '0x0000003b', probable: { driver: 'acmeaudio.sys', method: 'stack' } })]);
    expect(crashFindings(scanWith(one))).toEqual([]);
    expect(crashDrivers(one)).toEqual([]);
    // Lo stesso driver, scritto con maiuscole diverse, si conta una volta sola.
    const two = data([dump({ probable: { driver: 'AcmeNet.sys', method: 'param', param: 4 } }), dump({ time: '2026-10-01T08:00:00Z', probable: { driver: 'acmenet.sys', method: 'stack', unloaded: true } })]);
    const g = crashDrivers(two);
    expect(g).toHaveLength(1);
    expect(g[0]).toMatchObject({ count: 2, first: '2026-10-01T08:00:00Z', last: '2026-10-10T10:00:00Z', unloaded: true });
    expect(byId(scanWith(two), 'pc.crash.driver')?.verdict).toContain('già scaricato');
  });

  it('codice ricorrente senza driver: famiglia e azioni', () => {
    const mem = data([dump({ code: '0x0000001a' }), dump({ code: '0x0000001a', time: '2026-09-01T10:00:00Z' }), dump({ code: '0x00000050' })]);
    const f = byId(scanWith(mem), 'pc.crash.code')!;
    expect(f.severity).toBe('warn');
    expect(f.value).toBe('0x0000001a: 2 su 3');
    expect(f.verdict).toContain('MEMORY_MANAGEMENT');
    expect(f.verdict).toContain('la memoria (RAM)');
    expect(f.actions).toEqual(['test-memory', 'diagnose-bsod']);
    const disk = data([dump({ code: '0x0000007a' }), dump({ code: '0x0000007a' })]);
    expect(byId(scanWith(disk), 'pc.crash.code')?.actions).toEqual(['check-disk-errors', 'diagnose-bsod']);
    const hw = data([dump({ code: '0x00000124' }), dump({ code: '0x00000124' })]);
    expect(byId(scanWith(hw), 'pc.crash.code')?.actions).toEqual(['check-hardware', 'check-temperatures']);
    const unknown = data([dump({ code: '0x00abcdef' }), dump({ code: '0x00abcdef' })]);
    expect(byId(scanWith(unknown), 'pc.crash.code')?.verdict).toContain('non è nell\'elenco di Polaris');
    // Gli arresti provocati a mano non sono un problema da cercare.
    const manual = data([dump({ code: '0x000000e2' }), dump({ code: '0x000000e2' })]);
    expect(crashFindings(scanWith(manual))).toEqual([]);
    // Con un driver ricorrente il codice è già nel suo giudizio.
    const both = data([dump({ probable: { driver: 'acmenet.sys', method: 'param', param: 4 } }), dump({ probable: { driver: 'acmenet.sys', method: 'param', param: 4 } })]);
    expect(crashFindings(scanWith(both)).map((x) => x.id)).toEqual(['pc.crash.driver']);
    expect(crashCodes(both)[0].count).toBe(2);
  });

  it('i file non letti non contano', () => {
    const d = data([dump({ error: 'accesso negato: serve avviare Polaris come amministratore', code: undefined }), dump({ error: 'file non leggibile', probable: { driver: 'acmenet.sys', method: 'stack' } }), dump({ probable: { driver: 'acmenet.sys', method: 'stack' } })]);
    expect(crashDrivers(d)).toEqual([]);
  });

  it('salvataggio dei dump disattivato o senza evento', () => {
    const off = (crashes: boolean) => data(crashes ? [dump({})] : [], { settings: { dumpEnabled: 0, logEvent: true } });
    const warn = byId(scanWith(off(true)), 'pc.crash.settings')!;
    expect(warn.severity).toBe('warn');
    expect(warn.value).toBe('disattivato');
    expect(warn.actions).toEqual(['enable-minidump']);
    expect(warn.verdict).toContain('Polaris non cambia l\'impostazione');
    expect(byId(scanWith(off(false)), 'pc.crash.settings')?.severity).toBe('info');
    // Nessun file ma schermate blu nel registro: conta lo stesso.
    expect(byId(scanWith(off(false), [bsodEvent(1)]), 'pc.crash.settings')?.severity).toBe('warn');
    const noLog = byId(scanWith(data([], { settings: { dumpEnabled: 3, logEvent: false } })), 'pc.crash.settings')!;
    expect(noLog.severity).toBe('info');
    expect(noLog.verdict).toContain('incompleto');
    expect(byId(scanWith(data([])), 'pc.crash.settings')).toBeUndefined();
  });

  it('senza amministratore: il codice dall\'evento 1001 e l\'invito ad avviare Polaris come amministratore', () => {
    const denied = data([], { folder: 'denied', needsAdmin: true, total: 0 });
    const f = byId(scanWith(denied, [bsodEvent(2)]), 'pc.crash.access')!;
    expect(f.severity).toBe('info');
    expect(f.value).toBe('serve l\'amministratore');
    expect(f.verdict).toContain('2 schermate blu negli ultimi 30 giorni');
    expect(f.verdict).toContain('0x000000d1 DRIVER_IRQL_NOT_LESS_OR_EQUAL');
    expect(f.actions).toEqual(['read-crash-files']);
    // Senza schermate blu non c'è nulla da leggere.
    expect(byId(scanWith(denied), 'pc.crash.access')).toBeUndefined();
    // Il conteggio resta quello di pc.events.bsod.
    expect(byId(scanWith(denied, [bsodEvent(2)]), 'pc.events.bsod')?.value).toBe('2 in 30 giorni');
  });

  it('senza dati sulle schermate blu (rapporti vecchi) e nella demo della clinica nessun giudizio', () => {
    expect(crashFindings(scanWith(undefined, [bsodEvent(3)]))).toEqual([]);
    expect(crashFindings(clinicScan)).toEqual([]);
    expect(clinicScan.pc?.crashes?.dumps).toEqual([]);
  });

  it('ogni giudizio ha la sua voce nella knowledge base e azioni esistenti, con le soglie dichiarate come scelte di Polaris', () => {
    for (const id of ['pc.crash.driver', 'pc.crash.code', 'pc.crash.settings', 'pc.crash.access']) expect(METRICS[id], id).toBeDefined();
    for (const id of ['pc.crash.driver', 'pc.crash.code']) expect(METRICS[id].limits).toContain('scelte di Polaris');
    for (const id of ['update-crash-driver', 'test-memory', 'check-temperatures', 'enable-minidump', 'read-crash-files']) expect(ACTIONS[id], id).toBeDefined();
    expect(ACTIONS['enable-minidump'].why).toContain('Polaris non cambia');
    for (const [action, tools] of Object.entries(ACTION_TOOLS)) {
      expect(ACTIONS[action], action).toBeDefined();
      expect(tools.length).toBeGreaterThan(0);
    }
  });
});

describe('demo', () => {
  it('casa: minidump dal più recente, driver di fantasia, coerenti con l\'evento 1001', () => {
    const c = demoScan.pc!.crashes!;
    const times = c.dumps.map((d) => d.time!);
    expect([...times].sort().reverse()).toEqual(times);
    for (const d of c.dumps) if (d.probable) expect(d.probable.driver.indexOf('acme')).toBe(0);
    for (const d of c.dumps) for (const s of d.stack ?? []) expect(s.indexOf('acme')).toBe(0);
    const ev = parseBugcheckEvent(lastBugcheckEvent(demoScan.pc!.events)!.detail)!;
    expect(ev.code).toBe(c.dumps[0].code);
    expect(ev.params).toEqual(c.dumps[0].params);
    expect(lastBugcheckEvent(demoScan.pc!.events)!.last).toBe(c.dumps[0].time);
    expect(c.memoryDump).toBeUndefined();
  });
});

describe('interfaccia', () => {
  it('unisce una nuova lettura solo al rapporto dell\'agente dello stesso PC e della stessa analisi', () => {
    const s = scanWith(data([]));
    const t = { host: 'PC-PROVA', startedAt: s.agent.startedAt };
    expect(sameCrashTarget(t, s, 'agent')).toBe(true);
    expect(sameCrashTarget(t, s, 'demo')).toBe(false);
    expect(sameCrashTarget(t, s, 'file')).toBe(false);
    expect(sameCrashTarget({ ...t, startedAt: '2026-10-16T00:00:00Z' }, s, 'agent')).toBe(false);
    expect(sameCrashTarget({ ...t, host: 'ALTRO' }, s, 'agent')).toBe(false);
    expect(sameCrashTarget(undefined, s, 'agent')).toBe(false);
  });

  it('la gravità di ogni file ha sempre un testo, e c\'è sempre un motivo se manca il driver', () => {
    expect(crashBadge(dump({}))).toEqual({ sev: 'warn', label: 'schermata blu' });
    expect(crashBadge(dump({ error: 'file non leggibile' }))).toEqual({ sev: 'unknown', label: 'file non letto' });
    expect(crashBadge(dump({ code: '0x000000e2' }))).toEqual({ sev: 'info', label: 'arresto provocato' });
    expect(crashBadge(dump({ code: undefined }))).toEqual({ sev: 'unknown', label: 'codice non scritto' });
    expect(noCulpritText(dump({ code: '0x00000124' }))).toContain('hardware');
    expect(noCulpritText(dump({ limited: 'inconsistent' }))).toContain('solo l\'intestazione');
    expect(noCulpritText(dump({}))).toContain('nessun driver di terze parti');
  });
});

describe('documento e rapporto', () => {
  it('il documento elenca le schermate blu senza percorsi', () => {
    const s = clone(demoScan);
    s.pc!.crashes!.settings!.minidumpDir = '%USERPROFILE%\\Dump\\Minidump';
    s.pc!.crashes!.memoryDump = dump({ file: 'MEMORY.DMP', size: 1_200_000_000, code: '0x0000009f', dumpType: 'bitmap-kernel', limited: 'not-triage', time: '2026-09-27T21:14:03Z' });
    s.pc!.crashes!.dumps.push(dump({ file: '010126-1-01.dmp', time: '2026-01-01T10:00:00Z', error: 'accesso negato: serve avviare Polaris come amministratore', code: undefined }));
    const { body } = documentParts(s, analyze(s));
    const i = body.indexOf('<h2>Schermate blu (file di Windows)</h2>');
    expect(i).toBeGreaterThan(0);
    const sec = body.slice(i, body.indexOf('</section>', i));
    expect(sec).toContain('acmewlan.sys');
    expect(sec).toContain('dall\'indirizzo nel parametro 4');
    expect(sec).toContain('DRIVER_POWER_STATE_FAILURE');
    expect(sec).toContain('092726-8421-01.dmp');
    expect(sec).toContain('MEMORY.DMP');
    expect(sec).toContain('dei dump del kernel e completi Polaris legge solo l\'intestazione');
    expect(sec).toContain('non letto: accesso negato');
    expect(sec).toContain('dump automatico');
    expect(sec).toContain('indizio, non una certezza');
    for (const bad of ['%USERPROFILE%', 'Minidump', '\\Dump', 'SystemRoot', 'C:\\']) expect(sec, bad).not.toContain(bad);
  });

  it('senza amministratore il documento lo dice; senza schermate blu non ha la sezione', () => {
    const s = scanWith(data([], { folder: 'denied', needsAdmin: true }), [bsodEvent(1)]);
    const { body } = documentParts(s, analyze(s));
    expect(body).toContain('Per leggere i file delle schermate blu serve avviare Polaris come amministratore.');
    expect(documentParts(clinicScan, analyze(clinicScan)).body).not.toContain('<h2>Schermate blu');
  });

  it('il rapporto di testo ha una riga per minidump, entro 90 colonne', () => {
    const txt = renderText(demoScan, analyze(demoScan), { verbose: true });
    expect(txt).toContain(' Schermate blu nei minidump: 4 file; salvataggio: dump automatico');
    expect(txt).toContain('27/09/2026 0x0000009f DRIVER_POWER_STATE_FAILURE; indizio: acmewlan.sys');
    expect(txt).toContain('(parametro 4)');
    expect(txt).toContain('MEMORY_MANAGEMENT; nessun driver di terze parti');
    expect(txt).not.toContain('Minidump\\');
    for (const line of txt.split('\n')) expect(line.length, line).toBeLessThanOrEqual(90);
    const denied = scanWith(data([], { folder: 'denied', needsAdmin: true }), [bsodEvent(1)]);
    const t2 = renderText(denied, analyze(denied), {});
    expect(t2).toContain('Schermate blu nei minidump: cartella non leggibile');
    expect(t2.replace(/\s+/g, ' ')).toContain('Per leggere i file delle schermate blu serve avviare Polaris come amministratore.');
    expect(crashSummary(dump({ code: '0x000000e2' }))).toBe('0x000000e2 MANUALLY_INITIATED_CRASH');
  });

  it('il motore della riga di comando (ES2015, goja) dà gli stessi giudizi, documento e rapporto', async () => {
    const entry = fileURLToPath(new URL('../src/engine/global.ts', import.meta.url));
    const out = await build({ entryPoints: [entry], bundle: true, format: 'iife', target: 'es2015', write: false });
    const code = out.outputFiles[0].text;
    expect(code).not.toContain('toLocaleString');
    const ctx: Record<string, unknown> = {};
    ctx.globalThis = ctx;
    vm.createContext(ctx);
    vm.runInContext(code, ctx);
    const engine = ctx.PolarisEngine as { analyzeJson(s: string): string; reportText(s: string, v: boolean): string; reportHtml(s: string, v: string, g: string): string };
    for (const s of [demoScan, scanWith(data([], { folder: 'denied', needsAdmin: true, settings: { dumpEnabled: 0 } }), [bsodEvent(2)])]) {
      const json = JSON.stringify(s);
      expect(JSON.parse(engine.analyzeJson(json))).toEqual(JSON.parse(JSON.stringify(analyze(s))));
      expect(engine.reportText(json, true)).toBe(renderText(s, analyze(s), { verbose: true }));
      expect(engine.reportHtml(json, '0.10.0', 'oggi')).toContain('<h2>Schermate blu (file di Windows)</h2>');
    }
  });
});

describe('guida e glossario', () => {
  it('la guida spiega minidump, privilegi, indizio, che cosa fare e limiti', () => {
    const g = guideById('minidump-schermate-blu')!;
    expect(g.chapter).toBe('pc');
    expect(g.metrics).toEqual(['pc.crash.driver', 'pc.crash.code', 'pc.crash.settings', 'pc.crash.access']);
    expect(g.actions).toEqual(expect.arrayContaining(['update-crash-driver', 'test-memory', 'check-disk-errors', 'check-temperatures', 'enable-minidump', 'read-crash-files']));
    const text = JSON.stringify(g.blocks);
    for (const k of ['C:\\\\Windows\\\\Minidump', 'MEMORY.DMP', 'amministratore', 'indizio', 'P4', '0xD1', 'mdsched.exe', 'WinDbg', 'simboli di debug', 'tecnico', 'BlueScreenView', 'scelta da Polaris', 'polaris-cli crashes'])
      expect(text, k).toContain(k);
  });

  it('il glossario ha i termini delle schermate blu', () => {
    const terms = GLOSSARY.map((t) => t.term);
    for (const t of ['Minidump', 'Codice di arresto', 'Bug check', 'Driver', 'Dump della memoria', 'Simboli di debug']) expect(terms, t).toContain(t);
  });

  it('la guida della riga di comando elenca il comando', () => {
    expect(JSON.stringify(guideById('riga-di-comando')!.blocks)).toContain('polaris-cli crashes [--json]');
  });
});
