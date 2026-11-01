import { build } from 'esbuild';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
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
  crashFolderText,
  crashSummary,
  documentParts,
  lastBugcheckEvent,
  METRICS,
  noCulpritText,
  parseBugcheckEvent,
  renderText,
} from '../src/engine';
import type { CrashData, CrashDump, EventGroup, Finding, PcData, Scan } from '../src/engine';
import { clinicScan } from '../src/demo/clinic';
import { demoScan } from '../src/demo/sample';
import { ACTION_TOOLS } from '../src/tools';
import { crashBadge, CrashesCard, sameCrashTarget } from '../src/ui/crashes';
import type { ViewProps } from '../src/ui/views';
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
    // ...e non nascondono un altro codice che si ripete, anche se sono di più.
    const tests = data([
      dump({ code: '0x000000e2' }),
      dump({ code: '0x000000e2' }),
      dump({ code: '0x000000e2' }),
      dump({ code: '0x0000001a' }),
      dump({ code: '0x0000001a', time: '2026-09-01T10:00:00Z' }),
    ]);
    expect(crashCodes(tests)[0].key).toBe('0x000000e2');
    const f2 = byId(scanWith(tests), 'pc.crash.code')!;
    expect(f2.severity).toBe('warn');
    expect(f2.value).toBe('0x0000001a: 2 su 5');
    expect(f2.verdict).toContain('MEMORY_MANAGEMENT');
    expect(f2.actions).toEqual(['test-memory', 'diagnose-bsod']);
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

  it('senza evento nel registro e minidump non letti il numero non è verificabile', () => {
    // Caso normale senza amministratore: niente "le conta dai minidump" né "nessuna".
    const hidden = scanWith(data([], { settings: { dumpEnabled: 3, logEvent: false }, folder: 'denied', needsAdmin: true, total: 0 }));
    const set = byId(hidden, 'pc.crash.settings')!;
    expect(set.verdict).not.toContain('le conta dai minidump');
    expect(set.verdict).toContain('si leggono solo avviando Polaris come amministratore');
    expect(set.verdict).toContain('non si può verificare');
    const b = byId(hidden, 'pc.events.bsod')!;
    expect(b).toMatchObject({ severity: 'unknown', value: 'non verificabile', actions: ['read-crash-files'] });
    expect(renderText(hidden, analyze(hidden), {})).not.toContain('Schermate blu: nessuna');
    // Lettura interrotta: stesso giudizio, senza l'invito all'amministratore.
    const cut = scanWith(data([], { settings: { dumpEnabled: 3, logEvent: false }, partial: true }));
    expect(byId(cut, 'pc.events.bsod')).toMatchObject({ severity: 'unknown', actions: [] });
    expect(byId(cut, 'pc.crash.settings')!.verdict).toContain('non si sono potuti leggere per intero');
    // Né file né eventi: non resta traccia di nulla.
    const none = byId(scanWith(data([], { settings: { dumpEnabled: 0, logEvent: false } })), 'pc.events.bsod')!;
    expect(none).toMatchObject({ severity: 'unknown', actions: ['enable-minidump'] });
    expect(none.verdict).toContain('per non salvare i file');
    // Cartella letta per intero: lo zero è verificato.
    expect(byId(scanWith(data([], { settings: { dumpEnabled: 3, logEvent: false } })), 'pc.events.bsod')).toMatchObject({ severity: 'ok', value: 'nessuna' });
    // Con una schermata blu nel registro il numero c'è comunque.
    expect(byId(scanWith(data([], { settings: { dumpEnabled: 3, logEvent: false }, folder: 'denied', needsAdmin: true }), [bsodEvent(1)]), 'pc.events.bsod')?.value).toBe('1 in 30 giorni');
    expect(METRICS['pc.events.bsod'].scale!.some((x) => x.severity === 'unknown')).toBe(true);
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

describe('conteggio delle schermate blu (pc.events.bsod) con i minidump', () => {
  const bsodOf = (s: Scan) => analyze(s).findings.filter((f) => f.metric === 'pc.events.bsod');

  it('un minidump recente che il registro eventi non riporta non lascia il giudizio "nessuna"', () => {
    const s = scanWith(data([dump({})]), []);
    const b = bsodOf(s);
    expect(b).toHaveLength(1);
    expect(b[0].severity).toBe('warn');
    expect(b[0].value).toBe('1 in 30 giorni');
    expect(b[0].verdict).toContain('l\'ultima il 10 ottobre 2026');
    expect(b[0].verdict).toContain('0x000000d1 DRIVER_IRQL_NOT_LESS_OR_EQUAL');
    expect(b[0].verdict).toContain('Il numero viene dai file delle schermate blu (minidump): il registro eventi non ne riporta nessuna');
    expect(b[0].actions).toEqual(['diagnose-bsod']);
    // Nessun giudizio doppio sulle stesse schermate blu.
    expect(crashFindings(s)).toEqual([]);
    expect(renderText(s, analyze(s), {})).not.toContain('Schermate blu: nessuna');
    // Con LogEvent spento il motivo è noto.
    const noLog = scanWith(data([dump({})], { settings: { dumpEnabled: 3, logEvent: false } }), []);
    expect(bsodOf(noLog)[0].verdict).toContain('e Windows è impostato per non annotarle');
  });

  it('evento e file della stessa schermata blu non si sommano; vale il numero più alto', () => {
    expect(bsodOf(scanWith(data([dump({})]), [bsodEvent(1)]))[0]).toMatchObject({ value: '1 in 30 giorni', severity: 'warn' });
    expect(bsodOf(scanWith(data([dump({})]), [bsodEvent(1)]))[0].verdict).not.toContain('minidump');
    expect(bsodOf(scanWith(data([dump({})]), [bsodEvent(3)]))[0].value).toBe('3 in 30 giorni');
    const two = bsodOf(scanWith(data([dump({}), dump({ time: '2026-10-01T08:00:00Z', code: '0x0000001a' })]), [bsodEvent(1)]))[0];
    expect(two).toMatchObject({ value: '2 in 30 giorni', severity: 'crit' });
    expect(two.verdict).toContain('il registro eventi ne riporta solo una');
    expect(two.verdict).toContain('0x0000001a MEMORY_MANAGEMENT');
    expect(two.actions).toEqual(['diagnose-bsod', 'check-hardware']);
  });

  it('contano solo i minidump letti dentro la finestra degli eventi', () => {
    const old = scanWith(data([dump({ time: '2026-09-01T10:00:00Z' })]), []);
    expect(bsodOf(old)[0]).toMatchObject({ value: 'nessuna', severity: 'ok' });
    const unread = scanWith(data([dump({ error: 'file non leggibile', code: undefined }), dump({ code: undefined })]), []);
    expect(bsodOf(unread)[0].value).toBe('nessuna');
    // Senza l'ora scritta nel file vale la data del file.
    const byFile = scanWith(data([dump({ time: undefined, modified: '2026-10-11T08:00:00Z' })]), []);
    expect(bsodOf(byFile)[0].value).toBe('1 in 30 giorni');
    // Registro eventi non letto: i minidump recenti contano lo stesso, e il giudizio lo dice.
    const noLog = scanWith(data([dump({}), dump({ time: '2026-10-08T10:00:00Z', code: '0x0000003b' })]), []);
    delete noLog.pc!.eventsDays;
    const nl = bsodOf(noLog);
    expect(nl).toHaveLength(1);
    expect(nl[0]).toMatchObject({ value: '2 in 30 giorni', severity: 'crit' });
    expect(nl[0].verdict).toContain('Il registro eventi non è stato letto: il numero viene solo dai file delle schermate blu (minidump).');
    expect(nl[0].verdict).toContain('0x0000003b');
    const partial = scanWith(data([dump({})], { partial: true }), []);
    delete partial.pc!.eventsDays;
    expect(bsodOf(partial)[0].verdict).toContain('può essere incompleto');
    // Senza minidump recenti e senza registro non si dice nulla.
    const quiet = scanWith(data([dump({ time: '2026-08-01T10:00:00Z' })]), []);
    delete quiet.pc!.eventsDays;
    expect(bsodOf(quiet)).toEqual([]);
    // La demo resta coerente: un evento e un minidump nella finestra.
    expect(bsodOf(demoScan)[0].value).toBe('1 in 30 giorni');
    expect(bsodOf(demoScan)[0].verdict).not.toContain('Il numero viene dai file');
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
    expect(noCulpritText(dump({}))).toBe('nessun driver fuori dal nucleo di Windows (kernel e HAL) nello stack salvato');
    expect(noCulpritText(dump({ code: '0x000000e2' }))).toContain('di proposito');
    expect(noCulpritText(dump({ code: undefined }))).toBe('non cercato: codice non scritto nel file');
    expect(noCulpritText(dump({ dumpType: 'kernel', limited: 'not-triage' }))).toContain('solo l\'intestazione');
  });

  it('lettura interrotta: la scheda non dice "nessun file" se la cartella ne ha', () => {
    const text = (crashes: CrashData) => {
      const props = { scan: scanWith(crashes), live: false, source: 'file', addCrashes: () => false } as unknown as ViewProps;
      return renderToStaticMarkup(createElement(CrashesCard, props)).replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');
    };
    // Cartella elencata (3 file), nessun file letto prima della scadenza.
    const listed = text(data([], { total: 3, partial: true }));
    expect(listed).toContain('Nella cartella dei minidump ci sono 3 file, ma la lettura non è finita in tempo');
    expect(listed).not.toContain('Nessun file di schermata blu');
    expect(listed).toContain('Salvataggio dopo una schermata blu');
    // Lettura fermata prima della cartella: niente impostazioni, niente "nessun file".
    const stopped = text({ readAt: '2026-10-15T09:00:00Z', total: 0, dumps: [], partial: true });
    expect(stopped).toContain('La lettura dei file delle schermate blu non è finita in tempo');
    expect(stopped).not.toContain('Nessun file di schermata blu');
    expect(stopped).not.toContain('Salvataggio dopo una schermata blu');
    // Cartella vuota letta per intero.
    expect(text(data([]))).toContain('Nessun file di schermata blu nella cartella dei minidump.');
  });

  it('stato della cartella dei minidump', () => {
    expect(crashFolderText(data([dump({})]))).toBe('1 file');
    expect(crashFolderText(data([]))).toBe('nessun file');
    expect(crashFolderText(data([], { folder: 'missing' }))).toBe('nessun file');
    expect(crashFolderText(data([], { folder: 'denied', needsAdmin: true }))).toBe('cartella non leggibile');
    expect(crashFolderText(data([], { folder: 'error' }))).toBe('cartella non leggibile');
    expect(crashFolderText({ readAt: '2026-10-15T09:00:00Z', total: 0, dumps: [], partial: true })).toBe('lettura non finita in tempo');
    expect(crashFolderText(data([dump({})], { partial: true }))).toBe('1 file, lettura interrotta prima della fine');
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
    expect(sec).not.toContain('Lettura interrotta');
    s.pc!.crashes!.partial = true;
    expect(documentParts(s, analyze(s)).body).toContain('Lettura interrotta prima della fine: l\'elenco può essere incompleto.');
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
    expect(txt.replace(/\s+/g, ' ')).toContain('MEMORY_MANAGEMENT; nessun driver indicato fuori dal nucleo di Windows (060326-5121-01.dmp)');
    const sec = txt.slice(txt.indexOf('Schermate blu nei minidump'), txt.indexOf('(060326-5121-01.dmp)'));
    expect(sec).not.toContain('terze parti');
    expect(txt).not.toContain('Minidump\\');
    for (const line of txt.split('\n')) expect(line.length, line).toBeLessThanOrEqual(90);
    const denied = scanWith(data([], { folder: 'denied', needsAdmin: true }), [bsodEvent(1)]);
    const t2 = renderText(denied, analyze(denied), {});
    expect(t2).toContain('Schermate blu nei minidump: cartella non leggibile');
    expect(t2.replace(/\s+/g, ' ')).toContain('Per leggere i file delle schermate blu serve avviare Polaris come amministratore.');
    expect(crashSummary(dump({ code: '0x000000e2' }))).toBe('0x000000e2 MANUALLY_INITIATED_CRASH');
    expect(crashSummary(dump({ code: '0x00000124' }))).toBe('0x00000124 WHEA_UNCORRECTABLE_ERROR; nessun driver: errore segnalato dall\'hardware');
    expect(crashSummary(dump({ code: undefined }))).toBe('codice non scritto nel file');
    // Cartella illeggibile per un errore che non è di permessi: non è "nessun file".
    const broken = scanWith(data([], { folder: 'error' }));
    expect(renderText(broken, analyze(broken), {})).toContain('Schermate blu nei minidump: cartella non leggibile');
    const unfinished = scanWith({ readAt: '2026-10-15T09:00:00Z', total: 0, dumps: [], partial: true });
    expect(renderText(unfinished, analyze(unfinished), {})).toContain('Schermate blu nei minidump: lettura non finita in tempo');
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
    const scans = [
      demoScan,
      scanWith(data([], { folder: 'denied', needsAdmin: true, settings: { dumpEnabled: 0 } }), [bsodEvent(2)]),
      // Minidump che il registro eventi non riporta, con un codice ricorrente dopo arresti provocati.
      scanWith(data([dump({ code: '0x000000e2' }), dump({ code: '0x000000e2' }), dump({ code: '0x0000001a' }), dump({ code: '0x0000001a' })], { partial: true }), []),
    ];
    for (const s of scans) {
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
