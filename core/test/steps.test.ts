import { describe, expect, it } from 'vitest';
import { ACTIONS, analyze, asStep, DRIVER_PLACEHOLDER, renderText, stepCmd, stepLine, stepOpens, stepsFor, stepsText, stepText, stepVars, windowsMajor } from '../src/engine';
import type { Action, CrashDump, Scan } from '../src/engine';
import { clinicScan } from '../src/demo/clinic';
import { demoScan } from '../src/demo/sample';
import { readFileSync } from 'node:fs';
import { ACTION_APPS, ACTION_TOOLS, LOCATION_MARK, ROUTER_PANEL, TOOLS, WINDOWS_TOOLS } from '../src/tools';
import { CMD_HOW, CMD_HOW_ADMIN, planWinNote, privateIPv4, stepsKey, stepsSig, toolFor } from '../src/ui/plansteps';

// Passi guidati del piano: testo per la versione di Windows del PC, pagine da
// aprire solo dalla lista bianca, comandi da copiare, programmi utili per azione.

const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));

const sample: Action = {
  id: 'prova',
  title: 'Prova',
  why: 'perché',
  steps: [
    'Passo semplice.',
    { text: 'Impostazioni > Windows Update.', win10: 'Impostazioni > Aggiornamento e sicurezza > Windows Update.', open: 'windows-update' },
    { text: 'Solo su Windows 11.', only: 11, open: 'storage-recommendations' },
    { text: 'Nel Terminale:', cmd: 'chkdsk C: /scan', admin: true },
    { text: 'Nel pannello del router.', where: 'router', open: ROUTER_PANEL },
    { text: 'Di nuovo Windows Update.', open: 'windows-update' },
  ],
  check: 'Ripeti l\'analisi.',
  effort: 'facile',
  impact: 'alto',
};

describe('versione di Windows del PC', () => {
  it('dalla build, poi dal nome; Windows Server e rapporti senza PC: nessuna', () => {
    expect(windowsMajor(demoScan)).toBe(11);
    expect(windowsMajor(clinicScan)).toBe(10);
    const s = clone(demoScan) as Scan;
    s.pc!.os = { name: 'Windows 10 Pro', build: 19045 };
    expect(windowsMajor(s)).toBe(10);
    s.pc!.os = { name: 'Windows 11 Pro' };
    expect(windowsMajor(s)).toBe(11);
    s.pc!.os = { name: 'Windows Server 2025 Datacenter', build: 26100, server: true };
    expect(windowsMajor(s)).toBeUndefined();
    delete s.pc;
    expect(windowsMajor(s)).toBeUndefined();
    expect(windowsMajor(null)).toBeUndefined();
  });
});

describe('passi', () => {
  it('testo per la versione, entrambe le varianti quando la versione non è nota', () => {
    const s = sample.steps[1];
    expect(stepText(s, 11)).toBe('Impostazioni > Windows Update.');
    expect(stepText(s, 10)).toBe('Impostazioni > Aggiornamento e sicurezza > Windows Update.');
    expect(stepText(s)).toBe('Impostazioni > Windows Update. (Windows 10: Impostazioni > Aggiornamento e sicurezza > Windows Update.)');
    expect(stepText('Semplice.', 10)).toBe('Semplice.');
  });

  it('i passi di una sola versione si nascondono sull\'altra', () => {
    expect(stepsFor(sample, 11)).toHaveLength(6);
    expect(stepsFor(sample, 10).map((x) => x.text)).not.toContain('Solo su Windows 11.');
    expect(stepsFor(sample)).toHaveLength(6);
  });

  it('riga di testo con comando e avvertenze, per rapporto e documento', () => {
    expect(stepLine(sample.steps[3], 11)).toBe('Nel Terminale: Comando: chkdsk C: /scan [serve l\'amministratore]');
    expect(stepLine(sample.steps[4], 11)).toBe('Nel pannello del router. [sul router]');
    expect(stepLine(sample.steps[2])).toBe('Solo su Windows 11. [solo Windows 11]');
  });

  it('pagine aperte senza ripetizioni, testo completo per la ricerca', () => {
    expect(stepOpens(sample)).toEqual(['windows-update', 'storage-recommendations', ROUTER_PANEL]);
    expect(stepsText(sample)).toContain('Aggiornamento e sicurezza');
    expect(stepsText(sample)).toContain('chkdsk C: /scan');
    expect(stepsText(sample)).toContain('Ripeti l\'analisi.');
  });
});

describe('catalogo delle azioni', () => {
  const ids = new Set(WINDOWS_TOOLS.map((w) => w.id));

  it('ogni pagina da aprire è nella lista bianca (o è il pannello del router)', () => {
    for (const a of Object.values(ACTIONS)) {
      for (const raw of a.steps) {
        const s = asStep(raw);
        if (s.open) expect(s.open === ROUTER_PANEL || ids.has(s.open), `${a.id}: ${s.open}`).toBe(true);
        if (s.open === ROUTER_PANEL) expect(s.where, `${a.id}: il pannello del router è un passo sul router`).toBe('router');
        if (s.cmd) expect(s.cmd, `${a.id}: comando su una riga`).not.toMatch(/[\r\n]/);
        expect(s.text.trim().length, `${a.id}: passo vuoto`).toBeGreaterThan(0);
      }
    }
    for (const [action, tools] of Object.entries(ACTION_TOOLS)) {
      expect(ACTIONS[action], action).toBeDefined();
      for (const id of tools) expect(ids.has(id), `${action}: ${id}`).toBe(true);
    }
  });

  it('i programmi utili esistono, come le azioni a cui sono collegati', () => {
    for (const [action, apps] of Object.entries(ACTION_APPS)) {
      expect(ACTIONS[action], action).toBeDefined();
      expect(apps.length, action).toBeGreaterThan(0);
      for (const id of apps) expect(TOOLS.find((t) => t.id === id), `${action}: ${id}`).toBeDefined();
    }
    // Il pulsante "Vai alla sezione" porta solo a sezioni esistenti.
    for (const t of TOOLS) if (t.polarisView) expect(['pc', 'wifi', 'lan', 'internet', 'router', 'infra']).toContain(t.polarisView);
  });

  it('le pagine di una sola versione di Windows non si offrono sull\'altra', () => {
    expect(toolFor('storage-recommendations', 11)?.id).toBe('storage-recommendations');
    expect(toolFor('storage-recommendations', 10)).toBeUndefined();
    expect(toolFor('storage-recommendations')).toBeDefined();
    expect(toolFor(ROUTER_PANEL, 11)).toBeUndefined();
    expect(toolFor('cmd.exe', 11)).toBeUndefined();
  });

  it('le pagine solo per i passi non entrano nella cassetta degli attrezzi', () => {
    expect(WINDOWS_TOOLS.filter((w) => !w.stepOnly)).toHaveLength(16);
  });
});

// Due minidump letti con lo stesso driver indicato: abbastanza per il driver ricorrente.
function withDriver(driver: string): Scan {
  const s = clone(demoScan) as Scan;
  const dump = (i: number): CrashDump => ({
    file: `110826-1234-0${i}.dmp`,
    size: 1024,
    time: `2026-11-0${i}T10:00:00Z`,
    code: '0x000000d1',
    probable: { driver, method: 'param', param: 4 },
  });
  s.pc!.crashes = { readAt: '2026-11-08T10:00:00Z', folder: 'ok', total: 2, dumps: [dump(5), dump(6)] };
  return s;
}

describe('comandi da copiare', () => {
  const step = { text: 'Cerca il driver.', cmd: 'driverquery /v /fo csv | findstr /i {driver}' };

  it('il driver ricorrente delle schermate blu entra nel comando', () => {
    expect(stepVars(demoScan)).toEqual({ driver: 'acmewlan.sys' }); // la demo di casa ne ha uno
    const vars = stepVars(withDriver('nvlddmkm.sys'));
    expect(vars).toEqual({ driver: 'nvlddmkm.sys' });
    expect(stepCmd(step, vars)).toBe('driverquery /v /fo csv | findstr /i nvlddmkm.sys');
    expect(stepLine(step, 11, vars)).toBe('Cerca il driver. Comando: driverquery /v /fo csv | findstr /i nvlddmkm.sys');
    expect(stepLine(step, 11, vars, { cmd: false })).toBe('Cerca il driver.');
  });

  it('senza driver, o con un nome che potrebbe aggiungere comandi, resta il segnaposto', () => {
    const none = clone(demoScan) as Scan;
    delete none.pc!.crashes;
    expect(stepVars(none)).toEqual({});
    expect(stepVars(null)).toEqual({});
    expect(stepCmd(step)).toBe(`driverquery /v /fo csv | findstr /i ${DRIVER_PLACEHOLDER}`);
    for (const bad of ['x.sys & del /q *', 'a.sys|calc', 'a b.sys', '..\\evil.sys', 'nvlddmkm.exe', '"x.sys"', `${'a'.repeat(70)}.sys`]) {
      expect(stepVars(withDriver(bad)), bad).toEqual({});
    }
    expect(stepCmd('Passo senza comando.')).toBeUndefined();
  });

  it('il catalogo usa il segnaposto solo nel comando del driver', () => {
    for (const a of Object.values(ACTIONS))
      for (const raw of a.steps) {
        const s = asStep(raw);
        if (s.cmd?.includes('{')) expect(`${a.id}: ${s.cmd}`).toBe('update-crash-driver: driverquery /v /fo csv | findstr /i {driver}');
        expect(s.text, a.id).not.toContain('{driver}');
      }
  });

  it('come aprire il Prompt dei comandi, uguale su Windows 10 e 11', () => {
    expect(CMD_HOW).toContain('"cmd"');
    expect(CMD_HOW_ADMIN).toContain('"Esegui come amministratore"');
    expect(CMD_HOW_ADMIN).toContain('"Sì"');
  });
});

describe('nota sui nomi di Windows', () => {
  it('dice la versione del PC e quella dei nomi', () => {
    expect(planWinNote(11)).toContain('la versione di questo PC');
    expect(planWinNote(11, false)).toContain('la versione del PC analizzato'); // demo o rapporto importato
    expect(planWinNote(11)).toContain('Windows 11 24H2');
    expect(planWinNote(10)).toContain('Windows 10 22H2');
    expect(planWinNote()).toContain('24H2 e 22H2');
    for (const n of [planWinNote(10), planWinNote(11), planWinNote()]) expect(n).toContain('possono cambiare leggermente');
  });
});

describe('spunte dei passi', () => {
  it('una chiave per PC e per azione, e una firma che cambia con i passi', () => {
    expect(stepsKey('PC-1', 'update-windows')).toBe('polaris.steps.PC-1.update-windows');
    expect(stepsKey(undefined, 'update-windows')).toBe('polaris.steps.demo.update-windows');
    const a = ACTIONS['update-windows'];
    expect(stepsSig(a)).toBe(stepsSig(clone(a)));
    const b = clone(a);
    b.steps.splice(1, 0, 'Un passo nuovo.');
    expect(stepsSig(b)).not.toBe(stepsSig(a));
    // Azioni diverse, firme diverse.
    expect(new Set(Object.values(ACTIONS).map(stepsSig)).size).toBe(Object.keys(ACTIONS).length);
  });
});

describe('messaggio del permesso di posizione', () => {
  it('l\'agente usa ancora le parole che l\'interfaccia riconosce', () => {
    const go = readFileSync(new URL('../../windows/internal/winapi/hints.go', import.meta.url), 'utf8');
    const hint = /const LocationHint = "(.*)"\n/.exec(go)?.[1] ?? '';
    expect(hint).toContain(LOCATION_MARK);
  });
});

describe('pannello del router', () => {
  it('solo indirizzi IPv4 privati o link-local', () => {
    for (const ip of ['192.168.1.1', '10.0.0.138', '172.16.0.1', '172.31.255.254', '169.254.1.1']) expect(privateIPv4(ip), ip).toBe(true);
    for (const ip of [undefined, '', '8.8.8.8', '172.32.0.1', '100.64.0.1', 'fe80::1', '192.168.1.256', '192.168.1.1/24', 'http://192.168.1.1', ' 192.168.1.1', '010.0.0.1', '192.168.01.1', '0.0.0.0'])
      expect(privateIPv4(ip), String(ip)).toBe(false);
    expect(privateIPv4('10.0.0.0')).toBe(true);
  });
});

describe('rapporto di testo', () => {
  it('i passi seguono la versione di Windows del PC', () => {
    const home = renderText(demoScan, analyze(demoScan), { verbose: true });
    expect(home).toContain('I passi seguono i menu di Windows 11, la versione del PC analizzato.');
    const clinic = renderText(clinicScan, analyze(clinicScan), { verbose: true });
    expect(clinic).toContain('I passi seguono i menu di Windows 10, la versione del PC analizzato.');
    expect(home).not.toContain('[object Object]');
    expect(clinic).not.toContain('[object Object]');
    expect(home).toContain('Windows 11 24H2');
    expect(clinic).toContain('Windows 10 22H2');
  });

  it('nel rapporto il comando del driver ha già il nome del file', () => {
    const s = withDriver('nvlddmkm.sys');
    const text = renderText(s, analyze(s), { verbose: true });
    expect(text).toContain('Prompt dei comandi');
    // Il comando su una riga sua, intero: si copia dal file così com'è.
    expect(text.split('\n')).toContain('             driverquery /v /fo csv | findstr /i nvlddmkm.sys');
    expect(text).not.toContain('Comando:');
    expect(text).not.toContain('{driver}');
  });
});
