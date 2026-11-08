import { describe, expect, it } from 'vitest';
import { ACTIONS, analyze, asStep, renderText, stepLine, stepOpens, stepsFor, stepsText, stepText, windowsMajor } from '../src/engine';
import type { Action, Scan } from '../src/engine';
import { clinicScan } from '../src/demo/clinic';
import { demoScan } from '../src/demo/sample';
import { ACTION_APPS, ACTION_TOOLS, ROUTER_PANEL, TOOLS, WINDOWS_TOOLS } from '../src/tools';
import { privateIPv4, toolFor } from '../src/ui/plansteps';

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

describe('pannello del router', () => {
  it('solo indirizzi IPv4 privati o link-local', () => {
    for (const ip of ['192.168.1.1', '10.0.0.138', '172.16.0.1', '172.31.255.254', '169.254.1.1']) expect(privateIPv4(ip), ip).toBe(true);
    for (const ip of [undefined, '', '8.8.8.8', '172.32.0.1', '100.64.0.1', 'fe80::1', '192.168.1.256', '192.168.1.1/24', 'http://192.168.1.1', ' 192.168.1.1']) expect(privateIPv4(ip), String(ip)).toBe(false);
  });
});

describe('rapporto di testo', () => {
  it('i passi seguono la versione di Windows del PC', () => {
    const home = renderText(demoScan, analyze(demoScan), { verbose: true });
    expect(home).toContain('I passi seguono i menu di Windows 11, la versione di questo PC.');
    const clinic = renderText(clinicScan, analyze(clinicScan), { verbose: true });
    expect(clinic).toContain('I passi seguono i menu di Windows 10, la versione di questo PC.');
    expect(home).not.toContain('[object Object]');
    expect(clinic).not.toContain('[object Object]');
  });
});
