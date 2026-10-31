import { describe, expect, it } from 'vitest';
import { demoScan } from '../src/demo/sample';
import { clinicScan } from '../src/demo/clinic';
import type { SpaceReport } from '../src/engine';
import { driveParts, sameSpaceTarget, seconds, spaceNotes } from '../src/ui/space';

// Funzioni pure della scheda "Cosa occupa spazio".

const base: SpaceReport = {
  root: 'C:\\',
  drive: 'C:',
  totalBytes: 500e9,
  freeBytes: 100e9,
  allocBytes: 120e9,
  sizeBytes: 120e9,
  files: 1000,
  dirs: 100,
  startedAt: '2026-10-30T10:00:00Z',
  durationMs: 5000,
};

describe('durata dell\'analisi', () => {
  it('non scrive mai 60 secondi', () => {
    expect(seconds(400)).toBe('meno di un secondo');
    expect(seconds(119_400)).toBe('119 s');
    expect(seconds(119_600)).toBe('2 min 0 s');
    expect(seconds(179_600)).toBe('3 min 0 s');
    expect(seconds(239_999)).toBe('4 min 0 s');
    expect(seconds(185_000)).toBe('3 min 5 s');
  });
});

describe('a quale rapporto va un\'analisi', () => {
  it('reale: solo ai dati dell\'agente dello stesso PC', () => {
    const t = { host: demoScan.agent.host, live: true };
    expect(sameSpaceTarget(t, demoScan, 'agent')).toBe(true);
    expect(sameSpaceTarget(t, demoScan, 'file')).toBe(false);
    expect(sameSpaceTarget(t, demoScan, 'demo')).toBe(false);
    expect(sameSpaceTarget(t, clinicScan, 'agent')).toBe(false);
  });
  it('simulata: solo alla stessa demo', () => {
    const t = { host: demoScan.agent.host, live: false };
    expect(sameSpaceTarget(t, demoScan, 'demo')).toBe(true);
    expect(sameSpaceTarget(t, clinicScan, 'demo')).toBe(false);
    expect(sameSpaceTarget(t, demoScan, 'file')).toBe(false);
    expect(sameSpaceTarget(undefined, demoScan, 'demo')).toBe(false);
    expect(sameSpaceTarget(t, null, 'demo')).toBe(false);
  });
});

describe('barra dell\'unità', () => {
  it('in un\'analisi interrotta lo spazio non letto non sembra libero', () => {
    const parts = driveParts({ ...base, partial: true }, 0);
    expect(parts.map((p) => p.k)).toEqual(['files', 'unread', 'free']);
    expect(parts.find((p) => p.k === 'unread')!.v).toBe(280e9);
    // Le parti coprono tutta l'unità.
    expect(parts.reduce((s, p) => s + p.v, 0)).toBe(base.totalBytes);
  });
  it('in un\'analisi completa non c\'è la parte non letta', () => {
    expect(driveParts(base, 280e9).map((p) => p.k)).toEqual(['files', 'other', 'free']);
  });
});

describe('note sotto la barra', () => {
  const texts = (r: SpaceReport, elevated?: boolean) => spaceNotes(r, 0, r.totalBytes - r.freeBytes, elevated).map((n) => n.text);
  it('consiglia l\'amministratore solo se Polaris non lo è', () => {
    const r = { ...base, denied: 3, deniedPaths: ['C:\\System Volume Information'] };
    expect(texts(r, false)[0]).toMatch(/come amministratore/);
    expect(texts(r, true)[0]).toMatch(/riservate al sistema/);
    expect(texts(r, true)[0]).not.toMatch(/amministratore/);
    expect(texts(r)[0]).not.toMatch(/amministratore/);
  });
  it('conta a parte le cartelle non lette per errori del disco', () => {
    expect(texts({ ...base, errors: 1 }, false)).toEqual(['1 cartella non letta per errori del disco o del file system.']);
    const many = texts({ ...base, errors: 1234 }, false);
    expect(many).toEqual(['1.234 cartelle non lette per errori del disco o del file system.']);
    expect(many[0]).not.toMatch(/amministratore/);
  });
});
