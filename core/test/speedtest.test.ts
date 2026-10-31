import { build } from 'esbuild';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { describe, expect, it } from 'vitest';
import {
  ACTIONS,
  analyze,
  bloatSeverity,
  documentParts,
  mbpsText,
  METRICS,
  renderText,
  SPEED_BLOAT_CRIT_MS,
  SPEED_BLOAT_WARN_MS,
  speedBloat,
  speedDocRows,
  speedErr,
  speedLoadedText,
  speedValue,
  speedWhere,
  waitLabel,
} from '../src/engine';
import type { Finding, Scan, SpeedTest } from '../src/engine';
import { clinicScan } from '../src/demo/clinic';
import { demoScan } from '../src/demo/sample';
import { simulatedSpeed } from '../src/demo/simulate';
import { AUP_URL, CONSENT_CHECK, CONSENT_TEXT, dayLimitReached, PHASES, PRIVACY_URL, sameSpeedTarget, speedFitsScan, waitText } from '../src/ui/speedtest';
import { GLOSSARY, guideById, guidesForMetric } from '../src/guides';

// Test di velocità di Internet con M-Lab: giudizi e soglie del motore,
// unione al rapporto giusto, demo, documento e rapporto senza indirizzi,
// testo del consenso uguale a quello dell'agente.

const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));

/** Risultato tipico: fibra, cavo, coda contenuta in download e alta in upload. */
const base: SpeedTest = {
  startedAt: '2026-10-31T09:10:00Z',
  durationMs: 27800,
  provider: 'mlab-ndt7',
  server: { city: 'Milan', country: 'IT', site: 'mil05', machine: 'mlab1-mil05.mlab-oti.measurement-lab.org' },
  probe: '1.1.1.1',
  probeMethod: 'icmp',
  idle: { sent: 20, received: 20, minMs: 9.1, medianMs: 10.4, p95Ms: 12.2 },
  download: {
    mbps: 245.3,
    bytes: 306_600_000,
    ms: 10000,
    source: 'client',
    minRttMs: 9.2,
    rttMs: 14.6,
    retransPct: 0.8,
    latency: { sent: 40, received: 40, medianMs: 22.4, p95Ms: 31 },
    bloatMs: 12,
    bloatP95Ms: 20.6,
  },
  upload: {
    mbps: 48.2,
    bytes: 60_250_000,
    ms: 10000,
    source: 'server',
    latency: { sent: 40, received: 39, medianMs: 92.4, p95Ms: 140 },
    bloatMs: 82,
    bloatP95Ms: 129.6,
  },
};
const speed = (patch: Partial<SpeedTest>): SpeedTest => ({ ...clone(base), ...patch });

function scanWith(r: SpeedTest | undefined, kind: 'ethernet' | 'wifi' = 'ethernet', linkMbps?: number): Scan {
  return {
    schema: 1,
    agent: { name: 'STARNET Polaris', version: 'test', platform: 'windows', host: 'PC-01', startedAt: '2026-10-31T09:00:00Z', durationMs: 1000 },
    adapters: [{ name: 'Rete', kind, up: true, ipv4: ['192.168.1.20/24'], ipv6: [], gateways: ['192.168.1.1'], dns: ['192.168.1.1'], ...(linkMbps ? { linkMbps } : {}) }],
    gateway: { ip: '192.168.1.1' },
    internet: { targets: [], ...(r ? { speed: r } : {}) },
    errors: [],
  };
}
const findings = (s: Scan) => analyze(s).findings.filter((f) => f.id.startsWith('net.speed') || f.id === 'net.bufferbloat');
const byId = (fs: Finding[], id: string) => fs.find((f) => f.id === id);

describe('soglie del bufferbloat (P)', () => {
  it('sotto 30 ms va bene, fino a 100 è da migliorare, oltre è alto', () => {
    expect(SPEED_BLOAT_WARN_MS).toBe(30);
    expect(SPEED_BLOAT_CRIT_MS).toBe(100);
    expect(bloatSeverity(0)).toBe('ok');
    expect(bloatSeverity(29.9)).toBe('ok');
    expect(bloatSeverity(30)).toBe('warn');
    expect(bloatSeverity(100)).toBe('warn');
    expect(bloatSeverity(100.1)).toBe('crit');
  });

  it('decide il verso peggiore e conta le sonde perse', () => {
    const b = speedBloat(base);
    expect(b).toMatchObject({ worst: 82, worstP95: 129.6, dir: 'upload', severity: 'warn', lost: 1, sent: 80 });
    expect(speedBloat(speed({ download: undefined, upload: undefined })).severity).toBe('unknown');
  });

  it('la knowledge base dichiara le soglie come scelte di Polaris', () => {
    const m = METRICS['net.bufferbloat'];
    expect(m.scale?.map((s) => s.severity)).toEqual(['ok', 'warn', 'crit']);
    expect(m.scale?.map((s) => s.range).join(' ')).toMatch(/30 ms.*\(P\).*30 a 100 ms.*\(P\).*100 ms.*\(P\)/);
    expect(m.limits).toContain('scelta di Polaris');
    expect(m.limits).toContain('da verificare');
    // Nessuna affermazione senza fonte sulla percezione dei 30 ms: è una scelta.
    expect(m.limits).toContain('30 ms è una soglia prudente scelta da Polaris');
    expect(m.limits).not.toContain('variazione che si nota');
    // Le sonde senza risposta durante i trasferimenti sono spiegate come sono contate.
    expect(m.limits).toContain('almeno un secondo');
    expect(m.limits).not.toContain('non entrano nella mediana');
    expect(METRICS['net.speed.retrans'].limits).toContain('scelta di Polaris');
    expect(METRICS['net.speed'].scale?.[0].severity).toBe('info');
    expect(METRICS['net.speed'].limits).toContain('Ne.Me.Sys.');
  });
});

describe('giudizi del motore', () => {
  it('la velocità è solo un\'informazione, con il confronto con il contratto e la misura AGCOM', () => {
    const fs = findings(scanWith(base));
    const s = byId(fs, 'net.speed')!;
    expect(s).toMatchObject({ severity: 'info', category: 'internet', value: 'download 245 · upload 48,2 Mbit/s', numeric: 245.3, actions: ['speed-compare-contract'] });
    expect(s.verdict).toContain('Milano (mil05)');
    expect(s.verdict).toContain('una sola connessione per verso: 245 Mbit/s in download e 48,2 Mbit/s in upload.');
    expect(s.verdict).toContain('non conosce la velocità del tuo contratto');
    expect(s.verdict).toContain('Ne.Me.Sys.');
    expect(s.verdict).toContain('misurainternet.it');
    // Anche una velocità molto bassa resta un'informazione: Polaris non conosce il contratto.
    const slow = byId(findings(scanWith(speed({ download: { ...base.download!, mbps: 1.2 } }))), 'net.speed')!;
    expect(slow.severity).toBe('info');
    expect(slow.value).toBe('download 1,20 · upload 48,2 Mbit/s');
  });

  it('bufferbloat: gravità, azioni e verso peggiore', () => {
    const warn = byId(findings(scanWith(base)), 'net.bufferbloat')!;
    expect(warn).toMatchObject({ severity: 'warn', value: '+12 ms in download · +82 ms in upload', numeric: 82, actions: ['enable-sqm', 'reduce-load'] });
    expect(warn.verdict).toContain('in upload');
    expect(warn.verdict).toContain('10 ms a riposo');
    const ok = byId(findings(scanWith(speed({ upload: { ...base.upload!, bloatMs: 18, bloatP95Ms: 25 } }))), 'net.bufferbloat')!;
    expect(ok).toMatchObject({ severity: 'ok', actions: [] });
    const crit = byId(findings(scanWith(speed({ upload: { ...base.upload!, bloatMs: 240, bloatP95Ms: 410, latency: { sent: 40, received: 30, medianMs: 250 } } }))), 'net.bufferbloat')!;
    expect(crit.severity).toBe('crit');
    expect(crit.verdict).toContain('si spezzano');
    expect(crit.verdict).toContain('10 sonde su 80');
    // Senza latenza a riposo non si calcola.
    expect(byId(findings(scanWith(speed({ idle: undefined }))), 'net.bufferbloat')).toBeUndefined();
  });

  it('Wi-Fi, proxy, linee molto veloci e scheda a 100 Mbit/s sono detti nel giudizio', () => {
    const wifi = findings(scanWith(base, 'wifi'));
    expect(byId(wifi, 'net.speed')!.actions).toEqual(['speed-compare-contract', 'speed-test-cable']);
    expect(byId(wifi, 'net.speed')!.verdict).toContain('collegato in Wi-Fi');
    expect(byId(wifi, 'net.bufferbloat')!.actions).toContain('speed-test-cable');
    expect(byId(findings(scanWith(speed({ viaProxy: true }))), 'net.speed')!.verdict).toContain('attraverso il proxy');
    const fast = byId(findings(scanWith(speed({ download: { ...base.download!, mbps: 2210 } }))), 'net.speed')!;
    expect(fast.verdict).toContain('da 2,5 a 10 Gbit/s');
    expect(fast.value).toBe('download 2,21 Gbit/s · upload 48,2 Mbit/s');
    const capped = byId(findings(scanWith(speed({ download: { ...base.download!, mbps: 93.8 } }), 'ethernet', 100)), 'net.speed')!;
    expect(capped.verdict).toContain('collegata a 100 Mbit/s');
  });

  it('ritrasmissioni alte: solo informazione', () => {
    expect(byId(findings(scanWith(base)), 'net.speed.retrans')).toBeUndefined();
    const r = byId(findings(scanWith(speed({ download: { ...base.download!, retransPct: 6.3 } }))), 'net.speed.retrans')!;
    expect(r).toMatchObject({ severity: 'info', value: '6,3 %', actions: [] });
  });

  it('download non riuscito: non misurata, senza indirizzi nel messaggio', () => {
    const f = byId(findings(scanWith(speed({ download: { mbps: 0, bytes: 0, ms: 0, error: 'dial tcp 203.0.113.9:443: connessione rifiutata' }, upload: undefined }))), 'net.speed')!;
    expect(f.severity).toBe('unknown');
    expect(f.verdict).not.toContain('203.0.113.9');
    expect(f.verdict).toContain('[indirizzo]');
    expect(speedErr('upload non riuscito: [2001:db8::1]:443 non risponde')).toBe('[indirizzo] non risponde');
  });

  it('upload non riuscito: il download resta', () => {
    const f = byId(findings(scanWith(speed({ upload: { mbps: 0, bytes: 0, ms: 0, error: 'upload non riuscito: connessione interrotta' } }))), 'net.speed')!;
    expect(f.value).toBe('download 245 Mbit/s');
    expect(f.verdict).toContain('Upload non misurato: connessione interrotta.');
  });

  it('ogni azione e metrica usata esiste, ed è spiegata in una guida', () => {
    for (const id of ['speed-compare-contract', 'speed-test-cable', 'enable-sqm']) expect(ACTIONS[id], id).toBeDefined();
    for (const m of ['net.speed', 'net.bufferbloat', 'net.speed.retrans']) expect(guidesForMetric(m).map((g) => g.id)).toContain('velocita-internet');
    expect(ACTIONS['speed-compare-contract'].steps.join(' ')).toContain('non è una consulenza legale');
  });

  it('formati', () => {
    expect(mbpsText(3.456)).toBe('3,46 Mbit/s');
    expect(mbpsText(48.24)).toBe('48,2 Mbit/s');
    expect(mbpsText(940.4)).toBe('940 Mbit/s');
    expect(mbpsText(1240)).toBe('1,24 Gbit/s');
    expect(speedWhere({ city: 'Paris', country: 'FR', site: 'par05' })).toBe('Parigi, Francia (par05)');
    expect(speedWhere({ site: 'xyz01' })).toBe('server di M-Lab xyz01');
    expect(speedWhere(undefined)).toBe('server di M-Lab');
    expect(speedValue(speed({ download: undefined }))).toBe('non misurata');
  });
});

describe('unione al rapporto (come addCerts)', () => {
  it('solo sullo stesso PC, nella stessa rete e con la stessa origine', () => {
    const s = scanWith(undefined);
    const t = { live: true, host: 'PC-01', gateway: '192.168.1.1' };
    expect(sameSpeedTarget(t, s, 'agent')).toBe(true);
    expect(sameSpeedTarget(t, s, 'demo')).toBe(false);
    expect(sameSpeedTarget(t, s, 'file')).toBe(false);
    expect(sameSpeedTarget({ ...t, live: false }, s, 'demo')).toBe(true);
    expect(sameSpeedTarget({ ...t, gateway: '10.0.0.1' }, s, 'agent')).toBe(false);
    expect(sameSpeedTarget({ ...t, host: 'PC-02' }, s, 'agent')).toBe(false);
    expect(sameSpeedTarget(undefined, s, 'agent')).toBe(false);
    expect(sameSpeedTarget(t, null, 'agent')).toBe(false);
    // Le demo non si scambiano i risultati.
    const home = { live: false, host: demoScan.agent.host, gateway: demoScan.gateway?.ip };
    expect(sameSpeedTarget(home, demoScan, 'demo')).toBe(true);
    expect(sameSpeedTarget(home, clinicScan, 'demo')).toBe(false);
  });

  it('l\'ultimo test dell\'agente si recupera solo in un rapporto più vecchio del test', () => {
    // Analisi B fatta alle 21 (dopo un cambio di rete), test fatto alle 10 sulla rete A.
    const b = scanWith(undefined);
    b.agent.startedAt = '2026-10-31T21:00:00Z';
    expect(speedFitsScan(speed({ startedAt: '2026-10-31T10:00:00Z' }), b)).toBe(false);
    expect(speedFitsScan(speed({ startedAt: '2026-10-31T21:05:00Z' }), b)).toBe(true);
    expect(speedFitsScan(speed({ startedAt: '2026-10-31T21:00:00Z' }), b)).toBe(true);
    expect(speedFitsScan(speed({ startedAt: 'non è una data' }), b)).toBe(false);
  });

  it('il limite di oggi vale solo nel giorno in cui l\'agente l\'ha detto', () => {
    const now = Date.parse('2026-10-31T15:00:00');
    const today = new Date(now).toDateString();
    expect(dayLimitReached(0, today, now)).toBe(true);
    expect(dayLimitReached(1, today, now)).toBe(false);
    expect(dayLimitReached(undefined, today, now)).toBe(false);
    expect(dayLimitReached(0, today, Date.parse('2026-11-01T00:01:00'))).toBe(false);
  });
});

describe('sonde senza risposta durante i trasferimenti', () => {
  // ADSL o FTTC con l'upload pieno: coda oltre il secondo, nessuna sonda
  // risponde durante l'upload mentre a riposo rispondevano tutte.
  const lostUp = (agent: boolean): SpeedTest =>
    speed({
      probeTimeoutMs: 1000,
      download: { ...base.download!, latency: { sent: 40, received: 40, medianMs: 25.4, p95Ms: 31 }, bloatMs: 15, bloatP95Ms: 20.6 },
      upload: agent
        ? { ...base.upload!, latency: { sent: 20, received: 0, medianMs: 1000, p95Ms: 1000, medianAtLeast: true, p95AtLeast: true }, bloatMs: 989.6, bloatP95Ms: 989.6 }
        : { ...base.upload!, latency: { sent: 12, received: 0 }, bloatMs: undefined, bloatP95Ms: undefined },
    });

  it('come le conta l\'agente: giudizio alto con un valore minimo, mai "contenuta"', () => {
    const f = byId(findings(scanWith(lostUp(true))), 'net.bufferbloat')!;
    expect(f).toMatchObject({ severity: 'crit', value: '+15 ms in download · almeno +990 ms in upload', actions: ['enable-sqm', 'reduce-load'] });
    expect(f.verdict).toContain('la maggior parte delle sonde in upload non ha avuto risposta entro 1 s');
    expect(f.verdict).toContain('almeno 990 ms');
    expect(f.verdict).not.toContain('reggono');
    expect(speedBloat(lostUp(true))).toMatchObject({ severity: 'crit', atLeast: true, dir: 'upload', lost: 20, sent: 60 });
    expect(speedLoadedText(lostUp(true), lostUp(true).upload)).toBe('almeno 1000 ms (almeno +990 ms; 95° percentile almeno +990 ms), 20 sonde su 20 senza risposta entro 1 s');
  });

  it('dati senza mediana sotto carico: il motore ricava lo stesso minimo', () => {
    const r = lostUp(false);
    const f = byId(findings(scanWith(r)), 'net.bufferbloat')!;
    expect(f).toMatchObject({ severity: 'crit', value: '+15 ms in download · almeno +990 ms in upload' });
    expect(speedLoadedText(r, r.upload)).toBe('12 sonde su 12 senza risposta entro 1 s: almeno +990 ms rispetto al riposo');
    // Anche con tutte le sonde perse in entrambi i versi c'è un giudizio.
    const both = speed({
      download: { ...base.download!, latency: { sent: 20, received: 1 }, bloatMs: undefined, bloatP95Ms: undefined },
      upload: { ...base.upload!, latency: { sent: 12, received: 0 }, bloatMs: undefined, bloatP95Ms: undefined },
    });
    expect(byId(findings(scanWith(both)), 'net.bufferbloat')).toMatchObject({ severity: 'crit', value: 'almeno +990 ms in download · almeno +990 ms in upload' });
    // Senza latenza a riposo non si può dire che cosa sia una sonda persa.
    expect(byId(findings(scanWith({ ...r, idle: { sent: 20, received: 0 } })), 'net.bufferbloat')).toBeUndefined();
  });

  it('nel rapporto di testo e nel documento con il conteggio delle sonde', () => {
    const s = scanWith(lostUp(false));
    const txt = renderText(s, analyze(s), { verbose: true });
    // Le righe vanno a capo a 90 colonne: si confronta il testo con gli spazi uniti.
    const flat = txt.replace(/\s+/g, ' ');
    expect(flat).toContain('Latenza sotto carico: alta, almeno +990 ms in upload');
    expect(flat).toContain('latenza 12 sonde su 12 senza risposta entro 1 s: almeno +990 ms rispetto al riposo');
    expect(flat).not.toContain('Latenza sotto carico: contenuta');
    expect(flat).not.toContain('la latenza resta contenuta');
    const rows = speedDocRows(lostUp(false));
    expect(rows.find(([k]) => k === 'Latenza sotto carico')![1]).toBe(
      'download: 25 ms (+15 ms; 95° percentile +21 ms); upload: 12 sonde su 12 senza risposta entro 1 s: almeno +990 ms rispetto al riposo',
    );
    const { body } = documentParts(s, analyze(s), { version: '0.10.0', generated: 'oggi' });
    expect(body).toContain('almeno +990 ms rispetto al riposo');
  });

  it('oltre il 10 % di sonde senza risposta (P) il giudizio è almeno da migliorare', () => {
    const r = speed({
      download: { ...base.download!, latency: { sent: 40, received: 30, medianMs: 22.4, p95Ms: 1000, p95AtLeast: true }, bloatMs: 12, bloatP95Ms: 989.6 },
      upload: { ...base.upload!, latency: { sent: 40, received: 40, medianMs: 28.4, p95Ms: 35 }, bloatMs: 18, bloatP95Ms: 24.6 },
    });
    const f = byId(findings(scanWith(r)), 'net.bufferbloat')!;
    expect(f.severity).toBe('warn');
    expect(f.verdict).toContain('10 sonde su 80 non hanno avuto risposta entro 1 s');
    expect(f.verdict).toContain('picchi di coda oltre 1 s');
    expect(f.verdict).not.toContain('reggono');
    // Se se ne perdevano altrettante a riposo sono perdite sulla linea, non coda.
    const lossy = { ...r, idle: { sent: 20, received: 15, medianMs: 10.4 } };
    const g = byId(findings(scanWith(lossy)), 'net.bufferbloat')!;
    expect(g.severity).toBe('ok');
    expect(g.verdict).toContain('se ne perdevano anche a riposo');
  });

  it('attesa delle sonde', () => {
    expect(waitLabel(1000)).toBe('1 s');
    expect(waitLabel(1500)).toBe('1,5 s');
    expect(waitLabel(800)).toBe('800 ms');
  });
});

describe('upload su un altro server', () => {
  it('il risultato dice dove è stato misurato l\'upload', () => {
    const r = speed({ upload: { ...base.upload!, server: { city: 'Turin', country: 'IT', site: 'trn02' } } });
    const s = scanWith(r);
    expect(byId(findings(s), 'net.speed')!.verdict).toContain('L\'upload è stato misurato su un altro server: Torino (trn02), perché M-Lab non proponeva più quello del download.');
    expect(renderText(s, analyze(s), { verbose: true })).toContain('Upload: su un altro server di M-Lab, Torino (trn02)');
    expect(speedDocRows(r).find(([k]) => k === 'Server')![1]).toBe('M-Lab, Milano (mil05); upload: Torino (trn02)');
    expect(speedDocRows(base).find(([k]) => k === 'Server')![1]).toBe('M-Lab, Milano (mil05)');
  });
});

describe('demo', () => {
  it('casa: Wi-Fi, coda alta in upload; clinica: sonde TCP, coda da migliorare', () => {
    const home = simulatedSpeed(demoScan, Date.parse('2026-10-31T10:00:00Z'));
    expect(home).toMatchObject({ simulated: true, provider: 'mlab-ndt7', probeMethod: 'icmp', startedAt: '2026-10-31T10:00:00.000Z' });
    const hs = clone(demoScan);
    hs.internet = { ...hs.internet!, speed: home };
    const hf = analyze(hs).findings;
    expect(byId(hf, 'net.bufferbloat')!.severity).toBe('crit');
    expect(byId(hf, 'net.speed')!.title).toContain('(simulazione)');
    expect(byId(hf, 'net.speed')!.verdict).toContain('Wi-Fi');

    const clinic = simulatedSpeed(clinicScan);
    expect(clinic.probeMethod).toBe('tcp');
    const cs = clone(clinicScan);
    cs.internet = { ...cs.internet!, speed: clinic };
    expect(byId(analyze(cs).findings, 'net.bufferbloat')!.severity).toBe('warn');
    // Il Wi-Fi della clinica fa da limite: la velocità resta sotto il collegamento.
    const link = clinicScan.adapters.find((a) => a.up)!.linkMbps!;
    expect(clinic.download!.mbps).toBeLessThan(link);
  });

  it('i dati delle demo non contengono già un test (lo si simula a richiesta)', () => {
    expect(demoScan.internet?.speed).toBeUndefined();
    expect(clinicScan.internet?.speed).toBeUndefined();
  });
});

describe('documento e rapporto senza indirizzi', () => {
  const s = scanWith(speed({ download: { ...base.download!, error: 'trasferimento interrotto (dial tcp 198.51.100.4:443)' } }));
  const a = analyze(s);

  it('il documento stampabile ha la sezione, la nota legale e nessun IP pubblico', () => {
    const { body } = documentParts(s, a, { version: '0.10.0', generated: 'oggi' });
    expect(body).toContain('<h2>Velocità di Internet</h2>');
    expect(body).toContain('245 Mbit/s');
    expect(body).toContain('M-Lab, Milano (mil05)');
    expect(body).toContain('Ne.Me.Sys.');
    expect(body).not.toContain('198.51.100.4');
    expect(body).not.toMatch(/\b(?!1\.1\.1\.1)(\d{1,3}\.){3}\d{1,3}\b(?<!192\.168\.1\.\d+)/);
  });

  it('il rapporto di testo riporta misure, server e nota legale entro 90 colonne', () => {
    const txt = renderText(s, a, { verbose: true });
    expect(txt).toContain(' TEST DI VELOCITÀ DI INTERNET (M-LAB)');
    expect(txt).toContain('Server M-Lab: Milano (mil05)');
    expect(txt).toContain('Download: 245 Mbit/s, 307 MB in 10,0 s; latenza 22 ms (+12 ms');
    expect(txt).toContain('Latenza sotto carico: da migliorare, +82 ms in upload (soglie di Polaris');
    expect(txt).toContain('valore legale');
    expect(txt).not.toContain('198.51.100.4');
    for (const line of txt.split('\n')) expect(line.length, line).toBeLessThanOrEqual(90);
  });

  it('il motore della riga di comando (ES2015, goja) dà gli stessi giudizi, documento e rapporto', async () => {
    const entry = fileURLToPath(new URL('../src/engine/global.ts', import.meta.url));
    const out = await build({ entryPoints: [entry], bundle: true, format: 'iife', target: 'es2015', write: false });
    const ctx: Record<string, unknown> = {};
    ctx.globalThis = ctx;
    vm.createContext(ctx);
    vm.runInContext(out.outputFiles[0].text, ctx);
    const engine = ctx.PolarisEngine as { analyzeJson(s: string): string; reportText(s: string, v: boolean): string; reportHtml(s: string, v: string, g: string): string };
    const hs = clone(demoScan);
    hs.internet = { ...hs.internet!, speed: simulatedSpeed(demoScan, Date.parse('2026-10-31T10:00:00Z')) };
    const json = JSON.stringify(hs);
    expect(JSON.parse(engine.analyzeJson(json))).toEqual(JSON.parse(JSON.stringify(analyze(hs))));
    expect(engine.reportText(json, true)).toBe(renderText(hs, analyze(hs), { verbose: true }));
    expect(engine.reportHtml(json, '0.10.0', 'oggi')).toContain('<h2>Velocità di Internet</h2>');
    // Sonde senza risposta in upload (con e senza i valori minimi dell'agente) e upload su un altro server.
    for (const up of [
      { ...base.upload!, latency: { sent: 20, received: 0, medianMs: 1000, p95Ms: 1000, medianAtLeast: true, p95AtLeast: true }, bloatMs: 989.6, bloatP95Ms: 989.6 },
      { ...base.upload!, latency: { sent: 12, received: 0 }, bloatMs: undefined, bloatP95Ms: undefined, server: { city: 'Turin', country: 'IT', site: 'trn02' } },
    ]) {
      const ls = scanWith(speed({ probeTimeoutMs: 1000, upload: up }));
      const lj = JSON.stringify(ls);
      const la = JSON.parse(engine.analyzeJson(lj)) as { findings: Finding[] };
      expect(la).toEqual(JSON.parse(JSON.stringify(analyze(ls))));
      expect(la.findings.find((f) => f.id === 'net.bufferbloat')!.severity).toBe('crit');
      expect(engine.reportText(lj, true)).toBe(renderText(ls, analyze(ls), { verbose: true }));
    }
  });
});

describe('consenso', () => {
  it('ha lo stesso testo nell\'interfaccia e nell\'agente', () => {
    const go = readFileSync(fileURLToPath(new URL('../../windows/internal/speedtest/consent.go', import.meta.url)), 'utf8')
      .replace(/" \+ PrivacyURL \+ "/g, PRIVACY_URL)
      .replace(/" \+ AUPURL \+ "/g, AUP_URL);
    const block = /var ConsentText = \[\]string\{([\s\S]*?)\n\}/.exec(go)![1];
    const paras = [...block.matchAll(/^\s*"((?:[^"\\]|\\.)*)",$/gm)].map((m) => JSON.parse(`"${m[1]}"`) as string);
    expect(paras).toEqual(CONSENT_TEXT);
    expect(go).toContain(`ConsentCheck = "${CONSENT_CHECK}"`);
  });

  it('dice che cosa pubblica M-Lab, per quanto, e collega informativa e regole d\'uso', () => {
    const all = CONSENT_TEXT.join(' ');
    for (const k of ['Measurement Lab (M-Lab)', 'indirizzo IP pubblico', 'per sempre', '250 MB', 'connessioni a consumo', 'IP fisso', '16 anni', PRIVACY_URL, AUP_URL])
      expect(all, k).toContain(k);
    expect(CONSENT_CHECK).toContain('mio indirizzo IP');
  });

  it('fasi e attesa', () => {
    expect(PHASES.map((p) => p.id)).toEqual(['locate', 'idle', 'download', 'upload']);
    expect(waitText(45)).toBe('45 s');
    expect(waitText(80)).toBe('1 min 20 s');
    expect(waitText(120)).toBe('2 min');
  });
});

describe('guida e glossario', () => {
  it('la guida spiega misura, limiti, M-Lab e AGCOM', () => {
    const g = guideById('velocita-internet')!;
    expect(g.chapter).toBe('diagnosi');
    expect(g.actions).toEqual(expect.arrayContaining(['speed-compare-contract', 'speed-test-cable', 'enable-sqm']));
    const text = JSON.stringify(g.blocks);
    for (const k of ['Goodput', 'bufferbloat', 'una sola connessione', 'Wi-Fi', 'proxy', 'M-Lab', 'per sempre', 'Ne.Me.Sys.', 'SPID', '24 ore', '(P)', 'da verificare', 'non è una consulenza legale'])
      expect(text, k).toContain(k);
  });

  it('il glossario ha i termini nuovi', () => {
    for (const t of ['Goodput', 'M-Lab', 'Ne.Me.Sys.', 'Latenza sotto carico', 'ndt7', 'SQM', 'Bufferbloat']) expect(GLOSSARY.some((x) => x.term === t), t).toBe(true);
  });
});
