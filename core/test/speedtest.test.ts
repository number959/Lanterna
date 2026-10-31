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
  speedErr,
  speedValue,
  speedWhere,
} from '../src/engine';
import type { Finding, Scan, SpeedTest } from '../src/engine';
import { clinicScan } from '../src/demo/clinic';
import { demoScan } from '../src/demo/sample';
import { simulatedSpeed } from '../src/demo/simulate';
import { AUP_URL, CONSENT_CHECK, CONSENT_TEXT, PHASES, PRIVACY_URL, sameSpeedTarget, waitText } from '../src/ui/speedtest';
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
    expect(txt).toContain('Latenza sotto carico: da migliorare (soglie di Polaris');
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
