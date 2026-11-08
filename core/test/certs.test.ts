import { build } from 'esbuild';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { describe, expect, it } from 'vitest';
import {
  ACTIONS,
  analyze,
  certExpiry,
  certExpiryText,
  certFailHint,
  certIssues,
  certNormalize,
  certSeverity,
  certValue,
  certWarnDays,
  documentParts,
  METRICS,
  renderText,
  stepsText,
} from '../src/engine';
import type { CertResult, Scan } from '../src/engine';
import { clinicScan } from '../src/demo/clinic';
import { demoScan } from '../src/demo/sample';
import { simulatedCerts } from '../src/demo/simulate';
import { CERT_PORTS, certKey, certRowCheck, certSuggestions, fingerprintText, sameCertTarget } from '../src/ui/certs';
import { GLOSSARY, guideById, guidesForMetric } from '../src/guides';

// Certificati dei servizi interni: giudizi del motore, soglie di scadenza,
// dati dimostrativi e documento stampabile.

const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));

/** Certificato valido e attendibile, da modificare caso per caso. */
const good: CertResult = {
  label: 'Gestionale',
  host: 'gestionale.studio.local',
  port: 443,
  ip: '192.168.10.20',
  ok: true,
  tlsVersion: 'TLS 1.3',
  cipher: 'TLS_AES_128_GCM_SHA256',
  subject: 'gestionale.studio.local',
  issuer: 'CA Interna Studio',
  dnsNames: ['gestionale.studio.local'],
  notBefore: '2026-06-01T00:00:00Z',
  notAfter: '2027-06-01T00:00:00Z',
  daysLeft: 200,
  lifetimeDays: 365,
  keyType: 'ECDSA P-256',
  keyBits: 256,
  sigAlg: 'SHA256-RSA',
  nameMatch: true,
  chainLen: 2,
  trust: 'trusted',
  fingerprint: 'AB'.repeat(32),
};
const cert = (patch: Partial<CertResult>): CertResult => ({ ...good, ...patch });

function scanWith(results: CertResult[]): Scan {
  return {
    schema: 1,
    agent: { name: 'STARNET Polaris', version: 'test', platform: 'windows', startedAt: '2026-10-31T09:00:00Z', durationMs: 1000 },
    adapters: [],
    infra: { certs: { checkedAt: '2026-10-31T09:05:00Z', results } },
    errors: [],
  };
}

describe('soglie di scadenza', () => {
  it('problema entro 7 giorni, attenzione entro 30 o un terzo della durata', () => {
    expect(certExpiry(-1, 365)).toBe('expired');
    expect(certExpiry(-40, 365)).toBe('expired');
    expect(certExpiry(0, 365)).toBe('crit');
    expect(certExpiry(7, 365)).toBe('crit');
    expect(certExpiry(8, 365)).toBe('warn');
    expect(certExpiry(30, 365)).toBe('warn');
    expect(certExpiry(31, 365)).toBe('ok');
    // 90 giorni (Let's Encrypt): un terzo = 30.
    expect(certExpiry(30, 90)).toBe('warn');
    expect(certExpiry(31, 90)).toBe('ok');
    // 47 giorni (certificati pubblici dal 2029): un terzo = 15,67.
    expect(certExpiry(7, 47)).toBe('crit');
    expect(certExpiry(8, 47)).toBe('warn');
    expect(certExpiry(15, 47)).toBe('warn');
    expect(certExpiry(16, 47)).toBe('ok');
    // Durata ignota: soglie piene.
    expect(certExpiry(30)).toBe('warn');
    expect(certExpiry(31)).toBe('ok');
  });

  it('sotto i 7 giorni è un problema per qualunque durata', () => {
    // 15 giorni: un terzo = 5, sotto i 7 del problema; nessuna fascia di avviso.
    expect(certExpiry(5, 15)).toBe('crit');
    expect(certExpiry(7, 15)).toBe('crit');
    expect(certExpiry(8, 15)).toBe('ok');
    // Un giorno: sempre in scadenza, Polaris non sa se si rinnova da solo.
    expect(certExpiry(0, 1)).toBe('crit');
    expect(certExpiry(1, 1)).toBe('crit');
    expect(certExpiry(-1, 1)).toBe('expired');
  });

  it('calcola i giorni di avviso e li scrive in italiano', () => {
    expect(certWarnDays(365)).toBe(30);
    expect(certWarnDays(90)).toBe(30);
    expect(certWarnDays(47)).toBeCloseTo(15.67, 2);
    expect(certWarnDays()).toBe(30);
    expect(certExpiryText(-1)).toBe('scaduto');
    expect(certExpiryText(-12)).toBe('scaduto da 12 giorni');
    expect(certExpiryText(0)).toBe('scade entro un giorno');
    expect(certExpiryText(1)).toBe('scade tra 1 giorno');
    expect(certExpiryText(12)).toBe('scade tra 12 giorni');
    expect(certExpiryText(1500)).toBe('scade tra 4 anni');
  });
});

describe('giudizio per servizio', () => {
  const sev = (patch: Partial<CertResult>) => certSeverity(cert(patch));
  const ids = (patch: Partial<CertResult>) => certIssues(cert(patch)).map((i) => i.id);

  it('valido e attendibile: ok, nessuna azione', () => {
    expect(certSeverity(good)).toBe('ok');
    expect(certIssues(good)).toEqual([]);
    expect(certValue(good)).toBe('scade tra 200 giorni · TLS 1.3 · attendibile');
  });

  it('problemi: scaduto, entro 7 giorni, solo TLS 1.0/1.1, firma non valida, bloccato, revocato', () => {
    expect(sev({ daysLeft: -3 })).toBe('crit');
    expect(sev({ daysLeft: 5 })).toBe('crit');
    expect(sev({ legacyOnly: true, tlsVersion: 'TLS 1.0' })).toBe('crit');
    expect(sev({ trust: 'invalid-signature' })).toBe('crit');
    expect(sev({ trust: 'distrusted' })).toBe('crit');
    expect(sev({ trust: 'revoked' })).toBe('crit');
    expect(certIssues(cert({ daysLeft: -3 }))[0].action).toBe('renew-certificate');
    expect(certIssues(cert({ legacyOnly: true }))[0].action).toBe('disable-legacy-tls');
  });

  it('avvisi: in scadenza, nome, solo CN, firma debole, RSA corta, TLS vecchio accettato, catena, CA sconosciuta, uso', () => {
    expect(sev({ daysLeft: 20 })).toBe('warn');
    expect(sev({ nameMatch: false })).toBe('warn');
    expect(sev({ cnOnly: true, nameMatch: false, dnsNames: [] })).toBe('warn');
    expect(sev({ weakSig: true, sigAlg: 'SHA1-RSA' })).toBe('warn');
    expect(sev({ keyType: 'RSA', keyBits: 1024 })).toBe('warn');
    expect(sev({ keyType: 'RSA', keyBits: 2048 })).toBe('ok');
    expect(sev({ legacyToo: true })).toBe('warn');
    expect(sev({ trust: 'partial-chain' })).toBe('warn');
    expect(sev({ trust: 'untrusted-root' })).toBe('warn');
    expect(sev({ trust: 'wrong-usage' })).toBe('warn');
    // Solo CN: un solo avviso, non anche "nome non corrispondente".
    expect(ids({ cnOnly: true, nameMatch: false, dnsNames: [] })).toEqual(['cn-only']);
    expect(ids({ trust: 'untrusted-root' })).toEqual(['unknown-ca']);
    expect(certIssues(cert({ trust: 'untrusted-root' }))[0].action).toBe('trust-internal-ca');
    expect(certIssues(cert({ nameMatch: false }))[0].action).toBe('reissue-certificate-san');
  });

  it('autofirmato non attendibile e certificato client: informazioni, non errori', () => {
    expect(sev({ selfSigned: true, trust: 'untrusted-root', issuer: 'nas' })).toBe('info');
    expect(ids({ selfSigned: true, trust: 'untrusted-root' })).toEqual(['self-signed']);
    expect(sev({ clientCert: true })).toBe('info');
    expect(certIssues(cert({ clientCert: true }))[0].action).toBeUndefined();
    // Autofirmato ma reso attendibile di proposito: ok.
    expect(sev({ selfSigned: true, trust: 'trusted' })).toBe('ok');
    expect(certValue(cert({ selfSigned: true, trust: 'untrusted-root', daysLeft: 12 }))).toBe('scade tra 12 giorni · TLS 1.3 · autofirmato');
  });

  it('il più grave vince: TLS 1.1 e scadenza vicina', () => {
    const issues = certIssues(cert({ legacyOnly: true, tlsVersion: 'TLS 1.1', daysLeft: 11, lifetimeDays: 400 }));
    expect(issues.map((i) => [i.id, i.severity])).toEqual([
      ['legacy-only', 'crit'],
      ['expiring', 'warn'],
    ]);
  });

  it('servizio non controllato: gravità ignota con il motivo', () => {
    const r: CertResult = { host: '192.168.1.1', port: 443, ok: false, error: 'porta chiusa: nessun servizio in ascolto', daysLeft: 0, nameMatch: false };
    expect(certSeverity(r)).toBe('unknown');
    const f = analyze(scanWith([r])).findings.find((x) => x.metric === 'infra.cert')!;
    expect(f.severity).toBe('unknown');
    expect(f.value).toBe('non controllato');
    expect(f.verdict).toContain('porta chiusa');
    expect(f.verdict).toContain('8443');
    expect(f.actions).toEqual([]);
  });

  it('attendibilità non verificabile: non la dichiara', () => {
    const f = analyze(scanWith([cert({ trust: undefined })])).findings.find((x) => x.metric === 'infra.cert')!;
    expect(f.severity).toBe('ok');
    expect(f.verdict).toContain('non è stata verificata');
    expect(f.verdict).not.toContain('attendibile su questo PC,');
  });
});

describe('giudizi nel motore', () => {
  it('uno per servizio, con identificativo stabile da nome e porta', () => {
    const s = scanWith([good, cert({ label: undefined, host: '192.168.10.5', port: 8443, selfSigned: true, trust: 'untrusted-root' }), cert({ label: 'Doppione' })]);
    const fs = analyze(s).findings.filter((f) => f.metric === 'infra.cert');
    expect(fs.map((f) => f.id).sort()).toEqual(['infra.cert.192.168.10.5:8443', 'infra.cert.gestionale.studio.local:443', 'infra.cert.gestionale.studio.local:443#2']);
    for (const f of fs) {
      expect(f.category).toBe('infra');
      expect(METRICS[f.metric]).toBeDefined();
      for (const a of f.actions) expect(ACTIONS[a], a).toBeDefined();
    }
    expect(fs.find((f) => f.id === 'infra.cert.192.168.10.5:8443')!.title).toBe('Certificato · 192.168.10.5:8443');
    expect(fs.find((f) => f.id === 'infra.cert.gestionale.studio.local:443')!.numeric).toBe(200);
  });

  it('le azioni entrano nel piano con il giudizio che le richiede', () => {
    const a = analyze(scanWith([cert({ daysLeft: 3 }), cert({ host: 'nas.studio.local', legacyToo: true })]));
    const renew = a.plan.find((p) => p.action.id === 'renew-certificate')!;
    expect(renew.severity).toBe('crit');
    expect(renew.findings).toEqual(['infra.cert.gestionale.studio.local:443']);
    expect(a.plan.find((p) => p.action.id === 'disable-legacy-tls')!.severity).toBe('warn');
  });

  it('la voce di knowledge base ha soglie, perché e limiti, ed è spiegata da una guida', () => {
    const m = METRICS['infra.cert'];
    expect(m.scale!.map((x) => x.severity)).toEqual(['ok', 'info', 'warn', 'crit']);
    expect(m.limits).toContain('revoca');
    expect(m.limits).toContain('3389');
    expect(guidesForMetric('infra.cert').map((g) => g.id)).toContain('certificati-servizi-interni');
    for (const id of ['renew-certificate', 'trust-internal-ca', 'disable-legacy-tls', 'reissue-certificate-san']) expect(ACTIONS[id], id).toBeDefined();
    expect(stepsText(ACTIONS['trust-internal-ca'])).toContain('Autorità di certificazione radice attendibili');
  });
});

describe('servizi indicati dall\'utente', () => {
  it('normalizza come l\'agente', () => {
    expect(certNormalize('nas.local')).toEqual({ host: 'nas.local', port: 443 });
    expect(certNormalize(' 192.168.1.10:8443 ', 443)).toEqual({ host: '192.168.1.10', port: 8443 });
    expect(certNormalize('https://pacs.local:8443/viewer')).toEqual({ host: 'pacs.local', port: 8443 });
    expect(certNormalize('https://pacs.local/viewer', 5001)).toEqual({ host: 'pacs.local', port: 5001 });
    expect(certNormalize('ldaps://dc01.studio.local')).toEqual({ host: 'dc01.studio.local', port: 636 });
    expect(certNormalize('[fd00::5]:636')).toEqual({ host: 'fd00::5', port: 636 });
    expect(certNormalize('fd00::5')).toEqual({ host: 'fd00::5', port: 443 });
    expect(certNormalize('')).toHaveProperty('error');
    expect(certNormalize('nas local')).toHaveProperty('error');
    expect(certNormalize('nas.local', 70000)).toHaveProperty('error');
  });

  it('controlla le righe e avvisa per Desktop remoto e STARTTLS', () => {
    expect(certRowCheck('', '').hostError).toBeDefined();
    // Ogni errore sul campo che lo causa: porta sbagliata sulla porta, nome mancante sul nome.
    expect(certRowCheck('nas.local', '99999')).toEqual({ portError: expect.any(String) });
    expect(certRowCheck('', '0')).toEqual({ hostError: expect.any(String), portError: expect.any(String) });
    expect(certRowCheck('nas local', '').hostError).toBeDefined();
    expect(certRowCheck('nas.local', '')).toEqual({});
    expect(certRowCheck('https://nas.local:5001/', '').effective).toBe('nas.local:5001');
    // Il Desktop remoto blocca l'invio: la porta scritta nel campo o dentro l'indirizzo.
    expect(certRowCheck('pc-01', '3389')).toEqual({ portError: expect.stringContaining('Desktop remoto') });
    expect(certRowCheck('https://pc-01:3389', '')).toEqual({ hostError: expect.stringContaining('Desktop remoto') });
    expect(certRowCheck('mail.local', '587').note).toContain('STARTTLS');
    expect(certKey({ host: 'NAS.local:5001' })).toBe(certKey({ host: 'nas.local', port: 5001 }));
    expect(CERT_PORTS.map((p) => p.port)).toEqual(expect.arrayContaining([443, 8443, 636, 3269, 465, 993, 995, 990, 2762, 8883, 25, 587]));
    expect(CERT_PORTS.map((p) => p.port)).not.toContain(3389);
  });

  it('suggerimenti dopo un controllo non riuscito, secondo la causa', () => {
    expect(certFailHint('porta chiusa: nessun servizio in ascolto', 443)).toContain('8443');
    expect(certFailHint('porta chiusa: nessun servizio in ascolto')).toContain('8443');
    expect(certFailHint('il servizio su questa porta non usa TLS', 5001)).toContain('manuale');
    expect(certFailHint('il servizio su questa porta non usa TLS', 5001)).not.toContain('8443');
    expect(certFailHint('nome non risolto', 443)).toContain('indirizzo IP');
    const slow = certFailHint('il servizio non ha risposto in tempo', 443);
    // Le cause possibili, non una sola data per certa.
    expect(slow).toContain('spento');
    expect(slow).toContain('firewall');
    expect(slow).toContain('non usa TLS');
    expect(certFailHint('negoziazione TLS non riuscita', 443)).toBe('');
    expect(certFailHint(undefined, 443)).toBe('');
  });

  it('un controllo si unisce solo al rapporto della stessa rete e della stessa origine', () => {
    const live = { live: true, host: demoScan.agent.host, gateway: demoScan.gateway?.ip };
    expect(sameCertTarget(live, demoScan, 'agent')).toBe(true);
    // Rapporto importato o demo mostrati nel frattempo: niente.
    expect(sameCertTarget(live, demoScan, 'file')).toBe(false);
    expect(sameCertTarget(live, demoScan, 'demo')).toBe(false);
    // Altra demo o altro PC.
    expect(sameCertTarget(live, clinicScan, 'agent')).toBe(false);
    // Stesso PC su un'altra rete (gateway diverso).
    const moved = clone(demoScan);
    moved.gateway!.ip = '10.0.0.1';
    expect(sameCertTarget(live, moved, 'agent')).toBe(false);
    // Simulazione: solo sulla stessa demo.
    const sim = { live: false, host: clinicScan.agent.host, gateway: clinicScan.gateway?.ip };
    expect(sameCertTarget(sim, clinicScan, 'demo')).toBe(true);
    expect(sameCertTarget(sim, demoScan, 'demo')).toBe(false);
    expect(sameCertTarget(sim, clinicScan, 'agent')).toBe(false);
    expect(sameCertTarget(undefined, clinicScan, 'demo')).toBe(false);
    expect(sameCertTarget(sim, null, 'demo')).toBe(false);
  });

  it('impronta a coppie di cifre', () => {
    expect(fingerprintText('ABCDEF012345')).toBe('AB:CD:EF:01:23:45');
  });
});

describe('dati dimostrativi', () => {
  const hex64 = /^[0-9A-F]{64}$/;
  const isPrivate = (ip: string) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip);

  it('clinica: CA interna attendibile, PACS autofirmato con certificato client, NAS fermo a TLS 1.1 in scadenza, posta con STARTTLS', () => {
    const a = analyze(clinicScan);
    const sev = (id: string) => a.findings.find((f) => f.id === id)?.severity;
    expect(sev('infra.cert.ehr.clinica.local:443')).toBe('ok');
    expect(sev('infra.cert.10.20.50.20:2762')).toBe('info');
    expect(sev('infra.cert.nas.clinica.local:5001')).toBe('crit');
    expect(sev('infra.cert.mail.clinica.local:587')).toBe('ok');
    const pacs = clinicScan.infra!.certs!.results.find((r) => r.port === 2762)!;
    expect(pacs.clientCert && pacs.selfSigned).toBe(true);
    const nas = clinicScan.infra!.certs!.results.find((r) => r.port === 5001)!;
    expect(certExpiry(nas.daysLeft, nas.lifetimeDays)).toBe('warn');
    expect(clinicScan.infra!.certs!.results.find((r) => r.port === 587)!.starttls).toBe('smtp');
    for (const r of clinicScan.infra!.certs!.results) {
      expect(r.fingerprint).toMatch(hex64);
      expect(isPrivate(r.ip!)).toBe(true);
      // Giorni residui coerenti con la data del controllo.
      const days = Math.trunc((Date.parse(r.notAfter!) - Date.parse(clinicScan.infra!.certs!.checkedAt)) / 86_400_000);
      expect(days, r.host).toBe(r.daysLeft);
    }
  });

  it('simulazione della clinica: stessi esiti, date spostate a oggi', () => {
    const now = Date.parse('2026-10-31T10:00:00Z');
    const targets = clinicScan.infra!.certs!.results.map(({ label, host, port }) => ({ label, host, port }));
    const sim = simulatedCerts(clinicScan, targets, now);
    expect(sim.results.map(certSeverity)).toEqual(clinicScan.infra!.certs!.results.map(certSeverity));
    for (const r of sim.results) expect(Math.trunc((Date.parse(r.notAfter!) - now) / 86_400_000)).toBe(r.daysLeft);
    expect(simulatedCerts(clinicScan, targets, now)).toEqual(sim);
  });

  it('casa: suggerisce il pannello del router e lo simula coerente con l\'analisi', () => {
    const sugg = certSuggestions(demoScan);
    // La 443 del router risulta chiusa nell'analisi: si propone la 8443.
    expect(sugg).toEqual([{ label: 'Pannello del router', host: '192.168.1.1', port: 8443 }]);
    const sim = simulatedCerts(demoScan, [...sugg, { host: '192.168.1.1', port: 443 }, { host: '93.184.216.34' }, { host: 'pc-salotto', port: 3389 }]);
    const [router, closed, pub, rdp] = sim.results;
    // Il pannello risulta solo in HTTP: nessun certificato inventato sulla 8443.
    expect(demoScan.gateway?.web?.https).toBe(false);
    expect(router.ok).toBe(false);
    expect(router.error).toContain('porta chiusa');
    expect(certSeverity(router)).toBe('unknown');
    expect(closed.error).toContain('porta chiusa');
    expect(pub.ok).toBe(false);
    expect(pub.error).toContain('pubblico');
    expect(rdp.ok).toBe(false);
  });

  it('router con HTTPS: certificato autofirmato del dispositivo; firma coerente con la chiave', () => {
    const scan = clone(demoScan);
    scan.gateway!.web = { ...scan.gateway!.web, https: true };
    scan.gateway!.ports = scan.gateway!.ports!.map((p) => (p.port === 443 ? { ...p, open: true } : p));
    expect(certSuggestions(scan)).toEqual([{ label: 'Pannello del router', host: '192.168.1.1', port: 443 }]);
    const [router] = simulatedCerts(scan, certSuggestions(scan)).results;
    expect(router.ok && router.selfSigned).toBe(true);
    expect(router.fingerprint).toMatch(hex64);
    expect(certSeverity(router)).toBe('info');
    const many = simulatedCerts(scan, Array.from({ length: 12 }, (_, i) => ({ host: `nas-${i}.local` }))).results;
    for (const r of many) expect(r.sigAlg!.startsWith('ECDSA')).toBe(r.keyType!.startsWith('ECDSA'));
  });

  it('clinica: suggerisce il gateway e i servizi delle verifiche su porte cifrate', () => {
    const sugg = certSuggestions(clinicScan);
    expect(sugg.map(certKey)).toEqual(['10.20.30.1:443', 'ehr.clinica.local:443']);
  });

  it('la demo di casa non contiene certificati finché non li controlli', () => {
    expect(demoScan.infra?.certs).toBeUndefined();
  });
});

describe('documento e rapporto', () => {
  it('il documento elenca i certificati senza impronte né indirizzi pubblici', () => {
    const scan = clone(clinicScan);
    scan.infra!.certs!.results.push({ label: 'Servizio esterno', host: '93.184.216.34', port: 443, ok: false, error: 'indirizzo pubblico: si controllano solo i servizi della rete locale', daysLeft: 0, nameMatch: false });
    const { body } = documentParts(scan, analyze(scan));
    const sec = body.slice(body.indexOf('<h2>Certificati dei servizi</h2>'));
    expect(sec.length).toBeGreaterThan(30);
    const table = sec.slice(0, sec.indexOf('</section>'));
    expect(table).toContain('NAS archivio referti');
    expect(table).toContain('nas.clinica.local:5001');
    expect(table).toContain('26/10/2026');
    expect(table).toContain('autofirmato');
    expect(table).toContain('CA Interna Clinica');
    expect(table).toContain('TLS 1.1');
    expect(table).toContain('STARTTLS');
    expect(table).toMatch(/pd-sev pd-crit"><b aria-hidden="true">✕<\/b> Critico/);
    for (const r of scan.infra!.certs!.results) if (r.fingerprint) expect(body).not.toContain(r.fingerprint.slice(0, 16));
    expect(body).not.toContain('93.184.216.34');
    expect(table).toContain('[IP pubblico]');
    // La riga non riuscita dice perché, senza date né emittente.
    const failed = table.slice(table.indexOf('Servizio esterno'));
    expect(failed.slice(0, failed.indexOf('</tr>'))).toContain('non controllato: indirizzo pubblico');
    expect(failed.slice(0, failed.indexOf('</tr>'))).toMatch(/pd-sev pd-unknown/);
  });

  it('senza certificati il documento non ha la sezione', () => {
    const { body } = documentParts(demoScan, analyze(demoScan));
    expect(body).not.toContain('Certificati dei servizi');
  });

  it('il motore della riga di comando (ES2015, goja) dà gli stessi giudizi, documento e rapporto', async () => {
    const entry = fileURLToPath(new URL('../src/engine/global.ts', import.meta.url));
    const out = await build({ entryPoints: [entry], bundle: true, format: 'iife', target: 'es2015', write: false });
    const ctx: Record<string, unknown> = {};
    ctx.globalThis = ctx;
    vm.createContext(ctx);
    vm.runInContext(out.outputFiles[0].text, ctx);
    const engine = ctx.PolarisEngine as { analyzeJson(s: string): string; reportText(s: string, v: boolean): string; reportHtml(s: string, v: string, g: string): string };
    const json = JSON.stringify(clinicScan);
    expect(JSON.parse(engine.analyzeJson(json))).toEqual(JSON.parse(JSON.stringify(analyze(clinicScan))));
    expect(engine.reportText(json, true)).toBe(renderText(clinicScan, analyze(clinicScan), { verbose: true }));
    expect(engine.reportHtml(json, '0.10.0', 'oggi')).toContain('<h2>Certificati dei servizi</h2>');
  });

  it('il rapporto di testo riporta un riassunto per servizio entro 90 colonne', () => {
    const txt = renderText(clinicScan, analyze(clinicScan), { verbose: true });
    expect(txt).toContain(' Certificati dei servizi, 2026-10-14T09:21:30Z');
    expect(txt).toContain('[CRIT] NAS archivio referti nas.clinica.local:5001');
    expect(txt).toContain('scade il 26/10/2026 (11 g), TLS 1.1, attendibile');
    expect(txt).not.toContain('3976FAAE1BB5D9AA');
    for (const line of txt.split('\n')) expect(line.length, line).toBeLessThanOrEqual(90);
  });
});

describe('guida e glossario', () => {
  it('la guida spiega la misura e collega le azioni', () => {
    const g = guideById('certificati-servizi-interni')!;
    expect(g.metrics).toEqual(['infra.cert']);
    expect(g.actions).toEqual(expect.arrayContaining(['renew-certificate', 'trust-internal-ca', 'disable-legacy-tls', 'reissue-certificate-san']));
    const text = JSON.stringify(g.blocks);
    for (const k of ['RFC 8996', 'RFC 9325', 'RFC 9525', 'SC-081', 'PS3.15', '2762', 'revoca', '3389']) expect(text, k).toContain(k);
  });

  it('il glossario ha i termini dei certificati', () => {
    const terms = GLOSSARY.map((t) => t.term);
    for (const t of ['Certificato TLS', 'Autorità di certificazione', 'Certificato autofirmato', 'SAN', 'Impronta digitale', 'TLS reciproco', 'STARTTLS']) expect(terms, t).toContain(t);
  });

  it('la guida d\'uso elenca il controllo e il comando', () => {
    const uso = JSON.stringify([guideById('strumenti-avanzati')!.blocks, guideById('riga-di-comando')!.blocks]);
    expect(uso).toContain('certificati dei servizi');
    expect(uso).toContain('polaris-cli certs SERVIZIO... [--json]');
  });
});
