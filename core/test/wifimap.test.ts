import { build } from 'esbuild';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  ACTIONS,
  analyze,
  dipSeverity,
  documentParts,
  gatewayText,
  METRICS,
  pingMeasured,
  renderText,
  roomSlug,
  routerSilent,
  rssiSeverity,
  rssiWord,
  sampleIssues,
  sampleSeverity,
  surveyAliases,
  surveyForExport,
  surveyRooms,
  worstSample,
} from '../src/engine';
import type { Scan, SurveySample, WifiSurvey } from '../src/engine';
import { clinicScan } from '../src/demo/clinic';
import { demoScan } from '../src/demo/sample';
import { clinicSurvey, homeSurvey, seriesStats, simulatedSample } from '../src/demo/survey';
import { cleanRoom, mergeSample, onlyNetwork, removeFromSurvey, roomNameError, sameSurveyTarget, storeKey, surveyRefusal, surveyTargetOf, syncStored } from '../src/ui/wifimap';
import { GLOSSARY, guideById, guidesForMetric } from '../src/guides';
import { base } from './fixtures';

// Mappa del Wi-Fi per stanza: soglie, aggregazione per stanza, protezione dal
// cambio di rapporto, demo, privacy di documento ed esportazioni, motore ES2015.

const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));

/** Punto "buono" a 5 GHz, da modificare caso per caso. */
const good: SurveySample = {
  room: 'Studio',
  startedAt: '2026-10-31T09:00:00Z',
  durationMs: 15200,
  seconds: 15,
  ssid: 'Casa',
  band: '5',
  channel: 36,
  widthMhz: 80,
  phy: '802.11ac',
  rssi: [-63, -64, -63, -62, -63, -64, -63, -63, -62, -63, -64, -63, -63, -62, -63],
  medianDbm: -63,
  minDbm: -64,
  maxDbm: -62,
  p10Dbm: -64,
  spreadDb: 2,
  rxMbps: 433,
  txMbps: 390,
  bssids: ['aa:bb:cc:00:00:10'],
  roams: [],
  gateway: { target: '192.168.1.1', sent: 75, received: 75, lossPct: 0, medianMs: 3, p95Ms: 7, jitterMs: 1.2 },
  scan: { fresh: 9, stale: 0, connectedDbm: -63, utilizationPct: 20, stations: 4, alternatives: [], neighbors: { visible: 8, cochannel: 0, strong: 0 } },
};
const pt = (patch: Partial<SurveySample>): SurveySample => ({ ...clone(good), ...patch });
const ids = (s: SurveySample) => sampleIssues(s).map((i) => `${i.id}:${i.severity}`);

function withSurvey(survey: WifiSurvey, from: Scan = base()): Scan {
  const s = clone(from);
  s.wifi!.survey = clone(survey);
  return s;
}

describe('soglie del segnale', () => {
  it('mediana: ok da -67, info fino a -72, attenzione fino a -80, problema sotto', () => {
    expect([-50, -60, -67, -67.5, -72, -72.5, -80, -80.5, -90].map(rssiSeverity)).toEqual(['ok', 'ok', 'ok', 'info', 'info', 'warn', 'warn', 'crit', 'crit']);
    expect([-55, -60, -61, -67, -68, -72, -73, -80, -81].map(rssiWord)).toEqual([
      'ottimo', 'ottimo', 'buono', 'buono', 'sufficiente', 'sufficiente', 'debole', 'debole', 'molto debole',
    ]);
  });

  it('cali (10° percentile): un livello sotto la mediana, e contano solo se peggiorano', () => {
    expect([-60, -72, -73, -80, -81, -95].map(dipSeverity)).toEqual(['ok', 'ok', 'info', 'info', 'warn', 'warn']);
    expect(ids(pt({ p10Dbm: -74, minDbm: -75, spreadDb: 9 }))).toEqual(['dips:info']);
    expect(ids(pt({ medianDbm: -70, p10Dbm: -74, minDbm: -75, spreadDb: 8 }))).toEqual(['signal:info']); // stesso livello: non si ripete
    expect(ids(pt({ medianDbm: -66, p10Dbm: -82, minDbm: -83, spreadDb: 9 }))).toEqual(['dips:warn']);
    expect(sampleSeverity(pt({ medianDbm: -82, p10Dbm: -85, minDbm: -86, spreadDb: 5 }))).toBe('crit');
  });

  it('escursione oltre 10 dB da fermi, ma non con valori fermi', () => {
    expect(ids(pt({ minDbm: -70, maxDbm: -60, spreadDb: 10 }))).toEqual([]);
    const unstable = sampleIssues(pt({ band: '2.4', minDbm: -71, maxDbm: -60, spreadDb: 11, p10Dbm: -69 }));
    expect(unstable.map((i) => i.id)).toEqual(['unstable']);
    expect(unstable[0].text).toContain('forno a microonde');
    expect(unstable[0].actions).toEqual(['avoid-24-interference', 'use-5ghz']);
    const stuck = sampleIssues(pt({ rssi: Array(15).fill(-58), medianDbm: -58, minDbm: -58, maxDbm: -58, p10Dbm: -58, spreadDb: 0, stuck: true }));
    expect(stuck.map((i) => `${i.id}:${i.severity}`)).toEqual(['stuck:info']);
  });

  it('cambio di access point da fermo: avviso, con gli alias e mai il BSSID', () => {
    const s = pt({ bssids: ['aa:bb:cc:00:00:10', 'aa:bb:cc:00:00:20'], roams: [{ atMs: 6000, from: 'aa:bb:cc:00:00:10', to: 'aa:bb:cc:00:00:20' }] });
    const al = surveyAliases({ rooms: [{ name: 'Studio', samples: [s] }] });
    const roam = sampleIssues(s, al).find((i) => i.id === 'roam')!;
    expect(roam.severity).toBe('warn');
    expect(roam.text).toContain('AP A → AP B');
    expect(roam.text).not.toContain('aa:bb');
    expect(roam.actions).toEqual(['fix-roaming', 'plan-ap-channels']);
  });

  it('access point più forte di 8 dB nella stessa banda: client appiccicoso', () => {
    const alt = (rssiDbm: number, band: '2.4' | '5' = '5') => ({ bssid: 'aa:bb:cc:00:00:20', band, channel: band === '5' ? 44 : 6, rssiDbm });
    const sticky = (rssi: number, band?: '2.4' | '5') => pt({ medianDbm: -70, p10Dbm: -71, scan: { ...good.scan!, connectedDbm: -70, alternatives: [alt(rssi, band)] } });
    expect(ids(sticky(-63))).toEqual(['signal:info']); // 7 dB: no
    expect(ids(sticky(-62))).toEqual(['sticky:warn', 'signal:info']);
    // A 2,4 GHz il segnale è sempre più forte: non si confrontano bande diverse.
    expect(ids(sticky(-50, '2.4'))).toEqual(['signal:info']);
  });

  it('sui 2,4 GHz con la stessa rete a 5 GHz da -67 dBm: band steering', () => {
    const s = (rssi: number) => pt({ band: '2.4', channel: 6, widthMhz: 20, scan: { ...good.scan!, alternatives: [{ bssid: 'aa:bb:cc:00:00:11', band: '5', channel: 36, rssiDbm: rssi }] } });
    expect(ids(s(-67))).toEqual(['band:info']);
    expect(sampleIssues(s(-67))[0].actions).toEqual(['band-steering', 'use-5ghz']);
    expect(ids(s(-68))).toEqual([]);
  });

  it('router: perdite oltre l\'1 %, jitter da 10 e 30 ms, tempo di risposta solo con perdite', () => {
    const g = (patch: Partial<NonNullable<SurveySample['gateway']>>) => pt({ gateway: { ...good.gateway!, ...patch } });
    expect(ids(g({ received: 74, lossPct: 1.3 }))).toEqual(['loss:warn']);
    expect(ids(g({ received: 72, lossPct: 4 }))).toEqual(['loss:warn']);
    expect(ids(g({ received: 71, lossPct: 5.3 }))).toEqual(['loss:crit']);
    expect(ids(g({ jitterMs: 9.9 }))).toEqual([]);
    expect(ids(g({ jitterMs: 10 }))).toEqual(['jitter:warn']);
    expect(ids(g({ jitterMs: 30 }))).toEqual(['jitter:crit']);
    // Router lento ma senza perdite: risponde quando ha tempo, non è un problema della rete.
    expect(ids(g({ medianMs: 60 }))).toEqual([]);
    expect(ids(g({ medianMs: 25, received: 74, lossPct: 1.3 }))).toEqual(['loss:warn', 'rtt:warn']);
    expect(ids(g({ medianMs: 50, received: 74, lossPct: 1.3 }))).toEqual(['rtt:crit', 'loss:warn']);
    // Router non misurato: nessun giudizio.
    expect(ids(pt({ gateway: { sent: 0, received: 0, lossPct: 0, skipped: 'indirizzo pubblico' } }))).toEqual([]);
  });

  it('router che non risponde a nessun ping: non è una perdita, a meno che risponda in un\'altra misura', () => {
    const silentOld = { target: '192.168.1.1', sent: 75, received: 0, lossPct: 100 }; // agente precedente
    const silentNew = { ...silentOld, noReply: true, error: 'nessuna risposta su 75 ping: se il router è configurato per ignorarli, perdite e tempi qui non sono misurabili' };
    for (const g of [silentOld, silentNew]) {
      const s = pt({ medianDbm: -52, p10Dbm: -54, gateway: g });
      expect(routerSilent(g)).toBe(true);
      expect(ids(s)).toEqual([]);
      expect(sampleSeverity(s)).toBe('ok');
      expect(gatewayText(s)).toBe('nessuna risposta su 75 ping: il router forse li ignora, perdite e tempi non misurabili');
      // Lo stesso router ha risposto in un'altra misura: qui i dati non passano.
      const lost = sampleIssues(s, undefined, ['192.168.1.1']);
      expect(lost.map((i) => `${i.id}:${i.severity}`)).toEqual(['loss:crit']);
      expect(lost[0].text).toContain('mentre in altre misure risponde');
      expect(lost[0].text).toContain('VPN');
      expect(gatewayText(s, ['192.168.1.1'])).toBe('persi 75 su 75');
      // Un altro router che risponde non conta.
      expect(ids({ ...s, gateway: g })).toEqual([]);
      expect(sampleIssues(s, undefined, ['10.0.0.1'])).toEqual([]);
    }
    // Un errore locale (nessun ping partito) non è "nessuna risposta".
    const local = { target: '192.168.1.1', sent: 75, received: 0, lossPct: 100, error: 'nessun ping è partito: errore della scheda' };
    expect(routerSilent(local)).toBe(false);
    expect(pingMeasured(local, ['192.168.1.1'])).toBe(false);
    expect(gatewayText(pt({ gateway: local }), ['192.168.1.1'])).toBe('non misurato: nessun ping è partito: errore della scheda');
    expect(ids(pt({ gateway: local }))).toEqual([]);
  });

  it('casa con un router che ignora i ping: nessuna stanza diventa critica per le perdite', () => {
    const scan = clone(demoScan);
    for (const r of scan.wifi!.survey!.rooms)
      for (const s of r.samples) s.gateway = { target: '192.168.1.1', sent: 75, received: 0, lossPct: 100 };
    scan.gateway!.ping = { ...scan.gateway!.ping!, received: 0, avgMs: undefined, minMs: undefined, maxMs: undefined, jitterMs: undefined };
    const a = analyze(scan);
    const rooms = a.findings.filter((f) => f.id.startsWith('wifi.room.'));
    expect(rooms.find((f) => f.id === 'wifi.room.soggiorno')!.severity).toBe('ok');
    for (const f of rooms) {
      expect(f.verdict, f.id).not.toContain('Persi 75');
      expect(f.verdict, f.id).toContain('router: nessuna risposta su 75 ping');
    }
    // Decide il segnale: il Bagno (-79 dBm, instabile) resta da migliorare, lo Studio (-69 dBm) da sapere.
    expect(rooms.find((f) => f.id === 'wifi.room.bagno')!.severity).toBe('warn');
    expect(rooms.find((f) => f.id === 'wifi.room.studio')!.severity).toBe('info');
    // Se il router risponde in una stanza, le altre senza risposta sono perdite vere.
    scan.wifi!.survey!.rooms.find((r) => r.name === 'Soggiorno')!.samples[0].gateway = { target: '192.168.1.1', sent: 75, received: 75, lossPct: 0, medianMs: 3, jitterMs: 1 };
    const b = analyze(scan).findings.filter((f) => f.id.startsWith('wifi.room.'));
    expect(b.find((f) => f.id === 'wifi.room.soggiorno')!.severity).toBe('ok');
    expect(b.find((f) => f.id === 'wifi.room.studio')!.severity).toBe('crit');
    expect(b.find((f) => f.id === 'wifi.room.studio')!.verdict).toContain('nessuno dei 75 ping');
  });

  it('dBm stimati dalla qualità di Windows: il giudizio lo dichiara', () => {
    const f = analyze(withSurvey({ rooms: [{ name: 'Studio', samples: [pt({ estimated: true })] }] })).findings.find((x) => x.id === 'wifi.room.studio')!;
    expect(f.verdict).toContain('stimati dalla qualità del segnale riportata da Windows');
    const g = analyze(withSurvey({ rooms: [{ name: 'Studio', samples: [pt({})] }] })).findings.find((x) => x.id === 'wifi.room.studio')!;
    expect(g.verdict).not.toContain('stimati');
  });

  it('canale occupato oltre il 50 % e vicini forti sullo stesso canale', () => {
    expect(ids(pt({ scan: { ...good.scan!, utilizationPct: 50 } }))).toEqual([]);
    expect(ids(pt({ scan: { ...good.scan!, utilizationPct: 51 } }))).toEqual(['busy:warn']);
    expect(ids(pt({ scan: { ...good.scan!, neighbors: { visible: 9, cochannel: 2, strong: 1, strongestDbm: -60 } } }))).toEqual(['cochannel:info']);
  });

  it('ogni azione proposta esiste nel catalogo', () => {
    const worst = pt({
      band: '2.4', medianDbm: -84, p10Dbm: -88, minDbm: -90, maxDbm: -75, spreadDb: 15,
      bssids: ['a', 'b'], roams: [{ atMs: 1, from: 'a', to: 'b' }],
      gateway: { target: '192.168.1.1', sent: 75, received: 60, lossPct: 20, medianMs: 70, jitterMs: 40 },
      scan: { fresh: 1, stale: 0, connectedDbm: -84, utilizationPct: 80, stations: 30, alternatives: [{ bssid: 'c', band: '2.4', channel: 1, rssiDbm: -60 }, { bssid: 'd', band: '5', channel: 36, rssiDbm: -62 }], neighbors: { visible: 3, cochannel: 2, strong: 2, strongestDbm: -55 } },
    });
    const issues = sampleIssues(worst);
    expect(issues.map((i) => i.id).sort()).toEqual(['band', 'busy', 'cochannel', 'dips', 'jitter', 'loss', 'roam', 'rtt', 'signal', 'sticky', 'unstable'].filter((x) => x !== 'dips').sort());
    for (const i of issues) for (const a of i.actions) expect(ACTIONS[a], a).toBeDefined();
  });
});

describe('stanze', () => {
  it('per stanza conta il punto peggiore; le stanze vanno dalla più debole alla più forte', () => {
    const survey: WifiSurvey = {
      rooms: [
        { name: 'Soggiorno', samples: [pt({ room: 'Soggiorno', medianDbm: -52, p10Dbm: -54 })] },
        { name: 'Studio', samples: [pt({ room: 'Studio' }), pt({ room: 'Studio', startedAt: '2026-10-31T09:05:00Z', medianDbm: -74, p10Dbm: -76 })] },
        { name: 'Bagno', samples: [pt({ room: 'Bagno', medianDbm: -66, gateway: { ...good.gateway!, received: 70, lossPct: 6.7 } })] },
        { name: 'Camera', samples: [pt({ room: 'Camera', medianDbm: -70, p10Dbm: -71 })] },
      ],
    };
    expect(worstSample(survey.rooms[1])!.medianDbm).toBe(-74);
    const rooms = surveyRooms(survey);
    expect(rooms.map((r) => `${r.room.name}:${r.severity}`)).toEqual(['Bagno:crit', 'Studio:warn', 'Camera:info', 'Soggiorno:ok']);
    expect(rooms.map((r) => r.id)).toEqual(['wifi.room.bagno', 'wifi.room.studio', 'wifi.room.camera', 'wifi.room.soggiorno']);
    const a = analyze(withSurvey(survey));
    const f = a.findings.find((x) => x.id === 'wifi.room.studio')!;
    expect(f.metric).toBe('wifi.survey');
    expect(f.category).toBe('wifi');
    expect(f.value).toBe('-74 dBm · debole · 2 punti, il peggiore');
    expect(f.verdict).toContain('punto peggiore su 2');
    expect(f.actions).toEqual(['survey-place-ap', 'add-mesh']);
    const ok = a.findings.find((x) => x.id === 'wifi.room.soggiorno')!;
    expect(ok.severity).toBe('ok');
    expect(ok.verdict).toMatch(/^Segnale ottimo \(mediana -52 dBm/);
    // Le azioni delle stanze entrano nel piano.
    expect(a.plan.find((p) => p.action.id === 'survey-place-ap')?.findings).toEqual(expect.arrayContaining(['wifi.room.studio', 'wifi.room.camera']));
  });

  it('identificativi stabili dal nome, anche con accenti e nomi simili', () => {
    expect(roomSlug("Sala d'attesa")).toBe('sala-d-attesa');
    expect(roomSlug('Lavanderia è Più')).toBe('lavanderia-e-piu');
    expect(roomSlug('???')).toBe('stanza');
    expect(roomSlug('x'.repeat(50)).length).toBe(32);
    const rooms = surveyRooms({ rooms: [{ name: 'Studio', samples: [pt({})] }, { name: 'studio!', samples: [pt({})] }] });
    expect(rooms.map((r) => r.id).sort()).toEqual(['wifi.room.studio', 'wifi.room.studio-2']);
  });

  it('unisce le misure nella stanza giusta e toglie stanze e punti', () => {
    let sv = mergeSample(undefined, pt({ room: '  Sala   d\'attesa ' }));
    expect(sv.rooms.map((r) => r.name)).toEqual(["Sala d'attesa"]);
    sv = mergeSample(sv, pt({ room: "sala d'ATTESA", startedAt: '2026-10-31T09:10:00Z' }));
    sv = mergeSample(sv, pt({ room: 'Studio' }));
    expect(sv.rooms.map((r) => `${r.name}:${r.samples.length}`)).toEqual(["Sala d'attesa:2", 'Studio:1']);
    // La stessa misura due volte (ripresa dall'agente) non si duplica.
    sv = mergeSample(sv, pt({ room: 'Studio' }));
    expect(sv.rooms[1].samples).toHaveLength(1);
    expect(removeFromSurvey(sv, "SALA D'ATTESA", '2026-10-31T09:00:00Z')!.rooms[0].samples).toHaveLength(1);
    expect(removeFromSurvey(sv, 'studio')!.rooms.map((r) => r.name)).toEqual(["Sala d'attesa"]);
    expect(removeFromSurvey({ rooms: [{ name: 'A', samples: [pt({})] }] }, 'a')).toBeUndefined();
  });

  it('il nome della stanza segue le stesse regole dell\'agente', () => {
    expect(roomNameError('Ambulatorio 2')).toBeUndefined();
    expect(roomNameError('   ')).toMatch(/Scrivi il nome/);
    expect(roomNameError('è'.repeat(40))).toBeUndefined();
    expect(roomNameError('x'.repeat(41))).toMatch(/40 caratteri/);
    expect(roomNameError('Stanza\u0007')).toMatch(/non validi/);
    expect(cleanRoom('  Sala   1 ')).toBe('Sala 1');
  });
});

describe('protezione dal cambio di rapporto', () => {
  it('una misura si unisce solo al rapporto della stessa rete, dello stesso PC e della stessa origine', () => {
    const t = surveyTargetOf(demoScan, true);
    expect(t).toEqual({ live: true, host: demoScan.agent.host, gateway: demoScan.gateway?.ip, ssid: 'Casa-Rossi' });
    expect(sameSurveyTarget(t, demoScan, 'agent')).toBe(true);
    expect(sameSurveyTarget(t, demoScan, 'demo')).toBe(false); // misura reale, rapporto dimostrativo
    expect(sameSurveyTarget(t, demoScan, 'file')).toBe(false); // mai in un rapporto importato
    expect(sameSurveyTarget({ ...t, live: false }, demoScan, 'demo')).toBe(true);
    expect(sameSurveyTarget({ ...t, live: false }, clinicScan, 'demo')).toBe(false); // altra demo
    expect(sameSurveyTarget({ ...t, gateway: '10.0.0.1' }, demoScan, 'agent')).toBe(false);
    const noWifi = clone(demoScan);
    delete noWifi.wifi;
    expect(sameSurveyTarget(t, noWifi, 'agent')).toBe(false);
    expect(sameSurveyTarget(undefined, demoScan, 'agent')).toBe(false);
  });

  it('un\'altra rete Wi-Fi con lo stesso gateway (192.168.1.1) è un altro bersaglio', () => {
    const office = clone(demoScan);
    office.wifi!.connected!.ssid = 'Ufficio-Bianchi';
    delete office.wifi!.survey;
    const home = surveyTargetOf(demoScan, true);
    expect(office.gateway?.ip).toBe(demoScan.gateway?.ip);
    expect(sameSurveyTarget(home, office, 'agent')).toBe(false);
    // Salvataggio locale: chiavi diverse per reti diverse con lo stesso gateway.
    expect(storeKey(home)).not.toBe(storeKey(surveyTargetOf(office, true)));
    expect(storeKey({ live: true, host: 'PC', gateway: '192.168.1.1', ssid: 'Casa.Rossi 2' })).toBe('polaris.wifimap.PC.192.168.1.1.Casa.Rossi%202');
    // Dalla memoria si riprendono solo le misure della rete del rapporto.
    const mixed: WifiSurvey = { rooms: [{ name: 'Studio', samples: [pt({ ssid: 'Casa-Rossi' }), pt({ ssid: 'Ufficio-Bianchi', startedAt: '2026-10-31T10:00:00Z' })] }, { name: 'Sala', samples: [pt({ ssid: 'Ufficio-Bianchi' })] }] };
    expect(onlyNetwork(mixed, 'Casa-Rossi')!.rooms.map((r) => `${r.name}:${r.samples.length}`)).toEqual(['Studio:1']);
    expect(onlyNetwork(mixed, 'Altra')).toBeUndefined();
    // La misura deve essere della rete del rapporto: il PC può aver cambiato rete dopo l'analisi.
    const s = simulatedSample(demoScan, 'Cucina', 15, true, new Date('2026-10-31T10:00:00Z'));
    expect(surveyRefusal(home, demoScan, 'agent', s)).toBeUndefined();
    expect(surveyRefusal(home, demoScan, 'agent', { ...s, ssid: 'Ufficio-Bianchi' })).toMatch(/rete Wi-Fi diversa/);
    expect(surveyRefusal(home, office, 'agent', s)).toMatch(/rapporto mostrato è un altro/);
  });
});

describe('mappa salvata sul PC e rapporti esportati', () => {
  let store: Record<string, string>;
  beforeEach(() => {
    store = {};
    vi.stubGlobal('localStorage', {
      getItem: (k: string) => store[k] ?? null,
      setItem: (k: string, v: string) => {
        store[k] = v;
      },
      removeItem: (k: string) => {
        delete store[k];
      },
    });
  });
  afterEach(() => vi.unstubAllGlobals());

  const t = { live: true, host: 'PC-1', gateway: '192.168.1.1', ssid: 'Casa' };
  const studio = pt({ room: 'Studio', bssids: ['aa:bb:cc:00:00:10'] });
  const cucina = pt({ room: 'Cucina', startedAt: '2026-10-31T11:00:00Z', bssids: ['aa:bb:cc:00:00:20'] });

  it("una mappa riaperta da un rapporto esportato non sostituisce quella salvata, più recente", () => {
    // Salvata sul PC: Studio, poi Cucina misurata dopo l'esportazione.
    const saved: WifiSurvey = { rooms: [{ name: 'Studio', samples: [studio] }, { name: 'Cucina', samples: [cucina] }] };
    store[storeKey(t)] = JSON.stringify(saved);
    // Il rapporto esportato prima della Cucina: al posto dei BSSID ci sono gli alias.
    const exported = surveyForExport(withSurvey({ rooms: [{ name: 'Studio', samples: [studio] }] })).wifi!.survey!;
    expect(exported.rooms[0].samples[0].bssids).toEqual(['AP A']);
    let shown: WifiSurvey | undefined = exported;
    syncStored(t, exported, true, (s) => (shown = s));
    expect(JSON.parse(store[storeKey(t)])).toEqual(saved);
    // Al suo posto si mostra la mappa salvata per questo PC e questa rete.
    expect(shown).toEqual(saved);
    // Nemmeno dopo, con una misura nuova aggiunta alla mappa importata.
    const salotto = pt({ room: 'Salotto', startedAt: '2026-10-31T12:00:00Z', bssids: ['aa:bb:cc:00:00:30'] });
    syncStored(t, mergeSample(exported, salotto), false, () => undefined);
    expect(JSON.parse(store[storeKey(t)])).toEqual(saved);
  });

  it("con l'agente la mappa del rapporto si salva, e senza mappa si riprende quella salvata", () => {
    const mine: WifiSurvey = { rooms: [{ name: 'Studio', samples: [studio] }] };
    let shown: WifiSurvey | undefined;
    syncStored(t, undefined, true, (s) => (shown = s));
    expect(shown).toBeUndefined(); // niente da riprendere
    syncStored(t, mine, false, (s) => (shown = s));
    expect(JSON.parse(store[storeKey(t)])).toEqual(mine);
    syncStored(t, undefined, true, (s) => (shown = s));
    expect(shown).toEqual(mine);
    // Stanze tolte: si tolgono anche dalla memoria.
    syncStored(t, undefined, false, () => undefined);
    expect(store[storeKey(t)]).toBeUndefined();
  });
});

describe('demo', () => {
  it('casa: quattro stanze dalla più debole, con un punto in più nello studio', () => {
    const rooms = surveyRooms(demoScan.wifi!.survey);
    expect(rooms.map((r) => `${r.room.name}:${r.severity}`)).toEqual(['Bagno:crit', 'Camera:warn', 'Studio:info', 'Soggiorno:ok']);
    expect(demoScan.wifi!.survey).toEqual(homeSurvey);
    expect(rooms.find((r) => r.room.name === 'Studio')!.room.samples).toHaveLength(2);
    const camera = rooms.find((r) => r.room.name === 'Camera')!;
    expect(camera.issues.map((i) => i.id)).toEqual(expect.arrayContaining(['loss', 'band', 'busy', 'cochannel']));
    const bagno = rooms.find((r) => r.room.name === 'Bagno')!;
    expect(bagno.issues.map((i) => i.id)).toEqual(expect.arrayContaining(['signal', 'unstable', 'loss', 'jitter']));
  });

  it('clinica: accettazione ottima, corridoio della radiologia critico, un client appiccicoso e un roaming da fermo', () => {
    const rooms = surveyRooms(clinicScan.wifi!.survey);
    expect(rooms[0].room.name).toBe('Corridoio radiologia');
    expect(rooms[0].severity).toBe('crit');
    expect(rooms[rooms.length - 1].room.name).toBe('Accettazione');
    expect(clinicScan.wifi!.survey).toEqual(clinicSurvey);
    const amb2 = rooms.find((r) => r.room.name === 'Ambulatorio 2')!;
    expect(amb2.issues.map((i) => i.id)).toEqual(expect.arrayContaining(['sticky', 'loss']));
    const attesa = rooms.find((r) => r.room.name === "Sala d'attesa")!;
    expect(attesa.issues.map((i) => i.id)).toEqual(expect.arrayContaining(['roam', 'busy']));
  });

  it('le statistiche delle demo sono quelle delle loro letture', () => {
    for (const sv of [homeSurvey, clinicSurvey])
      for (const r of sv.rooms)
        for (const s of r.samples) {
          const st = seriesStats(s.rssi);
          expect([s.medianDbm, s.minDbm, s.maxDbm, s.p10Dbm, s.spreadDb], `${r.name}`).toEqual([st.medianDbm, st.minDbm, st.maxDbm, st.p10Dbm, st.spreadDb]);
          expect(s.rssi).toHaveLength(s.seconds);
          expect(s.room).toBe(r.name);
        }
  });

  it('la misura simulata dipende solo dal nome e usa le reti della demo', () => {
    const at = new Date('2026-10-31T10:00:00Z');
    const a = simulatedSample(demoScan, 'Cucina', 15, true, at);
    expect(simulatedSample(demoScan, '  cucina ', 15, true, at)).toEqual({ ...a, room: '  cucina ' });
    expect(a.ssid).toBe('Casa-Rossi');
    expect(a.rssi).toHaveLength(15);
    expect(['a4:2b:b0:11:22:33', 'a4:2b:b0:11:22:34']).toContain(a.bssids[0]);
    expect(a.gateway?.target).toBe('192.168.1.1');
    expect(a.scan?.neighbors.visible).toBeGreaterThan(0);
    const st = seriesStats(a.rssi);
    expect(a.medianDbm).toBe(st.medianDbm);
    // Senza scansione: niente reti.
    expect(simulatedSample(demoScan, 'Cucina', 10, false, at).scan).toBeUndefined();
    // Nessun nome o BSSID dei vicini nella misura.
    const json = JSON.stringify(a);
    for (const n of demoScan.wifi!.networks.filter((b) => b.ssid !== 'Casa-Rossi')) {
      if (n.ssid) expect(json).not.toContain(n.ssid);
      expect(json).not.toContain(n.bssid);
    }
  });
});

describe('documento, rapporto ed esportazione', () => {
  it('il documento ha la mappa con gli alias degli access point, mai i BSSID né i vicini', () => {
    const { body } = documentParts(clinicScan, analyze(clinicScan), { version: '0.10.0', generated: 'oggi' });
    expect(body).toContain('<h2>Mappa del Wi-Fi per stanza</h2>');
    expect(body).toContain('Corridoio radiologia');
    expect(body).toContain('AP A');
    const sec = body.slice(body.indexOf('<h2>Mappa del Wi-Fi per stanza</h2>'));
    const end = sec.indexOf('</section>');
    const html = sec.slice(0, end);
    expect(html).not.toMatch(/[0-9a-f]{2}(:[0-9a-f]{2}){5}/i);
    for (const n of ['Farmacia-Centrale', 'Studio-Dentistico', 'TIM-81726354']) expect(html).not.toContain(n);
    // Senza mappa, nessuna sezione.
    const s = clone(clinicScan);
    delete s.wifi!.survey;
    expect(documentParts(s, analyze(s)).body).not.toContain('Mappa del Wi-Fi per stanza');
  });

  it('il documento dichiara i dBm stimati anche nelle stanze a posto, e al massimo della scala scrive "almeno"', () => {
    // La cella "Segnale" della stanza: nel documento il giudizio delle stanze a posto non compare.
    const cell = (s: SurveySample) => {
      const scan = withSurvey({ rooms: [{ name: 'Studio', samples: [s] }] });
      const body = documentParts(scan, analyze(scan)).body;
      const sec = body.slice(body.indexOf('<h2>Mappa del Wi-Fi per stanza</h2>'));
      const row = sec.slice(sec.indexOf('<b>Studio</b>'));
      return row.slice(row.indexOf('</td><td>') + 9, row.indexOf('</td>', row.indexOf('</td><td>') + 9));
    };
    const all = (v: number) => ({ rssi: Array(15).fill(v), medianDbm: v, minDbm: v, maxDbm: v, p10Dbm: v, spreadDb: 0 });
    // Misurati: nessuna stima dichiarata, -50 è un valore esatto.
    expect(cell(pt({}))).toMatch(/^-63 dBm, buono/);
    expect(cell(pt({}))).not.toContain('stimati');
    expect(cell(pt({ ...all(-50), stuck: true }))).toMatch(/^-50 dBm, ottimo/);
    // Stimati dalla qualità di Windows: lo dice la cella, anche se la stanza è a posto e il giudizio non si stampa.
    const studio = (s: SurveySample) => analyze(withSurvey({ rooms: [{ name: 'Studio', samples: [s] }] })).findings.find((f) => f.id === 'wifi.room.studio')!;
    expect(studio(pt({ estimated: true })).severity).toBe('ok');
    expect(studio(pt({ ...all(-50), estimated: true })).severity).toBe('ok');
    const est = cell(pt({ estimated: true }));
    expect(est).toMatch(/^-63 dBm, buono/);
    expect(est).toContain('cali fino a -64 dBm');
    expect(est).toContain('stimati dalla qualità del segnale di Windows');
    // Qualità al 100 %: -50 dBm è solo un minimo, e i cali sopra -50 dBm non si vedono.
    const top = cell(pt({ ...all(-50), estimated: true }));
    expect(top).toMatch(/^almeno -50 dBm, ottimo/);
    expect(top).not.toContain('cali fino a -50');
    expect(top).toContain('cali non misurabili sopra -50 dBm');
    expect(top).toContain('stimati dalla qualità del segnale di Windows');
    // Mediana al massimo ma cali sotto: i cali restano un valore stimato.
    const dip = cell(pt({ rssi: [-50, -50, -50, -50, -50, -50, -50, -50, -50, -50, -50, -50, -53, -54, -55], medianDbm: -50, minDbm: -55, maxDbm: -50, p10Dbm: -54, spreadDb: 5, estimated: true }));
    expect(dip).toMatch(/^almeno -50 dBm, ottimo/);
    expect(dip).toContain('cali fino a -54 dBm');
    // La nota in fondo spiega la stima solo se c'è.
    const note = (s: SurveySample) => {
      const scan = withSurvey({ rooms: [{ name: 'Studio', samples: [s] }] });
      const body = documentParts(scan, analyze(scan)).body;
      return body.slice(body.indexOf('<h2>Mappa del Wi-Fi per stanza</h2>')).split('</section>')[0];
    };
    expect(note(pt({ estimated: true }))).toContain('da -100 a -50 dBm');
    expect(note(pt({}))).not.toContain('da -100 a -50 dBm');
  });

  it('il rapporto di testo elenca le stanze entro 90 colonne, con gli alias', () => {
    const txt = renderText(demoScan, analyze(demoScan), { verbose: true });
    expect(txt).toContain('MAPPA DEL WI-FI PER STANZA');
    const start = txt.indexOf('MAPPA DEL WI-FI PER STANZA');
    const end = txt.indexOf('INFRASTRUTTURA', start);
    const sec = txt.slice(start, end > 0 ? end : undefined);
    expect(sec).toContain('[CRIT] Bagno');
    expect(sec).toContain('access point: AP');
    expect(sec).not.toMatch(/[0-9a-f]{2}(:[0-9a-f]{2}){5}/i);
    for (const line of txt.split('\n')) expect(line.length, line).toBeLessThanOrEqual(90);
    // I giudizi delle stanze non contengono BSSID.
    for (const f of analyze(clinicScan).findings.filter((x) => x.id.startsWith('wifi.room.'))) expect(f.verdict).not.toMatch(/[0-9a-f]{2}(:[0-9a-f]{2}){5}/i);
  });

  it('l\'esportazione JSON sostituisce i BSSID della mappa con gli alias e tiene i nomi delle stanze', () => {
    const out = surveyForExport(clinicScan);
    const sv = JSON.stringify(out.wifi!.survey);
    expect(sv).not.toMatch(/[0-9a-f]{2}(:[0-9a-f]{2}){5}/i);
    expect(sv).toContain('"AP A"');
    expect(sv).toContain("Sala d'attesa");
    expect(out.wifi!.networks).toBe(clinicScan.wifi!.networks); // il resto non cambia
    expect(clinicScan.wifi!.survey!.rooms[0].samples[0].bssids[0]).toMatch(/^44:48/); // l'originale resta intatto
    const al = surveyAliases(clinicScan.wifi!.survey);
    const roam = out.wifi!.survey!.rooms.find((r) => r.name === "Sala d'attesa")!.samples[0].roams[0];
    expect([roam.from, roam.to]).toEqual([al('44:48:c1:a0:20:d0'), al('44:48:c1:a0:30:d0')]);
    // Un rapporto senza mappa esce identico.
    expect(surveyForExport(base())).toEqual(base());
    // Lo stesso giudizio prima e dopo l'esportazione.
    const sevs = (s: Scan) => analyze(s).findings.filter((f) => f.id.startsWith('wifi.room.')).map((f) => `${f.id}:${f.severity}`);
    expect(sevs(out)).toEqual(sevs(clinicScan));
    // Un rapporto esportato e riaperto: gli alias restano tali, una seconda esportazione non cambia nulla.
    const again = surveyAliases(out.wifi!.survey);
    expect(again('AP A')).toBe('AP A');
    expect(again('AP B')).toBe('AP B');
    expect(surveyForExport(out)).toEqual(out);
    // I BSSID veri hanno sempre un alias.
    expect(al('44:48:C1:A0:20:D0')).toMatch(/^AP [A-Z]$/);
  });

  it('un alias scritto in un punto importato non va a un altro access point', () => {
    // Un punto riaperto da un rapporto esportato ("AP A") e uno misurato dopo, con il BSSID vero.
    const old = pt({ bssids: ['AP A'], scan: { ...good.scan!, alternatives: [{ bssid: 'AP B', band: '5', channel: 44, rssiDbm: -70 }] } });
    const now = pt({ startedAt: '2026-10-31T10:00:00Z', bssids: ['aa:bb:cc:00:00:30'], roams: [] });
    for (const samples of [
      [old, now],
      [now, old],
    ]) {
      const sv: WifiSurvey = { rooms: [{ name: 'Studio', samples }] };
      const al = surveyAliases(sv);
      expect(al('AP A')).toBe('AP A');
      expect(al('AP B')).toBe('AP B');
      expect(al('aa:bb:cc:00:00:30')).toBe('AP C');
      const out = surveyForExport(withSurvey(sv)).wifi!.survey!.rooms[0].samples;
      expect(out.map((s) => s.bssids[0]).sort()).toEqual(['AP A', 'AP C']);
    }
  });

  it('il motore della riga di comando (ES2015, goja) dà gli stessi giudizi, documento e rapporto', async () => {
    const entry = fileURLToPath(new URL('../src/engine/global.ts', import.meta.url));
    const out = await build({ entryPoints: [entry], bundle: true, format: 'iife', target: 'es2015', write: false });
    const ctx: Record<string, unknown> = {};
    ctx.globalThis = ctx;
    vm.createContext(ctx);
    vm.runInContext(out.outputFiles[0].text, ctx);
    const engine = ctx.PolarisEngine as { analyzeJson(s: string): string; reportText(s: string, v: boolean): string; reportHtml(s: string, v: string, g: string): string };
    for (const s of [demoScan, clinicScan]) {
      const json = JSON.stringify(s);
      expect(JSON.parse(engine.analyzeJson(json))).toEqual(JSON.parse(JSON.stringify(analyze(s))));
      expect(engine.reportText(json, true)).toBe(renderText(s, analyze(s), { verbose: true }));
      expect(engine.reportHtml(json, '0.10.0', 'oggi')).toContain('<h2>Mappa del Wi-Fi per stanza</h2>');
    }
  });
});

describe('knowledge base e guide', () => {
  it('la metrica dichiara le soglie scelte da Polaris e quelle con fonte', () => {
    const m = METRICS['wifi.survey'];
    expect(m.scale?.map((s) => s.severity)).toEqual(['ok', 'ok', 'info', 'warn', 'crit']);
    for (const k of ['Cisco', 'Juniper Mist', 'Microsoft Teams', 'scelte di Polaris', 'da verificare', 'questo PC', 'SNR', 'posizione', 'ignorano', 'qualità del segnale']) expect(m.limits, k).toContain(k);
    for (const id of ['survey-place-ap', 'band-steering', 'avoid-24-interference', 'wired-backhaul']) expect(ACTIONS[id], id).toBeDefined();
  });

  it('la guida spiega come misurare e collega misura e azioni', () => {
    const g = guideById('wifi-stanza-per-stanza')!;
    expect(g.chapter).toBe('wifi');
    expect(guidesForMetric('wifi.survey').map((x) => x.id)).toContain('wifi-stanza-per-stanza');
    expect(g.actions).toEqual(expect.arrayContaining(['survey-place-ap', 'band-steering', 'avoid-24-interference', 'wired-backhaul', 'fix-roaming']));
    const text = JSON.stringify(g.blocks);
    for (const k of ['ITU-R P.1238', 'indicazioni generali', '-67 dBm', '-72 dBm', '(P)', 'RFC 5481', 'nomi di luogo', 'icona della posizione', 'SNR', 'questo PC', '6 GHz', 'ignorano i ping', 'qualità del segnale']) expect(text, k).toContain(k);
  });

  it('il glossario ha i termini della mappa', () => {
    const terms = GLOSSARY.map((t) => t.term);
    for (const t of ['dBm', 'Roaming', 'Jitter', 'Band steering', 'BSS Load', 'Percentile', 'Mediana', 'Attenuazione']) expect(terms, t).toContain(t);
  });

  it('la guida d\'uso elenca la mappa e il comando', () => {
    const uso = JSON.stringify([guideById('strumenti-avanzati')!.blocks, guideById('riga-di-comando')!.blocks]);
    expect(uso).toContain('mappa del Wi-Fi per stanza');
    expect(uso).toContain('polaris-cli wifi-survey STANZA');
    expect(uso).toContain('--senza-scansione');
  });
});
