import { describe, expect, it } from 'vitest';
import type { Scan, SpeedTest, WifiSurvey } from '../src/engine';
import { surveyForExport } from '../src/engine';
import { carryOver } from '../src/ui/App';
import { base } from './fixtures';

// "Nuova analisi": che cosa passa dal rapporto mostrato a quello nuovo.

const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));

/** Rapporto di un PC su una rete Wi-Fi: gateway 192.168.1.1 come moltissime reti. */
function report(host: string, ssid: string, mac?: string): Scan {
  const s = base();
  s.agent.host = host;
  s.wifi!.connected!.ssid = ssid;
  if (mac) s.gateway!.mac = mac;
  return s;
}

const speed: SpeedTest = {
  startedAt: '2026-10-31T09:00:00Z',
  durationMs: 30000,
  provider: 'mlab-ndt7',
  download: { mbps: 95, bytes: 1, ms: 1 },
};

function withSpeed(s: Scan): Scan {
  const out = clone(s);
  out.internet!.speed = speed;
  return out;
}

const infra = {
  inventory: { subnet: '192.168.1.0/24', scanned: 254, startedAt: '2026-10-31T08:00:00Z', durationMs: 9000, hosts: [] },
  certs: { checkedAt: '2026-10-31T08:10:00Z', results: [] },
};

const survey: WifiSurvey = {
  rooms: [
    {
      name: 'Studio',
      samples: [
        {
          room: 'Studio',
          startedAt: '2026-10-31T09:00:00Z',
          durationMs: 15200,
          seconds: 15,
          ssid: 'Casa-Rossi',
          rssi: [-63],
          medianDbm: -63,
          minDbm: -63,
          maxDbm: -63,
          p10Dbm: -63,
          spreadDb: 0,
          bssids: ['aa:bb:cc:00:00:10'],
          roams: [],
        },
      ],
    },
  ],
};

describe('nuova analisi: che cosa resta del rapporto mostrato', () => {
  it('il test di velocità di Internet resta solo per lo stesso PC sulla stessa rete (non basta lo stesso gateway)', () => {
    const home = withSpeed(report('PC-1', 'Casa-Rossi', 'aa:aa:aa:00:00:01'));
    // Altra rete Wi-Fi con lo stesso indirizzo del gateway: il test non le appartiene.
    expect(carryOver(home, 'agent', report('PC-1', 'Ufficio-Bianchi', 'bb:bb:bb:00:00:01')).internet!.speed).toBeUndefined();
    expect(carryOver(home, 'agent', report('PC-1', 'Ufficio-Bianchi')).internet!.speed).toBeUndefined();
    // Stesso nome della rete ma un altro router (MAC diverso): nemmeno.
    expect(carryOver(home, 'agent', report('PC-1', 'Casa-Rossi', 'bb:bb:bb:00:00:01')).internet!.speed).toBeUndefined();
    // Stessa rete: resta (il MAC si confronta solo se entrambi i rapporti lo conoscono).
    expect(carryOver(home, 'agent', report('PC-1', 'Casa-Rossi', 'AA:AA:AA:00:00:01')).internet!.speed).toEqual(speed);
    expect(carryOver(home, 'agent', report('PC-1', 'Casa-Rossi')).internet!.speed).toEqual(speed);
    // Altro PC.
    expect(carryOver(home, 'agent', report('PC-2', 'Casa-Rossi', 'aa:aa:aa:00:00:01')).internet!.speed).toBeUndefined();
    // Un rapporto importato o dimostrativo non passa mai nell'analisi nuova.
    expect(carryOver(home, 'file', report('PC-1', 'Casa-Rossi', 'aa:aa:aa:00:00:01')).internet!.speed).toBeUndefined();
    expect(carryOver(home, 'demo', report('PC-1', 'Casa-Rossi', 'aa:aa:aa:00:00:01')).internet!.speed).toBeUndefined();
    // Un test già nella nuova analisi non si tocca.
    const fresh = withSpeed(report('PC-1', 'Casa-Rossi'));
    fresh.internet!.speed = { ...speed, startedAt: '2026-10-31T10:00:00Z' };
    expect(carryOver(home, 'agent', fresh).internet!.speed!.startedAt).toBe('2026-10-31T10:00:00Z');
  });

  it("inventario e certificati di un rapporto importato non passano all'analisi di un altro PC con lo stesso gateway", () => {
    const amb03 = report('AMB-03', 'Clinica', 'aa:aa:aa:00:00:01');
    amb03.infra = clone({ ...infra, assessment: { answers: {}, updatedAt: '2026-10-31T08:00:00Z' } });
    const amb07 = report('AMB-07', 'Clinica', 'aa:aa:aa:00:00:01');
    expect(carryOver(amb03, 'file', amb07).infra).toBeUndefined();
    // Nemmeno dello stesso PC, se il rapporto è un file: le verifiche sono di allora.
    expect(carryOver(amb03, 'file', report('AMB-03', 'Clinica', 'aa:aa:aa:00:00:01')).infra).toBeUndefined();
    // Dall'agente: stesso PC e stessa rete sì, con l'autovalutazione tolta (sta nella memoria del PC).
    const kept = carryOver(amb03, 'agent', report('AMB-03', 'Clinica', 'aa:aa:aa:00:00:01')).infra;
    expect(kept?.inventory).toEqual(infra.inventory);
    expect(kept?.certs).toEqual(infra.certs);
    expect(kept?.assessment).toBeUndefined();
    // Dall'agente ma su un'altra rete o un altro PC: no.
    expect(carryOver(amb03, 'agent', report('AMB-03', 'Ospiti', 'aa:aa:aa:00:00:01')).infra).toBeUndefined();
    expect(carryOver(amb03, 'agent', report('AMB-03', 'Clinica', 'bb:bb:bb:00:00:01')).infra).toBeUndefined();
    expect(carryOver(amb03, 'agent', amb07).infra).toBeUndefined();
  });

  it('la mappa del Wi-Fi passa solo da un rapporto dell\'agente, mai da uno importato (con gli alias al posto dei BSSID)', () => {
    const live = report('PC-1', 'Casa-Rossi');
    live.wifi!.survey = clone(survey);
    expect(carryOver(live, 'agent', report('PC-1', 'Casa-Rossi')).wifi!.survey).toEqual(survey);
    const exported = surveyForExport(live);
    expect(exported.wifi!.survey!.rooms[0].samples[0].bssids).toEqual(['AP A']);
    expect(carryOver(exported, 'file', report('PC-1', 'Casa-Rossi')).wifi!.survey).toBeUndefined();
    expect(carryOver(live, 'demo', report('PC-1', 'Casa-Rossi')).wifi!.survey).toBeUndefined();
    expect(carryOver(live, 'agent', report('PC-1', 'Ufficio-Bianchi')).wifi!.survey).toBeUndefined();
  });

  it('senza rapporto precedente la nuova analisi resta com\'è', () => {
    const s = report('PC-1', 'Casa-Rossi');
    expect(carryOver(null, 'demo', s)).toBe(s);
  });
});
