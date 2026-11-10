import { describe, expect, it } from 'vitest';
import { analyze, buildNetworkMap, classifyHost, nearBssid } from '../src/engine';
import { labelKind, vlanIn } from '../src/engine/devicetype';
import type { InventoryHost, Scan } from '../src/engine';
import { clinicScan } from '../src/demo/clinic';
import { demoScan } from '../src/demo/sample';

// Mappa della rete: riconoscimento del tipo dei dispositivi, zone (sottoreti,
// VLAN, reti Wi-Fi), percorsi del traffico e disposizione senza sovrapposizioni.

const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const h = (p: Partial<InventoryHost>): InventoryHost => ({ ip: '192.168.1.50', ...p });

describe('riconoscimento del tipo', () => {
  it('ruolo, servizi, produttore, nome, TTL e MAC casuale', () => {
    expect(classifyHost(h({ ip: '192.168.1.1', gateway: true }), { gatewayIp: '192.168.1.1' }).kind).toBe('router');
    expect(classifyHost(h({ ip: '192.168.1.1', gateway: true }), { gatewayIp: '192.168.1.1', gatewayFirewall: true }).kind).toBe('firewall');
    const pr = classifyHost(h({ services: ['_ipp._tcp', '_pdl-datastream._tcp'] }));
    expect(pr).toMatchObject({ kind: 'printer', confidence: 'alta' });
    expect(pr.reasons[0]).toBe('annuncia il servizio di stampa');
    expect(classifyHost(h({ vendor: 'Hikvision' })).kind).toBe('camera');
    expect(classifyHost(h({ vendor: 'Synology', services: ['_smb._tcp'] })).kind).toBe('nas');
    expect(classifyHost(h({ name: 'BRN008077A1B2C3.home' })).kind).toBe('printer');
    expect(classifyHost(h({ upnp: ['urn:dial-multiscreen-org:service:dial:1'] })).kind).toBe('tv');
    expect(classifyHost(h({ roles: ['domain-controller'] })).kind).toBe('server');
    expect(classifyHost(h({ vendor: 'Yealink' })).kind).toBe('voip');
    expect(classifyHost(h({ mac: '00:15:5d:01:02:03' })).kind).toBe('vm');
    // AirPlay con la condivisione di file è un Mac, non una TV.
    expect(classifyHost(h({ services: ['_airplay._tcp', '_smb._tcp'] })).kind).toBe('laptop');
    const ph = classifyHost(h({ mac: 'da:a1:19:6b:22:01', randomMac: true }));
    expect(ph).toMatchObject({ kind: 'phone', confidence: 'bassa' });
    expect(classifyHost(h({ ttl: 128 })).kind).toBe('pc');
    expect(classifyHost(h({}))).toEqual({ kind: 'unknown', confidence: 'bassa', reasons: ['nessun segnale riconoscibile: il dispositivo risponde ma non si presenta'] });
  });

  it('access point dal BSSID vicino, nomi delle verifiche, numeri di VLAN', () => {
    expect(nearBssid('44:48:c1:a0:20:b0', ['44:48:c1:a0:20:d0'])).toBe('44:48:c1:a0:20:d0');
    expect(nearBssid('44:48:c1:a0:20:b0', ['44:48:c1:a0:90:d0'])).toBeUndefined();
    expect(classifyHost(h({ mac: '44:48:c1:a0:20:b0' }), { bssids: ['44:48:c1:a0:20:d0'] }).kind).toBe('ap');
    expect(labelKind('Pompe infusionali (VLAN 60)')).toBe('medical');
    expect(labelKind('PACS (DICOM)')).toBe('server');
    expect(labelKind('Telecamere (RTSP)')).toBe('camera');
    expect(labelKind('qualcosa')).toBeUndefined();
    expect(vlanIn('gw-vlan30.clinica.local')).toBe(30);
    expect(vlanIn('Pompe infusionali (VLAN 60)')).toBe(60);
    expect(vlanIn('vlan5000')).toBeUndefined();
    expect(vlanIn(undefined)).toBeUndefined();
  });
});

describe('mappa della rete', () => {
  it('clinica: zone, VLAN, reti Wi-Fi degli stessi access point e percorsi', () => {
    const m = buildNetworkMap(clinicScan, analyze(clinicScan));
    expect(m.fromInventory).toBe(true);
    expect(m.counts).toMatchObject({ firewall: 1, ap: 2, printer: 2, pc: 11 });
    const local = m.segments.find((s) => s.kind === 'local')!;
    expect(local).toMatchObject({ subnet: '10.20.30.0/24', vlan: 30 });
    expect(m.segments.find((s) => s.vlan === 60)?.label).toBe('VLAN 60 · 10.20.60.0/24');
    expect(m.segments.filter((s) => s.kind === 'wifi').map((s) => s.label).sort()).toEqual(['Rete Wi-Fi nascosta', 'Wi-Fi «Clinica-Ospiti»']);
    const inet = m.flows.find((f) => f.kind === 'internet')!;
    expect(inet.path).toEqual(['ip:10.20.30.57', 'ip:10.20.30.202', 'ip:10.20.30.1', 'internet']);
    const blocked = m.flows.filter((f) => f.kind === 'blocked');
    expect(blocked.find((f) => f.label === 'Gestione switch (SSH)')?.sev).toBe('crit');
    expect(blocked.find((f) => f.label.startsWith('Pompe'))?.sev).toBe('ok');
    expect(m.nodes.find((n) => n.ip === '10.20.60.15')?.kind).toBe('medical');
  });

  it('casa: router con il Wi-Fi, operatore con indirizzi privati, nessun secondo router', () => {
    const m = buildNetworkMap(demoScan, analyze(demoScan));
    const gw = m.nodes.find((n) => n.gateway)!;
    expect(gw.kind).toBe('router');
    expect(gw.roles).toContain('Wi-Fi «Casa-Rossi»');
    expect(m.nodes.find((n) => n.self)?.kind).toBe('laptop');
    expect(m.nodes.some((n) => n.label === 'Secondo router')).toBe(false);
    expect(m.nodes.find((n) => n.kind === 'isp')?.reasons[0]).toContain('indirizzi privati');
    expect(m.flows.find((f) => f.kind === 'internet')?.path).toEqual(['ip:192.168.1.34', 'ip:192.168.1.1', 'isp', 'internet']);
    expect(m.counts).toMatchObject({ nas: 1, printer: 1, camera: 1, tv: 1, iot: 3, phone: 1, pc: 1 });
  });

  it('secondo router subito dopo il gateway (doppio NAT)', () => {
    const s: Scan = clone(demoScan);
    s.internet!.traceroute = [{ ttl: 1, ip: '192.168.1.1', rttMs: 2.1 }, { ttl: 2, ip: '192.168.0.1', rttMs: 3.0 }, { ttl: 3, ip: '93.40.0.17', rttMs: 14 }];
    const m = buildNetworkMap(s);
    const r2 = m.nodes.find((n) => n.label === 'Secondo router')!;
    expect(r2).toMatchObject({ kind: 'router', inferred: true, ip: '192.168.0.1' });
    expect(m.flows.find((f) => f.kind === 'internet')?.path).toEqual(['ip:192.168.1.34', 'ip:192.168.1.1', 'ip:192.168.0.1', 'isp', 'internet']);
  });

  it('senza inventario usa i dispositivi visti dal PC e lo dice', () => {
    const s: Scan = clone(demoScan);
    delete s.infra;
    const m = buildNetworkMap(s);
    expect(m.fromInventory).toBe(false);
    expect(m.nodes.filter((n) => n.segment === 'seg:local').length).toBe(6);
    expect(m.notes[0]).toContain('inventario');
  });

  it('disposizione: zone che non si sovrappongono, dispositivi dentro la propria zona', () => {
    for (const s of [demoScan, clinicScan]) {
      const m = buildNetworkMap(s, analyze(s));
      for (let i = 0; i < m.segments.length; i++)
        for (let j = i + 1; j < m.segments.length; j++) {
          const a = m.segments[i];
          const b = m.segments[j];
          const overlap = a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;
          expect(overlap, `${a.id} e ${b.id}`).toBe(false);
        }
      for (const n of m.nodes) {
        expect(Number.isFinite(n.x) && Number.isFinite(n.y), n.id).toBe(true);
        const z = m.segments.find((x) => x.id === n.segment);
        if (z) expect(n.x > z.x && n.x < z.x + z.w && n.y > z.y && n.y < z.y + z.h, n.id).toBe(true);
        expect(n.x >= 0 && n.x <= m.width && n.y >= 0 && n.y <= m.height, n.id).toBe(true);
      }
    }
  });
});
