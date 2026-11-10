import { describe, expect, it } from 'vitest';
import { ACTIONS, analyze, discoveredNets, METRICS, netLabel, renderDocument, segmentationTargets, switchPort } from '../src/engine';
import type { Scan } from '../src/engine';
import { clinicScan } from '../src/demo/clinic';
import { demoScan } from '../src/demo/sample';
import { simulatedAD, simulatedL2, simulatedRemoteInventory, simulatedSnmp } from '../src/demo/discovery';

const withL2 = (s: Scan): Scan => ({ ...s, infra: { ...s.infra, discovery: { ...s.infra?.discovery, l2: simulatedL2(s) } } });

describe('scoperta delle reti e delle VLAN', () => {
  it('unisce rotte, switch, Active Directory e SNMP in un elenco di reti con le fonti', () => {
    const nets = discoveredNets(withL2(clinicScan));
    const local = nets[0];
    expect(local.local).toBe(true);
    expect(local.prefix).toBe('10.20.30.0/24');
    expect(local.vlan).toBe(30);
    expect(local.name).toBe('AMBULATORI');
    const med = nets.find((n) => n.vlan === 60)!;
    expect(med.prefix).toBe('10.20.60.0/24');
    expect(med.name).toBe('MEDICALI');
    expect(med.routers).toEqual(['10.20.60.1']);
    expect(med.hosts).toEqual(['10.20.60.15', '10.20.60.16', '10.20.60.17']);
    expect(med.sources).toContain('SNMP FW-CLINICA');
    // Server DNS e DHCP del PC nella VLAN 10, non tra i dispositivi da isolare.
    const srv = nets.find((n) => n.vlan === 10)!;
    expect(srv.servers).toEqual(['10.10.10.10', '10.10.10.11']);
    expect(srv.hosts).toEqual(['10.10.10.25']);
    // La /16 di Active Directory è un aggregato; il secondo sito resta una rete a sé.
    expect(nets.find((n) => n.prefix === '10.20.0.0/16')?.contains).toBeGreaterThan(5);
    expect(nets.find((n) => n.prefix === '10.30.0.0/16')?.site).toBe('Poliambulatorio-Nord');
    // VLAN 1 (presente su ogni switch) e voce: la 1 no, la 100 sì e marcata.
    expect(nets.some((n) => n.vlan === 1)).toBe(false);
    expect(nets.find((n) => n.vlan === 100)?.voice).toBe(true);
    expect(netLabel(med)).toBe('VLAN 60 MEDICALI');
    // La rete del PC per prima, poi le VLAN in ordine.
    const vl = nets.filter((n) => n.vlan && !n.local).map((n) => n.vlan!);
    expect(vl).toEqual([...vl].sort((a, b) => a - b));
  });

  it('propone destinazioni per il test di segmentazione senza router e con i server DNS', () => {
    const t = segmentationTargets(clinicScan);
    expect(t.filter((x) => x.label === 'VLAN 60 MEDICALI').map((x) => x.host)).toEqual(['10.20.60.15', '10.20.60.16']);
    expect(t.some((x) => /\.1$/.test(x.host) && x.expect === 'isolated')).toBe(false);
    expect(t.find((x) => x.host === '10.10.10.10')).toMatchObject({ port: 53, expect: 'reachable' });
    // Reti dei server (nome o server del PC) e servizi critici già verificati: mai "da isolare".
    expect(t.some((x) => x.expect === 'isolated' && /^10\.(20\.50|10\.10)\./.test(x.host))).toBe(false);
    expect(t.filter((x) => x.label === 'VLAN 999 GESTIONE').map((x) => x.host)).toEqual(['10.0.0.11', '10.0.0.12']);
    expect(t.length).toBeLessThanOrEqual(32);
    for (const x of t) expect(x.host).toMatch(/^10\./);
  });

  it('legge la porta dello switch e giudica DTP, Spanning Tree e SNMP', () => {
    const scan = withL2(clinicScan);
    const sp = switchPort(scan)!;
    expect(sp).toMatchObject({ name: 'SW-PIANO1.clinica.local', port: 'Gi1/0/12', vlan: 30, voiceVlan: 100, speedMbps: 1000, protocol: 'LLDP' });
    const a = analyze(scan);
    const f = (id: string) => a.findings.find((x) => x.id === id);
    expect(f('lan.switchport')).toMatchObject({ severity: 'info', category: 'infra' });
    expect(f('lan.switchport')!.verdict).toContain('VLAN 30');
    expect(f('lan.dtp')).toMatchObject({ severity: 'warn', actions: ['disable-dtp'] });
    expect(f('lan.stp')!.actions).toContain('stp-root');
    expect(f('lan.stp')!.verdict).toContain('priorità predefinita');
    expect(f('lan.vlan1')).toBeUndefined();
    expect(f('lan.snmp.10.0.0.2')).toMatchObject({ severity: 'warn', actions: ['snmp-harden'] });
    expect(f('lan.snmp.10.20.30.1')).toMatchObject({ severity: 'ok' });
    expect(f('lan.vlans')).toMatchObject({ severity: 'info', actions: ['test-segmentation'] });
    for (const x of a.findings) {
      expect(METRICS[x.metric], x.id).toBeDefined();
      for (const id of x.actions) expect(ACTIONS[id], id).toBeDefined();
    }
  });

  it('segnala la community predefinita, la porta in trunk e la VLAN 1 con altre VLAN', () => {
    const l2 = simulatedL2(clinicScan);
    l2.dtp = [{ version: 1, operStatus: 'trunk', adminStatus: 'desirable', frames: 1 }];
    l2.lldp = [{ ...l2.lldp![0], portVlanId: 1, duplex: 'half', speedMbps: 100 }];
    l2.cdp = [];
    const snmp = [simulatedSnmp(clinicScan, '10.0.0.2', true)];
    const scan: Scan = { ...clinicScan, infra: { ...clinicScan.infra, discovery: { ...clinicScan.infra!.discovery, l2, snmp } } };
    const a = analyze(scan);
    const f = (id: string) => a.findings.find((x) => x.id === id);
    expect(f('lan.dtp')!.severity).toBe('crit');
    expect(f('lan.vlan1')).toMatchObject({ severity: 'warn', actions: ['move-off-vlan1'] });
    expect(f('lan.switchport')).toMatchObject({ severity: 'warn', actions: ['check-duplex'] });
    expect(f('lan.snmp.10.0.0.2')!.severity).toBe('crit');
    expect(f('lan.snmp.10.0.0.2')!.verdict).toContain('community predefinita');
  });

  it('dice quando lo switch tace e non inventa nulla nella rete di casa', () => {
    const home = analyze(withL2(demoScan));
    expect(home.findings.filter((f) => f.id.startsWith('lan.') && ['lan.vlans', 'lan.dtp', 'lan.stp', 'lan.vlan1'].indexOf(f.id) >= 0)).toEqual([]);
    expect(simulatedAD(demoScan).read).toBe('nodomain');
    expect(() => simulatedSnmp(demoScan, '192.168.1.1', true)).toThrow(/nessuna risposta/);
    const none: Scan = { ...demoScan, adapters: demoScan.adapters.map((x) => (x.kind === 'ethernet' ? { ...x, up: true, ipv4: ['192.168.1.30/24'] } : x)) };
    const a = analyze(withL2(none));
    expect(a.findings.find((f) => f.id === 'lan.switchport')).toMatchObject({ severity: 'unknown', value: 'nessun annuncio' });
  });

  it('mette le reti scoperte nel documento stampabile, senza credenziali', () => {
    const scan = withL2(clinicScan);
    const html = renderDocument(scan, analyze(scan));
    expect(html).toContain('<h2>Reti e VLAN</h2>');
    expect(html).toContain('VLAN 60 MEDICALI');
    expect(html).toContain('SW-PIANO1.clinica.local');
    expect(html).not.toMatch(/authPass|privPass|"community"/);
    // Nella rete di casa, senza letture, la sezione non c'è.
    expect(renderDocument(demoScan, analyze(demoScan))).not.toContain('<h2>Reti e VLAN</h2>');
  });

  it('aggiunge l\'inventario di un\'altra sottorete alle reti note', () => {
    const inv = simulatedRemoteInventory(clinicScan, '10.20.50.0/24');
    expect(inv.hosts.map((h) => h.ip)).toEqual(['10.20.50.10', '10.20.50.20', '10.20.50.30', '10.20.50.40']);
    expect(simulatedRemoteInventory(clinicScan, '10.20.60.0/24').hosts).toEqual([]);
    const scan: Scan = { ...clinicScan, infra: { ...clinicScan.infra, remote: [inv] } };
    const n = discoveredNets(scan).find((x) => x.prefix === '10.20.50.0/24')!;
    expect(n.sources).toContain('inventario attraverso il router');
    const a = analyze(scan);
    expect(a.findings.find((f) => f.id === 'infra.inventory.10.20.50.0/24')).toMatchObject({ severity: 'info', actions: ['test-segmentation'] });
  });
});
