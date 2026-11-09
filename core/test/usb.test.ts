import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { ACTIONS, analyze, documentParts, METRICS, usbDeviceLabel, usbNodes, usbSlow, usbSlowReason } from '../src/engine';
import type { Finding, Scan, UsbDevice, UsbInfo } from '../src/engine';
import { clinicScan } from '../src/demo/clinic';
import { demoScan } from '../src/demo/sample';
import { guideById } from '../src/guides';
import { UsbCard } from '../src/ui/usb';

// Albero USB: porte in errore e dispositivi USB 3 a velocità USB 2.

const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const find = (s: Scan, id: string): Finding | undefined => analyze(s).findings.find((f) => f.id === id);

const ssd = (over: Partial<UsbDevice> = {}): UsbDevice => ({ name: 'Acme Portable SSD', vid: 'ACE1', pid: '5301', kind: 'storage', speed: 'high', canSuper: true, ...over });

describe('porte USB', () => {
  it('casa: nessuna porta in errore; clinica: masterizzatore senza corrente dietro un hub senza alimentatore', () => {
    const h = find(clone(demoScan), 'pc.usb.ports')!;
    expect(h.severity).toBe('ok');
    expect(h.value).toBe('4 dispositivi, nessuna porta in errore');
    const c = find(clone(clinicScan), 'pc.usb.ports')!;
    expect(c.severity).toBe('warn');
    expect(c.value).toBe('1 porta in errore');
    expect(c.verdict).toContain('porta 4 dell\'hub Genesys Logic USB2.0 Hub, Acme Slim DVD Writer: corrente insufficiente');
    expect(c.actions).toEqual(['usb-port-error']);
    expect(find(clone(clinicScan), 'pc.usb.speed')).toBeUndefined();
  });

  it('sovraccarico, nessun controller (macchina virtuale), lettura non riuscita', () => {
    const s = clone(demoScan);
    s.pc!.usb!.controllers[0].hub!.ports[0].status = 'overcurrent';
    const f = find(s, 'pc.usb.ports')!;
    expect(f.severity).toBe('warn');
    expect(f.verdict).toContain('sovraccarico elettrico');
    expect(f.verdict).toContain('Scollega subito il dispositivo');
    s.pc!.usb = { read: 'none', controllers: [] };
    expect(find(s, 'pc.usb.ports')).toBeUndefined();
    s.pc!.usb = { read: 'error', controllers: [] };
    expect(find(s, 'pc.usb.ports')!.severity).toBe('unknown');
  });
});

describe('velocità dei dispositivi USB', () => {
  it('casa: SSD USB 3 collegato in USB 2 a una porta USB 3 (colpa del cavo)', () => {
    const f = find(clone(demoScan), 'pc.usb.speed')!;
    expect(f.severity).toBe('warn');
    expect(f.verdict).toContain('Acme Portable SSD va a USB 2 (480 Mbit/s) ma saprebbe andare a 10 Gbit/s');
    expect(f.verdict).toContain('la porta è USB 3 ma il collegamento è avvenuto in USB 2');
    expect(f.verdict).toContain('in USB 2 si arriva a circa 40 MB/s');
    expect(f.actions).toEqual(['usb-faster-port']);
  });

  it('cause: porta USB 2, hub USB 2, 5 invece di 10 Gbit/s; gli hub non contano', () => {
    const info: UsbInfo = {
      read: 'ok',
      controllers: [
        {
          name: 'x',
          kind: 'xhci',
          hub: {
            kind: 'root',
            portCount: 4,
            ports: [
              { index: 1, status: 'ok', usb3: false, device: ssd() },
              {
                index: 2,
                status: 'ok',
                device: {
                  name: 'Hub',
                  vid: '05E3',
                  pid: '0610',
                  kind: 'hub',
                  speed: 'high',
                  canSuper: true,
                  hub: { kind: 'usb2', portCount: 4, ports: [{ index: 1, status: 'ok', device: ssd({ name: 'Acme Disk' }) }] },
                },
              },
              { index: 3, status: 'ok', usb3: true, device: ssd({ name: 'Acme Fast', speed: 'super', canSuperPlus: true }) },
            ],
          },
        },
      ],
    };
    const n = usbNodes(info);
    expect(n.map((x) => usbSlow(x))).toEqual(['usb2', undefined, 'usb2', 'gen1']);
    expect(usbSlowReason(n[0])).toContain('è collegato a una porta USB 2');
    expect(usbSlowReason(n[2])).toContain('dietro un hub USB 2');
    const s = clone(demoScan);
    s.pc!.usb = info;
    const f = find(s, 'pc.usb.speed')!;
    expect(f.value).toBe('3 dispositivi più lenti del possibile');
    expect(f.severity).toBe('warn');
    // Si mostrano i due collegati in USB 2: il terzo, a 5 invece di 10 Gbit/s, è tra gli "altri".
    expect(f.verdict).toContain('(e altri 1)');
    // Senza il tipo dell'hub non si dà la colpa a un hub USB 2; la metà USB 2 di un hub USB 3 (porta con compagna) indica il cavo.
    const hubPorts = (info.controllers[0].hub!.ports[1].device!.hub!);
    hubPorts.kind = undefined;
    expect(usbSlowReason(usbNodes(info)[2])).not.toContain('dietro un hub USB 2');
    hubPorts.kind = 'usb2';
    hubPorts.ports[0].companion = true;
    expect(usbSlowReason(usbNodes(info)[2])).toContain('la porta dell\'hub è USB 3');
    // Un solo dispositivo non di archiviazione più lento del possibile: solo informazione.
    info.controllers[0].hub!.ports = [{ index: 1, status: 'ok', usb3: false, device: ssd({ name: 'Acme Cam', kind: 'camera' }) }];
    expect(find(s, 'pc.usb.speed')!.severity).toBe('info');
  });

  it('nome con il produttore dal VID, senza ripeterlo', () => {
    expect(usbDeviceLabel({ name: 'USB Receiver', vid: '046D', pid: 'C52B', kind: 'input', speed: 'full' })).toBe('Logitech USB Receiver');
    expect(usbDeviceLabel({ name: 'Logitech USB Input Device', vid: '046d', pid: 'C077', kind: 'input', speed: 'low' })).toBe('Logitech USB Input Device');
    expect(usbDeviceLabel({ name: '', vid: 'ACE9', pid: '0001', kind: 'storage', speed: 'high' })).toBe('Memoria (disco, chiavetta, lettore di schede)');
  });
});

describe('catalogo, guida, documento e scheda', () => {
  it('voci, azioni e guida', () => {
    for (const id of ['pc.usb.ports', 'pc.usb.speed']) expect(METRICS[id], id).toBeTruthy();
    for (const id of ['usb-port-error', 'usb-faster-port']) expect(ACTIONS[id], id).toBeTruthy();
    const g = guideById('dispositivi-driver')!;
    expect(g.actions).toContain('usb-faster-port');
    expect(JSON.stringify(g.blocks)).toContain('porte compagne');
  });

  it('documento e scheda: albero con velocità ed errori, senza identificativi di istanza', () => {
    const s = clone(demoScan);
    const html = documentParts(s, analyze(s)).body;
    expect(html).toContain('<h2>Dispositivi USB</h2>');
    expect(html).toContain('Acme Portable SSD');
    expect(html).toContain('saprebbe andare a 10 Gbit/s');
    expect(html).not.toMatch(/USB\\(VID|ROOT_HUB)/);
    const card = renderToStaticMarkup(createElement(UsbCard, { pc: s.pc!, live: false }));
    expect(card).toContain('4 dispositivi su 1 controller');
    expect(card).toContain('Porta 5 · interna');
    expect(card).toContain('Logitech USB Receiver');
    expect(card).toContain('USB 3 (xHCI)');
    const c = clone(clinicScan);
    const ccard = renderToStaticMarkup(createElement(UsbCard, { pc: c.pc!, live: false }));
    expect(ccard).toContain('senza alimentatore');
    expect(ccard).toContain('corrente insufficiente');
    expect(ccard).toContain('codice 43: fermato dopo un errore');
    expect(ccard).not.toContain('codice 43: codice');
    c.pc!.usb = { read: 'none', controllers: [] };
    expect(renderToStaticMarkup(createElement(UsbCard, { pc: c.pc!, live: false }))).toContain('macchina virtuale');
    delete c.pc!.usb;
    expect(renderToStaticMarkup(createElement(UsbCard, { pc: c.pc!, live: false }))).toBe('');
  });
});
