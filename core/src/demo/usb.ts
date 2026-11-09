import type { UsbInfo } from '../engine/types';

// Albero USB dimostrativo, come lo legge l'agente (solo porte occupate). I
// dispositivi con un difetto hanno nomi di fantasia ("Acme...") e Vendor ID
// ACE* non assegnati a produttori veri, come in demo/devices.ts.
//
// Casa (portatile del 2021): un SSD esterno USB 3 che va a velocità USB 2
// perché collegato con un cavo solo USB 2 a una porta USB 3 (la porta ha la
// compagna USB 3); ricevitore Logitech, webcam e Bluetooth interni.
// Clinica (PC fisso): il lettore di smart card fermato dopo un errore (lo
// stesso di demo/devices.ts, codice 43), la stampante di etichette e un hub
// senza alimentatore con tastiera, mouse e un masterizzatore DVD a cui manca
// corrente.

export const homeUsb: UsbInfo = {
  read: 'ok',
  controllers: [
    {
      name: 'Intel(R) USB 3.10 eXtensible Host Controller - 1.20 (Microsoft)',
      kind: 'xhci',
      hub: {
        kind: 'root',
        portCount: 16,
        ports: [
          {
            index: 1,
            status: 'ok',
            usb3: false,
            visible: true,
            companion: true,
            device: { name: 'USB Receiver', vid: '046D', pid: 'C52B', kind: 'input', usb: '2.00', speed: 'full' },
          },
          {
            index: 2,
            status: 'ok',
            usb3: false,
            visible: true,
            companion: true,
            device: { name: 'Acme Portable SSD', vid: 'ACE1', pid: '5301', kind: 'storage', usb: '3.20', speed: 'high', canSuper: true, canSuperPlus: true },
          },
          {
            index: 5,
            status: 'ok',
            usb3: false,
            visible: false,
            device: { name: 'Integrated Camera', vid: '04F2', pid: 'B6D9', kind: 'camera', usb: '2.01', speed: 'high' },
          },
          {
            index: 10,
            status: 'ok',
            usb3: false,
            visible: false,
            device: { name: 'Intel(R) Wireless Bluetooth(R)', vid: '8087', pid: '0026', kind: 'bluetooth', usb: '2.01', speed: 'full' },
          },
        ],
      },
    },
  ],
};

export const clinicUsb: UsbInfo = {
  read: 'ok',
  controllers: [
    {
      name: 'Intel(R) USB 3.20 eXtensible Host Controller - 1.20 (Microsoft)',
      kind: 'xhci',
      hub: {
        kind: 'root',
        portCount: 26,
        ports: [
          {
            index: 1,
            status: 'ok',
            usb3: false,
            visible: true,
            companion: true,
            device: {
              name: 'USB2.0 Hub',
              vid: '05E3',
              pid: '0610',
              kind: 'hub',
              usb: '2.00',
              speed: 'high',
              hub: {
                kind: 'usb2',
                portCount: 4,
                busPowered: true,
                ports: [
                  { index: 1, status: 'ok', device: { name: 'USB Keyboard', vid: '413C', pid: '2113', kind: 'input', usb: '1.10', speed: 'low' } },
                  { index: 2, status: 'ok', device: { name: 'USB Optical Mouse', vid: '046D', pid: 'C077', kind: 'input', usb: '2.00', speed: 'low' } },
                  { index: 4, status: 'not-enough-power', device: { name: 'Acme Slim DVD Writer', vid: 'ACE4', pid: '0D01', kind: 'storage', usb: '2.00', speed: 'high' } },
                ],
              },
            },
          },
          {
            index: 3,
            status: 'ok',
            usb3: false,
            visible: true,
            companion: true,
            device: { name: 'GK420d', vid: '0A5F', pid: '0080', kind: 'printer', usb: '1.10', speed: 'full' },
          },
          {
            index: 4,
            status: 'ok',
            usb3: false,
            visible: true,
            companion: true,
            device: { name: 'Acme USB Smart Card Reader', vid: 'ACE3', pid: '0C11', kind: 'smartcard', usb: '2.00', speed: 'full', problem: 43 },
          },
        ],
      },
    },
  ],
};
