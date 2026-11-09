import type { DeviceClassCount, DevicesData } from '../engine/types';

// Dispositivi dimostrativi, come li legge l'agente. I dispositivi guasti e il
// driver delle schermate blu hanno nomi di fantasia ("Acme...") per non
// attribuire difetti a prodotti reali; i codici VEN/VID "ACE1"... non sono
// assegnati a produttori veri.
//
// Demo di casa (portatile del 2021 mai aggiornato): un dispositivo senza
// driver (codice 28), un dispositivo Bluetooth abbinato disattivato (il nome
// scelto dall'utente è già sostituito, come fa l'agente), il driver Wi-Fi
// "acmewlan.sys" indicato dalle schermate blu (demo/crashes.ts), tre driver
// di terze parti con più di cinque anni.
// Demo della clinica: il lettore di smart card (tessera sanitaria) fermato
// dopo un errore (codice 43); driver recenti; integrità della memoria attiva.

const classes = (list: [string, number, number?][]): DeviceClassCount[] =>
  list.map(([cls, count, problems]) => (problems ? { class: cls, count, problems } : { class: cls, count }));

const homeClasses = classes([
  ['', 1, 1],
  ['Bluetooth', 7, 1],
  ['System', 41],
  ['SoftwareDevice', 14],
  ['HIDClass', 12],
  ['USB', 9],
  ['Net', 9],
  ['Processor', 8],
  ['AudioEndpoint', 4],
  ['MEDIA', 3],
  ['Volume', 3],
  ['SoftwareComponent', 3],
  ['Mouse', 2],
  ['Monitor', 1],
  ['Display', 1],
  ['DiskDrive', 1],
  ['SCSIAdapter', 1],
  ['Keyboard', 1],
  ['Camera', 1],
  ['Battery', 2],
  ['Computer', 1],
  ['Firmware', 1],
  ['SecurityDevices', 1],
]);

export const homeDevices: DevicesData = {
  total: homeClasses.reduce((s, c) => s + c.count, 0),
  problems: 2,
  classes: homeClasses,
  items: [
    { name: 'Dispositivo sconosciuto', enumerator: 'ACPI', hardwareId: 'ACPI\\VEN_ACM&DEV_3401', problem: 28, problemStatus: '0xC0000490' },
    {
      name: 'Dispositivo Bluetooth',
      class: 'Bluetooth',
      enumerator: 'BTHENUM',
      hardwareId: 'BTHENUM',
      problem: 22,
      service: 'BthA2dp',
      driver: { provider: 'Microsoft', version: '10.0.22621.1', date: '2006-06-21', inf: 'bth.inf', inbox: true, file: 'btha2dp.sys' },
    },
    {
      name: 'Realtek(R) Audio',
      class: 'MEDIA',
      enumerator: 'HDAUDIO',
      hardwareId: 'HDAUDIO\\VEN_10EC&DEV_0256&SUBSYS_10251420&REV_1000',
      service: 'IntcAzAudAddService',
      driver: { provider: 'Realtek Semiconductor Corp.', version: '6.0.9088.1', date: '2021-01-12', inf: 'oem11.inf', file: 'rtkvhd64.sys' },
    },
    {
      name: 'Intel(R) Iris(R) Xe Graphics',
      class: 'Display',
      enumerator: 'PCI',
      hardwareId: 'PCI\\VEN_8086&DEV_9A49&SUBSYS_14201025&REV_01',
      service: 'igfxn',
      driver: { provider: 'Intel Corporation', version: '30.0.100.9864', date: '2021-08-10', inf: 'oem32.inf', file: 'igdkmdn64.sys' },
    },
    {
      name: 'Acme Wireless AX 160MHz',
      class: 'Net',
      enumerator: 'PCI',
      hardwareId: 'PCI\\VEN_ACE1&DEV_A0F0&SUBSYS_00344FFF&REV_20',
      service: 'acmewlan',
      driver: { provider: 'Acme', version: '22.40.0.7', date: '2020-11-05', inf: 'oem18.inf', file: 'acmewlan.sys' },
    },
    {
      name: 'Acme Wireless Bluetooth',
      class: 'Bluetooth',
      enumerator: 'USB',
      hardwareId: 'USB\\VID_ACE1&PID_0026&REV_0002',
      service: 'BTHUSB',
      driver: { provider: 'Acme', version: '22.40.0.2', date: '2020-11-05', inf: 'oem19.inf', file: 'bthusb.sys' },
    },
    {
      name: 'Intel(R) Serial IO I2C Host Controller - A0E8',
      class: 'System',
      enumerator: 'PCI',
      hardwareId: 'PCI\\VEN_8086&DEV_A0E8&SUBSYS_14201025&REV_20',
      service: 'iaLPSS2_I2C_TGL',
      driver: { provider: 'Intel Corporation', version: '30.100.2020.7', date: '2020-05-14', inf: 'oem5.inf', file: 'ialpss2_i2c_tgl.sys' },
    },
    {
      name: 'Intel(R) Serial IO I2C Host Controller - A0E9',
      class: 'System',
      enumerator: 'PCI',
      hardwareId: 'PCI\\VEN_8086&DEV_A0E9&SUBSYS_14201025&REV_20',
      service: 'iaLPSS2_I2C_TGL',
      driver: { provider: 'Intel Corporation', version: '30.100.2020.7', date: '2020-05-14', inf: 'oem5.inf', file: 'ialpss2_i2c_tgl.sys' },
    },
    {
      name: 'Realtek Audio Effects Component',
      class: 'SoftwareComponent',
      enumerator: 'SWD',
      driver: { provider: 'Realtek', version: '11.0.6000.252', date: '2021-01-12', inf: 'oem12.inf' },
    },
  ],
  codeIntegrity: { options: 0x1, enabled: true },
};

const clinicClasses = classes([
  ['SmartCardReader', 1, 1],
  ['System', 44],
  ['SoftwareDevice', 9],
  ['HIDClass', 8],
  ['USB', 8],
  ['Net', 7],
  ['Processor', 12],
  ['AudioEndpoint', 2],
  ['MEDIA', 2],
  ['Volume', 3],
  ['Mouse', 1],
  ['Keyboard', 1],
  ['Monitor', 2],
  ['Display', 1],
  ['DiskDrive', 2],
  ['SCSIAdapter', 1],
  ['Computer', 1],
  ['Firmware', 1],
  ['SecurityDevices', 1],
  ['PrintQueue', 3],
]);

export const clinicDevices: DevicesData = {
  total: clinicClasses.reduce((s, c) => s + c.count, 0),
  problems: 1,
  classes: clinicClasses,
  items: [
    {
      name: 'Acme USB Smart Card Reader',
      class: 'SmartCardReader',
      enumerator: 'USB',
      hardwareId: 'USB\\VID_ACE3&PID_0C11&REV_0100',
      problem: 43,
      service: 'acmescr',
      driver: { provider: 'Acme', version: '1.2.0.4', date: '2016-03-01', inf: 'oem7.inf', file: 'acmescr.sys' },
    },
    {
      name: 'Intel(R) UHD Graphics 770',
      class: 'Display',
      enumerator: 'PCI',
      hardwareId: 'PCI\\VEN_8086&DEV_4690&SUBSYS_0A9F1028&REV_0C',
      service: 'igfxn',
      driver: { provider: 'Intel Corporation', version: '31.0.101.5186', date: '2024-01-10', inf: 'oem21.inf', file: 'igdkmdn64.sys' },
    },
    {
      name: 'Intel(R) Ethernet Connection (17) I219-LM',
      class: 'Net',
      enumerator: 'PCI',
      hardwareId: 'PCI\\VEN_8086&DEV_1A1C&SUBSYS_0A9F1028&REV_11',
      service: 'e1dexpress',
      driver: { provider: 'Intel', version: '12.19.2.60', date: '2024-02-20', inf: 'oem14.inf', file: 'e1d68x64.sys' },
    },
    {
      name: 'Intel(R) Management Engine Interface #1',
      class: 'System',
      enumerator: 'PCI',
      hardwareId: 'PCI\\VEN_8086&DEV_7AE8&SUBSYS_0A9F1028&REV_11',
      service: 'MEIx64',
      driver: { provider: 'Intel', version: '2406.5.5.0', date: '2024-02-06', inf: 'oem9.inf', file: 'teedriverw10x64.sys' },
    },
  ],
  codeIntegrity: { options: 0x401, enabled: true, hvci: true },
};
