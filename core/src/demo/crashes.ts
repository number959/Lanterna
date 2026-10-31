import type { CrashData } from '../engine/types';

// Schermate blu dimostrative, inventate. I driver hanno nomi di fantasia
// ("acme...") per non attribuire guasti a prodotti reali.
//
// Come è costruita la demo di casa:
// - il minidump più recente (27/09/2026) ha lo stesso codice e gli stessi
//   parametri dell'evento 1001 del registro di sistema nella stessa demo
//   (0x9F DRIVER_POWER_STATE_FAILURE), con il driver Wi-Fi indicato dallo
//   stack salvato;
// - due minidump di agosto, fuori dalla finestra di 30 giorni degli eventi,
//   hanno 0xD1 con il parametro 4 dentro lo stesso driver: è il caso che il
//   giudizio "driver ricorrente" deve riconoscere (3 su 4, l'ultimo entro 30
//   giorni dall'analisi del 12/10/2026);
// - un minidump di giugno con 0x1A MEMORY_MANAGEMENT non indica driver;
// - impostazioni predefinite di Windows 11 (dump automatico); nessun
//   MEMORY.DMP, coerente con il disco quasi pieno della demo, perché con
//   poco spazio libero Windows non lo conserva;
// - la build nell'intestazione è quella di base del kernel (22621 anche su
//   23H2), come nei dump reali.
// La demo della clinica non ha schermate blu: la cartella dei minidump non
// esiste, come su un PC che non si è mai arrestato.

export const homeCrashes: CrashData = {
  readAt: '2026-10-12T20:30:20Z',
  settings: { dumpEnabled: 7, minidumpDir: '%SystemRoot%\\Minidump', dumpFile: '%SystemRoot%\\MEMORY.DMP', autoReboot: true, overwrite: true, logEvent: true },
  folder: 'ok',
  total: 4,
  dumps: [
    {
      file: '092726-8421-01.dmp',
      size: 1153024,
      modified: '2026-09-27T21:15:12Z',
      time: '2026-09-27T21:14:03Z',
      code: '0x0000009f',
      params: ['0x0000000000000003', '0xffffe50c3c7a5060', '0xfffff8045b67f7b0', '0xffffe50c4a3c9010'],
      bits: 64,
      machine: 'x64',
      build: 22621,
      processors: 8,
      dumpType: 'triage',
      drivers: 212,
      probable: { driver: 'acmewlan.sys', method: 'stack', offset: '0x2f1a4' },
      stack: ['acmewlan.sys', 'acmebtflt.sys'],
    },
    {
      file: '083026-7312-01.dmp',
      size: 1089536,
      modified: '2026-08-30T08:42:30Z',
      time: '2026-08-30T08:41:22Z',
      code: '0x000000d1',
      params: ['0x0000000000000010', '0x0000000000000002', '0x0000000000000000', '0xfffff8045b6a2c3e'],
      bits: 64,
      machine: 'x64',
      build: 22621,
      processors: 8,
      dumpType: 'triage',
      drivers: 209,
      probable: { driver: 'acmewlan.sys', method: 'param', param: 4, offset: '0x32c3e' },
      stack: ['acmewlan.sys'],
    },
    {
      file: '081426-6890-01.dmp',
      size: 1101824,
      modified: '2026-08-14T19:03:58Z',
      time: '2026-08-14T19:02:51Z',
      code: '0x000000d1',
      params: ['0x0000000000000000', '0x0000000000000002', '0x0000000000000000', '0xfffff80462b51a10'],
      bits: 64,
      machine: 'x64',
      build: 22621,
      processors: 8,
      dumpType: 'triage',
      drivers: 209,
      probable: { driver: 'acmewlan.sys', method: 'param', param: 4, offset: '0x31a10' },
      stack: ['acmewlan.sys'],
    },
    {
      file: '060326-5121-01.dmp',
      size: 958464,
      modified: '2026-06-03T10:13:40Z',
      time: '2026-06-03T10:12:40Z',
      code: '0x0000001a',
      params: ['0x0000000000041792', '0xffffcc8000a1b2c0', '0x0000000000100000', '0x0000000000000000'],
      bits: 64,
      machine: 'x64',
      build: 22621,
      processors: 8,
      dumpType: 'triage',
      drivers: 205,
    },
  ],
};

export const clinicCrashes: CrashData = {
  readAt: '2026-10-14T09:12:40Z',
  settings: { dumpEnabled: 7, minidumpDir: '%SystemRoot%\\Minidump', dumpFile: '%SystemRoot%\\MEMORY.DMP', autoReboot: true, overwrite: true, logEvent: true },
  folder: 'missing',
  total: 0,
  dumps: [],
};
