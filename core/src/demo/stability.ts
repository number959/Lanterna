import type { AppFailures, BootPerf, Reliability } from '../engine/types';

// Avvio, programmi che si chiudono da soli e indice di stabilità
// dimostrativi. Il programma che si chiude spesso e il servizio lento hanno
// nomi di fantasia ("Acme...") per non attribuire difetti a prodotti reali.
//
// Demo di casa (analisi del 12/10/2026): avvio lento, quasi tutto dopo il
// desktop per i 14 programmi all'avvio; un servizio di aggiornamento
// segnalato più volte; firmware nella norma; un programma che si chiude
// spesso, l'ultima volta il giorno prima; indice di stabilità sceso a 4,2.
// Demo della clinica: avvio di 38 s, nessun programma che si chiude, indice
// 9,1.

const day = (d: number) => `2026-${d < 0 ? '09' : '10'}-${String(d < 0 ? 30 + d : d).padStart(2, '0')}`;

export const homeBoot: BootPerf = {
  days: 90,
  channel: 'ok',
  firmwareMs: 9800,
  boots: [
    { time: '2026-09-23T08:00:05Z', totalMs: 118400, mainPathMs: 41200, postBootMs: 77200, startupApps: 14, degraded: true },
    { time: '2026-09-15T07:58:41Z', totalMs: 162300, mainPathMs: 58100, postBootMs: 104200, startupApps: 14, afterUpdate: true },
    { time: '2026-09-08T08:03:12Z', totalMs: 104800, mainPathMs: 39900, postBootMs: 64900, startupApps: 13 },
    { time: '2026-08-30T09:12:40Z', totalMs: 97100, mainPathMs: 38700, postBootMs: 58400, startupApps: 13 },
    { time: '2026-08-21T08:20:02Z', totalMs: 99600, mainPathMs: 40100, postBootMs: 59500, startupApps: 12 },
  ],
  slow: [
    { phase: 'boot', kind: 'service', name: 'AcmeUpdateSvc', friendly: 'Acme Update Service', version: '3.4.1', totalMs: 21500, degradationMs: 16800, count: 4, last: '2026-09-23T08:02:11Z' },
    { phase: 'boot', kind: 'app', name: 'OneDrive.exe', friendly: 'Microsoft OneDrive', version: '24.180.0905.0002', totalMs: 9400, degradationMs: 5100, count: 1, last: '2026-09-08T08:04:40Z' },
  ],
  shutdowns: [{ time: '2026-09-22T19:41:10Z', totalMs: 41800 }],
};

export const homeApps: AppFailures = {
  days: 30,
  channel: 'ok',
  crashes: 9,
  hangs: 3,
  apps: [
    {
      app: 'AcmePhotoStudio.exe',
      version: '8.2.0.114',
      crashes: 8,
      hangs: 2,
      last: '2026-10-11T18:22:40Z',
      modules: [
        { name: 'acmegpufx.dll', count: 6 },
        { name: 'ntdll.dll', count: 2 },
      ],
      exceptions: [
        { name: '0xc0000005', count: 7 },
        { name: '0xc0000374', count: 1 },
      ],
    },
    { app: 'msedge.exe', version: '129.0.2792.79', crashes: 1, hangs: 0, last: '2026-09-29T21:10:03Z', modules: [{ name: 'ntdll.dll', count: 1 }], exceptions: [{ name: '0xc0000409', count: 1 }] },
    { app: 'WINWORD.EXE', version: '16.0.17928.20156', crashes: 0, hangs: 1, last: '2026-09-25T10:44:51Z' },
  ],
  reports: [
    { event: 'APPCRASH', count: 9, last: '2026-10-11T18:22:41Z' },
    { event: 'AppHangB1', count: 3, last: '2026-10-02T15:12:09Z' },
    { event: 'BlueScreen', count: 1, last: '2026-09-27T14:05:31Z' },
  ],
  wer: {},
};

export const homeReliability: Reliability = {
  available: true,
  index: 4.2,
  indexAt: '2026-10-12T19:00:00Z',
  series: [
    ...[13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29].map((d, i) => ({ date: day(d - 30), index: Math.round((8.9 - i * 0.08) * 10) / 10 })),
    { date: '2026-09-30', index: 7.4 },
    { date: '2026-10-01', index: 7.3 },
    { date: '2026-10-02', index: 6.9 },
    { date: '2026-10-03', index: 6.9 },
    { date: '2026-10-04', index: 6.8 },
    { date: '2026-10-05', index: 6.5 },
    { date: '2026-10-06', index: 5.0 },
    { date: '2026-10-07', index: 4.9 },
    { date: '2026-10-08', index: 4.6 },
    { date: '2026-10-09', index: 4.6 },
    { date: '2026-10-10', index: 4.4 },
    { date: '2026-10-11', index: 4.1 },
    { date: '2026-10-12', index: 4.2 },
  ].slice(-30),
  records: [
    { category: 'app-crash', source: 'Application Error', id: 1000, product: 'AcmePhotoStudio.exe', count: 8, last: '2026-10-11T18:22:40Z' },
    { category: 'update-failed', source: 'Microsoft-Windows-WindowsUpdateClient', id: 20, product: 'Aggiornamento cumulativo per Windows 11 Version 23H2 per sistemi basati su x64', count: 3, last: '2026-10-08T03:12:00Z' },
    { category: 'app-hang', source: 'Application Hang', id: 1002, product: 'AcmePhotoStudio.exe', count: 2, last: '2026-10-02T15:12:08Z' },
    { category: 'windows-failure', source: 'Microsoft-Windows-WER-SystemErrorReporting', id: 1001, count: 1, last: '2026-09-27T14:05:31Z' },
  ],
  wmiEnabled: true,
};

export const clinicBoot: BootPerf = {
  days: 90,
  channel: 'ok',
  firmwareMs: 7200,
  boots: [
    { time: '2026-10-12T07:33:10Z', totalMs: 38200, mainPathMs: 21400, postBootMs: 16800, startupApps: 6 },
    { time: '2026-10-05T07:30:41Z', totalMs: 36900, mainPathMs: 20700, postBootMs: 16200, startupApps: 6 },
    { time: '2026-09-28T07:31:02Z', totalMs: 40100, mainPathMs: 22300, postBootMs: 17800, startupApps: 6 },
  ],
  shutdowns: [{ time: '2026-10-11T18:02:40Z', totalMs: 18300 }],
};

export const clinicApps: AppFailures = { days: 30, channel: 'ok', crashes: 0, hangs: 0, apps: [], wer: {} };

export const clinicReliability: Reliability = {
  available: true,
  index: 9.1,
  indexAt: '2026-10-14T06:00:00Z',
  series: [
    { date: '2026-10-08', index: 9.3 },
    { date: '2026-10-09', index: 9.2 },
    { date: '2026-10-10', index: 9.2 },
    { date: '2026-10-11', index: 9.1 },
    { date: '2026-10-12', index: 9.1 },
    { date: '2026-10-13', index: 9.1 },
    { date: '2026-10-14', index: 9.1 },
  ],
  records: [{ category: 'update', source: 'Microsoft-Windows-WindowsUpdateClient', id: 19, product: 'Aggiornamento della sicurezza', count: 2, last: '2026-09-10T03:00:00Z' }],
  wmiEnabled: true,
};
