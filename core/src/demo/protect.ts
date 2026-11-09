import type { AccessInfo, AccountsInfo, BackupInfo, EncryptionInfo, PrintingInfo } from '../engine/types';

// Cifratura, backup, account, accessi e stampanti dimostrativi.
//
// Demo di casa (portatile con Windows 11 Home e account locale): disco
// cifrato dalla crittografia automatica ma con la protezione mai attivata
// (chiave in chiaro), nessun punto di ripristino, Documenti in OneDrive,
// accesso automatico senza password nel registro, si lavora con l'account
// amministratore, nessun blocco dello schermo; la stampante Wi-Fi non in
// linea con due lavori fermi.
// Demo della clinica (Windows 10 Pro in dominio): BitLocker attivo con TPM e
// chiave di ripristino, backup notturno riuscito, account standard, Desktop
// remoto attivo con NLA dai criteri, blocco dopo 10 minuti; la stampante
// delle etichette senza carta.

export const homeEncryption: EncryptionInfo = {
  read: 'ok',
  preventAuto: false,
  volumes: [{ letter: 'C:', kind: 'os', conversion: 'encrypted', percent: 100, usedSpaceOnly: true, protection: 'off', method: 'xts-aes128', protectors: [] }],
};

export const homeBackup: BackupInfo = {
  restorePoints: { read: 'ok', count: 0 },
  imageBackup: { read: 'ok', days: 90 },
  oneDrive: ['documents'],
};

export const homeAccounts: AccountsInfo = {
  local: [
    { rid: 500, kind: 'builtin-admin', enabled: false, admin: true },
    { rid: 501, kind: 'guest', enabled: false },
    { rid: 503, kind: 'default', enabled: false },
    { rid: 504, kind: 'wdag', enabled: false },
    { rid: 1001, kind: 'user', enabled: true, admin: true, current: true },
  ],
  admins: { members: 2, localEnabled: 1 },
  currentIsAdmin: true,
};

export const homeAccess: AccessInfo = {
  autologon: { enabled: true },
  uac: { enabled: true, consentAdmin: 5, secureDesktop: true },
  lock: { saverActive: false, saverSecure: false, saverSec: 900 },
};

export const homePrinting: PrintingInfo = {
  spooler: { start: 'auto', running: true },
  printers: [
    { name: 'HP DeskJet 2700 series', kind: 'wsd', default: true, port: 'WSD-6f2c1a40-3b1e-4d6a-9c2f-1a2b3c4d5e6f', driver: 'HP DeskJet 2700 series PCL-3', status: 0x80, flags: ['offline'], jobs: 2, stuck: 2, oldestMin: 140 },
    { name: 'Microsoft Print to PDF', kind: 'virtual', port: 'PORTPROMPT:', driver: 'Microsoft Print To PDF', jobs: 0 },
    { name: 'OneNote (Desktop)', kind: 'virtual', port: 'nul:', driver: 'Send to Microsoft OneNote 16 Driver', jobs: 0 },
  ],
};

export const clinicEncryption: EncryptionInfo = {
  read: 'ok',
  volumes: [
    { letter: 'C:', kind: 'os', conversion: 'encrypted', percent: 100, protection: 'on', method: 'xts-aes128', protectors: ['tpm', 'recovery-password'], recoveryKeyId: '7F3A21C9' },
    { letter: 'D:', kind: 'fixed', conversion: 'decrypted', percent: 0, protection: 'off', method: 'none', protectors: [] },
  ],
};

export const clinicBackup: BackupInfo = {
  restorePoints: { read: 'ok', count: 4, newest: '2026-10-09T03:14:00Z', newestType: 'windows-update', oldest: '2026-09-02T03:10:00Z' },
  imageBackup: { read: 'ok', days: 90, lastSuccess: '2026-10-13T22:41:00Z', lastFailure: '2026-10-02T22:30:00Z', failureId: 49, failures: 1 },
};

export const clinicAccounts: AccountsInfo = {
  local: [
    { rid: 500, kind: 'builtin-admin', enabled: false, admin: true },
    { rid: 501, kind: 'guest', enabled: false },
    { rid: 503, kind: 'default', enabled: false },
    { rid: 504, kind: 'wdag', enabled: false },
    { rid: 1001, kind: 'user', enabled: true, admin: true, passwordNeverExpires: true },
  ],
  admins: { members: 3, localEnabled: 1, other: 2 },
};

export const clinicAccess: AccessInfo = {
  autologon: { enabled: false },
  rdp: { enabled: true, byPolicy: true, nla: true, port: 3389 },
  uac: { enabled: true, consentAdmin: 5, secureDesktop: true },
  lock: { inactivitySec: 600 },
};

export const clinicPrinting: PrintingInfo = {
  spooler: { start: 'auto', running: true },
  printers: [
    { name: 'Kyocera ECOSYS M2540dn (accettazione)', kind: 'tcp', default: true, port: '192.168.10.40', driver: 'Kyocera ECOSYS M2540dn KX', jobs: 0 },
    { name: 'Zebra GK420d (etichette)', kind: 'usb', port: 'USB001', driver: 'ZDesigner GK420d', status: 0x10, flags: ['paper-out'], jobs: 1 },
    { name: 'Microsoft Print to PDF', kind: 'virtual', port: 'PORTPROMPT:', driver: 'Microsoft Print To PDF', jobs: 0 },
  ],
  connections: 1,
};
