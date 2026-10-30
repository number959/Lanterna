import { fmt, thousands } from './fmt';
import type { SpaceReport } from './types';

// "Cosa occupa spazio": nomi, spiegazioni e consigli per le cartelle e i file
// noti che l'agente riconosce (SpaceHint.id). Le indicazioni sono generali,
// basate sulla documentazione Microsoft: menu e voci possono cambiare tra le
// versioni di Windows. Polaris non cancella nulla.

/**
 * Cosa fare con una cartella nota:
 * - tool: si libera con gli strumenti di Windows (Impostazioni, Pulizia disco);
 * - review: dati personali, da rivedere a mano;
 * - setting: si riduce da un'impostazione;
 * - keep: gestita da Windows, non va toccata a mano.
 */
export type SpaceRisk = 'tool' | 'review' | 'setting' | 'keep';

export const SPACE_RISK_LABEL: Record<SpaceRisk, string> = {
  tool: 'Si libera con Windows',
  review: 'Da rivedere',
  setting: 'Da impostazione',
  keep: 'Non toccare',
};

export interface SpaceHintInfo {
  label: string;
  risk: SpaceRisk;
  /** Cos'è. */
  what: string;
  /** Come recuperare spazio senza rischi (o perché non farlo). */
  how: string;
}

export const SPACE_HINTS: Record<string, SpaceHintInfo> = {
  'temp-user': {
    label: "File temporanei dell'utente",
    risk: 'tool',
    what: 'File lasciati da programmi e installazioni nella cartella temporanea. Quelli non modificati da più di una settimana in genere non servono più.',
    how: 'Impostazioni > Sistema > Archiviazione > File temporanei, oppure attiva Sensore memoria. Chiudi prima i programmi: i file in uso restano e non vanno forzati.',
  },
  'temp-windows': {
    label: 'File temporanei di Windows',
    risk: 'tool',
    what: 'File temporanei del sistema e dei servizi, nella cartella Temp di Windows.',
    how: "Impostazioni > Sistema > Archiviazione > File temporanei, oppure Pulizia disco > Pulizia file di sistema (servono i diritti di amministratore).",
  },
  'update-cache': {
    label: 'Download di Windows Update',
    risk: 'tool',
    what: 'Aggiornamenti scaricati da Windows Update, già installati o in attesa di esserlo.',
    how: 'Pulizia disco > Pulizia file di sistema > Pulizia di Windows Update, oppure Impostazioni > Sistema > Archiviazione > File temporanei. Non cancellare la cartella a mano mentre Windows si aggiorna.',
  },
  'delivery-optimization': {
    label: 'Cache di Ottimizzazione recapito',
    risk: 'tool',
    what: 'Copie di aggiornamenti e app da condividere con altri PC. Windows la svuota da solo dopo pochi giorni o quando occupa troppo.',
    how: 'Di solito non serve intervenire; se serve subito: Pulizia disco > File di Ottimizzazione recapito.',
  },
  'windows-old': {
    label: 'Installazione precedente di Windows (Windows.old)',
    risk: 'tool',
    what: "La versione precedente di Windows, conservata dopo un aggiornamento per poter tornare indietro. Windows la elimina da solo 10 giorni dopo l'aggiornamento, salvo impostazioni diverse.",
    how: 'Se il PC funziona bene e non vuoi tornare indietro: Impostazioni > Sistema > Archiviazione > File temporanei > Installazioni precedenti di Windows, oppure Pulizia disco > Pulizia file di sistema. Non si può annullare.',
  },
  'upgrade-files': {
    label: "File dell'aggiornamento di Windows",
    risk: 'tool',
    what: "Cartelle nascoste ($WINDOWS.~BT, $Windows.~WS) usate durante l'aggiornamento a una nuova versione di Windows.",
    how: "Pulizia disco > Pulizia file di sistema, voci sui file di installazione e di aggiornamento. Non cancellarle a mano durante un aggiornamento.",
  },
  'recycle-bin': {
    label: 'Cestino',
    risk: 'review',
    what: 'File eliminati: occupano spazio finché il Cestino non viene svuotato.',
    how: 'Controlla che non ci sia nulla da recuperare, poi svuota il Cestino. Sensore memoria, se attivo, elimina da solo gli elementi più vecchi (30 giorni di norma).',
  },
  winsxs: {
    label: 'Archivio dei componenti di Windows (WinSxS)',
    risk: 'keep',
    what: 'Componenti di Windows e degli aggiornamenti. Gran parte dei file è condivisa con System32 tramite collegamenti fisici: Esplora file la mostra più grande di quanto è, Polaris conta questi file una volta sola.',
    how: 'Non cancellare nulla a mano: Windows potrebbe non avviarsi più. Windows la riduce da solo; per farlo subito: Pulizia disco > Pulizia di Windows Update, oppure da amministratore Dism /Online /Cleanup-Image /StartComponentCleanup.',
  },
  installer: {
    label: 'Cache di Windows Installer',
    risk: 'keep',
    what: 'Copie dei pacchetti di installazione (MSI) dei programmi: servono per disinstallarli, ripararli e aggiornarli.',
    how: 'Non cancellare nulla a mano: i programmi non si disinstallerebbero più e questi file non si recuperano da un altro PC. Per ridurla, disinstalla i programmi che non usi.',
  },
  'error-reports': {
    label: 'Segnalazioni degli errori',
    risk: 'tool',
    what: 'Rapporti sugli errori dei programmi e di Windows, in attesa di invio o già inviati.',
    how: 'Pulizia disco, voci sui file della segnalazione errori di Windows.',
  },
  'crash-dumps': {
    label: 'File di dump degli arresti anomali',
    risk: 'tool',
    what: 'Copie della memoria salvate quando Windows o un programma si blocca: servono a capirne la causa. MEMORY.DMP può essere grande quanto la RAM.',
    how: "Se i blocchi sono risolti e l'assistenza non li ha chiesti: Pulizia disco > Pulizia file di sistema, voci sui file di dump della memoria.",
  },
  'browser-cache': {
    label: 'Cache dei browser',
    risk: 'tool',
    what: 'Copie di pagine e immagini dei siti visitati (Edge, Chrome, Firefox): si ricostruiscono da sole.',
    how: 'Svuotala dal browser, non cancellando le cartelle: in Edge Impostazioni > Privacy, ricerca e servizi > Cancella dati delle esplorazioni > Immagini e file memorizzati nella cache; in Chrome menu > Elimina dati di navigazione.',
  },
  'package-cache': {
    label: 'Cache dei pacchetti di installazione',
    risk: 'keep',
    what: 'Pacchetti salvati da Visual Studio, dalle librerie Visual C++ e da altri installatori per ripararsi e aggiornarsi.',
    how: 'Non cancellarla a mano: riparazioni e aggiornamenti di quei programmi non funzionerebbero più. Si riduce disinstallando i programmi che non servono.',
  },
  downloads: {
    label: 'Cartella Download',
    risk: 'review',
    what: 'File scaricati da Internet: spesso installazioni vecchie, archivi e documenti già salvati altrove.',
    how: 'Rivedila a mano ordinando per dimensione. Sensore memoria può eliminare i file non aperti da un certo numero di giorni, ma solo se lo attivi tu.',
  },
  onedrive: {
    label: 'OneDrive',
    risk: 'review',
    what: 'La cartella sincronizzata con il cloud. I file solo online non occupano spazio su questo disco.',
    how: 'Per i file che non usi spesso: tasto destro > Libera spazio. Restano nel cloud e si scaricano quando li apri. Non cancellarli per fare spazio: sparirebbero anche dal cloud.',
  },
  hibernation: {
    label: 'File di ibernazione (hiberfil.sys)',
    risk: 'setting',
    what: "Contiene la memoria quando il PC va in ibernazione e serve all'avvio rapido di Windows.",
    how: "Da amministratore, powercfg /h /type reduced lo rimpicciolisce e mantiene l'avvio rapido (ma non l'ibernazione). powercfg /h off lo elimina e disattiva anche ibernazione e avvio rapido.",
  },
  pagefile: {
    label: 'File di paging',
    risk: 'keep',
    what: 'pagefile.sys e swapfile.sys estendono la RAM sul disco e servono a salvare i dati in caso di blocco.',
    how: 'Non eliminarli. Le dimensioni si cambiano in Sistema > Impostazioni di sistema avanzate > Prestazioni > Memoria virtuale; è meglio lasciarle gestire a Windows.',
  },
  'virtual-disks': {
    label: 'Dischi virtuali (WSL, Docker, macchine virtuali)',
    risk: 'review',
    what: 'File dei dischi virtuali (.vhdx, .vmdk, .vdi): crescono quando si scrivono dati e non si rimpiccioliscono da soli quando si cancellano.',
    how: 'Libera prima spazio al loro interno (per Docker: docker system prune), poi compatta il disco a macchina spenta (wsl --shutdown, quindi Optimize-VHD o diskpart). Non cancellare il file: si perderebbero i dati della macchina virtuale.',
  },
};

export const SPACE_CATEGORY_LABEL: Record<string, string> = {
  video: 'Video',
  image: 'Immagini',
  audio: 'Audio',
  document: 'Documenti',
  archive: 'Archivi e immagini disco',
  program: 'Programmi e librerie',
  virtualdisk: 'Dischi virtuali',
  system: 'File di sistema',
  other: 'Altro',
};

/** Nome di una cartella nota (l'identificativo se sconosciuto). */
export const spaceHintLabel = (id: string) => SPACE_HINTS[id]?.label ?? id;

/**
 * Dimensione in unità decimali (1 GB = 10^9 byte, come le altre schede di
 * Polaris): "380,2 GB". Esplora file conta in potenze di 1024, quindi mostra
 * numeri circa il 7 % più piccoli per gli stessi byte.
 */
export function sizeText(b: number): string {
  if (!(b > 0)) return '0 B';
  if (b < 1000) return `${Math.round(b)} B`;
  const units = ['KB', 'MB', 'GB', 'TB', 'PB'];
  let v = b / 1000;
  let i = 0;
  while (v >= 999.95 && i < units.length - 1) {
    v /= 1000;
    i++;
  }
  return `${fmt(v, 1)} ${units[i]}`;
}

/** Percentuale con una cifra decimale: "55,3 %", "<0,1 %". */
export function pctText(part: number, total: number): string {
  if (!(total > 0)) return '';
  const p = (part / total) * 100;
  if (p > 0 && p < 0.1) return '<0,1 %';
  return `${fmt(Math.round(p * 10) / 10, 1)} %`;
}

/**
 * Spazio occupato sull'unità che l'analisi non ha trovato nei file leggibili
 * (cartelle protette, metadati del file system, copie shadow). Ha senso solo
 * per un'analisi completa della radice; sotto l'1 % del disco è rumore.
 */
export function unattributedBytes(r: SpaceReport): number {
  if (r.partial || !(r.totalBytes > 0) || r.root.length !== 3) return 0;
  const un = r.totalBytes - r.freeBytes - r.allocBytes;
  return un >= r.totalBytes / 100 ? un : 0;
}

/** Spazio che si recupera con gli strumenti di Windows, senza toccare dati personali. */
export function reclaimableBytes(r: SpaceReport): number {
  return (r.hints ?? []).filter((h) => SPACE_HINTS[h.id]?.risk === 'tool').reduce((s, h) => s + h.alloc, 0);
}

/** Riepilogo in una riga: "380,2 GB in 412.345 file e 98.765 cartelle". */
export const spaceLine = (r: SpaceReport) => `${sizeText(r.allocBytes)} in ${thousands(r.files)} file e ${thousands(r.dirs)} cartelle`;
