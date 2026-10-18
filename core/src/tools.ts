// Cassetta degli attrezzi: gli strumenti di Windows che Polaris può aprire e
// i programmi gratuiti di diagnostica più noti, con il loro sito ufficiale.
// I programmi non sono inclusi in Polaris (le licenze non lo permettono o non
// lo rendono opportuno): Polaris li rileva se sono già installati e li apre.
// Gli identificativi e i siti devono coincidere con il catalogo dell'agente
// (windows/internal/tools): lo verifica un test dell'agente.
// Siti e licenze verificati sui siti dei produttori il 18 ottobre 2026.

export type ToolCategory = 'disco' | 'hardware' | 'sicurezza' | 'avvio' | 'spazio' | 'errori' | 'windows';

export interface WinTool {
  id: string;
  name: string;
  what: string;
}

/** Strumenti integrati in Windows. */
export const WINDOWS_TOOLS: WinTool[] = [
  { id: 'windows-security', name: 'Sicurezza di Windows', what: 'antivirus, firewall, cronologia delle minacce, analisi offline' },
  { id: 'windows-update', name: 'Windows Update', what: 'aggiornamenti di sicurezza e di versione' },
  { id: 'task-manager', name: 'Gestione attività', what: 'processi, prestazioni, programmi all\'avvio' },
  { id: 'resource-monitor', name: 'Monitoraggio risorse', what: 'chi usa disco, rete e memoria, processo per processo' },
  { id: 'reliability', name: 'Monitoraggio affidabilità', what: 'cronologia di arresti anomali e installazioni, giorno per giorno' },
  { id: 'event-viewer', name: 'Visualizzatore eventi', what: 'il registro completo di sistema e applicazioni' },
  { id: 'startup-apps', name: 'App di avvio', what: 'attiva o disattiva i programmi che partono con Windows' },
  { id: 'storage', name: 'Archiviazione', what: 'file temporanei, Sensore memoria, spazio per cartella' },
  { id: 'disk-cleanup', name: 'Pulizia disco', what: 'file temporanei e residui degli aggiornamenti' },
  { id: 'defrag', name: 'Ottimizza unità', what: 'TRIM degli SSD e deframmentazione dei dischi meccanici' },
  { id: 'disk-management', name: 'Gestione disco', what: 'partizioni, lettere di unità, dischi nuovi' },
  { id: 'device-manager', name: 'Gestione dispositivi', what: 'driver e periferiche con problemi' },
  { id: 'memory-diagnostic', name: 'Diagnostica memoria Windows', what: 'test della RAM al riavvio' },
  { id: 'system-info', name: 'Informazioni di sistema', what: 'riepilogo completo di hardware, driver e firmware' },
  { id: 'power', name: 'Alimentazione', what: 'sospensione, schermo e modalità di risparmio energia' },
  { id: 'recovery', name: 'Ripristino', what: 'avvio avanzato e accesso alle impostazioni del firmware UEFI' },
];

/** Strumenti di Windows utili per ciascuna azione del piano (si aprono con un clic). */
export const ACTION_TOOLS: Record<string, string[]> = {
  'update-windows': ['windows-update'],
  'upgrade-windows': ['windows-update'],
  'free-disk-space': ['storage', 'disk-cleanup'],
  'check-disk-errors': ['event-viewer', 'disk-management'],
  'close-heavy-apps': ['task-manager', 'resource-monitor'],
  'trim-startup': ['startup-apps', 'task-manager'],
  'diagnose-bsod': ['reliability', 'event-viewer'],
  'check-hardware': ['memory-diagnostic', 'device-manager'],
  'enable-antivirus': ['windows-security'],
  'update-antivirus': ['windows-security'],
  'remove-threats': ['windows-security'],
  'defender-protection': ['windows-security'],
  'power-plan': ['power'],
  'update-gpu-driver': ['device-manager'],
  'firmware-security': ['recovery'],
  'dual-channel': ['system-info'],
};

export interface Tool {
  id: string;
  name: string;
  vendor: string;
  category: ToolCategory;
  /** Che cosa fa, in una frase. */
  what: string;
  /** Dove Polaris fa una cosa simile. */
  polaris?: string;
  license: string;
  site: string;
  note?: string;
  /** Si installa: Polaris può riconoscerlo e aprirlo. */
  installs?: boolean;
}

export const TOOLS: Tool[] = [
  {
    id: 'crystaldiskinfo',
    name: 'CrystalDiskInfo',
    vendor: 'Crystal Dew World',
    category: 'disco',
    what: 'Salute dei dischi: attributi SMART, temperatura, ore di accensione, avvisi in tempo reale.',
    polaris: 'Computer > Dischi e spazio: stato Buono/Attenzione/Critico, tabella SMART e registro NVMe.',
    license: 'open source, licenza MIT',
    site: 'https://crystalmark.info/en/software/crystaldiskinfo/',
    note: 'Utile se vuoi un avviso continuo dalla barra delle applicazioni o per dischi dietro controller particolari.',
    installs: true,
  },
  {
    id: 'crystaldiskmark',
    name: 'CrystalDiskMark',
    vendor: 'Crystal Dew World',
    category: 'disco',
    what: 'Test di velocità dei dischi, il riferimento per confrontare i propri valori con quelli dichiarati.',
    polaris: 'Computer > Test di velocità: stesso profilo (SEQ1M Q8T1, SEQ1M Q1T1, RND4K Q32T1, RND4K Q1T1), in versione breve.',
    license: 'open source, licenza MIT',
    site: 'https://crystalmark.info/en/software/crystaldiskmark/',
    installs: true,
  },
  {
    id: 'cpu-z',
    name: 'CPU-Z',
    vendor: 'CPUID',
    category: 'hardware',
    what: 'Scheda tecnica di processore, scheda madre, memoria (con i dati dei moduli) e grafica.',
    polaris: 'Computer > Scheda tecnica: processore, cache, core P ed E, moduli di memoria, firmware.',
    license: 'freeware, non ridistribuibile',
    site: 'https://www.cpuid.com/softwares/cpu-z.html',
    note: 'Legge anche i profili XMP/EXPO dei moduli, che Windows non mostra.',
    installs: true,
  },
  {
    id: 'hwinfo',
    name: 'HWiNFO',
    vendor: 'Martin Malík (REALiX)',
    category: 'hardware',
    what: 'Sensori in tempo reale (temperature, tensioni, ventole, consumi) e inventario hardware dettagliato.',
    polaris: 'Polaris non legge i sensori di temperatura di processore e scheda madre: per quelli serve HWiNFO.',
    license: 'gratuito per uso personale (licenza Pro per uso commerciale: da verificare sul sito)',
    site: 'https://www.hwinfo.com/',
    installs: true,
  },
  {
    id: 'malwarebytes',
    name: 'Malwarebytes',
    vendor: 'Malwarebytes',
    category: 'sicurezza',
    what: 'Seconda opinione contro malware, adware e programmi indesiderati, con scansione a richiesta.',
    polaris: 'Computer > Antivirus: stato e scansioni di Microsoft Defender.',
    license: 'versione gratuita per scansione e rimozione a richiesta; protezione in tempo reale a pagamento',
    site: 'https://www.malwarebytes.com/mwb-download',
    note: 'All\'installazione può attivare una prova della versione a pagamento: per non avere due antivirus in tempo reale insieme a Defender, al termine della prova resta la sola scansione a richiesta (da verificare nelle impostazioni del programma).',
    installs: true,
  },
  {
    id: 'safety-scanner',
    name: 'Microsoft Safety Scanner',
    vendor: 'Microsoft',
    category: 'sicurezza',
    what: 'Scanner antimalware a richiesta, senza installazione, con il motore di Defender e firme fresche.',
    license: 'gratuito',
    site: 'https://learn.microsoft.com/it-it/defender-endpoint/safety-scanner-download',
    note: 'Smette di funzionare 10 giorni dopo il download: va riscaricato a ogni uso.',
  },
  {
    id: 'eset-online-scanner',
    name: 'ESET Online Scanner',
    vendor: 'ESET',
    category: 'sicurezza',
    what: 'Scansione a richiesta con un motore diverso da quello di Microsoft: una vera seconda opinione.',
    license: 'gratuito',
    site: 'https://www.eset.com/int/home/online-scanner/',
  },
  {
    id: 'autoruns',
    name: 'Autoruns',
    vendor: 'Microsoft Sysinternals',
    category: 'avvio',
    what: 'Tutto ciò che parte da solo: programmi, servizi, driver, attività pianificate, estensioni.',
    polaris: 'Computer > Avvio e processi: chiavi Run e cartelle di esecuzione automatica.',
    license: 'gratuito',
    site: 'https://learn.microsoft.com/it-it/sysinternals/downloads/autoruns',
    note: 'Strumento per esperti: disattivare la voce sbagliata può impedire l\'avvio di Windows.',
  },
  {
    id: 'process-explorer',
    name: 'Process Explorer',
    vendor: 'Microsoft Sysinternals',
    category: 'avvio',
    what: 'Gestione attività avanzata: albero dei processi, file aperti, verifica delle firme e su VirusTotal.',
    polaris: 'Computer > Avvio e processi: i processi che pesano di più durante l\'analisi.',
    license: 'gratuito',
    site: 'https://learn.microsoft.com/it-it/sysinternals/downloads/process-explorer',
  },
  {
    id: 'memtest86',
    name: 'MemTest86',
    vendor: 'PassMark Software',
    category: 'hardware',
    what: 'Test approfondito della RAM da chiavetta USB avviabile, fuori da Windows.',
    polaris: 'Polaris non prova la RAM: per i blocchi casuali e le schermate blu sospette si usa questo o la Diagnostica memoria Windows.',
    license: 'versione gratuita; versioni Pro e Site a pagamento',
    site: 'https://www.memtest86.com/',
    note: 'Si prepara una chiavetta e si riavvia il PC da lì: un test completo dura ore.',
  },
  {
    id: 'wiztree',
    name: 'WizTree',
    vendor: 'Antibody Software',
    category: 'spazio',
    what: 'Mappa dello spazio sul disco in pochi secondi: trova subito cartelle e file più grandi.',
    polaris: 'Computer > Dischi e spazio: spazio libero per volume.',
    license: 'gratuito per uso personale; licenza a pagamento per uso commerciale',
    site: 'https://diskanalyzer.com/',
    installs: true,
  },
  {
    id: 'windirstat',
    name: 'WinDirStat',
    vendor: 'WinDirStat',
    category: 'spazio',
    what: 'Mappa dello spazio sul disco per cartelle e tipi di file.',
    polaris: 'Computer > Dischi e spazio: spazio libero per volume.',
    license: 'open source, licenza GNU GPL v3',
    site: 'https://windirstat.net/',
    note: 'Alternativa open source a WizTree, adatta anche agli uffici.',
    installs: true,
  },
  {
    id: 'bluescreenview',
    name: 'BlueScreenView',
    vendor: 'NirSoft',
    category: 'errori',
    what: 'Legge i file delle schermate blu e indica il driver coinvolto.',
    polaris: 'Computer > Eventi: codice delle schermate blu con la spiegazione.',
    license: 'freeware',
    site: 'https://www.nirsoft.net/utils/blue_screen_view.html',
    installs: true,
  },
  {
    id: 'pc-health-check',
    name: 'Controllo integrità PC',
    vendor: 'Microsoft',
    category: 'windows',
    what: 'Verifica ufficiale dei requisiti di Windows 11, compreso il modello di processore.',
    polaris: 'Computer > Valutazione: requisiti di Windows 11 verificabili da Windows (sui PC con Windows 10).',
    license: 'gratuito',
    site: 'https://support.microsoft.com/it-it/windows/come-usare-l-app-controllo-integrit%C3%A0-pc-9c8abd9b-03ba-4e67-81ef-36f37caa7844',
    installs: true,
  },
];

export const CATEGORY_LABEL: Record<ToolCategory, string> = {
  disco: 'Dischi',
  hardware: 'Hardware',
  sicurezza: 'Sicurezza',
  avvio: 'Avvio e processi',
  spazio: 'Spazio su disco',
  errori: 'Errori',
  windows: 'Windows',
};
