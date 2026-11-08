// Cassetta degli attrezzi: gli strumenti di Windows che Polaris può aprire e
// i programmi gratuiti di diagnostica più noti, con il loro sito ufficiale.
// CrystalDiskInfo, CrystalDiskMark e BlueScreenView, che si possono
// ridistribuire, sono inclusi nel pacchetto come copie originali del
// produttore. Gli altri no: su richiesta Polaris ne scarica la versione
// portable dal sito ufficiale e la avvia solo con la firma del produttore,
// oppure apre quella già installata.
// Identificativi, siti, versioni incluse e download devono coincidere con
// l'agente (windows/internal/tools) e con scripts/strumenti.sh: lo verificano
// i test dell'agente. Siti, licenze, indirizzi e firme verificati sui siti dei
// produttori il 18 e il 19 ottobre 2026.

export type ToolCategory = 'disco' | 'hardware' | 'sicurezza' | 'avvio' | 'spazio' | 'errori' | 'windows';

/** Sezioni di Polaris a cui un programma esterno rimanda (stessi nomi delle viste dell'interfaccia). */
export type ToolView = 'pc' | 'wifi' | 'lan' | 'internet' | 'router' | 'infra';

export interface WinTool {
  id: string;
  name: string;
  what: string;
  /** La pagina esiste solo in questa versione di Windows: sull'altra il pulsante non compare. */
  win?: 10 | 11;
  /** Si apre chiedendo i permessi di amministratore. */
  admin?: boolean;
  /** Pagina usata solo nei passi delle azioni: non compare nella cassetta degli attrezzi. */
  stepOnly?: boolean;
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
  // Pagine aperte dai passi delle azioni. Indirizzi ms-settings dalla tabella
  // ufficiale "Launch Windows Settings" di Microsoft Learn (versione del
  // 2/11/2026); "win" dove la tabella o l'interfaccia indicano una sola
  // versione di Windows.
  { id: 'windows-update-optional', name: 'Aggiornamenti facoltativi', what: 'driver e aggiornamenti facoltativi proposti da Windows Update', stepOnly: true },
  { id: 'windows-update-history', name: 'Cronologia aggiornamenti', what: 'aggiornamenti installati, non riusciti e da disinstallare', stepOnly: true },
  { id: 'windows-update-options', name: 'Opzioni avanzate di Windows Update', what: 'orario di attività, riavvio, aggiornamenti di altri prodotti Microsoft', stepOnly: true },
  { id: 'storage-recommendations', name: 'Consigli per la pulizia', what: 'file grandi, inutilizzati e da liberare proposti da Windows', win: 11, stepOnly: true },
  { id: 'storage-sense', name: 'Sensore memoria', what: 'pulizia automatica di file temporanei e Cestino', stepOnly: true },
  { id: 'installed-apps', name: 'App installate', what: 'programmi installati, da modificare o disinstallare', stepOnly: true },
  { id: 'location-privacy', name: 'Impostazioni della posizione', what: 'permesso di posizione, che Windows 11 24H2 chiede per leggere le reti Wi-Fi', stepOnly: true },
  { id: 'network-status', name: 'Rete e Internet', what: 'stato della connessione e impostazioni di rete', stepOnly: true },
  { id: 'wifi-settings', name: 'Wi-Fi', what: 'reti Wi-Fi, proprietà della connessione e DNS', stepOnly: true },
  { id: 'known-networks', name: 'Gestisci reti note', what: 'reti Wi-Fi salvate, da dimenticare e ricollegare', stepOnly: true },
  { id: 'ethernet-settings', name: 'Ethernet', what: 'proprietà della connessione via cavo e DNS', stepOnly: true },
  { id: 'network-advanced', name: 'Impostazioni di rete avanzate', what: 'schede di rete e reimpostazione della rete', win: 11, stepOnly: true },
  { id: 'proxy-settings', name: 'Proxy', what: 'proxy della connessione a Internet', stepOnly: true },
  { id: 'network-connections', name: 'Connessioni di rete', what: 'le schede di rete del Pannello di controllo, con indirizzi e DNS', stepOnly: true },
  { id: 'printers', name: 'Stampanti e scanner', what: 'stampanti installate e loro code', stepOnly: true },
  { id: 'display', name: 'Schermo', what: 'risoluzione, frequenza e grafica', stepOnly: true },
  { id: 'about', name: 'Informazioni sul sistema', what: 'nome del PC, processore, memoria, versione di Windows', stepOnly: true },
  { id: 'device-encryption', name: 'Crittografia dispositivo', what: 'cifratura del disco (BitLocker o Crittografia dispositivo)', stepOnly: true },
  { id: 'remote-desktop', name: 'Desktop remoto', what: 'accesso al PC con Desktop remoto', stepOnly: true },
  { id: 'date-time', name: 'Data e ora', what: 'fuso orario e sincronizzazione dell\'ora', stepOnly: true },
  { id: 'advanced-system', name: 'Impostazioni di sistema avanzate', what: 'avvio e ripristino (file delle schermate blu), prestazioni, variabili', admin: true, stepOnly: true },
  { id: 'firewall-panel', name: 'Windows Defender Firewall', what: 'il firewall nel Pannello di controllo, con le regole per profilo', stepOnly: true },
  { id: 'power-options', name: 'Opzioni risparmio energia', what: 'combinazioni di risparmio energia e avvio rapido', stepOnly: true },
  { id: 'services', name: 'Servizi', what: 'i servizi di Windows e il loro avvio', stepOnly: true },
  { id: 'certificates-computer', name: 'Certificati del computer', what: 'archivio dei certificati del PC, con le autorità radice attendibili', admin: true, stepOnly: true },
  { id: 'uac-settings', name: 'Controllo dell\'account utente', what: 'livello degli avvisi prima delle modifiche al PC', admin: true, stepOnly: true },
];

/**
 * Parole con cui comincia il messaggio dell'agente quando Windows 11 24H2 blocca
 * la lettura del Wi-Fi per il permesso di posizione (LocationHint in
 * windows/internal/winapi/hints.go): la sezione Wi-Fi offre allora il pulsante
 * che apre le impostazioni della posizione. Un test controlla che il messaggio
 * dell'agente le contenga ancora.
 */
export const LOCATION_MARK = 'permesso di posizione';

/** Identificativo che apre il pannello di gestione del router dell'analisi (solo indirizzi privati). */
export const ROUTER_PANEL = 'router-panel';

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
  'update-crash-driver': ['device-manager', 'windows-update'],
  'test-memory': ['memory-diagnostic'],
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
  /** La sezione di Polaris dove si trova quella funzione, per il pulsante "Vai". */
  polarisView?: ToolView;
  license: string;
  site: string;
  note?: string;
  /** Si installa: Polaris può riconoscerlo e aprirlo. */
  installs?: boolean;
  /** Versione della copia originale inclusa nel pacchetto di Polaris. */
  included?: string;
  /** Versione portable che Polaris scarica dal sito ufficiale, su richiesta. */
  portable?: PortableInfo;
}

export interface PortableInfo {
  /** Sito da cui si scarica. */
  from: string;
  /** Editore della firma digitale verificata prima di ogni avvio. */
  signer: string;
  /** Dimensione indicativa del download, in MB. */
  mb: number;
  /** Versione fissata; senza, si scarica l'ultima pubblicata dal produttore. */
  version?: string;
  /** Condizioni d'uso da leggere prima di scaricare. */
  terms: string;
  /** Giorni dopo i quali il programma smette di funzionare e va riscaricato. */
  expiresDays?: number;
}

export const TOOLS: Tool[] = [
  {
    id: 'crystaldiskinfo',
    name: 'CrystalDiskInfo',
    vendor: 'Crystal Dew World',
    category: 'disco',
    what: 'Salute dei dischi: attributi SMART, temperatura, ore di accensione, avvisi in tempo reale.',
    polaris: 'Computer > Dischi e spazio: stato Buono/Attenzione/Critico, tabella SMART e registro NVMe.',
    polarisView: 'pc',
    license: 'open source, licenza MIT (i componenti di terze parti hanno le loro licenze, nella cartella License del programma)',
    site: 'https://crystalmark.info/en/software/crystaldiskinfo/',
    note: 'Seconda opinione sui dischi, con la cronologia dei valori e l\'avviso continuo dalla barra delle applicazioni; legge anche dischi dietro alcuni controller RAID e adattatori USB. Chiede i permessi di amministratore.',
    installs: true,
    included: '9.9.2',
  },
  {
    id: 'crystaldiskmark',
    name: 'CrystalDiskMark',
    vendor: 'Crystal Dew World',
    category: 'disco',
    what: 'Test di velocità dei dischi, il riferimento per confrontare i propri valori con quelli dichiarati.',
    polaris: 'Computer > Test di velocità: stesso profilo (SEQ1M Q8T1, SEQ1M Q1T1, RND4K Q32T1, RND4K Q1T1), in versione breve.',
    polarisView: 'pc',
    license: 'open source, licenza MIT (DiskSpd di Microsoft e gli altri componenti hanno le loro licenze, nella cartella License del programma)',
    site: 'https://crystalmark.info/en/software/crystaldiskmark/',
    note: 'Il test completo, con numero di passate, dimensione del file e unità a scelta: confronta i valori con quelli dichiarati dal produttore del disco.',
    installs: true,
    included: '9.0.3',
  },
  {
    id: 'cpu-z',
    name: 'CPU-Z',
    vendor: 'CPUID',
    category: 'hardware',
    what: 'Scheda tecnica di processore, scheda madre, memoria (con i dati dei moduli) e grafica.',
    polaris: 'Computer > Scheda tecnica: processore, cache, core P ed E, velocità dei core in tempo reale, moduli di memoria, firmware.',
    polarisView: 'pc',
    license: 'freeware; il produttore non ne concede la ridistribuzione: Polaris lo scarica dal sito ufficiale',
    site: 'https://www.cpuid.com/softwares/cpu-z.html',
    note: 'Legge anche i profili XMP/EXPO dei moduli, che Windows non mostra.',
    installs: true,
    portable: { from: 'download.cpuid.com', signer: 'CPUID', mb: 5.5, version: '3.01', terms: 'gratuito (freeware); all\'avvio chiede i permessi di amministratore e carica il proprio driver' },
  },
  {
    id: 'hwinfo',
    name: 'HWiNFO',
    vendor: 'Martin Malík (REALiX)',
    category: 'hardware',
    what: 'Sensori in tempo reale (temperature, tensioni, ventole, consumi) e inventario hardware dettagliato.',
    polaris: 'Computer > Sensori: utilizzo, frequenze e limite del processore, consumi se Windows li espone, zone termiche, scheda video (temperatura e ventola dal driver), memoria, dischi, rete, batteria, con minimo, massimo, media e CSV. Le temperature, le tensioni e le ventole di processore e scheda madre richiedono un driver: per quelle serve HWiNFO.',
    polarisView: 'pc',
    license: 'gratuito per uso personale (licenza Pro per uso commerciale: da verificare sul sito)',
    site: 'https://www.hwinfo.com/',
    note: 'La versione scaricata da Polaris è la 8.34, l\'ultima che il produttore ha pubblicato su SourceForge; le più recenti si scaricano dal sito ufficiale, che non consente download automatici.',
    installs: true,
    portable: { from: 'downloads.sourceforge.net', signer: 'REALiX, s.r.o.', mb: 18.6, version: '8.34', terms: 'gratuito per uso personale; per uso commerciale serve la licenza Pro; chiede i permessi di amministratore' },
  },
  {
    id: 'malwarebytes',
    name: 'Malwarebytes',
    vendor: 'Malwarebytes',
    category: 'sicurezza',
    what: 'Seconda opinione contro malware, adware e programmi indesiderati, con scansione a richiesta.',
    polaris: 'Computer > Antivirus: stato e scansioni di Microsoft Defender.',
    polarisView: 'pc',
    license: 'versione gratuita per scansione e rimozione a richiesta; protezione in tempo reale a pagamento',
    site: 'https://www.malwarebytes.com/mwb-download',
    note: 'All\'installazione può attivare una prova della versione a pagamento: per non avere due antivirus in tempo reale insieme a Defender, al termine della prova resta la sola scansione a richiesta (da verificare nelle impostazioni del programma). Senza installare nulla c\'è AdwCleaner, dello stesso produttore.',
    installs: true,
  },
  {
    id: 'adwcleaner',
    name: 'AdwCleaner',
    vendor: 'Malwarebytes',
    category: 'sicurezza',
    what: 'Trova e rimuove adware, programmi indesiderati, barre degli strumenti e dirottamenti del browser, senza installazione.',
    polaris: 'Computer > Antivirus: minacce rilevate da Microsoft Defender.',
    polarisView: 'pc',
    license: 'gratuito',
    site: 'https://www.malwarebytes.com/adwcleaner',
    note: 'Prima di confermare la pulizia guarda l\'elenco: alcune voci (barre, programmi preinstallati) potresti volerle tenere. Chiede i permessi di amministratore.',
    portable: { from: 'downloads.malwarebytes.com', signer: 'Malwarebytes Inc', mb: 9.6, terms: 'gratuito; si scarica sempre l\'ultima versione' },
  },
  {
    id: 'safety-scanner',
    name: 'Microsoft Safety Scanner',
    vendor: 'Microsoft',
    category: 'sicurezza',
    what: 'Scanner antimalware a richiesta, senza installazione, con il motore di Defender e firme fresche.',
    license: 'gratuito',
    site: 'https://learn.microsoft.com/it-it/defender-endpoint/safety-scanner-download',
    note: 'Smette di funzionare 10 giorni dopo il download: va riscaricato a ogni uso. Contiene le firme antivirus, per questo pesa più di 200 MB.',
    portable: { from: 'go.microsoft.com', signer: 'Microsoft Corporation', mb: 230, expiresDays: 10, terms: 'gratuito; smette di funzionare 10 giorni dopo il download' },
  },
  {
    id: 'eset-online-scanner',
    name: 'ESET Online Scanner',
    vendor: 'ESET',
    category: 'sicurezza',
    what: 'Scansione a richiesta con un motore diverso da quello di Microsoft: una vera seconda opinione.',
    license: 'gratuito',
    site: 'https://www.eset.com/int/home/online-scanner/',
    note: 'All\'avvio scarica il motore e le firme di ESET: serve Internet.',
    portable: { from: 'download.eset.com', signer: 'ESET, spol. s r.o.', mb: 8.4, terms: 'gratuito; si scarica sempre l\'ultima versione' },
  },
  {
    id: 'autoruns',
    name: 'Autoruns',
    vendor: 'Microsoft Sysinternals',
    category: 'avvio',
    what: 'Tutto ciò che parte da solo: programmi, servizi, driver, attività pianificate, estensioni.',
    polaris: 'Computer > Avvio e processi: chiavi Run e cartelle di esecuzione automatica.',
    polarisView: 'pc',
    license: 'gratuito',
    site: 'https://learn.microsoft.com/it-it/sysinternals/downloads/autoruns',
    note: 'Strumento per esperti: disattivare la voce sbagliata può impedire l\'avvio di Windows.',
    portable: { from: 'download.sysinternals.com', signer: 'Microsoft Corporation', mb: 3.2, terms: 'gratuito (licenza Sysinternals); si scarica sempre l\'ultima versione' },
  },
  {
    id: 'process-explorer',
    name: 'Process Explorer',
    vendor: 'Microsoft Sysinternals',
    category: 'avvio',
    what: 'Gestione attività avanzata: albero dei processi, file aperti, verifica delle firme e su VirusTotal.',
    polaris: 'Computer > Avvio e processi: i processi che pesano di più durante l\'analisi.',
    polarisView: 'pc',
    license: 'gratuito',
    site: 'https://learn.microsoft.com/it-it/sysinternals/downloads/process-explorer',
    portable: { from: 'download.sysinternals.com', signer: 'Microsoft Corporation', mb: 3.8, terms: 'gratuito (licenza Sysinternals); si scarica sempre l\'ultima versione' },
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
    polaris: 'Computer > Cosa occupa spazio: mappa delle cartelle, file più grandi, tipi di file e cartelle note di Windows con i consigli, senza installare nulla.',
    polarisView: 'pc',
    license: 'gratuito per uso personale; licenza a pagamento per uso commerciale',
    site: 'https://diskanalyzer.com/',
    installs: true,
    portable: { from: 'diskanalyzer.com', signer: 'Antibody Software Limited', mb: 7.9, version: '4.33', terms: 'gratuito per uso personale; per uso commerciale serve la licenza del produttore' },
  },
  {
    id: 'windirstat',
    name: 'WinDirStat',
    vendor: 'WinDirStat',
    category: 'spazio',
    what: 'Mappa dello spazio sul disco per cartelle e tipi di file.',
    polaris: 'Computer > Cosa occupa spazio: mappa delle cartelle, file più grandi e tipi di file.',
    polarisView: 'pc',
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
    polaris: 'Computer > Schermate blu: legge i minidump (da amministratore) con codice, parametri e driver indicato come indizio.',
    polarisView: 'pc',
    license: 'freeware, ridistribuibile gratuitamente e senza modifiche',
    site: 'https://www.nirsoft.net/utils/blue_screen_view.html',
    note: 'Legge i minidump in C:\\Windows\\Minidump: per vederli tutti chiede i permessi di amministratore.',
    installs: true,
    included: '1.55',
  },
  {
    id: 'pc-health-check',
    name: 'Controllo integrità PC',
    vendor: 'Microsoft',
    category: 'windows',
    what: 'Verifica ufficiale dei requisiti di Windows 11, compreso il modello di processore.',
    polaris: 'Computer > Valutazione: requisiti di Windows 11 verificabili da Windows (sui PC con Windows 10).',
    polarisView: 'pc',
    license: 'gratuito',
    site: 'https://support.microsoft.com/it-it/windows/come-usare-l-app-controllo-integrit%C3%A0-pc-9c8abd9b-03ba-4e67-81ef-36f37caa7844',
    installs: true,
  },
];

/**
 * Programmi della cassetta utili per ciascuna azione del piano: compaiono
 * nell'azione con lo stato (incluso, installato, scaricabile) e il pulsante
 * per aprirli. Sono un secondo parere o un passo in più: dove Polaris fa già
 * la stessa cosa lo dice ("polaris" del programma).
 */
export const ACTION_APPS: Record<string, string[]> = {
  'check-disk-errors': ['crystaldiskinfo'],
  'backup-replace-disk': ['crystaldiskinfo'],
  'cool-disk': ['crystaldiskinfo', 'hwinfo'],
  'upgrade-ssd': ['crystaldiskmark', 'crystaldiskinfo'],
  'free-disk-space': ['wiztree', 'windirstat'],
  'space-analysis': ['wiztree', 'windirstat'],
  'review-large-files': ['wiztree', 'windirstat'],
  'diagnose-bsod': ['bluescreenview'],
  'update-crash-driver': ['bluescreenview'],
  'read-crash-files': ['bluescreenview'],
  'test-memory': ['memtest86'],
  'check-hardware': ['memtest86', 'hwinfo'],
  'check-temperatures': ['hwinfo'],
  'cool-cpu': ['hwinfo'],
  'check-power-supply': ['hwinfo'],
  'trim-startup': ['autoruns'],
  'close-heavy-apps': ['process-explorer'],
  'remove-threats': ['safety-scanner', 'eset-online-scanner', 'adwcleaner'],
  'upgrade-windows': ['pc-health-check'],
  'firmware-security': ['pc-health-check'],
  'add-ram': ['cpu-z'],
  'dual-channel': ['cpu-z'],
};

export const CATEGORY_LABEL: Record<ToolCategory, string> = {
  disco: 'Dischi',
  hardware: 'Hardware',
  sicurezza: 'Sicurezza',
  avvio: 'Avvio e processi',
  spazio: 'Spazio su disco',
  errori: 'Errori',
  windows: 'Windows',
};
