# Architettura

Il programma si chiamava LANterna fino alla versione 0.2.0: il repository e il modulo Go (`lanterna/...`) conservano quel
nome, che non compare più all'utente.

```
            ┌──────────────────────────── core/ (TypeScript) ────────────────────────────┐
            │  engine/   motore di analisi puro, senza DOM                                │
            │    types.ts       contratto dati Scan → Analysis                            │
            │    kb/metrics.ts  cos'è, come si legge (soglie), perché conta, limiti      │
            │    kb/actions.ts  catalogo azioni correttive condiviso                      │
            │    kb/assessment.ts  autovalutazione: aree, domande, punteggi               │
            │    analyze.ts     diagnosi, punteggi, piano d'azione                        │
            │    pc.ts          computer: Windows e supporto, dischi, eventi, test        │
            │    wifi.ts        canali, spettro, interferenza, AP della rete              │
            │    report.ts      rapporto testuale                                         │
            │    document.ts    documento stampabile: HTML A4 autonomo                    │
            │  guides/   66 guide come dati tipizzati, glossario, ricerca                 │
            │  demo/     PC e reti dimostrative Casa e Clinica, simulazioni               │
            │  ui/       interfaccia React (animazioni, suoni, grafici SVG, 10 viste)     │
            └───────────────▲───────────────────────────────▲────────────────────────────┘
                            │ stesso bundle                  │ engine.js (IIFE ES2015)
             interfaccia    │                                │
   ┌────────────────────────┴───────────┐     ┌──────────────┴───────────────┐
   │ WebView2 / browser / WebView       │     │ goja (interprete JS in Go)   │
   └────────────────────────▲───────────┘     └──────────────▲───────────────┘
                            │ HTTP /api (127.0.0.1)          │ JSON
   ┌────────────────────────┴───────────────────────────────┴───────────────┐
   │ windows/  agente Go: sonde → Scan (JSON)                                  │
   │   winapi/  wlanapi, IcmpSendEcho, GetAdaptersAddresses, ARP, firewall   │
   │   wlan/ ie/ netsh/  interpretazione byte per byte, collaudata ovunque   │
   │   probe/   DNS, UPnP/SSDP, porte e pannello del router, HTTPS          │
   │   infra/   inventario e verifiche su richiesta, ritmo prudente          │
   │   pcinfo/  dati del computer: API native + uno script PowerShell        │
   │   bench/   test di velocità di processore e dischi, su richiesta        │
   │   cpuclock/ velocità dei core in tempo reale dai contatori PDH          │
   │   defender/ Microsoft Defender: stato, minacce, scansioni a richiesta   │
   │   tools/   cassetta degli attrezzi: inclusi, scaricati, kit, lista bianca │
   │   winps/   avvio di Windows PowerShell senza moduli ereditati           │
   │   collect/ orchestrazione parallela con avanzamento reale               │
   │   server/  API locale + interfaccia incorporata                         │
   └──────────────────────────────────────────────────────────────────────────┘
   Android (plugin Kotlin) ed ESP32 (firmware ESP-IDF) produrranno lo stesso Scan.
```

## Principio: le sonde misurano, il nucleo interpreta

Ogni piattaforma produce uno `Scan` (`core/src/engine/types.ts`, rispecchiato in `windows/internal/scan/scan.go`) con **soli dati
grezzi**. Le spiegazioni, le soglie, i punteggi e il piano d'azione stanno solo nel motore TypeScript, così:

- un valore è spiegato allo stesso modo su Windows, Android ed ESP32;
- il rapporto da riga di comando dell'exe è identico a quello dell'interfaccia: l'exe esegue lo **stesso** `engine.js` con goja;
- un rapporto JSON salvato su una piattaforma si apre nell'interfaccia di un'altra (pulsante *Importa*).

Ogni campo dello `Scan` è facoltativo: una sonda che non sa misurare qualcosa lo omette e registra il motivo in `errors`; il
motore lo mostra come "non misurato" invece di inventare un giudizio.

## Motore di analisi

- Ogni misura diventa un `Finding` con gravità (`ok`, `info`, `warn`, `crit`, `unknown`), un verdetto contestuale ("-71 dBm: segnale
  debole…") e le azioni che lo risolvono.
- La knowledge base (`kb/metrics.ts`) contiene per ogni metrica la scala di lettura con le stesse soglie usate dal motore:
  l'interfaccia evidenzia la fascia in cui cade il valore misurato.
- Le diagnosi incrociano le misure: latenza alta verso Internet con router reattivo → linea o operatore; anche verso il router →
  problema in casa. Un router che ignora i ping ma risponde su altre porte non è "guasto". Un traceroute con un solo nodo lento non
  è un'anomalia.
- Il piano d'azione unisce le azioni ripetute (es. *Avvicina il dispositivo al router* risolve segnale, perdite e jitter) e le
  ordina per gravità, impatto, numero di problemi risolti e facilità.
- Il consiglio sui canali stima l'interferenza dallo spettro occupato da ogni rete, pesato per potenza e per il carico dichiarato
  (BSS Load). A 2,4 GHz consiglia solo 1, 6 o 11; a 5 GHz preferisce 36-48, poi i blocchi DFS, per ultimo 149-161 (in Italia/UE
  ammesso solo a bassa potenza). Le altre reti trasmesse dalle stesse radio (ospiti, dispositivi: BSSID che differiscono solo
  nell'ultima cifra o nel primo ottetto) non contano come interferenza.
- **Reti con più access point.** Gli AP della rete collegata si stimano contando le radio per banda (un router dual band conta
  uno); le radio con una protezione di famiglia diversa non sono AP della rete ma un possibile AP gemello, segnalato a parte. Il
  motore controlla AP propri sullo stesso canale che si ricevono entrambi sopra -80 dBm, il PC agganciato a un AP debole quando
  uno della stessa banda è più forte di almeno 10 dB (il giudizio sul segnale allora punta all'AP scelto, non alla copertura) e
  il roaming assistito (802.11k/v/r, uniformità tra AP, Mobility Domain).
- **Reti aziendali.** Un dominio (o un suffisso DNS non domestico con soli DNS interni) cambia i consigli: niente DNS pubblici sul
  PC, ma il DNS interno da potenziare. Sottoreti da /20 in su sono indicate come probabile rete piatta; lo stesso MAC per più
  indirizzi è un avviso se riguarda il router.
- **Infrastruttura.** Inventario, verifiche e autovalutazione entrano nello `Scan` (`infra`) e diventano giudizi di una categoria
  propria, che conta nel punteggio solo quando ci sono dati: segmentazione violata e servizi critici irraggiungibili sono critici;
  ogni area dell'autovalutazione ha un punteggio pesato e porta nel piano le azioni mancanti.
- **Computer** (`pc.ts`). La categoria `pc` pesa nel punteggio quanto il Wi-Fi, così il punteggio descrive PC e rete insieme;
  antivirus e aggiornamenti sono giudizi della categoria `security` ma si mostrano nella sezione Computer. Il supporto di Windows
  si valuta sulla data dell'analisi con un calendario per versione ed edizione (Windows 11 Home/Pro 24 mesi, Enterprise/Education
  36; Windows 10 con ESU; LTSC e Server da verificare), condiviso con la guida che lo riporta. Kernel-Power 41 ed EventLog 6008
  descrivono lo stesso spegnimento e non si sommano; gli errori di disco si collegano al disco del dettaglio (`HarddiskN`) e su
  unità USB valgono come semplice informazione. I test di velocità si confrontano con le soglie del tipo di unità (NVMe, SATA,
  HDD, USB). Un disco con guasto previsto diventa il problema più urgente del titolo e l'azione *copia i dati* sale in cima al
  piano (`URGENT_ACTIONS`). Date in italiano con la preposizione giusta ("dall'11 novembre"), senza `Intl` perché il motore gira
  anche in goja.
- **Documento stampabile** (`document.ts`). `documentParts` produce titolo, CSS e corpo; `renderDocument` li unisce in un HTML
  autonomo (nessuno script, immagine o collegamento esterno) in formato A4. Lo usano l'interfaccia (anteprima, stampa, file HTML)
  e l'exe (`report --html`, attraverso goja: per questo è scritto in ES2015 senza `Intl`). Tutti gli stili stanno sotto `.pdoc`,
  così l'anteprima non tocca il resto della pagina, salvo `@page`. I testi passano da un filtro che toglie indirizzi MAC e IPv4
  pubblici (restano gli indirizzi privati, i resolver 1.1.1.1, 8.8.8.8 e 9.9.9.9 e i numeri di versione); il logo è quello a
  colori, su fondo chiaro.

## Interfaccia

L'identità visiva viene dal marchio STARNET (`brand/`): blu profondo `#022D62` e ciano `#00B9FE`, esagono a punta in alto come la
cornice del logo, stella a quattro punte come accento. Il logo si usa solo nelle due versioni previste dalla sua guida (bianco sui
fondi scuri, a colori sui chiari), mai con ombre o deformazioni.

React 18 con un piccolo insieme di librerie, ciascuna con un compito preciso (versioni e licenze in `THIRD_PARTY_NOTICES.md`):

| Libreria | A cosa serve |
| --- | --- |
| Motion 13 (`motion/react`, MIT) | tutte le animazioni: entrate in cascata, molle fisiche, `AnimatePresence` per pagine/avvisi/pannelli, indicatori che scivolano (`layoutId`), tracciamento delle linee SVG (`pathLength`), barra superiore legata allo scorrimento. Caricata con `LazyMotion` in modalità *strict* e `MotionConfig reducedMotion="user"` |
| Lucide (`lucide-react`, ISC) | icone: si importano solo quelle usate |
| Radix Colors (MIT) | scale dei colori di stato (verde, indaco, ambra, rosso) per tema chiaro e scuro, nella variante P3 dove lo schermo la supporta; il blu e il ciano sono lasciati al marchio |
| Fontsource (font OFL-1.1) | Inter (testo), Saira con l'asse della larghezza (titoli e numeri grandi in versione estesa, vicina alla scritta STARNET), JetBrains Mono (valori misurati); solo i sottoinsiemi latini, incorporati nell'exe (~270 kB) |

Organizzazione di `core/src/ui/`:

- `brand.tsx` e `brand-paths.ts`: il marchio disegnato con i tracciati originali (generati da `scripts/brand.mjs` a partire dagli
  SVG ufficiali, mai ricopiati a mano). All'avvio la cornice si rivela in senso orario dal vertice alto, come il tratto ciano, e
  le due metà della stella si incastrano lungo la S; la forma finale è sempre quella originale. Da qui anche l'esagono del
  punteggio (`HexGauge`), che si riempie nello stesso verso.

- `motion.ts`: il linguaggio del movimento in un solo posto. Curva di uscita lunga per ciò che entra, curva simmetrica e breve per
  ciò che esce, tre molle (`snappy` per pressioni e indicatori, `smooth` per pannelli e layout, `gentle` per numeri e grafici).
  Tempi: 150-200 ms le microinterazioni, 300-450 ms le transizioni, 600-1200 ms i dati.
- `styles.css`: token di colore, raggi e ombre per i due temi; nessun framework CSS.
- `theme.ts`: tema automatico, scuro o chiaro (classi `dark`/`light` su `<html>`, le stesse usate da Radix); il cambio usa le View
  Transitions con un cerchio che si apre dal pulsante.
- `fx.ts`: grafica leggera. Misura la mediana del tempo tra i fotogrammi nei primi secondi; se supera 26 ms (meno di ~38 fps) toglie
  sfocature, trasparenze, bagliori e stelle animati e la rivelazione circolare del tema. La scelta manuale nella barra laterale vince
  sulla misura ed è ricordata.
- `scan.tsx`: la schermata di analisi. Al centro il simbolo STARNET, con una cornice esagonale che si completa con l'avanzamento
  reale di `/api/progress`; ogni sonda è una stella in orbita che, finita, si collega alla precedente formando una costellazione.
- `charts.tsx`: grafici SVG disegnati alla larghezza reale del contenitore (1 unità = 1 pixel, testi mai deformati), curve monotone
  che non inventano picchi; il monitor scorre in modo continuo invece che a scatti.
- `guides.tsx` e `diagrams.tsx`: il centro guide (biblioteca, lettore con indice, glossario, riferimento delle soglie, ricerca) e i
  diagrammi SVG animati all'ingresso nella vista, fermi con "riduci movimento".
- `infra.tsx`: la sezione Infrastruttura. L'inventario vive a livello di modulo, quindi prosegue anche cambiando pagina; senza
  agente (demo) inventario e verifiche sono simulati da `demo/simulate.ts` e dichiarati come tali; con un rapporto importato si
  consultano solo i risultati salvati.
- `anim.tsx`: icone animate in CSS (si disegnano, entrano con una spinta, girano, pulsano, scorrono), il caricamento a esagono
  (`HexLoader`, un tratto che percorre la cornice del marchio) e i segnaposto con riflesso (`Skeleton`). Tutto sotto
  `prefers-reduced-motion: no-preference`; il marchio non viene mai animato con effetti.
- `sound.ts`: suoni sintetizzati con Web Audio (oscillatori con attacco breve e coda esponenziale, volume generale 0,14), senza
  file audio. Sette segnali: tocco, apertura, riuscito, concluso, avviso, errore, richiamo. Stato fuori da React
  (`useSyncExternalStore`) così che messaggi e monitor possano suonare; preferenza in `localStorage`. Il contesto audio si sblocca
  al primo clic o tasto (regola dei browser) e finché è sospeso i suoni si saltano invece di accumularsi.
- `document.tsx`: anteprima del documento in un dialogo; "Stampa o salva PDF" aggiunge a `<html>` la classe `pdoc-printing`, che
  in stampa nasconde tutto tranne il documento.
- `clock.tsx`: velocità dei core in tempo reale nella scheda tecnica. Una lettura al secondo solo mentre il riquadro è montato e la
  pagina visibile; pausa; dopo un errore le letture si fermano fino a Riprova; nella demo valori simulati e dichiarati.
- `toolbox.tsx`: stato della cassetta condiviso a livello di modulo (una richiesta alla volta, rilettura ogni 400 ms durante un
  download anche cambiando sezione), conferma prima di scaricare, avanzamento, pannello del kit con coda ed esito.
- `monitor.ts`: la sessione del monitor appartiene all'App e continua fra le sezioni; riepilogo dell'intera sessione (media, 95°
  percentile, massimo con l'ora, perdite, interruzioni di almeno tre ping consecutivi, picchi oltre 2,5 volte il valore tipico) e
  CSV per i fogli di calcolo italiani (`;` e virgola decimale). Tre misure perse di fila suonano un richiamo, il ritorno della
  connessione un segnale di via libera.
- Autovalutazione e destinazioni delle verifiche restano in `localStorage`, separate per contesto (rete, demo); l'App le unisce
  allo `Scan` prima dell'analisi e delle esportazioni. Il MAC del router di ogni rete è ricordato per segnalare un cambio.

Accessibilità: navigazione completa da tastiera (scorciatoie `1`…`9` e `/`, ignorate mentre si scrive; frecce nei selettori a
segmenti e nei gruppi di risposte; collegamento "Vai al contenuto"), ruoli e stati ARIA su schede espandibili, interruttori e caselle, tabelle scorrevoli
raggiungibili con Tab, contrasto WCAG 2.1 AA in entrambi i temi, `prefers-reduced-motion` e `prefers-reduced-transparency`
rispettati. Le scelte sono state verificate con axe-core: [VERIFICHE.md](VERIFICHE.md).

## Agente Windows

| Misura | Come | Note |
| --- | --- | --- |
| Wi-Fi | `WlanGetNetworkBssList` + decodifica degli IE 802.11 (RSN, WPA, WPS, HT/VHT/HE/EHT Operation, BSS Load, Country) | dBm reali e larghezza effettiva; riserva `netsh wlan show interfaces` (it/en, tollerante alla code page) |
| Schede | `GetAdaptersAddresses` | ordinate come le sceglie Windows; gateway IPv4 anche dove `INCLUDE_GATEWAYS` è supportato solo con `AF_INET` |
| Ping, traceroute, MTU | `IcmpSendEcho` | nessun privilegio richiesto; traceroute con sonde scaglionate in parallelo; MTU con bit DF e ricerca binaria; riserva TCP se l'ICMP è filtrato |
| Dispositivi | `GetIpNetTable` | esclusi broadcast e multicast |
| Firewall | PowerShell `Get-NetFirewallProfile -PolicyStore ActiveStore` + `Get-NetConnectionProfile` | riserva sul registro (criteri inclusi) |
| DNS | richieste UDP costruite a mano, mediana su 5 nomi | NXDOMAIN conta come risposta |
| UPnP | SSDP + descrizione XML + `GetExternalIPAddress` | si contattano solo URL http della LAN privata |
| Router | connessione TCP alle porte di gestione comuni del **solo gateway**; intestazione e titolo del pannello | nessuna autenticazione |
| Roaming | IE 54 (Mobility Domain e FT su DS), 70 (RM Enabled Capabilities, Neighbor Report) e 127 (Extended Capabilities, BSS Transition); AKM FT | per ogni rete visibile, dagli stessi beacon |
| Dominio e DHCP | `GetComputerNameExW(ComputerNameDnsDomain)`; suffisso DNS e `Dhcpv4Server` da `GetAdaptersAddresses` | il server DHCP solo se la struttura restituita lo contiene |
| Inventario (su richiesta) | `IcmpSendEcho` a ogni indirizzo della sottorete (circa 30 al secondo, 8 in parallelo), poi `GetIpNetTable`, DNS inverso e richiesta NetBIOS *node status* (UDP 137) ai soli dispositivi trovati | solo reti private; oltre /22 solo il blocco /24 del PC; interruzione dopo 4 minuti |
| Verifiche (su richiesta) | connessione TCP alla porta indicata (aperta, chiusa con rifiuto, filtrata) o due ping; nomi risolti prima, preferendo IPv4 | solo destinazioni private, al massimo 64, 4 alla volta |
| Computer: sistema | `RtlGetVersion`, registro (`CurrentVersion`, `CentralProcessor`, `HiberbootEnabled`, chiavi dei riavvii in sospeso), `GetTickCount64`, `GlobalMemoryStatusEx`, `GetSystemPowerStatus`, `PowerGetActiveScheme` | Windows 11 riconosciuto dalla build (il registro dice ancora "Windows 10") |
| Computer: volumi | `GetLogicalDriveStrings`, `GetDriveType`, `GetDiskFreeSpaceEx`, `GetVolumeInformation` | solo dischi locali e rimovibili: niente unità di rete o CD |
| Computer: avvio e processi | chiavi `Run` (utente, computer, 32 bit), cartelle di esecuzione automatica, `StartupApproved`; Toolhelp32 + `GetProcessTimes` + `K32GetProcessMemoryInfo` su 1,5 s a fine analisi | cartella dell'utente sostituita da `%USERPROFILE%`; processi raggruppati per nome |
| Computer: dischi, eventi, sicurezza | un solo script PowerShell nascosto (vedi sotto) con uscita JSON: `Get-PhysicalDisk`, `Get-Partition`, `Get-StorageReliabilityCounter` (da amministratore), classi batteria di `root/wmi`, `Get-WinEvent` (livelli 1-3, 30 giorni, 14 codici), `root/SecurityCenter2` con riserva `Get-MpComputerStatus`, `Get-HotFix`, `Win32_Processor`, `Win32_VideoController` | ogni sezione protetta da `try`; timeout di 40 s; niente numeri di serie |
| Computer: SMART (da amministratore) | apertura del disco fisico in sola lettura, in parallelo allo script; `IOCTL_STORAGE_QUERY_PROPERTY` per il tipo di bus e, sugli NVMe, per il registro di salute (log 02h); sui SATA `IOCTL_ATA_PASS_THROUGH` (comandi SMART READ DATA e READ THRESHOLDS) con riserva `SMART_RCV_DRIVE_DATA` | stato Buono/Attenzione/Critico con le regole di CrystalDiskInfo: attributo guasto se l'attuale scende alla soglia; 05, C5, C6 e BB non nulli danno "Attenzione"; bit di avviso critico NVMe |
| Computer: scheda tecnica | `GetLogicalProcessorInformationEx` (core per classe di efficienza, cache per livello e tipo), istruzioni lette con CPUID, `GetFirmwareType`, Secure Boot dal registro, memoria video dal registro (`qwMemorySize`); nello script `Win32_ComputerSystem`, `Win32_BaseBoard`, `Win32_BIOS`, `Win32_PhysicalMemory`, `Win32_PhysicalMemoryArray`, TPM da `Win32_PnPEntity` | sola lettura; niente numeri di serie |
| Microsoft Defender | `Get-MpComputerStatus`, `Get-MpThreat` e `Get-MpThreatDetection` nello script; su richiesta `MpCmdRun.exe -Scan -ScanType 1\|2`, `-SignatureUpdate`, `-Scan -Cancel`, poi nuova lettura di stato e minacce | delle minacce solo nome, gravità, stato e date: niente percorsi dei file né nomi utente; non si sovrappone ai test di velocità |
| Cassetta degli attrezzi | `ShellExecute` di una voce della lista bianca (comando di Windows, indirizzo `ms-settings:`, programma trovato tra le voci di disinstallazione con un eseguibile ammesso, programma incluso o scaricato, sito https del produttore), con la cartella del programma come cartella di lavoro | da amministratore i siti si aprono tramite Esplora risorse, con i permessi normali; i programmi inclusi in `strumenti/` partono solo se l'eseguibile ha l'impronta SHA-256 scritta nell'agente; precedenza: incluso, poi scaricato, poi installato |
| Versioni portable (su richiesta) | `tools.Fetcher`: download https con il proxy di sistema, host ammessi controllati a ogni rimando, cookie (i mirror di SourceForge li usano), fino a 3 tentativi; limite di dimensione, risposte HTML scartate; estrazione dello zip con `filepath.IsLocal` e limite totale; impronta SHA-256 dell'archivio per le versioni fissate; firma Authenticode (`Get-AuthenticodeSignature`: stato `Valid` e nome del firmatario uguale a quello atteso) al download e prima di ogni avvio | in `%LOCALAPPDATA%\STARNET Polaris\strumenti\<id>` con `polaris.json` (impronta dell'eseguibile, versione, firmatario, data, indirizzo); l'impronta si ricalcola solo se cambiano dimensione o data del file; Safety Scanner scade dopo 10 giorni |
| Kit per i PC senza Internet (su richiesta) | lo stesso `Fetcher` scrive in `strumenti-scaricati` accanto all'exe (con un LEGGIMI); `Find` cerca nella cartella del PC e nel kit e preferisce la prima copia integra, prima quella del PC | la cartella deve essere scrivibile (verifica prima di partire, messaggi senza percorsi); sui PC senza rete valgono le stesse verifiche: impronta registrata e firma |
| Velocità dei core (dal vivo) | PDH con `PdhAddEnglishCounterW` (nomi uguali in ogni lingua): `\Processor Information(*)\% Processor Performance`, `Processor Frequency` e `% Processor Time`, letti con `PdhGetFormattedCounterArrayW` e `PDH_FMT_NOCAP100` (il turbo supera il 100 %); frequenza di un core = nominale × prestazioni / 100, media dall'istanza `_Total` come Gestione attività | i contatori si aprono alla prima lettura (due raccolte a 250 ms), letture ravvicinate condividono il campione, chiusura dopo un minuto senza letture; nominale di riserva da `~MHz` nel registro; bus nominale da SMBIOS (`Win32_Processor.ExternalClock`); nessun driver |
| Test del processore (su richiesta) | `compress/flate` su un testo sintetico deterministico: 3 s con un thread, 20 s con tutti, campioni al secondo | punta = migliore media su 3 s nella prima metà; finale = media dell'ultimo quarto |
| Test del disco (su richiesta) | `CreateFile` con `FILE_FLAG_NO_BUFFERING`, `FILE_FLAG_DELETE_ON_CLOSE` e `FILE_FLAG_OVERLAPPED`; ogni richiesta in coda è una goroutine con la sua `OVERLAPPED` e il suo evento (`GetOverlappedResult`); profilo di CrystalDiskMark: SEQ1M Q8T1, SEQ1M Q1T1, RND4K Q32T1, RND4K Q1T1, 4 s per misura | file fino a 1 GiB (o ciò che si scrive in 15 s), almeno 2 GiB lasciati liberi, buffer allineati a 4 KiB e dati non comprimibili |

Gli script PowerShell (dati del PC, Defender, firewall, verifica delle firme) passano da `winps`: `powershell.exe` dalla cartella
di sistema, mai un omonimo nel `PATH`, senza finestra e senza la variabile `PSModulePath`. Se Polaris viene avviato da
PowerShell 7 la eredita con i moduli di PowerShell 7 in testa, e Windows PowerShell proverebbe a caricare quelli (per esempio
`Microsoft.PowerShell.Security`, fatto per .NET Core); senza la variabile usa i propri percorsi predefiniti. All'errore di uno
script si aggiunge la prima riga scritta da PowerShell.

Modalità del programma: `Polaris.exe` (finestra), `report` (anche `--html`), `serve`, `bench cpu`, `bench disk`,
`defender status|quick|full|update`, `tools status|kit` e `clock`. La finestra usa WebView2; se il runtime manca (o non
funziona) STARNET Polaris lo dice con un messaggio e apre l'interfaccia nel browser predefinito. `Polaris.exe` è compilato come
applicazione grafica e si aggancia alla console del prompt quando riceve un comando; `polaris-cli.exe` è la stessa cosa compilata
per la console, comoda negli script.

## API locale

| Metodo e percorso | Risposta |
| --- | --- |
| `GET /api/info` | nome, versione, piattaforma, host |
| `GET /api/scan` | ultimo `Scan`, oppure `204` se non c'è ancora |
| `POST /api/scan` | `202` avvia un'analisi, `409` se è già in corso |
| `GET /api/progress` | fasi dell'analisi con stato reale (`pending`, `running`, `done`, `error`) |
| `GET /api/ping?target=gateway\|internet` | un singolo tempo di risposta per il monitor; usa la riserva TCP se nell'analisi l'host rispondeva solo così |
| `POST /api/inventory` | corpo `{"authorized": true}`: `202` avvia l'inventario della sottorete del PC; `400` senza conferma, `415` senza JSON, `422` se la rete non è privata o non ha altri indirizzi, `409` se è già in corso |
| `GET /api/inventory` | avanzamento (`ping`, poi `nomi`), eventuale errore e ultimo inventario |
| `POST /api/reach` | corpo `{"targets": [{"label", "host", "port", "expect": "reachable"\|"isolated"}]}`: esiti delle verifiche (sincrono, al massimo 2 minuti); `400` se le destinazioni non sono valide, `409` se ne è già in corso una |
| `GET /api/reach` | ultime verifiche, oppure `204` |
| `POST /api/bench` | corpo `{"kind": "cpu"}` oppure `{"kind": "disk", "drive": "C:", "confirm": true}`: `202` avvia il test; `400` senza conferma o con unità non valida, `422` se l'unità non è un disco locale o rimovibile, `409` se c'è un test o un'analisi in corso |
| `GET /api/bench` | test in corso con fase e avanzamento (campioni al secondo per il processore), eventuale errore e ultimi risultati |
| `DELETE /api/bench` | interrompe il test in corso; il file temporaneo del test del disco viene cancellato |
| `POST /api/defender` | corpo `{"action": "quick"\|"full"\|"update"}`: `202` avvia l'operazione; `400` per un'azione non valida, `422` se Defender non è disponibile, `409` se c'è già un'operazione o un test di velocità in corso |
| `GET /api/defender` | operazione in corso, eventuale errore ed esito dell'ultima (con stato e minacce riletti) |
| `DELETE /api/defender` | interrompe la scansione in corso |
| `GET /api/cpu/clock` | frequenza effettiva dei core in questo istante: media, core più veloce, nominale, percentuale, carico e valori per processore logico; `501` se i contatori non esistono, `503` se la lettura non riesce |
| `GET /api/tools` | programmi della cassetta installati (`installed`), inclusi nel pacchetto (`bundled`) e scaricati (`portable`, con `kit` per le copie del kit e `expired` per quelle scadute), con `problem` se l'eseguibile non è quello verificato; programmi scaricabili su questo PC (`fetchable`), disponibilità del kit (`kit`) e download in corso o concluso (`fetch`: programma, byte, totale, errore; per il kit anche `queue`, `ready` e `failed`). Mai percorsi |
| `POST /api/tools/fetch` | corpo `{"tool": "<id>"}`: `202` avvia il download della versione portable; `404` fuori catalogo, `400` se il programma non ha una versione portable per questo PC, `409` se c'è già un download, `501` se l'agente non scarica |
| `POST /api/tools/kit` | corpo `{"tools": ["<id>", ...]}`: `202` avvia la preparazione del kit (duplicati ignorati); `404` e `400` come sopra, `400` con elenco vuoto, `422` se la cartella di Polaris non è scrivibile, `409` se c'è già un download |
| `DELETE /api/tools/fetch` | interrompe il download o la preparazione del kit |
| `POST /api/tools/remove` | corpo `{"tool": "<id>"}`: elimina la copia scaricata (prima quella del PC, poi quella del kit); `409` se è in download o in coda |
| `POST /api/open` | corpo `{"tool": "<id>", "target": "app"\|"site"}`: apre uno strumento di Windows, un programma (la copia inclusa se integra, poi quella scaricata, con la firma verificata di nuovo, poi quella installata) o il sito ufficiale; `404` per un identificativo fuori dalla lista bianca, `400` per una destinazione non valida, `422` se il programma non c'è o la copia è alterata, `409` se la richiesta dei permessi di amministratore viene annullata |

Sicurezza: ascolto solo su `127.0.0.1`; richieste con `Host` diverso da localhost rifiutate (DNS rebinding); `POST` con `Origin`
estranea o `Sec-Fetch-Site: cross-site` rifiutate (CSRF); i `POST` di inventario e verifiche accettano solo corpi
`application/json` fino a 64 kB, che una pagina di un altro sito non può inviare senza un preflight CORS (lo stesso vale per i
test di velocità, Defender e l'apertura degli strumenti, e `DELETE` richiede comunque un preflight); `/api/open` riceve solo
identificativi, mai percorsi o comandi; i download seguono solo https e gli host del programma, anche nei rimandi, e un
programma scaricato parte solo con la firma dell'editore atteso; CSP restrittiva
sull'interfaccia; nessuna intestazione CORS. ESP32 ed
eventuali altri agenti esporranno la stessa API, quindi l'interfaccia non cambia.

## Scelte e alternative scartate

- **Go invece di C#/.NET**: un solo eseguibile statico, nessun runtime da installare, compilazione incrociata da qualunque sistema.
- **WebView2 invece di Electron**: l'eseguibile pesa ~16 MB invece di ~150 MB; il motore di rendering è lo stesso Chromium.
- **goja invece di riscrivere il motore in Go**: una sola implementazione delle spiegazioni e delle soglie.
- **IcmpSendEcho invece di `ping.exe`**: niente output localizzato da interpretare, nessuna finestra di console, tempi sotto il millisecondo.
- **Motion invece di GSAP**: copre da sola animazioni React, layout e SVG; GSAP avrebbe duplicato le stesse funzioni con una licenza
  propria non OSI. Nessun framework CSS (Tailwind, shadcn/ui, daisyUI): i componenti sono pochi e su misura, e i token CSS bastano.
- **SVG disegnato a mano invece di Three.js, Lottie o particelle**: grafici e schermata di analisi rappresentano dati veri; una scena
  3D o un'animazione preconfezionata avrebbero aggiunto peso senza informazione. Niente scorrimento "morbido" simulato (Lenis):
  quello nativo di WebView2 è già fluido e rispetta le impostazioni di accessibilità.
