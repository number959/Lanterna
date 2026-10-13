# Architettura

Il programma si chiamava LANterna fino alla versione 0.2.0: il repository e il modulo Go (`lanterna/...`) conservano quel
nome, che non compare più all'utente.

```
            ┌──────────────────────────── core/ (TypeScript) ────────────────────────────┐
            │  engine/   motore di analisi puro, senza DOM                                │
            │    types.ts       contratto dati Scan → Analysis                            │
            │    kb/metrics.ts  cos'è, come si legge (soglie), perché conta, limiti      │
            │    kb/actions.ts  catalogo azioni correttive condiviso                      │
            │    analyze.ts     diagnosi, punteggi, piano d'azione                        │
            │    wifi.ts        canali, spettro, interferenza, canale consigliato         │
            │    report.ts      rapporto testuale                                         │
            │  ui/       interfaccia React (animazioni, grafici SVG, 8 viste)             │
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
  ammesso solo a bassa potenza).

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

Accessibilità: navigazione completa da tastiera (scorciatoie `1`…`8` e `/`, ignorate mentre si scrive; frecce nei selettori a
segmenti; collegamento "Vai al contenuto"), ruoli e stati ARIA su schede espandibili, interruttori e caselle, tabelle scorrevoli
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

Modalità del programma: `Polaris.exe` (finestra), `report`, `serve`. La finestra usa WebView2; se il runtime manca (o non
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

Sicurezza: ascolto solo su `127.0.0.1`; richieste con `Host` diverso da localhost rifiutate (DNS rebinding); `POST` con `Origin`
estranea o `Sec-Fetch-Site: cross-site` rifiutate (CSRF); CSP restrittiva sull'interfaccia; nessuna intestazione CORS. ESP32 ed
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
