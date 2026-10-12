# Verifiche

Cosa è stato verificato, come, e cosa resta da provare. Data: 12 ottobre 2026, versione 0.1.0.

## 1. Test automatici

| Parte | Test | Cosa coprono |
| --- | --- | --- |
| Motore di analisi (`core/`, vitest) | 40 | conversioni frequenza/canale e spettro; soglie di ogni metrica ai bordi (es. -67/-68/-75/-76 dBm); diagnosi incrociate (latenza in casa o dell'operatore, router che ignora i ping, traceroute con nodo lento o percorso parziale, ping bloccati ma web funzionante); sicurezza (aperta, WEP, TKIP, WPA3, PMF, WPS); piano d'azione senza duplicati e con i critici in testa; rapporto testuale; **il bundle `engine.js` gira come script ES2015 senza moduli né Intl** (come in goja) e dà lo stesso risultato |
| Decoder 802.11 (`windows/internal/ie`) | 16 | beacon costruiti **byte per byte**: RSN (WPA2, WPA3, transizione, OWE, Enterprise, valori impliciti), WPA in modalità mista con TKIP, WEP dal bit Privacy, WPS, BSS Load, Country, HT 40 MHz sopra/sotto, VHT 80/160 (codifica moderna e deprecata), HE 6 GHz con campi opzionali, EHT 320 MHz, elementi troncati |
| Strutture wlanapi (`windows/internal/wlan`) | 5 | `WLAN_BSS_LIST`, `WLAN_CONNECTION_ATTRIBUTES`, `WLAN_INTERFACE_INFO_LIST` costruite byte per byte: RSSI con segno, frequenza in kHz, velocità in unità da 500 kbit/s, offset IE relativo alla voce e fuori dal buffer, conteggi incoerenti, descrizioni UTF-16 |
| Parser netsh (`windows/internal/netsh`) | 4 | output inglese e italiano, anche con lettere accentate storpiate dalla code page CP850; messaggio di Windows 11 sul permesso di posizione |
| Sonde di rete (`windows/internal/probe`) | 11 | pacchetto DNS confrontato byte per byte, server DNS finto (risposta, REFUSED, SERVFAIL, timeout); router UPnP finto completo (SSDP, descrizione XML, SOAP `GetExternalIPAddress`); filtro degli URL SSDP (solo LAN privata); porte; titolo del pannello; HTTPS |
| Orchestrazione (`windows/internal/collect`) | 7 | analisi completa su piattaforma simulata; traceroute; MTU con ricerca binaria; riserva TCP quando l'ICMP non funziona; interruzione rapida se l'host non risponde; assenza di gateway; scelta del metodo nel monitor |
| Server locale (`windows/internal/server`) | 3 | rifiuto di Host estranei, POST da altre origini e cross-site; CSP; ciclo avvio, avanzamento e risultato; ping del monitor; avvii concorrenti |
| Motore in goja (`windows/internal/engine`) | 3 | il vero `engine.js` eseguito nell'interprete dell'exe: rapporto e analisi, formattazione dei numeri con la virgola |

I test Go vengono eseguiti anche con il race detector.

## 2. Strutture di Windows confrontate con gli header ufficiali

Gli offset con cui l'agente legge le strutture restituite da Windows sono stati confrontati con quelli calcolati dal compilatore
sugli header ufficiali (mingw-w64 `wlanapi.h`, `iphlpapi.h`, `icmpapi.h`), con un programma C che stampa `offsetof`/`sizeof`,
eseguito sotto Wine. **Tutti coincidono**:

| Struttura | Dimensione | Campi verificati |
| --- | --- | --- |
| `WLAN_INTERFACE_INFO` | 532 | descrizione @16, stato @528; prima voce della lista @8 |
| `WLAN_CONNECTION_ATTRIBUTES` | 604 | associazione @520 (SSID +0, BSSID +40, PHY +48, qualità +56, rx +60, tx +64), sicurezza @588 (autenticazione +8, cifratura +12) |
| `WLAN_BSS_ENTRY` | 360 | BSSID @40, RSSI @56, capability @88, frequenza @92, rate set @96, offset IE @352, dimensione IE @356; prima voce @8 |
| `ICMP_ECHO_REPLY` (x64) | 40 | stato @4, RTT @8, dati @16, opzioni @24 |
| `IP_OPTION_INFORMATION` (x64) | 16 | flag @2, dati opzioni @8 |
| `MIB_IPNETROW` | 24 | MAC @8, indirizzo @16, tipo @20; prima riga @4 |

Verificati anche opcode (`current_connection` = 7, `channel_number` = 8, `rssi` = 0x10000102) e codici ICMP
(`IP_TTL_EXPIRED_TRANSIT` = 11013, `IP_REQ_TIMED_OUT` = 11010, `IP_PACKET_TOO_BIG` = 11009, `IP_FLAG_DF` = 2).

## 3. L'eseguibile Windows eseguito davvero sotto Wine 9.0

Compilato `LANterna.exe` / `lanterna-cli.exe` (Windows x64) ed eseguito sotto Wine in tre modi.

**Rapporto da riga di comando** (`lanterna-cli report`, `LANterna.exe report`): analisi completa in circa 9 s. Funzionano schede
di rete, gateway, ping al router (20/20), traceroute, DNS di sistema e pubblici, verifica HTTPS, tabella dei vicini, porte del
router e UPnP; il sistema viene riconosciuto come "Wine 9.0, emula Windows 10". Senza scheda Wi-Fi e senza PowerShell, Wi-Fi e
firewall risultano correttamente "non riusciti", con il motivo. Rapporto su file: UTF-8 con BOM e fine riga CRLF.

**Server locale + interfaccia vera in Chromium** (lo stesso motore di WebView2): l'interfaccia incorporata nell'exe avvia da sola
l'analisi, mostra le fasi reali, poi i dati misurati (non la demo); "Nuova analisi" e il monitor in tempo reale funzionano; nessun
errore in console; CSP attiva; `Host` estraneo e `POST` da altra origine rifiutati con 403.

**Finestra grafica su display virtuale** (Xvfb): sotto Wine il runtime WebView2 non esiste, quindi si è collaudata la gestione
della sua assenza: compare solo il messaggio che spiega cosa installare e apre l'interfaccia nel browser; con OK il programma
termina. Simulato anche il caso "runtime presente ma guasto": la finestra vuota viene nascosta e il messaggio resta visibile.

### Difetti trovati grazie a Wine e corretti

1. `GetAdaptersAddresses` con `GAA_FLAG_INCLUDE_GATEWAYS` e `AF_UNSPEC` restituiva `ERROR_NOT_SUPPORTED`: ora i gateway IPv4 si
   leggono con una seconda chiamata `AF_INET`. Senza questa correzione router e DNS non sarebbero stati individuati.
2. Il monitor mostrava il 100 % di pacchetti persi verso Internet dove l'ICMP è filtrato: ora usa il metodo (ICMP o TCP) che ha
   funzionato durante l'analisi.
3. Il traceroute lanciava tutte le sonde nello stesso istante e gonfiava i tempi dei primi salti (51,8 ms contro 4 ms del ping):
   ora le sonde sono scaglionate e si tiene il minimo di due campioni.
4. Senza WebView2, go-webview2 lasciava aperta una finestra vuota dietro il messaggio: ora il runtime si verifica prima di creare
   la finestra.
5. Distruggere quella finestra provocava un `WM_QUIT` che chiudeva subito il messaggio di avviso: ora la finestra viene nascosta.
6. `GET /api/scan` prima della prima analisi rispondeva 404 (errore in console): ora risponde 204.
7. L'avanzamento da riga di comando ripeteva le stesse righe; il titolo diceva "ottima forma" anche con misure non riuscite; un
   traceroute che non raggiunge la destinazione era descritto come "regolare".

## 4. Interfaccia in Chromium

Tutte le otto viste, in modalità demo, a 1366×900 (tema scuro e chiaro) e 390×844 (mobile): nessuno scorrimento orizzontale,
nessun errore JavaScript; animazioni disattivate con "riduci movimento"; gravità sempre indicate con icona e testo, non solo colore.

## 5. Cosa non è stato possibile verificare qui

| Parte | Perché | Come è stata coperta | Da provare su un PC |
| --- | --- | --- | --- |
| Lettura delle reti Wi-Fi da una scheda vera | Wine non ha schede Wi-Fi | decoder IE e strutture wlanapi collaudati byte per byte; offset confrontati con gli header ufficiali | sezione Wi-Fi: reti, dBm, larghezze, sicurezza della propria rete |
| Finestra WebView2 | Wine non ha il runtime | interfaccia collaudata in Chromium, che è il motore di WebView2; CI su Windows reale (sotto) | aspetto della finestra, nitidezza con ridimensionamento al 125-150 % |
| Permesso di posizione (Windows 11 24H2+) | serve Windows 11 con scheda Wi-Fi | messaggio di Windows riconosciuto nei test; errore `ACCESS_DENIED` tradotto in istruzioni | con posizione disattivata deve comparire la spiegazione, attivandola le reti |
| UPnP e porte di un router reale | nessun router domestico nel container | router UPnP simulato nei test | modello del router, porte aperte, IP pubblico |

## 6. Collaudo su Windows reale (CI)

Il workflow `.github/workflows/ci.yml` esegue tutti i test, compila lo zip (scaricabile come artefatto `LANterna-windows-amd64`)
e lo collauda su una macchina `windows-latest` di GitHub: versione e rilevamento di WebView2, rapporto con controlli sui dati
letti dalle API native (schede, gateway, firewall via PowerShell, HTTPS), server locale con analisi completa via API e, come prova
non bloccante, avvio della finestra grafica con cattura dello schermo (artefatto `collaudo-windows`).
