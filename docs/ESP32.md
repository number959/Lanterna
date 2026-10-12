# LANterna per ESP32: progetto

Stato: **progettato, non ancora realizzato**. Un piccolo strumento dedicato, in due usi:

1. **Sonda fissa**: resta accesa giorno e notte vicino al router o in una stanza problematica e registra latenza, perdite e qualità
   del Wi-Fi nel tempo. Serve a dimostrare i problemi intermittenti ("la sera cade la connessione") e a distinguerli tra Wi-Fi, router e linea.
2. **Strumento portatile**: con display e batteria, mostra segnale e canali mentre ci si sposta per la casa.

## Architettura

- Firmware **ESP-IDF 5.x** in C.
- Il dispositivo espone **la stessa API dell'agente Windows** (`/api/info`, `/api/scan`, `/api/progress`, `/api/ping`) con
  `esp_http_server` e serve l'interfaccia di `core/dist` da LittleFS, già compressa (`Content-Encoding: gzip`, circa 100 KB).
- L'analisi gira **nel browser** di chi si collega (PC o telefono): l'ESP32 misura e basta, quindi spiegazioni e piano d'azione sono
  identici alle altre piattaforme.
- Prima configurazione: modalità access point con pagina per inserire le credenziali Wi-Fi, poi modalità stazione per misurare.

## Misure

| Misura | Componente ESP-IDF | Note |
| --- | --- | --- |
| Reti visibili | `esp_wifi_scan_start` / `wifi_ap_record_t` | BSSID, SSID, canale primario e secondario (HT40 sopra/sotto), RSSI, autenticazione e cifrature, standard 11b/g/n/ax, paese |
| Carico dell'AP (BSS Load) e larghezze VHT/HE | facoltativo: modalità promiscua filtrata sui soli frame di gestione | si decodificano **solo i beacon** (pubblici per definizione), mai i frame dati; porting in C dei decoder IE con gli stessi vettori di test |
| Ping, traceroute | `esp_ping` | TTL configurabile, quindi anche traceroute |
| DNS, UPnP/SSDP, porte del router, HTTPS | socket lwIP, `esp_http_client` | come su Windows; solo verso il gateway |
| Andamento nel tempo | buffer circolare in RAM + riepiloghi orari in flash | esportabili come JSON (`Importa` nell'interfaccia) |

## Hardware consigliato

| Opzione | Perché | Limiti |
| --- | --- | --- |
| **ESP32-C5** (es. ESP32-C5-DevKitC-1) | unico ESP32 **dual band 2,4 + 5 GHz**, Wi-Fi 6 | più recente, meno schede con display pronte |
| **ESP32-S3** con display (es. LilyGO T-Display-S3) | economico, display e connettore batteria integrati, molta RAM (PSRAM) | **solo 2,4 GHz**: non vede le reti a 5 GHz |
| Aggiunta Ethernet (W5500 via SPI, oppure WT32-ETH01) | sonda fissa via cavo: misura la linea senza il Wi-Fi di mezzo | — |

Per una sonda fissa conviene l'alimentazione USB-C da 5 V; per lo strumento portatile una batteria LiPo da 1000-2000 mAh.

## Limiti da dichiarare nell'interfaccia

- Antenna su circuito stampato: l'RSSI differisce di qualche dB da quello di un telefono o di un PC (si può prevedere una
  correzione da calibrare).
- Una sola radio: durante una scansione la connessione si interrompe per qualche centinaio di millisecondi.
- Nessun dato del PC (firewall, schede di rete) e niente banda 6 GHz.
- Il server web del dispositivo non usa HTTPS: va usato solo nella rete locale, con password per le impostazioni e gli stessi
  controlli su `Host` e `Origin` dell'agente Windows.

## Lavoro stimato

1. Firmware base: Wi-Fi STA/AP, server HTTP, LittleFS con il bundle.
2. Sonde (scansione, ping, DNS, SSDP, porte) con la stessa API.
3. Registro storico e pagina "andamento" nell'interfaccia (utile anche per Windows in modalità monitor prolungato).
4. Versione con display: schermata essenziale con segnale, latenza e semaforo.
