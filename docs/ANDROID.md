# STARNET Polaris per Android: progetto

Stato: **progettato, non ancora realizzato**. Obiettivo: la stessa analisi e la stessa interfaccia della versione Windows, con le
misure che Android consente a un'app normale (senza root).

## Architettura

- Un'app a singola Activity con una `WebView` che carica il bundle di `core/dist` dagli asset tramite `WebViewAssetLoader`
  (`https://appassets.androidplatform.net/`).
- Le chiamate dell'interfaccia a `api/*` vengono intercettate in `shouldInterceptRequest` e servite da un modulo Kotlin con **la
  stessa API dell'agente Windows** (`/api/info`, `/api/scan`, `/api/progress`, `/api/ping`). L'interfaccia non cambia di una riga.
- Il modulo Kotlin produce lo stesso `Scan` JSON; motore di analisi, spiegazioni e piano d'azione restano quelli di `core/`.
- Decodifica degli Information Element 802.11: porting in Kotlin di `windows/internal/ie`, collaudato con **gli stessi vettori di
  test** costruiti byte per byte (da estrarre in un file JSON condiviso).

## Da dove arrivano i dati

| Misura | API Android | Note |
| --- | --- | --- |
| Reti visibili | `WifiManager.getScanResults()` → `ScanResult` | dBm (`level`), frequenza, `channelWidth`, `centerFreq0/1`; con Android 11+ `getWifiStandard()` e `getInformationElements()` (IE grezzi, quindi stessa decodifica di Windows) |
| Connessione | `WifiInfo` | `getRssi()`, `getRxLinkSpeedMbps()`/`getTxLinkSpeedMbps()` (10+), `getWifiStandard()` (11+), `getCurrentSecurityType()` (12+) |
| Indirizzi, gateway, DNS, MTU | `ConnectivityManager.getLinkProperties()` | rotte → gateway; `getMtu()` (10+); DNS privato |
| Ping | socket ICMP "ping" (`Os.socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)`) | consentiti alle app senza privilegi; riserva TCP come su Windows |
| Traceroute | `/system/bin/ping -c 1 -t TTL` | output di toybox (inglese, stabile) |
| DNS, UPnP, porte del router, HTTPS | socket standard | per SSDP acquisire un `WifiManager.MulticastLock`; HTTP in chiaro verso il router consentito solo per indirizzi privati (network security config) |
| Firewall | — | non esiste un equivalente: l'area *Sicurezza* valuta solo il Wi-Fi e il router |
| Dispositivi in rete | — | `/proc/net/arp` non è leggibile da Android 10; si possono elencare i dispositivi che si annunciano via mDNS (`NsdManager`) e SSDP |

## Permessi e limiti

- **Posizione**: per i risultati della scansione serve `ACCESS_FINE_LOCATION` con la localizzazione attiva; da Android 13 si può
  usare `NEARBY_WIFI_DEVICES` con `neverForLocation` per la scansione. SSID e BSSID della rete collegata restano legati al permesso
  di posizione: l'interfaccia deve spiegarlo prima di chiederlo (sul Play Store è obbligatoria un'informativa evidente).
- **Limite di scansioni**: da Android 9 un'app in primo piano può avviare 4 scansioni ogni 2 minuti. L'interfaccia deve mostrare
  quando è disponibile la prossima, oppure usare i risultati recenti già in cache del sistema.
- Niente socket raw: nessun MTU con bit DF affidabile (si può omettere la misura, il motore la segnalerà come non eseguita).
- Velocità della porta Ethernet: non pertinente sulla maggior parte dei telefoni.

## Hardware consigliato

- Minimo Android 10 (API 29); consigliato **Android 11+** per IE grezzi e standard Wi-Fi.
- Un telefono **Wi-Fi 6E/7** per vedere anche la banda 6 GHz.
- Utile un tablet economico dedicato come "strumento da tecnico", da portare stanza per stanza per mappare la copertura.

## Lavoro stimato

1. Progetto Android (Kotlin, `minSdk 29`) con WebView e caricamento del bundle.
2. Modulo sonde con API compatibile e test strumentali.
3. Porting dei decoder IE con vettori di test condivisi.
4. Flusso dei permessi con spiegazioni in italiano.
5. Funzione specifica per mobile: *percorso di copertura* (misure ripetute mentre ci si sposta, con la mappa delle stanze).
