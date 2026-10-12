# LANterna

Diagnostica della rete di casa che **spiega ogni valore**: per ciascuna misura dice cos'è, come si legge, quanto è grave nella tua
rete e cosa fare per migliorarla. Le azioni correttive confluiscono in un piano unico, ordinato per gravità, impatto e facilità.

![Panoramica](docs/img/panoramica.png)

<sub>Sopra: dati dimostrativi. Sotto: la finestra su Windows reale (macchina di collaudo della CI) con i dati misurati.</sub>

![LANterna su Windows reale](docs/img/windows-reale.png)

## Cosa misura

| Area | Misure |
| --- | --- |
| Wi-Fi | potenza in dBm, qualità, velocità radio, banda, standard (Wi-Fi 4…7), larghezza di canale, reti sullo stesso canale, canali 2,4 GHz sovrapposti, carico dichiarato dall'access point (BSS Load), sicurezza (WPA2/WPA3, TKIP, PMF, WPS), canale consigliato per 2,4 e 5 GHz |
| Rete locale | indirizzo e DHCP (APIPA), gateway, latenza/perdite/jitter verso il router, velocità della porta Ethernet, IPv6, dispositivi visti di recente |
| Internet | latenza, perdite e jitter verso Cloudflare, Google e Quad9, traceroute, MTU del percorso, navigazione HTTPS reale |
| DNS | tempo di risposta del DNS in uso e confronto con i resolver pubblici |
| Router e sicurezza | servizi esposti dal *proprio* router (Telnet, FTP, SMB…), UPnP IGD e indirizzo pubblico, pannello di gestione HTTP/HTTPS, profili del firewall di Windows |

## Piattaforme

| Piattaforma | Stato |
| --- | --- |
| **Windows 10/11** | programma portatile (`LANterna.exe`, nessuna installazione) con finestra nativa WebView2, rapporto da riga di comando e interfaccia nel browser |
| Android | progettato, da realizzare: [docs/ANDROID.md](docs/ANDROID.md) |
| ESP32 | progettato, da realizzare: [docs/ESP32.md](docs/ESP32.md) |

Tutte le piattaforme condividono lo **stesso nucleo**: interfaccia e motore di analisi in TypeScript (`core/`). Le sonde di ogni
piattaforma producono solo dati grezzi in un formato comune; l'interpretazione è sempre la stessa. Dettagli in
[docs/ARCHITETTURA.md](docs/ARCHITETTURA.md).

## Uso su Windows

Scarica `LANterna-windows-amd64.zip`, estrai la cartella e fai doppio clic su `LANterna.exe`. L'analisi parte da sola e dura circa 20 secondi.

```text
lanterna-cli report                 rapporto a schermo
lanterna-cli report --verbose       con spiegazioni e passi da seguire
lanterna-cli report --out r.txt     salva il rapporto (UTF-8, si apre col Blocco note)
lanterna-cli report --json          dati grezzi, riapribili nell'interfaccia con "Importa"
lanterna-cli serve --open           interfaccia nel browser su http://127.0.0.1:8737
```

Su Windows 11 24H2 e successivi la lettura delle reti Wi-Fi richiede il permesso di posizione per le app desktop: LANterna lo
rileva e spiega come attivarlo. Non servono privilegi di amministratore.

## Sviluppo

Requisiti: Node.js 20+, Go 1.24+. Si compila da Linux, macOS o Windows.

```bash
cd core && npm ci && npm test        # motore di analisi (vitest)
npm run dev                          # interfaccia con i dati dimostrativi su http://localhost:5173
cd ../windows && go test ./...       # agente Windows (gira anche su Linux)
cd .. && scripts/build-windows.sh    # build/LANterna/ e build/LANterna-windows-amd64.zip
```

`npm run dev` usa i dati dimostrativi; con `lanterna-cli serve` avviato, il server di sviluppo inoltra `/api` all'agente vero.

## Verifiche

Cosa è stato verificato e come, inclusa l'esecuzione dell'exe sotto Wine e su Windows reale in CI, e cosa resta da provare su un
PC con scheda Wi-Fi: [docs/VERIFICHE.md](docs/VERIFICHE.md).

## Privacy e sicurezza

- Tutto resta sul PC: nessun dato viene inviato a servizi esterni.
- Il server locale ascolta solo su `127.0.0.1`, rifiuta host diversi (DNS rebinding) e richieste da altre origini.
- Il controllo dei servizi esposti riguarda **esclusivamente il gateway** della rete a cui si è collegati, senza autenticarsi.
- Per le misure vengono contattati: il router, i resolver pubblici 1.1.1.1, 8.8.8.8 e 9.9.9.9, `www.google.com/generate_204` e
  `cp.cloudflare.com/generate_204`.

## Licenze

I componenti di terze parti inclusi nell'eseguibile e le loro licenze sono in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
(MIT, BSD, ISC, Apache-2.0 e la licenza del loader WebView2 di Microsoft). La licenza di LANterna stessa non è ancora stata scelta.
