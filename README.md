<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="brand/STARNET_22_Logo_Bianco.svg">
    <img src="brand/STARNET_22_Logo_Colore.svg" alt="STARNET" width="150">
  </picture>
</p>

# STARNET Polaris

**La stella polare della tua rete.** Diagnostica della rete di casa che **spiega ogni valore**: per ciascuna misura dice cos'è,
come si legge, quanto è grave nella tua rete e cosa fare per migliorarla. Le azioni correttive confluiscono in un piano unico,
ordinato per gravità, impatto e facilità.

Il nome nasce dal marchio STARNET: Polaris è la stella polare, quella che indica la direzione. Qui indica cosa sistemare per primo.

![Panoramica](docs/img/panoramica.webp)

<sub>Sopra: dati dimostrativi. Sotto: la finestra su Windows reale (macchina di collaudo della CI) con i dati misurati.</sub>

![STARNET Polaris su Windows reale](docs/img/windows-reale.webp)

## Interfaccia

Costruita attorno al marchio STARNET: i colori sono il blu profondo `#022D62` e il ciano `#00B9FE` del logo, la geometria è
l'esagono della sua cornice, i titoli usano un carattere esteso vicino alla scritta STARNET. Il logo compare come vuole la sua
guida: bianco sui fondi scuri, a colori sui fondi chiari, senza ombre né deformazioni.

Il movimento riprende il marchio:
- all'avvio la cornice si disegna in senso orario dal vertice alto, come il tratto ciano, e le due metà della stella si incastrano
  lungo la S;
- il punteggio è un esagono che si riempie allo stesso modo;
- durante l'analisi il simbolo sta al centro, la sua cornice si completa con l'avanzamento reale e le sonde, man mano che
  finiscono, si collegano in una costellazione;
- le sezioni entrano in cascata, i numeri si assestano con una molla, il monitor scorre in modo continuo.

Se in Windows le animazioni sono disattivate restano solo brevi dissolvenze: niente spostamenti, rotazioni o scorrimenti.

- **Tastiera**: `1`…`8` per le sezioni, `/` per cercare nella guida, frecce nei selettori; ogni comando è raggiungibile con Tab.
- **Grafica leggera**: senza accelerazione grafica (macchine virtuali, desktop remoto) Polaris se ne accorge dai fotogrammi lenti e
  toglie sfocature e trasparenze; si può anche attivare a mano in fondo alla barra laterale.
- Contrasto conforme a WCAG 2.1 AA in entrambi i temi; la gravità è sempre indicata da icona e testo, non solo dal colore.

| Wi-Fi e spettro radio | Piano d'azione (tema chiaro) | Mobile |
| --- | --- | --- |
| ![Wi-Fi](docs/img/wifi.webp) | ![Piano d'azione](docs/img/piano.webp) | ![Mobile](docs/img/mobile.webp) |

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
| **Windows 10/11** | programma portatile (`Polaris.exe`, nessuna installazione) con finestra nativa WebView2, rapporto da riga di comando e interfaccia nel browser |
| Android | progettato, da realizzare: [docs/ANDROID.md](docs/ANDROID.md) |
| ESP32 | progettato, da realizzare: [docs/ESP32.md](docs/ESP32.md) |

Tutte le piattaforme condividono lo **stesso nucleo**: interfaccia e motore di analisi in TypeScript (`core/`). Le sonde di ogni
piattaforma producono solo dati grezzi in un formato comune; l'interpretazione è sempre la stessa. Dettagli in
[docs/ARCHITETTURA.md](docs/ARCHITETTURA.md).

## Uso su Windows

Scarica `STARNET-Polaris-windows-amd64.zip`, estrai la cartella e fai doppio clic su `Polaris.exe`. L'analisi parte da sola e dura circa 20 secondi.

```text
polaris-cli report                  rapporto a schermo
polaris-cli report --verbose        con spiegazioni e passi da seguire
polaris-cli report --out r.txt      salva il rapporto (UTF-8, si apre col Blocco note)
polaris-cli report --json           dati grezzi, riapribili nell'interfaccia con "Importa"
polaris-cli serve --open            interfaccia nel browser su http://127.0.0.1:8737
```

Su Windows 11 24H2 e successivi la lettura delle reti Wi-Fi richiede il permesso di posizione per le app desktop: Polaris lo
rileva e spiega come attivarlo. Non servono privilegi di amministratore.

## Sviluppo

Requisiti: Node.js 20+, Go 1.24+. Si compila da Linux, macOS o Windows.

```bash
cd core && npm ci && npm test        # motore di analisi (vitest)
npm run dev                          # interfaccia con i dati dimostrativi su http://localhost:5173
cd ../windows && go test ./...       # agente Windows (gira anche su Linux)
cd .. && scripts/build-windows.sh    # build/STARNET-Polaris/ e build/STARNET-Polaris-windows-amd64.zip
```

`npm run dev` usa i dati dimostrativi; con `polaris-cli serve` avviato, il server di sviluppo inoltra `/api` all'agente vero.

Fino alla versione 0.2.0 il programma si chiamava LANterna: il repository e il modulo Go conservano quel nome interno.
I master del marchio sono in `brand/`; `node scripts/brand.mjs` rigenera i tracciati usati dall'interfaccia.

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
(MIT, BSD, ISC, Apache-2.0, SIL Open Font License 1.1 per i font e la licenza del loader WebView2 di Microsoft), generato da
`scripts/notices.sh` a partire da ciò che finisce davvero nel bundle. La licenza di STARNET Polaris stessa non è ancora stata scelta. Il marchio STARNET (cartella `brand/`) appartiene al suo
titolare e non è coperto da quelle licenze.
