<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="brand/STARNET_22_Logo_Bianco.svg">
    <img src="brand/STARNET_22_Logo_Colore.svg" alt="STARNET" width="150">
  </picture>
</p>

# STARNET Polaris

**La stella polare della tua rete.** Diagnostica di rete che **spiega ogni valore**: per ciascuna misura dice cos'è, come si
legge, quanto è grave nella tua rete e cosa fare per migliorarla. Le azioni correttive confluiscono in un piano unico, ordinato
per gravità, impatto e facilità.

Funziona in casa come in uno studio, in un'azienda o in una **struttura sanitaria**: riconosce le reti con più access point e
con dominio, censisce la sottorete, verifica la separazione tra le zone e i servizi critici e guida un'autovalutazione delle
misure organizzative. Una biblioteca di **48 guide** in italiano spiega tutto ciò che riguarda la rete, dalle basi alle reti
cliniche.

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

- **Tastiera**: `1`…`9` per le sezioni, `/` per cercare nella guida, frecce nei selettori e nelle risposte dell'autovalutazione;
  ogni comando è raggiungibile con Tab.
- **Grafica leggera**: senza accelerazione grafica (macchine virtuali, desktop remoto) Polaris se ne accorge dai fotogrammi lenti e
  toglie sfocature e trasparenze; si può anche attivare a mano in fondo alla barra laterale.
- Contrasto conforme a WCAG 2.1 AA in entrambi i temi; la gravità è sempre indicata da icona e testo, non solo dal colore.

| Wi-Fi e spettro radio | Piano d'azione (tema chiaro) | Mobile |
| --- | --- | --- |
| ![Wi-Fi](docs/img/wifi.webp) | ![Piano d'azione](docs/img/piano.webp) | ![Mobile](docs/img/mobile.webp) |

## Cosa misura

| Area | Misure |
| --- | --- |
| Wi-Fi | potenza in dBm, qualità, velocità radio, banda, standard (Wi-Fi 4…7), larghezza di canale, reti sullo stesso canale, canali 2,4 GHz sovrapposti, carico dichiarato dall'access point (BSS Load), sicurezza (WPA2/WPA3 Personal ed Enterprise, TKIP, PMF, WPS), canale consigliato per 2,4 e 5 GHz |
| Reti con più access point | AP della rete con canali, segnale, carico e roaming assistito (802.11k, 802.11v, 802.11r e Mobility Domain), AP propri sullo stesso canale, PC agganciato a un AP lontano (sticky client), stessa rete annunciata con protezioni diverse (possibile AP gemello) |
| Rete locale | indirizzo, DHCP e server DHCP (APIPA), gateway, latenza/perdite/jitter verso il router, velocità della porta Ethernet, IPv6, sottoreti molto ampie, dominio e DNS aziendali, stesso MAC per più indirizzi, MAC del router cambiato rispetto all'analisi precedente, dispositivi visti di recente |
| Internet | latenza, perdite e jitter verso Cloudflare, Google e Quad9, traceroute, MTU del percorso, navigazione HTTPS reale |
| DNS | tempo di risposta del DNS in uso e confronto con i resolver pubblici |
| Router e sicurezza | servizi esposti dal *proprio* router (Telnet, FTP, SMB…), UPnP IGD e indirizzo pubblico, pannello di gestione HTTP/HTTPS, profili del firewall di Windows |
| Infrastruttura (su richiesta) | inventario della sottorete, test di segmentazione tra le zone, raggiungibilità e tempi dei servizi critici, autovalutazione organizzativa in sei aree |
| Monitor | un ping al secondo verso router e Internet per tutta la sessione (fino a 12 ore, anche cambiando sezione), con picchi, interruzioni e relativa ora; esportazione CSV |

## Reti complesse e strutture sanitarie

![Infrastruttura](docs/img/infrastruttura.webp)

La sezione **Infrastruttura** raccoglie gli strumenti per le reti con più zone. Contattano altri dispositivi, quindi seguono
regole precise: partono **solo su richiesta**, l'inventario chiede la conferma di essere autorizzati (con l'attività concordata
con l'ingegneria clinica dove ci sono dispositivi medicali), si rivolgono **solo a indirizzi privati**, con un **ritmo prudente**
e **senza scansioni di porte**.

- **Inventario della sottorete**: un ping a ogni indirizzo (circa 30 al secondo, 8 alla volta), poi la tabella ARP, che rivela
  anche i dispositivi che ignorano il ping, e i nomi da DNS inverso e NetBIOS. Elenco filtrabile ed esportabile in CSV; segnala i
  dispositivi senza nome, i MAC casuali e la sottorete quasi piena. Oltre /22 si esamina solo il blocco /24 del PC.
- **Test di segmentazione e servizi critici**: si indicano le destinazioni che da questa zona devono rispondere (cartella
  clinica, PACS, HL7, DNS, controller di dominio…) e quelle che devono restare isolate (dispositivi medicali, gestione degli
  apparati, telecamere, ospiti). Per ognuna una connessione TCP alla porta indicata o due ping; le destinazioni si ricordano per
  rete. Una risposta da una zona che doveva essere isolata è un problema critico.
- **Autovalutazione**: 28 domande su segmentazione, dispositivi medicali, accessi e fornitori, backup, continuità e gestione
  degli incidenti. Le risposte restano sul PC ed entrano nel rapporto; ogni lacuna aggiunge al piano l'azione corrispondente. È
  una dichiarazione, non una verifica, e non sostituisce un audit.

Nelle reti con dominio Polaris non suggerisce di cambiare DNS sul PC (romperebbe i nomi interni) ma di potenziare il DNS interno.
Senza agente, le due reti dimostrative (*Casa* e *Clinica*) mostrano tutte le funzioni con dati e simulazioni dichiarati come tali.

| AP della rete (demo Clinica) | Esiti delle verifiche | Autovalutazione (tema chiaro) |
| --- | --- | --- |
| ![AP della rete](docs/img/ap-rete.webp) | ![Verifiche](docs/img/verifiche.webp) | ![Autovalutazione](docs/img/autovalutazione.webp) |

## Guide di rete

![Guide](docs/img/guide.webp)

48 guide in sette capitoli (fondamenti, Wi-Fi, rete cablata, servizi, sicurezza, reti complesse e sanità, diagnosi), un glossario
di 152 voci e la ricerca unificata su guide, glossario, misure e azioni. Ogni valore misurato e ogni azione del piano rimandano
alla guida che li spiega; sette diagrammi animati illustrano livelli, sottoreti, DHCP, canali, roaming, VLAN e zone di una rete
sanitaria. I riferimenti normativi citati (GDPR, NIS2, dispositivi medicali) sono una sintesi da verificare sui testi ufficiali,
non una consulenza legale.

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

`npm run dev` usa i dati dimostrativi (la rete *Casa*; dal selettore nell'avviso si passa a *Clinica*); con `polaris-cli serve`
avviato, il server di sviluppo inoltra `/api` all'agente vero.

Fino alla versione 0.2.0 il programma si chiamava LANterna: il repository e il modulo Go conservano quel nome interno.
I master del marchio sono in `brand/`; `node scripts/brand.mjs` rigenera i tracciati usati dall'interfaccia.

## Verifiche

Cosa è stato verificato e come, inclusa l'esecuzione dell'exe sotto Wine e su Windows reale in CI, e cosa resta da provare su un
PC con scheda Wi-Fi: [docs/VERIFICHE.md](docs/VERIFICHE.md).

## Privacy e sicurezza

- Tutto resta sul PC: nessun dato viene inviato a servizi esterni.
- Il server locale ascolta solo su `127.0.0.1`, rifiuta host diversi (DNS rebinding) e richieste da altre origini.
- Il controllo dei servizi esposti riguarda **esclusivamente il gateway** della rete a cui si è collegati, senza autenticarsi.
- Inventario e verifiche partono solo su richiesta, solo verso indirizzi privati (RFC 1918 e ULA IPv6) e senza scansioni di
  porte: l'inventario contatta i dispositivi della sola sottorete del PC, le verifiche solo le destinazioni indicate
  dall'utente. Le API locali rifiutano richieste senza conferma, con destinazioni non valide o pubbliche.
- Per le misure vengono contattati: il router, i resolver pubblici 1.1.1.1, 8.8.8.8 e 9.9.9.9, `www.google.com/generate_204` e
  `cp.cloudflare.com/generate_204`.

## Licenze

I componenti di terze parti inclusi nell'eseguibile e le loro licenze sono in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
(MIT, BSD, ISC, Apache-2.0, SIL Open Font License 1.1 per i font e la licenza del loader WebView2 di Microsoft), generato da
`scripts/notices.sh` a partire da ciò che finisce davvero nel bundle. La licenza di STARNET Polaris stessa non è ancora stata scelta. Il marchio STARNET (cartella `brand/`) appartiene al suo
titolare e non è coperto da quelle licenze.
