<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="brand/STARNET_22_Logo_Bianco.svg">
    <img src="brand/STARNET_22_Logo_Colore.svg" alt="STARNET" width="150">
  </picture>
</p>

# STARNET Polaris

**La stella polare del tuo PC e della tua rete.** Diagnostica di computer e rete, in un unico programma, che **spiega ogni
valore**: per ciascuna misura dice cos'è, come si legge, quanto è grave e cosa fare per migliorarla. Le azioni correttive
confluiscono in un piano unico, ordinato per gravità, impatto e facilità.

Del **computer** controlla versione e supporto di Windows, memoria, **salute dei dischi HDD e SSD** (attributi SMART e registro
NVMe come in CrystalDiskInfo, usura, temperatura, errori), **cosa occupa spazio** come WizTree, programmi all'avvio, processi, spegnimenti imprevisti,
schermate blu, **Microsoft Defender** (protezione, minacce e scansioni su richiesta), aggiornamenti e batteria; compila la
**scheda tecnica** come CPU-Z, con la **velocità dei core in tempo reale**, e offre **test di velocità** del processore e dei dischi,
questi con il profilo di CrystalDiskMark.
La **cassetta degli attrezzi** apre gli strumenti di Windows e **CrystalDiskInfo, CrystalDiskMark e BlueScreenView, inclusi nel
pacchetto**; CPU-Z, HWiNFO, Autoruns e gli altri programmi che non si possono ridistribuire li **scarica dal sito ufficiale**, solo
su richiesta, e li avvia solo con la firma digitale del produttore. Per i PC senza Internet prepara un **kit** da portare su una
chiavetta. Un **documento stampabile** riassume lo stato del PC, da consegnare o salvare in PDF.
Della **rete** misura Wi-Fi, router, Internet e DNS.

Funziona in casa come in uno studio, in un'azienda o in una **struttura sanitaria**: riconosce le reti con più access point e
con dominio, censisce la sottorete, verifica la separazione tra le zone e i servizi critici e guida un'autovalutazione delle
misure organizzative. Una biblioteca di **68 guide** in italiano spiega come usare il programma, il computer e la rete, dalle
basi alle reti cliniche.

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
- le sezioni entrano in cascata, i numeri si assestano con una molla, il monitor scorre in modo continuo;
- le icone della sezione scelta si disegnano, quelle delle operazioni in corso si animano (scansione, test, download), i
  caricamenti percorrono l'esagono del marchio e i dati in arrivo hanno segnaposto con un riflesso.

Se in Windows le animazioni sono disattivate restano solo brevi dissolvenze: niente spostamenti, rotazioni o scorrimenti.

**Suoni**: segnali brevi e a volume basso, generati dal programma senza file audio, per il cambio di sezione, le aperture, le
operazioni riuscite, la fine di analisi e test, avvisi, errori, minacce trovate e, nel monitor, l'interruzione e il ritorno della
connessione. Si spengono con l'altoparlante nella barra in alto e la scelta resta salvata.

- **Tastiera**: `1`…`9` e `0` per le sezioni, `/` per cercare nella guida, frecce nei selettori e nelle risposte dell'autovalutazione;
  ogni comando è raggiungibile con Tab.
- **Grafica leggera**: senza accelerazione grafica (macchine virtuali, desktop remoto) Polaris se ne accorge dai fotogrammi lenti e
  toglie sfocature e trasparenze; si può anche attivare a mano in fondo alla barra laterale.
- Contrasto conforme a WCAG 2.1 AA in entrambi i temi; la gravità è sempre indicata da icona e testo, non solo dal colore.

| Wi-Fi e spettro radio | Piano d'azione (tema chiaro) | Mobile |
| --- | --- | --- |
| ![Wi-Fi](docs/img/wifi.webp) | ![Piano d'azione](docs/img/piano.webp) | ![Mobile](docs/img/mobile.webp) |

## Il computer

![Computer](docs/img/computer.webp)

La sezione **Computer** descrive il PC da cui parte l'analisi, letto in **sola lettura** con le funzioni di Windows e un unico
script PowerShell nascosto: nessuna impostazione viene modificata.

- **Dischi**: tipo (SSD NVMe, SSD SATA, HDD, USB) e stato Buono, Attenzione o Critico con le regole di CrystalDiskInfo. Da
  amministratore Polaris legge il disco direttamente, in sola lettura: tabella degli attributi SMART dei dischi SATA (attuale,
  peggiore, soglia, dato grezzo), registro di salute NVMe (usura, riserva disponibile, dati scritti, spegnimenti non sicuri,
  errori del supporto), temperatura con la massima registrata. Errori di disco e file system dal registro eventi, collegati al
  disco coinvolto; spazio di ogni volume.
- **Sistema**: versione di Windows con le date di fine supporto (Windows 11 per versione ed edizione, Windows 10 ed ESU),
  memoria installata e in uso, carico del processore con i processi più pesanti, programmi all'avvio, tempo dall'ultimo
  riavvio (con l'effetto dell'avvio rapido) e riavvii in sospeso.
- **Stabilità e sicurezza**: spegnimenti imprevisti, schermate blu con il codice di arresto spiegato, errori hardware WHEA
  degli ultimi 30 giorni; antivirus dal Centro sicurezza; data dell'ultimo aggiornamento.
- **Microsoft Defender**: protezione in tempo reale e da manomissioni, firme, ultime scansioni e cronologia delle minacce (nome,
  gravità e stato, senza percorsi dei file né nomi utente). Su richiesta, scansione rapida o completa e aggiornamento delle firme
  con lo strumento ufficiale `MpCmdRun`; una scansione si può interrompere.
- **Scheda tecnica**, come in CPU-Z: processore (famiglia, modello e stepping, core P ed E, cache per livello, istruzioni,
  virtualizzazione), scheda madre e BIOS, moduli di memoria con slot, tipo e velocità, firmware UEFI, Secure Boot, TPM, scheda
  video e schermo. Giudizi su canali e velocità della memoria, Secure Boot, TPM e requisiti verificabili di Windows 11.
- **Velocità dei core in tempo reale**, come il "Core Speed" di CPU-Z: una lettura al secondo della frequenza effettiva (media dei
  core come in Gestione attività, core più veloce, percentuale rispetto alla base con il turbo, massima della sessione, carico),
  grafico dell'ultimo minuto e una barra per processore logico. I valori vengono dai contatori delle prestazioni di Windows, senza
  driver; bus e moltiplicatore sono quelli nominali dichiarati dal firmware.
- **Sensori in tempo reale**, come la finestra dei sensori di HWiNFO ma senza driver: una lettura al secondo con valore attuale,
  minimo, massimo e media di utilizzo, frequenze e limite di prestazioni del processore, consumi (se il PC espone i contatori
  Energy Meter), zone termiche ACPI, scheda video (utilizzo per motore, memoria e, quando il driver li fornisce, temperatura,
  ventola, potenza, frequenze e tensione), memoria, attività e temperatura dei dischi, rete, batteria e sistema. Grafico di ogni
  sensore, righe di dettaglio per processore logico, avvisi con suono quando una temperatura supera la soglia di attenzione o
  un sensore entra in allarme, registro CSV per Excel (da riga di comando scritto riga per riga, anche per ore).
  Ciò che richiede un driver in kernel (temperature, tensioni e ventole di processore e scheda madre) resta a HWiNFO, e Polaris
  lo dice.
- **Cosa occupa spazio**, come WizTree ma senza installare nulla: su richiesta legge l'elenco di file e cartelle di un'unità
  (decine o centinaia di voci per chiamata con `GetFileInformationByHandleEx`, in parallelo), senza aprire i file e senza
  cancellare nulla. Mostra la barra dell'unità, una mappa a riquadri navigabile, la tabella delle cartelle con "Apri in Esplora
  file", i 100 file più grandi, i tipi di file e le cartelle note di Windows (file temporanei, Windows.old, aggiornamenti, cache
  dei browser, Cestino, WinSxS, ibernazione, dischi virtuali...) divise in "si libera con Windows", "da rivedere", "da
  impostazione" e "non toccare", ognuna con il modo sicuro di recuperare spazio. Conta lo spazio occupato davvero sul disco, i
  file di Windows con più nomi (collegamenti fisici tra WinSxS e System32) una volta sola e i file solo online di OneDrive a
  parte, senza scaricarli; non segue giunzioni e link simbolici; dice quanto spazio non si vede dai file leggibili. Nei percorsi
  il profilo diventa `%USERPROFILE%`, gli altri utenti `‹utente N›` (anche in Windows.old e sulle altre unità), gli indirizzi
  e-mail `‹e-mail›` e i SID del Cestino perdono la parte che identifica il PC. Il motore stima lo spazio recuperabile e aggiunge al piano
  le azioni mirate (rimuovere Windows.old, liberare i file temporanei, rivedere i download, compattare i dischi virtuali).
- **Alimentazione**: salute della batteria, piano di alimentazione, driver della scheda video.
- **Test di velocità** (solo su richiesta): il processore comprime dati con un thread e con tutti per circa 25 secondi e rivela
  il calo dovuto a calore o limiti di potenza; il disco scrive e rilegge un file temporaneo fino a 1 GB senza cache di Windows
  con il profilo di CrystalDiskMark (SEQ1M Q8T1, SEQ1M Q1T1, RND4K Q32T1, RND4K Q1T1, in lettura e scrittura) e lo cancella
  alla fine anche se il test si interrompe (`FILE_FLAG_DELETE_ON_CLOSE`). I risultati si confrontano con quelli tipici del tipo
  di disco ed entrano nel rapporto; le prove precedenti restano sul PC per il confronto "prima e dopo".
- **Cassetta degli attrezzi**: 16 strumenti di Windows (Gestione attività, Monitoraggio affidabilità, Visualizzatore eventi,
  Diagnostica memoria...) e 15 programmi gratuiti di diagnostica, con che cosa fanno, licenza, sito ufficiale e dove Polaris fa
  una cosa simile. Tutto passa da una lista bianca: dall'interfaccia arriva solo un identificativo, mai un percorso o un comando.
  - **Inclusi** nella cartella `strumenti`: CrystalDiskInfo 9.9.2 e CrystalDiskMark 9.0.3 (licenza MIT, eseguibili firmati da
    CrystalMark Inc.) e BlueScreenView 1.55 (gratuito, ridistribuibile senza modifiche). Copie originali che si aprono con un
    clic, senza installare nulla; Polaris le avvia solo se l'eseguibile ha l'impronta SHA-256 attesa.
  - **Scaricati dal sito ufficiale**, solo su richiesta: CPU-Z, HWiNFO, AdwCleaner, Microsoft Safety Scanner, ESET Online
    Scanner, Autoruns, Process Explorer e WizTree. Prima di scaricare Polaris dice da dove, chi deve aver firmato, quanto pesa e
    con quali condizioni d'uso. Il download segue solo https e gli host del produttore, scarta file troppo grandi o pagine web al
    posto del programma, controlla l'impronta SHA-256 delle versioni fissate e la firma digitale (stato valido ed editore atteso)
    al download e a ogni avvio. I programmi restano in `%LOCALAPPDATA%\STARNET Polaris\strumenti`; una copia modificata non
    parte e si elimina dalla cassetta.
  - **Kit per i PC senza Internet**: su un PC collegato Polaris scarica i programmi scelti nella cartella `strumenti-scaricati`
    accanto a Polaris.exe; copiata la cartella di Polaris su una chiavetta, sui PC senza rete li trova lì e li avvia con le stesse
    verifiche. Il kit è per uso proprio: le licenze dei produttori non ne consentono la ridistribuzione.
- **Documento stampabile**: in A4, con punteggio e voto, le cinque cose da sistemare per prime, sistema, sicurezza, dischi e
  spazio, valutazione completa, scheda tecnica, stabilità, test di velocità, piano d'azione con caselle da spuntare e spazio per
  note e firma. Dall'interfaccia si stampa, si salva in PDF o si scarica in HTML autonomo; da riga di comando
  `polaris-cli report --html`. Non contiene numeri di serie, indirizzi MAC né l'IP pubblico.

Il punteggio della panoramica descrive PC e rete insieme; un disco che sta per guastarsi diventa il problema più urgente e la
prima azione del piano (copiare i dati). Nei rapporti la cartella dell'utente diventa `%USERPROFILE%` e non compaiono numeri di
serie.

| Test di velocità | Dischi e attributi SMART |
| --- | --- |
| ![Test di velocità](docs/img/test-velocita.webp) | ![Dischi](docs/img/dischi.webp) |

| Scheda tecnica | Microsoft Defender | Programmi inclusi (exe reale sotto Wine) |
| --- | --- | --- |
| ![Scheda tecnica](docs/img/scheda-tecnica.webp) | ![Antivirus](docs/img/antivirus.webp) | ![Cassetta degli attrezzi](docs/img/cassetta.webp) |

| Documento stampabile | Kit per i PC senza Internet (agente simulato) |
| --- | --- |
| ![Documento stampabile](docs/img/documento.webp) | ![Kit per i PC senza Internet](docs/img/kit.webp) |

| Sensori in tempo reale (demo: il portatile si scalda e limita il processore) |
| --- |
| ![Sensori in tempo reale](docs/img/sensori.webp) |

| Cosa occupa spazio (demo: C: quasi pieno per Windows.old, download e video) |
| --- |
| ![Cosa occupa spazio](docs/img/spazio.webp) |

## Cosa misura

| Area | Misure |
| --- | --- |
| Computer | versione e supporto di Windows, RAM installata e in uso, carico del processore e processi, velocità dei core in tempo reale, salute dei dischi (stato, attributi SMART, registro NVMe, usura, temperatura, errori), tipo del disco di sistema, spazio per volume, cosa occupa spazio (cartelle, file più grandi, tipi di file, cartelle note di Windows, spazio recuperabile), programmi all'avvio, riavvio e riavvii in sospeso, spegnimenti imprevisti, schermate blu, errori hardware e di disco nel registro, antivirus e Microsoft Defender (protezione, firme, scansioni, minacce), ultimo aggiornamento, batteria, piano di alimentazione, driver video, scheda tecnica (processore, memoria e canali, scheda madre, firmware, Secure Boot, TPM, video) |
| Test di velocità (su richiesta) | processore con un thread e con tutti, punta e velocità mantenuta; disco con il profilo di CrystalDiskMark (SEQ1M Q8T1, SEQ1M Q1T1, RND4K Q32T1, RND4K Q1T1), in MB/s e IOPS |
| Antivirus (su richiesta) | scansione rapida o completa e aggiornamento delle firme di Microsoft Defender |
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

## Guide

![Guide](docs/img/guide.webp)

68 guide in nove capitoli (usare STARNET Polaris, il computer, fondamenti, Wi-Fi, rete cablata, servizi, sicurezza, reti
complesse e sanità, diagnosi), un glossario di 208 voci e la ricerca unificata su guide, glossario, misure e azioni. La guida
d'uso parte dai primi passi e arriva alla riga di comando e alla cassetta degli attrezzi; il capitolo sul computer spiega
componenti, scheda tecnica, sensori in tempo reale, dischi HDD e SSD, attributi SMART, cosa occupa spazio e come liberarlo, test di velocità, memoria, avvio, aggiornamenti, antivirus e
Microsoft Defender, registro eventi, batteria e il metodo per un PC lento. Le date di supporto di
Windows citate sono quelle note a metà 2026 e vanno verificate sul sito Microsoft. Ogni valore misurato e ogni azione del piano rimandano
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

Scarica `STARNET-Polaris-windows-amd64.zip`, estrai la cartella e fai doppio clic su `Polaris.exe`. L'analisi parte da sola e dura circa 25 secondi.
Nella cartella `strumenti` ci sono CrystalDiskInfo, CrystalDiskMark e BlueScreenView: si aprono dalla cassetta degli attrezzi.

```text
polaris-cli report                  rapporto a schermo
polaris-cli report --verbose        con spiegazioni e passi da seguire
polaris-cli report --out r.txt      salva il rapporto (UTF-8, si apre col Blocco note)
polaris-cli report --json           dati grezzi, riapribili nell'interfaccia con "Importa"
polaris-cli serve --open            interfaccia nel browser su http://127.0.0.1:8737
polaris-cli bench cpu               test di velocità del processore (circa 25 secondi)
polaris-cli bench disk --drive D:   test di un'unità (file temporaneo cancellato alla fine)
polaris-cli defender status         stato di Microsoft Defender e minacce
polaris-cli defender quick          scansione rapida (full: completa; update: firme)
polaris-cli report --html --out stato-pc.html   documento stampabile sullo stato del PC
polaris-cli tools kit               kit per i PC senza Internet in strumenti-scaricati (--all: anche Safety Scanner)
polaris-cli tools status            programmi scaricati, sul PC e nel kit
polaris-cli clock                   velocità dei core in tempo reale (--seconds N, --json)
polaris-cli sensors --seconds 600 --csv sensori.csv   sensori come HWiNFO, con registro per Excel (--all, --json)
polaris-cli space C: --top 30       cosa occupa spazio, come WizTree (anche una cartella; --json)
```

Su Windows 11 24H2 e successivi la lettura delle reti Wi-Fi richiede il permesso di posizione per le app desktop: Polaris lo
rileva e spiega come attivarlo. Non servono privilegi di amministratore; avviando Polaris come amministratore compaiono anche
attributi SMART, registro NVMe, temperatura, usura ed errori dei dischi (e la temperatura dei dischi SATA nel monitor dei
sensori).

## Sviluppo

Requisiti: Node.js 20+, Go 1.24+; per i programmi inclusi curl e unzip (o Python 3). Si compila da Linux, macOS o Windows.

```bash
cd core && npm ci && npm test        # motore di analisi (vitest)
npm run dev                          # interfaccia con i dati dimostrativi su http://localhost:5173
cd ../windows && go test ./...       # agente Windows (gira anche su Linux)
cd .. && scripts/build-windows.sh    # build/STARNET-Polaris/ e build/STARNET-Polaris-windows-amd64.zip
```

La build scarica gli archivi originali di CrystalDiskInfo e CrystalDiskMark dalla pagina SourceForge del produttore e di
BlueScreenView da nirsoft.net, li verifica con l'impronta SHA-256 fissata in `scripts/strumenti.sh` e li estrae senza modifiche in
`strumenti/`; gli archivi restano in `build/cache-strumenti/`. Con `STRUMENTI=no scripts/build-windows.sh` il pacchetto esce senza
programmi inclusi.

`npm run dev` usa i dati dimostrativi (la rete *Casa*; dal selettore nell'avviso si passa a *Clinica*); con `polaris-cli serve`
avviato, il server di sviluppo inoltra `/api` all'agente vero.

Fino alla versione 0.2.0 il programma si chiamava LANterna: il repository e il modulo Go conservano quel nome interno.
I master del marchio sono in `brand/`; `node scripts/brand.mjs` rigenera i tracciati usati dall'interfaccia.

## Alternative open source

Quali programmi open source o quali funzioni native possono sostituire i download (CPU-Z, HWiNFO, Process Explorer, Autoruns,
WizTree, scanner antivirus), con licenze verificate, limiti e priorità: [docs/ALTERNATIVE-OPEN-SOURCE.md](docs/ALTERNATIVE-OPEN-SOURCE.md).

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
- I dati del computer si leggono senza modificare nulla; i test di velocità partono solo su richiesta, quello del disco con una
  conferma esplicita, lasciando almeno 2 GB liberi e cancellando il file di prova. Nei rapporti la cartella dell'utente è
  sostituita da `%USERPROFILE%`, i numeri di serie dei dischi non vengono letti e degli eventi si conservano solo origine,
  codice, numero e data (il dettaglio solo per schermate blu, dischi e file system).
- Di Microsoft Defender si leggono stato e cronologia delle minacce con nome, gravità e stato, senza percorsi dei file né nomi
  utente; scansioni e aggiornamento delle firme partono solo su richiesta (la scansione completa con una conferma).
- La cassetta degli attrezzi apre solo voci della sua lista bianca. I programmi inclusi si avviano solo se l'eseguibile è
  quello originale: una copia modificata o sostituita viene segnalata e non parte.
- I programmi scaricati arrivano solo quando li chiedi e solo dai siti del produttore (`download.cpuid.com`,
  `downloads.sourceforge.net`, `download.sysinternals.com`, `downloads.malwarebytes.com`, `go.microsoft.com`,
  `download.eset.com`, `diskanalyzer.com` e i loro server di distribuzione), passando dal proxy di sistema come il browser; la
  richiesta non porta dati del PC. Partono solo con la firma digitale valida dell'editore atteso, verificata da Windows a ogni
  avvio. La cartella del kit è affidabile quanto il supporto su cui sta: chi può scriverci può sostituire anche Polaris.exe.
- Il documento stampabile toglie indirizzi MAC e IP pubblici anche dai testi dei giudizi.

## Licenze

I componenti di terze parti inclusi nell'eseguibile e le loro licenze sono in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
(MIT, BSD, ISC, Apache-2.0, SIL Open Font License 1.1 per i font e la licenza del loader WebView2 di Microsoft), generato da
`scripts/notices.sh` a partire da ciò che finisce davvero nel bundle. Lo stesso file elenca i programmi della cartella
`strumenti` (CrystalDiskInfo e CrystalDiskMark, licenza MIT; BlueScreenView, gratuito e ridistribuibile senza modifiche) con
archivi, impronte e i componenti che contengono, ognuno con i testi completi nella propria cartella `License`. I programmi che
Polaris scarica su richiesta non fanno parte del pacchetto e restano soggetti alle licenze dei produttori. Tra questi c'è la libreria AMD_RC2t7 di CrystalDiskInfo, con una licenza
propria: si ridistribuisce solo dentro il pacchetto del programma, senza modifiche, e chiede un accordo aggiuntivo se le sue
funzioni o i suoi risultati vengono venduti. Se Polaris venisse distribuito a pagamento, queste condizioni andrebbero verificate. La licenza di STARNET Polaris stessa non è ancora stata scelta. Il marchio STARNET (cartella `brand/`) appartiene al suo
titolare e non è coperto da quelle licenze.
