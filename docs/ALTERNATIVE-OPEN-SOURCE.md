# Alternative open source ai programmi da scaricare

Oggi Polaris scarica su richiesta, dal sito del produttore, otto programmi che non si possono includere: CPU-Z, HWiNFO,
AdwCleaner, Microsoft Safety Scanner, ESET Online Scanner, Autoruns, Process Explorer e WizTree. Questo documento dice, per
ognuno, se esiste un'alternativa open source o un modo di fare la stessa cosa dentro Polaris, con quale licenza e con quali
limiti, per ridurre i download.

Le licenze sono state lette il **25/10/2026** dai file di licenza dei repository ufficiali (link in fondo). Il resto (stato dei
progetti, comportamento dei driver, segnalazioni degli antivirus) va **verificato** prima di integrare qualcosa: i progetti
cambiano. Non è una consulenza legale: per un uso commerciale le licenze vanno lette per intero.

## Due strade

1. **Fare la cosa dentro Polaris** (nativo), con funzioni documentate di Windows, in sola lettura e senza driver: nessun
   programma in più da scaricare, stessa interfaccia, stessi rapporti. È la strada già seguita per SMART, scheda tecnica, test
   di velocità, Defender e, ora, per la velocità dei core.
2. **Includere un programma open source** nella cartella `strumenti`, come CrystalDiskInfo e CrystalDiskMark: si può fare
   quando la licenza consente la ridistribuzione (MIT, BSD, MPL, GPL con i relativi obblighi), con la stessa verifica
   dell'impronta SHA-256 prima dell'avvio.

Un limite vale per tutti: temperature e tensioni della scheda madre, timing della memoria (SPD) e letture dirette dei registri
del processore richiedono un **driver in kernel**. Polaris non ne usa per scelta (sicurezza, firma dei driver, segnalazioni
degli antivirus), quindi quei dati restano ai programmi dedicati.

## Ricreare i programmi dentro Polaris: dove si può e dove no

Dalla 0.11.0 i programmi della cassetta degli attrezzi compaiono anche dentro le azioni del piano a cui servono, con lo stato
(incluso, installato, scaricabile) e i pulsanti per aprirli o scaricarli; quando Polaris fa già la stessa cosa, la scheda lo
dice e porta alla sezione. L'obiettivo resta averne bisogno il meno possibile, ricreando le funzioni dentro Polaris.

Il confine è lo stesso per tutti:

- si ricrea **la funzione**, partendo dalla documentazione pubblica di Windows, dalle specifiche (ATA, NVMe, SMBIOS, formati dei
  dump) e dai fatti tecnici descritti in fonti aperte; **mai** copiando, decompilando o analizzando il codice dei programmi
  proprietari (CPU-Z, HWiNFO, WizTree, BlueScreenView e Sysinternals lo sono);
- il codice open source si riusa solo dove la licenza lo consente: MIT, BSD e Apache con l'avviso di copyright nel pacchetto,
  come per le librerie già usate; il codice GPL non si copia, perché obbligherebbe a distribuire Polaris con la stessa licenza:
  lo si legge solo per i fatti (quali tabelle o registri esistono) e si scrive codice proprio;
- niente driver in kernel: quello che Windows non espone senza un driver resta ai programmi dedicati.

| Programma | Già dentro Polaris | Prossimo passo | Che cosa resta al programma, e perché |
| --- | --- | --- | --- |
| CrystalDiskInfo | salute dei dischi: SMART ATA e NVMe, stato, temperatura, ore di accensione, registro NVMe (0.6.0) | — | dischi dietro alcuni controller RAID e adattatori USB, cronologia continua dei valori; resta incluso come seconda opinione |
| CrystalDiskMark | test di velocità con lo stesso profilo, in versione breve (0.6.0) | — | il test completo con passate e dimensione del file a scelta; resta incluso |
| CPU-Z | scheda tecnica (0.6.0) e velocità dei core in tempo reale (0.7.0) | 0.13.0: nome in codice del processore e del chipset | profili XMP/EXPO e timing dei moduli di memoria, tensioni: richiedono letture con un driver |
| HWiNFO | sensori: utilizzo, frequenze, consumi esposti da Windows, zone termiche, scheda video, dischi, rete, batteria (0.8.0) | — | temperature, tensioni e ventole di processore e scheda madre: richiedono un driver |
| WizTree, WinDirStat | cosa occupa spazio (0.9.0) | 0.16.0: WinDirStat nella cartella `strumenti`, nel rispetto della GPL-3 | la velocità di WizTree sui dischi con milioni di file, che legge direttamente la tabella dei file di NTFS |
| BlueScreenView | file delle schermate blu (0.10.0) | — | il driver indicato è un indizio, e BlueScreenView può indicarne un altro; resta incluso |
| Process Explorer | i processi che pesano di più durante l'analisi | 0.13.0: processi con firma digitale verificata e connessioni di rete | file aperti e librerie di ogni processo: restano a Process Explorer o a System Informer (0.16.0) |
| Autoruns | chiavi Run e cartelle di esecuzione automatica | 0.13.0: attività pianificate, servizi, driver, sottoscrizioni WMI, estensioni dei browser | disattivare le voci: Polaris resta in sola lettura |
| Controllo integrità PC | requisiti di Windows 11 verificabili da Windows | 0.13.0: requisiti completi, con l'elenco dei processori supportati pubblicato da Microsoft | — |
| Malwarebytes, AdwCleaner, Microsoft Safety Scanner, ESET Online Scanner | stato, minacce e scansioni di Microsoft Defender (0.6.0) | — | un motore antivirus non si ricrea: firme e analisi aggiornate di continuo sono il prodotto stesso. Polaris usa Defender, già in Windows; per un secondo parere servono questi |
| MemTest86 | nessun test della RAM: il piano guida alla Diagnostica memoria Windows | 0.12.0: esito della Diagnostica memoria Windows nel rapporto | il test parte da una chiavetta, fuori da Windows: un programma che gira dentro Windows non può provare la memoria che Windows stesso occupa |

## Programma per programma

| Oggi si scarica | Alternativa | Licenza | Proposta | Limiti |
| --- | --- | --- | --- | --- |
| **CPU-Z** (scheda tecnica) | già nativo: scheda tecnica e velocità dei core in tempo reale; in più **libcpuid** (tabelle per riconoscere il nome in codice del processore) e **pci.ids** (nomi di chipset e dispositivi PCI) | libcpuid: BSD-2-Clause; pci.ids: GPL-2.0-or-later **oppure** BSD-3-Clause, a scelta | nativo: nome in codice del processore e del chipset; dettagli SMBIOS (memoria, scheda madre) letti con `GetSystemFirmwareTable` secondo la specifica DMTF pubblica | timing SPD della memoria, tensioni e clock misurati richiedono un driver |
| **HWiNFO** (sensori) | **LibreHardwareMonitor** (libreria e programma per sensori) | MPL-2.0; usa un driver in kernel (PawnIO, GPL-2.0-or-later con eccezione) | **fatto nella 0.8.0**, nativo: Computer > Sensori, con utilizzo, frequenze e limite di prestazioni del processore, consumi RAPL dove Windows li espone (Energy Meter), zone termiche ACPI, scheda video (utilizzo per motore, memoria e, dal driver WDDM 2.4+, temperatura, ventola, potenza, frequenze, tensione), memoria, dischi con la temperatura SMART, rete e batteria; minimo, massimo, media, avvisi e CSV | temperature e tensioni di CPU e scheda madre e ventole della scheda madre solo con un driver: integrare LibreHardwareMonitor significherebbe portare in Polaris un driver, contro le sue regole; per quelle resta HWiNFO |
| **Process Explorer** | **System Informer** (successore di Process Hacker) | MIT | includibile nella cartella `strumenti`; oppure nativo: processi con firma digitale verificata e connessioni di rete, in sola lettura | System Informer usa un proprio driver in kernel e alcuni antivirus lo segnalano come strumento sensibile (da verificare prima di includerlo) |
| **Autoruns** | **osquery** come riferimento (tabelle per avvio, attività pianificate, servizi, sottoscrizioni WMI) | Apache-2.0 / GPL-2.0, a scelta | nativo: estendere la sezione Avvio con attività pianificate, servizi, driver, sottoscrizioni WMI ed estensioni dei browser, in sola lettura | osquery è un agente pesante: conviene usarlo come elenco di cosa controllare, non includerlo |
| **WizTree** (spazio su disco) | **WinDirStat**; **gdu** (analizzatore in Go) | WinDirStat: GPL-3.0-or-later; gdu: MIT | **fatto nella 0.9.0**, nativo e con codice proprio (nessuna libreria nuova): Computer > Cosa occupa spazio e `polaris-cli space`, con mappa a riquadri, tabella delle cartelle con apertura in Esplora file, 100 file più grandi, tipi di file, cartelle note di Windows con i consigli, collegamenti fisici contati una volta, file solo online di OneDrive esclusi senza scaricarli; il motore stima lo spazio recuperabile e aggiunge le azioni al piano | senza leggere direttamente la tabella dei file di NTFS (che richiede l'amministratore) la lettura è più lenta di WizTree sui dischi con milioni di file; si vedono le 100 voci più grandi e un albero ridotto alle cartelle più grandi, non ogni singolo file; WizTree resta scaricabile per questi casi |
| **AdwCleaner**, **Microsoft Safety Scanner**, **ESET Online Scanner** | **Microsoft Defender**, già integrato; **ClamAV** come secondo parere; **YARA** per controlli mirati | ClamAV: GPL-2.0; YARA: BSD-3-Clause | tenere Defender come motore principale (nessun download); nativo: stato della protezione dalle app indesiderate (PUA) di Defender ed elenco delle estensioni dei browser | ClamAV ha bisogno di un archivio di firme di centinaia di MB da aggiornare e, su Windows, rileva meno dei motori commerciali (valutazione generale, da verificare su test indipendenti); YARA richiede regole curate e genera falsi positivi |
| **BlueScreenView** (già incluso) | lettura nativa dei minidump, dai layout pubblici (documentazione Microsoft dei codici di arresto e fonti aperte sul formato) | — | **fatto nella 0.10.0**, nativo e con codice proprio (nessuna libreria nuova): Computer > File delle schermate blu e `polaris-cli crashes`, con data, codice e significato, parametri, driver caricati e driver indicato come indizio (parametro documentato per il codice, altrimenti lo stack salvato), impostazioni dei dump; il motore segnala driver e codici ricorrenti | indizio e non certezza: BlueScreenView e WinDbg possono indicare un driver diverso; dump a 32 bit, kernel e completi solo nell'intestazione (provata su un dump vero di Windows Server 2025); elenco dei driver e stack provati solo su file costruiti dai layout pubblici; i file si leggono da amministratore; nessuna prova su Windows 11 su ARM. BlueScreenView resta incluso |

## Priorità consigliate

In ordine di utilità rispetto al lavoro:

1. ~~**Cosa occupa spazio**, nativo~~: fatto nella 0.9.0; sostituisce WizTree nella maggior parte dei casi, senza dipendenze
   nuove.
2. **Processi con firma e connessioni**, nativo: copre l'uso diagnostico più comune di Process Explorer.
3. **Avvio esteso** (attività pianificate, servizi, driver, sottoscrizioni WMI, estensioni dei browser), nativo: copre gran parte
   di Autoruns ed è utile anche per la sicurezza.
4. ~~**Monitor delle prestazioni** con i contatori di Windows (GPU, dischi, rete)~~: fatto nella 0.8.0 come monitor dei
   sensori, che riusa l'infrastruttura della velocità dei core.
5. **Nome in codice del processore e del chipset** (libcpuid, pci.ids): piccolo, migliora la scheda tecnica.
6. **System Informer e WinDirStat nella cartella `strumenti`**, dopo aver verificato driver e segnalazioni degli antivirus.
7. ~~**Minidump nativi**~~: fatti nella 0.10.0; BlueScreenView resta incluso per chi vuole il suo elenco completo.

Con i punti 1-4 i download restano necessari solo per le temperature, le tensioni e le ventole di processore e scheda madre
(HWiNFO o LibreHardwareMonitor) e per un secondo parere antivirus (Safety Scanner o ESET), cioè proprio dove servirebbe un driver
o un motore antivirus completo.

## Fonti

- System Informer, licenza MIT: <https://github.com/winsiderss/systeminformer/blob/master/LICENSE.txt>
- LibreHardwareMonitor, licenza MPL-2.0: <https://github.com/LibreHardwareMonitor/LibreHardwareMonitor/blob/master/LICENSE>
- PawnIO, GPL-2.0-or-later con eccezione: <https://github.com/namazso/PawnIO>
- WinDirStat, GPL-3.0-or-later, versione portable: <https://github.com/windirstat/windirstat>
- libcpuid, licenza BSD a due clausole: <https://github.com/anrieff/libcpuid/blob/master/COPYING>
- gdu, licenza MIT: <https://github.com/dundee/gdu/blob/master/LICENSE.md>
- ClamAV, GPL-2.0: <https://github.com/Cisco-Talos/clamav/blob/main/COPYING.txt>
- osquery, Apache-2.0 e GPL-2.0: <https://github.com/osquery/osquery/blob/master/LICENSE>
- YARA, licenza BSD a tre clausole: <https://github.com/VirusTotal/yara/blob/master/COPYING>
- pci.ids, GPL-2.0-or-later oppure BSD-3-Clause: <https://pci-ids.ucw.cz/>
- Passaggio di LibreHardwareMonitor e Fan Control da WinRing0 a PawnIO dopo le segnalazioni di Microsoft Defender: note di
  rilascio di Fan Control (v238) e discussioni dei progetti che lo usano, consultate il 25/10/2026.
