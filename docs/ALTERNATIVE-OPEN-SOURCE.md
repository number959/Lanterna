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

## Programma per programma

| Oggi si scarica | Alternativa | Licenza | Proposta | Limiti |
| --- | --- | --- | --- | --- |
| **CPU-Z** (scheda tecnica) | già nativo: scheda tecnica e velocità dei core in tempo reale; in più **libcpuid** (tabelle per riconoscere il nome in codice del processore) e **pci.ids** (nomi di chipset e dispositivi PCI) | libcpuid: BSD-2-Clause; pci.ids: GPL-2.0-or-later **oppure** BSD-3-Clause, a scelta | nativo: nome in codice del processore e del chipset; dettagli SMBIOS (memoria, scheda madre) letti con `GetSystemFirmwareTable` secondo la specifica DMTF pubblica | timing SPD della memoria, tensioni e clock misurati richiedono un driver |
| **HWiNFO** (sensori) | **LibreHardwareMonitor** (libreria e programma per sensori) | MPL-2.0; usa un driver in kernel (PawnIO, GPL-2.0-or-later con eccezione) | **fatto nella 0.8.0**, nativo: Computer > Sensori, con utilizzo, frequenze e limite di prestazioni del processore, consumi RAPL dove Windows li espone (Energy Meter), zone termiche ACPI, scheda video (utilizzo per motore, memoria e, dal driver WDDM 2.4+, temperatura, ventola, potenza, frequenze, tensione), memoria, dischi con la temperatura SMART, rete e batteria; minimo, massimo, media, avvisi e CSV | temperature e tensioni di CPU e scheda madre e ventole della scheda madre solo con un driver: integrare LibreHardwareMonitor significherebbe portare in Polaris un driver, contro le sue regole; per quelle resta HWiNFO |
| **Process Explorer** | **System Informer** (successore di Process Hacker) | MIT | includibile nella cartella `strumenti`; oppure nativo: processi con firma digitale verificata e connessioni di rete, in sola lettura | System Informer usa un proprio driver in kernel e alcuni antivirus lo segnalano come strumento sensibile (da verificare prima di includerlo) |
| **Autoruns** | **osquery** come riferimento (tabelle per avvio, attività pianificate, servizi, sottoscrizioni WMI) | Apache-2.0 / GPL-2.0, a scelta | nativo: estendere la sezione Avvio con attività pianificate, servizi, driver, sottoscrizioni WMI ed estensioni dei browser, in sola lettura | osquery è un agente pesante: conviene usarlo come elenco di cosa controllare, non includerlo |
| **WizTree** (spazio su disco) | **WinDirStat**; **gdu** (analizzatore in Go) | WinDirStat: GPL-3.0-or-later; gdu: MIT | nativo: "Cosa occupa spazio" con le cartelle più grandi del disco (codice proprio o la libreria di gdu); in alternativa WinDirStat incluso nella cartella `strumenti` (versione portable, con licenza e indicazione dei sorgenti) | senza leggere direttamente la tabella dei file di NTFS la scansione è più lenta di WizTree (minuti invece di secondi sui dischi grandi) |
| **AdwCleaner**, **Microsoft Safety Scanner**, **ESET Online Scanner** | **Microsoft Defender**, già integrato; **ClamAV** come secondo parere; **YARA** per controlli mirati | ClamAV: GPL-2.0; YARA: BSD-3-Clause | tenere Defender come motore principale (nessun download); nativo: stato della protezione dalle app indesiderate (PUA) di Defender ed elenco delle estensioni dei browser | ClamAV ha bisogno di un archivio di firme di centinaia di MB da aggiornare e, su Windows, rileva meno dei motori commerciali (valutazione generale, da verificare su test indipendenti); YARA richiede regole curate e genera falsi positivi |
| **BlueScreenView** (già incluso) | lettura nativa dei minidump (formato documentato da Microsoft) | — | nativo: codice di arresto e moduli caricati letti dai file `C:\Windows\Minidump` | individuare il driver colpevole come fa BlueScreenView richiede euristiche non banali |

## Priorità consigliate

In ordine di utilità rispetto al lavoro:

1. **Cosa occupa spazio**, nativo: sostituisce WizTree nella maggior parte dei casi, senza dipendenze nuove.
2. **Processi con firma e connessioni**, nativo: copre l'uso diagnostico più comune di Process Explorer.
3. **Avvio esteso** (attività pianificate, servizi, driver, sottoscrizioni WMI, estensioni dei browser), nativo: copre gran parte
   di Autoruns ed è utile anche per la sicurezza.
4. ~~**Monitor delle prestazioni** con i contatori di Windows (GPU, dischi, rete)~~: fatto nella 0.8.0 come monitor dei
   sensori, che riusa l'infrastruttura della velocità dei core.
5. **Nome in codice del processore e del chipset** (libcpuid, pci.ids): piccolo, migliora la scheda tecnica.
6. **System Informer e WinDirStat nella cartella `strumenti`**, dopo aver verificato driver e segnalazioni degli antivirus.
7. **Minidump nativi**: il più impegnativo; BlueScreenView incluso copre già il bisogno.

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
