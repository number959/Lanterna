# Piano dei rilasci

Ordine concordato l'8 novembre 2026, dopo la 0.10.0; lo stesso giorno i passi guidati sono diventati la 0.11.0 e le
versioni successive sono scalate di uno. Il 10 novembre la mappa della rete, la scoperta delle VLAN e le videoguide sono
diventate la 0.13.0, e le versioni successive sono scalate ancora di uno. Ogni versione segue lo stesso percorso della 0.10.0: ricerca sulle
fonti primarie, costruzione, revisione indipendente e correzioni, unione, verifiche complete (test, accessibilità, exe sotto
Wine, CI su Windows reale), documentazione e pacchetto con impronta SHA-256. Tutto in sola lettura, con API documentate di
Windows, senza driver in kernel; ciò che non si riesce a provare su hardware vero viene dichiarato in
[VERIFICHE.md](VERIFICHE.md).

| Versione | Contenuto | Stato |
| --- | --- | --- |
| 0.10.0 | Schermate blu come BlueScreenView, mappa del Wi-Fi per stanza, test di velocità di Internet, certificati dei servizi interni | fatta (1/11/2026) |
| 0.11.0 | **Passi guidati nel piano d'azione**: per ogni passo il percorso di Windows con i nomi italiani di menu e pulsanti, nella variante del PC analizzato (Windows 11 o Windows 10), il pulsante che apre la pagina giusta di Windows o il pannello del router, i comandi da copiare, le avvertenze (amministratore, router, altro dispositivo), la spunta per passo e "Come verificare"; **programmi utili dentro le azioni**, con lo stato e i pulsanti della cassetta degli attrezzi. Aggiunta su richiesta l'8/11/2026, prima del resto | fatta (8/11/2026; release v0.11.0 su GitHub creata come bozza il 9/11) |
| 0.12.0 | **Il computer, seconda parte**: dispositivi con problemi, driver vecchi o non firmati, durata dell'avvio, crash dei programmi e indice di affidabilità, esito della diagnostica memoria, aggiornamenti falliti, punti di ripristino e backup, BitLocker, account e accessi (amministratori, accesso automatico, Desktop remoto, UAC), stampanti e spooler, file system da controllare; **test della RAM con Windows acceso** (come HCI MemTest e MemTest64: solo la memoria libera, su richiesta e con conferma); **albero dei dispositivi USB** (come UsbTreeView). Nella cassetta: Memtest86+ e Rufus scaricabili dal sito ufficiale per il test da chiavetta, UsbTreeView incluso, HCI MemTest come collegamento | fatta (9/11/2026; release v0.12.0 su GitHub creata come bozza il 9/11) |
| 0.13.0 | **La rete, vista e spiegata**: **mappa della rete interattiva** con il tipo di ogni dispositivo riconosciuto da segnali che non forzano nulla (ruolo, produttore dal MAC, servizi mDNS e UPnP, ruoli NetBIOS, nome, TTL), zone per sottorete, VLAN e rete Wi-Fi, percorsi del traffico animati; **il traffico passo passo** (i pacchetti di un sito web, del DHCP, di un ping, del traceroute, dei servizi verificati e di una stampa, ricostruiti con gli indirizzi e i tempi dell'analisi, con vista della rete, vista a sequenza e tabella dei pacchetti); **scoperta delle VLAN e delle altre reti** senza indicarle (ascolto di quello che annuncia lo switch con LLDP, CDP, DTP e STP; tabella di instradamento; server in altre sottoreti; reti Wi-Fi degli stessi access point; sottoreti di Active Directory su richiesta; SNMP in sola lettura con le credenziali del tecnico), destinazioni scoperte nel test di segmentazione; **videoguide** animate con la voce italiana di Windows (Microsoft Elsa) e sottotitoli; guide riviste con nuovi schemi animati | fatta (10/11/2026; release v0.13.0 **pubblicata** su GitHub il 10/11/2026 alle 23:40 UTC, su richiesta di STARNET: workflow Release run 4 sul commit 087d277, tag `v0.13.0`, SHA-256 del pacchetto `bed651c46ba1384c429a975a00b2d70fcfec729e93054b589a4e8646085a1192`; ha sostituito la bozza del 10/11) |
| 0.14.0 | **Sostituzioni native di Process Explorer, Autoruns e Controllo integrità PC**: processi con firma digitale e connessioni di rete; avvio esteso (attività pianificate, servizi, driver, sottoscrizioni WMI, estensioni dei browser); nome in codice del processore e del chipset nella scheda tecnica; requisiti completi di Windows 11, compreso l'elenco dei processori supportati. Nella cassetta: TCPView e Process Monitor scaricabili dal sito Microsoft | |
| 0.15.0 | **Rete**: VPN, errori sulla porta Ethernet, impostazioni della scheda Wi-Fi, DNS cifrato e perdite, porte in uscita verso i servizi indicati dall'utente, modello e firmware del router, monitor a lungo termine con CSV, mappa del Wi-Fi con le radio raggruppate per access point, proxy PAC e con autenticazione per il test di velocità; **perdita e ritardo per tratto di rete nel tempo** (come WinMTR); **velocità della rete locale tra due PC** con Polaris (come iperf3). Nella cassetta: PuTTY incluso, Wireshark come collegamento | |
| 0.16.0 | **Tecnici e strutture**: riepilogo di più PC, storico e confronto tra analisi, analisi pianificata, verbale di intervento, impostazioni per l'organizzazione, modello per il registro degli asset, condivisioni SMB del PC, controllo versione, modalità utente e tecnico | |
| 0.17.0 | **Lingua inglese** per interfaccia e guide; **System Informer e WinDirStat** nella cartella `strumenti`, solo dopo la verifica di driver e segnalazioni degli antivirus e nel rispetto delle licenze (WinDirStat è GPL-3) | |
| poi | **Android** ed **ESP32** secondo [ANDROID.md](ANDROID.md) ed [ESP32.md](ESP32.md): compilabili e con test, ma dichiarati non provati su dispositivi veri finché non ce ne sono | |

Trasversali, fatti con la 0.11.0: aggiornamento di Go a 1.27.2 (Go 1.24 non è più supportato dal 10 febbraio 2026) e gli
avvisi di `go vet` a 32 bit in `pcinfo`. Il bundle dell'interfaccia resta un unico file per scelta (si apre anche come file
locale e dentro WebView2 senza un server): il limite dell'avviso di vite è alzato di conseguenza.

Aggiunte decise il 9/11/2026, dopo la ricerca sui programmi da inserire (licenze in
[ALTERNATIVE-OPEN-SOURCE.md](ALTERNATIVE-OPEN-SOURCE.md)): test della RAM con Windows acceso e albero USB nella 0.12.0,
programmi nuovi della cassetta distribuiti tra 0.12.0, 0.14.0 e 0.15.0, tratti di rete e rete locale nella 0.15.0.

Decisioni che restano a STARNET, già segnalate: informativa sulla privacy e contributo per il test di velocità di Internet
(regole d'uso di M-Lab); licenza di STARNET Polaris (se fosse venduto, BlueScreenView non potrebbe più stare nel pacchetto:
la sua licenza vieta di farsi pagare); se e quando uscire dall'Italia (da cui dipende la lingua inglese).
