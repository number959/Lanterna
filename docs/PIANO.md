# Piano dei rilasci

Ordine concordato l'8 novembre 2026, dopo la 0.10.0; lo stesso giorno i passi guidati sono diventati la 0.11.0 e le
versioni successive sono scalate di uno. Ogni versione segue lo stesso percorso della 0.10.0: ricerca sulle
fonti primarie, costruzione, revisione indipendente e correzioni, unione, verifiche complete (test, accessibilità, exe sotto
Wine, CI su Windows reale), documentazione e pacchetto con impronta SHA-256. Tutto in sola lettura, con API documentate di
Windows, senza driver in kernel; ciò che non si riesce a provare su hardware vero viene dichiarato in
[VERIFICHE.md](VERIFICHE.md).

| Versione | Contenuto | Stato |
| --- | --- | --- |
| 0.10.0 | Schermate blu come BlueScreenView, mappa del Wi-Fi per stanza, test di velocità di Internet, certificati dei servizi interni | fatta (1/11/2026) |
| 0.11.0 | **Passi guidati nel piano d'azione**: per ogni passo il percorso di Windows con i nomi italiani di menu e pulsanti, nella variante del PC analizzato (Windows 11 o Windows 10), il pulsante che apre la pagina giusta di Windows o il pannello del router, i comandi da copiare, le avvertenze (amministratore, router, altro dispositivo), la spunta per passo e "Come verificare"; **programmi utili dentro le azioni**, con lo stato e i pulsanti della cassetta degli attrezzi. Aggiunta su richiesta l'8/11/2026, prima del resto | in corso |
| 0.12.0 | **Il computer, seconda parte**: dispositivi con problemi, driver vecchi o non firmati, durata dell'avvio, crash dei programmi e indice di affidabilità, esito della diagnostica memoria, aggiornamenti falliti, punti di ripristino e backup, BitLocker, account e accessi (amministratori, accesso automatico, Desktop remoto, UAC), stampanti e spooler, file system da controllare | |
| 0.13.0 | **Sostituzioni native di Process Explorer, Autoruns e Controllo integrità PC**: processi con firma digitale e connessioni di rete; avvio esteso (attività pianificate, servizi, driver, sottoscrizioni WMI, estensioni dei browser); nome in codice del processore e del chipset nella scheda tecnica; requisiti completi di Windows 11, compreso l'elenco dei processori supportati | |
| 0.14.0 | **Rete**: VPN, errori sulla porta Ethernet, impostazioni della scheda Wi-Fi, DNS cifrato e perdite, porte in uscita verso i servizi indicati dall'utente, modello e firmware del router, monitor a lungo termine con CSV, mappa del Wi-Fi con le radio raggruppate per access point, proxy PAC e con autenticazione per il test di velocità | |
| 0.15.0 | **Tecnici e strutture**: riepilogo di più PC, storico e confronto tra analisi, analisi pianificata, verbale di intervento, impostazioni per l'organizzazione, modello per il registro degli asset, condivisioni SMB del PC, controllo versione, modalità utente e tecnico | |
| 0.16.0 | **Lingua inglese** per interfaccia e guide; **System Informer e WinDirStat** nella cartella `strumenti`, solo dopo la verifica di driver e segnalazioni degli antivirus e nel rispetto delle licenze (WinDirStat è GPL-3) | |
| poi | **Android** ed **ESP32** secondo [ANDROID.md](ANDROID.md) ed [ESP32.md](ESP32.md): compilabili e con test, ma dichiarati non provati su dispositivi veri finché non ce ne sono | |

Trasversali, fatti con la 0.11.0: aggiornamento di Go a 1.27.2 (Go 1.24 non è più supportato dal 10 febbraio 2026) e gli
avvisi di `go vet` a 32 bit in `pcinfo`. Il bundle dell'interfaccia resta un unico file per scelta (si apre anche come file
locale e dentro WebView2 senza un server): il limite dell'avviso di vite è alzato di conseguenza.

Decisioni che restano a STARNET, già segnalate: informativa sulla privacy e contributo per il test di velocità di Internet
(regole d'uso di M-Lab); licenza di STARNET Polaris; se e quando uscire dall'Italia (da cui dipende la lingua inglese).
