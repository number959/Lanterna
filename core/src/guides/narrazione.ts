// File generato da scripts/narrazione/genera.py: non modificare a mano.
// Le registrazioni della narrazione delle videoguide (una per frase) stanno in
// src/guides/narrazione/; qui c'è l'indice dal testo della frase al file.

export interface VoceRegistrata {
  /** Nome mostrato nel lettore. */
  nome: string;
  /** Motore di sintesi e modello con cui è stata generata. */
  motore: string;
  modello: string;
  /** Licenza del modello e attribuzione dovuta. */
  licenza: string;
}

export const VOCE: VoceRegistrata | undefined = {
  "nome": "Sara",
  "motore": "Kokoro-82M",
  "modello": "kokoro-v1.0.onnx, voce if_sara",
  "licenza": "Kokoro-82M di hexgrad, licenza Apache-2.0"
};

/** Per ogni frase registrata: il file e la durata in millisecondi. */
export const CLIP: Record<string, { file: string; ms: number }> = {
  "La mappa della rete disegna ciò che Polaris ha trovato intorno a questo PC.": {
    "file": "8c8d1054e9ce.ogg",
    "ms": 4254
  },
  "In alto c'è Internet, poi la rete dell'operatore e il router.": {
    "file": "0ae74be383f7.ogg",
    "ms": 3429
  },
  "Davanti al router ci sono le zone della rete, con i dispositivi disegnati secondo il loro tipo.": {
    "file": "784591ce8798.ogg",
    "ms": 5589
  },
  "Polaris non entra nei dispositivi: ascolta quello che dicono di sé.": {
    "file": "2cff7035081d.ogg",
    "ms": 3819
  },
  "Una stampante annuncia il servizio di stampa, una TV il servizio per trasmettere i video.": {
    "file": "2af1bdbab27f.ogg",
    "ms": 5291
  },
  "Contano anche il produttore della scheda di rete, il nome e il ruolo nella rete.": {
    "file": "74cfc3c75b8e.ogg",
    "ms": 4288
  },
  "Tocca un dispositivo per leggere perché è stato riconosciuto così.": {
    "file": "acdb8035f7e8.ogg",
    "ms": 3945
  },
  "Ogni riconoscimento ha una confidenza: alta, media o bassa.": {
    "file": "65b6cc2bdbcb.ogg",
    "ms": 3689
  },
  "Il punto interrogativo segna un'ipotesi con pochi indizi, da verificare di persona.": {
    "file": "abd722fbef0c.ogg",
    "ms": 5013
  },
  "L'ellisse tratteggiata a terra, sotto il disegno, indica un dispositivo dedotto, che non ha risposto direttamente.": {
    "file": "03eb233db342.ogg",
    "ms": 6485
  },
  "Le piattaforme sono le zone: la rete di questo PC, le altre sottoreti e le reti Wi-Fi separate.": {
    "file": "9c8a113c6f0b.ogg",
    "ms": 6080
  },
  "In una struttura sanitaria ogni zona è di solito una rete virtuale, chiamata VLAN.": {
    "file": "8970d05243d6.ogg",
    "ms": 4779
  },
  "Le zone sono collegate al firewall, che decide quale traffico può passare.": {
    "file": "551d18e0983e.ogg",
    "ms": 4471
  },
  "I pacchetti che scorrono, con l'etichetta del protocollo, mostrano il percorso del traffico di questo PC: una corsia per l'andata e una per il ritorno.": {
    "file": "337b8497e7e8.ogg",
    "ms": 8595
  },
  "Scegli un percorso sotto la mappa: verso Internet, verso il server dei nomi o verso un servizio.": {
    "file": "92805d510a15.ogg",
    "ms": 5440
  },
  "Un segnale di stop indica un collegamento bloccato come previsto.": {
    "file": "2d804a231eaa.ogg",
    "ms": 3733
  },
  "In rosso c'è un collegamento che passa anche se dovrebbe essere bloccato.": {
    "file": "308906dd3633.ogg",
    "ms": 3998
  },
  "Polaris vede il traffico di questo PC, non quello degli altri dispositivi.": {
    "file": "4817d749c608.ogg",
    "ms": 4331
  },
  "Senza l'inventario compaiono solo i dispositivi che il PC ha contattato di recente.": {
    "file": "498113827e0e.ogg",
    "ms": 4905
  },
  "L'inventario parte solo su richiesta, con un ritmo prudente e senza provare le porte dei dispositivi.": {
    "file": "09933c0a41ac.ogg",
    "ms": 5867
  },
  "All'avvio Polaris analizza il computer e la rete a cui è collegato.": {
    "file": "f6a4363e5dac.ogg",
    "ms": 3947
  },
  "Dura circa mezzo minuto e non cambia nessuna impostazione.": {
    "file": "fc92735be1f9.ogg",
    "ms": 3413
  },
  "Qui vedi la rete di una casa, come la disegna Polaris con i dati dimostrativi.": {
    "file": "dff52a8151bc.ogg",
    "ms": 4352
  },
  "Le misure seguono i livelli della rete, dal basso verso l'alto.": {
    "file": "9fe19f3edf23.ogg",
    "ms": 3492
  },
  "Prima la scheda di rete e il Wi-Fi, poi l'indirizzo e il router, infine Internet, i nomi e i siti.": {
    "file": "1b609147556e.ogg",
    "ms": 5333
  },
  "Se un livello non funziona, anche quelli sopra sembrano guasti: per questo si parte dal basso.": {
    "file": "af7809ef3c5e.ogg",
    "ms": 5419
  },
  "Il punteggio va da 0 a 100 e riassume la salute del computer e della rete.": {
    "file": "43259a17cebe.ogg",
    "ms": 4501
  },
  "Verde vuol dire buono, giallo da sistemare, rosso da sistemare per primo.": {
    "file": "b2afcfcc6e99.ogg",
    "ms": 4224
  },
  "Con un problema critico il punteggio resta sotto 70, anche se tutto il resto va bene.": {
    "file": "5b052e2092b0.ogg",
    "ms": 5141
  },
  "Ogni area ha la sua sezione: computer, Wi-Fi, rete locale, Internet, router e infrastruttura.": {
    "file": "7fa0f850ef1e.ogg",
    "ms": 5312
  },
  "Un clic su un giudizio apre la scheda che spiega il valore, le soglie e che cosa fare.": {
    "file": "a44c184c2173.ogg",
    "ms": 4544
  },
  "Nella sezione della rete locale c'è la mappa, con i dispositivi e i percorsi del traffico.": {
    "file": "2d840077861e.ogg",
    "ms": 5112
  },
  "Il piano d'azione mette in ordine le cose da fare, a partire dalla più urgente.": {
    "file": "8c1261c2094c.ogg",
    "ms": 4321
  },
  "Per esempio, con il Wi-Fi disturbato dai vicini propone di cambiare canale, passo dopo passo.": {
    "file": "9c5004ee27cb.ogg",
    "ms": 5525
  },
  "Ogni passo ha la sua spunta, così tieni il conto di ciò che hai già fatto.": {
    "file": "ffd2e53fe8ca.ogg",
    "ms": 4046
  },
  "Il pulsante Documento prepara una pagina sullo stato del PC e sul lavoro da fare.": {
    "file": "3fe34692935d.ogg",
    "ms": 4928
  },
  "Si stampa o si salva in un file PDF, da consegnare a chi usa il computer.": {
    "file": "2beaae3257ea.ogg",
    "ms": 4452
  },
  "E se la stampante non stampa, c'è una guida anche per questo.": {
    "file": "bf5f445e7d1a.ogg",
    "ms": 3371
  },
  "Dopo gli interventi, una nuova analisi conferma il risultato.": {
    "file": "a5ee917c655b.ogg",
    "ms": 3710
  },
  "In una clinica la rete è divisa in zone, ognuna in una VLAN, cioè una rete virtuale separata.": {
    "file": "2bfbe93573c3.ogg",
    "ms": 5158
  },
  "Un PC collegato a una porta dello switch vede solo la sua VLAN, ed è giusto così.": {
    "file": "3535ca8238e6.ogg",
    "ms": 4800
  },
  "Può però scoprire che le altre reti esistono, senza entrarci.": {
    "file": "c8ee2105a910.ogg",
    "ms": 3499
  },
  "Gli switch annunciano periodicamente chi sono, porta per porta.": {
    "file": "7194181275af.ogg",
    "ms": 3518
  },
  "Con LLDP e CDP, i protocolli di annuncio, dicono il nome dello switch, la porta e le VLAN dei dati e della voce.": {
    "file": "f5c4ee7a9391.ogg",
    "ms": 7083
  },
  "Polaris li ascolta per circa un minuto e non trasmette nulla.": {
    "file": "4db7868a9345.ogg",
    "ms": 3541
  },
  "Se arriva un annuncio DTP, la porta potrebbe diventare un trunk, cioè portare tutte le VLAN: va corretta sullo switch.": {
    "file": "6fe774eebf60.ogg",
    "ms": 6848
  },
  "Anche il PC sa già qualcosa delle altre reti.": {
    "file": "03a74a9852aa.ogg",
    "ms": 2859
  },
  "La tabella di instradamento può contenere le rotte verso altre reti interne.": {
    "file": "e30d4006a7af.ogg",
    "ms": 4376
  },
  "Un server che assegna gli indirizzi o risolve i nomi, se sta in un'altra rete, rivela la rete dei server.": {
    "file": "ba4744c00dd1.ogg",
    "ms": 5670
  },
  "Le reti Wi-Fi trasmesse dagli stessi access point di solito sono VLAN separate.": {
    "file": "f1ae6403fb92.ogg",
    "ms": 4821
  },
  "Con le credenziali del tecnico, Polaris interroga il router in sola lettura con SNMP, il protocollo di gestione degli apparati.": {
    "file": "9af1087c2062.ogg",
    "ms": 7893
  },
  "Il router risponde con l'elenco delle VLAN, il gateway di ogni rete e i dispositivi che ha visto.": {
    "file": "628bdfe823ff.ogg",
    "ms": 5312
  },
  "Le credenziali non vengono salvate, e la versione 3 di SNMP, che cifra, è da preferire.": {
    "file": "69d6f5a2d012.ogg",
    "ms": 5632
  },
  "Polaris non scansiona interi intervalli di indirizzi e non prova a saltare da una VLAN all'altra.": {
    "file": "d7ef028da1f7.ogg",
    "ms": 5611
  },
  "L'inventario di una rete parte solo su richiesta, una sottorete alla volta.": {
    "file": "c60bb7513792.ogg",
    "ms": 4239
  },
  "Sono tecniche da test di intrusione, che si usano solo con un incarico scritto.": {
    "file": "0d3d794534e4.ogg",
    "ms": 4267
  },
  "Qui gli ospiti raggiungono Internet, ma non la VLAN dei dispositivi medicali.": {
    "file": "d74ca12d98e7.ogg",
    "ms": 4309
  },
  "Le reti scoperte diventano destinazioni del test di segmentazione.": {
    "file": "7cbaabcc2dca.ogg",
    "ms": 4064
  },
  "Da questa zona, quelle che devono restare isolate non devono rispondere.": {
    "file": "cfed2a10ec00.ogg",
    "ms": 4096
  },
  "Se una zona isolata risponde, è già un risultato: le regole del firewall vanno riviste.": {
    "file": "0ed67e50dde9.ogg",
    "ms": 5333
  },
  "La forza del segnale Wi-Fi si misura in decibel milliwatt, con numeri negativi.": {
    "file": "62bb417ae7f7.ogg",
    "ms": 4608
  },
  "Più il numero è vicino a zero, più il segnale è forte: meno 50 è ottimo, meno 80 è molto debole.": {
    "file": "964ba640170e.ogg",
    "ms": 6336
  },
  "Ogni 3 decibel in meno la potenza si dimezza.": {
    "file": "4b64e33fda4a.ogg",
    "ms": 2965
  },
  "Il Wi-Fi usa soprattutto due bande: 2,4 e 5 gigahertz.": {
    "file": "7291e391ddf0.ogg",
    "ms": 4404
  },
  "La banda a 2,4 gigahertz arriva più lontano, ma ha pochi canali ed è affollata.": {
    "file": "6614ef1863b6.ogg",
    "ms": 5227
  },
  "La banda a 5 gigahertz è più veloce e ha molti più canali, ma attraversa peggio i muri.": {
    "file": "2f18e2ac99ba.ogg",
    "ms": 5077
  },
  "A 2,4 gigahertz ogni canale è largo circa 20 megahertz, ma i canali distano solo 5 megahertz.": {
    "file": "428aa5098d8e.ogg",
    "ms": 6754
  },
  "Per questo solo i canali 1, 6 e 11 non si sovrappongono.": {
    "file": "593dcb430881.ogg",
    "ms": 3627
  },
  "Due reti su canali vicini, come il 3 e il 6, si disturbano più di due reti sullo stesso canale.": {
    "file": "16fd046fef23.ogg",
    "ms": 5568
  },
  "Con più access point è il dispositivo a decidere quando cambiare, di solito quando il segnale cala.": {
    "file": "9968b8ac6ed5.ogg",
    "ms": 5397
  },
  "Tre funzioni lo aiutano: l'elenco degli access point vicini, l'invito a spostarsi e le chiavi preparate in anticipo.": {
    "file": "0b039eb21e35.ogg",
    "ms": 6784
  },
  "Un dispositivo che resta attaccato all'access point lontano va piano e rallenta anche gli altri.": {
    "file": "84b255b950fa.ogg",
    "ms": 5162
  },
  "Nella sezione Wi-Fi, Polaris misura il segnale stanza per stanza con questo PC.": {
    "file": "ad9b394bc0c3.ogg",
    "ms": 4769
  },
  "Le stanze più deboli vanno in cima all'elenco: si parte da lì per spostare il router o aggiungere un access point.": {
    "file": "470473a7510d.ogg",
    "ms": 6464
  },
  "I valori valgono per questo PC: un telefono nello stesso punto può ricevere in modo diverso.": {
    "file": "081473eec0e2.ogg",
    "ms": 5781
  },
  "Ogni dispositivo in rete ha un indirizzo IP: quattro numeri da 0 a 255, separati da punti.": {
    "file": "c29fab4c2b10.ogg",
    "ms": 6848
  },
  "Un esempio è 192.168.1.20, l'indirizzo che vedi nel disegno.": {
    "file": "d1f616fecda2.ogg",
    "ms": 6671
  },
  "Una parte dell'indirizzo indica la rete, il resto indica il dispositivo.": {
    "file": "7a8ad18686c7.ogg",
    "ms": 4179
  },
  "Quanto è lunga la parte di rete lo dice la maschera di sottorete.": {
    "file": "5395f1c2c03a.ogg",
    "ms": 3776
  },
  "Si scrive anche in breve con il numero di bit: barra 24 vuol dire 24 bit di rete.": {
    "file": "e240d0b63c1c.ogg",
    "ms": 5717
  },
  "Due dispositivi si parlano direttamente solo se stanno nella stessa sottorete.": {
    "file": "563be7bcfd75.ogg",
    "ms": 4541
  },
  "Per uscire dalla propria rete serve il gateway, cioè il router.": {
    "file": "1fd44a52fe2e.ogg",
    "ms": 3347
  },
  "Il PC gli consegna tutto ciò che è diretto altrove, Internet compresa.": {
    "file": "fa0acf103024.ogg",
    "ms": 3837
  },
  "Con un gateway sbagliato il PC parla con i vicini, ma non esce dalla rete.": {
    "file": "f95e9663e4fe.ogg",
    "ms": 4224
  },
  "Indirizzo, maschera, gateway e server dei nomi li assegna il DHCP, un servizio che di solito sta nel router.": {
    "file": "9d6ee6bf1964.ogg",
    "ms": 6443
  },
  "Il PC chiede in broadcast, cioè a tutti, se c'è un server.": {
    "file": "5424a2636bb7.ogg",
    "ms": 3179
  },
  "Il server offre un indirizzo, il PC lo richiede e il server conferma.": {
    "file": "204a4a8679ac.ogg",
    "ms": 4075
  },
  "L'indirizzo è un prestito a tempo: a metà del tempo il PC chiede di rinnovarlo.": {
    "file": "1a4a367b301f.ogg",
    "ms": 4641
  },
  "Se nessun server risponde, Windows si assegna da solo un indirizzo che inizia con 169.254.": {
    "file": "7676b0a2bcea.ogg",
    "ms": 7944
  },
  "È il segnale tipico di un problema di DHCP: il cavo, la porta dello switch o il server fermo.": {
    "file": "8dd1782392fa.ogg",
    "ms": 5739
  },
  "In una rete piatta ogni dispositivo può parlare con tutti gli altri.": {
    "file": "7c44ce369b75.ogg",
    "ms": 3854
  },
  "Se uno viene infettato, un ransomware, cioè un programma che cifra i file per chiedere un riscatto, raggiunge tutto ciò che vede.": {
    "file": "df6bf2576245.ogg",
    "ms": 7232
  },
  "Dividere la rete in zone limita i danni.": {
    "file": "20dbb98093ae.ogg",
    "ms": 2475
  },
  "Ogni zona è una VLAN, cioè una rete virtuale, con la sua sottorete.": {
    "file": "69fbfa3e4dfb.ogg",
    "ms": 3819
  },
  "Sullo stesso switch convivono postazioni, dispositivi medicali e ospiti, ma separati.": {
    "file": "a80eddb09936.ogg",
    "ms": 5141
  },
  "Un collegamento trunk porta tutte le VLAN fino al firewall.": {
    "file": "46498e6ce1f2.ogg",
    "ms": 3471
  },
  "Tra una zona e l'altra decide il firewall, con regole scritte.": {
    "file": "4d69343e4a18.ogg",
    "ms": 3563
  },
  "Passa solo ciò che serve, per esempio dagli uffici ai server.": {
    "file": "49334f17cac0.ogg",
    "ms": 3392
  },
  "Tutto ciò che non è scritto è vietato, come dagli ospiti ai dispositivi medicali.": {
    "file": "fb687d728eed.ogg",
    "ms": 4437
  },
  "Molti dispositivi medicali hanno sistemi datati, che non si aggiornano senza il produttore.": {
    "file": "4ad3beb9647f.ogg",
    "ms": 5461
  },
  "Alcuni sono fragili e si bloccano con un traffico inatteso.": {
    "file": "0dce60717f57.ogg",
    "ms": 3605
  },
  "Per questo stanno in zone dedicate e parlano solo con i server che servono, come l'archivio delle immagini.": {
    "file": "7543559c8db6.ogg",
    "ms": 5909
  },
  "Una segmentazione mai provata è solo un'ipotesi.": {
    "file": "9f428e69b282.ogg",
    "ms": 2965
  },
  "Da ogni zona, Polaris prova a raggiungere le destinazioni che devono restare isolate.": {
    "file": "17042616d577.ogg",
    "ms": 4942
  },
  "Sulla mappa, un segnale di stop indica un percorso bloccato come previsto.": {
    "file": "624483e845cd.ogg",
    "ms": 4224
  },
  "Un percorso in rosso passa dove non dovrebbe: le regole vanno riviste.": {
    "file": "acd47cbd0a1e.ogg",
    "ms": 4011
  },
  "Una memoria RAM difettosa provoca schermate blu, programmi che si chiudono e file danneggiati.": {
    "file": "e751713755ee.ogg",
    "ms": 5291
  },
  "Spesso il guasto compare solo ogni tanto: per trovarlo serve un test lungo.": {
    "file": "9abd37de33be.ogg",
    "ms": 4459
  },
  "Polaris prova la memoria libera senza riavviare il computer.": {
    "file": "5b8fdca0ca2d.ogg",
    "ms": 3371
  },
  "Lascia una riserva a Windows e blocca il resto, perché nessun altro programma lo usi.": {
    "file": "910057a0a7b3.ogg",
    "ms": 4587
  },
  "Poi scrive schemi di bit e li rilegge: un bit che torna diverso è un errore.": {
    "file": "7d803cade3a2.ogg",
    "ms": 4288
  },
  "La memoria usata da Windows e dai programmi aperti non si può provare da Windows.": {
    "file": "389846818f16.ogg",
    "ms": 4501
  },
  "Anche un solo errore è un problema serio.": {
    "file": "b5021b6cb041.ogg",
    "ms": 2581
  },
  "Un test senza errori, invece, vale solo per la memoria provata.": {
    "file": "b33dfeedad9a.ogg",
    "ms": 3732
  },
  "Per provare tutta la memoria serve Memtest86+, che parte da una chiavetta prima di Windows.": {
    "file": "9b3d2c5108f4.ogg",
    "ms": 5824
  },
  "Polaris scarica il file dal sito ufficiale e ne controlla l'impronta.": {
    "file": "b41155ce3345.ogg",
    "ms": 3904
  },
  "Con Rufus si scrive il file sulla chiavetta in modalità immagine DD: il contenuto della chiavetta si cancella.": {
    "file": "efc580b1173a.ogg",
    "ms": 6635
  },
  "Si riavvia il PC dalla chiavetta con il menu di avvio: di solito un tasto come F12 o Esc all'accensione.": {
    "file": "d66d9380e38c.ogg",
    "ms": 6613
  },
  "Se l'avvio protetto la rifiuta, si disattiva solo per il test e poi si riattiva.": {
    "file": "6585023f9640.ogg",
    "ms": 4501
  },
  "Con BitLocker attivo, tieni pronta la chiave di ripristino.": {
    "file": "8dad95c2037a.ogg",
    "ms": 3285
  },
  "Memtest86+ lavora fuori da Windows: lascialo almeno un passaggio completo, meglio tutta la notte.": {
    "file": "693b34c1b57e.ogg",
    "ms": 6187
  },
  "Una porta USB 3, spesso blu o con il simbolo SS, contiene in realtà due porte.": {
    "file": "1bb960b67321.ogg",
    "ms": 5120
  },
  "Una è la parte SuperSpeed, l'altra è una porta USB 2, detta compagna.": {
    "file": "781abe109dd9.ogg",
    "ms": 4373
  },
  "Un disco USB 3 sulla parte SuperSpeed lavora a 5 gigabit al secondo.": {
    "file": "68f29ed7ec9e.ogg",
    "ms": 4843
  },
  "Se il disco passa da un cavo USB 2, da una prolunga o da un hub USB 2, usa la porta compagna.": {
    "file": "65a768148a8e.ogg",
    "ms": 5909
  },
  "Funziona, ma a 480 megabit al secondo: in pratica circa 40 megabyte al secondo.": {
    "file": "c05e44e3bcd7.ogg",
    "ms": 6298
  },
  "Copiare 100 gigabyte richiede così più di 40 minuti.": {
    "file": "9594f84c4a07.ogg",
    "ms": 3627
  },
  "Collega il disco direttamente a una porta USB 3 del PC, con il suo cavo originale.": {
    "file": "719bf197fedc.ogg",
    "ms": 5248
  },
  "Evita prolunghe e hub vecchi: se serve un hub, che sia USB 3 e con l'alimentatore.": {
    "file": "4219cb63bd44.ogg",
    "ms": 4905
  },
  "Poi ripeti l'analisi per controllare la velocità.": {
    "file": "c96f4e69a5bc.ogg",
    "ms": 2880
  },
  "Nella sezione del computer, l'albero USB mostra ogni dispositivo con la velocità a cui sta lavorando davvero.": {
    "file": "054ec05e9ec4.ogg",
    "ms": 6613
  },
  "Se un dispositivo USB 3 lavora come USB 2, Polaris lo segnala con la causa più probabile.": {
    "file": "620bd51c5d58.ogg",
    "ms": 5824
  },
  "Le porte compagne le descrive il firmware del PC, e non sempre bene: è un indizio da verificare.": {
    "file": "9e2f9eb8de44.ogg",
    "ms": 5696
  },
  "La latenza è il tempo che un pacchetto impiega ad andare e tornare, in millisecondi.": {
    "file": "88c956c448b2.ogg",
    "ms": 4524
  },
  "Le perdite sono i pacchetti che non arrivano: anche pochi rovinano chiamate e videochiamate.": {
    "file": "1f6fae40a25a.ogg",
    "ms": 5259
  },
  "Il traffico di questo PC passa dallo switch e dal router prima di arrivare a Internet.": {
    "file": "c19df4bd4b78.ogg",
    "ms": 5067
  },
  "Polaris misura nello stesso momento verso il router e verso Internet.": {
    "file": "cd1511948530.ogg",
    "ms": 3883
  },
  "Se la latenza sale anche verso il router, il problema è in casa o in ufficio: Wi-Fi, cavo o apparati.": {
    "file": "28dc06ff55b0.ogg",
    "ms": 6123
  },
  "Se sale solo verso Internet, il problema è sulla linea o presso l'operatore.": {
    "file": "450b8b813ff4.ogg",
    "ms": 4386
  },
  "Il traceroute mostra i router attraversati per arrivare a una destinazione.": {
    "file": "1b336a071f86.ogg",
    "ms": 4288
  },
  "Manda pacchetti con un contatore chiamato tempo di vita, che ogni router diminuisce di uno.": {
    "file": "c89a4bec923d.ogg",
    "ms": 5163
  },
  "Quando arriva a zero, il router scarta il pacchetto e risponde: così si scopre chi è.": {
    "file": "8cb871f2a017.ogg",
    "ms": 4629
  },
  "I tempi crescono con la distanza, ed è normale.": {
    "file": "58dbf02fb50e.ogg",
    "ms": 2880
  },
  "Conta un salto brusco che resta alto anche nei router successivi.": {
    "file": "8d70b5fa889e.ogg",
    "ms": 3755
  },
  "Un router che non risponde, segnato con un asterisco, non è un guasto se quelli dopo rispondono.": {
    "file": "fb85824b1c33.ogg",
    "ms": 5224
  },
  "Se il problema nasce già verso il router, si cerca in casa: Wi-Fi, cavi e router.": {
    "file": "7640df061e77.ogg",
    "ms": 4800
  },
  "Se nasce più avanti, conviene portare all'operatore il rapporto di Polaris con le misure.": {
    "file": "a37ea9a2cb6d.ogg",
    "ms": 4907
  }
};
