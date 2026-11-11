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
  /** Con il testo della frase dà il nome di ogni file: le prime 12 cifre di sha1(chiave|testo). */
  chiave: string;
  /** Per una voce clonata da un campione: SHA-256 del file del campione usato per registrare. */
  campione?: string;
}

export const VOCE: VoceRegistrata | undefined = {
  "nome": "Giulia",
  "motore": "Qwen3-TTS",
  "modello": "Qwen3-TTS-12Hz-0.6B-Base, voce di riferimento giulia.flac",
  "licenza": "Qwen3-TTS di Alibaba Cloud, licenza Apache-2.0",
  "chiave": "qwen|Qwen3-TTS-12Hz-0.6B-Base||giulia.flac",
  "campione": "e39967f8e11a12067217a6e19ec3e9b1667abf5706de63623c85a17a04ee1d74"
};

/** Per ogni frase registrata: il file e la durata in millisecondi. */
export const CLIP: Record<string, { file: string; ms: number }> = {
  "La mappa della rete disegna ciò che Polaris ha trovato intorno a questo PC.": {
    "file": "c7219b672d8b.ogg",
    "ms": 4003
  },
  "In alto c'è Internet, poi la rete dell'operatore e il router.": {
    "file": "f1cf6d3fe7c1.ogg",
    "ms": 3578
  },
  "Davanti al router ci sono le zone della rete, con i dispositivi disegnati secondo il loro tipo.": {
    "file": "5fd2317d36bf.ogg",
    "ms": 5608
  },
  "Polaris non entra nei dispositivi: ascolta quello che dicono di sé.": {
    "file": "187251f46426.ogg",
    "ms": 4122
  },
  "Una stampante annuncia il servizio di stampa, una TV il servizio per trasmettere i video.": {
    "file": "e5ba1edba079.ogg",
    "ms": 4767
  },
  "Contano anche il produttore della scheda di rete, il nome e il ruolo nella rete.": {
    "file": "5a6c9d2bf4fa.ogg",
    "ms": 4840
  },
  "Tocca un dispositivo per leggere perché è stato riconosciuto così.": {
    "file": "c764aa38fe28.ogg",
    "ms": 3271
  },
  "Ogni riconoscimento ha una confidenza: alta, media o bassa.": {
    "file": "e399dac44a46.ogg",
    "ms": 4363
  },
  "Il punto interrogativo segna un'ipotesi con pochi indizi, da verificare di persona.": {
    "file": "7d6c77f463c7.ogg",
    "ms": 4560
  },
  "L'ellisse tratteggiata a terra, sotto il disegno, indica un dispositivo dedotto, che non ha risposto direttamente.": {
    "file": "53cf0182f014.ogg",
    "ms": 6734
  },
  "Le piattaforme sono le zone: la rete di questo PC, le altre sottoreti e le reti Wi-Fi separate.": {
    "file": "921595aa8326.ogg",
    "ms": 6198
  },
  "In una struttura sanitaria ogni zona è di solito una rete virtuale, chiamata VLAN.": {
    "file": "32696086c03d.ogg",
    "ms": 5008
  },
  "Le zone sono collegate al firewall, che decide quale traffico può passare.": {
    "file": "0f0b382f0bc7.ogg",
    "ms": 4698
  },
  "I pacchetti che scorrono, con l'etichetta del protocollo, mostrano il percorso del traffico di questo PC: una corsia per l'andata e una per il ritorno.": {
    "file": "eef1f55cdf06.ogg",
    "ms": 8141
  },
  "Scegli un percorso sotto la mappa: verso Internet, verso il server dei nomi o verso un servizio.": {
    "file": "6bad8ac290e5.ogg",
    "ms": 6418
  },
  "Un segnale di stop indica un collegamento bloccato come previsto.": {
    "file": "0bb7b68f22fa.ogg",
    "ms": 3729
  },
  "In rosso c'è un collegamento che passa anche se dovrebbe essere bloccato.": {
    "file": "bea8705ecdf4.ogg",
    "ms": 3760
  },
  "Polaris vede il traffico di questo PC, non quello degli altri dispositivi.": {
    "file": "04e32294a0c7.ogg",
    "ms": 4224
  },
  "Senza l'inventario compaiono solo i dispositivi che il PC ha contattato di recente.": {
    "file": "8f35b0d32eb0.ogg",
    "ms": 5054
  },
  "L'inventario parte solo su richiesta, con un ritmo prudente e senza provare le porte dei dispositivi.": {
    "file": "47908ad89ff6.ogg",
    "ms": 5734
  },
  "All'avvio Polaris analizza il computer e la rete a cui è collegato.": {
    "file": "d8df02bf9fef.ogg",
    "ms": 3741
  },
  "Dura circa mezzo minuto e non cambia nessuna impostazione.": {
    "file": "e28f19d796c7.ogg",
    "ms": 3645
  },
  "Qui vedi la rete di una casa, come la disegna Polaris con i dati dimostrativi.": {
    "file": "a3ea6f988088.ogg",
    "ms": 4425
  },
  "Le misure seguono i livelli della rete, dal basso verso l'alto.": {
    "file": "ef3759a7349c.ogg",
    "ms": 3512
  },
  "Prima la scheda di rete e il Wi-Fi, poi l'indirizzo e il router, infine Internet, i nomi e i siti.": {
    "file": "72de4f8afda8.ogg",
    "ms": 5780
  },
  "Se un livello non funziona, anche quelli sopra sembrano guasti: per questo si parte dal basso.": {
    "file": "651a2c6b20a3.ogg",
    "ms": 5491
  },
  "Il punteggio va da 0 a 100 e riassume la salute del computer e della rete.": {
    "file": "46c54630c8dd.ogg",
    "ms": 4630
  },
  "Verde vuol dire buono, giallo da sistemare, rosso da sistemare per primo.": {
    "file": "5527b697adc3.ogg",
    "ms": 4788
  },
  "Con un problema critico il punteggio resta sotto 70, anche se tutto il resto va bene.": {
    "file": "172ad0f89b66.ogg",
    "ms": 4907
  },
  "Ogni area ha la sua sezione: computer, Wi-Fi, rete locale, Internet, router e infrastruttura.": {
    "file": "2d9ef001e5cf.ogg",
    "ms": 7451
  },
  "Un clic su un giudizio apre la scheda che spiega il valore, le soglie e che cosa fare.": {
    "file": "2582c9202183.ogg",
    "ms": 4634
  },
  "Nella sezione della rete locale c'è la mappa, con i dispositivi e i percorsi del traffico.": {
    "file": "51a2a8b1cb5c.ogg",
    "ms": 4960
  },
  "Il piano d'azione mette in ordine le cose da fare, a partire dalla più urgente.": {
    "file": "e581cafcad16.ogg",
    "ms": 4249
  },
  "Per esempio, con il Wi-Fi disturbato dai vicini propone di cambiare canale, passo dopo passo.": {
    "file": "2f1fbc3ab0f9.ogg",
    "ms": 4972
  },
  "Ogni passo ha la sua spunta, così tieni il conto di ciò che hai già fatto.": {
    "file": "0ac43bfd4b17.ogg",
    "ms": 4298
  },
  "Il pulsante Documento prepara una pagina sullo stato del PC e sul lavoro da fare.": {
    "file": "c78cf6560701.ogg",
    "ms": 5024
  },
  "Si stampa o si salva in un file PDF, da consegnare a chi usa il computer.": {
    "file": "452821e5afa0.ogg",
    "ms": 4917
  },
  "E se la stampante non stampa, c'è una guida anche per questo.": {
    "file": "758ee9e1a56d.ogg",
    "ms": 3418
  },
  "Dopo gli interventi, una nuova analisi conferma il risultato.": {
    "file": "ede509476bf1.ogg",
    "ms": 3644
  },
  "In una clinica la rete è divisa in zone, ognuna in una VLAN, cioè una rete virtuale separata.": {
    "file": "6f9120320c00.ogg",
    "ms": 5598
  },
  "Un PC collegato a una porta dello switch vede solo la sua VLAN, ed è giusto così.": {
    "file": "b5db90310a3b.ogg",
    "ms": 5437
  },
  "Può però scoprire che le altre reti esistono, senza entrarci.": {
    "file": "efcaaf428f2b.ogg",
    "ms": 3397
  },
  "Gli switch annunciano periodicamente chi sono, porta per porta.": {
    "file": "a8235a8483a9.ogg",
    "ms": 3970
  },
  "Con LLDP e CDP, i protocolli di annuncio, dicono il nome dello switch, la porta e le VLAN dei dati e della voce.": {
    "file": "1f2088cd37a1.ogg",
    "ms": 7827
  },
  "Polaris li ascolta per circa un minuto e non trasmette nulla.": {
    "file": "33ee190d7866.ogg",
    "ms": 3776
  },
  "Se arriva un annuncio DTP, la porta potrebbe diventare un trunk, cioè portare tutte le VLAN: va corretta sullo switch.": {
    "file": "59690fd603b9.ogg",
    "ms": 7898
  },
  "Anche il PC sa già qualcosa delle altre reti.": {
    "file": "6f6e521e9d4b.ogg",
    "ms": 2778
  },
  "La tabella di instradamento può contenere le rotte verso altre reti interne.": {
    "file": "c64897e6680a.ogg",
    "ms": 3868
  },
  "Un server che assegna gli indirizzi o risolve i nomi, se sta in un'altra rete, rivela la rete dei server.": {
    "file": "2b17f233f9c1.ogg",
    "ms": 5746
  },
  "Le reti Wi-Fi trasmesse dagli stessi access point di solito sono VLAN separate.": {
    "file": "56197ee09618.ogg",
    "ms": 4457
  },
  "Con le credenziali del tecnico, Polaris interroga il router in sola lettura con SNMP, il protocollo di gestione degli apparati.": {
    "file": "4fcf692aa292.ogg",
    "ms": 8420
  },
  "Il router risponde con l'elenco delle VLAN, il gateway di ogni rete e i dispositivi che ha visto.": {
    "file": "5c41237168b6.ogg",
    "ms": 5734
  },
  "Le credenziali non vengono salvate, e la versione 3 di SNMP, che cifra, è da preferire.": {
    "file": "505ddf6393d8.ogg",
    "ms": 6789
  },
  "Polaris non scansiona interi intervalli di indirizzi e non prova a saltare da una VLAN all'altra.": {
    "file": "78eac9474d83.ogg",
    "ms": 5458
  },
  "L'inventario di una rete parte solo su richiesta, una sottorete alla volta.": {
    "file": "0ce1fbf21f3c.ogg",
    "ms": 4147
  },
  "Sono tecniche da test di intrusione, che si usano solo con un incarico scritto.": {
    "file": "7d242d0aa3c2.ogg",
    "ms": 4965
  },
  "Qui gli ospiti raggiungono Internet, ma non la VLAN dei dispositivi medicali.": {
    "file": "0beed44e9d07.ogg",
    "ms": 4322
  },
  "Le reti scoperte diventano destinazioni del test di segmentazione.": {
    "file": "be6358f055a2.ogg",
    "ms": 3853
  },
  "Da questa zona, quelle che devono restare isolate non devono rispondere.": {
    "file": "e9b2b96ef73c.ogg",
    "ms": 4625
  },
  "Se una zona isolata risponde, è già un risultato: le regole del firewall vanno riviste.": {
    "file": "873d231917d1.ogg",
    "ms": 5271
  },
  "La forza del segnale Wi-Fi si misura in decibel milliwatt, con numeri negativi.": {
    "file": "b539cc73bdb7.ogg",
    "ms": 4456
  },
  "Più il numero è vicino a zero, più il segnale è forte: meno 50 è ottimo, meno 80 è molto debole.": {
    "file": "a72fb67426d9.ogg",
    "ms": 8404
  },
  "Ogni 3 decibel in meno la potenza si dimezza.": {
    "file": "a78ff8c0c6ee.ogg",
    "ms": 2752
  },
  "Il Wi-Fi usa soprattutto due bande: 2,4 e 5 gigahertz.": {
    "file": "abd7324acf49.ogg",
    "ms": 4687
  },
  "La banda a 2,4 gigahertz arriva più lontano, ma ha pochi canali ed è affollata.": {
    "file": "4a340c2aa8a2.ogg",
    "ms": 5571
  },
  "La banda a 5 gigahertz è più veloce e ha molti più canali, ma attraversa peggio i muri.": {
    "file": "2cf8e6bb3047.ogg",
    "ms": 5468
  },
  "A 2,4 gigahertz ogni canale è largo circa 20 megahertz, ma i canali distano solo 5 megahertz.": {
    "file": "08ffcf6ddae4.ogg",
    "ms": 7613
  },
  "Per questo solo i canali 1, 6 e 11 non si sovrappongono.": {
    "file": "dd6c97818b05.ogg",
    "ms": 4396
  },
  "Due reti su canali vicini, come il 3 e il 6, si disturbano più di due reti sullo stesso canale.": {
    "file": "e17091e52d28.ogg",
    "ms": 5795
  },
  "Con più access point è il dispositivo a decidere quando cambiare, di solito quando il segnale cala.": {
    "file": "c2c2726e608c.ogg",
    "ms": 5379
  },
  "Tre funzioni lo aiutano: l'elenco degli access point vicini, l'invito a spostarsi e le chiavi preparate in anticipo.": {
    "file": "2475a1ea460d.ogg",
    "ms": 7038
  },
  "Un dispositivo che resta attaccato all'access point lontano va piano e rallenta anche gli altri.": {
    "file": "df0830eae443.ogg",
    "ms": 5689
  },
  "Nella sezione Wi-Fi, Polaris misura il segnale stanza per stanza con questo PC.": {
    "file": "eb5ebcf83200.ogg",
    "ms": 5244
  },
  "Le stanze più deboli vanno in cima all'elenco: si parte da lì per spostare il router o aggiungere un access point.": {
    "file": "3e8d19fc947b.ogg",
    "ms": 6598
  },
  "I valori valgono per questo PC: un telefono nello stesso punto può ricevere in modo diverso.": {
    "file": "13881a87b06d.ogg",
    "ms": 6067
  },
  "Ogni dispositivo in rete ha un indirizzo IP: quattro numeri da 0 a 255, separati da punti.": {
    "file": "ce02dbfc17d3.ogg",
    "ms": 7011
  },
  "Un esempio è 192.168.1.20, l'indirizzo che vedi nel disegno.": {
    "file": "4f8a9fcf1103.ogg",
    "ms": 6660
  },
  "Una parte dell'indirizzo indica la rete, il resto indica il dispositivo.": {
    "file": "616c69eb0ac8.ogg",
    "ms": 4145
  },
  "Quanto è lunga la parte di rete lo dice la maschera di sottorete.": {
    "file": "ebc414cbed49.ogg",
    "ms": 3405
  },
  "Si scrive anche in breve con il numero di bit: barra 24 vuol dire 24 bit di rete.": {
    "file": "c00ab15dacb1.ogg",
    "ms": 6161
  },
  "Due dispositivi si parlano direttamente solo se stanno nella stessa sottorete.": {
    "file": "4619c736b8c6.ogg",
    "ms": 4051
  },
  "Per uscire dalla propria rete serve il gateway, cioè il router.": {
    "file": "7427d0926274.ogg",
    "ms": 3346
  },
  "Il PC gli consegna tutto ciò che è diretto altrove, Internet compresa.": {
    "file": "865241a72f55.ogg",
    "ms": 4165
  },
  "Con un gateway sbagliato il PC parla con i vicini, ma non esce dalla rete.": {
    "file": "13a075b95119.ogg",
    "ms": 3967
  },
  "Indirizzo, maschera, gateway e server dei nomi li assegna il DHCP, un servizio che di solito sta nel router.": {
    "file": "0959a6aec998.ogg",
    "ms": 7266
  },
  "Il PC chiede in broadcast, cioè a tutti, se c'è un server.": {
    "file": "9ce7a5f6fd14.ogg",
    "ms": 3921
  },
  "Il server offre un indirizzo, il PC lo richiede e il server conferma.": {
    "file": "f81b0baec4a8.ogg",
    "ms": 4643
  },
  "L'indirizzo è un prestito a tempo: a metà del tempo il PC chiede di rinnovarlo.": {
    "file": "0028d55927f4.ogg",
    "ms": 4895
  },
  "Se nessun server risponde, Windows si assegna da solo un indirizzo che inizia con 169.254.": {
    "file": "2aa5d8bef862.ogg",
    "ms": 7900
  },
  "È il segnale tipico di un problema di DHCP: il cavo, la porta dello switch o il server fermo.": {
    "file": "3b5b9d6ae810.ogg",
    "ms": 5987
  },
  "In una rete piatta ogni dispositivo può parlare con tutti gli altri.": {
    "file": "0cbef37b61a5.ogg",
    "ms": 3816
  },
  "Se uno viene infettato, un ransomware, cioè un programma che cifra i file per chiedere un riscatto, raggiunge tutto ciò che vede.": {
    "file": "a5e51f6c0eba.ogg",
    "ms": 7306
  },
  "Dividere la rete in zone limita i danni.": {
    "file": "0b2b722f17cd.ogg",
    "ms": 2419
  },
  "Ogni zona è una VLAN, cioè una rete virtuale, con la sua sottorete.": {
    "file": "042c06e381cb.ogg",
    "ms": 4586
  },
  "Sullo stesso switch convivono postazioni, dispositivi medicali e ospiti, ma separati.": {
    "file": "6d8638b58ed1.ogg",
    "ms": 5529
  },
  "Un collegamento trunk porta tutte le VLAN fino al firewall.": {
    "file": "498beb8806e2.ogg",
    "ms": 3467
  },
  "Tra una zona e l'altra decide il firewall, con regole scritte.": {
    "file": "fc472e009138.ogg",
    "ms": 3574
  },
  "Passa solo ciò che serve, per esempio dagli uffici ai server.": {
    "file": "95265b8025d4.ogg",
    "ms": 4000
  },
  "Tutto ciò che non è scritto è vietato, come dagli ospiti ai dispositivi medicali.": {
    "file": "0e4829fc7e69.ogg",
    "ms": 4467
  },
  "Molti dispositivi medicali hanno sistemi datati, che non si aggiornano senza il produttore.": {
    "file": "ddb572c3c2c4.ogg",
    "ms": 5113
  },
  "Alcuni sono fragili e si bloccano con un traffico inatteso.": {
    "file": "4cfd07d65d1c.ogg",
    "ms": 3321
  },
  "Per questo stanno in zone dedicate e parlano solo con i server che servono, come l'archivio delle immagini.": {
    "file": "c0b1770f2895.ogg",
    "ms": 6009
  },
  "Una segmentazione mai provata è solo un'ipotesi.": {
    "file": "40f2ea8f036f.ogg",
    "ms": 2769
  },
  "Da ogni zona, Polaris prova a raggiungere le destinazioni che devono restare isolate.": {
    "file": "1da9627113e7.ogg",
    "ms": 4859
  },
  "Sulla mappa, un segnale di stop indica un percorso bloccato come previsto.": {
    "file": "247b9c239ded.ogg",
    "ms": 4771
  },
  "Un percorso in rosso passa dove non dovrebbe: le regole vanno riviste.": {
    "file": "28e71f87624a.ogg",
    "ms": 4397
  },
  "Una memoria RAM difettosa provoca schermate blu, programmi che si chiudono e file danneggiati.": {
    "file": "81ca2661ac09.ogg",
    "ms": 5709
  },
  "Spesso il guasto compare solo ogni tanto: per trovarlo serve un test lungo.": {
    "file": "6e1ca6d139c2.ogg",
    "ms": 4655
  },
  "Polaris prova la memoria libera senza riavviare il computer.": {
    "file": "418f1795038c.ogg",
    "ms": 3190
  },
  "Lascia una riserva a Windows e blocca il resto, perché nessun altro programma lo usi.": {
    "file": "e6bc1b9fa9f7.ogg",
    "ms": 4960
  },
  "Poi scrive schemi di bit e li rilegge: un bit che torna diverso è un errore.": {
    "file": "93a944755f38.ogg",
    "ms": 4654
  },
  "La memoria usata da Windows e dai programmi aperti non si può provare da Windows.": {
    "file": "a31efafdec49.ogg",
    "ms": 4664
  },
  "Anche un solo errore è un problema serio.": {
    "file": "6876f766d3aa.ogg",
    "ms": 2488
  },
  "Un test senza errori, invece, vale solo per la memoria provata.": {
    "file": "1a05a07e9288.ogg",
    "ms": 3793
  },
  "Per provare tutta la memoria serve Memtest86+, che parte da una chiavetta prima di Windows.": {
    "file": "77388cc70654.ogg",
    "ms": 5648
  },
  "Polaris scarica il file dal sito ufficiale e ne controlla l'impronta.": {
    "file": "927fb167044b.ogg",
    "ms": 4116
  },
  "Con Rufus si scrive il file sulla chiavetta in modalità immagine DD: il contenuto della chiavetta si cancella.": {
    "file": "6376305556ad.ogg",
    "ms": 6621
  },
  "Si riavvia il PC dalla chiavetta con il menu di avvio: di solito un tasto come F12 o Esc all'accensione.": {
    "file": "b5fd568b5ac8.ogg",
    "ms": 7042
  },
  "Se l'avvio protetto la rifiuta, si disattiva solo per il test e poi si riattiva.": {
    "file": "fb1f1ad7ff1e.ogg",
    "ms": 4526
  },
  "Con BitLocker attivo, tieni pronta la chiave di ripristino.": {
    "file": "cb41e3eed591.ogg",
    "ms": 3474
  },
  "Memtest86+ lavora fuori da Windows: lascialo almeno un passaggio completo, meglio tutta la notte.": {
    "file": "60175dab1411.ogg",
    "ms": 6348
  },
  "Una porta USB 3, spesso blu o con il simbolo SS, contiene in realtà due porte.": {
    "file": "39efad0d19d7.ogg",
    "ms": 5986
  },
  "Una è la parte SuperSpeed, l'altra è una porta USB 2, detta compagna.": {
    "file": "a27901a0ea0e.ogg",
    "ms": 4954
  },
  "Un disco USB 3 sulla parte SuperSpeed lavora a 5 gigabit al secondo.": {
    "file": "c9fb22d44235.ogg",
    "ms": 4498
  },
  "Se il disco passa da un cavo USB 2, da una prolunga o da un hub USB 2, usa la porta compagna.": {
    "file": "49763d358655.ogg",
    "ms": 6982
  },
  "Funziona, ma a 480 megabit al secondo: in pratica circa 40 megabyte al secondo.": {
    "file": "9a014f8b175b.ogg",
    "ms": 6372
  },
  "Copiare 100 gigabyte richiede così più di 40 minuti.": {
    "file": "53e5e4986fb1.ogg",
    "ms": 3562
  },
  "Collega il disco direttamente a una porta USB 3 del PC, con il suo cavo originale.": {
    "file": "477d32342512.ogg",
    "ms": 5219
  },
  "Evita prolunghe e hub vecchi: se serve un hub, che sia USB 3 e con l'alimentatore.": {
    "file": "652f8da128bd.ogg",
    "ms": 6343
  },
  "Poi ripeti l'analisi per controllare la velocità.": {
    "file": "770a4a751fa9.ogg",
    "ms": 2637
  },
  "Nella sezione del computer, l'albero USB mostra ogni dispositivo con la velocità a cui sta lavorando davvero.": {
    "file": "bfdf120af7b7.ogg",
    "ms": 7048
  },
  "Se un dispositivo USB 3 lavora come USB 2, Polaris lo segnala con la causa più probabile.": {
    "file": "9d9782a24470.ogg",
    "ms": 6119
  },
  "Le porte compagne le descrive il firmware del PC, e non sempre bene: è un indizio da verificare.": {
    "file": "95d7507cb20f.ogg",
    "ms": 6012
  },
  "La latenza è il tempo che un pacchetto impiega ad andare e tornare, in millisecondi.": {
    "file": "d67f37dd0f21.ogg",
    "ms": 4828
  },
  "Le perdite sono i pacchetti che non arrivano: anche pochi rovinano chiamate e videochiamate.": {
    "file": "8cf5e58fbe8c.ogg",
    "ms": 5118
  },
  "Il traffico di questo PC passa dallo switch e dal router prima di arrivare a Internet.": {
    "file": "6b6e91d9a571.ogg",
    "ms": 4438
  },
  "Polaris misura nello stesso momento verso il router e verso Internet.": {
    "file": "623130c6dd4e.ogg",
    "ms": 3663
  },
  "Se la latenza sale anche verso il router, il problema è in casa o in ufficio: Wi-Fi, cavo o apparati.": {
    "file": "4e2aa31ede58.ogg",
    "ms": 6472
  },
  "Se sale solo verso Internet, il problema è sulla linea o presso l'operatore.": {
    "file": "789bf4e1c04b.ogg",
    "ms": 4531
  },
  "Il traceroute mostra i router attraversati per arrivare a una destinazione.": {
    "file": "30d88cabd042.ogg",
    "ms": 4079
  },
  "Manda pacchetti con un contatore chiamato tempo di vita, che ogni router diminuisce di uno.": {
    "file": "88e87a341a04.ogg",
    "ms": 5460
  },
  "Quando arriva a zero, il router scarta il pacchetto e risponde: così si scopre chi è.": {
    "file": "010dd01c948b.ogg",
    "ms": 5329
  },
  "I tempi crescono con la distanza, ed è normale.": {
    "file": "997ea342d544.ogg",
    "ms": 2980
  },
  "Conta un salto brusco che resta alto anche nei router successivi.": {
    "file": "a2a08aa75461.ogg",
    "ms": 3465
  },
  "Un router che non risponde, segnato con un asterisco, non è un guasto se quelli dopo rispondono.": {
    "file": "58c04de07ee5.ogg",
    "ms": 5299
  },
  "Se il problema nasce già verso il router, si cerca in casa: Wi-Fi, cavi e router.": {
    "file": "b8c95b9fa8ad.ogg",
    "ms": 5270
  },
  "Se nasce più avanti, conviene portare all'operatore il rapporto di Polaris con le misure.": {
    "file": "2aa7a70dacf8.ogg",
    "ms": 4635
  }
};
