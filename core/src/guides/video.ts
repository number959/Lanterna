import type { VideoGuide } from './types';

// Videoguide: scene animate con una narrazione in italiano, letta dalla voce
// italiana di Windows (Microsoft Elsa) direttamente sul PC, senza audio
// registrato e senza servizi esterni. Ogni frase è anche un sottotitolo:
// frasi brevi, una idea per frase, parole che si capiscono ascoltandole.
// Regole per la narrazione (controllate dai test):
// - da 2 a 4 frasi per scena, ognuna di al massimo 200 caratteri;
// - niente simboli da leggere ad alta voce (frecce, barre, percentuali,
//   parentesi, puntini) né nomi di menu tra virgolette;
// - numeri e unità scritti come si pronunciano: "2,4 gigahertz",
//   "480 megabit al secondo", "circa 40 megabyte al secondo";
// - ogni sigla spiegata la prima volta che compare nella videoguida.

export const VIDEOS: VideoGuide[] = [
  {
    id: 'mappa-della-rete',
    chapter: 'uso',
    title: 'La mappa della rete',
    summary: 'Come leggere la mappa: tipi di dispositivo, zone, percorsi del traffico e quanto fidarsi di ogni riconoscimento.',
    guide: 'mappa-della-rete',
    scenes: [
      {
        title: 'Che cosa mostra',
        map: 'casa',
        narration: [
          'La mappa della rete disegna ciò che Polaris ha trovato intorno a questo PC.',
          'In alto c\'è Internet, poi la rete dell\'operatore e il router.',
          'Sotto il router ci sono i dispositivi della rete, ognuno con l\'icona del suo tipo.',
        ],
      },
      {
        title: 'Come riconosce i dispositivi',
        map: 'casa',
        narration: [
          'Polaris non entra nei dispositivi: ascolta quello che dicono di sé.',
          'Una stampante annuncia il servizio di stampa, una TV il servizio per trasmettere i video.',
          'Contano anche il produttore della scheda di rete, il nome e il ruolo nella rete.',
          'Tocca un dispositivo per leggere perché è stato riconosciuto così.',
        ],
      },
      {
        title: 'Quanto fidarsi',
        map: 'clinica',
        narration: [
          'Ogni riconoscimento ha una confidenza: alta, media o bassa.',
          'Il punto interrogativo segna un\'ipotesi con pochi indizi, da verificare di persona.',
          'L\'ombra tratteggiata sotto il disegno indica un dispositivo dedotto, che non ha risposto direttamente.',
        ],
      },
      {
        title: 'Le zone',
        map: 'clinica',
        narration: [
          'I riquadri sono le zone: la rete di questo PC, le altre sottoreti e le reti Wi-Fi separate.',
          'In una struttura sanitaria ogni zona è di solito una rete virtuale, chiamata VLAN.',
          'Le zone sono collegate al firewall, che decide quale traffico può passare.',
        ],
      },
      {
        title: 'Da dove passa il traffico',
        map: 'clinica',
        narration: [
          'I pallini che scorrono mostrano il percorso del traffico di questo PC.',
          'Scegli un percorso sotto la mappa: verso Internet, verso il server dei nomi o verso un servizio.',
          'Un segnale di stop indica un collegamento bloccato come previsto.',
          'In rosso c\'è un collegamento che passa anche se dovrebbe essere bloccato.',
        ],
      },
      {
        title: 'Che cosa non vede',
        map: 'casa',
        narration: [
          'Polaris vede il traffico di questo PC, non quello degli altri dispositivi.',
          'Senza l\'inventario compaiono solo i dispositivi che il PC ha contattato di recente.',
          'L\'inventario parte solo su richiesta, con un ritmo prudente e senza provare le porte dei dispositivi.',
        ],
      },
    ],
  },
  {
    id: 'prima-analisi',
    chapter: 'uso',
    title: 'La prima analisi',
    summary: 'Che cosa fa Polaris all\'avvio, come leggere punteggio, colori e sezioni, come seguire il piano d\'azione e preparare il documento da stampare.',
    guide: 'primi-passi',
    scenes: [
      {
        title: 'L\'analisi parte da sola',
        map: 'casa',
        narration: [
          'All\'avvio Polaris analizza il computer e la rete a cui è collegato.',
          'Dura circa mezzo minuto e non cambia nessuna impostazione.',
          'Qui vedi la rete di una casa, come la disegna Polaris con i dati dimostrativi.',
        ],
      },
      {
        title: 'Dal cavo ai siti web',
        diagram: 'osi',
        narration: [
          'Le misure seguono i livelli della rete, dal basso verso l\'alto.',
          'Prima la scheda di rete e il Wi-Fi, poi l\'indirizzo e il router, infine Internet, i nomi e i siti.',
          'Se un livello non funziona, anche quelli sopra sembrano guasti: per questo si parte dal basso.',
        ],
      },
      {
        title: 'Il punteggio e i colori',
        map: 'clinica',
        narration: [
          'Il punteggio va da 0 a 100 e riassume la salute del computer e della rete.',
          'Verde vuol dire buono, giallo da sistemare, rosso da sistemare per primo.',
          'Con un problema critico il punteggio resta sotto 70, anche se tutto il resto va bene.',
        ],
      },
      {
        title: 'Le sezioni',
        diagram: 'netmap',
        narration: [
          'Ogni area ha la sua sezione: computer, Wi-Fi, rete locale, Internet, router e infrastruttura.',
          'Un clic su un giudizio apre la scheda che spiega il valore, le soglie e che cosa fare.',
          'Nella sezione della rete locale c\'è la mappa, con i dispositivi e i percorsi del traffico.',
        ],
      },
      {
        title: 'Il piano d\'azione',
        diagram: 'channels24',
        narration: [
          'Il piano d\'azione mette in ordine le cose da fare, a partire dalla più urgente.',
          'Per esempio, con il Wi-Fi disturbato dai vicini propone di cambiare canale, passo dopo passo.',
          'Ogni passo ha la sua spunta, così tieni il conto di ciò che hai già fatto.',
        ],
      },
      {
        title: 'Il documento da stampare',
        diagram: 'printpath',
        narration: [
          'Il pulsante Documento prepara una pagina sullo stato del PC e sul lavoro da fare.',
          'Si stampa o si salva in un file PDF, da consegnare a chi usa il computer.',
          'E se la stampante non stampa, c\'è una guida anche per questo.',
          'Dopo gli interventi, una nuova analisi conferma il risultato.',
        ],
      },
    ],
  },
  {
    id: 'scoprire-vlan',
    chapter: 'complesse',
    title: 'Scoprire le VLAN e le altre reti',
    summary: 'Come un PC collegato a una porta dello switch scopre le altre reti senza entrarci: annunci dello switch, ciò che il PC sa già, domande in sola lettura al router.',
    guide: 'scoprire-vlan',
    scenes: [
      {
        title: 'Reti separate',
        diagram: 'clinic',
        narration: [
          'In una clinica la rete è divisa in zone, ognuna in una VLAN, cioè una rete virtuale separata.',
          'Un PC collegato a una porta dello switch vede solo la sua VLAN, ed è giusto così.',
          'Può però scoprire che le altre reti esistono, senza entrarci.',
        ],
      },
      {
        title: 'Ascoltare lo switch',
        diagram: 'lldp',
        narration: [
          'Gli switch annunciano periodicamente chi sono, porta per porta.',
          'Con LLDP e CDP, i protocolli di annuncio, dicono il nome dello switch, la porta e le VLAN dei dati e della voce.',
          'Polaris li ascolta per circa un minuto e non trasmette nulla.',
          'Se arriva un annuncio DTP, la porta potrebbe diventare un trunk, cioè portare tutte le VLAN: va corretta sullo switch.',
        ],
      },
      {
        title: 'Ciò che il PC sa già',
        map: 'clinica',
        narration: [
          'Anche il PC sa già qualcosa delle altre reti.',
          'La tabella di instradamento può contenere le rotte verso altre reti interne.',
          'Un server che assegna gli indirizzi o risolve i nomi, se sta in un\'altra rete, rivela la rete dei server.',
          'Le reti Wi-Fi trasmesse dagli stessi access point di solito sono VLAN separate.',
        ],
      },
      {
        title: 'Domande al router',
        diagram: 'snmp',
        narration: [
          'Con le credenziali del tecnico, Polaris interroga il router in sola lettura con SNMP, il protocollo di gestione degli apparati.',
          'Il router risponde con l\'elenco delle VLAN, il gateway di ogni rete e i dispositivi che ha visto.',
          'Le credenziali non vengono salvate, e la versione 3 di SNMP, che cifra, è da preferire.',
        ],
      },
      {
        title: 'Che cosa non si fa',
        diagram: 'vlan',
        narration: [
          'Polaris non scansiona interi intervalli di indirizzi e non prova a saltare da una VLAN all\'altra.',
          'L\'inventario di una rete parte solo su richiesta, una sottorete alla volta.',
          'Sono tecniche da test di intrusione, che si usano solo con un incarico scritto.',
          'Qui gli ospiti raggiungono Internet, ma non la VLAN dei dispositivi medicali.',
        ],
      },
      {
        title: 'Verificare l\'isolamento',
        diagram: 'intervlan',
        narration: [
          'Le reti scoperte diventano destinazioni del test di segmentazione.',
          'Da questa zona, quelle che devono restare isolate non devono rispondere.',
          'Se una zona isolata risponde, è già un risultato: le regole del firewall vanno riviste.',
        ],
      },
    ],
  },
  {
    id: 'wifi-segnale-canali',
    chapter: 'wifi',
    title: 'Segnale, bande e canali del Wi-Fi',
    summary: 'Come leggere la forza del segnale, quando usare 2,4 o 5 gigahertz, perché i canali vicini si disturbano e come un dispositivo passa da un access point all\'altro.',
    guide: 'wifi-bande-canali',
    scenes: [
      {
        title: 'La forza del segnale',
        diagram: 'roaming',
        narration: [
          'La forza del segnale Wi-Fi si misura in decibel milliwatt, con numeri negativi.',
          'Più il numero è vicino a zero, più il segnale è forte: meno 50 è ottimo, meno 80 è molto debole.',
          'Ogni 3 decibel in meno la potenza si dimezza.',
        ],
      },
      {
        title: '2,4 o 5 gigahertz',
        diagram: 'channels24',
        narration: [
          'Il Wi-Fi usa soprattutto due bande: 2,4 e 5 gigahertz.',
          'La banda a 2,4 gigahertz arriva più lontano, ma ha pochi canali ed è affollata.',
          'La banda a 5 gigahertz è più veloce e ha molti più canali, ma attraversa peggio i muri.',
        ],
      },
      {
        title: 'Canali che si sovrappongono',
        diagram: 'channels24',
        narration: [
          'A 2,4 gigahertz ogni canale è largo circa 20 megahertz, ma i canali distano solo 5 megahertz.',
          'Per questo solo i canali 1, 6 e 11 non si sovrappongono.',
          'Due reti su canali vicini, come il 3 e il 6, si disturbano più di due reti sullo stesso canale.',
        ],
      },
      {
        title: 'Il roaming',
        diagram: 'roaming',
        narration: [
          'Con più access point è il dispositivo a decidere quando cambiare, di solito quando il segnale cala.',
          'Tre funzioni lo aiutano: l\'elenco degli access point vicini, l\'invito a spostarsi e le chiavi preparate in anticipo.',
          'Un dispositivo che resta attaccato all\'access point lontano va piano e rallenta anche gli altri.',
        ],
      },
      {
        title: 'Misurare stanza per stanza',
        map: 'casa',
        narration: [
          'Nella sezione Wi-Fi, Polaris misura il segnale stanza per stanza con questo PC.',
          'Le stanze più deboli vanno in cima all\'elenco: si parte da lì per spostare il router o aggiungere un access point.',
          'I valori valgono per questo PC: un telefono nello stesso punto può ricevere in modo diverso.',
        ],
      },
    ],
  },
  {
    id: 'indirizzi-dhcp',
    chapter: 'fondamenti',
    title: 'Indirizzi IP, maschera e DHCP',
    summary: 'Che cosa sono indirizzo IP, maschera di sottorete e gateway, e come il DHCP li assegna in quattro messaggi.',
    guide: 'indirizzi-ip-subnet',
    scenes: [
      {
        title: 'L\'indirizzo IP',
        diagram: 'subnet',
        narration: [
          'Ogni dispositivo in rete ha un indirizzo IP: quattro numeri da 0 a 255, separati da punti.',
          'Un esempio è 192.168.1.20, l\'indirizzo che vedi nel disegno.',
          'Una parte dell\'indirizzo indica la rete, il resto indica il dispositivo.',
        ],
      },
      {
        title: 'La maschera',
        diagram: 'subnet',
        narration: [
          'Quanto è lunga la parte di rete lo dice la maschera di sottorete.',
          'Si scrive anche in breve con il numero di bit: barra 24 vuol dire 24 bit di rete.',
          'Due dispositivi si parlano direttamente solo se stanno nella stessa sottorete.',
        ],
      },
      {
        title: 'Il gateway',
        diagram: 'netmap',
        narration: [
          'Per uscire dalla propria rete serve il gateway, cioè il router.',
          'Il PC gli consegna tutto ciò che è diretto altrove, Internet compresa.',
          'Con un gateway sbagliato il PC parla con i vicini, ma non esce dalla rete.',
        ],
      },
      {
        title: 'Il DHCP in quattro messaggi',
        diagram: 'dhcp',
        narration: [
          'Indirizzo, maschera, gateway e server dei nomi li assegna il DHCP, un servizio che di solito sta nel router.',
          'Il PC chiede in broadcast, cioè a tutti, se c\'è un server.',
          'Il server offre un indirizzo, il PC lo richiede e il server conferma.',
        ],
      },
      {
        title: 'Il prestito e i problemi',
        diagram: 'dhcp',
        narration: [
          'L\'indirizzo è un prestito a tempo: a metà del tempo il PC chiede di rinnovarlo.',
          'Se nessun server risponde, Windows si assegna da solo un indirizzo che inizia con 169.254.',
          'È il segnale tipico di un problema di DHCP: il cavo, la porta dello switch o il server fermo.',
        ],
      },
    ],
  },
  {
    id: 'segmentazione-sanita',
    chapter: 'complesse',
    title: 'Segmentare la rete di una struttura sanitaria',
    summary: 'Perché dividere la rete in zone, come le regole del firewall decidono chi parla con chi, perché i dispositivi medicali stanno isolati e come si verifica l\'isolamento.',
    guide: 'segmentazione',
    scenes: [
      {
        title: 'Il rischio della rete piatta',
        diagram: 'clinic',
        narration: [
          'In una rete piatta ogni dispositivo può parlare con tutti gli altri.',
          'Se uno viene infettato, un ransomware, cioè un programma che cifra i file per chiedere un riscatto, raggiunge tutto ciò che vede.',
          'Dividere la rete in zone limita i danni.',
        ],
      },
      {
        title: 'Zone e VLAN',
        diagram: 'vlan',
        narration: [
          'Ogni zona è una VLAN, cioè una rete virtuale, con la sua sottorete.',
          'Sullo stesso switch convivono postazioni, dispositivi medicali e ospiti, ma separati.',
          'Un collegamento trunk porta tutte le VLAN fino al firewall.',
        ],
      },
      {
        title: 'Le regole del firewall',
        diagram: 'intervlan',
        narration: [
          'Tra una zona e l\'altra decide il firewall, con regole scritte.',
          'Passa solo ciò che serve, per esempio dagli uffici ai server.',
          'Tutto ciò che non è scritto è vietato, come dagli ospiti ai dispositivi medicali.',
        ],
      },
      {
        title: 'Perché isolare i medicali',
        diagram: 'clinic',
        narration: [
          'Molti dispositivi medicali hanno sistemi datati, che non si aggiornano senza il produttore.',
          'Alcuni sono fragili e si bloccano con un traffico inatteso.',
          'Per questo stanno in zone dedicate e parlano solo con i server che servono, come l\'archivio delle immagini.',
        ],
      },
      {
        title: 'Provare l\'isolamento',
        map: 'clinica',
        narration: [
          'Una segmentazione mai provata è solo un\'ipotesi.',
          'Da ogni zona, Polaris prova a raggiungere le destinazioni che devono restare isolate.',
          'Sulla mappa, un segnale di stop indica un percorso bloccato come previsto.',
          'Un percorso in rosso passa dove non dovrebbe: le regole vanno riviste.',
        ],
      },
    ],
  },
  {
    id: 'ram-memtest',
    chapter: 'pc',
    title: 'Provare la memoria RAM',
    summary: 'Il test della memoria con Windows acceso, i suoi limiti e come provare tutta la RAM con Memtest86+ da una chiavetta preparata con Rufus.',
    guide: 'manutenzione-windows',
    scenes: [
      {
        title: 'Perché provare la RAM',
        diagram: 'ramtest',
        narration: [
          'Una memoria RAM difettosa provoca schermate blu, programmi che si chiudono e file danneggiati.',
          'Spesso il guasto compare solo ogni tanto: per trovarlo serve un test lungo.',
        ],
      },
      {
        title: 'Il test con Windows acceso',
        diagram: 'ramtest',
        narration: [
          'Polaris prova la memoria libera senza riavviare il computer.',
          'Lascia una riserva a Windows e blocca il resto, perché nessun altro programma lo usi.',
          'Poi scrive schemi di bit e li rilegge: un bit che torna diverso è un errore.',
        ],
      },
      {
        title: 'I limiti',
        diagram: 'ramtest',
        narration: [
          'La memoria usata da Windows e dai programmi aperti non si può provare da Windows.',
          'Anche un solo errore è un problema serio.',
          'Un test senza errori, invece, vale solo per la memoria provata.',
        ],
      },
      {
        title: 'Preparare la chiavetta',
        diagram: 'memtestusb',
        narration: [
          'Per provare tutta la memoria serve Memtest86+, che parte da una chiavetta prima di Windows.',
          'Polaris scarica il file dal sito ufficiale e ne controlla l\'impronta.',
          'Con Rufus si scrive il file sulla chiavetta in modalità immagine DD: il contenuto della chiavetta si cancella.',
        ],
      },
      {
        title: 'Avviare Memtest86+',
        diagram: 'memtestusb',
        narration: [
          'Si riavvia il PC dalla chiavetta con il menu di avvio: di solito un tasto come F12 o Esc all\'accensione.',
          'Se l\'avvio protetto la rifiuta, si disattiva solo per il test e poi si riattiva.',
          'Con BitLocker attivo, tieni pronta la chiave di ripristino.',
          'Memtest86+ lavora fuori da Windows: lascialo almeno un passaggio completo, meglio tutta la notte.',
        ],
      },
    ],
  },
  {
    id: 'usb-lento',
    chapter: 'pc',
    title: 'Perché il disco USB va piano',
    summary: 'Un disco USB 3 che lavora come un USB 2: perché succede, quanto costa in velocità e come rimediare.',
    guide: 'dispositivi-driver',
    scenes: [
      {
        title: 'Due porte in una',
        diagram: 'usbspeed',
        narration: [
          'Una porta USB 3, spesso blu o con il simbolo SS, contiene in realtà due porte.',
          'Una è la parte SuperSpeed, l\'altra è una porta USB 2, detta compagna.',
          'Un disco USB 3 sulla parte SuperSpeed lavora a 5 gigabit al secondo.',
        ],
      },
      {
        title: 'Quando va piano',
        diagram: 'usbspeed',
        narration: [
          'Se il disco passa da un cavo USB 2, da una prolunga o da un hub USB 2, usa la porta compagna.',
          'Funziona, ma a 480 megabit al secondo: in pratica circa 40 megabyte al secondo.',
          'Copiare 100 gigabyte richiede così più di 40 minuti.',
        ],
      },
      {
        title: 'Come rimediare',
        diagram: 'usbspeed',
        narration: [
          'Collega il disco direttamente a una porta USB 3 del PC, con il suo cavo originale.',
          'Evita prolunghe e hub vecchi: se serve un hub, che sia USB 3 e con l\'alimentatore.',
          'Poi ripeti l\'analisi per controllare la velocità.',
        ],
      },
      {
        title: 'Che cosa mostra Polaris',
        diagram: 'usbspeed',
        narration: [
          'Nella sezione del computer, l\'albero USB mostra ogni dispositivo con la velocità a cui sta lavorando davvero.',
          'Se un dispositivo USB 3 lavora come USB 2, Polaris lo segnala con la causa più probabile.',
          'Le porte compagne le descrive il firmware del PC, e non sempre bene: è un indizio da verificare.',
        ],
      },
    ],
  },
  {
    id: 'percorso-internet',
    chapter: 'diagnosi',
    title: 'Il percorso verso Internet',
    summary: 'Latenza e perdite misurate verso il router e verso Internet, e come leggere un traceroute per capire dove nasce un problema.',
    guide: 'latenza-perdite-jitter-banda',
    scenes: [
      {
        title: 'Latenza e perdite',
        diagram: 'netmap',
        narration: [
          'La latenza è il tempo che un pacchetto impiega ad andare e tornare, in millisecondi.',
          'Le perdite sono i pacchetti che non arrivano: anche pochi rovinano chiamate e videochiamate.',
          'Il traffico di questo PC passa dallo switch e dal router prima di arrivare a Internet.',
        ],
      },
      {
        title: 'Router e Internet insieme',
        diagram: 'netmap',
        narration: [
          'Polaris misura nello stesso momento verso il router e verso Internet.',
          'Se la latenza sale anche verso il router, il problema è in casa o in ufficio: Wi-Fi, cavo o apparati.',
          'Se sale solo verso Internet, il problema è sulla linea o presso l\'operatore.',
        ],
      },
      {
        title: 'Come funziona il traceroute',
        diagram: 'traceroute',
        narration: [
          'Il traceroute mostra i router attraversati per arrivare a una destinazione.',
          'Manda pacchetti con un contatore chiamato tempo di vita, che ogni router diminuisce di uno.',
          'Quando arriva a zero, il router scarta il pacchetto e risponde: così si scopre chi è.',
        ],
      },
      {
        title: 'Leggere i tempi',
        diagram: 'traceroute',
        narration: [
          'I tempi crescono con la distanza, ed è normale.',
          'Conta un salto brusco che resta alto anche nei router successivi.',
          'Un router che non risponde, segnato con un asterisco, non è un guasto se quelli dopo rispondono.',
        ],
      },
      {
        title: 'Dove intervenire',
        diagram: 'netmap',
        narration: [
          'Se il problema nasce già verso il router, si cerca in casa: Wi-Fi, cavi e router.',
          'Se nasce più avanti, conviene portare all\'operatore il rapporto di Polaris con le misure.',
        ],
      },
    ],
  },
];

const byId = new Map(VIDEOS.map((v) => [v.id, v]));

export function videoById(id: string): VideoGuide | undefined {
  return byId.get(id);
}
