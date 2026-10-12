import type { Category, Severity } from '../types';

// Knowledge base delle metriche: per ogni valore che LANterna mostra spiega
// cos'è, come si legge (con le soglie usate dal motore), perché conta e
// quali limiti ha la misura. Le soglie qui scritte sono le stesse applicate
// in `analyze.ts`: se ne cambi una, aggiorna anche l'altra (i test lo
// verificano sui casi principali).

export interface ScaleStep {
  range: string;
  severity: Severity;
  meaning: string;
}

export interface Metric {
  id: string;
  label: string;
  category: Category;
  unit?: string;
  what: string;
  scale?: ScaleStep[];
  why: string;
  limits?: string;
}

const list: Metric[] = [
  // ---------------- Wi-Fi ----------------
  {
    id: 'wifi.rssi',
    label: 'Potenza del segnale (RSSI)',
    category: 'wifi',
    unit: 'dBm',
    what: 'La potenza con cui il tuo dispositivo riceve il segnale del router, espressa in decibel-milliwatt. I valori sono negativi: più si avvicinano a zero, più il segnale è forte. La scala è logaritmica, quindi ogni 3 dB in meno significano metà della potenza e 10 dB in meno un decimo.',
    scale: [
      { range: 'da -30 a -55 dBm', severity: 'ok', meaning: 'Eccellente: il router è vicino, si ottiene la massima velocità.' },
      { range: 'da -56 a -67 dBm', severity: 'ok', meaning: 'Buono: sufficiente per videochiamate, streaming 4K e giochi online.' },
      { range: 'da -68 a -75 dBm', severity: 'warn', meaning: 'Debole: navigazione ok, ma velocità ridotta e possibili scatti nelle chiamate.' },
      { range: 'sotto -75 dBm', severity: 'crit', meaning: 'Molto debole: disconnessioni, pagine lente, chiamate che cadono.' },
    ],
    why: 'Il segnale determina quale modulazione può usare la radio: con segnale forte trasmette molti bit per simbolo e va veloce, con segnale debole ripiega su schemi robusti ma lenti e ritrasmette spesso. È la prima cosa da sistemare quando il Wi-Fi è lento.',
    limits: 'Ogni scheda Wi-Fi misura in modo un po\' diverso (±3-5 dB). Il valore varia di qualche dB anche da fermi: conta l\'ordine di grandezza, non la cifra esatta. Windows non espone il rumore di fondo, quindi il rapporto segnale/rumore (SNR) non è misurabile da qui.',
  },
  {
    id: 'wifi.quality',
    label: 'Qualità del segnale (%)',
    category: 'wifi',
    unit: '%',
    what: 'La percentuale che Windows mostra nelle tacche del Wi-Fi. Non è una misura indipendente: Windows la calcola dalla potenza in dBm con una scala lineare, dove 0 % corrisponde a -100 dBm e 100 % a -50 dBm o meglio.',
    scale: [
      { range: '80-100 %', severity: 'ok', meaning: 'Circa -60 dBm o meglio: ottimo.' },
      { range: '64-79 %', severity: 'ok', meaning: 'Circa -68/-60 dBm: buono.' },
      { range: '50-63 %', severity: 'warn', meaning: 'Circa -75/-68 dBm: debole.' },
      { range: 'sotto 50 %', severity: 'crit', meaning: 'Oltre -75 dBm: insufficiente.' },
    ],
    why: 'È utile come confronto rapido, ma il valore in dBm è più preciso: quando sono disponibili entrambi LANterna valuta i dBm.',
  },
  {
    id: 'wifi.linkrate',
    label: 'Velocità di collegamento radio',
    category: 'wifi',
    unit: 'Mbit/s',
    what: 'La velocità con cui la scheda e il router si sono accordati a trasmettere in questo momento (PHY rate). Dipende da standard Wi-Fi, larghezza di canale, numero di antenne e qualità del segnale, e cambia continuamente.',
    scale: [
      { range: 'oltre 400 Mbit/s', severity: 'ok', meaning: 'Collegamento moderno e in ottime condizioni.' },
      { range: '144-400 Mbit/s', severity: 'ok', meaning: 'Adeguato alla maggior parte delle connessioni domestiche.' },
      { range: '54-143 Mbit/s', severity: 'warn', meaning: 'Limitato: rischi di non sfruttare una fibra veloce.' },
      { range: 'sotto 54 Mbit/s', severity: 'crit', meaning: 'Molto basso: segnale debole, standard vecchio o canale disturbato.' },
    ],
    why: 'La velocità reale di un trasferimento è circa la metà o due terzi del PHY rate, per via del protocollo e della condivisione del canale. Se il PHY rate è sotto la velocità della tua linea Internet, il collo di bottiglia è il Wi-Fi.',
    limits: 'Il valore è istantaneo: a dispositivo inattivo la scheda può scendere a velocità basse per risparmiare energia.',
  },
  {
    id: 'wifi.band',
    label: 'Banda di frequenza',
    category: 'wifi',
    what: 'Il Wi-Fi usa tre bande. 2,4 GHz: portata maggiore, ma solo 3 canali utili, affollata e condivisa con Bluetooth e microonde. 5 GHz: molti canali, velocità alte, portata un po\' minore. 6 GHz (Wi-Fi 6E/7): banda nuova e libera, velocità massime, portata più corta.',
    scale: [
      { range: '5 GHz o 6 GHz', severity: 'ok', meaning: 'Banda veloce e poco congestionata.' },
      { range: '2,4 GHz con 5 GHz disponibile', severity: 'warn', meaning: 'Stai usando la banda lenta pur potendo usare quella veloce.' },
      { range: '2,4 GHz senza alternative', severity: 'info', meaning: 'Il router non offre il 5 GHz o non è raggiungibile.' },
    ],
    why: 'Su 2,4 GHz la velocità reale raramente supera i 50-100 Mbit/s in un ambiente con vicini; a 5 GHz si superano facilmente i 300-500 Mbit/s.',
  },
  {
    id: 'wifi.phy',
    label: 'Standard Wi-Fi',
    category: 'wifi',
    what: 'La generazione del protocollo radio negoziata: 802.11b/g (anni 2000), 802.11n (Wi-Fi 4), 802.11ac (Wi-Fi 5), 802.11ax (Wi-Fi 6/6E), 802.11be (Wi-Fi 7). Ogni generazione migliora velocità ed efficienza con molti dispositivi.',
    scale: [
      { range: 'Wi-Fi 6, 6E, 7', severity: 'ok', meaning: 'Moderno, efficiente anche con molti dispositivi.' },
      { range: 'Wi-Fi 5 (802.11ac)', severity: 'ok', meaning: 'Ancora valido per la maggior parte delle case.' },
      { range: 'Wi-Fi 4 (802.11n)', severity: 'warn', meaning: 'Datato: limita la velocità con linee oltre 100 Mbit/s.' },
      { range: '802.11a/b/g', severity: 'crit', meaning: 'Obsoleto: massimo teorico 54 Mbit/s.' },
    ],
    why: 'La connessione usa lo standard più recente supportato da *entrambi*: un router Wi-Fi 6 con un portatile Wi-Fi 4 va alla velocità del Wi-Fi 4.',
  },
  {
    id: 'wifi.width',
    label: 'Larghezza di canale',
    category: 'wifi',
    unit: 'MHz',
    what: 'Quanta porzione di spettro occupa la rete: 20, 40, 80, 160 o 320 MHz. Raddoppiare la larghezza raddoppia circa la velocità massima, ma aumenta la probabilità di sovrapporsi ad altre reti.',
    scale: [
      { range: '2,4 GHz a 20 MHz', severity: 'ok', meaning: 'Impostazione corretta per convivere con i vicini.' },
      { range: '2,4 GHz a 40 MHz', severity: 'warn', meaning: 'Occupa due terzi della banda: crea e subisce interferenze.' },
      { range: '5 GHz a 80 MHz', severity: 'ok', meaning: 'Buon compromesso tra velocità e convivenza.' },
      { range: '5 GHz a 20/40 MHz', severity: 'info', meaning: 'Velocità massima ridotta; sensato solo in ambienti molto affollati.' },
    ],
    why: 'Nel 2,4 GHz ci sono solo 3 canali da 20 MHz che non si sovrappongono: una rete a 40 MHz ne usa due. Nel 5 GHz lo spazio è molto maggiore e 80 MHz è lo standard di fatto.',
  },
  {
    id: 'wifi.cochannel',
    label: 'Reti sullo stesso canale',
    category: 'wifi',
    what: 'Quante altre reti trasmettono sullo stesso canale (o su canali che si sovrappongono) della tua, pesate in base alla loro potenza. Il Wi-Fi è un mezzo condiviso: quando una rete trasmette, tutte le altre sullo stesso canale devono aspettare.',
    scale: [
      { range: 'nessuna rete forte', severity: 'ok', meaning: 'Il canale è tutto tuo.' },
      { range: '1-3 reti forti (sopra -75 dBm)', severity: 'warn', meaning: 'Dividi il tempo di trasmissione con i vicini.' },
      { range: '4 o più reti forti', severity: 'crit', meaning: 'Canale congestionato: velocità e latenza ne risentono molto.' },
    ],
    why: 'In un condominio è la causa più comune di Wi-Fi lento la sera, quando tutti sono connessi. Cambiare canale costa due minuti e può fare molta differenza.',
    limits: 'Si vedono solo le reti che il tuo dispositivo riesce a ricevere; non si vede quanto traffico fanno davvero, se non tramite il "carico" annunciato da alcuni router.',
  },
  {
    id: 'wifi.overlap24',
    label: 'Canale 2,4 GHz non standard',
    category: 'wifi',
    what: 'Nel 2,4 GHz i canali distano 5 MHz ma sono larghi 20 MHz: solo 1, 6 e 11 non si sovrappongono tra loro. Un canale intermedio (2-5, 7-10, 12-13) si sovrappone a due gruppi di reti.',
    scale: [
      { range: 'canale 1, 6 o 11', severity: 'ok', meaning: 'Allineato con il resto del mondo.' },
      { range: 'altri canali', severity: 'warn', meaning: 'Interferenza parziale con le reti su due canali standard.' },
    ],
    why: 'Due reti sullo stesso canale si "sentono" e si alternano in modo ordinato. Due reti su canali parzialmente sovrapposti non si decodificano a vicenda e si disturbano come rumore: è la situazione peggiore.',
  },
  {
    id: 'wifi.bssload',
    label: 'Occupazione del canale (dichiarata dal router)',
    category: 'wifi',
    unit: '%',
    what: 'Molti router annunciano nei loro beacon (elemento "BSS Load" dello standard 802.11) quanto tempo il canale risulta occupato e quanti dispositivi hanno collegati. È la misura più diretta di quanto il canale sia affollato.',
    scale: [
      { range: '0-40 %', severity: 'ok', meaning: 'Canale scarico.' },
      { range: '41-70 %', severity: 'warn', meaning: 'Canale impegnato: prestazioni variabili.' },
      { range: 'oltre 70 %', severity: 'crit', meaning: 'Canale saturo: lentezza e latenza alta garantite.' },
    ],
    why: 'Un\'occupazione alta significa che la radio passa la maggior parte del tempo ad aspettare il proprio turno: anche con segnale perfetto la velocità reale crolla.',
    limits: 'Non tutti i router includono questa informazione; quando manca la sezione non viene valutata.',
  },
  {
    id: 'wifi.security',
    label: 'Sicurezza Wi-Fi',
    category: 'security',
    what: 'Il protocollo che protegge la rete. Aperta: nessuna cifratura. WEP e WPA (TKIP): violabili in pochi minuti. WPA2 (AES/CCMP): sicuro con una buona password. WPA3 (SAE): il più recente, resiste agli attacchi a dizionario sulla password.',
    scale: [
      { range: 'WPA3 o WPA2/WPA3', severity: 'ok', meaning: 'Protezione moderna.' },
      { range: 'WPA2 con AES', severity: 'ok', meaning: 'Sicuro con una password robusta.' },
      { range: 'WPA2 con TKIP o mista', severity: 'warn', meaning: 'TKIP è deprecato e limita la velocità a 54 Mbit/s.' },
      { range: 'Aperta, WEP o WPA', severity: 'crit', meaning: 'Il traffico può essere letto o la rete violata.' },
    ],
    why: 'Chi entra nella tua rete Wi-Fi può raggiungere tutti i dispositivi di casa, intercettare il traffico non cifrato e usare la tua connessione per attività illecite a tuo nome.',
  },
  {
    id: 'wifi.pmf',
    label: 'Protezione frame di gestione (PMF)',
    category: 'security',
    what: 'Lo standard 802.11w firma i messaggi di servizio del Wi-Fi (ad esempio quelli di disconnessione), così nessuno può falsificarli.',
    scale: [
      { range: 'Obbligatoria', severity: 'ok', meaning: 'Protezione completa.' },
      { range: 'Supportata', severity: 'ok', meaning: 'Attiva con i dispositivi che la supportano.' },
      { range: 'Assente', severity: 'warn', meaning: 'Chiunque nel raggio può scollegare i tuoi dispositivi.' },
    ],
    why: 'Senza PMF un attacco di "deautenticazione" scollega i dispositivi a piacimento: è fastidioso di per sé e viene usato come primo passo per altri attacchi.',
  },
  {
    id: 'wifi.wps',
    label: 'WPS attivo',
    category: 'security',
    what: 'Il Wi-Fi Protected Setup permette di collegare un dispositivo premendo un tasto o digitando un PIN di 8 cifre, senza la password.',
    scale: [
      { range: 'Disattivato', severity: 'ok', meaning: 'Nessun rischio.' },
      { range: 'Attivo', severity: 'warn', meaning: 'Se è attiva la modalità PIN, la password può essere recuperata con un attacco a forza bruta.' },
    ],
    why: 'Il PIN WPS viene verificato in due metà indipendenti: invece di 100 milioni di combinazioni ne bastano circa 11.000. Alcuni router bloccano i tentativi, molti no.',
    limits: 'Dal beacon si vede se il WPS è annunciato, non se la modalità PIN è effettivamente abilitata.',
  },
  {
    id: 'wifi.networks',
    label: 'Reti visibili',
    category: 'wifi',
    what: 'Tutte le reti Wi-Fi che il dispositivo riceve, con potenza, canale, standard e sicurezza. Ogni riga è un "BSS", cioè una singola radio: un router dual-band compare due volte, un sistema mesh una volta per satellite.',
    why: 'Serve a capire quanto è affollato l\'ambiente radio e a scegliere il canale. Una rete con il tuo nome ma da una radio sconosciuta può indicare un ripetitore dimenticato o, raramente, un tentativo di impersonare la tua rete.',
  },

  // ---------------- LAN ----------------
  {
    id: 'lan.address',
    label: 'Indirizzo IP del PC',
    category: 'lan',
    what: 'L\'indirizzo che identifica il dispositivo nella rete di casa, normalmente assegnato automaticamente dal router (DHCP). Gli indirizzi privati tipici sono 192.168.x.x, 10.x.x.x e 172.16-31.x.x.',
    scale: [
      { range: 'indirizzo privato valido', severity: 'ok', meaning: 'Il PC ha ottenuto correttamente un indirizzo.' },
      { range: '169.254.x.x (APIPA)', severity: 'crit', meaning: 'Nessuno ha risposto alla richiesta di indirizzo: niente rete.' },
    ],
    why: 'Senza un indirizzo valido nella stessa sottorete del router il PC non può comunicare con nulla.',
  },
  {
    id: 'lan.gateway',
    label: 'Gateway predefinito',
    category: 'lan',
    what: 'L\'indirizzo del router, la "porta" attraverso cui passa tutto il traffico diretto fuori dalla rete di casa.',
    scale: [
      { range: 'presente e raggiungibile', severity: 'ok', meaning: 'Il PC sa dove inviare il traffico verso Internet.' },
      { range: 'assente', severity: 'crit', meaning: 'Il PC non può raggiungere Internet.' },
      { range: 'più gateway su schede diverse', severity: 'info', meaning: 'Possibili percorsi alternativi (VPN, hotspot, doppia connessione).' },
    ],
    why: 'È il primo punto da controllare: se il gateway non risponde, il problema è nella rete di casa e non nell\'operatore.',
  },
  {
    id: 'lan.gwlatency',
    label: 'Latenza verso il router',
    category: 'lan',
    unit: 'ms',
    what: 'Il tempo di andata e ritorno di un pacchetto tra il PC e il router (ping). Misura la qualità del solo tratto locale, cavo o Wi-Fi, escludendo Internet.',
    scale: [
      { range: 'sotto 5 ms', severity: 'ok', meaning: 'Ottimo (via cavo è normale stare sotto 1 ms).' },
      { range: '5-20 ms', severity: 'ok', meaning: 'Normale per il Wi-Fi.' },
      { range: '21-50 ms', severity: 'warn', meaning: 'Alto per una rete locale: Wi-Fi disturbato o router sovraccarico.' },
      { range: 'oltre 50 ms', severity: 'crit', meaning: 'Rete locale in difficoltà: ogni attività online ne risente.' },
    ],
    why: 'Tutta la latenza aggiunta qui si somma a quella verso Internet. Se è alta, cambiare operatore non serve: va sistemata la rete di casa.',
  },
  {
    id: 'lan.gwloss',
    label: 'Pacchetti persi verso il router',
    category: 'lan',
    unit: '%',
    what: 'La percentuale di ping verso il router che non ha ricevuto risposta.',
    scale: [
      { range: '0 %', severity: 'ok', meaning: 'Collegamento locale pulito.' },
      { range: '1-2 %', severity: 'warn', meaning: 'Perdite occasionali: tipico di Wi-Fi debole o disturbato.' },
      { range: 'oltre 2 %', severity: 'crit', meaning: 'Collegamento instabile: chiamate a scatti, download lenti.' },
    ],
    why: 'In una rete locale le perdite dovrebbero essere zero. Ogni pacchetto perso viene ritrasmesso, rallentando tutto; nei giochi e nelle chiamate si traduce in scatti.',
    limits: 'Alcuni router danno bassa priorità ai ping: una perdita isolata senza altri sintomi può non essere significativa.',
  },
  {
    id: 'net.jitter',
    label: 'Jitter (variazione della latenza)',
    category: 'internet',
    unit: 'ms',
    what: 'Quanto varia la latenza da un pacchetto al successivo. Una rete con 10 ms costanti è migliore di una che alterna 2 ms e 40 ms. LANterna lo misura sia verso il router (tratto locale) sia verso Internet.',
    scale: [
      { range: 'sotto 10 ms', severity: 'ok', meaning: 'Stabile (via cavo, verso il router, è normale stare sotto 1 ms).' },
      { range: '10-30 ms', severity: 'warn', meaning: 'Variabile: le chiamate possono avere piccoli scatti.' },
      { range: 'oltre 30 ms', severity: 'crit', meaning: 'Molto instabile: videochiamate e giochi ne soffrono.' },
    ],
    why: 'Le applicazioni in tempo reale (voce, video, giochi) usano un buffer per compensare le variazioni: se il jitter supera il buffer, l\'audio si interrompe o il gioco "scatta". Jitter alto solo verso Internet indica congestione della linea; anche verso il router indica Wi-Fi disturbato.',
  },
  {
    id: 'lan.linkspeed',
    label: 'Velocità della porta Ethernet',
    category: 'lan',
    unit: 'Mbit/s',
    what: 'La velocità negoziata tra la scheda di rete cablata e il router o lo switch: tipicamente 100, 1000 (gigabit) o 2500 Mbit/s.',
    scale: [
      { range: '1000 Mbit/s o più', severity: 'ok', meaning: 'Gigabit: il cavo non è un limite.' },
      { range: '100 Mbit/s', severity: 'warn', meaning: 'Limita qualsiasi linea oltre 100 Mbit/s; spesso indica un cavo difettoso.' },
      { range: '10 Mbit/s', severity: 'crit', meaning: 'Cavo o porta quasi certamente guasti.' },
    ],
    why: 'Un cavo con un filo interrotto fa scendere silenziosamente la connessione da 1000 a 100 Mbit/s: tutto funziona, ma la fibra da 1 Gbit/s diventa da 100.',
  },
  {
    id: 'lan.ipv6',
    label: 'Connettività IPv6',
    category: 'lan',
    what: 'IPv6 è la versione moderna del protocollo Internet. Un indirizzo IPv6 globale (che inizia con 2 o 3) significa che il tuo operatore e il router lo supportano.',
    scale: [
      { range: 'indirizzo globale presente', severity: 'ok', meaning: 'IPv6 attivo.' },
      { range: 'solo indirizzi locali (fe80::)', severity: 'info', meaning: 'IPv6 non fornito: Internet funziona comunque su IPv4.' },
    ],
    why: 'Non è indispensabile, ma alcuni servizi e giochi funzionano meglio in IPv6, che evita il NAT e i suoi limiti.',
  },
  {
    id: 'lan.neighbors',
    label: 'Dispositivi rilevati in rete',
    category: 'lan',
    what: 'Gli altri dispositivi con cui il PC ha comunicato di recente (tabella ARP/neighbor del sistema operativo).',
    why: 'Aiuta a riconoscere dispositivi sconosciuti. Non è un inventario completo: compaiono solo quelli con cui c\'è stato traffico. Per l\'elenco completo consulta la pagina "dispositivi connessi" del router.',
  },

  // ---------------- Internet ----------------
  {
    id: 'net.latency',
    label: 'Latenza verso Internet',
    category: 'internet',
    unit: 'ms',
    what: 'Il tempo di andata e ritorno verso server pubblici molto vicini a tutti (resolver DNS di Cloudflare, Google, Quad9). Include rete di casa, linea dell\'operatore e tratta fino al server.',
    scale: [
      { range: 'sotto 20 ms', severity: 'ok', meaning: 'Ottima (tipica della fibra FTTH).' },
      { range: '20-40 ms', severity: 'ok', meaning: 'Buona (tipica di FTTC/VDSL).' },
      { range: '41-80 ms', severity: 'warn', meaning: 'Discreta: nei giochi competitivi si sente.' },
      { range: 'oltre 80 ms', severity: 'crit', meaning: 'Alta: tipica di satellite, 4G congestionato o problemi di linea.' },
    ],
    why: 'La latenza determina la reattività: caricamento delle pagine, risposta nei giochi, ritardo nelle chiamate. Conta spesso più della velocità in Mbit/s.',
  },
  {
    id: 'net.loss',
    label: 'Pacchetti persi verso Internet',
    category: 'internet',
    unit: '%',
    what: 'La percentuale di ping verso i server pubblici rimasti senza risposta.',
    scale: [
      { range: '0 %', severity: 'ok', meaning: 'Linea pulita.' },
      { range: '1-2 %', severity: 'warn', meaning: 'Perdite lievi.' },
      { range: 'oltre 2 %', severity: 'crit', meaning: 'Linea instabile.' },
    ],
    why: 'Confrontata con la perdita verso il router individua dove sta il problema: perdite solo verso Internet indicano la linea o l\'operatore; perdite anche verso il router indicano la rete di casa.',
  },
  {
    id: 'net.trace',
    label: 'Percorso verso Internet (traceroute)',
    category: 'internet',
    what: 'L\'elenco dei router attraversati per raggiungere Internet, con il tempo di risposta di ciascuno. Il primo salto è il tuo router, i successivi appartengono all\'operatore.',
    scale: [
      { range: 'latenza che cresce gradualmente', severity: 'ok', meaning: 'Percorso regolare.' },
      { range: 'salto di oltre 30 ms tra un nodo e il successivo', severity: 'warn', meaning: 'Possibile congestione o tratta lunga in quel punto.' },
    ],
    why: 'Indica *dove* nasce un ritardo. Un salto alto subito dopo il router punta alla linea di accesso; uno più avanti alla rete dell\'operatore o a collegamenti internazionali.',
    limits: 'Molti router dell\'operatore non rispondono ai traceroute (asterischi) o rispondono lentamente perché danno bassa priorità a questi pacchetti: un singolo nodo lento seguito da nodi veloci non è un problema.',
  },
  {
    id: 'net.mtu',
    label: 'MTU del percorso',
    category: 'internet',
    unit: 'byte',
    what: 'La dimensione massima di un pacchetto che può attraversare l\'intero percorso senza essere spezzato. Lo standard Ethernet è 1500 byte; le connessioni PPPoE usano 1492; le VPN meno.',
    scale: [
      { range: '1500 byte', severity: 'ok', meaning: 'Standard, nessuna frammentazione.' },
      { range: '1400-1499 byte', severity: 'info', meaning: 'Normale per PPPoE o VPN.' },
      { range: 'sotto 1400 byte', severity: 'warn', meaning: 'Insolitamente bassa: può causare siti che si caricano a metà.' },
    ],
    why: 'Se un tratto del percorso non accetta pacchetti grandi e non lo segnala correttamente, le connessioni restano "appese": problema raro ma difficile da diagnosticare senza questa misura.',
  },
  {
    id: 'net.http',
    label: 'Raggiungibilità web',
    category: 'internet',
    what: 'Una richiesta HTTPS reale verso un sito molto diffuso, per verificare che la navigazione funzioni end-to-end (DNS, TCP, TLS, eventuali proxy).',
    scale: [
      { range: 'risposta in meno di 800 ms', severity: 'ok', meaning: 'Navigazione regolare (la prima richiesta include ricerca DNS, connessione e cifratura).' },
      { range: 'oltre 800 ms', severity: 'warn', meaning: 'Navigazione rallentata.' },
      { range: 'nessuna risposta', severity: 'crit', meaning: 'Non si naviga anche se la rete locale funziona.' },
    ],
    why: 'Il ping può funzionare anche quando la navigazione no (proxy, firewall aziendale, captive portal di hotel e aeroporti): questo test lo verifica.',
  },

  // ---------------- DNS ----------------
  {
    id: 'dns.time',
    label: 'Tempo di risposta DNS',
    category: 'dns',
    unit: 'ms',
    what: 'Quanto impiega il server DNS configurato (di solito il router, che inoltra all\'operatore) a tradurre un nome come "esempio.it" in indirizzo IP.',
    scale: [
      { range: 'sotto 30 ms', severity: 'ok', meaning: 'Veloce.' },
      { range: '30-100 ms', severity: 'ok', meaning: 'Accettabile.' },
      { range: '101-250 ms', severity: 'warn', meaning: 'Lento: ogni nuovo sito parte in ritardo.' },
      { range: 'oltre 250 ms o nessuna risposta', severity: 'crit', meaning: 'Molto lento o guasto: la navigazione sembra bloccata.' },
    ],
    why: 'Una pagina web moderna contatta decine di domini diversi: un DNS lento si moltiplica per ciascuno.',
    limits: 'Il primo accesso a un nome non in cache è più lento dei successivi: LANterna usa la mediana di più richieste con nomi diversi.',
  },
  {
    id: 'dns.compare',
    label: 'Confronto con DNS pubblici',
    category: 'dns',
    what: 'Lo stesso test eseguito verso resolver pubblici noti, per capire se cambiare DNS darebbe un vantaggio reale.',
    scale: [
      { range: 'DNS attuale tra i più veloci', severity: 'ok', meaning: 'Non serve cambiare.' },
      { range: 'pubblico più veloce di oltre 30 ms', severity: 'info', meaning: 'Cambiare DNS renderebbe la navigazione più reattiva.' },
    ],
    why: 'Il DNS dell\'operatore non è sempre il più veloce né il più affidabile; i resolver pubblici offrono a volte anche filtri contro siti malevoli.',
  },

  // ---------------- Router ----------------
  {
    id: 'router.port',
    label: 'Servizi esposti dal router',
    category: 'router',
    what: 'LANterna prova ad aprire una connessione verso le porte di gestione più comuni del *tuo* router (solo il gateway, solo dalla rete di casa), per capire quali servizi sono attivi.',
    scale: [
      { range: 'HTTP/HTTPS (80, 443, 8080, 8443)', severity: 'info', meaning: 'Pannello di gestione: normale.' },
      { range: 'DNS (53)', severity: 'ok', meaning: 'Il router fa da DNS per la rete: normale.' },
      { range: 'SSH (22)', severity: 'info', meaning: 'Accesso amministrativo cifrato: ok se lo usi, altrimenti disattivalo.' },
      { range: 'FTP (21), SMB (445)', severity: 'warn', meaning: 'Condivisione file: se non usi un disco USB sul router, disattivala.' },
      { range: 'Telnet (23)', severity: 'crit', meaning: 'Accesso amministrativo con password in chiaro: bersaglio classico dei malware.' },
    ],
    why: 'Meno servizi sono attivi sul router, minore è la superficie di attacco: ogni servizio è un programma che può avere vulnerabilità.',
    limits: 'Il controllo è fatto dalla rete locale: non dice cosa è esposto verso Internet. La prova di porte su dispositivi altrui senza autorizzazione è vietata: LANterna controlla esclusivamente il gateway della rete a cui sei collegato.',
  },
  {
    id: 'router.upnp',
    label: 'UPnP (Internet Gateway Device)',
    category: 'router',
    what: 'Un protocollo con cui i programmi della rete chiedono al router di aprire porte verso Internet in automatico, senza autenticazione.',
    scale: [
      { range: 'non rilevato', severity: 'ok', meaning: 'Le porte si aprono solo a mano.' },
      { range: 'attivo', severity: 'warn', meaning: 'Comodo per console e P2P, ma qualsiasi programma (anche malevolo) può aprire porte.' },
    ],
    why: 'È una delle impostazioni più discusse: comoda ma rischiosa. Se nessuno in casa usa console o programmi che lo richiedono, conviene spegnerlo.',
  },
  {
    id: 'router.web',
    label: 'Pannello di gestione del router',
    category: 'router',
    what: 'La pagina web di configurazione del router. LANterna legge solo l\'intestazione pubblica e il titolo della pagina, senza autenticarsi.',
    scale: [
      { range: 'raggiungibile via HTTPS', severity: 'ok', meaning: 'La password di amministrazione viaggia cifrata.' },
      { range: 'solo HTTP', severity: 'info', meaning: 'La password viaggia in chiaro nella rete locale.' },
    ],
    why: 'Il modello e la versione del server web aiutano a cercare aggiornamenti firmware e vulnerabilità note.',
  },
  {
    id: 'sec.firewall',
    label: 'Firewall di Windows',
    category: 'security',
    what: 'Windows ha tre profili firewall: Dominio (reti aziendali), Privata (casa, ufficio fidato) e Pubblica (bar, hotel, aeroporti). Il profilo attivo dipende da come hai classificato la rete.',
    scale: [
      { range: 'tutti attivi', severity: 'ok', meaning: 'Configurazione corretta.' },
      { range: 'profilo inattivo disattivato', severity: 'warn', meaning: 'Rischio quando ti colleghi a un altro tipo di rete.' },
      { range: 'profilo attivo disattivato', severity: 'crit', meaning: 'Il PC è esposto ora.' },
    ],
    why: 'Il firewall è l\'ultima barriera se un altro dispositivo della rete è compromesso o se sei su una rete pubblica.',
    limits: 'Se un antivirus di terze parti sostituisce il firewall di Windows, il profilo può risultare disattivato pur essendo il PC protetto.',
  },
];

export const METRICS: Record<string, Metric> = Object.fromEntries(list.map((m) => [m.id, m]));
export const METRIC_LIST = list;
