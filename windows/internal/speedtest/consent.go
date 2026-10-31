package speedtest

// Testo del consenso, mostrato prima di ogni test (la stessa versione è
// nell'interfaccia, core/src/ui/speedtest.tsx). M-Lab chiede un consenso
// informato prima di ogni misura, con i collegamenti alla sua informativa e
// alle regole d'uso.
const (
	ConsentTitle = "Test di velocità di Internet"
	PrivacyURL   = "https://www.measurementlab.net/privacy/"
	AUPURL       = "https://www.measurementlab.net/aup/"
	// ConsentCheck è la dichiarazione che l'utente accetta.
	ConsentCheck = "Ho letto e accetto che il risultato e il mio indirizzo IP vengano pubblicati da M-Lab"
)

// ConsentText: i paragrafi del consenso, nell'ordine.
var ConsentText = []string{
	"Il test dura circa 30 secondi. Polaris misura prima la latenza, poi scarica e invia dati per circa 20 secondi verso un server di Measurement Lab (M-Lab), un progetto senza scopo di lucro, scelto vicino a te (di solito in Italia).",
	"Il test può consumare molti dati: fino a circa 250 MB in download e 250 MB in upload. Evitalo su connessioni a consumo o sull'hotspot del telefono.",
	"M-Lab registra e pubblica per sempre, in un archivio aperto e senza restrizioni, il risultato del test insieme all'indirizzo IP pubblico della tua connessione, alla data e all'ora e al nome del programma (STARNET Polaris). Non riceve il tuo nome né altri dati del computer; dall'indirizzo IP si può risalire in modo approssimativo alla zona e all'operatore.",
	"Se la connessione ha un indirizzo IP fisso (studi, aziende, strutture sanitarie), il risultato resta pubblico e collegato a quell'indirizzo: verifica che le regole interne lo consentano.",
	"Titolare di questi dati è M-Lab: informativa su " + PrivacyURL + " e regole d'uso su " + AUPURL + ". Polaris non salva e non stampa il tuo indirizzo IP nei referti. Il test non è adatto a minori di 16 anni.",
}

// LegalNote accompagna ogni risultato.
const LegalNote = "La misura usa una sola connessione verso un server di M-Lab: serve a capire come va la linea, ma non ha valore legale. Per un reclamo all'operatore o per recedere senza costi serve la misura certificata AGCOM con Ne.Me.Sys. (www.misurainternet.it): PC collegato al modem con il cavo, misure per 24 ore, certificato con i dati dell'intestatario."
