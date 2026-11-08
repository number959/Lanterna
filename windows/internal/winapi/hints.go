package winapi

// LocationHint spiega come sbloccare l'accesso ai dati Wi-Fi su Windows 11 24H2+.
// Tra virgolette solo le etichette confermate da due fonti (8/11/2026): il nome
// della pagina, quello dei servizi di localizzazione (o di posizione) e quello
// dell'interruttore per le app desktop variano tra le fonti. L'interfaccia
// riconosce il messaggio da "permesso di posizione" (LOCATION_MARK in
// core/src/tools.ts) e offre il pulsante che apre la pagina
// (ms-settings:privacy-location). Sta fuori da wlan_windows.go perché il test
// giri anche nella CI su Linux.
const LocationHint = "Windows richiede il permesso di posizione per leggere le reti Wi-Fi: in Impostazioni > \"Privacy e sicurezza\" apri le impostazioni della posizione, attiva i servizi di localizzazione e consenti l'accesso alla posizione anche alle app desktop (se quell'interruttore è grigio, attiva prima \"Consenti alle app di accedere alla tua posizione\"), poi ripeti l'analisi."
