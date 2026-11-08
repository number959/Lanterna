package winapi

import (
	"strings"
	"testing"
)

// L'interfaccia riconosce il messaggio da queste parole e offre il pulsante che
// apre le impostazioni della posizione (LOCATION_MARK in core/src/tools.ts; lo
// controlla anche core/test/steps.test.ts leggendo questo pacchetto).
func TestLocationHint(t *testing.T) {
	if !strings.HasPrefix(LocationHint, "Windows richiede il permesso di posizione") {
		t.Fatalf("LocationHint cambiato: l'interfaccia lo riconosce da \"permesso di posizione\": %q", LocationHint)
	}
	for _, unconfirmed := range []string{"app desktop di accedere alla posizione", "\"Servizi di localizzazione\"", "> Posizione"} {
		if strings.Contains(LocationHint, unconfirmed) {
			t.Fatalf("etichetta non confermata nel messaggio: %s", unconfirmed)
		}
	}
}
