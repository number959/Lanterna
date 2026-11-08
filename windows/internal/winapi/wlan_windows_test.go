package winapi

import (
	"strings"
	"testing"
)

// L'interfaccia riconosce il messaggio da queste parole e offre il pulsante che
// apre le impostazioni della posizione (core/src/ui/views.tsx, LOCATION_MARK).
func TestLocationHint(t *testing.T) {
	if !strings.Contains(LocationHint, "permesso di posizione") {
		t.Fatalf("LocationHint senza \"permesso di posizione\": %q", LocationHint)
	}
	if strings.Contains(LocationHint, "app desktop di accedere alla posizione") {
		t.Fatal("etichetta non confermata nel messaggio")
	}
}
