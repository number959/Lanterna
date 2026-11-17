package main

import (
	"strings"
	"testing"
	"unicode/utf8"

	"lanterna/internal/collect"
)

// L'avanzamento mostra ogni fase finita una volta sola, con l'esito
// incolonnato anche per l'etichetta più lunga (Computer: processi, firme e
// connessioni), che con una larghezza fissa finiva attaccata all'esito.
func TestProgressLines(t *testing.T) {
	steps := []collect.Step{
		{ID: "adapters", Label: "Schede di rete e indirizzi", State: "done"},
		{ID: "gateway", Label: "Router: risposta e stabilità", State: "error"},
		{ID: "load", Label: "Computer: carico e processi", State: "running"},
		{ID: "procs", Label: "Computer: processi, firme e connessioni", State: "pending"},
	}
	shown := map[string]bool{}
	lines := progressLines(steps, shown)
	if len(lines) != 2 || !strings.HasSuffix(lines[0], "  ok") || !strings.HasSuffix(lines[1], "  non riuscita") {
		t.Fatalf("prime righe: %q", lines)
	}
	if len(progressLines(steps, shown)) != 0 {
		t.Fatal("fasi già mostrate ripetute")
	}
	steps[2].State, steps[3].State = "done", "done"
	lines = append(lines, progressLines(steps, shown)...)
	if len(lines) != 4 || !strings.Contains(lines[3], "Computer: processi, firme e connessioni  ok") {
		t.Fatalf("fase dei processi: %q", lines)
	}
	// Esiti nella stessa colonna (contando i caratteri, non i byte: «à»).
	col := -1
	for _, l := range lines {
		i := strings.LastIndex(l, "  ")
		c := utf8.RuneCountInString(l[:i])
		if col >= 0 && c != col {
			t.Fatalf("esiti non incolonnati:\n%s", strings.Join(lines, "\n"))
		}
		col = c
	}
}

// Il tempo annunciato non promette meno di quanto serve davvero (prima
// analisi su Windows reale: circa 45 secondi).
func TestScanNotice(t *testing.T) {
	if strings.Contains(scanNotice, "25 secondi") || !strings.Contains(scanNotice, "meno di un minuto") {
		t.Fatalf("annuncio dell'analisi: %q", scanNotice)
	}
}
