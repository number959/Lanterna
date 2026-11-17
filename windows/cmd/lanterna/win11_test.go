package main

import (
	"strings"
	"testing"

	"lanterna/internal/scan"
)

func TestPrintWin11(t *testing.T) {
	base := scan.Win11CPUCheck{At: "2026-11-17T10:00:00Z", Source: "https://learn.microsoft.com/en-us/windows-hardware/design/minimum/supported/windows-11-25h2-supported-intel-processors", Version: "25H2", Kind: "series", CPU: "Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz", Rows: 87}
	cases := []struct {
		mod  func(r *scan.Win11CPUCheck)
		want []string
	}{
		{func(r *scan.Win11CPUCheck) { r.Result, r.Match = "listed", "8th Generation Core i5 Processors" },
			[]string{"Processore: Intel(R) Core(TM) i5-8250U", "Elenco: Windows 11 25H2, per serie, 87 righe", "Esito: nell'elenco (riga «8th Generation Core i5 Processors»)."}},
		{func(r *scan.Win11CPUCheck) { r.Result = "notListed" },
			[]string{"Esito: non compare nell'elenco.", "usciti dopo l'elenco", "Controllo integrità PC"}},
		{func(r *scan.Win11CPUCheck) { r.Result, r.Match = "unknown", "Celeron 3000 Series" },
			[]string{"Esito: da verificare. La serie «Celeron 3000 Series» è nell'elenco"}},
		{func(r *scan.Win11CPUCheck) { r.Result = "unknown" },
			[]string{"Esito: da verificare. Dal nome del processore non si può dire"}},
		{func(r *scan.Win11CPUCheck) {
			r.Result, r.Error, r.Rows, r.Kind = "unknown", "learn.microsoft.com ha risposto 404", 0, "model"
		},
			[]string{"Elenco: Windows 11 25H2, per modello\n", "Confronto non riuscito: learn.microsoft.com ha risposto 404."}},
	}
	for i, c := range cases {
		r := base
		c.mod(&r)
		out := capture(t, func() { printWin11(&r) })
		for _, w := range c.want {
			if !strings.Contains(out, w) {
				t.Errorf("caso %d: manca %q in:\n%s", i, w, out)
			}
		}
		if strings.Contains(out, "::") {
			t.Errorf("caso %d: doppi due punti:\n%s", i, out)
		}
	}
}
