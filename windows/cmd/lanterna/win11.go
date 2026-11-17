package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"lanterna/internal/scan"
	"lanterna/internal/tools"
	"lanterna/internal/win11"
)

// win11Options prepara il confronto con l'elenco ufficiale dei processori:
// il processore di questo PC e lo stesso collegamento dei download della
// cassetta (proxy di sistema, User-Agent di Polaris).
func win11Options(f *tools.Fetcher) win11.Options {
	name, vendor := win11.LocalCPU()
	return win11.Options{Transport: f.Transport, UserAgent: f.UserAgent, CPU: name, Vendor: vendor}
}

// runWin11 confronta il processore con l'elenco dei processori supportati da
// Windows 11 che Microsoft pubblica su learn.microsoft.com: la pagina si
// scarica, si legge e si scarta.
func runWin11(args []string) error {
	fs := flag.NewFlagSet("win11", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "")
	fs.Usage = func() { fmt.Fprintf(os.Stderr, usage, version) }
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("argomento non previsto: %s", fs.Arg(0))
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	ctx, stop := context.WithTimeout(ctx, 35*time.Second)
	defer stop()
	if !*asJSON {
		fmt.Println("Scarico da learn.microsoft.com l'elenco ufficiale dei processori supportati da Windows 11...")
	}
	r := win11.Check(ctx, win11Options(newFetcher()))
	if *asJSON {
		b, _ := json.MarshalIndent(r, "", "  ")
		fmt.Println(string(b))
	} else {
		printWin11(r)
	}
	if r.Error != "" {
		return errors.New(r.Error)
	}
	return nil
}

func printWin11(r *scan.Win11CPUCheck) {
	cpu := r.CPU
	if cpu == "" {
		cpu = "nome non leggibile"
	}
	fmt.Printf("Processore: %s\n", cpu)
	if r.Source != "" {
		kind := "per serie"
		if r.Kind == "model" {
			kind = "per modello"
		}
		rows := ""
		if r.Rows > 0 {
			rows = fmt.Sprintf(", %d righe", r.Rows)
		}
		fmt.Printf("Elenco: Windows 11 %s, %s%s\n  %s\n", r.Version, kind, rows, r.Source)
	}
	if r.Error != "" {
		fmt.Printf("Confronto non riuscito: %s.\n", r.Error)
		fmt.Println("Per la verifica ufficiale usa l'app Controllo integrità PC di Microsoft.")
		return
	}
	switch {
	case r.Result == "listed":
		fmt.Printf("Esito: nell'elenco (riga «%s»).\n", r.Match)
	case r.Result == "notListed":
		fmt.Println("Esito: non compare nell'elenco.")
		fmt.Println("Microsoft considera supportati anche i processori usciti dopo l'elenco: per la conferma usa Controllo integrità PC.")
	case r.Match != "":
		fmt.Printf("Esito: da verificare. La serie «%s» è nell'elenco, ma comprende anche modelli di generazioni non supportate.\n", r.Match)
		fmt.Println("Per la conferma usa Controllo integrità PC.")
	default:
		fmt.Println("Esito: da verificare. Dal nome del processore non si può dire (processore virtuale, campione di prova o modello non riconosciuto).")
		fmt.Println("Per la conferma usa Controllo integrità PC.")
	}
	fmt.Println("Gli elenchi di Microsoft sono scritti per i PC nuovi; Windows Update controlla famiglia, modello e stepping del processore.")
}
