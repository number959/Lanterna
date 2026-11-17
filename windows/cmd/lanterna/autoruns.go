package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"lanterna/internal/autoruns"
	"lanterna/internal/scan"
)

// runAutoruns mostra ciò che si avvia da solo (come Autoruns): chiavi del
// registro, cartelle Esecuzione automatica, servizi, driver, attività
// pianificate, sottoscrizioni WMI, estensioni dei browser e dirottamenti
// noti. Legge soltanto: non disattiva e non cancella nulla.
func runAutoruns(args []string) error {
	fs := flag.NewFlagSet("autoruns", flag.ContinueOnError)
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
	ctx, stop := context.WithTimeout(ctx, 45*time.Second)
	defer stop()
	if !*asJSON {
		fmt.Fprintln(os.Stderr, "Lettura dell'avvio automatico e verifica delle firme (fino a 45 secondi)...")
	}
	d, err := autoruns.Collect(ctx)
	if d == nil {
		return err
	}
	if *asJSON {
		b, _ := json.MarshalIndent(d, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	printAutoruns(d)
	if err != nil {
		fmt.Println()
		fmt.Println("Non letto del tutto: " + err.Error())
	}
	return nil
}

var autorunCategoryText = map[string]string{
	"logon":    "Accesso (chiavi Run, cartelle Esecuzione automatica)",
	"winlogon": "Winlogon (Shell e Userinit)",
	"hijacks":  "Dirottamenti noti (IFEO, BootExecute, AppInit_DLLs)",
	"services": "Servizi",
	"drivers":  "Driver",
	"tasks":    "Attività pianificate",
	"wmi":      "Sottoscrizioni WMI",
	"browser":  "Estensioni dei browser",
	"lsa":      "Pacchetti di sicurezza (LSA)",
	"print":    "Monitor e processori di stampa",
	"network":  "Provider di rete",
}

var autorunSigText = map[string]string{
	"valid":         "firmato",
	"unsigned":      "senza firma",
	"tampered":      "firma non valida (file modificato)",
	"revoked":       "certificato revocato",
	"distrusted":    "firma rifiutata",
	"expired":       "certificato scaduto",
	"untrustedRoot": "certificato non attendibile",
	"wrongUsage":    "certificato per un altro uso",
	"policy":        "bloccato dai criteri",
	"invalid":       "firma non valida",
	"unreadable":    "file non leggibile",
	"unknown":       "firma non verificabile",
}

// fileText descrive il file di una voce: percorso, firma o mancanza.
func fileText(f *scan.FileFacts) string {
	if f == nil {
		return ""
	}
	s := f.Path
	switch {
	case f.Missing:
		s += " [FILE MANCANTE]"
	case f.Signature == nil:
		s += " [firma non verificata]"
	default:
		t := autorunSigText[f.Signature.Status]
		if t == "" {
			t = f.Signature.Status
		}
		if f.Signature.Signer != "" {
			t += ": " + f.Signature.Signer
		}
		s += " [" + t + "]"
	}
	return s
}

func printAutoruns(d *scan.AutorunsData) {
	who := "Lettura senza privilegi di amministratore: attività e servizi visibili a questo utente."
	if d.Elevated {
		who = "Lettura da amministratore."
	}
	fmt.Println(who)
	if d.Partial {
		fmt.Println("Tempo scaduto prima della fine: l'elenco o la verifica delle firme sono incompleti.")
	}
	if len(d.Denied) > 0 {
		var names []string
		for _, c := range d.Denied {
			n := strings.SplitN(autorunCategoryText[c], " (", 2)[0]
			if n != "" {
				n = strings.ToLower(n[:1]) + n[1:]
			}
			names = append(names, n)
		}
		fmt.Printf("Lette solo in parte per i permessi: %s.\n", strings.Join(names, ", "))
	}
	for _, c := range autoruns.Categories {
		n, ok := d.Counts[c]
		if !ok {
			continue
		}
		var list []scan.AutorunEntry
		for _, e := range d.Entries {
			if e.Category == c {
				list = append(list, e)
			}
		}
		fmt.Println()
		head := fmt.Sprintf("%s: %d", autorunCategoryText[c], n.Total)
		if n.Microsoft > 0 {
			head += fmt.Sprintf(", di cui %d di Windows firmate da Microsoft (non elencate)", n.Microsoft)
		}
		if hidden := n.Total - n.Microsoft - len(list); c == "browser" && hidden > 0 {
			head += fmt.Sprintf(", %d componenti interni dei browser (non elencati)", hidden)
		}
		fmt.Println(head)
		for _, e := range list {
			printAutorun(e)
		}
	}
}

func printAutorun(e scan.AutorunEntry) {
	state := ""
	if !e.Enabled {
		state = " (disattivata)"
	}
	fmt.Printf("  - %s%s\n", e.Name, state)
	var detail []string
	switch e.Category {
	case "services", "drivers":
		if e.Start != "" {
			detail = append(detail, "avvio "+e.Start)
		}
		if e.Running {
			detail = append(detail, "in esecuzione")
		}
		if e.Account != "" {
			detail = append(detail, "account "+e.Account)
		}
		if e.Unquoted {
			detail = append(detail, fmt.Sprintf("percorso con spazi senza virgolette, file intercettori presenti: %d", e.Interceptors))
		}
	case "tasks":
		if len(e.Triggers) > 0 {
			detail = append(detail, "quando: "+strings.Join(e.Triggers, ", "))
		}
		if e.RunAs != "" {
			detail = append(detail, "eseguita come "+e.RunAs)
		}
		if e.Highest {
			detail = append(detail, "con i privilegi più elevati")
		}
		if e.Hidden {
			detail = append(detail, "nascosta")
		}
		if e.LastRun != "" {
			detail = append(detail, "ultima esecuzione "+e.LastRun+" esito "+e.LastResult)
		}
	case "browser":
		detail = append(detail, e.Browser)
		if e.Profile > 0 {
			detail = append(detail, fmt.Sprintf("profilo %d", e.Profile))
		}
		if e.Source != "" {
			detail = append(detail, "origine "+e.Source)
		}
		if e.AllSites {
			detail = append(detail, "accesso a tutti i siti")
		}
		if e.ExtID != "" {
			detail = append(detail, e.ExtID)
		}
	case "wmi":
		detail = append(detail, e.Consumer)
		if e.Bound {
			detail = append(detail, "collegata a un filtro")
		} else {
			detail = append(detail, "non collegata")
		}
	}
	if len(detail) > 0 {
		fmt.Printf("      %s\n", strings.Join(detail, "; "))
	}
	if e.Location != "" {
		fmt.Printf("      in %s\n", e.Location)
	}
	if e.Command != "" {
		fmt.Printf("      comando: %s\n", e.Command)
	}
	if f := fileText(e.File); f != "" {
		fmt.Printf("      file: %s\n", f)
	}
	if f := fileText(e.Target); f != "" {
		fmt.Printf("      esegue: %s\n", f)
	}
}
