package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"lanterna/internal/procs"
	"lanterna/internal/scan"
)

// runProcs mostra i processi in esecuzione con la firma digitale dei file e
// le connessioni di rete riassunte (come Process Explorer e TCPView). Legge
// soltanto: non termina processi e non chiude connessioni.
func runProcs(args []string) error {
	fs := flag.NewFlagSet("procs", flag.ContinueOnError)
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
	ctx, stop := context.WithTimeout(ctx, 30*time.Second)
	defer stop()
	d, err := procs.Read(ctx, nil, time.Time{})
	if d == nil {
		return err
	}
	if *asJSON {
		b, _ := json.MarshalIndent(d, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	printProcs(d)
	return nil
}

var ownerText = map[string]string{"self": "tu", "system": "sistema", "other": "altro account", "unknown": "account non leggibile"}

var folderText = map[string]string{
	"windows": "Windows", "programFiles": "Programmi", "programData": "ProgramData", "appData": "AppData",
	"temp": "cartella temporanea", "downloads": "Download", "profile": "profilo dell'utente",
	"removable": "unità rimovibile", "network": "cartella di rete", "other": "altra cartella",
}

var sigText = map[string]string{
	"unsigned":      "nessuna firma digitale",
	"tampered":      "file modificato dopo la firma",
	"revoked":       "certificato revocato",
	"distrusted":    "firmatario bloccato su questo PC",
	"expired":       "firma scaduta",
	"untrustedRoot": "firmato da un'autorità non riconosciuta da Windows",
	"wrongUsage":    "certificato non valido per firmare programmi",
	"policy":        "non attendibile per le impostazioni di questo PC",
	"invalid":       "firma non valida",
	"unreadable":    "file non leggibile: firma da verificare",
	"unknown":       "firma non verificabile",
}

// signatureText descrive la firma del file in italiano.
func signatureText(f *scan.FileFacts) string {
	switch {
	case f.Missing:
		return "file non trovato"
	case f.Signature == nil:
		return "firma non verificata"
	}
	s := f.Signature
	out := sigText[s.Status]
	if s.Status == "valid" {
		out = "firma verificata"
	}
	if out == "" {
		out = "firma: " + s.Status
	}
	if s.Signer != "" {
		out += ": " + s.Signer
	}
	if s.Catalog {
		out += " (catalogo di Windows)"
	}
	if s.Microsoft {
		out += ", componente Microsoft"
	}
	if s.Code != "" && s.Status != "valid" && s.Status != "unsigned" {
		out += " [" + s.Code + "]"
	}
	return out
}

var scopeText = map[string]string{"all": "tutte le interfacce", "local": "solo questo PC", "specific": "un indirizzo"}

func listenText(ls []scan.ListenPort) string {
	parts := make([]string, 0, len(ls))
	for _, l := range ls {
		p := strings.ToUpper(l.Proto) + " " + strconv.Itoa(int(l.Port))
		if l.IPv6 {
			p += " IPv6"
		}
		parts = append(parts, p+" ("+scopeText[l.Scope]+")")
	}
	return strings.Join(parts, ", ")
}

func connsText(c *scan.ConnSummary) string {
	var parts []string
	if c.Internet > 0 {
		parts = append(parts, strconv.Itoa(c.Internet)+" verso Internet")
	}
	if c.LAN > 0 {
		parts = append(parts, strconv.Itoa(c.LAN)+" in rete locale")
	}
	if c.Local > 0 {
		parts = append(parts, strconv.Itoa(c.Local)+" con questo PC")
	}
	out := strings.Join(parts, ", ")
	if len(c.RemotePorts) > 0 {
		var ps []string
		for _, p := range c.RemotePorts {
			ps = append(ps, fmt.Sprintf("%d×%d", p.Port, p.Count))
		}
		out += "; porte remote " + strings.Join(ps, ", ")
	}
	return out
}

// unopenedText descrive un processo che non si è potuto aprire: senza
// amministratore lo si potrebbe aprire con i diritti in più; da
// amministratore lo tiene chiuso Windows.
func unopenedText(elevated bool) string {
	if elevated {
		return "non apribile: processo protetto da Windows"
	}
	return "non apribile senza amministratore"
}

func decimal(v float64) string {
	return strings.Replace(strconv.FormatFloat(v, 'f', 1, 64), ".", ",", 1)
}

func printProcs(d *scan.ProcessesData) {
	fmt.Printf("Processi in esecuzione: %d\n", len(d.Items))
	if d.Elevated {
		fmt.Println("Letti come amministratore.")
	} else {
		fmt.Println("Letti senza i diritti di amministratore.")
	}
	if d.Unreadable > 0 {
		if d.Elevated {
			// Da amministratore restano chiusi solo i processi protetti da Windows.
			fmt.Printf("Non apribili: %d, processi protetti da Windows (se ne conosce solo il nome).\n", d.Unreadable)
		} else {
			fmt.Printf("Non leggibili senza amministratore: %d (se ne conosce solo il nome).\n", d.Unreadable)
		}
	}
	if !d.ConnsRead {
		fmt.Println("Connessioni di rete non lette.")
	}
	if d.Partial {
		fmt.Println("Lettura non finita in tempo: alcuni file sono senza verifica della firma.")
	}
	var ms, others, unsigned, check int
	for _, p := range d.Items {
		if p.File == nil || p.File.Signature == nil {
			continue
		}
		switch s := p.File.Signature; {
		case s.Status == "valid" && s.Microsoft:
			ms++
		case s.Status == "valid":
			others++
		case s.Status == "unsigned":
			unsigned++
		default:
			check++
		}
	}
	fmt.Printf("Firme dei programmi: %d di Microsoft, %d di altri produttori, %d senza firma, %d da controllare.\n", ms, others, unsigned, check)
	for _, p := range d.Items {
		fmt.Println()
		var tags []string
		if p.Polaris {
			tags = append(tags, "STARNET Polaris")
		}
		if t := ownerText[p.Owner]; t != "" {
			tags = append(tags, t)
		}
		if p.Elevated {
			tags = append(tags, "amministratore")
		}
		if p.Access == "none" {
			tags = append(tags, unopenedText(d.Elevated))
		}
		if p.Arch != "" {
			tags = append(tags, p.Arch)
		}
		if p.MemoryMB > 0 {
			tags = append(tags, decimal(p.MemoryMB)+" MB")
		}
		if p.CPUPct != nil {
			tags = append(tags, "CPU "+decimal(*p.CPUPct)+" %")
		}
		line := fmt.Sprintf("%s (PID %d", p.Name, p.PID)
		if p.ParentPID != 0 {
			line += fmt.Sprintf(", padre %d", p.ParentPID)
		}
		line += ")"
		if len(tags) > 0 {
			line += " · " + strings.Join(tags, ", ")
		}
		fmt.Println(line)
		if len(p.Services) > 0 {
			fmt.Println("  Servizi: " + strings.Join(p.Services, ", "))
		}
		if f := p.File; f != nil {
			where := f.Path
			if t := folderText[f.Folder]; t != "" {
				where += " (" + t + ")"
			}
			fmt.Println("  File: " + where)
			st := signatureText(f) // comincia sempre con una lettera ASCII
			fmt.Println("  " + strings.ToUpper(st[:1]) + st[1:])
			var about []string
			if f.Description != "" {
				about = append(about, f.Description)
			}
			if f.Company != "" {
				about = append(about, f.Company)
			}
			if f.Version != "" {
				about = append(about, "versione "+f.Version)
			}
			if len(about) > 0 {
				fmt.Println("  Dichiarato dal file: " + strings.Join(about, " · "))
			}
		}
		if len(p.Listen) > 0 {
			fmt.Println("  In ascolto: " + listenText(p.Listen))
		}
		if p.Conns != nil {
			fmt.Println("  Connessioni: " + connsText(p.Conns))
		}
	}
	fmt.Println()
	fmt.Println("La revoca dei certificati non è controllata (nessun accesso alla rete). Polaris legge")
	fmt.Println("soltanto: non termina processi e non chiude connessioni; gli indirizzi remoti non si")
	fmt.Println("mostrano. Per vederli c'è TCPView di Microsoft Sysinternals.")
}
