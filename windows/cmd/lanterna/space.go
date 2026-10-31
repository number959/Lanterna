package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"lanterna/internal/scan"
	"lanterna/internal/space"
	"lanterna/internal/winapi"
)

// runSpace mostra cosa occupa spazio in un'unità o in una cartella, come
// WizTree: cartelle principali, file più grandi, categorie e cartelle note.
// Legge solo l'elenco dei file, non il loro contenuto, e non cancella nulla.
func runSpace(args []string) error {
	fs := flag.NewFlagSet("space", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "")
	top := fs.Int("top", 20, "")
	fs.Usage = func() { fmt.Fprintf(os.Stderr, usage, version) }
	// L'unità può stare prima o dopo le opzioni.
	root := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		root, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 1 || root != "" && fs.NArg() > 0 {
		return errors.New("indicare una sola unità o cartella")
	}
	if fs.NArg() == 1 {
		root = fs.Arg(0)
	}
	if root == "" {
		root = os.Getenv("SystemDrive")
		if root == "" {
			root = "C:"
		}
	}
	if *top < 0 || *top > 100 {
		return errors.New("--top deve essere tra 0 e 100")
	}
	root, err := space.Normalize(root)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	opt := space.Options{TopFiles: 100}
	if !*asJSON {
		fmt.Fprintf(os.Stderr, "Analisi dello spazio di %s (Ctrl+C per fermare)...\n", root)
		opt.Progress = func(p space.Progress) {
			fmt.Fprintf(os.Stderr, "\r  %s cartelle, %s file, %s   ", thousands(p.Dirs), thousands(p.Files), bytesText(p.Alloc))
		}
	}
	res, err := space.Scan(ctx, root, opt)
	if !*asJSON {
		fmt.Fprintln(os.Stderr)
	}
	if res == nil {
		return err
	}
	if *asJSON {
		b, _ := json.MarshalIndent(res.Report, "", "  ")
		fmt.Println(string(b))
	} else {
		printSpace(&res.Report, *top, winapi.Elevated())
	}
	if errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "Analisi interrotta: i valori sono parziali.")
		return nil
	}
	return err
}

func printSpace(r *scan.SpaceReport, top int, elevated bool) {
	fs := ""
	if r.FS != "" {
		fs = " (" + r.FS + ")"
	}
	fmt.Printf("Cosa occupa spazio in %s%s\n", r.Root, fs)
	if r.TotalBytes > 0 {
		fmt.Printf("Unità %s %s in tutto, liberi %s (%s)\n", r.Drive, bytesText(r.TotalBytes), bytesText(r.FreeBytes), pct(r.FreeBytes, r.TotalBytes))
	}
	fmt.Printf("Occupati %s da %s file in %s cartelle (dati: %s), letti in %s\n",
		bytesText(r.AllocBytes), thousands(r.Files), thousands(r.Dirs), bytesText(r.SizeBytes), secondsText(r.DurationMs))
	if r.Partial {
		fmt.Println("Analisi incompleta: i valori sono parziali.")
	}
	if r.LinkedBytes > 0 {
		fmt.Printf("Collegamenti fisici contati una volta sola: %s (file di Windows con più nomi, come in WinSxS).\n", bytesText(r.LinkedBytes))
	}
	if r.CloudFiles > 0 {
		fmt.Printf("File solo online: %s, %s nel cloud, quasi nulla su questo disco.\n", thousands(r.CloudFiles), bytesText(r.CloudBytes))
	}
	if r.Denied > 0 {
		if elevated {
			fmt.Printf("Cartelle riservate al sistema, non leggibili nemmeno da amministratore: %s.\n", thousands(r.Denied))
		} else {
			fmt.Printf("Cartelle non leggibili con i permessi attuali: %s (da amministratore se ne leggono di più).\n", thousands(r.Denied))
		}
	}
	if r.Errors > 0 {
		fmt.Printf("Cartelle non lette per errori del disco o del file system: %s.\n", thousands(r.Errors))
	}
	if un := unattributed(r); un > 0 {
		fmt.Printf("Spazio occupato non attribuito a file leggibili: %s (cartelle protette, metadati del file system, copie shadow).\n", bytesText(un))
	}

	if t := r.Tree; t != nil && (len(t.Children) > 0 || t.OwnFiles > 0) {
		fmt.Println("\nCartelle principali")
		for _, c := range t.Children {
			note := ""
			if c.Denied {
				note = "  (in parte non leggibile)"
			}
			fmt.Printf("  %-34s %10s %7s  %s file%s\n", clip(c.Name, 34), bytesText(c.Alloc), pct(c.Alloc, r.AllocBytes), thousands(c.Files), note)
		}
		if t.More != nil {
			fmt.Printf("  %-34s %10s %7s\n", fmt.Sprintf("altre %s cartelle", thousands(t.More.Dirs)), bytesText(t.More.Alloc), pct(t.More.Alloc, r.AllocBytes))
		}
		if t.OwnFiles > 0 {
			fmt.Printf("  %-34s %10s %7s  %s file\n", "(file nella cartella stessa)", bytesText(t.OwnAlloc), pct(t.OwnAlloc, r.AllocBytes), thousands(t.OwnFiles))
		}
	}

	if top > 0 && len(r.TopFiles) > 0 {
		fmt.Println("\nFile più grandi")
		for i, f := range r.TopFiles {
			if i == top {
				break
			}
			note := ""
			if f.Cloud {
				note = "  (solo online)"
			}
			fmt.Printf("  %10s  %s%s\n", bytesText(f.Alloc), f.Path, note)
		}
	}

	if len(r.Categories) > 0 {
		fmt.Println("\nPer tipo di file")
		for _, c := range r.Categories {
			label := space.CategoryLabels[c.ID]
			if label == "" {
				label = c.ID
			}
			fmt.Printf("  %-34s %10s %7s  %s file\n", label, bytesText(c.Alloc), pct(c.Alloc, r.AllocBytes), thousands(c.Files))
		}
	}

	if len(r.Hints) > 0 {
		fmt.Println("\nCartelle e file noti")
		for _, h := range r.Hints {
			label := space.HintLabels[h.ID]
			if label == "" {
				label = h.ID
			}
			where := ""
			if h.Path != "" {
				where = "  " + h.Path
			}
			fmt.Printf("  %-50s %10s%s\n", label, bytesText(h.Alloc), where)
		}
		fmt.Println("\nCosa si può liberare e come, senza rischi: nell'interfaccia (PC > Cosa occupa spazio)")
		fmt.Println("e nella guida \"Cosa occupa spazio\" (Guide > Il computer). Polaris non cancella nulla.")
	}
}

// unattributed è lo spazio occupato sull'unità che l'analisi non ha
// trovato nei file leggibili; ha senso solo per un'analisi completa della
// radice.
func unattributed(r *scan.SpaceReport) int64 {
	if r.Partial || r.TotalBytes <= 0 || len(r.Root) != 3 {
		return 0
	}
	un := r.TotalBytes - r.FreeBytes - r.AllocBytes
	// Sotto l'1 % del disco è rumore (metadati, arrotondamenti).
	if un < r.TotalBytes/100 {
		return 0
	}
	return un
}

// bytesText scrive una dimensione in unità decimali (1 GB = 10^9 byte, come
// le altre schede di Polaris), con la virgola: "380,2 GB".
func bytesText(b int64) string {
	if b < 1000 {
		return strconv.FormatInt(max(b, 0), 10) + " B"
	}
	units := []string{"KB", "MB", "GB", "TB", "PB"}
	v := float64(b) / 1000
	i := 0
	for v >= 999.95 && i < len(units)-1 {
		v /= 1000
		i++
	}
	return strings.Replace(strconv.FormatFloat(v, 'f', 1, 64), ".", ",", 1) + " " + units[i]
}

// thousands scrive un intero con il punto delle migliaia: "412.345".
func thousands(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte('.')
		}
		b.WriteRune(c)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

func pct(part, total int64) string {
	if total <= 0 {
		return ""
	}
	p := float64(part) / float64(total) * 100
	if p > 0 && p < 0.1 {
		return "<0,1 %"
	}
	return strings.Replace(strconv.FormatFloat(math.Round(p*10)/10, 'f', 1, 64), ".", ",", 1) + " %"
}

func secondsText(ms int64) string {
	if ms < 1000 {
		return "meno di un secondo"
	}
	s := (ms + 500) / 1000
	if s < 120 {
		return strconv.FormatInt(s, 10) + " s"
	}
	return fmt.Sprintf("%d min %d s", s/60, s%60)
}

// clip accorcia un nome lungo per la colonna, a carattere intero.
func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
