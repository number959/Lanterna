// LANterna: diagnostica della rete locale per Windows.
//
//	LANterna.exe                       finestra con l'interfaccia completa
//	LANterna.exe report [opzioni]      analisi e rapporto testuale
//	LANterna.exe serve [opzioni]       interfaccia nel browser (http://127.0.0.1:8737)
//	LANterna.exe version
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"lanterna/internal/assets"
	"lanterna/internal/collect"
	"lanterna/internal/engine"
	"lanterna/internal/gui"
	"lanterna/internal/scan"
	"lanterna/internal/server"
)

// version viene impostata in fase di build (-ldflags "-X main.version=...").
var version = "dev"

const usage = `LANterna %s - diagnostica della rete locale

Uso:
  LANterna                       apre la finestra con l'interfaccia completa
  LANterna report [opzioni]      esegue l'analisi e stampa il rapporto
      --json                     stampa i dati grezzi (JSON) invece del testo
      --verbose                  include spiegazioni e passi di ogni azione
      --out FILE                 scrive su file invece che a schermo
      --input FILE               analizza un rapporto JSON salvato invece di misurare
      --quick                    analisi rapida (meno ping, niente nuova scansione Wi-Fi)
  LANterna serve [opzioni]       interfaccia nel browser
      --port N                   porta locale (predefinita 8737)
      --open                     apre il browser automaticamente
  LANterna version               versione del programma e del motore
`

func newCollector(quick bool) *collect.Collector {
	opt := collect.DefaultOptions
	if quick {
		opt.PingCount, opt.Rescan, opt.UpnpWait = 8, false, 1500*time.Millisecond
	}
	return &collect.Collector{Platform: collect.Native{}, Net: collect.RealNetwork, Opt: opt, Version: version}
}

func main() {
	args := os.Args[1:]
	if len(args) > 0 {
		attachConsole()
	}
	var err error
	switch {
	case len(args) == 0:
		err = runWindow()
	case args[0] == "report":
		err = runReport(args[1:])
	case args[0] == "serve":
		err = runServe(args[1:])
	case args[0] == "version" || args[0] == "--version":
		eng, e := engine.Load(nil)
		ev := "non incluso"
		if e == nil {
			ev = eng.Version()
		}
		fmt.Printf("LANterna %s (motore di analisi %s)\n", version, ev)
	case args[0] == "help" || args[0] == "--help" || args[0] == "-h" || args[0] == "/?":
		fmt.Printf(usage, version)
	default:
		fmt.Fprintf(os.Stderr, "comando sconosciuto: %s\n\n", args[0])
		fmt.Fprintf(os.Stderr, usage, version)
		os.Exit(2)
	}
	if err != nil {
		if len(args) == 0 {
			gui.Error(err.Error())
		}
		fmt.Fprintln(os.Stderr, "Errore:", err)
		os.Exit(1)
	}
}

func runReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "")
	verbose := fs.Bool("verbose", false, "")
	out := fs.String("out", "", "")
	input := fs.String("input", "", "")
	quick := fs.Bool("quick", false, "")
	fs.Usage = func() { fmt.Fprintf(os.Stderr, usage, version) }
	if err := fs.Parse(args); err != nil {
		return err
	}
	var data []byte
	if *input != "" {
		b, err := os.ReadFile(*input)
		if err != nil {
			return err
		}
		var s scan.Scan
		if err := json.Unmarshal(b, &s); err != nil || s.Schema == 0 {
			return fmt.Errorf("%s non è un rapporto JSON di LANterna", *input)
		}
		data = b
	} else {
		fmt.Fprintln(os.Stderr, "Analisi della rete in corso (circa 20 secondi)...")
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()
		var mu sync.Mutex
		shown := map[string]bool{}
		s := newCollector(*quick).Run(ctx, func(steps []collect.Step) {
			mu.Lock()
			defer mu.Unlock()
			for _, st := range steps {
				if (st.State == "done" || st.State == "error") && !shown[st.ID] {
					shown[st.ID] = true
					mark := "ok"
					if st.State == "error" {
						mark = "non riuscita"
					}
					fmt.Fprintf(os.Stderr, "  - %-36s %s\n", st.Label, mark)
				}
			}
		})
		data, _ = json.MarshalIndent(s, "", "  ")
	}
	var text string
	if *asJSON {
		text = string(data) + "\n"
	} else {
		eng, err := engine.Load(nil)
		if err != nil {
			return err
		}
		if text, err = eng.Report(data, *verbose); err != nil {
			return fmt.Errorf("motore di analisi: %w", err)
		}
	}
	if *out != "" {
		// BOM UTF-8: il Blocco note e Excel riconoscono subito le lettere accentate.
		content := text
		if !*asJSON {
			content = "\ufeff" + strings.ReplaceAll(text, "\n", "\r\n")
		}
		if err := os.WriteFile(*out, []byte(content), 0o644); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "Rapporto salvato in", *out)
		return nil
	}
	fmt.Print(text)
	return nil
}

func startServer(port int) (*server.Server, string, error) {
	if !assets.Ready() {
		return nil, "", errors.New("questa build non include l'interfaccia web (usa scripts/build-windows.sh)")
	}
	ln, err := server.Listen(port)
	if err != nil {
		return nil, "", fmt.Errorf("porta %d non disponibile: %w", port, err)
	}
	c := newCollector(false)
	srv := &server.Server{Collector: c, Web: assets.Web(), Version: version, Ping: c.QuickPing}
	httpSrv := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = httpSrv.Serve(ln) }()
	return srv, "http://" + ln.Addr().String() + "/", nil
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	port := fs.Int("port", 8737, "")
	open := fs.Bool("open", false, "")
	fs.Usage = func() { fmt.Fprintf(os.Stderr, usage, version) }
	if err := fs.Parse(args); err != nil {
		return err
	}
	_, url, err := startServer(*port)
	if err != nil {
		return err
	}
	fmt.Printf("LANterna è in ascolto su %s (Ctrl+C per terminare)\n", url)
	if *open {
		go gui.Fallback(url)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	<-ctx.Done()
	return nil
}

func runWindow() error {
	srv, url, err := startServer(0)
	if err != nil {
		return err
	}
	srv.Start() // l'analisi parte subito, mentre la finestra si apre
	if err := gui.Run(url); errors.Is(err, gui.ErrNoWebView2) {
		gui.Fallback(url)
		return nil
	} else if err != nil {
		return err
	}
	return nil
}
