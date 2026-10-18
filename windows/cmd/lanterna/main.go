// STARNET Polaris: diagnostica di PC e rete per Windows.
//
//	Polaris.exe                        finestra con l'interfaccia completa
//	polaris-cli.exe report [opzioni]   analisi e rapporto testuale
//	polaris-cli.exe serve [opzioni]    interfaccia nel browser (http://127.0.0.1:8737)
//	polaris-cli.exe bench cpu|disk     test di velocità del processore o di un'unità
//	polaris-cli.exe version
//
// Polaris.exe è compilato come applicazione grafica, polaris-cli.exe per la
// console: accettano gli stessi comandi.
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
	"lanterna/internal/bench"
	"lanterna/internal/collect"
	"lanterna/internal/engine"
	"lanterna/internal/gui"
	"lanterna/internal/infra"
	"lanterna/internal/pcinfo"
	"lanterna/internal/probe"
	"lanterna/internal/scan"
	"lanterna/internal/server"
	"lanterna/internal/winapi"
)

// version viene impostata in fase di build (-ldflags "-X main.version=...").
var version = "dev"

const usage = `STARNET Polaris %s - diagnostica di PC e rete

Uso:
  Polaris                        apre la finestra con l'interfaccia completa
  polaris-cli report [opzioni]   esegue l'analisi e stampa il rapporto
      --json                     stampa i dati grezzi (JSON) invece del testo
      --verbose                  include spiegazioni e passi di ogni azione
      --out FILE                 scrive su file invece che a schermo
      --input FILE               analizza un rapporto JSON salvato invece di misurare
      --quick                    analisi rapida (meno ping, niente nuova scansione Wi-Fi)
  polaris-cli serve [opzioni]    interfaccia nel browser
      --port N                   porta locale (predefinita 8737)
      --open                     apre il browser automaticamente
  polaris-cli bench cpu          test di velocità del processore (circa 25 secondi)
  polaris-cli bench disk         test di velocità di un'unità (fino a 35 secondi):
      --drive X:                 unità da provare (predefinita quella di sistema)
                                 scrive un file temporaneo, cancellato alla fine
  polaris-cli bench ... --json   stampa il risultato in JSON
  polaris-cli bench ... --quick  versione breve, per le verifiche automatiche
  polaris-cli version            versione del programma e del motore
`

func newCollector(quick bool) *collect.Collector {
	opt := collect.DefaultOptions
	if quick {
		opt.PingCount, opt.Rescan, opt.UpnpWait = 8, false, 1500*time.Millisecond
	}
	return &collect.Collector{Platform: collect.Native{}, Net: collect.RealNetwork, Opt: opt, Version: version}
}

func main() {
	// La verifica HTTPS passa dal proxy di sistema, come il browser
	// (le variabili d'ambiente, se presenti, hanno la precedenza).
	if p := winapi.SystemProxy(); p != nil && !probe.EnvProxySet() {
		probe.HTTPProxy = p
	}
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
	case args[0] == "bench":
		err = runBench(args[1:])
	case args[0] == "version" || args[0] == "--version":
		eng, e := engine.Load(nil)
		ev := "non incluso"
		if e == nil {
			ev = eng.Version()
		}
		wv := gui.RuntimeVersion()
		if wv == "" {
			wv = "non installato (l'interfaccia si aprirà nel browser)"
		}
		fmt.Printf("STARNET Polaris %s (motore di analisi %s)\nWebView2: %s\n", version, ev, wv)
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
			return fmt.Errorf("%s non è un rapporto JSON di STARNET Polaris", *input)
		}
		data = b
	} else {
		fmt.Fprintln(os.Stderr, "Analisi di PC e rete in corso (circa 25 secondi)...")
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
	prims := infra.Native()
	srv := &server.Server{Collector: c, Web: assets.Web(), Version: version, Ping: c.QuickPing, Infra: &prims, InfraOpt: infra.Prudent,
		BenchCPU: func(ctx context.Context, r bench.Report) (*scan.CPUBench, error) {
			return bench.CPU(ctx, cpuOptions(false), r)
		},
		BenchDisk: func(ctx context.Context, drive string, r bench.Report) (*scan.DiskBench, error) {
			return runDiskBench(ctx, drive, false, r)
		},
		BenchDrive: func(drive string) error {
			_, err := bench.DirFor(drive)
			return err
		},
	}
	httpSrv := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = httpSrv.Serve(ln) }()
	return srv, "http://" + ln.Addr().String() + "/", nil
}

func cpuOptions(quick bool) bench.CPUOptions {
	opt := bench.DefaultCPU
	if quick {
		opt = bench.QuickCPU
	}
	opt.Load, opt.OnAC = pcinfo.CPULoad, pcinfo.OnAC
	return opt
}

func runDiskBench(ctx context.Context, drive string, quick bool, r bench.Report) (*scan.DiskBench, error) {
	d, err := bench.NormalizeDrive(drive)
	if err != nil {
		return nil, err
	}
	dir, err := bench.DirFor(d)
	if err != nil {
		return nil, err
	}
	opt := bench.DefaultDisk
	if quick {
		opt = bench.QuickDisk
	}
	opt.Drive, opt.Dir = d, dir
	return bench.Disk(ctx, opt, r)
}

func runBench(args []string) error {
	if len(args) == 0 || (args[0] != "cpu" && args[0] != "disk") {
		return errors.New("specificare cpu oppure disk (polaris-cli bench cpu)")
	}
	kind := args[0]
	fs := flag.NewFlagSet("bench", flag.ContinueOnError)
	drive := fs.String("drive", os.Getenv("SystemDrive"), "")
	asJSON := fs.Bool("json", false, "")
	quick := fs.Bool("quick", false, "")
	fs.Usage = func() { fmt.Fprintf(os.Stderr, usage, version) }
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	phase := ""
	report := func(p bench.Progress) {
		if p.Phase != phase && p.Phase != "done" {
			phase = p.Phase
			fmt.Fprintf(os.Stderr, "  - %s\n", benchPhaseLabel(p.Phase))
		}
	}
	var out any
	var text string
	if kind == "cpu" {
		fmt.Fprintln(os.Stderr, "Test del processore in corso (Ctrl+C per interrompere)...")
		res, err := bench.CPU(ctx, cpuOptions(*quick), report)
		if err != nil {
			return err
		}
		out = res
		text = fmt.Sprintf("Processore, %d thread\n  un thread:       %.1f MB/s\n  tutti i thread:  %.1f MB/s (punta), %.1f MB/s (prolungata)\n",
			res.Threads, res.SingleMBs, res.MultiMBs, res.SustainedMBs)
	} else {
		if *drive == "" {
			*drive = "C:"
		}
		fmt.Fprintf(os.Stderr, "Test dell'unità %s in corso: scrive un file temporaneo, cancellato alla fine (Ctrl+C per interrompere)...\n", strings.ToUpper(*drive))
		res, err := runDiskBench(ctx, *drive, *quick, report)
		if err != nil {
			return err
		}
		out = res
		text = fmt.Sprintf("Unità %s (file di %d MB)\n  sequenziale:  lettura %.1f MB/s, scrittura %.1f MB/s\n  casuale 4K:   lettura %.1f MB/s (%.0f IOPS), scrittura %.1f MB/s (%.0f IOPS)\n",
			res.Drive, res.FileMB, res.SeqReadMBs, res.SeqWriteMBs, res.RndReadMBs, res.RndReadIOPS, res.RndWriteMBs, res.RndWriteIOPS)
		if res.Note != "" {
			text += "  " + res.Note + "\n"
		}
	}
	if *asJSON {
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	fmt.Print(text)
	return nil
}

func benchPhaseLabel(p string) string {
	switch p {
	case "load":
		return "carico attuale del processore"
	case "single":
		return "un thread"
	case "multi":
		return "tutti i thread"
	case "seq-write":
		return "scrittura sequenziale"
	case "seq-read":
		return "lettura sequenziale"
	case "rnd-read":
		return "lettura casuale 4K"
	case "rnd-write":
		return "scrittura casuale 4K"
	}
	return p
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
	fmt.Printf("STARNET Polaris è in ascolto su %s (Ctrl+C per terminare)\n", url)
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
