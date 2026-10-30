// STARNET Polaris: diagnostica di PC e rete per Windows.
//
//	Polaris.exe                        finestra con l'interfaccia completa
//	polaris-cli.exe report [opzioni]   analisi e rapporto testuale
//	polaris-cli.exe serve [opzioni]    interfaccia nel browser (http://127.0.0.1:8737)
//	polaris-cli.exe bench cpu|disk     test di velocità del processore o di un'unità
//	polaris-cli.exe defender ...       stato e scansioni di Microsoft Defender
//	polaris-cli.exe sensors            monitor dei sensori
//	polaris-cli.exe space [C:]         cosa occupa spazio su un'unità
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
	"maps"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"lanterna/internal/assets"
	"lanterna/internal/bench"
	"lanterna/internal/collect"
	"lanterna/internal/cpuclock"
	"lanterna/internal/defender"
	"lanterna/internal/engine"
	"lanterna/internal/gui"
	"lanterna/internal/infra"
	"lanterna/internal/pcinfo"
	"lanterna/internal/probe"
	"lanterna/internal/scan"
	"lanterna/internal/sensors"
	"lanterna/internal/server"
	"lanterna/internal/space"
	"lanterna/internal/tools"
	"lanterna/internal/winapi"
)

// version viene impostata in fase di build (-ldflags "-X main.version=...").
var version = "dev"

const usage = `STARNET Polaris %s - diagnostica di PC e rete

Uso:
  Polaris                        apre la finestra con l'interfaccia completa
  polaris-cli report [opzioni]   esegue l'analisi e stampa il rapporto
      --json                     stampa i dati grezzi (JSON) invece del testo
      --html                     documento stampabile sullo stato del PC (con --out)
      --verbose                  include spiegazioni e passi di ogni azione
      --out FILE                 scrive su file invece che a schermo
      --input FILE               analizza un rapporto JSON salvato invece di misurare
      --quick                    analisi rapida (meno ping, niente nuova scansione Wi-Fi)
  polaris-cli serve [opzioni]    interfaccia nel browser
      --port N                   porta locale (predefinita 8737)
      --open                     apre il browser automaticamente
  polaris-cli bench cpu          test di velocità del processore (circa 25 secondi)
  polaris-cli bench disk         test di velocità di un'unità (fino a 50 secondi),
                                 con il profilo di CrystalDiskMark:
      --drive X:                 unità da provare (predefinita quella di sistema)
                                 scrive un file temporaneo, cancellato alla fine
  polaris-cli bench ... --json   stampa il risultato in JSON
  polaris-cli bench ... --quick  versione breve, per le verifiche automatiche
  polaris-cli defender status    stato di Microsoft Defender e minacce rilevate
  polaris-cli defender quick     scansione rapida con Microsoft Defender
  polaris-cli defender full      scansione completa (può durare ore)
  polaris-cli defender update    aggiornamento delle firme
  polaris-cli defender ... --json  stampa il risultato in JSON
  polaris-cli clock              frequenza effettiva dei core in tempo reale (Core Speed),
                                 una lettura al secondo:
      --seconds N                durata in secondi (predefinita 5)
      --json                     stampa le letture in JSON
  polaris-cli sensors            monitor dei sensori senza driver (come HWiNFO): utilizzo,
                                 frequenze, consumi esposti da Windows, zone termiche,
                                 scheda video, memoria, dischi, rete, batteria; alla fine
                                 attuale, minimo, massimo e media di ogni sensore
      --seconds N                durata in secondi, una lettura al secondo (predefinita 10)
      --all                      anche le righe di dettaglio (core, stati C, motori video)
      --csv FILE                 registra le letture in un file CSV per Excel, riga per riga
      --json                     stampa le letture in JSON
  polaris-cli space [C:|CARTELLA] cosa occupa spazio (come WizTree): cartelle principali,
                                 file più grandi, tipi di file, cartelle note di Windows;
                                 legge solo l'elenco dei file e non cancella nulla
      --top N                    quanti file più grandi mostrare (predefinito 20)
      --json                     stampa il risultato completo in JSON
  polaris-cli tools status       versioni portable scaricate (su questo PC e nel kit)
  polaris-cli tools kit [ID...]  prepara il kit per l'uso senza Internet: scarica dai
                                 siti ufficiali e verifica i programmi nella cartella
                                 strumenti-scaricati accanto a Polaris
      --all                      anche Microsoft Safety Scanner (oltre 200 MB,
                                 scade dopo 10 giorni)
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
	case args[0] == "defender":
		err = runDefender(args[1:])
	case args[0] == "tools":
		err = runTools(args[1:])
	case args[0] == "clock":
		err = runClock(args[1:])
	case args[0] == "sensors":
		err = runSensors(args[1:])
	case args[0] == "space":
		err = runSpace(args[1:])
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
	asHTML := fs.Bool("html", false, "")
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
	switch {
	case *asJSON:
		text = string(data) + "\n"
	case *asHTML:
		eng, err := engine.Load(nil)
		if err != nil {
			return err
		}
		if text, err = eng.Document(data, version, time.Now().Format("02/01/2006 alle 15:04")); err != nil {
			return fmt.Errorf("motore di analisi: %w", err)
		}
	default:
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
		if !*asJSON && !*asHTML {
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
	fetcher := newFetcher()
	clock := cpuclock.New()
	mon := sensors.New()
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
		DefenderRun:   defender.Run,
		DefenderReady: defender.Available,
		Tools:         tools.InstalledPrograms,
		Bundled:       tools.BundledPrograms,
		Portable:      fetcher.Find,
		FetchTool:     fetcher.Fetch,
		RemoveTool:    fetcher.Remove,
		FetchKit:      fetcher.FetchKit,
		KitCheck:      fetcher.KitCheck,
		CPUClock:      clock.Read,
		Sensors:       mon.Read,
		SpaceScan:     space.Scan,
		SpaceOpen:     space.Open,
		OpenTool:      func(id, target string) error { return tools.Open(id, target, fetcher) },
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
		row := func(label string, r, w float64) string {
			return fmt.Sprintf("  %-36s %9.1f MB/s %9.1f MB/s", label, r, w)
		}
		text = fmt.Sprintf("%-38s %14s %14s\n", fmt.Sprintf("Unità %s (file di %d MB)", res.Drive, res.FileMB), "lettura", "scrittura") +
			row("SEQ1M Q8T1  (sequenziale, 8 in coda)", res.SeqQ8ReadMBs, res.SeqQ8WriteMBs) + "\n" +
			row("SEQ1M Q1T1  (sequenziale)", res.SeqReadMBs, res.SeqWriteMBs) + "\n" +
			row("RND4K Q32T1 (casuale 4K, 32 in coda)", res.RndQ32ReadMBs, res.RndQ32WriteMBs) + fmt.Sprintf("  %.0f / %.0f IOPS\n", res.RndQ32ReadIOPS, res.RndQ32WriteIOPS) +
			row("RND4K Q1T1  (casuale 4K)", res.RndReadMBs, res.RndWriteMBs) + fmt.Sprintf("  %.0f / %.0f IOPS\n", res.RndReadIOPS, res.RndWriteIOPS)
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

var threatStatusText = map[string]string{
	"detected": "rilevata, da risolvere", "cleaned": "ripulita", "quarantined": "in quarantena", "removed": "rimossa",
	"allowed": "consentita", "blocked": "bloccata", "failed": "azione non riuscita", "unknown": "stato sconosciuto",
}

func printThreats(threats []scan.Threat) {
	if threats == nil {
		fmt.Println("Minacce: cronologia non leggibile (serve avviare come amministratore?)")
		return
	}
	if len(threats) == 0 {
		fmt.Println("Minacce: nessuna nella cronologia di Defender")
		return
	}
	fmt.Println("Minacce nella cronologia di Defender:")
	for _, t := range threats {
		day := t.Detected
		if len(day) >= 10 {
			day = day[:10]
		}
		active := ""
		if t.Active {
			active = ", ATTIVA"
		}
		fmt.Printf("  %s  %s (gravità %s): %s%s\n", day, t.Name, t.Severity, threatStatusText[t.Status], active)
	}
}

func runDefender(args []string) error {
	if len(args) == 0 {
		return errors.New("specificare status, quick, full oppure update (polaris-cli defender status)")
	}
	action := args[0]
	fs := flag.NewFlagSet("defender", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "")
	fs.Usage = func() { fmt.Fprintf(os.Stderr, usage, version) }
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if action == "status" {
		d, threats, err := pcinfo.DefenderStatus(ctx)
		if err != nil {
			return err
		}
		if *asJSON {
			b, _ := json.MarshalIndent(map[string]any{"defender": d, "threats": threats}, "", "  ")
			fmt.Println(string(b))
			return nil
		}
		age := func(p *int, never string) string {
			if p == nil {
				return never
			}
			return fmt.Sprintf("%d giorni fa", *p)
		}
		fmt.Printf("Microsoft Defender: modalità %s, protezione in tempo reale %v, protezione da manomissioni %v\n", d.Mode, onOff(d.RealTime), onOffPtr(d.TamperProtected))
		fmt.Printf("Firme: %s (%s); motore %s; piattaforma %s\n", d.SignatureVersion, age(d.SignatureAgeDays, "data sconosciuta"), d.EngineVersion, d.ProductVersion)
		fmt.Printf("Ultima scansione rapida: %s; completa: %s\n", age(d.QuickScanAgeDays, "mai"), age(d.FullScanAgeDays, "mai"))
		printThreats(threats)
		return nil
	}
	if _, err := defender.Args(action); err != nil {
		return err
	}
	label := map[string]string{defender.Quick: "Scansione rapida", defender.Full: "Scansione completa", defender.Update: "Aggiornamento delle firme"}[action]
	fmt.Fprintf(os.Stderr, "%s con Microsoft Defender in corso (Ctrl+C per interrompere)...\n", label)
	ctx, stop := context.WithTimeout(ctx, defender.Timeouts[action])
	defer stop()
	res, err := defender.Run(ctx, action)
	if err != nil {
		return err
	}
	if *asJSON {
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	fmt.Printf("%s (%d s)\n", res.Message, res.DurationMs/1000)
	if action != defender.Update {
		printThreats(res.Threats)
	}
	return nil
}

// runClock stampa la frequenza effettiva dei core una volta al secondo.
func runClock(args []string) error {
	fs := flag.NewFlagSet("clock", flag.ContinueOnError)
	seconds := fs.Int("seconds", 5, "")
	asJSON := fs.Bool("json", false, "")
	fs.Usage = func() { fmt.Fprintf(os.Stderr, usage, version) }
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *seconds < 1 || *seconds > 3600 {
		return errors.New("--seconds deve essere tra 1 e 3600")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	s := cpuclock.New()
	defer s.Close()
	var all []cpuclock.Sample
	for i := 0; i < *seconds; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Second):
			}
		}
		smp, err := s.Read(ctx)
		if err != nil {
			return err
		}
		if *asJSON {
			all = append(all, smp)
			continue
		}
		ratio := ""
		if smp.PerfPct > 0 {
			ratio = fmt.Sprintf(" (%.0f %% della base %.0f MHz)", smp.PerfPct, smp.BaseMHz)
		}
		fmt.Printf("Core Speed %.0f MHz%s; core più veloce %.0f MHz; carico %.0f %%; %d processori logici\n", smp.MHz, ratio, smp.MaxMHz, smp.LoadPct, len(smp.Cores))
	}
	if *asJSON {
		b, _ := json.MarshalIndent(all, "", "  ")
		fmt.Println(string(b))
	}
	return nil
}

// runSensors legge i sensori una volta al secondo e alla fine stampa il
// riepilogo, come le colonne di HWiNFO; con --csv registra ogni lettura. Il
// file si crea subito (un percorso sbagliato si scopre prima, non dopo ore) e
// si scrive riga per riga con le colonne della prima lettura, così resta su
// disco anche se il PC si blocca o si spegne; alla fine, se nel frattempo
// sono comparsi altri sensori, si riscrive completo.
func runSensors(args []string) error {
	fs := flag.NewFlagSet("sensors", flag.ContinueOnError)
	seconds := fs.Int("seconds", 10, "")
	all := fs.Bool("all", false, "")
	asJSON := fs.Bool("json", false, "")
	csvPath := fs.String("csv", "", "")
	fs.Usage = func() { fmt.Fprintf(os.Stderr, usage, version) }
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *seconds < 1 || *seconds > 86400 {
		return errors.New("--seconds deve essere tra 1 e 86400")
	}
	var csvFile *os.File
	if *csvPath != "" {
		f, err := os.Create(*csvPath)
		if err != nil {
			return fmt.Errorf("file CSV: %w", err)
		}
		csvFile = f
		defer csvFile.Close()
	}
	// SIGTERM arriva quando si chiude la finestra della console o ci si
	// disconnette: si salva comunque quanto letto.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	m := sensors.New()
	defer m.Close()
	reg := sensors.Log{KeepRows: csvFile != nil}
	var last sensors.Snapshot
	var readErr, csvErr error
	csvCols := 0
	if *asJSON {
		// Le letture si stampano man mano: nessun accumulo in memoria.
		fmt.Println("[")
	} else {
		fmt.Printf("Lettura dei sensori per %d s (Ctrl+C per fermare)...\n", *seconds)
	}
loop:
	for i := 0; i < *seconds; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				break loop
			case <-time.After(time.Second):
			}
		}
		snap, err := m.Read(ctx)
		if err != nil {
			readErr = err
			break
		}
		if *asJSON {
			b, _ := json.MarshalIndent(snap, "  ", "  ")
			sep := ","
			if reg.Len() == 0 {
				sep = ""
			}
			fmt.Printf("%s  %s\n", sep, b)
		}
		last = snap
		reg.Add(snap)
		if csvFile != nil {
			if reg.Len() == 1 {
				csvCols = reg.Columns()
				csvErr = reg.WriteHeader(csvFile, csvCols)
			}
			if csvErr == nil {
				csvErr = reg.WriteLastRow(csvFile, csvCols)
			}
			if csvErr != nil {
				readErr = fmt.Errorf("file CSV: %w", csvErr)
				break
			}
		}
	}
	if *asJSON {
		fmt.Println("]")
	}
	if reg.Len() == 0 {
		if readErr == nil {
			readErr = ctx.Err()
		}
		return readErr
	}
	if readErr != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "Lettura interrotta dopo %d letture: %v\n", reg.Len(), readErr)
	}
	if csvErr != nil {
		return readErr
	}
	if csvFile != nil {
		var werr error
		if reg.Columns() > csvCols {
			// Sensori comparsi dopo la prima lettura: si riscrive il file
			// completo, con tutte le colonne.
			if werr = csvFile.Truncate(0); werr == nil {
				if _, werr = csvFile.Seek(0, 0); werr == nil {
					werr = reg.WriteCSV(csvFile)
				}
			}
		}
		if cerr := csvFile.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return fmt.Errorf("file CSV: %w", werr)
		}
	}
	if *asJSON {
		return nil
	}
	group := ""
	for _, st := range reg.Stats() {
		if st.Detail && !*all {
			continue
		}
		if st.Group != group {
			group = st.Group
			fmt.Printf("\n%s\n", group)
		}
		cur := "-" // sparito prima dell'ultima lettura
		if st.Present {
			cur = sensors.Number(st.Cur)
		}
		fmt.Printf("  %-46s %10s %10s %10s %10s %s\n", st.Label, cur, sensors.Number(st.Min), sensors.Number(st.Max), sensors.Number(math.Round(st.Avg()*10)/10), st.Unit)
	}
	fmt.Printf("\n(colonne: attuale, minimo, massimo, media; %d letture)\n", reg.Len())
	for _, x := range last.Missing {
		fmt.Printf("Non disponibile: %s\n", x)
	}
	if csvFile != nil {
		fmt.Printf("Registro salvato in %s\n", *csvPath)
	}
	return nil
}

// newFetcher prepara i download delle versioni portable: dal sito ufficiale,
// passando dal proxy di sistema come il browser.
func newFetcher() *tools.Fetcher {
	return tools.NewFetcher("STARNET-Polaris/"+version, func(r *http.Request) (*url.URL, error) { return probe.HTTPProxy(r) })
}

func runTools(args []string) error {
	if len(args) == 0 {
		return errors.New("specificare status oppure kit (polaris-cli tools status)")
	}
	action := args[0]
	fs := flag.NewFlagSet("tools", flag.ContinueOnError)
	all := fs.Bool("all", false, "")
	fs.Usage = func() { fmt.Fprintf(os.Stderr, usage, version) }
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	f := newFetcher()
	ids := slices.Sorted(maps.Keys(tools.Portables))
	switch action {
	case "status":
		found := f.Find()
		for _, id := range ids {
			d, ok := found[id]
			switch {
			case !ok:
				fmt.Printf("  %-20s non scaricato\n", id)
			case d.Problem != "":
				fmt.Printf("  %-20s DA ELIMINARE: %s\n", id, d.Problem)
			default:
				where, expired := "su questo PC", ""
				if d.Kit {
					where = "nel kit"
				}
				if d.Expired {
					expired = "; SCADUTO, riscaricalo"
				}
				fmt.Printf("  %-20s %s, versione %s, firma di %s, scaricato il %s%s\n", id, where, d.Version, d.Signer, d.Date, expired)
			}
		}
		return nil
	case "kit":
		if fs.NArg() > 0 {
			ids = fs.Args()
		} else {
			ids = slices.DeleteFunc(ids, func(id string) bool {
				return tools.CanFetch(id, runtime.GOARCH) != nil || !*all && tools.Portables[id].ExpiresDays > 0
			})
		}
		for _, id := range ids {
			if err := tools.CanFetch(id, runtime.GOARCH); err != nil {
				return fmt.Errorf("%s: %w", id, err)
			}
		}
		if err := f.KitCheck(); err != nil {
			return err
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()
		fmt.Fprintf(os.Stderr, "Kit per l'uso senza Internet nella cartella %s accanto a Polaris (Ctrl+C per interrompere)\n", tools.KitName)
		var failed []string
		for _, id := range ids {
			var last time.Time
			d, err := f.FetchKit(ctx, id, func(done, total int64) {
				if time.Since(last) < time.Second {
					return
				}
				last = time.Now()
				if total > 0 {
					fmt.Fprintf(os.Stderr, "\r  %-20s %.1f di %.1f MB ", id, float64(done)/1e6, float64(total)/1e6)
				} else {
					fmt.Fprintf(os.Stderr, "\r  %-20s %.1f MB ", id, float64(done)/1e6)
				}
			})
			fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", 50))
			if err != nil {
				fmt.Printf("  %-20s NON RIUSCITO: %v\n", id, err)
				failed = append(failed, id)
				if ctx.Err() != nil {
					return errors.New("preparazione del kit interrotta")
				}
				continue
			}
			fmt.Printf("  %-20s pronto: versione %s, firma di %s verificata\n", id, d.Version, d.Signer)
		}
		if len(failed) > 0 {
			return fmt.Errorf("non riusciti: %s (riprova più tardi: il sito del produttore potrebbe non rispondere)", strings.Join(failed, ", "))
		}
		fmt.Printf("Kit pronto. Copia la cartella di Polaris, compresa %s, su una chiavetta: sui PC senza Internet Polaris usa questi programmi dopo averne verificato la firma.\n", tools.KitName)
		return nil
	}
	return errors.New("specificare status oppure kit (polaris-cli tools status)")
}

func onOff(b bool) string {
	if b {
		return "attiva"
	}
	return "disattivata"
}

func onOffPtr(b *bool) string {
	if b == nil {
		return "non riportata"
	}
	return onOff(*b)
}

func benchPhaseLabel(p string) string {
	switch p {
	case "load":
		return "carico attuale del processore"
	case "single":
		return "un thread"
	case "multi":
		return "tutti i thread"
	case "prep":
		return "preparazione del file di prova"
	case "seq-q8-read":
		return "lettura sequenziale, 8 richieste in coda (SEQ1M Q8T1)"
	case "seq-read":
		return "lettura sequenziale (SEQ1M Q1T1)"
	case "rnd-q32-read":
		return "lettura casuale 4K, 32 richieste in coda (RND4K Q32T1)"
	case "rnd-read":
		return "lettura casuale 4K (RND4K Q1T1)"
	case "seq-q8-write":
		return "scrittura sequenziale, 8 richieste in coda (SEQ1M Q8T1)"
	case "seq-write":
		return "scrittura sequenziale (SEQ1M Q1T1)"
	case "rnd-q32-write":
		return "scrittura casuale 4K, 32 richieste in coda (RND4K Q32T1)"
	case "rnd-write":
		return "scrittura casuale 4K (RND4K Q1T1)"
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
