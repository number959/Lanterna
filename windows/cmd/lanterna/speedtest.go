package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"

	"lanterna/internal/collect"
	"lanterna/internal/probe"
	"lanterna/internal/scan"
	"lanterna/internal/speedtest"
)

// speedOptions collega il test alle sonde di latenza dell'agente (echo ICMP
// verso il primo server pubblico dell'analisi, o connessioni TCP se i ping
// sono bloccati) e al proxy di sistema, come la verifica HTTPS.
func speedOptions(c *collect.Collector) speedtest.Options {
	target := collect.InternetTargets[0].IP
	return speedtest.Options{
		Version:     version,
		Proxy:       probe.HTTPProxy,
		ProbeTarget: target,
		Ping: func(ctx context.Context, tcp bool) *float64 {
			return c.QuickPing(ctx, target, []int{443, 53}, tcp)
		},
	}
}

// runSpeedTest esegue il test di velocità con M-Lab solo con --accetto:
// senza, mostra il testo del consenso e non si collega a nulla.
func runSpeedTest(args []string) error {
	fs := flag.NewFlagSet("speedtest", flag.ContinueOnError)
	accept := fs.Bool("accetto", false, "")
	asJSON := fs.Bool("json", false, "")
	fs.Usage = func() { fmt.Fprintf(os.Stderr, usage, version) }
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("argomento non previsto: %s", fs.Arg(0))
	}
	if !*accept {
		printConsent(os.Stdout)
		return nil
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	opt := speedOptions(newCollector(false))
	if !*asJSON {
		fmt.Fprintln(os.Stderr, "Test di velocità con M-Lab (circa 30 secondi, Ctrl+C per fermare)...")
		opt.Progress = func(p speedtest.Progress) { fmt.Fprintf(os.Stderr, "\r  %-60s", progressText(p)) }
	}
	res, err := speedtest.Run(ctx, opt)
	if !*asJSON {
		fmt.Fprintln(os.Stderr)
	}
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return errors.New("test interrotto")
		}
		return err
	}
	if *asJSON {
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	printSpeed(os.Stdout, res)
	return nil
}

func printConsent(w io.Writer) {
	fmt.Fprintln(w, speedtest.ConsentTitle+" (Measurement Lab, M-Lab)")
	fmt.Fprintln(w)
	for _, p := range speedtest.ConsentText {
		fmt.Fprintln(w, wrapText(p, 78, ""))
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, wrapText("Il test parte solo se dichiari: «"+speedtest.ConsentCheck+"». Per farlo, esegui:", 78, ""))
	fmt.Fprintln(w, "  polaris-cli speedtest --accetto")
	fmt.Fprintln(w, "Il consenso vale per un solo test.")
}

var phaseText = map[string]string{
	speedtest.PhaseLocate:   "Scelta del server di M-Lab",
	speedtest.PhaseIdle:     "Latenza a riposo",
	speedtest.PhaseDownload: "Download",
	speedtest.PhaseUpload:   "Upload",
}

func progressText(p speedtest.Progress) string {
	s := phaseText[p.Phase]
	if p.Mbps > 0 {
		s += ": " + mbpsText(p.Mbps)
	}
	if p.LatencyMs != nil {
		s += ", latenza " + msText(*p.LatencyMs)
	}
	return s
}

// Città dei server di M-Lab più vicini all'Italia, come le scrive Locate.
var cityIt = map[string]string{
	"Milan": "Milano", "Rome": "Roma", "Turin": "Torino", "Naples": "Napoli", "Florence": "Firenze", "Venice": "Venezia",
	"Genoa": "Genova", "Zurich": "Zurigo", "Geneva": "Ginevra", "Munich": "Monaco di Baviera", "Frankfurt": "Francoforte",
	"Paris": "Parigi", "Marseille": "Marsiglia", "London": "Londra", "Lisbon": "Lisbona", "Brussels": "Bruxelles",
	"Athens": "Atene", "Prague": "Praga", "Warsaw": "Varsavia", "Copenhagen": "Copenaghen", "Stockholm": "Stoccolma",
}

func serverText(s *scan.SpeedServer) string {
	if s == nil {
		return "—"
	}
	city := s.City
	if it, ok := cityIt[city]; ok {
		city = it
	}
	out := city
	if s.Country != "" {
		out = strings.TrimPrefix(out+", "+s.Country, ", ")
	}
	if s.Site != "" {
		out += " (" + s.Site + ")"
	}
	if out == "" {
		return "server di M-Lab"
	}
	return out
}

// Soglie del bufferbloat scelte da Polaris, le stesse del motore
// (core/src/engine/speedtest.ts): fino a 30 ms in più va bene, oltre 100 è alto.
func bloatGrade(ms float64) string {
	switch {
	case ms < 30:
		return "contenuta"
	case ms <= 100:
		return "da migliorare"
	}
	return "alta"
}

func printSpeed(w io.Writer, r *scan.SpeedTest) {
	fmt.Fprintln(w, "Test di velocità di Internet con M-Lab (ndt7, una connessione per verso)")
	fmt.Fprintf(w, "Server: %s\n", serverText(r.Server))
	dir := func(name string, d *scan.SpeedDir) {
		if d == nil {
			return
		}
		if d.Bytes == 0 && d.Error != "" {
			fmt.Fprintf(w, "%-9s non riuscito: %s\n", name+":", strings.TrimPrefix(d.Error, "upload non riuscito: "))
			return
		}
		note := ""
		if d.Capped {
			note = ", fermato al limite di 250 MB"
		}
		fmt.Fprintf(w, "%-9s %s (%s in %s%s)\n", name+":", mbpsText(d.Mbps), bytesText(d.Bytes), secondsText(d.Ms), note)
		if d.Error != "" {
			fmt.Fprintf(w, "          %s\n", d.Error)
		}
	}
	dir("Download", r.Download)
	dir("Upload", r.Upload)
	if r.Idle != nil && r.Idle.MedianMs != nil {
		how := "ping"
		if r.ProbeMethod == "tcp" {
			how = "connessioni TCP"
		}
		fmt.Fprintf(w, "Latenza a riposo: %s (mediana, %s verso %s)\n", msText(*r.Idle.MedianMs), how, r.Probe)
		worst := -1.0
		for _, x := range []struct {
			name string
			d    *scan.SpeedDir
		}{{"durante il download", r.Download}, {"durante l'upload", r.Upload}} {
			if x.d == nil || x.d.Latency == nil || x.d.Latency.MedianMs == nil || x.d.BloatMs == nil {
				continue
			}
			lost := ""
			if l := x.d.Latency; l.Sent > l.Received {
				lost = fmt.Sprintf(", %d su %d senza risposta", l.Sent-l.Received, l.Sent)
			}
			fmt.Fprintf(w, "Latenza %s: %s (+%s; 95° percentile +%s%s)\n", x.name, msText(*x.d.Latency.MedianMs), msText(*x.d.BloatMs), msText(*x.d.BloatP95Ms), lost)
			worst = max(worst, *x.d.BloatMs)
		}
		if worst >= 0 {
			fmt.Fprintf(w, "Latenza sotto carico (bufferbloat): %s, +%s nel caso peggiore (soglie di Polaris: sotto 30 ms va bene, oltre 100 ms è alta)\n", bloatGrade(worst), msText(worst))
		}
	} else {
		fmt.Fprintln(w, "Latenza: non misurata (nessuna risposta né ai ping né alle connessioni TCP)")
	}
	if d := r.Download; d != nil && d.MinRTTMs != nil {
		fmt.Fprintf(w, "Tempo di andata e ritorno minimo verso il server: %s\n", msText(*d.MinRTTMs))
	}
	if d := r.Download; d != nil && d.RetransPct != nil {
		fmt.Fprintf(w, "Dati ritrasmessi in download: %s %%\n", strings.Replace(strconv.FormatFloat(*d.RetransPct, 'f', 1, 64), ".", ",", 1))
	}
	if r.ViaProxy {
		fmt.Fprintln(w, "Il test è passato dal proxy: misura il percorso attraverso il proxy, non solo la linea.")
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, wrapText(speedtest.LegalNote, 78, ""))
	fmt.Fprintln(w, wrapText("Su linee molto veloci (da 2,5 Gbit/s in su) una sola connessione dà spesso valori più bassi dei test con più connessioni in parallelo.", 78, ""))
}

func mbpsText(v float64) string {
	dec := 0
	if v < 100 {
		dec = 1
	}
	if v < 10 {
		dec = 2
	}
	return strings.Replace(strconv.FormatFloat(v, 'f', dec, 64), ".", ",", 1) + " Mbit/s"
}

func msText(v float64) string {
	if v < 10 {
		return strings.Replace(strconv.FormatFloat(v, 'f', 1, 64), ".", ",", 1) + " ms"
	}
	return strconv.FormatFloat(v, 'f', 0, 64) + " ms"
}

// wrapText va a capo entro width colonne, con indent all'inizio delle righe successive.
func wrapText(s string, width int, indent string) string {
	var b strings.Builder
	line := 0
	for i, word := range strings.Fields(s) {
		n := len([]rune(word))
		if i > 0 && line+1+n > width {
			b.WriteString("\n" + indent)
			line = len(indent)
		} else if i > 0 {
			b.WriteByte(' ')
			line++
		}
		b.WriteString(word)
		line += n
	}
	return b.String()
}
