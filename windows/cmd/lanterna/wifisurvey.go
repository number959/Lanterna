package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"lanterna/internal/scan"
	"lanterna/internal/survey"
)

// runWifiSurvey misura il Wi-Fi nel punto in cui si trova il PC, per la
// mappa per stanza: polaris-cli wifi-survey Soggiorno [--secondi 15]
// [--senza-scansione] [--json].
func runWifiSurvey(args []string) error {
	fs := flag.NewFlagSet("wifi-survey", flag.ContinueOnError)
	secs := fs.Int("secondi", survey.DefaultSeconds, "")
	noScan := fs.Bool("senza-scansione", false, "")
	asJSON := fs.Bool("json", false, "")
	fs.Usage = func() { fmt.Fprintf(os.Stderr, usage, version) }
	var words []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return err
		}
		args = fs.Args()
		if len(args) > 0 {
			words = append(words, args[0])
			args = args[1:]
		}
	}
	room, err := survey.Room(strings.Join(words, " "))
	if err != nil {
		return fmt.Errorf("%v (esempio: polaris-cli wifi-survey Soggiorno)", err)
	}
	n, err := survey.Seconds(*secs)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Misura del Wi-Fi in «%s» per %d secondi: resta fermo con il portatile aperto dove si lavora.\n", room, n)
	fmt.Fprintln(os.Stderr, "Windows mostra l'icona della posizione mentre Polaris legge il Wi-Fi.")
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	shown, scanning := 0, false
	res, err := survey.Sample(ctx, survey.Options{Room: room, Seconds: n, Scan: !*noScan, Progress: func(p survey.Progress) {
		if p.Phase == "scansione" {
			if !scanning {
				scanning = true
				fmt.Fprintln(os.Stderr, "  scansione delle reti (circa 4 secondi)...")
			}
			return
		}
		for ; shown < len(p.Rssi); shown++ {
			fmt.Fprintf(os.Stderr, "  %2d/%d s  %d dBm\n", shown+1, n, p.Rssi[shown])
		}
	}})
	if err != nil {
		return err
	}
	if *asJSON {
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	printSurvey(res)
	return nil
}

func dec1(v float64) string { return strings.Replace(fmt.Sprintf("%.1f", v), ".", ",", 1) }

// dbmText scrive i dBm come interi quando lo sono ("-63"), altrimenti con la virgola ("-63,5").
func dbmText(v float64) string {
	if v == float64(int(v)) {
		return fmt.Sprintf("%d", int(v))
	}
	return dec1(v)
}

func printSurvey(s *scan.SurveySample) {
	fmt.Printf("%s · rete %s\n", s.Room, s.SSID)
	radio := []string{}
	if s.Band != "" {
		radio = append(radio, strings.Replace(s.Band, ".", ",", 1)+" GHz")
	}
	if s.Channel > 0 {
		radio = append(radio, fmt.Sprintf("canale %d", s.Channel))
	}
	if s.WidthMhz > 0 {
		radio = append(radio, fmt.Sprintf("%d MHz", s.WidthMhz))
	}
	if s.Phy != "" {
		radio = append(radio, s.Phy)
	}
	if len(radio) > 0 {
		fmt.Printf("  Radio: %s\n", strings.Join(radio, ", "))
	}
	fmt.Printf("  Segnale: mediana %s dBm, minimo %d, cali (10° percentile) %d, escursione %d dB, %d letture\n", dbmText(s.MedianDbm), s.MinDbm, s.P10Dbm, s.SpreadDb, len(s.Rssi))
	if s.Stuck {
		fmt.Println("  Valori fermi: Windows ha dato sempre lo stesso valore, forse la scheda non lo aggiorna ogni secondo")
	}
	if s.RxMbps > 0 || s.TxMbps > 0 {
		fmt.Printf("  Velocità radio: ricezione %d Mbit/s, trasmissione %d Mbit/s\n", s.RxMbps, s.TxMbps)
	}
	switch {
	case len(s.Roams) == 0 && len(s.BSSIDs) > 0:
		fmt.Printf("  Access point: %s, nessun cambio durante la misura\n", s.BSSIDs[0])
	case len(s.Roams) > 0:
		fmt.Printf("  Cambi di access point da fermo: %d (%s)\n", len(s.Roams), strings.Join(s.BSSIDs, " → "))
	}
	if g := s.Gateway; g != nil {
		switch {
		case g.Skipped != "":
			fmt.Printf("  Router: non misurato, %s\n", g.Skipped)
		case g.NoReply:
			fmt.Printf("  Router %s: %s\n", g.Target, g.Error)
		case g.Error != "":
			fmt.Printf("  Router: %s\n", g.Error)
		default:
			line := fmt.Sprintf("  Router %s: risposte %d su %d (perdite %s %%)", g.Target, g.Received, g.Sent, dec1(g.LossPct))
			if g.MedianMs != nil {
				line += fmt.Sprintf(", tempo mediano %s ms, 95° percentile %s ms", dec1(*g.MedianMs), dec1(*g.P95Ms))
			}
			if g.JitterMs != nil {
				line += fmt.Sprintf(", jitter %s ms", dec1(*g.JitterMs))
			}
			fmt.Println(line)
		}
	}
	if sc := s.Scan; sc != nil {
		parts := []string{}
		if sc.ConnectedDbm != nil {
			parts = append(parts, fmt.Sprintf("rete collegata a %d dBm", *sc.ConnectedDbm))
		}
		if sc.UtilizationPct != nil {
			p := fmt.Sprintf("canale occupato al %d %% secondo l'access point", *sc.UtilizationPct)
			if sc.Stations != nil {
				p += fmt.Sprintf(" (%d dispositivi)", *sc.Stations)
			}
			parts = append(parts, p)
		}
		if len(parts) > 0 {
			fmt.Printf("  Scansione: %s\n", strings.Join(parts, "; "))
		}
		for _, a := range sc.Alternatives {
			fmt.Printf("    Altro access point della stessa rete: %s GHz canale %d a %d dBm (%s)\n", strings.Replace(a.Band, ".", ",", 1), a.Channel, a.RssiDbm, a.BSSID)
		}
		nb := sc.Neighbors
		line := fmt.Sprintf("    Reti dei vicini: %d visibili, %d sullo stesso canale", nb.Visible, nb.Cochannel)
		if nb.Cochannel > 0 {
			forti := "forti"
			if nb.Strong == 1 {
				forti = "forte"
			}
			line += fmt.Sprintf(" (%d %s", nb.Strong, forti)
			if nb.StrongestDbm != nil {
				line += fmt.Sprintf(", la più forte a %d dBm", *nb.StrongestDbm)
			}
			line += ")"
		}
		fmt.Println(line)
		if sc.Stale > 0 {
			fmt.Printf("    %d reti sentite più di 10 secondi prima non sono state considerate\n", sc.Stale)
		}
		if sc.Error != "" {
			fmt.Printf("    %s\n", sc.Error)
		}
	}
	for _, n := range s.Notes {
		fmt.Printf("  Nota: %s\n", n)
	}
	fmt.Println("  I valori valgono per questo PC: un altro dispositivo, con altre antenne, riceve in modo diverso.")
}
