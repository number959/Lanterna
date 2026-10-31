package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"lanterna/internal/certs"
	"lanterna/internal/scan"
)

// runCerts controlla i certificati TLS dei servizi della rete locale indicati
// sulla riga di comando: "nas.local", "192.168.1.10:8443", "https://pacs.local".
func runCerts(args []string) error {
	fs := flag.NewFlagSet("certs", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "")
	fs.Usage = func() { fmt.Fprintf(os.Stderr, usage, version) }
	var hosts []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return err
		}
		args = fs.Args()
		if len(args) > 0 {
			hosts = append(hosts, args[0])
			args = args[1:]
		}
	}
	if len(hosts) == 0 {
		return errors.New("indicare almeno un servizio, per esempio: polaris-cli certs nas.local 192.168.1.10:8443")
	}
	targets := make([]scan.CertTarget, len(hosts))
	for i, h := range hosts {
		targets[i] = scan.CertTarget{Host: h}
	}
	if err := certs.Validate(targets); err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	d, err := certs.Check(ctx, targets, certs.Options{})
	if d == nil {
		return err
	}
	if *asJSON {
		b, _ := json.MarshalIndent(d, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	printCerts(d)
	return nil
}

var trustText = map[string]string{
	"trusted":           "attendibile su questo PC",
	"untrusted-root":    "emittente non attendibile su questo PC",
	"partial-chain":     "catena incompleta: manca un certificato intermedio",
	"invalid-signature": "firma non valida",
	"wrong-usage":       "non valido per i server TLS",
	"distrusted":        "bloccato da Windows",
	"revoked":           "revocato",
}

func printCerts(d *scan.CertData) {
	for i, r := range d.Results {
		if i > 0 {
			fmt.Println()
		}
		fmt.Printf("%s:%d", r.Host, r.Port)
		if r.IP != "" && r.IP != r.Host {
			fmt.Printf(" (%s)", r.IP)
		}
		fmt.Println()
		if !r.OK {
			fmt.Printf("  Non controllato: %s\n", r.Error)
			continue
		}
		tls := r.TLSVersion
		if r.StartTLS != "" {
			tls += " dopo STARTTLS"
		}
		fmt.Printf("  %s, %s\n", tls, r.Cipher)
		switch {
		case r.LegacyOnly:
			fmt.Println("  Offre solo TLS 1.0/1.1, versioni obsolete e non più sicure")
		case r.LegacyToo:
			fmt.Println("  Accetta anche TLS 1.0/1.1, versioni obsolete")
		}
		if r.ClientCert {
			fmt.Println("  Chiede anche un certificato al client (TLS reciproco)")
		}
		names := append(append([]string{}, r.DNSNames...), r.IPs...)
		fmt.Printf("  Certificato: %s", orDash(r.Subject))
		if len(names) > 0 {
			fmt.Printf(" (nomi: %s)", strings.Join(names, ", "))
		}
		fmt.Println()
		issuer := r.Issuer
		if r.SelfSigned {
			issuer = "autofirmato"
		}
		fmt.Printf("  Emesso da: %s\n", orDash(issuer))
		fmt.Printf("  Valido fino al %s (%s)\n", r.NotAfter[:10], daysText(r.DaysLeft))
		fmt.Printf("  Chiave %s %d bit, firma %s\n", r.KeyType, r.KeyBits, r.SigAlg)
		if !r.NameMatch {
			fmt.Println("  Il nome usato non è tra quelli del certificato: il browser mostrerà un avviso")
		}
		if r.CNOnly {
			fmt.Println("  Il certificato ha solo il Common Name: i browser moderni lo rifiutano")
		}
		if r.WeakSig {
			fmt.Println("  Firma con SHA-1 o MD5, non più sicura")
		}
		if t, found := trustText[r.Trust]; found {
			fmt.Printf("  %s\n", strings.ToUpper(t[:1])+t[1:])
		}
		fmt.Printf("  Impronta SHA-256: %s\n", r.Fingerprint)
	}
}

func daysText(d int) string {
	switch {
	case d < 0:
		return "scaduto"
	case d == 0:
		return "scade oggi"
	case d == 1:
		return "ancora 1 giorno"
	}
	return fmt.Sprintf("ancora %d giorni", d)
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
