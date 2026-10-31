package main

import (
	"strings"
	"testing"

	"lanterna/internal/scan"
)

func TestPrintCerts(t *testing.T) {
	d := &scan.CertData{Results: []scan.CertResult{
		{CertTarget: scan.CertTarget{Host: "pacs.local", Port: 2762}, IP: "192.168.10.20", OK: true, TLSVersion: "TLS 1.2", Cipher: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			LegacyToo: true, ClientCert: true, Subject: "pacs.local", DNSNames: []string{"pacs.local"}, SelfSigned: true, NotAfter: "2026-11-12T00:00:00Z", DaysLeft: 12,
			KeyType: "RSA", KeyBits: 2048, SigAlg: "SHA256-RSA", NameMatch: true, Trust: "untrusted-root", Fingerprint: "AB"},
		{CertTarget: scan.CertTarget{Host: "nas.local", Port: 443}, IP: "192.168.10.30", OK: true, TLSVersion: "TLS 1.1", LegacyOnly: true, Subject: "nas", CNOnly: true,
			Issuer: "CA dello studio", NotAfter: "2025-01-01T00:00:00Z", DaysLeft: -300, KeyType: "RSA", KeyBits: 1024, SigAlg: "SHA1-RSA", WeakSig: true, Trust: "trusted"},
		{CertTarget: scan.CertTarget{Host: "8.8.8.8", Port: 443}, Error: "indirizzo pubblico: si controllano solo i servizi della rete locale"},
	}}
	out := capture(t, func() { printCerts(d) })
	for _, want := range []string{
		"pacs.local:2762 (192.168.10.20)", "Accetta anche TLS 1.0/1.1", "TLS reciproco", "Emesso da: autofirmato", "Valido fino al 2026-11-12 (ancora 12 giorni)",
		"Emittente non attendibile su questo PC", "Offre solo TLS 1.0/1.1", "scaduto", "Il nome usato non è tra quelli", "solo il Common Name",
		"SHA-1 o MD5", "Attendibile su questo PC", "Non controllato: indirizzo pubblico",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("manca %q in:\n%s", want, out)
		}
	}
}
