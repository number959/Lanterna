package certs

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"lanterna/internal/scan"
)

var now = time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC)

type certSpec struct {
	cn        string
	dns       []string
	ips       []net.IP
	notBefore time.Time
	notAfter  time.Time
	isCA      bool
}

func makeCert(t *testing.T, s certSpec, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: s.cn, Organization: []string{"Studio di prova"}},
		NotBefore:             s.notBefore,
		NotAfter:              s.notAfter,
		DNSNames:              s.dns,
		IPAddresses:           s.ips,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  s.isCA,
	}
	signer, signKey := tmpl, key
	if parent != nil {
		signer, signKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

func tlsCert(chain []*x509.Certificate, key *ecdsa.PrivateKey) tls.Certificate {
	tc := tls.Certificate{PrivateKey: key, Leaf: chain[0]}
	for _, c := range chain {
		tc.Certificate = append(tc.Certificate, c.Raw)
	}
	return tc
}

// serve apre un servizio TLS su 127.0.0.1 e restituisce l'indirizzo.
func serve(t *testing.T, cfg *tls.Config) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				tc := tls.Server(c, cfg)
				_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
				if tc.Handshake() == nil {
					var b [1]byte
					_, _ = tc.Read(b[:])
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func opts() Options {
	return Options{
		Now:     func() time.Time { return now },
		Trust:   func([]*x509.Certificate) string { return "trusted" },
		Resolve: func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("127.0.0.1")}, nil },
	}
}

func check(t *testing.T, o Options, targets ...scan.CertTarget) []scan.CertResult {
	t.Helper()
	d, err := Check(context.Background(), targets, o)
	if err != nil {
		t.Fatal(err)
	}
	return d.Results
}

func TestCheck(t *testing.T) {
	ca, caKey := makeCert(t, certSpec{cn: "CA dello studio", notBefore: now.AddDate(-2, 0, 0), notAfter: now.AddDate(8, 0, 0), isCA: true}, nil, nil)
	leaf, key := makeCert(t, certSpec{cn: "nas.local", dns: []string{"nas.local"}, ips: []net.IP{net.ParseIP("127.0.0.1")}, notBefore: now.AddDate(0, 0, -100), notAfter: now.AddDate(0, 0, 20)}, ca, caKey)
	addr := serve(t, &tls.Config{Certificates: []tls.Certificate{tlsCert([]*x509.Certificate{leaf, ca}, key)}})
	_, port, _ := net.SplitHostPort(addr)

	r := check(t, opts(), scan.CertTarget{Label: "NAS", Host: addr}, scan.CertTarget{Host: "https://nas.local:" + port + "/login"}, scan.CertTarget{Host: "altro.local:" + port})
	a := r[0]
	if !a.OK || a.Error != "" || a.Label != "NAS" || a.IP != "127.0.0.1" || a.TLSVersion != "TLS 1.3" || a.Cipher == "" {
		t.Fatalf("collegamento: %+v", a)
	}
	if a.Subject != "nas.local" || a.Org != "Studio di prova" || a.Issuer != "CA dello studio" || a.ChainLen != 2 || a.SelfSigned || a.CNOnly {
		t.Errorf("certificato: %+v", a)
	}
	if !a.NameMatch || a.DaysLeft != 20 || a.LifetimeDays != 120 || a.KeyType != "ECDSA P-256" || a.KeyBits != 256 || a.WeakSig || a.Trust != "trusted" || len(a.Fingerprint) != 64 {
		t.Errorf("dettagli: %+v", a)
	}
	if a.LegacyOnly || a.LegacyToo || a.ClientCert {
		t.Errorf("TLS: %+v", a)
	}
	// Per nome (anche da un indirizzo https://...): il nome è tra quelli del certificato.
	if b := r[1]; !b.OK || b.Host != "nas.local" || !b.NameMatch {
		t.Errorf("per nome: %+v", b)
	}
	// Un altro nome che porta allo stesso servizio non corrisponde.
	if c := r[2]; !c.OK || c.NameMatch {
		t.Errorf("nome diverso: %+v", c)
	}
}

func TestCheckProblems(t *testing.T) {
	self, selfKey := makeCert(t, certSpec{cn: "router", ips: []net.IP{net.ParseIP("127.0.0.1")}, notBefore: now.AddDate(-5, 0, 0), notAfter: now.AddDate(-1, 0, 0)}, nil, nil)
	cnOnly, cnKey := makeCert(t, certSpec{cn: "vecchio.local", notBefore: now.AddDate(-1, 0, 0), notAfter: now.AddDate(1, 0, 0)}, nil, nil)
	expired := serve(t, &tls.Config{Certificates: []tls.Certificate{tlsCert([]*x509.Certificate{self}, selfKey)}})
	legacyOnly := serve(t, &tls.Config{Certificates: []tls.Certificate{tlsCert([]*x509.Certificate{cnOnly}, cnKey)}, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA}})
	legacyToo := serve(t, &tls.Config{Certificates: []tls.Certificate{tlsCert([]*x509.Certificate{cnOnly}, cnKey)}, MinVersion: tls.VersionTLS10,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}})
	mtls13 := serve(t, &tls.Config{Certificates: []tls.Certificate{tlsCert([]*x509.Certificate{cnOnly}, cnKey)}, ClientAuth: tls.RequireAnyClientCert})
	mtls12 := serve(t, &tls.Config{Certificates: []tls.Certificate{tlsCert([]*x509.Certificate{cnOnly}, cnKey)}, ClientAuth: tls.RequireAnyClientCert, MaxVersion: tls.VersionTLS12})
	o := opts()
	o.Trust = func([]*x509.Certificate) string { return "untrusted-root" }
	r := check(t, o, scan.CertTarget{Host: expired}, scan.CertTarget{Host: legacyOnly}, scan.CertTarget{Host: legacyToo}, scan.CertTarget{Host: mtls13}, scan.CertTarget{Host: mtls12})
	if e := r[0]; !e.OK || !e.SelfSigned || e.DaysLeft >= 0 || !e.NameMatch || e.Trust != "untrusted-root" {
		t.Errorf("autofirmato e scaduto: %+v", e)
	}
	if l := r[1]; !l.OK || !l.LegacyOnly || l.TLSVersion != "TLS 1.1" || !l.CNOnly || l.NameMatch {
		t.Errorf("solo TLS 1.0/1.1: %+v", l)
	}
	if l := r[2]; !l.OK || l.LegacyOnly || !l.LegacyToo || l.TLSVersion != "TLS 1.3" {
		t.Errorf("anche TLS 1.0/1.1: %+v", l)
	}
	if m := r[3]; !m.OK || !m.ClientCert || m.TLSVersion != "TLS 1.3" {
		t.Errorf("certificato client con TLS 1.3: %+v", m)
	}
	if m := r[4]; !m.OK || !m.ClientCert || m.TLSVersion != "TLS 1.2" {
		t.Errorf("certificato client con TLS 1.2: %+v", m)
	}
}

func TestSMTPStartTLS(t *testing.T) {
	leaf, key := makeCert(t, certSpec{cn: "posta.local", dns: []string{"posta.local"}, notBefore: now.AddDate(0, -1, 0), notAfter: now.AddDate(0, 6, 0)}, nil, nil)
	cfg := &tls.Config{Certificates: []tls.Certificate{tlsCert([]*x509.Certificate{leaf}, key)}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ehlo := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		rd := bufio.NewReader(c)
		c.Write([]byte("220-posta.local ESMTP\r\n220 pronto\r\n"))
		line, _ := rd.ReadString('\n')
		ehlo <- line
		c.Write([]byte("250-posta.local\r\n250-SIZE 1000\r\n250 STARTTLS\r\n"))
		if l, _ := rd.ReadString('\n'); strings.TrimSpace(l) != "STARTTLS" {
			return
		}
		c.Write([]byte("220 vai\r\n"))
		tc := tls.Server(c, cfg)
		_ = tc.Handshake()
	}()
	o := opts()
	o.Dial = func(ctx context.Context, addr string) (net.Conn, error) {
		if !strings.HasSuffix(addr, ":587") {
			t.Errorf("indirizzo: %s", addr)
		}
		return net.Dial("tcp", ln.Addr().String())
	}
	r := check(t, o, scan.CertTarget{Host: "posta.local", Port: 587})[0]
	if !r.OK || r.StartTLS != "smtp" || r.Subject != "posta.local" || !r.NameMatch {
		t.Fatalf("STARTTLS: %+v", r)
	}
	// Il PC si presenta con il suo indirizzo, mai con il suo nome.
	if got := <-ehlo; got != "EHLO [127.0.0.1]\r\n" {
		t.Errorf("EHLO: %q", got)
	}
}

func TestRefusals(t *testing.T) {
	o := opts()
	o.Dial = func(context.Context, string) (net.Conn, error) {
		t.Error("collegamento verso un indirizzo non ammesso")
		return nil, net.ErrClosed
	}
	o.Resolve = func(_ context.Context, host string) ([]net.IP, error) {
		switch host {
		case "misto.local":
			return []net.IP{net.ParseIP("192.168.1.10"), net.ParseIP("93.184.216.34")}, nil
		case "cgnat.local":
			return []net.IP{net.ParseIP("100.64.1.1")}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	r := check(t, o, scan.CertTarget{Host: "8.8.8.8"}, scan.CertTarget{Host: "misto.local"}, scan.CertTarget{Host: "cgnat.local"}, scan.CertTarget{Host: "sconosciuto.local"})
	for i, want := range []string{"pubblico", "pubblico", "pubblico", "non risolto"} {
		if r[i].OK || !strings.Contains(r[i].Error, want) {
			t.Errorf("%d: %+v", i, r[i])
		}
	}
	// Servizio che non parla TLS e porta chiusa.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			c.Close()
		}
	}()
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	closedAddr := closed.Addr().String()
	closed.Close()
	r = check(t, opts(), scan.CertTarget{Host: ln.Addr().String()}, scan.CertTarget{Host: closedAddr})
	ln.Close()
	if r[0].OK || !strings.Contains(r[0].Error, "non usa TLS") {
		t.Errorf("non TLS: %+v", r[0])
	}
	if r[1].OK || !strings.Contains(r[1].Error, "porta chiusa") {
		t.Errorf("porta chiusa: %+v", r[1])
	}
}

func TestTargetAndValidate(t *testing.T) {
	for in, want := range map[string]string{
		"nas.local":                    "nas.local:443",
		"192.168.1.10:8443":            "192.168.1.10:8443",
		"https://pacs.local:8443/view": "pacs.local:8443",
		"https://gestionale.local/":    "gestionale.local:443",
		"ldaps://dc.studio.local":      "dc.studio.local:636",
		"[fd00::5]:636":                "fd00::5:636",
	} {
		h, p, err := Target(scan.CertTarget{Host: in})
		if err != nil || h+":"+itoa(p) != want {
			t.Errorf("%s: %s %d %v", in, h, p, err)
		}
	}
	if h, p, _ := Target(scan.CertTarget{Host: "nas.local", Port: 5001}); h != "nas.local" || p != 5001 {
		t.Errorf("porta indicata: %s %d", h, p)
	}
	if err := Validate(nil); err == nil {
		t.Error("elenco vuoto accettato")
	}
	many := make([]scan.CertTarget, MaxTargets+1)
	for i := range many {
		many[i].Host = "nas.local"
	}
	if err := Validate(many); err == nil {
		t.Error("troppi servizi accettati")
	}
	for _, bad := range []string{"", "nas local", "a/b", "user@nas", "nas.local:70000"} {
		if err := Validate([]scan.CertTarget{{Host: bad}}); err == nil {
			t.Errorf("%q accettato", bad)
		}
	}
}

func itoa(n int) string { return big.NewInt(int64(n)).String() }

func TestTrustOf(t *testing.T) {
	for status, want := range map[uint32]string{
		0:                                      "trusted",
		trustNotTimeValid:                      "trusted",
		trustUntrustedRoot:                     "untrusted-root",
		trustUntrustedRoot | trustNotTimeValid: "untrusted-root",
		trustPartialChain:                      "partial-chain",
		trustNotSignatureValid:                 "invalid-signature",
		trustExplicitDistrust | trustUntrustedRoot: "distrusted",
		trustNotValidForUsage:                      "wrong-usage",
		trustRevocationUnknown:                     "trusted",
	} {
		if got := trustOf(status); got != want {
			t.Errorf("%#x: %s, atteso %s", status, got, want)
		}
	}
}
