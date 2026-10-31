// Package certs controlla i certificati TLS dei servizi della rete locale
// indicati dall'utente (gestionale, PACS, NAS, pannello del router, posta):
// scadenza, nomi, emittente, chiave, firma, versione di TLS e se questo PC li
// considera attendibili. Solo su richiesta, solo verso indirizzi privati, senza
// inviare dati applicativi né credenziali: ci si collega, si legge il
// certificato durante la negoziazione e si chiude.
package certs

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"lanterna/internal/infra"
	"lanterna/internal/scan"
)

// MaxTargets è il numero massimo di servizi per controllo.
const MaxTargets = 20

// Options regola i tempi; i valori zero usano quelli predefiniti.
type Options struct {
	Connect   time.Duration // 3 s
	Handshake time.Duration // 6 s
	Target    time.Duration // 12 s per servizio
	Workers   int           // 4
	// Resolve e Dial si sostituiscono nei test.
	Resolve func(ctx context.Context, host string) ([]net.IP, error)
	Dial    func(ctx context.Context, addr string) (net.Conn, error)
	// Trust valuta la catena con l'archivio di Windows (nil: non verificata).
	Trust func(chain []*x509.Certificate) string
	Now   func() time.Time
}

func (o *Options) defaults() {
	if o.Connect <= 0 {
		o.Connect = 3 * time.Second
	}
	if o.Handshake <= 0 {
		o.Handshake = 6 * time.Second
	}
	if o.Target <= 0 {
		o.Target = 12 * time.Second
	}
	if o.Workers <= 0 || o.Workers > 4 {
		o.Workers = 4
	}
	if o.Resolve == nil {
		o.Resolve = func(ctx context.Context, host string) ([]net.IP, error) {
			addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			ips := make([]net.IP, len(addrs))
			for i, a := range addrs {
				ips[i] = a.IP
			}
			return ips, err
		}
	}
	if o.Dial == nil {
		connect := o.Connect
		o.Dial = func(ctx context.Context, addr string) (net.Conn, error) {
			d := net.Dialer{Timeout: connect}
			return d.DialContext(ctx, "tcp", addr)
		}
	}
	if o.Trust == nil {
		o.Trust = platformTrust
	}
	if o.Now == nil {
		o.Now = time.Now
	}
}

// Target normalizza ciò che scrive l'utente: "nas.local", "192.168.1.10:8443",
// "https://pacs.local:8443/viewer", "[fd00::5]:636".
func Target(t scan.CertTarget) (host string, port int, err error) {
	h := strings.TrimSpace(t.Host)
	port = t.Port
	if strings.Contains(h, "://") {
		u, perr := url.Parse(h)
		if perr != nil || u.Hostname() == "" {
			return "", 0, errors.New("indirizzo non valido")
		}
		h = u.Hostname()
		if p := u.Port(); p != "" {
			port, _ = strconv.Atoi(p)
		} else if port == 0 {
			switch strings.ToLower(u.Scheme) {
			case "ldaps":
				port = 636
			case "smtps":
				port = 465
			case "imaps":
				port = 993
			default:
				port = 443
			}
		}
	} else if hh, pp, serr := net.SplitHostPort(h); serr == nil {
		h = hh
		port, _ = strconv.Atoi(pp)
	}
	h = strings.Trim(h, "[]")
	if port == 0 {
		port = 443
	}
	if h == "" || len(h) > 253 || strings.ContainsAny(h, " /\\@") {
		return "", 0, errors.New("indirizzo o nome mancante o non valido")
	}
	if port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("porta %d non valida", port)
	}
	return h, port, nil
}

// Validate controlla l'elenco prima di contattare qualunque servizio.
func Validate(targets []scan.CertTarget) error {
	if len(targets) == 0 {
		return errors.New("nessun servizio da controllare")
	}
	if len(targets) > MaxTargets {
		return fmt.Errorf("al massimo %d servizi per controllo (ne sono arrivati %d)", MaxTargets, len(targets))
	}
	for i, t := range targets {
		if _, _, err := Target(t); err != nil {
			return fmt.Errorf("servizio %d: %v", i+1, err)
		}
	}
	return nil
}

// allowed: solo reti private, loopback e indirizzi link-local. Niente
// indirizzi pubblici né CGNAT (100.64.0.0/10).
func allowed(ip net.IP) bool {
	return infra.Private(ip) || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

// Check controlla i servizi indicati, al massimo quattro insieme.
func Check(ctx context.Context, targets []scan.CertTarget, opt Options) (*scan.CertData, error) {
	if err := Validate(targets); err != nil {
		return nil, err
	}
	opt.defaults()
	out := &scan.CertData{CheckedAt: opt.Now().UTC().Format(time.RFC3339), Results: make([]scan.CertResult, len(targets))}
	sem := make(chan struct{}, opt.Workers)
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			tctx, cancel := context.WithTimeout(ctx, opt.Target)
			defer cancel()
			out.Results[i] = checkOne(tctx, t, opt)
		}()
	}
	wg.Wait()
	return out, ctx.Err()
}

func checkOne(ctx context.Context, t scan.CertTarget, opt Options) scan.CertResult {
	host, port, _ := Target(t)
	r := scan.CertResult{CertTarget: scan.CertTarget{Label: t.Label, Host: host, Port: port}}
	ip := net.ParseIP(host)
	if ip == nil {
		ips, err := opt.Resolve(ctx, host)
		if err != nil || len(ips) == 0 {
			r.Error = "nome non risolto"
			return r
		}
		// Tutti gli indirizzi del nome devono essere privati: un nome che
		// punta (anche) a Internet non si controlla.
		for _, x := range ips {
			if !allowed(x) {
				r.Error = "il nome porta a un indirizzo pubblico: si controllano solo i servizi della rete locale"
				return r
			}
		}
		ip = ips[0]
	} else if !allowed(ip) {
		r.Error = "indirizzo pubblico: si controllano solo i servizi della rete locale"
		return r
	}
	r.IP = ip.String()
	// Ci si collega all'indirizzo controllato, non di nuovo al nome.
	addr := net.JoinHostPort(r.IP, strconv.Itoa(port))
	sni := ""
	if net.ParseIP(host) == nil {
		sni = host
	}
	if port == 25 || port == 587 {
		r.StartTLS = "smtp"
	}

	p := probe(ctx, addr, sni, r.StartTLS, modern, opt)
	switch {
	case p.leaf != nil:
		r.OK = true
		r.TLSVersion, r.Cipher = tls.VersionName(p.version), tls.CipherSuiteName(p.cipher)
		r.ClientCert = p.clientCert
		// Accetta anche TLS 1.0 o 1.1?
		if lp := probe(ctx, addr, sni, r.StartTLS, legacy, opt); lp.leaf != nil {
			r.LegacyToo = true
		}
	case p.connected:
		// Collegato ma nessun certificato: forse solo TLS 1.0 o 1.1.
		if lp := probe(ctx, addr, sni, r.StartTLS, legacy, opt); lp.leaf != nil {
			p = lp
			r.OK, r.LegacyOnly = true, true
			r.TLSVersion, r.Cipher = tls.VersionName(p.version), tls.CipherSuiteName(p.cipher)
			r.ClientCert = p.clientCert
		} else {
			r.Error = explain(p.err)
		}
	default:
		r.Error = explain(p.err)
	}
	if r.OK {
		describe(&r, host, p.chain, opt)
	}
	return r
}

type mode int

const (
	modern mode = iota
	legacy
)

type probeResult struct {
	connected  bool
	leaf       *x509.Certificate
	chain      []*x509.Certificate
	version    uint16
	cipher     uint16
	clientCert bool
	err        error
}

// legacySuites: per riconoscere i servizi fermi a TLS 1.0/1.1 servono anche le
// suite che Go non propone più (scambio RSA, CBC, 3DES).
var legacySuites = func() []uint16 {
	var ids []uint16
	for _, s := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		if !strings.Contains(s.Name, "RC4") {
			ids = append(ids, s.ID)
		}
	}
	return ids
}()

func probe(ctx context.Context, addr, sni, starttls string, m mode, opt Options) (pr probeResult) {
	conn, err := opt.Dial(ctx, addr)
	if err != nil {
		pr.err = err
		return pr
	}
	defer conn.Close()
	pr.connected = true
	deadline := time.Now().Add(opt.Handshake)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	if starttls == "smtp" {
		if err := smtpStartTLS(conn); err != nil {
			pr.err = err
			return pr
		}
	}
	cfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // la catena si valuta dopo, senza interrompere la negoziazione
		VerifyConnection: func(cs tls.ConnectionState) error {
			pr.chain = cs.PeerCertificates
			if len(cs.PeerCertificates) > 0 {
				pr.leaf = cs.PeerCertificates[0]
			}
			pr.version, pr.cipher = cs.Version, cs.CipherSuite
			return nil
		},
	}
	if m == legacy {
		cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS10, tls.VersionTLS11
		cfg.CipherSuites = legacySuites
	}
	tc := tls.Client(conn, cfg)
	err = tc.HandshakeContext(ctx)
	if err != nil {
		pr.err = err
		// Con TLS 1.2 il rifiuto per il certificato client arriva durante la
		// negoziazione, dopo che il certificato del servizio è stato letto.
		if pr.leaf != nil && remoteAlert(err) {
			pr.clientCert = true
		}
		return pr
	}
	// Con TLS 1.3 il rifiuto arriva alla prima lettura: un'attesa breve.
	if pr.version == tls.VersionTLS13 {
		_ = tc.SetReadDeadline(time.Now().Add(time.Second))
		var b [1]byte
		if _, rerr := tc.Read(b[:]); rerr != nil && remoteAlert(rerr) {
			pr.clientCert = true
		}
	}
	return pr
}

// remoteAlert: il servizio ha chiuso con un avviso TLS (per esempio
// "certificate required" o "bad certificate").
func remoteAlert(err error) bool {
	var oe *net.OpError
	return errors.As(err, &oe) && oe.Op == "remote error"
}

// smtpStartTLS porta una connessione SMTP alla cifratura: saluto del
// server, EHLO con l'indirizzo del PC (mai il suo nome), STARTTLS.
func smtpStartTLS(conn net.Conn) error {
	rd := bufio.NewReader(conn)
	read := func(want string) (string, error) {
		var all strings.Builder
		for {
			line, err := rd.ReadString('\n')
			if err != nil {
				return all.String(), errors.New("il server di posta non ha risposto come previsto")
			}
			all.WriteString(line)
			if len(line) < 4 || !strings.HasPrefix(line, want) {
				return all.String(), errors.New("il server di posta non ha risposto come previsto")
			}
			if line[3] == ' ' {
				return all.String(), nil
			}
		}
	}
	if _, err := read("220"); err != nil {
		return err
	}
	local := "[127.0.0.1]"
	if ta, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		if ta.IP.To4() != nil {
			local = "[" + ta.IP.String() + "]"
		} else {
			local = "[IPv6:" + ta.IP.String() + "]"
		}
	}
	if _, err := fmt.Fprintf(conn, "EHLO %s\r\n", local); err != nil {
		return err
	}
	caps, err := read("250")
	if err != nil {
		return err
	}
	if !strings.Contains(strings.ToUpper(caps), "STARTTLS") {
		return errors.New("il server di posta non offre STARTTLS: la posta viaggia in chiaro")
	}
	if _, err := fmt.Fprint(conn, "STARTTLS\r\n"); err != nil {
		return err
	}
	_, err = read("220")
	return err
}

// explain traduce gli errori in frasi senza dettagli tecnici inutili.
func explain(err error) string {
	if err == nil {
		return "nessun certificato ricevuto"
	}
	msg := err.Error()
	var ne net.Error
	switch {
	case errors.As(err, &ne) && ne.Timeout(), errors.Is(err, context.DeadlineExceeded):
		return "il servizio non ha risposto in tempo"
	case strings.Contains(msg, "connection refused"), strings.Contains(msg, "actively refused"):
		return "porta chiusa: nessun servizio in ascolto"
	case strings.Contains(msg, "first record does not look like a TLS handshake"):
		return "il servizio su questa porta non usa TLS"
	case strings.Contains(msg, "unsupported elliptic curve"), strings.Contains(msg, "x509: "):
		return "certificato che il controllo non sa leggere (per esempio una curva non supportata)"
	case strings.Contains(msg, "posta"):
		return msg
	case remoteAlert(err):
		return "il servizio ha rifiutato la connessione TLS"
	}
	return "negoziazione TLS non riuscita"
}

// describe riempie il risultato con i dati del certificato.
func describe(r *scan.CertResult, host string, chain []*x509.Certificate, opt Options) {
	leaf := chain[0]
	now := opt.Now()
	r.ChainLen = len(chain)
	r.Subject = leaf.Subject.CommonName
	r.Org = first(leaf.Subject.Organization)
	r.Issuer = leaf.Issuer.CommonName
	r.IssuerOrg = first(leaf.Issuer.Organization)
	r.DNSNames = leaf.DNSNames
	for _, ip := range leaf.IPAddresses {
		r.IPs = append(r.IPs, ip.String())
	}
	r.NotBefore = leaf.NotBefore.UTC().Format(time.RFC3339)
	r.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
	r.DaysLeft = int(leaf.NotAfter.Sub(now).Hours() / 24)
	if leaf.NotAfter.Before(now) && r.DaysLeft == 0 {
		r.DaysLeft = -1
	}
	r.LifetimeDays = int(leaf.NotAfter.Sub(leaf.NotBefore).Hours()/24 + 0.5)
	switch k := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		r.KeyType, r.KeyBits = "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		r.KeyType, r.KeyBits = "ECDSA "+k.Curve.Params().Name, k.Curve.Params().BitSize
	case ed25519.PublicKey:
		r.KeyType, r.KeyBits = "Ed25519", 256
	default:
		r.KeyType = leaf.PublicKeyAlgorithm.String()
	}
	r.SigAlg = leaf.SignatureAlgorithm.String()
	switch leaf.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1, x509.MD5WithRSA, x509.MD2WithRSA:
		r.WeakSig = true
	}
	// Autofirmato: emittente uguale al soggetto e firma con la propria chiave
	// (CheckSignature accetta anche SHA-1, CheckSignatureFrom no).
	if string(leaf.RawIssuer) == string(leaf.RawSubject) {
		r.SelfSigned = leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil || r.KeyBits < 1024
	}
	// Il nome come l'ha scritto l'utente: un indirizzo IP va confrontato con
	// gli indirizzi del certificato, non con il nome inviato al server.
	r.NameMatch = leaf.VerifyHostname(host) == nil
	r.CNOnly = len(leaf.DNSNames) == 0 && len(leaf.IPAddresses) == 0 && leaf.Subject.CommonName != ""
	sum := sha256.Sum256(leaf.Raw)
	r.Fingerprint = strings.ToUpper(hex.EncodeToString(sum[:]))
	if opt.Trust != nil {
		r.Trust = opt.Trust(chain)
	}
}

func first(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}
