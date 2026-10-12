package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strings"
	"time"

	"lanterna/internal/scan"
)

// Nomi interrogati per misurare un server DNS: siti comuni (spesso già in
// cache, come nell'uso reale) e un paio meno frequenti.
var DNSNames = []string{"www.google.com", "www.wikipedia.org", "www.repubblica.it", "www.amazon.it", "www.youtube.com"}

// BuildQuery costruisce una richiesta DNS di tipo A con ricorsione.
func BuildQuery(id uint16, name string) ([]byte, error) {
	msg := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(msg[0:], id)
	msg[2] = 0x01                          // RD: ricorsione richiesta
	binary.BigEndian.PutUint16(msg[4:], 1) // 1 domanda
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("nome non valido: %q", name)
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0, 0, 1, 0, 1) // fine nome, QTYPE=A, QCLASS=IN
	return msg, nil
}

// CheckResponse verifica che la risposta corrisponda alla domanda.
// NXDOMAIN conta come risposta valida: il server ha risposto.
func CheckResponse(resp []byte, id uint16) error {
	if len(resp) < 12 {
		return errors.New("risposta troppo corta")
	}
	if binary.BigEndian.Uint16(resp) != id {
		return errors.New("identificativo diverso")
	}
	if resp[2]&0x80 == 0 {
		return errors.New("non è una risposta")
	}
	switch rcode := resp[3] & 0x0f; rcode {
	case 0, 3:
		return nil
	case 2:
		return errors.New("errore del server (SERVFAIL)")
	case 5:
		return errors.New("richiesta rifiutata (REFUSED)")
	default:
		return fmt.Errorf("codice di errore %d", rcode)
	}
}

// QueryOnce invia una richiesta e restituisce il tempo di risposta.
func QueryOnce(ctx context.Context, server, name string, timeout time.Duration) (time.Duration, error) {
	id := uint16(rand.Intn(65536))
	q, err := BuildQuery(id, name)
	if err != nil {
		return 0, err
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(server, "53"))
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	start := time.Now()
	if _, err := conn.Write(q); err != nil {
		return 0, err
	}
	buf := make([]byte, 1500)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return 0, errors.New("nessuna risposta entro il tempo limite")
			}
			return 0, err
		}
		if n >= 2 && binary.BigEndian.Uint16(buf) != id {
			continue // risposta tardiva a un'altra richiesta: si ignora
		}
		if err := CheckResponse(buf[:n], id); err != nil {
			return 0, err
		}
		return time.Since(start), nil
	}
}

// MeasureServer interroga il server con più nomi e riporta il tempo mediano.
func MeasureServer(ctx context.Context, server, label string, names []string) scan.DNSServerResult {
	r := scan.DNSServerResult{Server: server, Label: label}
	var times []float64
	var lastErr error
	for _, n := range names {
		d, err := QueryOnce(ctx, server, n, 2*time.Second)
		if err != nil {
			lastErr = err
			if len(times) == 0 && strings.Contains(err.Error(), "tempo limite") {
				break // primo nome senza risposta: inutile insistere per minuti
			}
			continue
		}
		times = append(times, float64(d.Microseconds())/1000)
	}
	if len(times) == 0 {
		if lastErr != nil {
			r.Error = lastErr.Error()
		}
		return r
	}
	sort.Float64s(times)
	r.OK = true
	r.TimeMs = scan.Ptr(round1(times[(len(times)-1)/2]))
	return r
}
