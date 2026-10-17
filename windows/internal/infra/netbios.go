package infra

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"time"
)

// Richiesta NetBIOS "node status" (RFC 1002, 4.2.17-18): un solo pacchetto
// UDP verso la porta 137; i PC Windows, le stampanti e molti dispositivi
// rispondono con l'elenco dei propri nomi.

// nbstatQuery costruisce la richiesta per il nome jolly "*".
func nbstatQuery(id uint16) []byte {
	q := []byte{byte(id >> 8), byte(id), 0x00, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0x20}
	name := make([]byte, 16)
	name[0] = '*'
	for _, c := range name {
		q = append(q, 'A'+(c>>4), 'A'+(c&0x0f))
	}
	return append(q, 0x00, 0x00, 0x21, 0x00, 0x01) // fine nome, tipo NBSTAT, classe IN
}

// parseNBStat restituisce il nome del computer: la prima voce unica con
// suffisso 0x00 (servizio workstation).
func parseNBStat(b []byte) (string, error) {
	if len(b) < 12 || b[2]&0x80 == 0 {
		return "", errors.New("non è una risposta NetBIOS")
	}
	if binary.BigEndian.Uint16(b[6:]) == 0 {
		return "", errors.New("risposta senza dati")
	}
	p := 12
	for p < len(b) {
		l := int(b[p])
		if l == 0 {
			p++
			break
		}
		if l&0xc0 == 0xc0 { // nome compresso
			p += 2
			break
		}
		p += 1 + l
	}
	p += 2 + 2 + 4 + 2 // tipo, classe, TTL, lunghezza dei dati
	if p >= len(b) {
		return "", errors.New("risposta troncata")
	}
	n := int(b[p])
	p++
	for i := 0; i < n && p+18 <= len(b); i++ {
		name := strings.TrimRight(string(b[p:p+15]), " \x00")
		suffix := b[p+15]
		flags := binary.BigEndian.Uint16(b[p+16:])
		if suffix == 0x00 && flags&0x8000 == 0 && name != "" {
			return name, nil
		}
		p += 18
	}
	return "", errors.New("nessun nome di computer nella risposta")
}

// NetBIOSName interroga un host; stringa vuota se non risponde in tempo.
func NetBIOSName(ctx context.Context, ip net.IP, timeout time.Duration) string {
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "udp4", net.JoinHostPort(ip4.String(), "137"))
	if err != nil {
		return ""
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	id := uint16(time.Now().UnixNano())
	if _, err := c.Write(nbstatQuery(id)); err != nil {
		return ""
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil || n < 12 || binary.BigEndian.Uint16(buf) != id {
		return ""
	}
	name, err := parseNBStat(buf[:n])
	if err != nil {
		return ""
	}
	return name
}
