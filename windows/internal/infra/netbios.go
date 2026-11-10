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

// NBStatus riassume la risposta "node status".
type NBStatus struct {
	// Name è il nome del computer: la prima voce unica con suffisso 0x00
	// (servizio workstation).
	Name string
	// Roles sono i ruoli dedotti dai suffissi dei nomi registrati (vedi nbRoles).
	Roles []string
}

// nbEntry è una voce della tabella dei nomi: nome di 15 caratteri, suffisso
// (il sedicesimo byte, che indica il servizio) e flag.
type nbEntry struct {
	name   string
	suffix byte
	flags  uint16
}

// Flag delle voci (RFC 1002, 4.2.18): G = nome di gruppo, DRG = nome in
// cancellazione, CNF = nome in conflitto.
const (
	nbGroup      = 0x8000
	nbDeregister = 0x1000
	nbConflict   = 0x0800
)

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

// nbEntries legge la tabella dei nomi; si ferma senza errore alla prima voce
// troncata.
func nbEntries(b []byte) ([]nbEntry, error) {
	if len(b) < 12 || b[2]&0x80 == 0 {
		return nil, errors.New("non è una risposta NetBIOS")
	}
	if binary.BigEndian.Uint16(b[6:]) == 0 {
		return nil, errors.New("risposta senza dati")
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
		return nil, errors.New("risposta troncata")
	}
	n := int(b[p])
	p++
	var out []nbEntry
	for i := 0; i < n && p+18 <= len(b); i++ {
		out = append(out, nbEntry{
			name:   strings.TrimRight(string(b[p:p+15]), " \x00"),
			suffix: b[p+15],
			flags:  binary.BigEndian.Uint16(b[p+16:]),
		})
		p += 18
	}
	return out, nil
}

// parseNBStat restituisce il nome del computer e i ruoli; errore se la
// risposta non contiene alcuna voce.
func parseNBStat(b []byte) (NBStatus, error) {
	entries, err := nbEntries(b)
	if err != nil {
		return NBStatus{}, err
	}
	if len(entries) == 0 {
		return NBStatus{}, errors.New("nessun nome nella risposta")
	}
	var st NBStatus
	for _, e := range entries {
		if e.suffix == 0x00 && e.flags&nbGroup == 0 && e.name != "" {
			st.Name = e.name
			break
		}
	}
	st.Roles = nbRoles(entries)
	return st, nil
}

// Ruoli in ordine fisso, così l'elenco non dipende dall'ordine delle voci.
var nbRoleOrder = []string{"workstation", "file-server", "domain-controller", "master-browser"}

// nbRoles deduce i ruoli dai suffissi dei nomi (tabella dei suffissi
// NetBIOS di Microsoft):
//   - <00> unico: servizio workstation → "workstation";
//   - <20> unico: servizio server, condivisione di file e stampanti → "file-server";
//   - <1C> di gruppo con il nome del dominio: controller di dominio →
//     "domain-controller" (il gruppo <1C> "INet~Services" è di IIS e non conta);
//   - <1D> unico (master browser della sottorete), <1B> unico (domain master
//     browser, cioè l'emulatore PDC) o il gruppo <01> "__MSBROWSE__" → "master-browser".
//
// Le voci in conflitto o in cancellazione non contano.
func nbRoles(entries []nbEntry) []string {
	has := map[string]bool{}
	for _, e := range entries {
		if e.name == "" || e.flags&(nbDeregister|nbConflict) != 0 {
			continue
		}
		group := e.flags&nbGroup != 0
		switch {
		case e.suffix == 0x00 && !group:
			has["workstation"] = true
		case e.suffix == 0x20 && !group:
			has["file-server"] = true
		case e.suffix == 0x1c && group && !strings.HasPrefix(strings.ToUpper(e.name), "INET~"):
			has["domain-controller"] = true
		case (e.suffix == 0x1d || e.suffix == 0x1b) && !group,
			e.suffix == 0x01 && group && strings.Contains(e.name, "__MSBROWSE__"):
			has["master-browser"] = true
		}
	}
	var out []string
	for _, r := range nbRoleOrder {
		if has[r] {
			out = append(out, r)
		}
	}
	return out
}

// NetBIOSStatus interroga un host; risultato vuoto se non risponde in tempo.
func NetBIOSStatus(ctx context.Context, ip net.IP, timeout time.Duration) NBStatus {
	ip4 := ip.To4()
	if ip4 == nil {
		return NBStatus{}
	}
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "udp4", net.JoinHostPort(ip4.String(), "137"))
	if err != nil {
		return NBStatus{}
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	id := uint16(time.Now().UnixNano())
	if _, err := c.Write(nbstatQuery(id)); err != nil {
		return NBStatus{}
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil || n < 12 || binary.BigEndian.Uint16(buf) != id {
		return NBStatus{}
	}
	st, err := parseNBStat(buf[:n])
	if err != nil {
		return NBStatus{}
	}
	return st
}

// NetBIOSName interroga un host e restituisce solo il nome del computer;
// stringa vuota se non risponde in tempo.
func NetBIOSName(ctx context.Context, ip net.IP, timeout time.Duration) string {
	return NetBIOSStatus(ctx, ip, timeout).Name
}
