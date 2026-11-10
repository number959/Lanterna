package infra

import (
	"context"
	"net"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"lanterna/internal/probe"
)

// SSDP (UPnP Device Architecture): una sola ricerca "ssdp:all" con MX 2. I
// dispositivi UPnP rispondono in unicast entro MX secondi, con una risposta
// per ogni dispositivo e servizio che ospitano; ST e USN ne riportano il tipo
// (URN). Non si scarica la descrizione indicata da LOCATION: vorrebbe dire
// contattare la porta HTTP di ogni dispositivo.

const (
	ssdpGroup    = "239.255.255.250:1900"
	maxUPnPTypes = 24  // tipi esportati per host
	maxURNLen    = 120 // URN più lunghi si scartano
	maxServerLen = 120 // caratteri dell'intestazione SERVER
)

// ssdpHost raccoglie le risposte SSDP di un indirizzo.
type ssdpHost struct {
	types  map[string]bool
	server string
}

// ssdpState raccoglie le risposte SSDP per indirizzo, solo per gli host
// della sottorete.
type ssdpState struct {
	subnet  *net.IPNet
	hosts   map[string]*ssdpHost
	packets int
}

// handle esamina un pacchetto; false quando si è superato il limite di
// pacchetti. Contano solo le risposte "HTTP/1.1 200" (probe.ParseSSDP).
func (s *ssdpState) handle(from *net.UDPAddr, b []byte) bool {
	if s.packets++; s.packets > maxPackets {
		return false
	}
	src := from.IP.To4()
	if src == nil || !inRange(s.subnet, src) {
		return true
	}
	hd, _ := probe.ParseSSDP(b)
	if hd == nil {
		return true
	}
	h := s.hosts[src.String()]
	if h == nil {
		h = &ssdpHost{types: map[string]bool{}}
		s.hosts[src.String()] = h
	}
	for _, v := range []string{hd["ST"], hd["USN"]} {
		if t, ok := upnpType(v); ok && len(h.types) < maxUPnPTypes {
			h.types[t] = true
		}
	}
	if h.server == "" {
		h.server = cleanText(hd["SERVER"], maxServerLen)
	}
	return true
}

// ssdpScan invia la ricerca e ascolta le risposte fino a end.
func ssdpScan(ctx context.Context, c MulticastConn, subnet *net.IPNet, end time.Time) map[string]*ssdpHost {
	st := &ssdpState{subnet: subnet, hosts: map[string]*ssdpHost{}}
	if ctx.Err() != nil || c.Send(probe.MSearch("ssdp:all")) != nil {
		return st.hosts
	}
	collect(ctx, c, make([]byte, 64<<10), end, st.handle)
	return st.hosts
}

// upnpType estrae il tipo URN da ST o da USN ("uuid:...::urn:schemas-upnp-org:
// device:MediaRenderer:1"). Gli identificativi "uuid:" (univoci per ogni
// apparecchio) e "upnp:rootdevice" non dicono che dispositivo sia: si scartano.
func upnpType(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if i := strings.Index(v, "::"); i >= 0 {
		v = strings.TrimSpace(v[i+2:])
	}
	if len(v) <= 4 || len(v) > maxURNLen || !strings.EqualFold(v[:4], "urn:") {
		return "", false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] > 0x7e {
			return "", false
		}
	}
	return v, true
}

// cleanText toglie i caratteri di controllo e di formato (e i byte non
// UTF-8), riduce gli spazi consecutivi a uno e taglia a max caratteri.
func cleanText(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case unicode.IsSpace(r):
			return ' '
		case r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r):
			return -1
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > max {
		s = strings.TrimSpace(string(r[:max]))
	}
	return s
}
