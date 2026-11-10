package infra

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"lanterna/internal/scan"
)

// ---------------------------------------------------------------- messaggi DNS costruiti a mano

// dnsBuilder scrive un messaggio DNS comprimendo i nomi come fanno i
// dispositivi: ogni suffisso già scritto diventa un puntatore.
type dnsBuilder struct {
	b          []byte
	offs       map[string]int
	qd, an, ar int
}

func newDNS(id, flags uint16) *dnsBuilder {
	d := &dnsBuilder{b: make([]byte, 12), offs: map[string]int{}}
	binary.BigEndian.PutUint16(d.b, id)
	binary.BigEndian.PutUint16(d.b[2:], flags)
	return d
}

func (d *dnsBuilder) name(labels []string) {
	for i := range labels {
		key := strings.ToLower(strings.Join(labels[i:], "\x00"))
		if off, ok := d.offs[key]; ok {
			d.b = append(d.b, 0xc0|byte(off>>8), byte(off))
			return
		}
		if len(d.b) < 0x3fff {
			d.offs[key] = len(d.b)
		}
		d.b = append(d.b, byte(len(labels[i])))
		d.b = append(d.b, labels[i]...)
	}
	d.b = append(d.b, 0)
}

func (d *dnsBuilder) question(labels []string) {
	d.name(labels)
	d.b = append(d.b, 0, dnsTypePTR, 0, dnsClassIN)
	d.qd++
}

// record aggiunge un record nella sezione delle risposte o in quella dei
// record aggiuntivi.
func (d *dnsBuilder) record(labels []string, typ, class uint16, additional bool, data func()) {
	d.name(labels)
	d.b = binary.BigEndian.AppendUint16(d.b, typ)
	d.b = binary.BigEndian.AppendUint16(d.b, class)
	d.b = binary.BigEndian.AppendUint32(d.b, 10)
	at := len(d.b)
	d.b = append(d.b, 0, 0)
	data()
	binary.BigEndian.PutUint16(d.b[at:], uint16(len(d.b)-at-2))
	if additional {
		d.ar++
	} else {
		d.an++
	}
}

func (d *dnsBuilder) ptr(owner, target []string) {
	d.record(owner, dnsTypePTR, dnsClassIN, false, func() { d.name(target) })
}

// Alcuni dispositivi mettono il bit cache-flush anche nelle risposte unicast:
// il parser lo deve ignorare.
func (d *dnsBuilder) srv(owner, host []string) {
	d.record(owner, dnsTypeSRV, dnsClassIN|0x8000, true, func() {
		d.b = append(d.b, 0, 0, 0, 0, 0x02, 0x77) // priorità, peso, porta 631
		d.name(host)
	})
}

func (d *dnsBuilder) txt(owner []string, s string) {
	d.record(owner, 16, dnsClassIN|0x8000, true, func() {
		d.b = append(d.b, byte(len(s)))
		d.b = append(d.b, s...)
	})
}

func (d *dnsBuilder) a(owner []string, ip string) {
	d.record(owner, dnsTypeA, dnsClassIN|0x8000, true, func() { d.b = append(d.b, net.ParseIP(ip).To4()...) })
}

func (d *dnsBuilder) bytes() []byte {
	binary.BigEndian.PutUint16(d.b[4:], uint16(d.qd))
	binary.BigEndian.PutUint16(d.b[6:], uint16(d.an))
	binary.BigEndian.PutUint16(d.b[10:], uint16(d.ar))
	return d.b
}

func lb(s string) []string { return strings.Split(s, ".") }

func udp(s string) *net.UDPAddr {
	a, err := net.ResolveUDPAddr("udp4", s)
	if err != nil {
		panic(err)
	}
	return a
}

// questionsOf legge le domande PTR di una richiesta mDNS.
func questionsOf(q []byte) (uint16, [][]string) {
	var names [][]string
	off := 12
	for i := 0; i < int(binary.BigEndian.Uint16(q[4:])); i++ {
		l, next, err := dnsName(q, off)
		if err != nil || next+4 > len(q) || binary.BigEndian.Uint16(q[next:]) != dnsTypePTR || binary.BigEndian.Uint16(q[next+2:]) != dnsClassIN {
			return 0, nil
		}
		names = append(names, l)
		off = next + 4
	}
	return binary.BigEndian.Uint16(q), names
}

// ---------------------------------------------------------------- dispositivi e rete finti

// mdnsSvc è un'istanza annunciata da un dispositivo: host e indirizzi solo
// se diversi da quelli del dispositivo (proxy del sonno).
type mdnsSvc struct {
	inst  string
	host  string
	addrs []string
}

// mdnsDev risponde alle domande come un risponditore mDNS: alla meta-domanda
// con i propri tipi, alle domande PTR con istanza, SRV, TXT e A.
type mdnsDev struct {
	from  string
	host  string
	addrs []string
	svcs  map[string]mdnsSvc
	bare  bool // risponde solo con il PTR, senza record aggiuntivi
}

func (d mdnsDev) answer(q []byte) []byte {
	id, qs := questionsOf(q)
	if len(qs) == 0 {
		return nil
	}
	m := newDNS(id, 0x8400) // QR e AA
	for _, n := range qs {
		m.question(n)
	}
	types := make([]string, 0, len(d.svcs))
	for t := range d.svcs {
		types = append(types, t)
	}
	sort.Strings(types)
	var asked []string
	for _, n := range qs {
		if nameKey(n) == metaKey {
			for _, t := range types {
				m.ptr(metaName, lb(t+".local"))
			}
			continue
		}
		if t, ok := browseType(n); ok {
			if s, ok := d.svcs[t]; ok {
				m.ptr(n, append([]string{s.inst}, lb(t+".local")...))
				asked = append(asked, t)
			}
		}
	}
	if m.an == 0 {
		return nil
	}
	for _, t := range asked {
		if d.bare {
			break
		}
		s := d.svcs[t]
		inst := append([]string{s.inst}, lb(t+".local")...)
		host, addrs := d.host, d.addrs
		if s.host != "" {
			host, addrs = s.host, s.addrs
		}
		m.srv(inst, []string{host, "local"})
		m.txt(inst, "note=Studio del dott. Mario Rossi")
		for _, a := range addrs {
			m.a([]string{host, "local"}, a)
		}
	}
	return m.bytes()
}

type fakePkt struct {
	from *net.UDPAddr
	data []byte
}

// fakeMcast è il socket multicast finto: a ogni pacchetto inviato mette in
// coda le risposte dei dispositivi.
type fakeMcast struct {
	reply  func(q []byte) []fakePkt
	queue  chan fakePkt
	closed chan struct{}
	once   sync.Once
	mu     sync.Mutex
	sent   [][]byte
}

func newFakeMcast(reply func([]byte) []fakePkt) *fakeMcast {
	return &fakeMcast{reply: reply, queue: make(chan fakePkt, 4096), closed: make(chan struct{})}
}

func (f *fakeMcast) Send(b []byte) error {
	f.mu.Lock()
	f.sent = append(f.sent, append([]byte(nil), b...))
	f.mu.Unlock()
	if f.reply != nil {
		for _, p := range f.reply(b) {
			f.queue <- p
		}
	}
	return nil
}

func (f *fakeMcast) Receive(buf []byte, deadline time.Time) (int, *net.UDPAddr, error) {
	t := time.NewTimer(time.Until(deadline))
	defer t.Stop()
	select {
	case p := <-f.queue:
		return copy(buf, p.data), p.from, nil
	case <-t.C:
		return 0, nil, os.ErrDeadlineExceeded
	case <-f.closed:
		return 0, nil, net.ErrClosed
	}
}

func (f *fakeMcast) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

func (f *fakeMcast) packets() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]byte(nil), f.sent...)
}

func (f *fakeMcast) isClosed() bool {
	select {
	case <-f.closed:
		return true
	default:
		return false
	}
}

// fakeGroups risponde ai gruppi mDNS e SSDP e ricorda come sono stati aperti.
type fakeGroups struct {
	mu     sync.Mutex
	locals map[string]string // gruppo → indirizzo locale
	conns  map[string]*fakeMcast
	mdns   []mdnsDev
	junk   []fakePkt // pacchetti estranei o malformati, alla prima domanda mDNS
	ssdp   []fakePkt // risposte alla ricerca SSDP
}

func (g *fakeGroups) open(local net.IP, group string) (MulticastConn, error) {
	var c *fakeMcast
	switch group {
	case mdnsGroup:
		first := true
		c = newFakeMcast(func(q []byte) []fakePkt {
			var out []fakePkt
			if first {
				out = append(out, g.junk...)
				first = false
			}
			for _, d := range g.mdns {
				if r := d.answer(q); r != nil {
					out = append(out, fakePkt{udp(d.from), r})
				}
			}
			return out
		})
	case ssdpGroup:
		c = newFakeMcast(func(q []byte) []fakePkt {
			if !bytes.HasPrefix(q, []byte("M-SEARCH * HTTP/1.1\r\n")) {
				return nil
			}
			return g.ssdp
		})
	default:
		return nil, errors.New("gruppo inatteso: " + group)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.locals == nil {
		g.locals, g.conns = map[string]string{}, map[string]*fakeMcast{}
	}
	g.locals[group] = local.String()
	g.conns[group] = c
	return c, nil
}

func ssdpResp(from string, lines ...string) fakePkt {
	return fakePkt{udp(from), []byte(strings.Join(lines, "\r\n") + "\r\n\r\n")}
}

// junkMDNS sono pacchetti estranei o malformati: porta sbagliata, fuori
// sottorete, nomi rotti, domande al posto di risposte, codici di errore (da
// scartare), più due casi limite: un record valido seguito da dati rotti
// (.33, vale il record valido) e tipi di servizio non validi (.36, il
// dispositivo esiste ma non ha tipi).
func junkMDNS() []fakePkt {
	meta := func(id uint16, flags uint16, types ...string) []byte {
		m := newDNS(id, flags)
		for _, t := range types {
			m.ptr(metaName, lb(t+".local"))
		}
		return m.bytes()
	}
	hdr := func(an uint16) []byte {
		b := make([]byte, 12)
		binary.BigEndian.PutUint16(b[2:], 0x8400)
		binary.BigEndian.PutUint16(b[6:], an)
		return b
	}
	// Record valido seguito da un nome con puntatore in avanti.
	partial := newDNS(0, 0x8400)
	partial.ptr(metaName, lb("_hap._tcp.local"))
	partial.an++
	partialBytes := append(partial.bytes(), 0xc0, 0xff, 0, 12, 0, 1)
	// Tipo di servizio con un nome personale al posto del servizio.
	personal := newDNS(0, 0x8400)
	personal.ptr(metaName, []string{"Mario Rossi", "_tcp", "local"})
	personal.ptr(metaName, lb("_ipp._tcp.example.com"))
	return []fakePkt{
		{udp("192.168.10.31:4444"), meta(0, 0x8400, "_ssh._tcp")},                                    // porta d'origine diversa da 5353
		{udp("10.0.0.5:5353"), meta(0, 0x8400, "_ssh._tcp")},                                         // fuori sottorete
		{udp("192.168.10.0:5353"), meta(0, 0x8400, "_ssh._tcp")},                                     // indirizzo di rete
		{udp("192.168.10.255:5353"), meta(0, 0x8400, "_ssh._tcp")},                                   // broadcast
		{udp("192.168.10.34:5353"), meta(0, 0x0000, "_ssh._tcp")},                                    // una domanda, non una risposta
		{udp("192.168.10.35:5353"), meta(0, 0x8403, "_ssh._tcp")},                                    // RCODE 3
		{udp("192.168.10.32:5353"), append(hdr(1), 0xc0, 0x0c)},                                      // puntatore a se stesso
		{udp("192.168.10.32:5353"), append(hdr(1), 0xc0, 0x40, 0, 0)},                                // puntatore in avanti
		{udp("192.168.10.32:5353"), append(hdr(1), 3, 'a', 'b')},                                     // etichetta troncata
		{udp("192.168.10.32:5353"), append(hdr(1), 0x40, 'x', 0)},                                    // etichetta estesa
		{udp("192.168.10.32:5353"), append(hdr(2), 1, 'a', 0, 0, 12, 0, 1, 0, 0, 0, 10, 0xff, 0xff)}, // dati oltre la fine
		{udp("192.168.10.32:5353"), []byte{0x84}},                                                    // più corto dell'intestazione
		{udp("192.168.10.32:5353"), nil},                                                             // vuoto
		{udp("192.168.10.33:5353"), partialBytes},
		{udp("192.168.10.36:5353"), personal.bytes()},
	}
}

// ---------------------------------------------------------------- inventario con i segnali

func TestInventorySegnali(t *testing.T) {
	lan := &fakeLAN{
		alive: map[string]time.Duration{"192.168.10.1": time.Millisecond, "192.168.10.12": time.Millisecond, "192.168.10.40": 3 * time.Millisecond},
		ttl:   map[string]int{"192.168.10.1": 255, "192.168.10.12": 128, "192.168.10.40": 64},
	}
	p := lan.prims()
	p.LookupAddr = nil
	p.Neighbors = func() ([]scan.Neighbor, error) {
		return []scan.Neighbor{
			{IP: "192.168.10.1", MAC: "a4:2b:b0:00:00:01"},
			{IP: "192.168.10.30", MAC: "00:1b:a9:12:34:56"}, // stampante che ignora il ping
			{IP: "192.168.10.41", MAC: "70:35:60:63:00:41"}, // Mac addormentato: risponde il proxy
			{IP: "192.168.10.77", MAC: "da:a1:19:00:00:77"},
		}, nil
	}
	dc := nbResponse(
		nbEntry{"SRV-DC01", 0x00, 0x0400}, nbEntry{"CLINICA", 0x00, 0x8400}, nbEntry{"CLINICA", 0x1c, 0x8400},
		nbEntry{"CLINICA", 0x1b, 0x0400}, nbEntry{"SRV-DC01", 0x20, 0x0400}, nbEntry{"CLINICA", 0x1e, 0x8400},
	)
	p.NetBIOS = func(ctx context.Context, ip net.IP, timeout time.Duration) NBStatus {
		if ip.String() == "192.168.10.12" {
			st, _ := parseNBStat(dc)
			return st
		}
		return NBStatus{}
	}
	g := &fakeGroups{
		mdns: []mdnsDev{
			{from: "192.168.10.30:5353", host: "NPI12AB", addrs: []string{"192.168.10.30"}, svcs: map[string]mdnsSvc{
				"_ipp._tcp": {inst: "Stampante Reparto"}, "_printer._tcp": {inst: "Stampante Reparto"},
				"_pdl-datastream._tcp": {inst: "Stampante Reparto"}, "_http._tcp": {inst: "Stampante Reparto"},
			}},
			{from: "192.168.10.40:5353", host: "Apple-TV-Sala", addrs: []string{"192.168.10.40"}, svcs: map[string]mdnsSvc{
				"_airplay._tcp":     {inst: "Apple TV Sala d'attesa"},
				"_raop._tcp":        {inst: "A1B2C3D4E5F6@Apple TV Sala d'attesa"},
				"_sleep-proxy._udp": {inst: "70-35-60-63.1 Apple TV"},
				// Il proxy del sonno risponde per i Mac addormentati.
				"_smb._tcp":        {inst: "MacBook di Anna", host: "MacBook-di-Anna", addrs: []string{"192.168.10.41"}},
				"_afpovertcp._tcp": {inst: "iMac di Anna", host: "iMac-di-Anna", addrs: []string{"192.168.10.42"}},
			}},
			{from: "192.168.10.77:5353", host: "iPhone-di-Mario", addrs: []string{"192.168.10.77", "8.8.8.8"}, svcs: map[string]mdnsSvc{
				"_companion-link._tcp": {inst: "iPhone di Mario"},
			}},
			// Chromecast che ignora ping e ARP e risponde senza record aggiuntivi.
			{from: "192.168.10.90:5353", host: "Chromecast-Sala", bare: true, svcs: map[string]mdnsSvc{
				"_googlecast._tcp": {inst: "Chromecast-Sala-1234"},
			}},
			{from: "10.0.0.5:5353", host: "server-esterno", addrs: []string{"10.0.0.5"}, svcs: map[string]mdnsSvc{
				"_ssh._tcp": {inst: "server-esterno"},
			}},
		},
		junk: junkMDNS(),
		ssdp: []fakePkt{
			ssdpResp("192.168.10.1:1900", "HTTP/1.1 200 OK", "CACHE-CONTROL: max-age=120", "ST: upnp:rootdevice",
				"USN: uuid:2b2b0000-11::upnp:rootdevice", "LOCATION: http://192.168.10.1:5000/rootDesc.xml", "SERVER: Linux/3.4 UPnP/1.0 MiniUPnPd/1.9"),
			ssdpResp("192.168.10.1:1900", "HTTP/1.1 200 OK", "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1",
				"USN: uuid:2b2b0000-11::urn:schemas-upnp-org:device:InternetGatewayDevice:1", "SERVER: un altro server"),
			ssdpResp("192.168.10.1:1900", "HTTP/1.1 200 OK", "ST: urn:schemas-upnp-org:service:WANIPConnection:1",
				"USN: uuid:2b2b0000-11::urn:schemas-upnp-org:service:WANIPConnection:1"),
			ssdpResp("192.168.10.30:49152", "HTTP/1.1 200 OK", "ST: urn:schemas-upnp-org:device:Printer:1", "SERVER: HP-ChaiSOE/1.0 UPnP/1.0"),
			ssdpResp("192.168.10.30:49152", "HTTP/1.1 200 OK", "ST: urn:schemas-upnp-org:device:Printer:1"),
			ssdpResp("192.168.10.30:49152", "HTTP/1.1 200 OK", "ST: urn:\xc3\x28non-ascii:1"),
			// Intestazioni insolite: minuscole, spazi, solo LF, caratteri di controllo.
			{udp("192.168.10.60:41952"), []byte("http/1.1 200 ok\nst:urn:schemas-upnp-org:device:MediaRenderer:1\n" +
				"usn :   uuid:abcd-ef::urn:dial-multiscreen-org:service:dial:1  \n" +
				"server:  Linux/4.9\tUPnP/1.0\x1b[31m  Cast\x07Device/1.0‮ \nlocation: http://192.168.10.60:8008/dd.xml\n\n")},
			ssdpResp("192.168.10.61:1900", "HTTP/1.1 200 OK", "ST: urn:schemas-upnp-org:device:MediaServer:1", "SERVER: "+strings.Repeat("NAS-Box/1.0 ", 30)),
			ssdpResp("192.168.10.50:2869", "HTTP/1.1 200 OK", "ST: urn:schemas-upnp-org:device:MediaServer:1",
				"SERVER: Microsoft-Windows/10.0 UPnP/1.0 UPnP-Device-Host/1.0"), // questo PC
			ssdpResp("192.168.10.62:1900", "HTTP/1.1 404 Not Found", "ST: urn:schemas-upnp-org:device:Basic:1"),
			ssdpResp("192.168.10.63:1900", "NOTIFY * HTTP/1.1", "NT: urn:schemas-upnp-org:device:Basic:1", "NTS: ssdp:alive"),
			{udp("192.168.10.64:1900"), []byte{0x00, 0xff, 0x13, 0x37, '\r', '\n'}},
			ssdpResp("172.16.0.9:1900", "HTTP/1.1 200 OK", "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1"),
		},
	}
	p.Multicast = g.open
	opt := fast
	opt.ListenWindow = 300 * time.Millisecond

	start := time.Now()
	inv, err := Inventory(context.Background(), InventoryRequest{CIDR: "192.168.10.50/24", Gateway: "192.168.10.1", SelfMAC: "3c:58:c2:aa:bb:cc"}, p, opt, nil)
	if err != nil {
		t.Fatal(err)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("inventario troppo lungo: %v", el)
	}
	got := map[string]scan.InventoryHost{}
	var order []string
	for _, h := range inv.Hosts {
		got[h.IP] = h
		order = append(order, h.IP)
	}
	want := []string{"192.168.10.1", "192.168.10.12", "192.168.10.30", "192.168.10.33", "192.168.10.36", "192.168.10.40", "192.168.10.41",
		"192.168.10.50", "192.168.10.60", "192.168.10.61", "192.168.10.77", "192.168.10.90"}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Fatalf("host: %v", order)
	}
	check := func(ip, field string, got []string, want ...string) {
		t.Helper()
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s %s: %q, attesi %q", ip, field, got, want)
		}
	}
	// TTL dal ping; assente per chi non ha risposto.
	for ip, ttl := range map[string]int{"192.168.10.1": 255, "192.168.10.12": 128, "192.168.10.40": 64, "192.168.10.30": 0, "192.168.10.50": 0} {
		if got[ip].TTL != ttl {
			t.Errorf("%s TTL %d, atteso %d", ip, got[ip].TTL, ttl)
		}
	}
	// mDNS.
	check(".30", "services", got["192.168.10.30"].Services, "_http._tcp", "_ipp._tcp", "_pdl-datastream._tcp", "_printer._tcp")
	check(".40", "services", got["192.168.10.40"].Services, "_airplay._tcp", "_raop._tcp", "_sleep-proxy._udp")
	check(".41", "services", got["192.168.10.41"].Services, "_smb._tcp")
	check(".77", "services", got["192.168.10.77"].Services, "_companion-link._tcp")
	check(".90", "services", got["192.168.10.90"].Services, "_googlecast._tcp")
	check(".33", "services", got["192.168.10.33"].Services, "_hap._tcp")
	check(".36", "services", got["192.168.10.36"].Services)
	if h := got["192.168.10.90"]; h.RttMs != nil || h.MAC != "" {
		t.Errorf("Chromecast visto solo via mDNS: %+v", h)
	}
	// SSDP.
	check(".1", "upnp", got["192.168.10.1"].UPnP, "urn:schemas-upnp-org:device:InternetGatewayDevice:1", "urn:schemas-upnp-org:service:WANIPConnection:1")
	check(".30", "upnp", got["192.168.10.30"].UPnP, "urn:schemas-upnp-org:device:Printer:1")
	check(".60", "upnp", got["192.168.10.60"].UPnP, "urn:dial-multiscreen-org:service:dial:1", "urn:schemas-upnp-org:device:MediaRenderer:1")
	check(".50", "upnp", got["192.168.10.50"].UPnP, "urn:schemas-upnp-org:device:MediaServer:1")
	for ip, server := range map[string]string{
		"192.168.10.1":  "Linux/3.4 UPnP/1.0 MiniUPnPd/1.9",
		"192.168.10.30": "HP-ChaiSOE/1.0 UPnP/1.0",
		"192.168.10.60": "Linux/4.9 UPnP/1.0[31m CastDevice/1.0",
		"192.168.10.61": strings.TrimSpace(strings.Repeat("NAS-Box/1.0 ", 10)),
		"192.168.10.40": "",
	} {
		if got[ip].Server != server {
			t.Errorf("%s server %q, atteso %q", ip, got[ip].Server, server)
		}
	}
	// NetBIOS e campi di prima.
	check(".12", "roles", got["192.168.10.12"].Roles, "workstation", "file-server", "domain-controller", "master-browser")
	if h := got["192.168.10.12"]; h.NetBIOS != "SRV-DC01" {
		t.Errorf("nome NetBIOS: %+v", h)
	}
	if h := got["192.168.10.1"]; !h.Gateway || h.MAC != "a4:2b:b0:00:00:01" {
		t.Errorf("gateway: %+v", h)
	}
	if h := got["192.168.10.50"]; !h.Self || h.MAC != "3c:58:c2:aa:bb:cc" || h.Server == "" {
		t.Errorf("questo PC: %+v", h)
	}

	// Pacchetti inviati: una ricerca SSDP, la meta-domanda mDNS e un secondo
	// giro con i soli tipi annunciati dagli host della sottorete.
	if g.locals[ssdpGroup] != "192.168.10.50" || g.locals[mdnsGroup] != "192.168.10.50" {
		t.Errorf("indirizzo locale dei socket: %v", g.locals)
	}
	sent := g.conns[ssdpGroup].packets()
	if len(sent) != 1 || !strings.Contains(string(sent[0]), "\r\nST: ssdp:all\r\n") || !strings.Contains(string(sent[0]), "\r\nMX: 2\r\n") ||
		!strings.Contains(string(sent[0]), "MAN: \"ssdp:discover\"") {
		t.Errorf("ricerca SSDP: %q", sent)
	}
	md := g.conns[mdnsGroup].packets()
	if len(md) < 2 || !bytes.Equal(md[0], mdnsQuery(metaName)) {
		t.Fatalf("domande mDNS: %d", len(md))
	}
	var asked []string
	for _, q := range md[1:] {
		_, names := questionsOf(q)
		if len(names) == 0 || len(names) > mdnsPerQuery {
			t.Errorf("domanda del secondo giro con %d richieste", len(names))
		}
		for _, n := range names {
			ty, ok := browseType(n)
			if !ok {
				t.Errorf("richiesta inattesa: %q", n)
			}
			asked = append(asked, ty)
		}
	}
	sort.Strings(asked)
	wantAsked := []string{"_afpovertcp._tcp", "_airplay._tcp", "_companion-link._tcp", "_googlecast._tcp", "_hap._tcp", "_http._tcp", "_ipp._tcp",
		"_pdl-datastream._tcp", "_printer._tcp", "_raop._tcp", "_sleep-proxy._udp", "_smb._tcp"}
	if len(md) != 3 || strings.Join(asked, ",") != strings.Join(wantAsked, ",") {
		t.Errorf("secondo giro (%d pacchetti): %v", len(md)-1, asked)
	}
	if !g.conns[ssdpGroup].isClosed() || !g.conns[mdnsGroup].isClosed() {
		t.Error("socket multicast non chiusi")
	}

	// Riservatezza: nell'inventario non compaiono nomi di istanze, nomi .local,
	// contenuti TXT né identificativi uuid.
	js, err := json.Marshal(inv)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"Mario", "Anna", "Stampante", "Apple TV", "Apple-TV", "Sala", "NPI12AB", "Chromecast", "iPhone", "MacBook", "iMac",
		".local", "note=", "uuid", "esterno", "8.8.8.8", "10.0.0.5", "172.16.0.9"} {
		if bytes.Contains(js, []byte(s)) {
			t.Errorf("l'inventario contiene %q: %s", s, js)
		}
	}
}

func TestInventorySegnaliAnnullato(t *testing.T) {
	lan := &fakeLAN{}
	p := lan.prims()
	g := &fakeGroups{}
	p.Multicast = g.open // nessuno risponde
	opt := fast
	opt.ListenWindow = 10 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	start := time.Now()
	if _, err := Inventory(ctx, InventoryRequest{CIDR: "192.168.10.50/24"}, p, opt, nil); err == nil {
		t.Fatal("contesto annullato: atteso errore")
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("l'ascolto non si è fermato all'annullamento: %v", el)
	}
	for group, c := range g.conns {
		if !c.isClosed() {
			t.Errorf("socket %s non chiuso", group)
		}
	}
}

func TestDiscoverAnnullatoNonInvia(t *testing.T) {
	g := &fakeGroups{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, sub, _ := net.ParseCIDR("192.168.10.0/24")
	for i := 0; i < 20; i++ { // il pacer potrebbe avere un battito pronto: non deve bastare
		if sigs := discover(ctx, Prims{Multicast: g.open}, net.ParseIP("192.168.10.50"), sub, fast); len(sigs) != 0 {
			t.Fatalf("segnali con contesto annullato: %v", sigs)
		}
		for group, c := range g.conns {
			if n := len(c.packets()); n != 0 || !c.isClosed() {
				t.Fatalf("%s: %d pacchetti inviati, chiuso=%v", group, n, c.isClosed())
			}
		}
	}
}

func TestInventorySenzaMulticast(t *testing.T) {
	lan := &fakeLAN{alive: map[string]time.Duration{"192.168.10.1": time.Millisecond}}
	p := lan.prims()
	p.Multicast = func(net.IP, string) (MulticastConn, error) { return nil, errors.New("porta occupata") }
	inv, err := Inventory(context.Background(), InventoryRequest{CIDR: "192.168.10.50/24"}, p, fast, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range inv.Hosts {
		if h.Services != nil || h.UPnP != nil || h.Server != "" {
			t.Fatalf("segnali senza socket: %+v", h)
		}
	}
}

// ---------------------------------------------------------------- parser DNS

func TestDNSName(t *testing.T) {
	msg := make([]byte, 12)
	msg = append(msg, 3, 'a', 'b', 'c', 5, 'l', 'o', 'c', 'a', 'l', 0) // 12: abc.local
	msg = append(msg, 3, 'x', 'y', 'z', 0xc0, 16)                      // 23: xyz + puntatore a "local"
	msg = append(msg, 0xc0, 23)                                        // 29: puntatore a xyz.local
	for _, c := range []struct {
		off  int
		want string
		next int
	}{{12, "abc.local", 23}, {23, "xyz.local", 29}, {29, "xyz.local", 31}} {
		l, next, err := dnsName(msg, c.off)
		if err != nil || strings.Join(l, ".") != c.want || next != c.next {
			t.Errorf("offset %d: %q %d %v", c.off, l, next, err)
		}
	}
	bad := map[string][]byte{
		"puntatore a se stesso": append(make([]byte, 12), 0xc0, 12),
		"puntatore in avanti":   append(make([]byte, 12), 0xc0, 14, 1, 'a', 0),
		"ciclo a due":           append(make([]byte, 12), 1, 'a', 0xc0, 16, 1, 'b', 0xc0, 12),
		"etichetta troncata":    append(make([]byte, 12), 5, 'a', 'b'),
		"puntatore troncato":    append(make([]byte, 12), 0xc0),
		"etichetta 0x40":        append(make([]byte, 12), 0x41, 'a', 0),
		"etichetta 0x80":        append(make([]byte, 12), 0x81, 'a', 0),
		"senza fine":            append(make([]byte, 12), 1, 'a'),
		"vuoto":                 make([]byte, 12),
	}
	long := make([]byte, 12)
	for i := 0; i < 5; i++ {
		long = append(long, 63)
		long = append(long, bytes.Repeat([]byte{'a'}, 63)...)
	}
	bad["oltre 255 byte"] = append(long, 0)
	for name, b := range bad {
		if l, _, err := dnsName(b, 12); err == nil {
			t.Errorf("%s: accettato %q", name, l)
		}
	}
	if _, _, err := dnsName(msg, -1); err == nil {
		t.Error("offset negativo accettato")
	}
}

func TestParseDNSRecordsAndCompression(t *testing.T) {
	m := newDNS(0, 0x8400)
	m.question(lb("_ipp._tcp.local"))
	inst := append([]string{"Stampante Reparto"}, lb("_ipp._tcp.local")...)
	m.ptr(lb("_ipp._tcp.local"), inst)
	m.srv(inst, lb("NPI12AB.local"))
	m.a(lb("NPI12AB.local"), "192.168.10.30")
	b := m.bytes()
	// La compressione è davvero usata: il PTR punta alla domanda.
	if bytes.Count(b, []byte("_ipp")) != 1 || bytes.Count(b, []byte("NPI12AB")) != 1 {
		t.Fatalf("nomi non compressi: % x", b)
	}
	flags, rrs, err := parseDNS(b)
	if err != nil || flags != 0x8400 || len(rrs) != 3 {
		t.Fatalf("%x %d %v", flags, len(rrs), err)
	}
	if rrs[1].class != dnsClassIN {
		t.Errorf("bit cache-flush non tolto: %x", rrs[1].class)
	}
	target, ok := rdataName(b, rrs[0], 0)
	if !ok || nameKey(target) != nameKey(inst) {
		t.Errorf("PTR: %q", target)
	}
	host, ok := rdataName(b, rrs[1], 6)
	if !ok || strings.Join(host, ".") != "NPI12AB.local" {
		t.Errorf("SRV: %q", host)
	}
	// Un messaggio troncato restituisce i record completi fino al taglio.
	for cut := 12; cut < len(b); cut++ {
		_, part, err := parseDNS(b[:cut])
		if err == nil {
			t.Fatalf("taglio a %d accettato", cut)
		}
		if len(part) > 3 {
			t.Fatalf("taglio a %d: %d record", cut, len(part))
		}
	}
	// Dati del PTR più corti del nome che contengono: scartato.
	short := append([]byte(nil), b...)
	binary.BigEndian.PutUint16(short[rrs[0].off-2:], 1)
	if _, rrs2, _ := parseDNS(short); len(rrs2) > 0 {
		if _, ok := rdataName(short, rrs2[0], 0); ok {
			t.Error("nome oltre i dati del record accettato")
		}
	}
}

func TestMDNSQuery(t *testing.T) {
	want := []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
		9, '_', 's', 'e', 'r', 'v', 'i', 'c', 'e', 's', 7, '_', 'd', 'n', 's', '-', 's', 'd', 4, '_', 'u', 'd', 'p', 5, 'l', 'o', 'c', 'a', 'l', 0,
		0, 12, 0, 1} // PTR, classe IN senza bit QU
	if got := mdnsQuery(metaName); !bytes.Equal(got, want) {
		t.Fatalf("% x", got)
	}
	// 41 tipi: "_zzz._udp" da 4 origini, gli altri da 1, 2 o 3.
	_, sub, _ := net.ParseCIDR("192.168.10.0/24")
	st := newMDNSState(sub)
	for i := 0; i < 40; i++ {
		for j := 0; j <= i%3; j++ {
			st.addMeta(fmt.Sprintf("10.%d.%d.1", i, j), fmt.Sprintf("_t%02d._tcp", i))
		}
	}
	for j := 0; j < 4; j++ {
		st.addMeta(fmt.Sprintf("10.99.%d.1", j), "_zzz._udp")
	}
	qs := st.round2()
	if len(qs) != 4 {
		t.Fatalf("%d pacchetti nel secondo giro (attesi 4: 32 tipi, 8 per pacchetto)", len(qs))
	}
	_, first := questionsOf(qs[0])
	if len(first) != mdnsPerQuery || strings.Join(first[0], ".") != "_zzz._udp.local" {
		t.Fatalf("prima domanda: %q (attesa la più diffusa)", first)
	}
	if st := newMDNSState(sub); st.round2() != nil {
		t.Fatal("secondo giro senza tipi")
	}
}

func TestServiceType(t *testing.T) {
	for in, want := range map[string]string{
		"_ipp._tcp.local":              "_ipp._tcp",
		"_IPP._TCP.LOCAL":              "_ipp._tcp",
		"_sleep-proxy._udp.local":      "_sleep-proxy._udp",
		"_androidtvremote2._tcp.local": "_androidtvremote2._tcp",
		"_nvstream_dbd._tcp.local":     "_nvstream_dbd._tcp",
		"_ipp._tcp.example.com":        "",
		"_ipp._sctp.local":             "",
		"ipp._tcp.local":               "",
		"_._tcp.local":                 "",
		"_una-stringa-davvero-troppo-lunga-per-un-servizio._tcp.local": "",
	} {
		got, ok := serviceType(lb(in))
		if got != want || ok != (want != "") {
			t.Errorf("%s: %q %v", in, got, ok)
		}
	}
	if _, ok := serviceType([]string{"_mario rossi", "_tcp", "local"}); ok {
		t.Error("spazio accettato")
	}
	for in, want := range map[string]string{
		"_ipp._tcp.local":                 "_ipp._tcp",
		"_universal._sub._ipp._tcp.local": "_ipp._tcp",
		"Stampante._ipp._tcp.local":       "",
		"_services._dns-sd._udp.local":    "",
		"_a._b._sub._ipp._tcp.local":      "",
	} {
		if got, _ := browseType(lb(in)); got != want {
			t.Errorf("browse %s: %q", in, got)
		}
	}
}

// ---------------------------------------------------------------- SSDP

func TestUPnPTypeAndCleanText(t *testing.T) {
	for in, want := range map[string]string{
		"urn:schemas-upnp-org:device:MediaRenderer:1":                            "urn:schemas-upnp-org:device:MediaRenderer:1",
		" uuid:4d696e69-444c::urn:schemas-upnp-org:service:ContentDirectory:1 ":  "urn:schemas-upnp-org:service:ContentDirectory:1",
		"URN:Microsoft Windows Peer Name Resolution Protocol: V4:IPV6:LinkLocal": "URN:Microsoft Windows Peer Name Resolution Protocol: V4:IPV6:LinkLocal",
		"uuid:4d696e69-444c-164e-9d41-001ec9b17d8b":                              "",
		"uuid:4d696e69::upnp:rootdevice":                                         "",
		"upnp:rootdevice":                                                        "",
		"ssdp:all":                                                               "",
		"urn:":                                                                   "",
		"urn:x\x00y":                                                             "",
		"urn:" + strings.Repeat("a", 200):                                        "",
	} {
		got, ok := upnpType(in)
		if got != want || ok != (want != "") {
			t.Errorf("%q: %q %v", in, got, ok)
		}
	}
	for in, want := range map[string]string{
		"  Linux/3.4  UPnP/1.0\r\n MiniUPnPd ": "Linux/3.4 UPnP/1.0 MiniUPnPd",
		"a\x00b\x1b[0mc​d‮e\xff":               "ab[0mcde",
		"":                                     "",
	} {
		if got := cleanText(in, 120); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
	if got := cleanText(strings.Repeat("è", 200), 120); len([]rune(got)) != 120 {
		t.Errorf("taglio a 120 caratteri: %d", len([]rune(got)))
	}
}

// Socket veri sull'interfaccia di loopback: il finto dispositivo UPnP
// risponde alla ricerca, come farebbe dal gruppo multicast.
func TestListenMulticastLoopback(t *testing.T) {
	dev, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skip("UDP su loopback non disponibile:", err)
	}
	defer dev.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := dev.ReadFrom(buf)
			if err != nil {
				return
			}
			if !strings.Contains(string(buf[:n]), "ST: ssdp:all") {
				continue
			}
			for _, st := range []string{"upnp:rootdevice", "urn:schemas-upnp-org:device:MediaServer:1"} {
				_, _ = dev.WriteTo([]byte("HTTP/1.1 200 OK\r\nST: "+st+"\r\nSERVER: Test/1.0\r\n\r\n"), addr)
			}
		}
	}()
	c, err := listenMulticast(net.ParseIP("127.0.0.1"), dev.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, _, err := c.Receive(make([]byte, 16), time.Now().Add(10*time.Millisecond)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("scadenza: %v", err)
	}
	_, lo, _ := net.ParseCIDR("127.0.0.0/8")
	hosts := ssdpScan(context.Background(), c, lo, time.Now().Add(500*time.Millisecond))
	h := hosts["127.0.0.1"]
	if h == nil || !h.types["urn:schemas-upnp-org:device:MediaServer:1"] || len(h.types) != 1 || h.server != "Test/1.0" {
		t.Fatalf("%+v", h)
	}
	if _, err := listenMulticast(nil, "non-un-indirizzo"); err == nil {
		t.Fatal("gruppo non valido accettato")
	}
}

func TestInRange(t *testing.T) {
	_, n24, _ := net.ParseCIDR("192.168.10.0/24")
	_, n22, _ := net.ParseCIDR("10.1.4.0/22")
	for _, c := range []struct {
		n    *net.IPNet
		ip   string
		want bool
	}{
		{n24, "192.168.10.1", true}, {n24, "192.168.10.254", true}, {n24, "192.168.10.0", false}, {n24, "192.168.10.255", false},
		{n24, "192.168.11.1", false}, {n24, "fd00::1", false}, {n22, "10.1.5.0", true}, {n22, "10.1.7.255", false}, {n22, "10.1.4.0", false},
		{nil, "192.168.10.1", false},
	} {
		if got := inRange(c.n, net.ParseIP(c.ip)); got != c.want {
			t.Errorf("%v %s: %v", c.n, c.ip, got)
		}
	}
}

// ---------------------------------------------------------------- NetBIOS

// nbResponse costruisce una risposta "node status" con le voci indicate.
func nbResponse(entries ...nbEntry) []byte {
	q := nbstatQuery(0x1234)
	resp := []byte{0x12, 0x34, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0}
	resp = append(resp, q[12:46]...)
	resp = append(resp, 0x00, 0x21, 0x00, 0x01, 0, 0, 0, 0, 0, byte(1+18*len(entries)+6))
	resp = append(resp, byte(len(entries)))
	for _, e := range entries {
		resp = append(resp, []byte((e.name + strings.Repeat(" ", 15))[:15])...)
		resp = append(resp, e.suffix, byte(e.flags>>8), byte(e.flags))
	}
	return append(resp, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
}

func TestNBRoles(t *testing.T) {
	cases := []struct {
		name    string
		resp    []byte
		netbios string
		roles   string
	}{
		{"controller di dominio", nbResponse(
			nbEntry{"SRV-DC01", 0x00, 0x0400}, nbEntry{"CLINICA", 0x00, 0x8400}, nbEntry{"CLINICA", 0x1c, 0x8400},
			nbEntry{"CLINICA", 0x1b, 0x0400}, nbEntry{"SRV-DC01", 0x20, 0x0400}, nbEntry{"CLINICA", 0x1e, 0x8400},
		), "SRV-DC01", "workstation,file-server,domain-controller,master-browser"},
		{"PC del gruppo di lavoro", nbResponse(
			nbEntry{"WORKGROUP", 0x00, 0x8400}, nbEntry{"PC-01", 0x00, 0x0400}, nbEntry{"PC-01", 0x20, 0x0400},
		), "PC-01", "workstation,file-server"},
		{"IIS non è un controller", nbResponse(
			nbEntry{"WEB01", 0x00, 0x0400}, nbEntry{"INet~Services", 0x1c, 0x8400}, nbEntry{"IS~WEB01", 0x00, 0x0400},
		), "WEB01", "workstation"},
		{"master browser", nbResponse(
			nbEntry{"NAS", 0x00, 0x0400}, nbEntry{"\x01\x02__MSBROWSE__\x02", 0x01, 0x8400}, nbEntry{"NAS", 0x20, 0x0400},
		), "NAS", "workstation,file-server,master-browser"},
		{"master browser della sottorete", nbResponse(nbEntry{"PC-07", 0x00, 0x0400}, nbEntry{"WORKGROUP", 0x1d, 0x0400}), "PC-07", "workstation,master-browser"},
		{"nomi in conflitto o in cancellazione", nbResponse(
			nbEntry{"PC-02", 0x00, 0x1400}, nbEntry{"PC-02", 0x20, 0x0c00},
		), "PC-02", ""},
		{"solo nomi di gruppo e server", nbResponse(nbEntry{"WORKGROUP", 0x00, 0x8400}, nbEntry{"NPI12AB", 0x20, 0x0400}), "", "file-server"},
	}
	for _, c := range cases {
		st, err := parseNBStat(c.resp)
		if err != nil || st.Name != c.netbios || strings.Join(st.Roles, ",") != c.roles {
			t.Errorf("%s: %+v %v", c.name, st, err)
		}
	}
	// Il conteggio promette più voci di quante ce ne siano: si leggono quelle presenti.
	r := nbResponse(nbEntry{"PC-03", 0x00, 0x0400}, nbEntry{"PC-03", 0x20, 0x0400})
	r[56] = 9
	if st, err := parseNBStat(r[:len(r)-6]); err != nil || st.Name != "PC-03" || strings.Join(st.Roles, ",") != "workstation,file-server" {
		t.Errorf("voci mancanti: %+v %v", st, err)
	}
	if _, err := parseNBStat(nbResponse()); err == nil {
		t.Error("risposta senza voci accettata")
	}
}

// ---------------------------------------------------------------- pacchetti arbitrari

// FuzzRisposte: nessun pacchetto, per quanto malformato, deve far fallire i
// parser delle risposte mDNS, SSDP e NetBIOS.
func FuzzRisposte(f *testing.F) {
	m := newDNS(0, 0x8400)
	inst := append([]string{"X"}, lb("_ipp._tcp.local")...)
	m.ptr(metaName, lb("_ipp._tcp.local"))
	m.ptr(lb("_ipp._tcp.local"), inst)
	m.srv(inst, lb("h.local"))
	m.a(lb("h.local"), "192.168.10.30")
	f.Add(m.bytes())
	for _, p := range junkMDNS() {
		f.Add(p.data)
	}
	f.Add([]byte("HTTP/1.1 200 OK\r\nST: urn:a:b\r\nUSN: uuid:x::urn:c:d\r\nSERVER: s\r\n\r\n"))
	f.Add(nbResponse(nbEntry{"A", 0x00, 0x0400}))
	_, sub, _ := net.ParseCIDR("192.168.10.0/24")
	f.Fuzz(func(t *testing.T, b []byte) {
		md := newMDNSState(sub)
		md.handle(udp("192.168.10.30:5353"), b)
		md.handle(udp("192.168.10.31:5353"), b)
		_ = md.round2()
		for ip, types := range md.services() {
			if !inRange(sub, net.ParseIP(ip)) {
				t.Fatalf("indirizzo fuori sottorete: %s", ip)
			}
			for ty := range types {
				if _, ok := serviceType(lb(ty + ".local")); !ok {
					t.Fatalf("tipo non valido: %q", ty)
				}
			}
		}
		ss := &ssdpState{subnet: sub, hosts: map[string]*ssdpHost{}}
		ss.handle(udp("192.168.10.30:1900"), b)
		for _, h := range ss.hosts {
			if len([]rune(h.server)) > maxServerLen {
				t.Fatalf("SERVER troppo lungo: %d", len(h.server))
			}
		}
		_, _ = parseNBStat(b)
	})
}
