package infra

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	"lanterna/internal/scan"
)

// Domande multicast dell'inventario: una ricerca SSDP e una domanda mDNS,
// partono insieme al giro di ping e ascoltano le risposte per ListenWindow.
// Ogni socket usa una porta effimera dell'indirizzo della scheda esaminata:
// i dispositivi rispondono in unicast a quella porta (Windows accetta le
// risposte unicast a una domanda multicast per 3 secondi) e nessuno riceve
// altro traffico oltre alla domanda.

const (
	defaultListen = 3 * time.Second
	// maxPackets limita i pacchetti esaminati per ciascun ascolto: una rete
	// grande ne produce qualche centinaio.
	maxPackets = 1024
	// recvSlice è l'attesa massima di una lettura: così l'annullamento del
	// contesto ferma l'ascolto entro un quarto di secondo.
	recvSlice = 250 * time.Millisecond
)

type udpMulticast struct {
	c   *net.UDPConn
	dst *net.UDPAddr
}

// listenMulticast apre un socket UDP sull'indirizzo IPv4 local, con una porta
// effimera, per interrogare il gruppo group ("indirizzo:porta"). Il TTL
// multicast resta quello predefinito (1): le domande non escono dalla rete
// locale.
func listenMulticast(local net.IP, group string) (MulticastConn, error) {
	dst, err := net.ResolveUDPAddr("udp4", group)
	if err != nil {
		return nil, err
	}
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: local})
	if err != nil {
		return nil, err
	}
	if dst.IP.IsMulticast() {
		multicastInterface(c, local)
	}
	return &udpMulticast{c: c, dst: dst}, nil
}

func (u *udpMulticast) Send(b []byte) error {
	_, err := u.c.WriteToUDP(b, u.dst)
	return err
}

func (u *udpMulticast) Receive(buf []byte, deadline time.Time) (int, *net.UDPAddr, error) {
	if err := u.c.SetReadDeadline(deadline); err != nil {
		return 0, nil, err
	}
	return u.c.ReadFromUDP(buf)
}

func (u *udpMulticast) Close() error { return u.c.Close() }

// collect passa a handle i pacchetti ricevuti fino a end. Restituisce false
// se l'ascolto deve finire prima: contesto annullato, errore del socket
// diverso dalla scadenza, oppure handle che chiede di smettere.
func collect(ctx context.Context, c MulticastConn, buf []byte, end time.Time, handle func(from *net.UDPAddr, b []byte) bool) bool {
	for ctx.Err() == nil {
		now := time.Now()
		if !now.Before(end) {
			return true
		}
		dl := end
		if s := now.Add(recvSlice); s.Before(dl) {
			dl = s
		}
		n, from, err := c.Receive(buf, dl)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			return false
		}
		if from != nil && n > 0 && n <= len(buf) && !handle(from, buf[:n]) {
			return false
		}
	}
	return false
}

// inRange dice se ip è un indirizzo di host della sottorete esaminata (né
// l'indirizzo di rete né quello di broadcast).
func inRange(n *net.IPNet, ip net.IP) bool {
	ip4 := ip.To4()
	if n == nil || ip4 == nil || !n.Contains(ip4) {
		return false
	}
	m := n.Mask
	if len(m) == net.IPv6len {
		m = m[12:]
	}
	if len(m) != net.IPv4len {
		return false
	}
	mask := binary.BigEndian.Uint32(m)
	host := ipToU32(ip4) &^ mask
	return host != 0 && host != ^mask
}

// signals sono i segnali raccolti per un indirizzo dalle domande multicast.
type signals struct {
	services map[string]bool // tipi DNS-SD
	upnp     map[string]bool // tipi URN
	server   string          // intestazione SERVER
	// seen: l'indirizzo ha inviato almeno una risposta valida, quindi il
	// dispositivo esiste anche se ignora il ping.
	seen bool
}

// discover invia la ricerca SSDP e la domanda mDNS dall'indirizzo self e ne
// raccoglie le risposte in parallelo. Restituisce i segnali per indirizzo,
// solo per gli host della sottorete.
func discover(ctx context.Context, p Prims, self net.IP, subnet *net.IPNet, opt Options) map[string]*signals {
	out := map[string]*signals{}
	if p.Multicast == nil {
		return out
	}
	window := opt.ListenWindow
	if window <= 0 {
		window = defaultListen
	}
	start := time.Now()
	var (
		wg   sync.WaitGroup
		md   *mdnsState
		ssdp map[string]*ssdpHost
	)
	if c, err := p.Multicast(self, ssdpGroup); err == nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer c.Close()
			ssdp = ssdpScan(ctx, c, subnet, start.Add(window))
		}()
	}
	if c, err := p.Multicast(self, mdnsGroup); err == nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer c.Close()
			md = mdnsScan(ctx, c, subnet, opt.Interval, start, window)
		}()
	}
	wg.Wait()

	get := func(ip string) *signals {
		s := out[ip]
		if s == nil {
			s = &signals{services: map[string]bool{}, upnp: map[string]bool{}}
			out[ip] = s
		}
		return s
	}
	for ip, h := range ssdp {
		s := get(ip)
		s.seen = true
		s.server = h.server
		for t := range h.types {
			s.upnp[t] = true
		}
	}
	if md != nil {
		for ip := range md.sources {
			get(ip).seen = true
		}
		for ip, types := range md.services() {
			s := get(ip)
			for t := range types {
				s.services[t] = true
			}
		}
	}
	return out
}

// attachSignals aggiunge i segnali agli host trovati. Un indirizzo che ha
// risposto alle domande multicast entra nell'inventario anche se ha ignorato
// ping e ARP; uno citato soltanto nei record di altri dispositivi no.
func attachSignals(found map[string]*scan.InventoryHost, sigs map[string]*signals, subnet *net.IPNet) {
	for ip, s := range sigs {
		if !inRange(subnet, net.ParseIP(ip)) {
			continue
		}
		h := found[ip]
		if h == nil {
			if !s.seen {
				continue
			}
			h = &scan.InventoryHost{IP: ip}
			found[ip] = h
		}
		h.Services = sortedKeys(s.services, maxServices)
		h.UPnP = sortedKeys(s.upnp, maxUPnPTypes)
		h.Server = s.server
	}
}

// sortedKeys restituisce al massimo max chiavi in ordine alfabetico (nil se
// non ce ne sono, così il campo JSON resta assente).
func sortedKeys(m map[string]bool, max int) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) > max {
		out = out[:max]
	}
	return out
}
