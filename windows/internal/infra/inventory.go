package infra

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"lanterna/internal/scan"
	"lanterna/internal/winapi"
)

// MaxPrefix è la sottorete più ampia esaminata per intero (/22 = 1022
// indirizzi); oltre si esamina solo il blocco /24 del PC.
const MaxPrefix = 22

// InventoryRequest descrive la rete da esaminare.
type InventoryRequest struct {
	CIDR    string // indirizzo del PC con il prefisso, per esempio 192.168.1.20/24
	Adapter string
	Gateway string
	SelfMAC string
}

// Progress riceve l'avanzamento: phase è "ping" o "nomi".
type Progress func(phase string, done, total int)

func ipToU32(ip net.IP) uint32 { return binary.BigEndian.Uint32(ip.To4()) }

func u32ToIP(v uint32) net.IP {
	b := make(net.IP, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

// Plan calcola la sottorete da esaminare e l'elenco dei suoi indirizzi
// (esclusi indirizzo di rete e broadcast).
func Plan(cidr string) (*net.IPNet, []net.IP, string, error) {
	ip, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, "", fmt.Errorf("indirizzo non valido: %q", cidr)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, nil, "", errors.New("l'inventario esamina solo le reti IPv4")
	}
	if !Private(ip4) {
		return nil, nil, "", fmt.Errorf("%s non è un indirizzo privato: l'inventario si esegue solo nelle reti locali", ip4)
	}
	ones, _ := n.Mask.Size()
	note := ""
	if ones < MaxPrefix {
		m := net.CIDRMask(24, 32)
		n = &net.IPNet{IP: ip4.Mask(m), Mask: m}
		note = fmt.Sprintf("La sottorete /%d contiene troppi indirizzi per un esame prudente: è stato esaminato solo il blocco %s in cui si trova il PC.", ones, n)
		ones = 24
	}
	if ones >= 31 {
		return nil, nil, "", errors.New("la sottorete non contiene altri dispositivi da cercare")
	}
	base := ipToU32(n.IP)
	size := uint32(1) << (32 - ones)
	hosts := make([]net.IP, 0, size-2)
	for i := uint32(1); i < size-1; i++ {
		hosts = append(hosts, u32ToIP(base+i))
	}
	return n, hosts, note, nil
}

// printable tiene solo i caratteri stampabili (i nomi NetBIOS possono
// contenere byte in codifiche locali).
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == '�' {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
}

// Inventory censisce la sottorete del PC: ping a ogni indirizzo con ritmo
// prudente, tabella ARP (molti dispositivi che ignorano il ping rispondono
// comunque alla richiesta ARP che lo precede), poi nome DNS inverso e nome
// NetBIOS dei soli dispositivi trovati. Non apre connessioni verso le porte.
func Inventory(ctx context.Context, req InventoryRequest, p Prims, opt Options, progress Progress) (*scan.Inventory, error) {
	start := time.Now()
	subnet, hosts, note, err := Plan(req.CIDR)
	if err != nil {
		return nil, err
	}
	self, _, _ := net.ParseCIDR(req.CIDR)
	self = self.To4()
	targets := make([]net.IP, 0, len(hosts))
	for _, h := range hosts {
		if !h.Equal(self) {
			targets = append(targets, h)
		}
	}
	if opt.Workers < 1 {
		opt.Workers = 1
	}
	// Le goroutine incrementano il contatore e poi riferiscono: due di loro
	// possono riferire in ordine inverso (6 prima di 5). Si inoltra solo un
	// valore che non torna indietro, così l'ultimo avanzamento è sempre quello
	// finale.
	var repMu sync.Mutex
	last := map[string]int{}
	report := func(phase string, done, total int) {
		if progress == nil {
			return
		}
		repMu.Lock()
		defer repMu.Unlock()
		if prev, ok := last[phase]; ok && done < prev {
			return
		}
		last[phase] = done
		progress(phase, done, total)
	}

	var mu sync.Mutex
	found := map[string]*scan.InventoryHost{}

	// 1. Ping: un pinger per lavoratore, una richiesta per intervallo.
	jobs := make(chan net.IP)
	var wg sync.WaitGroup
	var done int32
	total := len(targets)
	report("ping", 0, total)
	for w := 0; w < opt.Workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var pg winapi.Pinger
			if p.NewPinger != nil {
				pg, _ = p.NewPinger()
			}
			if pg != nil {
				defer pg.Close()
			}
			for ip := range jobs {
				if pg != nil {
					r := pg.Echo(ip, 64, 32, false, opt.PingTimeout)
					if r.Status == winapi.EchoOK && (r.From == nil || r.From.Equal(ip)) {
						v := ms(r.RTT)
						mu.Lock()
						found[ip.String()] = &scan.InventoryHost{IP: ip.String(), RttMs: &v}
						mu.Unlock()
					}
				}
				report("ping", int(atomic.AddInt32(&done, 1)), total)
			}
		}()
	}
	pc := newPacer(opt.Interval)
	for _, ip := range targets {
		if !pc.wait(ctx) {
			break
		}
		select {
		case jobs <- ip:
		case <-ctx.Done():
		}
	}
	close(jobs)
	pc.stop()
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("inventario interrotto: %w", err)
	}

	// 2. Tabella ARP letta dopo il giro di ping, quando è più completa.
	if p.Neighbors != nil {
		if ns, err := p.Neighbors(); err == nil {
			for _, nb := range ns {
				ip := net.ParseIP(nb.IP).To4()
				if ip == nil || !subnet.Contains(ip) || ip.Equal(self) {
					continue
				}
				h := found[ip.String()]
				if h == nil {
					h = &scan.InventoryHost{IP: ip.String()}
					found[ip.String()] = h
				}
				h.MAC = nb.MAC
			}
		}
	}
	found[self.String()] = &scan.InventoryHost{IP: self.String(), MAC: req.SelfMAC, Self: true}
	if g := found[req.Gateway]; g != nil {
		g.Gateway = true
	}
	list := make([]*scan.InventoryHost, 0, len(found))
	for _, h := range found {
		h.RandomMAC = h.MAC != "" && RandomMAC(h.MAC)
		list = append(list, h)
	}
	sort.Slice(list, func(i, j int) bool { return ipToU32(net.ParseIP(list[i].IP)) < ipToU32(net.ParseIP(list[j].IP)) })

	// 3. Nomi dei dispositivi trovati (DNS inverso e NetBIOS), con lo stesso ritmo.
	named := make(chan *scan.InventoryHost)
	var nd int32
	report("nomi", 0, len(list))
	for w := 0; w < opt.Workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range named {
				ip := net.ParseIP(h.IP)
				if p.LookupAddr != nil {
					lctx, cancel := context.WithTimeout(ctx, opt.NameTimeout)
					if names, err := p.LookupAddr(lctx, h.IP); err == nil && len(names) > 0 {
						h.Name = printable(strings.TrimSuffix(names[0], "."))
					}
					cancel()
				}
				if p.NetBIOS != nil && !h.Self {
					h.NetBIOS = printable(p.NetBIOS(ctx, ip, opt.NameTimeout))
				}
				report("nomi", int(atomic.AddInt32(&nd, 1)), len(list))
			}
		}()
	}
	pc = newPacer(opt.Interval)
	for _, h := range list {
		if !pc.wait(ctx) {
			break
		}
		select {
		case named <- h:
		case <-ctx.Done():
		}
	}
	close(named)
	pc.stop()
	wg.Wait()

	inv := &scan.Inventory{
		Subnet:     subnet.String(),
		Adapter:    req.Adapter,
		Scanned:    len(targets),
		Note:       note,
		StartedAt:  start.UTC().Format(time.RFC3339),
		DurationMs: time.Since(start).Milliseconds(),
		Hosts:      make([]scan.InventoryHost, len(list)),
	}
	for i, h := range list {
		inv.Hosts[i] = *h
	}
	return inv, nil
}
