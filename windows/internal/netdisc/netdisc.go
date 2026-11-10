// Package netdisc raccoglie quello che il PC sa già delle altre reti
// interne, senza contattare i dispositivi: la tabella di instradamento (le
// rotte ricevute dal DHCP con le opzioni 121 e 249 elencano spesso le altre
// sottoreti) e, su richiesta e solo per i PC in un dominio, le sottoreti
// definite in Active Directory (Siti e servizi), leggibili da ogni utente del
// dominio con una sola interrogazione al controller di dominio.
package netdisc

import (
	"net"
	"sort"
	"strings"
	"unicode"

	"lanterna/internal/scan"
)

// Route è una rotta IPv4 della tabella di instradamento verso un'altra rete.
type Route = scan.Route

// rawRoute è una riga della tabella come la legge Windows, prima del filtro.
type rawRoute struct {
	dest    net.IP
	prefix  int
	nextHop net.IP
	metric  uint32
	proto   uint32
	origin  uint32
}

var privateNets = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"} {
		_, n, _ := net.ParseCIDR(c)
		out = append(out, n)
	}
	return out
}()

func private(ip net.IP) bool {
	for _, n := range privateNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Valori di NL_ROUTE_PROTOCOL e NL_ROUTE_ORIGIN (nldef.h) usati per l'origine.
const (
	protoLocal   = 2 // MIB_IPPROTO_LOCAL: rete collegata direttamente
	protoNetMgmt = 3 // MIB_IPPROTO_NETMGMT: statica (route add, criteri)
	protoDHCP    = 19
	originDHCP   = 2 // NlroDHCP
)

// filterRoutes tiene le rotte verso reti private diverse da quelle del PC:
// niente rotta predefinita, rotte verso singoli indirizzi, multicast,
// broadcast, loopback e indirizzi automatici 169.254.
func filterRoutes(rows []rawRoute) []Route {
	seen := map[string]bool{}
	var out []Route
	for _, r := range rows {
		ip := r.dest.To4()
		if ip == nil || r.prefix < 8 || r.prefix > 30 || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || !private(ip) {
			continue
		}
		n := &net.IPNet{IP: ip.Mask(net.CIDRMask(r.prefix, 32)), Mask: net.CIDRMask(r.prefix, 32)}
		key := n.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		rt := Route{Prefix: key, Metric: r.metric}
		if nh := r.nextHop.To4(); nh != nil && !nh.IsUnspecified() {
			rt.NextHop = nh.String()
		}
		switch {
		case r.origin == originDHCP || r.proto == protoDHCP:
			rt.Origin = "dhcp"
		case r.proto == protoLocal && rt.NextHop == "":
			rt.Origin = "rete collegata"
		case r.proto == protoNetMgmt:
			rt.Origin = "manuale"
		default:
			rt.Origin = "altro"
		}
		out = append(out, rt)
	}
	sort.Slice(out, func(i, j int) bool { return ipLess(out[i].Prefix, out[j].Prefix) })
	return out
}

func ipLess(a, b string) bool {
	ia, _, _ := net.ParseCIDR(a)
	ib, _, _ := net.ParseCIDR(b)
	if ia == nil || ib == nil {
		return a < b
	}
	return string(ia.To16()) < string(ib.To16())
}

// ADSubnets è l'elenco delle sottoreti definite in Active Directory.
type ADSubnets struct {
	// Read: ok | nodomain (il PC non è in un dominio) | unreachable (controller
	// di dominio non raggiungibile) | denied | error.
	Read    string     `json:"read"`
	Subnets []ADSubnet `json:"subnets,omitempty"`
	Error   string     `json:"error,omitempty"`
}

// ADSubnet è una sottorete con il nome del sito a cui appartiene. Le
// descrizioni libere degli oggetti non vengono lette.
type ADSubnet struct {
	Prefix string `json:"prefix"`
	Site   string `json:"site,omitempty"`
}

// parseADOutput interpreta le righe dello script: "S<TAB>cidr<TAB>sito",
// "NODOMAIN" o "ERR<TAB>codice".
func parseADOutput(out string) ADSubnets {
	res := ADSubnets{Read: "ok", Subnets: []ADSubnet{}}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.ReplaceAll(out, "\r", ""), "\n") {
		f := strings.Split(strings.TrimSpace(line), "\t")
		switch f[0] {
		case "NODOMAIN":
			return ADSubnets{Read: "nodomain"}
		case "ERR":
			code := ""
			if len(f) > 1 {
				code = f[1]
			}
			return adError(code)
		case "S":
			if len(f) < 2 {
				continue
			}
			_, n, err := net.ParseCIDR(strings.TrimSpace(f[1]))
			if err != nil || seen[n.String()] {
				continue
			}
			seen[n.String()] = true
			s := ADSubnet{Prefix: n.String()}
			if len(f) > 2 {
				s.Site = clean(f[2], 64)
			}
			res.Subnets = append(res.Subnets, s)
			if len(res.Subnets) >= 2000 {
				return res
			}
		}
	}
	sort.Slice(res.Subnets, func(i, j int) bool { return ipLess(res.Subnets[i].Prefix, res.Subnets[j].Prefix) })
	return res
}

// adError traduce il codice HRESULT dell'eccezione .NET in uno stato.
func adError(code string) ADSubnets {
	switch strings.ToUpper(code) {
	case "-2147016646", "0X8007203A": // server non operativo
		return ADSubnets{Read: "unreachable", Error: "Il controller di dominio non risponde: il PC è fuori dalla rete dell'organizzazione?"}
	case "-2147024891", "0X80070005": // accesso negato
		return ADSubnets{Read: "denied", Error: "Accesso negato alla configurazione del dominio."}
	}
	return ADSubnets{Read: "error", Error: "Lettura delle sottoreti di Active Directory non riuscita."}
}

// clean toglie i caratteri di controllo e limita la lunghezza.
func clean(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if r := []rune(s); len(r) > max {
		s = string(r[:max])
	}
	return s
}
