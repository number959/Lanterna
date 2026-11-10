package infra

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sort"
	"strings"
	"time"
)

// mDNS (RFC 6762) e DNS-SD (RFC 6763). L'inventario fa una domanda
// "one-shot" da una porta effimera, mai dalla 5353: per i dispositivi è un
// risolutore semplice, a cui rispondono solo in unicast ripetendo l'ID e la
// domanda (RFC 6762, 5.1 e 6.7). Primo giro: la meta-domanda PTR
// "_services._dns-sd._udp.local", che elenca i tipi di servizio annunciati
// (RFC 6763, 9). Secondo giro, dopo un terzo dell'ascolto: le domande PTR per
// quei tipi, le cui risposte portano con sé i record SRV e A (RFC 6763, 12.1)
// che legano ogni istanza al proprio indirizzo.
//
// Riservatezza: i nomi delle istanze ("Stampante di Mario._ipp._tcp.local")
// e degli host ("iPhone-di-Anna.local") restano in memoria il tempo di
// collegare i servizi agli indirizzi; nell'inventario finiscono solo i tipi
// di servizio ("_ipp._tcp"). I record TXT non si leggono.

const (
	mdnsGroup = "224.0.0.251:5353"
	mdnsPort  = 5353

	dnsTypeA   = 1
	dnsTypePTR = 12
	dnsTypeSRV = 33
	dnsClassIN = 1

	mdnsMaxTypes = 32 // tipi chiesti nel secondo giro
	mdnsPerQuery = 8  // domande per pacchetto: al massimo 4 pacchetti nel secondo giro
	maxServices  = 32 // tipi esportati per host
	maxRecords   = 4096
)

var metaName = []string{"_services", "_dns-sd", "_udp", "local"}

var (
	errDNSShort = errors.New("messaggio DNS troncato")
	errDNSName  = errors.New("nome DNS non valido")
)

// mdnsQuery costruisce una domanda con una richiesta PTR per ogni nome. ID e
// flag a zero (RFC 6762, 18.1 e 18.6); classe IN senza il bit QU: arrivando
// da una porta diversa dalla 5353 la domanda riceve comunque solo risposte
// unicast.
func mdnsQuery(names ...[]string) []byte {
	msg := make([]byte, 12, 512)
	binary.BigEndian.PutUint16(msg[4:], uint16(len(names)))
	for _, n := range names {
		for _, l := range n {
			msg = append(msg, byte(len(l)))
			msg = append(msg, l...)
		}
		msg = append(msg, 0, 0, dnsTypePTR, 0, dnsClassIN)
	}
	return msg
}

// dnsName legge un nome a partire da off seguendo i puntatori di
// compressione (RFC 1035, 4.1.4) e restituisce le etichette e la posizione
// subito dopo il nome. Ogni puntatore deve tornare prima dell'inizio del
// tratto che si sta leggendo: un messaggio costruito ad arte non può creare
// cicli né far leggere fuori dal messaggio.
func dnsName(msg []byte, off int) ([]string, int, error) {
	var labels []string
	end := -1    // posizione dopo il nome nel tratto originale
	limit := off // un puntatore deve puntare prima di qui
	size := 1
	for jumps := 0; ; {
		if off < 0 || off >= len(msg) {
			return nil, 0, errDNSShort
		}
		c := int(msg[off])
		switch c & 0xc0 {
		case 0x00:
			if c == 0 {
				if end < 0 {
					end = off + 1
				}
				return labels, end, nil
			}
			if off+1+c > len(msg) {
				return nil, 0, errDNSShort
			}
			if size += c + 1; size > 255 {
				return nil, 0, errDNSName
			}
			labels = append(labels, string(msg[off+1:off+1+c]))
			off += 1 + c
		case 0xc0:
			if off+2 > len(msg) {
				return nil, 0, errDNSShort
			}
			ptr := int(binary.BigEndian.Uint16(msg[off:]) & 0x3fff)
			if end < 0 {
				end = off + 2
			}
			if jumps++; ptr >= limit || jumps > 64 {
				return nil, 0, errDNSName
			}
			off, limit = ptr, ptr
		default: // 0x40 e 0x80: etichette estese o riservate
			return nil, 0, errDNSName
		}
	}
}

// dnsRR è un record di risposta: nome, tipo, classe (senza il bit
// cache-flush di mDNS) e posizione dei dati nel messaggio, che serve per
// leggere i nomi compressi al loro interno.
type dnsRR struct {
	name  []string
	typ   uint16
	class uint16
	off   int
	len   int
}

// parseDNS legge l'intestazione e i record di un messaggio. Se il messaggio
// è malformato o troncato restituisce i record letti fino a quel punto
// insieme all'errore.
func parseDNS(msg []byte) (uint16, []dnsRR, error) {
	if len(msg) < 12 {
		return 0, nil, errDNSShort
	}
	flags := binary.BigEndian.Uint16(msg[2:])
	qd := int(binary.BigEndian.Uint16(msg[4:]))
	n := int(binary.BigEndian.Uint16(msg[6:])) + int(binary.BigEndian.Uint16(msg[8:])) + int(binary.BigEndian.Uint16(msg[10:]))
	off := 12
	for i := 0; i < qd; i++ {
		_, next, err := dnsName(msg, off)
		if err != nil {
			return flags, nil, err
		}
		if off = next + 4; off > len(msg) {
			return flags, nil, errDNSShort
		}
	}
	var rrs []dnsRR
	for i := 0; i < n && i < maxRecords; i++ {
		name, next, err := dnsName(msg, off)
		if err != nil {
			return flags, rrs, err
		}
		if next+10 > len(msg) {
			return flags, rrs, errDNSShort
		}
		rr := dnsRR{
			name:  name,
			typ:   binary.BigEndian.Uint16(msg[next:]),
			class: binary.BigEndian.Uint16(msg[next+2:]) & 0x7fff,
			off:   next + 10,
			len:   int(binary.BigEndian.Uint16(msg[next+8:])),
		}
		if rr.off+rr.len > len(msg) {
			return flags, rrs, errDNSShort
		}
		rrs = append(rrs, rr)
		off = rr.off + rr.len
	}
	return flags, rrs, nil
}

// rdataName legge il nome contenuto nei dati del record, dopo skip byte (6
// per SRV: priorità, peso e porta); il nome deve cominciare e finire nei dati.
func rdataName(msg []byte, rr dnsRR, skip int) ([]string, bool) {
	if rr.len <= skip {
		return nil, false
	}
	labels, next, err := dnsName(msg, rr.off+skip)
	if err != nil || next > rr.off+rr.len {
		return nil, false
	}
	return labels, true
}

// nameKey è la chiave di confronto di un nome: etichette in minuscolo (solo
// ASCII, come nel DNS) precedute dalla lunghezza, così due nomi diversi non
// danno mai la stessa chiave.
func nameKey(labels []string) string {
	var b strings.Builder
	for _, l := range labels {
		b.WriteByte(byte(len(l)))
		for i := 0; i < len(l); i++ {
			c := l[i]
			if 'A' <= c && c <= 'Z' {
				c += 'a' - 'A'
			}
			b.WriteByte(c)
		}
	}
	return b.String()
}

var metaKey = nameKey(metaName)

// serviceType restituisce "_servizio._tcp" (o "_udp") da un nome che finisce
// con "_servizio._tcp.local".
func serviceType(labels []string) (string, bool) {
	n := len(labels)
	if n < 3 || !strings.EqualFold(labels[n-1], "local") {
		return "", false
	}
	proto := strings.ToLower(labels[n-2])
	if proto != "_tcp" && proto != "_udp" {
		return "", false
	}
	svc := strings.ToLower(labels[n-3])
	if !validService(svc) {
		return "", false
	}
	return svc + "." + proto, true
}

// validService accetta "_" seguito da 1-31 lettere, cifre, trattini o
// trattini bassi. L'RFC 6335 si ferma a 15 caratteri senza "_" interni, ma
// alcuni dispositivi diffusi lo superano ("_androidtvremote2",
// "_nvstream_dbd"); il controllo esclude comunque spazi e testo libero.
func validService(s string) bool {
	if len(s) < 2 || len(s) > 32 || s[0] != '_' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// browseType riconosce il nome di una ricerca di istanze: "_ipp._tcp.local"
// oppure, per un sottotipo, "_universal._sub._ipp._tcp.local".
func browseType(labels []string) (string, bool) {
	switch {
	case len(labels) == 3:
	case len(labels) == 5 && strings.EqualFold(labels[1], "_sub"):
	default:
		return "", false
	}
	return serviceType(labels[len(labels)-3:])
}

// mdnsPTR è un'istanza vista in una risposta: chi l'ha annunciata, il tipo e
// la chiave del nome dell'istanza (solo in memoria).
type mdnsPTR struct {
	src, typ, inst string
}

// mdnsState raccoglie le risposte mDNS.
type mdnsState struct {
	subnet  *net.IPNet
	meta    map[string]map[string]bool // origine → tipi elencati dalla meta-domanda
	count   map[string]int             // tipo → origini che lo elencano
	ptrs    []mdnsPTR
	srv     map[string]string   // istanza → host (destinazione del record SRV)
	addrs   map[string][]net.IP // host → indirizzi IPv4 (record A)
	sources map[string]bool     // indirizzi da cui è arrivata una risposta valida
	packets int
}

func newMDNSState(subnet *net.IPNet) *mdnsState {
	return &mdnsState{
		subnet:  subnet,
		meta:    map[string]map[string]bool{},
		count:   map[string]int{},
		srv:     map[string]string{},
		addrs:   map[string][]net.IP{},
		sources: map[string]bool{},
	}
}

// handle esamina un pacchetto; false quando si è superato il limite di
// pacchetti. Si accettano solo risposte dalla porta 5353 (RFC 6762, 6) di un
// host della sottorete (RFC 6762, 11), con OPCODE e RCODE a zero (18.3 e
// 18.11); l'ID non conta (18.1).
func (m *mdnsState) handle(from *net.UDPAddr, b []byte) bool {
	if m.packets++; m.packets > maxPackets {
		return false
	}
	src := from.IP.To4()
	if src == nil || from.Port != mdnsPort || !inRange(m.subnet, src) {
		return true
	}
	flags, rrs, _ := parseDNS(b)
	if flags&0x8000 == 0 || flags&0x7800 != 0 || flags&0x000f != 0 || len(rrs) == 0 {
		return true
	}
	s := src.String()
	m.sources[s] = true
	for _, rr := range rrs {
		if rr.class != dnsClassIN {
			continue
		}
		switch rr.typ {
		case dnsTypePTR:
			target, ok := rdataName(b, rr, 0)
			if !ok {
				continue
			}
			if nameKey(rr.name) == metaKey {
				if t, ok := serviceType(target); ok && len(target) == 3 {
					m.addMeta(s, t)
				}
			} else if t, ok := browseType(rr.name); ok && len(target) > 3 && len(m.ptrs) < maxRecords {
				if it, ok := serviceType(target); ok && it == t {
					m.ptrs = append(m.ptrs, mdnsPTR{src: s, typ: t, inst: nameKey(target)})
				}
			}
		case dnsTypeSRV:
			if target, ok := rdataName(b, rr, 6); ok && len(rr.name) > 0 && len(m.srv) < maxRecords {
				m.srv[nameKey(rr.name)] = nameKey(target)
			}
		case dnsTypeA:
			if rr.len == 4 && len(rr.name) > 0 && len(m.addrs) < maxRecords {
				m.addAddr(nameKey(rr.name), net.IPv4(b[rr.off], b[rr.off+1], b[rr.off+2], b[rr.off+3]).To4())
			}
		}
	}
	return true
}

func (m *mdnsState) addMeta(src, t string) {
	if m.meta[src] == nil {
		m.meta[src] = map[string]bool{}
	}
	if !m.meta[src][t] && len(m.meta[src]) < maxServices {
		m.meta[src][t] = true
		m.count[t]++
	}
}

func (m *mdnsState) addAddr(host string, ip net.IP) {
	for _, a := range m.addrs[host] {
		if a.Equal(ip) {
			return
		}
	}
	if len(m.addrs[host]) < 8 {
		m.addrs[host] = append(m.addrs[host], ip)
	}
}

// round2 prepara le domande PTR per i tipi elencati: i più diffusi per primi,
// al massimo mdnsMaxTypes, mdnsPerQuery domande per pacchetto (RFC 6762, 5.3).
func (m *mdnsState) round2() [][]byte {
	types := make([]string, 0, len(m.count))
	for t := range m.count {
		types = append(types, t)
	}
	sort.Slice(types, func(i, j int) bool {
		if a, b := m.count[types[i]], m.count[types[j]]; a != b {
			return a > b
		}
		return types[i] < types[j]
	})
	if len(types) > mdnsMaxTypes {
		types = types[:mdnsMaxTypes]
	}
	var out [][]byte
	for len(types) > 0 {
		k := min(len(types), mdnsPerQuery)
		names := make([][]string, k)
		for i, t := range types[:k] {
			svc, proto, _ := strings.Cut(t, ".")
			names[i] = []string{svc, proto, "local"}
		}
		out = append(out, mdnsQuery(names...))
		types = types[k:]
	}
	return out
}

// services attribuisce i tipi agli indirizzi della sottorete. Un'istanza
// vale per gli indirizzi del suo host (SRV → A) e, se mancano quei record,
// per l'indirizzo che l'ha annunciata. I tipi della meta-domanda valgono per
// chi li ha elencati, tranne quando le sue istanze di quel tipo risultano
// tutte di altri host: succede con il proxy del sonno di Apple o con un
// gateway mDNS, che rispondono per conto di altri dispositivi.
func (m *mdnsState) services() map[string]map[string]bool {
	out := map[string]map[string]bool{}
	add := func(ip, t string) {
		if !inRange(m.subnet, net.ParseIP(ip)) {
			return
		}
		if out[ip] == nil {
			out[ip] = map[string]bool{}
		}
		out[ip][t] = true
	}
	type key struct{ src, typ string }
	own, other := map[key]bool{}, map[key]bool{}
	for _, p := range m.ptrs {
		k := key{p.src, p.typ}
		var ips []net.IP
		if host, ok := m.srv[p.inst]; ok {
			ips = m.addrs[host]
		}
		if len(ips) == 0 {
			add(p.src, p.typ)
			own[k] = true
			continue
		}
		for _, ip := range ips {
			add(ip.String(), p.typ)
			if ip.String() == p.src {
				own[k] = true
			} else {
				other[k] = true
			}
		}
	}
	for src, types := range m.meta {
		for t := range types {
			if k := (key{src, t}); other[k] && !own[k] {
				continue
			}
			add(src, t)
		}
	}
	return out
}

// mdnsScan fa i due giri di domande e ascolta le risposte fino a
// start+window. La prima domanda parte dopo un intervallo del ritmo
// prudente, il secondo giro a un terzo dell'ascolto, un pacchetto per
// intervallo.
func mdnsScan(ctx context.Context, c MulticastConn, subnet *net.IPNet, interval time.Duration, start time.Time, window time.Duration) *mdnsState {
	st := newMDNSState(subnet)
	pc := newPacer(interval)
	defer pc.stop()
	send := func(q []byte) bool { return pc.wait(ctx) && ctx.Err() == nil && c.Send(q) == nil }
	if !send(mdnsQuery(metaName)) {
		return st
	}
	buf := make([]byte, 64<<10)
	if !collect(ctx, c, buf, start.Add(window/3), st.handle) {
		return st
	}
	for _, q := range st.round2() {
		if !send(q) {
			break
		}
	}
	collect(ctx, c, buf, start.Add(window), st.handle)
	return st
}
