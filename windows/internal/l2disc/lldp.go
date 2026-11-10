package l2disc

import "fmt"

// Tipi di TLV LLDP (IEEE 802.1AB-2016, 8.5).
const (
	lldpEnd         = 0
	lldpChassisID   = 1
	lldpPortID      = 2
	lldpTTL         = 3
	lldpPortDescr   = 4
	lldpSystemName  = 5
	lldpSystemDescr = 6
	lldpSystemCaps  = 7
	lldpMgmtAddr    = 8
	lldpOrgSpecific = 127
)

// OUI dei TLV specifici di organizzazione e sottotipi usati.
var (
	ouiDot1 = [3]byte{0x00, 0x80, 0xc2} // IEEE 802.1 (802.1Q, Annex D)
	ouiDot3 = [3]byte{0x00, 0x12, 0x0f} // IEEE 802.3 (Clause 79)
	ouiMED  = [3]byte{0x00, 0x12, 0xbb} // ANSI/TIA-1057 LLDP-MED
)

const (
	dot1PortVlan     = 1
	dot1ProtocolVlan = 2
	dot1VlanName     = 3

	dot3MacPhy = 1

	medCapabilities = 1
	medPolicy       = 2
	medManufacturer = 9  // inventario: nome del costruttore
	medModel        = 10 // inventario: modello
	// Gli altri TLV di inventario (5-7 revisioni, 8 numero di serie, 11
	// identificativo del bene) non si leggono: il numero di serie non deve
	// mai uscire da Polaris.

	maxMgmtAddrs = 8
	maxVlans     = 128
)

// Sottotipi degli identificativi di chassis e porta (802.1AB, 8.5.2.2 e 8.5.3.2).
var chassisIDTypes = map[byte]string{
	1: "chassis-component", 2: "interface-alias", 3: "port-component", 4: "mac",
	5: "network-address", 6: "interface-name", 7: "local",
}

var portIDTypes = map[byte]string{
	1: "interface-alias", 2: "port-component", 3: "mac", 4: "network-address",
	5: "interface-name", 6: "agent-circuit-id", 7: "local",
}

// Funzioni di sistema (802.1AB, 8.5.8.1), in ordine di bit.
var lldpCapNames = []string{"other", "repeater", "bridge", "wlan-ap", "router", "telephone", "docsis", "station", "c-vlan", "s-vlan", "tpmr"}

// LLDP-MED (ANSI/TIA-1057): funzioni, classi di dispositivo e applicazioni.
var (
	medCapNames  = []string{"capabilities", "network-policy", "location", "power-pse", "power-pd", "inventory"}
	medClassName = map[byte]string{1: "endpoint-1", 2: "endpoint-2", 3: "endpoint-3", 4: "network"}
	medAppNames  = map[byte]string{
		1: "voice", 2: "voice-signaling", 3: "guest-voice", 4: "guest-voice-signaling",
		5: "softphone-voice", 6: "video-conferencing", 7: "streaming-video", 8: "video-signaling",
	}
)

const medAppVoice = 1

// bitNames elenca i nomi dei bit accesi, dal bit 0 in su.
func bitNames(v uint16, names []string) []string {
	var out []string
	for i, n := range names {
		if v&(1<<i) != 0 {
			out = append(out, n)
		}
	}
	return out
}

// lldpID decodifica un identificativo di chassis o di porta: sottotipo e
// valore. macSub è il sottotipo "indirizzo MAC" (4 per lo chassis, 3 per la
// porta), addrSub quello "indirizzo di rete" (5 e 4).
func lldpID(v []byte, types map[byte]string, macSub, addrSub byte) (text, kind string) {
	if len(v) < 1 {
		return "", ""
	}
	sub, val := v[0], v[1:]
	kind = types[sub]
	if kind == "" {
		kind = fmt.Sprintf("subtype-%d", sub)
	}
	switch kind {
	case "interface-alias", "chassis-component", "port-component":
		// ifAlias ed entPhysicalAlias sono scritti dall'amministratore e
		// possono contenere nomi di persone: non si esportano (resta il tipo).
		return "", kind
	}
	switch sub {
	case macSub:
		if len(val) == 6 {
			return macString(val), kind
		}
		return hexColon(val), kind
	case addrSub:
		if len(val) >= 1 {
			if s, ok := ianaAddress(val[0], val[1:]); ok {
				return s, kind
			}
		}
		return hexColon(val), kind
	}
	return idText(val), kind
}

// mauInfo descrive un tipo di MAU (IANA-MAU-MIB, dot3MauType; LLDP
// trasmette l'ultimo numero dell'OID, IEEE 802.3 Clause 79).
type mauInfo struct {
	name   string
	mbps   int
	duplex string
}

// mauTypes: i tipi più comuni. Dai 10 Gb/s in su e per le fibre "BX/LX10"
// lo standard prevede solo il full duplex. Gli altri numeri restano in
// MauType senza nome.
var mauTypes = map[int]mauInfo{
	5:   {"10BASE-T", 10, ""},
	10:  {"10BASE-T", 10, "half"},
	11:  {"10BASE-T", 10, "full"},
	14:  {"100BASE-T4", 100, ""},
	15:  {"100BASE-TX", 100, "half"},
	16:  {"100BASE-TX", 100, "full"},
	17:  {"100BASE-FX", 100, "half"},
	18:  {"100BASE-FX", 100, "full"},
	19:  {"100BASE-T2", 100, "half"},
	20:  {"100BASE-T2", 100, "full"},
	21:  {"1000BASE-X", 1000, "half"},
	22:  {"1000BASE-X", 1000, "full"},
	23:  {"1000BASE-LX", 1000, "half"},
	24:  {"1000BASE-LX", 1000, "full"},
	25:  {"1000BASE-SX", 1000, "half"},
	26:  {"1000BASE-SX", 1000, "full"},
	27:  {"1000BASE-CX", 1000, "half"},
	28:  {"1000BASE-CX", 1000, "full"},
	29:  {"1000BASE-T", 1000, "half"},
	30:  {"1000BASE-T", 1000, "full"},
	31:  {"10GBASE-X", 10000, "full"},
	32:  {"10GBASE-LX4", 10000, "full"},
	33:  {"10GBASE-R", 10000, "full"},
	34:  {"10GBASE-ER", 10000, "full"},
	35:  {"10GBASE-LR", 10000, "full"},
	36:  {"10GBASE-SR", 10000, "full"},
	37:  {"10GBASE-W", 10000, "full"},
	38:  {"10GBASE-EW", 10000, "full"},
	39:  {"10GBASE-LW", 10000, "full"},
	40:  {"10GBASE-SW", 10000, "full"},
	41:  {"10GBASE-CX4", 10000, "full"},
	44:  {"100BASE-BX10-D", 100, "full"},
	45:  {"100BASE-BX10-U", 100, "full"},
	46:  {"100BASE-LX10", 100, "full"},
	47:  {"1000BASE-BX10-D", 1000, "full"},
	48:  {"1000BASE-BX10-U", 1000, "full"},
	49:  {"1000BASE-LX10", 1000, "full"},
	54:  {"10GBASE-T", 10000, "full"},
	55:  {"10GBASE-LRM", 10000, "full"},
	56:  {"1000BASE-KX", 1000, "full"},
	57:  {"10GBASE-KX4", 10000, "full"},
	58:  {"10GBASE-KR", 10000, "full"},
	70:  {"40GBASE-KR4", 40000, "full"},
	71:  {"40GBASE-CR4", 40000, "full"},
	72:  {"40GBASE-SR4", 40000, "full"},
	73:  {"40GBASE-FR", 40000, "full"},
	74:  {"40GBASE-LR4", 40000, "full"},
	75:  {"100GBASE-CR10", 100000, "full"},
	76:  {"100GBASE-SR10", 100000, "full"},
	77:  {"100GBASE-LR4", 100000, "full"},
	78:  {"100GBASE-ER4", 100000, "full"},
	79:  {"1000BASE-T1", 1000, "full"},
	88:  {"25GBASE-CR", 25000, "full"},
	89:  {"25GBASE-CR-S", 25000, "full"},
	90:  {"25GBASE-KR", 25000, "full"},
	91:  {"25GBASE-KR-S", 25000, "full"},
	92:  {"25GBASE-R", 25000, "full"},
	93:  {"25GBASE-SR", 25000, "full"},
	94:  {"25GBASE-T", 25000, "full"},
	95:  {"40GBASE-ER4", 40000, "full"},
	96:  {"40GBASE-R", 40000, "full"},
	97:  {"40GBASE-T", 40000, "full"},
	98:  {"100GBASE-CR4", 100000, "full"},
	99:  {"100GBASE-KR4", 100000, "full"},
	100: {"100GBASE-KP4", 100000, "full"},
	101: {"100GBASE-R", 100000, "full"},
	102: {"100GBASE-SR4", 100000, "full"},
	103: {"2.5GBASE-T", 2500, "full"},
	104: {"5GBASE-T", 5000, "full"},
	105: {"100BASE-T1", 100, "full"},
}

// parseLLDP decodifica una LLDPDU (il corpo dopo l'EtherType 0x88CC). Ogni
// TLV ha un'intestazione di 16 bit: 7 bit di tipo e 9 di lunghezza. Un TLV
// troncato chiude la lettura: si tiene ciò che è stato letto fino a lì.
func parseLLDP(b []byte) packet {
	pk := packet{proto: protoLLDP}
	n := &LLDPNeighbor{}
	var chassisRaw, portRaw []byte
	haveID := false
	for i := 0; i+2 <= len(b); {
		h := be16(b[i:])
		typ, l := int(h>>9), int(h&0x1ff)
		i += 2
		if i+l > len(b) {
			break
		}
		v := b[i : i+l]
		i += l
		if typ == lldpEnd {
			break
		}
		pk.score++
		switch typ {
		case lldpChassisID:
			if len(v) >= 1 {
				chassisRaw, haveID = v, true
				n.ChassisID, n.ChassisIDType = lldpID(v, chassisIDTypes, 4, 5)
			}
		case lldpPortID:
			if len(v) >= 1 {
				portRaw, haveID = v, true
				n.PortID, n.PortIDType = lldpID(v, portIDTypes, 3, 4)
			}
		case lldpTTL:
			if len(v) >= 2 {
				n.TTL = int(be16(v))
			}
		case lldpPortDescr:
			// Descrizione della porta: spesso è scritta dall'amministratore e
			// può contenere nomi di persone, quindi non si legge.
		case lldpSystemName:
			n.SystemName = nameText(v)
		case lldpSystemDescr:
			n.SystemDescription = descText(v)
		case lldpSystemCaps:
			if len(v) >= 4 {
				n.CapabilitiesSupported = bitNames(be16(v), lldpCapNames)
				n.Capabilities = bitNames(be16(v[2:]), lldpCapNames)
			}
		case lldpMgmtAddr:
			// Lunghezza della stringa (sottotipo compreso), famiglia IANA,
			// indirizzo; seguono numero d'interfaccia e OID, non usati.
			if len(v) >= 2 {
				if al := int(v[0]); al >= 1 && 1+al <= len(v) {
					if s, ok := ianaAddress(v[1], v[2:1+al]); ok {
						n.ManagementAddresses = appendUnique(n.ManagementAddresses, s, maxMgmtAddrs)
					}
				}
			}
		case lldpOrgSpecific:
			if len(v) >= 4 {
				lldpOrg(n, [3]byte{v[0], v[1], v[2]}, v[3], v[4:])
			}
		}
	}
	if !haveID {
		return pk
	}
	pk.lldp = n
	pk.key = rawKey(chassisRaw, portRaw)
	return pk
}

// lldpOrg decodifica i TLV specifici di organizzazione usati da Polaris.
func lldpOrg(n *LLDPNeighbor, oui [3]byte, sub byte, d []byte) {
	switch oui {
	case ouiDot1:
		switch sub {
		case dot1PortVlan:
			if len(d) >= 2 {
				n.PortVlanID = int(be16(d)) // 0 = la porta non dice la propria VLAN
			}
		case dot1ProtocolVlan:
			if len(d) >= 3 && len(n.ProtocolVlans) < maxVlans {
				n.ProtocolVlans = append(n.ProtocolVlans, ProtocolVlan{
					ID:        int(be16(d[1:])),
					Supported: d[0]&0x02 != 0,
					Enabled:   d[0]&0x04 != 0,
				})
			}
		case dot1VlanName:
			// VLAN (2 byte), lunghezza del nome (1 byte, al massimo 32), nome.
			if len(d) >= 3 && len(n.Vlans) < maxVlans {
				name := d[3:]
				if nl := int(d[2]); nl < len(name) {
					name = name[:nl]
				}
				n.Vlans = append(n.Vlans, Vlan{ID: int(be16(d)), Name: clean(name)})
			}
		}
	case ouiDot3:
		if sub == dot3MacPhy && len(d) >= 5 {
			// Autonegoziazione (bit 0 supportata, bit 1 attiva), funzioni
			// annunciate (2 byte), tipo di MAU in uso (2 byte).
			switch {
			case d[0]&0x01 == 0:
				n.Autoneg = "unsupported"
			case d[0]&0x02 != 0:
				n.Autoneg = "on"
			default:
				n.Autoneg = "off"
			}
			n.MauType = int(be16(d[3:]))
			if m, ok := mauTypes[n.MauType]; ok {
				n.Mau, n.SpeedMbps, n.Duplex = m.name, m.mbps, m.duplex
			}
		}
	case ouiMED:
		switch sub {
		case medCapabilities:
			if len(d) >= 3 {
				n.MedCapabilities = bitNames(be16(d), medCapNames)
				n.MedClass = medClassName[d[2]]
			}
		case medPolicy:
			if len(d) >= 4 {
				medNetworkPolicy(n, d)
			}
		case medManufacturer:
			n.Manufacturer = nameText(d)
		case medModel:
			n.Model = nameText(d)
		}
	}
}

// medNetworkPolicy decodifica una politica di rete LLDP-MED: tipo di
// applicazione (1 byte) e 24 bit con U (politica sconosciuta), T
// (etichettata), X (riservato), VLAN (12 bit), priorità 802.1p (3 bit) e
// DSCP (6 bit). Una politica per applicazione: l'ultima vince.
func medNetworkPolicy(n *LLDPNeighbor, d []byte) {
	app := d[0]
	pol := uint32(d[1])<<16 | uint32(d[2])<<8 | uint32(d[3])
	p := MedPolicy{
		App:      medAppNames[app],
		Unknown:  pol&0x800000 != 0,
		Tagged:   pol&0x400000 != 0,
		Vlan:     int(pol>>9) & 0xfff,
		Priority: int(pol>>6) & 0x7,
		Dscp:     int(pol & 0x3f),
	}
	if p.App == "" {
		p.App = fmt.Sprintf("app-%d", app)
	}
	if app == medAppVoice {
		n.VoiceVlan = 0
		if !p.Unknown && p.Tagged && p.Vlan >= 1 && p.Vlan <= 4094 {
			n.VoiceVlan = p.Vlan
		}
	}
	for i := range n.Policies {
		if n.Policies[i].App == p.App {
			n.Policies[i] = p
			return
		}
	}
	if len(n.Policies) < len(medAppNames)+2 {
		n.Policies = append(n.Policies, p)
	}
}
