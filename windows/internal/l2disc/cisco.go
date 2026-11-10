package l2disc

import (
	"bytes"
	"fmt"
	"net"
)

// Tipi di TLV CDP usati. CDP è proprietario di Cisco: numeri e formati
// vengono dal dissettore di Wireshark (packet-cdp.c) e da lldpd, verificati
// sui campi più comuni.
const (
	cdpDeviceID   = 0x0001
	cdpAddresses  = 0x0002
	cdpPortID     = 0x0003
	cdpCaps       = 0x0004
	cdpSoftware   = 0x0005
	cdpPlatform   = 0x0006
	cdpVTPDomain  = 0x0009
	cdpNativeVlan = 0x000a
	cdpDuplex     = 0x000b
	cdpVoIPReply  = 0x000e
	cdpSystemName = 0x0014
	cdpMgmtAddrs  = 0x0016
	// 0x1001 (numero di serie, annunciato da alcuni access point) non si legge mai.

	maxCDPAddrs = 16
)

// Funzioni CDP, in ordine di bit (0x01 router ... 0x100 gestito da remoto).
var cdpCapNames = []string{"router", "bridge", "source-route-bridge", "switch", "host", "igmp", "repeater", "phone", "remote-managed"}

// Protocollo IPv6 nella forma 802.2 (LLC/SNAP + EtherType 0x86DD) usata
// dagli indirizzi CDP; IPv4 usa invece l'NLPID 0xCC.
var cdpIPv6Proto = []byte{0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x86, 0xdd}

const (
	cdpProtoNLPID = 1
	cdpProto8022  = 2
	nlpidIPv4     = 0xcc
)

// ciscoTLVs scorre i TLV di CDP e DTP: tipo e lunghezza di 16 bit, con la
// lunghezza che comprende i 4 byte d'intestazione. Un TLV troppo corto o
// troncato chiude la lettura.
func ciscoTLVs(b []byte, fn func(typ uint16, v []byte)) {
	for i := 0; i+4 <= len(b); {
		typ, l := be16(b[i:]), int(be16(b[i+2:]))
		if l < 4 || i+l > len(b) {
			return
		}
		fn(typ, b[i+4:i+l])
		i += l
	}
}

// parseCDP decodifica un pacchetto CDP: versione, TTL e checksum (4 byte),
// poi i TLV.
func parseCDP(b []byte) packet {
	pk := packet{proto: protoCDP}
	if len(b) < 4 {
		return pk
	}
	n := &CDPNeighbor{Version: int(b[0]), TTL: int(b[1])}
	var idRaw, portRaw []byte
	ciscoTLVs(b[4:], func(typ uint16, v []byte) {
		pk.score++
		switch typ {
		case cdpDeviceID:
			idRaw, n.DeviceID = v, nameText(v)
		case cdpAddresses:
			n.Addresses = cdpAddressList(v, n.Addresses)
		case cdpPortID:
			portRaw, n.PortID = v, clean(v)
		case cdpCaps:
			if len(v) >= 4 {
				n.Capabilities = bitNames(uint16(be32(v)&0xffff), cdpCapNames)
			}
		case cdpSoftware:
			n.Software = descText(v)
		case cdpPlatform:
			n.Platform = clean(v)
		case cdpVTPDomain:
			n.VtpDomain = clean(v)
		case cdpNativeVlan:
			if len(v) >= 2 {
				n.NativeVlan = vlanOrZero(be16(v))
			}
		case cdpDuplex:
			if len(v) >= 1 {
				n.Duplex = "half"
				if v[0] != 0 {
					n.Duplex = "full"
				}
			}
		case cdpVoIPReply:
			// Un byte (tipo di apparecchio, secondo Wireshark) e la VLAN
			// della voce su 2 byte.
			if len(v) >= 3 {
				n.VoiceVlan = vlanOrZero(be16(v[1:]))
			}
		case cdpSystemName:
			n.SystemName = nameText(v)
		case cdpMgmtAddrs:
			n.ManagementAddresses = cdpAddressList(v, n.ManagementAddresses)
		}
	})
	if idRaw == nil && portRaw == nil {
		return pk
	}
	pk.cdp = n
	pk.key = rawKey(idRaw, portRaw)
	return pk
}

// vlanOrZero accetta solo le VLAN valide (1-4094).
func vlanOrZero(v uint16) int {
	if v >= 1 && v <= 4094 {
		return int(v)
	}
	return 0
}

// cdpAddressList decodifica un elenco di indirizzi CDP: numero di
// indirizzi (4 byte), poi per ciascuno tipo di protocollo (1 = NLPID,
// 2 = 802.2), lunghezza e valore del protocollo, lunghezza (2 byte) e
// valore dell'indirizzo. Si tengono IPv4 e IPv6.
func cdpAddressList(v []byte, out []string) []string {
	if len(v) < 4 {
		return out
	}
	count := be32(v)
	p := 4
	for k := uint32(0); k < count && k < maxCDPAddrs; k++ {
		if p+2 > len(v) {
			break
		}
		ptype, plen := v[p], int(v[p+1])
		p += 2
		if p+plen+2 > len(v) {
			break
		}
		proto := v[p : p+plen]
		p += plen
		alen := int(be16(v[p:]))
		p += 2
		if p+alen > len(v) {
			break
		}
		a := v[p : p+alen]
		p += alen
		switch {
		case ptype == cdpProtoNLPID && plen == 1 && proto[0] == nlpidIPv4 && alen == 4:
			out = appendUnique(out, ipString(a), maxCDPAddrs)
		case ptype == cdpProto8022 && bytes.Equal(proto, cdpIPv6Proto) && alen == 16:
			out = appendUnique(out, ipString(a), maxCDPAddrs)
		}
	}
	return out
}

// ipString scrive un indirizzo IPv4 (4 byte) o IPv6 (16 byte).
func ipString(a []byte) string { return net.IP(a).String() }

// Tipi di TLV DTP (Dynamic Trunking Protocol, Cisco).
const (
	dtpDomain   = 0x0001
	dtpStatus   = 0x0002
	dtpType     = 0x0003
	dtpNeighbor = 0x0004
)

// Codifica di stato e tipo DTP. DTP non ha una specifica pubblica: i valori
// vengono dal dissettore di Wireshark (packet-dtp.c, ricostruito dal
// brevetto USA 6,445,715 di Cisco) e coincidono con i valori predefiniti
// di scapy e Yersinia (stato 0x03 = access/desirable, tipo 0xa5 =
// 802.1Q/802.1Q). Il brevetto conferma solo la struttura: stato
// amministrativo su 3 bit (on, off, desirable, auto) e stato operativo su
// 1 bit (access o trunk). Da verificare su apparati reali.
var (
	dtpAdminStatus = map[byte]string{1: "on", 2: "off", 3: "desirable", 4: "auto"} // bit 0-2 dello stato
	dtpOperType    = map[byte]string{1: "native", 2: "isl", 5: "802.1q"}           // bit 5-7 del tipo
	dtpAdminType   = map[byte]string{0: "negotiated", 1: "native", 2: "isl", 5: "802.1q"}
)

func nameOr(m map[byte]string, k byte) string {
	if s, ok := m[k]; ok {
		return s
	}
	return "unknown"
}

// parseDTP decodifica un pacchetto DTP: versione (1 byte) e TLV in stile
// CDP. src è il MAC sorgente, usato se manca il TLV del mittente.
func parseDTP(b, src []byte) packet {
	pk := packet{proto: protoDTP}
	if len(b) < 1 {
		return pk
	}
	d := &DTPInfo{Version: int(b[0])}
	var sender []byte
	ciscoTLVs(b[1:], func(typ uint16, v []byte) {
		pk.score++
		switch typ {
		case dtpDomain:
			d.Domain = clean(v)
		case dtpStatus:
			if len(v) >= 1 {
				s := v[0]
				d.RawStatus = fmt.Sprintf("0x%02x", s)
				d.OperStatus = "access"
				if s&0x80 != 0 {
					d.OperStatus = "trunk"
				}
				d.AdminStatus = nameOr(dtpAdminStatus, s&0x07)
			}
		case dtpType:
			if len(v) >= 1 {
				t := v[0]
				d.RawType = fmt.Sprintf("0x%02x", t)
				d.OperType = nameOr(dtpOperType, t>>5)
				d.AdminType = nameOr(dtpAdminType, t&0x07)
			}
		case dtpNeighbor:
			if len(v) >= 6 {
				sender = v[:6]
				d.Neighbor = macString(sender)
			}
		}
	})
	if sender == nil {
		sender = src
		if d.Neighbor == "" && len(src) == 6 {
			d.Neighbor = macString(src)
		}
	}
	pk.dtp = d
	pk.key = rawKey(sender)
	return pk
}
