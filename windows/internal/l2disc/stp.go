package l2disc

// Campi delle BPDU (IEEE 802.1D-2004, clausola 9; IEEE 802.1Q-2018,
// clausola 14 per MSTP). Gli offset partono dal Protocol Identifier, subito
// dopo l'intestazione LLC (o SNAP per PVST+).
const (
	bpduVersion      = 2
	bpduType         = 3
	bpduFlags        = 4
	bpduRootID       = 5
	bpduRootCost     = 13
	bpduBridgeID     = 17 // in MSTP è l'identificativo della radice regionale
	bpduPortID       = 25
	bpduMessageAge   = 27
	bpduMaxAge       = 29
	bpduHelloTime    = 31
	bpduForwardDelay = 33
	bpduConfigLen    = 35  // lunghezza della BPDU di configurazione
	bpduCISTBridgeID = 93  // MSTP: bridge che trasmette
	bpduMSTMinLen    = 101 // MSTP fino all'identificativo del bridge CIST compreso

	bpduTypeConfig = 0x00
	bpduTypeRST    = 0x02 // RSTP e MSTP
	bpduTypeTCN    = 0x80 // notifica di cambio topologia: nessun altro campo

	flagTC        = 0x01
	flagRoleMask  = 0x0c
	flagRoleShift = 2

	// PVST+ (Cisco): dopo la BPDU segue il TLV "VLAN di origine" (tipo 0,
	// lunghezza 2, VLAN). Wireshark (packet-bpdu.c) lo cerca all'offset 36;
	// per una BPDU di configurazione senza riempimento sarebbe a 35, che si
	// prova come riserva.
	pvstTLVOffset = 36
)

var stpProtocols = map[byte]string{0: "stp", 2: "rstp", 3: "mstp", 4: "spb"}

// Ruolo della porta che trasmette (bit 2-3 dei flag RSTP).
var stpRoles = map[byte]string{0: "unknown", 1: "alternate-backup", 2: "root", 3: "designated"}

// bridgeID divide un identificativo di bridge: priorità (4 bit alti, multipli
// di 4096), estensione dell'ID di sistema (12 bit: VLAN o istanza) e MAC.
func bridgeID(b []byte) (prio, ext int, mac string) {
	p := be16(b)
	return int(p & 0xf000), int(p & 0x0fff), macString(b[2:8])
}

// timer converte un tempo BPDU (unità di 1/256 di secondo) in secondi.
func timer(b []byte) int { return int(be16(b)) / 256 }

// parseBPDU decodifica una BPDU IEEE o PVST+ (pvst). Le notifiche di cambio
// topologia (TCN) si contano ma non portano informazioni.
func parseBPDU(b []byte, pvst bool) packet {
	pk := packet{proto: protoSTP}
	if len(b) < 4 || b[0] != 0 || b[1] != 0 {
		return pk
	}
	typ := b[bpduType]
	if (typ != bpduTypeConfig && typ != bpduTypeRST) || len(b) < bpduConfigLen {
		return pk
	}
	version := b[bpduVersion]
	s := &STPInfo{Format: "ieee", Protocol: stpProtocols[version]}
	if s.Protocol == "" {
		s.Protocol = "unknown"
	}
	if pvst {
		s.Format = "pvst"
		s.Vlan = pvstVlan(b)
	}
	flags := b[bpduFlags]
	s.TopologyChange = flags&flagTC != 0
	if typ == bpduTypeRST {
		s.PortRole = stpRoles[(flags&flagRoleMask)>>flagRoleShift]
	}
	s.RootPriority, s.RootSysIDExt, s.RootMac = bridgeID(b[bpduRootID:])
	s.RootPathCost = be32(b[bpduRootCost:])
	bridge := b[bpduBridgeID : bpduBridgeID+8]
	if version >= 3 && typ == bpduTypeRST && len(b) >= bpduMSTMinLen {
		bridge = b[bpduCISTBridgeID : bpduCISTBridgeID+8]
	}
	s.BridgePriority, s.BridgeSysIDExt, s.BridgeMac = bridgeID(bridge)
	port := be16(b[bpduPortID:])
	s.PortPriority, s.PortNumber = int(port>>12)*16, int(port&0x0fff)
	s.MessageAge = timer(b[bpduMessageAge:])
	s.MaxAge = timer(b[bpduMaxAge:])
	s.HelloTime = timer(b[bpduHelloTime:])
	s.ForwardDelay = timer(b[bpduForwardDelay:])
	pk.stp = s
	pk.score = 1
	pk.key = rawKey([]byte(s.Format), []byte{byte(s.Vlan >> 8), byte(s.Vlan)}, bridge, b[bpduPortID:bpduPortID+2])
	return pk
}

// pvstVlan legge la VLAN di origine di una BPDU PVST+ (0 se manca).
func pvstVlan(b []byte) int {
	for _, off := range []int{pvstTLVOffset, bpduConfigLen} {
		if off+6 <= len(b) && be16(b[off:]) == 0 && be16(b[off+2:]) == 2 {
			if v := vlanOrZero(be16(b[off+4:])); v != 0 {
				return v
			}
		}
	}
	return 0
}
