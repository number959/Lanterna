// Package l2disc ascolta e decodifica gli annunci di livello 2 che arrivano
// alla scheda di rete cablata del PC: LLDP (IEEE 802.1AB, con le estensioni
// IEEE 802.1, IEEE 802.3 e ANSI/TIA-1057 LLDP-MED), CDP e DTP di Cisco e le
// BPDU dello Spanning Tree (IEEE 802.1D, 802.1w, 802.1s e PVST+ di Cisco).
// Dicono a quale switch e a quale porta è collegato il PC, in quale VLAN si
// trova la porta, quali VLAN conosce lo switch, la VLAN della voce, il
// dominio VTP, se la porta negozia un trunk e chi è la radice dello Spanning
// Tree.
//
// Polaris non trasmette nulla: ascolta soltanto. I decodificatori non
// dipendono dal sistema operativo e i test usano trame costruite byte per
// byte; la cattura (Listen) usa quella integrata in Windows e funziona solo
// su Windows, da amministratore.
package l2disc

import (
	"encoding/binary"
	"encoding/hex"
)

// Stati della lettura (Discovery.Read).
const (
	ReadOK          = "ok"          // almeno una trama riconosciuta (LLDP, CDP, DTP, BPDU, VTP o 802.1X)
	ReadNone        = "none"        // ascolto concluso senza annunci
	ReadNoWired     = "nowired"     // nessuna scheda cablata collegata: ascolto non avviato
	ReadAdmin       = "admin"       // serve Polaris avviato come amministratore
	ReadUnsupported = "unsupported" // cattura dei pacchetti non disponibile
	ReadError       = "error"       // ascolto non riuscito (dettagli in Error)
)

// Discovery riassume ciò che lo switch annuncia sulla porta del PC.
type Discovery struct {
	Read     string         `json:"read"`               // vedi le costanti Read*
	Seconds  int            `json:"seconds"`            // durata dell'ascolto (0 se non è partito)
	Frames   int            `json:"frames"`             // trame ricevute, di qualunque protocollo
	Counts   Counts         `json:"counts"`             // trame per protocollo
	Adapters []string       `json:"adapters,omitempty"` // schede cablate in ascolto
	Lldp     []LLDPNeighbor `json:"lldp,omitempty"`
	Cdp      []CDPNeighbor  `json:"cdp,omitempty"`
	Dtp      []DTPInfo      `json:"dtp,omitempty"`   // una voce per porta che manda DTP
	Stp      []STPInfo      `json:"stp,omitempty"`   // una voce per bridge, porta e VLAN (PVST+)
	Error    string         `json:"error,omitempty"` // in italiano, senza percorsi né nomi utente
}

// Counts conta le trame ricevute per protocollo.
type Counts struct {
	Lldp  int `json:"lldp"`
	Cdp   int `json:"cdp"`
	Dtp   int `json:"dtp"`
	Stp   int `json:"stp"`   // BPDU IEEE e PVST+, comprese le notifiche di cambio topologia
	Vtp   int `json:"vtp"`   // annunci VTP: di solito solo sui trunk
	Eapol int `json:"eapol"` // 802.1X: lo switch chiede l'autenticazione della porta
	Other int `json:"other"` // trame non riconosciute
}

// LLDPNeighbor è un vicino LLDP: uno per coppia chassis+porta.
type LLDPNeighbor struct {
	Adapter               string         `json:"adapter,omitempty"` // scheda del PC che l'ha ricevuto
	ChassisID             string         `json:"chassisId"`
	ChassisIDType         string         `json:"chassisIdType"` // mac | network-address | interface-name | interface-alias | chassis-component | port-component | local
	PortID                string         `json:"portId"`
	PortIDType            string         `json:"portIdType"` // mac | network-address | interface-name | interface-alias | port-component | agent-circuit-id | local
	TTL                   int            `json:"ttl"`        // secondi; 0 = il vicino si sta spegnendo
	SystemName            string         `json:"systemName,omitempty"`
	SystemDescription     string         `json:"systemDescription,omitempty"` // prima riga
	Capabilities          []string       `json:"capabilities,omitempty"`      // funzioni attive: other, repeater, bridge, wlan-ap, router, telephone, docsis, station, c-vlan, s-vlan, tpmr
	CapabilitiesSupported []string       `json:"capabilitiesSupported,omitempty"`
	ManagementAddresses   []string       `json:"managementAddresses,omitempty"`
	PortVlanID            int            `json:"portVlanId,omitempty"` // VLAN non etichettata della porta (PVID)
	ProtocolVlans         []ProtocolVlan `json:"protocolVlans,omitempty"`
	Vlans                 []Vlan         `json:"vlans,omitempty"`     // VLAN con nome annunciate sulla porta
	VoiceVlan             int            `json:"voiceVlan,omitempty"` // dalla politica di rete LLDP-MED "voice", se etichettata
	Policies              []MedPolicy    `json:"policies,omitempty"`  // politiche di rete LLDP-MED
	MedClass              string         `json:"medClass,omitempty"`  // endpoint-1 | endpoint-2 | endpoint-3 | network
	MedCapabilities       []string       `json:"medCapabilities,omitempty"`
	Manufacturer          string         `json:"manufacturer,omitempty"` // inventario LLDP-MED (mai il numero di serie)
	Model                 string         `json:"model,omitempty"`
	Autoneg               string         `json:"autoneg,omitempty"`   // on | off | unsupported
	MauType               int            `json:"mauType,omitempty"`   // tipo di MAU in uso (IANA-MAU-MIB)
	Mau                   string         `json:"mau,omitempty"`       // es. 1000BASE-T
	SpeedMbps             int            `json:"speedMbps,omitempty"` // velocità del collegamento secondo lo switch
	Duplex                string         `json:"duplex,omitempty"`    // full | half
	Frames                int            `json:"frames"`
}

// Vlan è una VLAN annunciata con il suo nome (IEEE 802.1, VLAN Name).
type Vlan struct {
	ID   int    `json:"id"`
	Name string `json:"name,omitempty"`
}

// ProtocolVlan è una VLAN per protocollo (IEEE 802.1, Port and Protocol VLAN ID).
type ProtocolVlan struct {
	ID        int  `json:"id"`
	Supported bool `json:"supported"`
	Enabled   bool `json:"enabled"`
}

// MedPolicy è una politica di rete LLDP-MED (ANSI/TIA-1057, Network Policy).
type MedPolicy struct {
	App      string `json:"app"`               // voice | voice-signaling | guest-voice | guest-voice-signaling | softphone-voice | video-conferencing | streaming-video | video-signaling | app-N
	Unknown  bool   `json:"unknown,omitempty"` // politica non definita dallo switch (bit U)
	Tagged   bool   `json:"tagged"`            // traffico etichettato nella VLAN indicata (bit T)
	Vlan     int    `json:"vlan,omitempty"`
	Priority int    `json:"priority"` // priorità 802.1p
	Dscp     int    `json:"dscp"`
}

// CDPNeighbor è un vicino CDP: uno per coppia dispositivo+porta.
type CDPNeighbor struct {
	Adapter             string   `json:"adapter,omitempty"`
	Version             int      `json:"version"`
	TTL                 int      `json:"ttl"`
	DeviceID            string   `json:"deviceId"` // senza l'eventuale numero di serie
	PortID              string   `json:"portId,omitempty"`
	Platform            string   `json:"platform,omitempty"`
	Software            string   `json:"software,omitempty"`     // prima riga della versione
	Capabilities        []string `json:"capabilities,omitempty"` // router, bridge, source-route-bridge, switch, host, igmp, repeater, phone, remote-managed
	Addresses           []string `json:"addresses,omitempty"`
	ManagementAddresses []string `json:"managementAddresses,omitempty"`
	NativeVlan          int      `json:"nativeVlan,omitempty"`
	VoiceVlan           int      `json:"voiceVlan,omitempty"` // VoIP VLAN Reply
	VtpDomain           string   `json:"vtpDomain,omitempty"`
	Duplex              string   `json:"duplex,omitempty"` // full | half
	SystemName          string   `json:"systemName,omitempty"`
	Frames              int      `json:"frames"`
}

// DTPInfo descrive la negoziazione del trunk (DTP, Cisco) annunciata dalla
// porta. Un PC che riceve DTP è collegato a una porta che potrebbe essere
// portata a trunk. La codifica di stato e tipo non ha una specifica pubblica:
// vedi parseDTP.
type DTPInfo struct {
	Adapter     string `json:"adapter,omitempty"`
	Version     int    `json:"version"`
	Domain      string `json:"domain,omitempty"`      // dominio VTP
	OperStatus  string `json:"operStatus,omitempty"`  // access | trunk
	AdminStatus string `json:"adminStatus,omitempty"` // on | off | desirable | auto | unknown
	OperType    string `json:"operType,omitempty"`    // native | isl | 802.1q | unknown
	AdminType   string `json:"adminType,omitempty"`   // negotiated | native | isl | 802.1q | unknown
	RawStatus   string `json:"rawStatus,omitempty"`   // byte di stato come trasmesso, es. 0x03
	RawType     string `json:"rawType,omitempty"`     // byte di tipo come trasmesso, es. 0xa5
	Neighbor    string `json:"neighbor,omitempty"`    // MAC della porta dello switch
	Frames      int    `json:"frames"`
}

// STPInfo è una BPDU dello Spanning Tree: una voce per bridge, porta e VLAN.
type STPInfo struct {
	Adapter        string `json:"adapter,omitempty"`
	Format         string `json:"format"`         // ieee | pvst
	Protocol       string `json:"protocol"`       // stp | rstp | mstp | spb | unknown
	Vlan           int    `json:"vlan,omitempty"` // PVST+: VLAN di origine annunciata nella BPDU
	RootPriority   int    `json:"rootPriority"`   // multiplo di 4096
	RootSysIDExt   int    `json:"rootSysIdExt"`   // estensione dell'ID di sistema: con PVST+ è la VLAN
	RootMac        string `json:"rootMac"`
	RootPathCost   uint32 `json:"rootPathCost"`
	BridgePriority int    `json:"bridgePriority"` // bridge che trasmette (lo switch della porta)
	BridgeSysIDExt int    `json:"bridgeSysIdExt"`
	BridgeMac      string `json:"bridgeMac"`
	PortPriority   int    `json:"portPriority"`
	PortNumber     int    `json:"portNumber"`
	PortRole       string `json:"portRole,omitempty"`       // solo RSTP/MSTP: root | designated | alternate-backup | unknown
	TopologyChange bool   `json:"topologyChange,omitempty"` // almeno una BPDU con il bit TC durante l'ascolto
	MessageAge     int    `json:"messageAge"`               // secondi
	MaxAge         int    `json:"maxAge"`
	HelloTime      int    `json:"helloTime"`
	ForwardDelay   int    `json:"forwardDelay"`
	Frames         int    `json:"frames"`
}

// Frame è una trama Ethernet catturata, dall'indirizzo di destinazione in
// poi (senza preambolo né FCS). Adapter è il nome della scheda del PC che
// l'ha ricevuta, se noto.
type Frame struct {
	Adapter string
	Data    []byte
}

// Limiti contro le trame artefatte: oltre questi numeri le trame si contano
// ma non si conservano.
const (
	maxEntries = 64    // vicini (o istanze STP) per protocollo
	maxFrames  = 20000 // trame decodificate per riepilogo
)

// Summarize decodifica le trame e riassume ciò che annunciano.
func Summarize(frames [][]byte) Discovery {
	fs := make([]Frame, len(frames))
	for i, f := range frames {
		fs[i] = Frame{Data: f}
	}
	return SummarizeFrames(fs)
}

// SummarizeFrames è come Summarize ma conserva la scheda che ha ricevuto
// ogni trama. I vicini si contano una volta sola (stesso chassis e stessa
// porta, oppure stesso dispositivo e stessa porta); a parità di vicino vale
// la trama più completa, a parità di completezza la più recente.
func SummarizeFrames(frames []Frame) Discovery {
	d := Discovery{Read: ReadNone}
	var (
		lldp dedup[LLDPNeighbor]
		cdp  dedup[CDPNeighbor]
		dtp  dedup[DTPInfo]
		stp  dedup[STPInfo]
	)
	for i, f := range frames {
		d.Frames++
		if i >= maxFrames {
			d.Counts.Other++
			continue
		}
		p := parseFrame(f.Data)
		key := f.Adapter + "\x00" + p.key
		switch p.proto {
		case protoLLDP:
			d.Counts.Lldp++
			if p.lldp != nil {
				p.lldp.Adapter, p.lldp.Frames = f.Adapter, 1
				lldp.add(key, *p.lldp, p.score, func(dst *LLDPNeighbor, prev, _ LLDPNeighbor) { dst.Frames = prev.Frames + 1 })
			}
		case protoCDP:
			d.Counts.Cdp++
			if p.cdp != nil {
				p.cdp.Adapter, p.cdp.Frames = f.Adapter, 1
				cdp.add(key, *p.cdp, p.score, func(dst *CDPNeighbor, prev, _ CDPNeighbor) { dst.Frames = prev.Frames + 1 })
			}
		case protoDTP:
			d.Counts.Dtp++
			if p.dtp != nil {
				p.dtp.Adapter, p.dtp.Frames = f.Adapter, 1
				dtp.add(key, *p.dtp, p.score, func(dst *DTPInfo, prev, _ DTPInfo) { dst.Frames = prev.Frames + 1 })
			}
		case protoSTP:
			d.Counts.Stp++
			if p.stp != nil {
				p.stp.Adapter, p.stp.Frames = f.Adapter, 1
				stp.add(key, *p.stp, p.score, func(dst *STPInfo, prev, nw STPInfo) {
					dst.Frames = prev.Frames + 1
					dst.TopologyChange = prev.TopologyChange || nw.TopologyChange
				})
			}
		case protoVTP:
			d.Counts.Vtp++
		case protoEAPOL:
			d.Counts.Eapol++
		default:
			d.Counts.Other++
		}
	}
	d.Lldp, d.Cdp, d.Dtp, d.Stp = lldp.items, cdp.items, dtp.items, stp.items
	c := d.Counts
	if c.Lldp+c.Cdp+c.Dtp+c.Stp+c.Vtp+c.Eapol > 0 {
		d.Read = ReadOK
	}
	return d
}

// dedup conserva un elemento per chiave, nell'ordine in cui compaiono.
type dedup[T any] struct {
	items []T
	score []int
	index map[string]int
}

// add registra un elemento. Se la chiave c'è già, il nuovo elemento prende
// il posto del precedente quando è almeno altrettanto completo (score); merge
// riporta poi i dati cumulativi (trame contate, bit visti almeno una volta).
func (d *dedup[T]) add(key string, it T, score int, merge func(dst *T, prev, nw T)) {
	if i, ok := d.index[key]; ok {
		prev := d.items[i]
		if score >= d.score[i] {
			d.items[i], d.score[i] = it, score
		}
		merge(&d.items[i], prev, it)
		return
	}
	if len(d.items) >= maxEntries {
		return
	}
	if d.index == nil {
		d.index = map[string]int{}
	}
	d.index[key] = len(d.items)
	d.items = append(d.items, it)
	d.score = append(d.score, score)
}

type proto int

const (
	protoOther proto = iota
	protoLLDP
	protoCDP
	protoDTP
	protoSTP
	protoVTP
	protoEAPOL
)

// packet è il risultato della decodifica di una trama.
type packet struct {
	proto proto
	lldp  *LLDPNeighbor
	cdp   *CDPNeighbor
	dtp   *DTPInfo
	stp   *STPInfo
	key   string // chiave di deduplicazione (byte grezzi, non esportata)
	score int    // completezza: elementi decodificati
}

// EtherType e valori LLC/SNAP usati.
const (
	etherTypeVLAN  = 0x8100
	etherTypeQinQ  = 0x88a8
	etherTypeQinQ2 = 0x9100 // vecchio QinQ di alcuni costruttori
	etherTypeLLDP  = 0x88cc
	etherTypeEAPOL = 0x888e
	max8023Length  = 1500 // fino a qui il campo è una lunghezza 802.3, non un EtherType

	llcSTP  = 0x42 // DSAP/SSAP delle BPDU IEEE
	llcSNAP = 0xaa
	llcUI   = 0x03

	pidPVST = 0x010b
	pidCDP  = 0x2000
	pidVTP  = 0x2003
	pidDTP  = 0x2004
)

var ouiCisco = [3]byte{0x00, 0x00, 0x0c}

func be16(b []byte) uint16 { return binary.BigEndian.Uint16(b) }
func be32(b []byte) uint32 { return binary.BigEndian.Uint32(b) }

// parseFrame riconosce il protocollo dalla trama Ethernet (EtherType oppure
// lunghezza 802.3 con LLC/SNAP) e la passa al decodificatore giusto.
// Accetta fino a due etichette VLAN (802.1Q, 802.1ad), che Windows di solito
// toglie prima della cattura.
func parseFrame(b []byte) packet {
	if len(b) < 14 {
		return packet{}
	}
	src := b[6:12]
	et := be16(b[12:])
	p := 14
	for n := 0; n < 2 && (et == etherTypeVLAN || et == etherTypeQinQ || et == etherTypeQinQ2); n++ {
		if p+4 > len(b) {
			return packet{}
		}
		et = be16(b[p+2:])
		p += 4
	}
	switch {
	case et == etherTypeLLDP:
		return parseLLDP(b[p:])
	case et == etherTypeEAPOL:
		return packet{proto: protoEAPOL}
	case et <= max8023Length:
		body := b[p:]
		// La lunghezza 802.3 esclude il riempimento delle trame corte (le
		// BPDU sono più corte dei 46 byte minimi): si legge solo il dato vero.
		if int(et) < len(body) {
			body = body[:et]
		}
		return parseLLC(body, src)
	}
	return packet{}
}

// parseLLC distingue le BPDU IEEE (LLC 42-42-03) dai protocolli Cisco
// incapsulati in SNAP (AA-AA-03, OUI 00-00-0C).
func parseLLC(b, src []byte) packet {
	if len(b) < 3 || b[2] != llcUI {
		return packet{}
	}
	switch {
	case b[0] == llcSTP && b[1] == llcSTP:
		return parseBPDU(b[3:], false)
	case b[0] == llcSNAP && b[1] == llcSNAP:
		if len(b) < 8 || [3]byte{b[3], b[4], b[5]} != ouiCisco {
			return packet{}
		}
		body := b[8:]
		switch be16(b[6:]) {
		case pidCDP:
			return parseCDP(body)
		case pidDTP:
			return parseDTP(body, src)
		case pidPVST:
			return parseBPDU(body, true)
		case pidVTP:
			return packet{proto: protoVTP}
		}
	}
	return packet{}
}

// rawKey rende una sequenza di byte utilizzabile come parte di una chiave.
func rawKey(parts ...[]byte) string {
	var k []byte
	for _, p := range parts {
		k = append(k, hex.EncodeToString(p)...)
		k = append(k, '|')
	}
	return string(k)
}
