package snmp

import (
	"cmp"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/gosnmp/gosnmp"

	"lanterna/internal/oui"
)

// Oggetti letti, controllati sui testi delle MIB. Sono gli unici che Collect
// chiede: il resto di ciò che un GETBULK restituisce oltre la fine di una
// colonna si scarta senza esaminarlo. Il testo libero scritto dagli
// amministratori non si chiede: sysContact (1.3.6.1.2.1.1.4), sysLocation
// (1.3.6.1.2.1.1.6), ifAlias (1.3.6.1.2.1.31.1.1.1.18), lldpRemPortDesc
// (1.0.8802.1.1.2.1.4.1.1.8) e lldpLocPortDesc (1.0.8802.1.1.2.1.3.7.1.4).
// Le colonne lette con GETBULK non sono seguite da nessuno di questi.
const (
	// SNMPv2-MIB (RFC 3418): system = mib-2.1 = 1.3.6.1.2.1.1.
	oidSysDescr    = ".1.3.6.1.2.1.1.1.0"
	oidSysObjectID = ".1.3.6.1.2.1.1.2.0"
	oidSysUpTime   = ".1.3.6.1.2.1.1.3.0" // TimeTicks, centesimi di secondo
	oidSysName     = ".1.3.6.1.2.1.1.5.0"

	// IF-MIB (RFC 2863): ifEntry = 1.3.6.1.2.1.2.2.1, ifXEntry = 1.3.6.1.2.1.31.1.1.1;
	// indice ifIndex.
	oidIfDescr = ".1.3.6.1.2.1.2.2.1.2"
	oidIfType  = ".1.3.6.1.2.1.2.2.1.3"
	oidIfName  = ".1.3.6.1.2.1.31.1.1.1.1"

	// IP-MIB (RFC 4293, già in RFC 1213; deprecate ma diffusissime):
	// ipAddrEntry = 1.3.6.1.2.1.4.20.1, indice ipAdEntAddr (a.b.c.d);
	// ipNetToMediaEntry = 1.3.6.1.2.1.4.22.1, indice ifIndex.a.b.c.d.
	oidIPAdEntIfIndex          = ".1.3.6.1.2.1.4.20.1.2"
	oidIPAdEntNetMask          = ".1.3.6.1.2.1.4.20.1.3"
	oidIPNetToMediaPhysAddress = ".1.3.6.1.2.1.4.22.1.2"

	// BRIDGE-MIB (RFC 4188): dot1dBridge = 1.3.6.1.2.1.17. dot1dBasePortEntry
	// = .1.4.1, indice dot1dBasePort; dot1dTpFdbEntry = .4.3.1, indice
	// dot1dTpFdbAddress (MacAddress, 6 identificatori senza lunghezza).
	oidDot1dBasePortIfIndex = ".1.3.6.1.2.1.17.1.4.1.2"
	oidDot1dTpFdbPort       = ".1.3.6.1.2.1.17.4.3.1.2"

	// Q-BRIDGE-MIB (RFC 4363): qBridgeMIBObjects = 1.3.6.1.2.1.17.7.1.
	// dot1qTpFdbEntry = .2.2.1, indice dot1qFdbId.dot1qTpFdbAddress;
	// dot1qVlanStaticEntry = .4.3.1, indice dot1qVlanIndex.
	oidDot1qTpFdbPort      = ".1.3.6.1.2.1.17.7.1.2.2.1.2"
	oidDot1qVlanStaticName = ".1.3.6.1.2.1.17.7.1.4.3.1.1"

	// CISCO-VTP-MIB: ciscoVtpMIB = 1.3.6.1.4.1.9.9.46, vtpVlanEntry =
	// .1.3.1.1, indice managementDomainIndex.vtpVlanIndex.
	oidVtpVlanState = ".1.3.6.1.4.1.9.9.46.1.3.1.1.2"
	oidVtpVlanName  = ".1.3.6.1.4.1.9.9.46.1.3.1.1.4"

	// LLDP-MIB (IEEE 802.1AB-2005): lldpMIB = 1.0.8802.1.1.2.
	// lldpLocalSystemData = .1.3 (scalari .1.0 e .2.0, lldpLocPortEntry =
	// .7.1, indice lldpLocPortNum); lldpRemEntry = .1.4.1.1, indice
	// lldpRemTimeMark.lldpRemLocalPortNum.lldpRemIndex; lldpRemManAddrEntry
	// = .1.4.2.1, con in più lldpRemManAddrSubtype e lldpRemManAddr
	// (stringa di lunghezza variabile, preceduta dalla lunghezza). Con
	// GETBULK si legge solo lldpRemChassisIdSubtype, seguito da
	// lldpRemChassisId; le altre colonne si chiedono riga per riga.
	oidLldpLocChassisIDSubtype = ".1.0.8802.1.1.2.1.3.1.0"
	oidLldpLocChassisID        = ".1.0.8802.1.1.2.1.3.2.0"
	oidLldpLocPortIDSubtype    = ".1.0.8802.1.1.2.1.3.7.1.2"
	oidLldpLocPortID           = ".1.0.8802.1.1.2.1.3.7.1.3"
	oidLldpRemChassisIDSubtype = ".1.0.8802.1.1.2.1.4.1.1.4"
	oidLldpRemChassisID        = ".1.0.8802.1.1.2.1.4.1.1.5"
	oidLldpRemPortIDSubtype    = ".1.0.8802.1.1.2.1.4.1.1.6"
	oidLldpRemPortID           = ".1.0.8802.1.1.2.1.4.1.1.7"
	oidLldpRemSysName          = ".1.0.8802.1.1.2.1.4.1.1.9"
	oidLldpRemSysCapEnabled    = ".1.0.8802.1.1.2.1.4.1.1.12"
	oidLldpRemManAddrIfSubtype = ".1.0.8802.1.1.2.1.4.2.1.3"

	// Prefisso di sysObjectID dei dispositivi Cisco (enterprises.9).
	ciscoPrefix = "1.3.6.1.4.1.9."
)

// Lunghezze massime dei testi, in caratteri.
const (
	maxDescr = 200 // sysDescr
	maxText  = 128 // nomi e descrizioni
)

// Valori IANAifType (IANAifType-MIB).
const (
	ifTypeL2Vlan   = 135 // l2vlan
	ifTypeL3IPVlan = 136 // l3ipvlan
)

// collector legge le sezioni una dopo l'altra sulla stessa sessione.
type collector struct {
	s     *session
	res   *Result
	max   int
	names map[int]string // ifIndex → ifName
	descr map[int]string // ifIndex → ifDescr
	cisco bool
}

// column è una colonna di tabella da leggere per intero.
type column struct {
	obj, oid string
	fn       func(idx []uint32, v gosnmp.SnmpPDU)
}

// want è un oggetto da chiedere con GET e cosa farne del valore.
type want struct {
	oid string
	set func(v gosnmp.SnmpPDU)
}

// fetch chiede gli oggetti indicati con GET, a gruppi, e registra l'esito.
func (c *collector) fetch(o *outcome, obj string, ws []want) *Error {
	if len(ws) == 0 {
		return nil
	}
	oids := make([]string, len(ws))
	for i, w := range ws {
		oids[i] = w.oid
	}
	vals, err := c.s.get(oids)
	for _, w := range ws {
		if v, ok := vals[w.oid]; ok {
			w.set(v)
		}
	}
	return o.add(obj, false, err)
}

// outcome raccoglie come sono andate le letture di una sezione.
type outcome struct {
	max    int
	notes  []string
	errs   bool // almeno una lettura non riuscita
	capped bool // almeno una tabella oltre il limite di righe
}

// add registra l'esito di una lettura e restituisce l'errore che ferma
// tutta la lettura (nessuna risposta, credenziali, interruzione, tempo
// massimo); gli errori di una sola tabella diventano note.
func (o *outcome) add(obj string, full bool, err error) *Error {
	if full && !o.capped {
		o.capped = true
		o.notes = append(o.notes, fmt.Sprintf("elenco limitato a %d righe per tabella", o.max))
	}
	if err == nil {
		return nil
	}
	o.errs = true
	var fe *Error
	if errors.As(err, &fe) {
		o.notes = append(o.notes, "lettura interrotta: "+fe.Msg)
		return fe
	}
	o.notes = append(o.notes, obj+": "+err.Error())
	return nil
}

// set compila lo stato della sezione. present dice che il dispositivo
// gestisce la tabella anche se è vuota; empty spiega una sezione senza righe.
func (o *outcome) set(st *Status, rows int, present bool, source, empty string) {
	st.Rows, st.Source = rows, source
	st.Note = strings.Join(o.notes, "; ")
	switch {
	case rows > 0 && (o.errs || o.capped):
		st.State = StatePartial
	case rows > 0 || (present && !o.errs):
		st.State = StateOK
	case o.errs:
		st.State = StateError
	default:
		st.State = StateAbsent
	}
	if rows == 0 && !o.errs && st.Note == "" {
		st.Note = empty
	}
}

// fatal trasforma in errore bloccante un errore della prima richiesta: se il
// dispositivo non ha mai dato una risposta valida è inutile continuare.
func (c *collector) fatal(err error) *Error {
	var fe *Error
	if errors.As(err, &fe) {
		return fe
	}
	if !c.s.answered {
		return &Error{Kind: KindProtocol, Msg: err.Error()}
	}
	return nil
}

// system legge i dati generali: è la prima richiesta della lettura.
func (c *collector) system() *Error {
	st := &c.res.Sections.System
	st.Source = "SNMPv2-MIB"
	vals, err := c.s.get([]string{oidSysDescr, oidSysObjectID, oidSysUpTime, oidSysName})
	if err != nil {
		st.State = StateError
		if fe := c.fatal(err); fe != nil {
			st.Note = fe.Msg
			return fe
		}
		st.Note = "sysDescr, sysObjectID, sysUpTime, sysName: " + err.Error()
		return nil
	}
	var sys System
	if v, ok := vals[oidSysDescr]; ok {
		sys.Descr = text(v.Value, maxDescr)
	}
	if v, ok := vals[oidSysObjectID]; ok {
		if s, ok := v.Value.(string); ok {
			sys.ObjectID = strings.TrimPrefix(s, ".")
		}
	}
	if v, ok := vals[oidSysUpTime]; ok {
		if t, ok := v.Value.(uint32); ok {
			sys.UptimeSec = int64(t) / 100
		}
	}
	if v, ok := vals[oidSysName]; ok {
		sys.Name = text(v.Value, maxText)
	}
	c.cisco = strings.HasPrefix(sys.ObjectID, ciscoPrefix)
	if sys == (System{}) {
		st.State, st.Note = StateAbsent, "il dispositivo non ha fornito i dati di sistema"
		return nil
	}
	c.res.System = &sys
	st.State, st.Rows = StateOK, 1
	return nil
}

// vlanIfName riconosce i nomi delle interfacce VLAN: Vlan10, Vl10, VLAN 10,
// vlan.10, Vlanif10 (Huawei), Vlan-interface10 (H3C/HPE Comware).
var vlanIfName = regexp.MustCompile(`(?i)^(?:vlan|vl|vlanif|vlan-interface)[\s._-]*0*(\d{1,4})$`)

// vlanLike dice se l'interfaccia ha l'aspetto di un'interfaccia VLAN e, se
// il nome lo indica, di quale VLAN.
func vlanLike(name, descr string, ifType int) (bool, int) {
	for _, s := range []string{name, descr} {
		if m := vlanIfName.FindStringSubmatch(strings.TrimSpace(s)); m != nil {
			if id, _ := strconv.Atoi(m[1]); id >= 1 && id <= 4094 {
				return true, id
			}
		}
	}
	return ifType == ifTypeL2Vlan || ifType == ifTypeL3IPVlan, 0
}

// usableIP scarta indirizzi che non descrivono la rete (0.0.0.0, 127.x).
func usableIP(ip netip.Addr) bool {
	return ip.Is4() && !ip.IsLoopback() && !ip.IsUnspecified()
}

// interfaces legge interfacce e indirizzi IPv4. Di ogni interfaccia si
// leggono solo nome, descrizione e tipo generati dal dispositivo: ifAlias, la
// descrizione scritta dall'amministratore, può contenere nomi di persone
// ("PC dott. Rossi") e non si chiede.
func (c *collector) interfaces() *Error {
	o := outcome{max: c.max}
	types := map[int]int{}
	ifOf := map[netip.Addr]int{}      // indirizzo → ifIndex
	maskOf := map[netip.Addr]string{} // indirizzo → maschera
	// shown elenca, in ordine, le interfacce da mostrare: quelle con un
	// indirizzo IPv4 e quelle che hanno l'aspetto di interfacce VLAN.
	shown := func() []int {
		set := map[int]bool{}
		for ip, i := range ifOf {
			if i > 0 && usableIP(ip) {
				set[i] = true
			}
		}
		check := func(i int) {
			if ok, _ := vlanLike(c.names[i], c.descr[i], types[i]); ok {
				set[i] = true
			}
		}
		for i := range c.names {
			check(i)
		}
		for i := range c.descr {
			check(i)
		}
		for i := range types {
			check(i)
		}
		out := make([]int, 0, len(set))
		for i := range set {
			out = append(out, i)
		}
		slices.Sort(out)
		return out[:min(len(out), c.max)]
	}
	defer func() {
		ips := map[int][]netip.Addr{}
		for ip, i := range ifOf {
			if i > 0 && usableIP(ip) {
				ips[i] = append(ips[i], ip)
			}
		}
		list := []Iface{}
		for _, i := range shown() {
			_, vid := vlanLike(c.names[i], c.descr[i], types[i])
			f := Iface{Index: i, Name: c.names[i], Descr: c.descr[i], Type: types[i], VlanID: vid, IPs: []IfaceIP{}}
			slices.SortFunc(ips[i], netip.Addr.Compare)
			for _, ip := range ips[i] {
				f.IPs = append(f.IPs, ifaceIP(ip, maskOf[ip]))
			}
			list = append(list, f)
		}
		c.res.Interfaces = list
		o.set(&c.res.Sections.Interfaces, len(list), false, "IF-MIB, IP-MIB",
			"nessun indirizzo IPv4 e nessuna interfaccia VLAN (IF-MIB e IP-MIB assenti o vuote)")
	}()

	cols := []column{
		{"ifName", oidIfName, func(idx []uint32, v gosnmp.SnmpPDU) {
			if i, ok := single(idx); ok {
				c.names[i] = text(v.Value, maxText)
			}
		}},
		{"ifDescr", oidIfDescr, func(idx []uint32, v gosnmp.SnmpPDU) {
			if i, ok := single(idx); ok {
				c.descr[i] = text(v.Value, maxText)
			}
		}},
		{"ifType", oidIfType, func(idx []uint32, v gosnmp.SnmpPDU) {
			if i, ok := single(idx); ok {
				types[i], _ = intOf(v.Value)
			}
		}},
		{"ipAdEntIfIndex", oidIPAdEntIfIndex, func(idx []uint32, v gosnmp.SnmpPDU) {
			ip, ok := ipFromIndex(idx)
			n, ok2 := intOf(v.Value)
			if ok && ok2 {
				ifOf[ip] = n
			}
		}},
		{"ipAdEntNetMask", oidIPAdEntNetMask, func(idx []uint32, v gosnmp.SnmpPDU) {
			ip, ok := ipFromIndex(idx)
			m, ok2 := v.Value.(string) // gosnmp restituisce IpAddress come testo
			if ok && ok2 {
				maskOf[ip] = m
			}
		}},
	}
	for _, col := range cols {
		_, full, err := c.s.walk(col.oid, c.max, col.fn)
		if fe := o.add(col.obj, full, err); fe != nil {
			return fe
		}
	}
	return nil
}

// ifaceIP descrive un indirizzo con la sua maschera.
func ifaceIP(ip netip.Addr, mask string) IfaceIP {
	out := IfaceIP{IP: ip.String(), Mask: mask}
	if m, err := netip.ParseAddr(mask); err == nil && m.Is4() {
		if n, ok := maskBits(m.As4()); ok {
			out.Prefix = n
			out.Subnet = netip.PrefixFrom(ip, n).Masked().String()
		}
	}
	return out
}

// maskBits conta i bit di rete; una maschera non contigua non è valida.
func maskBits(b [4]byte) (int, bool) {
	v := binary.BigEndian.Uint32(b[:])
	n := bits.LeadingZeros32(^v)
	return n, v<<n == 0
}

// vtpStates sono gli stati non operativi di vtpVlanState.
var vtpStates = map[int]string{2: "suspended", 3: "mtuTooBigForDevice", 4: "mtuTooBigForTrunk"}

// reservedCisco riconosce le VLAN 1002-1005 che i Cisco creano da soli per
// FDDI e Token Ring (fddi-default, token-ring-default, fddinet-default,
// trnet-default): si mostrano solo se qualcuno le ha rinominate.
func reservedCisco(v *Vlan) bool {
	return v.ID >= 1002 && v.ID <= 1005 && (v.Name == "" || strings.HasSuffix(strings.ToLower(v.Name), "-default"))
}

// vlans legge le VLAN da Q-BRIDGE-MIB e, sui Cisco o se Q-BRIDGE-MIB non
// le elenca, da CISCO-VTP-MIB.
func (c *collector) vlans() *Error {
	o := outcome{max: c.max}
	byID := map[int]*Vlan{}
	var sources []string
	defer func() {
		list := []Vlan{}
		for _, v := range byID {
			if !reservedCisco(v) {
				list = append(list, *v)
			}
		}
		slices.SortFunc(list, func(a, b Vlan) int { return cmp.Compare(a.ID, b.ID) })
		c.res.Vlans = list
		o.set(&c.res.Sections.Vlans, len(list), false, strings.Join(sources, ", "),
			"il dispositivo non elenca VLAN via SNMP (Q-BRIDGE-MIB e CISCO-VTP-MIB assenti o vuote)")
	}()
	vlan := func(id uint32, create bool) *Vlan {
		if id < 1 || id > 4094 { // VlanIndex oltre 4094: VLAN locali all'agente
			return nil
		}
		v := byID[int(id)]
		if v == nil && create && len(byID) < c.max {
			v = &Vlan{ID: int(id)}
			byID[int(id)] = v
		}
		return v
	}
	n, full, err := c.s.walk(oidDot1qVlanStaticName, c.max, func(idx []uint32, v gosnmp.SnmpPDU) {
		if len(idx) == 1 {
			if x := vlan(idx[0], true); x != nil {
				x.Name = text(v.Value, maxText)
			}
		}
	})
	if fe := o.add("dot1qVlanStaticName", full, err); fe != nil {
		return fe
	}
	if n > 0 {
		sources = append(sources, "Q-BRIDGE-MIB")
		if !c.cisco {
			return nil
		}
	}
	n, full, err = c.s.walk(oidVtpVlanName, c.max, func(idx []uint32, v gosnmp.SnmpPDU) {
		if len(idx) == 2 {
			if x := vlan(idx[1], true); x != nil && x.Name == "" {
				x.Name = text(v.Value, maxText)
			}
		}
	})
	if fe := o.add("vtpVlanName", full, err); fe != nil {
		return fe
	}
	if n == 0 {
		return nil
	}
	sources = append(sources, "CISCO-VTP-MIB")
	_, full, err = c.s.walk(oidVtpVlanState, c.max, func(idx []uint32, v gosnmp.SnmpPDU) {
		if len(idx) == 2 {
			if x := vlan(idx[1], false); x != nil {
				s, _ := intOf(v.Value)
				x.State = vtpStates[s]
			}
		}
	})
	return o.add("vtpVlanState", full, err)
}

// Sottotipi di LLDP-MIB (LldpChassisIdSubtype, LldpPortIdSubtype).
var (
	chassisIDTypes = map[int]string{1: "chassisComponent", 2: "interfaceAlias", 3: "portComponent", 4: "macAddress", 5: "networkAddress", 6: "interfaceName", 7: "local"}
	portIDTypes    = map[int]string{1: "interfaceAlias", 2: "portComponent", 3: "macAddress", 4: "networkAddress", 5: "interfaceName", 6: "agentCircuitId", 7: "local"}
)

// capNames sono i bit di LldpSystemCapabilitiesMap, dal bit 0 (il più
// significativo del primo byte, RFC 3416).
var capNames = []string{"other", "repeater", "bridge", "wlanAccessPoint", "router", "telephone", "docsisCableDevice", "stationOnly"}

func caps(b []byte) []string {
	var out []string
	for i, name := range capNames {
		if i/8 < len(b) && b[i/8]&(0x80>>(i%8)) != 0 {
			out = append(out, name)
		}
	}
	return out
}

// aliasID dice se un identificativo LLDP è un alias scritto a mano
// dall'amministratore (ifAlias o entPhysicalAlias, secondo LLDP-MIB): come
// ifAlias può contenere nomi di persone, quindi non si chiede.
func aliasID(kind string) bool {
	return kind == "interfaceAlias" || kind == "chassisComponent" || kind == "portComponent"
}

// nbRow è un vicino in lettura: gli identificativi si decodificano alla fine,
// quando si conoscono i sottotipi.
type nbRow struct {
	sfx                 string // indice della riga: .lldpRemTimeMark.lldpRemLocalPortNum.lldpRemIndex
	port, rem           uint32
	chassisSub, portSub int
	chassis, portID     []byte
	n                   Neighbor
}

// lldp legge i vicini LLDP, il loro indirizzo di gestione e la porta locale
// su cui sono annunciati. Con GETBULK si legge solo la colonna che elenca i
// vicini; le altre si chiedono riga per riga, così la lettura non passa mai
// da lldpRemPortDesc, la descrizione scritta dall'amministratore del vicino.
func (c *collector) lldp() *Error {
	o := outcome{max: c.max}
	present := false
	type key struct{ port, rem uint32 }
	rows := map[key]*nbRow{}
	var list []*nbRow // le righe in ordine di porta e di indice
	locals := map[uint32]string{}
	defer func() {
		out := []Neighbor{}
		for _, r := range list {
			n := r.n
			n.LocalPortNum = int(r.port)
			n.LocalPort = locals[r.port]
			n.ChassisIDType = chassisIDTypes[r.chassisSub]
			n.ChassisID = decodeID(n.ChassisIDType, r.chassis)
			n.PortIDType = portIDTypes[r.portSub]
			n.PortID = decodeID(n.PortIDType, r.portID)
			out = append(out, n)
		}
		c.res.LldpNeighbors = out
		empty := "LLDP-MIB assente: LLDP spento o non consultabile via SNMP"
		if present {
			empty = "nessun vicino LLDP"
		}
		o.set(&c.res.Sections.Lldp, len(out), present, "LLDP-MIB", empty)
	}()

	// Il sottotipo dell'identificativo del dispositivo dice se LLDP-MIB c'è;
	// l'identificativo si chiede solo se non è un alias scritto a mano.
	sub := 0
	if fe := c.fetch(&o, "lldpLocChassisIdSubtype", []want{{oidLldpLocChassisIDSubtype, func(v gosnmp.SnmpPDU) {
		present = true
		sub, _ = intOf(v.Value)
	}}}); fe != nil {
		return fe
	}
	if kind := chassisIDTypes[sub]; present && !aliasID(kind) && c.res.System != nil {
		sys := c.res.System
		if fe := c.fetch(&o, "lldpLocChassisId", []want{{oidLldpLocChassisID, func(v gosnmp.SnmpPDU) {
			sys.ChassisID = decodeID(kind, bytesOf(v.Value))
		}}}); fe != nil {
			return fe
		}
	}

	// Vicini: l'indice di ogni riga viene dal sottotipo del loro identificativo.
	n, full, err := c.s.walk(oidLldpRemChassisIDSubtype, c.max, func(idx []uint32, v gosnmp.SnmpPDU) {
		if len(idx) != 3 {
			return
		}
		k := key{idx[1], idx[2]} // lldpRemTimeMark (idx[0]) cambia a ogni modifica: non identifica il vicino
		r := rows[k]
		if r == nil {
			r = &nbRow{port: k.port, rem: k.rem}
			rows[k] = r
		}
		r.sfx = formatOID(idx)
		r.chassisSub, _ = intOf(v.Value)
	})
	if fe := o.add("lldpRemChassisIdSubtype", full, err); fe != nil {
		return fe
	}
	if n == 0 {
		return nil
	}
	present = true
	for _, r := range rows {
		list = append(list, r)
	}
	slices.SortFunc(list, func(a, b *nbRow) int {
		return cmp.Or(cmp.Compare(a.port, b.port), cmp.Compare(a.rem, b.rem))
	})

	var ws []want
	for _, r := range list {
		ws = append(ws,
			want{oidLldpRemPortIDSubtype + r.sfx, func(v gosnmp.SnmpPDU) { r.portSub, _ = intOf(v.Value) }},
			want{oidLldpRemSysName + r.sfx, func(v gosnmp.SnmpPDU) { r.n.SysName = text(v.Value, maxText) }},
			want{oidLldpRemSysCapEnabled + r.sfx, func(v gosnmp.SnmpPDU) { r.n.CapsEnabled = caps(bytesOf(v.Value)) }})
	}
	if fe := c.fetch(&o, "lldpRemTable", ws); fe != nil {
		return fe
	}
	// Identificativi del vicino e della sua porta, se non sono alias scritti a mano.
	ws = nil
	for _, r := range list {
		if !aliasID(chassisIDTypes[r.chassisSub]) {
			ws = append(ws, want{oidLldpRemChassisID + r.sfx, func(v gosnmp.SnmpPDU) { r.chassis = bytesOf(v.Value) }})
		}
		if !aliasID(portIDTypes[r.portSub]) {
			ws = append(ws, want{oidLldpRemPortID + r.sfx, func(v gosnmp.SnmpPDU) { r.portID = bytesOf(v.Value) }})
		}
	}
	if fe := c.fetch(&o, "lldpRemTable", ws); fe != nil {
		return fe
	}

	// Indirizzo di gestione: il primo annunciato da ogni vicino (gli IPv4
	// vengono prima degli altri), con un GETNEXT per vicino.
	prefixes := make([]string, len(list))
	for i, r := range list {
		prefixes[i] = oidLldpRemManAddrIfSubtype + r.sfx
	}
	next, err := c.s.getNext(prefixes)
	for i, r := range list {
		pre, _ := parseOID(prefixes[i])
		if v, ok := next[prefixes[i]]; ok {
			if oid, ok := parseOID(v.Name); ok && len(oid) > len(pre) && hasPrefix(oid, pre) {
				r.n.MgmtIP = manAddrIPv4(oid[len(pre):])
			}
		}
	}
	if fe := o.add("lldpRemManAddrTable", false, err); fe != nil {
		return fe
	}

	// Porte locali con vicini: il nome viene dal loro identificativo
	// (lldpLocPortId), se non è un alias scritto a mano. lldpLocPortDesc non
	// si chiede: molti switch vi mettono la descrizione dell'amministratore.
	seen := map[uint32]bool{}
	var ports []uint32
	for _, r := range list {
		if !seen[r.port] {
			seen[r.port] = true
			ports = append(ports, r.port)
		}
	}
	subs := map[uint32]int{}
	ws = nil
	for _, p := range ports {
		sfx := "." + strconv.FormatUint(uint64(p), 10)
		ws = append(ws, want{oidLldpLocPortIDSubtype + sfx, func(v gosnmp.SnmpPDU) { subs[p], _ = intOf(v.Value) }})
	}
	if fe := c.fetch(&o, "lldpLocPortIdSubtype", ws); fe != nil {
		return fe
	}
	ws = nil
	for _, p := range ports {
		if kind := portIDTypes[subs[p]]; !aliasID(kind) {
			sfx := "." + strconv.FormatUint(uint64(p), 10)
			ws = append(ws, want{oidLldpLocPortID + sfx, func(v gosnmp.SnmpPDU) { locals[p] = decodeID(kind, bytesOf(v.Value)) }})
		}
	}
	return c.fetch(&o, "lldpLocPortId", ws)
}

// manAddrIPv4 legge l'indirizzo dall'indice di lldpRemManAddrTable dopo
// timeMark, porta e indice del vicino: famiglia (1 = ipV4, IANA
// AddressFamilyNumbers), lunghezza e indirizzo. Alcuni agenti omettono la
// lunghezza.
func manAddrIPv4(x []uint32) string {
	if len(x) < 1 || x[0] != 1 {
		return ""
	}
	x = x[1:]
	if len(x) == 5 && x[0] == 4 {
		x = x[1:]
	}
	if ip, ok := ipFromIndex(x); ok {
		return ip.String()
	}
	return ""
}

// decodeID rende leggibile un identificativo LLDP secondo il sottotipo. Gli
// alias scritti a mano non si chiedono e, se arrivassero, non si mostrano.
func decodeID(kind string, b []byte) string {
	switch {
	case aliasID(kind):
		return ""
	case kind == "macAddress" && len(b) == 6:
		return net.HardwareAddr(b).String()
	case kind == "networkAddress" && len(b) == 5 && b[0] == 1: // primo byte: famiglia IANA (1 = IPv4, 2 = IPv6)
		return netip.AddrFrom4([4]byte(b[1:5])).String()
	case kind == "networkAddress" && len(b) == 17 && b[0] == 2:
		return netip.AddrFrom16([16]byte(b[1:17])).String()
	case kind == "agentCircuitId":
		return hexBytes(b)
	}
	if s := strings.TrimRight(string(b), "\x00"); s != "" && utf8.ValidString(s) && !strings.ContainsFunc(s, unicode.IsControl) {
		return text(b, maxText)
	}
	return hexBytes(b)
}

func hexBytes(b []byte) string {
	b = b[:min(len(b), 64)]
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02x", x)
	}
	return strings.Join(parts, ":")
}

// arp legge la tabella ARP del dispositivo.
func (c *collector) arp() *Error {
	o := outcome{max: c.max}
	type entry struct {
		ip netip.Addr
		e  ArpEntry
	}
	var list []entry
	defer func() {
		slices.SortFunc(list, func(a, b entry) int {
			return cmp.Or(a.ip.Compare(b.ip), cmp.Compare(a.e.IfIndex, b.e.IfIndex))
		})
		out := make([]ArpEntry, len(list))
		for i, x := range list {
			out[i] = x.e
		}
		c.res.Arp = out
		o.set(&c.res.Sections.Arp, len(out), false, "IP-MIB",
			"tabella ARP vuota o non consultabile via SNMP (ipNetToMediaTable)")
	}()
	_, full, err := c.s.walk(oidIPNetToMediaPhysAddress, c.max, func(idx []uint32, v gosnmp.SnmpPDU) {
		if len(idx) != 5 || idx[0] == 0 || idx[0] > math.MaxInt32 {
			return
		}
		ip, ok := ipFromIndex(idx[1:])
		mac, ok2 := unicastMAC(bytesOf(v.Value)) // 0 = voce incompleta (RFC 4293)
		if ok && ok2 {
			list = append(list, entry{ip, ArpEntry{IfIndex: int(idx[0]), IP: ip.String(), MAC: mac, Vendor: oui.Lookup(mac)}})
		}
	})
	return o.add("ipNetToMediaPhysAddress", full, err)
}

// fdb legge quale MAC lo switch ha visto dietro a quale porta: da
// Q-BRIDGE-MIB o, se manca, da BRIDGE-MIB; poi traduce le porte del bridge
// in interfacce.
func (c *collector) fdb() *Error {
	o := outcome{max: c.max}
	var rows []FdbEntry
	ports := map[int]int{} // porta del bridge → ifIndex
	source := ""
	defer func() {
		for i := range rows {
			if ifi, ok := ports[rows[i].BridgePort]; ok {
				rows[i].IfIndex = ifi
				rows[i].Port = c.portName(ifi)
			}
		}
		slices.SortFunc(rows, func(a, b FdbEntry) int {
			return cmp.Or(cmp.Compare(a.BridgePort, b.BridgePort), cmp.Compare(a.FdbID, b.FdbID), strings.Compare(a.MAC, b.MAC))
		})
		if rows == nil {
			rows = []FdbEntry{}
		}
		c.res.Fdb = rows
		if c.cisco && source == "BRIDGE-MIB" {
			o.notes = append(o.notes, "sui Cisco la tabella BRIDGE-MIB letta senza indicare la VLAN riporta di solito solo la VLAN 1")
		}
		o.set(&c.res.Sections.Fdb, len(rows), false, source,
			"tabella degli indirizzi MAC vuota o non consultabile via SNMP (Q-BRIDGE-MIB e BRIDGE-MIB)")
	}()
	// La porta 0 indica un indirizzo noto ma non imparato su una porta: si scarta.
	add := func(macIdx []uint32, v gosnmp.SnmpPDU, fdbID int) {
		mac, ok := macFromIndex(macIdx)
		port, ok2 := intOf(v.Value)
		if ok && ok2 && port > 0 {
			rows = append(rows, FdbEntry{MAC: mac, BridgePort: port, FdbID: fdbID})
		}
	}
	n, full, err := c.s.walk(oidDot1qTpFdbPort, c.max, func(idx []uint32, v gosnmp.SnmpPDU) {
		if len(idx) == 7 && idx[0] <= math.MaxInt32 {
			add(idx[1:], v, int(idx[0]))
		}
	})
	if n > 0 {
		source = "Q-BRIDGE-MIB"
	}
	if fe := o.add("dot1qTpFdbPort", full, err); fe != nil {
		return fe
	}
	if n == 0 {
		n, full, err = c.s.walk(oidDot1dTpFdbPort, c.max, func(idx []uint32, v gosnmp.SnmpPDU) {
			if len(idx) == 6 {
				add(idx, v, 0)
			}
		})
		if n > 0 {
			source = "BRIDGE-MIB"
		}
		if fe := o.add("dot1dTpFdbPort", full, err); fe != nil {
			return fe
		}
	}
	if len(rows) == 0 {
		return nil
	}
	_, full, err = c.s.walk(oidDot1dBasePortIfIndex, c.max, func(idx []uint32, v gosnmp.SnmpPDU) {
		p, ok := single(idx)
		ifi, ok2 := intOf(v.Value)
		if ok && ok2 && ifi > 0 {
			ports[p] = ifi
		}
	})
	return o.add("dot1dBasePortIfIndex", full, err)
}

// portName è il nome dell'interfaccia: ifName o, se manca, ifDescr.
func (c *collector) portName(ifIndex int) string {
	if s := c.names[ifIndex]; s != "" {
		return s
	}
	return c.descr[ifIndex]
}

// single legge un indice di un solo intero (ifIndex, numero di porta).
func single(idx []uint32) (int, bool) {
	if len(idx) != 1 || idx[0] > math.MaxInt32 {
		return 0, false
	}
	return int(idx[0]), true
}

// ipFromIndex legge un IpAddress usato come indice (a.b.c.d).
func ipFromIndex(idx []uint32) (netip.Addr, bool) {
	if len(idx) != 4 {
		return netip.Addr{}, false
	}
	var b [4]byte
	for i, x := range idx {
		if x > 255 {
			return netip.Addr{}, false
		}
		b[i] = byte(x)
	}
	return netip.AddrFrom4(b), true
}

// macFromIndex legge un MacAddress usato come indice (6 identificatori).
func macFromIndex(idx []uint32) (string, bool) {
	if len(idx) != 6 {
		return "", false
	}
	b := make(net.HardwareAddr, 6)
	for i, x := range idx {
		if x > 255 {
			return "", false
		}
		b[i] = byte(x)
	}
	return b.String(), true
}

// unicastMAC accetta un indirizzo MAC di 6 byte che non sia zero (voce
// incompleta) né di gruppo (broadcast, multicast).
func unicastMAC(b []byte) (string, bool) {
	if len(b) != 6 || b[0]&1 != 0 || string(b) == "\x00\x00\x00\x00\x00\x00" {
		return "", false
	}
	return net.HardwareAddr(b).String(), true
}

// intOf legge un valore intero di gosnmp (Integer è int, Gauge32 uint,
// TimeTicks uint32) entro i limiti di Integer32, validi anche a 32 bit.
func intOf(v any) (int, bool) {
	var x int64
	switch n := v.(type) {
	case int:
		x = int64(n)
	case int32:
		x = int64(n)
	case int64:
		x = n
	case uint:
		if uint64(n) > math.MaxInt32 {
			return 0, false
		}
		x = int64(n)
	case uint32:
		x = int64(n)
	case uint64:
		if n > math.MaxInt32 {
			return 0, false
		}
		x = int64(n)
	default:
		return 0, false
	}
	if x < math.MinInt32 || x > math.MaxInt32 {
		return 0, false
	}
	return int(x), true
}

// bytesOf legge un OCTET STRING.
func bytesOf(v any) []byte {
	switch s := v.(type) {
	case []byte:
		return s
	case string:
		return []byte(s)
	}
	return nil
}

// text rende stampabile un DisplayString o SnmpAdminString: testo non UTF-8
// letto come Latin-1, caratteri di controllo e di formato tolti, spazi
// compattati, al massimo limit caratteri.
func text(v any, limit int) string {
	b := bytesOf(v)
	var s string
	if utf8.Valid(b) {
		s = string(b)
	} else {
		r := make([]rune, len(b))
		for i, c := range b {
			r[i] = rune(c)
		}
		s = string(r)
	}
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
			return ' '
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), r == utf8.RuneError:
			return -1
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > limit {
		s = strings.TrimSpace(string(r[:limit]))
	}
	return s
}
