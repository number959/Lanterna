package snmp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"lanterna/internal/l2disc"
	"lanterna/internal/oui"
)

// fast è il ritmo dei test: stesse regole di Prudent, tempi brevi.
var fast = Options{Timeout: 500 * time.Millisecond, Retries: 0, Interval: 3 * time.Millisecond, MaxRepetitions: 4, MaxRows: 4096, Deadline: 10 * time.Second}

const community = "Clinica-RO-2026"

var v2c = Creds{Version: "2c", Community: community}

// Testo libero scritto dagli amministratori, che può contenere nomi di
// persone: i finti dispositivi lo hanno, come quelli veri, ma Collect non
// deve né chiederlo né riceverlo.
const (
	oidSysContact      = ".1.3.6.1.2.1.1.4"
	oidSysLocation     = ".1.3.6.1.2.1.1.6"
	oidIfAlias         = ".1.3.6.1.2.1.31.1.1.1.18"
	oidLldpRemPortDesc = ".1.0.8802.1.1.2.1.4.1.1.8"
	oidLldpLocPortDesc = ".1.0.8802.1.1.2.1.3.7.1.4"
)

// forbiddenIn restituisce il primo OID che sta sotto uno degli oggetti vietati.
func forbiddenIn(oids []string) string {
	for _, o := range oids {
		for _, f := range []string{oidSysContact, oidSysLocation, oidIfAlias, oidLldpRemPortDesc, oidLldpLocPortDesc} {
			if o == f || strings.HasPrefix(o, f+".") {
				return o
			}
		}
	}
	return ""
}

// coreSwitch è uno switch Cisco di livello 3 con tre VLAN, due vicini LLDP,
// tabella ARP e tabella degli indirizzi MAC. Contiene anche colonne che
// Collect non legge, come un agente vero.
func coreSwitch() []gosnmp.SnmpPDU {
	descr := "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E8, RELEASE SOFTWARE (fc1)\r\n" +
		"Technical Support: http://www.cisco.com/techsupport\r\nCopyright (c) 1986-2023 by Cisco Systems, Inc.\r\n" + strings.Repeat("x", 150)
	d := []gosnmp.SnmpPDU{
		str(oidSysDescr, descr),
		{Name: oidSysObjectID, Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.4.1.9.1.1208"},
		{Name: oidSysUpTime, Type: gosnmp.TimeTicks, Value: uint32(123456789)},
		str(oidSysContact+".0", "Mario Rossi, 333 1234567"),
		str(oidSysName, "core-sw1.clinica.local"),
		str(oidSysLocation+".0", "Studio dott.ssa Bianchi"),
		num(".1.3.6.1.2.1.1.7.0", 6), // sysServices
		num(oidLldpLocChassisIDSubtype, 4),
		raw(oidLldpLocChassisID, 0x00, 0x1b, 0x54, 0xaa, 0xbb, 0xcc),
	}
	for _, f := range []struct {
		idx                int
		descr, name, alias string
		typ                int
	}{
		{1, "GigabitEthernet1/0/1", "Gi1/0/1", "Uplink router", 6},
		{2, "GigabitEthernet1/0/2", "Gi1/0/2", "PC dott. Rossi", 6},
		{3, "GigabitEthernet1/0/3", "Gi1/0/3", "", 6},
		{10, "Vlan10", "Vl10", "Rete della segreteria", 53},
		{20, "Vlan20", "Vl20", "Rete degli ambulatori", 136},
		{30, "Vlan30", "Vl30", "", 53},
		{100, "Loopback0", "Lo0", "gestione Bianchi", 24},
		{101, "Null0", "Nu0", "", 1},
		{102, "lo", "lo", "", 24},
	} {
		s := "." + strconv.Itoa(f.idx)
		d = append(d, num(".1.3.6.1.2.1.2.2.1.1"+s, f.idx), str(oidIfDescr+s, f.descr), num(oidIfType+s, f.typ),
			num(".1.3.6.1.2.1.2.2.1.4"+s, 1500), str(oidIfName+s, f.name),
			gosnmp.SnmpPDU{Name: ".1.3.6.1.2.1.31.1.1.1.2" + s, Type: gosnmp.Counter32, Value: uint32(7)}, // ifInMulticastPkts
			str(oidIfAlias+s, f.alias))
	}
	for _, a := range []struct {
		ip, mask string
		ifIndex  int
	}{
		{"192.168.10.1", "255.255.255.0", 10},
		{"10.20.0.1", "255.255.254.0", 20},
		{"10.20.5.1", "255.255.255.0", 20},
		{"10.255.255.1", "255.255.255.255", 100},
		{"127.0.0.1", "255.0.0.0", 102},
	} {
		d = append(d, ipv(".1.3.6.1.2.1.4.20.1.1."+a.ip, a.ip), num(oidIPAdEntIfIndex+"."+a.ip, a.ifIndex),
			ipv(oidIPAdEntNetMask+"."+a.ip, a.mask), num(".1.3.6.1.2.1.4.20.1.4."+a.ip, 1))
	}
	for _, e := range []struct {
		ifIndex int
		ip      string
		mac     []byte
	}{
		{10, "192.168.10.50", []byte{0x3c, 0x58, 0xc2, 0x11, 0x22, 0x33}},
		{10, "192.168.10.7", []byte{0x00, 0x1b, 0xa9, 0x12, 0x34, 0x56}},
		{20, "10.20.0.30", []byte{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01}},
		{20, "10.20.0.31", []byte{0, 0, 0, 0, 0, 0}},                       // incompleta
		{10, "192.168.10.255", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}, // broadcast
	} {
		s := "." + strconv.Itoa(e.ifIndex) + "." + e.ip
		d = append(d, raw(oidIPNetToMediaPhysAddress+s, e.mac...), ipv(".1.3.6.1.2.1.4.22.1.3"+s, e.ip), num(".1.3.6.1.2.1.4.22.1.4"+s, 3))
	}
	for id, name := range map[int]string{1: "default", 10: "Segreteria", 20: "Ambulatori", 30: "Ospiti"} {
		d = append(d, str(oidDot1qVlanStaticName+"."+strconv.Itoa(id), name), num(".1.3.6.1.2.1.17.7.1.4.3.1.5."+strconv.Itoa(id), 1))
	}
	for _, v := range []struct {
		id, state int
		name      string
	}{
		{1, 1, "default"}, {10, 1, "Segreteria"}, {20, 1, "Ambulatori"}, {40, 2, "Stampanti"},
		{1002, 1, "fddi-default"}, {1003, 1, "token-ring-default"}, {1004, 1, "fddinet-default"}, {1005, 1, "trnet-default"},
	} {
		s := ".1." + strconv.Itoa(v.id)
		d = append(d, num(oidVtpVlanState+s, v.state), num(".1.3.6.1.4.1.9.9.46.1.3.1.1.3"+s, 1), str(oidVtpVlanName+s, v.name))
	}
	// Vicini LLDP: un router sulla porta 1 e un telefono sulla porta 3.
	for _, n := range []struct {
		idx                       string
		chassisSub, portSub       int
		chassis, port             []byte
		portDesc, sysName, mgmtIP string
		caps                      byte
	}{
		{"0.1.1", 4, 5, []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, []byte("ge-0/0/1"), "uplink verso core", "router-1", "192.168.10.254", 0x28},
		{"1234.3.7", 5, 3, []byte{1, 192, 168, 10, 20}, []byte{0x00, 0x1b, 0x54, 0x01, 0x02, 0x03}, "Telefono di Mario Rossi", "SEP001B54010203", "192.168.10.20", 0x24},
	} {
		s := "." + n.idx
		d = append(d,
			num(oidLldpRemChassisIDSubtype+s, n.chassisSub), raw(oidLldpRemChassisID+s, n.chassis...),
			num(oidLldpRemPortIDSubtype+s, n.portSub), raw(oidLldpRemPortID+s, n.port...),
			str(oidLldpRemPortDesc+s, n.portDesc), str(oidLldpRemSysName+s, n.sysName),
			str(".1.0.8802.1.1.2.1.4.1.1.10"+s, "descrizione lunga"), raw(".1.0.8802.1.1.2.1.4.1.1.11"+s, 0xff, 0x00),
			raw(oidLldpRemSysCapEnabled+s, n.caps, 0x00),
			num(oidLldpRemManAddrIfSubtype+s+".1.4."+n.mgmtIP, 2), num(".1.0.8802.1.1.2.1.4.2.1.4"+s+".1.4."+n.mgmtIP, 0))
	}
	for _, p := range []struct {
		num      int
		sub      int
		id, desc string
	}{
		{1, 5, "Gi1/0/1", "Uplink router"}, {2, 5, "Gi1/0/2", "PC dott. Rossi"}, {3, 7, "3", "Telefono sala d'attesa"},
	} {
		s := "." + strconv.Itoa(p.num)
		d = append(d, num(oidLldpLocPortIDSubtype+s, p.sub), str(oidLldpLocPortID+s, p.id), str(oidLldpLocPortDesc+s, p.desc))
	}
	// Tabella degli indirizzi MAC (Q-BRIDGE-MIB) e porte del bridge.
	for _, f := range []struct {
		fdb, port int
		mac       string
	}{
		{10, 2, "60.88.194.17.34.51"}, {20, 3, "170.187.204.0.0.1"}, {10, 0, "0.27.84.170.187.204"},
	} {
		s := "." + strconv.Itoa(f.fdb) + "." + f.mac
		d = append(d, num(oidDot1qTpFdbPort+s, f.port), num(".1.3.6.1.2.1.17.7.1.2.2.1.3"+s, 3))
	}
	for p := 1; p <= 3; p++ {
		d = append(d, num(oidDot1dBasePortIfIndex+"."+strconv.Itoa(p), p))
	}
	return d
}

func TestCollectCoreSwitch(t *testing.T) {
	a := newAgent(t, community, coreSwitch())
	a.start(t)
	var steps []string
	res, err := Collect(context.Background(), "127.0.0.1", v2c, fast, func(s string) { steps = append(steps, s) })
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{stepSystem, stepInterfaces, stepVlans, stepLldp, stepArp, stepFdb}; !reflect.DeepEqual(steps, want) {
		t.Fatalf("passi: %q", steps)
	}
	if res.Target != "127.0.0.1" || res.Version != "2c" || res.Stopped != "" || res.Requests == 0 || len(res.Warnings) != 1 {
		t.Fatalf("intestazione: %+v", res)
	}

	sys := res.System
	if sys == nil || sys.ObjectID != "1.3.6.1.4.1.9.1.1208" || sys.Name != "core-sw1.clinica.local" || sys.UptimeSec != 1234567 || sys.ChassisID != "00:1b:54:aa:bb:cc" {
		t.Fatalf("sistema: %+v", sys)
	}
	if n := len([]rune(sys.Descr)); n != 200 || !strings.HasPrefix(sys.Descr, "Cisco IOS Software, C2960X") || strings.ContainsAny(sys.Descr, "\r\n") {
		t.Fatalf("sysDescr (%d caratteri): %q", n, sys.Descr)
	}

	wantIf := []Iface{
		{Index: 10, Name: "Vl10", Descr: "Vlan10", Type: 53, VlanID: 10,
			IPs: []IfaceIP{{IP: "192.168.10.1", Mask: "255.255.255.0", Prefix: 24, Subnet: "192.168.10.0/24"}}},
		{Index: 20, Name: "Vl20", Descr: "Vlan20", Type: 136, VlanID: 20,
			IPs: []IfaceIP{{IP: "10.20.0.1", Mask: "255.255.254.0", Prefix: 23, Subnet: "10.20.0.0/23"}, {IP: "10.20.5.1", Mask: "255.255.255.0", Prefix: 24, Subnet: "10.20.5.0/24"}}},
		{Index: 30, Name: "Vl30", Descr: "Vlan30", Type: 53, VlanID: 30, IPs: []IfaceIP{}},
		{Index: 100, Name: "Lo0", Descr: "Loopback0", Type: 24,
			IPs: []IfaceIP{{IP: "10.255.255.1", Mask: "255.255.255.255", Prefix: 32, Subnet: "10.255.255.1/32"}}},
	}
	if !reflect.DeepEqual(res.Interfaces, wantIf) {
		t.Fatalf("interfacce:\n%+v\natteso:\n%+v", res.Interfaces, wantIf)
	}

	wantVlans := []Vlan{{ID: 1, Name: "default"}, {ID: 10, Name: "Segreteria"}, {ID: 20, Name: "Ambulatori"}, {ID: 30, Name: "Ospiti"}, {ID: 40, Name: "Stampanti", State: "suspended"}}
	if !reflect.DeepEqual(res.Vlans, wantVlans) {
		t.Fatalf("VLAN: %+v", res.Vlans)
	}

	wantNb := []Neighbor{
		{LocalPortNum: 1, LocalPort: "Gi1/0/1", ChassisID: "00:11:22:33:44:55", ChassisIDType: "macAddress", PortID: "ge-0/0/1", PortIDType: "interfaceName",
			SysName: "router-1", CapsEnabled: []string{"bridge", "router"}, MgmtIP: "192.168.10.254"},
		{LocalPortNum: 3, LocalPort: "3", ChassisID: "192.168.10.20", ChassisIDType: "networkAddress", PortID: "00:1b:54:01:02:03", PortIDType: "macAddress",
			SysName: "SEP001B54010203", CapsEnabled: []string{"bridge", "telephone"}, MgmtIP: "192.168.10.20"},
	}
	if !reflect.DeepEqual(res.LldpNeighbors, wantNb) {
		t.Fatalf("vicini LLDP:\n%+v\natteso:\n%+v", res.LldpNeighbors, wantNb)
	}

	wantArp := []ArpEntry{
		{IfIndex: 20, IP: "10.20.0.30", MAC: "aa:bb:cc:00:00:01"},
		{IfIndex: 10, IP: "192.168.10.7", MAC: "00:1b:a9:12:34:56", Vendor: oui.Lookup("00:1b:a9:12:34:56")},
		{IfIndex: 10, IP: "192.168.10.50", MAC: "3c:58:c2:11:22:33", Vendor: oui.Lookup("3c:58:c2:11:22:33")},
	}
	if wantArp[1].Vendor != "Brother" {
		t.Fatalf("produttore del MAC della stampante: %q", wantArp[1].Vendor)
	}
	if !reflect.DeepEqual(res.Arp, wantArp) {
		t.Fatalf("ARP: %+v", res.Arp)
	}

	wantFdb := []FdbEntry{
		{MAC: "3c:58:c2:11:22:33", Port: "Gi1/0/2", BridgePort: 2, IfIndex: 2, FdbID: 10},
		{MAC: "aa:bb:cc:00:00:01", Port: "Gi1/0/3", BridgePort: 3, IfIndex: 3, FdbID: 20},
	}
	if !reflect.DeepEqual(res.Fdb, wantFdb) {
		t.Fatalf("FDB: %+v", res.Fdb)
	}

	sec := res.Sections
	for name, st := range map[string]Status{"system": sec.System, "interfaces": sec.Interfaces, "vlans": sec.Vlans, "lldp": sec.Lldp, "arp": sec.Arp, "fdb": sec.Fdb} {
		if st.State != StateOK || st.Note != "" {
			t.Errorf("sezione %s: %+v", name, st)
		}
	}
	if sec.Vlans.Source != "Q-BRIDGE-MIB, CISCO-VTP-MIB" || sec.Fdb.Source != "Q-BRIDGE-MIB" || sec.Vlans.Rows != 5 || sec.Fdb.Rows != 2 {
		t.Fatalf("origini e righe: %+v %+v", sec.Vlans, sec.Fdb)
	}

	requests, asked, returned, communities, maxReps, minGap := a.stats()
	if requests != res.Requests {
		t.Fatalf("richieste: l'agente ne ha ricevute %d, Collect ne conta %d", requests, res.Requests)
	}
	// Privacy: il testo libero scritto dagli amministratori non si chiede e
	// non arriva nemmeno in coda a un GETBULK.
	if o := forbiddenIn(append(asked, returned...)); o != "" {
		t.Fatalf("oggetto vietato chiesto o ricevuto: %s", o)
	}
	if len(communities) != 1 || communities[community] != requests {
		t.Fatalf("community usate: %v", communities)
	}
	// Ritmo: GETBULK piccoli e pausa tra una risposta e la richiesta successiva.
	if maxReps == 0 || maxReps > fast.MaxRepetitions {
		t.Fatalf("max-repetitions: %d", maxReps)
	}
	if minGap < fast.Interval {
		t.Fatalf("pausa minima tra le richieste: %v (attesa almeno %v)", minGap, fast.Interval)
	}

	b, err := json.Marshal(res)
	if err != nil || !strings.Contains(string(b), `"lldpNeighbors":[{"localPortNum":1,`) {
		t.Fatalf("JSON: %v %s", err, b)
	}
	for _, s := range []string{community, "Rossi", "Bianchi", "Uplink router", "uplink verso core", "Rete della", "sala d'attesa", `"alias"`, `"portDescr"`} {
		if strings.Contains(string(b), s) {
			t.Fatalf("il risultato contiene %q: %s", s, b)
		}
	}
}

// TestCollectLldpAliases: gli identificativi LLDP che sono alias scritti a
// mano (ifAlias, entPhysicalAlias) non si chiedono e non si mostrano; il
// tipo resta, così l'interfaccia sa perché l'identificativo manca.
func TestCollectLldpAliases(t *testing.T) {
	d := []gosnmp.SnmpPDU{
		str(oidSysDescr, "switch"), str(oidSysName, "sw-piano2"),
		num(oidLldpLocChassisIDSubtype, 1), str(oidLldpLocChassisID, "Armadio dott. Verdi"), // chassisComponent
		num(oidLldpLocPortIDSubtype+".5", 1), str(oidLldpLocPortID+".5", "Porta dott. Neri"), // interfaceAlias
		num(oidLldpLocPortIDSubtype+".6", 5), str(oidLldpLocPortID+".6", "Gi1/0/6"),
		str(oidLldpLocPortDesc+".5", "Porta dott. Neri"), str(oidLldpLocPortDesc+".6", "Presa 12 Bianchi"),
		num(oidLldpRemChassisIDSubtype+".0.5.1", 2), str(oidLldpRemChassisID+".0.5.1", "Ufficio Rossi"), // interfaceAlias
		num(oidLldpRemPortIDSubtype+".0.5.1", 1), str(oidLldpRemPortID+".0.5.1", "PC Rossi"), // interfaceAlias
		str(oidLldpRemPortDesc+".0.5.1", "PC Rossi"), str(oidLldpRemSysName+".0.5.1", "ws-12"),
		num(oidLldpRemChassisIDSubtype+".0.6.1", 4), raw(oidLldpRemChassisID+".0.6.1", 0x00, 0x11, 0x22, 0x33, 0x44, 0x66),
		num(oidLldpRemPortIDSubtype+".0.6.1", 2), str(oidLldpRemPortID+".0.6.1", "Presa 12 Bianchi"), // portComponent
		str(oidLldpRemSysName+".0.6.1", "ap-12"),
	}
	a := newAgent(t, community, d)
	a.start(t)
	res, err := Collect(context.Background(), "127.0.0.1", v2c, fast, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []Neighbor{
		{LocalPortNum: 5, ChassisIDType: "interfaceAlias", PortIDType: "interfaceAlias", SysName: "ws-12"},
		{LocalPortNum: 6, LocalPort: "Gi1/0/6", ChassisID: "00:11:22:33:44:66", ChassisIDType: "macAddress", PortIDType: "portComponent", SysName: "ap-12"},
	}
	if !reflect.DeepEqual(res.LldpNeighbors, want) || res.System.ChassisID != "" || res.Sections.Lldp.State != StateOK {
		t.Fatalf("vicini LLDP: %+v %+v %+v", res.LldpNeighbors, res.System, res.Sections.Lldp)
	}
	_, asked, _, _, _, _ := a.stats()
	for _, o := range asked {
		for _, alias := range []string{oidLldpLocChassisID, oidLldpLocPortID + ".5", oidLldpRemChassisID + ".0.5.1", oidLldpRemPortID + ".0.5.1", oidLldpRemPortID + ".0.6.1"} {
			if o == alias {
				t.Fatalf("alias chiesto: %s", o)
			}
		}
	}
	if o := forbiddenIn(asked); o != "" {
		t.Fatalf("oggetto vietato chiesto: %s", o)
	}
	b, _ := json.Marshal(res)
	for _, s := range []string{"Verdi", "Neri", "Rossi", "Bianchi"} {
		if strings.Contains(string(b), s) {
			t.Fatalf("il risultato contiene %q: %s", s, b)
		}
	}
}

// minimalDevice è un router domestico: niente ifXTable, VLAN, LLDP né ARP,
// tabella degli indirizzi MAC solo in BRIDGE-MIB.
func minimalDevice() []gosnmp.SnmpPDU {
	return []gosnmp.SnmpPDU{
		str(oidSysDescr, "Router  Citt\xe0\x00"),
		{Name: oidSysObjectID, Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.4.1.4413.1"},
		{Name: oidSysUpTime, Type: gosnmp.TimeTicks, Value: uint32(99)},
		str(oidSysName, ""),
		str(oidIfDescr+".1", "eth0"), str(oidIfDescr+".2", "br0.30"),
		num(oidIfType+".1", 6), num(oidIfType+".2", 6),
		num(oidIPAdEntIfIndex+".192.168.1.1", 1), ipv(oidIPAdEntNetMask+".192.168.1.1", "255.255.255.0"),
		num(oidDot1dTpFdbPort+".0.17.34.51.68.85", 1), num(oidDot1dTpFdbPort+".0.17.34.51.68.86", 0),
		num(oidDot1dBasePortIfIndex+".1", 1),
	}
}

func TestCollectMinimalDevice(t *testing.T) {
	a := newAgent(t, community, minimalDevice())
	a.start(t)
	res, err := Collect(context.Background(), "127.0.0.1", v2c, fast, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.System == nil || res.System.Descr != "Router Città" || res.System.UptimeSec != 0 || res.System.ChassisID != "" {
		t.Fatalf("sistema: %+v", res.System)
	}
	if len(res.Interfaces) != 1 || res.Interfaces[0].Descr != "eth0" || res.Interfaces[0].Name != "" || res.Interfaces[0].IPs[0].Subnet != "192.168.1.0/24" {
		t.Fatalf("interfacce: %+v", res.Interfaces)
	}
	if want := []FdbEntry{{MAC: "00:11:22:33:44:55", Port: "eth0", BridgePort: 1, IfIndex: 1}}; !reflect.DeepEqual(res.Fdb, want) {
		t.Fatalf("FDB: %+v", res.Fdb)
	}
	sec := res.Sections
	if sec.Fdb.State != StateOK || sec.Fdb.Source != "BRIDGE-MIB" {
		t.Fatalf("FDB: %+v", sec.Fdb)
	}
	for name, st := range map[string]Status{"vlans": sec.Vlans, "lldp": sec.Lldp, "arp": sec.Arp} {
		if st.State != StateAbsent || st.Rows != 0 || st.Note == "" {
			t.Errorf("sezione %s: %+v", name, st)
		}
	}
	if !strings.Contains(sec.Lldp.Note, "LLDP-MIB assente") {
		t.Fatalf("nota LLDP: %q", sec.Lldp.Note)
	}
	if res.Vlans == nil || res.LldpNeighbors == nil || res.Arp == nil {
		t.Fatal("le sezioni vuote devono essere elenchi vuoti, non null")
	}
}

func TestCollectRowCaps(t *testing.T) {
	d := minimalDevice()
	for i := 0; i < 30; i++ {
		d = append(d, raw(oidIPNetToMediaPhysAddress+".1.192.168.1."+strconv.Itoa(10+i), 0x00, 0x11, 0x22, 0x33, 0x44, byte(i)))
		d = append(d, num(oidDot1qTpFdbPort+".1.0.17.34.51.0."+strconv.Itoa(i), 1))
	}
	a := newAgent(t, community, d)
	a.start(t)
	opt := fast
	opt.MaxRows = 10
	res, err := Collect(context.Background(), "127.0.0.1", v2c, opt, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Arp) != 10 || res.Arp[0].IP != "192.168.1.10" || res.Arp[9].IP != "192.168.1.19" {
		t.Fatalf("ARP: %d righe, %+v", len(res.Arp), res.Arp)
	}
	if len(res.Fdb) != 10 || res.Sections.Fdb.Source != "Q-BRIDGE-MIB" {
		t.Fatalf("FDB: %d righe, %+v", len(res.Fdb), res.Sections.Fdb)
	}
	for _, st := range []Status{res.Sections.Arp, res.Sections.Fdb} {
		if st.State != StatePartial || st.Rows != 10 || !strings.Contains(st.Note, "limitato a 10 righe") {
			t.Fatalf("stato: %+v", st)
		}
	}
	// Con il limite le tabelle lunghe non si leggono per intero: circa tre
	// GETBULK per tabella invece di otto.
	if res.Requests > 30 {
		t.Fatalf("troppe richieste: %d", res.Requests)
	}
}

func TestCollectTableError(t *testing.T) {
	a := newAgent(t, community, coreSwitch())
	a.genErrUnder = oidDot1qVlanStaticName
	a.start(t)
	res, err := Collect(context.Background(), "127.0.0.1", v2c, fast, nil)
	if err != nil {
		t.Fatal(err)
	}
	st := res.Sections.Vlans
	if st.State != StatePartial || st.Source != "CISCO-VTP-MIB" || !strings.Contains(st.Note, "dot1qVlanStaticName: errore SNMP GenErr") {
		t.Fatalf("VLAN: %+v", st)
	}
	if len(res.Vlans) != 4 || res.Vlans[3].Name != "Stampanti" {
		t.Fatalf("VLAN da CISCO-VTP-MIB: %+v", res.Vlans)
	}
	if res.Stopped != "" || res.Sections.Fdb.State != StateOK {
		t.Fatalf("un errore di una tabella non deve fermare la lettura: %q %+v", res.Stopped, res.Sections.Fdb)
	}
}

func TestCollectWrongCommunity(t *testing.T) {
	a := newAgent(t, community, coreSwitch())
	a.start(t)
	opt := fast
	opt.Timeout, opt.Retries = 150*time.Millisecond, 1
	start := time.Now()
	res, err := Collect(context.Background(), "127.0.0.1", Creds{Version: "2c", Community: "Sbagliata-9"}, opt, nil)
	var e *Error
	if !errors.As(err, &e) || e.Kind != KindTimeout || res != nil || !strings.Contains(e.Msg, "community") {
		t.Fatalf("community sbagliata: %v %+v", err, res)
	}
	if strings.Contains(err.Error(), "Sbagliata-9") || strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("il messaggio non deve riportare community o indirizzi: %q", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("troppo lento: %v", d)
	}
	// Nessun tentativo con altre community: una richiesta più un nuovo tentativo.
	requests, _, _, communities, _, _ := a.stats()
	if requests != 2 || len(communities) != 1 || communities["Sbagliata-9"] != 2 {
		t.Fatalf("richieste %d, community %v", requests, communities)
	}
}

func TestCollectNoAnswerV3(t *testing.T) {
	a := newAgent(t, community, nil)
	a.silent = true
	a.start(t)
	opt := fast
	opt.Timeout = 150 * time.Millisecond
	_, err := Collect(context.Background(), "127.0.0.1", Creds{Version: "3", User: "tecnico", Auth: "SHA256", AuthPass: "password-lunga", Priv: "AES", PrivPass: "altra-password"}, opt, nil)
	var e *Error
	if !errors.As(err, &e) || e.Kind != KindTimeout || !strings.Contains(e.Msg, "SNMPv3") || strings.Contains(e.Msg, "password") {
		t.Fatalf("SNMPv3 senza risposta: %v", err)
	}
}

func TestCollectCancelWhileWaiting(t *testing.T) {
	a := newAgent(t, community, nil)
	a.silent = true
	a.start(t)
	opt := fast
	opt.Timeout = 5 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	start := time.Now()
	res, err := Collect(ctx, "127.0.0.1", v2c, opt, nil)
	var e *Error
	if !errors.As(err, &e) || e.Kind != KindCanceled || res != nil {
		t.Fatalf("interruzione: %v %+v", err, res)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("l'interruzione deve fermare subito l'attesa della risposta: %v", d)
	}
}

func TestCollectCancelMidway(t *testing.T) {
	a := newAgent(t, community, coreSwitch())
	a.start(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	res, err := Collect(ctx, "127.0.0.1", v2c, fast, func(step string) {
		if step == stepArp {
			cancel()
		}
	})
	var e *Error
	if !errors.As(err, &e) || e.Kind != KindCanceled || res == nil {
		t.Fatalf("interruzione: %v", err)
	}
	sec := res.Sections
	if sec.Lldp.State != StateOK || len(res.LldpNeighbors) != 2 || sec.Arp.State != StateError || sec.Fdb.State != StateSkipped || res.Stopped != "lettura interrotta" {
		t.Fatalf("risultato parziale: %q %+v", res.Stopped, sec)
	}
}

func TestCollectDeviceStopsAnswering(t *testing.T) {
	a := newAgent(t, community, coreSwitch())
	a.answerFirst = 4 // sistema e prime righe delle interfacce
	a.start(t)
	opt := fast
	opt.Timeout = 150 * time.Millisecond
	res, err := Collect(context.Background(), "127.0.0.1", v2c, opt, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Stopped, "smesso di rispondere") {
		t.Fatalf("motivo: %q", res.Stopped)
	}
	sec := res.Sections
	if sec.System.State != StateOK || (sec.Interfaces.State != StatePartial && sec.Interfaces.State != StateError) {
		t.Fatalf("sezioni lette: %+v", sec)
	}
	for _, st := range []Status{sec.Vlans, sec.Lldp, sec.Arp, sec.Fdb} {
		if st.State != StateSkipped || !strings.Contains(st.Note, "smesso di rispondere") {
			t.Fatalf("sezione dopo il silenzio: %+v", st)
		}
	}
	// Dopo il silenzio nessun'altra richiesta: quattro risposte e un tentativo a vuoto.
	if requests, _, _, _, _, _ := a.stats(); requests != 5 {
		t.Fatalf("richieste: %d", requests)
	}
}

func TestCollectDeadline(t *testing.T) {
	a := newAgent(t, community, coreSwitch())
	a.delay = 15 * time.Millisecond
	a.start(t)
	opt := fast
	opt.Deadline = 200 * time.Millisecond
	start := time.Now()
	res, err := Collect(context.Background(), "127.0.0.1", v2c, opt, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Stopped, "tempo massimo") || res.Sections.Fdb.State != StateSkipped {
		t.Fatalf("tempo massimo: %q %+v", res.Stopped, res.Sections)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("il tempo massimo non è stato rispettato: %v", d)
	}
}

func TestCollectRefused(t *testing.T) {
	// Porta UDP chiusa: Linux risponde con ICMP "port unreachable".
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(c.LocalAddr().(*net.UDPAddr).Port)
	c.Close()
	useLoopback(t, port)
	_, err = Collect(context.Background(), "127.0.0.1", v2c, fast, nil)
	var e *Error
	if !errors.As(err, &e) || e.Kind != KindRefused {
		t.Fatalf("porta chiusa: %v", err)
	}
}

// TestCollectV3 legge lo stesso switch in SNMPv3: scoperta del motore,
// autenticazione e cifratura vere (quelle di gosnmp) nei due sensi.
func TestCollectV3(t *testing.T) {
	v2, err := func() (*Result, error) {
		a := newAgent(t, community, coreSwitch())
		a.start(t)
		return Collect(context.Background(), "127.0.0.1", v2c, fast, nil)
	}()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		creds    Creds
		auth     gosnmp.SnmpV3AuthProtocol
		priv     gosnmp.SnmpV3PrivProtocol
		warnings int
	}{
		{Creds{Version: "3", User: "tecnico", Auth: "SHA-256", AuthPass: "Autenticazione-1", Priv: "AES", PrivPass: "Cifratura-2"}, gosnmp.SHA256, gosnmp.AES, 0},
		{Creds{Version: "3", User: "tecnico", Auth: "SHA", AuthPass: "Autenticazione-1"}, gosnmp.SHA, gosnmp.NoPriv, 1},
		{Creds{Version: "3", User: "tecnico", Auth: "MD5", AuthPass: "Autenticazione-1", Priv: "DES", PrivPass: "Cifratura-2"}, gosnmp.MD5, gosnmp.DES, 2},
	} {
		t.Run(tc.creds.Auth+"/"+tc.creds.Priv, func(t *testing.T) {
			a := newAgent(t, community, coreSwitch())
			a.user = &gosnmp.UsmSecurityParameters{UserName: "tecnico", AuthenticationProtocol: tc.auth, AuthenticationPassphrase: tc.creds.AuthPass,
				PrivacyProtocol: tc.priv, PrivacyPassphrase: tc.creds.PrivPass}
			a.start(t)
			res, err := Collect(context.Background(), "127.0.0.1", tc.creds, fast, nil)
			if err != nil {
				t.Fatal(err)
			}
			if res.Version != "3" || len(res.Warnings) != tc.warnings {
				t.Fatalf("intestazione: %q %q", res.Version, res.Warnings)
			}
			if !reflect.DeepEqual(res.Sections, v2.Sections) || !reflect.DeepEqual(res.System, v2.System) || !reflect.DeepEqual(res.Interfaces, v2.Interfaces) ||
				!reflect.DeepEqual(res.Vlans, v2.Vlans) || !reflect.DeepEqual(res.LldpNeighbors, v2.LldpNeighbors) ||
				!reflect.DeepEqual(res.Arp, v2.Arp) || !reflect.DeepEqual(res.Fdb, v2.Fdb) {
				t.Fatalf("SNMPv3 diverso da SNMPv2c:\n%+v\n%+v", res, v2)
			}
			// Un pacchetto in più per la scoperta del motore.
			if requests, _, _, _, _, _ := a.stats(); requests != res.Requests || res.Requests != v2.Requests+1 {
				t.Fatalf("richieste: agente %d, Collect %d, SNMPv2c %d", requests, res.Requests, v2.Requests)
			}
		})
	}
}

func TestCollectV3Rejected(t *testing.T) {
	for _, tc := range []struct {
		name   string
		creds  Creds
		report string
		want   string
	}{
		{"password errata", Creds{Version: "3", User: "tecnico", Auth: "SHA", AuthPass: "password-sbagliata"}, wrongDigests, "rifiutato le credenziali"},
		{"utente sconosciuto", Creds{Version: "3", User: "nessuno"}, unknownUserNames, "non conosce questo utente"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newAgent(t, community, nil)
			a.user = &gosnmp.UsmSecurityParameters{UserName: "tecnico", AuthenticationProtocol: gosnmp.SHA, AuthenticationPassphrase: "password-dell-agente", PrivacyProtocol: gosnmp.NoPriv}
			a.script = func(req *gosnmp.SnmpPacket, n int) *gosnmp.SnmpPacket {
				if n == 1 { // scoperta del motore SNMPv3
					return v3Report(req, unknownEngineIDs)
				}
				return v3Report(req, tc.report)
			}
			a.start(t)
			_, err := Collect(context.Background(), "127.0.0.1", tc.creds, fast, nil)
			var e *Error
			if !errors.As(err, &e) || e.Kind != KindAuth || !strings.Contains(e.Msg, tc.want) {
				t.Fatalf("errore: %v", err)
			}
			if strings.Contains(e.Msg, "password-sbagliata") || strings.Contains(e.Msg, "tecnico") || strings.Contains(e.Msg, "nessuno") {
				t.Fatalf("il messaggio riporta le credenziali: %q", e.Msg)
			}
		})
	}
}

func TestCheckTarget(t *testing.T) {
	for in, want := range map[string]string{"192.168.1.1": "192.168.1.1", " 10.0.0.254 ": "10.0.0.254", "172.16.0.1": "172.16.0.1", "172.31.255.254": "172.31.255.254"} {
		if a, err := checkTarget(in); err != nil || a.String() != want {
			t.Fatalf("%q: %v %v", in, a, err)
		}
	}
	for in, kind := range map[string]Kind{
		"":                     KindInvalid,
		"router.local":         KindInvalid,
		"192.168.1.0/24":       KindInvalid,
		"192.168.1.1-20":       KindInvalid,
		"192.168.1.1,2":        KindInvalid,
		"192.168.1.1 10.0.0.1": KindInvalid,
		"192.168.001.001":      KindInvalid,
		"fd00::1":              KindInvalid,
		"::ffff:192.168.1.1":   KindInvalid,
		"192.168.1.255":        KindInvalid,
		"10.1.2.0":             KindInvalid,
		"8.8.8.8":              KindNotPrivate,
		"172.32.0.1":           KindNotPrivate,
		"100.64.0.1":           KindNotPrivate,
		"127.0.0.1":            KindNotPrivate,
		"169.254.10.1":         KindNotPrivate,
		"255.255.255.255":      KindNotPrivate,
		"Segreta!2026":         KindInvalid,
	} {
		_, err := checkTarget(in)
		if err == nil || err.Kind != kind {
			t.Fatalf("%q: %v (atteso %s)", in, err, kind)
		}
		if strings.Contains(err.Msg, "Segreta") {
			t.Fatalf("il messaggio ripete un testo non valido: %q", err.Msg)
		}
	}
}

func TestCredsApply(t *testing.T) {
	g := &gosnmp.GoSNMP{}
	if err := (Creds{Version: "v2c", Community: community}).apply(g); err != nil || g.Version != gosnmp.Version2c || g.Community != community || g.SecurityParameters != nil {
		t.Fatalf("v2c: %v %+v", err, g)
	}
	for _, tc := range []struct {
		c     Creds
		flags gosnmp.SnmpV3MsgFlags
		auth  gosnmp.SnmpV3AuthProtocol
		priv  gosnmp.SnmpV3PrivProtocol
	}{
		{Creds{Version: "3", User: "u", Auth: "SHA256", AuthPass: "12345678", Priv: "AES", PrivPass: "abcdefgh"}, gosnmp.AuthPriv, gosnmp.SHA256, gosnmp.AES},
		{Creds{Version: "3", User: "u", Auth: "sha-512", AuthPass: "12345678", Priv: "aes-128", PrivPass: "abcdefgh"}, gosnmp.AuthPriv, gosnmp.SHA512, gosnmp.AES},
		{Creds{Version: "3", User: "u", Auth: "SHA", AuthPass: "12345678"}, gosnmp.AuthNoPriv, gosnmp.SHA, gosnmp.NoPriv},
		{Creds{Version: "3", User: "u", Auth: "MD5", AuthPass: "12345678", Priv: "DES", PrivPass: "abcdefgh"}, gosnmp.AuthPriv, gosnmp.MD5, gosnmp.DES},
		{Creds{Version: "3", User: "u", Auth: "SHA224", AuthPass: "12345678"}, gosnmp.AuthNoPriv, gosnmp.SHA224, gosnmp.NoPriv},
		{Creds{Version: "3", User: "u", Auth: "SHA384", AuthPass: "12345678"}, gosnmp.AuthNoPriv, gosnmp.SHA384, gosnmp.NoPriv},
		{Creds{Version: "3", User: "u"}, gosnmp.NoAuthNoPriv, gosnmp.NoAuth, gosnmp.NoPriv},
		{Creds{Version: "3", User: "u", Auth: "none", Priv: "NONE"}, gosnmp.NoAuthNoPriv, gosnmp.NoAuth, gosnmp.NoPriv},
	} {
		g := &gosnmp.GoSNMP{}
		if err := tc.c.apply(g); err != nil {
			t.Fatalf("%v: %v", tc.c.Auth, err)
		}
		usm, ok := g.SecurityParameters.(*gosnmp.UsmSecurityParameters)
		if !ok || g.Version != gosnmp.Version3 || g.SecurityModel != gosnmp.UserSecurityModel || g.MsgFlags != tc.flags || g.Community != "" {
			t.Fatalf("%s/%s: %+v", tc.c.Auth, tc.c.Priv, g)
		}
		if usm.UserName != "u" || usm.AuthenticationProtocol != tc.auth || usm.PrivacyProtocol != tc.priv ||
			usm.AuthenticationPassphrase != tc.c.AuthPass || usm.PrivacyPassphrase != tc.c.PrivPass {
			t.Fatalf("%s/%s: %s", tc.c.Auth, tc.c.Priv, usm.SafeString())
		}
	}
}

func TestCredsValidation(t *testing.T) {
	for name, c := range map[string]Creds{
		"versione":               {Version: "1", Community: community},
		"senza versione":         {Community: community},
		"community vuota":        {Version: "2c", Community: "  "},
		"community lunga":        {Version: "2c", Community: strings.Repeat("c", 128)},
		"utente mancante":        {Version: "3", Auth: "SHA", AuthPass: "12345678"},
		"utente lungo":           {Version: "3", User: strings.Repeat("u", 33)},
		"autenticazione ignota":  {Version: "3", User: "u", Auth: "SHA3", AuthPass: "12345678"},
		"cifratura ignota":       {Version: "3", User: "u", Auth: "SHA", AuthPass: "12345678", Priv: "AES256", PrivPass: "12345678"},
		"cifratura senza auth":   {Version: "3", User: "u", Priv: "AES", PrivPass: "12345678"},
		"password auth mancante": {Version: "3", User: "u", Auth: "SHA"},
		"password auth corta":    {Version: "3", User: "u", Auth: "SHA", AuthPass: "1234567"},
		"password priv mancante": {Version: "3", User: "u", Auth: "SHA", AuthPass: "12345678", Priv: "AES"},
		"password priv corta":    {Version: "3", User: "u", Auth: "SHA", AuthPass: "12345678", Priv: "DES", PrivPass: "corta"},
		"password senza auth":    {Version: "3", User: "u", AuthPass: "Segreta!2026"},
		"password senza priv":    {Version: "3", User: "u", Auth: "SHA", AuthPass: "12345678", PrivPass: "Segreta!2026"},
	} {
		err := c.apply(&gosnmp.GoSNMP{})
		if err == nil || err.Kind != KindInvalid {
			t.Fatalf("%s: accettate (%v)", name, err)
		}
		if strings.Contains(err.Msg, "Segreta") || strings.Contains(err.Msg, "12345678") || strings.Contains(err.Msg, community) {
			t.Fatalf("%s: il messaggio riporta un segreto: %q", name, err.Msg)
		}
	}
	// Nessun pacchetto parte con credenziali non valide.
	a := newAgent(t, community, coreSwitch())
	a.start(t)
	if _, err := Collect(context.Background(), "127.0.0.1", Creds{Version: "3", User: "u", Auth: "SHA", AuthPass: "corta"}, fast, nil); err == nil {
		t.Fatal("credenziali non valide accettate")
	}
	if requests, _, _, _, _, _ := a.stats(); requests != 0 {
		t.Fatalf("richieste inviate con credenziali non valide: %d", requests)
	}
}

func TestCredsHidden(t *testing.T) {
	c := Creds{Version: "3", User: "utente-segreto", Auth: "SHA256", AuthPass: "Password-Auth-1", Priv: "AES", PrivPass: "Password-Priv-2", Community: "Community-3"}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{fmt.Sprintf("%v %+v %#v %s %q", c, c, c, c, c), fmt.Sprint(&c), string(b)} {
		for _, secret := range []string{"utente-segreto", "Password-Auth-1", "Password-Priv-2", "Community-3"} {
			if strings.Contains(s, secret) {
				t.Fatalf("segreto visibile: %s", s)
			}
		}
	}
	// La lettura delle credenziali dal JSON dell'interfaccia funziona.
	var in Creds
	if err := json.Unmarshal([]byte(`{"version":"2c","community":"abc"}`), &in); err != nil || in.Community != "abc" {
		t.Fatalf("lettura JSON: %v %+v", err, in.Version)
	}
}

func TestSessionWipe(t *testing.T) {
	g := &gosnmp.GoSNMP{}
	if err := (Creds{Version: "3", User: "u", Auth: "SHA", AuthPass: "12345678", Priv: "AES", PrivPass: "abcdefgh"}).apply(g); err != nil {
		t.Fatal(err)
	}
	usm := g.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	secret, priv := []byte{1, 2, 3, 4}, []byte{5, 6, 7, 8}
	usm.SecretKey, usm.PrivacyKey = secret, priv
	(&session{g: g}).wipe()
	if !reflect.DeepEqual(secret, []byte{0, 0, 0, 0}) || !reflect.DeepEqual(priv, []byte{0, 0, 0, 0}) {
		t.Fatalf("chiavi non azzerate: %v %v", secret, priv)
	}
	if usm.AuthenticationPassphrase != "" || usm.PrivacyPassphrase != "" || g.SecurityParameters != nil {
		t.Fatal("password ancora raggiungibili")
	}
	g = &gosnmp.GoSNMP{Community: community}
	(&session{g: g}).wipe()
	if g.Community != "" {
		t.Fatal("community ancora raggiungibile")
	}
}

func TestDescribe(t *testing.T) {
	timeout := fmt.Errorf("request timeout (after 1 retries): %w", gosnmp.ErrMaxRetriesExceeded)
	for _, tc := range []struct {
		err          error
		v3, answered bool
		kind         Kind
		msg          string
	}{
		{timeout, false, false, KindTimeout, "community"},
		{timeout, true, false, KindTimeout, "SNMPv3"},
		{timeout, false, true, KindTimeout, "smesso di rispondere"},
		{&net.OpError{Op: "read", Net: "udp", Err: timeoutErr{}}, false, false, KindTimeout, "community"},
		{fmt.Errorf("x: %w", gosnmp.ErrUnknownUsername), true, false, KindAuth, "utente"},
		{gosnmp.ErrWrongDigest, true, false, KindAuth, "autenticazione"},
		{gosnmp.ErrDecryption, true, false, KindAuth, "cifratura"},
		{gosnmp.ErrUnknownSecurityLevel, true, false, KindAuth, "livello di sicurezza"},
		{errors.New("incoming packet is not authentic, discarding"), true, false, KindAuth, "credenziali"},
		{gosnmp.ErrUnknownEngineID, true, false, KindProtocol, "SNMPv3"},
		{gosnmp.ErrInvalidMsgs, true, false, KindProtocol, "SNMPv3"},
		{&net.OpError{Op: "read", Net: "udp", Err: &os.SyscallError{Syscall: "recvfrom", Err: syscall.ECONNREFUSED}}, false, false, KindRefused, "porta UDP 161"},
		{fmt.Errorf("error reading from socket: %w", syscall.Errno(10061)), false, false, KindRefused, "porta UDP 161"},
		{errors.New("wsarecv: An existing connection was forcibly closed by the remote host. connection refused"), false, false, KindRefused, "porta"},
		{&net.OpError{Op: "dial", Net: "udp", Err: syscall.ENETUNREACH}, false, false, KindUnreachable, "raggiungibile"},
		{syscall.Errno(10065), false, false, KindUnreachable, "raggiungibile"},
		{errors.New("unable to decode packet body"), false, true, KindProtocol, "non valida"},
	} {
		e := describe(tc.err, tc.v3, tc.answered)
		if e.Kind != tc.kind || !strings.Contains(e.Msg, tc.msg) {
			t.Fatalf("%v: %s %q", tc.err, e.Kind, e.Msg)
		}
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestOptionsNormalized(t *testing.T) {
	if got := (Options{}).normalized(); got.Timeout != Prudent.Timeout || got.Interval != Prudent.Interval || got.MaxRepetitions != 16 || got.MaxRows != 4096 || got.Deadline != time.Minute || got.Retries != 0 {
		t.Fatalf("valori predefiniti: %+v", got)
	}
	if got := (Options{Timeout: time.Hour, Retries: 9, MaxRepetitions: 500, MaxRows: 1 << 30, Deadline: 24 * time.Hour}).normalized(); got.Timeout != 10*time.Second || got.Retries != 3 || got.MaxRepetitions != 50 || got.MaxRows != 65536 || got.Deadline != 10*time.Minute {
		t.Fatalf("limiti: %+v", got)
	}
	if got := Prudent.normalized(); got != Prudent {
		t.Fatalf("Prudent cambia: %+v", got)
	}
}

func TestText(t *testing.T) {
	for in, want := range map[string]string{
		"  core-sw1 \x00\x00":   "core-sw1",
		"riga1\r\nriga2\ttab":   "riga1 riga2 tab",
		"Citt\xe0":              "Città",
		"nome‮esac​":            "nomeesac",
		"Vlan 10 \x1b[31mrosso": "Vlan 10 [31mrosso",
	} {
		if got := text([]byte(in), maxText); got != want {
			t.Fatalf("%q: %q", in, got)
		}
	}
	if got := text(strings.Repeat("è", 300), 200); len([]rune(got)) != 200 {
		t.Fatalf("taglio: %d caratteri", len([]rune(got)))
	}
	if text(42, 10) != "" || text(nil, 10) != "" {
		t.Fatal("valori non testuali")
	}
}

func TestDecodeID(t *testing.T) {
	for _, tc := range []struct {
		kind string
		b    []byte
		want string
	}{
		{"macAddress", []byte{0, 0x1b, 0x54, 0xaa, 0xbb, 0xcc}, "00:1b:54:aa:bb:cc"},
		{"macAddress", []byte("Gi1/0/1"), "Gi1/0/1"}, // sottotipo sbagliato: si mostra il testo
		{"networkAddress", []byte{1, 10, 0, 0, 1}, "10.0.0.1"},
		{"networkAddress", append([]byte{2, 0xfd}, make([]byte, 15)...), "fd00::"},
		{"interfaceName", []byte("ge-0/0/1\x00"), "ge-0/0/1"},
		{"local", []byte("3"), "3"},
		{"local", []byte{0x01, 0x02, 0xff}, "01:02:ff"},
		{"agentCircuitId", []byte("abc"), "61:62:63"},
		{"", nil, ""},
		// Alias scritti a mano dagli amministratori: mai mostrati.
		{"interfaceAlias", []byte("PC Rossi"), ""},
		{"chassisComponent", []byte("Armadio Verdi"), ""},
		{"portComponent", []byte("Presa 12"), ""},
	} {
		if got := decodeID(tc.kind, tc.b); got != tc.want {
			t.Fatalf("%s % x: %q", tc.kind, tc.b, got)
		}
	}
	for kind, alias := range map[string]bool{"interfaceAlias": true, "chassisComponent": true, "portComponent": true, "interfaceName": false, "macAddress": false, "local": false, "": false} {
		if aliasID(kind) != alias {
			t.Fatalf("aliasID(%q)", kind)
		}
	}
}

func TestCaps(t *testing.T) {
	if got := caps([]byte{0x28}); !reflect.DeepEqual(got, []string{"bridge", "router"}) {
		t.Fatal(got)
	}
	if got := caps([]byte{0x91, 0xff}); !reflect.DeepEqual(got, []string{"other", "wlanAccessPoint", "stationOnly"}) {
		t.Fatal(got)
	}
	if caps(nil) != nil {
		t.Fatal("nessun bit")
	}
}

func TestVlanLike(t *testing.T) {
	for _, tc := range []struct {
		name, descr string
		ifType      int
		ok          bool
		id          int
	}{
		{"Vl10", "Vlan10", 53, true, 10},
		{"", "VLAN 0020", 1, true, 20},
		{"Vlanif300", "", 6, true, 300},
		{"Vlan-interface4094", "", 136, true, 4094},
		{"vlan.7", "", 1, true, 7},
		{"Vlan4095", "", 1, false, 0},
		{"irb.100", "", 136, true, 0},
		{"eth0.10", "", 135, true, 0},
		{"Gi1/0/1", "GigabitEthernet1/0/1", 6, false, 0},
		{"DEFAULT_VLAN", "", 53, false, 0},
	} {
		if ok, id := vlanLike(tc.name, tc.descr, tc.ifType); ok != tc.ok || id != tc.id {
			t.Fatalf("%q %q %d: %v %d", tc.name, tc.descr, tc.ifType, ok, id)
		}
	}
}

func TestIfaceIPAndIndexes(t *testing.T) {
	ip := netip.MustParseAddr("10.1.2.3")
	if got := ifaceIP(ip, "255.255.240.0"); got != (IfaceIP{IP: "10.1.2.3", Mask: "255.255.240.0", Prefix: 20, Subnet: "10.1.0.0/20"}) {
		t.Fatalf("%+v", got)
	}
	if got := ifaceIP(ip, "255.0.255.0"); got.Prefix != 0 || got.Subnet != "" {
		t.Fatalf("maschera non contigua: %+v", got)
	}
	if got := ifaceIP(ip, ""); got.Prefix != 0 || got.Subnet != "" || got.Mask != "" {
		t.Fatalf("maschera assente: %+v", got)
	}
	if manAddrIPv4([]uint32{1, 4, 192, 168, 1, 2}) != "192.168.1.2" || manAddrIPv4([]uint32{1, 192, 168, 1, 2}) != "192.168.1.2" ||
		manAddrIPv4([]uint32{2, 16, 0xfd}) != "" || manAddrIPv4([]uint32{1, 4, 300, 1, 1, 1}) != "" {
		t.Fatal("indirizzo di gestione LLDP")
	}
	if _, ok := macFromIndex([]uint32{1, 2, 3, 4, 5, 256}); ok {
		t.Fatal("MAC con byte oltre 255")
	}
	if _, ok := unicastMAC([]byte{0x01, 0, 0x5e, 0, 0, 1}); ok {
		t.Fatal("MAC multicast accettato")
	}
	// Valori oltre Integer32, validi anche dove int e uint sono a 32 bit.
	for _, v := range []any{uint(1) << 31, uint32(1) << 31, uint64(1) << 40, int64(-1) << 40} {
		if n, ok := intOf(v); ok || n != 0 {
			t.Fatalf("intero fuori limite accettato: %v", v)
		}
	}
	if n, ok := intOf(uint(7)); !ok || n != 7 {
		t.Fatal("Gauge32")
	}
}

func TestOIDs(t *testing.T) {
	a, _ := parseOID(".1.3.6.1.2.1.2")
	b, _ := parseOID("1.3.6.1.2.1.10")
	c, _ := parseOID(".1.3.6.1.2.1.2.1")
	if compareOID(a, b) != -1 || compareOID(b, a) != 1 || compareOID(a, c) != -1 || compareOID(a, a) != 0 {
		t.Fatal("ordine degli OID")
	}
	if !hasPrefix(c, a) || hasPrefix(a, c) || formatOID(c) != ".1.3.6.1.2.1.2.1" {
		t.Fatal("prefissi")
	}
	for _, bad := range []string{"", ".", "1..2", "1.x", "1.4294967296"} {
		if _, ok := parseOID(bad); ok {
			t.Fatalf("%q accettato", bad)
		}
	}
	// Ogni OID usato è valido e nessuno sta sotto il testo libero scritto
	// dagli amministratori (sysContact, sysLocation, ifAlias, descrizioni LLDP).
	used := []string{oidSysDescr, oidSysObjectID, oidSysUpTime, oidSysName, oidIfDescr, oidIfType, oidIfName,
		oidIPAdEntIfIndex, oidIPAdEntNetMask, oidIPNetToMediaPhysAddress, oidDot1dBasePortIfIndex, oidDot1dTpFdbPort,
		oidDot1qTpFdbPort, oidDot1qVlanStaticName, oidVtpVlanState, oidVtpVlanName, oidLldpLocChassisIDSubtype,
		oidLldpLocChassisID, oidLldpLocPortIDSubtype, oidLldpLocPortID, oidLldpRemChassisIDSubtype,
		oidLldpRemChassisID, oidLldpRemPortIDSubtype, oidLldpRemPortID, oidLldpRemSysName,
		oidLldpRemSysCapEnabled, oidLldpRemManAddrIfSubtype}
	for _, o := range used {
		if _, ok := parseOID(o); !ok {
			t.Fatalf("OID: %s", o)
		}
	}
	if o := forbiddenIn(used); o != "" {
		t.Fatalf("OID vietato tra quelli usati: %s", o)
	}
}

func TestPrivateIPv4(t *testing.T) {
	for ip, want := range map[string]bool{
		"10.0.0.1": true, "10.255.255.254": true, "172.16.0.1": true, "172.31.255.1": true, "192.168.0.1": true,
		"172.15.0.1": false, "172.32.0.1": false, "192.169.0.1": false, "11.0.0.1": false, "127.0.0.1": false, "fd00::1": false,
	} {
		if privateIPv4(netip.MustParseAddr(ip)) != want {
			t.Fatalf("%s", ip)
		}
	}
}

func TestCheckTargetExported(t *testing.T) {
	if err := CheckTarget("192.168.1.2"); err != nil {
		t.Fatalf("indirizzo privato rifiutato: %v", err)
	}
	for _, bad := range []string{"8.8.8.8", "", "10.0.0.0/24", "router.local", "192.168.1.255"} {
		if err := CheckTarget(bad); err == nil {
			t.Errorf("%q accettato", bad)
		}
	}
}

func TestSerialNamesDropped(t *testing.T) {
	// I firewall e gli switch che usano il numero di serie come nome
	// predefinito non lo portano nei risultati.
	for _, c := range []struct{ in, want string }{
		{"FGT60F1234567890", ""},
		{"S248DF3X17000123", ""},
		{"SW-CORE(FOC1234X5YZ)", "SW-CORE"},
		{"FW-CLINICA", "FW-CLINICA"},
	} {
		if got := l2disc.StripSerials(c.in); got != c.want {
			t.Errorf("%q: %q, atteso %q", c.in, got, c.want)
		}
	}
}
