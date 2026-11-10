package l2disc

import (
	"encoding/json"
	"net"
	"reflect"
	"strings"
	"testing"
)

// switchLLDP è la LLDPDU di uno switch d'accesso Cisco con le estensioni
// IEEE 802.1, IEEE 802.3 e LLDP-MED, compreso l'inventario (con numero di
// serie e identificativo del bene, che non devono uscire).
func switchLLDP() []byte {
	return lldpFrame(
		tlv(1, 4, 0x00, 0x1b, 0x54, 0xaa, 0xbb, 0x00), // chassis: MAC
		tlv(2, append([]byte{5}, "Gi1/0/12"...)...),   // porta: nome d'interfaccia
		tlv(3, 0x00, 0x78),                            // TTL 120 s
		tlv(4, []byte("GigabitEthernet1/0/12")...),
		tlv(5, []byte("SW-PIANO1.clinica.local")...),
		tlv(6, []byte("Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E4, RELEASE SOFTWARE (fc2)\r\nTechnical Support: http://www.cisco.com/techsupport\r\nCopyright (c) 1986-2021 by Cisco Systems, Inc.")...),
		tlv(7, 0x00, 0x14, 0x00, 0x04), // supportate: bridge e router; attiva: bridge
		// Gestione: stringa di 5 byte (famiglia IPv4 + indirizzo), numerazione
		// per ifIndex, interfaccia 1, nessun OID.
		tlv(8, 5, 1, 192, 168, 10, 2, 2, 0, 0, 0, 1, 0),
		org(ouiDot1, 1, 0x00, 0x14), // PVID 20
		org(ouiDot1, 2, 0x06, 0x00, 0x1e),
		org(ouiDot1, 3, cat(u16(20), []byte{6}, []byte("UFFICI"))...),
		org(ouiDot1, 3, cat(u16(100), []byte{4}, []byte("VOCE"))...),
		org(ouiDot3, 1, 0x03, 0x6c, 0x01, 0x00, 0x1e), // autonegoziazione attiva, MAU 30
		org(ouiMED, 1, 0x00, 0x0f, 0x04),              // funzioni MED, classe "network connectivity"
		// Voce: U=0 T=1 X=0, VLAN 100, priorità 5, DSCP 46
		// = 010 000001100100 101 101110 = 0x40 0xC9 0x6E.
		org(ouiMED, 2, 0x01, 0x40, 0xc9, 0x6e),
		org(ouiMED, 8, []byte("FOC1234X5YZ")...), // numero di serie
		org(ouiMED, 9, []byte("Cisco Systems, Inc.")...),
		org(ouiMED, 10, []byte("WS-C2960X-48FPD-L")...),
		org(ouiMED, 11, []byte("INV-0042")...),  // identificativo del bene
		org([3]byte{0x00, 0x01, 0x42}, 1, 0x01), // OUI Cisco: ignorato
	)
}

func onlyLLDP(t *testing.T, f []byte) LLDPNeighbor {
	t.Helper()
	d := Summarize([][]byte{f})
	if d.Counts.Lldp != 1 || len(d.Lldp) != 1 {
		t.Fatalf("atteso un vicino LLDP: %+v", d)
	}
	return d.Lldp[0]
}

func TestLLDPAccessSwitch(t *testing.T) {
	n := onlyLLDP(t, switchLLDP())
	want := LLDPNeighbor{
		ChassisID: "00:1b:54:aa:bb:00", ChassisIDType: "mac",
		PortID: "Gi1/0/12", PortIDType: "interface-name",
		TTL:                   120,
		SystemName:            "SW-PIANO1.clinica.local",
		SystemDescription:     "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E4, RELEASE SOFTWARE (fc2)",
		Capabilities:          []string{"bridge"},
		CapabilitiesSupported: []string{"bridge", "router"},
		ManagementAddresses:   []string{"192.168.10.2"},
		PortVlanID:            20,
		ProtocolVlans:         []ProtocolVlan{{ID: 30, Supported: true, Enabled: true}},
		Vlans:                 []Vlan{{ID: 20, Name: "UFFICI"}, {ID: 100, Name: "VOCE"}},
		VoiceVlan:             100,
		Policies:              []MedPolicy{{App: "voice", Tagged: true, Vlan: 100, Priority: 5, Dscp: 46}},
		MedClass:              "network",
		MedCapabilities:       []string{"capabilities", "network-policy", "location", "power-pse"},
		Manufacturer:          "Cisco Systems, Inc.",
		Model:                 "WS-C2960X-48FPD-L",
		Autoneg:               "on",
		MauType:               30,
		Mau:                   "1000BASE-T",
		SpeedMbps:             1000,
		Duplex:                "full",
		Frames:                1,
	}
	if !reflect.DeepEqual(n, want) {
		t.Fatalf("\nottenuto %+v\natteso   %+v", n, want)
	}
}

func TestLLDPNeverExportsSerialNumbers(t *testing.T) {
	b, _ := json.Marshal(onlyLLDP(t, switchLLDP()))
	for _, s := range []string{"FOC1234X5YZ", "INV-0042"} {
		if strings.Contains(string(b), s) {
			t.Fatalf("%q esportato: %s", s, b)
		}
	}
	// FortiSwitch senza nome: il nome di sistema predefinito è il numero di serie.
	n := onlyLLDP(t, lldpFrame(tlv(1, 4, 0x70, 0x4c, 0xa5, 0x01, 0x02, 0x03), tlv(2, append([]byte{5}, "port5"...)...),
		tlv(3, 0, 120), tlv(5, []byte("S248DF3X17000123")...)))
	if n.SystemName != "" || n.ChassisID != "70:4c:a5:01:02:03" {
		t.Fatalf("%+v", n)
	}
	// Seriale come identificativo locale dello chassis.
	n = onlyLLDP(t, lldpFrame(tlv(1, append([]byte{7}, "FGT60E4Q16000000"...)...), tlv(2, 7, 'p', '1'), tlv(3, 0, 120)))
	if n.ChassisID != "" || n.ChassisIDType != "local" {
		t.Fatalf("%+v", n)
	}
}

func TestLLDPIdentifiers(t *testing.T) {
	v6 := net.ParseIP("fe80::1")
	cases := []struct {
		chassis, port []byte
		wantC, wantCT string
		wantP, wantPT string
	}{
		{cat([]byte{5, 1}, []byte{10, 0, 0, 1}), cat([]byte{3}, macSwitch), "10.0.0.1", "network-address", "00:1b:54:aa:bb:0c", "mac"},
		{cat([]byte{5, 2}, v6), cat([]byte{4, 1}, []byte{10, 0, 0, 9}), "fe80::1", "network-address", "10.0.0.9", "network-address"},
		{cat([]byte{7}, []byte("switch-lab\x00")), cat([]byte{6}, []byte{0x00, 0x01, 0xff}), "switch-lab", "local", "00:01:ff", "agent-circuit-id"},
		{cat([]byte{4}, []byte{1, 2, 3}), cat([]byte{1}, []byte("uplink")), "01:02:03", "mac", "", "interface-alias"},
		{cat([]byte{9}, []byte("x")), cat([]byte{2}, []byte("Slot 1")), "x", "subtype-9", "Slot 1", "port-component"},
		{cat([]byte{5, 9}, []byte{1, 2}), []byte{7}, "09:01:02", "network-address", "", "local"},
	}
	for _, c := range cases {
		n := onlyLLDP(t, lldpFrame(tlv(1, c.chassis...), tlv(2, c.port...), tlv(3, 0, 120)))
		if n.ChassisID != c.wantC || n.ChassisIDType != c.wantCT || n.PortID != c.wantP || n.PortIDType != c.wantPT {
			t.Errorf("chassis %x porta %x: %q %q %q %q", c.chassis, c.port, n.ChassisID, n.ChassisIDType, n.PortID, n.PortIDType)
		}
	}
}

func TestLLDPTruncatedKeepsWhatWasRead(t *testing.T) {
	f := ethernet(dstLLDP, 0x88cc, cat(
		tlv(1, 4, 0x00, 0x1b, 0x54, 0xaa, 0xbb, 0x00),
		tlv(2, 5, 'G', 'i', '1'),
		[]byte{0x0a, 0x64, 'S', 'W'}, // nome di sistema che dichiara 100 byte e ne ha 2
	))
	n := onlyLLDP(t, f)
	if n.ChassisID != "00:1b:54:aa:bb:00" || n.PortID != "Gi1" || n.SystemName != "" {
		t.Fatalf("%+v", n)
	}
	// Senza identificativi la trama si conta ma non dà un vicino.
	d := Summarize([][]byte{lldpFrame(tlv(3, 0, 120))})
	if d.Counts.Lldp != 1 || len(d.Lldp) != 0 || d.Read != ReadOK {
		t.Fatalf("%+v", d)
	}
}

func TestLLDPWithVLANTag(t *testing.T) {
	plain := onlyLLDP(t, switchLLDP())
	tagged := onlyLLDP(t, sampleFrames()[7])
	if !reflect.DeepEqual(plain, tagged) {
		t.Fatalf("l'etichetta 802.1Q non deve cambiare la decodifica:\n%+v\n%+v", plain, tagged)
	}
}

func TestLLDPMedPolicies(t *testing.T) {
	n := onlyLLDP(t, lldpFrame(
		tlv(1, 4, 0x00, 0x04, 0xf2, 0x00, 0x00, 0x01), tlv(2, 3, 0x00, 0x04, 0xf2, 0x00, 0x00, 0x01), tlv(3, 0, 120),
		org(ouiMED, 1, 0x00, 0x33, 0x03), // telefono: classe III
		// Voce senza etichetta (T=0, VLAN 0, priorità 6, DSCP 46): 0x00 0x01 0xae.
		org(ouiMED, 2, 0x01, 0x00, 0x01, 0xae),
		// Segnalazione voce con politica sconosciuta (U=1): 0x80 0x00 0x00.
		org(ouiMED, 2, 0x02, 0x80, 0x00, 0x00),
		// Applicazione 12, non definita da TIA-1057: VLAN 30 etichettata.
		org(ouiMED, 2, 0x0c, 0x40, 0x3c, 0x00),
	))
	want := []MedPolicy{
		{App: "voice", Priority: 6, Dscp: 46},
		{App: "voice-signaling", Unknown: true},
		{App: "app-12", Tagged: true, Vlan: 30},
	}
	if n.VoiceVlan != 0 || n.MedClass != "endpoint-3" || !reflect.DeepEqual(n.Policies, want) {
		t.Fatalf("%+v", n)
	}
	if !reflect.DeepEqual(n.MedCapabilities, []string{"capabilities", "network-policy", "power-pd", "inventory"}) {
		t.Fatalf("%v", n.MedCapabilities)
	}
}

func TestLLDPMacPhy(t *testing.T) {
	cases := []struct {
		an     byte
		mau    int
		auto   string
		name   string
		mbps   int
		duplex string
	}{
		{0x03, 16, "on", "100BASE-TX", 100, "full"},
		{0x01, 15, "off", "100BASE-TX", 100, "half"},
		{0x00, 54, "unsupported", "10GBASE-T", 10000, "full"},
		{0x03, 103, "on", "2.5GBASE-T", 2500, "full"},
		{0x03, 999, "on", "", 0, ""},
	}
	for _, c := range cases {
		n := onlyLLDP(t, lldpFrame(tlv(1, 4, 1, 2, 3, 4, 5, 6), tlv(2, 7, 'p'), tlv(3, 0, 120),
			org(ouiDot3, 1, cat([]byte{c.an, 0x00, 0x00}, u16(c.mau))...)))
		if n.Autoneg != c.auto || n.MauType != c.mau || n.Mau != c.name || n.SpeedMbps != c.mbps || n.Duplex != c.duplex {
			t.Errorf("MAU %d: %+v", c.mau, n)
		}
	}
}

func TestLLDPManagementAddresses(t *testing.T) {
	v6 := net.ParseIP("2001:db8::10")
	n := onlyLLDP(t, lldpFrame(tlv(1, 4, 1, 2, 3, 4, 5, 6), tlv(2, 7, 'p'), tlv(3, 0, 120),
		tlv(8, cat([]byte{17, 2}, v6, []byte{1, 0, 0, 0, 0, 0})...),
		tlv(8, 7, 6, 0x00, 0x1b, 0x54, 0xaa, 0xbb, 0x00, 1, 0, 0, 0, 0, 0), // famiglia 802 (MAC)
		tlv(8, 5, 1, 192, 168, 10, 2, 1, 0, 0, 0, 0, 0),
		tlv(8, 5, 1, 192, 168, 10, 2, 1, 0, 0, 0, 0, 0), // doppione
		tlv(8, 40, 1, 1, 2), // lunghezza oltre il TLV
		tlv(8, 3, 1, 10, 0), // IPv4 di 2 byte
	))
	want := []string{"2001:db8::10", "00:1b:54:aa:bb:00", "192.168.10.2"}
	if !reflect.DeepEqual(n.ManagementAddresses, want) {
		t.Fatalf("%v", n.ManagementAddresses)
	}
}

func TestLLDPVlanNameLength(t *testing.T) {
	n := onlyLLDP(t, lldpFrame(tlv(1, 4, 1, 2, 3, 4, 5, 6), tlv(2, 7, 'p'), tlv(3, 0, 120),
		org(ouiDot1, 3, cat(u16(10), []byte{4}, []byte("DATIxyz"))...), // nome più corto del TLV
		org(ouiDot1, 3, cat(u16(11), []byte{20}, []byte("OSPITI"))...), // nome che dichiara più byte di quelli presenti
		org(ouiDot1, 3, cat(u16(12), []byte{3}, []byte("A\x00\x07"))...),
	))
	want := []Vlan{{ID: 10, Name: "DATI"}, {ID: 11, Name: "OSPITI"}, {ID: 12, Name: "A"}}
	if !reflect.DeepEqual(n.Vlans, want) {
		t.Fatalf("%+v", n.Vlans)
	}
}
