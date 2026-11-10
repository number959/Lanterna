package l2disc

import (
	"encoding/json"
	"net"
	"reflect"
	"strings"
	"testing"
)

// switchCDP è il pacchetto CDP di un Catalyst con il numero di serie nel
// Device ID, come lo annunciano i Nexus, e il TLV del numero di serie degli
// access point: nessuno dei due deve uscire.
func switchCDP() []byte {
	return cdpFrame(
		ctlv(0x0001, []byte("SW-CORE(FOC1234X5YZ)")...),
		ctlv(0x0002, cat(u32(2),
			[]byte{1, 1, 0xcc}, u16(4), []byte{10, 1, 1, 2}, // NLPID, IPv4
			[]byte{2, 8}, cdpIPv6Proto, u16(16), net.ParseIP("2001:db8::2"), // 802.2, IPv6
		)...),
		ctlv(0x0003, []byte("GigabitEthernet1/0/5")...),
		ctlv(0x0004, 0x00, 0x00, 0x00, 0x29), // router, switch, IGMP
		ctlv(0x0005, []byte("Cisco IOS Software, C3750E Software (C3750E-UNIVERSALK9-M), Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)\nTechnical Support: http://www.cisco.com/techsupport\nCopyright (c) 1986-2017 by Cisco Systems, Inc.")...),
		ctlv(0x0006, []byte("cisco WS-C3750X-48P")...),
		ctlv(0x0009, []byte("STARNET")...),
		ctlv(0x000a, 0x00, 0x14),       // VLAN nativa 20
		ctlv(0x000b, 0x01),             // full duplex
		ctlv(0x000e, 0x01, 0x00, 0x64), // VLAN della voce 100
		ctlv(0x0010, 0x00, 0x00),       // consumo: ignorato
		ctlv(0x0014, []byte("SW-CORE")...),
		ctlv(0x0016, cat(u32(1), []byte{1, 1, 0xcc}, u16(4), []byte{10, 1, 1, 2})...),
		ctlv(0x1001, []byte("FOC1234X5YZ")...), // numero di serie (access point)
	)
}

func onlyCDP(t *testing.T, f []byte) CDPNeighbor {
	t.Helper()
	d := Summarize([][]byte{f})
	if d.Counts.Cdp != 1 || len(d.Cdp) != 1 {
		t.Fatalf("atteso un vicino CDP: %+v", d)
	}
	return d.Cdp[0]
}

func TestCDPSwitch(t *testing.T) {
	n := onlyCDP(t, switchCDP())
	want := CDPNeighbor{
		Version: 2, TTL: 180,
		DeviceID:            "SW-CORE",
		PortID:              "GigabitEthernet1/0/5",
		Platform:            "cisco WS-C3750X-48P",
		Software:            "Cisco IOS Software, C3750E Software (C3750E-UNIVERSALK9-M), Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)",
		Capabilities:        []string{"router", "switch", "igmp"},
		Addresses:           []string{"10.1.1.2", "2001:db8::2"},
		ManagementAddresses: []string{"10.1.1.2"},
		NativeVlan:          20,
		VoiceVlan:           100,
		VtpDomain:           "STARNET",
		Duplex:              "full",
		SystemName:          "SW-CORE",
		Frames:              1,
	}
	if !reflect.DeepEqual(n, want) {
		t.Fatalf("\nottenuto %+v\natteso   %+v", n, want)
	}
	b, _ := json.Marshal(n)
	if strings.Contains(string(b), "FOC1234X5YZ") {
		t.Fatalf("numero di serie esportato: %s", b)
	}
}

func TestCDPPhone(t *testing.T) {
	n := onlyCDP(t, cdpFrame(
		ctlv(0x0001, []byte("SEP001122334455")...), // nome ricavato dal MAC: resta
		ctlv(0x0003, []byte("Port 1")...),
		ctlv(0x0004, 0x00, 0x00, 0x01, 0x90), // host (0x10), telefono (0x80), gestito da remoto (0x100)
		ctlv(0x0006, []byte("Cisco IP Phone 8845")...),
		ctlv(0x000b, 0x00),
	))
	if n.DeviceID != "SEP001122334455" || n.Duplex != "half" || !reflect.DeepEqual(n.Capabilities, []string{"host", "phone", "remote-managed"}) {
		t.Fatalf("%+v", n)
	}
}

func TestCDPMalformed(t *testing.T) {
	// Un TLV che dichiara meno dei 4 byte d'intestazione chiude la lettura.
	n := onlyCDP(t, cdpFrame(ctlv(0x0001, []byte("SW")...), []byte{0x00, 0x06, 0x00, 0x02}, ctlv(0x0003, []byte("Gi0/1")...)))
	if n.DeviceID != "SW" || n.PortID != "" {
		t.Fatalf("%+v", n)
	}
	// Elenco di indirizzi che dichiara 4 miliardi di voci e ne ha una e mezza.
	n = onlyCDP(t, cdpFrame(ctlv(0x0001, []byte("SW")...), ctlv(0x0002, cat(u32(0xffffffff), []byte{1, 1, 0xcc}, u16(4), []byte{10, 0, 0, 1}, []byte{2, 8, 0xaa})...)))
	if !reflect.DeepEqual(n.Addresses, []string{"10.0.0.1"}) {
		t.Fatalf("%+v", n.Addresses)
	}
	// VLAN fuori intervallo e VoIP VLAN Reply di 2 byte: ignorate.
	n = onlyCDP(t, cdpFrame(ctlv(0x0001, []byte("SW")...), ctlv(0x000a, 0x0f, 0xff), ctlv(0x000e, 0x00, 0x64)))
	if n.NativeVlan != 0 || n.VoiceVlan != 0 {
		t.Fatalf("%+v", n)
	}
	// Solo l'intestazione: si conta, ma non c'è un vicino.
	d := Summarize([][]byte{ieee8023(dstCisco, snap(0x2000, []byte{0x02, 0xb4, 0x00, 0x00}))})
	if d.Counts.Cdp != 1 || len(d.Cdp) != 0 {
		t.Fatalf("%+v", d)
	}
}

func TestDTPStatusAndType(t *testing.T) {
	cases := []struct {
		status, typ                    byte
		oper, admin, operType, adminTy string
	}{
		{0x03, 0xa5, "access", "desirable", "802.1q", "802.1q"},
		{0x04, 0xa5, "access", "auto", "802.1q", "802.1q"},
		{0x81, 0x40, "trunk", "on", "isl", "negotiated"},
		{0x84, 0x45, "trunk", "auto", "isl", "802.1q"},
		{0x02, 0x00, "access", "off", "unknown", "negotiated"},
		{0x07, 0xff, "access", "unknown", "unknown", "unknown"},
	}
	for _, c := range cases {
		d := Summarize([][]byte{dtpFrame(c.status, c.typ)})
		if d.Counts.Dtp != 1 || len(d.Dtp) != 1 {
			t.Fatalf("%+v", d)
		}
		x := d.Dtp[0]
		if x.OperStatus != c.oper || x.AdminStatus != c.admin || x.OperType != c.operType || x.AdminType != c.adminTy {
			t.Errorf("stato %#02x tipo %#02x: %+v", c.status, c.typ, x)
		}
		if x.Version != 1 || x.Domain != "STARNET" || x.Neighbor != "00:1b:54:aa:bb:0c" || x.Frames != 1 {
			t.Errorf("%+v", x)
		}
	}
	x := Summarize([][]byte{dtpFrame(0x03, 0xa5)}).Dtp[0]
	if x.RawStatus != "0x03" || x.RawType != "0xa5" {
		t.Fatalf("%+v", x)
	}
}

func TestDTPWithoutSenderUsesSourceMAC(t *testing.T) {
	d := Summarize([][]byte{
		ieee8023(dstCisco, snap(0x2004, cat([]byte{0x01}, ctlv(2, 0x04)))),
		ieee8023(dstCisco, snap(0x2004, cat([]byte{0x01}, ctlv(2, 0x04)))),
	})
	if len(d.Dtp) != 1 || d.Dtp[0].Neighbor != "00:1b:54:aa:bb:0c" || d.Dtp[0].Frames != 2 || d.Dtp[0].Domain != "" {
		t.Fatalf("%+v", d.Dtp)
	}
}
