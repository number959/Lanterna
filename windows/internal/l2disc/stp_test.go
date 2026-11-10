package l2disc

import (
	"reflect"
	"testing"
)

var macCIST = []byte{0x00, 0x1b, 0x54, 0xaa, 0xbb, 0x01}

// mstBPDU è una BPDU MSTP senza istanze MSTI: dopo i 36 byte della RST
// seguono lunghezza della versione 3, identificativo della configurazione
// MST (51 byte), costo interno, identificativo del bridge CIST (offset 93)
// e salti rimanenti.
func mstBPDU() []byte {
	name := make([]byte, 32)
	copy(name, "REGIONE")
	return cat(
		bpdu(3, 0x02, 0x3c, bridge(0x8000, macRoot...), 20000, bridge(0x8000, macRoot...), 0x8003),
		u16(64), []byte{0}, name, u16(1), make([]byte, 16), u32(0),
		bridge(0x8000, macCIST...), []byte{20},
	)
}

func onlySTP(t *testing.T, f []byte) STPInfo {
	t.Helper()
	d := Summarize([][]byte{f})
	if d.Counts.Stp != 1 || len(d.Stp) != 1 {
		t.Fatalf("attesa una BPDU: %+v", d)
	}
	return d.Stp[0]
}

func TestSTPConfigBPDU(t *testing.T) {
	// Trama 802.3 riempita fino a 60 byte: il riempimento non va letto.
	s := onlySTP(t, sampleFrames()[3])
	want := STPInfo{
		Format: "ieee", Protocol: "stp",
		RootPriority: 32768, RootSysIDExt: 1, RootMac: "00:11:22:33:44:55", RootPathCost: 19,
		BridgePriority: 32768, BridgeSysIDExt: 1, BridgeMac: "00:1b:54:aa:bb:00",
		PortPriority: 128, PortNumber: 5,
		MessageAge: 1, MaxAge: 20, HelloTime: 2, ForwardDelay: 15,
		Frames: 1,
	}
	if !reflect.DeepEqual(s, want) {
		t.Fatalf("\nottenuto %+v\natteso   %+v", s, want)
	}
}

func TestRSTPRoleAndTopologyChange(t *testing.T) {
	// Flag 0x3d: TC, ruolo "designated" (3), learning, forwarding.
	s := onlySTP(t, sampleFrames()[5])
	if s.Protocol != "rstp" || s.PortRole != "designated" || !s.TopologyChange || s.RootPriority != 4096 || s.PortNumber != 1 {
		t.Fatalf("%+v", s)
	}
	for flags, role := range map[byte]string{0x00: "unknown", 0x04: "alternate-backup", 0x08: "root"} {
		s = onlySTP(t, stpFrame(bpdu(2, 0x02, flags, bridge(0x8000, macRoot...), 4, bridge(0x8000, macBridge...), 0x8001)))
		if s.PortRole != role || s.TopologyChange {
			t.Errorf("flag %#02x: %+v", flags, s)
		}
	}
}

func TestMSTPUsesCISTBridge(t *testing.T) {
	s := onlySTP(t, sampleFrames()[6])
	if s.Protocol != "mstp" || s.BridgeMac != "00:1b:54:aa:bb:01" || s.RootMac != "00:11:22:33:44:55" || s.RootPathCost != 20000 || s.PortRole != "designated" {
		t.Fatalf("%+v", s)
	}
	// MSTP troncata prima del bridge CIST: resta il campo standard.
	s = onlySTP(t, stpFrame(mstBPDU()[:60]))
	if s.Protocol != "mstp" || s.BridgeMac != "00:11:22:33:44:55" {
		t.Fatalf("%+v", s)
	}
}

func TestPVSTPlus(t *testing.T) {
	cfg := bpdu(0, 0x00, 0x00, bridge(0x8000|30, macRoot...), 0, bridge(0x8000|30, macRoot...), 0x8002)
	rst := bpdu(2, 0x02, 0x3c, bridge(0x6000|40, macRoot...), 4, bridge(0x8000|40, macBridge...), 0x8002)
	cases := []struct {
		frame []byte
		proto string
		vlan  int
	}{
		{sampleFrames()[4], "stp", 20},                   // configurazione con riempimento: TLV a 36
		{pvstFrame(cfg, 30), "stp", 30},                  // configurazione senza riempimento: TLV a 35
		{pvstFrame(rst, 40), "rstp", 40},                 // Rapid PVST+
		{ieee8023(dstPVST, snap(0x010b, cfg)), "stp", 0}, // senza TLV
		{pvstFrame(cat(cfg, []byte{0}), 4095), "stp", 0}, // VLAN non valida
	}
	for i, c := range cases {
		s := onlySTP(t, c.frame)
		if s.Format != "pvst" || s.Protocol != c.proto || s.Vlan != c.vlan {
			t.Errorf("caso %d: %+v", i, s)
		}
	}
	if s := onlySTP(t, pvstFrame(rst, 40)); s.RootSysIDExt != 40 || s.RootPriority != 0x6000 || s.BridgeSysIDExt != 40 {
		t.Fatalf("estensione dell'ID di sistema: %+v", s)
	}
}

func TestSTPWithoutInformation(t *testing.T) {
	cases := [][]byte{
		stpFrame([]byte{0x00, 0x00, 0x00, 0x80}), // TCN
		stpFrame([]byte{0x00, 0x01, 0x00, 0x00}), // identificativo di protocollo errato
		stpFrame(bpdu(0, 0x00, 0x00, bridge(0x8000, macRoot...), 0, bridge(0x8000, macRoot...), 0x8001)[:30]),
		stpFrame([]byte{0x00}),
	}
	for i, f := range cases {
		d := Summarize([][]byte{f})
		if d.Counts.Stp != 1 || len(d.Stp) != 0 || d.Read != ReadOK {
			t.Errorf("caso %d: %+v", i, d)
		}
	}
	s := onlySTP(t, stpFrame(bpdu(7, 0x02, 0x00, bridge(0x8000, macRoot...), 0, bridge(0x8000, macRoot...), 0x8001)))
	if s.Protocol != "unknown" {
		t.Fatalf("%+v", s)
	}
}
