package wlan

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

// Costruzione byte per byte delle strutture di wlanapi.h (offset verificati
// contro gli header ufficiali, vedi docs/VERIFICHE.md).

func put32(b []byte, off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }

func putSSID(b []byte, s string) {
	put32(b, 0, uint32(len(s)))
	copy(b[4:36], s)
}

type entry struct {
	ssid   string
	bssid  [6]byte
	rssi   int32
	cap    uint16
	kHz    uint32
	rates  []uint16
	ies    []byte
	ieOffs int // 0 = calcolato
}

func bssList(entries ...entry) []byte {
	head := 8 + len(entries)*BssEntrySize
	buf := make([]byte, head)
	for i, e := range entries {
		v := buf[8+i*BssEntrySize : 8+(i+1)*BssEntrySize]
		putSSID(v, e.ssid)
		copy(v[40:46], e.bssid[:])
		put32(v, 48, 1)              // dot11BssType: infrastruttura
		put32(v, 56, uint32(e.rssi)) // lRssi (con segno)
		put32(v, 60, 80)             // uLinkQuality
		binary.LittleEndian.PutUint16(v[88:], e.cap)
		put32(v, 92, e.kHz)
		put32(v, 96, uint32(2*len(e.rates)))
		for k, r := range e.rates {
			binary.LittleEndian.PutUint16(v[100+2*k:], r)
		}
		// Gli IE stanno dopo tutte le voci; l'offset è relativo all'inizio della voce.
		off := len(buf) - (8 + i*BssEntrySize)
		if e.ieOffs != 0 {
			off = e.ieOffs
		}
		put32(v, 352, uint32(off))
		put32(v, 356, uint32(len(e.ies)))
		buf = append(buf, e.ies...)
	}
	put32(buf, 0, uint32(len(buf))) // dwTotalSize
	put32(buf, 4, uint32(len(entries)))
	return buf
}

var rsnPSK = []byte{48, 20, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 2, 0x80, 0}
var htOp40 = []byte{61, 22, 5, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
var bssLoad = []byte{11, 5, 9, 0, 158, 0, 0}

func TestParseBssList(t *testing.T) {
	buf := bssList(
		entry{ssid: "Casa-Rossi", bssid: [6]byte{0xa4, 0x2b, 0xb0, 0x11, 0x22, 0x33}, rssi: -71, cap: 0x0411, kHz: 2432000,
			rates: []uint16{0x8002, 0x8004, 0x000c, 0x006c}, ies: append(append(append([]byte{}, rsnPSK...), htOp40...), bssLoad...)},
		entry{ssid: "Bar", bssid: [6]byte{1, 2, 3, 4, 5, 6}, rssi: -88, cap: 0x0401, kHz: 2412000, rates: []uint16{0x8002, 0x8016}},
		entry{ssid: "Rotto", bssid: [6]byte{9, 9, 9, 9, 9, 9}, rssi: -50, cap: 0x0011, kHz: 5180000, ies: rsnPSK, ieOffs: 1 << 20},
	)
	nets, err := ParseBssList(buf)
	if err != nil || len(nets) != 3 {
		t.Fatalf("%v %d", err, len(nets))
	}
	a := nets[0]
	if a.SSID != "Casa-Rossi" || a.BSSID != "a4:2b:b0:11:22:33" || a.RssiDbm != -71 || a.FreqMhz != 2432 || a.Channel != 5 || a.Band != "2.4" {
		t.Fatalf("voce 1: %+v", a)
	}
	if a.WidthMhz != 40 || a.CenterChannel != 7 || a.Phy != "802.11n" || a.Security.Protocol != "wpa2" || a.Security.PMF != "capable" {
		t.Fatalf("voce 1 (IE): %+v %+v", a, a.Security)
	}
	if a.BssLoad == nil || a.BssLoad.Stations != 9 || a.BssLoad.UtilizationPct != 62 {
		t.Fatalf("BSS Load: %+v", a.BssLoad)
	}
	// Elementi presenti ma nessuna funzione di roaming annunciata: il campo c'è, tutto falso.
	if a.Roaming == nil || a.Roaming.K || a.Roaming.V || a.Roaming.R {
		t.Fatalf("roaming voce 1: %+v", a.Roaming)
	}
	b := nets[1]
	// Senza elementi del beacon non si può sapere: il campo manca.
	if b.Roaming != nil {
		t.Fatalf("roaming voce 2 senza IE: %+v", b.Roaming)
	}
	// Senza IE: rete aperta a 20 MHz, standard dedotto dalle velocità (max 11 Mbit/s = 802.11b).
	if b.Security.Protocol != "open" || b.Security.PMF != "" || b.WidthMhz != 20 || b.Phy != "802.11b" || b.RssiDbm != -88 {
		t.Fatalf("voce 2: %+v %+v", b, b.Security)
	}
	// Offset IE fuori dal buffer: gli IE si ignorano, la voce resta (Privacy → WEP).
	c := nets[2]
	if c.Band != "5" || c.Channel != 36 || c.Security.Protocol != "wep" || c.Phy != "802.11a" {
		t.Fatalf("voce 3: %+v %+v", c, c.Security)
	}
}

func TestParseBssListRoaming(t *testing.T) {
	ies := append(append(append([]byte{}, rsnPSK...),
		54, 3, 0x12, 0x34, 0x00), // Mobility Domain 1234
		70, 5, 0x02, 0, 0, 0, 0, // Neighbor Report
		127, 3, 0, 0, 0x08, // BSS Transition
	)
	nets, err := ParseBssList(bssList(entry{ssid: "Reparto", bssid: [6]byte{0, 0x11, 0x22, 0x33, 0x44, 0x55}, rssi: -60, cap: 0x0011, kHz: 5500000, ies: ies}))
	if err != nil || len(nets) != 1 {
		t.Fatalf("%v %d", err, len(nets))
	}
	if r := nets[0].Roaming; r == nil || !r.K || !r.V || !r.R || r.MDID != "1234" || r.FTOverDS {
		t.Fatalf("roaming: %+v", r)
	}
}

func TestParseBssListTruncated(t *testing.T) {
	buf := bssList(entry{ssid: "A", kHz: 2412000}, entry{ssid: "B", kHz: 2437000})
	put32(buf, 4, 5) // dichiara più voci di quelle presenti
	nets, err := ParseBssList(buf)
	if err != nil || len(nets) != 2 {
		t.Fatalf("%v %d", err, len(nets))
	}
	if _, err := ParseBssList([]byte{1, 2}); err == nil {
		t.Fatal("buffer troppo corto accettato")
	}
}

func TestParseConnection(t *testing.T) {
	b := make([]byte, ConnectionAttrsSize)
	put32(b, 0, StateConnected)
	putSSID(b[520:], "Casa-Rossi")
	copy(b[560:566], []byte{0xa4, 0x2b, 0xb0, 0x11, 0x22, 0x33})
	put32(b, 568, 10)     // dot11_phy_type_he
	put32(b, 576, 58)     // qualità
	put32(b, 580, 144400) // kbit/s
	put32(b, 584, 117000)
	put32(b, 596, 7) // DOT11_AUTH_ALGO_RSNA_PSK
	put32(b, 600, 4) // DOT11_CIPHER_ALGO_CCMP
	c, err := ParseConnection(b)
	if err != nil {
		t.Fatal(err)
	}
	if c.SSID != "Casa-Rossi" || c.BSSID != "a4:2b:b0:11:22:33" || PhyNames[c.PhyType] != "802.11ax" || c.Quality != 58 ||
		c.RxKbps != 144400 || AuthNames[c.AuthAlgo] != "WPA2-Personal" || CipherNames[c.CipherAlgo] != "CCMP" || ProtocolFromAuth(c.AuthAlgo) != "wpa2" {
		t.Fatalf("%+v", c)
	}
	if _, err := ParseConnection(b[:600]); err == nil {
		t.Fatal("struttura troncata accettata")
	}
}

func TestParseInterfaceList(t *testing.T) {
	b := make([]byte, 8+2*InterfaceInfoSize)
	put32(b, 0, 2)
	for i, d := range []string{"Intel(R) Wi-Fi 6 AX201 160MHz", "Scheda è USB"} {
		e := b[8+i*InterfaceInfoSize:]
		e[0] = byte(0x10 + i)
		for k, u := range utf16.Encode([]rune(d)) {
			binary.LittleEndian.PutUint16(e[16+2*k:], u)
		}
		put32(e, 528, uint32(i)+1) // 1 = connessa, 2 = ad hoc
	}
	list, err := ParseInterfaceList(b)
	if err != nil || len(list) != 2 {
		t.Fatalf("%v %v", err, list)
	}
	if list[0].Description != "Intel(R) Wi-Fi 6 AX201 160MHz" || list[0].State != StateConnected || list[0].GUID[0] != 0x10 {
		t.Fatalf("%+v", list[0])
	}
	if list[1].Description != "Scheda è USB" {
		t.Fatalf("UTF-16: %q", list[1].Description)
	}
	put32(b, 0, 3)
	if _, err := ParseInterfaceList(b); err == nil {
		t.Fatal("conteggio incoerente accettato")
	}
}

func TestChannels(t *testing.T) {
	for _, c := range []struct {
		f, ch int
		band  string
	}{{2412, 1, "2.4"}, {2484, 14, "2.4"}, {5180, 36, "5"}, {5825, 165, "5"}, {5955, 1, "6"}, {7115, 233, "6"}} {
		if ChannelOf(c.f) != c.ch || BandOf(c.f) != c.band || ChannelToFreq(c.ch, c.band) != c.f {
			t.Errorf("%+v", c)
		}
	}
}
