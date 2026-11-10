package l2disc

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// Costruttori di trame: ogni test assembla la trama byte per byte, come
// arriverebbe dallo switch, così è facile confrontarla con gli standard.

var (
	dstLLDP   = []byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e}
	dstSTP    = []byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x00}
	dstCisco  = []byte{0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc}
	dstPVST   = []byte{0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcd}
	macSwitch = []byte{0x00, 0x1b, 0x54, 0xaa, 0xbb, 0x0c} // MAC della porta dello switch
)

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func u16(v int) []byte    { return []byte{byte(v >> 8), byte(v)} }
func u32(v uint32) []byte { return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)} }

// ethernet costruisce una trama Ethernet II.
func ethernet(dst []byte, etherType int, payload []byte) []byte {
	return cat(dst, macSwitch, u16(etherType), payload)
}

// ieee8023 costruisce una trama 802.3 con il campo lunghezza, riempita fino
// ai 60 byte minimi come fa la scheda di rete.
func ieee8023(dst, llc []byte) []byte {
	f := cat(dst, macSwitch, u16(len(llc)), llc)
	for len(f) < 60 {
		f = append(f, 0)
	}
	return f
}

// snap antepone l'intestazione LLC/SNAP di Cisco (OUI 00-00-0C).
func snap(pid int, body []byte) []byte {
	return cat([]byte{0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c}, u16(pid), body)
}

// tlv costruisce un TLV LLDP: 7 bit di tipo, 9 di lunghezza.
func tlv(typ int, v ...byte) []byte { return cat(u16(typ<<9|len(v)), v) }

// org costruisce un TLV LLDP specifico di organizzazione.
func org(oui [3]byte, sub byte, d ...byte) []byte { return tlv(127, cat(oui[:], []byte{sub}, d)...) }

func lldpFrame(tlvs ...[]byte) []byte {
	return ethernet(dstLLDP, 0x88cc, cat(append(tlvs, tlv(0))...))
}

// ctlv costruisce un TLV di CDP o DTP: la lunghezza comprende i 4 byte
// d'intestazione.
func ctlv(typ int, v ...byte) []byte { return cat(u16(typ), u16(len(v)+4), v) }

func cdpFrame(tlvs ...[]byte) []byte {
	// Versione 2, TTL 180 s, checksum (non verificata).
	return ieee8023(dstCisco, snap(0x2000, cat([]byte{0x02, 0xb4, 0x12, 0x34}, cat(tlvs...))))
}

func dtpFrame(status, typ byte) []byte {
	return ieee8023(dstCisco, snap(0x2004, cat([]byte{0x01},
		ctlv(1, append([]byte("STARNET"), 0)...), // dominio VTP terminato da zero
		ctlv(2, status),
		ctlv(3, typ),
		ctlv(4, macSwitch...),
	)))
}

// bridge costruisce un identificativo di bridge: priorità+estensione e MAC.
func bridge(prio int, mac ...byte) []byte { return cat(u16(prio), mac) }

var (
	macRoot   = []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	macBridge = []byte{0x00, 0x1b, 0x54, 0xaa, 0xbb, 0x00}
)

// bpdu costruisce una BPDU di configurazione o RST (35 byte, più il byte
// "Version 1 Length" per RSTP/MSTP). Tempi: età 1 s, età massima 20 s,
// hello 2 s, forward delay 15 s, in 1/256 di secondo.
func bpdu(version, typ, flags byte, root []byte, cost uint32, br []byte, port int) []byte {
	b := cat([]byte{0x00, 0x00, version, typ, flags}, root, u32(cost), br, u16(port),
		u16(1*256), u16(20*256), u16(2*256), u16(15*256))
	if typ == 0x02 {
		b = append(b, 0x00)
	}
	return b
}

func stpFrame(b []byte) []byte { return ieee8023(dstSTP, cat([]byte{0x42, 0x42, 0x03}, b)) }

func pvstFrame(b []byte, vlan int) []byte {
	return ieee8023(dstPVST, snap(0x010b, cat(b, u16(0), u16(2), u16(vlan))))
}

// Campioni usati da più test e come seme del fuzzing.
func sampleFrames() [][]byte {
	cfg := bpdu(0, 0x00, 0x00, bridge(0x8001, macRoot...), 19, bridge(0x8001, macBridge...), 0x8005)
	return [][]byte{
		switchLLDP(),
		switchCDP(),
		dtpFrame(0x03, 0xa5),
		stpFrame(cfg),
		pvstFrame(append(cfg, 0x00), 20),
		stpFrame(bpdu(2, 0x02, 0x3d, bridge(0x1000, macRoot...), 4, bridge(0x8000, macBridge...), 0x8001)),
		stpFrame(mstBPDU()),
		ethernet(dstLLDP, 0x8100, cat(u16(20), u16(0x88cc), switchLLDP()[14:])),
	}
}

func TestSummarizeAggregates(t *testing.T) {
	cfg := bpdu(0, 0x00, 0x00, bridge(0x8001, macRoot...), 19, bridge(0x8001, macBridge...), 0x8005)
	ipv4 := ethernet(dstLLDP, 0x0800, make([]byte, 46))
	eapol := ethernet([]byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x03}, 0x888e, []byte{0x01, 0x00, 0x00, 0x05, 0x01, 0x01, 0x00, 0x05, 0x01})
	vtp := ieee8023(dstCisco, snap(0x2003, []byte{0x02, 0x01, 0x00, 0x07}))
	d := Summarize([][]byte{
		switchLLDP(), switchLLDP(), switchCDP(), dtpFrame(0x03, 0xa5),
		stpFrame(cfg), stpFrame(cfg), stpFrame(cfg), pvstFrame(append(cfg, 0x00), 20),
		ipv4, eapol, vtp, nil,
	})
	want := Counts{Lldp: 2, Cdp: 1, Dtp: 1, Stp: 4, Vtp: 1, Eapol: 1, Other: 2}
	if d.Read != ReadOK || d.Frames != 12 || d.Counts != want {
		t.Fatalf("read=%s frames=%d counts=%+v", d.Read, d.Frames, d.Counts)
	}
	if len(d.Lldp) != 1 || d.Lldp[0].Frames != 2 {
		t.Fatalf("lo stesso vicino LLDP va contato una volta: %+v", d.Lldp)
	}
	if len(d.Cdp) != 1 || len(d.Dtp) != 1 {
		t.Fatalf("cdp=%d dtp=%d", len(d.Cdp), len(d.Dtp))
	}
	if len(d.Stp) != 2 || d.Stp[0].Format != "ieee" || d.Stp[0].Frames != 3 || d.Stp[1].Format != "pvst" || d.Stp[1].Vlan != 20 {
		t.Fatalf("stp: %+v", d.Stp)
	}
}

func TestSummarizeEmptyAndUnknown(t *testing.T) {
	if d := Summarize(nil); d.Read != ReadNone || d.Frames != 0 {
		t.Fatalf("%+v", d)
	}
	d := Summarize([][]byte{ethernet(dstLLDP, 0x0800, make([]byte, 46)), {0x01}})
	if d.Read != ReadNone || d.Frames != 2 || d.Counts.Other != 2 {
		t.Fatalf("trame sconosciute: %+v", d)
	}
}

func TestSummarizeKeepsMostCompleteFrame(t *testing.T) {
	full := switchLLDP()
	// Stesso chassis e stessa porta, ma solo i TLV obbligatori.
	short := lldpFrame(
		tlv(1, 4, 0x00, 0x1b, 0x54, 0xaa, 0xbb, 0x00),
		tlv(2, append([]byte{5}, "Gi1/0/12"...)...),
		tlv(3, 0x00, 0x78),
	)
	d := Summarize([][]byte{full, short})
	if len(d.Lldp) != 1 || d.Lldp[0].Frames != 2 || d.Lldp[0].SystemName == "" {
		t.Fatalf("va tenuta la trama più completa: %+v", d.Lldp)
	}
	d = Summarize([][]byte{short, full})
	if d.Lldp[0].SystemName == "" || d.Lldp[0].Frames != 2 {
		t.Fatalf("la trama completa successiva sostituisce quella ridotta: %+v", d.Lldp)
	}
}

func TestSummarizeTopologyChangeIsSticky(t *testing.T) {
	mk := func(flags byte) []byte {
		return stpFrame(bpdu(2, 0x02, flags, bridge(0x8000, macRoot...), 4, bridge(0x8000, macBridge...), 0x8001))
	}
	d := Summarize([][]byte{mk(0x3c), mk(0x3d), mk(0x3c)})
	if len(d.Stp) != 1 || !d.Stp[0].TopologyChange || d.Stp[0].Frames != 3 {
		t.Fatalf("il bit TC visto una volta va conservato: %+v", d.Stp)
	}
}

func TestSummarizeFramesPerAdapter(t *testing.T) {
	d := SummarizeFrames([]Frame{{Adapter: "Ethernet", Data: switchLLDP()}, {Adapter: "Ethernet 2", Data: switchLLDP()}})
	if len(d.Lldp) != 2 || d.Lldp[0].Adapter != "Ethernet" || d.Lldp[1].Adapter != "Ethernet 2" {
		t.Fatalf("un vicino per scheda: %+v", d.Lldp)
	}
}

func TestSummarizeLimitsEntries(t *testing.T) {
	var frames [][]byte
	for i := 0; i < 100; i++ {
		frames = append(frames, lldpFrame(tlv(1, 4, 0x02, 0, 0, 0, 0, byte(i)), tlv(2, 7, 'p'), tlv(3, 0, 120)))
	}
	d := Summarize(frames)
	if len(d.Lldp) != maxEntries || d.Counts.Lldp != 100 {
		t.Fatalf("vicini=%d trame=%d", len(d.Lldp), d.Counts.Lldp)
	}
}

func TestJSONNames(t *testing.T) {
	d := Summarize(sampleFrames())
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, k := range []string{`"read":"ok"`, `"chassisId":`, `"portVlanId":20`, `"voiceVlan":100`, `"vlans":[`, `"deviceId":"SW-CORE"`,
		`"nativeVlan":20`, `"vtpDomain":"STARNET"`, `"adminStatus":"desirable"`, `"rootMac":`, `"rootSysIdExt":1`, `"counts":{`} {
		if !strings.Contains(s, k) {
			t.Errorf("manca %s in %s", k, s)
		}
	}
	for _, secret := range []string{"FOC1234X5YZ", "INV-0042"} {
		if strings.Contains(s, secret) {
			t.Errorf("il numero di serie o l'identificativo del bene %q non deve uscire: %s", secret, s)
		}
	}
}

// Ogni prefisso di una trama valida è una trama troncata: niente panic.
func TestTruncatedFramesDoNotPanic(t *testing.T) {
	for _, f := range sampleFrames() {
		for i := range len(f) {
			_ = parseFrame(f[:i])
		}
	}
}

// checkText verifica che ogni testo esportato sia UTF-8 valido, senza
// caratteri di controllo e entro maxRunes.
func checkText(t *testing.T, v reflect.Value) {
	t.Helper()
	switch v.Kind() {
	case reflect.String:
		s := v.String()
		if !utf8.ValidString(s) || utf8.RuneCountInString(s) > maxRunes {
			t.Fatalf("testo non valido o troppo lungo: %q", s)
		}
		for _, r := range s {
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
				t.Fatalf("carattere di controllo in %q", s)
			}
		}
	case reflect.Struct:
		for i := range v.NumField() {
			checkText(t, v.Field(i))
		}
	case reflect.Slice:
		for i := range v.Len() {
			checkText(t, v.Index(i))
		}
	case reflect.Pointer:
		if !v.IsNil() {
			checkText(t, v.Elem())
		}
	}
}

// FuzzParse: qualunque trama deve dare un riepilogo coerente, mai un
// arresto, con testi puliti e limiti rispettati.
func FuzzParse(f *testing.F) {
	for _, s := range sampleFrames() {
		f.Add(s)
	}
	f.Add([]byte{})
	f.Add(ieee8023(dstSTP, []byte{0x42, 0x42, 0x03, 0x00, 0x00, 0x00, 0x80}))
	f.Fuzz(func(t *testing.T, b []byte) {
		d := Summarize([][]byte{b, b})
		if d.Frames != 2 {
			t.Fatalf("trame contate: %d", d.Frames)
		}
		c := d.Counts
		if c.Lldp+c.Cdp+c.Dtp+c.Stp+c.Vtp+c.Eapol+c.Other != 2 {
			t.Fatalf("conteggi incoerenti: %+v", c)
		}
		if len(d.Lldp)+len(d.Cdp)+len(d.Dtp)+len(d.Stp) > 1 {
			t.Fatalf("due trame uguali devono dare al più un vicino: %+v", d)
		}
		for _, n := range d.Lldp {
			if len(n.Vlans) > maxVlans || len(n.ManagementAddresses) > maxMgmtAddrs || n.Frames != 2 {
				t.Fatalf("limiti LLDP: %+v", n)
			}
		}
		checkText(t, reflect.ValueOf(d))
		if _, err := json.Marshal(d); err != nil {
			t.Fatal(err)
		}
	})
}
