package ie

import (
	"reflect"
	"testing"
)

// Costruttori di elementi: ogni test assembla il buffer esattamente come
// apparirebbe in un beacon, così è facile confrontarlo con lo standard.

func el(id byte, data ...byte) []byte { return append([]byte{id, byte(len(data))}, data...) }

func ext(extID byte, data ...byte) []byte {
	return append([]byte{255, byte(len(data) + 1), extID}, data...)
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// RSN WPA2-Personal: versione 1, gruppo CCMP, 1 pairwise CCMP, 1 AKM PSK, capacità.
func rsnWPA2(caps uint16) []byte {
	return el(48,
		0x01, 0x00, // versione 1
		0x00, 0x0f, 0xac, 0x04, // gruppo: CCMP
		0x01, 0x00, // 1 suite pairwise
		0x00, 0x0f, 0xac, 0x04, // CCMP
		0x01, 0x00, // 1 AKM
		0x00, 0x0f, 0xac, 0x02, // PSK
		byte(caps), byte(caps>>8), // RSN capabilities
	)
}

func TestSplitTruncated(t *testing.T) {
	buf := cat(el(0, 'a', 'b'), []byte{3, 5, 1}) // il secondo dichiara 5 byte ma ne ha 1
	elems, err := Split(buf)
	if err == nil {
		t.Fatal("atteso errore per elemento troncato")
	}
	if len(elems) != 1 || string(elems[0].Data) != "ab" {
		t.Fatalf("gli elementi validi prima del troncamento vanno conservati: %+v", elems)
	}
}

func TestOpenNetwork24(t *testing.T) {
	buf := cat(
		el(0, []byte("Bar Centrale")...),
		el(1, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24), // rate supportati
		el(3, 6), // DS Parameter Set: canale 6
	)
	info, err := Parse(buf, 0x0401, 2437) // ESS + short slot, nessun bit Privacy
	if err != nil {
		t.Fatal(err)
	}
	if info.SSID != "Bar Centrale" || info.DSChannel != 6 {
		t.Fatalf("SSID/canale: %+v", info)
	}
	if info.Security.Protocol != "open" || info.WidthMhz != 20 {
		t.Fatalf("rete aperta a 20 MHz attesa: %+v", info)
	}
	if got := info.Phy(2437, 54); got != "802.11g" {
		t.Fatalf("phy = %s", got)
	}
}

func TestWEPFromPrivacyBit(t *testing.T) {
	info, _ := Parse(el(0, 'x'), 0x0011, 2412) // ESS + Privacy, nessun RSN/WPA
	if info.Security.Protocol != "wep" {
		t.Fatalf("protocollo = %s", info.Security.Protocol)
	}
}

func TestWPA2PersonalPMFCapable(t *testing.T) {
	info, _ := Parse(rsnWPA2(rsnCapMFPC), 0x0011, 5180)
	s := info.Security
	if s.Protocol != "wpa2" || s.PMF != "capable" || s.Group != "CCMP" {
		t.Fatalf("%+v", s)
	}
	if !reflect.DeepEqual(s.AKM, []string{"PSK"}) || !reflect.DeepEqual(s.Pairwise, []string{"CCMP"}) {
		t.Fatalf("%+v", s)
	}
}

func TestWPA3TransitionAndRequiredPMF(t *testing.T) {
	buf := el(48,
		0x01, 0x00,
		0x00, 0x0f, 0xac, 0x04,
		0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
		0x02, 0x00, // 2 AKM
		0x00, 0x0f, 0xac, 0x02, // PSK
		0x00, 0x0f, 0xac, 0x08, // SAE
		0xc0, 0x00, // MFPC + MFPR
	)
	info, _ := Parse(buf, 0x0011, 5180)
	if info.Security.Protocol != "wpa2/wpa3" || info.Security.PMF != "required" {
		t.Fatalf("%+v", info.Security)
	}
	saeOnly := el(48, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x08, 0xc0, 0x00)
	info, _ = Parse(saeOnly, 0x0011, 5955)
	if info.Security.Protocol != "wpa3" {
		t.Fatalf("%+v", info.Security)
	}
}

func TestMixedWPAWPA2ReportsTKIP(t *testing.T) {
	wpa := el(221,
		0x00, 0x50, 0xf2, 0x01, // OUI Microsoft, tipo 1 = WPA
		0x01, 0x00, // versione
		0x00, 0x50, 0xf2, 0x02, // gruppo TKIP
		0x01, 0x00, 0x00, 0x50, 0xf2, 0x02, // pairwise TKIP
		0x01, 0x00, 0x00, 0x50, 0xf2, 0x02, // AKM PSK
	)
	info, _ := Parse(cat(rsnWPA2(0), wpa), 0x0011, 2437)
	s := info.Security
	if s.Protocol != "wpa2" || !reflect.DeepEqual(s.Pairwise, []string{"CCMP", "TKIP"}) || s.PMF != "disabled" {
		t.Fatalf("%+v", s)
	}
	only, _ := Parse(wpa, 0x0011, 2437)
	if only.Security.Protocol != "wpa" || only.Security.Group != "TKIP" {
		t.Fatalf("%+v", only.Security)
	}
}

func TestOWEAndEnterprise(t *testing.T) {
	owe := el(48, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 18, 0xc0, 0x00)
	info, _ := Parse(owe, 0x0011, 5180)
	if info.Security.Protocol != "owe" {
		t.Fatalf("%+v", info.Security)
	}
	ent := el(48, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x01)
	info, _ = Parse(ent, 0x0011, 5180)
	if info.Security.Protocol != "wpa2" || info.Security.AKM[0] != "802.1X" || info.Security.PMF != "disabled" {
		t.Fatalf("%+v", info.Security)
	}
}

func TestRSNDefaultsWhenFieldsMissing(t *testing.T) {
	// Solo la versione: lo standard impone CCMP/CCMP/802.1X come valori impliciti.
	info, _ := Parse(el(48, 0x01, 0x00), 0x0011, 5180)
	s := info.Security
	if s.Group != "CCMP" || s.Pairwise[0] != "CCMP" || s.AKM[0] != "802.1X" || s.Protocol != "wpa2" {
		t.Fatalf("%+v", s)
	}
}

func TestWPSDetection(t *testing.T) {
	wps := el(221,
		0x00, 0x50, 0xf2, 0x04, // OUI Microsoft, tipo 4 = WPS
		0x10, 0x4a, 0x00, 0x01, 0x10, // Version: 0x10
		0x10, 0x44, 0x00, 0x01, 0x02, // Wi-Fi Protected Setup State: configurato
	)
	info, _ := Parse(cat(rsnWPA2(0), wps), 0x0011, 2437)
	if !info.Security.WPS {
		t.Fatal("WPS non rilevato")
	}
	notWps := el(221, 0x00, 0x50, 0xf2, 0x04, 0x10, 0x4a, 0x00, 0x01, 0x10)
	info, _ = Parse(cat(rsnWPA2(0), notWps), 0x0011, 2437)
	if info.Security.WPS {
		t.Fatal("WPS rilevato senza l'attributo di stato")
	}
}

func TestBSSLoadAndCountry(t *testing.T) {
	buf := cat(
		el(7, 'I', 'T', 0x20, 0x01, 0x0d, 0x14), // Country "IT", canali 1-13 a 20 dBm
		el(11, 0x09, 0x00, 0x9e, 0x00, 0x00),    // 9 stazioni, utilizzo 158/255
	)
	info, _ := Parse(buf, 0x0011, 2432)
	if info.Country != "IT" || !info.HasBSSLoad || info.Stations != 9 || info.Utilization != 158 {
		t.Fatalf("%+v", info)
	}
}

func htOp(primary, info1 byte) []byte {
	return el(61, primary, info1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
}

func TestHT40Above24(t *testing.T) {
	// Canale 5, secondario sopra (offset 1), larghezza qualsiasi (bit 2).
	info, _ := Parse(cat(el(45, make([]byte, 26)...), htOp(5, 0x05)), 0, 2432)
	if info.WidthMhz != 40 || info.CenterChannel != 7 || !info.HT {
		t.Fatalf("%+v", info)
	}
	if info.Phy(2432, 0) != "802.11n" {
		t.Fatal(info.Phy(2432, 0))
	}
}

func TestHT40BelowAndTwentyOnly(t *testing.T) {
	info, _ := Parse(htOp(11, 0x07), 0, 2462) // secondario sotto
	if info.WidthMhz != 40 || info.CenterChannel != 9 {
		t.Fatalf("%+v", info)
	}
	info, _ = Parse(htOp(11, 0x03), 0, 2462) // offset dichiarato ma STA width = solo 20
	if info.WidthMhz != 20 {
		t.Fatalf("%+v", info)
	}
}

func TestVHT80And160(t *testing.T) {
	// 36 primario, blocco 36-48 a 80 MHz: CCFS0 = 42.
	vht80 := el(192, 0x01, 42, 0, 0xfc, 0xff)
	info, _ := Parse(cat(htOp(36, 0x05), el(191, make([]byte, 12)...), vht80), 0, 5180)
	if info.WidthMhz != 80 || info.CenterChannel != 42 || info.Phy(5180, 0) != "802.11ac" {
		t.Fatalf("%+v", info)
	}
	// 160 MHz con codifica moderna: CCFS0 = 42 (80 primario), CCFS1 = 50 (centro 160).
	vht160 := el(192, 0x01, 42, 50, 0xfc, 0xff)
	info, _ = Parse(cat(htOp(36, 0x05), vht160), 0, 5180)
	if info.WidthMhz != 160 || info.CenterChannel != 50 {
		t.Fatalf("%+v", info)
	}
	// Codifica deprecata "2 = 160 MHz" con centro in CCFS0.
	info, _ = Parse(cat(htOp(36, 0x05), el(192, 0x02, 50, 0, 0, 0)), 0, 5180)
	if info.WidthMhz != 160 || info.CenterChannel != 50 {
		t.Fatalf("%+v", info)
	}
	// VHT "0" = 20/40: decide l'HT Operation.
	info, _ = Parse(cat(htOp(36, 0x05), el(192, 0x00, 0, 0, 0, 0)), 0, 5180)
	if info.WidthMhz != 40 || info.CenterChannel != 38 {
		t.Fatalf("%+v", info)
	}
}

func TestHE6GHzOperation(t *testing.T) {
	// HE Operation con 6 GHz Operation Information presente (bit 17).
	heop := ext(36,
		0x00, 0x00, 0x02, // parametri: bit 17 = 6 GHz Operation Info presente
		0x01,       // BSS color
		0xfc, 0xff, // basic HE-MCS
		37,   // canale primario 37
		0x02, // controllo: larghezza 80 MHz
		39,   // CCFS0 = 39 (blocco 33-45)
		0,    // CCFS1
		0x06, // rate minimo
	)
	info, _ := Parse(cat(ext(35, make([]byte, 20)...), heop), 0, 6135)
	if !info.HE || info.WidthMhz != 80 || info.CenterChannel != 39 || info.Phy(6135, 0) != "802.11ax" {
		t.Fatalf("%+v", info)
	}
	// Con VHT Op Info (bit 14) e co-hosted (bit 15) presenti l'offset si sposta di 4 byte.
	heop2 := ext(36,
		0x00, 0xc0, 0x02,
		0x01, 0xfc, 0xff,
		0x01, 42, 0, // VHT Operation Information (ignorata nel 6 GHz)
		0x03,                   // Max Co-Hosted BSSID Indicator
		33, 0x03, 39, 47, 0x06, // 160 MHz: CCFS1 = 47
	)
	info, _ = Parse(heop2, 0, 6115)
	if info.WidthMhz != 160 || info.CenterChannel != 47 {
		t.Fatalf("%+v", info)
	}
}

func TestEHT320(t *testing.T) {
	ehtop := ext(106,
		0x01,                   // EHT Operation Information presente
		0x44, 0x44, 0x44, 0x44, // basic EHT-MCS/NSS
		0x04, // controllo: 320 MHz
		47,   // CCFS0: centro del 160 primario
		31,   // CCFS1: centro del 320
	)
	info, _ := Parse(cat(ext(108, make([]byte, 10)...), ehtop), 0, 6115)
	if !info.EHT || info.WidthMhz != 320 || info.CenterChannel != 31 || info.Phy(6115, 0) != "802.11be" {
		t.Fatalf("%+v", info)
	}
	// Parametro senza informazione di operazione: si ricade sulle altre fonti.
	info, _ = Parse(cat(htOp(36, 0x05), ext(106, 0x00, 0x44, 0x44, 0x44, 0x44)), 0, 5180)
	if info.WidthMhz != 40 {
		t.Fatalf("%+v", info)
	}
}

func TestUnknownVendorSuite(t *testing.T) {
	buf := el(48, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x14, 0x72, 0x05, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02)
	info, _ := Parse(buf, 0x0011, 5180)
	if info.Security.Pairwise[0] != "vendor-001472-5" {
		t.Fatalf("%+v", info.Security)
	}
}

// Roaming assistito: RM Enabled Capabilities (70) con Neighbor Report,
// Extended Capabilities (127) con il bit 19, Mobility Domain (54).
func TestRoaming(t *testing.T) {
	rsnFT := el(48,
		0x01, 0x00,
		0x00, 0x0f, 0xac, 0x04, // gruppo CCMP
		0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, // pairwise CCMP
		0x02, 0x00, 0x00, 0x0f, 0xac, 0x01, 0x00, 0x0f, 0xac, 0x03, // AKM 802.1X e FT-802.1X
		0x80, 0x00, // MFPC
	)
	buf := cat(
		el(0, []byte("Clinica")...),
		rsnFT,
		el(54, 0x4c, 0x1d, 0x01),             // MDID 4c1d, FT over DS
		el(70, 0x73, 0x00, 0x00, 0x00, 0x00), // link measurement, neighbor report, ...
		el(127, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x40), // bit 2, bit 19 (BSS Transition), bit 62
	)
	info, err := Parse(buf, 0x0011, 5180)
	if err != nil {
		t.Fatal(err)
	}
	want := Roaming{K: true, V: true, R: true, MDID: "4c1d", FTOverDS: true}
	if info.Roaming != want {
		t.Fatalf("roaming = %+v, atteso %+v", info.Roaming, want)
	}
	if info.Security.Protocol != "wpa2" || !reflect.DeepEqual(info.Security.AKM, []string{"802.1X", "FT-802.1X"}) {
		t.Fatalf("sicurezza: %+v", info.Security)
	}
}

func TestRoamingAssente(t *testing.T) {
	buf := cat(
		el(0, []byte("Casa")...),
		rsnWPA2(0x0080),
		el(70, 0x01, 0x00, 0x00, 0x00, 0x00), // solo link measurement: niente Neighbor Report
		el(127, 0x04, 0x00, 0x00),            // bit 19 spento
	)
	info, err := Parse(buf, 0x0011, 2437)
	if err != nil {
		t.Fatal(err)
	}
	if info.Roaming != (Roaming{}) {
		t.Fatalf("nessuna funzione di roaming attesa: %+v", info.Roaming)
	}
}

// Extended Capabilities troppo corto per contenere il bit 19: nessun errore, V falso.
func TestRoamingExtCapCorto(t *testing.T) {
	info, err := Parse(cat(el(127, 0x04, 0x00)), 0x0001, 2412)
	if err != nil || info.Roaming.V {
		t.Fatalf("err=%v roaming=%+v", err, info.Roaming)
	}
}

// Solo AKM FT-PSK, senza elemento Mobility Domain: 802.11r comunque annunciato.
func TestRoamingDaAKM(t *testing.T) {
	rsn := el(48,
		0x01, 0x00,
		0x00, 0x0f, 0xac, 0x04,
		0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
		0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, // FT-PSK
		0x00, 0x00,
	)
	info, err := Parse(rsn, 0x0011, 5500)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Roaming.R || info.Roaming.MDID != "" {
		t.Fatalf("roaming = %+v", info.Roaming)
	}
}
