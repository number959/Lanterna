package wlan

import (
	"encoding/binary"
	"testing"
)

func TestBandFor(t *testing.T) {
	// Con la frequenza la banda è certa, anche per i canali che si ripetono.
	for _, c := range []struct {
		freq, ch int
		want     string
	}{
		{2437, 6, "2.4"}, {5180, 36, "5"}, {5745, 149, "5"}, {5955, 1, "6"}, {6135, 37, "6"}, {6695, 149, "6"}, {7115, 233, "6"},
	} {
		if got := BandFor(c.freq, c.ch); got != c.want {
			t.Errorf("%d MHz canale %d: %q invece di %q", c.freq, c.ch, got, c.want)
		}
	}
	// Senza frequenza: i canali 6 GHz che non esistono a 5 GHz non devono più
	// risultare 5 GHz (prima "oltre 14 = 5 GHz").
	for ch, want := range map[int]string{
		1: "2.4", 6: "2.4", 13: "2.4", 14: "2.4",
		36: "5", 40: "5", 64: "5", 100: "5", 144: "5", 149: "5", 165: "5", 177: "5", 38: "5",
		17: "6", 21: "6", 37: "6", 53: "6", 93: "6", 101: "6", 145: "6", 181: "6", 233: "6",
	} {
		if got := BandFor(0, ch); got != want {
			t.Errorf("canale %d: %q invece di %q", ch, got, want)
		}
	}
	// La frequenza calcolata dal canale torna con la banda giusta.
	if f := ChannelToFreq(37, BandFor(0, 37)); f != 6135 {
		t.Errorf("canale 37 a 6 GHz: %d MHz", f)
	}
}

func TestParseBssTimes(t *testing.T) {
	buf := bssList(
		entry{ssid: "Casa", bssid: [6]byte{0xa4, 0x2b, 0xb0, 0x11, 0x22, 0x33}, rssi: -60, kHz: 5180000},
		entry{ssid: "Senza frequenza", bssid: [6]byte{1, 1, 1, 1, 1, 1}, kHz: 0},
		entry{ssid: "Vicino", bssid: [6]byte{1, 2, 3, 4, 5, 6}, rssi: -80, kHz: 2412000},
	)
	// ullHostTimestamp a offset 80 di ogni voce (FILETIME a 64 bit).
	binary.LittleEndian.PutUint64(buf[8+80:], 0x01DD4A2B3C4D5E6F)
	binary.LittleEndian.PutUint64(buf[8+2*BssEntrySize+80:], 0)
	times, err := ParseBssTimes(buf)
	if err != nil || len(times) != 2 {
		t.Fatalf("%v %+v", err, times)
	}
	if times[0].BSSID != "a4:2b:b0:11:22:33" || times[0].FreqMhz != 5180 || times[0].HostTime != 0x01DD4A2B3C4D5E6F {
		t.Fatalf("voce 1: %+v", times[0])
	}
	if times[1].BSSID != "01:02:03:04:05:06" || times[1].FreqMhz != 2412 || times[1].HostTime != 0 {
		t.Fatalf("voce 3: %+v", times[1])
	}
	// Stesse voci, stesso ordine di ParseBssList.
	nets, _ := ParseBssList(buf)
	if len(nets) != len(times) || nets[1].BSSID != times[1].BSSID {
		t.Fatalf("ordine diverso da ParseBssList: %+v", nets)
	}
	if _, err := ParseBssTimes([]byte{1}); err == nil {
		t.Fatal("buffer troppo corto accettato")
	}
}

func TestParseConnectionState(t *testing.T) {
	b := make([]byte, ConnectionAttrsSize)
	put32(b, 0, 5) // wlan_interface_state_associating
	c, err := ParseConnection(b)
	if err != nil || c.State != 5 {
		t.Fatalf("%v %+v", err, c)
	}
}
