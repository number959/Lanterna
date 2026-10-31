package survey

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"lanterna/internal/scan"
)

func bss(ssid, bssid string, dbm, ch int, band string, width int) scan.Bss {
	return scan.Bss{SSID: ssid, BSSID: bssid, RssiDbm: dbm, Channel: ch, Band: band, WidthMhz: width}
}

func TestAgeMs(t *testing.T) {
	now := time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC)
	if a := AgeMs(FileTime(now.Add(-3*time.Second)), now); a != 3000 {
		t.Fatalf("3 s: %d", a)
	}
	if a := AgeMs(FileTime(now.Add(2*time.Second)), now); a != 0 {
		t.Fatalf("poco nel futuro (orologi diversi): %d", a)
	}
	for _, h := range []uint64{0, 12345, FileTime(now.Add(-48 * time.Hour)), FileTime(now.Add(10 * time.Minute))} {
		if a := AgeMs(h, now); a != -1 {
			t.Errorf("istante non plausibile %d: %d", h, a)
		}
	}
	// FILETIME noto: 1/1/1970 = 116444736000000000.
	if FileTime(time.Unix(0, 0)) != 116444736000000000 {
		t.Fatal("epoca FILETIME")
	}
}

func TestFacts(t *testing.T) {
	me := bss("Casa", "aa:bb:cc:00:00:10", -66, 36, "5", 80)
	me.CenterChannel = 42
	me.BssLoad = &scan.BssLoad{Stations: 7, UtilizationPct: 61}
	nets := []Seen{
		{Bss: me, AgeMs: 500},
		// Stessa rete: alternative per banda (vince la più forte), una vecchia da scartare.
		{Bss: bss("Casa", "aa:bb:cc:00:00:20", -55, 44, "5", 80), AgeMs: 800},
		{Bss: bss("Casa", "aa:bb:cc:00:00:30", -60, 100, "5", 80), AgeMs: 900},
		{Bss: bss("Casa", "aa:bb:cc:00:00:11", -50, 6, "2.4", 20), AgeMs: 700},
		{Bss: bss("Casa", "aa:bb:cc:00:00:40", -40, 149, "5", 80), AgeMs: 25_000},
		// Rete ospiti della stessa radio: non è un vicino.
		{Bss: bss("Casa-Ospiti", "aa:bb:cc:00:00:1f", -66, 36, "5", 80), AgeMs: 500},
		// Vicini: due sullo stesso blocco da 80 MHz (36-48), uno nascosto.
		{Bss: bss("Vicino", "11:22:33:44:55:66", -70, 40, "5", 20), AgeMs: 1200},
		{Bss: bss("", "11:22:33:44:55:77", -82, 48, "5", 40), AgeMs: 1500},
		// Vicino su un altro blocco e a 2,4 GHz: visibili ma non sul canale.
		{Bss: bss("Lontano", "22:22:33:44:55:66", -60, 52, "5", 20), AgeMs: 1000},
		{Bss: bss("Vicino", "11:22:33:44:55:65", -50, 6, "2.4", 20), AgeMs: 1000},
		// Vicino forte ma sentito 30 secondi prima: scartato.
		{Bss: bss("Vecchio", "33:22:33:44:55:66", -45, 36, "5", 80), AgeMs: 30_000},
		// Età sconosciuta: si tiene.
		{Bss: bss("Ignoto", "44:22:33:44:55:66", -88, 36, "5", 20), AgeMs: -1},
	}
	f := Facts(nets, "Casa", "AA:BB:CC:00:00:10", "5", 36)
	if f.Fresh != 10 || f.Stale != 2 {
		t.Fatalf("fresche %d vecchie %d", f.Fresh, f.Stale)
	}
	if f.ConnectedDbm == nil || *f.ConnectedDbm != -66 || *f.UtilizationPct != 61 || *f.Stations != 7 {
		t.Fatalf("collegata: %+v", f)
	}
	if len(f.Alternatives) != 2 || f.Alternatives[0].Band != "2.4" || f.Alternatives[0].RssiDbm != -50 ||
		f.Alternatives[1].Band != "5" || f.Alternatives[1].RssiDbm != -55 || f.Alternatives[1].BSSID != "aa:bb:cc:00:00:20" {
		t.Fatalf("alternative: %+v", f.Alternatives)
	}
	nb := f.Neighbors
	if nb.Visible != 5 || nb.Cochannel != 3 || nb.Strong != 1 || nb.StrongestDbm == nil || *nb.StrongestDbm != -70 {
		t.Fatalf("vicini: %+v", nb)
	}
	if len(nb.Channels) != 3 || nb.Channels[0] != 36 || nb.Channels[1] != 40 || nb.Channels[2] != 48 {
		t.Fatalf("canali: %v", nb.Channels)
	}
	// Privacy: dei vicini restano solo numeri, mai nomi o BSSID.
	b, _ := json.Marshal(f.Neighbors)
	for _, s := range []string{"Vicino", "11:22:33", "Ignoto", "Ospiti"} {
		if strings.Contains(string(b), s) {
			t.Errorf("%s nei vicini: %s", s, b)
		}
	}
}

func TestFactsWithoutConnectedEntry(t *testing.T) {
	// La rete collegata manca dalla lista: si usano banda e canale della connessione, a 20 MHz.
	nets := []Seen{
		{Bss: bss("Vicino", "11:22:33:44:55:66", -70, 3, "2.4", 20), AgeMs: 100},
		{Bss: bss("Altro", "11:22:33:44:55:67", -70, 11, "2.4", 20), AgeMs: 100},
	}
	f := Facts(nets, "Casa", "aa:bb:cc:00:00:10", "2.4", 1)
	if f.ConnectedDbm != nil || f.Neighbors.Visible != 2 || f.Neighbors.Cochannel != 1 || f.Neighbors.Channels[0] != 3 {
		t.Fatalf("%+v", f)
	}
	if c := connectedBss(nets, "Casa", "aa:bb:cc:00:00:10"); c != nil {
		t.Fatal("trovata una rete che non c'è")
	}
}
