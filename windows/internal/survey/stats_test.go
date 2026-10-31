package survey

import (
	"math"
	"strings"
	"testing"
)

func ip(v int) *int { return &v }

func TestMedianPercentile(t *testing.T) {
	if m := Median([]float64{-70, -60, -65}); m != -65 {
		t.Fatalf("mediana dispari: %v", m)
	}
	if m := Median([]float64{-70, -60, -66, -64}); m != -65 {
		t.Fatalf("mediana pari: %v", m)
	}
	if Median(nil) != 0 || PercentileInt(nil, 10) != 0 || Percentile(nil, 95) != 0 {
		t.Fatal("serie vuota")
	}
	// Rango più vicino: con 15 valori il 10° percentile è il 2° più basso.
	xs := []int{-60, -61, -62, -63, -64, -65, -66, -67, -68, -69, -70, -71, -72, -73, -80}
	if p := PercentileInt(xs, 10); p != -73 {
		t.Fatalf("p10: %d", p)
	}
	// 95° percentile di 20 tempi: il 19° in ordine.
	rtt := make([]float64, 20)
	for i := range rtt {
		rtt[i] = float64(i + 1)
	}
	if p := Percentile(rtt, 95); p != 19 {
		t.Fatalf("p95: %v", p)
	}
	if p := PercentileInt([]int{-50}, 10); p != -50 {
		t.Fatalf("un valore: %d", p)
	}
}

func TestSignalStats(t *testing.T) {
	s := SignalStats([]int{-62, -64, -63, -75, -61, -63, -62, -64, -63, -62, -63, -64, -62, -63, -66})
	if s.Median != -63 || s.Min != -75 || s.Max != -61 || s.Spread != 14 || s.P10 != -66 || s.Stuck {
		t.Fatalf("%+v", s)
	}
	// Tutte uguali: valori fermi (almeno 5 letture).
	if s := SignalStats([]int{-58, -58, -58, -58, -58, -58}); !s.Stuck || s.Spread != 0 {
		t.Fatalf("fermi: %+v", s)
	}
	if s := SignalStats([]int{-58, -58, -58}); s.Stuck {
		t.Fatal("troppo poche letture per dire che sono ferme")
	}
	if s := SignalStats(nil); s != (Signal{}) {
		t.Fatalf("vuota: %+v", s)
	}
}

func TestRoams(t *testing.T) {
	rs := []Reading{
		{AtMs: 0, BSSID: "AA:00:00:00:00:01", Dbm: ip(-70)},
		{AtMs: 1000, BSSID: "aa:00:00:00:00:01", Dbm: ip(-72)},
		{AtMs: 2000, BSSID: "", Dbm: nil}, // lettura mancata: non è un cambio
		{AtMs: 3000, BSSID: "aa:00:00:00:00:02", Dbm: ip(-60)},
		{AtMs: 4000, BSSID: "aa:00:00:00:00:02", Dbm: ip(-61)},
		{AtMs: 5000, BSSID: "aa:00:00:00:00:01", Dbm: ip(-71)},
	}
	bssids, roams := Roams(rs)
	if strings.Join(bssids, ",") != "aa:00:00:00:00:01,aa:00:00:00:00:02" {
		t.Fatalf("bssid: %v", bssids)
	}
	if len(roams) != 2 || roams[0].AtMs != 3000 || roams[0].From != "aa:00:00:00:00:01" || roams[0].To != "aa:00:00:00:00:02" ||
		*roams[0].FromDbm != -72 || *roams[0].ToDbm != -60 || roams[1].To != "aa:00:00:00:00:01" {
		t.Fatalf("cambi: %+v", roams)
	}
	if b, r := Roams(nil); b == nil || r == nil || len(b)+len(r) != 0 {
		t.Fatal("serie vuota: elenchi vuoti, non nil")
	}
}

func f(v float64) Echo { return &v }

func TestPingStats(t *testing.T) {
	// 10 inviati, 1 perso; jitter RFC 5481 sulle risposte consecutive.
	echoes := []Echo{f(2), f(4), nil, f(3), f(3), f(10), f(2), f(2), f(3), f(2)}
	p := PingStats("192.168.1.1", echoes)
	if p.Sent != 10 || p.Received != 9 || p.LossPct != 10 {
		t.Fatalf("%+v", p)
	}
	if *p.MedianMs != 3 || *p.P95Ms != 10 {
		t.Fatalf("mediana %v p95 %v", *p.MedianMs, *p.P95Ms)
	}
	// |4-2|+|3-4|+|3-3|+|10-3|+|2-10|+|2-2|+|3-2|+|2-3| = 2+1+0+7+8+0+1+1 = 20, su 8 differenze.
	if *p.JitterMs != 2.5 {
		t.Fatalf("jitter: %v", *p.JitterMs)
	}
	// Tutto perso: niente tempi, perdita 100 %.
	q := PingStats("192.168.1.1", []Echo{nil, nil, nil})
	if q.LossPct != 100 || q.MedianMs != nil || q.JitterMs != nil {
		t.Fatalf("%+v", q)
	}
	if j := Jitter([]float64{5}); j != 0 {
		t.Fatal(j)
	}
	if v := PingStats("x", []Echo{f(1), nil, nil}).LossPct; math.Abs(v-66.7) > 1e-9 {
		t.Fatalf("arrotondamento: %v", v)
	}
}

func TestInputLimits(t *testing.T) {
	for in, want := range map[int]int{0: 15, 10: 10, 15: 15, 20: 20} {
		if got, err := Seconds(in); err != nil || got != want {
			t.Errorf("%d secondi: %d %v", in, got, err)
		}
	}
	for _, bad := range []int{9, 21, -1, 60} {
		if _, err := Seconds(bad); err == nil {
			t.Errorf("%d secondi accettati", bad)
		}
	}
	if r, err := Room("  Sala   d'attesa "); err != nil || r != "Sala d'attesa" {
		t.Fatalf("%q %v", r, err)
	}
	if r, err := Room(strings.Repeat("è", 40)); err != nil || r == "" {
		t.Fatalf("40 caratteri accentati: %v", err)
	}
	for _, bad := range []string{"", "   ", strings.Repeat("a", 41), "Stanza\x07", "Stu\u009bdio", string([]byte{0xff, 0xfe})} {
		if _, err := Room(bad); err == nil {
			t.Errorf("%q accettato", bad)
		}
	}
}
