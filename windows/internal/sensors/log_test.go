package sensors

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestLog(t *testing.T) {
	t0 := time.Date(2026, 10, 30, 9, 0, 0, 0, time.Local)
	snap := func(sec int, cpu float64, extra bool) Snapshot {
		s := Snapshot{At: t0.Add(time.Duration(sec) * time.Second), Groups: []Group{{ID: "cpu", Name: "Intel; \"i5\"", Sensors: []Sensor{{ID: "cpu.usage", Label: "Utilizzo totale", Value: cpu, Unit: "%"}}}}}
		if extra {
			s.Groups = append(s.Groups, Group{ID: "battery.0", Name: "=SOMMA(A1)", Sensors: []Sensor{{ID: "battery.0.rate", Label: "Potenza", Value: -7.5, Unit: "W", Detail: true}}})
		}
		return s
	}
	l := Log{KeepRows: true}
	l.Add(snap(0, 10, false))
	l.Add(snap(1, 30.5, true))
	l.Add(snap(2, 20, false))
	st := l.Stats()
	if len(st) != 2 || st[0].ID != "cpu.usage" || st[1].ID != "battery.0.rate" {
		t.Fatalf("ordine: %+v", st)
	}
	if c := st[0]; c.Cur != 20 || c.Min != 10 || c.Max != 30.5 || c.N != 3 || c.Avg() != 60.5/3 {
		t.Errorf("riepilogo: %+v media %v", c, c.Avg())
	}
	if b := st[1]; b.N != 1 || b.Min != -7.5 || !b.Detail || b.Present {
		t.Errorf("sensore comparso dopo e poi sparito: %+v", b)
	}
	if !st[0].Present || l.Len() != 3 {
		t.Errorf("presenza e conteggio: %+v %d", st[0], l.Len())
	}
	var buf bytes.Buffer
	if err := l.WriteCSV(&buf); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(buf.String(), "\r\n")
	want := []string{
		"\ufeffData e ora;\"Intel; \"\"i5\"\" - Utilizzo totale [%]\";'=SOMMA(A1) - Potenza [W]",
		"2026-10-30 09:00:00;10;",
		"2026-10-30 09:00:01;30,5;-7,5",
		"2026-10-30 09:00:02;20;",
		"",
	}
	if len(lines) != len(want) {
		t.Fatalf("righe: %q", lines)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("riga %d: %q, attesa %q", i, lines[i], want[i])
		}
	}
	// Scrittura man mano: intestazione e righe con le colonne della prima lettura.
	var st2 bytes.Buffer
	stream := Log{KeepRows: true}
	stream.Add(snap(0, 10, false))
	n := stream.Columns()
	_ = stream.WriteHeader(&st2, n)
	_ = stream.WriteLastRow(&st2, n)
	stream.Add(snap(1, 30.5, true))
	_ = stream.WriteLastRow(&st2, n)
	if got := st2.String(); got != "\ufeffData e ora;\"Intel; \"\"i5\"\" - Utilizzo totale [%]\"\r\n2026-10-30 09:00:00;10\r\n2026-10-30 09:00:01;30,5\r\n" || stream.Columns() != 2 {
		t.Errorf("scrittura man mano: %q", got)
	}
	// Senza KeepRows niente righe: il CSV ha solo l'intestazione.
	var light Log
	light.Add(snap(0, 10, true))
	var lb bytes.Buffer
	_ = light.WriteCSV(&lb)
	if n := strings.Count(lb.String(), "\r\n"); n != 1 || light.Stats()[0].N != 1 {
		t.Errorf("registro leggero: %d righe", n)
	}
	if Number(1234.5) != "1234,5" || Number(-0.25) != "-0,25" || Number(3) != "3" {
		t.Error("formato dei numeri")
	}
}
