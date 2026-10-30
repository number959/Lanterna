package sensors

import (
	"bufio"
	"io"
	"math"
	"strconv"
	"strings"
	"time"
)

// Stat riassume un sensore lungo una sessione: valore attuale, minimo,
// massimo e media, come le colonne di HWiNFO.
type Stat struct {
	ID, Group, Label, Unit string
	Detail                 bool
	// Cur è l'ultimo valore letto; Present dice se il sensore c'era
	// nell'ultima lettura (se no, Cur è vecchio e non va mostrato come attuale).
	Cur, Min, Max float64
	Present       bool
	sum           float64
	N             int
	last          int
}

// Avg è la media delle letture.
func (s Stat) Avg() float64 {
	if s.N == 0 {
		return math.NaN()
	}
	return s.sum / float64(s.N)
}

// logRow è una lettura per il CSV: i valori nell'ordine delle colonne
// (NaN se il sensore mancava); le colonne aggiunte dopo mancano in coda.
type logRow struct {
	at   time.Time
	vals []float64
}

// Log raccoglie le letture di una sessione per il riepilogo e, con
// KeepRows, per il file CSV.
type Log struct {
	// KeepRows conserva ogni lettura per il CSV; senza, solo il riepilogo,
	// che occupa poca memoria anche in una registrazione di un giorno.
	KeepRows bool
	order    []string
	stats    map[string]*Stat
	rows     []logRow
	n        int
}

// Add aggiunge una lettura.
func (l *Log) Add(s Snapshot) {
	if l.stats == nil {
		l.stats = map[string]*Stat{}
	}
	l.n++
	for _, g := range s.Groups {
		for _, x := range g.Sensors {
			st := l.stats[x.ID]
			if st == nil {
				st = &Stat{ID: x.ID, Group: g.Name, Label: x.Label, Unit: x.Unit, Detail: x.Detail, Min: x.Value, Max: x.Value}
				l.stats[x.ID] = st
				l.order = append(l.order, x.ID)
			}
			st.Cur = x.Value
			st.Min = math.Min(st.Min, x.Value)
			st.Max = math.Max(st.Max, x.Value)
			st.sum += x.Value
			st.N++
			st.last = l.n
		}
	}
	if l.KeepRows {
		row := logRow{at: s.At, vals: make([]float64, len(l.order))}
		for i, id := range l.order {
			if st := l.stats[id]; st.last == l.n {
				row.vals[i] = st.Cur
			} else {
				row.vals[i] = math.NaN()
			}
		}
		l.rows = append(l.rows, row)
	}
}

// Len è il numero di letture aggiunte.
func (l *Log) Len() int { return l.n }

// Stats restituisce il riepilogo nell'ordine in cui i sensori sono comparsi.
func (l *Log) Stats() []Stat {
	out := make([]Stat, 0, len(l.order))
	for _, id := range l.order {
		st := *l.stats[id]
		st.Present = st.last == l.n
		out = append(out, st)
	}
	return out
}

// Number scrive un numero con la virgola decimale, come lo legge Excel in
// italiano.
func Number(v float64) string {
	return strings.Replace(strconv.FormatFloat(v, 'f', -1, 64), ".", ",", 1)
}

// csvText rende sicuro un testo per il CSV: punto e virgola e virgolette
// raddoppiate tra virgolette, e un apostrofo davanti a ciò che un foglio di
// calcolo prenderebbe per una formula.
func csvText(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		s = "'" + s
	}
	if strings.ContainsAny(s, ";\"\n\r") {
		s = `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

// Columns è il numero di sensori comparsi finora (le colonne del CSV).
func (l *Log) Columns() int { return len(l.order) }

// WriteCSV scrive il registro: una riga per lettura, una colonna per
// sensore, separatore punto e virgola e virgola decimale, con la marca UTF-8
// iniziale perché Excel riconosca gli accenti.
func (l *Log) WriteCSV(w io.Writer) error {
	bw := bufio.NewWriter(w)
	l.writeHeader(bw, len(l.order))
	for i := range l.rows {
		l.writeRow(bw, i, len(l.order))
	}
	return bw.Flush()
}

// WriteHeader scrive l'intestazione con le prime n colonne e WriteLastRow
// l'ultima lettura limitata alle stesse: servono a scrivere il registro man
// mano, così resta su disco anche se il PC si blocca o si spegne.
func (l *Log) WriteHeader(w io.Writer, n int) error {
	bw := bufio.NewWriter(w)
	l.writeHeader(bw, n)
	return bw.Flush()
}

// WriteLastRow scrive l'ultima lettura (con KeepRows) nelle prime n colonne.
func (l *Log) WriteLastRow(w io.Writer, n int) error {
	if len(l.rows) == 0 {
		return nil
	}
	bw := bufio.NewWriter(w)
	l.writeRow(bw, len(l.rows)-1, n)
	return bw.Flush()
}

func (l *Log) writeHeader(bw *bufio.Writer, n int) {
	bw.WriteString("\ufeffData e ora")
	for _, id := range l.order[:min(n, len(l.order))] {
		st := l.stats[id]
		h := st.Group + " - " + st.Label
		if st.Unit != "" {
			h += " [" + st.Unit + "]"
		}
		bw.WriteString(";" + csvText(h))
	}
	bw.WriteString("\r\n")
}

func (l *Log) writeRow(bw *bufio.Writer, i, n int) {
	r := l.rows[i]
	bw.WriteString(r.at.Local().Format("2006-01-02 15:04:05"))
	for c := 0; c < min(n, len(l.order)); c++ {
		bw.WriteByte(';')
		if c < len(r.vals) && !math.IsNaN(r.vals[c]) {
			bw.WriteString(Number(r.vals[c]))
		}
	}
	bw.WriteString("\r\n")
}
