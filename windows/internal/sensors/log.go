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
	Cur, Min, Max          float64
	sum                    float64
	N                      int
}

// Avg è la media delle letture.
func (s Stat) Avg() float64 {
	if s.N == 0 {
		return math.NaN()
	}
	return s.sum / float64(s.N)
}

type logRow struct {
	at   time.Time
	vals map[string]float64
}

// Log raccoglie le letture di una sessione per il riepilogo e il file CSV.
type Log struct {
	order []string
	stats map[string]*Stat
	rows  []logRow
}

// Add aggiunge una lettura.
func (l *Log) Add(s Snapshot) {
	if l.stats == nil {
		l.stats = map[string]*Stat{}
	}
	row := logRow{at: s.At, vals: map[string]float64{}}
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
			row.vals[x.ID] = x.Value
		}
	}
	l.rows = append(l.rows, row)
}

// Stats restituisce il riepilogo nell'ordine in cui i sensori sono comparsi.
func (l *Log) Stats() []Stat {
	out := make([]Stat, 0, len(l.order))
	for _, id := range l.order {
		out = append(out, *l.stats[id])
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

// WriteCSV scrive il registro: una riga per lettura, una colonna per
// sensore, separatore punto e virgola e virgola decimale, con la marca UTF-8
// iniziale perché Excel riconosca gli accenti.
func (l *Log) WriteCSV(w io.Writer) error {
	bw := bufio.NewWriter(w)
	bw.WriteString("\ufeffData e ora")
	for _, id := range l.order {
		st := l.stats[id]
		h := st.Group + " - " + st.Label
		if st.Unit != "" {
			h += " [" + st.Unit + "]"
		}
		bw.WriteString(";" + csvText(h))
	}
	bw.WriteString("\r\n")
	for _, r := range l.rows {
		bw.WriteString(r.at.Local().Format("2006-01-02 15:04:05"))
		for _, id := range l.order {
			bw.WriteByte(';')
			if v, found := r.vals[id]; found {
				bw.WriteString(Number(v))
			}
		}
		bw.WriteString("\r\n")
	}
	return bw.Flush()
}
