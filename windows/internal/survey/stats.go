package survey

import (
	"errors"
	"math"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"lanterna/internal/scan"
)

// Statistiche della misura: funzioni pure, collaudate su ogni sistema.

// Durata della misura in secondi: 15 come la finestra "in ogni intervallo di
// 15 secondi" dei requisiti di rete di Microsoft Teams, tra 10 e 20.
const (
	DefaultSeconds = 15
	MinSeconds     = 10
	MaxSeconds     = 20
	// MaxRoom: lunghezza massima del nome della stanza (caratteri).
	MaxRoom = 40
)

// Seconds normalizza la durata richiesta: 0 vale 15.
func Seconds(s int) (int, error) {
	if s == 0 {
		return DefaultSeconds, nil
	}
	if s < MinSeconds || s > MaxSeconds {
		return 0, errors.New("la durata della misura va da 10 a 20 secondi")
	}
	return s, nil
}

// Room controlla il nome della stanza: da 1 a 40 caratteri, senza caratteri
// di controllo. Gli spazi in eccesso si tolgono.
func Room(name string) (string, error) {
	n := strings.Join(strings.Fields(name), " ")
	if n == "" {
		return "", errors.New("indica il nome della stanza, per esempio Soggiorno o Ambulatorio 2")
	}
	if !utf8.ValidString(n) {
		return "", errors.New("il nome della stanza contiene caratteri non validi")
	}
	for _, r := range n {
		if unicode.IsControl(r) || r == '�' {
			return "", errors.New("il nome della stanza contiene caratteri non validi")
		}
	}
	if utf8.RuneCountInString(n) > MaxRoom {
		return "", errors.New("il nome della stanza può avere al massimo 40 caratteri")
	}
	return n, nil
}

func sortedInts(xs []int) []int {
	s := append([]int(nil), xs...)
	sort.Ints(s)
	return s
}

// Median è la mediana (con un numero pari di valori, la media dei due centrali).
func Median(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	m := len(s) / 2
	if len(s)%2 == 1 {
		return s[m]
	}
	return (s[m-1] + s[m]) / 2
}

// rank restituisce l'indice (da 0) del percentile p con il metodo del rango
// più vicino: il valore è sempre uno di quelli misurati.
func rank(n int, p float64) int {
	k := int(math.Ceil(p/100*float64(n))) - 1
	if k < 0 {
		k = 0
	}
	if k >= n {
		k = n - 1
	}
	return k
}

// PercentileInt è il percentile p (0-100) con il metodo del rango più vicino.
func PercentileInt(xs []int, p float64) int {
	if len(xs) == 0 {
		return 0
	}
	s := sortedInts(xs)
	return s[rank(len(s), p)]
}

// Percentile è il percentile p (0-100) con il metodo del rango più vicino.
func Percentile(xs []float64, p float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	return s[rank(len(s), p)]
}

// Signal riassume le letture del segnale (dBm).
type Signal struct {
	Median float64
	Min    int
	Max    int
	P10    int
	Spread int
	// Stuck: almeno 5 letture, tutte identiche.
	Stuck bool
}

// SignalStats calcola mediana, minimo, massimo, 10° percentile (i cali) ed
// escursione (massimo meno minimo) delle letture.
func SignalStats(rssi []int) Signal {
	if len(rssi) == 0 {
		return Signal{}
	}
	f := make([]float64, len(rssi))
	for i, v := range rssi {
		f[i] = float64(v)
	}
	s := sortedInts(rssi)
	st := Signal{Median: Median(f), Min: s[0], Max: s[len(s)-1], P10: PercentileInt(rssi, 10)}
	st.Spread = st.Max - st.Min
	st.Stuck = len(rssi) >= 5 && st.Spread == 0
	return st
}

// QualityDbm converte la qualità del segnale di Windows (wlanSignalQuality,
// 0-100) in dBm: secondo la documentazione di WLAN_ASSOCIATION_ATTRIBUTES 0
// vale -100 dBm, 100 vale -50 dBm, in mezzo interpolazione lineare. Sopra
// -50 dBm la qualità resta 100: il valore è un minimo.
func QualityDbm(q int) int {
	if q < 0 {
		q = 0
	}
	if q > 100 {
		q = 100
	}
	return q/2 - 100
}

// Reading è una lettura al secondo della connessione.
type Reading struct {
	AtMs  int64
	BSSID string
	Dbm   *int
}

// Roams trova i cambi di access point nella sequenza delle letture: un BSSID
// diverso dal precedente (le letture senza BSSID non contano). Restituisce
// anche i BSSID visti, nell'ordine.
func Roams(rs []Reading) (bssids []string, roams []scan.SurveyRoam) {
	bssids, roams = []string{}, []scan.SurveyRoam{}
	last := ""
	var lastDbm *int
	for _, r := range rs {
		b := strings.ToLower(r.BSSID)
		if b == "" {
			continue
		}
		if last != "" && b != last {
			roams = append(roams, scan.SurveyRoam{AtMs: r.AtMs, From: last, To: b, FromDbm: lastDbm, ToDbm: r.Dbm})
		}
		seen := false
		for _, x := range bssids {
			if x == b {
				seen = true
			}
		}
		if !seen {
			bssids = append(bssids, b)
		}
		last, lastDbm = b, r.Dbm
	}
	return bssids, roams
}

// Echo è l'esito di un ping: RTT in millisecondi, nil se perso.
type Echo = *float64

func round1(v float64) float64 { return math.Round(v*10) / 10 }

// PingStats riassume una serie di ping nell'ordine di invio: perdite,
// mediana e 95° percentile del tempo di risposta, jitter come media delle
// differenze assolute tra risposte consecutive (IPDV, RFC 5481).
func PingStats(target string, echoes []Echo) *scan.SurveyPing {
	p := &scan.SurveyPing{Target: target, Sent: len(echoes)}
	var rtt []float64
	for _, e := range echoes {
		if e != nil {
			rtt = append(rtt, *e)
		}
	}
	p.Received = len(rtt)
	if p.Sent > 0 {
		p.LossPct = round1(100 * float64(p.Sent-p.Received) / float64(p.Sent))
	}
	if len(rtt) > 0 {
		m, q := round1(Median(rtt)), round1(Percentile(rtt, 95))
		p.MedianMs, p.P95Ms = &m, &q
	}
	if len(rtt) > 1 {
		j := round1(Jitter(rtt))
		p.JitterMs = &j
	}
	return p
}

// Jitter è la media di |D(i) - D(i-1)| tra tempi consecutivi (RFC 5481).
func Jitter(rtt []float64) float64 {
	if len(rtt) < 2 {
		return 0
	}
	sum := 0.0
	for i := 1; i < len(rtt); i++ {
		sum += math.Abs(rtt[i] - rtt[i-1])
	}
	return sum / float64(len(rtt)-1)
}

// medianInt è la mediana arrotondata di valori interi (0 se non ce ne sono).
func medianInt(xs []int) int {
	if len(xs) == 0 {
		return 0
	}
	f := make([]float64, len(xs))
	for i, v := range xs {
		f[i] = float64(v)
	}
	return int(math.Round(Median(f)))
}
