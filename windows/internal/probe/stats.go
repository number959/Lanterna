// Package probe contiene le misure di rete che non dipendono dal sistema
// operativo (DNS, UPnP, porte, HTTP) e il calcolo delle statistiche.
package probe

import (
	"math"

	"lanterna/internal/scan"
)

func round1(x float64) float64 { return math.Round(x*10) / 10 }

// PingStats calcola min/media/max e jitter da una serie di campioni in ms
// (nil = nessuna risposta). Il jitter è la media delle differenze assolute
// tra risposte consecutive, come in RFC 3550 senza il filtro esponenziale.
func PingStats(target, label, method string, samples []*float64) scan.PingStats {
	st := scan.PingStats{Target: target, Label: label, Method: method, Sent: len(samples), Samples: make([]*float64, len(samples))}
	var ok []float64
	for i, s := range samples {
		if s != nil {
			v := round1(*s)
			st.Samples[i] = &v
			ok = append(ok, *s)
		}
	}
	st.Received = len(ok)
	if len(ok) == 0 {
		return st
	}
	mn, mx, sum := ok[0], ok[0], 0.0
	for _, v := range ok {
		mn = math.Min(mn, v)
		mx = math.Max(mx, v)
		sum += v
	}
	st.MinMs = scan.Ptr(round1(mn))
	st.MaxMs = scan.Ptr(round1(mx))
	st.AvgMs = scan.Ptr(round1(sum / float64(len(ok))))
	if len(ok) > 1 {
		j := 0.0
		for i := 1; i < len(ok); i++ {
			j += math.Abs(ok[i] - ok[i-1])
		}
		st.JitterMs = scan.Ptr(round1(j / float64(len(ok)-1)))
	}
	return st
}
