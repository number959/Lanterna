package survey

import (
	"net"
	"sort"
	"strings"
	"time"

	"lanterna/internal/scan"
	"lanterna/internal/wlan"
)

// Che cosa dice la scansione fatta dopo la misura: il miglior altro access
// point della stessa rete e le reti dei vicini sullo stesso spettro, solo
// come conteggi, canali e dBm.

// MaxAgeMs: le voci della lista sentite più di 10 secondi prima si scartano.
// Da collegato il servizio WLAN può non scansionare affatto (documentazione
// di WlanScan): senza questo filtro si confronterebbero dati vecchi.
const MaxAgeMs = 10_000

// StrongDbm: oltre questo valore una rete vicina è "forte", come nel motore
// di analisi (STRONG_NEIGHBOUR_DBM).
const StrongDbm = -75

// Seen è una rete della lista con l'età della voce in millisecondi (-1 se
// la scheda non fornisce un istante plausibile).
type Seen struct {
	scan.Bss
	AgeMs int64
}

// fileTimeEpoch: differenza tra il 1601 (FILETIME) e il 1970 in intervalli di 100 ns.
const fileTimeEpoch = 116444736000000000

// FileTime converte un istante in FILETIME (intervalli di 100 ns dal 1601).
func FileTime(t time.Time) uint64 { return uint64(t.UnixNano()/100 + fileTimeEpoch) }

// AgeMs è l'età di una voce ricevuta all'istante host (FILETIME). Restituisce
// -1 quando l'istante manca o non è plausibile (nel futuro di oltre un minuto
// o più vecchio di un giorno): alcune schede non lo compilano.
func AgeMs(host uint64, now time.Time) int64 {
	if host == 0 {
		return -1
	}
	age := (int64(FileTime(now)) - int64(host)) / 10_000
	if age < -60_000 || age > 86_400_000 {
		return -1
	}
	if age < 0 {
		return 0
	}
	return age
}

type span struct{ lo, hi int }

// spectrum è l'intervallo di frequenze occupato da una rete (come nel motore).
func spectrum(b scan.Bss) span {
	w := b.WidthMhz
	if w <= 0 {
		w = 20
	}
	ch := b.Channel
	if b.CenterChannel != 0 {
		ch = b.CenterChannel
	}
	c := wlan.ChannelToFreq(ch, b.Band)
	return span{c - w/2, c + w/2}
}

func overlaps(a, b span) bool { return min(a.hi, b.hi) > max(a.lo, b.lo) }

// sameRadio: due reti trasmesse dalla stessa radio (più SSID sullo stesso AP),
// con la stessa regola del motore: stessa banda e canale, BSSID diversi solo
// nell'ultima cifra esadecimale o solo nel primo ottetto. È una stima: non
// esiste una regola valida per tutti i produttori.
func sameRadio(a, b scan.Bss) bool {
	if a.Band != b.Band || a.Channel != b.Channel || strings.EqualFold(a.BSSID, b.BSSID) {
		return false
	}
	x, err1 := net.ParseMAC(a.BSSID)
	y, err2 := net.ParseMAC(b.BSSID)
	if err1 != nil || err2 != nil || len(x) != 6 || len(y) != 6 {
		return false
	}
	for i := 1; i <= 4; i++ {
		if x[i] != y[i] {
			return false
		}
	}
	return (x[0] == y[0] && x[5]&0xf0 == y[5]&0xf0) || x[5] == y[5]
}

// Facts ricava i dati della scansione per un punto. ssid e bssid sono la
// rete e l'access point a cui il PC era collegato alla fine della misura;
// band e channel servono quando la rete collegata manca dalla lista.
func Facts(nets []Seen, ssid, bssid, band string, channel int) *scan.SurveyScan {
	out := &scan.SurveyScan{}
	var fresh []scan.Bss
	for _, n := range nets {
		if n.AgeMs > MaxAgeMs {
			out.Stale++
			continue
		}
		fresh = append(fresh, n.Bss)
	}
	out.Fresh = len(fresh)

	me := scan.Bss{SSID: ssid, BSSID: bssid, Band: band, Channel: channel, WidthMhz: 20}
	var own []scan.Bss
	for _, b := range fresh {
		if ssid != "" && b.SSID == ssid {
			own = append(own, b)
		}
		if strings.EqualFold(b.BSSID, bssid) && b.SSID == ssid {
			me = b
			v := b.RssiDbm
			out.ConnectedDbm = &v
			if b.BssLoad != nil {
				u, st := b.BssLoad.UtilizationPct, b.BssLoad.Stations
				out.UtilizationPct, out.Stations = &u, &st
			}
		}
	}

	// Il miglior altro access point della stessa rete, banda per banda.
	best := map[string]scan.SurveyAlt{}
	for _, b := range own {
		if strings.EqualFold(b.BSSID, bssid) {
			continue
		}
		if cur, ok := best[b.Band]; !ok || b.RssiDbm > cur.RssiDbm {
			best[b.Band] = scan.SurveyAlt{BSSID: strings.ToLower(b.BSSID), Band: b.Band, Channel: b.Channel, RssiDbm: b.RssiDbm}
		}
	}
	for _, a := range best {
		out.Alternatives = append(out.Alternatives, a)
	}
	sort.Slice(out.Alternatives, func(i, j int) bool { return out.Alternatives[i].RssiDbm > out.Alternatives[j].RssiDbm })

	// Reti dei vicini: tutto ciò che non è la propria rete né un'altra rete
	// delle stesse radio (ospiti, dispositivi).
	mine := spectrum(me)
	chans := map[int]bool{}
	for _, b := range fresh {
		if ssid != "" && b.SSID == ssid {
			continue
		}
		sibling := false
		for _, o := range own {
			if sameRadio(o, b) {
				sibling = true
				break
			}
		}
		if sibling {
			continue
		}
		out.Neighbors.Visible++
		if b.Band != me.Band || me.Channel == 0 || !overlaps(mine, spectrum(b)) {
			continue
		}
		out.Neighbors.Cochannel++
		if b.RssiDbm > StrongDbm {
			out.Neighbors.Strong++
		}
		if s := out.Neighbors.StrongestDbm; s == nil || b.RssiDbm > *s {
			v := b.RssiDbm
			out.Neighbors.StrongestDbm = &v
		}
		chans[b.Channel] = true
	}
	for c := range chans {
		out.Neighbors.Channels = append(out.Neighbors.Channels, c)
	}
	sort.Ints(out.Neighbors.Channels)
	return out
}

// connectedBss cerca nella lista (anche nelle voci vecchie: la frequenza di
// un access point non cambia con l'età della voce) la rete collegata.
func connectedBss(nets []Seen, ssid, bssid string) *scan.Bss {
	for i := range nets {
		if strings.EqualFold(nets[i].BSSID, bssid) && nets[i].SSID == ssid {
			return &nets[i].Bss
		}
	}
	return nil
}
