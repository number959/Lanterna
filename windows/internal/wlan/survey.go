package wlan

import "errors"

// Aiuti per la mappa del Wi-Fi per stanza: la banda di un canale quando
// manca la frequenza e l'istante in cui la scheda ha ricevuto ogni beacon.

// BandFor restituisce la banda ("2.4", "5" o "6"). Con la frequenza centrale
// del canale (MHz) la risposta è certa; senza, la si deduce dal numero di
// canale, che però si ripete tra le bande:
//   - senza canale (0) la banda non si conosce: "";
//   - 1-14 sono 2,4 GHz (1, 5, 9 e 13 esistono anche a 6 GHz: si sceglie
//     la banda di gran lunga più comune);
//   - a 6 GHz i canali sono 1, 5, 9 ... 233 (4n+1): da 17 a 145 e da 181 in
//     su nessun canale a 5 GHz ha quella forma, quindi sono 6 GHz;
//   - 149-177 (4n+1) esistono a 5 GHz e a 6 GHz: si sceglie 5 GHz (in
//     Europa il 6 GHz arriva solo al canale 93);
//   - gli altri sopra 14 sono 5 GHz.
func BandFor(freqMhz, channel int) string {
	if freqMhz > 0 {
		return BandOf(freqMhz)
	}
	switch {
	case channel <= 0:
		return ""
	case channel <= 14:
		return "2.4"
	case channel%4 == 1 && (channel <= 145 || (channel >= 181 && channel <= 233)):
		return "6"
	}
	return "5"
}

// bssHostTimeOffset è offsetof(WLAN_BSS_ENTRY, ullHostTimestamp): FILETIME
// (intervalli di 100 ns dal 1601) in cui la scheda ha ricevuto il beacon o la
// risposta alla ricerca.
const bssHostTimeOffset = 80

// BssTime dice quando la scheda ha sentito una rete per l'ultima volta.
type BssTime struct {
	BSSID    string
	FreqMhz  int
	HostTime uint64 // FILETIME; 0 se la scheda non lo fornisce
}

// ParseBssTimes legge BSSID, frequenza e ullHostTimestamp di ogni voce di
// WLAN_BSS_LIST, nello stesso ordine e con gli stessi controlli di
// ParseBssList (le voci senza frequenza si saltano).
func ParseBssTimes(b []byte) ([]BssTime, error) {
	if len(b) < listHeader {
		return nil, errors.New("WLAN_BSS_LIST troppo corta")
	}
	total := int(u32(b, 0))
	if total > len(b) {
		total = len(b)
	}
	n := int(u32(b, 4))
	out := make([]BssTime, 0, n)
	for i := 0; i < n; i++ {
		off := listHeader + i*BssEntrySize
		if off+BssEntrySize > total {
			break
		}
		e := b[off : off+BssEntrySize]
		freq := int(u32(e, 92) / 1000)
		if freq == 0 {
			continue
		}
		host := uint64(u32(e, bssHostTimeOffset)) | uint64(u32(e, bssHostTimeOffset+4))<<32
		out = append(out, BssTime{BSSID: MAC(e[40:46]), FreqMhz: freq, HostTime: host})
	}
	return out, nil
}
