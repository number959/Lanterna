// Package netsh interpreta l'output testuale di "netsh wlan show interfaces",
// usato come riserva quando l'API Wi-Fi nativa non è disponibile.
//
// L'output è localizzato (italiano, inglese...) e a seconda di come viene
// lanciato può arrivare nella code page OEM (CP850) invece che in UTF-8, con
// le lettere accentate storpiate ("VelocitÓ"). Per questo le etichette non si
// confrontano alla lettera: si normalizzano a sole lettere e cifre ASCII e si
// riconoscono per parole chiave.
package netsh

import (
	"strconv"
	"strings"
)

// Interface è una scheda Wi-Fi come descritta da netsh.
type Interface struct {
	Name, Description, State string
	Connected                bool
	SSID, BSSID              string
	Band                     string // "2.4", "5", "6" o ""
	Channel                  int
	Radio                    string // es. "802.11ax"
	Auth, Cipher             string
	RxMbps, TxMbps           float64
	SignalPct                *int
	RssiDbm                  *int
}

// norm riduce un'etichetta a [a-z0-9].
func norm(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

type field int

const (
	fNone field = iota
	fName
	fDescription
	fState
	fSSID
	fBSSID
	fBand
	fChannel
	fRadio
	fAuth
	fCipher
	fRx
	fTx
	fSignal
	fRssi
)

func classify(label string) field {
	n := norm(label)
	switch {
	case n == "name" || n == "nome":
		return fName
	case n == "description" || n == "descrizione":
		return fDescription
	case n == "state" || n == "stato":
		return fState
	case n == "ssid":
		return fSSID
	case strings.Contains(n, "bssid"):
		return fBSSID
	case n == "band" || n == "banda":
		return fBand
	case n == "channel" || n == "canale":
		return fChannel
	case strings.Contains(n, "radio"):
		return fRadio
	case n == "authentication" || n == "autenticazione":
		return fAuth
	case n == "cipher" || n == "crittografia":
		return fCipher
	case strings.Contains(n, "receive") || strings.Contains(n, "ricez"):
		return fRx
	case strings.Contains(n, "transmit") || strings.Contains(n, "trasm"):
		return fTx
	case n == "signal" || n == "segnale":
		return fSignal
	case n == "rssi":
		return fRssi
	}
	return fNone
}

func number(s string) (float64, bool) {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "%"))
	s = strings.ReplaceAll(s, ",", ".")
	f, err := strconv.ParseFloat(s, 64)
	return f, err == nil
}

// ParseInterfaces legge tutte le schede presenti nell'output.
func ParseInterfaces(out string) []Interface {
	var list []Interface
	var cur *Interface
	for _, line := range strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n") {
		i := strings.Index(line, ":")
		if i <= 0 || !strings.HasPrefix(line, " ") {
			continue // intestazioni e righe vuote
		}
		label, value := line[:i], strings.TrimSpace(line[i+1:])
		f := classify(label)
		if f == fName {
			list = append(list, Interface{Name: value})
			cur = &list[len(list)-1]
			continue
		}
		if cur == nil || f == fNone {
			continue
		}
		switch f {
		case fDescription:
			cur.Description = value
		case fState:
			cur.State = value
			v := norm(value)
			cur.Connected = strings.HasPrefix(v, "connect") || strings.HasPrefix(v, "conness")
		case fSSID:
			cur.SSID = value
		case fBSSID:
			cur.BSSID = strings.ToLower(value)
		case fBand:
			switch {
			case strings.HasPrefix(value, "2"):
				cur.Band = "2.4"
			case strings.HasPrefix(value, "5"):
				cur.Band = "5"
			case strings.HasPrefix(value, "6"):
				cur.Band = "6"
			}
		case fChannel:
			if n, ok := number(value); ok {
				cur.Channel = int(n)
			}
		case fRadio:
			cur.Radio = value
		case fAuth:
			cur.Auth = value
		case fCipher:
			cur.Cipher = value
		case fRx:
			cur.RxMbps, _ = number(value)
		case fTx:
			cur.TxMbps, _ = number(value)
		case fSignal:
			if n, ok := number(value); ok {
				v := int(n)
				cur.SignalPct = &v
			}
		case fRssi:
			if n, ok := number(value); ok {
				v := int(n)
				cur.RssiDbm = &v
			}
		}
	}
	return list
}

// Connected restituisce la prima scheda collegata, se c'è.
func Connected(list []Interface) *Interface {
	for i := range list {
		if list[i].Connected {
			return &list[i]
		}
	}
	return nil
}

// LocationDenied riconosce il messaggio con cui Windows 11 24H2 e successivi
// rifiutano i comandi Wi-Fi quando le app non hanno il permesso di posizione.
func LocationDenied(out string) bool {
	n := norm(out)
	return strings.Contains(n, "locationpermission") || strings.Contains(n, "autorizzazionedipercorso") ||
		strings.Contains(n, "autorizzazioneposizione") || strings.Contains(n, "mssettingsprivacylocation")
}
