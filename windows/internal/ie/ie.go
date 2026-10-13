// Package ie decodifica gli Information Element 802.11 contenuti nei beacon
// e nelle probe response, così come Windows li restituisce in
// WlanGetNetworkBssList. Non dipende dal sistema operativo: i test usano
// buffer costruiti byte per byte secondo IEEE 802.11-2020 / 802.11ax / 802.11be.
package ie

import (
	"encoding/binary"
	"fmt"
)

// Identificativi degli elementi usati.
const (
	idSSID       = 0
	idDSParams   = 3
	idCountry    = 7
	idBSSLoad    = 11
	idHTCap      = 45
	idRSN        = 48
	idHTOp       = 61
	idVHTCap     = 191
	idVHTOp      = 192
	idVendor     = 221
	idExtension  = 255
	extHECap     = 35
	extHEOp      = 36
	extEHTOp     = 106
	extEHTCap    = 108
	capPrivacy   = 1 << 4 // bit "Privacy" del Capability Information
	rsnCapMFPR   = 1 << 6
	rsnCapMFPC   = 1 << 7
	wpsStateAttr = 0x1044
)

// Element è un singolo elemento TLV.
type Element struct {
	ID    byte
	ExtID byte // valido solo se ID == 255
	Data  []byte
}

// Split divide il buffer in elementi. Un elemento troncato termina la
// lettura senza errore fatale: i beacon reali a volte sono malformati e si
// preferisce usare ciò che è leggibile.
func Split(buf []byte) ([]Element, error) {
	var out []Element
	for i := 0; i < len(buf); {
		if i+2 > len(buf) {
			return out, fmt.Errorf("elemento troncato all'offset %d", i)
		}
		id, l := buf[i], int(buf[i+1])
		if i+2+l > len(buf) {
			return out, fmt.Errorf("elemento %d dichiara %d byte ma ne restano %d", id, l, len(buf)-i-2)
		}
		e := Element{ID: id, Data: buf[i+2 : i+2+l]}
		if id == idExtension && l >= 1 {
			e.ExtID = e.Data[0]
			e.Data = e.Data[1:]
		}
		out = append(out, e)
		i += 2 + l
	}
	return out, nil
}

// Security è la protezione annunciata dalla rete.
type Security struct {
	Protocol string // open | owe | wep | wpa | wpa2 | wpa2/wpa3 | wpa3 | unknown
	AKM      []string
	Pairwise []string
	Group    string
	PMF      string // disabled | capable | required
	WPS      bool
}

// Info riassume quello che serve a Polaris di una singola rete.
type Info struct {
	SSID          string
	DSChannel     int
	Country       string
	HasBSSLoad    bool
	Stations      int
	Utilization   int // 0-255 come nel frame
	HT, VHT       bool
	HE, EHT       bool
	WidthMhz      int // 0 = sconosciuta (si assume 20)
	CenterChannel int // canale centrale del blocco largo, 0 se 20 MHz
	Security      Security
}

var cipherNames = map[byte]string{
	1: "WEP-40", 2: "TKIP", 4: "CCMP", 5: "WEP-104", 6: "BIP-CMAC-128",
	8: "GCMP", 9: "GCMP-256", 10: "CCMP-256", 11: "BIP-GMAC-128", 12: "BIP-GMAC-256", 13: "BIP-CMAC-256",
}

var akmNames = map[byte]string{
	1: "802.1X", 2: "PSK", 3: "FT-802.1X", 4: "FT-PSK", 5: "802.1X-SHA256", 6: "PSK-SHA256",
	8: "SAE", 9: "FT-SAE", 11: "802.1X-SuiteB", 12: "802.1X-SuiteB-192", 13: "FT-802.1X-SHA384",
	18: "OWE", 24: "SAE-EXT-KEY", 25: "FT-SAE-EXT-KEY",
}

var ouiIEEE = [3]byte{0x00, 0x0f, 0xac}
var ouiMicrosoft = [3]byte{0x00, 0x50, 0xf2}

func suiteName(s []byte, names map[byte]string, oui [3]byte) string {
	if len(s) < 4 {
		return "?"
	}
	if [3]byte{s[0], s[1], s[2]} != oui {
		return fmt.Sprintf("vendor-%02x%02x%02x-%d", s[0], s[1], s[2], s[3])
	}
	if n, ok := names[s[3]]; ok {
		return n
	}
	return fmt.Sprintf("tipo-%d", s[3])
}

// suites legge "conteggio (2 byte LE) + n suite da 4 byte" a partire da p.
func suites(d []byte, p int, names map[byte]string, oui [3]byte) ([]string, int, bool) {
	if p+2 > len(d) {
		return nil, p, false
	}
	n := int(binary.LittleEndian.Uint16(d[p:]))
	p += 2
	if p+4*n > len(d) {
		return nil, p, false
	}
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, suiteName(d[p+4*i:p+4*i+4], names, oui))
	}
	return out, p + 4*n, true
}

type rsnInfo struct {
	group    string
	pairwise []string
	akm      []string
	caps     uint16
	hasCaps  bool
}

// parseRSN decodifica l'elemento RSN (o il corpo dell'elemento WPA vendor,
// che ha la stessa struttura con OUI Microsoft).
func parseRSN(d []byte, oui [3]byte) (rsnInfo, bool) {
	var r rsnInfo
	if len(d) < 2 || binary.LittleEndian.Uint16(d) != 1 {
		return r, false
	}
	p := 2
	// Tutti i campi successivi sono opzionali: se mancano valgono i default
	// dello standard (CCMP / CCMP / 802.1X).
	if p+4 <= len(d) {
		r.group = suiteName(d[p:p+4], cipherNames, oui)
		p += 4
	} else {
		r.group = "CCMP"
	}
	var ok bool
	if r.pairwise, p, ok = suites(d, p, cipherNames, oui); !ok {
		if r.pairwise == nil {
			r.pairwise = []string{"CCMP"}
		}
		return r, true
	}
	if r.akm, p, ok = suites(d, p, akmNames, oui); !ok {
		return r, true
	}
	if p+2 <= len(d) {
		r.caps = binary.LittleEndian.Uint16(d[p:])
		r.hasCaps = true
	}
	return r, true
}

// wpsPresent verifica il corpo vendor WPS (OUI Microsoft tipo 4): basta che
// contenga l'attributo "Wi-Fi Protected Setup State".
func wpsPresent(d []byte) bool {
	for p := 0; p+4 <= len(d); {
		t := binary.BigEndian.Uint16(d[p:])
		l := int(binary.BigEndian.Uint16(d[p+2:]))
		if t == wpsStateAttr {
			return true
		}
		p += 4 + l
	}
	return false
}

// Parse decodifica gli elementi di una rete. capability è il campo
// Capability Information del beacon (serve a riconoscere il WEP), freqMhz
// la frequenza del canale primario (serve a interpretare la larghezza).
func Parse(buf []byte, capability uint16, freqMhz int) (Info, error) {
	elems, err := Split(buf)
	var info Info
	var rsn, wpa *rsnInfo
	var htOp, vhtOp, heOp, ehtOp []byte
	for _, e := range elems {
		switch e.ID {
		case idSSID:
			info.SSID = string(e.Data)
		case idDSParams:
			if len(e.Data) >= 1 {
				info.DSChannel = int(e.Data[0])
			}
		case idCountry:
			if len(e.Data) >= 2 && isAlpha(e.Data[0]) && isAlpha(e.Data[1]) {
				info.Country = string(e.Data[:2])
			}
		case idBSSLoad:
			if len(e.Data) >= 3 {
				info.HasBSSLoad = true
				info.Stations = int(binary.LittleEndian.Uint16(e.Data))
				info.Utilization = int(e.Data[2])
			}
		case idHTCap:
			info.HT = true
		case idHTOp:
			info.HT = true
			htOp = e.Data
		case idVHTCap:
			info.VHT = true
		case idVHTOp:
			info.VHT = true
			vhtOp = e.Data
		case idRSN:
			if r, ok := parseRSN(e.Data, ouiIEEE); ok {
				rsn = &r
			}
		case idVendor:
			if len(e.Data) >= 4 && [3]byte{e.Data[0], e.Data[1], e.Data[2]} == ouiMicrosoft {
				switch e.Data[3] {
				case 1:
					if r, ok := parseRSN(e.Data[4:], ouiMicrosoft); ok {
						wpa = &r
					}
				case 4:
					info.Security.WPS = info.Security.WPS || wpsPresent(e.Data[4:])
				}
			}
		case idExtension:
			switch e.ExtID {
			case extHECap:
				info.HE = true
			case extHEOp:
				info.HE = true
				heOp = e.Data
			case extEHTCap:
				info.EHT = true
			case extEHTOp:
				info.EHT = true
				ehtOp = e.Data
			}
		}
	}
	info.Security = security(rsn, wpa, capability, info.Security.WPS)
	info.WidthMhz, info.CenterChannel = width(freqMhz, htOp, vhtOp, heOp, ehtOp)
	return info, err
}

func isAlpha(b byte) bool { return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') }

func contains(xs []string, vals ...string) bool {
	for _, x := range xs {
		for _, v := range vals {
			if x == v {
				return true
			}
		}
	}
	return false
}

func security(rsn, wpa *rsnInfo, capability uint16, wps bool) Security {
	s := Security{WPS: wps, PMF: "disabled", AKM: []string{}, Pairwise: []string{}}
	switch {
	case rsn != nil:
		s.AKM = rsn.akm
		if s.AKM == nil {
			s.AKM = []string{"802.1X"} // default dello standard se il campo manca
		}
		s.Pairwise = rsn.pairwise
		s.Group = rsn.group
		if wpa != nil {
			// Modalità mista WPA/WPA2: si riportano anche le cifrature WPA,
			// tipicamente TKIP, che abbassano la sicurezza effettiva.
			for _, c := range wpa.pairwise {
				if !contains(s.Pairwise, c) {
					s.Pairwise = append(s.Pairwise, c)
				}
			}
		}
		if rsn.hasCaps {
			switch {
			case rsn.caps&rsnCapMFPR != 0:
				s.PMF = "required"
			case rsn.caps&rsnCapMFPC != 0:
				s.PMF = "capable"
			}
		}
		sae := contains(s.AKM, "SAE", "FT-SAE", "SAE-EXT-KEY", "FT-SAE-EXT-KEY")
		psk := contains(s.AKM, "PSK", "FT-PSK", "PSK-SHA256")
		ent := contains(s.AKM, "802.1X", "FT-802.1X", "802.1X-SHA256", "FT-802.1X-SHA384")
		suiteB := contains(s.AKM, "802.1X-SuiteB", "802.1X-SuiteB-192")
		owe := contains(s.AKM, "OWE")
		switch {
		case sae && (psk || ent):
			s.Protocol = "wpa2/wpa3"
		case sae || suiteB:
			s.Protocol = "wpa3"
		case psk || ent:
			s.Protocol = "wpa2"
		case owe:
			s.Protocol = "owe"
		default:
			s.Protocol = "unknown"
		}
	case wpa != nil:
		s.Protocol = "wpa"
		s.AKM = wpa.akm
		if s.AKM == nil {
			s.AKM = []string{}
		}
		s.Pairwise = wpa.pairwise
		s.Group = wpa.group
	case capability&capPrivacy != 0:
		s.Protocol = "wep"
		s.Pairwise = []string{"WEP"}
	default:
		s.Protocol = "open"
	}
	return s
}

func chanOf(freqMhz int) int {
	switch {
	case freqMhz == 2484:
		return 14
	case freqMhz >= 2412 && freqMhz < 2484:
		return (freqMhz - 2407) / 5
	case freqMhz == 5935:
		return 2
	case freqMhz >= 5955:
		return (freqMhz - 5950) / 5
	case freqMhz >= 5000:
		return (freqMhz - 5000) / 5
	}
	return 0
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// width calcola larghezza effettiva e canale centrale dalle informazioni di
// operazione, dalla più recente alla più vecchia.
func width(freqMhz int, htOp, vhtOp, heOp, ehtOp []byte) (int, int) {
	primary := chanOf(freqMhz)
	is24 := freqMhz < 3000
	is6 := freqMhz >= 5925

	// EHT (Wi-Fi 7): parametro bit 0 = presenza dell'EHT Operation Information.
	if len(ehtOp) >= 8 && ehtOp[0]&0x01 != 0 {
		ctl := ehtOp[5] & 0x07
		ccfs0, ccfs1 := int(ehtOp[6]), int(ehtOp[7])
		switch ctl {
		case 4:
			return 320, ccfs1
		case 3:
			return 160, ccfs1
		case 2:
			return 80, ccfs0
		case 1:
			return 40, ccfs0
		case 0:
			return 20, 0
		}
	}

	// HE (Wi-Fi 6/6E): nel 6 GHz la larghezza sta nella 6 GHz Operation Information.
	if is6 && len(heOp) >= 6 {
		params := uint32(heOp[0]) | uint32(heOp[1])<<8 | uint32(heOp[2])<<16
		p := 6 // parametri (3) + BSS color (1) + basic HE-MCS (2)
		if params&(1<<14) != 0 {
			p += 3 // VHT Operation Information
		}
		if params&(1<<15) != 0 {
			p++ // Max Co-Hosted BSSID Indicator
		}
		if params&(1<<17) != 0 && p+5 <= len(heOp) {
			ctl := heOp[p+1] & 0x03
			ccfs0, ccfs1 := int(heOp[p+2]), int(heOp[p+3])
			switch ctl {
			case 3:
				if ccfs1 != 0 {
					return 160, ccfs1
				}
				return 160, ccfs0
			case 2:
				return 80, ccfs0
			case 1:
				return 40, ccfs0
			default:
				return 20, 0
			}
		}
	}

	// HT Operation: canale secondario e larghezza consentita.
	w, center := 20, 0
	if len(htOp) >= 2 {
		offset := htOp[1] & 0x03
		anyWidth := htOp[1]&0x04 != 0
		if anyWidth && offset == 1 {
			w, center = 40, primary+2
		} else if anyWidth && offset == 3 {
			w, center = 40, primary-2
		}
	}
	if is24 {
		return w, center
	}

	// VHT Operation (5 GHz), con la codifica moderna del 160 MHz su CCFS1.
	if len(vhtOp) >= 3 {
		cw := vhtOp[0]
		ccfs0, ccfs1 := int(vhtOp[1]), int(vhtOp[2])
		switch cw {
		case 1:
			switch {
			case ccfs1 == 0:
				return 80, ccfs0
			case abs(ccfs1-ccfs0) == 8:
				return 160, ccfs1
			default:
				return 160, ccfs0 // 80+80: due blocchi separati, si riporta il primo
			}
		case 2:
			return 160, ccfs0
		case 3:
			return 160, ccfs0
		}
	}
	return w, center
}

// Phy restituisce lo standard più recente annunciato dalla rete.
func (i Info) Phy(freqMhz int, maxRateMbps float64) string {
	switch {
	case i.EHT:
		return "802.11be"
	case i.HE:
		return "802.11ax"
	case i.VHT:
		return "802.11ac"
	case i.HT:
		return "802.11n"
	case freqMhz >= 5000:
		return "802.11a"
	case maxRateMbps > 11:
		return "802.11g"
	default:
		return "802.11b"
	}
}
