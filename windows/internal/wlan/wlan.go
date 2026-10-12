// Package wlan interpreta le strutture restituite dalla Native Wifi API di
// Windows (wlanapi.h) a partire dai loro byte. È separato dalle chiamate di
// sistema per poterlo collaudare ovunque con buffer costruiti a mano.
//
// Gli offset sono stati verificati stampando offsetof/sizeof dagli header
// ufficiali (mingw-w64) in un programma eseguito sotto Wine: vedi
// docs/VERIFICHE.md. Sono identici su x64 e ARM64.
package wlan

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"

	"lanterna/internal/ie"
	"lanterna/internal/scan"
)

const (
	InterfaceInfoSize   = 532 // sizeof(WLAN_INTERFACE_INFO)
	ConnectionAttrsSize = 604 // sizeof(WLAN_CONNECTION_ATTRIBUTES)
	BssEntrySize        = 360 // sizeof(WLAN_BSS_ENTRY)
	listHeader          = 8   // offsetof(WLAN_*_LIST, primo elemento)

	StateConnected = 1 // wlan_interface_state_connected
)

func u32(b []byte, off int) uint32 { return binary.LittleEndian.Uint32(b[off:]) }

// MAC formatta un indirizzo in minuscolo con i due punti.
func MAC(b []byte) string {
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02x", x)
	}
	return strings.Join(parts, ":")
}

func utf16z(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
		if u[i] == 0 {
			u = u[:i]
			break
		}
	}
	return string(utf16.Decode(u))
}

func ssid(b []byte) string {
	n := int(u32(b, 0))
	if n > 32 {
		n = 32
	}
	return string(b[4 : 4+n])
}

// Interface è un elemento di WLAN_INTERFACE_INFO_LIST.
type Interface struct {
	GUID        [16]byte
	Description string
	State       uint32
}

// ParseInterfaceList legge WLAN_INTERFACE_INFO_LIST.
func ParseInterfaceList(b []byte) ([]Interface, error) {
	if len(b) < listHeader {
		return nil, errors.New("WLAN_INTERFACE_INFO_LIST troppo corta")
	}
	n := int(u32(b, 0))
	if listHeader+n*InterfaceInfoSize > len(b) {
		return nil, fmt.Errorf("WLAN_INTERFACE_INFO_LIST: %d schede dichiarate, buffer di %d byte", n, len(b))
	}
	out := make([]Interface, n)
	for i := range out {
		e := b[listHeader+i*InterfaceInfoSize:]
		copy(out[i].GUID[:], e[0:16])
		out[i].Description = utf16z(e[16 : 16+512])
		out[i].State = u32(e, 528)
	}
	return out, nil
}

// Connection è il contenuto utile di WLAN_CONNECTION_ATTRIBUTES.
type Connection struct {
	SSID, BSSID string
	PhyType     uint32
	Quality     int
	RxKbps      uint32
	TxKbps      uint32
	AuthAlgo    uint32
	CipherAlgo  uint32
}

// ParseConnection legge WLAN_CONNECTION_ATTRIBUTES.
func ParseConnection(b []byte) (Connection, error) {
	if len(b) < ConnectionAttrsSize {
		return Connection{}, fmt.Errorf("WLAN_CONNECTION_ATTRIBUTES di %d byte invece di %d", len(b), ConnectionAttrsSize)
	}
	const assoc, sec = 520, 588
	return Connection{
		SSID:       ssid(b[assoc:]),
		BSSID:      MAC(b[assoc+40 : assoc+46]),
		PhyType:    u32(b, assoc+48),
		Quality:    int(u32(b, assoc+56)),
		RxKbps:     u32(b, assoc+60),
		TxKbps:     u32(b, assoc+64),
		AuthAlgo:   u32(b, sec+8),
		CipherAlgo: u32(b, sec+12),
	}, nil
}

var PhyNames = map[uint32]string{4: "802.11a", 5: "802.11b", 6: "802.11g", 7: "802.11n", 8: "802.11ac", 9: "802.11ad", 10: "802.11ax", 11: "802.11be"}

var AuthNames = map[uint32]string{
	1: "Aperta", 2: "WEP condivisa", 3: "WPA-Enterprise", 4: "WPA-Personal", 6: "WPA2-Enterprise",
	7: "WPA2-Personal", 8: "WPA3-Enterprise 192", 9: "WPA3-Personal", 10: "OWE", 11: "WPA3-Enterprise",
}

var CipherNames = map[uint32]string{0: "nessuna", 1: "WEP-40", 2: "TKIP", 4: "CCMP", 5: "WEP-104", 8: "GCMP", 9: "GCMP-256", 10: "CCMP-256", 0x101: "WEP"}

// ProtocolFromAuth serve quando la rete collegata non compare nella scansione.
func ProtocolFromAuth(auth uint32) string {
	switch auth {
	case 1:
		return "open"
	case 2:
		return "wep"
	case 3, 4:
		return "wpa"
	case 6, 7:
		return "wpa2"
	case 8, 9, 11:
		return "wpa3"
	case 10:
		return "owe"
	}
	return "unknown"
}

func BandOf(freq int) string {
	switch {
	case freq < 3000:
		return "2.4"
	case freq >= 5925:
		return "6"
	}
	return "5"
}

func ChannelOf(freq int) int {
	switch {
	case freq == 2484:
		return 14
	case freq >= 2412 && freq < 2484:
		return (freq - 2407) / 5
	case freq == 5935:
		return 2
	case freq >= 5955:
		return (freq - 5950) / 5
	}
	return (freq - 5000) / 5
}

func ChannelToFreq(ch int, band string) int {
	switch band {
	case "2.4":
		if ch == 14 {
			return 2484
		}
		return 2407 + 5*ch
	case "6":
		return 5950 + 5*ch
	}
	return 5000 + 5*ch
}

// ParseBssList legge WLAN_BSS_LIST e decodifica gli Information Element di
// ogni rete. Le voci con dati incoerenti vengono saltate, non fanno fallire
// l'intera lista.
func ParseBssList(b []byte) ([]scan.Bss, error) {
	if len(b) < listHeader {
		return nil, errors.New("WLAN_BSS_LIST troppo corta")
	}
	total := int(u32(b, 0))
	if total > len(b) {
		total = len(b)
	}
	n := int(u32(b, 4))
	out := make([]scan.Bss, 0, n)
	for i := 0; i < n; i++ {
		off := listHeader + i*BssEntrySize
		if off+BssEntrySize > total {
			break
		}
		e := b[off : off+BssEntrySize]
		freq := int(u32(e, 92) / 1000) // ulChCenterFrequency è in kHz
		if freq == 0 {
			continue
		}
		var maxRate float64
		rates := int(u32(e, 96)) / 2 // uRateSetLength è in byte
		for k := 0; k < rates && k < 126; k++ {
			// Unità da 500 kbit/s; il bit 15 segnala le velocità "di base".
			r := float64(binary.LittleEndian.Uint16(e[100+2*k:])&0x7fff) / 2
			if r > maxRate {
				maxRate = r
			}
		}
		capInfo := binary.LittleEndian.Uint16(e[88:])
		ieOff, ieSize := int(u32(e, 352)), int(u32(e, 356)) // offset relativo all'inizio della voce
		var ies []byte
		if ieOff >= BssEntrySize && ieSize > 0 && off+ieOff+ieSize <= total {
			ies = b[off+ieOff : off+ieOff+ieSize]
		}
		info, _ := ie.Parse(ies, capInfo, freq)
		bs := scan.Bss{
			SSID:     ssid(e),
			BSSID:    MAC(e[40:46]),
			RssiDbm:  int(int32(u32(e, 56))),
			FreqMhz:  freq,
			Channel:  ChannelOf(freq),
			Band:     BandOf(freq),
			WidthMhz: info.WidthMhz,
			Phy:      info.Phy(freq, maxRate),
			Country:  info.Country,
		}
		if bs.WidthMhz == 0 {
			bs.WidthMhz = 20
		}
		if info.CenterChannel != 0 && info.CenterChannel != bs.Channel {
			bs.CenterChannel = info.CenterChannel
		}
		if info.HasBSSLoad {
			bs.BssLoad = &scan.BssLoad{Stations: info.Stations, UtilizationPct: (info.Utilization*100 + 127) / 255}
		}
		s := info.Security
		bs.Security = &scan.WifiSecurity{Protocol: s.Protocol, AKM: s.AKM, Pairwise: s.Pairwise, Group: s.Group, PMF: s.PMF, WPS: s.WPS}
		if s.Protocol == "open" || s.Protocol == "wep" || s.Protocol == "wpa" {
			bs.Security.PMF = "" // la PMF non esiste senza RSN
		}
		out = append(out, bs)
	}
	return out, nil
}
