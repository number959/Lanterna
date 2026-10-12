//go:build windows

package winapi

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"lanterna/internal/ie"
	"lanterna/internal/netsh"
	"lanterna/internal/scan"
)

// Native Wifi API (wlanapi.dll). Le strutture restituite vengono lette come
// byte agli offset documentati in wlanapi.h, identici su x64 e ARM64.

var (
	wlanapi                = windows.NewLazySystemDLL("wlanapi.dll")
	procWlanOpenHandle     = wlanapi.NewProc("WlanOpenHandle")
	procWlanCloseHandle    = wlanapi.NewProc("WlanCloseHandle")
	procWlanEnumInterfaces = wlanapi.NewProc("WlanEnumInterfaces")
	procWlanQueryInterface = wlanapi.NewProc("WlanQueryInterface")
	procWlanGetBssList     = wlanapi.NewProc("WlanGetNetworkBssList")
	procWlanScan           = wlanapi.NewProc("WlanScan")
	procWlanFreeMemory     = wlanapi.NewProc("WlanFreeMemory")
)

const (
	opCurrentConnection = 7
	opChannelNumber     = 8
	opRssi              = 0x10000102
	stateConnected      = 1
	bssTypeAny          = 3

	ifaceInfoSize = 532 // WLAN_INTERFACE_INFO
	bssEntrySize  = 360 // WLAN_BSS_ENTRY
)

// LocationHint spiega come sbloccare l'accesso ai dati Wi-Fi su Windows 11 24H2+.
const LocationHint = "Windows richiede il permesso di posizione per leggere le reti Wi-Fi: apri Impostazioni > Privacy e sicurezza > Posizione e attiva \"Servizi di localizzazione\" e \"Consenti alle app desktop di accedere alla posizione\", poi ripeti l'analisi."

type wlanErr uint32

func (e wlanErr) Error() string {
	switch uint32(e) {
	case uint32(windows.ERROR_ACCESS_DENIED):
		return LocationHint
	case uint32(windows.ERROR_SERVICE_NOT_ACTIVE):
		return "il servizio Configurazione automatica WLAN (WlanSvc) non è attivo"
	case uint32(windows.ERROR_NOT_FOUND):
		return "scheda Wi-Fi non trovata"
	}
	return fmt.Sprintf("errore Wi-Fi %d: %v", uint32(e), windows.Errno(e))
}

func call(p *windows.LazyProc, args ...uintptr) error {
	if err := p.Find(); err != nil {
		return fmt.Errorf("wlanapi.dll non disponibile: %w", err)
	}
	r, _, _ := p.Call(args...)
	if r != 0 {
		return wlanErr(r)
	}
	return nil
}

func free(p *byte) {
	if p != nil {
		procWlanFreeMemory.Call(uintptr(unsafe.Pointer(p)))
	}
}

func u32(b []byte, off int) uint32 { return binary.LittleEndian.Uint32(b[off:]) }

func utf16z(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return windows.UTF16ToString(u)
}

func macString(b []byte) string {
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02x", x)
	}
	return strings.Join(parts, ":")
}

type wlanIface struct {
	guid        windows.GUID
	description string
	state       uint32
}

var phyNames = map[uint32]string{4: "802.11a", 5: "802.11b", 6: "802.11g", 7: "802.11n", 8: "802.11ac", 9: "802.11ad", 10: "802.11ax", 11: "802.11be"}

var authNames = map[uint32]string{
	1: "Aperta", 2: "WEP condivisa", 3: "WPA-Enterprise", 4: "WPA-Personal", 6: "WPA2-Enterprise",
	7: "WPA2-Personal", 8: "WPA3-Enterprise 192", 9: "WPA3-Personal", 10: "OWE", 11: "WPA3-Enterprise",
}

var cipherNames = map[uint32]string{0: "nessuna", 1: "WEP-40", 2: "TKIP", 4: "CCMP", 5: "WEP-104", 8: "GCMP", 9: "GCMP-256", 10: "CCMP-256", 0x101: "WEP"}

// protocolFromAuth serve quando la rete collegata non compare nella scansione.
func protocolFromAuth(auth uint32) string {
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

func bandOf(freq int) string {
	switch {
	case freq < 3000:
		return "2.4"
	case freq >= 5925:
		return "6"
	}
	return "5"
}

func chanToFreq(ch int, band string) int {
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

func enumInterfaces(h windows.Handle) ([]wlanIface, error) {
	var list *byte
	if err := call(procWlanEnumInterfaces, uintptr(h), 0, uintptr(unsafe.Pointer(&list))); err != nil {
		return nil, err
	}
	defer free(list)
	n := int(*(*uint32)(unsafe.Pointer(list)))
	b := unsafe.Slice(list, 8+n*ifaceInfoSize)
	out := make([]wlanIface, 0, n)
	for i := 0; i < n; i++ {
		e := b[8+i*ifaceInfoSize:]
		var it wlanIface
		it.guid = *(*windows.GUID)(unsafe.Pointer(&e[0]))
		it.description = utf16z(e[16 : 16+512])
		it.state = u32(e, 528)
		out = append(out, it)
	}
	return out, nil
}

func query(h windows.Handle, g *windows.GUID, op uint32) ([]byte, func(), error) {
	var size uint32
	var data *byte
	var vt uint32
	if err := call(procWlanQueryInterface, uintptr(h), uintptr(unsafe.Pointer(g)), uintptr(op), 0,
		uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&data)), uintptr(unsafe.Pointer(&vt))); err != nil {
		return nil, func() {}, err
	}
	return unsafe.Slice(data, size), func() { free(data) }, nil
}

func connection(h windows.Handle, it wlanIface) (*scan.WifiConnection, uint32, error) {
	b, release, err := query(h, &it.guid, opCurrentConnection)
	if err != nil {
		return nil, 0, err
	}
	defer release()
	if len(b) < 604 {
		return nil, 0, errors.New("risposta WLAN_CONNECTION_ATTRIBUTES troppo corta")
	}
	ssidLen := int(u32(b, 520))
	if ssidLen > 32 {
		ssidLen = 32
	}
	c := &scan.WifiConnection{
		Interface: it.description,
		SSID:      string(b[524 : 524+ssidLen]),
		BSSID:     macString(b[560:566]),
		Phy:       phyNames[u32(b, 568)],
		RxMbps:    int(u32(b, 580) / 1000),
		TxMbps:    int(u32(b, 584) / 1000),
	}
	q := int(u32(b, 576))
	c.SignalQuality = &q
	auth := u32(b, 596)
	c.Auth = authNames[auth]
	c.Cipher = cipherNames[u32(b, 600)]
	if ch, rel, err := query(h, &it.guid, opChannelNumber); err == nil && len(ch) >= 4 {
		c.Channel = int(u32(ch, 0))
		rel()
	}
	if r, rel, err := query(h, &it.guid, opRssi); err == nil && len(r) >= 4 {
		v := int(int32(u32(r, 0)))
		if v < 0 && v > -120 {
			c.RssiDbm = &v
		}
		rel()
	}
	return c, auth, nil
}

func bssList(h windows.Handle, it wlanIface) ([]scan.Bss, error) {
	var list *byte
	if err := call(procWlanGetBssList, uintptr(h), uintptr(unsafe.Pointer(&it.guid)), 0, bssTypeAny, 0, 0, uintptr(unsafe.Pointer(&list))); err != nil {
		return nil, err
	}
	defer free(list)
	total := int(*(*uint32)(unsafe.Pointer(list)))
	b := unsafe.Slice(list, total)
	n := int(u32(b, 4))
	out := make([]scan.Bss, 0, n)
	for i := 0; i < n; i++ {
		off := 8 + i*bssEntrySize
		if off+bssEntrySize > total {
			break
		}
		e := b[off : off+bssEntrySize]
		ssidLen := int(u32(e, 0))
		if ssidLen > 32 {
			ssidLen = 32
		}
		freq := int(u32(e, 92) / 1000)
		if freq == 0 {
			continue
		}
		var maxRate float64
		rl := int(u32(e, 96)) / 2
		for k := 0; k < rl && k < 126; k++ {
			r := float64(binary.LittleEndian.Uint16(e[100+2*k:])&0x7fff) / 2
			if r > maxRate {
				maxRate = r
			}
		}
		capInfo := binary.LittleEndian.Uint16(e[88:])
		ieOff, ieSize := int(u32(e, 352)), int(u32(e, 356))
		var ies []byte
		if ieOff > 0 && off+ieOff+ieSize <= total {
			ies = b[off+ieOff : off+ieOff+ieSize]
		}
		info, _ := ie.Parse(ies, capInfo, freq)
		band := bandOf(freq)
		bs := scan.Bss{
			SSID:     string(e[4 : 4+ssidLen]),
			BSSID:    macString(e[40:46]),
			RssiDbm:  int(int32(u32(e, 56))),
			FreqMhz:  freq,
			Channel:  chanOf(freq),
			Band:     band,
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
			bs.Security.PMF = ""
		}
		out = append(out, bs)
	}
	return out, nil
}

func chanOf(freq int) int {
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

// Wifi legge la connessione attuale e le reti visibili. Con rescan chiede
// prima alla scheda una scansione aggiornata (circa 4 secondi).
func Wifi(ctx context.Context, rescan bool) (*scan.WifiData, error) {
	var neg uint32
	var h windows.Handle
	if err := call(procWlanOpenHandle, 2, 0, uintptr(unsafe.Pointer(&neg)), uintptr(unsafe.Pointer(&h))); err != nil {
		return wifiFromNetsh(ctx, err)
	}
	defer procWlanCloseHandle.Call(uintptr(h), 0)
	ifaces, err := enumInterfaces(h)
	if err != nil {
		return nil, err
	}
	data := &scan.WifiData{Source: "wlanapi", Networks: []scan.Bss{}}
	if len(ifaces) == 0 {
		data.Error = "nessuna scheda Wi-Fi presente"
		return data, nil
	}
	// Si usa la prima scheda collegata, altrimenti la prima disponibile.
	it := ifaces[0]
	for _, x := range ifaces {
		if x.state == stateConnected {
			it = x
			break
		}
	}
	if rescan {
		if err := call(procWlanScan, uintptr(h), uintptr(unsafe.Pointer(&it.guid)), 0, 0, 0); err == nil {
			select {
			case <-time.After(4 * time.Second):
			case <-ctx.Done():
			}
		}
	}
	var auth uint32
	if it.state == stateConnected {
		c, a, err := connection(h, it)
		if err != nil {
			data.Error = err.Error()
		} else {
			data.Connected, auth = c, a
		}
	}
	nets, err := bssList(h, it)
	if err != nil {
		data.Error = err.Error()
	}
	data.Networks = nets
	if data.Networks == nil {
		data.Networks = []scan.Bss{}
	}
	if c := data.Connected; c != nil {
		found := false
		for i := range data.Networks {
			n := &data.Networks[i]
			if strings.EqualFold(n.BSSID, c.BSSID) {
				n.Connected, found = true, true
				c.Band, c.Channel, c.WidthMhz = n.Band, n.Channel, n.WidthMhz
				if c.RssiDbm == nil {
					v := n.RssiDbm
					c.RssiDbm = &v
				}
			}
		}
		if !found && c.Channel > 0 {
			// La rete collegata non è nella scansione (permessi o scansione
			// incompleta): la si aggiunge con i dati della connessione, senza
			// inventare la larghezza di canale (0 = sconosciuta).
			band := "2.4"
			if c.Channel > 14 {
				band = "5"
			}
			c.Band = band
			bs := scan.Bss{SSID: c.SSID, BSSID: c.BSSID, FreqMhz: chanToFreq(c.Channel, band), Channel: c.Channel, Band: band, Phy: c.Phy, Connected: true}
			switch {
			case c.RssiDbm != nil:
				bs.RssiDbm = *c.RssiDbm
			case c.SignalQuality != nil:
				bs.RssiDbm = *c.SignalQuality/2 - 100
			}
			pairwise := []string{}
			if c.Cipher != "" && c.Cipher != "nessuna" {
				pairwise = []string{c.Cipher}
			}
			bs.Security = &scan.WifiSecurity{Protocol: protocolFromAuth(auth), AKM: []string{}, Pairwise: pairwise}
			data.Networks = append(data.Networks, bs)
		}
	}
	return data, nil
}

// wifiFromNetsh è la riserva quando wlanapi.dll non è utilizzabile.
func wifiFromNetsh(ctx context.Context, apiErr error) (*scan.WifiData, error) {
	out, err := runHidden(ctx, 10*time.Second, "cmd.exe", "/c", "chcp 65001 >nul & netsh wlan show interfaces")
	if err != nil && out == "" {
		return nil, fmt.Errorf("%v; netsh: %v", apiErr, err)
	}
	if netsh.LocationDenied(out) {
		return &scan.WifiData{Source: "netsh", Networks: []scan.Bss{}, Error: LocationHint}, nil
	}
	data := &scan.WifiData{Source: "netsh", Networks: []scan.Bss{}}
	ifs := netsh.ParseInterfaces(out)
	if len(ifs) == 0 {
		data.Error = "nessuna scheda Wi-Fi presente"
		return data, nil
	}
	c := netsh.Connected(ifs)
	if c == nil {
		return data, nil
	}
	data.Connected = &scan.WifiConnection{
		Interface: c.Description, SSID: c.SSID, BSSID: c.BSSID, SignalQuality: c.SignalPct, RssiDbm: c.RssiDbm,
		RxMbps: int(c.RxMbps), TxMbps: int(c.TxMbps), Phy: c.Radio, Band: c.Band, Channel: c.Channel, Auth: c.Auth, Cipher: c.Cipher,
	}
	return data, nil
}
