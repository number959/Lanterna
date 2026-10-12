//go:build windows

package winapi

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"lanterna/internal/netsh"
	"lanterna/internal/scan"
	"lanterna/internal/wlan"
)

// Native Wifi API (wlanapi.dll). Qui ci sono solo le chiamate di sistema:
// l'interpretazione dei byte restituiti è nel pacchetto wlan, collaudato
// con strutture costruite byte per byte.

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
	bssTypeAny          = 3
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

func guidOf(g [16]byte) windows.GUID { return *(*windows.GUID)(unsafe.Pointer(&g[0])) }

func enumInterfaces(h windows.Handle) ([]wlan.Interface, error) {
	var list *byte
	if err := call(procWlanEnumInterfaces, uintptr(h), 0, uintptr(unsafe.Pointer(&list))); err != nil {
		return nil, err
	}
	defer free(list)
	n := int(*(*uint32)(unsafe.Pointer(list)))
	return wlan.ParseInterfaceList(unsafe.Slice(list, 8+n*wlan.InterfaceInfoSize))
}

// query restituisce una copia dei dati, così la memoria di wlanapi si libera subito.
func query(h windows.Handle, g *windows.GUID, op uint32) ([]byte, error) {
	var size uint32
	var data *byte
	var vt uint32
	if err := call(procWlanQueryInterface, uintptr(h), uintptr(unsafe.Pointer(g)), uintptr(op), 0,
		uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&data)), uintptr(unsafe.Pointer(&vt))); err != nil {
		return nil, err
	}
	defer free(data)
	return append([]byte(nil), unsafe.Slice(data, size)...), nil
}

func connection(h windows.Handle, it wlan.Interface) (*scan.WifiConnection, uint32, error) {
	g := guidOf(it.GUID)
	b, err := query(h, &g, opCurrentConnection)
	if err != nil {
		return nil, 0, err
	}
	a, err := wlan.ParseConnection(b)
	if err != nil {
		return nil, 0, err
	}
	q := a.Quality
	c := &scan.WifiConnection{
		Interface: it.Description, SSID: a.SSID, BSSID: a.BSSID, Phy: wlan.PhyNames[a.PhyType], SignalQuality: &q,
		RxMbps: int(a.RxKbps / 1000), TxMbps: int(a.TxKbps / 1000), Auth: wlan.AuthNames[a.AuthAlgo], Cipher: wlan.CipherNames[a.CipherAlgo],
	}
	if ch, err := query(h, &g, opChannelNumber); err == nil && len(ch) >= 4 {
		c.Channel = int(*(*uint32)(unsafe.Pointer(&ch[0])))
	}
	if r, err := query(h, &g, opRssi); err == nil && len(r) >= 4 {
		if v := int(*(*int32)(unsafe.Pointer(&r[0]))); v < 0 && v > -120 {
			c.RssiDbm = &v
		}
	}
	return c, a.AuthAlgo, nil
}

func bssList(h windows.Handle, it wlan.Interface) ([]scan.Bss, error) {
	g := guidOf(it.GUID)
	var list *byte
	if err := call(procWlanGetBssList, uintptr(h), uintptr(unsafe.Pointer(&g)), 0, bssTypeAny, 0, 0, uintptr(unsafe.Pointer(&list))); err != nil {
		return nil, err
	}
	defer free(list)
	total := int(*(*uint32)(unsafe.Pointer(list)))
	return wlan.ParseBssList(unsafe.Slice(list, total))
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
		if x.State == wlan.StateConnected {
			it = x
			break
		}
	}
	if rescan {
		g := guidOf(it.GUID)
		if err := call(procWlanScan, uintptr(h), uintptr(unsafe.Pointer(&g)), 0, 0, 0); err == nil {
			select {
			case <-time.After(4 * time.Second):
			case <-ctx.Done():
			}
		}
	}
	var auth uint32
	if it.State == wlan.StateConnected {
		c, a, err := connection(h, it)
		if err != nil {
			data.Error = err.Error()
		} else {
			data.Connected, auth = c, a
		}
	}
	if nets, err := bssList(h, it); err != nil {
		data.Error = err.Error()
	} else {
		data.Networks = nets
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
			bs := scan.Bss{SSID: c.SSID, BSSID: c.BSSID, FreqMhz: wlan.ChannelToFreq(c.Channel, band), Channel: c.Channel, Band: band, Phy: c.Phy, Connected: true}
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
			bs.Security = &scan.WifiSecurity{Protocol: wlan.ProtocolFromAuth(auth), AKM: []string{}, Pairwise: pairwise}
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
