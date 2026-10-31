//go:build windows

package winapi

import (
	"errors"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"lanterna/internal/scan"
	"lanterna/internal/wlan"
)

// Primitive di wlanapi per la mappa del Wi-Fi per stanza: un handle che resta
// aperto per tutta la misura e letture della connessione di una scheda
// precisa (identificata dal GUID), una al secondo. Solo letture: nessuna
// impostazione della scheda viene cambiata (niente background_scan_enabled
// né media_streaming_mode).

// ErrWlanNotConnected: la scheda non è collegata (o si sta ricollegando).
var ErrWlanNotConnected = errors.New("scheda Wi-Fi non collegata")

// WlanSession è un handle di wlanapi per una misura; va chiuso con Close.
type WlanSession struct{ h windows.Handle }

// OpenWlan apre l'handle del servizio WLAN.
func OpenWlan() (*WlanSession, error) {
	var neg uint32
	var h windows.Handle
	if err := call(procWlanOpenHandle, 2, 0, uintptr(unsafe.Pointer(&neg)), uintptr(unsafe.Pointer(&h))); err != nil {
		return nil, err
	}
	return &WlanSession{h: h}, nil
}

// Close chiude l'handle.
func (s *WlanSession) Close() { procWlanCloseHandle.Call(uintptr(s.h), 0) }

// Interfaces elenca le schede Wi-Fi.
func (s *WlanSession) Interfaces() ([]wlan.Interface, error) { return enumInterfaces(s.h) }

// WlanLink è una lettura della connessione: attributi, canale e segnale in dBm.
type WlanLink struct {
	wlan.Connection
	Channel int
	RssiDbm *int
}

// Link legge la connessione della scheda guid. Senza il permesso di
// posizione (Windows 11 24H2 e successivi) l'errore è LocationHint.
func (s *WlanSession) Link(guid [16]byte) (WlanLink, error) {
	g := guidOf(guid)
	b, err := query(s.h, &g, opCurrentConnection)
	if err != nil {
		var we wlanErr
		if errors.As(err, &we) && (uint32(we) == uint32(windows.ERROR_INVALID_STATE) || uint32(we) == uint32(windows.ERROR_NOT_FOUND)) {
			return WlanLink{}, ErrWlanNotConnected
		}
		return WlanLink{}, err
	}
	a, err := wlan.ParseConnection(b)
	if err != nil {
		return WlanLink{}, err
	}
	if a.State != wlan.StateConnected {
		return WlanLink{}, ErrWlanNotConnected
	}
	l := WlanLink{Connection: a}
	if ch, err := query(s.h, &g, opChannelNumber); err == nil && len(ch) >= 4 {
		l.Channel = int(*(*uint32)(unsafe.Pointer(&ch[0])))
	}
	if r, err := query(s.h, &g, opRssi); err == nil && len(r) >= 4 {
		if v := int(*(*int32)(unsafe.Pointer(&r[0]))); v < 0 && v > -120 {
			l.RssiDbm = &v
		}
	}
	return l, nil
}

// Scan chiede alla scheda una scansione e torna subito: la scheda ha fino a
// 4 secondi per completarla.
func (s *WlanSession) Scan(guid [16]byte) error {
	g := guidOf(guid)
	return call(procWlanScan, uintptr(s.h), uintptr(unsafe.Pointer(&g)), 0, 0, 0)
}

// BssList legge le reti note alla scheda e, per ciascuna, quando l'ha sentita.
func (s *WlanSession) BssList(guid [16]byte) ([]scan.Bss, []wlan.BssTime, error) {
	g := guidOf(guid)
	var list *byte
	if err := call(procWlanGetBssList, uintptr(s.h), uintptr(unsafe.Pointer(&g)), 0, bssTypeAny, 0, 0, uintptr(unsafe.Pointer(&list))); err != nil {
		return nil, nil, err
	}
	defer free(list)
	buf := unsafe.Slice(list, int(*(*uint32)(unsafe.Pointer(list))))
	nets, err := wlan.ParseBssList(buf)
	if err != nil {
		return nil, nil, err
	}
	times, _ := wlan.ParseBssTimes(buf)
	return nets, times, nil
}

// InterfaceGateway restituisce il primo gateway IPv4 della scheda di rete con
// questo GUID ("" se non ne ha). Il GUID della scheda Wi-Fi è lo stesso che
// GetAdaptersAddresses riporta come AdapterName.
func InterfaceGateway(guid [16]byte) string {
	first, err := getAdapters(windows.AF_INET, gaaSkipAnycast|gaaSkipMulticast|gaaIncludeGateways)
	if err != nil {
		return ""
	}
	want := guidOf(guid).String()
	for a := first; a != nil; a = a.Next {
		if !strings.EqualFold(windows.BytePtrToString(a.AdapterName), want) {
			continue
		}
		for gw := a.FirstGatewayAddress; gw != nil; gw = gw.Next {
			if ip := gw.Address.IP(); ip != nil && ip.To4() != nil && !ip.IsUnspecified() {
				return ip.String()
			}
		}
	}
	return ""
}
