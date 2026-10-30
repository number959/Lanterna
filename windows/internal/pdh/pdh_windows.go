//go:build windows

package pdh

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	dll                              = windows.NewLazySystemDLL("pdh.dll")
	procPdhOpenQueryW                = dll.NewProc("PdhOpenQueryW")
	procPdhAddEnglishCounterW        = dll.NewProc("PdhAddEnglishCounterW")
	procPdhCollectQueryData          = dll.NewProc("PdhCollectQueryData")
	procPdhGetFormattedCounterArrayW = dll.NewProc("PdhGetFormattedCounterArrayW")
	procPdhGetFormattedCounterValue  = dll.NewProc("PdhGetFormattedCounterValue")
	procPdhCloseQuery                = dll.NewProc("PdhCloseQuery")
)

const (
	fmtDouble        = 0x00000200
	fmtNoCap100      = 0x00008000 // le prestazioni superano 100 % in turbo
	moreData         = 0x800007D2
	cstatusValidData = 0x00000000
	cstatusNewData   = 0x00000001

	// PDH_FMT_COUNTERVALUE_ITEM_W: puntatore al nome, poi PDH_FMT_COUNTERVALUE
	// (CStatus a 4 byte e un'unione da 8 byte allineata a 8). Sono 24 byte con
	// lo stato a +8 e il valore a +16 su 386, amd64 e arm64.
	itemSize  = 24
	statusOff = 8
	doubleOff = 16
)

// Query raccoglie insieme i valori di più contatori.
type Query struct {
	h uintptr
	// wild: contatori con il carattere jolly, letti istanza per istanza.
	wild map[Counter]bool
}

// Open apre una query vuota.
func Open() (*Query, error) {
	if err := dll.Load(); err != nil {
		return nil, ErrUnavailable
	}
	var h uintptr
	if r, _, _ := procPdhOpenQueryW.Call(0, 0, uintptr(unsafe.Pointer(&h))); r != 0 {
		return nil, &Error{"PdhOpenQuery", uint32(r)}
	}
	return &Query{h: h, wild: map[Counter]bool{}}, nil
}

// Add aggiunge un contatore per percorso inglese, per esempio
// `\Processor Information(*)\% Processor Time`.
func (q *Query) Add(path string) (Counter, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var c uintptr
	if r, _, _ := procPdhAddEnglishCounterW.Call(q.h, uintptr(unsafe.Pointer(p)), 0, uintptr(unsafe.Pointer(&c))); r != 0 {
		return 0, &Error{"PdhAddEnglishCounter", uint32(r)}
	}
	q.wild[Counter(c)] = strings.Contains(path, "(*)")
	return Counter(c), nil
}

// Collect raccoglie un campione di tutti i contatori. I contatori "di
// rapporto" (percentuali, byte al secondo) hanno un valore solo dalla seconda
// raccolta in poi.
func (q *Query) Collect() error {
	if r, _, _ := procPdhCollectQueryData.Call(q.h); r != 0 {
		return &Error{"PdhCollectQueryData", uint32(r)}
	}
	return nil
}

// Values restituisce il valore di ogni istanza del contatore nell'ultima
// raccolta; le istanze senza un valore valido (per esempio appena comparse)
// mancano. Per un contatore senza carattere jolly la chiave è "".
func (q *Query) Values(c Counter) (map[string]float64, error) {
	const format = fmtDouble | fmtNoCap100
	if !q.wild[c] {
		// PDH_FMT_COUNTERVALUE: CStatus a +0, il double a +8 su tutte le
		// architetture (il campo di riempimento lo tiene lì anche su 386).
		var v struct {
			status uint32
			_      uint32
			value  float64
		}
		if r, _, _ := procPdhGetFormattedCounterValue.Call(uintptr(c), format, 0, uintptr(unsafe.Pointer(&v))); r != 0 {
			return nil, &Error{"PdhGetFormattedCounterValue", uint32(r)}
		}
		switch v.status {
		case cstatusValidData, cstatusNewData:
			return map[string]float64{"": v.value}, nil
		}
		return map[string]float64{}, nil
	}
	var size, count uint32
	r, _, _ := procPdhGetFormattedCounterArrayW.Call(uintptr(c), format, uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&count)), 0)
	if uint32(r) != moreData {
		return nil, &Error{"PdhGetFormattedCounterArray", uint32(r)}
	}
	if size == 0 || count == 0 {
		return map[string]float64{}, nil
	}
	buf := make([]byte, size)
	r, _, _ = procPdhGetFormattedCounterArrayW.Call(uintptr(c), format, uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&buf[0])))
	if r != 0 {
		return nil, &Error{"PdhGetFormattedCounterArray", uint32(r)}
	}
	out := make(map[string]float64, count)
	for k := uint32(0); k < count; k++ {
		off := int(k) * itemSize
		if off+itemSize > len(buf) {
			break
		}
		item := unsafe.Pointer(&buf[off])
		// I nomi stanno nello stesso buffer, dopo gli elementi.
		var name string
		if p := *(**uint16)(item); p != nil {
			name = windows.UTF16PtrToString(p)
		}
		switch *(*uint32)(unsafe.Add(item, statusOff)) {
		case cstatusValidData, cstatusNewData:
			out[name] = *(*float64)(unsafe.Add(item, doubleOff))
		}
	}
	return out, nil
}

// Close chiude la query e libera i contatori.
func (q *Query) Close() {
	if q.h != 0 {
		procPdhCloseQuery.Call(q.h)
		q.h = 0
	}
}
