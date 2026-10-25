//go:build windows

package cpuclock

import (
	"fmt"
	"math"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	pdh                              = windows.NewLazySystemDLL("pdh.dll")
	procPdhOpenQueryW                = pdh.NewProc("PdhOpenQueryW")
	procPdhAddEnglishCounterW        = pdh.NewProc("PdhAddEnglishCounterW")
	procPdhCollectQueryData          = pdh.NewProc("PdhCollectQueryData")
	procPdhGetFormattedCounterArrayW = pdh.NewProc("PdhGetFormattedCounterArrayW")
	procPdhCloseQuery                = pdh.NewProc("PdhCloseQuery")
)

const (
	pdhFmtDouble        = 0x00000200
	pdhFmtNoCap100      = 0x00008000 // le prestazioni superano 100 % in turbo
	pdhMoreData         = 0x800007D2
	pdhCstatusValidData = 0x00000000
	pdhCstatusNewData   = 0x00000001

	// PDH_FMT_COUNTERVALUE_ITEM_W: puntatore al nome, poi PDH_FMT_COUNTERVALUE
	// (CStatus a 4 byte e un'unione da 8 byte allineata a 8). Sono 24 byte con
	// lo stato a +8 e il valore a +16 su 386, amd64 e arm64.
	itemSize  = 24
	statusOff = 8
	doubleOff = 16
)

// Percorsi in inglese: PdhAddEnglishCounterW li accetta con Windows in
// qualunque lingua (i nomi localizzati cambiano, per esempio, in italiano).
const (
	pathPerf = `\Processor Information(*)\% Processor Performance`
	pathFreq = `\Processor Information(*)\Processor Frequency`
	pathLoad = `\Processor Information(*)\% Processor Time`
)

type pdhSource struct {
	query            uintptr
	perf, freq, load uintptr
}

func pdhErr(op string, r uintptr) error {
	return fmt.Errorf("%s: errore PDH 0x%08X", op, uint32(r))
}

// New prepara la lettura della frequenza, con la frequenza nominale scritta
// da Windows nel registro come riserva.
func New() *Sampler {
	return &Sampler{Open: Open, Fallback: registryMHz()}
}

func registryMHz() float64 {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\CentralProcessor\0`, registry.QUERY_VALUE)
	if err != nil {
		return 0
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("~MHz")
	if err != nil {
		return 0
	}
	return float64(v)
}

// Open apre i contatori delle prestazioni del processore.
func Open() (Source, error) {
	if err := pdh.Load(); err != nil {
		return nil, ErrUnavailable
	}
	var q uintptr
	if r, _, _ := procPdhOpenQueryW.Call(0, 0, uintptr(unsafe.Pointer(&q))); r != 0 {
		return nil, pdhErr("PdhOpenQuery", r)
	}
	s := &pdhSource{query: q}
	add := func(path string, h *uintptr) error {
		p, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return err
		}
		if r, _, _ := procPdhAddEnglishCounterW.Call(q, uintptr(unsafe.Pointer(p)), 0, uintptr(unsafe.Pointer(h))); r != 0 {
			return pdhErr("PdhAddEnglishCounter", r)
		}
		return nil
	}
	if err := add(pathPerf, &s.perf); err != nil {
		s.Close()
		return nil, fmt.Errorf("%w (%v)", ErrUnavailable, err)
	}
	// Senza la frequenza nominale per istanza si usa quella del registro.
	if add(pathFreq, &s.freq) != nil {
		s.freq = 0
	}
	// Il carico è facoltativo.
	if add(pathLoad, &s.load) != nil {
		s.load = 0
	}
	return s, nil
}

func (s *pdhSource) Collect() error {
	if r, _, _ := procPdhCollectQueryData.Call(s.query); r != 0 {
		return pdhErr("PdhCollectQueryData", r)
	}
	return nil
}

func (s *pdhSource) Read() (map[string]Reading, error) {
	out := map[string]Reading{}
	put := func(h uintptr, set func(*Reading, float64)) error {
		if h == 0 {
			return nil
		}
		vals, err := counterArray(h)
		if err != nil {
			return err
		}
		for name, v := range vals {
			x, ok := out[name]
			if !ok {
				x = Reading{Perf: math.NaN(), Freq: math.NaN(), Load: math.NaN()}
			}
			set(&x, v)
			out[name] = x
		}
		return nil
	}
	if err := put(s.perf, func(x *Reading, v float64) { x.Perf = v }); err != nil {
		return nil, err
	}
	_ = put(s.freq, func(x *Reading, v float64) { x.Freq = v })
	_ = put(s.load, func(x *Reading, v float64) { x.Load = v })
	return out, nil
}

func (s *pdhSource) Close() {
	if s.query != 0 {
		procPdhCloseQuery.Call(s.query)
		s.query = 0
	}
}

// counterArray legge tutte le istanze di un contatore con il carattere jolly.
func counterArray(h uintptr) (map[string]float64, error) {
	const format = pdhFmtDouble | pdhFmtNoCap100
	var size, count uint32
	r, _, _ := procPdhGetFormattedCounterArrayW.Call(h, format, uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&count)), 0)
	if uint32(r) != pdhMoreData {
		return nil, pdhErr("PdhGetFormattedCounterArray", r)
	}
	if size == 0 || count == 0 {
		return map[string]float64{}, nil
	}
	buf := make([]byte, size)
	r, _, _ = procPdhGetFormattedCounterArrayW.Call(h, format, uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&buf[0])))
	if r != 0 {
		return nil, pdhErr("PdhGetFormattedCounterArray", r)
	}
	out := make(map[string]float64, count)
	for k := uint32(0); k < count; k++ {
		off := int(k) * itemSize
		if off+itemSize > len(buf) {
			break
		}
		item := unsafe.Pointer(&buf[off])
		// I nomi stanno nello stesso buffer, dopo gli elementi.
		name := windows.UTF16PtrToString(*(**uint16)(item))
		switch *(*uint32)(unsafe.Add(item, statusOff)) {
		case pdhCstatusValidData, pdhCstatusNewData:
			out[name] = *(*float64)(unsafe.Add(item, doubleOff))
		}
	}
	return out, nil
}
