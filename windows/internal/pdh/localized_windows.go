//go:build windows

package pdh

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi32                                = windows.NewLazySystemDLL("advapi32.dll")
	procPerfEnumerateCounterSet             = advapi32.NewProc("PerfEnumerateCounterSet")
	procPerfQueryCounterSetRegistrationInfo = advapi32.NewProc("PerfQueryCounterSetRegistrationInfo")
	kernel32                                = windows.NewLazySystemDLL("kernel32.dll")
	procGetUserDefaultUILanguage            = kernel32.NewProc("GetUserDefaultUILanguage")
	procGetSystemDefaultUILanguage          = kernel32.NewProc("GetSystemDefaultUILanguage")
)

// Richieste di PerfQueryCounterSetRegistrationInfo (PERFREGINFOTYPE, perflib.h).
const (
	perfRegCounterSetNameString = 3
	perfRegCounterNameStrings   = 5
	errorNotEnoughMemory        = 8 // ERROR_NOT_ENOUGH_MEMORY
)

// forceLocalized salta il tentativo con i nomi inglesi e usa sempre la
// traduzione, anche verso l'inglese: serve a provarla su un Windows in
// inglese (POLARIS_PDH_LOCALIZED=1).
var forceLocalized = os.Getenv("POLARIS_PDH_LOCALIZED") == "1"

var localized = &translator{reg: registry{
	sets: func() ([]GUID, error) {
		if err := procPerfEnumerateCounterSet.Find(); err != nil {
			return nil, err
		}
		var n uint32
		r, _, _ := procPerfEnumerateCounterSet.Call(0, 0, 0, uintptr(unsafe.Pointer(&n)))
		if r != 0 && r != errorNotEnoughMemory {
			return nil, windows.Errno(r)
		}
		if n == 0 || n > 10000 {
			return nil, nil
		}
		out := make([]GUID, n)
		r, _, _ = procPerfEnumerateCounterSet.Call(0, uintptr(unsafe.Pointer(&out[0])), uintptr(n), uintptr(unsafe.Pointer(&n)))
		if r != 0 {
			return nil, windows.Errno(r)
		}
		return out[:min(int(n), len(out))], nil
	},
	setName: func(g GUID, lang uint16) (string, bool) {
		b, ok := regInfo(g, perfRegCounterSetNameString, lang)
		if !ok {
			return "", false
		}
		return utf16z(b), true
	},
	counters: func(g GUID, lang uint16) (map[uint32]string, bool) {
		b, ok := regInfo(g, perfRegCounterNameStrings, lang)
		if !ok {
			return nil, false
		}
		return parseCounterNames(b), true
	},
	langs: func() []uint16 {
		var out []uint16
		for _, p := range []*windows.LazyProc{procGetUserDefaultUILanguage, procGetSystemDefaultUILanguage} {
			if p.Find() == nil {
				r, _, _ := p.Call()
				out = append(out, uint16(r))
			}
		}
		return out
	},
	english: forceLocalized,
}}

// regInfo chiama PerfQueryCounterSetRegistrationInfo, ingrandendo il buffer
// se serve.
func regInfo(g GUID, code uint32, lang uint16) ([]byte, bool) {
	if procPerfQueryCounterSetRegistrationInfo.Find() != nil {
		return nil, false
	}
	b := make([]byte, 512)
	for range 3 {
		var need uint32
		r, _, _ := procPerfQueryCounterSetRegistrationInfo.Call(0, uintptr(unsafe.Pointer(&g)), uintptr(code), uintptr(lang), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), uintptr(unsafe.Pointer(&need)))
		switch {
		case r == 0 && int(need) <= len(b):
			return b[:need], true
		case r == errorNotEnoughMemory && int(need) > len(b) && need < 1<<20:
			b = make([]byte, need)
		default:
			return nil, false
		}
	}
	return nil, false
}
