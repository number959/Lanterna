//go:build windows

package pcinfo

import (
	"errors"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// user32 è dichiarata in access_windows.go.
var (
	procGetDisplayConfigBufferSizes = user32.NewProc("GetDisplayConfigBufferSizes")
	procQueryDisplayConfig          = user32.NewProc("QueryDisplayConfig")
	procDisplayConfigGetDeviceInfo  = user32.NewProc("DisplayConfigGetDeviceInfo")
)

// qdcOnlyActivePaths è QDC_ONLY_ACTIVE_PATHS: solo gli schermi in uso.
const qdcOnlyActivePaths = 0x2

// readDisplays legge gli schermi in uso con le API di configurazione dello
// schermo (Windows 7 e successivi; i bit per canale da Windows 10 1709).
// Solo letture: SetDisplayConfig non si usa.
func readDisplays() ([]rawDisplay, error) {
	if procQueryDisplayConfig.Find() != nil || procGetDisplayConfigBufferSizes.Find() != nil {
		return nil, errors.New("non disponibile")
	}
	// La configurazione può cambiare tra le due chiamate (uno schermo
	// collegato in quel momento): ERROR_INSUFFICIENT_BUFFER, si riprova.
	for try := 0; try < 3; try++ {
		var np, nm uint32
		if r, _, _ := procGetDisplayConfigBufferSizes.Call(qdcOnlyActivePaths, uintptr(unsafe.Pointer(&np)), uintptr(unsafe.Pointer(&nm))); r != 0 {
			return nil, syscall.Errno(r)
		}
		if np == 0 {
			return nil, nil
		}
		if np > 64 || nm > 256 {
			return nil, errors.New("configurazione dello schermo non plausibile")
		}
		// Buffer allineati a 8 (le modalità contengono un UINT64).
		paths := make([]uint64, (int(np)*dcPathSize+7)/8)
		modes := make([]uint64, (int(max(nm, 1))*dcModeSize+7)/8)
		r, _, _ := procQueryDisplayConfig.Call(qdcOnlyActivePaths, uintptr(unsafe.Pointer(&np)), uintptr(unsafe.Pointer(&paths[0])),
			uintptr(unsafe.Pointer(&nm)), uintptr(unsafe.Pointer(&modes[0])), 0)
		if r == uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			continue
		}
		if r != 0 {
			return nil, syscall.Errno(r)
		}
		pb := unsafe.Slice((*byte)(unsafe.Pointer(&paths[0])), len(paths)*8)
		mb := unsafe.Slice((*byte)(unsafe.Pointer(&modes[0])), len(modes)*8)
		list := parseDisplayConfig(pb, int(np), mb, int(nm))
		for i := range list {
			name := make([]uint64, (dcTargetNameSize+7)/8)
			nb := unsafe.Slice((*byte)(unsafe.Pointer(&name[0])), dcTargetNameSize)
			dcHeader(nb, dcInfoTargetName, dcTargetNameSize, list[i])
			if r, _, _ := procDisplayConfigGetDeviceInfo.Call(uintptr(unsafe.Pointer(&name[0]))); r == 0 {
				if path, _, ok := parseTargetName(nb); ok {
					list[i].Path = path
				}
			}
			color := make([]uint64, dcAdvColorSize/8)
			cb := unsafe.Slice((*byte)(unsafe.Pointer(&color[0])), dcAdvColorSize)
			dcHeader(cb, dcInfoAdvColor, dcAdvColorSize, list[i])
			if r, _, _ := procDisplayConfigGetDeviceInfo.Call(uintptr(unsafe.Pointer(&color[0]))); r == 0 {
				list[i].Bits = parseAdvancedColor(cb)
			}
		}
		return list, nil
	}
	return nil, errors.New("la configurazione dello schermo è cambiata durante la lettura")
}
