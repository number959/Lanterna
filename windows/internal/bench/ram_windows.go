//go:build windows

package bench

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32                       = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalMemoryStatusEx       = kernel32.NewProc("GlobalMemoryStatusEx")
	procGetProcessWorkingSetSizeEx = kernel32.NewProc("GetProcessWorkingSetSizeEx")
	procSetProcessWorkingSetSizeEx = kernel32.NewProc("SetProcessWorkingSetSizeEx")
)

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

func memStatus() (memoryStatusEx, bool) {
	m := memoryStatusEx{Length: uint32(unsafe.Sizeof(memoryStatusEx{}))}
	r, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&m)))
	return m, r != 0
}

const (
	quotaLimitsHardwsMinDisable = 0x2
	quotaLimitsHardwsMaxDisable = 0x8
	lockChunk                   = 64 << 20
	// ramFloor: sotto questa memoria libera il test si ferma per non mettere
	// in difficoltà Windows e i programmi aperti.
	ramFloor = 192 << 20
)

// allocRAM riserva la memoria libera meno una riserva per Windows (almeno
// 1 GB o un ottavo della RAM) e la blocca in RAM a blocchi da 64 MB
// (VirtualLock), alzando il working set del processo; quello che non si
// riesce a bloccare viene comunque provato ma è dichiarato.
func allocRAM(maxMB int) (*ramBlock, error) {
	m, ok := memStatus()
	if !ok {
		return nil, ErrRAMLow
	}
	reserve := max(uint64(1)<<30, m.TotalPhys/8)
	if m.AvailPhys <= reserve+256<<20 {
		return nil, ErrRAMLow
	}
	size := m.AvailPhys - reserve
	if maxMB > 0 && size > uint64(maxMB)<<20 {
		size = uint64(maxMB) << 20
	}
	if unsafe.Sizeof(uintptr(0)) == 4 && size > 1<<30 {
		size = 1 << 30 // spazio degli indirizzi limitato dei processi a 32 bit
	}
	size &^= 1<<16 - 1 // multiplo di 64 KB
	if size < 64<<20 {
		return nil, ErrRAMLow
	}
	addr, err := windows.VirtualAlloc(0, uintptr(size), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return nil, ErrRAMLow
	}
	proc := windows.CurrentProcess()
	var oldMin, oldMax uintptr
	var oldFlags uint32
	hadWS := false
	if r, _, _ := procGetProcessWorkingSetSizeEx.Call(uintptr(proc), uintptr(unsafe.Pointer(&oldMin)), uintptr(unsafe.Pointer(&oldMax)), uintptr(unsafe.Pointer(&oldFlags))); r != 0 {
		hadWS = true
		procSetProcessWorkingSetSizeEx.Call(uintptr(proc), oldMin+uintptr(size), oldMax+uintptr(size)+256<<20, quotaLimitsHardwsMinDisable|quotaLimitsHardwsMaxDisable)
	}
	var locked uint64
	for off := uint64(0); off < size; off += lockChunk {
		n := min(uint64(lockChunk), size-off)
		if windows.VirtualLock(addr+uintptr(off), uintptr(n)) != nil {
			break
		}
		locked += n
	}
	// La memoria viene da VirtualAlloc, fuori dal garbage collector: si
	// reinterpreta l'indirizzo senza la conversione diretta da uintptr.
	base := *(*unsafe.Pointer)(unsafe.Pointer(&addr))
	words := unsafe.Slice((*uint64)(base), size/8)
	free := func() {
		if locked > 0 {
			windows.VirtualUnlock(addr, uintptr(locked))
		}
		windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
		if hadWS {
			procSetProcessWorkingSetSizeEx.Call(uintptr(proc), oldMin, oldMax, uintptr(oldFlags))
		}
	}
	pressure := func() bool {
		s, ok := memStatus()
		return ok && s.AvailPhys < ramFloor
	}
	return &ramBlock{words: words, lockedMB: int(locked >> 20), totalMB: int(m.TotalPhys >> 20), availMB: int(m.AvailPhys >> 20), free: free, pressure: pressure}, nil
}
