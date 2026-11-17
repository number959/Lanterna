//go:build windows

package pcinfo

import (
	"encoding/binary"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wddmGdi32                  = windows.NewLazySystemDLL("gdi32.dll")
	procD3DKMTEnumAdapters2    = wddmGdi32.NewProc("D3DKMTEnumAdapters2")
	procD3DKMTQueryAdapterInfo = wddmGdi32.NewProc("D3DKMTQueryAdapterInfo")
	procD3DKMTCloseAdapter     = wddmGdi32.NewProc("D3DKMTCloseAdapter")
)

// Tipi di KMTQUERYADAPTERINFOTYPE (valori espliciti di d3dkmthk.h, gli
// stessi di internal/sensors/gpu.go) e bit di D3DKMT_ADAPTERTYPE.
const (
	kmtAdapterRegistryInfo = 8
	kmtDriverVersion       = 13
	kmtAdapterType         = 15
	kmtTypeRender          = 1 << 0
	kmtTypeSoftware        = 1 << 2
)

// kmtAdapterInfo è D3DKMT_ADAPTERINFO (20 byte su tutte le architetture).
type kmtAdapterInfo struct {
	hAdapter   uint32
	luidLow    uint32
	luidHigh   int32
	numSources uint32
	precise    int32
}

// kmtEnumAdapters2 è D3DKMT_ENUMADAPTERS2.
type kmtEnumAdapters2 struct {
	numAdapters uint32
	adapters    *kmtAdapterInfo
}

// kmtQueryAdapterInfo è D3DKMT_QUERYADAPTERINFO.
type kmtQueryAdapterInfo struct {
	hAdapter uint32
	typ      uint32
	data     unsafe.Pointer
	size     uint32
}

func kmtQuery(h, typ uint32, out []byte) bool {
	q := kmtQueryAdapterInfo{hAdapter: h, typ: typ, data: unsafe.Pointer(&out[0]), size: uint32(len(out))}
	r, _, _ := procD3DKMTQueryAdapterInfo.Call(uintptr(unsafe.Pointer(&q)))
	return r == 0
}

// readWddm elenca le schede video con la versione WDDM del driver.
func readWddm() []wddmAdapter {
	if procD3DKMTEnumAdapters2.Find() != nil || procD3DKMTQueryAdapterInfo.Find() != nil {
		return nil
	}
	var e kmtEnumAdapters2
	if r, _, _ := procD3DKMTEnumAdapters2.Call(uintptr(unsafe.Pointer(&e))); r != 0 || e.numAdapters == 0 || e.numAdapters > 64 {
		return nil
	}
	list := make([]kmtAdapterInfo, e.numAdapters)
	e.adapters = &list[0]
	if r, _, _ := procD3DKMTEnumAdapters2.Call(uintptr(unsafe.Pointer(&e))); r != 0 {
		return nil
	}
	var out []wddmAdapter
	for _, a := range list[:min(int(e.numAdapters), len(list))] {
		var w wddmAdapter
		var typ [4]byte
		if kmtQuery(a.hAdapter, kmtAdapterType, typ[:]) {
			t := binary.LittleEndian.Uint32(typ[:])
			w.Software = t&kmtTypeSoftware != 0 || t&kmtTypeRender == 0
		}
		// D3DKMT_ADAPTERREGISTRYINFO: quattro stringhe da MAX_PATH caratteri;
		// la prima è il nome della scheda.
		reg := make([]uint16, 4*260)
		if kmtQuery(a.hAdapter, kmtAdapterRegistryInfo, unsafe.Slice((*byte)(unsafe.Pointer(&reg[0])), len(reg)*2)) {
			w.Name = strings.TrimSpace(windows.UTF16ToString(reg[:260]))
		}
		var ver [4]byte
		if kmtQuery(a.hAdapter, kmtDriverVersion, ver[:]) {
			w.Version = int(binary.LittleEndian.Uint32(ver[:]))
		}
		out = append(out, w)
		h := a.hAdapter
		procD3DKMTCloseAdapter.Call(uintptr(unsafe.Pointer(&h)))
	}
	return out
}
