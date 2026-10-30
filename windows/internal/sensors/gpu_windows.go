//go:build windows

package sensors

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	gdi32                      = windows.NewLazySystemDLL("gdi32.dll")
	procD3DKMTEnumAdapters2    = gdi32.NewProc("D3DKMTEnumAdapters2")
	procD3DKMTQueryAdapterInfo = gdi32.NewProc("D3DKMTQueryAdapterInfo")
	procD3DKMTCloseAdapter     = gdi32.NewProc("D3DKMTCloseAdapter")
)

// d3dkmtAdapterInfo è D3DKMT_ADAPTERINFO: handle, LUID (parte bassa e alta),
// numero di uscite video, un BOOL; 20 byte su tutte le architetture.
type d3dkmtAdapterInfo struct {
	hAdapter   uint32
	luidLow    uint32
	luidHigh   int32
	numSources uint32
	precise    int32
}

// d3dkmtEnumAdapters2 è D3DKMT_ENUMADAPTERS2.
type d3dkmtEnumAdapters2 struct {
	numAdapters uint32
	adapters    *d3dkmtAdapterInfo
}

// d3dkmtQueryAdapterInfo è D3DKMT_QUERYADAPTERINFO.
type d3dkmtQueryAdapterInfo struct {
	hAdapter uint32
	typ      uint32
	data     unsafe.Pointer
	size     uint32
}

type gpuAdapter struct {
	handle uint32
	base   GPU
	// perf: il driver è WDDM 2.4 o successivo; node3D: il motore 3D.
	perf   bool
	node3D uint32
}

// gpuReader tiene aperte le schede video finché il monitor è attivo.
type gpuReader struct {
	adapters []gpuAdapter
}

func ntErr(op string, r uintptr) error {
	return fmt.Errorf("%s: NTSTATUS 0x%08X", op, uint32(r))
}

// openGPUs elenca le schede video con D3DKMTEnumAdapters2.
func openGPUs() (*gpuReader, error) {
	if err := procD3DKMTEnumAdapters2.Find(); err != nil {
		return nil, errors.New("D3DKMTEnumAdapters2 non disponibile")
	}
	var e d3dkmtEnumAdapters2
	if r, _, _ := procD3DKMTEnumAdapters2.Call(uintptr(unsafe.Pointer(&e))); r != 0 {
		return nil, ntErr("D3DKMTEnumAdapters2", r)
	}
	if e.numAdapters == 0 || e.numAdapters > 64 {
		return &gpuReader{}, nil
	}
	list := make([]d3dkmtAdapterInfo, e.numAdapters)
	e.adapters = &list[0]
	if r, _, _ := procD3DKMTEnumAdapters2.Call(uintptr(unsafe.Pointer(&e))); r != 0 {
		return nil, ntErr("D3DKMTEnumAdapters2", r)
	}
	g := &gpuReader{}
	for _, a := range list[:min(int(e.numAdapters), len(list))] {
		var typ [4]byte
		software := false
		if queryAdapter(a.hAdapter, kmtqaiAdapterType, typ[:]) == nil {
			software = binary.LittleEndian.Uint32(typ[:])&adapterTypeSoftware != 0
		}
		// D3DKMT_ADAPTERREGISTRYINFO: quattro stringhe da MAX_PATH caratteri;
		// la prima è il nome della scheda.
		reg := make([]byte, 4*260*2)
		name := ""
		if queryAdapter(a.hAdapter, kmtqaiAdapterRegistryInfo, reg) == nil {
			name = strings.TrimSpace(windows.UTF16ToString(unsafe.Slice((*uint16)(unsafe.Pointer(&reg[0])), 260)))
		}
		base := emptyGPU(luidKey(a.luidLow, a.luidHigh), name, software)
		caps := make([]byte, adapterPerfDataCapsSize)
		if !software && queryAdapter(a.hAdapter, kmtqaiAdapterPerfDataCaps, caps) == nil {
			c := parseCaps(caps)
			base.TempMaxC, base.TempWarnC = c.TempMaxC, c.TempWarnC
		}
		var ver [4]byte
		perf := !software && queryAdapter(a.hAdapter, kmtqaiDriverVersion, ver[:]) == nil && binary.LittleEndian.Uint32(ver[:]) >= wddm24
		g.adapters = append(g.adapters, gpuAdapter{handle: a.hAdapter, base: base, perf: perf, node3D: node3D(a.hAdapter)})
	}
	return g, nil
}

// node3D cerca il motore 3D tra i motori della scheda (il primo lo è di
// solito, ma la documentazione non lo garantisce); 0 se non lo trova.
func node3D(h uint32) uint32 {
	for n := uint32(0); n < maxNodes; n++ {
		b := make([]byte, nodeMetadataSize)
		binary.LittleEndian.PutUint32(b, n) // scheda fisica 0 nei 16 bit alti
		if queryAdapter(h, kmtqaiNodeMetadata, b) != nil {
			break
		}
		if binary.LittleEndian.Uint32(b[4:]) == engineType3D {
			return n
		}
	}
	return 0
}

// queryAdapter chiama D3DKMTQueryAdapterInfo; i primi byte di out fanno da
// ingresso (indice della scheda fisica, numero del motore).
func queryAdapter(h uint32, typ uint32, out []byte) error {
	q := d3dkmtQueryAdapterInfo{hAdapter: h, typ: typ, data: unsafe.Pointer(&out[0]), size: uint32(len(out))}
	if r, _, _ := procD3DKMTQueryAdapterInfo.Call(uintptr(unsafe.Pointer(&q))); r != 0 {
		return ntErr("D3DKMTQueryAdapterInfo", r)
	}
	return nil
}

// read legge temperatura, ventola, potenza, frequenze e tensione. I driver
// che non le forniscono restituiscono un errore: i valori restano assenti.
func (g *gpuReader) read() []GPU {
	out := make([]GPU, 0, len(g.adapters))
	for _, a := range g.adapters {
		x := a.base
		if a.perf {
			perf := make([]byte, adapterPerfDataSize)
			if queryAdapter(a.handle, kmtqaiAdapterPerfData, perf) == nil {
				applyAdapterPerf(&x, perf)
			}
			node := make([]byte, nodePerfDataSize)
			binary.LittleEndian.PutUint32(node, a.node3D)
			if queryAdapter(a.handle, kmtqaiNodePerfData, node) == nil {
				applyNodePerf(&x, node)
			}
		}
		out = append(out, x)
	}
	return out
}

func (g *gpuReader) close() {
	for _, a := range g.adapters {
		h := a.handle
		procD3DKMTCloseAdapter.Call(uintptr(unsafe.Pointer(&h)))
	}
	g.adapters = nil
}
