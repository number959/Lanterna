package sensors

import (
	"encoding/binary"
	"fmt"
)

// Telemetria delle schede video dalle funzioni D3DKMT di gdi32.dll (d3dkmthk.h
// del Windows Driver Kit), le stesse da cui Gestione attività legge la
// temperatura della GPU. I valori li fornisce il driver video (WDDM 2.4 o
// successivo, cioè Windows 10 1803 in poi), se il produttore li implementa.

// Tipi di KMTQUERYADAPTERINFOTYPE usati (valori espliciti di d3dkmthk.h: la
// numerazione per posizione della pagina di Microsoft Learn non vale, perché
// salta il 14).
const (
	kmtqaiAdapterRegistryInfo = 8
	kmtqaiDriverVersion       = 13
	kmtqaiAdapterType         = 15
	kmtqaiNodeMetadata        = 25
	kmtqaiNodePerfData        = 61
	kmtqaiAdapterPerfData     = 62
	kmtqaiAdapterPerfDataCaps = 63

	// D3DKMT_ADAPTERTYPE: bit RenderSupported e SoftwareDevice (Microsoft
	// Basic Render Driver).
	adapterTypeRender   = 1 << 0
	adapterTypeSoftware = 1 << 2

	// D3DKMT_DRIVERVERSION: i dati sulle prestazioni richiedono WDDM 2.4.
	wddm24 = 2400

	// D3DKMT_NODEMETADATA (#pragma pack(1)): NodeOrdinalAndAdapterIndex, poi
	// DXGK_NODEMETADATA con EngineType a +4; 78 byte. DXGK_ENGINE_TYPE_3D = 1.
	nodeMetadataSize = 78
	engineType3D     = 1
	maxNodes         = 64

	// Dimensioni delle strutture (allineamento naturale, uguale su 386, amd64
	// e arm64 perché i campi a 8 byte sono allineati a 8 anche su 386).
	adapterPerfDataSize     = 64 // D3DKMT_ADAPTER_PERFDATA
	adapterPerfDataCapsSize = 40 // D3DKMT_ADAPTER_PERFDATACAPS
	nodePerfDataSize        = 56 // D3DKMT_NODE_PERFDATA
)

// luidKey scrive il LUID come nei nomi delle istanze PDH della GPU, in
// minuscolo: prima la parte alta, poi la bassa.
func luidKey(low uint32, high int32) string {
	return fmt.Sprintf("0x%08x_0x%08x", uint32(high), low)
}

// gpuCaps sono i limiti dichiarati dal driver (D3DKMT_ADAPTER_PERFDATACAPS):
// temperature in decimi di °C.
type gpuCaps struct {
	TempMaxC, TempWarnC float64
}

func parseCaps(b []byte) gpuCaps {
	c := gpuCaps{TempMaxC: nan, TempWarnC: nan}
	if len(b) < adapterPerfDataCapsSize {
		return c
	}
	le := binary.LittleEndian
	if v := le.Uint32(b[28:]); v > 0 {
		c.TempMaxC = float64(v) / 10
	}
	if v := le.Uint32(b[32:]); v > 0 {
		c.TempWarnC = float64(v) / 10
	}
	return c
}

// applyAdapterPerf legge D3DKMT_ADAPTER_PERFDATA: frequenza della memoria in
// Hz (+8), giri della ventola (+48), potenza in decimi di punto percentuale
// (+52), temperatura in decimi di °C (+56). Gli zeri valgono "non fornito".
func applyAdapterPerf(g *GPU, b []byte) {
	if len(b) < adapterPerfDataSize {
		return
	}
	le := binary.LittleEndian
	if v := le.Uint64(b[8:]); v > 0 {
		g.MemMHz = float64(v) / 1e6
	}
	if v := le.Uint32(b[48:]); v > 0 {
		g.FanRPM = float64(v)
	}
	if v := le.Uint32(b[52:]); v > 0 {
		g.PowerPct = float64(v) / 10
	}
	if v := le.Uint32(b[56:]); v > 0 {
		g.TempC = float64(v) / 10
	}
}

// applyNodePerf legge D3DKMT_NODE_PERFDATA del motore 3D: frequenza in Hz
// (+8) e tensione in millivolt (+32).
func applyNodePerf(g *GPU, b []byte) {
	if len(b) < nodePerfDataSize {
		return
	}
	le := binary.LittleEndian
	if v := le.Uint64(b[8:]); v > 0 {
		g.CoreMHz = float64(v) / 1e6
	}
	if v := le.Uint32(b[32:]); v > 0 {
		g.VoltageMV = float64(v)
	}
}

// emptyGPU è una scheda senza valori letti.
func emptyGPU(luid, name string, software bool) GPU {
	return GPU{LUID: luid, Name: name, Software: software, TempC: nan, TempWarnC: nan, TempMaxC: nan, FanRPM: nan, PowerPct: nan, CoreMHz: nan, MemMHz: nan, VoltageMV: nan}
}
