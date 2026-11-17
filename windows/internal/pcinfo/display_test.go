package pcinfo

import (
	"encoding/binary"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"unicode/utf16"

	"lanterna/internal/scan"
)

// dcPath scrive un DISPLAYCONFIG_PATH_INFO con gli scostamenti di wingdi.h.
func dcPath(b []byte, adapterLow, adapterHigh, target, tech, sourceMode uint32) {
	le := binary.LittleEndian
	le.PutUint32(b[12:], sourceMode) // sourceInfo.modeInfoIdx
	le.PutUint32(b[20:], adapterLow) // targetInfo.adapterId
	le.PutUint32(b[24:], adapterHigh)
	le.PutUint32(b[28:], target)
	le.PutUint32(b[32:], dcModeIdxInvalid)
	le.PutUint32(b[36:], tech)
	le.PutUint32(b[60:], 1) // targetAvailable
	le.PutUint32(b[68:], 1) // DISPLAYCONFIG_PATH_ACTIVE
}

func TestParseDisplayConfig(t *testing.T) {
	paths := make([]byte, 2*dcPathSize)
	dcPath(paths[0:], 0x1234, 0, 0x1100, 5, 1)                              // HDMI, modalità della sorgente all'indice 1
	dcPath(paths[dcPathSize:], 0x1234, 0, 0x1101, techInternal, 0xFFFFFFFF) // pannello interno senza modalità
	modes := make([]byte, 2*dcModeSize)
	le := binary.LittleEndian
	le.PutUint32(modes[0:], 2) // modalità di destinazione: non serve
	le.PutUint32(modes[dcModeSize:], dcModeTypeSource)
	le.PutUint32(modes[dcModeSize+16:], 2560)
	le.PutUint32(modes[dcModeSize+20:], 1440)
	got := parseDisplayConfig(paths, 2, modes, 2)
	want := []rawDisplay{
		{AdapterLow: 0x1234, TargetID: 0x1100, Tech: 5, HasTech: true, Width: 2560, Height: 1440},
		{AdapterLow: 0x1234, TargetID: 0x1101, Tech: techInternal, HasTech: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("percorsi:\n got %+v\nwant %+v", got, want)
	}
	// Buffer più corti del dichiarato: si legge solo ciò che c'è.
	if got := parseDisplayConfig(paths[:dcPathSize+10], 2, modes, 2); len(got) != 1 {
		t.Errorf("buffer troncato: %d percorsi", len(got))
	}
	if got := parseDisplayConfig(paths, 2, modes[:dcModeSize], 2); got[0].Width != 0 {
		t.Errorf("modalità fuori dal buffer usata: %+v", got[0])
	}
	// Indici anomali (da 0x80000000 in su): con GOARCH=386 int(idx) era
	// negativo e lo slicing andava in panic. Nessun panic, nessuna modalità.
	for _, idx := range []uint32{0x82000000, 0x80000000, 0xFFFFFFFE, 0x04000001} {
		dcPath(paths[0:], 0x1234, 0, 0x1100, 5, idx)
		got := parseDisplayConfig(paths, 2, modes, 2)
		if len(got) != 2 || got[0].Width != 0 || got[0].Height != 0 {
			t.Errorf("indice %#x: %+v", idx, got)
		}
	}
	if got := parseDisplayConfig(paths, 2, modes, -1); len(got) != 2 || got[0].Width != 0 {
		t.Errorf("numero di modalità negativo: %+v", got)
	}
}

func TestParsePreferredMode(t *testing.T) {
	d := rawDisplay{AdapterLow: 1, TargetID: 0x1101}
	b := make([]byte, dcPrefModeSize)
	dcHeader(b, dcInfoPrefMode, dcPrefModeSize, d)
	le := binary.LittleEndian
	if le.Uint32(b[0:]) != 3 || le.Uint32(b[4:]) != 80 {
		t.Errorf("intestazione della modalità preferita: % x", b[:20])
	}
	le.PutUint32(b[dcPrefWidthAt:], 1920)
	le.PutUint32(b[dcPrefHeightAt:], 1080)
	if w, h := parsePreferredMode(b); w != 1920 || h != 1080 {
		t.Errorf("modalità preferita: %dx%d", w, h)
	}
	if w, h := parsePreferredMode(b[:dcPrefModeSize-1]); w != 0 || h != 0 {
		t.Errorf("buffer corto accettato: %dx%d", w, h)
	}
	le.PutUint32(b[dcPrefHeightAt:], 0)
	if w, h := parsePreferredMode(b); w != 0 || h != 0 {
		t.Errorf("altezza zero accettata: %dx%d", w, h)
	}
	le.PutUint32(b[dcPrefHeightAt:], 70000)
	if w, h := parsePreferredMode(b); w != 0 || h != 0 {
		t.Errorf("valore non plausibile accettato: %dx%d", w, h)
	}
}

func TestDisplayDeviceInfo(t *testing.T) {
	d := rawDisplay{AdapterLow: 0xAABBCCDD, AdapterHigh: 0x11, TargetID: 0x1100}
	b := make([]byte, dcTargetNameSize)
	dcHeader(b, dcInfoTargetName, dcTargetNameSize, d)
	le := binary.LittleEndian
	if le.Uint32(b[0:]) != 2 || le.Uint32(b[4:]) != 420 || le.Uint32(b[8:]) != 0xAABBCCDD || le.Uint32(b[12:]) != 0x11 || le.Uint32(b[16:]) != 0x1100 {
		t.Errorf("intestazione: % x", b[:20])
	}
	path := `\\?\DISPLAY#DELA0B2#5&2a0c4b4&0&UID4353#{e6f07b5f-ee97-4a90-b076-33f57bf4eaa7}`
	for i, c := range utf16.Encode([]rune(path)) {
		le.PutUint16(b[dcTargetPathAt+2*i:], c)
	}
	le.PutUint32(b[dcTargetTechAt:], 10)
	p, tech, ok := parseTargetName(b)
	if !ok || p != path || tech != 10 {
		t.Errorf("nome della destinazione: %q %d %v", p, tech, ok)
	}
	if _, _, ok := parseTargetName(b[:100]); ok {
		t.Error("buffer corto accettato")
	}
	c := make([]byte, dcAdvColorSize)
	for _, x := range []struct {
		v    uint32
		want int
	}{{8, 8}, {10, 10}, {6, 6}, {0, 0}, {99, 0}} {
		le.PutUint32(c[dcAdvColorBitsAt:], x.v)
		if got := parseAdvancedColor(c); got != x.want {
			t.Errorf("bit per canale %d: %d", x.v, got)
		}
	}
	if parseAdvancedColor(c[:20]) != 0 {
		t.Error("buffer corto accettato")
	}
}

func TestMonitorKeyAndDiagonal(t *testing.T) {
	a := monitorKey(`\\?\DISPLAY#DELA0B2#5&2a0c4b4&0&UID4353#{e6f07b5f-ee97-4a90-b076-33f57bf4eaa7}`)
	b := monitorKey(`DISPLAY\DELA0B2\5&2a0c4b4&0&UID4353_0`)
	if a != b || a != `DISPLAY\DELA0B2\5&2A0C4B4&0&UID4353` {
		t.Errorf("chiavi diverse: %q %q", a, b)
	}
	for _, c := range []struct {
		w, h int
		want float64
	}{{34, 19, 15.3}, {60, 34, 27.2}, {22, 12, 9.9}, {160, 90, 72.3}, {0, 19, 0}, {34, 0, 0}, {1, 1, 0}, {2000, 2000, 0}} {
		if got := diagonalIn(c.w, c.h); got != c.want {
			t.Errorf("diagonale %dx%d cm: %v, attesa %v", c.w, c.h, got, c.want)
		}
	}
	for _, v := range []uint32{techInternal, 11, 13} {
		if !internalTech(v) {
			t.Errorf("collegamento %#x non riconosciuto come interno", v)
		}
	}
	for _, v := range []uint32{0, 4, 5, 10, 15, 17, 0xFFFFFFFF} {
		if internalTech(v) {
			t.Errorf("collegamento %#x preso per interno", v)
		}
	}
}

func TestBuildDisplays(t *testing.T) {
	vot := func(v int64) *int64 { return &v }
	native := []rawDisplay{
		{TargetID: 1, Tech: 10, HasTech: true, Width: 2560, Height: 1440, Bits: 10, Path: `\\?\DISPLAY#GSM5B7F#5&1&0&UID256#{e6f07b5f-ee97-4a90-b076-33f57bf4eaa7}`},
		// Pannello da 1080p duplicato su un proiettore a 800×600: la risoluzione nativa resta.
		{TargetID: 2, Tech: techInternal, HasTech: true, Width: 800, Height: 600, NativeWidth: 1920, NativeHeight: 1080, Bits: 8, Path: `\\?\DISPLAY#LGD06A5#4&2&0&UID8388688#{e6f07b5f-ee97-4a90-b076-33f57bf4eaa7}`},
		{TargetID: 3, Tech: 17, HasTech: true, Width: 1024, Height: 768}, // schermo virtuale: niente dimensioni
	}
	wmi := []psMonitor{
		{ID: `DISPLAY\LGD06A5\4&2&0&UID8388688_0`, W: 34, H: 19, Vot: vot(-2147483648)},
		{ID: `DISPLAY\GSM5B7F\5&1&0&UID256_0`, W: 60, H: 34, Vot: vot(10)},
	}
	got := BuildDisplays(native, wmi, nil)
	want := []scan.Display{
		{Width: 800, Height: 600, NativeWidth: 1920, NativeHeight: 1080, DiagonalIn: 15.3, BitsPerColor: 8, Internal: true},
		{Width: 2560, Height: 1440, DiagonalIn: 27.2, BitsPerColor: 10},
		{Width: 1024, Height: 768},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("schermi:\n got %+v\nwant %+v", got, want)
	}
	// Mai percorsi, ID d'istanza o nomi nel JSON.
	js, _ := json.Marshal(got)
	if strings.Contains(string(js), "DISPLAY") || strings.Contains(string(js), "UID") {
		t.Errorf("identificativi nel JSON: %s", js)
	}

	// Senza lettura nativa: gli schermi WMI, con la risoluzione della sola scheda video.
	gpus := []scan.PcGPU{{Name: "Intel(R) UHD Graphics 620", Width: 1366, Height: 768}, {Name: "Microsoft Basic Display Adapter"}}
	got = BuildDisplays(nil, wmi[:1], gpus)
	if len(got) != 1 || !got[0].Internal || got[0].DiagonalIn != 15.3 || got[0].Width != 1366 || got[0].Height != 768 {
		t.Errorf("solo WMI: %+v", got)
	}
	// Due schermi WMI: la risoluzione non si può attribuire.
	got = BuildDisplays(nil, wmi, gpus)
	if len(got) != 2 || got[0].Width != 0 || got[1].Width != 0 {
		t.Errorf("solo WMI con due schermi: %+v", got)
	}
	if BuildDisplays(nil, nil, gpus) != nil {
		t.Error("senza schermi deve restare vuoto")
	}
	// Al massimo maxDisplays.
	many := make([]rawDisplay, 12)
	if got := BuildDisplays(many, nil, nil); len(got) != maxDisplays {
		t.Errorf("limite degli schermi: %d", len(got))
	}
}
