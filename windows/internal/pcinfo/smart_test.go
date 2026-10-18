package pcinfo

import (
	"encoding/binary"
	"math"
	"testing"

	"lanterna/internal/scan"
)

type ataEntry struct {
	id, current, worst byte
	flags              uint16
	raw                int64
}

// ataBlock costruisce un blocco SMART READ DATA come lo restituisce il disco.
func ataBlock(entries ...ataEntry) []byte {
	b := make([]byte, 512)
	b[0] = 0x10 // revisione
	for i, e := range entries {
		o := 2 + i*12
		b[o] = e.id
		binary.LittleEndian.PutUint16(b[o+1:], e.flags)
		b[o+3], b[o+4] = e.current, e.worst
		for k := range 6 {
			b[o+5+k] = byte(e.raw >> (8 * k))
		}
	}
	return b
}

// thrBlock costruisce il blocco delle soglie: coppie identificativo, soglia.
func thrBlock(pairs ...[2]byte) []byte {
	b := make([]byte, 512)
	for i, p := range pairs {
		b[2+i*12], b[2+i*12+1] = p[0], p[1]
	}
	return b
}

// Un Seagate da 1 TB con settori riallocati oltre la soglia del produttore:
// attributo 05 a 5 con soglia 10, come lo mostrerebbe CrystalDiskInfo in
// rosso. La temperatura (C2) porta nel dato grezzo anche la minima (17 °C,
// quinto byte), come fanno molti produttori.
func TestParseSmart(t *testing.T) {
	data := ataBlock(
		ataEntry{0x01, 77, 64, 0x000F, 0x0000_0567_8C3A},
		ataEntry{0x05, 5, 5, 0x0033, 1856},
		ataEntry{0x09, 71, 71, 0x0032, 25432},
		ataEntry{0xC2, 38, 52, 0x0022, 0x0011_0000_0026},
		ataEntry{0xC5, 100, 100, 0x0012, 48},
		ataEntry{0xC6, 100, 100, 0x0010, 48},
		ataEntry{0xFF, 1, 1, 0, 0}, // voce non valida: scartata
		ataEntry{0xF1, 100, 253, 0x0000, 0xFFFF_FFFF_FFFF},
	)
	// Soglie in ordine diverso dagli attributi e senza C2: si abbinano per
	// identificativo, non per posizione.
	thr := thrBlock([2]byte{0x05, 10}, [2]byte{0x01, 6}, [2]byte{0x09, 0}, [2]byte{0xC5, 0}, [2]byte{0xC6, 0})
	attrs := ParseSmart(data, thr)
	if len(attrs) != 7 {
		t.Fatalf("attributi: %d %+v", len(attrs), attrs)
	}
	byID := map[int]scan.SmartAttr{}
	for _, a := range attrs {
		byID[a.ID] = a
	}
	if a := byID[0x05]; a.Current != 5 || a.Worst != 5 || a.Raw != 1856 || a.Flags != 0x33 || a.Threshold == nil || *a.Threshold != 10 {
		t.Errorf("05: %+v", a)
	}
	if a := byID[0x01]; a.Raw != 0x0567_8C3A || *a.Threshold != 6 {
		t.Errorf("01: %+v", a)
	}
	if a := byID[0xC2]; a.Threshold != nil || a.Raw&0xFF != 38 || a.Raw>>32&0xFF != 17 {
		t.Errorf("C2: %+v", a)
	}
	// 48 bit tutti a uno: il valore massimo, senza segno negativo.
	if a := byID[0xF1]; a.Raw != 0xFFFF_FFFF_FFFF || a.Worst != 253 {
		t.Errorf("F1: %+v", a)
	}
	if a := byID[0x09]; a.Threshold == nil || *a.Threshold != 0 || a.Raw != 25432 {
		t.Errorf("09: %+v", a)
	}

	// Senza soglie gli attributi restano, con la soglia sconosciuta.
	for _, a := range ParseSmart(data, nil) {
		if a.Threshold != nil {
			t.Errorf("soglia inventata: %+v", a)
		}
	}
	if ParseSmart(data[:300], thr) != nil {
		t.Error("blocco troncato accettato")
	}
}

func TestSmartValid(t *testing.T) {
	if smartValid(make([]byte, 512)) {
		t.Error("blocco vuoto accettato")
	}
	full := make([]byte, 512)
	for i := range full {
		full[i] = 0xFF
	}
	if smartValid(full) {
		t.Error("blocco 0xFF accettato")
	}
	if !smartValid(ataBlock(ataEntry{id: 0x09, current: 100, worst: 100})) {
		t.Error("blocco valido scartato")
	}
	if smartValid(nil) {
		t.Error("nil accettato")
	}
}

// nvmeLog costruisce una pagina 02h come quella di un Samsung 980 da 1 TB.
func nvmeLog() []byte {
	b := make([]byte, 512)
	put := func(o int, v uint64) { binary.LittleEndian.PutUint64(b[o:], v) }
	b[0] = 0
	binary.LittleEndian.PutUint16(b[1:], 311) // 38 °C
	b[3], b[4], b[5] = 100, 10, 3
	put(32, 12_345_678) // unità da 512 000 byte lette
	put(48, 9_876_543)
	put(112, 1234)
	put(128, 5120)
	put(144, 37)
	put(160, 0)
	put(176, 12)
	binary.LittleEndian.PutUint32(b[192:], 4)
	binary.LittleEndian.PutUint32(b[196:], 1)
	return b
}

func TestParseNVMeHealth(t *testing.T) {
	h := ParseNVMeHealth(nvmeLog())
	if h == nil {
		t.Fatal("nil")
	}
	if h.CriticalWarning != 0 || h.TemperatureC == nil || *h.TemperatureC != 38 || h.AvailableSparePct != 100 || h.SpareThresholdPct != 10 || h.PercentageUsed != 3 {
		t.Errorf("intestazione: %+v", h)
	}
	// 12 345 678 × 512 000 byte = 6 320,99 GB; 9 876 543 × 512 000 = 5 056,79 GB.
	if h.DataReadGB != 6321 || h.DataWrittenGB != 5056.8 {
		t.Errorf("dati: letti %v, scritti %v", h.DataReadGB, h.DataWrittenGB)
	}
	if h.PowerCycles != 1234 || h.PowerOnHours != 5120 || h.UnsafeShutdowns != 37 || h.MediaErrors != 0 || h.ErrorLogEntries != 12 ||
		h.WarningTempMinutes != 4 || h.CriticalTempMinutes != 1 {
		t.Errorf("contatori: %+v", h)
	}

	// Contatore oltre i 64 bit: saturato invece che negativo.
	b := nvmeLog()
	binary.LittleEndian.PutUint64(b[128+8:], 1)
	b[0] = 0x05 // riserva sotto soglia e affidabilità degradata
	binary.LittleEndian.PutUint16(b[1:], 0)
	h = ParseNVMeHealth(b)
	if h.PowerOnHours != math.MaxInt64 || h.CriticalWarning != 5 || h.TemperatureC != nil {
		t.Errorf("limiti: %+v", h)
	}
	if ParseNVMeHealth(b[:200]) != nil {
		t.Error("registro troncato accettato")
	}
}

func TestNVMeValid(t *testing.T) {
	if nvmeValid(make([]byte, 512)) || nvmeValid(nil) {
		t.Error("registro vuoto accettato")
	}
	if !nvmeValid(nvmeLog()) {
		t.Error("registro valido scartato")
	}
}

func TestSmartOf(t *testing.T) {
	pc := &scan.PcData{Disks: []scan.PhysicalDisk{{ID: "0", Name: "NVMe"}, {ID: "1", Name: "SATA"}, {ID: "2", Name: "USB"}}}
	smartOf(pc, map[string]diskSmart{
		"0": {NVMe: ParseNVMeHealth(nvmeLog())},
		"1": {Attrs: ParseSmart(ataBlock(ataEntry{id: 0x09, current: 99, worst: 99, raw: 100}), nil)},
		"7": {Attrs: []scan.SmartAttr{{ID: 1}}}, // disco non elencato: ignorato
	})
	if pc.Disks[0].NVMe == nil || pc.Disks[0].Smart != nil {
		t.Errorf("disco 0: %+v", pc.Disks[0])
	}
	if len(pc.Disks[1].Smart) != 1 || pc.Disks[1].NVMe != nil {
		t.Errorf("disco 1: %+v", pc.Disks[1])
	}
	if pc.Disks[2].Smart != nil || pc.Disks[2].NVMe != nil {
		t.Errorf("disco 2: %+v", pc.Disks[2])
	}
	smartOf(pc, nil) // nessuna lettura: niente da fare, nessun panico
}
