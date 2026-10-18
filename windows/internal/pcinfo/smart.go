package pcinfo

// Decodifica dei dati SMART letti direttamente dal disco, come fanno
// CrystalDiskInfo e smartctl: il blocco degli attributi dei dischi ATA e il
// registro di salute dei dischi NVMe. Sono strutture da 512 byte definite
// dalle specifiche ATA e NVMe; la lettura dal disco è in smart_windows.go.

import (
	"encoding/binary"
	"math"

	"lanterna/internal/scan"
)

// smartEntries è il numero di attributi nel blocco SMART ATA: 30 voci da 12
// byte a partire dall'offset 2 (i primi due byte sono la revisione).
const smartEntries = 30

// ParseSmart decodifica il blocco "SMART READ DATA" e, se letto, quello delle
// soglie ("SMART READ THRESHOLDS"). Ogni attributo occupa 12 byte:
// identificativo, flag (2 byte), valore attuale, peggiore, dato grezzo (6
// byte, little endian) e un byte riservato. Le soglie hanno lo stesso passo:
// identificativo e soglia. Le voci con identificativo zero sono vuote.
func ParseSmart(data, thresholds []byte) []scan.SmartAttr {
	if len(data) < 2+smartEntries*12 {
		return nil
	}
	thr := map[byte]int{}
	if len(thresholds) >= 2+smartEntries*12 {
		for i := range smartEntries {
			o := 2 + i*12
			if id := thresholds[o]; id != 0 {
				thr[id] = int(thresholds[o+1])
			}
		}
	}
	out := []scan.SmartAttr{}
	for i := range smartEntries {
		o := 2 + i*12
		id := data[o]
		if id == 0 || id == 0xFF {
			continue
		}
		var raw int64
		for k := 5; k >= 0; k-- {
			raw = raw<<8 | int64(data[o+5+k])
		}
		a := scan.SmartAttr{
			ID:      int(id),
			Flags:   int(binary.LittleEndian.Uint16(data[o+1:])),
			Current: int(data[o+3]),
			Worst:   int(data[o+4]),
			Raw:     raw,
		}
		if t, ok := thr[id]; ok {
			a.Threshold = &t
		}
		out = append(out, a)
	}
	return out
}

// smartValid scarta i blocchi che alcuni driver restituiscono senza errori ma
// senza dati: tutti zero o tutti 0xFF.
func smartValid(data []byte) bool {
	if len(data) < 2+smartEntries*12 {
		return false
	}
	for i := range smartEntries {
		if id := data[2+i*12]; id != 0 && id != 0xFF {
			return true
		}
	}
	return false
}

// nvmeUnitBytes è il valore di un'unità dei contatori di dati letti e scritti:
// mille blocchi da 512 byte.
const nvmeUnitBytes = 512_000

// ParseNVMeHealth decodifica la pagina di registro 02h della specifica NVMe
// ("SMART / Health Information", 512 byte). I contatori sono a 128 bit: oltre
// i 63 bit (irraggiungibili nella pratica) si saturano.
func ParseNVMeHealth(b []byte) *scan.NVMeHealth {
	if len(b) < 512 {
		return nil
	}
	u128 := func(o int) int64 {
		lo, hi := binary.LittleEndian.Uint64(b[o:]), binary.LittleEndian.Uint64(b[o+8:])
		if hi != 0 || lo > math.MaxInt64 {
			return math.MaxInt64
		}
		return int64(lo)
	}
	gb := func(units int64) float64 { return round1(float64(units) * nvmeUnitBytes / 1e9) }
	h := &scan.NVMeHealth{
		CriticalWarning:     int(b[0]),
		AvailableSparePct:   int(b[3]),
		SpareThresholdPct:   int(b[4]),
		PercentageUsed:      int(b[5]),
		DataReadGB:          gb(u128(32)),
		DataWrittenGB:       gb(u128(48)),
		PowerCycles:         u128(112),
		PowerOnHours:        u128(128),
		UnsafeShutdowns:     u128(144),
		MediaErrors:         u128(160),
		ErrorLogEntries:     u128(176),
		WarningTempMinutes:  int64(binary.LittleEndian.Uint32(b[192:])),
		CriticalTempMinutes: int64(binary.LittleEndian.Uint32(b[196:])),
	}
	// La temperatura composita è in kelvin; zero significa "non riportata".
	if k := int(binary.LittleEndian.Uint16(b[1:])); k > 0 {
		c := k - 273
		h.TemperatureC = &c
	}
	return h
}

// nvmeValid scarta un registro vuoto: un disco funzionante riporta almeno la
// temperatura o la riserva disponibile.
func nvmeValid(b []byte) bool {
	return len(b) >= 512 && (binary.LittleEndian.Uint16(b[1:]) != 0 || b[3] != 0)
}

// smartOf associa ai dischi fisici i dati SMART letti, per numero di disco.
func smartOf(pc *scan.PcData, read map[string]diskSmart) {
	for i := range pc.Disks {
		if s, ok := read[pc.Disks[i].ID]; ok {
			pc.Disks[i].Smart, pc.Disks[i].NVMe = s.Attrs, s.NVMe
		}
	}
}

// diskSmart è ciò che si è riusciti a leggere da un disco.
type diskSmart struct {
	Attrs []scan.SmartAttr
	NVMe  *scan.NVMeHealth
}
