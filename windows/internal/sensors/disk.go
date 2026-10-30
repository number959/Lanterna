package sensors

import "encoding/binary"

// STORAGE_TEMPERATURE_DATA_DESCRIPTOR (ntddstor.h), risposta a
// IOCTL_STORAGE_QUERY_PROPERTY con StorageDeviceTemperatureProperty: Version,
// Size, CriticalTemperature (+8) e WarningTemperature (+10) in °C con segno,
// InfoCount (+12), poi da +24 le voci STORAGE_TEMPERATURE_INFO da 16 byte
// (Index +0, Temperature +2, OverThreshold +4). 0x8000 vuol dire "non
// riportato". La voce 0 è di solito la temperatura complessiva (composite)
// degli NVMe.
const (
	storageDeviceTemperatureProperty = 52
	tempNotReported                  = -32768
)

// parseStorageTemp restituisce temperatura e soglie del disco (NaN se non
// riportate); false se non c'è una temperatura plausibile.
func parseStorageTemp(b []byte) (temp, warn, crit float64, valid bool) {
	temp, warn, crit = nan, nan, nan
	if len(b) < 24 {
		return
	}
	le := binary.LittleEndian
	n := int(le.Uint16(b[12:]))
	n = min(n, (len(b)-24)/16)
	if size := int(le.Uint32(b[4:])); size >= 24 {
		n = min(n, (size-24)/16)
	}
	plausible := func(v int16) bool { return v != tempNotReported && v > -40 && v < 150 }
	if c := int16(le.Uint16(b[8:])); plausible(c) && c > 0 {
		crit = float64(c)
	}
	if w := int16(le.Uint16(b[10:])); plausible(w) && w > 0 {
		warn = float64(w)
	}
	for i := 0; i < n; i++ {
		e := b[24+16*i:]
		index, t, over := le.Uint16(e[0:]), int16(le.Uint16(e[2:])), int16(le.Uint16(e[4:]))
		// Sensori non implementati: 0 °C con soglia 0, oppure indici assurdi.
		if !plausible(t) || index > 8 || t == 0 && over == 0 {
			continue
		}
		if !valid || index == 0 {
			temp, valid = float64(t), true
		}
		if index == 0 {
			break
		}
	}
	return
}
