package space

import (
	"encoding/binary"
	"unicode/utf16"
)

// FILE_ID_BOTH_DIR_INFO (winbase.h, MS-FSCC FileIdBothDirectoryInformation):
// stessi scostamenti su 386, amd64 e arm64, letti dal buffer senza dipendere
// dall'allineamento delle strutture Go. Con l'attributo di reparse, EaSize
// contiene il tag (come in os.ReadDir).
const (
	offNext      = 0
	offLastWrite = 24
	offEndOfFile = 40
	offAlloc     = 48
	offAttrs     = 56
	offNameLen   = 60
	offEaSize    = 64
	offFileID    = 96
	offName      = 104

	attrDirectory = 0x10
)

// parseDirInfo legge le voci FILE_ID_BOTH_DIR_INFO concatenate nel buffer.
func parseDirInfo(buf []byte, out []entry) []entry {
	le := binary.LittleEndian
	for off := 0; off+offName <= len(buf); {
		b := buf[off:]
		n := int(le.Uint32(b[offNameLen:]))
		if offName+n > len(b) {
			break
		}
		u := make([]uint16, n/2)
		for i := range u {
			u[i] = le.Uint16(b[offName+2*i:])
		}
		name := string(utf16.Decode(u))
		if name != "." && name != ".." {
			attrs := le.Uint32(b[offAttrs:])
			e := entry{
				Name:  name,
				Dir:   attrs&attrDirectory != 0,
				Size:  int64(le.Uint64(b[offEndOfFile:])),
				Alloc: int64(le.Uint64(b[offAlloc:])),
				Attrs: attrs,
				ID:    le.Uint64(b[offFileID:]),
			}
			// Tutti 1: il file system non ha un numero univoco per il file.
			if e.ID == ^uint64(0) {
				e.ID = 0
			}
			if attrs&attrReparse != 0 {
				e.Tag = le.Uint32(b[offEaSize:])
			}
			// FILETIME: centinaia di nanosecondi dal 1601.
			if ft := int64(le.Uint64(b[offLastWrite:])); ft > 116444736000000000 {
				e.Mod = (ft - 116444736000000000) / 10_000_000
			}
			out = append(out, e)
		}
		next := int(le.Uint32(b[offNext:]))
		if next == 0 {
			break
		}
		off += next
	}
	return out
}
