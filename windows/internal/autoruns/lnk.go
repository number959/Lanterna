package autoruns

import (
	"encoding/binary"
	"strings"
	"unicode/utf16"
)

// shortcut sono le parti di un collegamento .lnk che servono: il file a cui
// punta e gli argomenti.
type shortcut struct {
	Target   string // percorso assoluto, eventualmente con %VARIABILI%
	Relative string // percorso relativo alla cartella del collegamento
	Args     string
}

// Costanti del formato Shell Link ([MS-SHLLINK], specifica aperta di
// Microsoft): intestazione di 0x4C byte con il CLSID
// 00021401-0000-0000-C000-000000000046.
const (
	lnkHeaderSize       = 0x4C
	lnkHasIDList        = 0x1
	lnkHasLinkInfo      = 0x2
	lnkHasName          = 0x4
	lnkHasRelativePath  = 0x8
	lnkHasWorkingDir    = 0x10
	lnkHasArguments     = 0x20
	lnkHasIconLocation  = 0x40
	lnkIsUnicode        = 0x80
	lnkForceNoLinkInfo  = 0x100
	lnkHasExpString     = 0x200
	lnkEnvBlockSig      = 0xA0000001
	lnkEnvBlockSize     = 0x314
	linkInfoLocalPath   = 0x1
	linkInfoUnicodeHead = 0x24
)

var lnkCLSID = []byte{0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}

// parseLnk legge un collegamento .lnk senza usare la shell (niente COM):
// destinazione da EnvironmentVariableDataBlock (se il collegamento usa le
// variabili), da LinkInfo (LocalBasePath + CommonPathSuffix) o dal percorso
// relativo, più gli argomenti. Ogni lettura controlla i limiti: un file
// rovinato restituisce false, mai un errore di memoria.
func parseLnk(b []byte) (shortcut, bool) {
	var sc shortcut
	if len(b) < lnkHeaderSize || binary.LittleEndian.Uint32(b) != lnkHeaderSize || string(b[4:20]) != string(lnkCLSID) {
		return sc, false
	}
	flags := binary.LittleEndian.Uint32(b[0x14:])
	off := lnkHeaderSize
	u16 := func(at int) (int, bool) {
		if at < 0 || at+2 > len(b) {
			return 0, false
		}
		return int(binary.LittleEndian.Uint16(b[at:])), true
	}
	u32 := func(at int) (int, bool) {
		if at < 0 || at+4 > len(b) {
			return 0, false
		}
		return int(binary.LittleEndian.Uint32(b[at:])), true
	}
	if flags&lnkHasIDList != 0 {
		n, ok := u16(off)
		if !ok {
			return sc, false
		}
		off += 2 + n
	}
	base := ""
	if flags&lnkHasLinkInfo != 0 {
		size, ok := u32(off)
		if !ok || size < 0x1C || off+size > len(b) {
			return sc, false
		}
		li := b[off : off+size]
		head := int(binary.LittleEndian.Uint32(li[4:]))
		liFlags := binary.LittleEndian.Uint32(li[8:])
		if flags&lnkForceNoLinkInfo == 0 && liFlags&linkInfoLocalPath != 0 {
			lbp := int(binary.LittleEndian.Uint32(li[16:]))
			cps := int(binary.LittleEndian.Uint32(li[24:]))
			if head >= linkInfoUnicodeHead && len(li) >= linkInfoUnicodeHead {
				base = utf16z(li, int(binary.LittleEndian.Uint32(li[28:]))) + utf16z(li, int(binary.LittleEndian.Uint32(li[32:])))
			}
			if base == "" {
				base = ansiz(li, lbp) + ansiz(li, cps)
			}
		}
		off += size
	}
	unicode := flags&lnkIsUnicode != 0
	str := func() (string, bool) {
		n, ok := u16(off)
		if !ok {
			return "", false
		}
		off += 2
		if unicode {
			if off+2*n > len(b) {
				return "", false
			}
			s := decodeUTF16(b[off : off+2*n])
			off += 2 * n
			return s, true
		}
		if off+n > len(b) {
			return "", false
		}
		s := latin1(b[off : off+n])
		off += n
		return s, true
	}
	for _, f := range []uint32{lnkHasName, lnkHasRelativePath, lnkHasWorkingDir, lnkHasArguments, lnkHasIconLocation} {
		if flags&f == 0 {
			continue
		}
		s, ok := str()
		if !ok {
			return sc, false
		}
		switch f {
		case lnkHasRelativePath:
			sc.Relative = s
		case lnkHasArguments:
			sc.Args = strings.TrimSpace(s)
		}
	}
	env := ""
	for off+8 <= len(b) {
		size, _ := u32(off)
		if size < 8 || off+size > len(b) {
			break
		}
		sig, _ := u32(off + 4)
		if uint32(sig) == lnkEnvBlockSig && size >= lnkEnvBlockSize {
			// TargetAnsi (260 byte) e poi TargetUnicode (260 caratteri).
			env = utf16z(b[off:off+size], 8+260)
			if env == "" {
				env = ansiz(b[off:off+size], 8)
			}
		}
		off += size
	}
	switch {
	case flags&lnkHasExpString != 0 && env != "":
		sc.Target = env
	case base != "":
		sc.Target = base
	}
	return sc, sc.Target != "" || sc.Relative != ""
}

// utf16z legge una stringa UTF-16 terminata da zero a partire da at.
func utf16z(b []byte, at int) string {
	if at <= 0 || at >= len(b) {
		return ""
	}
	end := at
	for end+1 < len(b) && (b[end] != 0 || b[end+1] != 0) {
		end += 2
	}
	return decodeUTF16(b[at:end])
}

func decodeUTF16(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}

// ansiz legge una stringa terminata da zero nella code page del sistema,
// letta qui come Latin-1 (basta per i percorsi; le forme Unicode hanno la
// precedenza quando ci sono).
func ansiz(b []byte, at int) string {
	if at <= 0 || at >= len(b) {
		return ""
	}
	end := at
	for end < len(b) && b[end] != 0 {
		end++
	}
	return latin1(b[at:end])
}

func latin1(b []byte) string {
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return string(r)
}
