package autoruns

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

// lnkSpec descrive un collegamento .lnk da costruire secondo [MS-SHLLINK].
type lnkSpec struct {
	idList   bool   // con un LinkTargetIDList (saltato dal lettore)
	local    string // LocalBasePath (ANSI e, se unicode, anche Unicode)
	unicode  bool   // LinkInfo con le forme Unicode
	relative string
	args     string
	env      string // EnvironmentVariableDataBlock
}

func le16(v int) []byte { b := make([]byte, 2); binary.LittleEndian.PutUint16(b, uint16(v)); return b }
func le32(v int) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, uint32(v)); return b }

func utf16Bytes(s string, zero bool) []byte {
	u := utf16.Encode([]rune(s))
	if zero {
		u = append(u, 0)
	}
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

func buildLnk(t *testing.T, s lnkSpec) []byte {
	t.Helper()
	flags := lnkIsUnicode
	if s.idList {
		flags |= lnkHasIDList
	}
	if s.local != "" {
		flags |= lnkHasLinkInfo
	}
	if s.relative != "" {
		flags |= lnkHasRelativePath
	}
	if s.args != "" {
		flags |= lnkHasArguments
	}
	if s.env != "" {
		flags |= lnkHasExpString
	}
	h := make([]byte, lnkHeaderSize)
	copy(h, le32(lnkHeaderSize))
	copy(h[4:], lnkCLSID)
	copy(h[0x14:], le32(flags))
	out := h
	if s.idList {
		out = append(out, le16(4)...)
		out = append(out, 2, 0, 0, 0) // un ItemID vuoto e il terminatore
	}
	if s.local != "" {
		head := 0x1C
		if s.unicode {
			head = 0x24
		}
		ansi := append([]byte(s.local), 0)
		suffix := []byte{0}
		lbp := head
		cps := lbp + len(ansi)
		body := append(append([]byte{}, ansi...), suffix...)
		var lbpU, cpsU int
		if s.unicode {
			lbpU = head + len(body)
			u := utf16Bytes(s.local, true)
			cpsU = lbpU + len(u)
			body = append(append(body, u...), 0, 0)
		}
		li := le32(head + len(body))
		li = append(li, le32(head)...)
		li = append(li, le32(linkInfoLocalPath)...)
		li = append(li, le32(0)...) // VolumeIDOffset (non serve)
		li = append(li, le32(lbp)...)
		li = append(li, le32(0)...)
		li = append(li, le32(cps)...)
		if s.unicode {
			li = append(li, le32(lbpU)...)
			li = append(li, le32(cpsU)...)
		}
		out = append(append(out, li...), body...)
	}
	for _, str := range []string{s.relative, s.args} {
		if str == "" {
			continue
		}
		out = append(out, le16(len(utf16.Encode([]rune(str))))...)
		out = append(out, utf16Bytes(str, false)...)
	}
	if s.env != "" {
		blk := make([]byte, lnkEnvBlockSize)
		copy(blk, le32(lnkEnvBlockSize))
		binary.LittleEndian.PutUint32(blk[4:], lnkEnvBlockSig)
		copy(blk[8:], s.env)
		copy(blk[8+260:], utf16Bytes(s.env, true))
		out = append(out, blk...)
	}
	return append(out, le32(0)...) // TerminalBlock
}

func TestParseLnk(t *testing.T) {
	for _, c := range []struct {
		spec   lnkSpec
		target string
		rel    string
		args   string
	}{
		{lnkSpec{idList: true, local: `C:\Program Files\App\app.exe`, unicode: true, args: "--min"}, `C:\Program Files\App\app.exe`, "", "--min"},
		{lnkSpec{local: `C:\Tools\a.exe`}, `C:\Tools\a.exe`, "", ""},
		{lnkSpec{local: `C:\Users\Zoë\x.exe`, unicode: true}, `C:\Users\Zoë\x.exe`, "", ""},
		{lnkSpec{local: `C:\Users\anna\AppData\Local\x.exe`, env: `%LOCALAPPDATA%\x.exe`}, `%LOCALAPPDATA%\x.exe`, "", ""},
		{lnkSpec{relative: `..\..\bin\b.exe`, args: "-q"}, "", `..\..\bin\b.exe`, "-q"},
	} {
		b := buildLnk(t, c.spec)
		sc, ok := parseLnk(b)
		if !ok || sc.Target != c.target || sc.Relative != c.rel || sc.Args != c.args {
			t.Errorf("%+v: %+v %v", c.spec, sc, ok)
		}
		// Ogni troncamento si rifiuta o si legge senza errori di memoria.
		for n := 0; n < len(b); n++ {
			parseLnk(b[:n])
		}
	}
	if _, ok := parseLnk([]byte("MZ")); ok {
		t.Error("file non .lnk accettato")
	}
	b := buildLnk(t, lnkSpec{local: `C:\a.exe`})
	b[4] ^= 0xFF
	if _, ok := parseLnk(b); ok {
		t.Error("CLSID sbagliato accettato")
	}
}

func FuzzParseLnk(f *testing.F) {
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) >= 20 {
			copy(b, le32(lnkHeaderSize))
			copy(b[4:], lnkCLSID)
		}
		parseLnk(b)
	})
}
