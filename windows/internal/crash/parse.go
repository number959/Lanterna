// Package crash legge i file che Windows salva dopo una schermata blu
// (arresto di sistema, "bug check"), come BlueScreenView ma senza programmi
// esterni: codice di arresto, parametri, ora, tipo di dump e, nei minidump a
// 64 bit, il driver indicato come probabile causa. Solo letture: i file si
// aprono in lettura condivisa e le impostazioni di Windows non si toccano.
//
// Il formato non ha documentazione Microsoft completa. Gli offset vengono da
// fonti pubbliche concordi, verificate compilando le strutture e con
// controlli aritmetici su output pubblici di .dumpdebug (Windows XP, 7 SP1 e
// 10 19041):
//   - DUMP_HEADER64/32 e i valori di DumpType: metadati di mindumpdef.h
//     pubblicati da Microsoft (crate windows-sys, MIT/Apache-2.0), kdmp-parser
//     (MIT), Volatility e Rekall (solo fatti);
//   - TRIAGE_DUMP64, voci dei driver e driver scaricati: Ghidra
//     (Apache-2.0, FileFormats/dump/pagedump) e i valori di .dumpdebug.
//
// Nessun codice è stato copiato: qui ci sono solo offset e costanti.
package crash

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	sigPage   = 0x45474150 // 'PAGE', anche riempimento dei campi non scritti
	validDU64 = 0x34365544 // 'DU64': intestazione a 64 bit
	validDump = 0x504D5544 // 'DUMP': intestazione a 32 bit
	fill64    = 0x4547415045474150

	header64Size = 0x2000
	header32Size = 0x1000
	triage64Size = 0x80
	driverEntry  = 0x90 // DUMP_DRIVER_ENTRY64
	unloadEntry  = 0x38 // DUMP_UNLOADED_DRIVERS64

	dumpTypeTriage = 4

	// Flag di MiniDumpFields (TRIAGE_DUMP_*).
	triageStack      = 0x20
	triageDriverList = 0x40
)

// Limiti di sicurezza: un file danneggiato o costruito ad arte non deve far
// leggere quantità enormi di dati. I valori reali sono molto più bassi
// (180-230 driver, 50 driver scaricati, stack di 16 KB al massimo).
const (
	MaxDrivers      = 2048
	MaxUnloaded     = 64
	MaxStringPool   = 1 << 20
	MaxStackBytes   = 64 << 10
	maxStackDeclare = 1 << 20
	maxNameChars    = 260
	maxStackModules = 6
)

var (
	// ErrNotDump: il file non comincia con la firma dei dump di Windows.
	ErrNotDump = errors.New("non è un file di dump di Windows")
	// ErrTruncated: il file è più corto dell'intestazione.
	ErrTruncated = errors.New("file troncato: intestazione incompleta")
)

// Module è un driver con il suo intervallo di indirizzi [Base, Base+Size).
type Module struct {
	Name     string
	Base     uint64
	Size     uint64
	Unloaded bool
}

func (m Module) contains(a uint64) bool { return a >= m.Base && a-m.Base < m.Size }

// Culprit è il driver indicato come probabile causa.
type Culprit struct {
	Module Module
	// Method: "param" o "stack".
	Method string
	// Param è il numero del parametro (2, 3 o 4) con il metodo "param".
	Param  int
	Offset uint64
}

// Dump è il contenuto utile di un file di dump.
type Dump struct {
	Bits       int
	Code       uint32
	CodeSet    bool
	Params     [4]uint64
	ParamSet   [4]bool
	Machine    uint32
	Build      int
	Processors int
	DumpType   uint32
	TypeSet    bool
	Time       time.Time // zero se assente
	Fields     uint32    // MiniDumpFields
	FieldsSet  bool
	Drivers    []Module
	Unloaded   []Module
	// StackBytes è quanta parte dello stack salvato è stata esaminata.
	StackBytes int
	Probable   *Culprit
	// StackModules: moduli non del kernel trovati nello stack, in ordine.
	StackModules []string
	// Limited: "" analisi completa; "not-triage", "32bit", "too-large",
	// "inconsistent" se ci sono solo i dati dell'intestazione.
	Limited string
	// Reason spiega in breve un'incoerenza (per i test e la diagnostica).
	Reason string
}

// Options regola la lettura.
type Options struct {
	// HeaderOnly legge solo l'intestazione (MEMORY.DMP, file molto grandi).
	HeaderOnly bool
}

// Parse legge un dump da r, lungo size byte. Restituisce un errore solo se il
// file non è un dump o l'intestazione è incompleta; un'incoerenza nei dati
// del minidump lascia i dati dell'intestazione e lo dice in Limited.
func Parse(r io.ReaderAt, size int64, opt Options) (*Dump, error) {
	var sig [8]byte
	if size < 8 {
		return nil, ErrTruncated
	}
	if _, err := r.ReadAt(sig[:], 0); err != nil {
		return nil, ErrTruncated
	}
	le := binary.LittleEndian
	if le.Uint32(sig[0:]) != sigPage {
		return nil, ErrNotDump
	}
	switch le.Uint32(sig[4:]) {
	case validDU64:
		h, err := readAt(r, size, 0, header64Size)
		if err != nil {
			return nil, ErrTruncated
		}
		d := header64(h)
		switch {
		case opt.HeaderOnly:
			if d.TypeSet && d.DumpType == dumpTypeTriage {
				d.Limited = "too-large"
			} else {
				d.Limited = "not-triage"
			}
		case !d.TypeSet || d.DumpType != dumpTypeTriage:
			d.Limited = "not-triage"
		default:
			triage64(r, size, d)
		}
		return d, nil
	case validDump:
		h, err := readAt(r, size, 0, header32Size)
		if err != nil {
			return nil, ErrTruncated
		}
		d := header32(h)
		// Del formato a 32 bit le fonti confermano solo l'intestazione.
		if d.TypeSet && d.DumpType == dumpTypeTriage {
			d.Limited = "32bit"
		} else {
			d.Limited = "not-triage"
		}
		return d, nil
	}
	return nil, ErrNotDump
}

// readAt legge n byte all'offset off, solo se stanno nel file.
func readAt(r io.ReaderAt, size, off, n int64) ([]byte, error) {
	if off < 0 || n < 0 || off > size || n > size-off {
		return nil, io.ErrUnexpectedEOF
	}
	b := make([]byte, n)
	if _, err := r.ReadAt(b, off); err != nil && !(errors.Is(err, io.EOF) && n == 0) {
		return nil, io.ErrUnexpectedEOF
	}
	return b, nil
}

// u32 e u64 leggono un campo; ok è falso se contiene il riempimento 'PAGE'.
func u32(b []byte, off int) (uint32, bool) {
	v := binary.LittleEndian.Uint32(b[off:])
	return v, v != sigPage
}

func u64(b []byte, off int) (uint64, bool) {
	v := binary.LittleEndian.Uint64(b[off:])
	return v, v != fill64
}

// filetime converte un FILETIME (intervalli di 100 ns dal 1601, UTC); zero
// se assente o fuori da un intervallo plausibile.
func filetime(v uint64, ok bool) time.Time {
	if !ok || v == 0 || v > 1<<62 {
		return time.Time{}
	}
	const epochDiff = 116444736000000000 // dal 1601 al 1970, in 100 ns
	if v < epochDiff {
		return time.Time{}
	}
	t := time.Unix(0, int64(v-epochDiff)*100).UTC()
	if t.Year() < 2000 || t.Year() > 2100 {
		return time.Time{}
	}
	return t
}

func header64(h []byte) *Dump {
	d := &Dump{Bits: 64}
	if v, ok := u32(h, 0x0C); ok && v < 100000 {
		d.Build = int(v)
	}
	d.Machine, _ = u32(h, 0x30)
	if v, ok := u32(h, 0x34); ok && v <= 4096 {
		d.Processors = int(v)
	}
	d.Code, d.CodeSet = u32(h, 0x38)
	for i := 0; i < 4; i++ {
		d.Params[i], d.ParamSet[i] = u64(h, 0x40+8*i)
	}
	d.DumpType, d.TypeSet = u32(h, 0xF98)
	t, ok := u64(h, 0xFA8)
	d.Time = filetime(t, ok)
	d.Fields, d.FieldsSet = u32(h, 0x1038)
	return d
}

func header32(h []byte) *Dump {
	d := &Dump{Bits: 32}
	if v, ok := u32(h, 0x0C); ok && v < 100000 {
		d.Build = int(v)
	}
	d.Machine, _ = u32(h, 0x20)
	if v, ok := u32(h, 0x24); ok && v <= 4096 {
		d.Processors = int(v)
	}
	d.Code, d.CodeSet = u32(h, 0x28)
	for i := 0; i < 4; i++ {
		v, ok := u32(h, 0x2C+4*i)
		d.Params[i], d.ParamSet[i] = uint64(v), ok
	}
	d.DumpType, d.TypeSet = u32(h, 0xF88)
	d.Fields, d.FieldsSet = u32(h, 0xF8C)
	t, ok := u64(h, 0xFC0)
	d.Time = filetime(t, ok)
	return d
}

// triage64 legge la parte del minidump a 64 bit che segue l'intestazione:
// driver caricati e scaricati, stack salvato. Gli offset di TRIAGE_DUMP64
// sono assoluti nel file.
func triage64(r io.ReaderAt, size int64, d *Dump) {
	fail := func(why string) {
		d.Drivers, d.Unloaded, d.StackBytes, d.Probable, d.StackModules = nil, nil, 0, nil, nil
		d.Limited, d.Reason = "inconsistent", why
	}
	t, err := readAt(r, size, header64Size, triage64Size)
	if err != nil {
		fail("dati del minidump mancanti")
		return
	}
	le := binary.LittleEndian
	const first = header64Size + triage64Size // nulla può stare prima
	fields := uint32(0xFFFFFFFF)
	if d.FieldsSet {
		fields = d.Fields
	}
	inFile := func(off, n uint64) bool { return off >= first && off <= uint64(size) && n <= uint64(size)-off }

	if fields&triageDriverList != 0 {
		off, count := uint64(le.Uint32(t[0x30:])), uint64(le.Uint32(t[0x34:]))
		pool, poolSize := uint64(le.Uint32(t[0x38:])), uint64(le.Uint32(t[0x3C:]))
		if count > MaxDrivers {
			fail(fmt.Sprintf("troppi driver (%d)", count))
			return
		}
		if count > 0 {
			if !inFile(off, count*driverEntry) {
				fail("elenco dei driver fuori dal file")
				return
			}
			if poolSize < 6 || poolSize > MaxStringPool || !inFile(pool, poolSize) {
				fail("nomi dei driver fuori dal file")
				return
			}
			list, err1 := readAt(r, size, int64(off), int64(count*driverEntry))
			names, err2 := readAt(r, size, int64(pool), int64(poolSize))
			if err1 != nil || err2 != nil {
				fail("elenco dei driver non leggibile")
				return
			}
			for i := uint64(0); i < count; i++ {
				e := list[i*driverEntry:]
				nameOff := uint64(le.Uint32(e[0:]))
				if nameOff < pool || nameOff+4 > pool+poolSize {
					fail("nome di un driver fuori dall'elenco dei nomi")
					return
				}
				name, ok := utf16z(names[nameOff+4-pool:], true)
				if !ok || name == "" {
					fail("nome di un driver non valido")
					return
				}
				base, span := le.Uint64(e[0x38:]), uint64(le.Uint32(e[0x48:]))
				if base+span < base {
					fail("intervallo di un driver non valido")
					return
				}
				d.Drivers = append(d.Drivers, Module{Name: BaseName(name), Base: base, Size: span})
			}
		}
	}

	if off := uint64(le.Uint32(t[0x18:])); off != 0 {
		if !inFile(off, 8) {
			fail("driver scaricati fuori dal file")
			return
		}
		c, _ := readAt(r, size, int64(off), 8)
		count := le.Uint64(c)
		if count > MaxUnloaded || !inFile(off+8, count*unloadEntry) {
			fail("elenco dei driver scaricati non valido")
			return
		}
		list, err := readAt(r, size, int64(off+8), int64(count*unloadEntry))
		if err != nil {
			fail("elenco dei driver scaricati non leggibile")
			return
		}
		for i := uint64(0); i < count; i++ {
			e := list[i*unloadEntry:]
			// Il nome è in DriverName (12 caratteri al massimo); Name.Length
			// dice quanti sono validi, in byte.
			chars, cut := int(le.Uint16(e[0:]))/2, false
			if chars > 12 {
				chars, cut = 12, true
			}
			name, _ := utf16z(e[0x10:0x10+2*chars], false)
			start, end := le.Uint64(e[0x28:]), le.Uint64(e[0x30:])
			if name == "" || end <= start {
				continue
			}
			if cut && len([]rune(name)) == 12 {
				name += "…" // nome più lungo, troncato da Windows
			}
			d.Unloaded = append(d.Unloaded, Module{Name: BaseName(name), Base: start, Size: end - start, Unloaded: true})
		}
	}

	var stack []byte
	if fields&triageStack != 0 {
		off, n := uint64(le.Uint32(t[0x28:])), uint64(le.Uint32(t[0x2C:]))
		if n > maxStackDeclare || n > 0 && !inFile(off, n) {
			fail("stack salvato fuori dal file")
			return
		}
		if n > MaxStackBytes {
			n = MaxStackBytes
		}
		if n > 0 {
			if stack, err = readAt(r, size, int64(off), int64(n)); err != nil {
				fail("stack salvato non leggibile")
				return
			}
		}
	}
	d.StackBytes = len(stack)
	attribute(d, stack)
}

// utf16z decodifica una stringa UTF-16LE fino al primo NUL, entro b e al più
// maxNameChars caratteri; ok è falso con caratteri di controllo, con un nome
// troppo lungo o, se needNul, quando il NUL non c'è prima della fine di b
// (i nomi dei driver scaricati stanno invece in un campo fisso di 12
// caratteri, che può essere pieno).
func utf16z(b []byte, needNul bool) (string, bool) {
	var u []uint16
	terminated := false
	for i := 0; i+1 < len(b) && len(u) <= maxNameChars; i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			terminated = true
			break
		}
		if c < 0x20 || c == 0x7F {
			return "", false
		}
		u = append(u, c)
	}
	if len(u) > maxNameChars || needNul && !terminated {
		return "", false
	}
	return string(utf16.Decode(u)), true
}

// BaseName toglie il percorso: "\SystemRoot\system32\drivers\x.sys" -> "x.sys".
// Nei minidump di Windows 7 i nomi sono percorsi completi, che possono
// contenere la cartella di un utente.
func BaseName(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		p = p[i+1:]
	}
	return strings.TrimSpace(p)
}

// addrParam indica, per i codici documentati, quale parametro contiene
// l'indirizzo dell'istruzione che ha causato l'arresto (Microsoft Learn,
// "Bug check code reference": 0xA e 0xD1 parametro 4; 0x1E, 0x7E, 0x8E,
// 0x3B, 0x1000007E e 0x1000008E parametro 2; 0x50 parametro 3).
var addrParam = map[uint32]int{
	0x0000000A: 4,
	0x000000D1: 4,
	0x0000001E: 2,
	0x0000007E: 2,
	0x1000007E: 2,
	0x0000008E: 2,
	0x1000008E: 2,
	0x0000003B: 2,
	0x00000050: 3,
}

// noCulprit sono i codici per cui un driver nello stack non è un indizio:
// errore segnalato dall'hardware (0x124, WHEA) e arresti provocati a mano
// (0xE2 dalla tastiera, 0x1C8 tenendo premuto il pulsante, 0xDEADDEAD).
var noCulprit = map[uint32]bool{0x124: true, 0xE2: true, 0x1C8: true, 0xDEADDEAD: true}

// Manual dice se il codice è di un arresto provocato di proposito (0xE2,
// 0x1C8, 0xDEADDEAD): non c'è un driver da cercare.
func Manual(code uint32) bool { return code != 0x124 && noCulprit[code] }

// ignored sono i moduli del nucleo di Windows: kernel, HAL e PSHED compaiono
// in quasi ogni stack perché sono loro a gestire interruzioni, eccezioni ed
// errori hardware e a chiamare KeBugCheckEx. Come la parola chiave "ignore"
// di triage.ini nel debugger di Microsoft, si saltano per arrivare al primo
// driver che non è del nucleo.
var ignored = map[string]bool{
	"ntoskrnl.exe": true, "ntkrnlmp.exe": true, "ntkrnlpa.exe": true, "ntkrpamp.exe": true, "ntkrla57.exe": true,
	"hal.dll": true, "halacpi.dll": true, "halapic.dll": true, "halmacpi.dll": true, "halaacpi.dll": true,
	"pshed.dll": true,
}

// Ignored dice se un modulo è del nucleo di Windows e non si indica mai come causa.
func Ignored(name string) bool { return ignored[strings.ToLower(name)] }

// AddrParam restituisce il parametro con l'indirizzo dell'istruzione per il
// codice indicato (0 se il codice non ne ha uno documentato).
func AddrParam(code uint32) int { return addrParam[code] }

// attribute cerca il driver indicato: prima l'indirizzo del parametro
// documentato per il codice, poi lo stack salvato, un valore di 8 byte alla
// volta, come nell'esame manuale dello stack descritto da Microsoft. I
// valori nello stack possono essere resti di chiamate precedenti: il
// risultato è un indizio.
func attribute(d *Dump, stack []byte) {
	if !d.CodeSet || noCulprit[d.Code] {
		return
	}
	loaded := sorted(d.Drivers)
	unloaded := sorted(d.Unloaded)
	find := func(a uint64) *Module {
		if m := lookup(loaded, a); m != nil {
			return m
		}
		return lookup(unloaded, a)
	}
	if p := addrParam[d.Code]; p > 0 && d.ParamSet[p-1] {
		a := d.Params[p-1]
		if m := find(a); m != nil && !Ignored(m.Name) {
			d.Probable = &Culprit{Module: *m, Method: "param", Param: p, Offset: a - m.Base}
		}
	}
	seen := map[string]bool{}
	for i := 0; i+8 <= len(stack); i += 8 {
		a := binary.LittleEndian.Uint64(stack[i:])
		m := find(a)
		if m == nil || Ignored(m.Name) {
			continue
		}
		if d.Probable == nil {
			d.Probable = &Culprit{Module: *m, Method: "stack", Offset: a - m.Base}
		}
		key := strings.ToLower(m.Name)
		if !seen[key] && len(d.StackModules) < maxStackModules {
			seen[key] = true
			d.StackModules = append(d.StackModules, m.Name)
		}
	}
}

func sorted(ms []Module) []Module {
	out := make([]Module, 0, len(ms))
	for _, m := range ms {
		if m.Base != 0 && m.Size != 0 {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Base < out[j].Base })
	return out
}

// lookup trova il modulo che contiene a (l'ultimo che comincia prima di a).
func lookup(ms []Module, a uint64) *Module {
	i := sort.Search(len(ms), func(i int) bool { return ms[i].Base > a }) - 1
	if i >= 0 && ms[i].contains(a) {
		return &ms[i]
	}
	return nil
}

// TypeName dà il nome breve del tipo di dump (DUMP_TYPE di mindumpdef.h;
// 8, 9 e 10 sono i tipi scritti dal debugger con .dump).
func TypeName(t uint32, set bool) string {
	if !set {
		return "unknown"
	}
	switch t {
	case 1, 10:
		return "full"
	case 2, 8:
		return "kernel"
	case 3:
		return "header"
	case 4:
		return "triage"
	case 5:
		return "bitmap-full"
	case 6:
		return "bitmap-kernel"
	case 7:
		return "automatic"
	case 9:
		return "kernel-user"
	}
	return "unknown"
}

// MachineName dà l'architettura da MachineImageType (IMAGE_FILE_MACHINE_*).
func MachineName(m uint32) string {
	switch m {
	case 0x8664:
		return "x64"
	case 0x014C:
		return "x86"
	case 0xAA64:
		return "arm64"
	}
	return ""
}
