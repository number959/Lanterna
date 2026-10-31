package crash

import (
	"encoding/binary"
	"time"
	"unicode/utf16"
)

// Dump sintetici costruiti dai layout verificati (vedi parse.go): nessun
// file reale, nessun dato personale. I nomi dei driver di terze parti sono
// inventati.

type fxModule struct {
	name string
	base uint64
	size uint32
}

type fixture struct {
	bits     int // 64 (predefinito) o 32
	code     uint32
	params   [4]uint64
	dumpType uint32
	build    uint32
	time     time.Time
	fields   uint32 // MiniDumpFields; 0 = 0xDFF come su Windows 10
	drivers  []fxModule
	unloaded []fxModule
	stack    []uint64
	// raw modifica i byte finali, per costruire file incoerenti.
	raw func(b []byte, l layout)
}

// layout sono gli offset assoluti delle parti del minidump costruito.
type layout struct {
	unloaded, stack, drivers, pool, poolSize, size int
}

const fxTimeDefault = "2026-09-27T21:14:03Z"

func putU32(b []byte, off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }
func putU64(b []byte, off int, v uint64) { binary.LittleEndian.PutUint64(b[off:], v) }

func toFiletime(t time.Time) uint64 { return uint64(t.UnixNano()/100) + 116444736000000000 }

func align8(n int) int { return (n + 7) &^ 7 }

// pageFill riempie b con 'PAGE', come fa il kernel per i campi non scritti.
func pageFill(b []byte) {
	for i := 0; i+4 <= len(b); i += 4 {
		copy(b[i:], "PAGE")
	}
}

func (f fixture) bytes() []byte {
	b, _ := f.build64()
	return b
}

func (f fixture) build64() ([]byte, layout) {
	if f.bits == 32 {
		return f.build32(), layout{}
	}
	t := f.time
	if t.IsZero() {
		t, _ = time.Parse(time.RFC3339, fxTimeDefault)
	}
	fields := f.fields
	if fields == 0 {
		fields = 0xDFF
	}
	build := f.build
	if build == 0 {
		build = 26100
	}
	h := make([]byte, header64Size+triage64Size)
	pageFill(h[:header64Size])
	copy(h[0:], "PAGEDU64")
	putU32(h, 0x08, 0x0F)
	putU32(h, 0x0C, build)
	putU32(h, 0x30, 0x8664)
	putU32(h, 0x34, 8)
	putU32(h, 0x38, f.code)
	putU32(h, 0x3C, 0) // riempimento dopo BugCheckCode
	for i, p := range f.params {
		putU64(h, 0x40+8*i, p)
	}
	putU32(h, 0xF98, f.dumpType)
	putU64(h, 0xFA8, toFiletime(t))
	putU32(h, 0x1038, fields)
	if f.dumpType != dumpTypeTriage {
		return h[:header64Size], layout{size: header64Size}
	}

	// Dopo l'intestazione e TRIAGE_DUMP64: driver scaricati, stack, elenco
	// dei driver e nomi, ciascuno allineato a 8 byte come nei dump reali.
	l := layout{unloaded: header64Size + triage64Size + 0x50} // spazio per MM_TRIAGE
	l.stack = align8(l.unloaded + 8 + len(f.unloaded)*unloadEntry)
	l.drivers = align8(l.stack + 8*len(f.stack))
	l.pool = align8(l.drivers + len(f.drivers)*driverEntry)
	var pool []byte
	nameOffs := make([]int, len(f.drivers))
	for i, d := range f.drivers {
		u := utf16.Encode([]rune(d.name))
		e := make([]byte, align8(4+2*len(u)+2))
		putU32(e, 0, uint32(len(u)))
		for j, c := range u {
			binary.LittleEndian.PutUint16(e[4+2*j:], c)
		}
		nameOffs[i] = l.pool + len(pool)
		pool = append(pool, e...)
	}
	l.poolSize = len(pool)
	l.size = align8(l.pool+len(pool)) + 8

	b := make([]byte, l.size)
	copy(b, h)
	tr := b[header64Size:]
	putU32(tr, 0x04, uint32(l.size)) // SizeOfDump
	putU32(tr, 0x08, uint32(l.size-4))
	putU32(tr, 0x0C, 0x348)
	putU32(tr, 0x10, 0xF00)
	putU32(tr, 0x14, header64Size+triage64Size)
	putU32(tr, 0x18, uint32(l.unloaded))
	putU32(tr, 0x28, uint32(l.stack))
	putU32(tr, 0x2C, uint32(8*len(f.stack)))
	putU32(tr, 0x30, uint32(l.drivers))
	putU32(tr, 0x34, uint32(len(f.drivers)))
	putU32(tr, 0x38, uint32(l.pool))
	putU32(tr, 0x3C, uint32(l.poolSize))
	putU64(tr, 0x48, 0xffff8c06072b6938) // TopOfStack: lo stack pointer

	putU64(b, l.unloaded, uint64(len(f.unloaded)))
	for i, u := range f.unloaded {
		e := b[l.unloaded+8+i*unloadEntry:]
		name := utf16.Encode([]rune(u.name))
		binary.LittleEndian.PutUint16(e[0:], uint16(2*len(name)))
		binary.LittleEndian.PutUint16(e[2:], uint16(2*len(name)))
		for j, c := range name {
			if j < 12 {
				binary.LittleEndian.PutUint16(e[0x10+2*j:], c)
			}
		}
		putU64(e, 0x28, u.base)
		putU64(e, 0x30, u.base+uint64(u.size))
	}
	for i, v := range f.stack {
		putU64(b, l.stack+8*i, v)
	}
	for i, d := range f.drivers {
		e := b[l.drivers+i*driverEntry:]
		putU32(e, 0, uint32(nameOffs[i]))
		putU64(e, 0x38, d.base)
		putU64(e, 0x40, d.base+0x1000) // EntryPoint
		putU32(e, 0x48, d.size)
	}
	copy(b[l.pool:], pool)
	copy(b[l.size-4:], "TRGD")
	if f.raw != nil {
		f.raw(b, l)
	}
	return b, l
}

func (f fixture) build32() []byte {
	t := f.time
	if t.IsZero() {
		t, _ = time.Parse(time.RFC3339, fxTimeDefault)
	}
	b := make([]byte, header32Size+0x68)
	pageFill(b[:header32Size])
	copy(b[0:], "PAGEDUMP")
	putU32(b, 0x08, 0x0F)
	putU32(b, 0x0C, 2600)
	putU32(b, 0x20, 0x014C)
	putU32(b, 0x24, 2)
	putU32(b, 0x28, f.code)
	for i, p := range f.params {
		putU32(b, 0x2C+4*i, uint32(p))
	}
	putU32(b, 0xF88, f.dumpType)
	putU32(b, 0xF8C, 0xDFF)
	putU64(b, 0xFC0, toFiletime(t))
	return b
}

// Moduli inventati, con indirizzi del kernel a 64 bit plausibili.
var (
	fxKernel = fxModule{`\SystemRoot\system32\ntoskrnl.exe`, 0xfffff80450000000, 0x1046000}
	fxHal    = fxModule{"hal.dll", 0xfffff80451100000, 0x6000}
	fxNet    = fxModule{`\SystemRoot\System32\drivers\fictnet.sys`, 0xfffff8045b600000, 0x9a000}
	fxAudio  = fxModule{"fictaudio.sys", 0xfffff8045c200000, 0x40000}
	fxOldVPN = fxModule{"oldvpnflt.sys", 0xfffff8045d000000, 0x20000}
)

func fxTriage(code uint32, params [4]uint64, stack ...uint64) fixture {
	return fixture{
		code:     code,
		params:   params,
		dumpType: dumpTypeTriage,
		drivers:  []fxModule{fxKernel, fxHal, fxNet},
		unloaded: []fxModule{fxOldVPN},
		stack:    stack,
	}
}
