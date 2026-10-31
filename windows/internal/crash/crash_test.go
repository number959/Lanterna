package crash

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lanterna/internal/scan"
)

func parse(t *testing.T, b []byte, opt Options) *Dump {
	t.Helper()
	d, err := Parse(bytes.NewReader(b), int64(len(b)), opt)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return d
}

func TestPublicLayoutArithmetic(t *testing.T) {
	// Controlli sui valori pubblici di .dumpdebug (Windows 7 SP1 e 10 19041,
	// x64) che fissano le costanti usate dal parser.
	if header64Size+triage64Size != 0x2080 { // MmOffset osservato
		t.Fatal("TRIAGE_DUMP64 non finisce a 0x2080")
	}
	if (0xECF0-0x87B0)/0xB4 != driverEntry || (0x185E8-0x107E8)/0xE0 != driverEntry {
		t.Fatal("passo delle voci dei driver diverso da 0x90")
	}
	if 0x7948+0xB28 != 0x8470 { // CallStackOffset + SizeOfCallStack = DebuggerDataOffset
		t.Fatal("regioni non contigue")
	}
	if 8+50*unloadEntry != 0xAF8 { // 50 driver scaricati su Windows 10
		t.Fatal("dimensione dei driver scaricati")
	}
	if header32Size+0x68 != 0x1068 {
		t.Fatal("MmOffset a 32 bit")
	}
}

func TestHeader64(t *testing.T) {
	when := time.Date(2026, 9, 27, 21, 14, 3, 0, time.UTC)
	b := fixture{code: 0x9F, params: [4]uint64{3, 0xffffe50c3c7a5060, 0xfffff8045b67f7b0, 0xffffe50c4a3c9010}, dumpType: 6, time: when, build: 22621}.bytes()
	d := parse(t, b, Options{})
	if d.Bits != 64 || d.Code != 0x9F || !d.CodeSet || d.Build != 22621 || d.Processors != 8 || MachineName(d.Machine) != "x64" {
		t.Fatalf("intestazione: %+v", d)
	}
	if !d.Time.Equal(when) {
		t.Fatalf("ora: %v", d.Time)
	}
	if TypeName(d.DumpType, d.TypeSet) != "bitmap-kernel" || d.Limited != "not-triage" || d.Drivers != nil {
		t.Fatalf("tipo: %s %q", TypeName(d.DumpType, d.TypeSet), d.Limited)
	}
	var cd scan.CrashDump
	fill(&cd, d)
	if cd.Code != "0x0000009f" || cd.Params[1] != "0xffffe50c3c7a5060" || cd.Params[0] != "0x0000000000000003" || cd.Time != "2026-09-27T21:14:03Z" {
		t.Fatalf("formato: %+v", cd)
	}
}

func TestHeader32(t *testing.T) {
	b := fixture{bits: 32, code: 0x96, params: [4]uint64{0x8a3e5f20, 1, 2, 3}, dumpType: dumpTypeTriage}.bytes()
	d := parse(t, b, Options{})
	if d.Bits != 32 || d.Code != 0x96 || d.Build != 2600 || MachineName(d.Machine) != "x86" || d.Processors != 2 {
		t.Fatalf("intestazione a 32 bit: %+v", d)
	}
	// Del triage a 32 bit le fonti confermano solo l'intestazione.
	if d.Limited != "32bit" || len(d.Drivers) != 0 || d.Probable != nil {
		t.Fatalf("triage a 32 bit: %+v", d)
	}
	var cd scan.CrashDump
	fill(&cd, d)
	if cd.Params[0] != "0x8a3e5f20" || cd.Code != "0x00000096" || cd.Bits != 32 {
		t.Fatalf("parametri a 32 bit: %+v", cd)
	}
	k := parse(t, fixture{bits: 32, code: 0xA, dumpType: 1}.bytes(), Options{})
	if k.Limited != "not-triage" || TypeName(k.DumpType, k.TypeSet) != "full" {
		t.Fatalf("dump completo a 32 bit: %+v", k)
	}
}

func TestPageFillIsUnset(t *testing.T) {
	b := make([]byte, header64Size)
	pageFill(b)
	copy(b[4:], "DU64")
	d := parse(t, b, Options{})
	if d.CodeSet || d.TypeSet || !d.Time.IsZero() || d.Build != 0 || d.Processors != 0 || d.FieldsSet {
		t.Fatalf("i campi 'PAGE' devono risultare non impostati: %+v", d)
	}
	for i, ok := range d.ParamSet {
		if ok {
			t.Fatalf("parametro %d impostato", i+1)
		}
	}
	var cd scan.CrashDump
	fill(&cd, d)
	if cd.Code != "" || cd.Params != nil || cd.Time != "" || cd.DumpType != "unknown" || cd.Limited != "not-triage" {
		t.Fatalf("dump senza dati: %+v", cd)
	}
	// Un minidump con parametri 'PAGE' non usa il metodo del parametro.
	f := fxTriage(0xD1, [4]uint64{fill64, fill64, fill64, fill64}, fxNet.base+0x10)
	d = parse(t, f.bytes(), Options{})
	if d.Probable == nil || d.Probable.Method != "stack" {
		t.Fatalf("parametro non impostato: %+v", d.Probable)
	}
}

func TestTriageDrivers(t *testing.T) {
	b := fxTriage(0x9F, [4]uint64{3}).bytes()
	d := parse(t, b, Options{})
	if d.Limited != "" || len(d.Drivers) != 3 || len(d.Unloaded) != 1 {
		t.Fatalf("minidump: limited=%q reason=%q drivers=%d unloaded=%d", d.Limited, d.Reason, len(d.Drivers), len(d.Unloaded))
	}
	want := []string{"ntoskrnl.exe", "hal.dll", "fictnet.sys"}
	for i, w := range want {
		if d.Drivers[i].Name != w {
			t.Fatalf("driver %d: %q", i, d.Drivers[i].Name)
		}
	}
	if d.Drivers[2].Base != fxNet.base || d.Drivers[2].Size != uint64(fxNet.size) {
		t.Fatalf("intervallo: %+v", d.Drivers[2])
	}
	// DriverName ha 12 caratteri: "oldvpnflt.sys" ne ha 13 e Windows lo tronca.
	if u := d.Unloaded[0]; u.Name != "oldvpnflt.sy…" || !u.Unloaded || u.Size != uint64(fxOldVPN.size) {
		t.Fatalf("driver scaricato: %+v", u)
	}
	if d.Probable != nil {
		t.Fatalf("senza stack né parametro non c'è indizio: %+v", d.Probable)
	}
}

func TestParamAttributionD1(t *testing.T) {
	// Come nel dump pubblico di Windows 7: 0xD1 con il parametro 4 dentro un
	// driver di terze parti.
	p4 := fxNet.base + 0x3c78
	f := fxTriage(0xD1, [4]uint64{0x34, 2, 1, p4}, fxKernel.base+0x100, fxAudio.base+0x20)
	f.drivers = append(f.drivers, fxAudio)
	d := parse(t, f.bytes(), Options{})
	if d.Probable == nil || d.Probable.Module.Name != "fictnet.sys" || d.Probable.Method != "param" || d.Probable.Param != 4 || d.Probable.Offset != 0x3c78 {
		t.Fatalf("indizio dal parametro: %+v", d.Probable)
	}
	if strings.Join(d.StackModules, ",") != "fictaudio.sys" {
		t.Fatalf("moduli nello stack: %v", d.StackModules)
	}
	var cd scan.CrashDump
	fill(&cd, d)
	if cd.Probable.Driver != "fictnet.sys" || cd.Probable.Offset != "0x3c78" || cd.Drivers != 4 || cd.DumpType != "triage" {
		t.Fatalf("rapporto: %+v %+v", cd, cd.Probable)
	}
	// Gli altri codici con indirizzo documentato.
	for code, p := range map[uint32]int{0x0A: 4, 0x1E: 2, 0x7E: 2, 0x1000007E: 2, 0x8E: 2, 0x3B: 2, 0x50: 3} {
		var params [4]uint64
		params[p-1] = fxNet.base + 8
		d := parse(t, fxTriage(code, params).bytes(), Options{})
		if d.Probable == nil || d.Probable.Param != p || d.Probable.Module.Name != "fictnet.sys" {
			t.Errorf("codice 0x%X: %+v", code, d.Probable)
		}
	}
}

func TestStackAttribution(t *testing.T) {
	f := fxTriage(0x9F, [4]uint64{3, 0xffffe50c3c7a5060},
		0x0000000000000001,  // valore qualunque
		fxKernel.base+0x4ae, // il kernel si salta
		fxHal.base+0x10,     // anche la HAL
		0xfffff80499999999,  // fuori da ogni modulo
		fxAudio.base+0x1234, // il primo driver di terze parti
		fxNet.base+0x500,
		fxAudio.base+0x99, // già visto
	)
	f.drivers = append(f.drivers, fxAudio)
	d := parse(t, f.bytes(), Options{})
	if d.Probable == nil || d.Probable.Module.Name != "fictaudio.sys" || d.Probable.Method != "stack" || d.Probable.Offset != 0x1234 {
		t.Fatalf("indizio dallo stack: %+v", d.Probable)
	}
	if strings.Join(d.StackModules, ",") != "fictaudio.sys,fictnet.sys" || d.StackBytes != 56 {
		t.Fatalf("moduli nello stack: %v (%d byte)", d.StackModules, d.StackBytes)
	}
}

func TestParamInKernelFallsBackToStack(t *testing.T) {
	d := parse(t, fxTriage(0x3B, [4]uint64{0xc0000005, fxKernel.base + 0x40}, fxNet.base+0x77).bytes(), Options{})
	if d.Probable == nil || d.Probable.Method != "stack" || d.Probable.Module.Name != "fictnet.sys" {
		t.Fatalf("parametro nel kernel: %+v", d.Probable)
	}
	// Solo moduli del kernel: nessun indizio.
	d = parse(t, fxTriage(0x3B, [4]uint64{0xc0000005, fxKernel.base + 0x40}, fxHal.base+1).bytes(), Options{})
	if d.Probable != nil {
		t.Fatalf("il kernel non è mai indicato: %+v", d.Probable)
	}
}

func TestUnloadedDriverAttribution(t *testing.T) {
	d := parse(t, fxTriage(0xD1, [4]uint64{0, 2, 0, fxOldVPN.base + 0x10}).bytes(), Options{})
	if d.Probable == nil || !d.Probable.Module.Unloaded || d.Probable.Method != "param" {
		t.Fatalf("driver scaricato: %+v", d.Probable)
	}
	var cd scan.CrashDump
	fill(&cd, d)
	if !cd.Probable.Unloaded || cd.Probable.Driver != "oldvpnflt.sy…" {
		t.Fatalf("driver scaricato: %+v", cd.Probable)
	}
	f := fxTriage(0xD1, [4]uint64{0, 2, 0, 0xfffff8046f000020})
	f.unloaded = []fxModule{{"vpn.sys", 0xfffff8046f000000, 0x1000}}
	if d := parse(t, f.bytes(), Options{}); d.Probable == nil || d.Probable.Module.Name != "vpn.sys" {
		t.Fatalf("nome breve: %+v", d.Probable)
	}
}

func TestNoCulpritCodes(t *testing.T) {
	for _, code := range []uint32{0x124, 0xE2, 0x1C8, 0xDEADDEAD} {
		f := fxTriage(code, [4]uint64{0, fxNet.base, fxNet.base, fxNet.base}, fxNet.base+4)
		d := parse(t, f.bytes(), Options{})
		if d.Probable != nil || len(d.StackModules) != 0 {
			t.Errorf("0x%X: nessun indizio atteso, trovato %+v", code, d.Probable)
		}
	}
}

func TestInconsistentFallsBackToHeader(t *testing.T) {
	cases := map[string]func(b []byte, l layout){
		"troppi driver":            func(b []byte, l layout) { putU32(b, header64Size+0x34, MaxDrivers+1) },
		"elenco fuori dal file":    func(b []byte, l layout) { putU32(b, header64Size+0x30, uint32(l.size-0x20)) },
		"elenco prima del triage":  func(b []byte, l layout) { putU32(b, header64Size+0x30, 0x100) },
		"nome fuori dal pool":      func(b []byte, l layout) { putU32(b, l.drivers, uint32(l.pool+l.poolSize)) },
		"pool troppo grande":       func(b []byte, l layout) { putU32(b, header64Size+0x3C, MaxStringPool+8) },
		"nome senza terminatore":   func(b []byte, l layout) { putU32(b, header64Size+0x3C, 8) },
		"nome con controllo":       func(b []byte, l layout) { b[l.pool+4] = 0x07 },
		"intervallo che trabocca":  func(b []byte, l layout) { putU64(b, l.drivers+0x38, 0xffffffffffffff00) },
		"stack fuori dal file":     func(b []byte, l layout) { putU32(b, header64Size+0x2C, uint32(l.size)) },
		"stack dichiarato enorme":  func(b []byte, l layout) { putU32(b, header64Size+0x2C, maxStackDeclare+8) },
		"troppi driver scaricati":  func(b []byte, l layout) { putU64(b, l.unloaded, MaxUnloaded+1) },
		"scaricati fuori dal file": func(b []byte, l layout) { putU32(b, header64Size+0x18, uint32(l.size-4)) },
	}
	for name, raw := range cases {
		f := fxTriage(0xD1, [4]uint64{0, 2, 0, fxNet.base + 0x10}, fxNet.base+0x20)
		f.raw = raw
		d := parse(t, f.bytes(), Options{})
		if d.Limited != "inconsistent" || d.Reason == "" || d.Drivers != nil || d.Unloaded != nil || d.Probable != nil || d.StackModules != nil {
			t.Errorf("%s: atteso solo l'intestazione, ottenuto limited=%q drivers=%d probable=%+v", name, d.Limited, len(d.Drivers), d.Probable)
			continue
		}
		if d.Code != 0xD1 || !d.ParamSet[3] || d.Time.IsZero() {
			t.Errorf("%s: l'intestazione deve restare: %+v", name, d)
		}
	}
}

func TestEveryPrefixIsSafe(t *testing.T) {
	f := fxTriage(0xD1, [4]uint64{0, 2, 0, fxNet.base + 0x10}, fxKernel.base, fxNet.base+0x20)
	full := f.bytes()
	for n := 0; n <= len(full); n++ {
		b := full[:n]
		d, err := Parse(bytes.NewReader(b), int64(n), Options{})
		switch {
		case n < header64Size:
			if err == nil {
				t.Fatalf("%d byte: errore atteso", n)
			}
		case n < len(full):
			if err != nil || d.Code != 0xD1 {
				t.Fatalf("%d byte: intestazione attesa, %v", n, err)
			}
			if d.Limited == "" && n < len(full)-8 {
				// Mancano parti del minidump: o incoerente, o le parti
				// mancanti erano dopo quelle lette (il marcatore finale).
				t.Fatalf("%d byte: dati del minidump letti da un file troncato", n)
			}
		default:
			if err != nil || d.Limited != "" || d.Probable == nil {
				t.Fatalf("file intero: %v %+v", err, d)
			}
		}
	}
}

func TestNotADump(t *testing.T) {
	for _, b := range [][]byte{nil, []byte("MZ"), []byte("PAGEXXXX" + strings.Repeat("\x00", 0x2000)), bytes.Repeat([]byte{0xFF}, 0x3000), []byte("MDMP\x93\xa7\x00\x00")} {
		if _, err := Parse(bytes.NewReader(b), int64(len(b)), Options{}); err == nil {
			t.Fatalf("%q: errore atteso", b[:min(len(b), 8)])
		}
	}
	if _, err := Parse(bytes.NewReader([]byte("MDMP\x93\xa7\x00\x00")), 8, Options{}); !errors.Is(err, ErrNotDump) {
		t.Fatalf("minidump di un programma: %v", err)
	}
	if _, err := Parse(bytes.NewReader([]byte("PAGEDU64")), 8, Options{}); !errors.Is(err, ErrTruncated) {
		t.Fatalf("intestazione incompleta: %v", err)
	}
}

func TestHeaderOnly(t *testing.T) {
	b := fxTriage(0xD1, [4]uint64{0, 2, 0, fxNet.base}).bytes()
	d := parse(t, b, Options{HeaderOnly: true})
	if d.Limited != "too-large" || d.Drivers != nil || d.Probable != nil || d.Code != 0xD1 {
		t.Fatalf("solo intestazione: %+v", d)
	}
}

func TestPrivacyOfNames(t *testing.T) {
	f := fxTriage(0xD1, [4]uint64{0, 2, 0, 0xfffff8046e000010})
	f.drivers = append(f.drivers, fxModule{`\??\C:\Users\Mario Rossi\AppData\Local\Temp\fictdrv.sys`, 0xfffff8046e000000, 0x8000})
	d := parse(t, f.bytes(), Options{})
	var cd scan.CrashDump
	fill(&cd, d)
	j, _ := json.Marshal(cd)
	if cd.Probable == nil || cd.Probable.Driver != "fictdrv.sys" || strings.Contains(string(j), "Mario") || strings.Contains(string(j), `Users`) || strings.Contains(string(j), "SystemRoot") {
		t.Fatalf("nomi con percorso: %s", j)
	}
	if BaseName(`C:/Users/x/a.sys`) != "a.sys" || BaseName("b.sys") != "b.sys" {
		t.Fatal("BaseName")
	}
}

func TestDisplayPath(t *testing.T) {
	cases := []struct{ in, profile, want string }{
		{`%SystemRoot%\Minidump`, `C:\Users\anna`, `%SystemRoot%\Minidump`},
		{`C:\Users\anna\Dumps`, `C:\Users\anna`, `%USERPROFILE%\Dumps`},
		{`c:\users\ANNA\Dumps`, `C:\Users\anna`, `%USERPROFILE%\Dumps`},
		{`C:\Users\annamaria\Dumps`, `C:\Users\anna`, `C:\Users\‹utente›\Dumps`},
		{`D:\Users\Mario Rossi\Dump\MEMORY.DMP`, ``, `D:\Users\‹utente›\Dump\MEMORY.DMP`},
		{`C:\Users\Public\Dumps`, ``, `C:\Users\Public\Dumps`},
		{`C:\Documents and Settings\Luca\x.dmp`, ``, `C:\Documents and Settings\‹utente›\x.dmp`},
	}
	for _, c := range cases {
		if got := DisplayPath(c.in, c.profile); got != c.want {
			t.Errorf("DisplayPath(%q) = %q, atteso %q", c.in, got, c.want)
		}
	}
}

func TestNamesAndTypes(t *testing.T) {
	if CodeText(0xD1) != "0x000000D1 DRIVER_IRQL_NOT_LESS_OR_EQUAL" || CodeText(0x12345) != "0x00012345" {
		t.Fatal("CodeText")
	}
	for code := range addrParam {
		if Names[code] == "" {
			t.Errorf("codice con parametro documentato senza nome: 0x%X", code)
		}
	}
	types := map[uint32]string{1: "full", 2: "kernel", 3: "header", 4: "triage", 5: "bitmap-full", 6: "bitmap-kernel", 7: "automatic", 8: "kernel", 9: "kernel-user", 10: "full", 77: "unknown"}
	for v, w := range types {
		if TypeName(v, true) != w {
			t.Errorf("tipo %d: %s", v, TypeName(v, true))
		}
	}
	if TypeName(4, false) != "unknown" || MachineName(0xAA64) != "arm64" || MachineName(1) != "" {
		t.Fatal("nomi")
	}
	if !Ignored("NTOSKRNL.EXE") || Ignored("fictnet.sys") {
		t.Fatal("moduli ignorati")
	}
}

// ---------------------------------------------------------------- Collect

type memFile struct{ *bytes.Reader }

func (memFile) Close() error { return nil }

type fakeFile struct {
	data []byte
	mod  time.Time
	err  error
	size int64 // se diverso da zero sostituisce len(data)
}

type fakeSys struct {
	settings *scan.CrashSettings
	dirErr   error
	files    map[string]fakeFile // nome -> file nella cartella dei minidump
	memory   *fakeFile
	opened   []string
}

const (
	fxDir    = `/dati/Minidump`
	fxMemory = `/dati/MEMORY.DMP`
)

func (f *fakeSys) system() System {
	return System{
		Settings: func() (*scan.CrashSettings, string, string) { return f.settings, fxDir, fxMemory },
		ReadDir: func(dir string) ([]Entry, error) {
			if dir != fxDir {
				return nil, fs.ErrNotExist
			}
			if f.dirErr != nil {
				return nil, f.dirErr
			}
			var out []Entry
			for name, x := range f.files {
				size := x.size
				if size == 0 {
					size = int64(len(x.data))
				}
				out = append(out, Entry{Name: name, Size: size, Mod: x.mod})
			}
			out = append(out, Entry{Name: "sottocartella.dmp", Dir: true})
			return out, nil
		},
		Stat: func(path string) (Entry, error) {
			if path != fxMemory || f.memory == nil {
				return Entry{}, fs.ErrNotExist
			}
			return Entry{Name: "MEMORY.DMP", Size: int64(len(f.memory.data)), Mod: f.memory.mod}, nil
		},
		Open: func(path string) (File, error) {
			f.opened = append(f.opened, path)
			var x fakeFile
			if path == fxMemory && f.memory != nil {
				x = *f.memory
			} else if y, ok := f.files[filepath.Base(path)]; ok {
				x = y
			} else {
				return nil, fs.ErrNotExist
			}
			if x.err != nil {
				return nil, &fs.PathError{Op: "open", Path: path, Err: x.err}
			}
			return memFile{bytes.NewReader(x.data)}, nil
		},
		Now: func() time.Time { return time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC) },
	}
}

func day(d int) time.Time { return time.Date(2026, 9, d, 10, 0, 0, 0, time.UTC) }

func TestCollect(t *testing.T) {
	three := 3
	yes := true
	good := fxTriage(0xD1, [4]uint64{0, 2, 0, fxNet.base + 0x10})
	good.time = day(20)
	older := fxTriage(0x3B, [4]uint64{0xc0000005, fxNet.base + 0x40})
	older.time = day(2)
	mem := fixture{code: 0x9F, dumpType: 6, time: day(27)}.bytes()
	f := &fakeSys{
		settings: &scan.CrashSettings{DumpEnabled: &three, MinidumpDir: `%SystemRoot%\Minidump`, AutoReboot: &yes},
		files: map[string]fakeFile{
			"092026-1234-01.dmp": {data: good.bytes(), mod: day(20)},
			"090226-5678-01.dmp": {data: older.bytes(), mod: day(2)},
			"092526-0001-01.DMP": {data: []byte("non è un dump"), mod: day(25)},
			"092726-9999-01.dmp": {err: fs.ErrPermission, mod: day(27), size: 1 << 20},
			"leggimi.txt":        {data: []byte("x"), mod: day(28)},
		},
		memory: &fakeFile{data: mem, mod: day(27)},
	}
	d := Collect(context.Background(), f.system())
	if d.Folder != "ok" || d.Total != 4 || len(d.Dumps) != 4 || !d.NeedsAdmin || d.Settings == nil || *d.Settings.DumpEnabled != 3 || d.ReadAt != "2026-10-31T09:00:00Z" {
		t.Fatalf("raccolta: %+v", d)
	}
	order := []string{"092726-9999-01.dmp", "092526-0001-01.DMP", "092026-1234-01.dmp", "090226-5678-01.dmp"}
	for i, w := range order {
		if d.Dumps[i].File != w {
			t.Fatalf("ordine %d: %s (atteso %s)", i, d.Dumps[i].File, w)
		}
	}
	if d.Dumps[0].Error != errDenied || d.Dumps[0].Code != "" || d.Dumps[0].Size != 1<<20 {
		t.Fatalf("file non leggibile: %+v", d.Dumps[0])
	}
	if d.Dumps[1].Error != errBadDump {
		t.Fatalf("file non valido: %+v", d.Dumps[1])
	}
	if p := d.Dumps[2].Probable; p == nil || p.Driver != "fictnet.sys" || p.Method != "param" || d.Dumps[2].Time != "2026-09-20T10:00:00Z" {
		t.Fatalf("minidump: %+v", d.Dumps[2])
	}
	if m := d.MemoryDump; m == nil || m.File != "MEMORY.DMP" || m.Code != "0x0000009f" || m.DumpType != "bitmap-kernel" || m.Limited != "not-triage" {
		t.Fatalf("MEMORY.DMP: %+v", d.MemoryDump)
	}
	j, _ := json.Marshal(d)
	if strings.Contains(string(j), "/dati") || strings.Contains(string(j), "leggimi") || strings.Contains(string(j), "sottocartella") {
		t.Fatalf("percorsi o file estranei nel risultato: %s", j)
	}
}

func TestCollectDeniedFolder(t *testing.T) {
	zero := 0
	f := &fakeSys{settings: &scan.CrashSettings{DumpEnabled: &zero}, dirErr: &fs.PathError{Op: "open", Path: fxDir, Err: fs.ErrPermission}}
	d := Collect(context.Background(), f.system())
	if d.Folder != "denied" || !d.NeedsAdmin || d.Settings == nil || *d.Settings.DumpEnabled != 0 || d.Dumps == nil || len(d.Dumps) != 0 {
		t.Fatalf("cartella negata: %+v", d)
	}
	j, _ := json.Marshal(d)
	if !strings.Contains(string(j), `"dumps":[]`) || !strings.Contains(string(j), `"dumpEnabled":0`) {
		t.Fatalf("JSON: %s", j)
	}
	f = &fakeSys{dirErr: fs.ErrNotExist}
	if d := Collect(context.Background(), f.system()); d.Folder != "missing" || d.NeedsAdmin || d.Total != 0 {
		t.Fatalf("cartella assente: %+v", d)
	}
	f = &fakeSys{dirErr: errors.New("errore del disco")}
	if d := Collect(context.Background(), f.system()); d.Folder != "error" {
		t.Fatalf("errore generico: %+v", d)
	}
}

func TestCollectCapsAndLimits(t *testing.T) {
	f := &fakeSys{files: map[string]fakeFile{}}
	small := fxTriage(0xD1, [4]uint64{0, 2, 0, fxNet.base}).bytes()
	for i := 0; i < MaxFiles+10; i++ {
		f.files[fmt.Sprintf("%03d.dmp", i)] = fakeFile{data: small, mod: day(1).Add(time.Duration(i) * time.Hour)}
	}
	// Un minidump enorme: solo l'intestazione.
	f.files["grande.dmp"] = fakeFile{data: small, size: MaxParseBytes + 1, mod: day(29)}
	d := Collect(context.Background(), f.system())
	if d.Total != MaxFiles+11 || len(d.Dumps) != MaxFiles {
		t.Fatalf("limite di file: total=%d letti=%d", d.Total, len(d.Dumps))
	}
	if d.Dumps[0].File != "grande.dmp" || d.Dumps[0].Limited != "too-large" || d.Dumps[0].Probable != nil {
		t.Fatalf("file grande: %+v", d.Dumps[0])
	}
	if d.Dumps[1].File != "059.dmp" {
		t.Fatalf("i più recenti prima: %s", d.Dumps[1].File)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if d := Collect(ctx, f.system()); !d.Partial || len(d.Dumps) != 0 {
		t.Fatalf("lettura interrotta: %+v", d)
	}
}

func TestErrTextHasNoPath(t *testing.T) {
	for _, err := range []error{
		&fs.PathError{Op: "open", Path: `C:\Users\anna\x.dmp`, Err: fs.ErrPermission},
		&fs.PathError{Op: "open", Path: `C:\Users\anna\x.dmp`, Err: fs.ErrNotExist},
		&fs.PathError{Op: "read", Path: `C:\Users\anna\x.dmp`, Err: errors.New("I/O")},
		ErrNotDump, ErrTruncated,
	} {
		if s := errText(err); strings.Contains(s, "anna") || strings.Contains(s, `\`) || s == "" {
			t.Fatalf("messaggio: %q", s)
		}
	}
}
