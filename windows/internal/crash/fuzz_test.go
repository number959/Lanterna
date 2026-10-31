package crash

import (
	"bytes"
	"testing"

	"lanterna/internal/scan"
)

// FuzzParse: qualunque contenuto deve dare un errore o un risultato coerente,
// mai un arresto, e il driver indicato deve stare tra quelli elencati.
func FuzzParse(f *testing.F) {
	stack := fxTriage(0x9F, [4]uint64{3}, fxKernel.base, fxAudio.base+4, fxNet.base+8)
	stack.drivers = append(stack.drivers, fxAudio)
	for _, fx := range []fixture{
		fxTriage(0xD1, [4]uint64{0x34, 2, 1, fxNet.base + 0x3c78}),
		fxTriage(0xD1, [4]uint64{0, 2, 0, fxOldVPN.base + 0x10}),
		stack,
		{code: 0x124, dumpType: 6},
		{bits: 32, code: 0x96, dumpType: dumpTypeTriage},
	} {
		f.Add(fx.bytes())
	}
	f.Add([]byte("PAGEDU64"))
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, opt := range []Options{{}, {HeaderOnly: true}} {
			d, err := Parse(bytes.NewReader(b), int64(len(b)), opt)
			if err != nil {
				if d != nil {
					t.Fatal("risultato insieme a un errore")
				}
				continue
			}
			if len(d.Drivers) > MaxDrivers || len(d.Unloaded) > MaxUnloaded || d.StackBytes > MaxStackBytes || len(d.StackModules) > maxStackModules {
				t.Fatalf("limiti superati: %d %d %d", len(d.Drivers), len(d.Unloaded), d.StackBytes)
			}
			if p := d.Probable; p != nil {
				found := false
				for _, m := range append(append([]Module(nil), d.Drivers...), d.Unloaded...) {
					if m.Name == p.Module.Name && m.Base == p.Module.Base {
						found = true
					}
				}
				if !found || Ignored(p.Module.Name) || d.Limited != "" {
					t.Fatalf("indizio non coerente: %+v", p)
				}
			}
			var cd scan.CrashDump
			fill(&cd, d)
		}
	})
}
