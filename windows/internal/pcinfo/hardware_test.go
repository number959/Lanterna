package pcinfo

import (
	"encoding/binary"
	"reflect"
	"testing"

	"lanterna/internal/scan"
)

// lpiCore costruisce un record RelationProcessorCore con una maschera di
// affinità di "threads" bit.
func lpiCore(class byte, threads int) []byte {
	r := make([]byte, 8+24+16)
	binary.LittleEndian.PutUint32(r[0:], relationProcessorCore)
	binary.LittleEndian.PutUint32(r[4:], uint32(len(r)))
	if threads > 1 {
		r[8] = 1 // LTP_PC_SMT
	}
	r[9] = class
	binary.LittleEndian.PutUint16(r[8+22:], 1)
	binary.LittleEndian.PutUint64(r[8+24:], 1<<threads-1)
	return r
}

// lpiCache costruisce un record RelationCache (tipo 0 unificata, 1
// istruzioni, 2 dati, 3 tracce).
func lpiCache(level, ways byte, sizeKB, kind uint32) []byte {
	r := make([]byte, 8+32+16)
	binary.LittleEndian.PutUint32(r[0:], relationCache)
	binary.LittleEndian.PutUint32(r[4:], uint32(len(r)))
	r[8], r[9] = level, ways
	binary.LittleEndian.PutUint16(r[10:], 64)
	binary.LittleEndian.PutUint32(r[12:], sizeKB*1024)
	binary.LittleEndian.PutUint32(r[16:], kind)
	return r
}

func lpiPackage() []byte {
	r := make([]byte, 8+24+16)
	binary.LittleEndian.PutUint32(r[0:], relationProcessorPackage)
	binary.LittleEndian.PutUint32(r[4:], uint32(len(r)))
	return r
}

// Un processore ibrido in piccolo: 2 core P con due thread ciascuno e 4 core
// E, ciascuno con le sue cache L1, L2 dei core E condivisa, L3 comune.
func TestParseLPI(t *testing.T) {
	var b []byte
	for range 2 {
		b = append(b, lpiCore(1, 2)...)
		b = append(b, lpiCache(1, 12, 48, 2)...)
		b = append(b, lpiCache(1, 8, 32, 1)...)
		b = append(b, lpiCache(2, 10, 1280, 0)...)
	}
	for range 4 {
		b = append(b, lpiCore(0, 1)...)
		b = append(b, lpiCache(1, 8, 32, 2)...)
		b = append(b, lpiCache(1, 8, 64, 1)...)
	}
	b = append(b, lpiCache(2, 16, 2048, 0)...)
	b = append(b, lpiCache(3, 12, 12288, 0)...)
	b = append(b, lpiCache(1, 0xFF, 16, 3)...) // cache di tracce: ignorata
	b = append(b, lpiPackage()...)
	b = append(b, 1, 2, 3) // coda troncata: ignorata senza errori

	info := parseLPI(b)
	if info.cores != 6 || info.threads != 8 || info.packages != 1 {
		t.Fatalf("core %d, thread %d, pacchetti %d", info.cores, info.threads, info.packages)
	}
	if !reflect.DeepEqual(info.classes, []int{2, 4}) {
		t.Errorf("classi: %v (attese 2 P e 4 E)", info.classes)
	}
	want := []scan.HwCache{
		{Level: 1, Kind: "data", SizeKB: 48, Count: 2, Ways: 12},
		{Level: 1, Kind: "data", SizeKB: 32, Count: 4, Ways: 8},
		{Level: 1, Kind: "instruction", SizeKB: 64, Count: 4, Ways: 8},
		{Level: 1, Kind: "instruction", SizeKB: 32, Count: 2, Ways: 8},
		{Level: 2, Kind: "unified", SizeKB: 2048, Count: 1, Ways: 16},
		{Level: 2, Kind: "unified", SizeKB: 1280, Count: 2, Ways: 10},
		{Level: 3, Kind: "unified", SizeKB: 12288, Count: 1, Ways: 12},
	}
	if !reflect.DeepEqual(info.caches, want) {
		t.Errorf("cache:\n%+v\nattese:\n%+v", info.caches, want)
	}

	// Processore tradizionale: una sola classe.
	flat := append(lpiCore(0, 2), lpiCore(0, 2)...)
	if info := parseLPI(flat); !reflect.DeepEqual(info.classes, []int{2}) || info.threads != 4 {
		t.Errorf("non ibrido: %+v", info)
	}
	// Record con dimensione impossibile: la lettura si ferma.
	bad := lpiCore(0, 1)
	binary.LittleEndian.PutUint32(bad[4:], 4)
	if info := parseLPI(bad); info.cores != 0 {
		t.Errorf("record non valido accettato: %+v", info)
	}
}

func TestParseCPUIdent(t *testing.T) {
	f, m, s, ok := parseCPUIdent("Intel64 Family 6 Model 154 Stepping 3")
	if !ok || f != 6 || m != 154 || s != 3 {
		t.Errorf("Intel: %d %d %d %v", f, m, s, ok)
	}
	if f, m, s, ok := parseCPUIdent("AMD64 Family 25 Model 33 Stepping 2"); !ok || f != 25 || m != 33 || s != 2 {
		t.Errorf("AMD: %d %d %d", f, m, s)
	}
	if _, _, _, ok := parseCPUIdent("ARMv8 (64-bit) Family 8 Model D4B Revision 0"); ok {
		t.Error("identificativo ARM interpretato come x86")
	}
}

func TestHardwareNormalizers(t *testing.T) {
	for in, want := range map[int]string{26: "DDR4", 34: "DDR5", 35: "LPDDR5", 30: "LPDDR4", 24: "DDR3", 0: "", 99: ""} {
		if got := memType(in); got != want {
			t.Errorf("memType(%d)=%q", in, got)
		}
	}
	if memForm(8) != "DIMM" || memForm(12) != "SODIMM" || memForm(0) != "" {
		t.Error("memForm")
	}
	if chassisOf(1) != "desktop" || chassisOf(2) != "laptop" || chassisOf(0) != "" || chassisOf(6) != "other" {
		t.Error("chassisOf")
	}
	if tpmOf([]string{"Dispositivo di sicurezza AMD", "Trusted Platform Module 2.0"}) != "2.0" || tpmOf([]string{"Trusted Platform Module"}) != "?" || tpmOf(nil) != "" {
		t.Error("tpmOf")
	}
	for _, s := range []string{"To be filled by O.E.M.", " Default string ", "Unknown", "System manufacturer"} {
		if cleanVendor(s) != "" {
			t.Errorf("segnaposto %q mantenuto", s)
		}
	}
	if cleanVendor(" ASUSTeK COMPUTER INC. ") != "ASUSTeK COMPUTER INC." {
		t.Error("cleanVendor")
	}
}

// Sezione "hw" e schede video come le produce lo script su un fisso con due
// moduli DDR4 sullo stesso canale e un TPM 2.0.
const psHWFixture = `{"gpus":[{"name":"NVIDIA GeForce RTX 3060","driverVersion":"32.0.15.6094","driverDate":"2024-08-14","w":2560,"h":1440,"hz":144},` +
	`{"name":"Microsoft Basic Display Adapter","driverVersion":"10.0","driverDate":"","w":0,"h":0,"hz":0}],` +
	`"hw":{"vendor":"System manufacturer","model":"System Product Name","type":1,"hypervisor":true,"boardVendor":"ASUSTeK COMPUTER INC.","board":"PRIME B550-PLUS","boardVersion":"Rev X.0x",` +
	`"biosVendor":"American Megatrends Inc.","bios":"3002","biosDate":"2023-02-09","socket":"AM4","virt":null,"slots":4,"maxKB":134217728,` +
	`"mem":[{"size":8589934592,"speed":2133,"conf":2133,"vendor":"Kingston","part":"KHX3200C16D4/8GX  ","slot":"DIMM_A1","bank":"BANK 0","type":26,"form":8,"mv":1200},` +
	`{"size":8589934592,"speed":2133,"conf":2133,"vendor":"Kingston","part":"KHX3200C16D4/8GX","slot":"DIMM_A2","bank":"BANK 1","type":26,"form":8,"mv":1200},` +
	`{"size":0,"speed":0,"conf":0,"vendor":"","part":"","slot":"","bank":"","type":0,"form":0,"mv":0}],` +
	`"tpm":["Trusted Platform Module 2.0"]},"errors":{}}`

func TestMergeHW(t *testing.T) {
	ps, err := parsePS(psHWFixture)
	if err != nil {
		t.Fatal(err)
	}
	pc := &scan.PcData{Hardware: &scan.Hardware{CPU: &scan.HwCPU{Cores: 8}, Firmware: "uefi"}}
	merge(pc, ps, "C:")
	if len(pc.GPUs) != 2 || pc.GPUs[0].Width != 2560 || pc.GPUs[0].Height != 1440 || pc.GPUs[0].RefreshHz != 144 || pc.GPUs[1].Width != 0 {
		t.Errorf("schede video: %+v", pc.GPUs)
	}
	hw := pc.Hardware
	// I segnaposto dei fissi assemblati non diventano produttore e modello.
	if hw.Vendor != "" || hw.Model != "" || hw.Chassis != "desktop" || !hw.Hypervisor || hw.Firmware != "uefi" {
		t.Errorf("sistema: %+v", hw)
	}
	if hw.Board == nil || hw.Board.Product != "PRIME B550-PLUS" || hw.Board.BiosVersion != "3002" || hw.Board.BiosDate != "2023-02-09" {
		t.Errorf("scheda madre: %+v", hw.Board)
	}
	if hw.CPU.Socket != "AM4" || hw.CPU.Virtualization != nil || hw.CPU.Cores != 8 {
		t.Errorf("processore: %+v", hw.CPU)
	}
	m := hw.Memory
	if m == nil || m.Slots != 4 || m.MaxGB != 128 || len(m.Modules) != 2 {
		t.Fatalf("memoria: %+v", m)
	}
	if mod := m.Modules[0]; mod.SizeGB != 8 || mod.Type != "DDR4" || mod.Form != "DIMM" || mod.SpeedMTs != 2133 || mod.Part != "KHX3200C16D4/8GX" || mod.Slot != "DIMM_A1" || mod.VoltageMV != 1200 {
		t.Errorf("modulo: %+v", mod)
	}
	if hw.TPM == nil || *hw.TPM != "2.0" {
		t.Errorf("TPM: %v", hw.TPM)
	}

	// TPM non leggibile (sezione assente) e nessun TPM (elenco vuoto) restano distinti.
	none := &scan.Hardware{}
	mergeHW(none, &psHW{TPM: &[]string{}})
	if none.TPM == nil || *none.TPM != "" || none.Memory != nil || none.Board != nil {
		t.Errorf("nessun TPM: %+v", none)
	}
	unread := &scan.Hardware{}
	mergeHW(unread, &psHW{})
	if unread.TPM != nil {
		t.Errorf("TPM non letto: %v", *unread.TPM)
	}
}

func TestX86Features(t *testing.T) {
	f := x86Features()
	if len(f) == 0 {
		t.Skip("non è un processore x86")
	}
	// SSE2 è sempre presente sui processori a 64 bit.
	if f[0] != "SSE2" {
		t.Errorf("istruzioni: %v", f)
	}
}
