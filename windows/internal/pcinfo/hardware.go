package pcinfo

// Scheda tecnica del computer, come in CPU-Z: processore (famiglia, core per
// classe di efficienza, cache, istruzioni), scheda madre e BIOS, moduli di
// memoria, firmware, Secure Boot e TPM. Qui stanno i decodificatori
// indipendenti dal sistema; le letture sono in hardware_windows.go e nello
// script PowerShell (sezione "hw").

import (
	"encoding/binary"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/cpu"

	"lanterna/internal/scan"
)

// Relazioni di SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX.
const (
	relationProcessorCore    = 0
	relationCache            = 2
	relationProcessorPackage = 3
)

// lpiInfo è il riassunto di GetLogicalProcessorInformationEx.
type lpiInfo struct {
	cores, threads, packages int
	classes                  []int
	caches                   []scan.HwCache
}

// parseLPI decodifica il buffer di GetLogicalProcessorInformationEx: una
// sequenza di record di lunghezza variabile (Relationship e Size, poi la
// struttura della relazione). Per i core: Flags (bit 0 = più thread per
// core), EfficiencyClass, 20 byte riservati, GroupCount e le maschere
// GROUP_AFFINITY (8 byte di maschera, 2 di gruppo, 6 riservati). Per le
// cache: Level, Associativity, LineSize, CacheSize e Type.
func parseLPI(b []byte) lpiInfo {
	var info lpiInfo
	classCount := map[int]int{}
	type cacheKey struct{ level, kind, size, ways int }
	caches := map[cacheKey]int{}
	for off := 0; off+8 <= len(b); {
		rel := binary.LittleEndian.Uint32(b[off:])
		size := int(binary.LittleEndian.Uint32(b[off+4:]))
		if size < 8 || off+size > len(b) {
			break
		}
		r := b[off+8 : off+size]
		switch rel {
		case relationProcessorCore:
			if len(r) >= 24 {
				info.cores++
				classCount[int(r[1])]++
				groups := int(binary.LittleEndian.Uint16(r[22:]))
				for g := 0; g < groups && 24+g*16+8 <= len(r); g++ {
					mask := binary.LittleEndian.Uint64(r[24+g*16:])
					for ; mask != 0; mask &= mask - 1 {
						info.threads++
					}
				}
			}
		case relationCache:
			if len(r) >= 12 {
				k := cacheKey{level: int(r[0]), ways: int(r[1]), size: int(binary.LittleEndian.Uint32(r[4:])), kind: int(binary.LittleEndian.Uint32(r[8:]))}
				caches[k]++
			}
		case relationProcessorPackage:
			info.packages++
		}
		off += size
	}
	for c := range classCount {
		info.classes = append(info.classes, c)
	}
	// Dalla classe più potente (valore più alto) alla meno potente.
	sort.Sort(sort.Reverse(sort.IntSlice(info.classes)))
	counts := make([]int, len(info.classes))
	for i, c := range info.classes {
		counts[i] = classCount[c]
	}
	info.classes = counts
	kinds := map[int]string{0: "unified", 1: "instruction", 2: "data"}
	for k, n := range caches {
		kind, ok := kinds[k.kind]
		if !ok || k.size <= 0 {
			continue // cache di tracce o voci non valide
		}
		ways := k.ways
		if ways == 0xFF {
			ways = 0 // completamente associativa: non ha un numero di vie
		}
		info.caches = append(info.caches, scan.HwCache{Level: k.level, Kind: kind, SizeKB: k.size / 1024, Count: n, Ways: ways})
	}
	order := map[string]int{"data": 0, "instruction": 1, "unified": 2}
	sort.Slice(info.caches, func(i, j int) bool {
		a, b := info.caches[i], info.caches[j]
		if a.Level != b.Level {
			return a.Level < b.Level
		}
		if order[a.Kind] != order[b.Kind] {
			return order[a.Kind] < order[b.Kind]
		}
		return a.SizeKB > b.SizeKB
	})
	return info
}

var cpuIdentRe = regexp.MustCompile(`Family (\d+) Model (\d+) Stepping (\d+)`)

// parseCPUIdent legge famiglia, modello e stepping dalla stringa del
// registro ("Intel64 Family 6 Model 154 Stepping 3").
func parseCPUIdent(s string) (family, model, stepping int, ok bool) {
	m := cpuIdentRe.FindStringSubmatch(s)
	if m == nil {
		return 0, 0, 0, false
	}
	family, _ = strconv.Atoi(m[1])
	model, _ = strconv.Atoi(m[2])
	stepping, _ = strconv.Atoi(m[3])
	return family, model, stepping, true
}

// x86Features elenca le estensioni più note del set di istruzioni, lette
// con CPUID. POPCNT e SSE4.2 sono richieste da Windows 11 24H2.
func x86Features() []string {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "386" {
		return nil
	}
	x := cpu.X86
	list := []struct {
		has  bool
		name string
	}{
		{x.HasSSE2, "SSE2"}, {x.HasSSE3, "SSE3"}, {x.HasSSSE3, "SSSE3"}, {x.HasSSE41, "SSE4.1"}, {x.HasSSE42, "SSE4.2"},
		{x.HasPOPCNT, "POPCNT"}, {x.HasAES, "AES"}, {x.HasAVX, "AVX"}, {x.HasAVX2, "AVX2"}, {x.HasFMA, "FMA3"},
		{x.HasAVX512F, "AVX-512"}, {x.HasAVXVNNI, "AVX-VNNI"}, {x.HasBMI2, "BMI2"}, {x.HasRDRAND, "RDRAND"},
	}
	out := []string{}
	for _, f := range list {
		if f.has {
			out = append(out, f.name)
		}
	}
	return out
}

// memType traduce il tipo di memoria SMBIOS (Win32_PhysicalMemory.SMBIOSMemoryType).
func memType(t int) string {
	switch t {
	case 18:
		return "DDR"
	case 19, 20:
		return "DDR2"
	case 24:
		return "DDR3"
	case 26:
		return "DDR4"
	case 27:
		return "LPDDR"
	case 28:
		return "LPDDR2"
	case 29:
		return "LPDDR3"
	case 30:
		return "LPDDR4"
	case 34:
		return "DDR5"
	case 35:
		return "LPDDR5"
	}
	return ""
}

// memForm traduce il formato del modulo (FormFactor): DIMM nei fissi,
// SODIMM nei portatili; la memoria saldata riporta altri valori.
func memForm(f int) string {
	switch f {
	case 8:
		return "DIMM"
	case 12:
		return "SODIMM"
	}
	return ""
}

// chassisOf traduce Win32_ComputerSystem.PCSystemType.
func chassisOf(t int) string {
	switch t {
	case 1:
		return "desktop"
	case 2:
		return "laptop"
	case 3:
		return "workstation"
	case 4, 5, 7:
		return "server"
	case 8:
		return "tablet"
	case 0:
		return ""
	}
	return "other"
}

var tpmVerRe = regexp.MustCompile(`(\d\.\d)`)

// tpmOf ricava la versione del TPM dai nomi dei dispositivi di sicurezza
// ("Trusted Platform Module 2.0"); "" se nessuno è un TPM.
func tpmOf(names []string) string {
	for _, n := range names {
		if !strings.Contains(strings.ToLower(n), "trusted platform module") {
			continue
		}
		if m := tpmVerRe.FindString(n); m != "" {
			return m
		}
		return "?"
	}
	return ""
}

// cleanVendor scarta i valori segnaposto che alcuni firmware lasciano nei
// campi di testo ("To be filled by O.E.M.", "Default string", "Unknown").
func cleanVendor(s string) string {
	s = strings.TrimSpace(s)
	switch strings.ToLower(s) {
	case "", "to be filled by o.e.m.", "default string", "unknown", "not specified", "system manufacturer", "system product name", "none", "undefined":
		return ""
	}
	return s
}

// mergeHW completa la scheda tecnica con i dati dello script PowerShell.
func mergeHW(hw *scan.Hardware, ps *psHW) {
	if ps == nil {
		return
	}
	hw.Vendor, hw.Model = cleanVendor(ps.Vendor), cleanVendor(ps.Model)
	hw.Chassis = chassisOf(ps.Type)
	hw.Hypervisor = ps.Hypervisor
	b := &scan.HwBoard{
		Vendor: cleanVendor(ps.BoardVendor), Product: cleanVendor(ps.Board), Version: cleanVendor(ps.BoardVersion),
		BiosVendor: cleanVendor(ps.BiosVendor), BiosVersion: cleanVendor(ps.Bios), BiosDate: ps.BiosDate,
	}
	if *b != (scan.HwBoard{}) {
		hw.Board = b
	}
	if hw.CPU != nil {
		hw.CPU.Socket = cleanVendor(ps.Socket)
		hw.CPU.Virtualization = ps.Virt
	}
	m := &scan.HwMemory{Slots: ps.Slots}
	if ps.MaxKB > 0 {
		m.MaxGB = round1(float64(ps.MaxKB) / (1 << 20))
	}
	for _, x := range ps.Mem {
		if x.Size <= 0 {
			continue
		}
		m.Modules = append(m.Modules, scan.HwModule{
			Slot: strings.TrimSpace(x.Slot), Bank: strings.TrimSpace(x.Bank),
			SizeGB: round1(float64(x.Size) / (1 << 30)), Type: memType(x.Type), Form: memForm(x.Form),
			SpeedMTs: x.Speed, ConfiguredMTs: x.Conf, Vendor: cleanVendor(x.Vendor), Part: cleanVendor(x.Part), VoltageMV: x.MV,
		})
	}
	if m.Slots > 0 || len(m.Modules) > 0 {
		hw.Memory = m
	}
	if ps.TPM != nil {
		t := tpmOf(*ps.TPM)
		hw.TPM = &t
	}
}

// psHW rispecchia la sezione "hw" dello script.
type psHW struct {
	Vendor       string `json:"vendor"`
	Model        string `json:"model"`
	Type         int    `json:"type"`
	Hypervisor   bool   `json:"hypervisor"`
	BoardVendor  string `json:"boardVendor"`
	Board        string `json:"board"`
	BoardVersion string `json:"boardVersion"`
	BiosVendor   string `json:"biosVendor"`
	Bios         string `json:"bios"`
	BiosDate     string `json:"biosDate"`
	Socket       string `json:"socket"`
	Virt         *bool  `json:"virt"`
	Slots        int    `json:"slots"`
	MaxKB        int64  `json:"maxKB"`
	Mem          []struct {
		Size   int64  `json:"size"`
		Speed  int    `json:"speed"`
		Conf   int    `json:"conf"`
		Vendor string `json:"vendor"`
		Part   string `json:"part"`
		Slot   string `json:"slot"`
		Bank   string `json:"bank"`
		Type   int    `json:"type"`
		Form   int    `json:"form"`
		MV     int    `json:"mv"`
	} `json:"mem"`
	TPM *[]string `json:"tpm"`
}
