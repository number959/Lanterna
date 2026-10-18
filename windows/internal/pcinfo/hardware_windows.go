//go:build windows

package pcinfo

import (
	"errors"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows/registry"

	"lanterna/internal/scan"
)

var (
	procGetLogicalProcessorInformationEx = kernel32.NewProc("GetLogicalProcessorInformationEx")
	procGetFirmwareType                  = kernel32.NewProc("GetFirmwareType")
	procIsProcessorFeaturePresent        = kernel32.NewProc("IsProcessorFeaturePresent")
)

// hardwareNative legge la parte della scheda tecnica disponibile con le API
// di Windows: processore, firmware e Secure Boot. Il resto arriva dallo
// script PowerShell (mergeHW).
func hardwareNative() *scan.Hardware {
	hw := &scan.Hardware{CPU: cpuHardware()}
	switch firmwareType() {
	case 1:
		hw.Firmware = "bios"
	case 2:
		hw.Firmware = "uefi"
	}
	hw.SecureBoot = secureBoot()
	return hw
}

func cpuHardware() *scan.HwCPU {
	c := &scan.HwCPU{}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\CentralProcessor\0`, registry.QUERY_VALUE); err == nil {
		c.Vendor, _, _ = k.GetStringValue("VendorIdentifier")
		ident, _, _ := k.GetStringValue("Identifier")
		c.Family, c.Model, c.Stepping, _ = parseCPUIdent(ident)
		k.Close()
	}
	if b, err := logicalProcessorInfo(); err == nil {
		info := parseLPI(b)
		c.Cores, c.Threads, c.Packages, c.CoreClasses, c.Caches = info.cores, info.threads, info.packages, info.classes, info.caches
	}
	if runtime.GOARCH == "arm64" {
		c.Features = armFeatures()
	} else {
		c.Features = x86Features()
	}
	return c
}

// logicalProcessorInfo chiama GetLogicalProcessorInformationEx per tutte le
// relazioni: la prima chiamata restituisce la dimensione necessaria.
func logicalProcessorInfo() ([]byte, error) {
	if procGetLogicalProcessorInformationEx.Find() != nil {
		return nil, errors.New("non disponibile")
	}
	const relationAll = 0xFFFF
	var n uint32
	procGetLogicalProcessorInformationEx.Call(relationAll, 0, uintptr(unsafe.Pointer(&n)))
	if n == 0 || n > 1<<20 {
		return nil, errors.New("dimensione non valida")
	}
	b := make([]byte, n)
	if r, _, err := procGetLogicalProcessorInformationEx.Call(relationAll, uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&n))); r == 0 {
		return nil, err
	}
	return b[:n], nil
}

// firmwareType: 1 BIOS (avvio legacy), 2 UEFI, 0 sconosciuto.
func firmwareType() uint32 {
	if procGetFirmwareType.Find() != nil {
		return 0
	}
	var t uint32
	if r, _, _ := procGetFirmwareType.Call(uintptr(unsafe.Pointer(&t))); r == 0 {
		return 0
	}
	return t
}

// secureBoot legge lo stato dell'avvio protetto; nil se la chiave non
// esiste (avvio legacy o Windows senza supporto).
func secureBoot() *bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\SecureBoot\State`, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("UEFISecureBootEnabled")
	if err != nil {
		return nil
	}
	on := v != 0
	return &on
}

// armFeatures usa IsProcessorFeaturePresent: sui processori ARM le
// istruzioni non si leggono con CPUID.
func armFeatures() []string {
	if procIsProcessorFeaturePresent.Find() != nil {
		return nil
	}
	list := []struct {
		pf   uintptr
		name string
	}{{19, "NEON"}, {30, "AES/SHA"}, {31, "CRC32"}, {34, "LSE"}}
	out := []string{}
	for _, f := range list {
		if r, _, _ := procIsProcessorFeaturePresent.Call(f.pf); r != 0 {
			out = append(out, f.name)
		}
	}
	return out
}

// gpuVRAM legge la memoria video dalle chiavi dei driver delle schede video:
// Win32_VideoController la tronca a 4 GB. Restituisce i MB per nome della
// scheda (in minuscolo).
func gpuVRAM() map[string]int {
	const class = `SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}`
	out := map[string]int{}
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, class, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return out
	}
	defer root.Close()
	subs, _ := root.ReadSubKeyNames(0)
	for _, s := range subs {
		if len(s) != 4 || strings.Trim(s, "0123456789") != "" {
			continue // "Properties" e simili non sono schede
		}
		k, err := registry.OpenKey(root, s, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		name, _, _ := k.GetStringValue("DriverDesc")
		var bytes uint64
		if v, _, err := k.GetIntegerValue("HardwareInformation.qwMemorySize"); err == nil {
			bytes = v
		} else if v, _, err := k.GetIntegerValue("HardwareInformation.MemorySize"); err == nil {
			bytes = v
		} else if b, _, err := k.GetBinaryValue("HardwareInformation.MemorySize"); err == nil && len(b) >= 4 {
			bytes = uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24
		}
		k.Close()
		if name != "" && bytes >= 1<<20 {
			out[strings.ToLower(strings.TrimSpace(name))] = int(bytes >> 20)
		}
	}
	return out
}
