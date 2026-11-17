//go:build windows

package win11

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

// LocalCPU legge nome (ProcessorNameString) e produttore (VendorIdentifier)
// del processore di questo PC dal registro, come la scheda tecnica.
func LocalCPU() (name, vendor string) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\CentralProcessor\0`, registry.QUERY_VALUE)
	if err != nil {
		return "", ""
	}
	defer k.Close()
	name, _, _ = k.GetStringValue("ProcessorNameString")
	vendor, _, _ = k.GetStringValue("VendorIdentifier")
	return strings.Join(strings.Fields(name), " "), strings.TrimSpace(vendor)
}
