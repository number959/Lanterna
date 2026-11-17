//go:build windows

package win11

import "testing"

// Prova su Windows reale: nome e produttore del processore si leggono dal
// registro e il produttore ha un elenco (Intel, AMD o Qualcomm).
func TestLocalCPUWindows(t *testing.T) {
	name, vendor := LocalCPU()
	if name == "" || vendor == "" {
		t.Fatalf("processore non letto: %q %q", name, vendor)
	}
	v := VendorOf(vendor, name)
	if _, ok := Lists[v]; !ok {
		t.Errorf("produttore non riconosciuto: %q (%q)", vendor, name)
	}
	t.Logf("%s (%s): elenco %s", name, vendor, Lists[v].URL)
}
