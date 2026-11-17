package pcinfo

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"lanterna/internal/scan"
)

// pciDev costruisce un dispositivo PCI come lo legge readDevices: gli
// hardware ID nell'ordine di Windows, la classe tra i compatible ID.
func pciDev(ven, dev, subsys, rev, cc string) rawDevice {
	return rawDevice{
		Enumerator: "PCI",
		HardwareIDs: []string{
			`PCI\VEN_` + ven + `&DEV_` + dev + `&SUBSYS_` + subsys + `&REV_` + rev,
			`PCI\VEN_` + ven + `&DEV_` + dev + `&SUBSYS_` + subsys,
		},
		CompatibleIDs: []string{
			`PCI\VEN_` + ven + `&DEV_` + dev + `&REV_` + rev,
			`PCI\VEN_` + ven + `&DEV_` + dev,
			`PCI\VEN_` + ven + `&CC_` + cc,
			`PCI\VEN_` + ven + `&CC_` + cc[:4],
			`PCI\VEN_` + ven,
			`PCI\CC_` + cc,
			`PCI\CC_` + cc[:4],
		},
	}
}

func TestPciFuncOf(t *testing.T) {
	d := pciDev("8086", "7A04", "7D251462", "11", "060100")
	f, ok := pciFuncOf(d.HardwareIDs, d.CompatibleIDs)
	if !ok || f != (scan.PciFunc{Vendor: "8086", Device: "7A04", Rev: "11", Class: "0601"}) {
		t.Fatalf("funzione: %+v %v", f, ok)
	}
	// La classe può stare anche tra gli hardware ID, in minuscolo.
	f, ok = pciFuncOf([]string{`pci\ven_1022&dev_790b&subsys_88771043&rev_71`, `PCI\VEN_1022&DEV_790B&CC_0C0500`}, nil)
	if !ok || f.Class != "0C05" || f.Rev != "71" || f.Device != "790B" {
		t.Errorf("SMBus AMD: %+v", f)
	}
	// ID incoerenti o non PCI: nessun dato.
	if _, ok := pciFuncOf([]string{`PCI\VEN_8086&DEV_7A04`, `PCI\VEN_8086&DEV_7A05`}); ok {
		t.Error("ID incoerenti accettati")
	}
	if _, ok := pciFuncOf([]string{`ACPI\PNP0A08`, `USB\VID_046D&PID_C52B`}); ok {
		t.Error("dispositivo non PCI accettato")
	}
}

func TestChipsetIntel(t *testing.T) {
	raw := []rawDevice{
		pciDev("8086", "A700", "7D251462", "01", "060000"), // host bridge (Raptor Lake)
		pciDev("10DE", "2206", "38811462", "A1", "030000"), // scheda video: non è chipset
		pciDev("8086", "7A60", "7D251462", "11", "0C0330"), // USB del PCH: non serve
		pciDev("8086", "7A23", "7D251462", "11", "0C0500"), // SMBus
		pciDev("8086", "7A04", "7D251462", "11", "060100"), // LPC/eSPI: Z790
		{Enumerator: "ACPI", HardwareIDs: []string{`ACPI\PNP0A08`}},
		{Enumerator: "USB", HardwareIDs: []string{`USB\VID_8086&PID_0026&REV_0002`}},
	}
	got := ChipsetOf(raw)
	want := []scan.PciFunc{
		{Vendor: "8086", Device: "7A04", Rev: "11", Class: "0601"},
		{Vendor: "8086", Device: "7A23", Rev: "11", Class: "0C05"},
		{Vendor: "8086", Device: "A700", Rev: "01", Class: "0600"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("chipset Intel:\n got %+v\nwant %+v", got, want)
	}
}

func TestChipsetAMD(t *testing.T) {
	// Scheda AM5 con due chip Promontory 21 in cascata (X670): le porte a
	// valle sono tante e uguali, le funzioni dell'FCH stanno nel processore.
	raw := []rawDevice{
		pciDev("1022", "14D8", "88771043", "00", "060000"), // complesso radice
		pciDev("1022", "14DA", "00000000", "00", "060000"), // host bridge fittizio
		pciDev("1022", "14DA", "00000000", "00", "060000"),
		pciDev("1022", "14DA", "00000000", "00", "060000"),
		pciDev("1022", "43F4", "33281B21", "01", "060400"), // primo chip, a monte
		pciDev("1022", "43F5", "33281B21", "01", "060400"),
		pciDev("1022", "43F5", "33281B21", "01", "060400"),
		pciDev("1022", "43F4", "33281B21", "01", "060400"), // secondo chip, a monte
		pciDev("1022", "43F5", "33281B21", "01", "060400"),
		pciDev("1022", "43F6", "10621B21", "01", "010601"),
		pciDev("1022", "43F7", "11421B21", "01", "0C0330"),
		pciDev("1022", "790B", "88771043", "71", "0C0500"),
		pciDev("1022", "790E", "88771043", "51", "060100"),
		pciDev("1022", "43F7", "11421B21", "01", "0C0330"),
	}
	got := ChipsetOf(raw)
	want := []scan.PciFunc{
		{Vendor: "1022", Device: "790E", Rev: "51", Class: "0601"},
		{Vendor: "1022", Device: "43F4", Rev: "01", Class: "0604"},
		{Vendor: "1022", Device: "43F5", Rev: "01", Class: "0604"},
		{Vendor: "1022", Device: "43F4", Rev: "01", Class: "0604"},
		{Vendor: "1022", Device: "43F6", Rev: "01", Class: "0106"},
		{Vendor: "1022", Device: "43F7", Rev: "01", Class: "0C03"},
		{Vendor: "1022", Device: "790B", Rev: "71", Class: "0C05"},
		{Vendor: "1022", Device: "14D8", Rev: "00", Class: "0600"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("chipset AMD:\n got %+v\nwant %+v", got, want)
	}
	if len(got) != maxChipsetFuncs {
		t.Errorf("limite di %d funzioni non rispettato: %d", maxChipsetFuncs, len(got))
	}
	// Nessun ID d'istanza o SUBSYS nel JSON: solo i quattro campi.
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "SUBSYS") || strings.Contains(string(b), "1B21") || strings.Contains(string(b), `\`) {
		t.Errorf("dati in più nel JSON: %s", b)
	}
	// Un portatile AMD senza chipset separato: solo FCH e host bridge.
	got = ChipsetOf([]rawDevice{pciDev("1022", "790E", "0B291028", "51", "060100"), pciDev("1022", "1630", "0B291028", "00", "060000")})
	if len(got) != 2 || got[0].Device != "790E" || got[1].Device != "1630" {
		t.Errorf("portatile AMD: %+v", got)
	}
	if ChipsetOf(nil) != nil {
		t.Error("senza dispositivi deve restare vuoto")
	}
}
