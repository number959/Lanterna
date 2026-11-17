package pcinfo

import (
	"regexp"
	"strings"

	"lanterna/internal/scan"
)

// Chipset della scheda madre, dagli hardware ID e dai compatible ID PCI che
// readDevices legge già per Gestione dispositivi: qui si scelgono le sole
// funzioni che identificano il chipset, prima del filtro di BuildDevices
// (che scarta i dispositivi con il driver di Windows, cioè proprio questi).
// Escono solo produttore, dispositivo, revisione e classe: mai l'ID
// d'istanza (posizione sul bus, a volte numeri di serie). Il nome del chipset
// lo ricava il motore TypeScript da una tabella propria.
//
// Formato degli ID (Microsoft Learn, «Identifiers for PCI Devices»):
// PCI\VEN_v(4)&DEV_d(4)&SUBSYS_s(4)n(4)&REV_r(2), ..., PCI\VEN_v(4)&DEV_d(4)&CC_c(2)s(2)p(2);
// da Windows 10 alcuni ID con CC_ stanno tra i compatible ID, per questo si
// leggono entrambi gli elenchi.

// Classi PCI (classe e sottoclasse) che descrivono il chipset.
const (
	pciHostBridge = "0600" // host bridge (controller della memoria o complesso radice)
	pciISABridge  = "0601" // bridge ISA/LPC/eSPI: nei PC Intel è la funzione D31:F0 del PCH
	pciSMBus      = "0C05" // controller SMBus
)

// maxChipsetFuncs limita le funzioni esportate.
const maxChipsetFuncs = 8

var (
	pciVenDev = regexp.MustCompile(`^PCI\\VEN_([0-9A-F]{4})&DEV_([0-9A-F]{4})(?:&|$)`)
	pciRev    = regexp.MustCompile(`&REV_([0-9A-F]{2})(?:&|$)`)
	pciClass  = regexp.MustCompile(`(?:\\|&)CC_([0-9A-F]{4})(?:[0-9A-F]{2})?(?:&|$)`)
)

// pciFuncOf ricava produttore, dispositivo, revisione e classe dagli ID di
// un dispositivo PCI; false se non è un dispositivo PCI riconoscibile.
func pciFuncOf(ids ...[]string) (scan.PciFunc, bool) {
	var f scan.PciFunc
	for _, list := range ids {
		for _, raw := range list {
			id := strings.ToUpper(strings.TrimSpace(raw))
			if !strings.HasPrefix(id, `PCI\`) {
				continue
			}
			if m := pciVenDev.FindStringSubmatch(id); m != nil {
				if f.Vendor == "" {
					f.Vendor, f.Device = m[1], m[2]
				} else if f.Vendor != m[1] || f.Device != m[2] {
					// ID incoerenti tra loro: meglio niente che un dato sbagliato.
					return scan.PciFunc{}, false
				}
			}
			if m := pciRev.FindStringSubmatch(id); m != nil && f.Rev == "" {
				f.Rev = m[1]
			}
			if m := pciClass.FindStringSubmatch(id); m != nil && f.Class == "" {
				f.Class = m[1]
			}
		}
	}
	return f, f.Vendor != "" && f.Device != ""
}

// amdPromontory dice se una funzione AMD appartiene a un chipset separato
// delle schede AM4 e AM5 (Promontory e derivati): le funzioni dell'FCH
// (790E, 790B) stanno nel processore e non distinguono il chipset. Elenco
// da pci.ids (versione 2026.11.16, scelta la licenza BSD-3-Clause; solo
// fatti, non il file) e Linux xhci-pci.c (PROMONTORYA_1..4): serie 300,
// X399 e 400 (43B0-43D5), 500 (43E9-43EE), 600 e 800 (43F4-43FD), X570
// (57AD a monte, 57A3 e 57A4, USB 149C).
func amdPromontory(device string) bool {
	switch device {
	case "57AD", "57A3", "57A4", "149C":
		return true
	}
	return device >= "43B0" && device <= "43FF"
}

// amdUpstream sono le porte a monte dei chip AMD delle serie 600 e 800: con
// due chip in cascata (X670, X670E, X870E) ce ne sono due uguali, quindi
// per queste si tiene anche il doppione (ipotesi da verificare su PC veri).
var amdUpstream = map[string]bool{"43F4": true}

// chipsetRank ordina le funzioni per quanto dicono del chipset: prima il
// bridge LPC/eSPI (il modello del chipset Intel), poi i chip AMD separati,
// poi SMBus e host bridge. -1 se la funzione non interessa.
func chipsetRank(f scan.PciFunc) int {
	switch {
	case f.Class == pciISABridge:
		return 0
	case f.Vendor == "1022" && amdPromontory(f.Device):
		return 1
	case f.Class == pciSMBus:
		return 2
	case f.Class == pciHostBridge:
		return 3
	}
	return -1
}

// ChipsetOf sceglie tra i dispositivi PCI presenti le funzioni che
// identificano il chipset, senza doppioni (tranne il secondo chip AMD a
// monte) e al massimo maxChipsetFuncs.
func ChipsetOf(raw []rawDevice) []scan.PciFunc {
	var byRank [4][]scan.PciFunc
	seen := map[scan.PciFunc]int{}
	for _, r := range raw {
		if e := strings.ToUpper(strings.TrimSpace(r.Enumerator)); e != "" && e != "PCI" {
			continue
		}
		f, ok := pciFuncOf(r.HardwareIDs, r.CompatibleIDs)
		if !ok {
			continue
		}
		rank := chipsetRank(f)
		if rank < 0 {
			continue
		}
		limit := 1
		if f.Vendor == "1022" && amdUpstream[f.Device] {
			limit = 2
		}
		if seen[f] >= limit {
			continue
		}
		seen[f]++
		byRank[rank] = append(byRank[rank], f)
	}
	var out []scan.PciFunc
	for _, list := range byRank {
		for _, f := range list {
			if len(out) == maxChipsetFuncs {
				return out
			}
			out = append(out, f)
		}
	}
	return out
}
