package pcinfo

import (
	"strings"

	"lanterna/internal/scan"
)

// Modello del driver video (WDDM), dichiarato a Windows dal driver e letto
// con D3DKMTQueryAdapterInfo(KMTQAITYPE_DRIVERVERSION) come fa il monitor dei
// sensori: 2000 = WDDM 2.0, il minimo di Windows 11. Niente
// D3D12CreateDevice: caricherebbe il driver video dentro Polaris.

// wddmAdapter è una scheda video vista da D3DKMT.
type wddmAdapter struct {
	Name     string // AdapterString del registro della scheda
	Software bool   // Microsoft Basic Render Driver o scheda senza motore di rendering
	Version  int    // KMTQAITYPE_DRIVERVERSION (0 se non letta)
}

// normGPUName confronta i nomi senza maiuscole, marchi e spazi multipli.
func normGPUName(s string) string {
	s = strings.ToLower(s)
	for _, x := range []string{"(r)", "(tm)", "®", "™"} {
		s = strings.ReplaceAll(s, x, " ")
	}
	return strings.Join(strings.Fields(s), " ")
}

// AssignWddm associa la versione WDDM alle schede video dell'analisi
// (Win32_VideoController): per nome, quando il nome della scheda D3DKMT
// corrisponde a uno e un solo nome; altrimenti, se c'è una sola scheda non
// software da una parte e una sola scheda (esclusi gli adattatori di base
// di Microsoft) dall'altra, a quella. Nei casi incerti il valore resta
// assente: meglio nessun dato che quello di un'altra scheda.
func AssignWddm(gpus []scan.PcGPU, adapters []wddmAdapter) {
	var real []wddmAdapter
	for _, a := range adapters {
		if !a.Software && a.Version > 0 {
			real = append(real, a)
		}
	}
	if len(real) == 0 || len(gpus) == 0 {
		return
	}
	done := false
	for _, a := range real {
		match := -1
		for i, g := range gpus {
			if normGPUName(g.Name) == normGPUName(a.Name) && a.Name != "" {
				if match >= 0 {
					match = -2 // due schede con lo stesso nome: non si sa quale
					break
				}
				match = i
			}
		}
		if match >= 0 {
			gpus[match].Wddm = a.Version
			done = true
		}
	}
	if done {
		return
	}
	candidates := []int{}
	for i, g := range gpus {
		if !strings.HasPrefix(normGPUName(g.Name), "microsoft ") {
			candidates = append(candidates, i)
		}
	}
	if len(real) == 1 && len(candidates) == 1 {
		gpus[candidates[0]].Wddm = real[0].Version
	}
}
