package pcinfo

import "time"

// CPUByPID confronta due letture dei processi e restituisce il carico di
// ciascun PID in percentuale della capacità totale (tutti i processori), con
// lo stesso calcolo di GroupProcesses; solo i PID presenti in entrambe le
// letture. Serve ai processi con firma (pacchetto procs), che riportano il
// carico misurato a fine analisi.
func CPUByPID(before, after []ProcSample, elapsed time.Duration, ncpu int) map[uint32]float64 {
	capacity := float64(elapsed.Nanoseconds()/100) * float64(max(ncpu, 1))
	out := map[uint32]float64{}
	if capacity <= 0 {
		return out
	}
	prev := map[uint32]ProcSample{}
	for _, p := range before {
		prev[p.PID] = p
	}
	for _, p := range after {
		// Stesso PID ma tempo di CPU minore: è un processo nuovo con il PID
		// riutilizzato, non si misura.
		if q, ok := prev[p.PID]; ok && p.CPU >= q.CPU && q.Name == p.Name {
			out[p.PID] = round1(100 * float64(p.CPU-q.CPU) / capacity)
		}
	}
	return out
}
