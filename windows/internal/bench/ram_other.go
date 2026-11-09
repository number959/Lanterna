//go:build !windows

package bench

import "runtime"

// allocRAM fuori da Windows (solo per le prove): memoria normale di Go, non
// bloccata in RAM, al massimo 64 MB se non indicato.
func allocRAM(maxMB int) (*ramBlock, error) {
	if maxMB <= 0 {
		maxMB = 64
	}
	w := make([]uint64, maxMB<<20/8)
	return &ramBlock{words: w, totalMB: maxMB, availMB: maxMB, free: func() { runtime.KeepAlive(w) }}, nil
}
