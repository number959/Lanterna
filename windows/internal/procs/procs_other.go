//go:build !windows

package procs

import (
	"context"

	"lanterna/internal/scan"
)

// Read è disponibile solo su Windows: altrove restituisce ErrUnavailable.
func Read(ctx context.Context, cpu map[uint32]float64) (*scan.ProcessesData, error) {
	return nil, ErrUnavailable
}
