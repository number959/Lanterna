//go:build !windows

package pcinfo

import (
	"context"
	"errors"
	"time"

	"lanterna/internal/scan"
)

// Collect è disponibile solo su Windows.
func Collect(ctx context.Context) (*scan.PcData, error) {
	return nil, errors.New("misura disponibile solo su Windows")
}

// SampleLoad è disponibile solo su Windows.
func SampleLoad(ctx context.Context, d time.Duration) (*float64, []scan.ProcessInfo) {
	return nil, nil
}

// CPULoad è disponibile solo su Windows.
func CPULoad(ctx context.Context, d time.Duration) *float64 { return nil }

// OnAC è disponibile solo su Windows.
func OnAC() *bool { return nil }
