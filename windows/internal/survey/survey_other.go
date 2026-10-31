//go:build !windows

package survey

import (
	"context"

	"lanterna/internal/scan"
)

// Sample fuori da Windows non è disponibile.
func Sample(context.Context, Options) (*scan.SurveySample, error) { return nil, ErrUnavailable }
