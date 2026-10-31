//go:build !windows

package crash

import (
	"context"

	"lanterna/internal/scan"
)

// Read esiste solo su Windows.
func Read(context.Context) (*scan.CrashData, error) { return nil, ErrUnavailable }
