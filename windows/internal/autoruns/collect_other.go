//go:build !windows

package autoruns

import (
	"context"
	"errors"

	"lanterna/internal/scan"
)

// Collect fuori da Windows non ha nulla da leggere.
func Collect(context.Context) (*scan.AutorunsData, error) {
	return nil, errors.New("avvio automatico disponibile solo su Windows")
}
