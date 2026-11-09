//go:build !windows

package winevt

import (
	"context"
	"errors"
)

// Query è disponibile solo su Windows.
func Query(ctx context.Context, channel, xpath string, max int) ([]Event, error) {
	return nil, errors.New("registro eventi disponibile solo su Windows")
}
