//go:build !windows

package procs

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Fuori da Windows la lettura non c'è: il server risponde 501.
func TestReadUnavailable(t *testing.T) {
	d, err := Read(context.Background(), nil, time.Time{})
	if d != nil || !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("%+v %v", d, err)
	}
}
