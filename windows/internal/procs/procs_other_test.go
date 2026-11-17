//go:build !windows

package procs

import (
	"context"
	"errors"
	"testing"
)

// Fuori da Windows la lettura non c'è: il server risponde 501.
func TestReadUnavailable(t *testing.T) {
	d, err := Read(context.Background(), nil)
	if d != nil || !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("%+v %v", d, err)
	}
}
