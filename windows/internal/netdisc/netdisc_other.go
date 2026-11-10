//go:build !windows

package netdisc

import (
	"context"
	"errors"
)

// Routes non è disponibile fuori da Windows.
func Routes() ([]Route, error) { return nil, errors.New("disponibile solo su Windows") }

// ADSubnetsOf non è disponibile fuori da Windows.
func ADSubnetsOf(_ context.Context, _ string) ADSubnets {
	return ADSubnets{Read: "error", Error: "disponibile solo su Windows"}
}
