//go:build !windows

package l2disc

import (
	"context"
	"testing"
)

func TestListenUnsupported(t *testing.T) {
	d := Listen(context.Background(), 0)
	if d.Read != ReadUnsupported || d.Error == "" || d.Seconds != 0 {
		t.Fatalf("%+v", d)
	}
}
