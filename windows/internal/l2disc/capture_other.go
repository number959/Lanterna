//go:build !windows

package l2disc

import (
	"context"
	"time"
)

// Listen è disponibile solo su Windows.
func Listen(ctx context.Context, d time.Duration) Discovery {
	return Discovery{Read: ReadUnsupported, Error: msgUnsupported}
}
