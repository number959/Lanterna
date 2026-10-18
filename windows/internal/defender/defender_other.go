//go:build !windows

package defender

import "context"

// Available: Defender esiste solo su Windows.
func Available() error { return ErrUnavailable }

// Run è disponibile solo su Windows.
func Run(ctx context.Context, action string) (*Result, error) {
	if _, err := Args(action); err != nil {
		return nil, err
	}
	return nil, ErrUnavailable
}
