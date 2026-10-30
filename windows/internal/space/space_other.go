//go:build !windows

package space

import "context"

// Scan non è disponibile fuori da Windows.
func Scan(context.Context, string, Options) (*Result, error) { return nil, ErrUnavailable }

// Normalize non è disponibile fuori da Windows.
func Normalize(string) (string, error) { return "", ErrUnavailable }

// Open non è disponibile fuori da Windows.
func Open(string, bool) error { return ErrUnavailable }
