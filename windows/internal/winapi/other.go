//go:build !windows

package winapi

import (
	"context"

	"lanterna/internal/scan"
)

func NewPinger() (Pinger, error)                           { return nil, ErrUnsupported }
func Adapters() ([]scan.Adapter, error)                    { return nil, ErrUnsupported }
func Neighbors() ([]scan.Neighbor, error)                  { return nil, ErrUnsupported }
func Wifi(context.Context, bool) (*scan.WifiData, error)   { return nil, ErrUnsupported }
func Firewall(context.Context) (*scan.FirewallData, error) { return nil, ErrUnsupported }
func Elevated() bool                                       { return false }
func OSDescription() string                                { return "sistema non Windows" }
