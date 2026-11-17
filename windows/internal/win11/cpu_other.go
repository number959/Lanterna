//go:build !windows

package win11

// LocalCPU è disponibile solo su Windows.
func LocalCPU() (name, vendor string) { return "", "" }
