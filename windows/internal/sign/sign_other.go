//go:build !windows

package sign

import (
	"context"

	"lanterna/internal/scan"
)

// Fuori da Windows non c'è WinVerifyTrust: nessuna firma e nessuna
// informazione di versione.
func verify(context.Context, string) *scan.FileSignature { return nil }

func versionInfo(string) (company, description, version string) { return "", "", "" }
