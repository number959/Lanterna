//go:build windows

package sign

import (
	"context"

	"lanterna/internal/scan"
)

// verify verifica la firma Authenticode di path: prima quella incorporata,
// poi il catalogo di Windows. DA IMPLEMENTARE (0.14.0): WinVerifyTrust con
// WINTRUST_ACTION_GENERIC_VERIFY_V2, WTD_REVOKE_NONE e
// WTD_CACHE_ONLY_URL_RETRIEVAL; catalogo con CryptCATAdmin*.
func verify(ctx context.Context, path string) *scan.FileSignature { return nil }

// versionInfo legge CompanyName, FileDescription e FileVersion dalle
// informazioni di versione. DA IMPLEMENTARE (0.14.0).
func versionInfo(path string) (company, description, version string) { return "", "", "" }
