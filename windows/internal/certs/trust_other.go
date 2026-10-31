//go:build !windows

package certs

import "crypto/x509"

// platformTrust: fuori da Windows l'attendibilità non si valuta.
func platformTrust([]*x509.Certificate) string { return "" }
