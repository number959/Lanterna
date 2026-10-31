package certs

// Bit di CERT_TRUST_STATUS.dwErrorStatus (wincrypt.h).
const (
	trustNotTimeValid      = 0x00000001
	trustNotTimeNested     = 0x00000002
	trustRevoked           = 0x00000004
	trustNotSignatureValid = 0x00000008
	trustNotValidForUsage  = 0x00000010
	trustUntrustedRoot     = 0x00000020
	trustRevocationUnknown = 0x00000040
	trustCyclic            = 0x00000080
	trustOfflineRevocation = 0x01000000
	trustPartialChain      = 0x00010000
	trustExplicitDistrust  = 0x04000000
)

// trustOf riduce lo stato della catena a una parola. Scadenza e revoca non
// contano qui (la scadenza si calcola dalle date, la revoca non si controlla
// per non contattare indirizzi che l'utente non ha indicato).
func trustOf(status uint32) string {
	s := status &^ (trustNotTimeValid | trustNotTimeNested | trustRevocationUnknown | trustOfflineRevocation)
	switch {
	case s == 0:
		return "trusted"
	case s&trustExplicitDistrust != 0:
		return "distrusted"
	case s&trustRevoked != 0:
		return "revoked"
	case s&(trustNotSignatureValid|trustCyclic) != 0:
		return "invalid-signature"
	case s&trustPartialChain != 0:
		return "partial-chain"
	case s&trustUntrustedRoot != 0:
		return "untrusted-root"
	case s&trustNotValidForUsage != 0:
		return "wrong-usage"
	}
	return "untrusted-root"
}
