//go:build windows

package certs

import (
	"crypto/x509"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Indicatori di CertGetCertificateChain (wincrypt.h): solo ciò che è già
// sul PC, senza scaricare emittenti, elenchi o radici da Internet.
const (
	chainCacheOnlyURLRetrieval     = 0x00000004
	chainReturnLowerQuality        = 0x00000080
	chainDisableAuthRootAutoUpdate = 0x00000100
)

var oidServerAuth = []byte("1.3.6.1.5.5.7.3.1\x00")

// platformTrust costruisce la catena con l'archivio dei certificati di
// Windows dell'utente (che comprende quelli del computer, dei criteri di
// gruppo e di Active Directory), con gli intermedi presentati dal servizio.
// La scadenza e il nome si valutano a parte: qui conta solo chi ha firmato.
func platformTrust(chain []*x509.Certificate) string {
	if len(chain) == 0 {
		return ""
	}
	leaf, err := windows.CertCreateCertificateContext(windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING, &chain[0].Raw[0], uint32(len(chain[0].Raw)))
	if err != nil {
		return ""
	}
	defer windows.CertFreeCertificateContext(leaf)
	store, err := windows.CertOpenStore(windows.CERT_STORE_PROV_MEMORY, 0, 0, windows.CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG, 0)
	if err != nil {
		return ""
	}
	defer windows.CertCloseStore(store, 0)
	for _, c := range chain[1:] {
		ctx, err := windows.CertCreateCertificateContext(windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING, &c.Raw[0], uint32(len(c.Raw)))
		if err != nil {
			continue
		}
		_ = windows.CertAddCertificateContextToStore(store, ctx, windows.CERT_STORE_ADD_ALWAYS, nil)
		windows.CertFreeCertificateContext(ctx)
	}
	usage := &oidServerAuth[0]
	para := windows.CertChainPara{
		RequestedUsage: windows.CertUsageMatch{
			Type:  windows.USAGE_MATCH_TYPE_AND,
			Usage: windows.CertEnhKeyUsage{Length: 1, UsageIdentifiers: &usage},
		},
	}
	para.Size = uint32(unsafe.Sizeof(para))
	var cc *windows.CertChainContext
	flags := uint32(chainCacheOnlyURLRetrieval | chainReturnLowerQuality | chainDisableAuthRootAutoUpdate)
	if err := windows.CertGetCertificateChain(0, leaf, nil, store, &para, flags, 0, &cc); err != nil {
		return ""
	}
	defer windows.CertFreeCertificateChain(cc)
	return trustOf(cc.TrustStatus.ErrorStatus)
}
