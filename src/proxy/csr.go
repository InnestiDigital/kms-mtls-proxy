package proxy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"

	"mtls-proxy/src/config"
)

// WriteCSR builds a certificate signing request and signs it with the CMK, so
// the request can be handed to the third party's CA without the private key
// ever existing outside KMS.
//
// x509.CreateCertificateRequest accepts a crypto.Signer, so no DER is
// assembled by hand.
func WriteCSR(cfg config.Config, signer crypto.Signer, out io.Writer) error {
	subject := pkix.Name{
		CommonName:   cfg.CSRCommonName,
		Organization: []string{cfg.CSROrg},
	}
	// Country is optional; an empty attribute is worse than an absent one.
	if cfg.CSRCountry != "" {
		subject.Country = []string{cfg.CSRCountry}
	}
	tmpl := &x509.CertificateRequest{Subject: subject}
	switch signer.Public().(type) {
	case *rsa.PublicKey:
		// PKCS#1 v1.5 for the request itself. The handshake negotiates PSS
		// independently of how the CSR was signed.
		tmpl.SignatureAlgorithm = x509.SHA256WithRSA
	case *ecdsa.PublicKey:
		tmpl.SignatureAlgorithm = x509.ECDSAWithSHA256
	default:
		return fmt.Errorf("unsupported public key type %T", signer.Public())
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, signer)
	if err != nil {
		return fmt.Errorf("create CSR: %w", err)
	}
	if err := pem.Encode(out, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}); err != nil {
		return fmt.Errorf("encode CSR: %w", err)
	}
	return nil
}
