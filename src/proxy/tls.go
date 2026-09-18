package proxy

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"mtls-proxy/src/config"
)

// clientCertificate pairs the PEM certificate chain with the KMS signer. The
// usual tls.LoadX509KeyPair cannot be used because there is no key file.
//
// The chain is inline from the environment: Fargate injects secrets as
// environment variables and offers no way to mount one as a file. For local
// development the Makefile reads the file into the variable.
func clientCertificate(cfg config.Config, signer crypto.Signer) (*tls.Certificate, error) {
	chain, err := parseCertChain([]byte(cfg.ClientCertContents))
	if err != nil {
		return nil, fmt.Errorf("client certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, fmt.Errorf("parse leaf certificate: %w", err)
	}
	return &tls.Certificate{
		Certificate: chain,
		PrivateKey:  signer,
		Leaf:        leaf,
	}, nil
}

// clientTLSConfig builds the TLS configuration used toward the third party.
func clientTLSConfig(cert *tls.Certificate, caPath string) (*tls.Config, error) {
	conf := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
		// Session resumption is what keeps kms:Sign off the request path:
		// without it every new connection costs another signature, another
		// round trip and another billed request.
		ClientSessionCache: tls.NewLRUClientSessionCache(sessionCacheSize),
	}
	if caPath == "" {
		return conf, nil
	}
	pemBytes, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read upstream CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("no certificates found in %s", caPath)
	}
	conf.RootCAs = pool
	return conf, nil
}

// parseCertChain reads every CERTIFICATE block from PEM data, leaf first.
func parseCertChain(pemBytes []byte) ([][]byte, error) {
	var chain [][]byte
	for {
		var blk *pem.Block
		blk, pemBytes = pem.Decode(pemBytes)
		if blk == nil {
			break
		}
		if blk.Type == "CERTIFICATE" {
			chain = append(chain, blk.Bytes)
		}
	}
	if len(chain) == 0 {
		return nil, errors.New("no CERTIFICATE blocks found")
	}
	return chain, nil
}
