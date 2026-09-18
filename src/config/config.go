// Package config holds the proxy's runtime configuration, read once from the
// environment at startup.
package config

import (
	"errors"
	"os"
)

// Config is the full runtime configuration. Which fields are required depends
// on the subcommand, so Load performs no validation; each entrypoint calls the
// Validate method for the subcommand it is running.
type Config struct {
	KMSKeyID           string // KMS_KEY_ID
	UpstreamHost       string // UPSTREAM_HOST
	ClientCertContents string // CLIENT_CERT_PEM_CONTENTS
	UpstreamCAPEM      string // UPSTREAM_CA_PEM
	Listen             string // LISTEN
	CSRCommonName      string // CSR_COMMON_NAME
	CSROrg             string // CSR_ORG
	CSRCountry         string // CSR_COUNTRY
}

// Load reads the configuration from the environment, applying defaults.
func Load() Config {
	listen := os.Getenv("LISTEN")
	if listen == "" {
		listen = ":8443"
	}
	return Config{
		KMSKeyID:           os.Getenv("KMS_KEY_ID"),
		UpstreamHost:       os.Getenv("UPSTREAM_HOST"),
		ClientCertContents: os.Getenv("CLIENT_CERT_PEM_CONTENTS"),
		UpstreamCAPEM:      os.Getenv("UPSTREAM_CA_PEM"),
		Listen:             listen,
		CSRCommonName:      os.Getenv("CSR_COMMON_NAME"),
		CSROrg:             os.Getenv("CSR_ORG"),
		CSRCountry:         os.Getenv("CSR_COUNTRY"),
	}
}

// ValidateProxy reports what the proxy subcommand is missing, so a
// misconfigured container fails at startup with a usable message rather than
// on the first request.
func (c Config) ValidateProxy() error {
	if c.KMSKeyID == "" {
		return errors.New("KMS_KEY_ID is required")
	}
	if c.UpstreamHost == "" {
		return errors.New("UPSTREAM_HOST is required")
	}
	if c.ClientCertContents == "" {
		return errors.New("CLIENT_CERT_PEM_CONTENTS is required")
	}
	return nil
}

// ValidateCSR reports what the csr subcommand is missing.
func (c Config) ValidateCSR() error {
	if c.KMSKeyID == "" {
		return errors.New("KMS_KEY_ID is required")
	}
	if c.CSRCommonName == "" {
		return errors.New("CSR_COMMON_NAME is required")
	}
	if c.CSROrg == "" {
		return errors.New("CSR_ORG is required")
	}
	return nil
}
