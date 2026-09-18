package config_test

import (
	"strings"
	"testing"

	"mtls-proxy/src/config"
)

func TestLoadDefaults(t *testing.T) {
	for _, key := range []string{
		"KMS_KEY_ID", "UPSTREAM_HOST", "CLIENT_CERT_PEM_CONTENTS",
		"UPSTREAM_CA_PEM", "LISTEN", "CSR_COMMON_NAME", "CSR_ORG", "CSR_COUNTRY",
	} {
		t.Setenv(key, "")
	}

	cfg := config.Load()

	if cfg.Listen != ":8443" {
		t.Errorf("Listen defaulted to %q, want :8443", cfg.Listen)
	}
	// Listen is the only value with a default. Everything identifying a
	// deployment, a company or a counterparty must come from the environment,
	// so that this binary carries no knowledge of who runs it.
	for _, c := range []struct{ got, field string }{
		{cfg.KMSKeyID, "KMSKeyID"},
		{cfg.UpstreamHost, "UpstreamHost"},
		{cfg.ClientCertContents, "ClientCertContents"},
		{cfg.CSRCommonName, "CSRCommonName"},
		{cfg.CSROrg, "CSROrg"},
		{cfg.CSRCountry, "CSRCountry"},
	} {
		if c.got != "" {
			t.Errorf("%s defaulted to %q, want empty so validation can report it", c.field, c.got)
		}
	}
}

func TestLoadReadsEnvironment(t *testing.T) {
	t.Setenv("KMS_KEY_ID", "key-1")
	t.Setenv("UPSTREAM_HOST", "api.example.test")
	t.Setenv("CLIENT_CERT_PEM_CONTENTS", "-----BEGIN CERTIFICATE-----")
	t.Setenv("UPSTREAM_CA_PEM", "/certs/ca.pem")
	t.Setenv("LISTEN", "127.0.0.1:9999")
	t.Setenv("CSR_COMMON_NAME", "cn.example.test")
	t.Setenv("CSR_ORG", "Other Org")
	t.Setenv("CSR_COUNTRY", "IT")

	cfg := config.Load()

	for _, c := range []struct{ got, want, field string }{
		{cfg.KMSKeyID, "key-1", "KMSKeyID"},
		{cfg.UpstreamHost, "api.example.test", "UpstreamHost"},
		{cfg.ClientCertContents, "-----BEGIN CERTIFICATE-----", "ClientCertContents"},
		{cfg.UpstreamCAPEM, "/certs/ca.pem", "UpstreamCAPEM"},
		{cfg.Listen, "127.0.0.1:9999", "Listen"},
		{cfg.CSRCommonName, "cn.example.test", "CSRCommonName"},
		{cfg.CSROrg, "Other Org", "CSROrg"},
		{cfg.CSRCountry, "IT", "CSRCountry"},
	} {
		if c.got != c.want {
			t.Errorf("%s is %q, want %q", c.field, c.got, c.want)
		}
	}
}

func TestValidateProxy(t *testing.T) {
	valid := config.Config{
		KMSKeyID:           "key-1",
		UpstreamHost:       "api.example.test",
		ClientCertContents: "-----BEGIN CERTIFICATE-----",
	}

	t.Run("accepts a complete configuration", func(t *testing.T) {
		if err := valid.ValidateProxy(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	for _, name := range []string{"KMS_KEY_ID", "UPSTREAM_HOST", "CLIENT_CERT_PEM_CONTENTS"} {
		t.Run("names missing "+name, func(t *testing.T) {
			cfg := valid
			switch name {
			case "KMS_KEY_ID":
				cfg.KMSKeyID = ""
			case "UPSTREAM_HOST":
				cfg.UpstreamHost = ""
			case "CLIENT_CERT_PEM_CONTENTS":
				cfg.ClientCertContents = ""
			}
			err := cfg.ValidateProxy()
			if err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("got %v, want a %s error", err, name)
			}
		})
	}
}

func TestValidateCSR(t *testing.T) {
	valid := config.Config{
		KMSKeyID:      "key-1",
		CSRCommonName: "client.example.com",
		CSROrg:        "Example Organisation",
	}

	t.Run("accepts a complete configuration", func(t *testing.T) {
		if err := valid.ValidateCSR(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	for _, name := range []string{"KMS_KEY_ID", "CSR_COMMON_NAME", "CSR_ORG"} {
		t.Run("names missing "+name, func(t *testing.T) {
			cfg := valid
			switch name {
			case "KMS_KEY_ID":
				cfg.KMSKeyID = ""
			case "CSR_COMMON_NAME":
				cfg.CSRCommonName = ""
			case "CSR_ORG":
				cfg.CSROrg = ""
			}
			err := cfg.ValidateCSR()
			if err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("got %v, want a %s error", err, name)
			}
		})
	}
}
