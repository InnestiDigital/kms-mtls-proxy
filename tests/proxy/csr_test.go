package proxy_test

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"mtls-proxy/src/config"
	"mtls-proxy/src/proxy"
	"mtls-proxy/tests/kmsfake"
)

// TestWriteCSR covers the request handed to the third party's CA. The
// signature must verify against the KMS public key, otherwise the CA rejects
// it and the failure surfaces days later in someone else's inbox.
func TestWriteCSR(t *testing.T) {
	signer := newFakeSigner(t)
	pub, ok := signer.Public().(*rsa.PublicKey)
	if !ok {
		t.Fatalf("Public() is %T, want *rsa.PublicKey", signer.Public())
	}
	cfg := config.Config{
		KMSKeyID:      kmsfake.KeyID,
		CSRCommonName: "client.example.com",
		CSROrg:        "Example Organisation",
		CSRCountry:    "ZZ",
	}

	var out bytes.Buffer
	if err := proxy.WriteCSR(cfg, signer, &out); err != nil {
		t.Fatalf("WriteCSR: %v", err)
	}

	blk, rest := pem.Decode(out.Bytes())
	if blk == nil {
		t.Fatal("output is not PEM")
	}
	if blk.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("PEM block is %q, want CERTIFICATE REQUEST", blk.Type)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("unexpected trailing data after the request")
	}

	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature does not verify: %v", err)
	}

	if got := csr.Subject.CommonName; got != cfg.CSRCommonName {
		t.Errorf("common name is %q, want %q", got, cfg.CSRCommonName)
	}
	if got := csr.Subject.Organization; len(got) != 1 || got[0] != cfg.CSROrg {
		t.Errorf("organization is %v, want [%s]", got, cfg.CSROrg)
	}
	if got := csr.Subject.Country; len(got) != 1 || got[0] != cfg.CSRCountry {
		t.Errorf("country is %v, want [%s]", got, cfg.CSRCountry)
	}

	// The request must carry the KMS public key, not some locally generated
	// one: that is what binds the issued certificate to the CMK.
	got, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		t.Fatalf("marshal CSR public key: %v", err)
	}
	want, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal KMS public key: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("the request does not carry the KMS public key")
	}
}

// TestWriteCSROmitsEmptyCountry keeps an unset country out of the subject
// rather than emitting an empty attribute a CA may reject.
func TestWriteCSROmitsEmptyCountry(t *testing.T) {
	signer := newFakeSigner(t)

	var out bytes.Buffer
	cfg := config.Config{
		KMSKeyID:      kmsfake.KeyID,
		CSRCommonName: "client.example.com",
		CSROrg:        "Example Organisation",
	}
	if err := proxy.WriteCSR(cfg, signer, &out); err != nil {
		t.Fatalf("WriteCSR: %v", err)
	}
	blk, _ := pem.Decode(out.Bytes())
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if len(csr.Subject.Country) != 0 {
		t.Fatalf("country is %v, want absent", csr.Subject.Country)
	}
}
