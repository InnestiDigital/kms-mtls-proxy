package kms_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"mtls-proxy/src/kms"
	"mtls-proxy/tests/kmsfake"
)

// TestRealKMSSignerMatchesFakeAssumptions checks the signing algorithms the
// proxy can ask for against the real service, and verifies each signature
// against the key's public half.
func TestRealKMSSignerMatchesFakeAssumptions(t *testing.T) {
	signer, err := kms.NewSignerFromEnv(t.Context(), kmsfake.RealKeyID(t))
	if err != nil {
		t.Fatalf("NewSignerFromEnv: %v", err)
	}

	pub, ok := signer.Public().(*rsa.PublicKey)
	if !ok {
		t.Fatalf("Public() is %T, want *rsa.PublicKey", signer.Public())
	}
	t.Logf("key is %d bits", pub.Size()*8)

	digest := sha256.Sum256([]byte("verification payload"))

	t.Run("RSASSA_PSS_SHA_256", func(t *testing.T) {
		opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
		sig, err := signer.Sign(rand.Reader, digest[:], opts)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if err := rsa.VerifyPSS(pub, crypto.SHA256, digest[:], sig, opts); err != nil {
			t.Fatalf("PSS signature does not verify: %v", err)
		}
	})

	t.Run("RSASSA_PKCS1_V1_5_SHA_256", func(t *testing.T) {
		sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
			t.Fatalf("PKCS#1 v1.5 signature does not verify: %v", err)
		}
	})

	t.Run("SHA-1 is refused locally", func(t *testing.T) {
		if _, err := signer.Sign(rand.Reader, make([]byte, 20), crypto.SHA1); err == nil {
			t.Fatal("expected SHA-1 to be refused before reaching the service")
		}
	})
}
