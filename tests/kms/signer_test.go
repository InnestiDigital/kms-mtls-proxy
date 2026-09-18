package kms_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"mtls-proxy/src/kms"
	"mtls-proxy/tests/kmsfake"
)

// TestSignerAlgorithmSelection drives the mapping from a requested signing
// algorithm to a KMS algorithm through Sign itself, so it exercises the same
// path the TLS handshake and CSR generation take.
func TestSignerAlgorithmSelection(t *testing.T) {
	fake := kmsfake.New(t)
	signer, err := kms.NewSigner(t.Context(), fake, kmsfake.KeyID)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	cases := []struct {
		name    string
		hash    crypto.Hash
		opts    crypto.SignerOpts
		wantErr bool
	}{
		// TLS 1.3 mandates PSS for RSA certificates, so this is the path the
		// handshake actually takes.
		{"tls1.3 rsa-pss sha256", crypto.SHA256, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}, false},
		{"rsa-pss sha384", crypto.SHA384, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA384}, false},
		{"rsa-pss sha512", crypto.SHA512, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA512}, false},
		// CreateCertificateRequest asks for PKCS#1 v1.5.
		{"csr pkcs1v15 sha256", crypto.SHA256, crypto.SHA256, false},
		// KMS cannot produce these; signing anyway would yield a signature
		// the peer rejects, which is far harder to debug than failing here.
		{"pss salt length mismatch", crypto.SHA256, &rsa.PSSOptions{SaltLength: 1, Hash: crypto.SHA256}, true},
		{"sha1 rejected", crypto.SHA1, crypto.SHA1, true},
		{"pss sha1 rejected", crypto.SHA1, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA1}, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := signer.Sign(rand.Reader, digest(c.hash), c.opts)
			if c.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func digest(h crypto.Hash) []byte {
	switch h {
	case crypto.SHA1:
		sum := sha1.Sum([]byte("payload"))
		return sum[:]
	case crypto.SHA384:
		sum := sha512.Sum384([]byte("payload"))
		return sum[:]
	case crypto.SHA512:
		sum := sha512.Sum512([]byte("payload"))
		return sum[:]
	default:
		sum := sha256.Sum256([]byte("payload"))
		return sum[:]
	}
}

// TestSignerAgainstFake covers the Signer end to end: the public key is
// fetched and parsed, and a signature produced by the service verifies
// against it.
func TestSignerAgainstFake(t *testing.T) {
	fake := kmsfake.New(t)
	signer, err := kms.NewSigner(t.Context(), fake, kmsfake.KeyID)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	pub, ok := signer.Public().(*rsa.PublicKey)
	if !ok {
		t.Fatalf("Public() returned %T, want *rsa.PublicKey", signer.Public())
	}
	if pub.N.Cmp(fake.PublicKey().N) != 0 {
		t.Fatal("Public() does not match the key the service holds")
	}

	digest := sha256.Sum256([]byte("payload to authenticate"))

	t.Run("PSS, as TLS 1.3 requires", func(t *testing.T) {
		opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
		sig, err := signer.Sign(rand.Reader, digest[:], opts)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if err := rsa.VerifyPSS(pub, crypto.SHA256, digest[:], sig, opts); err != nil {
			t.Fatalf("signature does not verify: %v", err)
		}
	})

	t.Run("PKCS#1 v1.5, as CSR signing uses", func(t *testing.T) {
		sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
			t.Fatalf("signature does not verify: %v", err)
		}
	})

	if got := signer.SignCount(); got != 2 {
		t.Fatalf("SignCount is %d, want 2", got)
	}
	if fake.Signs() != 2 {
		t.Fatalf("fake served %d Sign calls, want 2", fake.Signs())
	}
}

// TestNewSignerRejectsNonSigningKey covers the guard that a key usable for
// encryption must not be accepted: single-purpose keys are a requirement.
func TestNewSignerRejectsNonSigningKey(t *testing.T) {
	fake := kmsfake.New(t, kmsfake.WithKeyUsage(types.KeyUsageTypeEncryptDecrypt))

	_, err := kms.NewSigner(t.Context(), fake, kmsfake.KeyID)
	if err == nil {
		t.Fatal("expected a key with ENCRYPT_DECRYPT usage to be refused")
	}
	if !strings.Contains(err.Error(), "SIGN_VERIFY") {
		t.Fatalf("error %q does not explain the required usage", err)
	}
}

// TestSignerRejectsUnsupportedHashLocally asserts the mapping refuses locally
// rather than spending a request to be told no.
func TestSignerRejectsUnsupportedHashLocally(t *testing.T) {
	fake := kmsfake.New(t)
	signer, err := kms.NewSigner(t.Context(), fake, kmsfake.KeyID)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	if _, err := signer.Sign(rand.Reader, make([]byte, 20), crypto.SHA1); err == nil {
		t.Fatal("expected SHA-1 to be refused")
	}
	if fake.Signs() != 0 {
		t.Fatal("a request was sent for an algorithm known to be unsupported")
	}
}
