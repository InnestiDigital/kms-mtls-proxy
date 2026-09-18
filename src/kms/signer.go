// Package kms provides a crypto.Signer backed by an asymmetric AWS KMS key, so
// a TLS client certificate can be used without its private key ever existing
// outside the service.
package kms

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"sync/atomic"

	"github.com/aws/aws-sdk-go-v2/config"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// kmsAPI is the subset of the KMS API the signer uses. *awskms.Client
// satisfies it; tests substitute a local implementation.
type kmsAPI interface {
	GetPublicKey(context.Context, *awskms.GetPublicKeyInput, ...func(*awskms.Options)) (*awskms.GetPublicKeyOutput, error)
	Sign(context.Context, *awskms.SignInput, ...func(*awskms.Options)) (*awskms.SignOutput, error)
}

// Signer is a crypto.Signer backed by an asymmetric KMS CMK. Sign is a network
// call; the private key is never held in this process.
type Signer struct {
	api   kmsAPI
	keyID string
	pub   crypto.PublicKey
	signs atomic.Uint64
}

// NewSigner fetches the public half of the CMK and verifies the key is usable
// for signing.
func NewSigner(ctx context.Context, api kmsAPI, keyID string) (*Signer, error) {
	out, err := api.GetPublicKey(ctx, &awskms.GetPublicKeyInput{KeyId: &keyID})
	if err != nil {
		return nil, fmt.Errorf("kms GetPublicKey: %w", err)
	}
	if out.KeyUsage != types.KeyUsageTypeSignVerify {
		// A signing key must not also be usable for encryption. KMS enforces
		// this per CMK; refuse anything not created that way.
		return nil, fmt.Errorf("CMK %s has usage %s, want SIGN_VERIFY", keyID, out.KeyUsage)
	}
	pub, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse KMS public key: %w", err)
	}
	return &Signer{api: api, keyID: keyID, pub: pub}, nil
}

// NewSignerFromEnv builds a Signer using the ambient AWS credential chain
// (task role, instance role or shared config).
func NewSignerFromEnv(ctx context.Context, keyID string) (*Signer, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	return NewSigner(ctx, awskms.NewFromConfig(cfg), keyID)
}

func (s *Signer) Public() crypto.PublicKey { return s.pub }

// SignCount is the number of kms:Sign calls made so far. Session resumption is
// supposed to keep this far below the request count; if the two track each
// other, resumption is not working and both latency and cost scale with
// traffic.
func (s *Signer) SignCount() uint64 { return s.signs.Load() }

func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	alg, err := signingAlgorithm(s.pub, opts)
	if err != nil {
		return nil, err
	}
	out, err := s.api.Sign(context.Background(), &awskms.SignInput{
		KeyId:            &s.keyID,
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: alg,
	})
	if err != nil {
		return nil, fmt.Errorf("kms Sign (%s): %w", alg, err)
	}
	// Logged rather than exported as a metric: these should be rare enough
	// that one line each is cheap, and it gives a countable signal in
	// CloudWatch Logs without adding a metrics dependency.
	log.Printf("kms:Sign #%d (%s)", s.signs.Add(1), alg)
	return out.Signature, nil
}
