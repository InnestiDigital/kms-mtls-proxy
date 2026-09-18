// Package kmsfake provides an in-process stand-in for the KMS API, so packages
// that sign through KMS can be tested without credentials or network access.
//
// It implements the same interface *awskms.Client does, signing with a locally
// generated RSA key, so src/kms is exercised end to end minus the network.
//
// TEST SUPPORT ONLY. Nothing under tests/ is imported by the application, so
// none of it is linked into the shipped binary.
package kmsfake

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// KeyID is an arbitrary well-formed key ARN for tests to pass around.
const KeyID = "arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000000"

// KMS is a stand-in for the KMS API backed by a locally generated RSA key.
type KMS struct {
	key         *rsa.PrivateKey
	keyUsage    types.KeyUsageType
	signLatency time.Duration

	signs int
}

// Option configures a KMS.
type Option func(*KMS)

// WithKeyUsage overrides the usage reported by GetPublicKey, to exercise the
// guard that refuses a key which can also decrypt.
func WithKeyUsage(usage types.KeyUsageType) Option {
	return func(k *KMS) { k.keyUsage = usage }
}

// WithSignLatency makes every Sign wait before returning, standing in for the
// round trip to the real service. The fake answers in microseconds, which
// would otherwise make a handshake look free; the real call is dominated by
// the network, so a measurement taken without this is not comparable to one
// taken against KMS.
func WithSignLatency(d time.Duration) Option {
	return func(k *KMS) { k.signLatency = d }
}

// New starts a fake and registers its shutdown with the test.
func New(t testing.TB, opts ...Option) *KMS {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate fake KMS key: %v", err)
	}
	k := &KMS{key: key, keyUsage: types.KeyUsageTypeSignVerify}
	for _, opt := range opts {
		opt(k)
	}
	return k
}

// PublicKey is the public half of the key the fake signs with.
func (k *KMS) PublicKey() *rsa.PublicKey { return &k.key.PublicKey }

// Signs is the number of successful Sign calls served.
func (k *KMS) Signs() int { return k.signs }

func (k *KMS) GetPublicKey(_ context.Context, in *awskms.GetPublicKeyInput, _ ...func(*awskms.Options)) (*awskms.GetPublicKeyOutput, error) {
	der, err := x509.MarshalPKIXPublicKey(&k.key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &awskms.GetPublicKeyOutput{
		KeyId:     in.KeyId,
		PublicKey: der,
		KeySpec:   types.KeySpecRsa2048,
		KeyUsage:  k.keyUsage,
		SigningAlgorithms: []types.SigningAlgorithmSpec{
			types.SigningAlgorithmSpecRsassaPssSha256, types.SigningAlgorithmSpecRsassaPssSha384, types.SigningAlgorithmSpecRsassaPssSha512,
			types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, types.SigningAlgorithmSpecRsassaPkcs1V15Sha384, types.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
		},
	}, nil
}

func (k *KMS) Sign(_ context.Context, in *awskms.SignInput, _ ...func(*awskms.Options)) (*awskms.SignOutput, error) {
	hash, pss, err := algorithmParams(in.SigningAlgorithm)
	if err != nil {
		return nil, err
	}
	if in.MessageType != types.MessageTypeDigest {
		return nil, errors.New("expected MessageType DIGEST, got " + string(in.MessageType))
	}
	if len(in.Message) != hash.Size() {
		return nil, errors.New("digest length does not match the signing algorithm")
	}
	time.Sleep(k.signLatency)

	var sig []byte
	if pss {
		sig, err = rsa.SignPSS(rand.Reader, k.key, hash, in.Message,
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: hash})
	} else {
		sig, err = rsa.SignPKCS1v15(rand.Reader, k.key, hash, in.Message)
	}
	if err != nil {
		return nil, err
	}

	k.signs++
	return &awskms.SignOutput{
		KeyId:            in.KeyId,
		Signature:        sig,
		SigningAlgorithm: in.SigningAlgorithm,
	}, nil
}

// algorithmParams maps a KMS signing algorithm onto a hash and a padding mode.
func algorithmParams(alg types.SigningAlgorithmSpec) (crypto.Hash, bool, error) {
	switch alg {
	case types.SigningAlgorithmSpecRsassaPssSha256:
		return crypto.SHA256, true, nil
	case types.SigningAlgorithmSpecRsassaPssSha384:
		return crypto.SHA384, true, nil
	case types.SigningAlgorithmSpecRsassaPssSha512:
		return crypto.SHA512, true, nil
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha256:
		return crypto.SHA256, false, nil
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha384:
		return crypto.SHA384, false, nil
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha512:
		return crypto.SHA512, false, nil
	}
	return 0, false, errors.New("unsupported signing algorithm " + string(alg))
}
