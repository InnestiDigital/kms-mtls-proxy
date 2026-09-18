package kms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// signingAlgorithm maps what crypto/tls or crypto/x509 asks for onto a KMS
// signing algorithm.
func signingAlgorithm(pub crypto.PublicKey, opts crypto.SignerOpts) (types.SigningAlgorithmSpec, error) {
	h := opts.HashFunc()

	if pss, ok := opts.(*rsa.PSSOptions); ok {
		// KMS always uses salt length == hash length, which is what TLS asks
		// for. Reject anything else rather than produce a signature the peer
		// will fail to verify.
		if pss.SaltLength != rsa.PSSSaltLengthEqualsHash && pss.SaltLength != h.Size() {
			return "", fmt.Errorf("PSS salt length %d unsupported, KMS uses hash length (%d)", pss.SaltLength, h.Size())
		}
		switch h {
		case crypto.SHA256:
			return types.SigningAlgorithmSpecRsassaPssSha256, nil
		case crypto.SHA384:
			return types.SigningAlgorithmSpecRsassaPssSha384, nil
		case crypto.SHA512:
			return types.SigningAlgorithmSpecRsassaPssSha512, nil
		}
		return "", fmt.Errorf("unsupported PSS hash %s", h)
	}

	switch pub.(type) {
	case *rsa.PublicKey:
		switch h {
		case crypto.SHA256:
			return types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, nil
		case crypto.SHA384:
			return types.SigningAlgorithmSpecRsassaPkcs1V15Sha384, nil
		case crypto.SHA512:
			return types.SigningAlgorithmSpecRsassaPkcs1V15Sha512, nil
		}
	case *ecdsa.PublicKey:
		switch h {
		case crypto.SHA256:
			return types.SigningAlgorithmSpecEcdsaSha256, nil
		case crypto.SHA384:
			return types.SigningAlgorithmSpecEcdsaSha384, nil
		case crypto.SHA512:
			return types.SigningAlgorithmSpecEcdsaSha512, nil
		}
	}
	return "", fmt.Errorf("unsupported key/hash combination %T/%s", pub, h)
}
