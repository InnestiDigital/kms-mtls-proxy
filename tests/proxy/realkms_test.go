package proxy_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"mtls-proxy/src/config"
	"mtls-proxy/src/kms"
	"mtls-proxy/src/proxy"
	"mtls-proxy/tests/kmsfake"
)

// TestRealKMSMutualTLSHandshake is the claim the whole design rests on: a
// private key that exists only inside KMS completes a mutual TLS handshake.
// Skipped unless MTLS_PROXY_REAL_KMS_KEY_ID is set.
func TestRealKMSMutualTLSHandshake(t *testing.T) {
	keyID := kmsfake.RealKeyID(t)
	signer, err := kms.NewSignerFromEnv(t.Context(), keyID)
	if err != nil {
		t.Fatalf("NewSignerFromEnv: %v", err)
	}

	caKey, caCert := newCA(t)
	clientCertDER := newClientCert(t, caKey, caCert, signer.Public())

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	var negotiated atomic.Uint32
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		negotiated.Store(uint32(r.TLS.Version))
		_, _ = io.WriteString(w, "authenticated as "+r.TLS.PeerCertificates[0].Subject.CommonName)
	}))
	upstream.TLS = &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  caPool,
		// TLS 1.3 forces RSA-PSS for RSA certificates, which is the path a
		// modern third party will take.
		MinVersion: tls.VersionTLS13,
	}
	upstream.StartTLS()
	defer upstream.Close()
	caPool.AddCert(upstream.Certificate())

	cfg := proxyConfig(t, upstream.URL, upstream.Certificate().Raw, clientCertDER)
	startProxy(t, cfg, signer)

	resp, err := http.Get("http://" + cfg.Listen + "/verify")
	if err != nil {
		t.Fatalf("request through proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %s, want 200", resp.Status)
	}
	if got, want := string(body), "authenticated as test-client"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if got := negotiated.Load(); got != tls.VersionTLS13 {
		t.Errorf("negotiated TLS version %x, want 1.3", got)
	}
	t.Logf("TLS 1.3 handshake completed using %d KMS signing operation(s)", signer.SignCount())
}

// TestRealKMSCSR confirms the request handed to a CA is well formed and signed
// by the real key.
func TestRealKMSCSR(t *testing.T) {
	keyID := kmsfake.RealKeyID(t)
	signer, err := kms.NewSignerFromEnv(t.Context(), keyID)
	if err != nil {
		t.Fatalf("NewSignerFromEnv: %v", err)
	}

	var out bytes.Buffer
	cfg := config.Config{
		KMSKeyID:      keyID,
		CSRCommonName: "client.example.com",
		CSROrg:        "Example Organisation",
		CSRCountry:    "ZZ",
	}
	if err := proxy.WriteCSR(cfg, signer, &out); err != nil {
		t.Fatalf("WriteCSR: %v", err)
	}

	blk, _ := pem.Decode(out.Bytes())
	if blk == nil || blk.Type != "CERTIFICATE REQUEST" {
		t.Fatal("output is not a PEM certificate request")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature does not verify: %v", err)
	}
	t.Logf("CSR signed with %s", csr.SignatureAlgorithm)
}
