package proxy_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"mtls-proxy/src/config"
	"mtls-proxy/src/kms"
	"mtls-proxy/src/proxy"
	"mtls-proxy/tests/kmsfake"
)

// TestMutualTLSWithKMSSigner is the load-bearing test: a client certificate
// whose private key exists only behind the KMS API completes a real mutual TLS
// handshake and carries a proxied request.
func TestMutualTLSWithKMSSigner(t *testing.T) {
	caKey, caCert := newCA(t)
	signer := newFakeSigner(t)
	clientCertDER := newClientCert(t, caKey, caCert, signer.Public())

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	var sawClientCN atomic.Value
	upstream := newMutualTLSServer(t, caPool, func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 {
			t.Error("upstream received no client certificate")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		sawClientCN.Store(r.TLS.PeerCertificates[0].Subject.CommonName)
		_, _ = io.WriteString(w, "upstream ok: "+r.URL.Path)
	})
	caPool.AddCert(upstream.Certificate())

	cfg := proxyConfig(t, upstream.URL, upstream.Certificate().Raw, clientCertDER)
	startProxy(t, cfg, signer)

	resp, err := http.Get("http://" + cfg.Listen + "/some/path?a=1")
	if err != nil {
		t.Fatalf("request through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %s, want 200", resp.Status)
	}
	body, _ := io.ReadAll(resp.Body)
	if got, want := string(body), "upstream ok: /some/path"; got != want {
		t.Fatalf("got body %q, want %q", got, want)
	}
	if got := sawClientCN.Load(); got != "test-client" {
		t.Fatalf("upstream saw client CN %v, want test-client", got)
	}
	if signer.SignCount() == 0 {
		t.Fatal("no signing operation took place, the client certificate was not used")
	}
}

// TestSigningStaysOffRequestPath asserts the connection reuse the sidecar
// exists for: many requests must not mean many signatures.
func TestSigningStaysOffRequestPath(t *testing.T) {
	caKey, caCert := newCA(t)
	signer := newFakeSigner(t)
	clientCertDER := newClientCert(t, caKey, caCert, signer.Public())

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	upstream := newMutualTLSServer(t, caPool, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	caPool.AddCert(upstream.Certificate())

	cfg := proxyConfig(t, upstream.URL, upstream.Certificate().Raw, clientCertDER)
	startProxy(t, cfg, signer)

	const requests = 20
	for i := 0; i < requests; i++ {
		resp, err := http.Get("http://" + cfg.Listen + "/")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: got status %s, want 200", i, resp.Status)
		}
	}

	n := signer.SignCount()
	if n == 0 {
		t.Fatal("no signing operation took place, the handshake did not use the certificate")
	}
	if n >= requests {
		t.Fatalf("%d signing operations for %d requests: connections are not being reused", n, requests)
	}
	t.Logf("%d signing operations for %d requests", n, requests)
}

// TestServeReturns502WhenUpstreamUnreachable covers what a caller sees when
// the third party is unreachable: a 502 rather than a hanging request or a
// panic.
func TestServeReturns502WhenUpstreamUnreachable(t *testing.T) {
	signer := newFakeSigner(t)
	caKey, caCert := newCA(t)
	clientCertDER := newClientCert(t, caKey, caCert, signer.Public())

	cfg := proxyConfig(t, "https://127.0.0.1:1", nil, clientCertDER)
	startProxy(t, cfg, signer)

	resp, err := http.Get("http://" + cfg.Listen + "/")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("got status %s, want 502", resp.Status)
	}
}

func TestServeRejectsInvalidCertificatePEM(t *testing.T) {
	signer := newFakeSigner(t)
	cfg := config.Config{
		KMSKeyID:           kmsfake.KeyID,
		UpstreamHost:       "example.test",
		ClientCertContents: "not pem at all",
		Listen:             freePort(t),
	}
	err := proxy.Serve(t.Context(), cfg, signer)
	if err == nil || !strings.Contains(err.Error(), "no CERTIFICATE blocks") {
		t.Fatalf("got %v, want a client certificate parse error", err)
	}
}

func TestServeRejectsMissingUpstreamCA(t *testing.T) {
	signer := newFakeSigner(t)
	caKey, caCert := newCA(t)
	der := newClientCert(t, caKey, caCert, signer.Public())

	cfg := config.Config{
		KMSKeyID:           kmsfake.KeyID,
		UpstreamHost:       "example.test",
		ClientCertContents: pemString(der),
		UpstreamCAPEM:      filepath.Join(t.TempDir(), "absent.pem"),
		Listen:             freePort(t),
	}
	err := proxy.Serve(t.Context(), cfg, signer)
	if err == nil || !strings.Contains(err.Error(), "read upstream CA") {
		t.Fatalf("got %v, want an upstream CA read error", err)
	}
}

func TestHealthcheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, "ok\n")
	}))
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "http://")
	if err := proxy.Healthcheck(config.Config{Listen: addr}); err != nil {
		t.Fatalf("healthcheck against a live server failed: %v", err)
	}
	if err := proxy.Healthcheck(config.Config{Listen: "127.0.0.1:1"}); err == nil {
		t.Fatal("expected an error when nothing is listening")
	}
}

// --- helpers ---

func newFakeSigner(t testing.TB, opts ...kmsfake.Option) *kms.Signer {
	t.Helper()
	fake := kmsfake.New(t, opts...)
	signer, err := kms.NewSigner(t.Context(), fake, kmsfake.KeyID)
	if err != nil {
		t.Fatalf("NewSigner against the fake endpoint: %v", err)
	}
	return signer
}

// proxyConfig returns a configuration pointing the proxy at the upstream, with
// the client certificate inline and the upstream CA written to a temporary
// file. An empty upstreamCADER leaves the proxy on the system root pool.
func proxyConfig(t testing.TB, upstreamURL string, upstreamCADER, clientCertDER []byte) config.Config {
	t.Helper()
	u, err := url.Parse(upstreamURL)
	if err != nil {
		t.Fatalf("parse %s: %v", upstreamURL, err)
	}
	cfg := config.Config{
		KMSKeyID:           kmsfake.KeyID,
		UpstreamHost:       u.Host,
		ClientCertContents: pemString(clientCertDER),
		Listen:             freePort(t),
	}
	if upstreamCADER != nil {
		caPath := filepath.Join(t.TempDir(), "upstream-ca.pem")
		writePEM(t, caPath, upstreamCADER)
		cfg.UpstreamCAPEM = caPath
	}
	return cfg
}

// startProxy runs Serve in the background, waits until it is healthy and
// registers a clean drain with the test.
func startProxy(t testing.TB, cfg config.Config, signer crypto.Signer) {
	t.Helper()
	// t.Context is cancelled just before cleanups run, which is the drain signal.
	done := make(chan error, 1)
	go func() { done <- proxy.Serve(t.Context(), cfg, signer) }()

	t.Cleanup(func() {
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve returned %v, want a clean drain", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("Serve did not drain within 10s")
		}
	})

	waitForHealthy(t, cfg.Listen)
}

func newMutualTLSServer(t testing.TB, clientCAs *x509.CertPool, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  clientCAs,
		MinVersion: tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func newCA(t testing.TB) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	return key, cert
}

// newClientCert issues a client certificate for a public key whose private
// half lives elsewhere, which is the whole point of the design.
func newClientCert(t testing.TB, caKey *rsa.PrivateKey, caCert *x509.Certificate, pub crypto.PublicKey) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		// Signature only, never encryption: the usage split the key policy
		// relies on.
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, pub, caKey)
	if err != nil {
		t.Fatalf("create client certificate: %v", err)
	}
	return der
}

func pemString(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func writePEM(t testing.TB, path string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, []byte(pemString(der)), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func freePort(t testing.TB) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func waitForHealthy(t testing.TB, addr string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if err := proxy.Healthcheck(config.Config{Listen: addr}); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("proxy did not become healthy")
}
