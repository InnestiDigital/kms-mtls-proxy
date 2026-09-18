package proxy_test

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"mtls-proxy/tests/kmsfake"
)

// The cost of the proxy splits in two, and the split is what matters when
// sizing it: a request on an established connection never touches KMS, while
// a request that has to open one pays for a handshake and a signature.
//
// These benchmarks reproduce both without AWS. The absolute numbers are not
// the point — they are machine-specific, and the fake signs locally — but the
// ratio between them is, and it holds on any machine:
//
//	go test ./tests/proxy -bench . -benchtime 200x -run '^$'
//
// signLatency stands in for the round trip to KMS, which is what a real
// handshake actually waits on. 10ms is the order of magnitude to expect from
// a task running in the same region as the key; measured from a laptop over
// the public internet it was 128ms, almost all of it network.
const signLatency = 10 * time.Millisecond

// BenchmarkUpstreamDirect is the baseline: the same backend, reached without
// the proxy in the path. Subtract it from BenchmarkWarmRequest to get what the
// proxy itself adds.
func BenchmarkUpstreamDirect(b *testing.B) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	b.Cleanup(upstream.Close)

	client := &http.Client{}
	b.ReportAllocs()
	for b.Loop() {
		get(b, client, upstream.URL)
	}
}

// BenchmarkWarmRequest measures the common case: the connection to the third
// party is already open, so the request costs a proxy hop and nothing else.
func BenchmarkWarmRequest(b *testing.B) {
	signer := newFakeSigner(b, kmsfake.WithSignLatency(signLatency))
	caKey, caCert := newCA(b)
	clientCertDER := newClientCert(b, caKey, caCert, signer.Public())

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)
	upstream := newMutualTLSServer(b, caPool, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	caPool.AddCert(upstream.Certificate())

	cfg := proxyConfig(b, upstream.URL, upstream.Certificate().Raw, clientCertDER)
	startProxy(b, cfg, signer)

	client := &http.Client{}
	get(b, client, "http://"+cfg.Listen+"/") // open the upstream connection first

	b.ReportAllocs()
	for b.Loop() {
		get(b, client, "http://"+cfg.Listen+"/")
	}
}

// BenchmarkColdConnection measures the other case: every request opens a new
// connection to the third party, so every request pays for a full handshake
// and one kms:Sign. This is what the latency looks like when connection reuse
// is not working, which is the failure worth alerting on.
func BenchmarkColdConnection(b *testing.B) {
	signer := newFakeSigner(b, kmsfake.WithSignLatency(signLatency))
	caKey, caCert := newCA(b)
	clientCertDER := newClientCert(b, caKey, caCert, signer.Public())

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)
	upstream := newUnresumableServer(b, caPool)
	caPool.AddCert(upstream.Certificate())

	cfg := proxyConfig(b, upstream.URL, upstream.Certificate().Raw, clientCertDER)
	startProxy(b, cfg, signer)

	client := &http.Client{}
	b.ReportAllocs()
	for b.Loop() {
		get(b, client, "http://"+cfg.Listen+"/")
	}
}

// newUnresumableServer is a third party that hangs up after every response and
// refuses to resume sessions, so the proxy has no choice but to handshake
// again, and to sign again, for each request.
func newUnresumableServer(b testing.TB, clientCAs *x509.CertPool) *httptest.Server {
	b.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	srv.TLS = &tls.Config{
		ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientCAs:              clientCAs,
		MinVersion:             tls.VersionTLS12,
		MaxVersion:             tls.VersionTLS12, // TLS 1.3 resumes even without tickets
		SessionTicketsDisabled: true,
	}
	srv.Config.SetKeepAlivesEnabled(false)
	srv.StartTLS()
	b.Cleanup(srv.Close)
	return srv
}

func get(b *testing.B, client *http.Client, url string) {
	b.Helper()
	resp, err := client.Get(url)
	if err != nil {
		b.Fatalf("GET %s: %v", url, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b.Fatalf("GET %s: got status %s, want 200", url, resp.Status)
	}
}
