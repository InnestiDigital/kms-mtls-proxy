package proxy_test

import (
	"crypto/x509"
	"io"
	"net/http"
	"strings"
	"testing"

	"mtls-proxy/src/proxy"
)

// TestProbeReportsResumption covers the case the probe exists to confirm: a
// third party that issues session tickets, so connections after the first cost
// no signature.
func TestProbeReportsResumption(t *testing.T) {
	signer := newFakeSigner(t)
	caKey, caCert := newCA(t)
	clientCertDER := newClientCert(t, caKey, caCert, signer.Public())

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)
	upstream := newMutualTLSServer(t, caPool, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	caPool.AddCert(upstream.Certificate())

	cfg := proxyConfig(t, upstream.URL, upstream.Certificate().Raw, clientCertDER)

	var out strings.Builder
	if err := proxy.Probe(t.Context(), cfg, signer, 4, &out); err != nil {
		t.Fatalf("Probe against a resuming server: %v", err)
	}
	if got := out.String(); !strings.Contains(got, "resumption is working") {
		t.Fatalf("got %q, want a report that resumption is working", got)
	}
	if n := signer.SignCount(); n != 1 {
		t.Fatalf("got %d signing operations for 4 connections, want 1", n)
	}
}

// TestMetricsExposesSignCount covers the signal the README tells operators to
// alert on. Logs carry it too, but an alert should not require log parsing.
func TestMetricsExposesSignCount(t *testing.T) {
	signer := newFakeSigner(t)
	caKey, caCert := newCA(t)
	clientCertDER := newClientCert(t, caKey, caCert, signer.Public())

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)
	upstream := newMutualTLSServer(t, caPool, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	caPool.AddCert(upstream.Certificate())

	cfg := proxyConfig(t, upstream.URL, upstream.Certificate().Raw, clientCertDER)
	startProxy(t, cfg, signer)

	resp, err := http.Get("http://" + cfg.Listen + "/")
	if err != nil {
		t.Fatalf("request through proxy: %v", err)
	}
	_ = resp.Body.Close()

	metrics, err := http.Get("http://" + cfg.Listen + "/metrics")
	if err != nil {
		t.Fatalf("scrape /metrics: %v", err)
	}
	defer func() { _ = metrics.Body.Close() }()
	body, _ := io.ReadAll(metrics.Body)

	want := "mtls_proxy_kms_sign_total 1"
	if !strings.Contains(string(body), want) {
		t.Fatalf("got %q, want it to contain %q", body, want)
	}
}

// TestProbeFailsWithoutResumption is the reason the probe returns an error
// rather than only printing: a third party that never resumes makes every
// connection cost a signature, and that should stop a deployment.
func TestProbeFailsWithoutResumption(t *testing.T) {
	signer := newFakeSigner(t)
	caKey, caCert := newCA(t)
	clientCertDER := newClientCert(t, caKey, caCert, signer.Public())

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)
	upstream := newUnresumableServer(t, caPool)
	caPool.AddCert(upstream.Certificate())

	cfg := proxyConfig(t, upstream.URL, upstream.Certificate().Raw, clientCertDER)

	var out strings.Builder
	err := proxy.Probe(t.Context(), cfg, signer, 4, &out)
	if err == nil {
		t.Fatal("Probe accepted a server that never resumes, want an error")
	}
	if !strings.Contains(err.Error(), "session tickets") {
		t.Fatalf("got %v, want an error naming session tickets", err)
	}
	if n := signer.SignCount(); n != 4 {
		t.Fatalf("got %d signing operations for 4 connections, want 4", n)
	}
}
