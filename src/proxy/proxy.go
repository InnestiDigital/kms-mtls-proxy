// Package proxy accepts plain HTTP and forwards it to a third party over
// mutual TLS, authenticating with a certificate whose private key is held in
// AWS KMS.
package proxy

import (
	"context"
	"crypto"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os/signal"
	"syscall"
	"time"

	"mtls-proxy/src/config"
)

const (
	idleConnTimeout   = 90 * time.Second
	readHeaderTimeout = 10 * time.Second
	maxIdleConns      = 16
	sessionCacheSize  = 64
	// ECS sends SIGTERM and waits for StopTimeout (30s by default) before
	// SIGKILL. Finish in-flight requests comfortably inside that.
	shutdownGrace = 20 * time.Second
	// The certificate and the key are replaced together, so an expiry caught
	// late is an outage plus a key ceremony, not just a renewal.
	expiryWarningWindow = 30 * 24 * time.Hour
)

// Serve runs until the context is cancelled or a termination signal arrives,
// then drains. The configuration must already have passed ValidateProxy, and
// the signer is the private half of the client certificate.
func Serve(ctx context.Context, cfg config.Config, signer crypto.Signer) error {
	cert, err := clientCertificate(cfg, signer)
	if err != nil {
		return err
	}

	tlsConf, err := clientTLSConfig(cert, cfg.UpstreamCAPEM)
	if err != nil {
		return err
	}

	target, err := url.Parse("https://" + cfg.UpstreamHost)
	if err != nil {
		return fmt.Errorf("upstream host: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok\n")
	})
	// The signature count is the one number worth alerting on, so it is
	// scrapeable rather than only greppable in the logs. Prometheus text
	// format, hand-written: one counter does not justify a dependency.
	if counter, ok := signer.(signCounter); ok {
		mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; version=0.0.4")
			fmt.Fprintf(w, "# HELP mtls_proxy_kms_sign_total Number of kms:Sign calls made, one per TLS handshake.\n"+
				"# TYPE mtls_proxy_kms_sign_total counter\n"+
				"mtls_proxy_kms_sign_total %d\n", counter.SignCount())
		})
	}
	mux.Handle("/", newReverseProxy(target, tlsConf))

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	log.Printf("proxying %s -> %s as %s (key %s)",
		cfg.Listen, target, cert.Leaf.Subject.CommonName, cfg.KMSKeyID)
	if notAfter := cert.Leaf.NotAfter; time.Until(notAfter) < expiryWarningWindow {
		log.Printf("WARNING: client certificate expires %s", notAfter.Format(time.RFC3339))
	}

	return serveUntilSignal(ctx, srv)
}

// serveUntilSignal runs the server until SIGTERM or SIGINT, then drains.
// Without this, an ECS deployment severs in-flight third-party requests.
func serveUntilSignal(ctx context.Context, srv *http.Server) error {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	log.Printf("signal received, draining for up to %s", shutdownGrace)

	// WithoutCancel, not ctx: ctx is already cancelled here, so draining with it
	// would give Shutdown an expired deadline and sever in-flight requests.
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	log.Print("drained")
	return nil
}

// newReverseProxy forwards to the third party over the supplied client TLS
// configuration.
func newReverseProxy(target *url.URL, tlsConf *tls.Config) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.Host = target.Host
			r.SetXForwarded()
		},
		Transport: &http.Transport{
			TLSClientConfig:     tlsConf,
			MaxIdleConnsPerHost: maxIdleConns,
			IdleConnTimeout:     idleConnTimeout,
			ForceAttemptHTTP2:   true,
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			log.Printf("upstream error: %v", err)
			http.Error(w, "upstream error", http.StatusBadGateway)
		},
	}
}
