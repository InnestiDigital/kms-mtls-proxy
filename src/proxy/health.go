package proxy

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"mtls-proxy/src/config"
)

// Healthcheck probes the local /healthz endpoint. It exists so the image's
// HEALTHCHECK needs no curl or wget, and so it works as an unprivileged user.
func Healthcheck(cfg config.Config) error {
	addr := cfg.Listen
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + addr + "/healthz")
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz returned %s", resp.Status)
	}
	return nil
}
