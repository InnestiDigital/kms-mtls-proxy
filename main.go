// Command mtls-proxy originates mutual TLS to a third party using a client
// certificate whose private key never leaves AWS KMS.
//
// See README.md for configuration and usage.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"

	"mtls-proxy/src/config"
	"mtls-proxy/src/kms"
	"mtls-proxy/src/proxy"
)

func main() {
	cmd := "proxy"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}

	if err := run(context.Background(), cmd, config.Load()); err != nil {
		log.Fatal(err)
	}
}

// probeConnections is how many connections `probe` opens, from the second
// argument. Five is enough to see resumption without hammering a third party.
func probeConnections() int {
	if len(os.Args) > 2 {
		if n, err := strconv.Atoi(os.Args[2]); err == nil && n > 0 {
			return n
		}
	}
	return 5
}

// run is the composition root: it validates the configuration, builds the KMS
// signer and hands both to the package implementing the subcommand. Keeping
// the wiring here is what lets src/proxy depend on plain crypto.Signer rather
// than on the AWS SDK.
func run(ctx context.Context, cmd string, cfg config.Config) error {
	switch cmd {
	case "proxy":
		if err := cfg.ValidateProxy(); err != nil {
			return err
		}
		signer, err := kms.NewSignerFromEnv(ctx, cfg.KMSKeyID)
		if err != nil {
			return err
		}
		return proxy.Serve(ctx, cfg, signer)
	case "csr":
		if err := cfg.ValidateCSR(); err != nil {
			return err
		}
		signer, err := kms.NewSignerFromEnv(ctx, cfg.KMSKeyID)
		if err != nil {
			return err
		}
		return proxy.WriteCSR(cfg, signer, os.Stdout)
	case "probe":
		if err := cfg.ValidateProxy(); err != nil {
			return err
		}
		signer, err := kms.NewSignerFromEnv(ctx, cfg.KMSKeyID)
		if err != nil {
			return err
		}
		return proxy.Probe(ctx, cfg, signer, probeConnections(), os.Stdout)
	case "healthcheck":
		return proxy.Healthcheck(cfg)
	default:
		return fmt.Errorf("unknown subcommand %q (proxy|probe|csr|healthcheck)", cmd)
	}
}
