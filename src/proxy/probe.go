package proxy

import (
	"context"
	"crypto"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"mtls-proxy/src/config"
)

// ticketWait bounds how long a probe waits for a session ticket after the
// handshake. The ticket follows the handshake immediately, so this is a margin
// for a slow link rather than a real wait, and it is only paid on connections
// that did not already resume.
const ticketWait = 750 * time.Millisecond

// signCounter is implemented by the KMS signer. Probe and the metrics endpoint
// use it opportunistically, so neither depends on the concrete type.
type signCounter interface {
	SignCount() uint64
}

// Probe opens connections to the third party and reports how many of them
// resumed a session rather than signing a fresh handshake.
//
// This exists because the whole cost model rests on resumption: one signature
// per connection is only true if the third party issues session tickets. If it
// does not, every connection costs a kms:Sign and a full handshake, and both
// latency and cost scale with traffic. That is a property of their server, not
// of this code, so it cannot be assumed. Run this before deploying.
//
// It returns an error when nothing resumed, so it can gate a deployment.
func Probe(ctx context.Context, cfg config.Config, signer crypto.Signer, connections int, out io.Writer) error {
	cert, err := clientCertificate(cfg, signer)
	if err != nil {
		return err
	}
	tlsConf, err := clientTLSConfig(cert, cfg.UpstreamCAPEM)
	if err != nil {
		return err
	}

	addr := cfg.UpstreamHost
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "443")
	}

	fmt.Fprintf(out, "probing %s with %d connections\n", addr, connections)

	// One dialer for all of them, so they share the session cache exactly as
	// the running proxy would.
	dialer := &tls.Dialer{Config: tlsConf}
	resumed := 0
	for i := 1; i <= connections; i++ {
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return fmt.Errorf("connection %d: %w", i, err)
		}
		tlsConn := conn.(*tls.Conn)
		state := tlsConn.ConnectionState()
		if state.DidResume {
			resumed++
		} else {
			// Under TLS 1.3 the session ticket arrives after the handshake and
			// is only processed while reading, so a connection that is opened
			// and closed caches nothing and every probe would report no
			// resumption. Read with a deadline rather than sending a request:
			// a probe must not have side effects on the third party.
			_ = tlsConn.SetReadDeadline(time.Now().Add(ticketWait))
			var discard [1]byte
			_, _ = tlsConn.Read(discard[:])
		}
		fmt.Fprintf(out, "  connection %d: %s, %s, resumed=%t\n",
			i, tlsVersion(state.Version), tls.CipherSuiteName(state.CipherSuite), state.DidResume)
		_ = conn.Close()
	}

	if counter, ok := signer.(signCounter); ok {
		fmt.Fprintf(out, "kms:Sign calls: %d for %d connections\n", counter.SignCount(), connections)
	}

	switch {
	case connections < 2:
		fmt.Fprintf(out, "run with 2 or more connections to observe resumption\n")
		return nil
	case resumed == 0:
		return fmt.Errorf("no connection resumed: this third party appears not to issue session tickets, "+
			"so every connection will cost a kms:Sign and a full handshake (%d/%d resumed)", resumed, connections)
	default:
		fmt.Fprintf(out, "%d/%d connections resumed: session resumption is working\n", resumed, connections)
		return nil
	}
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	}
	return "TLS " + strings.TrimPrefix(fmt.Sprintf("%#x", v), "0x")
}
