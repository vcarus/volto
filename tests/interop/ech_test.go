// Encrypted Client Hello against a second volto process that holds an ECH key
// and runs with `[security] require_ech = true`.
//
// The client is Go's crypto/tls under quic-go, an ECH implementation that
// shares nothing with the rustls client the in-tree tests use, nor with the
// server's AWS-LC. With the server's own ECHConfigList it has to complete a
// handshake on the inner ClientHello and carry a CONNECT-UDP session. With a
// list for a key the server does not hold, or with no list, it has to hear
// nothing at all: the server's socket gate drops the handshake before quinn or
// TLS sees a byte of it, so the client's handshake times out rather than
// failing on an answer.
//
// The second server, its key and the two lists are prepared by
// `serve.sh prepare-ech`, which both ./run-local.sh and the CI job call.
package interop

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	masque "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	// Address of the volto server that holds an ECH key and requires ECH.
	envECHAddr = "VOLTO_ECH_ADDR"
	// That server's ECHConfigList, in standard base64, as `volto ech-keygen`
	// prints it.
	envECHConfig = "VOLTO_ECH_CONFIG"
	// The ECHConfigList of a key that server does not hold.
	envECHOtherConfig = "VOLTO_ECH_OTHER_CONFIG"
)

// How long a client that is meant to hear nothing waits for the first packet
// of an answer. Loopback answers in microseconds, so this only decides how
// long proving the silence takes.
const silence = 3 * time.Second

// echEnv returns the ECH server's address and the two lists.
func echEnv(t *testing.T) (string, []byte, []byte) {
	t.Helper()

	addr := os.Getenv(envECHAddr)
	if addr == "" {
		t.Fatalf("%s is not set: this suite tests a server started by CI, it does not start one", envECHAddr)
	}
	decode := func(name string) []byte {
		raw := os.Getenv(name)
		if raw == "" {
			t.Fatalf("%s is not set", name)
		}
		list, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			t.Fatalf("%s is not base64: %v", name, err)
		}
		return list
	}
	return addr, decode(envECHConfig), decode(envECHOtherConfig)
}

// echRoots trusts the server's self-signed certificate, as dialProxy does.
func echRoots(t *testing.T) *x509.CertPool {
	t.Helper()

	pem, err := os.ReadFile(os.Getenv(envCert))
	if err != nil {
		t.Fatalf("reading %s: %v", envCert, err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatalf("%s contains no certificate", envCert)
	}
	return roots
}

// dialECH opens a QUIC connection to addr offering ECH under list, or no ECH
// when list is nil, giving up after idle without an answer.
func dialECH(t *testing.T, ctx context.Context, addr string, list []byte, idle time.Duration) (*quic.Conn, error) {
	t.Helper()

	return quic.DialAddr(ctx, addr, &tls.Config{
		RootCAs:                        echRoots(t),
		ServerName:                     sni(),
		NextProtos:                     []string{http3.NextProtoH3},
		MinVersion:                     tls.VersionTLS13,
		EncryptedClientHelloConfigList: list,
	}, &quic.Config{
		EnableDatagrams:      true,
		InitialPacketSize:    1350,
		HandshakeIdleTimeout: idle,
		MaxIdleTimeout:       idle,
	})
}

// With the server's own list, Go's client completes the handshake with ECH
// accepted and carries a CONNECT-UDP session, under require_ech.
func TestECHWithTheServersListIsAcceptedUnderRequireECH(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	addr, list, _ := echEnv(t)
	conn, err := dialECH(t, ctx, addr, list, 10*time.Second)
	if err != nil {
		t.Fatalf("QUIC handshake with ECH to %s failed: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.CloseWithError(0, "") })
	if !conn.ConnectionState().TLS.ECHAccepted {
		t.Fatal("the handshake completed without ECH accepted")
	}

	client, err := (&masque.Transport{}).NewClientConn(conn)
	if err != nil {
		t.Fatalf("HTTP/3 client connection: %v", err)
	}
	target := startEchoTarget(t, 0xE0)
	session, rsp, err := client.Dial(newRequest(t, ctx, templateFor(t, addr), target))
	if err != nil {
		t.Fatalf("CONNECT-UDP to %s over ECH: %v", target, err)
	}
	defer session.Close()
	if rsp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", rsp.StatusCode)
	}
	payload := []byte("volto-interop-over-ech")
	reply := exchange(t, session, payload)
	if want := append([]byte{0xE0}, payload...); string(reply) != string(want) {
		t.Fatalf("reply = %q, want %q", reply, want)
	}
}

// With a list for another key, or with no list, the client hears nothing: its
// handshake ends in a timeout, not in an error the server sent.
func TestECHWithoutTheServersKeyGetsNoReply(t *testing.T) {
	addr, _, other := echEnv(t)
	for _, tc := range []struct {
		name string
		list []byte
	}{
		{"a list for another key", other},
		{"no list", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			conn, err := dialECH(t, ctx, addr, tc.list, silence)
			if err == nil {
				_ = conn.CloseWithError(0, "")
				t.Fatalf("a handshake completed with %s", tc.name)
			}
			var idle *quic.IdleTimeoutError
			var handshake *quic.HandshakeTimeoutError
			if !errors.As(err, &idle) && !errors.As(err, &handshake) {
				t.Fatalf("with %s the handshake must time out with no answer, got: %v", tc.name, err)
			}
		})
	}
}
