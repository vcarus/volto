// Cross-implementation interop checks: a third-party MASQUE client drives
// CONNECT-UDP sessions through a running volto server.
//
// Every other test in this repository has volto on both ends — the in-process
// HTTP/3 client in `tests/common/mod.rs` is built from the same pinned `h3`
// revision as the server, so the two agree by construction even where both are
// wrong. This suite removes that symmetry: the client is Go's
// github.com/quic-go/masque-go on top of quic-go, an implementation that shares
// no code, no QUIC stack and no reading of the RFCs with volto.
//
// It is driven by the `interop` job of .github/workflows/ci.yml, which starts a
// real volto process and passes its address, SNI and certificate in the
// environment. Nothing here starts or configures the server.
package interop

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	masque "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

const (
	// Address the volto server under test listens on, as host:port.
	envAddr = "VOLTO_ADDR"
	// Name to validate the server certificate against. Defaults to "localhost".
	envSNI = "VOLTO_SNI"
	// PEM file holding the server's self-signed certificate, which is trusted
	// as a root here rather than skipping verification: an interop test that
	// does not verify the certificate would not notice a TLS regression.
	envCert = "VOLTO_CERT"
	// Credentials sent as HTTP Basic on every CONNECT request. Both empty means
	// the server under test has authentication disabled.
	envUser     = "VOLTO_USER"
	envPassword = "VOLTO_PASSWORD"
)

// Bound on any single exchange. Everything here is loopback, so this only ever
// fires when something is actually broken.
const exchangeTimeout = 10 * time.Second

// A port volto's default policy refuses (SMTP), used to drive a refusal.
const deniedPort = 25

// dialProxy opens one QUIC connection to the server under test.
//
// The connection is returned as a masque.ClientConn, on which any number of
// CONNECT-UDP sessions can be opened — that multiplexing is the whole point of
// MASQUE, and the case this suite cares most about.
func dialProxy(t *testing.T, ctx context.Context) *masque.ClientConn {
	t.Helper()

	addr := os.Getenv(envAddr)
	if addr == "" {
		t.Fatalf("%s is not set: this suite tests a server started by CI, it does not start one", envAddr)
	}

	sni := os.Getenv(envSNI)
	if sni == "" {
		sni = "localhost"
	}

	certPath := os.Getenv(envCert)
	if certPath == "" {
		t.Fatalf("%s is not set: the server certificate has to be trusted explicitly", envCert)
	}
	pem, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("reading %s = %q: %v", envCert, certPath, err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatalf("%s = %q contains no certificate", envCert, certPath)
	}

	conn, err := quic.DialAddr(ctx, addr, &tls.Config{
		RootCAs:    roots,
		ServerName: sni,
		NextProtos: []string{http3.NextProtoH3},
	}, &quic.Config{
		EnableDatagrams: true,
		// Large enough that a tunnelled QUIC handshake would still fit; also
		// what masque-go's own Transport defaults to.
		InitialPacketSize: 1350,
	})
	if err != nil {
		t.Fatalf("QUIC handshake with %s failed: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.CloseWithError(0, "") })

	client, err := (&masque.Transport{}).NewClientConn(conn)
	if err != nil {
		t.Fatalf("HTTP/3 client connection: %v", err)
	}
	return client
}

// proxyTemplate builds the RFC 9298 §2 default URI template for the server.
//
// Surge has no way to configure a template either, so this is the same URI
// shape the production client uses.
func proxyTemplate(t *testing.T) *uritemplate.Template {
	t.Helper()

	sni := os.Getenv(envSNI)
	if sni == "" {
		sni = "localhost"
	}
	_, port, err := net.SplitHostPort(os.Getenv(envAddr))
	if err != nil {
		t.Fatalf("%s = %q is not host:port: %v", envAddr, os.Getenv(envAddr), err)
	}

	raw := fmt.Sprintf("https://%s/.well-known/masque/udp/{target_host}/{target_port}/", net.JoinHostPort(sni, port))
	tmpl, err := uritemplate.New(raw)
	if err != nil {
		t.Fatalf("parsing URI template %q: %v", raw, err)
	}
	return tmpl
}

// newRequest builds a CONNECT-UDP request for target, carrying credentials when
// the environment supplies them.
func newRequest(t *testing.T, ctx context.Context, tmpl *uritemplate.Template, target string) *masque.Request {
	t.Helper()

	req, err := masque.NewRequest(ctx, tmpl, target)
	if err != nil {
		t.Fatalf("building a CONNECT-UDP request for %s: %v", target, err)
	}
	if user := os.Getenv(envUser); user != "" {
		// The header Surge was observed to use. Sending it from an unrelated
		// client is what proves the server does not depend on anything
		// Surge-specific about how it is framed.
		req.Header().Set("Proxy-Authorization", basicCredentials(user, os.Getenv(envPassword)))
	}
	return req
}

// basicCredentials renders an HTTP Basic field value (RFC 7617).
func basicCredentials(user, password string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

	plain := []byte(user + ":" + password)
	token := make([]byte, 0, 4*((len(plain)+2)/3))
	for i := 0; i < len(plain); i += 3 {
		chunk := plain[i:min(i+3, len(plain))]
		var bits uint32
		for j := 0; j < 3; j++ {
			bits <<= 8
			if j < len(chunk) {
				bits |= uint32(chunk[j])
			}
		}
		for j := 0; j < len(chunk)+1; j++ {
			token = append(token, alphabet[(bits>>(18-6*j))&0x3f])
		}
		for j := len(chunk) + 1; j < 4; j++ {
			token = append(token, '=')
		}
	}
	return "Basic " + string(token)
}

// startEchoTarget runs a UDP server that echoes each packet back with tag
// prepended, and returns its address.
//
// The tag is what turns "a packet came back" into "the packet came back from
// the target this session was opened for": with several sessions in flight on
// one QUIC connection, a Quarter Stream ID mix-up shows up as a reply carrying
// somebody else's tag rather than as a lost packet.
func startEchoTarget(t *testing.T, tag byte) string {
	t.Helper()

	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("binding a UDP echo target: %v", err)
	}
	t.Cleanup(func() { _ = socket.Close() })

	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := socket.ReadFrom(buf)
			if err != nil {
				return
			}
			reply := append([]byte{tag}, buf[:n]...)
			if _, err := socket.WriteTo(reply, from); err != nil {
				return
			}
		}
	}()

	return socket.LocalAddr().String()
}

// exchange sends payload through a session and returns what came back.
func exchange(t *testing.T, session *masque.Conn, payload []byte) []byte {
	t.Helper()

	if err := session.SetReadDeadline(time.Now().Add(exchangeTimeout)); err != nil {
		t.Fatalf("setting a read deadline: %v", err)
	}
	if _, err := session.WriteTo(payload, nil); err != nil {
		t.Fatalf("sending %d bytes to the target: %v", len(payload), err)
	}

	buf := make([]byte, 65535)
	n, _, err := session.ReadFrom(buf)
	if err != nil {
		t.Fatalf("reading the reply to %q: %v", payload, err)
	}
	return buf[:n]
}

// checkCapsuleResponse asserts the response fields RFC 9297 §3.4 requires of a
// message whose body is a capsule sequence.
func checkCapsuleResponse(t *testing.T, rsp *http.Response) {
	t.Helper()

	if got := rsp.Header.Get("Capsule-Protocol"); got != "?1" {
		t.Errorf("Capsule-Protocol = %q, want %q", got, "?1")
	}
	// RFC 9297 §3.4: a capsule-carrying message must not frame a body length.
	for _, name := range []string{"Content-Length", "Content-Type", "Transfer-Encoding"} {
		if got := rsp.Header.Get(name); got != "" {
			t.Errorf("%s = %q, want it absent", name, got)
		}
	}
}

// One session, several round trips: the baseline that the tunnel carries UDP
// payloads in both directions unmodified.
//
// More than one round trip on purpose. A Context ID or Quarter Stream ID that
// is only right for the first packet is a real failure mode (it is exactly what
// the h3-datagram release bug looked like), and a single-exchange test would
// pass straight through it.
func TestSingleSessionRoundTrips(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	client := dialProxy(t, ctx)
	tmpl := proxyTemplate(t)
	target := startEchoTarget(t, 0xA0)

	session, rsp, err := client.Dial(newRequest(t, ctx, tmpl, target))
	if err != nil {
		t.Fatalf("CONNECT-UDP to %s: %v", target, err)
	}
	defer session.Close()

	if rsp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", rsp.StatusCode)
	}
	checkCapsuleResponse(t, rsp)

	for i := 0; i < 8; i++ {
		payload := []byte(fmt.Sprintf("volto-interop-packet-%d", i))
		reply := exchange(t, session, payload)

		want := append([]byte{0xA0}, payload...)
		if string(reply) != string(want) {
			t.Fatalf("round %d: reply = %q, want %q", i, reply, want)
		}
	}
}

// Three sessions on one QUIC connection, each with its own target.
//
// This is the regression baseline for the Quarter-Stream-ID class of bug: with
// every session multiplexed onto the same connection, misrouting a datagram
// does not lose it, it delivers it to the wrong session — which the per-target
// tag makes visible. All three sessions are written to before any of them is
// read, so the packets really are in flight at the same time.
func TestConcurrentSessionsDoNotCrossTalk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	client := dialProxy(t, ctx)
	tmpl := proxyTemplate(t)

	tags := []byte{0xB1, 0xB2, 0xB3}
	sessions := make([]*masque.Conn, len(tags))
	for i, tag := range tags {
		target := startEchoTarget(t, tag)
		session, rsp, err := client.Dial(newRequest(t, ctx, tmpl, target))
		if err != nil {
			t.Fatalf("session %d: CONNECT-UDP to %s: %v", i, target, err)
		}
		defer session.Close()

		if rsp.StatusCode != http.StatusOK {
			t.Fatalf("session %d: status = %d, want 200", i, rsp.StatusCode)
		}
		checkCapsuleResponse(t, rsp)
		sessions[i] = session
	}

	for round := 0; round < 4; round++ {
		payloads := make([][]byte, len(sessions))
		for i, session := range sessions {
			payloads[i] = []byte(fmt.Sprintf("session-%d-round-%d", i, round))
			if err := session.SetReadDeadline(time.Now().Add(exchangeTimeout)); err != nil {
				t.Fatalf("session %d: setting a read deadline: %v", i, err)
			}
			if _, err := session.WriteTo(payloads[i], nil); err != nil {
				t.Fatalf("session %d: sending: %v", i, err)
			}
		}

		for i, session := range sessions {
			buf := make([]byte, 65535)
			n, _, err := session.ReadFrom(buf)
			if err != nil {
				t.Fatalf("session %d round %d: reading the reply: %v", i, round, err)
			}

			want := append([]byte{tags[i]}, payloads[i]...)
			if string(buf[:n]) != string(want) {
				t.Fatalf("session %d round %d: reply = %q, want %q (a reply tagged for another session means datagrams are misrouted)",
					i, round, buf[:n], want)
			}
		}
	}
}

// A refusal has to be a well-formed HTTP response, not a dropped stream: a
// third-party client must be able to tell "denied" from "broken".
//
// The port is the one volto's default policy refuses, so this also proves the
// policy runs before anything is opened towards the target.
func TestDeniedTargetIsRefusedWithProxyStatus(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	client := dialProxy(t, ctx)
	tmpl := proxyTemplate(t)
	target := net.JoinHostPort("127.0.0.1", fmt.Sprint(deniedPort))

	session, rsp, err := client.Dial(newRequest(t, ctx, tmpl, target))
	if err == nil {
		session.Close()
		t.Fatalf("CONNECT-UDP to %s succeeded, want a refusal", target)
	}
	if rsp == nil {
		t.Fatalf("CONNECT-UDP to %s failed without a response: %v", target, err)
	}
	if rsp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rsp.StatusCode)
	}
	// RFC 9209: the reason is machine-readable, which is what makes a refusal
	// diagnosable from the client side.
	if got := rsp.Header.Get("Proxy-Status"); got != "volto; error=http_request_denied" {
		t.Errorf("Proxy-Status = %q, want %q", got, "volto; error=http_request_denied")
	}
}

// Credentials are checked before the request is routed, so a client that omits
// them is challenged rather than tunnelled.
//
// Skipped when the server under test has authentication disabled.
func TestMissingCredentialsAreChallenged(t *testing.T) {
	if os.Getenv(envUser) == "" {
		t.Skipf("%s is not set: the server under test has authentication disabled", envUser)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	client := dialProxy(t, ctx)
	tmpl := proxyTemplate(t)
	target := startEchoTarget(t, 0xC0)

	// Deliberately built without newRequest, so no credentials are attached.
	req, err := masque.NewRequest(ctx, tmpl, target)
	if err != nil {
		t.Fatalf("building a CONNECT-UDP request: %v", err)
	}

	session, rsp, err := client.Dial(req)
	if err == nil {
		session.Close()
		t.Fatal("an unauthenticated CONNECT-UDP succeeded, want 407")
	}
	if rsp == nil {
		t.Fatalf("CONNECT-UDP failed without a response: %v", err)
	}
	if rsp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", rsp.StatusCode)
	}
	if got := rsp.Header.Get("Proxy-Authenticate"); got != `Basic realm="masque"` {
		t.Errorf("Proxy-Authenticate = %q, want %q", got, `Basic realm="masque"`)
	}
}
