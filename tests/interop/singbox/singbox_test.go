// Cross-implementation interop checks with sing-box, the client the
// documentation tells users to run where Surge is not available.
//
// sing-box 1.15 speaks HTTP/3 CONNECT for TCP and RFC 9298 CONNECT-UDP for UDP
// from its `http` outbound with `"version": 3`. Its HTTP/3 layer is its own,
// on a fork of quic-go, so it shares no code with volto, with masque-go or with
// aioquic. This suite runs it the way a user does: the pinned release built as
// a binary from this module's go.mod, started as a subprocess with a JSON
// configuration, and driven through its SOCKS5 inbounds.
//
// The SOCKS5 client is written here (RFC 1928, CONNECT and UDP ASSOCIATE),
// because the standard library has no SOCKS5 UDP client.
//
// It is driven by the `interop` job of .github/workflows/ci.yml and by
// ../run-local.sh, which start the two volto servers and pass their addresses,
// SNI, credentials and certificate in the same VOLTO_* environment the
// masque-go suite in ../ reads. Nothing here starts or configures volto.
package singbox

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const (
	// Address the plain volto server listens on, as host:port.
	envAddr = "VOLTO_ADDR"
	// The name in the server certificate, sent as the SNI. Defaults to
	// "localhost".
	envSNI = "VOLTO_SNI"
	// PEM file holding the server's self-signed certificate. sing-box is told
	// to trust it by the SHA-256 of its DER encoding, the form
	// script/install-selfsigned.sh prints for a sing-box user.
	envCert = "VOLTO_CERT"
	// Credentials sent as HTTP Basic on every CONNECT request. An empty user
	// means the server under test has authentication disabled.
	envUser     = "VOLTO_USER"
	envPassword = "VOLTO_PASSWORD"
	// Address of the second server, which holds an ECH key and requires ECH.
	envECHAddr = "VOLTO_ECH_ADDR"
	// That server's ECHConfigList in standard base64, as `volto ech-keygen`
	// prints it.
	envECHConfig = "VOLTO_ECH_CONFIG"
)

// The sing-box main package. Its version is the one this module's go.mod
// requires, so Dependabot moves it and go.sum pins every hash.
const singBoxPackage = "github.com/sagernet/sing-box/cmd/sing-box"

// Bound on any single exchange. Everything is on loopback, so this fires only
// when something is broken.
const exchangeTimeout = 10 * time.Second

// How long sing-box has to open its SOCKS5 inbounds after it starts.
const startTimeout = 30 * time.Second

// A port volto's default policy refuses (SMTP), used to drive a refusal.
const deniedPort = 25

// The size of the bulk transfer in each direction.
const transferSize = 4 << 20

// The outbound and inbound tags. One SOCKS5 inbound per outbound, routed by
// inbound, so a test chooses the server by the port it connects to.
const (
	tagPlain     = "volto"
	tagECH       = "volto-ech"
	tagAnonymous = "volto-anonymous"
)

// fixture is the running sing-box process and the SOCKS5 address of each
// inbound it serves.
type fixture struct {
	cmd *exec.Cmd
	log *syncBuffer
	// SOCKS5 address per outbound tag. A tag is absent when the environment
	// does not supply what its outbound needs.
	inbounds map[string]string
	// Why the ECH outbound is absent, when it is.
	echMissing string
	exited     chan struct{}
}

var (
	setupOnce sync.Once
	running   *fixture
	setupErr  error
)

// TestMain stops sing-box after the last test, and prints its log when a test
// failed: the log is the client half of a failure, where volto's log is the
// server half.
func TestMain(m *testing.M) {
	code := m.Run()
	if running != nil {
		_ = running.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-running.exited:
		case <-time.After(5 * time.Second):
			_ = running.cmd.Process.Kill()
			<-running.exited
		}
		if code != 0 {
			fmt.Fprintf(os.Stderr, "--- sing-box log ---\n%s--- end of sing-box log ---\n", running.log.String())
		}
	}
	os.Exit(code)
}

// proxy returns the running sing-box, building and starting it on the first
// call. A missing variable fails the test that needs it, as in the masque-go
// suite.
func proxy(t *testing.T) *fixture {
	t.Helper()
	if os.Getenv(envAddr) == "" {
		t.Fatalf("%s is not set: this suite tests a server started by CI, it does not start one", envAddr)
	}
	if os.Getenv(envCert) == "" {
		t.Fatalf("%s is not set: the server certificate has to be trusted explicitly", envCert)
	}
	setupOnce.Do(func() { running, setupErr = start() })
	if setupErr != nil {
		t.Fatalf("starting sing-box: %v", setupErr)
	}
	return running
}

// inbound returns the SOCKS5 address that routes to the outbound tag.
func (f *fixture) inbound(t *testing.T, tag string) string {
	t.Helper()
	addr, ok := f.inbounds[tag]
	if !ok {
		switch tag {
		case tagECH:
			t.Fatal(f.echMissing)
		default:
			t.Fatalf("no inbound for %s", tag)
		}
	}
	return addr
}

// waitForLog waits until sing-box's log holds text, and fails the test when it
// does not within a few seconds. A refusal reaches the SOCKS5 client before
// sing-box has finished logging it.
func (f *fixture) waitForLog(t *testing.T, text string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(f.log.String(), text) {
		if time.Now().After(deadline) {
			t.Fatalf("sing-box did not log %q", text)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// sni is the name sent to the server and the name in its certificate.
func sni() string {
	if name := os.Getenv(envSNI); name != "" {
		return name
	}
	return "localhost"
}

// certificateSHA256 is the base64 SHA-256 of the DER certificate in VOLTO_CERT,
// the value of sing-box's `certificate_sha256`.
func certificateSHA256() (string, error) {
	path := os.Getenv(envCert)
	text, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading %s = %q: %w", envCert, path, err)
	}
	block, _ := pem.Decode(text)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("%s = %q contains no PEM certificate", envCert, path)
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return "", fmt.Errorf("%s = %q: %w", envCert, path, err)
	}
	sum := sha256.Sum256(block.Bytes)
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}

// The outbound, in the shape script/install-selfsigned.sh prints it, plus the
// tag. sing-box refuses an unknown field, so a renamed field fails the run.
type httpOutbound struct {
	Type                   string     `json:"type"`
	Tag                    string     `json:"tag"`
	Server                 string     `json:"server"`
	ServerPort             int        `json:"server_port"`
	Version                int        `json:"version"`
	DisableVersionFallback bool       `json:"disable_version_fallback"`
	Username               string     `json:"username,omitempty"`
	Password               string     `json:"password,omitempty"`
	TLS                    tlsOptions `json:"tls"`
}

type tlsOptions struct {
	Enabled           bool        `json:"enabled"`
	ServerName        string      `json:"server_name"`
	CertificateSHA256 []string    `json:"certificate_sha256"`
	ECH               *echOptions `json:"ech,omitempty"`
}

type echOptions struct {
	Enabled bool `json:"enabled"`
	// The lines of a PEM block around the ECHConfigList. sing-box joins them
	// with newlines and decodes the result as PEM.
	Config []string `json:"config"`
}

// echPEMLines wraps an ECHConfigList given in base64 into the lines sing-box's
// `ech.config` takes, in the form the installer prints.
func echPEMLines(list string) []string {
	return []string{"-----BEGIN ECH CONFIGS-----", list, "-----END ECH CONFIGS-----"}
}

// newOutbound is the outbound for the volto server at addr.
func newOutbound(tag, addr, user, password, pin string) (httpOutbound, error) {
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return httpOutbound{}, fmt.Errorf("server address %q is not host:port: %w", addr, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return httpOutbound{}, fmt.Errorf("server address %q: %w", addr, err)
	}
	return httpOutbound{
		Type:       "http",
		Tag:        tag,
		Server:     host,
		ServerPort: port,
		Version:    3,
		// volto serves HTTP/3 alone, so a fallback to HTTP/2 or HTTP/1.1 over
		// TCP could only hide a failure of the HTTP/3 path this suite tests.
		DisableVersionFallback: true,
		Username:               user,
		Password:               password,
		TLS: tlsOptions{
			Enabled:           true,
			ServerName:        sni(),
			CertificateSHA256: []string{pin},
		},
	}, nil
}

// freePort returns a loopback port that is free for both TCP and UDP at the
// moment of the call. The SOCKS5 inbound listens on both. The sockets close
// before sing-box binds, so another process could take the port in between;
// sing-box then exits and the wait reports it.
func freePort() (int, error) {
	for range 32 {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return 0, err
		}
		port := listener.Addr().(*net.TCPAddr).Port
		packet, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		_ = listener.Close()
		if err == nil {
			_ = packet.Close()
			return port, nil
		}
	}
	return 0, errors.New("no loopback port free for both TCP and UDP")
}

// start builds sing-box, writes its configuration and starts it, then waits
// until every SOCKS5 inbound accepts.
func start() (*fixture, error) {
	work, err := os.MkdirTemp("", "volto-singbox-")
	if err != nil {
		return nil, err
	}
	binary := filepath.Join(work, "sing-box")
	// `with_quic` is the build tag that includes HTTP/3. The official release
	// builds carry it as well.
	build := exec.Command("go", "build", "-tags", "with_quic", "-o", binary, singBoxPackage)
	if output, err := build.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("go build %s: %v\n%s", singBoxPackage, err, output)
	}

	pin, err := certificateSHA256()
	if err != nil {
		return nil, err
	}
	user, password := os.Getenv(envUser), os.Getenv(envPassword)

	f := &fixture{log: &syncBuffer{}, inbounds: map[string]string{}, exited: make(chan struct{})}
	var outbounds []httpOutbound

	plain, err := newOutbound(tagPlain, os.Getenv(envAddr), user, password, pin)
	if err != nil {
		return nil, err
	}
	outbounds = append(outbounds, plain)

	switch echAddr, echList := os.Getenv(envECHAddr), os.Getenv(envECHConfig); {
	case echAddr == "":
		f.echMissing = fmt.Sprintf("%s is not set: this suite tests a server started by CI, it does not start one", envECHAddr)
	case echList == "":
		f.echMissing = fmt.Sprintf("%s is not set", envECHConfig)
	default:
		if _, err := base64.StdEncoding.DecodeString(echList); err != nil {
			f.echMissing = fmt.Sprintf("%s is not base64: %v", envECHConfig, err)
			break
		}
		ech, err := newOutbound(tagECH, echAddr, user, password, pin)
		if err != nil {
			return nil, err
		}
		ech.TLS.ECH = &echOptions{Enabled: true, Config: echPEMLines(echList)}
		outbounds = append(outbounds, ech)
	}

	// An outbound with no username, for the 407 test. Only when the server
	// has authentication on.
	if user != "" {
		anonymous, err := newOutbound(tagAnonymous, os.Getenv(envAddr), "", "", pin)
		if err != nil {
			return nil, err
		}
		outbounds = append(outbounds, anonymous)
	}

	var inbounds, rules []map[string]any
	for _, outbound := range outbounds {
		port, err := freePort()
		if err != nil {
			return nil, err
		}
		inboundTag := "in-" + outbound.Tag
		inbounds = append(inbounds, map[string]any{
			"type":        "socks",
			"tag":         inboundTag,
			"listen":      "127.0.0.1",
			"listen_port": port,
		})
		rules = append(rules, map[string]any{
			"inbound":  []string{inboundTag},
			"outbound": outbound.Tag,
		})
		f.inbounds[outbound.Tag] = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	}

	config, err := json.MarshalIndent(map[string]any{
		"log":       map[string]any{"level": "debug", "timestamp": true},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"route":     map[string]any{"rules": rules, "final": tagPlain},
	}, "", "  ")
	if err != nil {
		return nil, err
	}
	configPath := filepath.Join(work, "config.json")
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		return nil, err
	}

	f.cmd = exec.Command(binary, "run", "-c", configPath)
	f.cmd.Stdout = f.log
	f.cmd.Stderr = f.log
	if err := f.cmd.Start(); err != nil {
		return nil, err
	}
	go func() {
		_ = f.cmd.Wait()
		close(f.exited)
	}()

	deadline := time.Now().Add(startTimeout)
	for _, addr := range f.inbounds {
		for {
			conn, err := net.DialTimeout("tcp", addr, time.Second)
			if err == nil {
				_ = conn.Close()
				break
			}
			select {
			case <-f.exited:
				return nil, fmt.Errorf("sing-box exited during startup:\n%s", f.log.String())
			default:
			}
			if time.Now().After(deadline) {
				_ = f.cmd.Process.Kill()
				<-f.exited
				return nil, fmt.Errorf("sing-box did not open %s within %s:\n%s", addr, startTimeout, f.log.String())
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	return f, nil
}

// syncBuffer is a bytes.Buffer that sing-box's output and the tests can share.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// --- SOCKS5 (RFC 1928) ------------------------------------------------------

// The reply code of a successful request (RFC 1928 section 6).
const socksSucceeded = 0x00

// socksGreet opens a TCP connection to the SOCKS5 server at proxyAddr and
// negotiates "no authentication required".
func socksGreet(t *testing.T, proxyAddr string) *net.TCPConn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, exchangeTimeout)
	if err != nil {
		t.Fatalf("connecting to the SOCKS5 inbound %s: %v", proxyAddr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(exchangeTimeout))
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("SOCKS5 greeting: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("SOCKS5 method selection: %v", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("SOCKS5 method selection = %x, want 0500", reply)
	}
	return conn.(*net.TCPConn)
}

// socksAddress encodes host and port as a SOCKS5 address: an IPv4 or IPv6
// literal by its family, anything else as a domain name.
func socksAddress(host string, port int) []byte {
	var out []byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			out = append([]byte{0x01}, v4...)
		} else {
			out = append([]byte{0x04}, ip.To16()...)
		}
	} else {
		out = append([]byte{0x03, byte(len(host))}, host...)
	}
	return binary.BigEndian.AppendUint16(out, uint16(port))
}

// readSocksAddress reads a SOCKS5 address from r.
func readSocksAddress(r io.Reader) (net.IP, int, error) {
	kind := make([]byte, 1)
	if _, err := io.ReadFull(r, kind); err != nil {
		return nil, 0, err
	}
	var length int
	switch kind[0] {
	case 0x01:
		length = 4
	case 0x04:
		length = 16
	case 0x03:
		size := make([]byte, 1)
		if _, err := io.ReadFull(r, size); err != nil {
			return nil, 0, err
		}
		length = int(size[0])
	default:
		return nil, 0, fmt.Errorf("unknown SOCKS5 address type %#x", kind[0])
	}
	raw := make([]byte, length+2)
	if _, err := io.ReadFull(r, raw); err != nil {
		return nil, 0, err
	}
	port := int(binary.BigEndian.Uint16(raw[length:]))
	if kind[0] == 0x03 {
		return nil, port, nil
	}
	return net.IP(raw[:length]), port, nil
}

// socksRequest sends request command cmd for host:port on conn and returns the
// reply code and the bound address. An error means the server closed the
// connection, or sent something that is not a reply, before a reply code.
func socksRequest(conn *net.TCPConn, cmd byte, host string, port int) (byte, net.IP, int, error) {
	request := append([]byte{0x05, cmd, 0x00}, socksAddress(host, port)...)
	if _, err := conn.Write(request); err != nil {
		return 0, nil, 0, err
	}
	head := make([]byte, 3)
	if _, err := io.ReadFull(conn, head); err != nil {
		return 0, nil, 0, err
	}
	if head[0] != 0x05 {
		return 0, nil, 0, fmt.Errorf("SOCKS5 reply version %#x", head[0])
	}
	ip, boundPort, err := readSocksAddress(conn)
	return head[1], ip, boundPort, err
}

// dialTCP opens a TCP tunnel to host:port through the SOCKS5 inbound of the
// outbound tag, and fails the test when the request is not granted.
func dialTCP(t *testing.T, tag, host string, port int) *net.TCPConn {
	t.Helper()
	conn := socksGreet(t, proxy(t).inbound(t, tag))
	code, _, _, err := socksRequest(conn, 0x01, host, port)
	if err != nil {
		t.Fatalf("SOCKS5 CONNECT to %s through %s: %v", net.JoinHostPort(host, strconv.Itoa(port)), tag, err)
	}
	if code != socksSucceeded {
		t.Fatalf("SOCKS5 CONNECT to %s through %s: reply %#x, want success", net.JoinHostPort(host, strconv.Itoa(port)), tag, code)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn
}

// association is one SOCKS5 UDP ASSOCIATE: the TCP connection that holds it
// open and the UDP socket that sends through it.
type association struct {
	control *net.TCPConn
	socket  *net.UDPConn
	relay   *net.UDPAddr
}

// associate opens a UDP association through the SOCKS5 inbound of the outbound
// tag.
func associate(t *testing.T, tag string) *association {
	t.Helper()
	inbound := proxy(t).inbound(t, tag)
	control := socksGreet(t, inbound)
	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("binding the client's UDP socket: %v", err)
	}
	t.Cleanup(func() { _ = socket.Close() })
	local := socket.LocalAddr().(*net.UDPAddr)
	code, ip, port, err := socksRequest(control, 0x03, local.IP.String(), local.Port)
	if err != nil {
		t.Fatalf("SOCKS5 UDP ASSOCIATE through %s: %v", tag, err)
	}
	if code != socksSucceeded {
		t.Fatalf("SOCKS5 UDP ASSOCIATE through %s: reply %#x, want success", tag, code)
	}
	if ip == nil || ip.IsUnspecified() {
		// RFC 1928 section 6 leaves the relay address to the server; an
		// unspecified one means the address the client connected to.
		host, _, _ := net.SplitHostPort(inbound)
		ip = net.ParseIP(host)
	}
	_ = control.SetDeadline(time.Time{})
	return &association{control: control, socket: socket, relay: &net.UDPAddr{IP: ip, Port: port}}
}

// send sends payload to target through the association.
func (a *association) send(t *testing.T, target *net.UDPAddr, payload []byte) {
	t.Helper()
	datagram := append([]byte{0x00, 0x00, 0x00}, socksAddress(target.IP.String(), target.Port)...)
	datagram = append(datagram, payload...)
	if _, err := a.socket.WriteToUDP(datagram, a.relay); err != nil {
		t.Fatalf("sending %d bytes to %s: %v", len(payload), target, err)
	}
}

// receive returns the next payload that comes back through the association.
func (a *association) receive(t *testing.T) []byte {
	t.Helper()
	_ = a.socket.SetReadDeadline(time.Now().Add(exchangeTimeout))
	buf := make([]byte, 65535)
	n, err := a.socket.Read(buf)
	if err != nil {
		t.Fatalf("reading a reply through the association: %v", err)
	}
	reader := bytes.NewReader(buf[:n])
	head := make([]byte, 3)
	if _, err := io.ReadFull(reader, head); err != nil || head[2] != 0 {
		t.Fatalf("a SOCKS5 UDP reply without a valid header: %x", buf[:n])
	}
	if _, _, err := readSocksAddress(reader); err != nil {
		t.Fatalf("a SOCKS5 UDP reply with an unreadable address: %v", err)
	}
	payload, _ := io.ReadAll(reader)
	return payload
}

// --- targets ------------------------------------------------------------------

// startUDPEcho runs a UDP server that echoes each packet back with tag
// prepended, and returns its address. The tag is what turns "a packet came
// back" into "the packet came back from the target this session was opened
// for", as in the masque-go suite.
func startUDPEcho(t *testing.T, tag byte) *net.UDPAddr {
	t.Helper()
	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("binding a UDP echo target: %v", err)
	}
	t.Cleanup(func() { _ = socket.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := socket.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if _, err := socket.WriteToUDP(append([]byte{tag}, buf[:n]...), from); err != nil {
				return
			}
		}
	}()
	return socket.LocalAddr().(*net.UDPAddr)
}

// startTCPEcho runs a TCP target that echoes each read back with tag prepended.
// When it reads EOF it writes tag followed by afterEOF and closes. That last
// reply reaches the client only if the client's FIN reached the target as a
// write shutdown and left the target's sending side open.
func startTCPEcho(t *testing.T, tag byte, afterEOF []byte) *net.TCPAddr {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("binding a TCP echo target: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 65536)
				for {
					n, err := conn.Read(buf)
					if n > 0 {
						if _, werr := conn.Write(append([]byte{tag}, buf[:n]...)); werr != nil {
							return
						}
					}
					if errors.Is(err, io.EOF) {
						if len(afterEOF) > 0 {
							_, _ = conn.Write(append([]byte{tag}, afterEOF...))
						}
						return
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return listener.Addr().(*net.TCPAddr)
}

// roundTripTCP writes payload on conn and reads back tag and payload.
func roundTripTCP(t *testing.T, conn *net.TCPConn, tag byte, payload []byte) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(exchangeTimeout))
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("writing %q: %v", payload, err)
	}
	want := append([]byte{tag}, payload...)
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("reading the reply to %q: %v", payload, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("reply = %q, want %q", got, want)
	}
}

// --- tests --------------------------------------------------------------------

// A TCP tunnel by address: several round trips, then the RFC 9114 section 4.4
// half-close, as in the aioquic suite's test_tcp_tunnel_round_trips. The
// client's FIN must reach the target as a write shutdown, the reply the target
// writes after its EOF must still arrive, and the target's close must come back
// as the end of the stream.
func TestTCPTunnelRoundTrips(t *testing.T) {
	afterEOF := []byte("volto-singbox-tcp-after-eof")
	target := startTCPEcho(t, 0xD0, afterEOF)
	conn := dialTCP(t, tagPlain, target.IP.String(), target.Port)

	for i := range 8 {
		roundTripTCP(t, conn, 0xD0, fmt.Appendf(nil, "volto-singbox-tcp-%d", i))
	}

	if err := conn.CloseWrite(); err != nil {
		t.Fatalf("half-closing the tunnel: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(exchangeTimeout))
	rest, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("reading after the FIN: %v", err)
	}
	if want := append([]byte{0xD0}, afterEOF...); !bytes.Equal(rest, want) {
		t.Fatalf("after the FIN: %q, want %q", rest, want)
	}
}

// A TCP tunnel to a target named by a host name: sing-box passes the name to
// the proxy in the CONNECT request, and volto resolves it.
func TestTCPTunnelToATargetByName(t *testing.T) {
	target := startTCPEcho(t, 0xD1, nil)
	conn := dialTCP(t, tagPlain, "localhost", target.Port)
	roundTripTCP(t, conn, 0xD1, []byte("volto-singbox-tcp-by-name"))
}

// Four MiB in each direction at the same time, compared by digest at both
// ends. A tunnel that drops, repeats or reorders a byte under flow control
// fails here and not in the short exchanges above.
func TestTCPTransferInBothDirections(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("binding the transfer target: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	toTarget := make([]byte, transferSize)
	toClient := make([]byte, transferSize)
	_, _ = rand.Read(toTarget)
	_, _ = rand.Read(toClient)

	// What the target received, by digest, or why it could not read it all.
	received := make(chan any, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			received <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Minute))
		go func() { _, _ = conn.Write(toClient) }()
		hash := sha256.New()
		if _, err := io.CopyN(hash, conn, transferSize); err != nil {
			received <- err
			return
		}
		received <- [32]byte(hash.Sum(nil))
		// Held open until the client has read everything and closes.
		_, _ = io.Copy(io.Discard, conn)
	}()

	target := listener.Addr().(*net.TCPAddr)
	conn := dialTCP(t, tagPlain, target.IP.String(), target.Port)
	_ = conn.SetDeadline(time.Now().Add(time.Minute))

	writeErr := make(chan error, 1)
	go func() {
		_, err := conn.Write(toTarget)
		writeErr <- err
	}()
	hash := sha256.New()
	if _, err := io.CopyN(hash, conn, transferSize); err != nil {
		t.Fatalf("reading the target's %d bytes: %v", transferSize, err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("writing %d bytes to the target: %v", transferSize, err)
	}
	if got, want := [32]byte(hash.Sum(nil)), sha256.Sum256(toClient); got != want {
		t.Fatalf("the client received %x, the target sent %x", got, want)
	}
	switch got := (<-received).(type) {
	case error:
		t.Fatalf("the target could not read the client's %d bytes: %v", transferSize, got)
	case [32]byte:
		if want := sha256.Sum256(toTarget); got != want {
			t.Fatalf("the target received %x, the client sent %x", got, want)
		}
	}
}

// One UDP association, several round trips at sizes from 16 to 1200 bytes. More
// than one round trip on purpose, as in the masque-go test of the same name: a
// Context ID or Quarter Stream ID that is right only for the first packet is a
// real failure mode. 1200 bytes plus the tag fits the datagram limit volto
// computes at its default MTU; a larger payload is dropped by that limit, which
// is a property of the server's path and not of this client.
func TestSingleSessionRoundTrips(t *testing.T) {
	target := startUDPEcho(t, 0xA0)
	session := associate(t, tagPlain)

	for i, size := range []int{16, 64, 256, 512, 1000, 1200, 16, 1200} {
		payload := bytes.Repeat([]byte{byte('a' + i)}, size)
		copy(payload, fmt.Sprintf("round-%d-", i))
		session.send(t, target, payload)
		reply := session.receive(t)
		if want := append([]byte{0xA0}, payload...); !bytes.Equal(reply, want) {
			t.Fatalf("round %d, %d bytes: reply of %d bytes, want %d bytes tagged %#x",
				i, size, len(reply), len(want), 0xA0)
		}
	}
}

// Eight UDP associations at once, each to its own target, on the one QUIC
// connection sing-box keeps to the server.
//
// The Quarter-Stream-ID regression baseline, from a fourth implementation:
// with every session multiplexed onto one connection, a misrouted datagram is
// not lost but delivered to the wrong session, which the per-target tag shows.
// Every association is written to before any is read, so the packets are in
// flight together.
func TestConcurrentSessionsDoNotCrossTalk(t *testing.T) {
	const count = 8
	sessions := make([]*association, count)
	targets := make([]*net.UDPAddr, count)
	for i := range count {
		targets[i] = startUDPEcho(t, byte(0xB0+i))
		sessions[i] = associate(t, tagPlain)
	}

	for round := range 4 {
		payloads := make([][]byte, count)
		for i, session := range sessions {
			payloads[i] = fmt.Appendf(nil, "session-%d-round-%d", i, round)
			session.send(t, targets[i], payloads[i])
		}
		for i, session := range sessions {
			reply := session.receive(t)
			if want := append([]byte{byte(0xB0 + i)}, payloads[i]...); !bytes.Equal(reply, want) {
				t.Fatalf("session %d round %d: reply = %q, want %q (a reply tagged for another session means datagrams are misrouted)",
					i, round, reply, want)
			}
		}
	}
}

// A target on a port volto's default policy refuses: the server answers 403,
// and sing-box fails the SOCKS5 request rather than reporting a tunnel.
func TestDeniedTargetIsRefused(t *testing.T) {
	f := proxy(t)
	conn := socksGreet(t, f.inbound(t, tagPlain))
	code, _, _, err := socksRequest(conn, 0x01, "127.0.0.1", deniedPort)
	if err == nil && code == socksSucceeded {
		t.Fatalf("SOCKS5 CONNECT to port %d succeeded, want a refusal", deniedPort)
	}
	// sing-box names the status it was refused with; the SOCKS5 reply cannot.
	f.waitForLog(t, fmt.Sprintf("open connection to 127.0.0.1:%d using outbound/http[%s]: unexpected status: 403 Forbidden", deniedPort, tagPlain))
}

// An outbound without credentials draws the 407 challenge, and sing-box fails
// the SOCKS5 request. Skipped when the server under test has authentication
// disabled.
func TestMissingCredentialsAreChallenged(t *testing.T) {
	if os.Getenv(envUser) == "" {
		t.Skipf("%s is not set: the server under test has authentication disabled", envUser)
	}
	f := proxy(t)
	target := startTCPEcho(t, 0xC0, nil)
	conn := socksGreet(t, f.inbound(t, tagAnonymous))
	code, _, _, err := socksRequest(conn, 0x01, target.IP.String(), target.Port)
	if err == nil && code == socksSucceeded {
		t.Fatal("a CONNECT without credentials succeeded, want 407")
	}
	// sing-box reports a 407 in these words, not by the status line, and the
	// server log shows the 407 itself (log_id 3gmzhaq7, reason "no
	// credentials"), which serve.sh check permits.
	f.waitForLog(t, fmt.Sprintf("open connection to %s using outbound/http[%s]: authentication required", target, tagAnonymous))
}

// With the server's ECHConfigList, sing-box completes the handshake on the inner
// ClientHello and carries a UDP session, against a server with require_ech,
// which answers no client that does not offer ECH under its key.
func TestECHWithTheServersListIsAcceptedUnderRequireECH(t *testing.T) {
	target := startUDPEcho(t, 0xE0)
	session := associate(t, tagECH)
	payload := []byte("volto-singbox-over-ech")
	session.send(t, target, payload)
	if reply, want := session.receive(t), append([]byte{0xE0}, payload...); !bytes.Equal(reply, want) {
		t.Fatalf("reply = %q, want %q", reply, want)
	}
}

// The TCP path through the ECH server.
func TestTCPTunnelOverECH(t *testing.T) {
	target := startTCPEcho(t, 0xE1, nil)
	conn := dialTCP(t, tagECH, target.IP.String(), target.Port)
	roundTripTCP(t, conn, 0xE1, []byte("volto-singbox-tcp-over-ech"))
}
