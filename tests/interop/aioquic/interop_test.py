#!/usr/bin/env python3
"""Cross-implementation interop checks: aioquic drives volto.

The masque-go suite next door already removes the volto-on-both-ends symmetry
for CONNECT-UDP, but it leaves two holes this suite covers:

- masque-go speaks only CONNECT-UDP, so the plain CONNECT (TCP) tunnel has no
  cross-implementation check at all without this suite.
- masque-go owns the whole datagram encoding, so it cannot send a datagram
  with a non-zero Context ID and watch it being ignored; here the Context ID
  prefix is applied by hand, which is exactly what makes that test possible.

aioquic shares no code, no QUIC stack and no reading of the RFCs with either
volto or quic-go, so agreement here is a third independent vote.

Like the Go suite, this one is driven by the `interop` job of ci.yml: a real
volto process is started by CI and its address, SNI, certificate and
credentials arrive in the environment. Nothing here starts a server.
"""

import asyncio
import base64
import os
import sys

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.buffer import Buffer, encode_uint_var
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, DatagramReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration

# Bound on any single exchange. Everything is loopback; this fires only when
# something is actually broken.
EXCHANGE_TIMEOUT = 10.0

# A port volto's default policy refuses (SMTP), used to drive a refusal.
DENIED_PORT = 25


def env_addr():
    addr = os.environ.get("VOLTO_ADDR")
    if not addr:
        sys.exit("VOLTO_ADDR is not set: this suite tests a server started by CI")
    host, _, port = addr.rpartition(":")
    return host, int(port)


def env_sni():
    return os.environ.get("VOLTO_SNI", "localhost")


def basic_credentials():
    """The Proxy-Authorization value for the configured user, or None."""
    user = os.environ.get("VOLTO_USER", "")
    if not user:
        return None
    plain = f"{user}:{os.environ.get('VOLTO_PASSWORD', '')}".encode()
    return b"Basic " + base64.b64encode(plain)


class Refused(Exception):
    """A request drew a non-200 response; carries the response fields."""

    def __init__(self, status, headers):
        super().__init__(f"status {status}")
        self.status = status
        self.headers = headers


class ProxyClient(QuicConnectionProtocol):
    """One QUIC connection to volto, multiplexing any number of tunnels.

    The HTTP/3 layer is aioquic's own; this class only routes its per-stream
    events into queues the tests can await.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._h3 = H3Connection(self._quic, enable_webtransport=True)
        self._events = {}  # stream_id -> asyncio.Queue of H3 events

    def quic_event_received(self, event):
        for h3_event in self._h3.handle_event(event):
            stream_id = getattr(h3_event, "stream_id", None)
            if stream_id is not None:
                self._queue(stream_id).put_nowait(h3_event)

    def _queue(self, stream_id):
        return self._events.setdefault(stream_id, asyncio.Queue())

    async def _next_event(self, stream_id):
        return await asyncio.wait_for(
            self._queue(stream_id).get(), timeout=EXCHANGE_TIMEOUT
        )

    async def _request(self, headers):
        """Sends a CONNECT-shaped request and waits for the response fields.

        Returns the stream id on a 200; raises Refused otherwise.
        """
        stream_id = self._quic.get_next_available_stream_id()
        self._h3.send_headers(stream_id, headers, end_stream=False)
        self.transmit()

        event = await self._next_event(stream_id)
        assert isinstance(event, HeadersReceived), f"expected headers, got {event}"
        fields = dict(event.headers)
        status = int(fields[b":status"])
        if status != 200:
            raise Refused(status, fields)
        return stream_id, fields

    async def connect_tcp(self, authority):
        """Opens a plain CONNECT tunnel (RFC 9114 §4.4) to authority."""
        headers = [(b":method", b"CONNECT"), (b":authority", authority.encode())]
        credentials = basic_credentials()
        if credentials:
            headers.append((b"proxy-authorization", credentials))
        stream_id, _ = await self._request(headers)
        return stream_id

    async def connect_udp(self, host, port, with_credentials=True):
        """Opens a CONNECT-UDP session (RFC 9298) via the well-known template."""
        authority = f"{env_sni()}:{env_addr()[1]}"
        path = f"/.well-known/masque/udp/{host}/{port}/"
        headers = [
            (b":method", b"CONNECT"),
            (b":protocol", b"connect-udp"),
            (b":scheme", b"https"),
            (b":authority", authority.encode()),
            (b":path", path.encode()),
        ]
        credentials = basic_credentials()
        if with_credentials and credentials:
            headers.append((b"proxy-authorization", credentials))
        stream_id, fields = await self._request(headers)

        # RFC 9297 §3.2 and §3.4: the response advertises the capsule protocol
        # and must not frame a body length.
        assert fields.get(b"capsule-protocol") == b"?1", fields
        for name in (b"content-length", b"content-type", b"transfer-encoding"):
            assert name not in fields, f"{name} must be absent, got {fields}"
        return stream_id

    def send_stream(self, stream_id, data, end_stream=False):
        self._h3.send_data(stream_id, data, end_stream=end_stream)
        self.transmit()

    async def recv_stream(self, stream_id):
        """Waits for the next DATA chunk; returns (bytes, stream_ended)."""
        event = await self._next_event(stream_id)
        assert isinstance(event, DataReceived), f"expected data, got {event}"
        return event.data, event.stream_ended

    def send_udp(self, stream_id, payload, context_id=0):
        """Sends one HTTP Datagram with an explicit Context ID prefix.

        The prefix is applied by hand on purpose: RFC 9298 §5's "drop
        silently" rule for unknown Context IDs can only be tested by a client
        allowed to send one.
        """
        self._h3.send_datagram(stream_id, encode_uint_var(context_id) + payload)
        self.transmit()

    async def recv_udp(self, stream_id):
        """Waits for the next datagram on a session; returns its UDP payload."""
        event = await self._next_event(stream_id)
        assert isinstance(event, DatagramReceived), f"expected datagram, got {event}"
        buffer = Buffer(data=event.data)
        context_id = buffer.pull_uint_var()
        assert context_id == 0, f"context id {context_id} on a proxied payload"
        return event.data[buffer.tell() :]


def proxy_connection():
    """An async context manager holding one connection to the server under test."""
    host, port = env_addr()
    cert = os.environ.get("VOLTO_CERT")
    if not cert:
        sys.exit("VOLTO_CERT is not set: the certificate has to be trusted explicitly")

    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=H3_ALPN,
        server_name=env_sni(),
        # QUIC datagram support is a transport parameter; without it the
        # DATAGRAM frames the UDP tests depend on cannot flow at all.
        max_datagram_frame_size=65536,
    )
    configuration.load_verify_locations(cafile=cert)
    return connect(host, port, configuration=configuration, create_protocol=ProxyClient)


async def start_tagged_udp_echo(tag):
    """A UDP target echoing each packet back with tag prepended.

    The tag turns "a packet came back" into "the packet came back from the
    target this session was opened for" — the Quarter-Stream-ID regression
    shape, same as the Go suite.
    """
    loop = asyncio.get_running_loop()

    class Echo(asyncio.DatagramProtocol):
        def connection_made(self, transport):
            self.transport = transport

        def datagram_received(self, data, addr):
            self.transport.sendto(bytes([tag]) + data, addr)

    transport, _ = await loop.create_datagram_endpoint(
        Echo, local_addr=("127.0.0.1", 0)
    )
    host, port = transport.get_extra_info("sockname")[:2]
    return transport, host, port


async def start_tagged_tcp_echo(tag):
    """A TCP target echoing each read back with tag prepended, closing on EOF."""

    async def serve(reader, writer):
        # A tunnel still open when its QUIC connection closes is aborted
        # towards the target, so a reset here is an ordinary ending.
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                writer.write(bytes([tag]) + data)
                await writer.drain()
        except ConnectionError:
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(serve, "127.0.0.1", 0)
    host, port = server.sockets[0].getsockname()[:2]
    return server, host, port


# --- tests -----------------------------------------------------------------


async def test_tcp_tunnel_round_trips():
    """The one path no other independent implementation exercises.

    Several round trips (a tunnel that is only right for the first write is a
    real failure mode), then the RFC 9114 §4.4 half-close: the client's FIN
    must reach the target as a write-shutdown, the target's close must come
    back as end of the response — and neither may tear the other down early.
    """
    server, host, port = await start_tagged_tcp_echo(0xD0)
    try:
        async with proxy_connection() as client:
            stream_id = await client.connect_tcp(f"{host}:{port}")

            for i in range(8):
                payload = f"volto-aioquic-tcp-{i}".encode()
                client.send_stream(stream_id, payload)
                got = b""
                want = bytes([0xD0]) + payload
                while len(got) < len(want):
                    data, ended = await client.recv_stream(stream_id)
                    assert not ended, "the tunnel ended mid-exchange"
                    got += data
                assert got == want, f"round {i}: {got!r} != {want!r}"

            # Half-close: FIN towards the target, EOF back from it.
            client.send_stream(stream_id, b"", end_stream=True)
            while True:
                data, ended = await client.recv_stream(stream_id)
                assert data == b"", f"unexpected data after FIN: {data!r}"
                if ended:
                    break
    finally:
        server.close()


async def test_tcp_tunnels_do_not_cross_talk():
    """TCP mirror of the Go suite's concurrent-sessions test.

    Two tunnels on one connection, both written before either is read, each
    reply checked for its own target's tag: a stream mix-up delivers to the
    wrong tunnel, not to nowhere.
    """
    tags = [0xD1, 0xD2]
    servers = []
    try:
        async with proxy_connection() as client:
            streams = []
            for tag in tags:
                server, host, port = await start_tagged_tcp_echo(tag)
                servers.append(server)
                streams.append(await client.connect_tcp(f"{host}:{port}"))

            for round_number in range(4):
                payloads = []
                for stream_id in streams:
                    payload = f"tunnel-{stream_id}-round-{round_number}".encode()
                    payloads.append(payload)
                    client.send_stream(stream_id, payload)

                for stream_id, payload, tag in zip(streams, payloads, tags):
                    got = b""
                    want = bytes([tag]) + payload
                    while len(got) < len(want):
                        data, ended = await client.recv_stream(stream_id)
                        assert not ended, "a tunnel ended mid-exchange"
                        got += data
                    assert got == want, f"{got!r} != {want!r} (misrouted tunnel data)"
    finally:
        for server in servers:
            server.close()


async def test_udp_session_round_trips():
    """Baseline: the tunnel carries UDP payloads both ways unmodified."""
    transport, host, port = await start_tagged_udp_echo(0xA0)
    try:
        async with proxy_connection() as client:
            stream_id = await client.connect_udp(host, port)
            for i in range(8):
                payload = f"volto-aioquic-udp-{i}".encode()
                client.send_udp(stream_id, payload)
                reply = await client.recv_udp(stream_id)
                want = bytes([0xA0]) + payload
                assert reply == want, f"round {i}: {reply!r} != {want!r}"
    finally:
        transport.close()


async def test_udp_sessions_do_not_cross_talk():
    """Three sessions on one connection: the Quarter-Stream-ID baseline."""
    tags = [0xB1, 0xB2, 0xB3]
    transports = []
    try:
        async with proxy_connection() as client:
            streams = []
            for tag in tags:
                transport, host, port = await start_tagged_udp_echo(tag)
                transports.append(transport)
                streams.append(await client.connect_udp(host, port))

            for round_number in range(4):
                payloads = []
                for stream_id in streams:
                    payload = f"session-{stream_id}-round-{round_number}".encode()
                    payloads.append(payload)
                    client.send_udp(stream_id, payload)

                for stream_id, payload, tag in zip(streams, payloads, tags):
                    reply = await client.recv_udp(stream_id)
                    want = bytes([tag]) + payload
                    assert reply == want, (
                        f"{reply!r} != {want!r} (a reply tagged for another "
                        "session means datagrams are misrouted)"
                    )
    finally:
        for transport in transports:
            transport.close()


async def test_unknown_context_id_is_dropped_silently():
    """RFC 9298 §5: an unknown Context ID is dropped, never answered and
    never fatal — the session must keep working afterwards."""
    transport, host, port = await start_tagged_udp_echo(0xC5)
    try:
        async with proxy_connection() as client:
            stream_id = await client.connect_udp(host, port)

            client.send_udp(stream_id, b"should-never-reach-the-target", context_id=7)
            client.send_udp(stream_id, b"should-arrive")

            reply = await client.recv_udp(stream_id)
            want = bytes([0xC5]) + b"should-arrive"
            assert reply == want, (
                f"{reply!r} != {want!r} (the context-7 datagram must be "
                "dropped, not forwarded or answered)"
            )
    finally:
        transport.close()


async def test_missing_credentials_are_challenged():
    """Credentials are checked before routing; omitting them draws a 407."""
    if not os.environ.get("VOLTO_USER"):
        print("  skipped: VOLTO_USER is not set, authentication is disabled")
        return
    transport, host, port = await start_tagged_udp_echo(0xC0)
    try:
        async with proxy_connection() as client:
            try:
                await client.connect_udp(host, port, with_credentials=False)
            except Refused as refusal:
                assert refusal.status == 407, f"status {refusal.status}, want 407"
                challenge = refusal.headers.get(b"proxy-authenticate")
                assert challenge == b'Basic realm="masque"', challenge
            else:
                raise AssertionError("an unauthenticated CONNECT-UDP succeeded")
    finally:
        transport.close()


async def test_denied_target_is_refused_with_proxy_status():
    """A policy refusal is a well-formed 403 with a machine-readable reason
    (RFC 9209), not a dropped stream."""
    async with proxy_connection() as client:
        try:
            await client.connect_udp("127.0.0.1", DENIED_PORT)
        except Refused as refusal:
            assert refusal.status == 403, f"status {refusal.status}, want 403"
            proxy_status = refusal.headers.get(b"proxy-status")
            assert proxy_status == b"volto; error=http_request_denied", proxy_status
        else:
            raise AssertionError(f"CONNECT-UDP to port {DENIED_PORT} succeeded")


TESTS = [
    test_tcp_tunnel_round_trips,
    test_tcp_tunnels_do_not_cross_talk,
    test_udp_session_round_trips,
    test_udp_sessions_do_not_cross_talk,
    test_unknown_context_id_is_dropped_silently,
    test_missing_credentials_are_challenged,
    test_denied_target_is_refused_with_proxy_status,
]


async def main():
    failures = 0
    for test in TESTS:
        print(f"=== {test.__name__}")
        try:
            await asyncio.wait_for(test(), timeout=60)
        except Exception:  # noqa: BLE001 - a test failure, whatever its type
            import traceback

            traceback.print_exc()
            failures += 1
            print(f"--- FAIL {test.__name__}")
        else:
            print(f"--- PASS {test.__name__}")
    if failures:
        sys.exit(f"{failures} of {len(TESTS)} tests failed")


if __name__ == "__main__":
    asyncio.run(main())
