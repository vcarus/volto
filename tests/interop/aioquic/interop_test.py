#!/usr/bin/env python3
"""Cross-implementation interop checks: aioquic drives volto.

The masque-go suite next door already removes the volto-on-both-ends symmetry
for CONNECT-UDP, but it leaves three holes this suite covers:

- masque-go speaks only CONNECT-UDP, so the plain CONNECT (TCP) tunnel has no
  cross-implementation check at all without this suite.
- masque-go owns the whole datagram encoding, so it cannot send a datagram
  with a non-zero Context ID and watch it being ignored; here the Context ID
  prefix is applied by hand, which is exactly what makes that test possible.
- masque-go sends datagrams only on a session its Dial has already opened, so
  it cannot send one before the request it belongs to; aioquic can name a
  stream that does not exist yet, by writing the QUIC DATAGRAM frame itself.

aioquic shares no code, no QUIC stack and no reading of the RFCs with either
volto or quic-go, so agreement here is a third independent vote.

Like the Go suite, this one is driven by the `interop` job of ci.yml: a real
volto process is started by CI and its address, SNI, certificate and
credentials arrive in the environment. Nothing here starts a server.
"""

import asyncio
import base64
import inspect
import os
import sys

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.buffer import Buffer, encode_uint_var
from aioquic.h3.connection import H3_ALPN, ErrorCode, H3Connection, Setting
from aioquic.h3.events import (
    DataReceived,
    DatagramReceived,
    HeadersReceived,
    ResetReceived,
    StopReceived,
)
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


def tcp_request(authority):
    """The fields of a plain CONNECT request (RFC 9114 §4.4) to authority."""
    headers = [(b":method", b"CONNECT"), (b":authority", authority.encode())]
    credentials = basic_credentials()
    if credentials:
        headers.append((b"proxy-authorization", credentials))
    return headers


def udp_request(host, port, credential_header=b"proxy-authorization"):
    """The fields of a CONNECT-UDP request (RFC 9298) for host and port.

    host goes into the well-known template as given, so a caller may
    percent-encode it. The credentials go in credential_header, or nowhere
    when it is None.
    """
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
    if credential_header and credentials:
        headers.append((credential_header, credentials))
    return headers


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

    async def settings(self):
        """Waits for the server's SETTINGS; returns them as a dict."""
        for _ in range(int(EXCHANGE_TIMEOUT / 0.01)):
            if self._h3.received_settings is not None:
                return self._h3.received_settings
            await asyncio.sleep(0.01)
        raise AssertionError("no SETTINGS from the server")

    def send_request(self, headers):
        """Sends request headers on the next request stream; returns its id."""
        stream_id = self._quic.get_next_available_stream_id()
        self._h3.send_headers(stream_id, headers, end_stream=False)
        self.transmit()
        return stream_id

    async def response(self, stream_id):
        """Waits for the response on a request stream.

        Returns (fields, stopped, ended): the response fields, the code of a
        STOP_SENDING that aioquic reported before them or None, and whether
        the response ended the stream.
        """
        event = await self._next_event(stream_id)
        stopped = None
        if isinstance(event, StopReceived):
            stopped = event.error_code
            event = await self._next_event(stream_id)
        assert isinstance(event, HeadersReceived), f"expected headers, got {event}"
        return dict(event.headers), stopped, event.stream_ended

    async def reset_code(self, stream_id):
        """Waits for the server to reset a request stream; returns the code.

        A STOP_SENDING may come first. A response or data instead fails.
        """
        while True:
            event = await self._next_event(stream_id)
            if isinstance(event, ResetReceived):
                return event.error_code
            assert isinstance(event, StopReceived), f"expected a reset, got {event}"

    async def _request(self, headers):
        """Sends a CONNECT-shaped request and waits for the response fields.

        Returns the stream id on a 200; raises Refused otherwise.
        """
        stream_id = self.send_request(headers)
        fields, stopped, _ = await self.response(stream_id)
        # RFC 9114 §4.1: "When the server does not need to receive the
        # remainder of the request, it MAY abort reading the request stream,
        # send a complete response, and cleanly close the sending part of the
        # stream. The error code H3_NO_ERROR SHOULD be used when requesting
        # that the client stop sending on the request stream." volto does
        # this with a refusal, and aioquic can report the STOP_SENDING before
        # the response it belongs to.
        assert stopped in (None, ErrorCode.H3_NO_ERROR), stopped
        status = int(fields[b":status"])
        if status != 200:
            raise Refused(status, fields)
        return stream_id, fields

    async def connect_tcp(self, authority):
        """Opens a plain CONNECT tunnel (RFC 9114 §4.4) to authority."""
        stream_id, _ = await self._request(tcp_request(authority))
        return stream_id

    async def connect_udp(self, host, port, credential_header=b"proxy-authorization"):
        """Opens a CONNECT-UDP session (RFC 9298) via the well-known template.

        The credentials go in credential_header, or nowhere when it is None.
        """
        stream_id, fields = await self._request(udp_request(host, port, credential_header))

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

    def send_udp_before_request(self, stream_id, payload):
        """Sends one HTTP Datagram for a request stream not yet opened.

        aioquic's HTTP/3 layer refuses a datagram for a stream that has sent
        no HEADERS, so this writes the QUIC DATAGRAM frame itself: the
        Quarter Stream ID, then Context ID 0, then the payload (RFC 9297
        §2.1, RFC 9298 §5).
        """
        quarter_stream_id = encode_uint_var(stream_id // 4)
        self._quic.send_datagram_frame(quarter_stream_id + encode_uint_var(0) + payload)
        self.transmit()

    async def recv_udp(self, stream_id):
        """Waits for the next datagram on a session; returns its UDP payload."""
        event = await self._next_event(stream_id)
        assert isinstance(event, DatagramReceived), f"expected datagram, got {event}"
        buffer = Buffer(data=event.data)
        context_id = buffer.pull_uint_var()
        assert context_id == 0, f"context id {context_id} on a proxied payload"
        return event.data[buffer.tell() :]

    async def datagrams_after(self, stream_id, wait=0.3):
        """Waits, then takes the datagrams queued for a session meanwhile.

        For a check that something did not arrive: wait bounds how long it
        could still take on loopback.
        """
        await asyncio.sleep(wait)
        queued = self._queue(stream_id)
        datagrams = []
        while not queued.empty():
            event = queued.get_nowait()
            if isinstance(event, DatagramReceived):
                datagrams.append(event.data)
        return datagrams


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


async def start_tagged_tcp_echo(tag, after_eof=b""):
    """A TCP target echoing each read back with tag prepended, closing on EOF.

    With after_eof set, the target writes tag followed by after_eof once it
    has read EOF, and only then closes. That reply can reach the client only
    if the client's FIN reached the target as a write-shutdown and left the
    target's own sending side open.
    """

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
            if after_eof:
                writer.write(bytes([tag]) + after_eof)
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
    must reach the target as a write-shutdown, the reply the target writes
    after its EOF must still arrive, and the target's close must come back as
    end of the response. Neither may tear the other down early.
    """
    after_eof = b"volto-aioquic-tcp-after-eof"
    server, host, port = await start_tagged_tcp_echo(0xD0, after_eof)
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

            # Half-close: FIN towards the target, which answers its EOF with
            # one reply and then closes. The reply has to arrive, and then
            # the end of the response.
            client.send_stream(stream_id, b"", end_stream=True)
            got = b""
            while True:
                data, ended = await client.recv_stream(stream_id)
                got += data
                if ended:
                    break
            want = bytes([0xD0]) + after_eof
            assert got == want, f"after the FIN: {got!r} != {want!r}"
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


async def test_udp_sessions_past_quarter_stream_id_64_do_not_cross_talk():
    """The baseline's check on Quarter Stream IDs that take two bytes.

    RFC 9000 §16 encodes a variable-length integer of 64 or more in two bytes,
    so a session on stream 256 or later carries a two-byte Quarter Stream ID,
    as most sessions on a busy production connection do. Sixty-four refused
    requests use up streams 0 to 252 first. Each refusal ends its stream, so
    the connection never holds more than one tunnel while they run.
    """
    tags = [0xF1, 0xF2, 0xF3]
    transports = []
    try:
        async with proxy_connection() as client:
            for _ in range(64):
                try:
                    await client.connect_udp("127.0.0.1", DENIED_PORT)
                except Refused as refusal:
                    assert refusal.status == 403, f"status {refusal.status}, want 403"
                else:
                    raise AssertionError(f"CONNECT-UDP to port {DENIED_PORT} succeeded")

            streams = []
            for tag in tags:
                transport, host, port = await start_tagged_udp_echo(tag)
                transports.append(transport)
                stream_id = await client.connect_udp(host, port)
                assert stream_id // 4 >= 64, f"stream {stream_id} has a one-byte quarter"
                streams.append(stream_id)

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
            # The context-7 payload is not merely ordered after the other one:
            # nothing else comes back at all.
            later = await client.datagrams_after(stream_id)
            assert not later, f"the context-7 datagram was answered: {later!r}"
    finally:
        transport.close()


async def test_datagram_before_its_request_is_delivered():
    """RFC 9297 §2.1 lets the receiver hold a datagram whose request stream
    does not exist yet, and volto does: a datagram sent before the request's
    HEADERS reaches the target once the session is open, sent once and never
    repeated."""
    transport, host, port = await start_tagged_udp_echo(0xE1)
    try:
        async with proxy_connection() as client:
            # RFC 9297 §2.1.1: no DATAGRAM frame before the server's SETTINGS
            # have arrived with SETTINGS_H3_DATAGRAM = 1.
            await client.settings()

            # The stream the next request will open, named before it exists.
            stream_id = client._quic.get_next_available_stream_id()
            client.send_udp_before_request(stream_id, b"sent-before-the-request")
            # What puts the datagram before the stream: a bounded wait, since
            # the client cannot see when the server routes it. Well inside
            # volto's hold time of 333 ms.
            await asyncio.sleep(0.05)

            opened = await client.connect_udp(host, port)
            assert opened == stream_id, f"the request opened {opened}, not {stream_id}"

            reply = await client.recv_udp(stream_id)
            want = bytes([0xE1]) + b"sent-before-the-request"
            assert reply == want, (
                f"{reply!r} != {want!r} (a datagram sent before its request must "
                "be held until the session is open, then forwarded)"
            )

            # Delivered once: no second copy arrives for the session.
            repeats = await client.datagrams_after(stream_id)
            assert not repeats, f"the held datagram was delivered again: {repeats!r}"
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
                await client.connect_udp(host, port, credential_header=None)
            except Refused as refusal:
                assert refusal.status == 407, f"status {refusal.status}, want 407"
                challenge = refusal.headers.get(b"proxy-authenticate")
                assert challenge == b'Basic realm="proxy"', challenge
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


async def udp_round_trip(client, stream_id, tag, payload):
    """Sends payload on a session and asserts its tagged echo comes back."""
    client.send_udp(stream_id, payload)
    reply = await client.recv_udp(stream_id)
    want = bytes([tag]) + payload
    assert reply == want, f"{reply!r} != {want!r}"


async def test_datagram_capsule_without_a_context_id_is_a_malformed_message():
    """A DATAGRAM capsule on the request stream carries a payload, and one
    whose value ends before its Context ID resets the stream with
    H3_MESSAGE_ERROR: RFC 9297 §3.3 treats such a capsule "as it if were a
    malformed or incomplete message", which RFC 9114 §4.1.2 answers with that
    code."""
    transport, host, port = await start_tagged_udp_echo(0xC7)
    try:
        async with proxy_connection() as client:
            stream_id = await client.connect_udp(host, port)

            # RFC 9297 §3.5: type 0x00, length, then Context ID 0 and the
            # payload. The reply comes back as a QUIC datagram.
            value = encode_uint_var(0) + b"in-a-capsule"
            client.send_stream(stream_id, encode_uint_var(0) + encode_uint_var(len(value)) + value)
            reply = await client.recv_udp(stream_id)
            assert reply == bytes([0xC7]) + b"in-a-capsule", reply

            # Type 0x00 with a length of 0: no room for the Context ID.
            client.send_stream(stream_id, encode_uint_var(0) + encode_uint_var(0))
            code = await client.reset_code(stream_id)
            assert code == ErrorCode.H3_MESSAGE_ERROR, f"reset with {code:#x}"
    finally:
        transport.close()


async def test_a_percent_sign_without_two_hex_digits_is_refused_on_its_stream():
    """RFC 3986 §2.1 writes a percent-encoded octet as "%" HEXDIG HEXDIG. A
    request whose path holds a "%" without two hex digits after it is
    malformed, and its stream is reset with H3_MESSAGE_ERROR (RFC 9114
    §4.1.2). The connection carries on: a session whose host is a complete
    escape, 127.0.0.%31, is decoded to 127.0.0.1 and works."""
    transport, host, port = await start_tagged_udp_echo(0xC8)
    try:
        async with proxy_connection() as client:
            stream_id = client.send_request(udp_request("a%zz", port))
            code = await client.reset_code(stream_id)
            assert code == ErrorCode.H3_MESSAGE_ERROR, f"reset with {code:#x}"

            assert host == "127.0.0.1", host
            stream_id = await client.connect_udp("127.0.0.%31", port)
            await udp_round_trip(client, stream_id, 0xC8, b"after-the-refusal")
    finally:
        transport.close()


async def test_a_blackholed_target_is_accepted_then_closed():
    """D49: a target whose every address is the unspecified one draws a 200
    and the end of the stream, with no data, as a target that accepts and
    hangs up at once would. This is the answer Surge sees for a name its DNS
    blackholed."""
    async with proxy_connection() as client:
        stream_id = client.send_request(tcp_request("0.0.0.0:9"))
        fields, stopped, ended = await client.response(stream_id)
        assert fields[b":status"] == b"200", fields
        assert b"proxy-status" not in fields, fields
        assert stopped in (None, ErrorCode.H3_NO_ERROR), stopped
        while not ended:
            event = await client._next_event(stream_id)
            if isinstance(event, StopReceived):
                assert event.error_code == ErrorCode.H3_NO_ERROR, event
                continue
            assert isinstance(event, DataReceived) and not event.data, (
                f"expected the end of the stream and nothing else, got {event}"
            )
            ended = event.stream_ended


async def test_denied_tcp_target_is_refused_with_proxy_status():
    """The CONNECT (TCP) mirror of the CONNECT-UDP refusal: 403 with the
    same Proxy-Status."""
    async with proxy_connection() as client:
        try:
            await client.connect_tcp(f"127.0.0.1:{DENIED_PORT}")
        except Refused as refusal:
            assert refusal.status == 403, f"status {refusal.status}, want 403"
            proxy_status = refusal.headers.get(b"proxy-status")
            assert proxy_status == b"volto; error=http_request_denied", proxy_status
        else:
            raise AssertionError(f"CONNECT to port {DENIED_PORT} succeeded")


async def test_credentials_in_authorization_pass_after_a_challenge():
    """The server reads HTTP Basic from Authorization as well as from
    Proxy-Authorization, and a 407 costs only its own request: the next one
    on the same connection, with credentials, opens a session."""
    if not os.environ.get("VOLTO_USER"):
        print("  skipped: VOLTO_USER is not set, authentication is disabled")
        return
    transport, host, port = await start_tagged_udp_echo(0xC9)
    try:
        async with proxy_connection() as client:
            try:
                await client.connect_udp(host, port, credential_header=None)
            except Refused as refusal:
                assert refusal.status == 407, f"status {refusal.status}, want 407"
            else:
                raise AssertionError("an unauthenticated CONNECT-UDP succeeded")

            stream_id = await client.connect_udp(host, port, credential_header=b"authorization")
            await udp_round_trip(client, stream_id, 0xC9, b"authorized")
    finally:
        transport.close()


async def test_a_session_the_client_resets_leaves_the_connection_working():
    """A client that resets a CONNECT-UDP stream (RFC 9000 §19.4) and stops
    reading it ends that session only: a new session on the same connection
    carries datagrams."""
    transport, host, port = await start_tagged_udp_echo(0xCA)
    try:
        async with proxy_connection() as client:
            first = await client.connect_udp(host, port)
            await udp_round_trip(client, first, 0xCA, b"before-the-reset")
            client._quic.reset_stream(first, ErrorCode.H3_REQUEST_CANCELLED)
            client._quic.stop_stream(first, ErrorCode.H3_REQUEST_CANCELLED)
            client.transmit()

            second = await client.connect_udp(host, port)
            await udp_round_trip(client, second, 0xCA, b"after-the-reset")
    finally:
        transport.close()


async def test_unknown_stream_and_frame_types_are_ignored():
    """RFC 9114 §6.2.3 and §7.2.8 reserve stream and frame types of the form
    0x1f * N + 0x21, and "Endpoints MUST NOT consider these streams to have
    any meaning upon receipt", and the same of frames. One of each, the frame
    on the client's control stream, leaves the connection working."""
    reserved = 0x1F * 3 + 0x21
    transport, host, port = await start_tagged_udp_echo(0xCB)
    try:
        async with proxy_connection() as client:
            await client.settings()
            unknown = client._h3._create_uni_stream(reserved)
            client._quic.send_stream_data(unknown, b"no meaning")
            control = client._h3._local_control_stream_id
            client._quic.send_stream_data(
                control, encode_uint_var(reserved) + encode_uint_var(10) + b"no meaning"
            )
            client.transmit()

            stream_id = await client.connect_udp(host, port)
            await udp_round_trip(client, stream_id, 0xCB, b"after-unknown-types")
    finally:
        transport.close()


async def test_settings_carry_what_a_masque_client_needs():
    """SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 9220 §3) and SETTINGS_H3_DATAGRAM
    (RFC 9297 §2.1.1) at 1, the zero QPACK dynamic table this server keeps,
    and its 64 KiB field section limit."""
    async with proxy_connection() as client:
        settings = await client.settings()
    assert settings.get(Setting.ENABLE_CONNECT_PROTOCOL) == 1, settings
    assert settings.get(Setting.H3_DATAGRAM) == 1, settings
    assert settings.get(Setting.QPACK_MAX_TABLE_CAPACITY, 0) == 0, settings
    assert settings.get(Setting.MAX_FIELD_SECTION_SIZE) == 64 * 1024, settings


async def test_an_oversized_field_section_costs_only_its_request():
    """RFC 9114 §4.2.2 sizes a field section as each field's name and value
    "plus an overhead of 32 bytes for each field", so many one-byte fields
    pass the advertised limit in a small frame. The server answers 431, stops
    the rest of the request with H3_EXCESSIVE_LOAD, and the connection
    carries on."""
    transport, host, port = await start_tagged_udp_echo(0xCC)
    try:
        async with proxy_connection() as client:
            limit = (await client.settings())[Setting.MAX_FIELD_SECTION_SIZE]
            padding = [(b"a", b"b")] * (limit // 34 + 1)
            stream_id = client.send_request(udp_request(host, port) + padding)
            fields, stopped, _ = await client.response(stream_id)
            assert fields[b":status"] == b"431", fields
            while stopped is None:
                event = await client._next_event(stream_id)
                if isinstance(event, StopReceived):
                    stopped = event.error_code
                else:
                    assert isinstance(event, DataReceived) and not event.data, (
                        f"expected a stop, got {event}"
                    )
            assert stopped == ErrorCode.H3_EXCESSIVE_LOAD, f"stopped with {stopped:#x}"

            stream_id = await client.connect_udp(host, port)
            await udp_round_trip(client, stream_id, 0xCC, b"after-the-431")
    finally:
        transport.close()


# Written out rather than derived, because the order is the reading order: the
# two tunnel kinds and their isolation checks first, then the edge cases.
# `check_tests_are_accounted_for` is what makes the hand-written list safe.
TESTS = [
    test_tcp_tunnel_round_trips,
    test_tcp_tunnels_do_not_cross_talk,
    test_udp_session_round_trips,
    test_udp_sessions_do_not_cross_talk,
    test_udp_sessions_past_quarter_stream_id_64_do_not_cross_talk,
    test_unknown_context_id_is_dropped_silently,
    test_datagram_before_its_request_is_delivered,
    test_missing_credentials_are_challenged,
    test_denied_target_is_refused_with_proxy_status,
    test_datagram_capsule_without_a_context_id_is_a_malformed_message,
    test_a_percent_sign_without_two_hex_digits_is_refused_on_its_stream,
    test_a_blackholed_target_is_accepted_then_closed,
    test_denied_tcp_target_is_refused_with_proxy_status,
    test_credentials_in_authorization_pass_after_a_challenge,
    test_a_session_the_client_resets_leaves_the_connection_working,
    test_unknown_stream_and_frame_types_are_ignored,
    test_settings_carry_what_a_masque_client_needs,
    test_an_oversized_field_section_costs_only_its_request,
]


def check_tests_are_accounted_for():
    """TESTS names every test in this file, and nothing that is not one.

    This suite is its own runner rather than a discovery-based one: the Go half
    is driven by `go test`, which finds every `TestXxx` by itself, and nothing
    here does that. A `test_*` added to the file and not added to `TESTS` would
    simply never run, silently, on the half that carries the whole independent
    coverage of the plain CONNECT path.

    Both directions, because either one alone passes over an empty scan: a
    coroutine defined here that the list does not name, and a name on the list
    that this module does not define, which is what a rename leaves behind. Same
    latch as `it_docs.every_page_under_docs_is_read_or_exempt_by_name` in the
    Rust suite, for the same reason.
    """
    defined = {
        name
        for name, value in globals().items()
        if name.startswith("test_") and inspect.iscoroutinefunction(value)
    }
    listed = [test.__name__ for test in TESTS]

    if not TESTS:
        sys.exit("TESTS is empty, so this suite would pass having run nothing")

    unlisted = sorted(defined - set(listed))
    if unlisted:
        sys.exit(
            f"these tests are defined in {os.path.basename(__file__)} and are not "
            f"in TESTS, so they never run: {unlisted}"
        )

    missing = sorted(set(listed) - defined)
    if missing:
        sys.exit(f"TESTS names tests this module does not define: {missing}")

    duplicated = sorted({name for name in listed if listed.count(name) > 1})
    if duplicated:
        sys.exit(f"TESTS names the same test more than once: {duplicated}")


async def main():
    # Every verdict here is an assert, and -O or PYTHONOPTIMIZE removes them.
    if not __debug__:
        sys.exit("run this suite without -O: its checks are assert statements")
    check_tests_are_accounted_for()
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
