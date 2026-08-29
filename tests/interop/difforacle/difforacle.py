#!/usr/bin/env python3
"""Differential decoding oracle for QPACK and Huffman: ls-qpack judges volto.

The fuzz targets next door in `fuzz/` ask "does an input crash, and does what
this encoder wrote come back out of this decoder". Neither question can catch a
decoder that *accepts* what the RFC says it must refuse, and `src/h3/huffman.rs`
has no encoder at all, so a round trip cannot reach it. This suite asks the
question those cannot: put one byte sequence through volto's decoder and through
an unrelated one, and compare the two answers -- both the accept/reject verdict
and, when both accept, the field sequence byte for byte.

The judge is `pylsqpack`, the Python binding to LiteSpeed's ls-qpack, pinned in
`../aioquic/requirements.txt` (Dependabot watches that file). It is the QPACK
implementation aioquic ships with, it is deployed in LiteSpeed's own server, and
it shares nothing with volto: not the table transcription, not the integer
decoder, not the reading of RFC 7541 Appendix B.

Three directions are run, and all three matter:

1.  decode -- generated field sections, mutated field sections and pure noise
    through both decoders. One input crosses the section prefix, the field line
    representations, the prefixed integers and the Huffman decoder at once.
2.  encode -- volto's own encoder output through ls-qpack. `tests/common` shares
    volto's codec with the server, so this is the only place a fault both ends
    of the integration suite would agree on can show up.
3.  strictness -- a fixed table of inputs the RFCs name as errors, each one
    checked to be refused by both.

Every input is derived from a seed, so a campaign is repeatable: the seed and
the counts are printed in the summary and belong in any report of a finding.

Usage:

    python3 -m venv .venv && .venv/bin/pip install -r ../aioquic/requirements.txt
    .venv/bin/python difforacle.py --seed 1 --count 20000

`--oracle PATH` skips the `cargo build` and uses an already-built binary.
"""

import argparse
import binascii
import random
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pylsqpack

# ---------------------------------------------------------------------------
# RFC 7541 Appendix B, transcribed independently of src/h3/huffman.rs
# ---------------------------------------------------------------------------
#
# (code, bit length) per symbol, symbols 0..=255 then EOS at index 256. The
# transcription is checked below against the encoded literals RFC 7541 Appendix
# C.4 prints, so a mistyped entry fails at import rather than as a phantom
# divergence.
CODES = [
    (0x1FF8, 13), (0x7FFFD8, 23), (0xFFFFFE2, 28), (0xFFFFFE3, 28),
    (0xFFFFFE4, 28), (0xFFFFFE5, 28), (0xFFFFFE6, 28), (0xFFFFFE7, 28),
    (0xFFFFFE8, 28), (0xFFFFEA, 24), (0x3FFFFFFC, 30), (0xFFFFFE9, 28),
    (0xFFFFFEA, 28), (0x3FFFFFFD, 30), (0xFFFFFEB, 28), (0xFFFFFEC, 28),
    (0xFFFFFED, 28), (0xFFFFFEE, 28), (0xFFFFFEF, 28), (0xFFFFFF0, 28),
    (0xFFFFFF1, 28), (0xFFFFFF2, 28), (0x3FFFFFFE, 30), (0xFFFFFF3, 28),
    (0xFFFFFF4, 28), (0xFFFFFF5, 28), (0xFFFFFF6, 28), (0xFFFFFF7, 28),
    (0xFFFFFF8, 28), (0xFFFFFF9, 28), (0xFFFFFFA, 28), (0xFFFFFFB, 28),
    (0x14, 6), (0x3F8, 10), (0x3F9, 10), (0xFFA, 12),
    (0x1FF9, 13), (0x15, 6), (0xF8, 8), (0x7FA, 11),
    (0x3FA, 10), (0x3FB, 10), (0xF9, 8), (0x7FB, 11),
    (0xFA, 8), (0x16, 6), (0x17, 6), (0x18, 6),
    (0x0, 5), (0x1, 5), (0x2, 5), (0x19, 6),
    (0x1A, 6), (0x1B, 6), (0x1C, 6), (0x1D, 6),
    (0x1E, 6), (0x1F, 6), (0x5C, 7), (0xFB, 8),
    (0x7FFC, 15), (0x20, 6), (0xFFB, 12), (0x3FC, 10),
    (0x1FFA, 13), (0x21, 6), (0x5D, 7), (0x5E, 7),
    (0x5F, 7), (0x60, 7), (0x61, 7), (0x62, 7),
    (0x63, 7), (0x64, 7), (0x65, 7), (0x66, 7),
    (0x67, 7), (0x68, 7), (0x69, 7), (0x6A, 7),
    (0x6B, 7), (0x6C, 7), (0x6D, 7), (0x6E, 7),
    (0x6F, 7), (0x70, 7), (0x71, 7), (0x72, 7),
    (0xFC, 8), (0x73, 7), (0xFD, 8), (0x1FFB, 13),
    (0x7FFF0, 19), (0x1FFC, 13), (0x3FFC, 14), (0x22, 6),
    (0x7FFD, 15), (0x3, 5), (0x23, 6), (0x4, 5),
    (0x24, 6), (0x5, 5), (0x25, 6), (0x26, 6),
    (0x27, 6), (0x6, 5), (0x74, 7), (0x75, 7),
    (0x28, 6), (0x29, 6), (0x2A, 6), (0x7, 5),
    (0x2B, 6), (0x76, 7), (0x2C, 6), (0x8, 5),
    (0x9, 5), (0x2D, 6), (0x77, 7), (0x78, 7),
    (0x79, 7), (0x7A, 7), (0x7B, 7), (0x7FFE, 15),
    (0x7FC, 11), (0x3FFD, 14), (0x1FFD, 13), (0xFFFFFFC, 28),
    (0xFFFE6, 20), (0x3FFFD2, 22), (0xFFFE7, 20), (0xFFFE8, 20),
    (0x3FFFD3, 22), (0x3FFFD4, 22), (0x3FFFD5, 22), (0x7FFFD9, 23),
    (0x3FFFD6, 22), (0x7FFFDA, 23), (0x7FFFDB, 23), (0x7FFFDC, 23),
    (0x7FFFDD, 23), (0x7FFFDE, 23), (0xFFFFEB, 24), (0x7FFFDF, 23),
    (0xFFFFEC, 24), (0xFFFFED, 24), (0x3FFFD7, 22), (0x7FFFE0, 23),
    (0xFFFFEE, 24), (0x7FFFE1, 23), (0x7FFFE2, 23), (0x7FFFE3, 23),
    (0x7FFFE4, 23), (0x1FFFDC, 21), (0x3FFFD8, 22), (0x7FFFE5, 23),
    (0x3FFFD9, 22), (0x7FFFE6, 23), (0x7FFFE7, 23), (0xFFFFEF, 24),
    (0x3FFFDA, 22), (0x1FFFDD, 21), (0xFFFE9, 20), (0x3FFFDB, 22),
    (0x3FFFDC, 22), (0x7FFFE8, 23), (0x7FFFE9, 23), (0x1FFFDE, 21),
    (0x7FFFEA, 23), (0x3FFFDD, 22), (0x3FFFDE, 22), (0xFFFFF0, 24),
    (0x1FFFDF, 21), (0x3FFFDF, 22), (0x7FFFEB, 23), (0x7FFFEC, 23),
    (0x1FFFE0, 21), (0x1FFFE1, 21), (0x3FFFE0, 22), (0x1FFFE2, 21),
    (0x7FFFED, 23), (0x3FFFE1, 22), (0x7FFFEE, 23), (0x7FFFEF, 23),
    (0xFFFEA, 20), (0x3FFFE2, 22), (0x3FFFE3, 22), (0x3FFFE4, 22),
    (0x7FFFF0, 23), (0x3FFFE5, 22), (0x3FFFE6, 22), (0x7FFFF1, 23),
    (0x3FFFFE0, 26), (0x3FFFFE1, 26), (0xFFFEB, 20), (0x7FFF1, 19),
    (0x3FFFE7, 22), (0x7FFFF2, 23), (0x3FFFE8, 22), (0x1FFFFEC, 25),
    (0x3FFFFE2, 26), (0x3FFFFE3, 26), (0x3FFFFE4, 26), (0x7FFFFDE, 27),
    (0x7FFFFDF, 27), (0x3FFFFE5, 26), (0xFFFFF1, 24), (0x1FFFFED, 25),
    (0x7FFF2, 19), (0x1FFFE3, 21), (0x3FFFFE6, 26), (0x7FFFFE0, 27),
    (0x7FFFFE1, 27), (0x3FFFFE7, 26), (0x7FFFFE2, 27), (0xFFFFF2, 24),
    (0x1FFFE4, 21), (0x1FFFE5, 21), (0x3FFFFE8, 26), (0x3FFFFE9, 26),
    (0xFFFFFFD, 28), (0x7FFFFE3, 27), (0x7FFFFE4, 27), (0x7FFFFE5, 27),
    (0xFFFEC, 20), (0xFFFFF3, 24), (0xFFFED, 20), (0x1FFFE6, 21),
    (0x3FFFE9, 22), (0x1FFFE7, 21), (0x1FFFE8, 21), (0x7FFFF3, 23),
    (0x3FFFEA, 22), (0x3FFFEB, 22), (0x1FFFFEE, 25), (0x1FFFFEF, 25),
    (0xFFFFF4, 24), (0xFFFFF5, 24), (0x3FFFFEA, 26), (0x7FFFF4, 23),
    (0x3FFFFEB, 26), (0x7FFFFE6, 27), (0x3FFFFEC, 26), (0x3FFFFED, 26),
    (0x7FFFFE7, 27), (0x7FFFFE8, 27), (0x7FFFFE9, 27), (0x7FFFFEA, 27),
    (0x7FFFFEB, 27), (0xFFFFFFE, 28), (0x7FFFFEC, 27), (0x7FFFFED, 27),
    (0x7FFFFEE, 27), (0x7FFFFEF, 27), (0x7FFFFF0, 27), (0x3FFFFEE, 26),
    (0x3FFFFFFF, 30),
]

EOS = 256


def huffman_bits(data):
    """The bit string RFC 7541 Appendix B assigns to `data`, unpadded."""
    bits = []
    for byte in data:
        code, length = CODES[byte]
        bits.extend((code >> shift) & 1 for shift in range(length - 1, -1, -1))
    return bits


def pack(bits, pad_bit=1):
    """Packs a bit list into octets, padding the last one with `pad_bit`."""
    bits = list(bits)
    while len(bits) % 8:
        bits.append(pad_bit)
    out = bytearray()
    for index in range(0, len(bits), 8):
        byte = 0
        for bit in bits[index:index + 8]:
            byte = (byte << 1) | bit
        out.append(byte)
    return bytes(out)


def huffman_encode(data):
    """RFC 7541 §5.2: the codes concatenated, padded with EOS's leading bits."""
    return pack(huffman_bits(data))


# RFC 7541 Appendix C.4 prints these literals in full, so reproducing them proves
# the table above was transcribed correctly -- without consulting the
# implementation under test.
for _plain, _encoded in [
    (b"www.example.com", "f1e3c2e5f23a6ba0ab90f4ff"),
    (b"no-cache", "a8eb10649cbf"),
    (b"custom-key", "25a849e95ba97d7f"),
    (b"custom-value", "25a849e95bb8e8b4bf"),
]:
    assert huffman_encode(_plain) == binascii.unhexlify(_encoded), _plain


# ---------------------------------------------------------------------------
# RFC 7541 §5.1 and RFC 9204 §4.5, on the encoding side
# ---------------------------------------------------------------------------


def enc_int(prefix_bits, flags, value, extra_zero_octets=0):
    """A prefixed integer with `flags` in the bits above the prefix.

    `extra_zero_octets` lengthens the continuation list with that many octets
    that add nothing: the last octet gets its continuation bit set and a `0x00`
    is appended, as many times as asked. The value is unchanged -- each added
    octet contributes `0 << shift` -- so this is the same integer spelled at
    length. RFC 7541 §5.1 gives an encoder's pseudocode, which never produces
    one of these, but states no minimality rule a decoder must enforce, so
    whether such an encoding is accepted is exactly the kind of question this
    suite exists to ask.

    A value below the prefix maximum has no continuation list to lengthen, so
    `extra_zero_octets` does nothing there.
    """
    mask = (1 << prefix_bits) - 1
    head = (flags << prefix_bits) & 0xFF
    if value < mask:
        return bytes([head | value])
    out = bytearray([head | mask])
    value -= mask
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    for _ in range(extra_zero_octets):
        out[-1] |= 0x80
        out.append(0x00)
    return bytes(out)


def enc_str(prefix_bits, flags, data, huffman_coded, extra_zero_octets=0):
    """A string literal: an `H` bit, a length, then the octets."""
    body = huffman_encode(data) if huffman_coded else data
    head = enc_int(
        prefix_bits,
        (flags << 1) | (1 if huffman_coded else 0),
        len(body),
        extra_zero_octets,
    )
    return head + body


def prefix(required_insert_count=0, sign=0, delta_base=0, extra_zero_octets=0):
    """RFC 9204 §4.5.1's two integers."""
    return enc_int(8, 0, required_insert_count, extra_zero_octets) + enc_int(
        7, sign, delta_base, extra_zero_octets
    )


def indexed_static(index, extra=0):
    """§4.5.2 Indexed Field Line, T = 1."""
    return enc_int(6, 0b11, index, extra)


def indexed_dynamic(index, extra=0):
    """§4.5.2 Indexed Field Line, T = 0: a dynamic reference."""
    return enc_int(6, 0b10, index, extra)


def indexed_post_base(index, extra=0):
    """§4.5.3 Indexed Field Line With Post-Base Index."""
    return enc_int(4, 0b0001, index, extra)


def literal_name_ref(index, value, static=True, never=0, huff=False, extra=0):
    """§4.5.4 Literal Field Line With Name Reference."""
    flags = 0b0100 | (never << 1) | (1 if static else 0)
    return enc_int(4, flags, index, extra) + enc_str(7, 0, value, huff, extra)


def literal_post_base(index, value, never=0, huff=False, extra=0):
    """§4.5.5 Literal Field Line With Post-Base Name Reference."""
    return enc_int(3, never, index, extra) + enc_str(7, 0, value, huff, extra)


def literal_literal(name, value, never=0, huff_name=False, huff_value=False, extra=0):
    """§4.5.6 Literal Field Line With Literal Name."""
    return enc_str(3, 0b001_0 | never, name, huff_name, extra) + enc_str(
        7, 0, value, huff_value, extra
    )


# The QPACK static table's size (RFC 9204 Appendix A), so the generator can aim
# just inside and just outside it. Transcribing the entries themselves is
# unnecessary: ls-qpack carries its own copy and that is the point.
STATIC_TABLE_LEN = 99


# ---------------------------------------------------------------------------
# The two decoders
# ---------------------------------------------------------------------------


def volto_verdicts(oracle, requests):
    """Runs every request through the volto oracle in one batch."""
    completed = subprocess.run(
        [str(oracle)],
        input="\n".join(requests) + "\n",
        capture_output=True,
        text=True,
        check=True,
    )
    verdicts = completed.stdout.splitlines()
    if len(verdicts) != len(requests):
        sys.exit(
            f"the oracle answered {len(verdicts)} of {len(requests)} requests"
            f"; stderr was {completed.stderr!r}"
        )
    return verdicts


def lsqpack_verdict(block):
    """ls-qpack's answer for one encoded field section.

    A fresh decoder per input, with the capacity and blocked-stream counts volto
    advertises in SETTINGS: `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0` and
    `SETTINGS_QPACK_BLOCKED_STREAMS = 0`. That is what makes a dynamic table
    reference comparable -- ls-qpack refuses one for the same reason volto does,
    because the settings it was built with leave no dynamic entries to name.
    """
    decoder = pylsqpack.Decoder(0, 0)
    try:
        _control, headers = decoder.feed_header(0, block)
    except pylsqpack.StreamBlocked:
        return ("err", "blocked")
    except pylsqpack.DecompressionFailed as error:
        return ("err", str(error))
    return ("ok", tuple(headers))


def volto_fields(verdict):
    """The field sequence in an `ok` verdict line, as (name, value) bytes."""
    parts = verdict.split()
    fields = []
    for part in parts[1:]:
        name, _, value = part.partition("=")
        fields.append((binascii.unhexlify(name), binascii.unhexlify(value)))
    return tuple(fields)


# ---------------------------------------------------------------------------
# Corpus
# ---------------------------------------------------------------------------

NAMES = [
    b":authority", b":method", b":path", b":protocol", b":scheme", b":status",
    b"proxy-authorization", b"authorization", b"capsule-protocol", b"user-agent",
    b"x-forwarded-for", b"cookie", b"", b"a", b"x" * 64,
]

VALUES = [
    b"", b"CONNECT", b"GET", b"connect-udp", b"https", b"200", b"407",
    b"example.com:443", b"/.well-known/masque/udp/192.0.2.1/443/",
    b"Basic dXNlcjpwYXNz", b"?1", b"a" * 300, bytes(range(256)),
]


def a_legal_section(rng):
    """A field section a conformant encoder with no dynamic table could send."""
    body = b""
    for _ in range(rng.randrange(0, 6)):
        pick = rng.randrange(3)
        extra = rng.choice([0, 0, 0, 1, 2])
        if pick == 0:
            body += indexed_static(rng.randrange(STATIC_TABLE_LEN), extra)
        elif pick == 1:
            body += literal_name_ref(
                rng.randrange(STATIC_TABLE_LEN),
                rng.choice(VALUES),
                never=rng.randrange(2),
                huff=bool(rng.randrange(2)),
                extra=extra,
            )
        else:
            body += literal_literal(
                rng.choice(NAMES),
                rng.choice(VALUES),
                never=rng.randrange(2),
                huff_name=bool(rng.randrange(2)),
                huff_value=bool(rng.randrange(2)),
                extra=extra,
            )
    return prefix(0, 0, rng.choice([0, 0, 0, 1, 5])) + body


def a_mutation(rng, seed_block):
    """One structured edit of a section that was legal before it."""
    block = bytearray(seed_block)
    for _ in range(rng.randrange(1, 4)):
        if not block:
            block.append(rng.randrange(256))
            continue
        pick = rng.randrange(5)
        at = rng.randrange(len(block))
        if pick == 0:
            block[at] ^= 1 << rng.randrange(8)
        elif pick == 1:
            block[at] = rng.choice([0x00, 0x01, 0x7F, 0x80, 0xBF, 0xC0, 0xFF])
        elif pick == 2:
            del block[at:]
        elif pick == 3:
            block.insert(at, rng.randrange(256))
        else:
            block.extend(seed_block[: rng.randrange(1, len(seed_block) + 1)])
    return bytes(block)


def a_noise_block(rng):
    """Bytes with no structure at all, from a deliberately lumpy alphabet.

    Half of them are given a valid section prefix first. Without that the field
    line parser is nearly unreachable: the Required Insert Count has to be zero,
    so only one first octet in 256 gets past the prefix at all.
    """
    length = rng.randrange(0, 48)
    if rng.randrange(2):
        body = bytes(rng.randrange(256) for _ in range(length))
    else:
        alphabet = [0x00, 0x01, 0x10, 0x20, 0x40, 0x50, 0x7F, 0x80, 0xC0, 0xFF]
        body = bytes(rng.choice(alphabet) for _ in range(length))
    return (prefix() if rng.randrange(2) else b"") + body


def a_huffman_literal(rng):
    """A Huffman-coded literal, valid or one edit away from it."""
    plain = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 20)))
    bits = huffman_bits(plain)
    pick = rng.randrange(6)
    if pick == 0:
        return pack(bits)
    if pick == 1:
        # Padded with zeros: RFC 7541 §5.2 makes that a decoding error unless
        # the code happened to end on an octet boundary.
        return pack(bits, pad_bit=0)
    if pick == 2:
        # A whole further octet of padding, which §5.2 forbids outright.
        return pack(bits) + b"\xff"
    if pick == 3:
        # EOS spliced in, which §5.2 forbids wherever it lands.
        at = rng.randrange(len(bits) + 1)
        code, length = CODES[EOS]
        eos = [(code >> shift) & 1 for shift in range(length - 1, -1, -1)]
        return pack(bits[:at] + eos + bits[at:])
    if pick == 4:
        encoded = bytearray(pack(bits))
        if encoded:
            encoded[rng.randrange(len(encoded))] ^= 1 << rng.randrange(8)
        return bytes(encoded)
    return bytes(rng.randrange(256) for _ in range(rng.randrange(0, 12)))


def a_targeted_block(rng):
    """Edge cases worth reaching more often than chance would reach them."""
    pick = rng.randrange(8)
    if pick == 0:
        # Static indices around the end of the table, and far past it.
        index = rng.choice(
            [0, 1, 62, 63, 64, 97, 98, 99, 100, 127, 128, 1 << 16, (1 << 62) - 1]
        )
        return prefix() + indexed_static(index)
    if pick == 1:
        # The same, in a literal's name reference, whose prefix is four bits.
        index = rng.choice([0, 14, 15, 16, 98, 99, 100, 1 << 20])
        return prefix() + literal_name_ref(index, rng.choice(VALUES))
    if pick == 2:
        # The same value spelled at length: 1 to 12 octets that add nothing.
        return prefix(extra_zero_octets=rng.randrange(1, 4)) + indexed_static(
            rng.choice([63, 64, 98]), rng.randrange(1, 13)
        )
    if pick == 3:
        # A continuation list that never ends, cut off after a while.
        return prefix() + bytes([0xFF]) + b"\xff" * rng.randrange(1, 16)
    if pick == 4:
        # Values around the 64-bit boundary of the decoder's accumulator.
        octets = b"\xff" * rng.randrange(8, 11)
        return prefix() + bytes([0xFF]) + octets + bytes([rng.randrange(0x80)])
    if pick == 5:
        # A length that claims more octets than the section holds.
        return (
            prefix()
            + enc_int(4, 0b0101, 0)
            + enc_int(7, 0, rng.choice([1, 2, 127, 128, 1 << 30]))
            + bytes(rng.randrange(3))
        )
    if pick == 6:
        # A Huffman literal in the name position, where the length prefix is
        # three bits rather than seven.
        literal = a_huffman_literal(rng)
        return (
            prefix()
            + enc_int(3, 0b0011, len(literal))
            + literal
            + enc_str(7, 0, rng.choice(VALUES), False)
        )
    # A field section prefix with every combination of the two flag bits.
    return prefix(
        required_insert_count=rng.choice([0, 0, 0, 1]),
        sign=rng.randrange(2),
        delta_base=rng.choice([0, 1, 2, 126, 127, 128]),
    ) + indexed_static(23)


def huffman_in_a_section(literal):
    """Wraps a Huffman literal as the value of a `:authority` field line.

    The value position rather than the name: a name is a token, and a judge is
    entitled to reject one that is empty or holds an octet no token may. Nothing
    constrains a value's octets, so what comes back is the Huffman decoder's
    output and only that.
    """
    return prefix() + enc_int(4, 0b0101, 0) + enc_int(7, 1, len(literal)) + literal


def transcription_cases():
    """Every static table entry and every Huffman symbol, one at a time.

    Two tables are transcribed by hand in volto -- RFC 9204 Appendix A in
    `src/h3/qpack.rs` and RFC 7541 Appendix B in `src/h3/huffman.rs` -- and a
    single mistyped row in either is a decoder that quietly reports the wrong
    field. Neither a round trip nor a fuzzer can see that: both would agree with
    the typo. ls-qpack carries its own copy of both, so walking them entry by
    entry is the check that closes it.

    These are ordinary comparison inputs rather than strictness ones: both sides
    must accept, and the fields must be identical.
    """
    blocks = []
    for index in range(STATIC_TABLE_LEN):
        # Name and value together.
        blocks.append(prefix() + indexed_static(index))
        # The name alone, with a literal value that cannot collide with it.
        blocks.append(prefix() + literal_name_ref(index, b"probe"))
    for symbol in range(256):
        blocks.append(huffman_in_a_section(huffman_encode(bytes([symbol]))))
    # Every symbol at once, which lands each code on every bit alignment, and
    # a few pairs to cross codes of very different lengths.
    blocks.append(huffman_in_a_section(huffman_encode(bytes(range(256)))))
    blocks.append(huffman_in_a_section(huffman_encode(bytes(reversed(range(256))))))
    for symbol in range(0, 256, 7):
        blocks.append(huffman_in_a_section(huffman_encode(bytes([symbol, 255 - symbol]))))
    return blocks


# The strictness table: inputs the RFCs name as errors, quoted where they are
# stated. Both decoders must refuse every one.
def strictness_cases():
    cases = []

    def case(what, block, why):
        cases.append((what, block, why))

    # RFC 9204 §2.2.3: a reference to a dynamic table entry with none declared.
    case("indexed dynamic entry", prefix() + indexed_dynamic(0),
         "RFC 9204 2.2.3")
    case("indexed post-base entry", prefix() + indexed_post_base(0),
         "RFC 9204 2.2.3")
    case("literal, dynamic name reference", prefix() + literal_name_ref(0, b"v", static=False),
         "RFC 9204 2.2.3")
    case("literal, post-base name reference", prefix() + literal_post_base(0, b"v"),
         "RFC 9204 2.2.3")

    # RFC 9204 §3.1: an invalid static table index.
    case("static index one past the table",
         prefix() + indexed_static(STATIC_TABLE_LEN), "RFC 9204 3.1")
    case("static index far past the table",
         prefix() + indexed_static(100000), "RFC 9204 3.1")
    case("literal name index past the table",
         prefix() + literal_name_ref(STATIC_TABLE_LEN, b"v"), "RFC 9204 3.1")

    # RFC 9204 §4.5.1.1: a Required Insert Count no conformant encoder could
    # have produced, the dynamic table being of zero capacity.
    for count in (1, 2, 63, 255, 1000):
        case(f"required insert count {count}",
             prefix(required_insert_count=count) + indexed_static(23),
             "RFC 9204 4.5.1.1")

    # RFC 9204 §4.5.1.2: "An endpoint MUST treat a field block with a Sign bit
    # of 1 as invalid if the value of Required Insert Count is less than or
    # equal to the value of Delta Base." Required Insert Count is zero here, so
    # every Delta Base qualifies.
    for delta in (0, 1, 7, 200):
        case(f"sign bit set, delta base {delta}",
             prefix(sign=1, delta_base=delta) + indexed_static(23),
             "RFC 9204 4.5.1.2")

    # RFC 7541 §5.2, the three Huffman rules.
    case("huffman padding of eight ones",
         huffman_in_a_section(huffman_encode(b"0") + b"\xff"), "RFC 7541 5.2")
    case("huffman padding of zeros",
         huffman_in_a_section(pack(huffman_bits(b"0"), pad_bit=0)), "RFC 7541 5.2")
    case("huffman literal of one zero octet",
         huffman_in_a_section(b"\x00"), "RFC 7541 5.2")
    case("huffman EOS alone",
         huffman_in_a_section(pack([1] * 30)), "RFC 7541 5.2")
    case("huffman EOS after a symbol",
         huffman_in_a_section(pack(huffman_bits(b"a") + [1] * 30)), "RFC 7541 5.2")
    case("huffman padding of nine ones",
         huffman_in_a_section(pack(huffman_bits(b"0") + [1] * 9)), "RFC 7541 5.2")
    # The same rule where the padding is a whole octet on its own. "www" is
    # 3 * 5 = 15 bits, so one pad bit finishes the octet and the next octet is
    # eight further bits of padding: nine in total, two past the limit.
    case("huffman padding spilling into a second octet",
         huffman_in_a_section(huffman_encode(b"www") + b"\xff"), "RFC 7541 5.2")
    # And where the codes stop exactly on an octet boundary, so the added octet
    # is the whole of the padding: "1" and "0" are 5 bits each, "-" is 6.
    case("huffman padding of exactly one octet",
         huffman_in_a_section(huffman_encode(b"10-") + b"\xff"), "RFC 7541 5.2")

    # Truncation: a representation that ends before it is finished.
    case("prefix only, one octet", b"\x00", "truncated")
    case("literal with no length octet", prefix() + b"\x51", "truncated")
    case("literal shorter than declared", prefix() + b"\x51\x0b/", "truncated")
    case("prefixed integer with no continuation", prefix() + b"\xff", "truncated")
    case("continuation that never terminates", prefix() + b"\xff" + b"\xff" * 8,
         "truncated")

    # RFC 9204 §7.4: a value larger than the decoder can decode.
    case("prefixed integer past 2^64", prefix() + b"\xff" + b"\xff" * 12 + b"\x01",
         "RFC 9204 7.4")
    return cases


# ---------------------------------------------------------------------------
# The campaign
# ---------------------------------------------------------------------------


def compare(blocks, verdicts, kinds):
    """Pairs each volto verdict with ls-qpack's and returns the disagreements."""
    divergences = []
    tally = Counter()
    for block, verdict, kind in zip(blocks, verdicts, kinds):
        theirs = lsqpack_verdict(block)
        ours_ok = verdict.startswith("ok")
        theirs_ok = theirs[0] == "ok"

        if ours_ok != theirs_ok:
            tally["verdict"] += 1
            divergences.append((kind, block, verdict, theirs, "verdict"))
        elif ours_ok and volto_fields(verdict) != theirs[1]:
            tally["fields"] += 1
            divergences.append((kind, block, verdict, theirs, "fields"))
        else:
            tally["agree"] += 1
        tally[f"{kind}/{'accept' if ours_ok else 'reject'}"] += 1
    return divergences, tally


def signature(kind, block, verdict, theirs, why):
    """A short label that groups divergences of the same cause together."""
    if why == "fields":
        return (kind, "both accept, the fields differ", "")
    if verdict.startswith("ok"):
        return (kind, "volto accepts, ls-qpack refuses", "")
    return (kind, "volto refuses, ls-qpack accepts", verdict[len("err ") :])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=1, help="corpus seed")
    parser.add_argument(
        "--count", type=int, default=5000, help="inputs per generated direction"
    )
    parser.add_argument("--oracle", help="a prebuilt diff_oracle binary")
    parser.add_argument(
        "--examples", type=int, default=3, help="divergences printed per signature"
    )
    parser.add_argument(
        "--dump", help="write every divergence to this file, one per line"
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[3]
    oracle = args.oracle
    if not oracle:
        subprocess.run(
            ["cargo", "build", "--release", "--example", "diff_oracle"],
            cwd=root,
            check=True,
        )
        oracle = root / "target" / "release" / "examples" / "diff_oracle"

    rng = random.Random(args.seed)

    blocks, kinds = [], []

    # Direction 1a: sections a conformant encoder could have produced.
    legal = [a_legal_section(rng) for _ in range(args.count)]
    blocks += legal
    kinds += ["legal"] * len(legal)

    # Direction 1b: one to three edits away from those.
    mutated = [a_mutation(rng, rng.choice(legal)) for _ in range(args.count)]
    blocks += mutated
    kinds += ["mutated"] * len(mutated)

    # Direction 1c: no structure at all.
    noise = [a_noise_block(rng) for _ in range(args.count)]
    blocks += noise
    kinds += ["noise"] * len(noise)

    # Direction 1d: Huffman literals, carried as a field value.
    huff = [huffman_in_a_section(a_huffman_literal(rng)) for _ in range(args.count)]
    blocks += huff
    kinds += ["huffman"] * len(huff)

    # Direction 1e: the edge cases chance would seldom reach.
    targeted = [a_targeted_block(rng) for _ in range(args.count)]
    blocks += targeted
    kinds += ["targeted"] * len(targeted)

    # Direction 1f: the two hand-transcribed tables, entry by entry.
    transcription = transcription_cases()
    blocks += transcription
    kinds += ["table"] * len(transcription)

    # Direction 3: the fixed strictness table.
    strict = strictness_cases()
    strict_at = len(blocks)
    blocks += [block for _, block, _ in strict]
    kinds += ["strict"] * len(strict)

    requests = ["section " + block.hex() for block in blocks]
    verdicts = volto_verdicts(oracle, requests)
    divergences, tally = compare(blocks, verdicts, kinds)

    # The strictness table is not about agreement: both sides must refuse, and
    # a side that accepts is named even when the other one accepts too.
    lax = []
    for offset, (what, block, why) in enumerate(strict):
        ours = verdicts[strict_at + offset]
        theirs = lsqpack_verdict(block)
        if ours.startswith("ok"):
            lax.append((what, why, block, "volto", ours))
        if theirs[0] == "ok":
            lax.append((what, why, block, "ls-qpack", str(theirs[1])))

    # Direction 2: volto's encoder, judged by ls-qpack.
    encode_requests, encode_expected = [], []
    for _ in range(args.count):
        fields = [
            (rng.choice(NAMES), rng.choice(VALUES))
            for _ in range(rng.randrange(1, 5))
        ]
        # An empty field name is not something this encoder is ever handed, and
        # a judge may refuse it as a header rather than as QPACK.
        fields = [(name or b"x", value) for name, value in fields]
        encode_requests.append(
            "encode "
            + ",".join(f"{name.hex()}={value.hex()}" for name, value in fields)
        )
        encode_expected.append(tuple(fields))

    encode_verdicts = volto_verdicts(oracle, encode_requests)
    encode_divergences = []
    for expected, verdict in zip(encode_expected, encode_verdicts):
        if not verdict.startswith("ok "):
            encode_divergences.append((expected, verdict, ("err", "volto refused")))
            continue
        block = binascii.unhexlify(verdict.split()[1])
        theirs = lsqpack_verdict(block)
        if theirs[0] != "ok" or theirs[1] != expected:
            encode_divergences.append((expected, verdict, theirs))

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------
    print(f"seed {args.seed}, {args.count} inputs per generated direction")
    print(f"decode: {len(blocks)} inputs, {tally['agree']} agreed")
    for key in sorted(tally):
        if "/" in key:
            print(f"  {key:24s} {tally[key]}")
    print(f"encode: {len(encode_requests)} sections through ls-qpack")
    print(f"strict: {len(strict)} inputs both sides must refuse, {len(lax)} accepted")

    for what, why, block, who, said in lax:
        print(f"  {who} accepts '{what}' ({why}): {block.hex()} -> {said}")

    if args.dump:
        with open(args.dump, "w", encoding="ascii") as handle:
            for kind, block, verdict, theirs, why in divergences:
                handle.write(f"{kind}\t{why}\t{block.hex()}\t{verdict}\t{theirs}\n")

    if not divergences and not encode_divergences:
        print("no divergence")
        return 0 if not lax else 1

    grouped = {}
    for entry in divergences:
        grouped.setdefault(signature(*entry), []).append(entry)

    print(f"\n{len(divergences)} decode divergences in {len(grouped)} signatures")
    for sig, entries in sorted(grouped.items(), key=lambda item: -len(item[1])):
        distinct = sorted({entry[1] for entry in entries})
        print(f"\n  {sig[0]}: {sig[1]} {sig[2]}".rstrip())
        print(f"    {len(entries)} inputs, {len(distinct)} distinct")
        seen = set()
        shown = 0
        for kind, block, verdict, theirs, _why in entries:
            if block in seen:
                continue
            seen.add(block)
            shown += 1
            if shown > args.examples:
                break
            print(f"    input    {block.hex()}")
            print(f"      volto    {verdict}")
            print(f"      ls-qpack {theirs}")

    if encode_divergences:
        print(f"\n{len(encode_divergences)} encode divergences")
        for expected, verdict, theirs in encode_divergences[: args.examples]:
            print(f"    fields   {expected}")
            print(f"      volto    {verdict}")
            print(f"      ls-qpack {theirs}")

    return 1


if __name__ == "__main__":
    sys.exit(main())
