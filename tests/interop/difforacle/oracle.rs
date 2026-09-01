//! The volto half of the QPACK/Huffman differential oracle.
//!
//! A filter, not a test: it reads one request per line from standard input and
//! writes one verdict per line to standard output, so that a driver can put the
//! same bytes through this server's decoder and through an independent one and
//! compare the two answers. The driver is `difforacle.py` next door, which
//! judges with `pylsqpack` (the C library ls-qpack); see the README for why
//! that pairing and how to run it.
//!
//! Keeping the two halves in separate processes is what makes the comparison
//! worth anything: nothing here is shared with the judge, not the table
//! transcription, not the integer decoder, not the reading of the RFC.
//!
//! # The line protocol
//!
//! Requests, one per line, blank lines and `#` comments ignored:
//!
//! * `section <hex>` — decode `<hex>` as a QPACK encoded field section
//!   (RFC 9204 §4.5), prefix included.
//! * `huffman <hex>` — decode `<hex>` as a Huffman-coded string literal
//!   (RFC 7541 §5.2). Reached through [`volto::h3::huffman`] directly, so a
//!   padding rule can be exercised without a field section around it.
//! * `encode <namehex>=<valuehex>[,<namehex>=<valuehex>]...` — encode those
//!   fields as a field section. `encode` alone is the empty section.
//!
//! Verdicts, one per line:
//!
//! * `ok <namehex>=<valuehex> ...` for an accepted field section (an empty
//!   section is a bare `ok`), `ok <hex>` for `huffman` and `encode`.
//! * `err <connection|stream> <CODE> <detail>` for a rejected input, where
//!   `CODE` is the RFC 9114 §8.1 name this server answers with.
//! * `bad <detail>` for a malformed request line, which is the driver's fault
//!   rather than a verdict about the input.
//!
//! The first argument, if given, is the `SETTINGS_MAX_FIELD_SECTION_SIZE` to
//! decode against. It defaults to `u64::MAX` rather than this server's
//! advertised limit, because that limit is a local policy rather than a rule of
//! RFC 9204: leaving it out of the way keeps every disagreement the driver sees
//! a disagreement about the encoding.

use std::fmt::Write as _;
use std::io::{self, BufRead, BufWriter, Write as _};

use bytes::BytesMut;
use volto::h3::error::Violation;
use volto::h3::{huffman, qpack};

fn main() -> io::Result<()> {
    let max_section_size = std::env::args()
        .nth(1)
        .map_or(Ok(u64::MAX), |arg| arg.parse())
        .unwrap_or(u64::MAX);

    let input = io::stdin().lock();
    let mut output = BufWriter::new(io::stdout().lock());

    for line in input.lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let (verb, rest) = line.split_once(' ').unwrap_or((line, ""));
        let verdict = match verb {
            "section" => match unhex(rest) {
                Some(block) => match qpack::decode(&block, max_section_size) {
                    Ok(fields) => {
                        let mut line = String::from("ok");
                        for field in fields {
                            let _ = write!(line, " {}={}", hex(&field.name), hex(&field.value));
                        }
                        line
                    }
                    Err(violation) => rejected(&violation),
                },
                None => "bad the section is not hexadecimal".to_owned(),
            },
            "huffman" => match unhex(rest) {
                Some(literal) => match huffman::decode(&literal) {
                    Ok(decoded) => format!("ok {}", hex(&decoded)),
                    Err(violation) => rejected(&violation),
                },
                None => "bad the literal is not hexadecimal".to_owned(),
            },
            "encode" => match fields(rest) {
                Some(fields) => {
                    let mut block = BytesMut::new();
                    qpack::encode(
                        &mut block,
                        fields
                            .iter()
                            .map(|(name, value)| (name.as_slice(), value.as_slice())),
                    );
                    format!("ok {}", hex(&block))
                }
                None => "bad the fields are not hexadecimal pairs".to_owned(),
            },
            other => format!("bad unknown request {other}"),
        };

        writeln!(output, "{verdict}")?;
    }

    output.flush()
}

/// A rejection, as its class, its code and the detail the server logs.
fn rejected(violation: &Violation) -> String {
    let class = if violation.is_connection_error() {
        "connection"
    } else {
        "stream"
    };
    format!("err {class} {violation}")
}

/// Parses `<namehex>=<valuehex>,...`, the argument of the `encode` request.
fn fields(spec: &str) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
    if spec.is_empty() {
        return Some(Vec::new());
    }
    spec.split(',')
        .map(|pair| {
            let (name, value) = pair.split_once('=')?;
            Some((unhex(name)?, unhex(value)?))
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(pair, 16).ok()
        })
        .collect()
}
