//! Every production log statement in `src/` is accounted for.
//!
//! D97 settled that log volume is a bounded resource: `journald` rate limiting
//! counts *lines*, per unit, so a peer that can provoke one production-level
//! line per request does not merely fill a disk — it spends this service's whole
//! allowance and the genuine lines that follow are dropped. The rule it left
//! behind is that a production line a peer can repeat at will goes through
//! [`volto::logfmt::Sampler`]'s doubling schedule, or is deliberately unsampled
//! for a reason somebody wrote down.
//!
//! `it_log_amplification` is the *behavioural* half of that rule: it drives five
//! scenarios and counts what reaches a capturing subscriber. What it cannot see
//! is a sixth one — a `warn!` added tomorrow, on a path no probe walks, reaching
//! production with nobody having asked the question. This is the other half:
//! every `info!`, `warn!` and `error!` in `src/` has to appear in the table
//! below, saying what bounds it and why. Adding a production log line is then a
//! deliberate act with a diff, and so is deleting or rewording one.
//!
//! # What is in scope
//!
//! `info!`, `warn!` and `error!`, because the shipped filter is `volto=info`
//! (`script/config.example.toml`, `docs/configuration.md`) and those are the
//! three levels that survive it. `debug!` and `trace!` are out: an operator has
//! to turn them on, and D97 deliberately left the per-packet debug lines
//! unsampled. `error!` is in even though nothing a peer does reaches one today —
//! the point of the gate is that the first one to be reachable is a decision
//! rather than an accident.
//!
//! Comments are excluded, so the prose explaining a line does not count as the
//! line, and `#[cfg(test)]` items are excluded, so `main.rs`'s syslog-formatter
//! test — which writes one event per level on purpose — is not mistaken for
//! something a peer can reach.
//!
//! # What this gate does *not* claim
//!
//! It does not prove that an entry marked [`Bound::Sampled`] really reaches a
//! sampler on every path; that is what `it_log_amplification`'s probes and the
//! unit tests beside each call site are for. What it proves is that the set of
//! production log statements in `src/` is exactly the set somebody has answered
//! the D97 question about. Membership is the invariant; the reason column is
//! where the answer lives.

#[path = "common/scripts.rs"]
mod scripts;

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use scripts::{code_only, repo_root, rust_files};

/// What keeps one production log statement from becoming a flood.
///
/// Every entry in [`ACCOUNTED`] carries one of these plus a sentence saying why
/// it applies *there*. The enum is the vocabulary D97 argues in; the sentence is
/// the argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bound {
    /// Not reachable by a peer at all: this is the operator's own start,
    /// reload, shutdown or signal, and there are as many of them as the
    /// operator asked for.
    Lifecycle,
    /// At most one per QUIC connection, so a peer pays a whole handshake per
    /// line. D76 bounds an unauthenticated connection in time, bytes and
    /// concurrency at once, which is what makes that price real.
    PerConnection,
    /// One per tunnel or session: the access log. Deliberately unsampled — an
    /// access log that drops records is not an access log — and pinned to
    /// exactly one line by `it_log_amplification`.
    PerTunnel,
    /// Peer-repeatable, and bounded by [`volto::logfmt::Sampler`]'s doubling
    /// schedule.
    Sampled,
    /// Peer-repeatable, and bounded by a configured budget instead: the
    /// connection is closed when the budget runs out, so the line count per
    /// handshake is a number in the configuration file.
    Budgeted,
    /// Peer-repeatable, unsampled, and deliberately so. The reason has to say
    /// what makes each line expensive enough for the peer that there is no
    /// flood to bound.
    UnsampledOnPurpose,
}

/// One production log statement, and the answer to "what bounds this?".
struct Accounted {
    /// The file it lives in, relative to `src/`.
    file: &'static str,
    /// The message it writes, exactly — the last string literal of the macro
    /// invocation, with Rust's escapes resolved.
    message: &'static str,
    /// Which kind of bound applies.
    bound: Bound,
    /// Why it applies here. One line, and it has to be about *this* statement.
    reason: &'static str,
}

/// Every production log statement in `src/`, and why each cannot become a flood.
///
/// Keyed by file and message: a new line, a deleted line and a reworded line all
/// fail this gate until somebody edits this table. The four entries D97 calls
/// deliberately unsampled carry that ADR's own reasoning, so the argument lives
/// beside the line rather than only in a document `src/` cannot see.
const ACCOUNTED: &[Accounted] = &[
    Accounted {
        file: "conn.rs",
        message: "sent GOAWAY, draining tunnels",
        bound: Bound::PerConnection,
        reason: "The shutdown arm is guarded by `going_away`, so it runs once per \
                 connection, and only after the operator asked for a shutdown.",
    },
    Accounted {
        file: "conn.rs",
        message: "every tunnel finished after GOAWAY",
        bound: Bound::PerConnection,
        reason: "The last thing a draining connection says before its loop ends; \
                 the arm is guarded by `going_away` and the loop breaks on it.",
    },
    Accounted {
        file: "conn.rs",
        message: "authentication failed",
        bound: Bound::Budgeted,
        reason: "D97's exemption: at most `security.max_auth_failures` per \
                 connection, which is already a bound -- the connection is closed \
                 when the budget runs out, so guessing costs a handshake.",
    },
    Accounted {
        file: "conn.rs",
        message: "closing the connection after repeated authentication failures",
        bound: Bound::PerConnection,
        reason: "Written once, immediately before the close that ends the \
                 connection, so there cannot be a second one on it.",
    },
    Accounted {
        file: "conn.rs",
        message: "connection is at its tunnel limit; further refusals on this connection are \
                  logged at debug level until the count doubles",
        bound: Bound::Sampled,
        reason: "Every request past the quota is refused this way at one HEADERS \
                 frame apiece, so `Context::limit_refusals` samples it and the \
                 reports carry the running total.",
    },
    Accounted {
        file: "main.rs",
        message: "{warning}",
        bound: Bound::Lifecycle,
        reason: "One per warning the loaded configuration produced, at startup, \
                 before any peer exists.",
    },
    Accounted {
        file: "main.rs",
        message: "volto stopped",
        bound: Bound::Lifecycle,
        reason: "The last line the process writes.",
    },
    Accounted {
        file: "main.rs",
        message: "could not install the SIGHUP handler; reload is unavailable",
        bound: Bound::Lifecycle,
        reason: "Once at startup, on the path that then gives up on reload \
                 entirely.",
    },
    Accounted {
        file: "main.rs",
        message: "received SIGHUP, reloading configuration",
        bound: Bound::Lifecycle,
        reason: "One per SIGHUP, and a signal comes from the host's own operator \
                 or from `certbot`, never from a peer.",
    },
    Accounted {
        file: "main.rs",
        message: "configuration reload failed; the running configuration is unchanged",
        bound: Bound::Lifecycle,
        reason: "At most one per SIGHUP, on the same operator-driven path.",
    },
    Accounted {
        file: "main.rs",
        message: "could not install the SIGTERM handler",
        bound: Bound::Lifecycle,
        reason: "Once at startup; the watcher returns straight after it.",
    },
    Accounted {
        file: "main.rs",
        message: "could not wait for SIGINT",
        bound: Bound::Lifecycle,
        reason: "Once, and the signal watcher returns straight after it.",
    },
    Accounted {
        file: "main.rs",
        message: "received a termination signal",
        bound: Bound::Lifecycle,
        reason: "Once: the watcher fires the shutdown trigger and ends.",
    },
    Accounted {
        file: "main.rs",
        message: "could not wait for Ctrl-C",
        bound: Bound::Lifecycle,
        reason: "The non-unix arm of the same watcher, and it returns after it.",
    },
    Accounted {
        file: "main.rs",
        message: "received Ctrl-C",
        bound: Bound::Lifecycle,
        reason: "The non-unix arm of the same watcher, once per process.",
    },
    Accounted {
        file: "quic.rs",
        message: "accepting QUIC connections",
        bound: Bound::Lifecycle,
        reason: "Once, when the endpoint starts its accept loop.",
    },
    Accounted {
        file: "quic.rs",
        message: "connection established",
        bound: Bound::PerConnection,
        reason: "One per completed QUIC handshake, which is the price D76 makes \
                 a peer pay before it can write anything at all.",
    },
    Accounted {
        file: "quic.rs",
        message: "connection closed",
        bound: Bound::PerConnection,
        reason: "The other end of the same pair: one per connection, carrying the \
                 counters that were collected for it.",
    },
    Accounted {
        file: "quic.rs",
        message: "connection closed with error",
        bound: Bound::PerConnection,
        reason: "The same line for a connection that ended badly -- one per \
                 connection. What a peer can write *into* it is D97's fifth rule, \
                 held by `logfmt::peer_error`, not by the volume.",
    },
    Accounted {
        file: "quic.rs",
        message: "shutting down: no new connections, letting existing tunnels finish",
        bound: Bound::Lifecycle,
        reason: "Once, when `drain` closes the door.",
    },
    Accounted {
        file: "quic.rs",
        message: "every connection finished within the grace period",
        bound: Bound::Lifecycle,
        reason: "One of the two outcomes of the single drain, written once.",
    },
    Accounted {
        file: "quic.rs",
        message: "grace period expired, closing the remaining connections",
        bound: Bound::Lifecycle,
        reason: "The other outcome of the same single drain.",
    },
    Accounted {
        file: "quic.rs",
        message: "configuration reloaded; new connections will use it",
        bound: Bound::Lifecycle,
        reason: "One per successful reload, and a reload starts with SIGHUP.",
    },
    Accounted {
        file: "quic.rs",
        message: "{warning}",
        bound: Bound::Lifecycle,
        reason: "One per warning the reloaded configuration produced, on the same \
                 operator-driven path.",
    },
    Accounted {
        file: "quic.rs",
        message: "RLIMIT_NOFILE leaves no room for limits.max_connections x \
                  limits.max_targets_per_conn: clients at their quotas can exhaust the \
                  process. Raise LimitNOFILE (systemd) or lower either limit.",
        bound: Bound::Lifecycle,
        reason: "At most one per bind or reload: it is a verdict on the \
                 configuration against the process's own fd limit.",
    },
    Accounted {
        file: "quic.rs",
        message: "the kernel refused the UDP socket buffer {} asks for, so the socket keeps the \
                  operating system default. Lower the value, or raise this host's ceiling ({} on \
                  Linux, kern.ipc.maxsockbuf on macOS).",
        bound: Bound::Lifecycle,
        reason: "At most one per socket buffer at bind time, so two per process \
                 start.",
    },
    Accounted {
        file: "quic.rs",
        message: "the kernel granted less UDP socket buffer than {} asks for: a burst that \
                  outruns this socket is dropped there, silently, and has to be sent again. Raise \
                  this host's ceiling (sysctl -w {}=<bytes> on Linux, kern.ipc.maxsockbuf on \
                  macOS) or lower {} so it stops asking for more than the host allows.",
        bound: Bound::Lifecycle,
        reason: "The read-back half of the same bind-time check, and skipped \
                 entirely when the refusal above already spoke.",
    },
    Accounted {
        file: "tunnel/mod.rs",
        message: "every address of the target is a DNS blackhole",
        bound: Bound::UnsampledOnPurpose,
        reason: "D97's exemption: this is D49's evidence line, and it fires on \
                 ordinary ad-blocked traffic rather than on an attack -- an \
                 operator reading it needs the record of which name it was, not a \
                 sample. `logfmt::addresses` is what bounds its length.",
    },
    Accounted {
        file: "tunnel/mod.rs",
        message: "every address of the target is prohibited by policy; further refusals on this \
                  connection are logged at debug level until the count doubles",
        bound: Bound::Sampled,
        reason: "The cheapest production line in the server -- an IP literal takes \
                 no resolver slot and holds no socket -- so a port scan is 65535 of \
                 them. `Context::policy_refusals` turns that into 17.",
    },
    Accounted {
        file: "tunnel/tcp.rs",
        message: "tcp tunnel established",
        bound: Bound::PerTunnel,
        reason: "D97's exemption: this is the access log, and an access log that \
                 drops records is not an access log. One line per tunnel is the \
                 floor `it_log_amplification` pins.",
    },
    Accounted {
        file: "tunnel/udp.rs",
        message: "udp session established",
        bound: Bound::PerTunnel,
        reason: "D97's exemption, and the cheapest tunnel there is, so this is the \
                 floor probe: `it_log_amplification` asserts exactly one line per \
                 session and no more.",
    },
    Accounted {
        file: "tunnel/udp.rs",
        message: "client sent an oversized UDP payload, aborting the session",
        bound: Bound::UnsampledOnPurpose,
        reason: "D97's exemption: a payload over `MAX_UDP_PAYLOAD` costs the peer \
                 at least 64 KiB to send and the session ends on the spot, so there \
                 is no flood to bound -- one line per 64 KiB and per session.",
    },
    Accounted {
        file: "tunnel/udp.rs",
        message: "target packet too large for a QUIC datagram, dropping; further drops on this \
                  session are logged at debug level until the count doubles",
        bound: Bound::Sampled,
        reason: "Surge advertises `max_datagram_frame_size = 1300`, which a large \
                 DNS answer clears routinely, so these arrive per packet; the \
                 session's `oversize_drops` sampler picks the 1st, 2nd, 4th and so \
                 on.",
    },
    Accounted {
        file: "tunnel/udp.rs",
        message: "QUIC datagram send buffer full, older datagrams evicted; further evictions on \
                  this session are logged at debug level until the count doubles",
        bound: Bound::Sampled,
        reason: "Also per packet once quinn's send queue has fallen behind; the \
                 session's `evictions` sampler bounds it the same way.",
    },
];

fn source_root() -> PathBuf {
    repo_root().join("src")
}

/// The macros a production log line is written with.
///
/// The trailing `(` is part of the name on purpose: it is what tells a macro
/// invocation from a mention of one, and every call in this crate is written
/// with parentheses.
const PRODUCTION_MACROS: [&str; 3] = ["info!(", "warn!(", "error!("];

/// A production log statement found in `src/`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Statement {
    /// The file, relative to `src/`.
    file: String,
    /// The line the macro's name is on.
    line: usize,
    /// The message the statement writes.
    message: String,
}

/// `text` with the comments and the `#[cfg(test)]` items blanked out, line for
/// line.
///
/// Line for line matters: the result is joined back together with newlines and
/// keeps the same line count as the file, so an offset into it still names a
/// line an operator can open.
///
/// A `#[cfg(test)]` item is skipped by brace balance rather than to the end of
/// the file, because two of them in this crate are single functions inside an
/// `impl` (`logfmt::Sampler::seen`, `h3::frame`'s test-only accessor) with
/// production code after them. A miscount cannot pass silently either way: too
/// much skipped leaves a table entry with nothing to match, and too little
/// finds a statement that is not in the table.
fn production_code(text: &str) -> String {
    let mut out = String::new();
    let mut skipping: Option<isize> = None;

    for line in text.lines() {
        let code = code_only(line).unwrap_or("");

        if let Some(depth) = skipping.as_mut() {
            *depth += brace_delta(code);
            if *depth <= 0 && code.contains('}') {
                skipping = None;
            }
        } else if code.trim() == "#[cfg(test)]" {
            skipping = Some(0);
        } else {
            out.push_str(code);
        }

        out.push('\n');
    }

    out
}

/// How far one line of code opens or closes braces.
fn brace_delta(code: &str) -> isize {
    code.chars()
        .map(|ch| match ch {
            '{' => 1,
            '}' => -1,
            _ => 0,
        })
        .sum()
}

/// The line an offset into [`production_code`]'s output belongs to.
fn line_at(code: &str, offset: usize) -> usize {
    code[..offset].bytes().filter(|byte| *byte == b'\n').count() + 1
}

/// The index just past the string literal whose opening quote is at `open`.
///
/// Escapes are honoured, so a `\"` inside a message does not end it. Raw
/// strings are not: this crate has none outside its test modules, which are
/// blanked before anything gets here.
fn string_end(chars: &[(usize, char)], open: usize) -> usize {
    let mut index = open + 1;
    while index < chars.len() {
        match chars[index].1 {
            '\\' => index += 2,
            '"' => return index + 1,
            _ => index += 1,
        }
    }
    chars.len()
}

/// A string literal's text, with Rust's escapes resolved.
///
/// The one that matters here is the line continuation: a long message is
/// written as `"... further \` newline `    ones are ..."`, where the backslash
/// eats the newline *and* the indentation after it. Resolving it is what lets
/// the table quote the message an operator will actually read in the journal.
fn unescape(chars: impl Iterator<Item = char>) -> String {
    let mut out = String::new();
    let mut chars = chars.peekable();

    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('0') => out.push('\0'),
            Some('\n') => {
                while chars.peek().is_some_and(|ch| ch.is_whitespace()) {
                    chars.next();
                }
            }
            Some(other) => out.push(other),
            None => {}
        }
    }

    out
}

/// The macro invocation whose opening parenthesis is at `open`: the index just
/// past its closing one, and the last string literal inside it.
///
/// The last literal is the message: `tracing` takes the structured fields first
/// and the message last, and every call in this crate is written that way. A
/// literal in a field value — there is none today — would be overtaken by the
/// message that follows it.
fn invocation(chars: &[(usize, char)], open: usize) -> (usize, String) {
    let mut depth = 0usize;
    let mut message = String::new();
    let mut index = open;

    while index < chars.len() {
        match chars[index].1 {
            '"' => {
                let end = string_end(chars, index);
                let last = end.saturating_sub(1).max(index + 1);
                message = unescape(chars[index + 1..last].iter().map(|(_, ch)| *ch));
                index = end;
            }
            '(' => {
                depth += 1;
                index += 1;
            }
            ')' => {
                depth -= 1;
                index += 1;
                if depth == 0 {
                    return (index, message);
                }
            }
            _ => index += 1,
        }
    }

    (chars.len(), message)
}

/// Whether `ch` could be part of an identifier, and so whether a macro name
/// starting here is really the start of one.
fn is_identifier(ch: char) -> bool {
    ch.is_alphanumeric() || ch == '_'
}

/// Every production log statement in one file's code.
fn log_statements(file: &str, code: &str) -> Vec<Statement> {
    let chars: Vec<(usize, char)> = code.char_indices().collect();
    let mut found = Vec::new();
    let mut index = 0;

    while index < chars.len() {
        let (offset, ch) = chars[index];

        if ch == '"' {
            index = string_end(&chars, index);
            continue;
        }

        let name = PRODUCTION_MACROS
            .iter()
            .find(|name| code[offset..].starts_with(**name));

        // `tracing::warn!` is reached through a path, so what precedes the name
        // may be a colon; what it may not be is another identifier character,
        // which is what would make this the tail of a different macro's name.
        let starts_a_name = index == 0 || !is_identifier(chars[index - 1].1);

        if let (Some(name), true) = (name, starts_a_name) {
            let open = index + name.chars().count() - 1;
            let (end, message) = invocation(&chars, open);
            found.push(Statement {
                file: file.to_string(),
                line: line_at(code, offset),
                message,
            });
            index = end;
            continue;
        }

        index += 1;
    }

    found
}

/// Every production log statement in `src/`, in a stable order.
fn scan() -> Vec<Statement> {
    let root = source_root();
    assert!(
        root.is_dir(),
        "there is no {} to scan: this gate cannot pass by finding nothing",
        root.display()
    );

    let mut found = Vec::new();
    for path in rust_files(&root) {
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        let relative = path.strip_prefix(&root).unwrap_or(&path);
        found.extend(log_statements(
            &relative.display().to_string(),
            &production_code(&text),
        ));
    }

    found.sort();
    found
}

/// Nothing writes a production log line without somebody having said what
/// bounds it.
#[test]
fn every_production_log_statement_is_accounted_for() {
    let found = scan();

    // The way a source-scanning gate fails without saying so: it stops finding
    // anything and reports that everything is accounted for (`it_scrub`'s
    // lesson, learned the hard way). A scanner that has gone partly blind is
    // caught by `the_table_names_no_statement_that_is_gone` instead, which turns
    // every statement it stopped seeing into a stale entry.
    assert!(
        !found.is_empty(),
        "the scanner found no production log statement at all in {}, which cannot \
         be true of this crate: the gate is broken, not satisfied",
        source_root().display()
    );

    let table: BTreeSet<(&str, &str)> = ACCOUNTED
        .iter()
        .map(|entry| (entry.file, entry.message))
        .collect();

    let unaccounted: Vec<String> = found
        .iter()
        .filter(|statement| !table.contains(&(statement.file.as_str(), statement.message.as_str())))
        .map(|statement| {
            format!(
                "src/{}:{}: {:?}",
                statement.file, statement.line, statement.message
            )
        })
        .collect();

    assert!(
        unaccounted.is_empty(),
        "{} production log statement(s) nobody has answered D97 for. A line at \
         `info` or above is one a peer may be able to repeat: say what bounds it \
         -- a `logfmt::Sampler`, a configured budget, one per connection, one per \
         tunnel -- and add it to `ACCOUNTED` in this file with the reason:\n  {}",
        unaccounted.len(),
        unaccounted.join("\n  ")
    );
}

/// The table may not outlive the lines it describes.
///
/// A stale entry is worse than a missing one: it makes the gate look like it is
/// guarding something it is not, and it keeps a reason alive for a line that no
/// longer exists to be judged against it.
#[test]
fn the_table_names_no_statement_that_is_gone() {
    let found: BTreeSet<(String, String)> = scan()
        .into_iter()
        .map(|statement| (statement.file, statement.message))
        .collect();

    let stale: Vec<String> = ACCOUNTED
        .iter()
        .filter(|entry| !found.contains(&(entry.file.to_string(), entry.message.to_string())))
        .map(|entry| format!("src/{}: {:?}", entry.file, entry.message))
        .collect();

    assert!(
        stale.is_empty(),
        "{} entr(y/ies) in `ACCOUNTED` match no statement in `src/`. A log line \
         that was deleted or reworded takes its entry with it:\n  {}",
        stale.len(),
        stale.join("\n  ")
    );
}

/// Every entry answers the question, and answers it once.
#[test]
fn every_entry_carries_a_reason_and_a_distinct_key() {
    let mut keys = BTreeSet::new();
    for entry in ACCOUNTED {
        assert!(
            !entry.reason.trim().is_empty(),
            "src/{}: {:?} has no reason, which is the only thing this table is for",
            entry.file,
            entry.message
        );
        assert!(
            !entry.message.trim().is_empty(),
            "src/{}: an entry with no message matches every statement and guards none",
            entry.file
        );
        assert!(
            keys.insert((entry.file, entry.message)),
            "src/{}: {:?} is in the table twice, so one of the two reasons is \
             unreachable",
            entry.file,
            entry.message
        );
    }
}

/// An entry that claims the doubling schedule has to be in a file that has one.
///
/// A smoke check, not a proof: what really pins the wiring is
/// `it_log_amplification`, which counts the lines a storm buys, and the unit
/// tests beside each sampler. What this catches is the cheap mistake — marking a
/// line `Sampled` in a file where no sampler exists — which is exactly what
/// somebody reaching for the quietest entry in the enum would do.
#[test]
fn a_sampled_entry_lives_beside_a_sampler() {
    let root = source_root();

    for entry in ACCOUNTED.iter().filter(|e| e.bound == Bound::Sampled) {
        let path = root.join(entry.file);
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        assert!(
            production_code(&text).contains(".record()"),
            "src/{}: {:?} is marked as sampled, but nothing in that file records \
             into a `logfmt::Sampler`",
            entry.file,
            entry.message
        );
    }
}

/// The scanner can fail, which is the half a passing gate never shows.
#[test]
fn the_scanner_finds_a_statement_and_leaves_the_prose_about_it_alone() {
    // A one-line call, fields and all.
    let one = log_statements("x.rs", "    info!(live = n, \"sent GOAWAY\");\n");
    assert_eq!(one.len(), 1);
    assert_eq!(one[0].line, 1);
    assert_eq!(one[0].message, "sent GOAWAY");

    // The shape most of this crate's calls take: several lines, the message
    // last, and a `\` continuation inside it.
    let spread = production_code(
        "fn f() {\n\
         \x20   warn!(\n\
         \x20       stream_id,\n\
         \x20       \"at the limit; further refusals are logged \\\n\
         \x20        at debug level\"\n\
         \x20   );\n\
         }\n",
    );
    let spread = log_statements("x.rs", &spread);
    assert_eq!(spread.len(), 1);
    assert_eq!(
        spread[0].line, 2,
        "a statement is named by the macro's line"
    );
    assert_eq!(
        spread[0].message, "at the limit; further refusals are logged at debug level",
        "the continuation's newline and indentation are not part of the message"
    );

    // A comment about a log line is not a log line, and neither is a mention of
    // the macro inside a message.
    let prose = production_code(
        "// warn!(\"about to warn\");\n\
         /// The first drop is worth an `info!`.\n\
         fn f() { debug!(\"quiet\"); }\n",
    );
    assert!(log_statements("x.rs", &prose).is_empty());

    // Parentheses inside a message are message, not structure -- a naive
    // balance would end the invocation early and take the wrong literal.
    let parens = log_statements("x.rs", "info!(n, \"a limit (D77) was reached\");\n");
    assert_eq!(parens.len(), 1);
    assert_eq!(parens[0].message, "a limit (D77) was reached");

    // A test module writes log lines nobody can reach, and is blanked whole --
    // while the production code after it survives, which is what a
    // skip-to-end-of-file rule would get wrong.
    let with_tests = production_code(
        "info!(\"production\");\n\
         #[cfg(test)]\n\
         mod tests {\n\
         \x20   fn c() { warn!(\"a warning\"); }\n\
         }\n\
         info!(\"production again\");\n",
    );
    let statements = log_statements("x.rs", &with_tests);
    assert_eq!(
        statements
            .iter()
            .map(|s| s.message.as_str())
            .collect::<Vec<_>>(),
        vec!["production", "production again"]
    );
    assert_eq!(statements[1].line, 6, "blanking must not renumber the file");
}
