//! A lossy path under the replay, injected with `tc`/netem.
//!
//! # Why the replay needs one
//!
//! The shape replay reproduces *what the client does*: when connections arrive,
//! how many tunnels they carry, how they end. What it has never reproduced is
//! *the path they do it over*. Everything runs on loopback -- sub-millisecond
//! round trip, not one packet lost -- against a production link measured at
//! 80-95 ms whose ninetieth-percentile connection loses 13% of the packets the
//! server sends it.
//!
//! That gap is not a rounding error, it is a whole half of the server that never
//! runs: loss recovery, the congestion controller, path MTU discovery and every
//! timer that keys off the round trip. So "the replay found no server-side
//! fault" could only ever mean "none on a path that cannot fail", and the one
//! production symptom the replay was built to chase -- the erasure-loss spikes
//! on one of the captured hosts -- is loss-driven by definition and therefore
//! structurally out of its reach.
//!
//! This module closes that. It puts a real qdisc on the real kernel path the
//! replay's packets take, so the loss and the delay are applied by the same code
//! that would apply them on a wire, not simulated inside the harness.
//!
//! # What it shapes, and what it deliberately does not
//!
//! Everything in the replay is on `lo`: the client, the server, and the echo
//! targets the server dials on the client's behalf. Shaping `lo` wholesale would
//! therefore put 90 ms and 13% loss on the *server-to-target* hop as well, which
//! production does not have in anything like that shape -- and would slow the
//! target side so much that the replay could no longer execute its plan.
//!
//! So the shaping is aimed at the QUIC four-tuple only. A `prio` qdisc with an
//! all-zero priomap sends every unmatched packet to band 1, which is a plain
//! pfifo; two `u32` filters pick out UDP carrying the lab server's port and send
//! it to bands 3 and 4, one netem each:
//!
//! ```text
//!                        ┌─ 1:1  pfifo   ← everything else, untouched
//!   lo root  prio 1: ────┼─ 1:3  netem   ← udp dport = server  (client → server)
//!                        └─ 1:4  netem   ← udp sport = server  (server → client)
//! ```
//!
//! Two netems rather than one because the two directions are not the same
//! measurement. The `loss_permille` a closing line reports is computed from
//! `lost_packets / sent_packets` -- packets *this server sent* and later judged
//! lost -- so it is the server-to-client direction alone, and being able to set
//! that direction on its own is what makes the server's own number a check on
//! the injection rather than a coincidence.
//!
//! Three further details matter enough to be defaults rather than options:
//!
//! * **Segmentation offload is turned off**, which helps less than it looks and
//!   is documented here so nobody assumes otherwise. quinn hands the kernel one
//!   `UDP_SEGMENT` batch worth many datagrams, and segmentation happens in
//!   `validate_xmit_skb` -- *downstream* of the qdisc -- so netem takes its loss
//!   draw on the whole batch whatever `ethtool` says. Loss is therefore bursty
//!   in units of the sender's batch rather than the independent erasure D33/D71
//!   settled the character of. What keeps that small is the congestion
//!   controller: under loss the batches are, and the runs this was built for
//!   measured about 1.5 datagrams per draw. `ethtool -K lo gso off tso off
//!   tx-udp-segmentation off` is kept because it makes the device behave like a
//!   NIC rather than a loopback shortcut, not because it makes the loss
//!   per-datagram.
//! * **`lo` is given a 1500-byte MTU.** At its default 65536 every DPLPMTUD
//!   probe succeeds by construction and path MTU discovery is not under test at
//!   all. At 1500 the probes are real, the configured `mtu_upper_bound` of 1464
//!   is reachable, and `mtu_black_holes` on the closing line becomes a genuine
//!   answer to the D81 question of whether loss makes the black-hole detector
//!   fire on a path that has no black hole.
//! * **There is a rate.** Loopback has no bottleneck, so without one the
//!   congestion controller's bandwidth estimate climbs until the netem backlog
//!   overflows and the overflow drops -- congestion loss -- contaminate the
//!   erasure model the run is trying to hold. A finite rate keeps the
//!   bandwidth-delay product finite and the backlog inside `limit`.
//!
//! # Reading the result
//!
//! [`Shaper::counters`] reads back what each netem actually did, in the two
//! different units [`Counters`] documents. Neither is the loss the connections
//! saw. That number is the server's own: `lost_packets` over `sent_packets` on
//! every closing line, which is per QUIC packet and directional -- and the
//! stronger check is the two put together, `sent_packets` minus the datagrams
//! the downlink netem delivered, since one comes from the server's accounting
//! and the other from the kernel's with nothing in common between them.
//!
//! A loss draw count far above the configured share of the traffic means the
//! backlog overflowed rather than the model firing, and `limit` or `rate` needs
//! raising: the run would be measuring congestion it did not intend to create.
//!
//! # Requirements
//!
//! Linux, `iproute2`, and `CAP_NET_ADMIN` -- so, in this tree, a container:
//!
//! ```sh
//! docker run --rm --cap-add=NET_ADMIN ... rust:1 ...
//! ```
//!
//! [`Shaper::install`] panics rather than degrading if any of that is missing. A
//! replay that believes it is lossy and is not would report the loopback result
//! under a lossy heading, which is worse than not running at all.

// The package-wide default is `deny` (`Cargo.toml`); this file argues for its
// allow: the link parameters are ones this module writes out itself.
#![allow(clippy::as_conversions)]

use std::process::Command;

/// The device every replay socket is on.
const DEVICE: &str = "lo";

/// One direction of the path.
#[derive(Clone, Debug, PartialEq)]
pub struct Direction {
    /// One-way delay. Half the round trip, since both directions carry it.
    pub delay_ms: f64,
    /// Standard deviation of the delay, normally distributed.
    pub jitter_ms: f64,
    /// Independent per-packet loss, as a percentage.
    pub loss_percent: f64,
    /// A `tc` rate, e.g. `100mbit`. Empty for no rate limit.
    pub rate: String,
}

/// A path to put under the replay.
#[derive(Clone, Debug, PartialEq)]
pub struct Spec {
    pub up: Direction,
    pub down: Direction,
    /// What `lo` is set to for the run. Restored afterwards.
    pub mtu: u32,
    /// Packets each netem may hold before it drops for want of room.
    pub limit: u32,
    /// The name this spec was asked for, for the run's own report.
    pub name: String,
}

impl Spec {
    /// The round trip this spec produces, both directions together.
    pub fn round_trip_ms(&self) -> f64 {
        self.up.delay_ms + self.down.delay_ms
    }

    /// Parses `VOLTO_REPLAY_NETEM`.
    ///
    /// The value is a comma-separated list. A bare word is a preset and seeds
    /// everything; a `key=value` overrides one field, and later tokens win, so
    /// `spike,rate=50mbit` is the spike preset on a slower link. `off`, or an
    /// empty value, is no shaping at all and yields `None`.
    ///
    /// | key | meaning |
    /// |---|---|
    /// | `rtt` | round trip in ms, split evenly between the directions |
    /// | `jitter` | delay standard deviation in ms, per direction |
    /// | `loss` | per-packet loss percentage, both directions |
    /// | `uploss` / `downloss` | the same, one direction only |
    /// | `rate` | a `tc` rate, both directions |
    /// | `uprate` / `downrate` | the same, one direction only |
    /// | `mtu` | what `lo` is set to for the run |
    /// | `limit` | packets one netem may hold |
    ///
    /// The presets are the two intensities the captured host actually shows,
    /// plus the far end of the same phenomenon:
    ///
    /// | preset | loss | where the number comes from |
    /// |---|---|---|
    /// | `steady` | 0.2% | the standing measured rate for this link (D33) |
    /// | `spike` | 13% | the p90 connection in `profiles/host-b.json` |
    /// | `severe` | 42% | the other intensity point D71 recorded |
    pub fn parse(text: &str) -> Result<Option<Self>, String> {
        let text = text.trim();
        if text.is_empty() || text.eq_ignore_ascii_case("off") || text == "0" {
            return Ok(None);
        }

        // Every preset is the same path at a different loss; only the loss moves.
        let preset = |loss: f64| Spec {
            up: Direction {
                delay_ms: 45.0,
                jitter_ms: 6.0,
                loss_percent: loss,
                rate: "100mbit".to_owned(),
            },
            down: Direction {
                delay_ms: 45.0,
                jitter_ms: 6.0,
                loss_percent: loss,
                rate: "100mbit".to_owned(),
            },
            mtu: 1500,
            limit: 20_000,
            name: text.to_owned(),
        };

        // Absent a preset the defaults are the path without its loss, so a bare
        // `rtt=90` is a clean 90 ms link rather than an error.
        let mut spec = preset(0.0);

        for token in text.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            let Some((key, value)) = token.split_once('=') else {
                match token {
                    "steady" => spec = preset(0.2),
                    "spike" => spec = preset(13.0),
                    "severe" => spec = preset(42.0),
                    "clean" => spec = preset(0.0),
                    other => {
                        return Err(format!(
                            "netem: `{other}` is neither a preset \
                             (clean, steady, spike, severe) nor a key=value"
                        ));
                    }
                }
                spec.name = text.to_owned();
                continue;
            };

            let number = |what: &str| -> Result<f64, String> {
                value
                    .parse::<f64>()
                    .map_err(|_| format!("netem: `{what}` wants a number, got `{value}`"))
            };

            match key.trim() {
                "rtt" => {
                    let half = number("rtt")? / 2.0;
                    spec.up.delay_ms = half;
                    spec.down.delay_ms = half;
                }
                "jitter" => {
                    let jitter = number("jitter")?;
                    spec.up.jitter_ms = jitter;
                    spec.down.jitter_ms = jitter;
                }
                "loss" => {
                    let loss = number("loss")?;
                    spec.up.loss_percent = loss;
                    spec.down.loss_percent = loss;
                }
                "uploss" => spec.up.loss_percent = number("uploss")?,
                "downloss" => spec.down.loss_percent = number("downloss")?,
                "rate" => {
                    spec.up.rate = value.to_owned();
                    spec.down.rate = value.to_owned();
                }
                "uprate" => spec.up.rate = value.to_owned(),
                "downrate" => spec.down.rate = value.to_owned(),
                "mtu" => spec.mtu = number("mtu")? as u32,
                "limit" => spec.limit = number("limit")? as u32,
                other => return Err(format!("netem: unknown key `{other}`")),
            }
        }

        Ok(Some(spec))
    }
}

/// What one netem did, read back off its own counters.
///
/// The two fields are **not in the same unit**, which is measured rather than
/// assumed -- a probe that sent 16 000 datagrams as 2 000 `UDP_SEGMENT` batches
/// through a netem asked for 13% loss reported `Sent 13888 pkt (dropped 264)`,
/// and 13 888 is exactly the datagram count that arrived while 264 is the number
/// of *batches* the loss model deleted (264 x 8 = 2 112 = 16 000 - 13 888). So
/// `delivered` counts datagrams after segmentation and `loss_draws` counts the
/// sender's batches, and dividing one by the other understates the loss by
/// whatever the average batch size is.
///
/// That is also why turning segmentation offload off does not make the loss
/// per-datagram: segmentation happens in `validate_xmit_skb`, downstream of the
/// qdisc, so netem draws on the batch however the device is configured. The
/// residual burstiness is the batch size, which a congestion controller under
/// loss keeps small -- around 1.5 datagrams in the runs this was built for.
#[derive(Clone, Copy, Debug, Default)]
pub struct Counters {
    /// Datagrams that came out the far side, counted after segmentation.
    pub delivered: u64,
    /// Loss draws the model took, each removing one sender batch.
    pub loss_draws: u64,
}

/// A qdisc tree installed on `lo`, removed again when this is dropped.
pub struct Shaper {
    spec: Spec,
    /// `lo`'s MTU before the run, to be put back.
    previous_mtu: Option<u32>,
    /// Whether offloads were turned off, and so should be turned back on.
    offloads_disabled: bool,
}

impl Shaper {
    /// Installs `spec` around the lab server's UDP `port`.
    ///
    /// Panics on anything missing or refused. See the module documentation for
    /// why this is not allowed to degrade to a no-op.
    pub fn install(spec: Spec, port: u16) -> Self {
        require_tc();

        // Any tree left behind by a run that died without unwinding would
        // silently take precedence over this one; `del` on an empty device is an
        // error, so its failure is not one.
        let _ = run(&["qdisc", "del", "dev", DEVICE, "root"]);

        let mut shaper = Self {
            spec,
            previous_mtu: None,
            offloads_disabled: false,
        };

        // One datagram per loss draw. Best effort: a kernel without one of these
        // features refuses the flag, and the run is still worth having -- but it
        // is worth knowing about, so it is said out loud rather than swallowed.
        match Command::new("ethtool")
            .args(["-K", DEVICE, "gso", "off", "tso", "off"])
            .output()
        {
            Ok(output) if output.status.success() => {
                let _ = Command::new("ethtool")
                    .args(["-K", DEVICE, "tx-udp-segmentation", "off"])
                    .output();
                shaper.offloads_disabled = true;
            }
            _ => eprintln!(
                "netem: could not turn segmentation offload off on {DEVICE}; \
                 loss will be applied per GSO batch rather than per datagram"
            ),
        }

        shaper.previous_mtu = read_mtu();
        set_mtu(shaper.spec.mtu);

        // Band 1 is a plain pfifo and the priomap sends everything there, so
        // nothing reaches a netem except by way of a filter below.
        run_or_panic(&[
            "qdisc", "add", "dev", DEVICE, "root", "handle", "1:", "prio", "bands", "4", "priomap",
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
        ]);

        // Installing any root qdisc on `lo` replaces `noqueue`, so the traffic
        // this module is *not* shaping -- the server's TCP to the echo targets --
        // acquires a queue it did not have, and the default one is `lo`'s
        // 1000-packet transmit queue. A loopback sender outruns that in a burst,
        // and the resulting drops would be an artefact of the shaping showing up
        // on the hop the shaping deliberately leaves alone. A generous pfifo on
        // band 1 keeps that hop behaving as it did with no qdisc at all.
        run_or_panic(&[
            "qdisc", "add", "dev", DEVICE, "parent", "1:1", "handle", "10:", "pfifo", "limit",
            "100000",
        ]);

        add_netem(&shaper.spec.up, "1:3", "30:", shaper.spec.limit);
        add_netem(&shaper.spec.down, "1:4", "40:", shaper.spec.limit);

        // `dport` is the client talking to the server, `sport` the server
        // answering. Nothing else on the device carries this port, so the pair
        // is exactly the QUIC connection and nothing besides.
        add_filter("dport", port, "1:3");
        add_filter("sport", port, "1:4");

        shaper
    }

    pub fn spec(&self) -> &Spec {
        &self.spec
    }

    /// Reads the two netems' counters. Uplink first, then downlink.
    pub fn counters(&self) -> (Counters, Counters) {
        let text = String::from_utf8_lossy(
            &Command::new("tc")
                .args(["-s", "qdisc", "show", "dev", DEVICE])
                .output()
                .expect("tc must run")
                .stdout,
        )
        .into_owned();

        (parse_counters(&text, "30:"), parse_counters(&text, "40:"))
    }
}

impl Drop for Shaper {
    fn drop(&mut self) {
        let _ = run(&["qdisc", "del", "dev", DEVICE, "root"]);
        if let Some(mtu) = self.previous_mtu {
            set_mtu(mtu);
        }
        if self.offloads_disabled {
            let _ = Command::new("ethtool")
                .args(["-K", DEVICE, "gso", "on", "tso", "on"])
                .output();
        }
    }
}

// --------------------------------------------------------------------------
// Talking to iproute2
// --------------------------------------------------------------------------

fn require_tc() {
    let available = Command::new("tc")
        .arg("-V")
        .output()
        .is_ok_and(|output| output.status.success());
    assert!(
        available,
        "netem was asked for but `tc` will not run. A shaped replay needs \
         Linux, iproute2 and CAP_NET_ADMIN -- see tests/replay/lossy-lab.sh, \
         which supplies all three. Refusing to run unshaped under a shaped \
         heading."
    );
}

fn run(args: &[&str]) -> Result<(), String> {
    let output = Command::new("tc")
        .args(args)
        .output()
        .map_err(|error| format!("tc {}: {error}", args.join(" ")))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "tc {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn run_or_panic(args: &[&str]) {
    if let Err(error) = run(args) {
        panic!("{error}");
    }
}

fn add_netem(direction: &Direction, parent: &str, handle: &str, limit: u32) {
    let mut args: Vec<String> = ["qdisc", "add", "dev", DEVICE, "parent", parent, "handle"]
        .iter()
        .map(|part| (*part).to_owned())
        .collect();
    args.push(handle.to_owned());
    args.push("netem".to_owned());
    args.push("limit".to_owned());
    args.push(limit.to_string());

    args.push("delay".to_owned());
    args.push(format!("{}ms", direction.delay_ms));
    if direction.jitter_ms > 0.0 {
        args.push(format!("{}ms", direction.jitter_ms));
        args.push("distribution".to_owned());
        args.push("normal".to_owned());
    }

    // `loss 0%` is accepted but says nothing; leaving it out keeps the qdisc
    // dump readable, which is what a run's own report quotes.
    if direction.loss_percent > 0.0 {
        args.push("loss".to_owned());
        args.push(format!("{}%", direction.loss_percent));
    }

    if !direction.rate.is_empty() {
        args.push("rate".to_owned());
        args.push(direction.rate.clone());
    }

    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    run_or_panic(&borrowed);
}

fn add_filter(port_side: &str, port: u16, flowid: &str) {
    let port = port.to_string();
    run_or_panic(&[
        "filter", "add", "dev", DEVICE, "protocol", "ip", "parent", "1:", "prio", "1", "u32",
        // UDP only, and then the port half of the four-tuple.
        "match", "ip", "protocol", "17", "0xff", "match", "ip", port_side, &port, "0xffff",
        "flowid", flowid,
    ]);
}

fn read_mtu() -> Option<u32> {
    let output = Command::new("ip")
        .args(["link", "show", DEVICE])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let rest = text.split(" mtu ").nth(1)?;
    rest.split_whitespace().next()?.parse().ok()
}

fn set_mtu(mtu: u32) {
    let output = Command::new("ip")
        .args(["link", "set", "dev", DEVICE, "mtu", &mtu.to_string()])
        .output()
        .expect("ip must run");
    assert!(
        output.status.success(),
        "could not set {DEVICE}'s MTU to {mtu}: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
}

/// Pulls one netem's `Sent ... pkt (dropped ...` line out of a `tc -s` dump.
fn parse_counters(dump: &str, handle: &str) -> Counters {
    let mut lines = dump.lines();
    while let Some(line) = lines.next() {
        if !(line.contains("qdisc netem") && line.contains(handle)) {
            continue;
        }
        let Some(stats) = lines.next() else {
            break;
        };
        let delivered = stats
            .split_whitespace()
            .zip(stats.split_whitespace().skip(1))
            .find(|(_, next)| *next == "pkt")
            .and_then(|(value, _)| value.parse().ok())
            .unwrap_or(0);
        let loss_draws = stats
            .split_once("(dropped ")
            .and_then(|(_, rest)| rest.split(&[',', ' '][..]).next())
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        return Counters {
            delivered,
            loss_draws,
        };
    }
    Counters::default()
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_is_no_shaping() {
        assert_eq!(Spec::parse("").expect("parses"), None);
        assert_eq!(Spec::parse("off").expect("parses"), None);
        assert_eq!(Spec::parse("  OFF  ").expect("parses"), None);
    }

    #[test]
    fn presets_differ_only_in_loss() {
        let steady = Spec::parse("steady").expect("parses").expect("a spec");
        let spike = Spec::parse("spike").expect("parses").expect("a spec");

        assert_eq!(steady.round_trip_ms(), 90.0);
        assert_eq!(spike.round_trip_ms(), 90.0);
        assert_eq!(steady.up.loss_percent, 0.2);
        assert_eq!(spike.up.loss_percent, 13.0);
        assert_eq!(steady.down.rate, spike.down.rate);
        assert_eq!(steady.mtu, spike.mtu);
    }

    #[test]
    fn a_round_trip_is_split_between_the_directions() {
        let spec = Spec::parse("rtt=80").expect("parses").expect("a spec");
        assert_eq!(spec.up.delay_ms, 40.0);
        assert_eq!(spec.down.delay_ms, 40.0);
        assert_eq!(spec.round_trip_ms(), 80.0);
    }

    #[test]
    fn later_tokens_override_the_preset() {
        let spec = Spec::parse("spike,downloss=42,rate=50mbit,mtu=1400")
            .expect("parses")
            .expect("a spec");
        assert_eq!(spec.up.loss_percent, 13.0);
        assert_eq!(spec.down.loss_percent, 42.0);
        assert_eq!(spec.up.rate, "50mbit");
        assert_eq!(spec.mtu, 1400);
    }

    #[test]
    fn a_typo_is_refused_rather_than_ignored() {
        assert!(Spec::parse("spke").is_err());
        assert!(Spec::parse("loss=lots").is_err());
        assert!(Spec::parse("lsos=1").is_err());
    }

    #[test]
    fn counters_come_off_a_tc_dump() {
        let dump = "\
qdisc prio 1: root refcnt 2 bands 4 priomap 0 0 0 0
 Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0)
 backlog 0b 0p requeues 0
qdisc netem 30: parent 1:3 limit 20000 delay 45ms 6ms loss 0.2% rate 100Mbit
 Sent 24786594 bytes 19957 pkt (dropped 43, overlimits 0 requeues 0)
 backlog 0b 0p requeues 0
qdisc netem 40: parent 1:4 limit 20000 delay 45ms 6ms loss 13% rate 100Mbit
 Sent 12000 bytes 100 pkt (dropped 15, overlimits 0 requeues 0)
 backlog 0b 0p requeues 0
";
        let up = parse_counters(dump, "30:");
        assert_eq!((up.delivered, up.loss_draws), (19957, 43));

        let down = parse_counters(dump, "40:");
        assert_eq!((down.delivered, down.loss_draws), (100, 15));

        assert_eq!(parse_counters(dump, "99:").delivered, 0);
    }
}
