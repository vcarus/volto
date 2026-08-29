//! Reading a traffic shape profile, and turning it into a plan.
//!
//! The profile is what `tests/replay/shape_extract.py` distils out of a
//! production log: distributions, not events. This module reads one, samples
//! from it with a seeded generator, and produces the schedule `it_replay` then
//! drives -- when each connection starts, how long it works, how it ends, and
//! what its tunnels look like.
//!
//! # Why the JSON reader is here
//!
//! `volto` has no JSON dependency and this harness does not justify adding one:
//! it reads one file, written by a script in this same directory, whose shape it
//! knows. The reader below is the subset that file uses. The same argument the
//! tree already makes for its hand-rolled varints and its hand-rolled Base64.
//!
//! # What the sampler is
//!
//! A histogram in the profile is a list of `[lower bound, count]` pairs. A
//! sample picks a bucket in proportion to its count, then a value uniformly
//! inside it. That reproduces the shape of a distribution -- including its tail,
//! which is where every interesting connection in this data lives -- without
//! storing the values themselves, and it is stable under a seed, so a run that
//! finds something can be run again.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fmt;

// --------------------------------------------------------------------------
// JSON
// --------------------------------------------------------------------------

/// A JSON value, in the subset a shape profile uses.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Number(f64),
    Str(String),
    Array(Vec<Json>),
    Object(BTreeMap<String, Json>),
}

impl Json {
    /// Parses a whole document, which must be one value and nothing after it.
    pub fn parse(text: &str) -> Result<Self, String> {
        let bytes = text.as_bytes();
        let mut parser = Parser { bytes, at: 0 };
        let value = parser.value()?;
        parser.spaces();
        if parser.at != bytes.len() {
            return Err(format!("trailing input at byte {}", parser.at));
        }
        Ok(value)
    }

    /// The value under `key`, for an object.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(entries) => entries.get(key),
            _ => None,
        }
    }

    /// The value at a slash-separated path, panicking with the path if absent.
    ///
    /// Panicking rather than returning an error on purpose: a profile missing a
    /// field the planner needs is a broken input, and the useful report is
    /// which field, not a chain of `?`.
    #[track_caller]
    pub fn at(&self, path: &str) -> &Json {
        self.maybe(path)
            .unwrap_or_else(|| panic!("the profile has no `{path}`"))
    }

    /// [`Self::at`] for a path a profile is allowed not to have.
    ///
    /// The extractor leaves out what it could not measure -- a capture with no
    /// restart bursts has no burst-size histogram -- rather than writing an
    /// empty one, so a reader has to be able to ask.
    pub fn maybe(&self, path: &str) -> Option<&Json> {
        let mut here = self;
        for step in path.split('/') {
            here = here.get(step)?;
        }
        Some(here)
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Json::Number(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(values) => Some(values),
            _ => None,
        }
    }

    /// The number at `path`, panicking if it is missing or not a number.
    #[track_caller]
    pub fn number(&self, path: &str) -> f64 {
        self.at(path)
            .as_f64()
            .unwrap_or_else(|| panic!("`{path}` is not a number"))
    }

    /// Every `key -> number` pair of an object, for the share tables.
    pub fn number_map(&self, path: &str) -> Vec<(String, f64)> {
        match self.at(path) {
            Json::Object(entries) => entries
                .iter()
                .filter_map(|(key, value)| value.as_f64().map(|number| (key.clone(), number)))
                .collect(),
            other => panic!("`{path}` is {other:?}, not an object"),
        }
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Parser<'_> {
    fn spaces(&mut self) {
        while self
            .bytes
            .get(self.at)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
        {
            self.at += 1;
        }
    }

    fn eat(&mut self, byte: u8) -> Result<(), String> {
        if self.bytes.get(self.at) == Some(&byte) {
            self.at += 1;
            Ok(())
        } else {
            Err(format!(
                "expected `{}` at byte {}",
                char::from(byte),
                self.at
            ))
        }
    }

    fn literal(&mut self, word: &str) -> Result<(), String> {
        if self.bytes[self.at.min(self.bytes.len())..].starts_with(word.as_bytes()) {
            self.at += word.len();
            Ok(())
        } else {
            Err(format!("expected `{word}` at byte {}", self.at))
        }
    }

    fn value(&mut self) -> Result<Json, String> {
        self.spaces();
        match self.bytes.get(self.at) {
            None => Err("input ended where a value was expected".to_owned()),
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => self.string().map(Json::Str),
            Some(b't') => self.literal("true").map(|()| Json::Bool(true)),
            Some(b'f') => self.literal("false").map(|()| Json::Bool(false)),
            Some(b'n') => self.literal("null").map(|()| Json::Null),
            Some(_) => self.number(),
        }
    }

    fn object(&mut self) -> Result<Json, String> {
        self.eat(b'{')?;
        let mut entries = BTreeMap::new();
        self.spaces();
        if self.bytes.get(self.at) == Some(&b'}') {
            self.at += 1;
            return Ok(Json::Object(entries));
        }
        loop {
            self.spaces();
            let key = self.string()?;
            self.spaces();
            self.eat(b':')?;
            let value = self.value()?;
            entries.insert(key, value);
            self.spaces();
            match self.bytes.get(self.at) {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Json::Object(entries));
                }
                _ => return Err(format!("expected `,` or `}}` at byte {}", self.at)),
            }
        }
    }

    fn array(&mut self) -> Result<Json, String> {
        self.eat(b'[')?;
        let mut values = Vec::new();
        self.spaces();
        if self.bytes.get(self.at) == Some(&b']') {
            self.at += 1;
            return Ok(Json::Array(values));
        }
        loop {
            values.push(self.value()?);
            self.spaces();
            match self.bytes.get(self.at) {
                Some(b',') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    return Ok(Json::Array(values));
                }
                _ => return Err(format!("expected `,` or `]` at byte {}", self.at)),
            }
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.eat(b'"')?;
        let mut out = String::new();
        loop {
            let byte = *self
                .bytes
                .get(self.at)
                .ok_or_else(|| "input ended inside a string".to_owned())?;
            self.at += 1;
            match byte {
                b'"' => return Ok(out),
                b'\\' => {
                    let escape = *self
                        .bytes
                        .get(self.at)
                        .ok_or_else(|| "input ended inside an escape".to_owned())?;
                    self.at += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let digits = self
                                .bytes
                                .get(self.at..self.at + 4)
                                .ok_or_else(|| "a short \\u escape".to_owned())?;
                            let text = std::str::from_utf8(digits)
                                .map_err(|_| "a \\u escape that is not hex".to_owned())?;
                            let point = u32::from_str_radix(text, 16)
                                .map_err(|_| "a \\u escape that is not hex".to_owned())?;
                            // Only the basic plane: a profile carries ASCII, and
                            // a surrogate pair here would be a sign the file is
                            // not one.
                            out.push(
                                char::from_u32(point)
                                    .ok_or_else(|| "a \\u escape outside the BMP".to_owned())?,
                            );
                            self.at += 4;
                        }
                        other => return Err(format!("unknown escape `\\{}`", char::from(other))),
                    }
                }
                other => {
                    // The input is already `&str`, so a multi-byte sequence is
                    // valid UTF-8 by construction; copy it through unchanged.
                    let start = self.at - 1;
                    let mut end = self.at;
                    if other >= 0x80 {
                        while self.bytes.get(end).is_some_and(|b| b & 0xc0 == 0x80) {
                            end += 1;
                        }
                        self.at = end;
                    }
                    out.push_str(
                        std::str::from_utf8(&self.bytes[start..end.max(start + 1)])
                            .map_err(|_| "invalid UTF-8 in a string".to_owned())?,
                    );
                }
            }
        }
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.at;
        while self
            .bytes
            .get(self.at)
            .is_some_and(|byte| matches!(byte, b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E'))
        {
            self.at += 1;
        }
        let text = std::str::from_utf8(&self.bytes[start..self.at])
            .map_err(|_| "a number that is not UTF-8".to_owned())?;
        text.parse::<f64>()
            .map(Json::Number)
            .map_err(|_| format!("`{text}` is not a number"))
    }
}

// --------------------------------------------------------------------------
// Sampling
// --------------------------------------------------------------------------

/// SplitMix64: a seeded generator with no dependency and no surprises.
///
/// Every number this harness needs comes from here, so a run is completely
/// determined by its seed: the same seed replays the same connections in the
/// same order with the same targets. That is the difference between a load test
/// and a reproducible experiment.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        // Any seed works, including zero: the constant below is added before
        // the first mix, so the sequence never starts from a fixed point.
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A value in `[0, 1)`.
    pub fn unit(&mut self) -> f64 {
        // 53 bits: the mantissa of an f64, so every value is representable and
        // the spacing is uniform.
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// A value in `[low, high)`, or `low` when the range is empty.
    pub fn range(&mut self, low: f64, high: f64) -> f64 {
        if high <= low {
            low
        } else {
            low + self.unit() * (high - low)
        }
    }

    /// A value in `0..limit`.
    pub fn below(&mut self, limit: usize) -> usize {
        if limit == 0 {
            0
        } else {
            (self.next_u64() % limit as u64) as usize
        }
    }

    /// Whether an event of probability `chance` happens.
    pub fn chance(&mut self, chance: f64) -> bool {
        self.unit() < chance
    }
}

/// A distribution read back out of a profile.
#[derive(Debug, Clone)]
pub struct Histogram {
    /// `(lower bound, cumulative count)`, ascending.
    cumulative: Vec<(f64, u64)>,
    /// The lower bounds again, so a bucket's upper edge is the next one's lower.
    edges: Vec<f64>,
    total: u64,
    max: f64,
    empty_value: f64,
}

impl Histogram {
    /// [`Self::read`] for a summary the profile may not carry at all.
    pub fn read_maybe(summary: Option<&Json>, empty_value: f64) -> Self {
        match summary {
            Some(summary) => Self::read(summary, empty_value),
            None => Self {
                cumulative: Vec::new(),
                edges: Vec::new(),
                total: 0,
                max: 0.0,
                empty_value,
            },
        }
    }

    /// Reads the `buckets` list of a summary, or an empty distribution.
    ///
    /// `empty_value` is what an empty distribution samples: a quantity the
    /// capture never recorded (a release too old to log it) should not stop a
    /// replay, it should fall back to something stated.
    pub fn read(summary: &Json, empty_value: f64) -> Self {
        let max = summary.get("max").and_then(Json::as_f64).unwrap_or(0.0);
        let mut cumulative = Vec::new();
        let mut edges = Vec::new();
        let mut running = 0u64;

        if let Some(buckets) = summary.get("buckets").and_then(Json::as_array) {
            for bucket in buckets {
                let pair = bucket
                    .as_array()
                    .expect("a bucket is a [bound, count] pair");
                let bound = pair[0].as_f64().expect("a bucket bound is a number");
                let count = pair[1].as_f64().expect("a bucket count is a number") as u64;
                running += count;
                edges.push(bound);
                cumulative.push((bound, running));
            }
        }

        Self {
            cumulative,
            edges,
            total: running,
            max,
            empty_value,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    /// One sample: a bucket in proportion to its count, uniform inside it.
    pub fn sample(&self, rng: &mut Rng) -> f64 {
        if self.total == 0 {
            return self.empty_value;
        }

        let pick = rng.next_u64() % self.total;
        let index = self
            .cumulative
            .partition_point(|(_, running)| *running <= pick);
        let index = index.min(self.cumulative.len() - 1);

        let low = self.edges[index];
        let high = self
            .edges
            .get(index + 1)
            .copied()
            .unwrap_or_else(|| self.max.max(low));
        rng.range(low, high)
    }

    /// A sample rounded to a whole number, which is what counts want.
    pub fn sample_u64(&self, rng: &mut Rng) -> u64 {
        self.sample(rng).max(0.0).round() as u64
    }
}

/// A weighted choice over named outcomes, e.g. the close-reason mix.
pub struct Choice {
    weights: Vec<(String, f64)>,
    total: f64,
}

impl Choice {
    pub fn new(weights: Vec<(String, f64)>) -> Self {
        let total = weights.iter().map(|(_, weight)| weight).sum();
        Self { weights, total }
    }

    pub fn pick(&self, rng: &mut Rng) -> &str {
        if self.total <= 0.0 {
            return "";
        }
        let mut pick = rng.unit() * self.total;
        for (name, weight) in &self.weights {
            pick -= weight;
            if pick <= 0.0 {
                return name;
            }
        }
        &self.weights[self.weights.len() - 1].0
    }
}

// --------------------------------------------------------------------------
// The fan-out model
// --------------------------------------------------------------------------

/// How a connection's tunnels spread over distinct targets.
///
/// Built from the profile's rarefaction curve -- "after n tunnels, a connection
/// had touched this many distinct targets on average". The curve is turned into
/// a probability that the *next* tunnel goes somewhere new, which is all a
/// generator needs: `p_new(n) = distinct(n + 1) - distinct(n)`, interpolated
/// between the measured points and extrapolated past the last one by holding
/// the final slope.
pub struct FanOut {
    /// `(n, mean distinct)`, ascending in n.
    curve: Vec<(f64, f64)>,
    /// Share of tunnels the single most popular target takes, used to bias
    /// reuse towards a few targets rather than spreading it evenly.
    top_share: f64,
}

impl FanOut {
    pub fn read(profile: &Json) -> Self {
        let mut curve = Vec::new();
        for point in profile
            .at("tunnels/fanout/curve")
            .as_array()
            .expect("the fan-out curve is a list")
        {
            let point = point.as_array().expect("a curve point is a list");
            curve.push((
                point[0].as_f64().expect("n is a number"),
                point[1].as_f64().expect("distinct is a number"),
            ));
        }
        curve.sort_by(|a, b| a.0.total_cmp(&b.0));

        let top_share = profile
            .at("tunnels/popularity/share_of_tunnels")
            .get("top_1")
            .and_then(Json::as_f64)
            .unwrap_or(0.1);

        Self { curve, top_share }
    }

    /// Mean distinct targets after `n` tunnels, interpolated.
    fn distinct(&self, n: f64) -> f64 {
        if self.curve.is_empty() {
            return n;
        }
        if n <= self.curve[0].0 {
            return self.curve[0].1 * (n / self.curve[0].0).max(0.0);
        }
        for pair in self.curve.windows(2) {
            let (x0, y0) = pair[0];
            let (x1, y1) = pair[1];
            if n <= x1 {
                return y0 + (y1 - y0) * (n - x0) / (x1 - x0);
            }
        }
        // Past the measured range, hold the last slope rather than flatten: a
        // connection that keeps going keeps finding new targets, just slowly.
        let (x0, y0) = self.curve[self.curve.len() - 2];
        let (x1, y1) = self.curve[self.curve.len() - 1];
        let slope = (y1 - y0) / (x1 - x0);
        y1 + slope * (n - x1)
    }

    /// Whether tunnel number `seen + 1` should go to a target not yet used.
    pub fn wants_new_target(&self, seen: usize, rng: &mut Rng) -> bool {
        let n = seen as f64;
        let chance = (self.distinct(n + 1.0) - self.distinct(n)).clamp(0.0, 1.0);
        rng.chance(chance)
    }

    /// Which already-used target to go back to.
    ///
    /// Weighted towards the first few a connection touched, because that is what
    /// the popularity table says production looks like: one target takes about a
    /// seventh of all tunnels and ten take two thirds. A uniform pick would give
    /// every target the same rate and make the replay's target set look like a
    /// scan rather than like someone browsing.
    pub fn revisit(&self, used: usize, rng: &mut Rng) -> usize {
        if used <= 1 {
            return 0;
        }
        if rng.chance(self.top_share.clamp(0.0, 0.9)) {
            return 0;
        }
        // Otherwise a square-biased pick: still tilted towards the earlier
        // entries, without collapsing onto them.
        let draw = rng.unit() * rng.unit();
        ((draw * used as f64) as usize).min(used - 1)
    }
}

// --------------------------------------------------------------------------
// The plan
// --------------------------------------------------------------------------

/// How a replayed connection is meant to end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ending {
    /// The client stops using the connection and says nothing: the server's
    /// idle timer reclaims it. What Surge does on a network switch or app exit.
    Idle,
    /// A clean application close with code 0, which is what Surge sends when it
    /// closes a connection on purpose.
    PeerClose,
    /// An application close with H3_GENERAL_PROTOCOL_ERROR: the peer reporting
    /// that this server broke the protocol.
    ProtocolViolation,
    /// Left open, to be caught by the server's shutdown at the end of the run.
    Outlive,
}

impl fmt::Display for Ending {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Ending::Idle => "idle",
            Ending::PeerClose => "peer_close",
            Ending::ProtocolViolation => "protocol_violation",
            Ending::Outlive => "outlive",
        })
    }
}

/// What a replayed tunnel does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelKind {
    /// CONNECT to a name that resolves, then an echo of `bytes`.
    Tcp,
    /// CONNECT to an address literal, which costs no name lookup (D90).
    TcpLiteral,
    /// CONNECT-UDP, then datagram round trips.
    Udp,
    /// A target every address of which is the unspecified one: accepted and
    /// closed on the spot (D49).
    Blackhole,
}

/// One tunnel in the plan.
#[derive(Debug, Clone)]
pub struct TunnelPlan {
    /// Milliseconds after this connection opened.
    ///
    /// An offset rather than a gap, so that a compressed gap shorter than the
    /// runtime's timer resolution costs nothing: two tunnels whose production
    /// spacing compresses below a millisecond land on the same offset and go
    /// out back to back, instead of each being rounded up to a millisecond and
    /// stretching the connection to several times its length.
    pub at_ms: u64,
    pub kind: TunnelKind,
    /// Index into the connection's own target list, so repeats are repeats.
    pub target: usize,
    /// Bytes to push through, already capped.
    pub bytes: u32,
}

/// One connection in the plan.
#[derive(Debug, Clone)]
pub struct ConnectionPlan {
    /// Milliseconds after the start of the run.
    pub start_ms: u64,
    /// How long the client keeps working on it.
    pub active_ms: u64,
    pub ending: Ending,
    pub tunnels: Vec<TunnelPlan>,
    /// How many distinct targets this connection's tunnels use.
    pub targets: usize,
    /// Whether this connection is one of a restart burst, and so aborts a
    /// predecessor mid-transfer when it starts.
    pub in_burst: bool,
}

/// Everything the planner was told, kept so the report can print it.
#[derive(Debug, Clone, Copy)]
pub struct Scaling {
    /// Wall-clock seconds the run is allowed.
    pub wall_seconds: u64,
    /// How much production time one second of the run stands for.
    pub compression: f64,
    /// The lab server's idle timeout, in seconds.
    pub idle_seconds: u64,
    /// The idle timeout in force when the capture was taken, in seconds.
    /// Subtracted from an idle-ended connection's lifetime, because that
    /// lifetime includes the whole wait for the timer that ended it.
    ///
    /// The *effective* one, not the configured one: RFC 9000 §10.1 makes it the
    /// minimum of what the two endpoints advertise, and the client advertises
    /// less than this server does (see `DEFAULT_MAX_IDLE_TIMEOUT`).
    pub production_idle_seconds: u64,
    /// Largest transfer a single tunnel is asked for.
    pub max_transfer: u32,
    /// Most tunnels one connection is asked for.
    pub max_tunnels: u64,
}

/// What the planner had to bend to fit the run, reported alongside the results.
#[derive(Debug, Clone, Copy, Default)]
pub struct Compromises {
    /// Connections whose sampled tunnel count was above `max_tunnels`.
    pub tunnel_counts_capped: u64,
    /// Tunnels whose sampled byte count was above `max_transfer`.
    pub transfers_capped: u64,
    /// Tunnels whose compressed spacing rounded down to nothing, so they go out
    /// together instead of at their own moment.
    pub spacings_collapsed: u64,
    /// Tunnels dropped because the connection ran out of its active window.
    pub tunnels_past_window: u64,
    /// Connections planned from the joint table rather than from the marginals.
    pub from_joint_table: u64,
}

pub struct Plan {
    pub connections: Vec<ConnectionPlan>,
    pub scaling: Scaling,
    pub compromises: Compromises,
    pub fanout: FanOut,
}

/// One row of the profile's `(outcome, lifetime, tunnels)` contingency table.
///
/// Drawing a connection's ending, lifetime and tunnel count from one row rather
/// than from three separate distributions is what keeps the plan inside the
/// space production actually occupies: an idle close never lands on a
/// forty-millisecond connection, and ten thousand tunnels never land inside a
/// one-second window, because no production connection did either.
struct JointRow {
    outcome: String,
    lifetime_low: f64,
    lifetime_high: f64,
    tunnels_low: f64,
    tunnels_high: f64,
    count: f64,
}

struct JointTable {
    rows: Vec<JointRow>,
    total: f64,
}

impl JointTable {
    fn read(profile: &Json) -> Self {
        let mut rows = Vec::new();
        let mut total = 0.0;

        if let Some(list) = profile
            .maybe("connections/joint/rows")
            .and_then(Json::as_array)
        {
            for row in list {
                let row = row.as_array().expect("a joint row is a list");
                let count = row[5].as_f64().expect("a joint count is a number");
                total += count;
                rows.push(JointRow {
                    outcome: row[0].as_str().expect("an outcome is a string").to_owned(),
                    lifetime_low: row[1].as_f64().expect("a number"),
                    lifetime_high: row[2].as_f64().expect("a number"),
                    tunnels_low: row[3].as_f64().expect("a number"),
                    tunnels_high: row[4].as_f64().expect("a number"),
                    count,
                });
            }
        }

        Self { rows, total }
    }

    fn draw(&self, rng: &mut Rng) -> Option<(&str, f64, f64)> {
        if self.total <= 0.0 {
            return None;
        }
        let mut pick = rng.unit() * self.total;
        for row in &self.rows {
            pick -= row.count;
            if pick <= 0.0 {
                return Some((
                    &row.outcome,
                    rng.range(row.lifetime_low, row.lifetime_high),
                    rng.range(row.tunnels_low, row.tunnels_high),
                ));
            }
        }
        let last = self.rows.last()?;
        Some((&last.outcome, last.lifetime_low, last.tunnels_low))
    }
}

fn ending_of(outcome: &str) -> Ending {
    match outcome {
        "protocol_violation" => Ending::ProtocolViolation,
        "peer_close" | "server_shutdown" | "other_error" => Ending::PeerClose,
        "drained" => Ending::Outlive,
        _ => Ending::Idle,
    }
}

/// Builds the schedule a run follows.
pub fn plan(profile: &Json, scaling: Scaling, seed: u64) -> Plan {
    let mut rng = Rng::new(seed);

    let interarrival = Histogram::read(profile.at("connections/interarrival"), 1000.0);
    let lifetime = Histogram::read(profile.at("connections/lifetime"), 60_000.0);
    let per_connection = Histogram::read(profile.at("tunnels/per_connection"), 1.0);
    let spacing = Histogram::read(profile.at("tunnels/spacing_within_connection/gap"), 1_000.0);
    let transfer = Histogram::read(profile.at("tunnels/transport_bytes_per_tunnel"), 4_096.0);

    // The preferred source for a connection's ending, lifetime and tunnel
    // count. The three marginals above stay as the fallback for a capture whose
    // releases were too old to log a tunnel count, where the table is empty.
    let table = JointTable::read(profile);
    let outcomes = Choice::new(profile.number_map("connections/outcome_share"));
    let fanout = FanOut::read(profile);

    let udp_share = profile.number("tunnels/udp_share_of_established");
    let blackhole_share = profile.number("tunnels/blackhole_share_of_attempts");
    let literal_share = profile.number("tunnels/literal_share_of_attempts");

    // A restart burst per this many connections, and how big one is. Both come
    // straight out of the profile; a capture with no bursts produces none.
    let burst_count = profile.number("restarts/client_bursts/bursts");
    let connection_count = profile.number("connections/count");
    let burst_chance = if connection_count > 0.0 {
        burst_count / connection_count
    } else {
        0.0
    };
    let burst_size = Histogram::read_maybe(profile.maybe("restarts/client_bursts/size"), 4.0);

    let mut compromises = Compromises::default();
    let mut connections = Vec::new();
    let window_ms = scaling.wall_seconds * 1000;
    let mut now_ms = 0.0f64;
    let mut burst_left = 0u64;

    while (now_ms as u64) < window_ms {
        let in_burst = burst_left > 0;
        if burst_left > 0 {
            burst_left -= 1;
        } else if rng.chance(burst_chance) {
            // A burst is several connections arriving at once: the first is
            // this one, the rest follow immediately.
            burst_left = burst_size.sample_u64(&mut rng).saturating_sub(1).min(31);
        }

        let (ending, sampled_lifetime, wanted) = match table.draw(&mut rng) {
            Some((outcome, lifetime_ms, tunnels)) => {
                compromises.from_joint_table += 1;
                (
                    ending_of(outcome),
                    lifetime_ms,
                    tunnels.round().max(1.0) as u64,
                )
            }
            None => (
                ending_of(outcomes.pick(&mut rng)),
                lifetime.sample(&mut rng),
                per_connection.sample_u64(&mut rng).max(1),
            ),
        };

        // A production lifetime is established-to-closed. For a connection the
        // idle timer ended, that includes the whole wait for the timer, which
        // the replay serves with its own much shorter one -- so the wait is
        // taken off before the compression, leaving the part the client was
        // actually working. A floor of one production second under it, because
        // a connection that opened a tunnel was working for *some* time and the
        // bucket it was drawn from may sit below the timeout.
        let working = if ending == Ending::Idle {
            (sampled_lifetime - (scaling.production_idle_seconds * 1000) as f64).max(1000.0)
        } else {
            sampled_lifetime
        };
        let active_ms = (working / scaling.compression).round().max(1.0) as u64;

        let tunnel_count = if wanted > scaling.max_tunnels {
            compromises.tunnel_counts_capped += 1;
            scaling.max_tunnels
        } else {
            wanted
        };

        let mut tunnels = Vec::new();
        let mut targets = 0usize;
        // Kept as a float and only rounded at the end, so that a run of gaps
        // each below a millisecond still adds up to the milliseconds they are
        // worth instead of being lost or rounded up one by one.
        let mut offset_ms = 0.0f64;
        let mut previous_at = 0u64;
        for index in 0..tunnel_count {
            if index > 0 {
                offset_ms += spacing.sample(&mut rng) / scaling.compression;
            }
            let at_ms = offset_ms.round() as u64;
            if index > 0 && at_ms == previous_at {
                compromises.spacings_collapsed += 1;
            }
            previous_at = at_ms;

            if at_ms > active_ms {
                compromises.tunnels_past_window += tunnel_count - index;
                break;
            }

            let target = if targets == 0 || fanout.wants_new_target(index as usize, &mut rng) {
                targets += 1;
                targets - 1
            } else {
                fanout.revisit(targets, &mut rng)
            };

            let kind = if rng.chance(blackhole_share) {
                TunnelKind::Blackhole
            } else if rng.chance(udp_share) {
                TunnelKind::Udp
            } else if rng.chance(literal_share) {
                TunnelKind::TcpLiteral
            } else {
                TunnelKind::Tcp
            };

            let sampled_bytes = transfer.sample(&mut rng);
            let bytes = if sampled_bytes > scaling.max_transfer as f64 {
                compromises.transfers_capped += 1;
                scaling.max_transfer
            } else {
                sampled_bytes.max(1.0) as u32
            };

            tunnels.push(TunnelPlan {
                at_ms,
                kind,
                target,
                bytes,
            });
        }

        connections.push(ConnectionPlan {
            start_ms: now_ms as u64,
            active_ms,
            ending,
            tunnels,
            targets: targets.max(1),
            in_burst,
        });

        // Inside a burst the next connection follows at once; otherwise the
        // profile's own arrival gap decides.
        now_ms += if burst_left > 0 {
            rng.range(1.0, 25.0).round()
        } else {
            (interarrival.sample(&mut rng) / scaling.compression).max(1.0)
        };
    }

    Plan {
        connections,
        scaling,
        compromises,
        fanout,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_reads_the_shapes_a_profile_uses() {
        let value =
            Json::parse(r#"{"a": [1, 2.5, -3e2], "b": {"c": "x\ny"}, "d": true, "e": null}"#)
                .expect("parses");

        assert_eq!(
            value.at("a").as_array().expect("array")[2].as_f64(),
            Some(-300.0)
        );
        assert_eq!(value.at("b/c").as_str(), Some("x\ny"));
        assert_eq!(value.get("d"), Some(&Json::Bool(true)));
        assert_eq!(value.get("e"), Some(&Json::Null));
    }

    #[test]
    fn a_histogram_stays_inside_its_buckets() {
        let summary = Json::parse(r#"{"max": 400, "buckets": [[10, 3], [100, 1]]}"#).expect("json");
        let histogram = Histogram::read(&summary, 0.0);
        let mut rng = Rng::new(7);

        let mut low = 0;
        for _ in 0..2000 {
            let value = histogram.sample(&mut rng);
            assert!(
                (10.0..=400.0).contains(&value),
                "{value} escaped the buckets"
            );
            if value < 100.0 {
                low += 1;
            }
        }
        // Three quarters of the mass is in the first bucket; a generator that
        // ignored the counts would land near half.
        assert!(
            (1300..1700).contains(&low),
            "{low} of 2000 in the low bucket"
        );
    }

    #[test]
    fn the_same_seed_replays_the_same_numbers() {
        let mut first = Rng::new(0x5eed);
        let mut second = Rng::new(0x5eed);
        for _ in 0..64 {
            assert_eq!(first.next_u64(), second.next_u64());
        }
    }
}
