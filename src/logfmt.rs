//! Formatting helpers for log fields.
//!
//! Operator-facing fields print the value, never Rust's `Option` spelling: a line
//! reads `alpn=h3`, not `alpn=Some("h3")`. When the value is absent the field
//! still appears, carrying [`ABSENT`] — dropping it instead would make the shape
//! of the line depend on its contents, which is exactly what a `grep` or a log
//! shipper cannot cope with.
//!
//! The rule is about *audience*, not about level: `info`/`warn` lines are read by
//! whoever is running the server, so they print values. The `debug` forensic dump
//! in [`crate::conn`] deliberately keeps `Debug` shapes — there the Rust spelling
//! of a header map, or of an absent `:protocol`, *is* the evidence D3 is waiting
//! for.

use std::fmt;

/// What an absent value prints as.
pub const ABSENT: &str = "-";

/// Formats an optional log field: the value itself, or [`ABSENT`].
///
/// ```
/// # use volto::logfmt::or_dash;
/// assert_eq!(or_dash(Some("h3")).to_string(), "h3");
/// assert_eq!(or_dash(None::<&str>).to_string(), "-");
/// ```
pub fn or_dash<T: fmt::Display>(value: Option<T>) -> impl fmt::Display {
    /// Carries the option to the point tracing actually formats the field, so
    /// nothing is allocated for a field that a filter discards.
    struct OrDash<T>(Option<T>);

    impl<T: fmt::Display> fmt::Display for OrDash<T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match &self.0 {
                Some(value) => value.fmt(f),
                None => f.write_str(ABSENT),
            }
        }
    }

    OrDash(value)
}

#[cfg(test)]
mod tests {
    use super::{or_dash, ABSENT};
    use std::net::SocketAddr;

    /// A value present prints as itself, with no wrapper and no quotes.
    #[test]
    fn a_present_value_prints_as_itself() {
        assert_eq!(or_dash(Some("h3")).to_string(), "h3");
        assert_eq!(
            or_dash(Some(String::from("localhost"))).to_string(),
            "localhost"
        );

        let address: SocketAddr = "127.0.0.1:443".parse().expect("address");
        assert_eq!(or_dash(Some(address)).to_string(), "127.0.0.1:443");
    }

    /// An absent value prints as the placeholder, so the field keeps its shape.
    #[test]
    fn an_absent_value_prints_as_the_placeholder() {
        assert_eq!(or_dash(None::<&str>).to_string(), ABSENT);
        assert_eq!(or_dash(None::<SocketAddr>).to_string(), ABSENT);
    }

    /// The placeholder is not something a real value could be confused with in a
    /// `grep`: it is one character, and none of the fields this is used on can
    /// produce it.
    #[test]
    fn the_placeholder_is_a_single_dash() {
        assert_eq!(ABSENT, "-");
    }
}
