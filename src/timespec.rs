//! Parsing of user-supplied durations (Key Vault rotation policies use
//! ISO-8601 durations) and timestamps (key expiry / not-before).

use anyhow::{bail, Context as _, Result};
use azure_core::time::{parse_rfc3339, Duration, OffsetDateTime};

/// Split "<digits><unit-char>" shorthand; returns (n, lowercase unit).
fn split_shorthand(s: &str) -> Option<(u32, char)> {
    let unit = s.chars().last()?;
    if !unit.is_ascii_alphabetic() {
        return None;
    }
    let n: u32 = s[..s.len() - 1].parse().ok()?;
    Some((n, unit.to_ascii_lowercase()))
}

/// Parse a policy duration: "<n>d" (days), "<n>m" (months), "<n>y" (years),
/// or a raw ISO-8601 duration like "P90D" (passed through uppercased).
/// Key Vault policies have no sub-day granularity.
#[allow(dead_code)] // used by key create/rotation tasks
pub fn policy_duration(s: &str) -> Result<String> {
    let t = s.trim();
    if t.len() > 1 && t.to_ascii_uppercase().starts_with('P') {
        return Ok(t.to_ascii_uppercase());
    }
    match split_shorthand(t) {
        Some((n, 'd')) if n > 0 => Ok(format!("P{n}D")),
        Some((n, 'm')) if n > 0 => Ok(format!("P{n}M")),
        Some((n, 'y')) if n > 0 => Ok(format!("P{n}Y")),
        _ => bail!(
            "invalid duration '{s}': expected <n>d, <n>m (months), <n>y, \
             or an ISO-8601 duration like P90D"
        ),
    }
}

/// Parse a timestamp: RFC-3339 datetime, bare date (midnight UTC), or
/// "+<n>d|m|y" relative to `now` (months ≈ 30 days, years ≈ 365 days).
#[allow(dead_code)] // used by key create/rotation tasks
pub fn timestamp(s: &str, now: OffsetDateTime) -> Result<OffsetDateTime> {
    let t = s.trim();
    if let Some(rest) = t.strip_prefix('+') {
        let days = match split_shorthand(rest) {
            Some((n, 'd')) if n > 0 => i64::from(n),
            Some((n, 'm')) if n > 0 => i64::from(n) * 30,
            Some((n, 'y')) if n > 0 => i64::from(n) * 365,
            _ => bail!("invalid relative time '{s}': expected +<n>d, +<n>m, or +<n>y"),
        };
        return Ok(now + Duration::days(days));
    }
    let full = if t.contains('T') {
        t.to_string()
    } else {
        format!("{t}T00:00:00Z")
    };
    parse_rfc3339(&full).with_context(|| {
        format!(
            "invalid timestamp '{s}': expected RFC-3339 (2027-01-01[T12:30:00Z]) or +<duration>"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> OffsetDateTime {
        // 2023-11-14T22:13:20Z
        OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap()
    }

    #[test]
    fn shorthand_durations() {
        assert_eq!(policy_duration("90d").unwrap(), "P90D");
        assert_eq!(policy_duration("3m").unwrap(), "P3M");
        assert_eq!(policy_duration("2y").unwrap(), "P2Y");
    }

    #[test]
    fn iso8601_passes_through_uppercased() {
        assert_eq!(policy_duration("P90D").unwrap(), "P90D");
        assert_eq!(policy_duration("p1y10d").unwrap(), "P1Y10D");
    }

    #[test]
    fn rejects_bad_durations() {
        for bad in ["", "d", "90", "90x", "-90d", "0d", "P"] {
            assert!(policy_duration(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn bare_date_is_midnight_utc() {
        let t = timestamp("2027-01-01", now()).unwrap();
        assert_eq!(t.unix_timestamp(), 1_798_761_600); // 2027-01-01T00:00:00Z
    }

    #[test]
    fn full_rfc3339_passes_through() {
        let t = timestamp("2027-01-01T12:30:00Z", now()).unwrap();
        assert_eq!(t.unix_timestamp(), 1_798_806_600);
    }

    #[test]
    fn relative_days_from_now() {
        let t = timestamp("+90d", now()).unwrap();
        assert_eq!(t - now(), Duration::days(90));
        // months = 30 days, years = 365 days (documented approximation)
        assert_eq!(timestamp("+3m", now()).unwrap() - now(), Duration::days(90));
        assert_eq!(
            timestamp("+1y", now()).unwrap() - now(),
            Duration::days(365)
        );
    }

    #[test]
    fn rejects_bad_timestamps() {
        for bad in ["", "tomorrow", "+90", "+x", "2027-13-40"] {
            assert!(timestamp(bad, now()).is_err(), "accepted {bad:?}");
        }
    }
}
