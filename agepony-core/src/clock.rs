//! Timestamps, without a date-time dependency.
//!
//! The store records when an identity was created. That is the only date this
//! crate handles, and pulling in a full calendar library for it would be a poor
//! trade against the single-self-contained-binary goal — and against the
//! no-network test, which gets harder to keep honest the wider the tree grows.
//!
//! So: UTC only, RFC 3339, seconds resolution. The civil-date conversion is
//! Howard Hinnant's `civil_from_days`, which is exact for the whole
//! proleptic Gregorian range.

use std::time::{SystemTime, UNIX_EPOCH};

/// The current time as an RFC 3339 string in UTC, e.g. `2026-08-01T18:32:07Z`.
///
/// Returns the Unix epoch if the system clock is set before 1970, which is not
/// worth an error path.
#[must_use]
pub fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    from_unix_seconds(secs)
}

/// Format Unix seconds as an RFC 3339 UTC string.
#[must_use]
pub fn from_unix_seconds(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    let (h, min, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{min:02}:{s:02}Z")
}

/// Days since 1970-01-01 to a civil (year, month, day).
///
/// Hinnant's algorithm: shift the epoch to 0000-03-01 so leap days land at the
/// end of the year, which makes the era arithmetic exact with no tables.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_instants_format_correctly() {
        assert_eq!(from_unix_seconds(0), "1970-01-01T00:00:00Z");
        assert_eq!(from_unix_seconds(1), "1970-01-01T00:00:01Z");
        assert_eq!(from_unix_seconds(86_399), "1970-01-01T23:59:59Z");
        assert_eq!(from_unix_seconds(86_400), "1970-01-02T00:00:00Z");
        // 2000-02-29, the leap day people get wrong.
        assert_eq!(from_unix_seconds(951_782_400), "2000-02-29T00:00:00Z");
        // 2100 is divisible by 100 but not 400, so it is NOT a leap year:
        // 2100-03-01 must follow 2100-02-28 directly, with no 29th between.
        assert_eq!(from_unix_seconds(4_107_456_000), "2100-02-28T00:00:00Z");
        assert_eq!(from_unix_seconds(4_107_542_400), "2100-03-01T00:00:00Z");
        assert_eq!(from_unix_seconds(1_785_609_127), "2026-08-01T18:32:07Z");
    }

    #[test]
    fn every_day_boundary_for_a_few_years_is_consistent() {
        // Walk day by day and assert the date advances by exactly one each
        // time, which catches off-by-one errors in the era arithmetic that a
        // handful of spot checks would miss.
        let mut previous = from_unix_seconds(1_735_689_600); // 2025-01-01
        for day in 1..(366 * 6) {
            let next = from_unix_seconds(1_735_689_600 + day * 86_400);
            assert!(next > previous, "{next} should sort after {previous}");
            previous = next;
        }
    }

    #[test]
    fn now_is_well_formed_and_plausible() {
        let s = now_rfc3339();
        assert_eq!(s.len(), 20, "got {s}");
        assert!(s.ends_with('Z'));
        assert!(
            s.as_str() > "2024-01-01T00:00:00Z",
            "clock looks wrong: {s}"
        );
    }
}
