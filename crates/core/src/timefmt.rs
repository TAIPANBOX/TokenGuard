//! Minimal RFC 3339 (UTC) timestamp formatting, with no date-library
//! dependency: a small, well-known civil-calendar algorithm (Howard Hinnant's
//! `civil_from_days`, <http://howardhinnant.github.io/date_algorithms.html>)
//! turns days-since-epoch into y/m/d.
//!
//! Shared location (P3/agent-passport): this started as a private helper in
//! `crates/gateway/src/focusexport.rs` (FOCUS CSV export, second precision).
//! The agent-event NDJSON exporter (`crates/core/src/agent_event.rs`) needs
//! the SAME calendar math but at millisecond precision (`ts` in the envelope,
//! agent-passport SPEC.md §6), and it must be callable from both the gateway
//! and cloud crates — so the calendar math moved here rather than being
//! duplicated. `focusexport.rs` now calls into this module instead of
//! carrying its own copy.

/// Format epoch milliseconds as an RFC 3339 UTC timestamp at second precision
/// (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn ts_millis_to_rfc3339(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let hour = secs_of_day / 3600;
    let min = (secs_of_day % 3600) / 60;
    let sec = secs_of_day % 60;
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// Format epoch milliseconds as an RFC 3339 UTC timestamp at millisecond
/// precision (`YYYY-MM-DDTHH:MM:SS.sssZ`) — the precision the agent-event
/// envelope's `ts` field uses (agent-passport SPEC.md §6 example:
/// `"2026-07-09T03:12:44.100Z"`).
pub fn ts_millis_to_rfc3339_millis(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let millis_of_sec = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let hour = secs_of_day / 3600;
    let min = (secs_of_day % 3600) / 60;
    let sec = secs_of_day % 60;
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}.{millis_of_sec:03}Z")
}

/// Days-since-epoch (1970-01-01 = 0) -> (year, month, day). See module doc.
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// The inverse of [`civil_from_days`]: (year, month, day) -> days-since-epoch.
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400); // [0, 399]
    let mp = (m as i64 + 9) % 12; // [0, 11]
    let doy = (153 * mp + 2) / 5 + d as i64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ts_millis_to_rfc3339_known_values() {
        assert_eq!(ts_millis_to_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(ts_millis_to_rfc3339(1_000), "1970-01-01T00:00:01Z");
        assert_eq!(ts_millis_to_rfc3339(86_400_000), "1970-01-02T00:00:00Z");
        assert_eq!(
            ts_millis_to_rfc3339(1_704_067_200_000),
            "2024-01-01T00:00:00Z"
        );
        // Leap day.
        assert_eq!(
            ts_millis_to_rfc3339(1_709_208_000_000),
            "2024-02-29T12:00:00Z"
        );
    }

    #[test]
    fn ts_millis_to_rfc3339_millis_known_values() {
        assert_eq!(ts_millis_to_rfc3339_millis(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            ts_millis_to_rfc3339_millis(1_704_067_200_100),
            "2024-01-01T00:00:00.100Z"
        );
        assert_eq!(
            ts_millis_to_rfc3339_millis(1_704_067_200_999),
            "2024-01-01T00:00:00.999Z"
        );
    }

    #[test]
    fn rfc3339_round_trips_over_a_range_of_days() {
        // civil_from_days / days_from_civil must be exact inverses across a
        // span that includes multiple leap years and century boundaries.
        for days in -1000..1000 {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days, "{y:04}-{m:02}-{d:02}");
        }
    }
}
