//! Per-business-unit monthly budget accounting (docs/20).
//!
//! Deliberately OUTSIDE `LedgerBackend`/raft: the replicated run ledger's
//! state identity must not grow a new dimension as a routine edit (repo
//! invariant 5). These counters are in-process and per-gateway - they reset
//! on restart and are not fleet-consistent; docs/20 section 3 states this
//! plainly. The durable cross-fleet view of unit spend is the trace/Cloud
//! aggregation, not this map. What this map buys is the same
//! reserve-then-settle atomicity run budgets have (ADR-2): when a unit's
//! agents fan out, concurrent calls race for the same monthly cap, and a
//! naive check-then-add would let them all pass at once.
//!
//! The window is the UTC calendar month. Counters roll over lazily: the
//! first operation that observes a new month resets the unit's counters. A
//! settle that arrives for a reservation taken in a previous window is
//! dropped (the window it belonged to has already been reset; releasing it
//! into the new month would corrupt the fresh counters).

use std::collections::HashMap;
use std::sync::Mutex;
use tokenfuse_core::Microusd;

/// Milliseconds per UTC day.
const DAY_MILLIS: i64 = 86_400_000;

/// The UTC `YYYY-MM` window key for an epoch-milliseconds timestamp.
///
/// Civil-from-days conversion (Howard Hinnant's algorithm), inlined so the
/// gateway does not grow a calendar dependency for one function.
pub fn month_key(ts_millis: i64) -> String {
    let days = ts_millis.div_euclid(DAY_MILLIS);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}")
}

/// A granted unit reservation. Hand it back to [`UnitLedger::settle`] with
/// the real cost once the call completes (or with zero to release it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitReservation {
    pub unit: String,
    pub amount: Microusd,
    /// The window the reservation was taken in; a settle against a stale
    /// window is ignored (see module doc).
    window: String,
}

/// A refused reservation: granting `would` would exceed the unit's cap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitExceeded {
    pub unit: String,
    pub budget: Microusd,
    /// Settled spend at refusal time (mirrors `BudgetError::Exceeded::spent`:
    /// committed spend, not counting in-flight reservations).
    pub spent: Microusd,
}

#[derive(Debug)]
struct UnitState {
    window: String,
    reserved: Microusd,
    spent: Microusd,
}

/// In-process per-unit monthly ledger. Caps come from the identity map file
/// (`base`) and may be overridden centrally from the Cloud control plane
/// (`overrides`, replace-all on every poll tick, mirroring the run-budget
/// override semantics). An override may also impose a cap on a unit the file
/// left uncapped.
#[derive(Default)]
pub struct UnitLedger {
    base: HashMap<String, Microusd>,
    overrides: Mutex<HashMap<String, Microusd>>,
    state: Mutex<HashMap<String, UnitState>>,
}

impl UnitLedger {
    pub fn new(base: HashMap<String, Microusd>) -> Self {
        UnitLedger {
            base,
            overrides: Mutex::new(HashMap::new()),
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Replace the full central-override map (poller tick). Removing a unit
    /// from the overrides restores the map file's cap.
    pub fn set_overrides(&self, overrides: HashMap<String, Microusd>) {
        *self.overrides.lock().unwrap() = overrides;
    }

    /// The cap in effect for a unit: central override first, file cap second.
    pub fn effective_cap(&self, unit: &str) -> Option<Microusd> {
        if let Some(v) = self.overrides.lock().unwrap().get(unit) {
            return Some(*v);
        }
        self.base.get(unit).copied()
    }

    /// Roll the unit's window forward if `now` is in a new month. Assumes the
    /// state lock is held (operates on the entry).
    fn rolled<'a>(
        state: &'a mut HashMap<String, UnitState>,
        unit: &str,
        now_window: &str,
    ) -> &'a mut UnitState {
        let entry = state.entry(unit.to_string()).or_insert_with(|| UnitState {
            window: now_window.to_string(),
            reserved: Microusd::ZERO,
            spent: Microusd::ZERO,
        });
        if entry.window != now_window {
            entry.window = now_window.to_string();
            entry.reserved = Microusd::ZERO;
            entry.spent = Microusd::ZERO;
        }
        entry
    }

    /// Atomically reserve `estimate` against the unit's monthly cap.
    ///
    /// `Ok(None)` when the unit has no cap in effect: nothing is accounted
    /// and nothing needs settling. `Err` reserves nothing.
    pub fn try_reserve(
        &self,
        unit: &str,
        estimate: Microusd,
        now_millis: i64,
    ) -> Result<Option<UnitReservation>, UnitExceeded> {
        let Some(cap) = self.effective_cap(unit) else {
            return Ok(None);
        };
        let window = month_key(now_millis);
        let mut state = self.state.lock().unwrap();
        let s = Self::rolled(&mut state, unit, &window);
        let would = s.spent + s.reserved + estimate;
        if would > cap {
            return Err(UnitExceeded {
                unit: unit.to_string(),
                budget: cap,
                spent: s.spent,
            });
        }
        s.reserved = s.reserved + estimate;
        Ok(Some(UnitReservation {
            unit: unit.to_string(),
            amount: estimate,
            window,
        }))
    }

    /// Reserve without a cap check (shadow/warn: a breach must be recorded,
    /// never blocked - the exact contract `Ledger::reserve_unchecked` has for
    /// run budgets). Still `None` when the unit has no cap in effect, since
    /// uncapped units are not accounted here at all.
    pub fn reserve_unchecked(
        &self,
        unit: &str,
        estimate: Microusd,
        now_millis: i64,
    ) -> Option<UnitReservation> {
        self.effective_cap(unit)?;
        let window = month_key(now_millis);
        let mut state = self.state.lock().unwrap();
        let s = Self::rolled(&mut state, unit, &window);
        s.reserved = s.reserved + estimate;
        Some(UnitReservation {
            unit: unit.to_string(),
            amount: estimate,
            window,
        })
    }

    /// Settle a reservation with the real cost: release the estimate, add the
    /// actual spend. A settle whose reservation window is no longer current
    /// is dropped (the counters it belonged to were reset at rollover).
    pub fn settle(&self, reservation: &UnitReservation, actual: Microusd, now_millis: i64) {
        let now_window = month_key(now_millis);
        if reservation.window != now_window {
            return;
        }
        let mut state = self.state.lock().unwrap();
        let Some(s) = state.get_mut(&reservation.unit) else {
            return;
        };
        if s.window != reservation.window {
            return;
        }
        s.reserved = s.reserved.saturating_sub(reservation.amount);
        s.spent = s.spent + actual;
    }

    /// Committed spend for a unit in the current window (for error bodies and
    /// observability). Zero when the unit has no state yet.
    pub fn spent(&self, unit: &str, now_millis: i64) -> Microusd {
        let window = month_key(now_millis);
        let state = self.state.lock().unwrap();
        match state.get(unit) {
            Some(s) if s.window == window => s.spent,
            _ => Microusd::ZERO,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usd(v: f64) -> Microusd {
        Microusd::from_usd(v)
    }

    /// 2026-07-15T00:00:00Z, a fixed mid-month instant for tests.
    const JULY: i64 = 1_784_073_600_000;
    /// One day into the following month.
    const AUGUST: i64 = JULY + 17 * DAY_MILLIS;

    #[test]
    fn month_key_matches_known_dates() {
        assert_eq!(month_key(0), "1970-01");
        assert_eq!(month_key(-1), "1969-12");
        assert_eq!(month_key(JULY), "2026-07");
        assert_eq!(month_key(AUGUST), "2026-08");
        // 2024-02-29T12:00:00Z (leap day).
        assert_eq!(month_key(1_709_208_000_000), "2024-02");
    }

    #[test]
    fn uncapped_unit_is_not_accounted() {
        let ledger = UnitLedger::new(HashMap::new());
        assert_eq!(ledger.try_reserve("treasury", usd(1.0), JULY), Ok(None));
        assert_eq!(ledger.reserve_unchecked("treasury", usd(1.0), JULY), None);
        assert_eq!(ledger.spent("treasury", JULY), Microusd::ZERO);
    }

    #[test]
    fn reserve_then_settle_tracks_spend_within_the_cap() {
        let ledger = UnitLedger::new(HashMap::from([("treasury".into(), usd(10.0))]));
        let res = ledger
            .try_reserve("treasury", usd(4.0), JULY)
            .unwrap()
            .expect("capped unit reserves");
        ledger.settle(&res, usd(3.5), JULY);
        assert_eq!(ledger.spent("treasury", JULY), usd(3.5));
        // Remaining headroom is cap - spent: a fresh reserve for it succeeds.
        assert!(ledger.try_reserve("treasury", usd(6.5), JULY).is_ok());
    }

    #[test]
    fn reservation_blocks_when_it_would_exceed_the_cap() {
        let ledger = UnitLedger::new(HashMap::from([("treasury".into(), usd(1.0))]));
        let _held = ledger.try_reserve("treasury", usd(0.9), JULY).unwrap();
        let err = ledger.try_reserve("treasury", usd(0.2), JULY).unwrap_err();
        assert_eq!(err.unit, "treasury");
        assert_eq!(err.budget, usd(1.0));
        assert_eq!(err.spent, Microusd::ZERO);
    }

    #[test]
    fn reserve_unchecked_records_past_the_cap_without_error() {
        let ledger = UnitLedger::new(HashMap::from([("treasury".into(), usd(1.0))]));
        let res = ledger
            .reserve_unchecked("treasury", usd(5.0), JULY)
            .expect("capped unit records");
        ledger.settle(&res, usd(5.0), JULY);
        assert_eq!(ledger.spent("treasury", JULY), usd(5.0));
        // The checked path now refuses (over cap), proving the breach landed.
        assert!(ledger.try_reserve("treasury", usd(0.1), JULY).is_err());
    }

    #[test]
    fn counters_roll_over_at_the_month_boundary() {
        let ledger = UnitLedger::new(HashMap::from([("treasury".into(), usd(1.0))]));
        let res = ledger
            .try_reserve("treasury", usd(1.0), JULY)
            .unwrap()
            .unwrap();
        ledger.settle(&res, usd(1.0), JULY);
        assert!(ledger.try_reserve("treasury", usd(0.5), JULY).is_err());
        // New month: fresh counters, the same reserve succeeds.
        assert!(ledger
            .try_reserve("treasury", usd(0.5), AUGUST)
            .unwrap()
            .is_some());
        assert_eq!(ledger.spent("treasury", JULY), Microusd::ZERO);
    }

    #[test]
    fn a_stale_window_settle_is_dropped() {
        let ledger = UnitLedger::new(HashMap::from([("treasury".into(), usd(10.0))]));
        let res = ledger
            .try_reserve("treasury", usd(2.0), JULY)
            .unwrap()
            .unwrap();
        // The month turned while the call was in flight; rollover happened.
        let _ = ledger.try_reserve("treasury", usd(1.0), AUGUST).unwrap();
        ledger.settle(&res, usd(2.0), AUGUST);
        // August's counters must not absorb July's settle.
        assert_eq!(ledger.spent("treasury", AUGUST), Microusd::ZERO);
    }

    #[test]
    fn central_override_wins_over_the_file_cap_and_can_cap_an_uncapped_unit() {
        let ledger = UnitLedger::new(HashMap::from([("treasury".into(), usd(10.0))]));
        ledger.set_overrides(HashMap::from([
            ("treasury".into(), usd(1.0)),
            ("lending".into(), usd(2.0)),
        ]));
        assert_eq!(ledger.effective_cap("treasury"), Some(usd(1.0)));
        assert_eq!(ledger.effective_cap("lending"), Some(usd(2.0)));
        assert!(ledger.try_reserve("treasury", usd(1.5), JULY).is_err());
        // Clearing the overrides restores the file cap.
        ledger.set_overrides(HashMap::new());
        assert_eq!(ledger.effective_cap("treasury"), Some(usd(10.0)));
        assert_eq!(ledger.effective_cap("lending"), None);
    }

    #[test]
    fn concurrent_reservations_never_oversubscribe_the_cap() {
        use std::sync::Arc;
        use std::thread;

        let ledger = Arc::new(UnitLedger::new(HashMap::from([(
            "treasury".to_string(),
            usd(10.0),
        )])));
        let mut handles = Vec::new();
        for _ in 0..50 {
            let l = Arc::clone(&ledger);
            handles.push(thread::spawn(move || {
                l.try_reserve("treasury", usd(1.0), JULY).is_ok()
            }));
        }
        let granted = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|&ok| ok)
            .count();
        assert_eq!(granted, 10);
    }
}
