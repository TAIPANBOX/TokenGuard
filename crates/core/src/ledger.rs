//! The reserve → settle ledger (ADR-2).
//!
//! Before a call we atomically *reserve* its estimated cost against a run's
//! budget; after the response we *settle* the reservation with the real cost.
//! Reserve-then-settle is the only correct approach under concurrency: when an
//! agent fans out sub-agents, several calls race for the same budget, and a
//! naive "check spent, then add" would let them all pass the check at once.
//!
//! This in-process implementation guards the whole map with a `Mutex`, which
//! makes each reserve an atomic check-and-add. The fleet/HA backends (Redis,
//! then embedded raft) implement the same contract behind the same API.

use crate::money::Microusd;
use std::collections::HashMap;
use std::sync::Mutex;
use thiserror::Error;

/// A read-only view of a run's accounting state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunSnapshot {
    pub budget: Microusd,
    /// Estimated cost of calls that are reserved but not yet settled.
    pub reserved: Microusd,
    /// Real cost of calls that have completed and settled.
    pub spent: Microusd,
    /// Number of calls reserved so far (each reserve is one step).
    pub steps: u32,
}

impl RunSnapshot {
    /// Money committed or in flight — what a new reservation is checked against.
    pub fn in_flight(&self) -> Microusd {
        self.spent + self.reserved
    }

    /// Budget still available for new reservations (never negative).
    pub fn remaining(&self) -> Microusd {
        self.budget.saturating_sub(self.in_flight())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BudgetError {
    #[error("unknown run: {run_id}")]
    UnknownRun { run_id: String },
    #[error("budget exceeded for run {run_id}: {would} would exceed budget {budget}")]
    Exceeded {
        run_id: String,
        budget: Microusd,
        spent: Microusd,
        would: Microusd,
    },
}

/// A successful reservation. Hand it back to [`Ledger::settle`] with the real
/// cost once the call completes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reservation {
    pub run_id: String,
    pub amount: Microusd,
    /// 1-based step index this reservation represents.
    pub step: u32,
}

#[derive(Debug, Clone, Copy)]
struct RunState {
    budget: Microusd,
    reserved: Microusd,
    spent: Microusd,
    steps: u32,
}

/// In-process reserve/settle ledger. Cheap to clone via `Arc` at the call site.
#[derive(Default)]
pub struct Ledger {
    runs: Mutex<HashMap<String, RunState>>,
}

impl Ledger {
    pub fn new() -> Self {
        Ledger::default()
    }

    /// Register a run with its budget. Idempotent for the budget; existing
    /// counters are preserved so re-declaring a run mid-flight is safe.
    pub fn open_run(&self, run_id: impl Into<String>, budget: Microusd) {
        let mut runs = self.runs.lock().unwrap();
        runs.entry(run_id.into())
            .and_modify(|s| s.budget = budget)
            .or_insert(RunState {
                budget,
                reserved: Microusd::ZERO,
                spent: Microusd::ZERO,
                steps: 0,
            });
    }

    pub fn snapshot(&self, run_id: &str) -> Option<RunSnapshot> {
        let runs = self.runs.lock().unwrap();
        runs.get(run_id).map(|s| RunSnapshot {
            budget: s.budget,
            reserved: s.reserved,
            spent: s.spent,
            steps: s.steps,
        })
    }

    /// Atomically reserve `estimate` against the run's remaining budget.
    /// Increments the step counter on success.
    pub fn reserve(&self, run_id: &str, estimate: Microusd) -> Result<Reservation, BudgetError> {
        let mut runs = self.runs.lock().unwrap();
        let state = runs
            .get_mut(run_id)
            .ok_or_else(|| BudgetError::UnknownRun {
                run_id: run_id.to_string(),
            })?;

        let would = state.spent + state.reserved + estimate;
        if would > state.budget {
            return Err(BudgetError::Exceeded {
                run_id: run_id.to_string(),
                budget: state.budget,
                spent: state.spent,
                would,
            });
        }

        state.reserved = state.reserved + estimate;
        state.steps += 1;
        Ok(Reservation {
            run_id: run_id.to_string(),
            amount: estimate,
            step: state.steps,
        })
    }

    /// Reserve without a budget check. Used in shadow/warn modes, where a breach
    /// must be *recorded* (so spend and steps stay accurate) but must not block.
    /// Always succeeds; opens the run at zero budget if it does not exist.
    pub fn reserve_unchecked(&self, run_id: &str, estimate: Microusd) -> Reservation {
        let mut runs = self.runs.lock().unwrap();
        let state = runs.entry(run_id.to_string()).or_insert(RunState {
            budget: Microusd::ZERO,
            reserved: Microusd::ZERO,
            spent: Microusd::ZERO,
            steps: 0,
        });
        state.reserved = state.reserved + estimate;
        state.steps += 1;
        Reservation {
            run_id: run_id.to_string(),
            amount: estimate,
            step: state.steps,
        }
    }

    /// Settle a reservation with the real cost: release the reserved estimate
    /// and add the actual spend. Over- or under-estimates self-correct here.
    pub fn settle(&self, reservation: &Reservation, actual: Microusd) {
        let mut runs = self.runs.lock().unwrap();
        if let Some(state) = runs.get_mut(&reservation.run_id) {
            state.reserved = state.reserved.saturating_sub(reservation.amount);
            state.spent = state.spent + actual;
        }
    }

    /// Remove a run and return its final snapshot.
    pub fn close_run(&self, run_id: &str) -> Option<RunSnapshot> {
        let mut runs = self.runs.lock().unwrap();
        runs.remove(run_id).map(|s| RunSnapshot {
            budget: s.budget,
            reserved: s.reserved,
            spent: s.spent,
            steps: s.steps,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usd(v: f64) -> Microusd {
        Microusd::from_usd(v)
    }

    #[test]
    fn reserve_unknown_run_errors() {
        let ledger = Ledger::new();
        let err = ledger.reserve("nope", usd(0.1)).unwrap_err();
        assert!(matches!(err, BudgetError::UnknownRun { .. }));
    }

    #[test]
    fn reserve_then_settle_tracks_spend_and_releases_reservation() {
        let ledger = Ledger::new();
        ledger.open_run("r1", usd(5.0));

        let res = ledger.reserve("r1", usd(1.0)).unwrap();
        let mid = ledger.snapshot("r1").unwrap();
        assert_eq!(mid.reserved, usd(1.0));
        assert_eq!(mid.spent, Microusd::ZERO);
        assert_eq!(mid.steps, 1);

        // Real cost came in lower than the estimate.
        ledger.settle(&res, usd(0.8));
        let after = ledger.snapshot("r1").unwrap();
        assert_eq!(after.reserved, Microusd::ZERO);
        assert_eq!(after.spent, usd(0.8));
        assert_eq!(after.remaining(), usd(4.2));
    }

    #[test]
    fn reservation_blocks_when_it_would_exceed_budget() {
        let ledger = Ledger::new();
        ledger.open_run("r1", usd(1.0));
        ledger.reserve("r1", usd(0.9)).unwrap();

        let err = ledger.reserve("r1", usd(0.2)).unwrap_err();
        match err {
            BudgetError::Exceeded { would, budget, .. } => {
                assert_eq!(budget, usd(1.0));
                assert_eq!(would, usd(1.1));
            }
            other => panic!("expected Exceeded, got {other:?}"),
        }
    }

    #[test]
    fn reserve_unchecked_records_past_budget_without_error() {
        let ledger = Ledger::new();
        ledger.open_run("r1", usd(1.0));
        // Reserve beyond budget: shadow mode records it, does not block.
        let res = ledger.reserve_unchecked("r1", usd(5.0));
        assert_eq!(res.step, 1);
        let snap = ledger.snapshot("r1").unwrap();
        assert_eq!(snap.reserved, usd(5.0));
        // The checked path, by contrast, would have refused this.
        assert!(ledger.reserve("r1", usd(0.1)).is_err());
    }

    #[test]
    fn concurrent_reservations_never_oversubscribe_budget() {
        use std::sync::Arc;
        use std::thread;

        let ledger = Arc::new(Ledger::new());
        // Budget for exactly 10 reservations of $1.
        ledger.open_run("r1", usd(10.0));

        let mut handles = Vec::new();
        for _ in 0..50 {
            let l = Arc::clone(&ledger);
            handles.push(thread::spawn(move || l.reserve("r1", usd(1.0)).is_ok()));
        }
        let granted = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|&ok| ok)
            .count();

        // No matter the interleaving, at most 10 reservations can be granted.
        assert_eq!(granted, 10);
        assert_eq!(ledger.snapshot("r1").unwrap().reserved, usd(10.0));
    }
}
