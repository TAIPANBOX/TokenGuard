//! The ledger authority behind the gateway, abstracted so it can be either the
//! in-process [`tokenfuse_core::Ledger`] (default) or a raft-replicated ledger
//! shared across gateways (the `cluster` feature).
//!
//! Reserve/open/snapshot are `async` because a replicated backend must reach
//! consensus before answering. `settle` stays synchronous and fire-and-forget:
//! it needs no result and must be callable from `SettleGuard::drop` (which can't
//! await) — the local backend settles inline, the raft backend spawns the write.

use async_trait::async_trait;
use tokenfuse_core::{BudgetError, Ledger, Microusd, Reservation, RunSnapshot};

/// A budget ledger the gateway can reserve/settle against.
#[async_trait]
pub trait LedgerBackend: Send + Sync {
    /// Register a run with its budget (and optional parent for hierarchy).
    async fn open_run(&self, run_id: &str, budget: Microusd, parent: Option<&str>);

    /// Reserve `estimate` if it fits the budget; otherwise return the error.
    async fn reserve(&self, run_id: &str, estimate: Microusd) -> Result<Reservation, BudgetError>;

    /// Reserve without a budget check (shadow/warn modes record but never block).
    async fn reserve_unchecked(&self, run_id: &str, estimate: Microusd) -> Reservation;

    /// Current accounting for a run, if known.
    async fn snapshot(&self, run_id: &str) -> Option<RunSnapshot>;

    /// All known runs and their accounting (backs the observability API).
    async fn list_runs(&self) -> Vec<(String, RunSnapshot)>;

    /// Settle a reservation with its actual cost. Fire-and-forget: no result,
    /// callable from a non-async `Drop`.
    fn settle(&self, reservation: &Reservation, actual: Microusd);
}

/// The default in-process backend: a thin async wrapper over the sync `Ledger`.
pub struct LocalLedger(pub std::sync::Arc<Ledger>);

#[async_trait]
impl LedgerBackend for LocalLedger {
    async fn open_run(&self, run_id: &str, budget: Microusd, parent: Option<&str>) {
        self.0.open_run(run_id, budget, parent);
    }

    async fn reserve(&self, run_id: &str, estimate: Microusd) -> Result<Reservation, BudgetError> {
        self.0.reserve(run_id, estimate)
    }

    async fn reserve_unchecked(&self, run_id: &str, estimate: Microusd) -> Reservation {
        self.0.reserve_unchecked(run_id, estimate)
    }

    async fn snapshot(&self, run_id: &str) -> Option<RunSnapshot> {
        self.0.snapshot(run_id)
    }

    async fn list_runs(&self) -> Vec<(String, RunSnapshot)> {
        self.0.list_runs()
    }

    fn settle(&self, reservation: &Reservation, actual: Microusd) {
        self.0.settle(reservation, actual);
    }
}
