//! Raft type configuration and the replicated budget-ledger domain.
//!
//! The state machine *is* a budget ledger: `Reserve` and `Settle` are applied
//! as raft log entries, so the affordability check is linearized across every
//! node. A leader can never oversubscribe a budget even if two sub-agents race
//! against different nodes — the check happens once, in log order, on the
//! committed state machine.
//!
//! Budgets are **hierarchical**: a run may declare a `parent`, and a reserve
//! must fit the run's budget *and every ancestor's* (all-or-nothing), rolling
//! the reservation up the chain — so a sub-agent's spend counts against its
//! parent's cap. This mirrors `tokenfuse-core::Ledger` exactly, now replicated.

use std::collections::BTreeMap;
use std::io::Cursor;

use openraft::BasicNode;
use serde::{Deserialize, Serialize};

/// Cluster node identity.
pub type NodeId = u64;

/// Max ancestor depth walked when rolling reservations up a run tree — a guard
/// against accidental cycles or pathological nesting.
const MAX_CHAIN_DEPTH: usize = 64;

openraft::declare_raft_types!(
    /// TokenFuse's raft types: budget ops in, an accept/deny response out.
    pub TypeConfig:
        D = Request,
        R = Response,
        NodeId = NodeId,
        Node = BasicNode,
        Entry = openraft::Entry<TypeConfig>,
        SnapshotData = Cursor<Vec<u8>>,
        AsyncRuntime = openraft::TokioRuntime,
);

/// A write against the replicated ledger. Amounts are integer **microdollars**
/// (µUSD), matching `tokenfuse-core::Money` — no floats in the consensus path.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Request {
    /// Create (or reset) a run with a hard budget ceiling and optional parent.
    Open {
        run: String,
        budget_micros: u64,
        /// Ancestor run this one rolls up into (hierarchical sub-agent budgets).
        parent: Option<String>,
    },
    /// Reserve headroom before a call. Accepted only if it still fits at the run
    /// and every ancestor.
    Reserve { run: String, micros: u64 },
    /// Settle a prior reservation with the actual spend (rolls up the chain).
    Settle {
        run: String,
        reserved_micros: u64,
        actual_micros: u64,
    },
}

/// The result of applying a [`Request`] to the committed state machine.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Response {
    /// Whether the operation was accepted (a `Reserve` that fit every level).
    pub accepted: bool,
    /// Committed spend after applying (settled dollars only), at the leaf run.
    pub spent_micros: u64,
    /// Outstanding reservations at the leaf run.
    pub reserved_micros: u64,
    /// The leaf run's hard ceiling.
    pub budget_micros: u64,
    /// The leaf run's step count (each accepted reserve is one step).
    pub step: u32,
    /// When not accepted, the run whose budget was exceeded (leaf or an
    /// ancestor) — lets the caller say "parent run X exceeded".
    pub blocked_run: Option<String>,
    /// Human-readable reason when `accepted == false`.
    pub reason: String,
}

/// Per-run accounting held in the replicated state machine.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunState {
    pub budget_micros: u64,
    pub reserved_micros: u64,
    pub spent_micros: u64,
    /// Number of accepted reserves (steps) on this run.
    pub steps: u32,
    /// Ancestor run this one rolls up into.
    pub parent: Option<String>,
}

impl RunState {
    /// Total committed against the budget: settled spend plus live reservations.
    pub fn committed(&self) -> u64 {
        self.spent_micros.saturating_add(self.reserved_micros)
    }
}

/// The full replicated state: the ledger plus raft bookkeeping needed for
/// snapshots (last applied log id and the active membership).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LedgerState {
    pub runs: BTreeMap<String, RunState>,
}

impl LedgerState {
    /// The chain of run ids from `run` up through its ancestors (leaf first).
    /// Missing ancestors and cycles terminate the walk.
    fn chain(&self, run: &str) -> Vec<String> {
        let mut ids = Vec::new();
        let mut cur = Some(run.to_string());
        while let Some(id) = cur {
            if ids.contains(&id) || ids.len() >= MAX_CHAIN_DEPTH {
                break;
            }
            match self.runs.get(&id) {
                Some(s) => {
                    let parent = s.parent.clone();
                    ids.push(id);
                    cur = parent;
                }
                None => break,
            }
        }
        ids
    }

    /// A response echoing a run's current leaf numbers.
    fn leaf_response(&self, run: &str, accepted: bool) -> Response {
        let s = self.runs.get(run).cloned().unwrap_or_default();
        Response {
            accepted,
            spent_micros: s.spent_micros,
            reserved_micros: s.reserved_micros,
            budget_micros: s.budget_micros,
            step: s.steps,
            blocked_run: None,
            reason: String::new(),
        }
    }

    /// Apply one request in log order, returning the response for that entry.
    /// This is the single point where a budget is enforced across the cluster.
    pub fn apply(&mut self, req: &Request) -> Response {
        match req {
            Request::Open {
                run,
                budget_micros,
                parent,
            } => {
                match self.runs.get_mut(run) {
                    // Existing run: update the budget, preserve counters + parent.
                    Some(s) => s.budget_micros = *budget_micros,
                    // New run: set budget and parent.
                    None => {
                        self.runs.insert(
                            run.clone(),
                            RunState {
                                budget_micros: *budget_micros,
                                parent: parent.clone(),
                                ..Default::default()
                            },
                        );
                    }
                }
                self.leaf_response(run, true)
            }

            Request::Reserve { run, micros } => {
                if !self.runs.contains_key(run) {
                    let mut r = self.leaf_response(run, false);
                    r.blocked_run = Some(run.clone());
                    r.reason = format!("unknown_run: {run}");
                    return r;
                }
                let ids = self.chain(run);

                // Check every level first (all-or-nothing).
                for id in &ids {
                    let s = &self.runs[id];
                    let would = s.committed().saturating_add(*micros);
                    if would > s.budget_micros {
                        return Response {
                            accepted: false,
                            spent_micros: s.spent_micros,
                            reserved_micros: s.reserved_micros,
                            budget_micros: s.budget_micros,
                            step: self.runs[run].steps,
                            blocked_run: Some(id.clone()),
                            reason: format!(
                                "budget_exceeded on '{id}': need {would} µUSD > budget {} µUSD",
                                s.budget_micros
                            ),
                        };
                    }
                }

                // Apply to every level; steps increments on the leaf only.
                for id in &ids {
                    let s = self.runs.get_mut(id).expect("in chain");
                    s.reserved_micros = s.reserved_micros.saturating_add(*micros);
                }
                let leaf = self.runs.get_mut(run).expect("leaf");
                leaf.steps += 1;
                self.leaf_response(run, true)
            }

            Request::Settle {
                run,
                reserved_micros,
                actual_micros,
            } => {
                let ids = self.chain(run);
                for id in &ids {
                    if let Some(s) = self.runs.get_mut(id) {
                        s.reserved_micros = s.reserved_micros.saturating_sub(*reserved_micros);
                        s.spent_micros = s.spent_micros.saturating_add(*actual_micros);
                    }
                }
                self.leaf_response(run, true)
            }
        }
    }
}
