//! Raft-replicated ledger backend (feature `cluster`).
//!
//! The gateway co-locates a raft node (`tokenfuse_cluster::server::HttpNode`) and
//! runs its HTTP server so peer gateways can replicate to it. Reserve/open/settle
//! become raft writes, transparently forwarded to the leader; the budget check is
//! therefore linearized across every gateway sharing the cluster — no two agents
//! double-spend the same ceiling, and budgets survive a gateway crash.
//!
//! Limitations (documented; follow-ups): hierarchical sub-agent budgets and
//! per-run step counts are not yet modelled in the replicated state machine, so
//! `parent` is ignored and `steps` reads back as a local counter. If consensus is
//! unreachable, reserve **fails open** (consistent with TokenFuse's default) so a
//! cluster outage degrades to "no enforcement", never "all agents blocked".

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokenfuse_cluster::net_http::Peers;
use tokenfuse_cluster::server::{self, HttpNode};
use tokenfuse_cluster::types::Request;
use tokenfuse_core::{BudgetError, Microusd, Reservation, RunSnapshot};

use crate::ledger_backend::LedgerBackend;

pub struct RaftLedger {
    node: Arc<HttpNode>,
    /// Per-run step counter (the replicated SM does not track steps yet).
    steps: Mutex<HashMap<String, u32>>,
}

impl RaftLedger {
    /// Build the co-located raft node, start its HTTP server on `addr`, and
    /// optionally initialize the cluster (do this on exactly one node).
    pub async fn start(
        id: u64,
        addr: SocketAddr,
        peers: Peers,
        bootstrap: bool,
    ) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
        let node = HttpNode::build(id, peers).await?;

        // Serve peer RPCs + the admin/app API in the background.
        let serve_node = node.clone();
        tokio::spawn(async move {
            if let Err(e) = server::serve(serve_node, addr).await {
                tracing::error!("cluster server exited: {e}");
            }
        });

        if bootstrap {
            let init_node = node.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                match init_node.init().await {
                    Ok(()) => tracing::info!("raft cluster initialized"),
                    Err(e) => tracing::info!("raft init skipped: {e}"),
                }
            });
        }

        Ok(Arc::new(Self {
            node,
            steps: Mutex::new(HashMap::new()),
        }))
    }

    fn next_step(&self, run: &str) -> u32 {
        let mut s = self.steps.lock().unwrap();
        let e = s.entry(run.to_string()).or_insert(0);
        *e += 1;
        *e
    }
}

#[async_trait]
impl LedgerBackend for RaftLedger {
    async fn open_run(&self, run_id: &str, budget: Microusd, _parent: Option<&str>) {
        let req = Request::Open {
            run: run_id.to_string(),
            budget_micros: budget.0.max(0) as u64,
        };
        if let Err(e) = self.node.submit(req).await {
            tracing::warn!(run = run_id, "cluster open_run failed: {e}");
        }
    }

    async fn reserve(&self, run_id: &str, estimate: Microusd) -> Result<Reservation, BudgetError> {
        let req = Request::Reserve {
            run: run_id.to_string(),
            micros: estimate.0.max(0) as u64,
        };
        match self.node.submit(req).await {
            Ok(resp) if resp.accepted => Ok(Reservation {
                run_id: run_id.to_string(),
                amount: estimate,
                step: self.next_step(run_id),
            }),
            Ok(resp) => Err(BudgetError::Exceeded {
                run_id: run_id.to_string(),
                budget: Microusd(resp.budget_micros as i64),
                spent: Microusd(resp.spent_micros as i64),
                would: Microusd((resp.reserved_micros + resp.spent_micros) as i64 + estimate.0),
            }),
            // Fail open: if consensus is unreachable, don't block the agent.
            Err(e) => {
                tracing::warn!(run = run_id, "cluster reserve failed open: {e}");
                Ok(Reservation {
                    run_id: run_id.to_string(),
                    amount: estimate,
                    step: self.next_step(run_id),
                })
            }
        }
    }

    async fn reserve_unchecked(&self, run_id: &str, estimate: Microusd) -> Reservation {
        // Shadow/warn: record the attempt but always hand back a reservation.
        let _ = self
            .node
            .submit(Request::Reserve {
                run: run_id.to_string(),
                micros: estimate.0.max(0) as u64,
            })
            .await;
        Reservation {
            run_id: run_id.to_string(),
            amount: estimate,
            step: self.next_step(run_id),
        }
    }

    async fn snapshot(&self, run_id: &str) -> Option<RunSnapshot> {
        self.node.sm.read_run(run_id).await.map(|s| RunSnapshot {
            budget: Microusd(s.budget_micros as i64),
            reserved: Microusd(s.reserved_micros as i64),
            spent: Microusd(s.spent_micros as i64),
            steps: self.steps.lock().unwrap().get(run_id).copied().unwrap_or(0),
        })
    }

    async fn list_runs(&self) -> Vec<(String, RunSnapshot)> {
        let steps = self.steps.lock().unwrap().clone();
        self.node
            .sm
            .list_runs()
            .await
            .into_iter()
            .map(|(run, s)| {
                let snap = RunSnapshot {
                    budget: Microusd(s.budget_micros as i64),
                    reserved: Microusd(s.reserved_micros as i64),
                    spent: Microusd(s.spent_micros as i64),
                    steps: steps.get(&run).copied().unwrap_or(0),
                };
                (run, snap)
            })
            .collect()
    }

    fn settle(&self, reservation: &Reservation, actual: Microusd) {
        let node = self.node.clone();
        let req = Request::Settle {
            run: reservation.run_id.clone(),
            reserved_micros: reservation.amount.0.max(0) as u64,
            actual_micros: actual.0.max(0) as u64,
        };
        // Fire-and-forget: settle needs no result and may run from Drop.
        tokio::spawn(async move {
            if let Err(e) = node.submit(req).await {
                tracing::warn!("cluster settle failed: {e}");
            }
        });
    }
}
