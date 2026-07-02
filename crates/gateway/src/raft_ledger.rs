//! Raft-replicated ledger backend (feature `cluster`).
//!
//! The gateway co-locates a raft node (`tokenfuse_cluster::server::HttpNode`) and
//! runs its HTTP server so peer gateways can replicate to it. Reserve/open/settle
//! become raft writes, transparently forwarded to the leader; the budget check is
//! therefore linearized across every gateway sharing the cluster — no two agents
//! double-spend the same ceiling, and budgets survive a gateway crash.
//!
//! The replicated state machine models **hierarchical** budgets (a run rolls up
//! into its `parent`) and per-run **step** counts, matching the in-process
//! ledger. If consensus is unreachable, reserve **fails open** (consistent with
//! TokenFuse's default) so a cluster outage degrades to "no enforcement", never
//! "all agents blocked".

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokenfuse_cluster::net_http::Peers;
use tokenfuse_cluster::server::{self, HttpNode};
use tokenfuse_cluster::types::Request;
use tokenfuse_core::{BudgetError, Microusd, Reservation, RunSnapshot};

use crate::ledger_backend::LedgerBackend;

pub struct RaftLedger {
    node: Arc<HttpNode>,
}

impl RaftLedger {
    /// Build the co-located raft node, start its HTTP server on `addr`, and
    /// optionally initialize the cluster (do this on exactly one node).
    pub async fn start(
        id: u64,
        addr: SocketAddr,
        peers: Peers,
        bootstrap: bool,
        data_dir: Option<String>,
    ) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
        let node = match data_dir {
            Some(dir) if !dir.is_empty() => {
                tracing::info!(%dir, "raft storage: durable (redb)");
                HttpNode::build_durable(id, peers, dir).await?
            }
            _ => {
                tracing::info!(
                    "raft storage: in-memory (set TOKENFUSE_CLUSTER_DATA_DIR for durable)"
                );
                HttpNode::build(id, peers).await?
            }
        };

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

        Ok(Arc::new(Self { node }))
    }
}

fn snap_of(s: tokenfuse_cluster::types::RunState) -> RunSnapshot {
    RunSnapshot {
        budget: Microusd(s.budget_micros as i64),
        reserved: Microusd(s.reserved_micros as i64),
        spent: Microusd(s.spent_micros as i64),
        steps: s.steps,
    }
}

#[async_trait]
impl LedgerBackend for RaftLedger {
    async fn open_run(&self, run_id: &str, budget: Microusd, parent: Option<&str>) {
        let req = Request::Open {
            run: run_id.to_string(),
            budget_micros: budget.0.max(0) as u64,
            parent: parent.map(|p| p.to_string()),
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
                step: resp.step,
            }),
            Ok(resp) => Err(BudgetError::Exceeded {
                // The blocked run may be an ancestor — surface it so the gateway
                // can say "parent run X exceeded" vs "per-run budget exceeded".
                run_id: resp.blocked_run.unwrap_or_else(|| run_id.to_string()),
                budget: Microusd(resp.budget_micros as i64),
                spent: Microusd(resp.spent_micros as i64),
                would: Microusd(
                    (resp.reserved_micros + resp.spent_micros) as i64 + estimate.0.max(0),
                ),
            }),
            // Fail open: if consensus is unreachable, don't block the agent.
            Err(e) => {
                tracing::warn!(run = run_id, "cluster reserve failed open: {e}");
                Ok(Reservation {
                    run_id: run_id.to_string(),
                    amount: estimate,
                    step: 0,
                })
            }
        }
    }

    async fn reserve_unchecked(&self, run_id: &str, estimate: Microusd) -> Reservation {
        // Shadow/warn: record the attempt but always hand back a reservation.
        let step = match self
            .node
            .submit(Request::Reserve {
                run: run_id.to_string(),
                micros: estimate.0.max(0) as u64,
            })
            .await
        {
            Ok(resp) => resp.step,
            Err(_) => 0,
        };
        Reservation {
            run_id: run_id.to_string(),
            amount: estimate,
            step,
        }
    }

    async fn snapshot(&self, run_id: &str) -> Option<RunSnapshot> {
        self.node.sm.read_run(run_id).await.map(snap_of)
    }

    async fn list_runs(&self) -> Vec<(String, RunSnapshot)> {
        self.node
            .sm
            .list_runs()
            .await
            .into_iter()
            .map(|(run, s)| (run, snap_of(s)))
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
