//! TokenFuse HA cluster: a raft-replicated budget ledger.
//!
//! A single gateway is a single point of failure and a single point of budget
//! truth. This crate replicates the ledger across N nodes with the [openraft]
//! consensus library so that:
//!
//! * budgets survive a node crash (the ledger is committed to a quorum), and
//! * the affordability check is **linearized** — `Reserve` is a log entry, so
//!   two sub-agents racing against different nodes can never both slip past the
//!   same budget ceiling.
//!
//! The [`Cluster`] helper wires up an in-process 3-node cluster for the demo
//! and tests; the [`store`] and [`network`] pieces are the real openraft
//! backends (swap the in-memory store for redb and the router for HTTP to
//! deploy).

pub mod net_http;
pub mod network;
pub mod redbstore;
pub mod server;
pub mod store;
pub mod types;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use openraft::{BasicNode, Config, Raft};

use crate::network::Router;
use crate::store::{LogStore, StateMachineStore};
use crate::types::{NodeId, Request, Response, RunState, TypeConfig};

/// A single running raft node: its `Raft` handle plus a state-machine clone for
/// local reads.
pub struct Node {
    pub id: NodeId,
    pub raft: Raft<TypeConfig>,
    pub sm: StateMachineStore,
}

impl Node {
    /// Read a run's replicated accounting from this node's local applied state.
    /// Eventually consistent on followers.
    pub async fn read_run(&self, run: &str) -> Option<RunState> {
        self.sm.read_run(run).await
    }
}

/// An in-process cluster of raft nodes sharing one router.
pub struct Cluster {
    pub nodes: Vec<Node>,
    #[allow(dead_code)]
    router: Router,
}

/// Raft timings shared by the in-process and HTTP nodes. Fast enough that tests
/// and the demo converge in well under a second; real deployments raise the
/// election window to tolerate network jitter.
pub fn node_config() -> Config {
    Config {
        cluster_name: "tokenfuse".to_string(),
        heartbeat_interval: 50,
        election_timeout_min: 150,
        election_timeout_max: 300,
        ..Default::default()
    }
}

impl Cluster {
    /// Build and initialize an N-node cluster (single-region, in process).
    /// Node `ids[0]` initializes membership and becomes the initial leader.
    pub async fn start(ids: &[NodeId]) -> Result<Self, Box<dyn std::error::Error>> {
        let config = Arc::new(node_config().validate()?);
        let router = Router::default();

        let mut nodes = Vec::new();
        for &id in ids {
            // Keep a clone of the state machine so we can serve local reads; the
            // clone shares the same `Arc<Mutex<..>>` the Raft applies entries to.
            let sm = StateMachineStore::default();
            let raft = Raft::new(
                id,
                config.clone(),
                router.clone(),
                LogStore::default(),
                sm.clone(),
            )
            .await?;
            router.register(id, raft.clone()).await;
            nodes.push(Node { id, raft, sm });
        }

        // Initialize membership on the first node.
        let members: BTreeMap<NodeId, BasicNode> =
            ids.iter().map(|&i| (i, BasicNode::default())).collect();
        nodes[0].raft.initialize(members).await?;

        Ok(Self { nodes, router })
    }

    /// The current leader id, if one is elected.
    pub async fn leader(&self) -> Option<NodeId> {
        for n in &self.nodes {
            if let Some(l) = n.raft.current_leader().await {
                return Some(l);
            }
        }
        None
    }

    /// Node handle by id.
    pub fn node(&self, id: NodeId) -> Option<&Node> {
        self.nodes.iter().find(|n| n.id == id)
    }

    /// Wait until a leader is elected (or time out).
    pub async fn wait_for_leader(&self, timeout: Duration) -> Option<NodeId> {
        let start = tokio::time::Instant::now();
        loop {
            if let Some(l) = self.leader().await {
                return Some(l);
            }
            if start.elapsed() > timeout {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Submit a write through the current leader and return the applied response.
    pub async fn write(&self, req: Request) -> Result<Response, Box<dyn std::error::Error>> {
        let leader_id = self.leader().await.ok_or("no leader elected")?;
        let leader = self.node(leader_id).ok_or("leader not local")?;
        let resp = leader.raft.client_write(req).await?;
        Ok(resp.data)
    }

    /// Gracefully shut down every node.
    pub async fn shutdown(self) {
        for n in self.nodes {
            let _ = n.raft.shutdown().await;
        }
    }

    /// Membership as a set (for change_membership calls).
    pub fn member_ids(&self) -> BTreeSet<NodeId> {
        self.nodes.iter().map(|n| n.id).collect()
    }
}
