//! Per-node HTTP server: exposes the raft RPC endpoints that [`crate::net_http`]
//! calls between peers, plus a small management + application API.
//!
//! Endpoints:
//! * `POST /raft/append`   · `POST /raft/vote` · `POST /raft/snapshot` — raft RPCs
//! * `POST /mgmt/init`     — initialize the cluster with the configured members
//! * `GET  /mgmt/metrics`  — `{ id, leader, state }` summary
//! * `POST /api/write`     — submit a `Request` (routed by raft to the leader)
//! * `GET  /api/read/{run}`— local (eventually-consistent) read of a run
//! * `GET  /healthz`

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use openraft::error::{InstallSnapshotError, RaftError};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use openraft::{BasicNode, Raft};
use serde::{Deserialize, Serialize};

use crate::net_http::{HttpNetwork, Peers};
use crate::store::{LogStore, StateMachineStore};
use crate::types::{NodeId, Request, Response, RunState, TypeConfig};

/// A raft node reachable over HTTP: its `Raft` handle, a state-machine clone for
/// local reads, and the peer map it was built with.
pub struct HttpNode {
    pub id: NodeId,
    pub raft: Raft<TypeConfig>,
    pub sm: StateMachineStore,
    pub peers: Peers,
}

impl HttpNode {
    /// Build a node whose replication uses the HTTP transport. `peers` maps every
    /// member id (including this one) to its base URL.
    pub async fn build(id: NodeId, peers: Peers) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
        let config = Arc::new(crate::node_config().validate()?);
        let sm = StateMachineStore::default();
        let network = HttpNetwork::new(peers.clone());
        let raft = Raft::new(id, config, network, LogStore::default(), sm.clone()).await?;
        Ok(Arc::new(Self {
            id,
            raft,
            sm,
            peers,
        }))
    }

    /// Initialize the cluster with the configured members (call on exactly one
    /// node). Returns `Ok` on success or if it was already initialized.
    pub async fn init(&self) -> Result<(), String> {
        let members: BTreeMap<NodeId, BasicNode> = self
            .peers
            .keys()
            .map(|&i| (i, BasicNode::default()))
            .collect();
        self.raft
            .initialize(members)
            .await
            .map_err(|e| e.to_string())
    }

    /// Submit a write, transparently forwarding to the current leader over HTTP
    /// if this node is a follower. Returns the applied [`Response`] or a
    /// human-readable error. This keeps all openraft error handling inside the
    /// cluster crate so embedders (the gateway) need only its public API.
    pub async fn submit(&self, req: Request) -> Result<Response, String> {
        use openraft::error::{ClientWriteError, RaftError};
        match self.raft.client_write(req.clone()).await {
            Ok(r) => Ok(r.data),
            Err(RaftError::APIError(ClientWriteError::ForwardToLeader(f))) => match f.leader_id {
                Some(leader) if leader != self.id => match self.peers.get(&leader) {
                    Some(base) => match Client::new(base.clone()).write(&req).await {
                        Ok(inner) => inner,
                        Err(e) => Err(e.to_string()),
                    },
                    None => Err(format!("no address for leader {leader}")),
                },
                _ => Err("no leader elected".into()),
            },
            Err(e) => Err(e.to_string()),
        }
    }
}

/// A compact, serde-friendly view of a node's raft metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSummary {
    pub id: NodeId,
    pub leader: Option<NodeId>,
    pub state: String,
}

/// Build the axum router for a node.
pub fn router(node: Arc<HttpNode>) -> Router {
    Router::new()
        .route("/raft/append", post(r_append))
        .route("/raft/vote", post(r_vote))
        .route("/raft/snapshot", post(r_snapshot))
        .route("/mgmt/init", post(m_init))
        .route("/mgmt/metrics", get(m_metrics))
        .route("/api/write", post(a_write))
        .route("/api/read/{run}", get(a_read))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(node)
}

/// Bind `addr` and serve this node until the process exits.
pub async fn serve(node: Arc<HttpNode>, addr: SocketAddr) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    serve_on(node, listener).await
}

/// Serve this node on an already-bound listener (useful for tests that bind to
/// an OS-assigned `:0` port before wiring up the peer map).
pub async fn serve_on(
    node: Arc<HttpNode>,
    listener: tokio::net::TcpListener,
) -> std::io::Result<()> {
    axum::serve(listener, router(node)).await
}

// ---- raft RPC endpoints ---------------------------------------------------

async fn r_append(
    State(n): State<Arc<HttpNode>>,
    Json(rpc): Json<AppendEntriesRequest<TypeConfig>>,
) -> Json<Result<AppendEntriesResponse<NodeId>, RaftError<NodeId>>> {
    Json(n.raft.append_entries(rpc).await)
}

async fn r_vote(
    State(n): State<Arc<HttpNode>>,
    Json(rpc): Json<VoteRequest<NodeId>>,
) -> Json<Result<VoteResponse<NodeId>, RaftError<NodeId>>> {
    Json(n.raft.vote(rpc).await)
}

async fn r_snapshot(
    State(n): State<Arc<HttpNode>>,
    Json(rpc): Json<InstallSnapshotRequest<TypeConfig>>,
) -> Json<Result<InstallSnapshotResponse<NodeId>, RaftError<NodeId, InstallSnapshotError>>> {
    Json(n.raft.install_snapshot(rpc).await)
}

// ---- management endpoints -------------------------------------------------

async fn m_init(State(n): State<Arc<HttpNode>>) -> Json<Result<(), String>> {
    let members: BTreeMap<NodeId, BasicNode> =
        n.peers.keys().map(|&i| (i, BasicNode::default())).collect();
    Json(n.raft.initialize(members).await.map_err(|e| e.to_string()))
}

async fn m_metrics(State(n): State<Arc<HttpNode>>) -> Json<MetricsSummary> {
    let m = n.raft.metrics().borrow().clone();
    Json(MetricsSummary {
        id: n.id,
        leader: m.current_leader,
        state: format!("{:?}", m.state),
    })
}

// ---- application endpoints ------------------------------------------------

async fn a_write(
    State(n): State<Arc<HttpNode>>,
    Json(req): Json<Request>,
) -> Json<Result<Response, String>> {
    Json(
        n.raft
            .client_write(req)
            .await
            .map(|r| r.data)
            .map_err(|e| e.to_string()),
    )
}

async fn a_read(State(n): State<Arc<HttpNode>>, Path(run): Path<String>) -> Json<Option<RunState>> {
    Json(n.sm.read_run(&run).await)
}

// ---- thin client (for the demo binary and tests) --------------------------

/// A minimal HTTP client for a node's management + application API.
pub struct Client {
    base: String,
    http: reqwest::Client,
}

impl Client {
    pub fn new(base: impl Into<String>) -> Self {
        Self {
            base: base.into(),
            http: reqwest::Client::new(),
        }
    }

    pub async fn init(&self) -> Result<Result<(), String>, reqwest::Error> {
        self.http
            .post(format!("{}/mgmt/init", self.base))
            .send()
            .await?
            .json()
            .await
    }

    pub async fn metrics(&self) -> Result<MetricsSummary, reqwest::Error> {
        self.http
            .get(format!("{}/mgmt/metrics", self.base))
            .send()
            .await?
            .json()
            .await
    }

    pub async fn write(&self, req: &Request) -> Result<Result<Response, String>, reqwest::Error> {
        self.http
            .post(format!("{}/api/write", self.base))
            .json(req)
            .send()
            .await?
            .json()
            .await
    }

    pub async fn read(&self, run: &str) -> Result<Option<RunState>, reqwest::Error> {
        self.http
            .get(format!("{}/api/read/{run}", self.base))
            .send()
            .await?
            .json()
            .await
    }
}
