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

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Path, Request as HttpRequest, State};
use axum::http::{header::AUTHORIZATION, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response as AxumResponse};
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
use crate::redbstore::{open_node_db, RedbLogStore, RedbStateMachineStore};
use crate::store::{LedgerReader, LogStore, StateMachineStore};
use crate::types::{NodeId, Request, Response, RunState, TypeConfig};

/// A raft node reachable over HTTP: its `Raft` handle, a read handle for local
/// (eventually-consistent) reads, and the peer map it was built with.
pub struct HttpNode {
    pub id: NodeId,
    pub raft: Raft<TypeConfig>,
    pub sm: Arc<dyn LedgerReader>,
    pub peers: Peers,
    /// Shared cluster token. When set, every endpoint except `/healthz` requires
    /// `Authorization: Bearer <token>`, and this node presents it to peers.
    pub token: Option<Arc<str>>,
}

impl HttpNode {
    /// Build a node with **in-memory** storage (fast; state lost on restart).
    /// `peers` maps every member id (including this one) to its base URL.
    /// `token`, if set, secures every endpoint except `/healthz`.
    pub async fn build(
        id: NodeId,
        peers: Peers,
        token: Option<String>,
    ) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
        let config = Arc::new(crate::node_config().validate()?);
        let sm = StateMachineStore::default();
        let network = HttpNetwork::with_token(peers.clone(), token.clone());
        let raft = Raft::new(id, config, network, LogStore::default(), sm.clone()).await?;
        Ok(Arc::new(Self {
            id,
            raft,
            sm: Arc::new(sm),
            peers,
            token: token.map(Arc::from),
        }))
    }

    /// Build a node with **durable** redb storage under `dir` — budgets survive a
    /// process restart. One redb file per node (`<dir>/node-<id>.redb`).
    pub async fn build_durable(
        id: NodeId,
        peers: Peers,
        dir: impl AsRef<std::path::Path>,
        token: Option<String>,
    ) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
        let config = Arc::new(crate::node_config().validate()?);
        let db = open_node_db(dir, id)?;
        let log = RedbLogStore::new(db.clone())?;
        let sm = RedbStateMachineStore::new(db)?;
        let network = HttpNetwork::with_token(peers.clone(), token.clone());
        let raft = Raft::new(id, config, network, log, sm.clone()).await?;
        Ok(Arc::new(Self {
            id,
            raft,
            sm: Arc::new(sm),
            peers,
            token: token.map(Arc::from),
        }))
    }

    /// Initialize the cluster with the configured members (call on exactly one
    /// node). Each member's address travels in its `BasicNode`, so nodes can be
    /// reached from the replicated membership. Returns `Ok` on success or if it
    /// was already initialized.
    pub async fn init(&self) -> Result<(), String> {
        let members: BTreeMap<NodeId, BasicNode> = self
            .peers
            .iter()
            .map(|(&i, url)| (i, BasicNode::new(url)))
            .collect();
        self.raft
            .initialize(members)
            .await
            .map_err(|e| e.to_string())
    }

    /// Initialize a single-voter cluster (just this node). Grow it afterwards
    /// with [`add_learner`](Self::add_learner) + [`change_membership`].
    pub async fn init_single(&self) -> Result<(), String> {
        let url = self.peers.get(&self.id).cloned().unwrap_or_default();
        let members = BTreeMap::from([(self.id, BasicNode::new(url))]);
        self.raft
            .initialize(members)
            .await
            .map_err(|e| e.to_string())
    }

    /// Add a learner (a node that replicates but does not vote) at `addr`,
    /// blocking until it catches up. Promote it to a voter with
    /// [`change_membership`](Self::change_membership).
    pub async fn add_learner(&self, id: NodeId, addr: &str) -> Result<(), String> {
        self.raft
            .add_learner(id, BasicNode::new(addr), true)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Set the voter set (join/leave). Learners not in the set are demoted;
    /// call `add_learner` first for any new voter.
    pub async fn change_membership(&self, voters: BTreeSet<NodeId>) -> Result<(), String> {
        self.raft
            .change_membership(voters, false)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// **Linearizable** read of a run: confirms leadership + a committed read
    /// index before reading, and forwards to the leader if this node is a
    /// follower. Stronger than [`sm.read_run`](crate::store::LedgerReader), which
    /// is an eventually-consistent local read.
    pub async fn read_run_linearizable(&self, run: &str) -> Result<Option<RunState>, String> {
        use openraft::error::{CheckIsLeaderError, ForwardToLeader, RaftError};
        match self.raft.ensure_linearizable().await {
            Ok(_) => Ok(self.sm.read_run(run).await),
            Err(RaftError::APIError(CheckIsLeaderError::ForwardToLeader(ForwardToLeader {
                leader_id: Some(leader),
                ..
            }))) if leader != self.id => match self.peers.get(&leader) {
                Some(base) => {
                    let tok = self.token.as_ref().map(|t| t.to_string());
                    match Client::with_token(base.clone(), tok).read_linear(run).await {
                        Ok(inner) => inner,
                        Err(e) => Err(e.to_string()),
                    }
                }
                None => Err(format!("no address for leader {leader}")),
            },
            Err(e) => Err(e.to_string()),
        }
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
                    Some(base) => {
                        let tok = self.token.as_ref().map(|t| t.to_string());
                        match Client::with_token(base.clone(), tok).write(&req).await {
                            Ok(inner) => inner,
                            Err(e) => Err(e.to_string()),
                        }
                    }
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

/// Reject requests without a valid `Authorization: Bearer <token>` when the node
/// has a cluster token configured. `/healthz` is exempt (mounted separately).
async fn require_auth(
    State(n): State<Arc<HttpNode>>,
    req: HttpRequest,
    next: Next,
) -> AxumResponse {
    match &n.token {
        None => next.run(req).await,
        Some(tok) => {
            let ok = req
                .headers()
                .get(AUTHORIZATION)
                .and_then(|h| h.to_str().ok())
                .map(|h| h == format!("Bearer {tok}"))
                .unwrap_or(false);
            if ok {
                next.run(req).await
            } else {
                (StatusCode::UNAUTHORIZED, "unauthorized").into_response()
            }
        }
    }
}

/// Build the axum router for a node. All endpoints except `/healthz` require the
/// cluster token (when one is configured).
pub fn router(node: Arc<HttpNode>) -> Router {
    let protected = Router::new()
        .route("/raft/append", post(r_append))
        .route("/raft/vote", post(r_vote))
        .route("/raft/snapshot", post(r_snapshot))
        .route("/mgmt/init", post(m_init))
        .route("/mgmt/init-single", post(m_init_single))
        .route("/mgmt/add-learner", post(m_add_learner))
        .route("/mgmt/change-membership", post(m_change_membership))
        .route("/mgmt/metrics", get(m_metrics))
        .route("/api/write", post(a_write))
        .route("/api/read/{run}", get(a_read))
        .route("/api/read-linear/{run}", get(a_read_linear))
        .route_layer(middleware::from_fn_with_state(node.clone(), require_auth))
        .with_state(node.clone());
    let public = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .with_state(node);
    protected.merge(public)
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

/// Install the process-level rustls crypto provider exactly once. rustls 0.23
/// requires this when more than one backend is compiled in.
fn install_crypto_provider() {
    static PROVIDER: std::sync::Once = std::sync::Once::new();
    PROVIDER.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// Serve this node over **HTTPS** with the given PEM cert + key. Peer/admin URLs
/// must then use `https://`; clients trust the cert via a public CA or
/// `TOKENFUSE_CLUSTER_CA`.
pub async fn serve_tls(
    node: Arc<HttpNode>,
    addr: SocketAddr,
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
) -> std::io::Result<()> {
    install_crypto_provider();
    let config = axum_server::tls_rustls::RustlsConfig::from_pem(cert_pem, key_pem).await?;
    axum_server::bind_rustls(addr, config)
        .serve(router(node).into_make_service())
        .await
}

/// Serve over **mutual TLS**: in addition to presenting `cert_pem`/`key_pem`, the
/// server *requires* every peer to present a client certificate signed by
/// `client_ca_pem`. Combined with the bearer token this gives cryptographic peer
/// authentication for the raft mesh — an unauthenticated TCP client can't even
/// complete the handshake. Peers must set `TOKENFUSE_CLUSTER_CLIENT_CERT/_KEY`.
pub async fn serve_mtls(
    node: Arc<HttpNode>,
    addr: SocketAddr,
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    client_ca_pem: Vec<u8>,
) -> std::io::Result<()> {
    install_crypto_provider();

    let ioerr = |e: String| std::io::Error::new(std::io::ErrorKind::InvalidInput, e);

    // Trust anchors for verifying client certs.
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut &client_ca_pem[..]) {
        let cert = cert.map_err(|e| ioerr(format!("client CA parse: {e}")))?;
        roots
            .add(cert)
            .map_err(|e| ioerr(format!("client CA add: {e}")))?;
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| ioerr(format!("client verifier: {e}")))?;

    // This node's own serving cert chain + key.
    let certs = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ioerr(format!("server cert parse: {e}")))?;
    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .map_err(|e| ioerr(format!("server key parse: {e}")))?
        .ok_or_else(|| ioerr("no private key in TLS key PEM".into()))?;

    let server_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|e| ioerr(format!("server config: {e}")))?;

    let config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(server_config));
    axum_server::bind_rustls(addr, config)
        .serve(router(node).into_make_service())
        .await
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
    Json(n.init().await)
}

async fn m_init_single(State(n): State<Arc<HttpNode>>) -> Json<Result<(), String>> {
    Json(n.init_single().await)
}

#[derive(Deserialize)]
struct AddLearner {
    id: NodeId,
    addr: String,
}

async fn m_add_learner(
    State(n): State<Arc<HttpNode>>,
    Json(body): Json<AddLearner>,
) -> Json<Result<(), String>> {
    Json(n.add_learner(body.id, &body.addr).await)
}

async fn m_change_membership(
    State(n): State<Arc<HttpNode>>,
    Json(voters): Json<BTreeSet<NodeId>>,
) -> Json<Result<(), String>> {
    Json(n.change_membership(voters).await)
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

async fn a_read_linear(
    State(n): State<Arc<HttpNode>>,
    Path(run): Path<String>,
) -> Json<Result<Option<RunState>, String>> {
    Json(n.read_run_linearizable(&run).await)
}

// ---- thin client (for the demo binary and tests) --------------------------

/// A minimal HTTP client for a node's management + application API.
pub struct Client {
    base: String,
    http: reqwest::Client,
    token: Option<String>,
}

impl Client {
    pub fn new(base: impl Into<String>) -> Self {
        Self::with_token(base, None)
    }

    /// `token`, if set, is sent as `Authorization: Bearer <token>` on every call.
    pub fn with_token(base: impl Into<String>, token: Option<String>) -> Self {
        Self {
            base: base.into(),
            http: crate::net_http::build_client(),
            token,
        }
    }

    fn post(&self, path: &str) -> reqwest::RequestBuilder {
        let b = self.http.post(format!("{}{}", self.base, path));
        match &self.token {
            Some(t) => b.bearer_auth(t),
            None => b,
        }
    }

    fn get(&self, path: &str) -> reqwest::RequestBuilder {
        let b = self.http.get(format!("{}{}", self.base, path));
        match &self.token {
            Some(t) => b.bearer_auth(t),
            None => b,
        }
    }

    pub async fn init(&self) -> Result<Result<(), String>, reqwest::Error> {
        self.post("/mgmt/init").send().await?.json().await
    }

    pub async fn init_single(&self) -> Result<Result<(), String>, reqwest::Error> {
        self.post("/mgmt/init-single").send().await?.json().await
    }

    pub async fn add_learner(
        &self,
        id: NodeId,
        addr: &str,
    ) -> Result<Result<(), String>, reqwest::Error> {
        self.post("/mgmt/add-learner")
            .json(&serde_json::json!({ "id": id, "addr": addr }))
            .send()
            .await?
            .json()
            .await
    }

    pub async fn change_membership(
        &self,
        voters: &BTreeSet<NodeId>,
    ) -> Result<Result<(), String>, reqwest::Error> {
        self.post("/mgmt/change-membership")
            .json(voters)
            .send()
            .await?
            .json()
            .await
    }

    pub async fn metrics(&self) -> Result<MetricsSummary, reqwest::Error> {
        self.get("/mgmt/metrics").send().await?.json().await
    }

    pub async fn write(&self, req: &Request) -> Result<Result<Response, String>, reqwest::Error> {
        self.post("/api/write").json(req).send().await?.json().await
    }

    pub async fn read(&self, run: &str) -> Result<Option<RunState>, reqwest::Error> {
        self.get(&format!("/api/read/{run}"))
            .send()
            .await?
            .json()
            .await
    }

    pub async fn read_linear(
        &self,
        run: &str,
    ) -> Result<Result<Option<RunState>, String>, reqwest::Error> {
        self.get(&format!("/api/read-linear/{run}"))
            .send()
            .await?
            .json()
            .await
    }
}
