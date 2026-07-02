//! Cross-process raft transport over HTTP.
//!
//! `HttpNetwork` is a [`RaftNetworkFactory`] that resolves a target node id to a
//! peer base URL and POSTs the three raft RPCs as JSON to that peer's
//! [`crate::server`] endpoints. This is what lets a cluster form across separate
//! processes / machines instead of only in one process (see [`crate::network`]
//! for the in-process router used by tests and the single-binary demo).
//!
//! Wire contract (must match `crate::server`):
//! * `POST {peer}/raft/append`   → `Result<AppendEntriesResponse, RaftError>`
//! * `POST {peer}/raft/vote`     → `Result<VoteResponse, RaftError>`
//! * `POST {peer}/raft/snapshot` → `Result<InstallSnapshotResponse, RaftError<_, InstallSnapshotError>>`

use std::collections::BTreeMap;
use std::sync::Arc;

use openraft::error::{InstallSnapshotError, NetworkError, RPCError, RaftError, RemoteError};
use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use openraft::BasicNode;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::types::{NodeId, TypeConfig};

/// Maps node id → peer base URL (e.g. `http://127.0.0.1:5001`).
pub type Peers = Arc<BTreeMap<NodeId, String>>;

/// HTTP raft network factory shared by all replication tasks on a node.
#[derive(Clone)]
pub struct HttpNetwork {
    peers: Peers,
    client: reqwest::Client,
    token: Option<Arc<str>>,
}

impl HttpNetwork {
    pub fn new(peers: Peers) -> Self {
        Self::with_token(peers, None)
    }

    /// `token`, if set, is sent as `Authorization: Bearer <token>` on every peer
    /// RPC (must match the peers' `TOKENFUSE_CLUSTER_TOKEN`).
    pub fn with_token(peers: Peers, token: Option<String>) -> Self {
        Self {
            peers,
            client: reqwest::Client::new(),
            token: token.map(Arc::from),
        }
    }
}

impl RaftNetworkFactory<TypeConfig> for HttpNetwork {
    type Network = HttpConn;

    async fn new_client(&mut self, target: NodeId, node: &BasicNode) -> Self::Network {
        // Prefer the address carried in the replicated membership (so nodes added
        // at runtime via add_learner are reachable); fall back to the static
        // bootstrap peer map for the initial members.
        let base = if !node.addr.is_empty() {
            node.addr.clone()
        } else {
            self.peers.get(&target).cloned().unwrap_or_default()
        };
        HttpConn {
            target,
            base,
            client: self.client.clone(),
            token: self.token.clone(),
        }
    }
}

/// A one-peer HTTP connection.
pub struct HttpConn {
    target: NodeId,
    base: String,
    client: reqwest::Client,
    token: Option<Arc<str>>,
}

impl HttpConn {
    /// POST `req` as JSON to `{base}{path}` and decode the JSON body as `Resp`.
    /// Transport-level failures map to `Unreachable`/`NetworkError`.
    async fn post<Req, Resp, E>(
        &self,
        path: &str,
        req: &Req,
    ) -> Result<Resp, RPCError<NodeId, BasicNode, E>>
    where
        Req: Serialize,
        Resp: DeserializeOwned,
        E: std::error::Error,
    {
        if self.base.is_empty() {
            let e = std::io::Error::new(std::io::ErrorKind::NotConnected, "no url for peer");
            return Err(RPCError::Network(NetworkError::new(&e)));
        }
        let url = format!("{}{}", self.base, path);
        let mut builder = self.client.post(&url).json(req);
        if let Some(tok) = &self.token {
            builder = builder.bearer_auth(tok);
        }
        let resp = builder
            .send()
            .await
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))?;
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))?;
        serde_json::from_slice(&bytes).map_err(|e| RPCError::Network(NetworkError::new(&e)))
    }
}

impl RaftNetwork<TypeConfig> for HttpConn {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        let res: Result<AppendEntriesResponse<NodeId>, RaftError<NodeId>> =
            self.post("/raft/append", &rpc).await?;
        res.map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<NodeId>,
        _option: RPCOption,
    ) -> Result<VoteResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        let res: Result<VoteResponse<NodeId>, RaftError<NodeId>> =
            self.post("/raft/vote", &rpc).await?;
        res.map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<NodeId>,
        RPCError<NodeId, BasicNode, RaftError<NodeId, InstallSnapshotError>>,
    > {
        let res: Result<InstallSnapshotResponse<NodeId>, RaftError<NodeId, InstallSnapshotError>> =
            self.post("/raft/snapshot", &rpc).await?;
        res.map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
    }
}
