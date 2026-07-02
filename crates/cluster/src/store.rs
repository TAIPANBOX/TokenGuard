//! In-memory raft storage: a log store and a state-machine store.
//!
//! Both are `Clone` handles over an `Arc<Mutex<..>>`, so openraft can take a
//! reader/snapshot-builder as an independent handle sharing the same data. This
//! is the reference in-memory backend; a durable backend (redb/RocksDB) is a
//! drop-in replacement behind the same two traits.

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::io::Cursor;
use std::ops::RangeBounds;
use std::sync::Arc;

use openraft::storage::{
    LogFlushed, LogState, RaftLogStorage, RaftSnapshotBuilder, RaftStateMachine,
};
use openraft::{
    Entry, EntryPayload, LogId, OptionalSend, RaftLogReader, Snapshot, SnapshotMeta, StorageError,
    StoredMembership, Vote,
};
use tokio::sync::Mutex;

use crate::types::{LedgerState, NodeId, Response, TypeConfig};

// ---------------------------------------------------------------------------
// Log store
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct LogInner {
    vote: Option<Vote<NodeId>>,
    log: BTreeMap<u64, Entry<TypeConfig>>,
    committed: Option<LogId<NodeId>>,
    last_purged: Option<LogId<NodeId>>,
}

/// Cloneable handle to the raft log.
#[derive(Clone, Debug, Default)]
pub struct LogStore {
    inner: Arc<Mutex<LogInner>>,
}

impl RaftLogReader<TypeConfig> for LogStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + OptionalSend>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<TypeConfig>>, StorageError<NodeId>> {
        let inner = self.inner.lock().await;
        Ok(inner.log.range(range).map(|(_, v)| v.clone()).collect())
    }
}

impl RaftLogStorage<TypeConfig> for LogStore {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, StorageError<NodeId>> {
        let inner = self.inner.lock().await;
        let last = inner
            .log
            .iter()
            .next_back()
            .map(|(_, e)| e.log_id)
            .or(inner.last_purged);
        Ok(LogState {
            last_purged_log_id: inner.last_purged,
            last_log_id: last,
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &Vote<NodeId>) -> Result<(), StorageError<NodeId>> {
        self.inner.lock().await.vote = Some(*vote);
        Ok(())
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<NodeId>>, StorageError<NodeId>> {
        Ok(self.inner.lock().await.vote)
    }

    async fn save_committed(
        &mut self,
        committed: Option<LogId<NodeId>>,
    ) -> Result<(), StorageError<NodeId>> {
        self.inner.lock().await.committed = committed;
        Ok(())
    }

    async fn read_committed(&mut self) -> Result<Option<LogId<NodeId>>, StorageError<NodeId>> {
        Ok(self.inner.lock().await.committed)
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<TypeConfig>,
    ) -> Result<(), StorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        {
            let mut inner = self.inner.lock().await;
            for entry in entries {
                inner.log.insert(entry.log_id.index, entry);
            }
        }
        // In-memory append is immediately durable; signal completion.
        callback.log_io_completed(Ok(()));
        Ok(())
    }

    async fn truncate(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        let mut inner = self.inner.lock().await;
        let keys: Vec<u64> = inner.log.range(log_id.index..).map(|(k, _)| *k).collect();
        for k in keys {
            inner.log.remove(&k);
        }
        Ok(())
    }

    async fn purge(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        let mut inner = self.inner.lock().await;
        inner.last_purged = Some(log_id);
        let keys: Vec<u64> = inner.log.range(..=log_id.index).map(|(k, _)| *k).collect();
        for k in keys {
            inner.log.remove(&k);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// State machine store
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct StoredSnapshot {
    meta: SnapshotMeta<NodeId, openraft::BasicNode>,
    data: Vec<u8>,
}

#[derive(Debug, Default)]
struct SmInner {
    last_applied: Option<LogId<NodeId>>,
    last_membership: StoredMembership<NodeId, openraft::BasicNode>,
    ledger: LedgerState,
    snapshot_idx: u64,
    current_snapshot: Option<StoredSnapshot>,
}

/// Cloneable handle to the replicated ledger state machine. The gateway keeps a
/// clone to serve fast local (eventually-consistent) reads of a run's spend.
#[derive(Clone, Debug, Default)]
pub struct StateMachineStore {
    inner: Arc<Mutex<SmInner>>,
}

impl StateMachineStore {
    /// Read a run's committed spend and reservations from the local applied
    /// state. On a follower this is eventually consistent; for a linearizable
    /// read, call `Raft::ensure_linearizable()` on the leader first.
    pub async fn read_run(&self, run: &str) -> Option<crate::types::RunState> {
        self.inner.lock().await.ledger.runs.get(run).cloned()
    }

    /// Snapshot every run's replicated accounting (for observability views).
    pub async fn list_runs(&self) -> Vec<(String, crate::types::RunState)> {
        self.inner
            .lock()
            .await
            .ledger
            .runs
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

/// Read-side of a replicated ledger, shared by the in-memory and redb state
/// machines so a node can serve local reads regardless of its backend.
#[async_trait::async_trait]
pub trait LedgerReader: Send + Sync {
    async fn read_run(&self, run: &str) -> Option<crate::types::RunState>;
    async fn list_runs(&self) -> Vec<(String, crate::types::RunState)>;
}

#[async_trait::async_trait]
impl LedgerReader for StateMachineStore {
    async fn read_run(&self, run: &str) -> Option<crate::types::RunState> {
        StateMachineStore::read_run(self, run).await
    }
    async fn list_runs(&self) -> Vec<(String, crate::types::RunState)> {
        StateMachineStore::list_runs(self).await
    }
}

impl RaftSnapshotBuilder<TypeConfig> for StateMachineStore {
    async fn build_snapshot(&mut self) -> Result<Snapshot<TypeConfig>, StorageError<NodeId>> {
        let mut inner = self.inner.lock().await;
        let data = serde_json::to_vec(&inner.ledger).expect("ledger serializes");
        let last_applied = inner.last_applied;
        let last_membership = inner.last_membership.clone();
        inner.snapshot_idx += 1;
        let snapshot_id = match last_applied {
            Some(id) => format!("{}-{}-{}", id.leader_id, id.index, inner.snapshot_idx),
            None => format!("--{}", inner.snapshot_idx),
        };
        let meta = SnapshotMeta {
            last_log_id: last_applied,
            last_membership,
            snapshot_id,
        };
        inner.current_snapshot = Some(StoredSnapshot {
            meta: meta.clone(),
            data: data.clone(),
        });
        Ok(Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(data)),
        })
    }
}

impl RaftStateMachine<TypeConfig> for StateMachineStore {
    type SnapshotBuilder = Self;

    async fn applied_state(
        &mut self,
    ) -> Result<
        (
            Option<LogId<NodeId>>,
            StoredMembership<NodeId, openraft::BasicNode>,
        ),
        StorageError<NodeId>,
    > {
        let inner = self.inner.lock().await;
        Ok((inner.last_applied, inner.last_membership.clone()))
    }

    async fn apply<I>(&mut self, entries: I) -> Result<Vec<Response>, StorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        let mut inner = self.inner.lock().await;
        let mut responses = Vec::new();
        for entry in entries {
            inner.last_applied = Some(entry.log_id);
            match entry.payload {
                EntryPayload::Blank => responses.push(Response::default()),
                EntryPayload::Normal(req) => {
                    let resp = inner.ledger.apply(&req);
                    responses.push(resp);
                }
                EntryPayload::Membership(mem) => {
                    inner.last_membership = StoredMembership::new(Some(entry.log_id), mem);
                    responses.push(Response::default());
                }
            }
        }
        Ok(responses)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        self.clone()
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<Cursor<Vec<u8>>>, StorageError<NodeId>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<NodeId, openraft::BasicNode>,
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<NodeId>> {
        let bytes = snapshot.into_inner();
        let ledger: LedgerState = serde_json::from_slice(&bytes).expect("snapshot deserializes");
        let mut inner = self.inner.lock().await;
        inner.ledger = ledger;
        inner.last_applied = meta.last_log_id;
        inner.last_membership = meta.last_membership.clone();
        inner.current_snapshot = Some(StoredSnapshot {
            meta: meta.clone(),
            data: bytes,
        });
        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<TypeConfig>>, StorageError<NodeId>> {
        let inner = self.inner.lock().await;
        Ok(inner.current_snapshot.as_ref().map(|s| Snapshot {
            meta: s.meta.clone(),
            snapshot: Box::new(Cursor::new(s.data.clone())),
        }))
    }
}
