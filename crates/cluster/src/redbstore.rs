//! Durable raft storage backed by [redb] — an embedded, pure-Rust ACID key-value
//! store (single file, no C deps). Drop-in replacements for the in-memory
//! `LogStore` / `StateMachineStore` behind the same openraft traits, so budgets
//! survive a **process restart**, not just a node crash within a live cluster.
//!
//! One redb file per node holds three tables: the raft log (`index → Entry`),
//! raft metadata (`vote` / `committed` / `purged`), and the state machine
//! (`state` blob + `snapshot` blob). Writes commit before returning, giving the
//! durability openraft's contract requires.
//!
//! [redb]: https://docs.rs/redb
//!
// openraft's `StorageError` is intentionally rich (and large); its size is out
// of our control, so allow the large-Err lint for this backend.
#![allow(clippy::result_large_err)]

use std::fmt::Debug;
use std::io::Cursor;
use std::ops::RangeBounds;
use std::path::Path;
use std::sync::Arc;

use openraft::storage::{
    LogFlushed, LogState, RaftLogStorage, RaftSnapshotBuilder, RaftStateMachine,
};
use openraft::{
    AnyError, Entry, EntryPayload, LogId, OptionalSend, RaftLogReader, Snapshot, SnapshotMeta,
    StorageError, StorageIOError, StoredMembership, Vote,
};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::store::LedgerReader;
use crate::types::{LedgerState, NodeId, Response, RunState, TypeConfig};

const LOG: TableDefinition<u64, &[u8]> = TableDefinition::new("raft_log");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("raft_meta");
const SM: TableDefinition<&str, &[u8]> = TableDefinition::new("state_machine");

// ---- error helpers --------------------------------------------------------

fn wl(e: impl std::error::Error + 'static) -> StorageError<NodeId> {
    StorageIOError::write_logs(AnyError::new(&e)).into()
}
fn rl(e: impl std::error::Error + 'static) -> StorageError<NodeId> {
    StorageIOError::read_logs(AnyError::new(&e)).into()
}
fn wv(e: impl std::error::Error + 'static) -> StorageError<NodeId> {
    StorageIOError::write_vote(AnyError::new(&e)).into()
}
fn wsm(e: impl std::error::Error + 'static) -> StorageError<NodeId> {
    StorageIOError::write_state_machine(AnyError::new(&e)).into()
}
fn rsm(e: impl std::error::Error + 'static) -> StorageError<NodeId> {
    StorageIOError::read_state_machine(AnyError::new(&e)).into()
}

/// Open (or create) the redb database for node `id` under `dir`.
pub fn open_node_db(
    dir: impl AsRef<Path>,
    id: NodeId,
) -> Result<Arc<Database>, redb::DatabaseError> {
    std::fs::create_dir_all(dir.as_ref()).ok();
    let path = dir.as_ref().join(format!("node-{id}.redb"));
    Ok(Arc::new(Database::create(path)?))
}

// ---------------------------------------------------------------------------
// Log store
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct RedbLogStore {
    db: Arc<Database>,
}

impl RedbLogStore {
    pub fn new(db: Arc<Database>) -> Result<Self, StorageError<NodeId>> {
        // Ensure the tables exist so first reads don't fail.
        let w = db.begin_write().map_err(wl)?;
        {
            w.open_table(LOG).map_err(wl)?;
            w.open_table(META).map_err(wl)?;
        }
        w.commit().map_err(wl)?;
        Ok(Self { db })
    }

    fn get_meta<T: for<'de> Deserialize<'de>>(
        &self,
        key: &str,
    ) -> Result<Option<T>, StorageError<NodeId>> {
        let r = self.db.begin_read().map_err(rl)?;
        let t = r.open_table(META).map_err(rl)?;
        match t.get(key).map_err(rl)? {
            Some(v) => Ok(Some(serde_json::from_slice(v.value()).map_err(rl)?)),
            None => Ok(None),
        }
    }

    fn put_meta<T: Serialize>(&self, key: &str, val: &T) -> Result<(), StorageError<NodeId>> {
        let bytes = serde_json::to_vec(val).map_err(wv)?;
        let w = self.db.begin_write().map_err(wv)?;
        {
            let mut t = w.open_table(META).map_err(wv)?;
            t.insert(key, bytes.as_slice()).map_err(wv)?;
        }
        w.commit().map_err(wv)?;
        Ok(())
    }
}

impl RaftLogReader<TypeConfig> for RedbLogStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + OptionalSend>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<TypeConfig>>, StorageError<NodeId>> {
        let start = match range.start_bound() {
            std::ops::Bound::Included(&x) => x,
            std::ops::Bound::Excluded(&x) => x + 1,
            std::ops::Bound::Unbounded => 0,
        };
        let end = match range.end_bound() {
            std::ops::Bound::Included(&x) => x + 1,
            std::ops::Bound::Excluded(&x) => x,
            std::ops::Bound::Unbounded => u64::MAX,
        };
        let r = self.db.begin_read().map_err(rl)?;
        let t = r.open_table(LOG).map_err(rl)?;
        let mut out = Vec::new();
        for kv in t.range(start..end).map_err(rl)? {
            let (_, v) = kv.map_err(rl)?;
            out.push(serde_json::from_slice(v.value()).map_err(rl)?);
        }
        Ok(out)
    }
}

impl RaftLogStorage<TypeConfig> for RedbLogStore {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, StorageError<NodeId>> {
        let last_purged: Option<LogId<NodeId>> = self.get_meta("purged")?;
        let r = self.db.begin_read().map_err(rl)?;
        let t = r.open_table(LOG).map_err(rl)?;
        let last = match t.last().map_err(rl)? {
            Some((_, v)) => {
                let e: Entry<TypeConfig> = serde_json::from_slice(v.value()).map_err(rl)?;
                Some(e.log_id)
            }
            None => last_purged,
        };
        Ok(LogState {
            last_purged_log_id: last_purged,
            last_log_id: last,
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &Vote<NodeId>) -> Result<(), StorageError<NodeId>> {
        self.put_meta("vote", vote)
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<NodeId>>, StorageError<NodeId>> {
        self.get_meta("vote")
    }

    async fn save_committed(
        &mut self,
        committed: Option<LogId<NodeId>>,
    ) -> Result<(), StorageError<NodeId>> {
        self.put_meta("committed", &committed)
    }

    async fn read_committed(&mut self) -> Result<Option<LogId<NodeId>>, StorageError<NodeId>> {
        Ok(self.get_meta("committed")?.flatten())
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
        let w = self.db.begin_write().map_err(wl)?;
        {
            let mut t = w.open_table(LOG).map_err(wl)?;
            for entry in entries {
                let bytes = serde_json::to_vec(&entry).map_err(wl)?;
                t.insert(entry.log_id.index, bytes.as_slice()).map_err(wl)?;
            }
        }
        // Commit (durable) before signalling completion.
        w.commit().map_err(wl)?;
        callback.log_io_completed(Ok(()));
        Ok(())
    }

    async fn truncate(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        let w = self.db.begin_write().map_err(wl)?;
        {
            let mut t = w.open_table(LOG).map_err(wl)?;
            let keys: Vec<u64> = t
                .range(log_id.index..)
                .map_err(wl)?
                .map(|kv| kv.map(|(k, _)| k.value()))
                .collect::<Result<_, _>>()
                .map_err(wl)?;
            for k in keys {
                t.remove(k).map_err(wl)?;
            }
        }
        w.commit().map_err(wl)?;
        Ok(())
    }

    async fn purge(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        self.put_meta("purged", &Some(log_id))?;
        let w = self.db.begin_write().map_err(wl)?;
        {
            let mut t = w.open_table(LOG).map_err(wl)?;
            let keys: Vec<u64> = t
                .range(..=log_id.index)
                .map_err(wl)?
                .map(|kv| kv.map(|(k, _)| k.value()))
                .collect::<Result<_, _>>()
                .map_err(wl)?;
            for k in keys {
                t.remove(k).map_err(wl)?;
            }
        }
        w.commit().map_err(wl)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// State machine store
// ---------------------------------------------------------------------------

#[derive(Default, Serialize, Deserialize, Clone)]
struct SmPersist {
    last_applied: Option<LogId<NodeId>>,
    last_membership: StoredMembership<NodeId, openraft::BasicNode>,
    ledger: LedgerState,
}

#[derive(Serialize, Deserialize, Clone)]
struct StoredSnapshot {
    meta: SnapshotMeta<NodeId, openraft::BasicNode>,
    data: Vec<u8>,
}

struct SmMem {
    persist: SmPersist,
    snapshot: Option<StoredSnapshot>,
    snapshot_idx: u64,
}

#[derive(Clone)]
pub struct RedbStateMachineStore {
    db: Arc<Database>,
    mem: Arc<Mutex<SmMem>>,
}

impl RedbStateMachineStore {
    /// Open the state machine, loading any persisted state + snapshot from redb.
    pub fn new(db: Arc<Database>) -> Result<Self, StorageError<NodeId>> {
        let w = db.begin_write().map_err(wsm)?;
        {
            w.open_table(SM).map_err(wsm)?;
        }
        w.commit().map_err(wsm)?;

        let (persist, snapshot) = {
            let r = db.begin_read().map_err(rsm)?;
            let t = r.open_table(SM).map_err(rsm)?;
            let persist: SmPersist = match t.get("state").map_err(rsm)? {
                Some(v) => serde_json::from_slice(v.value()).map_err(rsm)?,
                None => SmPersist::default(),
            };
            let snapshot: Option<StoredSnapshot> = match t.get("snapshot").map_err(rsm)? {
                Some(v) => Some(serde_json::from_slice(v.value()).map_err(rsm)?),
                None => None,
            };
            (persist, snapshot)
        };

        Ok(Self {
            db,
            mem: Arc::new(Mutex::new(SmMem {
                persist,
                snapshot,
                snapshot_idx: 0,
            })),
        })
    }

    fn persist_state(&self, persist: &SmPersist) -> Result<(), StorageError<NodeId>> {
        let bytes = serde_json::to_vec(persist).map_err(wsm)?;
        let w = self.db.begin_write().map_err(wsm)?;
        {
            let mut t = w.open_table(SM).map_err(wsm)?;
            t.insert("state", bytes.as_slice()).map_err(wsm)?;
        }
        w.commit().map_err(wsm)?;
        Ok(())
    }

    fn persist_snapshot(&self, snap: &StoredSnapshot) -> Result<(), StorageError<NodeId>> {
        let bytes = serde_json::to_vec(snap).map_err(wsm)?;
        let w = self.db.begin_write().map_err(wsm)?;
        {
            let mut t = w.open_table(SM).map_err(wsm)?;
            t.insert("snapshot", bytes.as_slice()).map_err(wsm)?;
        }
        w.commit().map_err(wsm)?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl LedgerReader for RedbStateMachineStore {
    async fn read_run(&self, run: &str) -> Option<RunState> {
        self.mem.lock().await.persist.ledger.runs.get(run).cloned()
    }
    async fn list_runs(&self) -> Vec<(String, RunState)> {
        self.mem
            .lock()
            .await
            .persist
            .ledger
            .runs
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

impl RaftSnapshotBuilder<TypeConfig> for RedbStateMachineStore {
    async fn build_snapshot(&mut self) -> Result<Snapshot<TypeConfig>, StorageError<NodeId>> {
        let mut mem = self.mem.lock().await;
        let data = serde_json::to_vec(&mem.persist.ledger).map_err(wsm)?;
        let last_applied = mem.persist.last_applied;
        let last_membership = mem.persist.last_membership.clone();
        mem.snapshot_idx += 1;
        let snapshot_id = match last_applied {
            Some(id) => format!("{}-{}-{}", id.leader_id, id.index, mem.snapshot_idx),
            None => format!("--{}", mem.snapshot_idx),
        };
        let meta = SnapshotMeta {
            last_log_id: last_applied,
            last_membership,
            snapshot_id,
        };
        let stored = StoredSnapshot {
            meta: meta.clone(),
            data: data.clone(),
        };
        self.persist_snapshot(&stored)?;
        mem.snapshot = Some(stored);
        Ok(Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(data)),
        })
    }
}

impl RaftStateMachine<TypeConfig> for RedbStateMachineStore {
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
        let mem = self.mem.lock().await;
        Ok((
            mem.persist.last_applied,
            mem.persist.last_membership.clone(),
        ))
    }

    async fn apply<I>(&mut self, entries: I) -> Result<Vec<Response>, StorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        let mut mem = self.mem.lock().await;
        let mut responses = Vec::new();
        for entry in entries {
            mem.persist.last_applied = Some(entry.log_id);
            match entry.payload {
                EntryPayload::Blank => responses.push(Response::default()),
                EntryPayload::Normal(req) => {
                    let resp = mem.persist.ledger.apply(&req);
                    responses.push(resp);
                }
                EntryPayload::Membership(m) => {
                    mem.persist.last_membership = StoredMembership::new(Some(entry.log_id), m);
                    responses.push(Response::default());
                }
            }
        }
        // Persist the whole applied state (durable) before returning.
        let persist = mem.persist.clone();
        self.persist_state(&persist)?;
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
        let ledger: LedgerState = serde_json::from_slice(&bytes).map_err(wsm)?;
        let mut mem = self.mem.lock().await;
        mem.persist.ledger = ledger;
        mem.persist.last_applied = meta.last_log_id;
        mem.persist.last_membership = meta.last_membership.clone();
        let persist = mem.persist.clone();
        self.persist_state(&persist)?;
        let stored = StoredSnapshot {
            meta: meta.clone(),
            data: bytes,
        };
        self.persist_snapshot(&stored)?;
        mem.snapshot = Some(stored);
        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<TypeConfig>>, StorageError<NodeId>> {
        let mem = self.mem.lock().await;
        Ok(mem.snapshot.as_ref().map(|s| Snapshot {
            meta: s.meta.clone(),
            snapshot: Box::new(Cursor::new(s.data.clone())),
        }))
    }
}
