//! Event sink: durable, queryable trace of every settled call.
//!
//! Telemetry is written as Parquet segments (W8) rather than into a database:
//! unlimited retention at object-storage prices, data in an open format the user
//! owns, and the same files back `tokenfuse sql`, the dashboard, and (later)
//! backtesting. `NullSink` is the default so the gateway has zero storage
//! dependency until you opt in with `TOKENFUSE_DATA_DIR`.

use std::fs::{create_dir_all, File};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use datafusion::arrow::array::{Int64Array, StringArray, UInt32Array, UInt64Array};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::parquet::arrow::ArrowWriter;

/// One settled call, the unit of the trace.
///
/// Schema evolution note (P2 → P3/agent-passport → P4/outcome-tags → key
/// identity → unit identity): `agent_id` and `saved_microusd` were appended
/// after the first files were written (P2); `parent_run_id` and
/// `on_behalf_of` follow the exact same pattern (P3); `outcome` follows it
/// again (P4); `key_id` follows it once more; `unit`
/// (docs/20-identity-map.md section 4) follows it again. New fields go at the
/// END and the Parquet schema keeps a stable order (see
/// [`ParquetSink::schema`]); old files simply lack the trailing columns and
/// read back as defaults (see `sqlq`). Never reorder or remove a field - that
/// breaks backward-compatible reads.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CallRecord {
    pub ts_millis: i64,
    pub run_id: String,
    pub model: String,
    pub decision: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_microusd: i64,
    pub step: u32,
    /// Attribution: which logical agent/sub-agent made the call (from the
    /// `X-Fuse-Agent-Id` request header). `""` when unset. Request-scoped
    /// metadata only — not part of ledger/budget accounting.
    pub agent_id: String,
    /// Dollars a semantic-cache hit avoided (microdollars). Non-zero only on
    /// `cache_hit` rows; `0` on every other record.
    pub saved_microusd: i64,
    /// The run's parent, from `X-Fuse-Parent-Run-Id` (agent-passport SPEC.md
    /// §3.2 — TokenFuse's existing hierarchical-budget header, now also
    /// recorded on the trace). `""` when the run has no parent. Before this
    /// field, the value lived only in the ledger's in-memory hierarchy (see
    /// `crate::proxy::messages`) and was never written to the trace.
    pub parent_run_id: String,
    /// Raw, unparsed value of `X-Fuse-On-Behalf-Of` (agent-passport SPEC.md
    /// §5): a comma-separated, root-first delegation chain of `agent://`/
    /// `user://` URIs. `""` when unset. Captured verbatim — this phase does
    /// not validate, parse, or truncate entries; see `crate::proxy` for the
    /// header's cap/ignore behavior.
    pub on_behalf_of: String,
    /// Opaque outcome tag from `X-Fuse-Outcome` (P4, unit economics), e.g.
    /// `case_resolved`, `escalated`, `abandoned`. `""` when unset. Captured
    /// verbatim, capture-only — no run-level state is built in the proxy (see
    /// `crate::proxy` for the header's cap/ignore behavior, same shape as
    /// `on_behalf_of`).
    ///
    /// Semantics for consumers: an agent typically tags only its FINAL call of
    /// a run, but any call in the run may carry the header. A run's outcome is
    /// the LAST non-empty `outcome` value recorded for its `run_id`, in call
    /// order — later tags override earlier ones. This trace column is a raw,
    /// per-call capture; computing "the" outcome of a run is a read-side
    /// aggregation (see `tokenfuse_core::outcomes`), not something recorded
    /// here.
    pub outcome: String,
    /// The stable identity of the CLIENT CREDENTIAL this call was made with,
    /// resolved server-side by `crate::clientkeys` from the `x-fuse-key`
    /// header. `""` when client keys are not configured, which is every
    /// deployment that has not opted in.
    ///
    /// Unlike `agent_id`, this is NOT client-supplied, and that difference is
    /// the whole reason it exists: `agent_id` is a header the caller writes, so
    /// it is sound for attribution a cooperating fleet reports about itself and
    /// unsound as the key of a budget, which a caller could then move off simply
    /// by sending a different one. A budget above the run keys on this instead.
    ///
    /// Still attribution-only HERE: this field records identity, it does not
    /// enforce anything. Enforcement is a later slice.
    pub key_id: String,
    /// The business unit this call's key/agent maps to, resolved server-side
    /// from the identity map (docs/20-identity-map.md). `""` when the
    /// identity map is off or nothing matched.
    ///
    /// Attribution/aggregation only, exactly like `key_id` above - not part
    /// of run-ledger accounting.
    pub unit: String,
}

/// Current wall-clock time in epoch millis (0 if the clock is before the epoch).
pub fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub trait EventSink: Send + Sync {
    fn record(&self, rec: CallRecord);
    /// Flush any buffered records to storage.
    fn flush(&self);
}

/// Default no-op sink — no storage dependency.
pub struct NullSink;

impl EventSink for NullSink {
    fn record(&self, _rec: CallRecord) {}
    fn flush(&self) {}
}

/// Fan a record out to two sinks (e.g. Parquet + OTel).
pub struct TeeSink {
    pub first: Arc<dyn EventSink>,
    pub second: Arc<dyn EventSink>,
}

impl EventSink for TeeSink {
    fn record(&self, rec: CallRecord) {
        self.first.record(rec.clone());
        self.second.record(rec);
    }
    fn flush(&self) {
        self.first.flush();
        self.second.flush();
    }
}

/// Buffers records and writes them as rotating Parquet files in `dir`.
pub struct ParquetSink {
    dir: PathBuf,
    buffer: Mutex<Vec<CallRecord>>,
    threshold: usize,
    seq: AtomicU64,
    /// Per-instance token woven into every segment filename. `seq` is
    /// per-process and restarts at 0, and `File::create` truncates, so two
    /// gateways sharing one `TOKENFUSE_DATA_DIR` (an HA cluster's nodes, or a
    /// restarted process meeting the previous run's files) would otherwise
    /// both write `calls-00000000.parquet` and clobber each other's trace. A
    /// pid + start-nanos token makes each writer's segment names unique, so
    /// concurrent processes and restarts never collide. Readers enumerate by
    /// `.parquet` extension, not by exact name, so the wider name is
    /// transparent to `focus-export` / `outcomes` / `sqlq`.
    instance: String,
}

impl ParquetSink {
    pub fn new(dir: impl Into<PathBuf>, threshold: usize) -> std::io::Result<Self> {
        let dir = dir.into();
        create_dir_all(&dir)?;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        Ok(ParquetSink {
            dir,
            buffer: Mutex::new(Vec::new()),
            threshold: threshold.max(1),
            seq: AtomicU64::new(0),
            instance: format!("{:x}-{:x}", std::process::id(), nanos),
        })
    }

    fn schema() -> Arc<Schema> {
        Arc::new(Schema::new(vec![
            Field::new("ts_millis", DataType::Int64, false),
            Field::new("run_id", DataType::Utf8, false),
            Field::new("model", DataType::Utf8, false),
            Field::new("decision", DataType::Utf8, false),
            Field::new("input_tokens", DataType::UInt64, false),
            Field::new("output_tokens", DataType::UInt64, false),
            Field::new("cost_microusd", DataType::Int64, false),
            Field::new("step", DataType::UInt32, false),
            // Appended P2 columns. Keep these LAST and in this order so files
            // written before/after the change stay mutually readable.
            Field::new("agent_id", DataType::Utf8, false),
            Field::new("saved_microusd", DataType::Int64, false),
            // Appended P3 (agent-passport) columns — same rule: LAST, in this
            // order. See [`CallRecord`]'s doc for what each carries.
            Field::new("parent_run_id", DataType::Utf8, false),
            Field::new("on_behalf_of", DataType::Utf8, false),
            // Appended P4 (outcome-tags) column — same rule: LAST. See
            // [`CallRecord::outcome`] for what it carries.
            Field::new("outcome", DataType::Utf8, false),
            // Appended key-identity column — same rule: LAST. See
            // [`CallRecord::key_id`]; this is the first column on the trace
            // that the caller cannot choose.
            Field::new("key_id", DataType::Utf8, false),
            // Appended unit-identity column - same rule: LAST. See
            // [`CallRecord::unit`] (docs/20-identity-map.md section 4).
            Field::new("unit", DataType::Utf8, false),
        ]))
    }

    /// The unified schema used to *read* the whole trace directory.
    ///
    /// Why this differs from [`schema`](Self::schema) (the write schema): the
    /// trace is append-only across a schema change, so one directory holds both
    /// OLD files (8 columns, written before P2) and NEW files (10 columns).
    /// DataFusion unions the per-file schemas, but when it null-fills the
    /// appended columns for an old file it enforces the merged column's declared
    /// nullability — a `non-nullable` column that must hold NULLs is an Arrow
    /// validation error ("declared as non-nullable but contains null values").
    /// So the appended columns are declared NULLABLE here and this schema is
    /// handed to the reader explicitly, which (a) makes null-fill of old files
    /// legal and (b) guarantees the columns exist in the table schema even when
    /// the directory contains ONLY old files. Queries then `COALESCE` the NULLs
    /// to the documented defaults (`''` / `0`). Writers never emit NULLs, so the
    /// stricter write schema stays correct for what we produce.
    pub fn read_schema() -> Arc<Schema> {
        Arc::new(Schema::new(vec![
            Field::new("ts_millis", DataType::Int64, false),
            Field::new("run_id", DataType::Utf8, false),
            Field::new("model", DataType::Utf8, false),
            Field::new("decision", DataType::Utf8, false),
            Field::new("input_tokens", DataType::UInt64, false),
            Field::new("output_tokens", DataType::UInt64, false),
            Field::new("cost_microusd", DataType::Int64, false),
            Field::new("step", DataType::UInt32, false),
            Field::new("agent_id", DataType::Utf8, true),
            Field::new("saved_microusd", DataType::Int64, true),
            // P3 (agent-passport): same schema-evolution treatment as the P2
            // columns above — nullable here so an old (pre-P3) file's missing
            // columns null-fill legally; queries `COALESCE` to `''`.
            Field::new("parent_run_id", DataType::Utf8, true),
            Field::new("on_behalf_of", DataType::Utf8, true),
            // P4 (outcome-tags): same schema-evolution treatment again —
            // nullable here so a pre-P4 file's missing column null-fills
            // legally; queries `COALESCE` to `''`.
            Field::new("outcome", DataType::Utf8, true),
            // Key identity: same treatment once more, so every trace written
            // before client keys existed still reads back.
            Field::new("key_id", DataType::Utf8, true),
            // Unit identity: same treatment once more, so every trace
            // written before the identity map existed still reads back.
            Field::new("unit", DataType::Utf8, true),
        ]))
    }

    fn write_batch(&self, records: &[CallRecord]) -> Result<(), Box<dyn std::error::Error>> {
        if records.is_empty() {
            return Ok(());
        }
        let schema = Self::schema();
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int64Array::from(
                    records.iter().map(|r| r.ts_millis).collect::<Vec<_>>(),
                )),
                Arc::new(StringArray::from(
                    records.iter().map(|r| r.run_id.clone()).collect::<Vec<_>>(),
                )),
                Arc::new(StringArray::from(
                    records.iter().map(|r| r.model.clone()).collect::<Vec<_>>(),
                )),
                Arc::new(StringArray::from(
                    records
                        .iter()
                        .map(|r| r.decision.clone())
                        .collect::<Vec<_>>(),
                )),
                Arc::new(UInt64Array::from(
                    records.iter().map(|r| r.input_tokens).collect::<Vec<_>>(),
                )),
                Arc::new(UInt64Array::from(
                    records.iter().map(|r| r.output_tokens).collect::<Vec<_>>(),
                )),
                Arc::new(Int64Array::from(
                    records.iter().map(|r| r.cost_microusd).collect::<Vec<_>>(),
                )),
                Arc::new(UInt32Array::from(
                    records.iter().map(|r| r.step).collect::<Vec<_>>(),
                )),
                Arc::new(StringArray::from(
                    records
                        .iter()
                        .map(|r| r.agent_id.clone())
                        .collect::<Vec<_>>(),
                )),
                Arc::new(Int64Array::from(
                    records.iter().map(|r| r.saved_microusd).collect::<Vec<_>>(),
                )),
                Arc::new(StringArray::from(
                    records
                        .iter()
                        .map(|r| r.parent_run_id.clone())
                        .collect::<Vec<_>>(),
                )),
                Arc::new(StringArray::from(
                    records
                        .iter()
                        .map(|r| r.on_behalf_of.clone())
                        .collect::<Vec<_>>(),
                )),
                Arc::new(StringArray::from(
                    records
                        .iter()
                        .map(|r| r.outcome.clone())
                        .collect::<Vec<_>>(),
                )),
                Arc::new(StringArray::from(
                    records.iter().map(|r| r.key_id.clone()).collect::<Vec<_>>(),
                )),
                Arc::new(StringArray::from(
                    records.iter().map(|r| r.unit.clone()).collect::<Vec<_>>(),
                )),
            ],
        )?;

        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let path = self
            .dir
            .join(format!("calls-{}-{seq:08}.parquet", self.instance));
        let file = File::create(path)?;
        let mut writer = ArrowWriter::try_new(file, schema, None)?;
        writer.write(&batch)?;
        writer.close()?;
        Ok(())
    }
}

impl EventSink for ParquetSink {
    fn record(&self, rec: CallRecord) {
        let to_flush = {
            let mut buf = self.buffer.lock().unwrap();
            buf.push(rec);
            if buf.len() >= self.threshold {
                std::mem::take(&mut *buf)
            } else {
                Vec::new()
            }
        };
        if let Err(e) = self.write_batch(&to_flush) {
            eprintln!("parquet sink write error: {e}");
        }
    }

    fn flush(&self) {
        let rest = {
            let mut buf = self.buffer.lock().unwrap();
            std::mem::take(&mut *buf)
        };
        if let Err(e) = self.write_batch(&rest) {
            eprintln!("parquet sink flush error: {e}");
        }
    }
}

impl Drop for ParquetSink {
    fn drop(&mut self) {
        self.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(run: &str, cost: i64) -> CallRecord {
        CallRecord {
            ts_millis: 1,
            run_id: run.into(),
            model: "m".into(),
            decision: "allow".into(),
            input_tokens: 100,
            output_tokens: 50,
            cost_microusd: cost,
            step: 1,
            agent_id: String::new(),
            saved_microusd: 0,
            parent_run_id: String::new(),
            on_behalf_of: String::new(),
            outcome: String::new(),
            key_id: String::new(),
            unit: String::new(),
        }
    }

    #[test]
    fn flushes_a_parquet_file_at_threshold() {
        let dir = std::env::temp_dir().join(format!("tf-sink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let sink = ParquetSink::new(&dir, 2).unwrap();
        sink.record(rec("a", 10));
        // Below threshold: nothing written yet.
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        sink.record(rec("b", 20));
        // Threshold hit: one file written.
        let files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|x| x == "parquet")
                    .unwrap_or(false)
            })
            .collect();
        assert_eq!(files.len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn flush_writes_remaining_buffer() {
        let dir = std::env::temp_dir().join(format!("tf-sink-flush-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let sink = ParquetSink::new(&dir, 1000).unwrap();
        sink.record(rec("a", 10));
        sink.flush();
        let count = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|x| x == "parquet")
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(count, 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    // Regression: two sinks sharing one dir (HA cluster nodes, or a restart
    // meeting the previous run's files) must NOT clobber each other's segments.
    // Before per-instance filenames both wrote calls-00000000.parquet and one
    // truncated the other; this asserts both segments survive and are readable.
    #[test]
    fn two_sinks_sharing_a_dir_do_not_clobber() {
        let dir = std::env::temp_dir().join(format!("tf-sink-share-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let a = ParquetSink::new(&dir, 1).unwrap();
        let b = ParquetSink::new(&dir, 1).unwrap();
        assert_ne!(a.instance, b.instance, "each sink gets a unique instance");
        a.record(rec("run-a", 10));
        b.record(rec("run-b", 20));

        let files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|x| x == "parquet")
                    .unwrap_or(false)
            })
            .collect();
        assert_eq!(files.len(), 2, "both sinks' segments survive");
        // Every segment is an intact, self-contained Parquet file: the format
        // brackets each file with the 4-byte `PAR1` magic. A clobbered /
        // interleaved write would fail this. (A shared-name collision would
        // also have left only one file, already caught by the count above.)
        for f in &files {
            let bytes = std::fs::read(f.path()).unwrap();
            assert!(bytes.len() > 8, "segment is non-empty");
            assert_eq!(&bytes[..4], b"PAR1", "starts with the parquet magic");
            assert_eq!(
                &bytes[bytes.len() - 4..],
                b"PAR1",
                "ends with the parquet magic"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}
