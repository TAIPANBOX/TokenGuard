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
/// Schema evolution note (P2): `agent_id` and `saved_microusd` were appended
/// after the first files were written. New fields go at the END and the Parquet
/// schema keeps a stable order (see [`ParquetSink::schema`]); old files simply
/// lack the trailing columns and read back as defaults (see `sqlq`). Never
/// reorder or remove a field — that breaks backward-compatible reads.
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
}

impl ParquetSink {
    pub fn new(dir: impl Into<PathBuf>, threshold: usize) -> std::io::Result<Self> {
        let dir = dir.into();
        create_dir_all(&dir)?;
        Ok(ParquetSink {
            dir,
            buffer: Mutex::new(Vec::new()),
            threshold: threshold.max(1),
            seq: AtomicU64::new(0),
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
            ],
        )?;

        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let path = self.dir.join(format!("calls-{seq:08}.parquet"));
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
}
