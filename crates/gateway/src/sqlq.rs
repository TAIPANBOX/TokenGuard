//! `tokenfuse sql "<query>"` — run SQL over the Parquet trace with DataFusion.
//!
//! The trace directory is registered as a table named `calls`, so you can ask
//! things like:
//!   tokenfuse sql "select run_id, sum(cost_microusd)/1e6 as usd \
//!                  from calls group by run_id order by usd desc"

use datafusion::arrow::record_batch::RecordBatch;
use datafusion::arrow::util::pretty::pretty_format_batches;
use datafusion::prelude::{ParquetReadOptions, SessionContext};

use crate::sink::ParquetSink;

/// Run `query` against the Parquet trace in `dir`, returning result batches.
///
/// The trace directory is append-only across schema changes, so it can mix OLD
/// files (pre-P2, missing `agent_id`/`saved_microusd`) with NEW files that have
/// them. We hand DataFusion an EXPLICIT unified schema ([`ParquetSink::read_schema`])
/// instead of letting it infer, because inference unions the per-file schemas
/// but keeps the appended columns non-nullable — and null-filling those for an
/// old file is then an Arrow validation error. The read schema declares the
/// appended columns nullable, which makes null-fill legal and also guarantees
/// the columns exist even when the directory holds only old files. Queries
/// `COALESCE` the NULLs to defaults (`''` / `0`). See `sqlq::tests` for the
/// mixed-schema proof.
pub async fn query(sql: &str, dir: &str) -> Result<Vec<RecordBatch>, Box<dyn std::error::Error>> {
    let ctx = SessionContext::new();
    let schema = ParquetSink::read_schema();
    let opts = ParquetReadOptions::default().schema(&schema);
    ctx.register_parquet("calls", dir, opts).await?;
    let df = ctx.sql(sql).await?;
    Ok(df.collect().await?)
}

/// Run `query` and print the result as a table (used by the CLI).
pub async fn run(sql: &str, dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    let batches = query(sql, dir).await?;
    println!("{}", pretty_format_batches(&batches)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sink::{CallRecord, EventSink, ParquetSink};

    #[tokio::test]
    async fn writes_then_queries_aggregate_cost() {
        let dir = std::env::temp_dir().join(format!("tf-sql-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let dir_str = dir.to_str().unwrap().to_string();

        // Write a few records via the sink, then query them back.
        {
            let sink = ParquetSink::new(&dir, 1).unwrap();
            for (i, cost) in [1_000_000i64, 2_000_000, 3_000_000].into_iter().enumerate() {
                sink.record(CallRecord {
                    ts_millis: i as i64,
                    run_id: "r1".into(),
                    model: "m".into(),
                    decision: "allow".into(),
                    input_tokens: 10,
                    output_tokens: 5,
                    cost_microusd: cost,
                    step: (i + 1) as u32,
                    agent_id: String::new(),
                    saved_microusd: 0,
                });
            }
        }

        let batches = query(
            "select sum(cost_microusd) as total, count(*) as n from calls",
            &dir_str,
        )
        .await
        .unwrap();

        let total = batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<datafusion::arrow::array::Int64Array>()
            .unwrap()
            .value(0);
        let n = batches[0]
            .column(1)
            .as_any()
            .downcast_ref::<datafusion::arrow::array::Int64Array>()
            .unwrap()
            .value(0);
        assert_eq!(total, 6_000_000);
        assert_eq!(n, 3);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// THE CRUX (P2 schema evolution): a trace directory that mixes an OLD file
    /// (written before `agent_id`/`saved_microusd` existed) with a NEW file (with
    /// them) must read back cleanly, with old rows defaulting the new columns.
    ///
    /// Empirical finding: DataFusion DOES union the per-file schemas (via
    /// `Schema::try_merge`) and null-fills columns a given file lacks — BUT it
    /// preserves the new file's declared nullability on the merged column. With
    /// the write schema's appended columns non-nullable, reading the old file
    /// then fails at RecordBatch validation: "Column 'agent_id' is declared as
    /// non-nullable but contains null values". The fix is `query`'s explicit
    /// unified read schema ([`ParquetSink::read_schema`]) that declares the
    /// appended columns nullable, making null-fill legal; `COALESCE` maps the
    /// NULLs to the documented defaults (`''` / `0`). This test proves the
    /// end-to-end path and locks the behavior in. (Verified: without the read
    /// schema this test fails with exactly that Arrow error.)
    #[tokio::test]
    async fn mixed_old_and_new_schema_files_read_with_defaults() {
        use datafusion::arrow::array::{Array, Int64Array, StringArray, UInt32Array, UInt64Array};
        use datafusion::arrow::datatypes::{DataType, Field, Schema};
        use datafusion::arrow::record_batch::RecordBatch;
        use datafusion::parquet::arrow::ArrowWriter;
        use std::sync::Arc;

        let dir = std::env::temp_dir().join(format!("tf-sql-mixed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let dir_str = dir.to_str().unwrap().to_string();

        // 1) Write an OLD-schema file by hand: exactly the pre-P2 8 columns, so
        //    it genuinely lacks `agent_id`/`saved_microusd` on disk.
        let old_schema = Arc::new(Schema::new(vec![
            Field::new("ts_millis", DataType::Int64, false),
            Field::new("run_id", DataType::Utf8, false),
            Field::new("model", DataType::Utf8, false),
            Field::new("decision", DataType::Utf8, false),
            Field::new("input_tokens", DataType::UInt64, false),
            Field::new("output_tokens", DataType::UInt64, false),
            Field::new("cost_microusd", DataType::Int64, false),
            Field::new("step", DataType::UInt32, false),
        ]));
        let old_batch = RecordBatch::try_new(
            old_schema.clone(),
            vec![
                Arc::new(Int64Array::from(vec![1i64])),
                Arc::new(StringArray::from(vec!["old-run"])),
                Arc::new(StringArray::from(vec!["m"])),
                Arc::new(StringArray::from(vec!["cache_hit"])),
                Arc::new(UInt64Array::from(vec![0u64])),
                Arc::new(UInt64Array::from(vec![0u64])),
                Arc::new(Int64Array::from(vec![0i64])),
                Arc::new(UInt32Array::from(vec![1u32])),
            ],
        )
        .unwrap();
        {
            let file = std::fs::File::create(dir.join("calls-old.parquet")).unwrap();
            let mut w = ArrowWriter::try_new(file, old_schema, None).unwrap();
            w.write(&old_batch).unwrap();
            w.close().unwrap();
        }

        // 2) Write a NEW-schema file via the current sink (has both columns).
        {
            let sink = ParquetSink::new(&dir, 1).unwrap();
            sink.record(CallRecord {
                ts_millis: 2,
                run_id: "new-run".into(),
                model: "m".into(),
                decision: "cache_hit".into(),
                input_tokens: 0,
                output_tokens: 0,
                cost_microusd: 0,
                step: 1,
                agent_id: "agent-7".into(),
                saved_microusd: 250_000,
            });
        }

        // 3) Read via the sqlq path with the robust coalesce the CLIs use.
        let batches = query(
            "select run_id, coalesce(saved_microusd, 0) as saved, \
             coalesce(agent_id, '') as agent from calls order by run_id",
            &dir_str,
        )
        .await
        .expect("mixed-schema read must succeed");

        // Collect into (run_id, saved, agent) rows across all batches.
        let mut rows: Vec<(String, i64, String)> = Vec::new();
        for b in &batches {
            let runs = b
                .column(0)
                .as_any()
                .downcast_ref::<datafusion::arrow::array::StringViewArray>()
                .map(|a| {
                    (0..a.len())
                        .map(|i| a.value(i).to_string())
                        .collect::<Vec<_>>()
                })
                .or_else(|| {
                    b.column(0)
                        .as_any()
                        .downcast_ref::<StringArray>()
                        .map(|a| (0..a.len()).map(|i| a.value(i).to_string()).collect())
                })
                .unwrap();
            let saved = b.column(1).as_any().downcast_ref::<Int64Array>().unwrap();
            let agent = b
                .column(2)
                .as_any()
                .downcast_ref::<datafusion::arrow::array::StringViewArray>()
                .map(|a| {
                    (0..a.len())
                        .map(|i| a.value(i).to_string())
                        .collect::<Vec<_>>()
                })
                .or_else(|| {
                    b.column(2)
                        .as_any()
                        .downcast_ref::<StringArray>()
                        .map(|a| (0..a.len()).map(|i| a.value(i).to_string()).collect())
                })
                .unwrap();
            for i in 0..b.num_rows() {
                rows.push((runs[i].clone(), saved.value(i), agent[i].clone()));
            }
        }

        assert_eq!(rows.len(), 2, "both files' rows must be present");
        // Old row: new columns absent on disk → default to 0 / "".
        assert_eq!(rows[0].0, "new-run");
        assert_eq!(rows[0].1, 250_000);
        assert_eq!(rows[0].2, "agent-7");
        assert_eq!(rows[1].0, "old-run");
        assert_eq!(rows[1].1, 0, "old file's saved_microusd defaults to 0");
        assert_eq!(rows[1].2, "", "old file's agent_id defaults to ''");

        std::fs::remove_dir_all(&dir).ok();
    }
}
