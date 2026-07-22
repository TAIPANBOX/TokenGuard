//! `tokenfuse sql "<query>"` — run SQL over the Parquet trace with DataFusion.
//!
//! The trace directory is registered as a table named `calls`, so you can ask
//! things like:
//!   tokenfuse sql "select run_id, sum(cost_microusd)/1e6 as usd \
//!                  from calls group by run_id order by usd desc"

use datafusion::arrow::array::{Array, Int64Array, StringArray, StringViewArray};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::arrow::util::pretty::pretty_format_batches;
use datafusion::prelude::{ParquetReadOptions, SessionContext};
use tokenfuse_core::savings::Call;

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

/// Read a string cell whether the column is `Utf8` or `Utf8View` (DataFusion
/// picks the view type by default). Shared by the trace-reading CLIs.
pub fn str_at(col: &dyn Array, i: usize) -> String {
    if let Some(a) = col.as_any().downcast_ref::<StringArray>() {
        return a.value(i).to_string();
    }
    if let Some(a) = col.as_any().downcast_ref::<StringViewArray>() {
        return a.value(i).to_string();
    }
    String::new()
}

/// Load `run_id`, `decision`, `cost_microusd`, `saved_microusd` from the trace
/// as [`tokenfuse_core::savings::Call`] rows, optionally filtered to a
/// `[since, until]` `ts_millis` window (pass `None, None` for the whole trace).
///
/// The shared loader behind `tokenfuse savings` (calls with `None, None`) and
/// `tokenfuse compliance` (which passes its `--since`/`--until` window). Both
/// read the same `calls` rows into the same `Call` type; only the time filter
/// differed, so it lives here once. `since`/`until` are parsed `i64` literals,
/// so inlining them into the WHERE clause is injection-safe.
///
/// `coalesce(saved_microusd, 0)` keeps the read robust across schema evolution:
/// files written before the column existed surface it as NULL, which this maps
/// to the documented default of 0 (see `sqlq::tests` for the mixed-schema proof).
pub async fn load_calls(
    dir: &str,
    since: Option<i64>,
    until: Option<i64>,
) -> Result<Vec<Call>, Box<dyn std::error::Error>> {
    let mut sql = String::from(
        "select run_id, decision, cast(cost_microusd as bigint) as cost, \
         cast(coalesce(saved_microusd, 0) as bigint) as saved from calls",
    );
    let mut conds: Vec<String> = Vec::new();
    if let Some(s) = since {
        conds.push(format!("ts_millis >= {s}"));
    }
    if let Some(u) = until {
        conds.push(format!("ts_millis <= {u}"));
    }
    if !conds.is_empty() {
        sql.push_str(" where ");
        sql.push_str(&conds.join(" and "));
    }

    let batches = query(&sql, dir).await?;
    let mut calls = Vec::new();
    for b in &batches {
        let cost = b
            .column(2)
            .as_any()
            .downcast_ref::<Int64Array>()
            .ok_or("cost column type")?;
        let saved = b
            .column(3)
            .as_any()
            .downcast_ref::<Int64Array>()
            .ok_or("saved column type")?;
        for i in 0..b.num_rows() {
            calls.push(Call {
                run_id: str_at(b.column(0).as_ref(), i),
                decision: str_at(b.column(1).as_ref(), i),
                cost_microusd: cost.value(i),
                saved_microusd: saved.value(i),
            });
        }
    }
    Ok(calls)
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
                    parent_run_id: String::new(),
                    on_behalf_of: String::new(),
                    outcome: String::new(),
                    key_id: String::new(),
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
                parent_run_id: String::new(),
                on_behalf_of: String::new(),
                outcome: String::new(),
                key_id: String::new(),
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

    /// P3 (agent-passport): the SAME schema-evolution proof as
    /// `mixed_old_and_new_schema_files_read_with_defaults`, one generation
    /// later — a trace directory that mixes a PRE-P3 file (10 columns,
    /// written before `parent_run_id`/`on_behalf_of` existed) with a NEW file
    /// (12 columns, with them) must read back cleanly, with old rows
    /// defaulting the two new columns to `''`.
    #[tokio::test]
    async fn mixed_pre_p3_and_p3_schema_files_read_with_defaults() {
        use datafusion::arrow::array::{Int64Array, StringArray, UInt32Array, UInt64Array};
        use datafusion::arrow::datatypes::{DataType, Field, Schema};
        use datafusion::arrow::record_batch::RecordBatch;
        use datafusion::parquet::arrow::ArrowWriter;
        use std::sync::Arc;

        let dir = std::env::temp_dir().join(format!("tf-sql-mixed-p3-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let dir_str = dir.to_str().unwrap().to_string();

        // 1) Write a PRE-P3 file by hand: exactly today's 10 columns (P2),
        //    genuinely lacking `parent_run_id`/`on_behalf_of` on disk.
        let pre_p3_schema = Arc::new(Schema::new(vec![
            Field::new("ts_millis", DataType::Int64, false),
            Field::new("run_id", DataType::Utf8, false),
            Field::new("model", DataType::Utf8, false),
            Field::new("decision", DataType::Utf8, false),
            Field::new("input_tokens", DataType::UInt64, false),
            Field::new("output_tokens", DataType::UInt64, false),
            Field::new("cost_microusd", DataType::Int64, false),
            Field::new("step", DataType::UInt32, false),
            Field::new("agent_id", DataType::Utf8, false),
            Field::new("saved_microusd", DataType::Int64, false),
        ]));
        let pre_p3_batch = RecordBatch::try_new(
            pre_p3_schema.clone(),
            vec![
                Arc::new(Int64Array::from(vec![1i64])),
                Arc::new(StringArray::from(vec!["pre-p3-run"])),
                Arc::new(StringArray::from(vec!["m"])),
                Arc::new(StringArray::from(vec!["allow"])),
                Arc::new(UInt64Array::from(vec![10u64])),
                Arc::new(UInt64Array::from(vec![5u64])),
                Arc::new(Int64Array::from(vec![1_000i64])),
                Arc::new(UInt32Array::from(vec![1u32])),
                Arc::new(StringArray::from(vec!["agent-old"])),
                Arc::new(Int64Array::from(vec![0i64])),
            ],
        )
        .unwrap();
        {
            let file = std::fs::File::create(dir.join("calls-pre-p3.parquet")).unwrap();
            let mut w = ArrowWriter::try_new(file, pre_p3_schema, None).unwrap();
            w.write(&pre_p3_batch).unwrap();
            w.close().unwrap();
        }

        // 2) Write a P3-schema file via the current sink (has both new columns).
        {
            let sink = ParquetSink::new(&dir, 1).unwrap();
            sink.record(CallRecord {
                ts_millis: 2,
                run_id: "p3-run".into(),
                model: "m".into(),
                decision: "allow".into(),
                input_tokens: 0,
                output_tokens: 0,
                cost_microusd: 0,
                step: 1,
                agent_id: "agent-new".into(),
                saved_microusd: 0,
                parent_run_id: "parent-run-1".into(),
                on_behalf_of: "user://acme.example/j.doe,agent://acme.example/orchestrator".into(),
                outcome: String::new(),
                key_id: String::new(),
            });
        }

        // 3) Read via the sqlq path with the robust coalesce the CLIs use.
        let batches = query(
            "select run_id, coalesce(parent_run_id, '') as parent, \
             coalesce(on_behalf_of, '') as obo from calls order by run_id",
            &dir_str,
        )
        .await
        .expect("mixed pre-P3/P3 schema read must succeed");

        let mut rows: Vec<(String, String, String)> = Vec::new();
        for b in &batches {
            for i in 0..b.num_rows() {
                rows.push((
                    str_at(b.column(0).as_ref(), i),
                    str_at(b.column(1).as_ref(), i),
                    str_at(b.column(2).as_ref(), i),
                ));
            }
        }

        assert_eq!(rows.len(), 2, "both files' rows must be present");
        assert_eq!(rows[0].0, "p3-run");
        assert_eq!(rows[0].1, "parent-run-1");
        assert_eq!(
            rows[0].2,
            "user://acme.example/j.doe,agent://acme.example/orchestrator"
        );
        assert_eq!(rows[1].0, "pre-p3-run");
        assert_eq!(rows[1].1, "", "pre-P3 file's parent_run_id defaults to ''");
        assert_eq!(rows[1].2, "", "pre-P3 file's on_behalf_of defaults to ''");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// P4 (outcome-tags): the SAME schema-evolution proof again, one more
    /// generation later — a trace directory that mixes a PRE-P4 file (12
    /// columns, written before `outcome` existed) with a NEW file (13
    /// columns, with it) must read back cleanly, with the old row defaulting
    /// the new column to `''`.
    #[tokio::test]
    async fn mixed_pre_p4_and_p4_schema_files_read_with_defaults() {
        use datafusion::arrow::array::{Int64Array, StringArray, UInt32Array, UInt64Array};
        use datafusion::arrow::datatypes::{DataType, Field, Schema};
        use datafusion::arrow::record_batch::RecordBatch;
        use datafusion::parquet::arrow::ArrowWriter;
        use std::sync::Arc;

        let dir = std::env::temp_dir().join(format!("tf-sql-mixed-p4-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let dir_str = dir.to_str().unwrap().to_string();

        // 1) Write a PRE-P4 file by hand: exactly today's 12 columns (P3),
        //    genuinely lacking `outcome` on disk.
        let pre_p4_schema = Arc::new(Schema::new(vec![
            Field::new("ts_millis", DataType::Int64, false),
            Field::new("run_id", DataType::Utf8, false),
            Field::new("model", DataType::Utf8, false),
            Field::new("decision", DataType::Utf8, false),
            Field::new("input_tokens", DataType::UInt64, false),
            Field::new("output_tokens", DataType::UInt64, false),
            Field::new("cost_microusd", DataType::Int64, false),
            Field::new("step", DataType::UInt32, false),
            Field::new("agent_id", DataType::Utf8, false),
            Field::new("saved_microusd", DataType::Int64, false),
            Field::new("parent_run_id", DataType::Utf8, false),
            Field::new("on_behalf_of", DataType::Utf8, false),
        ]));
        let pre_p4_batch = RecordBatch::try_new(
            pre_p4_schema.clone(),
            vec![
                Arc::new(Int64Array::from(vec![1i64])),
                Arc::new(StringArray::from(vec!["pre-p4-run"])),
                Arc::new(StringArray::from(vec!["m"])),
                Arc::new(StringArray::from(vec!["allow"])),
                Arc::new(UInt64Array::from(vec![10u64])),
                Arc::new(UInt64Array::from(vec![5u64])),
                Arc::new(Int64Array::from(vec![1_000i64])),
                Arc::new(UInt32Array::from(vec![1u32])),
                Arc::new(StringArray::from(vec!["agent-old"])),
                Arc::new(Int64Array::from(vec![0i64])),
                Arc::new(StringArray::from(vec![""])),
                Arc::new(StringArray::from(vec![""])),
            ],
        )
        .unwrap();
        {
            let file = std::fs::File::create(dir.join("calls-pre-p4.parquet")).unwrap();
            let mut w = ArrowWriter::try_new(file, pre_p4_schema, None).unwrap();
            w.write(&pre_p4_batch).unwrap();
            w.close().unwrap();
        }

        // 2) Write a P4-schema file via the current sink (has the new column).
        {
            let sink = ParquetSink::new(&dir, 1).unwrap();
            sink.record(CallRecord {
                ts_millis: 2,
                run_id: "p4-run".into(),
                model: "m".into(),
                decision: "allow".into(),
                input_tokens: 0,
                output_tokens: 0,
                cost_microusd: 0,
                step: 1,
                agent_id: "agent-new".into(),
                saved_microusd: 0,
                parent_run_id: String::new(),
                on_behalf_of: String::new(),
                outcome: "case_resolved".into(),
                key_id: String::new(),
            });
        }

        // 3) Read via the sqlq path with the robust coalesce the CLIs use.
        let batches = query(
            "select run_id, coalesce(outcome, '') as outcome from calls order by run_id",
            &dir_str,
        )
        .await
        .expect("mixed pre-P4/P4 schema read must succeed");

        let mut rows: Vec<(String, String)> = Vec::new();
        for b in &batches {
            for i in 0..b.num_rows() {
                rows.push((
                    str_at(b.column(0).as_ref(), i),
                    str_at(b.column(1).as_ref(), i),
                ));
            }
        }

        assert_eq!(rows.len(), 2, "both files' rows must be present");
        assert_eq!(rows[0].0, "p4-run");
        assert_eq!(rows[0].1, "case_resolved");
        assert_eq!(rows[1].0, "pre-p4-run");
        assert_eq!(rows[1].1, "", "pre-P4 file's outcome defaults to ''");

        std::fs::remove_dir_all(&dir).ok();
    }
}
