//! Added-latency benchmark for the gateway.
//!
//! Two measurements:
//!
//! - **Part A — enforcement decision path.** The synchronous work Tokenfuse adds
//!   to every call: estimate → policy evaluate → reserve → settle. This is the
//!   honest "added latency" number, independent of the provider round trip.
//! - **Part B — full in-process request.** A request driven through the whole
//!   axum handler against a no-op (stub) upstream. This includes routing, body
//!   parsing, and response building on top of Part A.
//!
//! Run with: `cargo run -p tokenfuse-gateway --release --example bench`
//! Tune iterations via `BENCH_ITERS_A` / `BENCH_ITERS_B`.

use std::sync::Arc;
use std::time::Instant;

use axum::body::{to_bytes, Body};
use axum::http::Request;
use tokenfuse_core::{evaluate, Ledger, Microusd, ModelPrice, Policy, PriceBook, Usage};
use tokenfuse_gateway::app;
use tokenfuse_gateway::provider::StubProvider;
use tokenfuse_gateway::state::AppState;
use tower::ServiceExt;

fn percentile(sorted: &[u128], p: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = (((sorted.len() - 1) as f64) * p).round() as usize;
    sorted[idx]
}

fn report(name: &str, mut samples: Vec<u128>) {
    samples.sort_unstable();
    let n = samples.len();
    let sum: u128 = samples.iter().sum();
    let mean = sum as f64 / n as f64;
    let us = |ns: u128| ns as f64 / 1000.0;
    println!("\n{name}  (n = {n})");
    println!("  mean   {:>8.3} µs", mean / 1000.0);
    println!("  p50    {:>8.3} µs", us(percentile(&samples, 0.50)));
    println!("  p90    {:>8.3} µs", us(percentile(&samples, 0.90)));
    println!("  p99    {:>8.3} µs", us(percentile(&samples, 0.99)));
    println!("  p99.9  {:>8.3} µs", us(percentile(&samples, 0.999)));
    println!("  max    {:>8.3} µs", us(percentile(&samples, 1.0)));
    let target_ns = 3_000_000u128; // 3 ms
    let p99 = percentile(&samples, 0.99);
    println!(
        "  → p99 {} 3 ms target ({:.3} µs)",
        if p99 <= target_ns { "MEETS" } else { "MISSES" },
        us(p99)
    );
}

fn prices() -> PriceBook {
    PriceBook::new().with(
        "bench-model",
        ModelPrice::per_mtok_usd(3.0, 15.0, 0.30, 3.75),
    )
}

/// Part A: the pure enforcement decision path, no async, no HTTP.
fn bench_decision_path(iters: usize) {
    let prices = prices();
    let ledger = Ledger::new();
    // A budget large enough never to trip during the run.
    ledger.open_run("bench", Microusd(i64::MAX / 2));
    let policy = Policy::default();
    let usage = Usage {
        input_tokens: 1_000,
        output_tokens: 500,
        ..Default::default()
    };

    // Warm up.
    for _ in 0..(iters / 10).max(1) {
        let est =
            tokenfuse_gateway::estimate::estimate_cost(&prices, "bench-model", 4000, Some(500))
                .unwrap();
        let snap = ledger.snapshot("bench").unwrap();
        let _ = evaluate(&policy, &snap, est);
        let r = ledger.reserve("bench", est).unwrap();
        let actual = prices.cost("bench-model", &usage).unwrap();
        ledger.settle(&r, actual);
    }

    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        let est =
            tokenfuse_gateway::estimate::estimate_cost(&prices, "bench-model", 4000, Some(500))
                .unwrap();
        let snap = ledger.snapshot("bench").unwrap();
        let _ = evaluate(&policy, &snap, est);
        let r = ledger.reserve("bench", est).unwrap();
        let actual = prices.cost("bench-model", &usage).unwrap();
        ledger.settle(&r, actual);
        samples.push(start.elapsed().as_nanos());
    }
    report("Part A — enforcement decision path", samples);
}

/// Part B: a full request through the axum handler against the stub upstream.
async fn bench_full_request(iters: usize) {
    let state = AppState::new(
        Arc::new(Ledger::new()),
        Arc::new(prices()),
        Arc::new(Policy::default()),
        Arc::new(StubProvider::default()),
        "bench",
    );
    let router = app(state);
    let body = br#"{"model":"bench-model","max_tokens":500}"#;

    let make_req = || {
        Request::post("/v1/messages")
            .header("x-fuse-run-id", "bench-run")
            .header("x-fuse-budget-usd", "1000000")
            .body(Body::from(&body[..]))
            .unwrap()
    };

    for _ in 0..(iters / 10).max(1) {
        let resp = router.clone().oneshot(make_req()).await.unwrap();
        let _ = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    }

    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        let resp = router.clone().oneshot(make_req()).await.unwrap();
        let _ = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        samples.push(start.elapsed().as_nanos());
    }
    report("Part B — full in-process request (stub upstream)", samples);
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let iters_a: usize = std::env::var("BENCH_ITERS_A")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200_000);
    let iters_b: usize = std::env::var("BENCH_ITERS_B")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50_000);

    println!("Tokenfuse latency benchmark");
    println!("(build with --release for meaningful numbers)");

    bench_decision_path(iters_a);
    bench_full_request(iters_b).await;
}
