//! End-to-end test of the raft-replicated ledger backend behind the gateway's
//! `LedgerBackend` trait (feature `cluster`). Proves the co-located raft node
//! enforces budgets — the same contract the in-process ledger provides, but
//! replicated. Compiles to nothing without the feature.
#![cfg(feature = "cluster")]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use tokenfuse_core::{BudgetError, Microusd};
use tokenfuse_gateway::ledger_backend::LedgerBackend;
use tokenfuse_gateway::raft_ledger::RaftLedger;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn raft_backend_enforces_and_settles() {
    // Single-node cluster on a fixed local port (no other test uses it).
    let addr = "127.0.0.1:5599";
    let mut peers = BTreeMap::new();
    peers.insert(1u64, format!("http://{addr}"));
    let rl: Arc<dyn LedgerBackend> =
        RaftLedger::start(1, addr.parse().unwrap(), Arc::new(peers), true, None, None)
            .await
            .unwrap();

    // Wait until the cluster is ready: open_run only sticks once a leader exists,
    // so poll snapshot until the budget is replicated.
    let run = "r";
    let mut ready = false;
    for _ in 0..100 {
        rl.open_run(run, Microusd::from_usd(1.0), None).await;
        if let Some(s) = rl.snapshot(run).await {
            if s.budget == Microusd::from_usd(1.0) {
                ready = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ready, "single-node cluster never became ready");

    // First reserve fits; the second pushes over $1.00 and must be denied.
    let a = rl.reserve(run, Microusd::from_usd(0.6)).await;
    assert!(a.is_ok(), "first reserve should fit");

    let b = rl.reserve(run, Microusd::from_usd(0.6)).await;
    match b {
        Err(BudgetError::Exceeded { .. }) => {}
        other => panic!("second reserve must be denied by consensus, got {other:?}"),
    }

    // Settle the first reservation; spend must show up in the replicated snapshot.
    rl.settle(&a.unwrap(), Microusd::from_usd(0.4));
    let mut settled = false;
    for _ in 0..100 {
        if let Some(s) = rl.snapshot(run).await {
            if s.spent == Microusd::from_usd(0.4) && s.reserved == Microusd::ZERO {
                settled = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(settled, "settle must replicate to the state machine");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn raft_backend_enforces_parent_budget() {
    let addr = "127.0.0.1:5601";
    let mut peers = BTreeMap::new();
    peers.insert(1u64, format!("http://{addr}"));
    let rl: Arc<dyn LedgerBackend> =
        RaftLedger::start(1, addr.parse().unwrap(), Arc::new(peers), true, None, None)
            .await
            .unwrap();

    // Wait for readiness by opening the parent until it replicates.
    let mut ready = false;
    for _ in 0..100 {
        rl.open_run("parent", Microusd::from_usd(1.0), None).await;
        if rl
            .snapshot("parent")
            .await
            .is_some_and(|s| s.budget == Microusd::from_usd(1.0))
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ready);
    // Child has a huge own budget but rolls up into the $1.00 parent.
    rl.open_run("child", Microusd::from_usd(100.0), Some("parent"))
        .await;

    let a = rl.reserve("child", Microusd::from_usd(0.6)).await;
    assert!(a.is_ok(), "first child reserve fits child and parent");

    // Second child reserve fits the child but busts the parent → denied, and the
    // error must name the *parent* as the blocked run.
    match rl.reserve("child", Microusd::from_usd(0.6)).await {
        Err(BudgetError::Exceeded { run_id, .. }) => {
            assert_eq!(run_id, "parent", "the parent must be the blocking run");
        }
        other => panic!("expected parent-budget denial, got {other:?}"),
    }
}
