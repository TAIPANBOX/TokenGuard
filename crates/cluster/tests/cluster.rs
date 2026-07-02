//! Integration tests for the raft-replicated budget ledger.
//!
//! These spin up a real 3-node in-process cluster with live election timers, so
//! they run on a multi-thread runtime with real time.

use std::time::Duration;

use tokenfuse_cluster::types::{Request, RunState};
use tokenfuse_cluster::Cluster;

const USD: u64 = 1_000_000;

async fn quorum_sees<F>(cluster: &Cluster, run: &str, pred: F)
where
    F: Fn(&RunState) -> bool,
{
    // Poll every node until a quorum (2 of 3) has applied the expected state.
    for _ in 0..100 {
        let mut ok = 0;
        for n in &cluster.nodes {
            if let Some(s) = n.read_run(run).await {
                if pred(&s) {
                    ok += 1;
                }
            }
        }
        if ok >= 2 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("quorum never converged on expected state for run {run}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn elects_leader_and_replicates_budget() {
    let cluster = Cluster::start(&[1, 2, 3]).await.unwrap();
    let leader = cluster.wait_for_leader(Duration::from_secs(5)).await;
    assert!(leader.is_some(), "a leader must be elected");

    let run = "run-a";
    cluster
        .write(Request::Open {
            run: run.into(),
            budget_micros: USD,
            parent: None,
        })
        .await
        .unwrap();

    let r = cluster
        .write(Request::Reserve {
            run: run.into(),
            micros: 30 * 10_000,
        })
        .await
        .unwrap();
    assert!(r.accepted);
    assert_eq!(r.reserved_micros, 30 * 10_000);

    // The write returns only after commit; it must be replicated to a quorum.
    quorum_sees(&cluster, run, |s| s.reserved_micros == 30 * 10_000).await;

    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn consensus_never_oversubscribes_budget() {
    let cluster = Cluster::start(&[1, 2, 3]).await.unwrap();
    cluster
        .wait_for_leader(Duration::from_secs(5))
        .await
        .unwrap();

    let run = "run-b";
    cluster
        .write(Request::Open {
            run: run.into(),
            budget_micros: USD,
            parent: None,
        })
        .await
        .unwrap();

    // Reserve up to exactly the ceiling.
    let a = cluster
        .write(Request::Reserve {
            run: run.into(),
            micros: 60 * 10_000,
        })
        .await
        .unwrap();
    assert!(a.accepted);
    let b = cluster
        .write(Request::Reserve {
            run: run.into(),
            micros: 40 * 10_000,
        })
        .await
        .unwrap();
    assert!(b.accepted, "reserving exactly to the ceiling fits");

    // One microdollar more must be denied by the state machine.
    let c = cluster
        .write(Request::Reserve {
            run: run.into(),
            micros: 1,
        })
        .await
        .unwrap();
    assert!(!c.accepted, "over-budget reserve must be denied");
    assert!(c.reason.contains("budget_exceeded"));
    assert_eq!(
        c.reserved_micros, USD,
        "denied reserve leaves state unchanged"
    );

    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn settle_moves_reserved_to_spent() {
    let cluster = Cluster::start(&[1, 2, 3]).await.unwrap();
    cluster
        .wait_for_leader(Duration::from_secs(5))
        .await
        .unwrap();

    let run = "run-c";
    cluster
        .write(Request::Open {
            run: run.into(),
            budget_micros: USD,
            parent: None,
        })
        .await
        .unwrap();
    cluster
        .write(Request::Reserve {
            run: run.into(),
            micros: 50 * 10_000,
        })
        .await
        .unwrap();
    let s = cluster
        .write(Request::Settle {
            run: run.into(),
            reserved_micros: 50 * 10_000,
            actual_micros: 20 * 10_000,
        })
        .await
        .unwrap();
    assert_eq!(s.spent_micros, 20 * 10_000);
    assert_eq!(s.reserved_micros, 0);

    quorum_sees(&cluster, run, |st| {
        st.spent_micros == 20 * 10_000 && st.reserved_micros == 0
    })
    .await;

    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn subagent_reserve_rolls_up_and_parent_budget_blocks() {
    let cluster = Cluster::start(&[1, 2, 3]).await.unwrap();
    cluster
        .wait_for_leader(Duration::from_secs(5))
        .await
        .unwrap();

    // Parent caps the whole task at $1.00; the child's own budget is huge.
    cluster
        .write(Request::Open {
            run: "parent".into(),
            budget_micros: USD,
            parent: None,
        })
        .await
        .unwrap();
    cluster
        .write(Request::Open {
            run: "child".into(),
            budget_micros: 100 * USD,
            parent: Some("parent".into()),
        })
        .await
        .unwrap();

    // First child reserve fits child *and* parent.
    let a = cluster
        .write(Request::Reserve {
            run: "child".into(),
            micros: 60 * 10_000,
        })
        .await
        .unwrap();
    assert!(a.accepted);

    // The reservation rolled up: the parent now shows $0.60 reserved.
    quorum_sees(&cluster, "parent", |st| st.reserved_micros == 60 * 10_000).await;

    // A second child reserve fits the child ($1.20 < $100) but busts the parent
    // ($1.20 > $1.00) — denied, and the blocked run is the parent.
    let b = cluster
        .write(Request::Reserve {
            run: "child".into(),
            micros: 60 * 10_000,
        })
        .await
        .unwrap();
    assert!(
        !b.accepted,
        "must be blocked by the parent's tighter budget"
    );
    assert_eq!(b.blocked_run.as_deref(), Some("parent"));

    cluster.shutdown().await;
}
