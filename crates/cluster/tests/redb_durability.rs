//! Durability test for the redb-backed raft storage: a budget written before a
//! "restart" (drop the node, reopen the same redb dir) must still be there.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use tokenfuse_cluster::net_http::Peers;
use tokenfuse_cluster::server::HttpNode;
use tokenfuse_cluster::types::Request;

fn temp_dir(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("tf-redb-{}-{}", tag, std::process::id()))
}

async fn wait_leader(node: &HttpNode) {
    for _ in 0..100 {
        if node.raft.current_leader().await.is_some() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn budgets_survive_a_restart() {
    let dir = temp_dir("durability");
    std::fs::remove_dir_all(&dir).ok();
    // Single-node cluster; the peer URL is never dialed (no peers to replicate to).
    let peers: Peers = Arc::new(BTreeMap::from([(1u64, "http://127.0.0.1:1".to_string())]));

    // --- round 1: open durable node, write a budget, then "crash" (drop) ---
    {
        let node = HttpNode::build_durable(1, peers.clone(), &dir, None)
            .await
            .unwrap();
        node.init().await.unwrap();
        wait_leader(&node).await;

        node.submit(Request::Open {
            run: "r".into(),
            budget_micros: 1_000_000,
            parent: None,
        })
        .await
        .unwrap();
        let resp = node
            .submit(Request::Reserve {
                run: "r".into(),
                micros: 600_000,
            })
            .await
            .unwrap();
        assert!(resp.accepted, "reserve should fit");

        node.raft.shutdown().await.unwrap();
    }
    // Give the OS a beat to release the redb file handle.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // --- round 2: reopen the SAME dir; the state must have persisted ---
    {
        let node = HttpNode::build_durable(1, peers.clone(), &dir, None)
            .await
            .unwrap();
        let s = node
            .sm
            .read_run("r")
            .await
            .expect("run must persist across restart");
        assert_eq!(s.budget_micros, 1_000_000, "budget persisted");
        assert_eq!(s.reserved_micros, 600_000, "reservation persisted");
        node.raft.shutdown().await.unwrap();
    }

    std::fs::remove_dir_all(&dir).ok();
}
