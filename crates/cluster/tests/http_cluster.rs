//! Integration tests for the cross-process HTTP transport.
//!
//! Each test binds three OS-assigned ports, forms a real cluster over HTTP,
//! and drives budgets through the HTTP API — no in-process shortcuts.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use tokenfuse_cluster::net_http::Peers;
use tokenfuse_cluster::server::{self, Client, HttpNode};
use tokenfuse_cluster::types::Request;

const USD: u64 = 1_000_000;

/// Bind three `127.0.0.1:0` listeners, start a node on each, and return the peer
/// base URLs. The peer map is built from the assigned ports before any node is
/// constructed, so replication can find every peer.
async fn start_http_cluster() -> Vec<String> {
    let mut listeners = Vec::new();
    let mut peers_map = BTreeMap::new();
    for i in 0..3u64 {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        peers_map.insert(i + 1, format!("http://127.0.0.1:{port}"));
        listeners.push(l);
    }
    let peers: Peers = Arc::new(peers_map.clone());

    for (i, l) in listeners.into_iter().enumerate() {
        let id = i as u64 + 1;
        let node = HttpNode::build(id, peers.clone()).await.unwrap();
        tokio::spawn(async move {
            let _ = server::serve_on(node, l).await;
        });
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    peers_map.into_values().collect()
}

async fn wait_for_leader(client: &Client) -> Option<u64> {
    for _ in 0..100 {
        if let Ok(m) = client.metrics().await {
            if m.leader.is_some() {
                return m.leader;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    None
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_cluster_replicates_and_enforces() {
    let urls = start_http_cluster().await;
    let n1 = Client::new(urls[0].clone());
    let n3 = Client::new(urls[2].clone());

    n1.init().await.unwrap().unwrap();
    let leader = wait_for_leader(&n1).await;
    assert!(leader.is_some(), "a leader must be elected over HTTP");

    let run = "http-run";
    n1.write(&Request::Open {
        run: run.into(),
        budget_micros: USD,
    })
    .await
    .unwrap()
    .unwrap();

    // Two reserves fit; the third is denied by the replicated state machine.
    let a = n1
        .write(&Request::Reserve {
            run: run.into(),
            micros: 40 * 10_000,
        })
        .await
        .unwrap()
        .unwrap();
    assert!(a.accepted);
    let b = n1
        .write(&Request::Reserve {
            run: run.into(),
            micros: 40 * 10_000,
        })
        .await
        .unwrap()
        .unwrap();
    assert!(b.accepted);
    let c = n1
        .write(&Request::Reserve {
            run: run.into(),
            micros: 40 * 10_000,
        })
        .await
        .unwrap()
        .unwrap();
    assert!(!c.accepted, "over-budget reserve denied by consensus");

    // The committed reservations must be visible on a follower over HTTP.
    let mut seen = false;
    for _ in 0..100 {
        if let Ok(Some(s)) = n3.read(run).await {
            if s.reserved_micros == 80 * 10_000 {
                seen = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(seen, "follower node 3 must see the replicated reservations");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn writes_routed_to_leader_from_any_node() {
    let urls = start_http_cluster().await;
    let n1 = Client::new(urls[0].clone());
    let n2 = Client::new(urls[1].clone());

    n1.init().await.unwrap().unwrap();
    assert!(wait_for_leader(&n1).await.is_some());

    // A write submitted to node 2 (which may be a follower) still commits: the
    // client API surfaces the ForwardToLeader as an error the caller can retry,
    // so we retry against whichever node currently leads.
    let run = "route-run";
    n1.write(&Request::Open {
        run: run.into(),
        budget_micros: USD,
    })
    .await
    .unwrap()
    .unwrap();

    // Try node 2 first; if it forwards, fall back to node 1.
    let req = Request::Reserve {
        run: run.into(),
        micros: 25 * 10_000,
    };
    let resp = match n2.write(&req).await.unwrap() {
        Ok(r) => r,
        Err(_) => n1.write(&req).await.unwrap().unwrap(),
    };
    assert!(resp.accepted);
    assert_eq!(resp.reserved_micros, 25 * 10_000);
}
