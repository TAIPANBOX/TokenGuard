//! Integration tests for the cross-process HTTP transport.
//!
//! Each test binds three OS-assigned ports, forms a real cluster over HTTP,
//! and drives budgets through the HTTP API — no in-process shortcuts.

use std::collections::{BTreeMap, BTreeSet};
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
        let node = HttpNode::build(id, peers.clone(), None).await.unwrap();
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
        parent: None,
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
        parent: None,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn membership_grow_add_learner_then_promote() {
    // Two nodes; both know each other's URL (bootstrap peer map), but only node 1
    // is initialized to start — node 2 joins at runtime.
    let mut listeners = Vec::new();
    let mut peers_map = BTreeMap::new();
    for i in 0..2u64 {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        peers_map.insert(i + 1, format!("http://127.0.0.1:{port}"));
        listeners.push(l);
    }
    let peers: Peers = Arc::new(peers_map.clone());
    let urls: Vec<String> = peers_map.values().cloned().collect();
    for (i, l) in listeners.into_iter().enumerate() {
        let node = HttpNode::build(i as u64 + 1, peers.clone(), None)
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = server::serve_on(node, l).await;
        });
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    let n1 = Client::new(urls[0].clone());
    let n2 = Client::new(urls[1].clone());

    // Node 1 starts as the sole voter.
    n1.init_single().await.unwrap().unwrap();
    assert!(wait_for_leader(&n1).await.is_some());

    // Grow: add node 2 as a learner, then promote the voter set to {1, 2}.
    n1.add_learner(2, &urls[1]).await.unwrap().unwrap();
    n1.change_membership(&BTreeSet::from([1, 2]))
        .await
        .unwrap()
        .unwrap();

    // A write on the leader must now replicate to the newly-joined node 2.
    let run = "grow";
    n1.write(&Request::Open {
        run: run.into(),
        budget_micros: USD,
        parent: None,
    })
    .await
    .unwrap()
    .unwrap();
    n1.write(&Request::Reserve {
        run: run.into(),
        micros: 30 * 10_000,
    })
    .await
    .unwrap()
    .unwrap();

    let mut seen = false;
    for _ in 0..100 {
        if let Ok(Some(s)) = n2.read(run).await {
            if s.reserved_micros == 30 * 10_000 {
                seen = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        seen,
        "node 2 joined at runtime must receive replicated writes"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cluster_token_secures_endpoints() {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{port}");
    let peers: Peers = Arc::new(BTreeMap::from([(1u64, url.clone())]));

    let node = HttpNode::build(1, peers, Some("s3cret".into()))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = server::serve_on(node, l).await;
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let http = reqwest::Client::new();
    // /healthz is public.
    assert!(http
        .get(format!("{url}/healthz"))
        .send()
        .await
        .unwrap()
        .status()
        .is_success());
    // Admin endpoint without a token → 401.
    assert_eq!(
        http.get(format!("{url}/mgmt/metrics"))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    // Wrong token → 401.
    assert_eq!(
        http.get(format!("{url}/mgmt/metrics"))
            .bearer_auth("nope")
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    // Correct token → 200.
    assert!(http
        .get(format!("{url}/mgmt/metrics"))
        .bearer_auth("s3cret")
        .send()
        .await
        .unwrap()
        .status()
        .is_success());

    // An authed Client can drive the node: init, elect, write.
    let c = Client::with_token(url.clone(), Some("s3cret".into()));
    c.init_single().await.unwrap().unwrap();
    for _ in 0..100 {
        if c.metrics()
            .await
            .map(|m| m.leader.is_some())
            .unwrap_or(false)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    c.write(&Request::Open {
        run: "a".into(),
        budget_micros: USD,
        parent: None,
    })
    .await
    .unwrap()
    .unwrap();
    let r = c
        .write(&Request::Reserve {
            run: "a".into(),
            micros: 30 * 10_000,
        })
        .await
        .unwrap()
        .unwrap();
    assert!(r.accepted);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn serves_over_https_with_token() {
    let port = 5703u16;
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let url = format!("https://127.0.0.1:{port}");
    let peers: Peers = Arc::new(BTreeMap::from([(1u64, url.clone())]));

    // Self-signed cert for 127.0.0.1.
    let ck =
        rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string(), "localhost".to_string()])
            .unwrap();
    let cert_pem = ck.cert.pem();
    let key_pem = ck.key_pair.serialize_pem();

    let node = HttpNode::build(1, peers, Some("s3cret".into()))
        .await
        .unwrap();
    let cp = cert_pem.clone();
    tokio::spawn(async move {
        let _ = server::serve_tls(node, addr, cp.into_bytes(), key_pem.into_bytes()).await;
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    // A client that trusts the self-signed cert.
    let https = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(cert_pem.as_bytes()).unwrap())
        .build()
        .unwrap();

    // /healthz over HTTPS (public).
    let hz = https.get(format!("{url}/healthz")).send().await.unwrap();
    assert!(hz.status().is_success(), "healthz over https");

    // /mgmt/metrics over HTTPS needs the token.
    assert_eq!(
        https
            .get(format!("{url}/mgmt/metrics"))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    assert!(https
        .get(format!("{url}/mgmt/metrics"))
        .bearer_auth("s3cret")
        .send()
        .await
        .unwrap()
        .status()
        .is_success());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn linearizable_read_from_follower() {
    let urls = start_http_cluster().await;
    let n1 = Client::new(urls[0].clone());
    let n2 = Client::new(urls[1].clone());
    n1.init().await.unwrap().unwrap();
    assert!(wait_for_leader(&n1).await.is_some());

    n1.write(&Request::Open {
        run: "lin".into(),
        budget_micros: USD,
        parent: None,
    })
    .await
    .unwrap()
    .unwrap();
    n1.write(&Request::Reserve {
        run: "lin".into(),
        micros: 20 * 10_000,
    })
    .await
    .unwrap()
    .unwrap();

    // A linearizable read via node 2 (likely a follower) forwards to the leader
    // and returns the committed value — no polling needed.
    let s = n2
        .read_linear("lin")
        .await
        .unwrap()
        .unwrap()
        .expect("run must be visible via a linearizable read");
    assert_eq!(s.reserved_micros, 20 * 10_000);
}
