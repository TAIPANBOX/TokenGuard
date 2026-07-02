//! `tokenfuse-cluster` — a raft-replicated budget ledger.
//!
//! Subcommands:
//!   cargo run -p tokenfuse-cluster                # in-process 3-node demo
//!   cargo run -p tokenfuse-cluster -- demo-http   # 3 nodes over real HTTP sockets
//!   cargo run -p tokenfuse-cluster -- serve --id 1 \
//!       --http 127.0.0.1:5001 \
//!       --peers 1=http://127.0.0.1:5001,2=http://127.0.0.1:5002,3=http://127.0.0.1:5003 \
//!       [--init]                                  # run one node of a real cluster

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use tokenfuse_cluster::net_http::Peers;
use tokenfuse_cluster::server::{self, Client, HttpNode};
use tokenfuse_cluster::types::Request;
use tokenfuse_cluster::Cluster;

const USD: u64 = 1_000_000; // 1 USD in microdollars

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("error")),
        )
        .init();

    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("serve") => serve(args.collect()).await,
        Some("demo-http") => demo_http().await,
        _ => demo_in_process().await,
    }
}

/// Parse `--flag value` pairs into a map.
fn parse_flags(args: Vec<String>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        if let Some(key) = a.strip_prefix("--") {
            // Boolean flags (e.g. --init) get an empty value.
            match it.next() {
                Some(v) if !v.starts_with("--") => {
                    out.insert(key.to_string(), v);
                }
                Some(v) => {
                    out.insert(key.to_string(), String::new());
                    // `v` was actually the next flag; re-handle it.
                    if let Some(k2) = v.strip_prefix("--") {
                        out.insert(k2.to_string(), String::new());
                    }
                }
                None => {
                    out.insert(key.to_string(), String::new());
                }
            }
        }
    }
    out
}

/// `--peers 1=http://host:port,2=http://...` → map.
fn parse_peers(spec: &str) -> Peers {
    let mut m = BTreeMap::new();
    for pair in spec.split(',').filter(|s| !s.is_empty()) {
        if let Some((id, url)) = pair.split_once('=') {
            if let Ok(id) = id.trim().parse::<u64>() {
                m.insert(id, url.trim().to_string());
            }
        }
    }
    Arc::new(m)
}

/// Run a single node of an HTTP cluster.
async fn serve(args: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    let flags = parse_flags(args);
    let id: u64 = flags
        .get("id")
        .and_then(|s| s.parse().ok())
        .ok_or("--id required")?;
    let http = flags.get("http").cloned().ok_or("--http addr required")?;
    let peers = parse_peers(flags.get("peers").map(|s| s.as_str()).unwrap_or(""));

    let node = HttpNode::build(id, peers).await?;
    let addr = http.parse()?;
    println!("node {id} serving on http://{http}");

    // Optionally initialize the cluster from this node once it is listening.
    if flags.contains_key("init") {
        let base = format!("http://{http}");
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            let c = Client::new(base);
            match c.init().await {
                Ok(Ok(())) => println!("cluster initialized from node {id}"),
                Ok(Err(e)) => println!("init rejected: {e}"),
                Err(e) => println!("init call failed: {e}"),
            }
        });
    }

    server::serve(node, addr).await?;
    Ok(())
}

/// Spin up three HTTP nodes in one process (each on its own port) and drive the
/// budget scenario through the HTTP API — proving replication over real sockets.
async fn demo_http() -> Result<(), Box<dyn std::error::Error>> {
    println!("── TokenFuse HA cluster demo (HTTP transport) ──\n");
    let ports = [5001u16, 5002, 5003];
    let peers: Peers = Arc::new(
        ports
            .iter()
            .enumerate()
            .map(|(i, p)| (i as u64 + 1, format!("http://127.0.0.1:{p}")))
            .collect(),
    );

    // Start every node's HTTP server.
    for (i, port) in ports.iter().enumerate() {
        let id = i as u64 + 1;
        let node = HttpNode::build(id, peers.clone()).await?;
        let addr = format!("127.0.0.1:{port}").parse()?;
        tokio::spawn(async move {
            let _ = server::serve(node, addr).await;
        });
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    println!(
        "started 3 nodes over HTTP: {:?}",
        peers.values().collect::<Vec<_>>()
    );

    // Initialize the cluster via node 1's API.
    let n1 = Client::new("http://127.0.0.1:5001");
    n1.init().await?.map_err(|e| format!("init: {e}"))?;

    // Wait for a leader.
    let mut leader = None;
    for _ in 0..100 {
        if let Ok(m) = n1.metrics().await {
            if let Some(l) = m.leader {
                leader = Some(l);
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    println!("leader elected: node {}\n", leader.ok_or("no leader")?);

    let run = "agent-42";
    n1.write(&Request::Open {
        run: run.into(),
        budget_micros: USD,
        parent: None,
    })
    .await?
    .map_err(|e| format!("open: {e}"))?;
    println!("opened budget for {run}: $1.00\n");

    for (i, cents) in [40u64, 40, 40].into_iter().enumerate() {
        let micros = cents * 10_000;
        let resp = n1
            .write(&Request::Reserve {
                run: run.into(),
                micros,
            })
            .await?
            .map_err(|e| format!("reserve: {e}"))?;
        println!(
            "reserve #{}  ${:.2}  → {}  (reserved ${:.2} / budget ${:.2})",
            i + 1,
            micros as f64 / USD as f64,
            if resp.accepted {
                "ACCEPTED"
            } else {
                "DENIED  "
            },
            resp.reserved_micros as f64 / USD as f64,
            resp.budget_micros as f64 / USD as f64,
        );
    }

    // Read the replicated state back from node 3 (a follower) over HTTP.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let n3 = Client::new("http://127.0.0.1:5003");
    let state = n3.read(run).await?.ok_or("run not replicated to node 3")?;
    println!(
        "\nread replicated state from follower node 3 (HTTP):\n  reserved ${:.2} / budget ${:.2}",
        state.reserved_micros as f64 / USD as f64,
        state.budget_micros as f64 / USD as f64,
    );
    println!("\n✔ budget replicated + enforced across 3 nodes over real HTTP sockets.");
    Ok(())
}

/// The original single-process demo (in-process router transport).
async fn demo_in_process() -> Result<(), Box<dyn std::error::Error>> {
    println!("── TokenFuse HA cluster demo (in-process) ──\n");
    println!("starting 3 nodes {{1, 2, 3}} …");
    let cluster = Cluster::start(&[1, 2, 3]).await?;

    let leader = cluster
        .wait_for_leader(Duration::from_secs(5))
        .await
        .ok_or("no leader elected")?;
    println!("leader elected: node {leader}\n");

    let run = "agent-42";
    cluster
        .write(Request::Open {
            run: run.to_string(),
            budget_micros: USD,
            parent: None,
        })
        .await?;
    println!("opened budget for {run}: $1.00\n");

    for (i, cents) in [40, 40, 40].into_iter().enumerate() {
        let micros = cents * 10_000;
        let resp = cluster
            .write(Request::Reserve {
                run: run.to_string(),
                micros,
            })
            .await?;
        let verdict = if resp.accepted {
            "ACCEPTED"
        } else {
            "DENIED  "
        };
        println!(
            "reserve #{}  ${:.2}  → {verdict}  (reserved ${:.2} / budget ${:.2}){}",
            i + 1,
            micros as f64 / USD as f64,
            resp.reserved_micros as f64 / USD as f64,
            resp.budget_micros as f64 / USD as f64,
            if resp.accepted {
                String::new()
            } else {
                format!("  — {}", resp.reason)
            }
        );
    }

    cluster
        .write(Request::Settle {
            run: run.to_string(),
            reserved_micros: 40 * 10_000,
            actual_micros: 25 * 10_000,
        })
        .await?;
    println!("\nsettled reservation #1: actual $0.25 (was reserved $0.40)");

    tokio::time::sleep(Duration::from_millis(200)).await;
    let follower_id = cluster
        .nodes
        .iter()
        .map(|n| n.id)
        .find(|&id| id != leader)
        .unwrap();
    let follower = cluster.node(follower_id).unwrap();
    let state = follower.read_run(run).await.unwrap();
    println!(
        "\nread replicated state from follower node {follower_id}:\n  spent    ${:.2}\n  reserved ${:.2}\n  budget   ${:.2}",
        state.spent_micros as f64 / USD as f64,
        state.reserved_micros as f64 / USD as f64,
        state.budget_micros as f64 / USD as f64,
    );

    println!("\n✔ budget replicated + enforced by consensus across 3 nodes.");
    cluster.shutdown().await;
    Ok(())
}
