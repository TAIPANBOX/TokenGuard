# 10 · High-Availability Cluster — a raft-replicated budget ledger

> Status: **implemented** (`crates/cluster`). In-process 3-node cluster runs in
> the demo and CI; the storage and network layers are the real openraft
> backends, ready to swap for durable storage + HTTP transport.

## Why

A single gateway is two single points of failure at once:

1. **Availability** — if the process dies, every agent loses its guardrail.
2. **Truth** — the ledger (who has spent what against which budget) lives in one
   process's memory. Lose it and you lose the one number that decides whether
   the next call is allowed.

For a component whose whole job is to *stop* runaway spend, "the enforcer
crashed so we stopped enforcing" is the worst possible failure mode. Budgets
must outlive any one node, and the affordability decision must stay correct even
when several gateways serve the same run concurrently.

## What consensus buys us

We replicate the ledger across N nodes with [openraft] (Raft consensus). Two
properties fall out:

| Property | How raft delivers it |
|---|---|
| **Durability** | A `Reserve`/`Settle` is committed only once a **quorum** (⌈N/2⌉+1) has it in its log. A minority of nodes can crash without losing a single committed budget update. |
| **Linearizability** | Every budget mutation is a log entry applied in a **total order**. The affordability check runs once, in that order, on the committed state machine — so two sub-agents racing against two different gateways can never *both* squeeze past the same ceiling. |

That second point is the subtle one. With independent per-node counters you get
a classic double-spend: node A and node B each see `$0.80 / $1.00` and each
approve a `$0.30` reserve, landing the run at `$1.40`. Putting the check *inside*
the replicated state machine makes the ceiling a cluster-wide invariant, not a
per-node hope.

## Design

```
          client_write(Reserve{run, µUSD})
                      │
                      ▼
             ┌─────────────────┐   append_entries (quorum)
             │   Leader (n1)   │ ───────────────┐
             │  Raft + Ledger  │                ▼
             └─────────────────┘        ┌──────────────┐  ┌──────────────┐
                      │                  │ Follower n2  │  │ Follower n3  │
                      │ commit @ quorum  │ Raft+Ledger  │  │ Raft+Ledger  │
                      ▼                  └──────────────┘  └──────────────┘
             apply in log order:  runs[run].committed()+µUSD ≤ budget ?
                      │                accept → reserved += µUSD
                      ▼                deny   → Response{accepted:false}
             Response returned to caller after commit
```

### The state machine *is* the ledger

`crates/cluster/src/types.rs` defines the replicated domain:

- **`Request`** — `Open{run, budget}` · `Reserve{run, µUSD}` · `Settle{run,
  reserved, actual}`. Amounts are integer **microdollars**, matching
  `tokenfuse-core::Money`; no floats ever enter the consensus path.
- **`LedgerState::apply`** — the single place a budget is enforced. `Reserve`
  is accepted iff `spent + reserved + amount ≤ budget`; otherwise it returns
  `accepted: false` with a `budget_exceeded` reason and leaves state untouched.
- **`Response`** — accept/deny plus the post-apply `spent` / `reserved` /
  `budget`, so the caller learns the authoritative numbers.

### Storage (`store.rs`)

Two openraft **storage-v2** traits, both cloneable handles over
`Arc<Mutex<..>>` so a reader / snapshot-builder can share the same data:

- **`LogStore`** — `RaftLogStorage` + `RaftLogReader`: the vote, the log
  (`BTreeMap<index, Entry>`), committed pointer, purge/truncate, and an
  immediate flush callback (in-memory writes are durable on return).
- **`StateMachineStore`** — `RaftStateMachine` + `RaftSnapshotBuilder`: applies
  entries into `LedgerState`, tracks `last_applied` + membership, and
  serialises/installs JSON snapshots. It also exposes `read_run()` for fast
  **local** reads of a run's spend (eventually consistent on followers).

This is the reference **in-memory** backend. A durable deployment swaps it for
redb/RocksDB behind the exact same two traits — no change to the domain or the
gateway.

### Network — two transports, same traits

The three raft RPCs (`append_entries`, `vote`, `install_snapshot`) are abstracted
behind openraft's `RaftNetwork`/`RaftNetworkFactory`. Two implementations ship:

- **In-process (`network.rs`)** — `Router` dispatches RPCs straight to the target
  node's `Raft` handle. Makes a whole cluster runnable in one binary; used by the
  demo and the in-process tests.
- **Cross-process over HTTP (`net_http.rs` + `server.rs`)** — `HttpNetwork`
  resolves a node id to a peer base URL and POSTs each RPC as JSON; `server.rs`
  is a small axum server per node that exposes `/raft/append`, `/raft/vote`,
  `/raft/snapshot` (peer RPCs) plus `/mgmt/init`, `/mgmt/metrics`, `/api/write`,
  and `/api/read/{run}`. This is what lets gateways on **separate machines** form
  one cluster. openraft's RPC types are `serde`-serialized (the `serde` feature),
  so the wire format is just JSON.

Run a real node:

```bash
tokenfuse-cluster serve --id 1 --http 127.0.0.1:5001 \
  --peers 1=http://127.0.0.1:5001,2=http://127.0.0.1:5002,3=http://127.0.0.1:5003 --init
# (repeat on each host with its own --id/--http; --init once)
```

Or watch three HTTP nodes form a cluster in one process:

```bash
cargo run -p tokenfuse-cluster -- demo-http
```

### Cluster helper (`lib.rs`)

`Cluster::start(&[1,2,3])` builds and initializes the nodes; `write()` routes to
the current leader and returns the applied `Response`; `wait_for_leader()`,
`leader()`, `node()`, and `shutdown()` round it out.

## Run it

```bash
cargo run -p tokenfuse-cluster
```

```
── TokenFuse HA cluster demo ──
starting 3 nodes {1, 2, 3} …
leader elected: node 1
opened budget for agent-42: $1.00
reserve #1  $0.40  → ACCEPTED  (reserved $0.40 / budget $1.00)
reserve #2  $0.40  → ACCEPTED  (reserved $0.80 / budget $1.00)
reserve #3  $0.40  → DENIED    (reserved $0.80 / budget $1.00)  — budget_exceeded: need 1200000 µUSD > budget 1000000 µUSD
settled reservation #1: actual $0.25 (was reserved $0.40)
read replicated state from follower node 2:
  spent    $0.25
  reserved $0.40
  budget   $1.00
✔ budget replicated + enforced by consensus across 3 nodes.
```

The last two blocks are the proof: the over-budget reserve is denied by the
committed state machine, and the resulting spend is read back from a **follower**
— i.e. it really replicated, it wasn't just the leader's local memory.

## Tested invariants (`tests/cluster.rs`)

Real 3-node clusters with live election timers (multi-thread runtime):

- **`elects_leader_and_replicates_budget`** — a leader is elected and a committed
  reserve reaches a quorum's applied state.
- **`consensus_never_oversubscribes_budget`** — reserving exactly to the ceiling
  is accepted; one microdollar more is denied and leaves state unchanged.
- **`settle_moves_reserved_to_spent`** — settle converts a reservation to spend
  across the quorum.

## Tested invariants — HTTP transport (`tests/http_cluster.rs`)

Real clusters formed over `127.0.0.1:0` sockets, driven entirely through the
HTTP API:

- **`http_cluster_replicates_and_enforces`** — a leader is elected over HTTP, an
  over-budget reserve is denied by consensus, and the committed reservations are
  read back from a **follower** over HTTP.
- **`writes_routed_to_leader_from_any_node`** — a write sent to a follower is
  surfaced as a retryable forward, and commits against the leader.

## Gateway integration (implemented)

The gateway talks to the cluster through an async `LedgerBackend` trait
(`crates/gateway/src/ledger_backend.rs`):

- The default backend, `LocalLedger`, wraps the in-process `tokenfuse-core::Ledger`
  — behaviour and performance unchanged when cluster mode is off.
- Behind the gateway's `cluster` feature, `RaftLedger`
  (`crates/gateway/src/raft_ledger.rs`) **co-locates a raft node** in the gateway
  process, runs its HTTP server so peer gateways replicate to it, and turns
  `open`/`reserve`/`settle` into raft writes (transparently forwarded to the
  leader). The budget check is therefore linearized across every gateway sharing
  the cluster.

`reserve`/`open`/`snapshot` are `async` (consensus round-trips); `settle` stays
synchronous and fire-and-forget so `SettleGuard::drop` still works — the local
backend settles inline, the raft backend spawns the write.

Enable it at launch (built with `--features cluster`):

```bash
TOKENFUSE_CLUSTER_ID=1 \
TOKENFUSE_CLUSTER_ADDR=127.0.0.1:5001 \
TOKENFUSE_CLUSTER_PEERS=1=http://127.0.0.1:5001,2=http://127.0.0.1:5002,3=http://127.0.0.1:5003 \
TOKENFUSE_CLUSTER_BOOTSTRAP=1 \
tokenfuse                       # run one gateway per host; BOOTSTRAP on exactly one
```

If consensus is unreachable, `reserve` **fails open** (consistent with
TokenFuse's default) — a cluster outage degrades to "no enforcement", never
"all agents blocked".

**Current limitations (documented):** the replicated state machine is flat, so
hierarchical sub-agent budgets (`X-Fuse-Parent-Run-Id`) and per-run step counts
are honoured only by the local backend; under cluster mode `parent` is ignored
and `steps` is a local counter. Porting the parent-chain into the SM is a
follow-up.

## Not yet (follow-ups)

- **Hierarchy + steps in the replicated SM** (see limitation above).
- **Durable storage backend** (redb) behind the storage traits.
- **`change_membership` join/leave** flow for rolling deploys (the API exposes
  `initialize`; add-learner/promote endpoints are the next increment).
- **Linearizable follower reads** via `ensure_linearizable()` + leader forward
  (reads today are eventually-consistent local reads).
- **HTTPS / auth** on the raft + admin endpoints for cross-machine deploys.

[openraft]: https://docs.rs/openraft
