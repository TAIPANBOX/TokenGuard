# TokenFuse — Semantic cache: detailed design

> Phase 2.5. Status: designed 2026-07-02. Headline showcase: "Saved this month: $X" + a "% of savings" pricing model.

## A.1. Task boundaries

We cache LLM responses to repeated/similar requests. We NEVER cache: calls involving side-effect tools; errors and model refusals; tainted contexts (tied to the taint model, doc 07); time-sensitive requests.

## A.2. Two-layer structure

**L1 — exact:** key = BLAKE3(model + normalized system prompt + messages + tools schema + sampling parameters). Only at temperature 0 or with explicit opt-in. Byte-for-byte replay.

**L2 — semantic:** works ONLY within a hard partition:

```
Key = [hard part, exact match]
         tenant_id + model + hash(system prompt) + hash(tools) + task_type
       [soft part, similarity]
         embedding(semantic core of the request)
```

Semantic core = the last user message + task instruction (excluding retrieval context, ≤512 tokens). The partition always includes a tenant slot; optionally user_id.

**Current implementation note (2026-07-12):** the shipped gateway is single-tenant per process today (one gateway deployment serves one tenant), so the `tenant_id` slot above is not yet wired to a real per-request identity. `crates/gateway/src/proxy.rs` calls `SemanticCache::partition_key` with a fixed literal `"default"` in the tenant slot for every request that process handles. That is not a cross-tenant leak in the shipped topology, since a single process never serves more than one tenant. It is, however, a landmine for the future: before any shared/hosted multi-tenant gateway mode ships (one process serving multiple tenants), a real per-request tenant id MUST be threaded from the request into `partition_key`, or requests from different tenants sharing that process would land in the same cache partition.

## A.3. Thresholds + guard rails

| Similarity | Decision |
|---|---|
| ≥ 0.97 | auto-hit (default, per task-type) |
| 0.93–0.97 | "verified hit": optional Haiku judge (disabled by default) |
| < 0.93 | miss |

**Entity guard (mandatory):** "a plan for 5 users" vs "for 50" = similarity ~0.99. Extract numbers/dates/IDs/emails/URLs from both requests (regex, <1 ms) → the sets must match exactly, otherwise miss. Length-ratio guard > 1.5 → miss.

**Shadow mode first:** during the first week the cache only logs "would have been a hit, would have saved $X" — the user sees the projected savings and the false-hit rate BEFORE it's turned on.

## A.4. Local ONNX model

| Decision | Choice |
|---|---|
| Model | multilingual-e5-small int8 ONNX (~50 MB, 384d) — multilingual (Ukrainian/English), 2–5 ms CPU |
| Runtime | fastembed-rs (ort + tokenizers, battle-tested by Qdrant) |
| Distribution | model NOT bundled in the binary: downloaded on first start into the data-dir + checksum; an air-gapped archive is available. The binary stays ~10 MB |
| ANN | usearch (HNSW, SIMD, mmap), a separate index per partition — no external vector DB |
| Model swap | `embedding_model` config; entries from different models = different epochs |

Hit latency: embed ~3 ms + HNSW ~0.5 ms + guards ~1 ms ≈ 5 ms versus ~2,000 ms for a live call.

## A.5. Invalidation (7 mechanisms)

1. **Partition-based (free):** a change to the system prompt/tools/model = a different hard key — old entries simply aren't found. The most common case requires no action.
2. **TTL per policy:** default 24h; per task-type (docs-qa: 7d, support: 1h).
3. **Epochs:** cache_epoch per partition; a bump = an instant logical flush (lazy eviction).
4. **Tags:** entries carry tags (X-Fuse-Tags, tools). CLI `tokenfuse cache invalidate --tag docs-v2` + `POST /v1/cache/invalidate` — a hook for CI/CD.
5. **Temporal classifier:** "today/now/latest/dates" → a short TTL (15 min) or bypass. A keyword list, not ML.
6. **Feedback:** `POST /v1/cache/report-bad-hit` + a dashboard button → the entry is killed, the partition threshold +0.01 (self-tuning).
7. **Eviction:** TinyLFU, entries/bytes limits per partition.

## A.6. Replay and accounting

- A hit = a synthesized SSE stream, header `X-Fuse-Cache: hit; similarity=0.984; age=3612s`.
- The ledger records saved_microusd = the price of the original call at current pricing.
- Only stop_reason: end_turn is cached; tool_use responses — L1 only.

## A.7. Config

```yaml
cache:
  mode: shadow            # off | shadow | on
  l1: { enabled: true, ttl: 7d }
  l2:
    enabled: true
    threshold: 0.97
    judge: { enabled: false, model: claude-haiku-4-5 }
    ttl: 24h
    max_entries_per_partition: 100_000
    entity_guard: true
    temporal_bypass: true
  never_cache:
    - { tools_present: true, except_readonly: true }
    - { tainted: true }
    - { task_type: "financial-*" }
```

## A.8. Default decisions (locked in)

Favor conservatism over hit-rate: shadow mode mandatory for the first week → threshold 0.97 with no judge → entity guard always on → tools = L1 only. One false hit costs trust in the entire feature.
