# 18 · Show HN launch writeup

> Status: **draft for review** — not posted. Everything below is ready to
> copy-paste; pick one title, post the body as the submission text, and put
> the prepared first comment in immediately after submitting.
>
> HN "Show HN" rules require something people can try. We qualify:
> `docker run -p 4100:4100 ghcr.io/taipanbox/tokenfuse` works offline against
> the built-in fake provider, and the rug-pull demo is one `cargo run`.

## Title (pick one, ≤80 chars)

1. `Show HN: TokenFuse – a kill-switch proxy that stops runaway AI agent spend`
2. `Show HN: TokenFuse – per-run budgets and loop detection for AI agents (Rust)`
3. `Show HN: A circuit breaker for AI agents – budgets enforced with HTTP 402`

Recommendation: **#1** — leads with the artifact class ("proxy"), the verb
("stops"), and the pain ("runaway agent spend"). #3 is the fallback if a
mod normalizes the title; "HTTP 402" is good nerd-bait but buries the value.

**URL:** `https://github.com/TAIPANBOX/tokenfuse`

---

## Submission text

I run coding and research agents, and twice I've watched one get stuck in a
retry loop overnight. Nothing *looked* wrong — every call returned 200 OK, the
APM stayed green — the bill was the only symptom. One study of agentic coding
tasks found a single task can consume up to 1,000× the tokens of a plain chat
query, and the *same* task can vary 30× run-to-run depending on how the loop
unfolds. Per-key spend limits don't help: the unit that matters for an agent
is the **run** — one task, hundreds of calls, often several sub-agents — and
no provider limit can say "this task has a $2 ceiling" or notice that call
#34 is identical to call #31.

So I built TokenFuse: a reverse proxy you drop between your agent and the
LLM provider with a one-line base-URL change. It estimates the cost of every
call *before* forwarding it, checks it against a per-run budget (hierarchical
— a sub-agent's spend rolls up into its parent's ceiling), runs loop
detectors (identical-call, ping-pong, context-growth), and the moment a run
would go over, it returns **HTTP 402** and the agent stops cleanly. The
tagline is literal: enforcement, not observability. A dashboard tells you the
fire happened; this is the breaker.

Things in it I haven't seen built together elsewhere:

- **Budgets that survive a crash.** In cluster mode, reserve/settle goes
  through a raft state machine (openraft + redb), so two gateways serving the
  same run can't both slip past one ceiling, and a budget outlives a process
  restart.
- **An out-of-band kill switch.** There's an iPhone/Watch app whose kill
  request is signed on-device by the Secure Enclave. If the box running your
  agents is the thing misbehaving, a control path that doesn't live on that
  box stops being paranoia.
- **A free MCP rug-pull scanner.** MCP clients re-fetch `tools/list` on every
  connection and trust whatever comes back, so a tool a human approved can
  silently change its description or schema later. `tokenfuse mcp-scan` pins
  a fingerprint of the tool set you approved and flags any drift; it ships as
  a GitHub Action so a rug pull fails the PR. There's a self-contained demo —
  it starts its own stub server, poisons it, and catches itself:
  `cargo run --example rugpull_demo -p tokenfuse-gateway`.

Tech: Rust workspace; the enforcement decision itself is ~0.4 µs p99
in-process, ~0.8 ms p50 added on the wire; SSE streams pass straight through.
Telemetry goes to Parquet files, queryable with `tokenfuse sql "..."` — no
database. Metadata-only by default: it prices and counts your traffic, it
doesn't store prompt contents.

Honest limitations, so you don't have to dig for them: budget enforcement is
estimate-before / settle-after, a fast pre-flight approximation reconciled
against real usage — not a hard guarantee that not one extra cent is spent.
It's fail-open by default (if TokenFuse breaks, your traffic flows — run the
HA cluster if you want the opposite trade-off). And it's a young v0.3.0:
functional and CI-tested, but no external security audit yet. Default mode is
**shadow** — it records what it *would* have blocked and changes nothing, so
you can evaluate it risk-free and flip to enforce when the numbers convince
you.

Everything is Apache-2.0, self-hosted, and free forever: the proxy, the CLI,
the scanner and the CI action, and the Cloud control plane with the fleet
dashboard. No seat limits, no time limit, no paid tier.

Try it (offline, no signup — built-in fake provider):

    docker run -p 4100:4100 ghcr.io/taipanbox/tokenfuse

I'd especially value feedback on the loop-detection heuristics (what runaway
patterns have bitten you that identical-call/ping-pong/context-growth
wouldn't catch?) and on whether estimate-then-settle budgets are honest
enough for your production bar.

---

## Prepared first comment (post immediately after submitting)

A bit more detail for the skeptical, because the obvious questions have real
answers:

**"My provider already has spend limits."** Org-level limits cap a month and
a key. They can't cap one task, can't see that a sub-agent belongs to a
parent task, can't detect a loop (the provider sees valid, novel-enough
requests), and can't stop a run mid-flight. Also: one TokenFuse fronts
Anthropic, OpenAI, Ollama, vLLM — any Anthropic/OpenAI-shaped endpoint — so
the budget is provider-agnostic.

**"Why not LiteLLM / a gateway?"** Gateways are routing + per-key caps, and
they're good at that. Run-scoped hierarchical budgets, loop detection, and a
kill-switch for a task in flight is a different job. We're complementary —
some people run TokenFuse behind their router.

**"Isn't loop detection just heuristics? False positives?"** Yes, they're
deterministic heuristics, deliberately — no LLM in the enforcement path. The
mitigation is workflow: shadow mode logs what would have been blocked, and
`tokenfuse backtest` replays a candidate policy over your own past (Parquet)
traffic before you enforce anything. You see your false-positive rate on your
own workload first.

**"What's the catch on 'free'?"** There is no catch: the whole thing is free
and self-hosted, including the Cloud control plane (fleet dashboard, central
budgets, Slack/mobile kill). No seat limits, no time limit, no paid tier. The
commercial product is separate: a secured, managed enterprise control room
over the whole agent-governance stack, for companies that want the stack run
for them. TokenFuse itself stays free and open.

**"Secure Enclave kill switch sounds like a gimmick."** It's the answer to a
specific threat: the host running your agents is compromised or looping so
hard you can't SSH in. Every other kill path (API, TUI, Slack, dashboard)
ultimately routes through infrastructure the agent host can reach. A phone
that signs the stop order in hardware is an independent control path, and
"stolen API token ≠ ability to stop or fake-stop the fleet" falls out of the
signature check.

**"Does it read my prompts?"** No — metadata-only by default. Cost, token
counts, timing, fingerprints. The DLP/taint features that do look at content
run in-process and still don't persist prompt bodies.

Source, benchmarks (methodology included), and a 15-doc design trail are all
in the repo. Ask me anything, I'll be here all day.

---

## Launch checklist

- [ ] Post on a **weekday, 14:00–16:00 Kyiv** (07:00–09:00 US Eastern) —
      catches US morning without the weekend graveyard.
- [ ] Submission: title #1, URL = repo, body = submission text above.
- [ ] First comment in within 2 minutes (text above).
- [ ] Warm the demo: confirm `ghcr.io/taipanbox/tokenfuse` pulls clean on a
      fresh machine and `rugpull_demo` runs green on current main.
- [ ] `README` top: no broken images/links (HN traffic reads it before you
      can fix anything).
- [ ] Be available for ~4 hours to answer; short, technical, no defensive
      tone. Concede weak points fast (audit, estimate-vs-guarantee) — the
      honesty *is* the differentiator.
- [ ] Do NOT ask anyone for upvotes, share the direct HN link for "support",
      or reply-spam — voting-ring detection buries the post.
- [ ] If it doesn't stick (<10 points in 2h): fine — one re-post attempt is
      acceptable HN etiquette a few weeks later with a reworked title. Keep
      the text; iterate the hook.
- [ ] After the thread: harvest every objection into `docs/05-open-questions.md`
      and the FAQ; HN threads are free product research.

## Assets available if wanted

- `docs/assets/tokenfuse-top.gif` — the `tokenfuse top` kill in action
  (good for a comment reply, HN itself is text-only).
- `docs/17-rugpull-demo.md` — deep-link when the MCP security subthread
  starts (it will).
- `BENCHMARKS.md` — deep-link for the inevitable "µs claims or it didn't
  happen" comment.
