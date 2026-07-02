# tokenfuse (Python SDK)

Thin, dependency-free helpers to route an agent's LLM calls through the
[Tokenfuse](https://github.com/TAIPANBOX/tokenfuse) gateway and turn its `402`
blocks into typed exceptions.

Tokenfuse is a **drop-in proxy** — you don't rewrite your agent, you point your
provider client at the gateway and attach a few headers.

## Install

```bash
pip install tokenfuse   # (planned; for now: pip install -e sdk/python)
```

## Use

```python
import anthropic, tokenfuse

client = anthropic.Anthropic(
    base_url=tokenfuse.gateway_url(),                    # http://127.0.0.1:4100
    default_headers=tokenfuse.run_headers("run-42", budget_usd=5.0, task_type="code-review"),
)

try:
    msg = client.messages.create(model="claude-sonnet", max_tokens=1024, messages=[...])
except tokenfuse.BudgetExceeded as e:
    print(f"run {e.run_id}: spent ${e.spent_usd} of ${e.budget_usd}")
except tokenfuse.LoopDetected as e:
    print(f"runaway loop on {e.run_id}: {e.reason}")
```

For raw HTTP clients (`requests` / `httpx`), call `tokenfuse.check_response(resp)`
after the request, or `tokenfuse.raise_for_fuse(status_code, body)`.

## Exceptions

All inherit `tokenfuse.FuseError` (fields: `run_id`, `budget_usd`, `spent_usd`,
`policy_id`, `reason`):

- `BudgetExceeded` — the run's budget would be exceeded
- `LoopDetected` — a runaway loop was detected
- `PolicyViolation` — a policy limit was hit
- `Killed` — an operator killed the run
