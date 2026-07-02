"""Tokenfuse Python SDK — thin helpers to route an agent's LLM calls through the
Tokenfuse gateway and to turn its 402 responses into typed exceptions.

Tokenfuse is a drop-in proxy: you don't rewrite your agent, you just point your
provider client at the gateway and attach a few headers. This SDK builds those
headers/URLs and interprets the gateway's stable error contract.

Example (Anthropic client)::

    import anthropic, tokenfuse

    client = anthropic.Anthropic(
        base_url=tokenfuse.gateway_url(),                 # http://127.0.0.1:4100
        default_headers=tokenfuse.run_headers("run-42", budget_usd=5.0),
    )
    try:
        msg = client.messages.create(model="claude-sonnet", max_tokens=1024, messages=[...])
    except tokenfuse.BudgetExceeded as e:
        print(f"run {e.run_id} hit its budget: spent ${e.spent_usd} of ${e.budget_usd}")

The SDK is pure-stdlib; it does not depend on any provider package.
"""

from __future__ import annotations

import json
from typing import Any, Mapping

__all__ = [
    "DEFAULT_GATEWAY",
    "gateway_url",
    "messages_url",
    "run_headers",
    "raise_for_fuse",
    "check_response",
    "FuseError",
    "BudgetExceeded",
    "LoopDetected",
    "PolicyViolation",
    "Killed",
]

DEFAULT_GATEWAY = "http://127.0.0.1:4100"


def gateway_url(gateway: str = DEFAULT_GATEWAY) -> str:
    """Base URL to hand to a provider client's ``base_url``."""
    return gateway.rstrip("/")


def messages_url(gateway: str = DEFAULT_GATEWAY) -> str:
    """Full URL of the Anthropic-style messages endpoint."""
    return f"{gateway_url(gateway)}/v1/messages"


def run_headers(
    run_id: str,
    *,
    budget_usd: float | None = None,
    task_type: str | None = None,
    parent_run_id: str | None = None,
    tags: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Build the ``X-Fuse-*`` attribution headers for a run.

    Only ``run_id`` is required; without it the gateway treats a call as an
    unmanaged pass-through.
    """
    headers: dict[str, str] = {"X-Fuse-Run-Id": run_id}
    if budget_usd is not None:
        headers["X-Fuse-Budget-Usd"] = repr(float(budget_usd))
    if task_type is not None:
        headers["X-Fuse-Task-Type"] = task_type
    if parent_run_id is not None:
        headers["X-Fuse-Parent-Run-Id"] = parent_run_id
    if tags:
        headers["X-Fuse-Tags"] = ",".join(f"{k}={v}" for k, v in tags.items())
    return headers


class FuseError(Exception):
    """Base class for a Tokenfuse 402 block."""

    def __init__(
        self,
        message: str,
        *,
        run_id: str | None = None,
        budget_usd: float | None = None,
        spent_usd: float | None = None,
        policy_id: str | None = None,
        reason: str | None = None,
    ) -> None:
        super().__init__(message)
        self.run_id = run_id
        self.budget_usd = budget_usd
        self.spent_usd = spent_usd
        self.policy_id = policy_id
        self.reason = reason


class BudgetExceeded(FuseError):
    """The run's budget would be exceeded (error type ``budget_exceeded``)."""


class LoopDetected(FuseError):
    """A runaway loop was detected (error type ``loop_detected``)."""


class PolicyViolation(FuseError):
    """A policy limit was violated (error type ``policy_violation``)."""


class Killed(FuseError):
    """The run was killed by an operator (error type ``killed``)."""


_ERROR_TYPES: dict[str, type[FuseError]] = {
    "budget_exceeded": BudgetExceeded,
    "loop_detected": LoopDetected,
    "policy_violation": PolicyViolation,
    "killed": Killed,
}


def _coerce_body(body: Any) -> dict[str, Any]:
    if isinstance(body, (bytes, bytearray)):
        body = body.decode("utf-8", "replace")
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            return {}
    return body if isinstance(body, dict) else {}


def raise_for_fuse(status_code: int, body: Any) -> None:
    """Raise the appropriate :class:`FuseError` if ``status_code`` is 402 and the
    body carries a Tokenfuse error. No-op for any other status.

    ``body`` may be a dict, a JSON string, or raw bytes.
    """
    if status_code != 402:
        return
    data = _coerce_body(body)
    err = data.get("error")
    if not isinstance(err, dict):
        return
    kind = err.get("type", "")
    cls = _ERROR_TYPES.get(kind, FuseError)
    raise cls(
        err.get("reason") or kind or "tokenfuse blocked the request",
        run_id=err.get("run_id"),
        budget_usd=err.get("budget_usd"),
        spent_usd=err.get("spent_usd"),
        policy_id=err.get("policy_id"),
        reason=err.get("reason"),
    )


def check_response(response: Any) -> None:
    """Convenience for ``requests``/``httpx`` responses: inspect a duck-typed
    object with ``.status_code`` and ``.json()``/``.text`` and raise on a
    Tokenfuse 402.
    """
    status = getattr(response, "status_code", None)
    if status != 402:
        return
    body: Any
    try:
        body = response.json()
    except Exception:  # noqa: BLE001 — fall back to text
        body = getattr(response, "text", "")
    raise_for_fuse(402, body)
