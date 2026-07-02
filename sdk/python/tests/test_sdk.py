import json

import pytest

import tokenfuse


def test_gateway_and_messages_url():
    assert tokenfuse.gateway_url() == "http://127.0.0.1:4100"
    assert tokenfuse.gateway_url("http://host:9/") == "http://host:9"
    assert tokenfuse.messages_url("http://host:9") == "http://host:9/v1/messages"


def test_run_headers_minimal():
    h = tokenfuse.run_headers("run-1")
    assert h == {"X-Fuse-Run-Id": "run-1"}


def test_run_headers_full():
    h = tokenfuse.run_headers(
        "run-1",
        budget_usd=5.0,
        task_type="code-review",
        parent_run_id="parent",
        tags={"team": "core"},
    )
    assert h["X-Fuse-Run-Id"] == "run-1"
    assert h["X-Fuse-Budget-Usd"] == "5.0"
    assert h["X-Fuse-Task-Type"] == "code-review"
    assert h["X-Fuse-Parent-Run-Id"] == "parent"
    assert h["X-Fuse-Tags"] == "team=core"


def test_raise_for_fuse_ignores_non_402():
    tokenfuse.raise_for_fuse(200, {"ok": True})  # no raise


def test_raise_for_fuse_budget_exceeded_from_dict():
    body = {
        "error": {
            "type": "budget_exceeded",
            "run_id": "r2",
            "budget_usd": 5.0,
            "spent_usd": 4.97,
            "policy_id": "default",
            "reason": "per-run budget exceeded",
            "retryable": False,
        }
    }
    with pytest.raises(tokenfuse.BudgetExceeded) as ei:
        tokenfuse.raise_for_fuse(402, body)
    e = ei.value
    assert e.run_id == "r2"
    assert e.budget_usd == 5.0
    assert e.spent_usd == 4.97
    assert isinstance(e, tokenfuse.FuseError)


def test_raise_for_fuse_loop_detected_from_json_string():
    body = json.dumps({"error": {"type": "loop_detected", "run_id": "r3", "reason": "loop"}})
    with pytest.raises(tokenfuse.LoopDetected):
        tokenfuse.raise_for_fuse(402, body)


def test_raise_for_fuse_killed_from_bytes():
    body = json.dumps({"error": {"type": "killed", "run_id": "r4"}}).encode()
    with pytest.raises(tokenfuse.Killed):
        tokenfuse.raise_for_fuse(402, body)


def test_unknown_type_falls_back_to_base_error():
    with pytest.raises(tokenfuse.FuseError):
        tokenfuse.raise_for_fuse(402, {"error": {"type": "something_new"}})


def test_raise_for_fuse_taint_blocked_403():
    body = {"error": {"type": "taint_blocked", "run_id": "r6", "reason": "web denies exec"}}
    with pytest.raises(tokenfuse.TaintBlocked) as ei:
        tokenfuse.raise_for_fuse(403, body)
    assert ei.value.run_id == "r6"


def test_check_response_duck_typed():
    class FakeResp:
        status_code = 402

        def json(self):
            return {"error": {"type": "budget_exceeded", "run_id": "r5"}}

    with pytest.raises(tokenfuse.BudgetExceeded):
        tokenfuse.check_response(FakeResp())
