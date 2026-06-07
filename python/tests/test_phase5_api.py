"""Phase 5 backend tests: the resumable RunService state machine and the HTTP API
that the desktop UI calls. These prove the full governed flow — intent -> plan ->
authorize -> sandboxed execution -> human approval gate -> tamper-evident evidence —
works headlessly over the same surface the GUI uses.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from aetheros_orchestrator.api import create_app
from aetheros_orchestrator.run_service import RunService, RunStatus


INTENT = "Investigate the production incident in checkout and restore service"


# ── RunService state machine ─────────────────────────────────────────────────

def test_run_service_pauses_at_approval_gate_then_completes():
    svc = RunService()
    run = svc.create_run(INTENT)
    assert run.status == RunStatus.PLANNED
    assert len(run.plan.steps) >= 4

    state = svc.advance(run.run_id)
    # First high-impact step (the restart) should pause for approval.
    assert state.status == RunStatus.AWAITING_APPROVAL
    assert state.pending_step_id is not None

    # Approve the gated step and continue; a second gate (slack post) may appear.
    while state.status == RunStatus.AWAITING_APPROVAL:
        state = svc.resume(
            run.run_id, state.pending_step_id, approved=True, approver="human:vamsi"
        )

    assert state.status == RunStatus.COMPLETED
    assert state.denied_reason is None

    ev = svc.evidence(run.run_id)
    assert ev["verified"] is True
    # Every executed step carries provenance from the sandbox.
    invoked = [e for e in ev["entries"] if e["event_type"] == "tool.invoked"]
    assert invoked and all("provenance_id" in e["payload"] for e in invoked)


def test_run_service_halts_when_human_denies():
    svc = RunService()
    run = svc.create_run(INTENT)
    state = svc.advance(run.run_id)
    assert state.status == RunStatus.AWAITING_APPROVAL

    state = svc.resume(
        run.run_id, state.pending_step_id, approved=False, approver="human:vamsi"
    )
    assert state.status == RunStatus.HALTED
    assert "approval denied" in (state.denied_reason or "")
    # Ledger still verifies after a halt.
    assert svc.evidence(run.run_id)["verified"] is True


def test_resume_rejects_wrong_step():
    svc = RunService()
    run = svc.create_run(INTENT)
    svc.advance(run.run_id)
    with pytest.raises(ValueError):
        svc.resume(run.run_id, "step-does-not-exist", approved=True, approver="x")


# ── HTTP API ──────────────────────────────────────────────────────────────────

def _client() -> TestClient:
    return TestClient(create_app(RunService()))


def test_api_health_and_policy():
    c = _client()
    assert c.get("/health").json()["status"] == "ok"
    pol = c.get("/config/policy").json()
    assert pol["default_allow"] is False
    rule_ids = {r["id"] for r in pol["rules"]}
    assert "deny-prod-delete" in rule_ids


def test_api_full_governed_run_over_http():
    c = _client()
    created = c.post("/runs", json={"intent": INTENT}).json()
    run_id = created["run_id"]
    assert created["status"] == "planned"
    assert created["autonomy_tier"] >= 1

    state = c.post(f"/runs/{run_id}/advance").json()
    assert state["status"] == "awaiting_approval"

    # Approve through any gates.
    while state["status"] == "awaiting_approval":
        state = c.post(
            f"/runs/{run_id}/resume",
            json={"step_id": state["pending_step_id"], "approved": True, "approver": "human:vamsi"},
        ).json()

    assert state["status"] == "completed"
    assert all(s["status"] in ("executed",) for s in state["plan"])

    ev = c.get(f"/runs/{run_id}/evidence").json()
    assert ev["verified"] is True
    assert ev["length"] >= 7


def test_api_unknown_run_is_404():
    c = _client()
    assert c.get("/runs/nope").status_code == 404
    assert c.post("/runs/nope/advance").status_code == 404


def test_api_resume_conflict_when_not_awaiting():
    c = _client()
    run_id = c.post("/runs", json={"intent": INTENT}).json()["run_id"]
    # Resuming before advancing to a gate is a conflict.
    r = c.post(
        f"/runs/{run_id}/resume",
        json={"step_id": "step-1", "approved": True, "approver": "x"},
    )
    assert r.status_code == 409
