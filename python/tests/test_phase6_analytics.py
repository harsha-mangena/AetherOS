"""Phase 6c tests: analytics as a pure, isolation-preserving projection over evidence.

Proves the metrics are derived from real ledger entries (traceable to the audit trail),
are scoped per tenant, and reconcile with what actually executed.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from aetheros_orchestrator.analytics import compute_tenant_analytics
from aetheros_orchestrator.api import create_app
from aetheros_orchestrator.run_service import RunService


def _svc() -> RunService:
    svc = RunService(earn_autonomy_to=2)
    svc.tenants.create("Tenant A", tenant_id="tenant-a")
    svc.tenants.create("Tenant B", tenant_id="tenant-b")
    return svc


def _drive_to_completion(svc: RunService, run_id: str, tenant: str) -> None:
    """Advance a run, auto-approving every gate, until terminal."""
    state = svc.advance(run_id, tenant)
    guard = 0
    while state.status == "awaiting_approval" and guard < 20:
        state = svc.resume(run_id, state.pending_step_id, True, "human:test", tenant)
        guard += 1


def test_analytics_reflect_executed_work():
    svc = _svc()
    run = svc.create_run("investigate the production incident", tenant_id="tenant-a")
    _drive_to_completion(svc, run.run_id, "tenant-a")

    a = svc.analytics("tenant-a")
    assert a["tenant_id"] == "tenant-a"
    assert a["runs"]["total"] == 1
    assert a["runs"]["completed"] == 1
    assert a["tools"]["invocations"] >= 1
    assert a["spend"]["total_minor"] > 0
    # Spend-by-tool must reconcile with total spend.
    assert sum(a["spend"]["by_tool"].values()) == a["spend"]["total_minor"]
    # Every metric is backed by scanned evidence, and all ledgers verify.
    assert a["integrity"]["evidence_entries_scanned"] > 0
    assert a["integrity"]["all_ledgers_verified"] is True


def test_analytics_are_tenant_scoped():
    svc = _svc()
    ra = svc.create_run("incident a", tenant_id="tenant-a")
    rb = svc.create_run("incident b", tenant_id="tenant-b")
    _drive_to_completion(svc, ra.run_id, "tenant-a")
    _drive_to_completion(svc, rb.run_id, "tenant-b")

    a = svc.analytics("tenant-a")
    b = svc.analytics("tenant-b")
    # Each tenant sees exactly its own single run, never the other's.
    assert a["runs"]["total"] == 1
    assert b["runs"]["total"] == 1


def test_analytics_empty_tenant():
    svc = _svc()
    a = svc.analytics("tenant-a")
    assert a["runs"]["total"] == 0
    assert a["spend"]["total_minor"] == 0
    assert a["integrity"]["all_ledgers_verified"] is True  # vacuously true


def test_compute_handles_unverified_ledger():
    # A tampered/unverified report flips the integrity flag.
    reports = [
        {"verified": False, "entries": [{"event_type": "tool.invoked", "payload": {"tool": "x", "cost_minor": 10}}]},
    ]
    metrics = compute_tenant_analytics("t", reports)
    assert metrics.all_ledgers_verified is False
    assert metrics.total_spend_minor == 10
    assert metrics.spend_by_tool == {"x": 10}


def test_compute_counts_governance_events():
    reports = [
        {
            "verified": True,
            "entries": [
                {"event_type": "policy.denied", "payload": {}},
                {"event_type": "approval.granted", "payload": {}},
                {"event_type": "approval.denied", "payload": {}},
                {"event_type": "autonomy.promoted", "payload": {}},
                {"event_type": "tool.failed", "payload": {}},
                {"event_type": "run.halted", "payload": {}},
            ],
        }
    ]
    m = compute_tenant_analytics("t", reports)
    assert m.policy_violations == 1
    assert m.approvals_granted == 1
    assert m.approvals_denied == 1
    assert m.autonomy_promotions == 1
    assert m.tool_failures == 1
    assert m.runs_halted == 1
    assert round(m.approval_rate, 2) == 0.5


def test_api_analytics_endpoint_scoped_by_header():
    svc = _svc()
    c = TestClient(create_app(svc))
    created = c.post(
        "/runs", json={"intent": "investigate incident"}, headers={"X-Tenant-Id": "tenant-a"}
    )
    run_id = created.json()["run_id"]
    # Drive via the API, auto-approving gates.
    state = c.post(f"/runs/{run_id}/advance", headers={"X-Tenant-Id": "tenant-a"}).json()
    guard = 0
    while state["status"] == "awaiting_approval" and guard < 20:
        state = c.post(
            f"/runs/{run_id}/resume",
            json={"step_id": state["pending_step_id"], "approved": True, "approver": "human"},
            headers={"X-Tenant-Id": "tenant-a"},
        ).json()
        guard += 1

    a = c.get("/analytics", headers={"X-Tenant-Id": "tenant-a"}).json()
    assert a["runs"]["total"] == 1
    assert a["runs"]["completed"] == 1
    # Tenant B sees nothing.
    b = c.get("/analytics", headers={"X-Tenant-Id": "tenant-b"}).json()
    assert b["runs"]["total"] == 0
    # Unknown tenant is a 404.
    assert c.get("/analytics", headers={"X-Tenant-Id": "ghost"}).status_code == 404
