"""Phase 7 API tests: constitution view, compliance export, over the HTTP surface."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from aetheros_orchestrator.api import create_app
from aetheros_orchestrator.run_service import RunService


INTENT = "Investigate the production incident in checkout and restore service"


def _client() -> TestClient:
    return TestClient(create_app(RunService()))


def test_constitution_endpoint_returns_articles() -> None:
    c = _client()
    r = c.get("/config/constitution")
    assert r.status_code == 200
    body = r.json()
    assert "version" in body
    assert isinstance(body["articles"], list)


def test_compliance_endpoint_empty_tenant_is_attestable() -> None:
    c = _client()
    r = c.get("/compliance")
    assert r.status_code == 200
    body = r.json()
    # No runs yet -> vacuously attestable and compliant.
    assert body["attestable"] is True
    assert body["compliant"] is True
    assert body["run_count"] == 0


def test_compliance_endpoint_after_a_governed_run() -> None:
    svc = RunService()
    c = TestClient(create_app(svc))
    run = svc.create_run(INTENT)
    # Drive the run forward through any approval gates.
    state = svc.advance(run.run_id)
    while state.status == "awaiting_approval":
        state = svc.resume(run.run_id, state.pending_step_id, approved=True, approver="human:vamsi")

    r = c.get("/compliance")
    assert r.status_code == 200
    body = r.json()
    assert body["run_count"] >= 1
    # The trail must verify, so the tenant is attestable.
    assert body["attestable"] is True
    # Each report carries its run id and findings.
    assert all("run_id" in rep for rep in body["reports"])
    assert all(rep["findings"] for rep in body["reports"])


def test_compliance_unknown_tenant_404() -> None:
    c = _client()
    r = c.get("/compliance", headers={"X-Tenant-Id": "does-not-exist"})
    assert r.status_code == 404
