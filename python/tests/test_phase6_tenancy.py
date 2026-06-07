"""Phase 6a tests: multi-tenant workspace isolation as an *enforced* boundary.

These are mostly negative tests. The point of multi-tenancy here is security, not
data partitioning, so the suite proves that resources created under one tenant are
unreachable from another — and that the API does not even leak their existence.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from aetheros_orchestrator.api import create_app
from aetheros_orchestrator.run_service import RunService
from aetheros_orchestrator.tenancy import (
    DEFAULT_TENANT_ID,
    CrossTenantAccess,
    TenantError,
    TenantRegistry,
    UnknownTenant,
    _slugify,
)


# ── registry unit tests ──────────────────────────────────────────────────────


def test_registry_create_and_get():
    reg = TenantRegistry()
    t = reg.create("Acme Corp")
    assert t.tenant_id == "acme-corp"
    assert reg.get("acme-corp").display_name == "Acme Corp"
    assert reg.exists("acme-corp")


def test_registry_rejects_duplicate():
    reg = TenantRegistry()
    reg.create("Acme", tenant_id="acme")
    with pytest.raises(TenantError):
        reg.create("Acme Again", tenant_id="acme")


def test_registry_rejects_bad_slug():
    reg = TenantRegistry()
    with pytest.raises(TenantError):
        reg.create("x", tenant_id="x")  # too short


def test_registry_unknown_raises():
    reg = TenantRegistry()
    with pytest.raises(UnknownTenant):
        reg.get("nope")


def test_ensure_is_idempotent():
    reg = TenantRegistry()
    a = reg.ensure("team-a", "Team A")
    b = reg.ensure("team-a", "Team A (ignored)")
    assert a.tenant_id == b.tenant_id == "team-a"


def test_slugify():
    assert _slugify("Hello World!") == "hello-world"
    assert _slugify("  ALL_CAPS  ") == "all-caps"


# ── service-level isolation ───────────────────────────────────────────────────


def _svc_with_two_tenants() -> RunService:
    svc = RunService(earn_autonomy_to=2)
    svc.tenants.create("Tenant A", tenant_id="tenant-a")
    svc.tenants.create("Tenant B", tenant_id="tenant-b")
    return svc


def test_default_tenant_always_exists():
    svc = RunService()
    assert svc.tenants.exists(DEFAULT_TENANT_ID)
    # A run with no tenant lands in the default tenant.
    run = svc.create_run("investigate incident")
    assert run.tenant_id == DEFAULT_TENANT_ID


def test_run_is_tagged_with_its_tenant():
    svc = _svc_with_two_tenants()
    run = svc.create_run("investigate incident", tenant_id="tenant-a")
    assert run.tenant_id == "tenant-a"
    assert run.to_view()["tenant_id"] == "tenant-a"


def test_cross_tenant_get_is_denied():
    """The core invariant: tenant B cannot read tenant A's run."""
    svc = _svc_with_two_tenants()
    run = svc.create_run("investigate incident", tenant_id="tenant-a")
    # Same tenant: fine.
    assert svc.get(run.run_id, "tenant-a").run_id == run.run_id
    # Cross tenant: denied.
    with pytest.raises(CrossTenantAccess):
        svc.get(run.run_id, "tenant-b")


def test_cross_tenant_advance_resume_evidence_denied():
    svc = _svc_with_two_tenants()
    run = svc.create_run("investigate incident", tenant_id="tenant-a")
    with pytest.raises(CrossTenantAccess):
        svc.advance(run.run_id, "tenant-b")
    with pytest.raises(CrossTenantAccess):
        svc.evidence(run.run_id, "tenant-b")
    with pytest.raises(CrossTenantAccess):
        svc.resume(run.run_id, "step-1", True, "human:x", "tenant-b")


def test_list_runs_is_tenant_scoped():
    svc = _svc_with_two_tenants()
    svc.create_run("incident one", tenant_id="tenant-a")
    svc.create_run("incident two", tenant_id="tenant-a")
    svc.create_run("incident three", tenant_id="tenant-b")
    assert len(svc.list_runs("tenant-a")) == 2
    assert len(svc.list_runs("tenant-b")) == 1
    # Tenant A's runs never show up in tenant B's listing.
    a_ids = {r["run_id"] for r in svc.list_runs("tenant-a")}
    b_ids = {r["run_id"] for r in svc.list_runs("tenant-b")}
    assert a_ids.isdisjoint(b_ids)


def test_unknown_tenant_run_creation_rejected():
    svc = RunService()
    with pytest.raises(UnknownTenant):
        svc.create_run("incident", tenant_id="ghost-tenant")


def test_per_tenant_budget_ceiling_enforced():
    svc = RunService()
    svc.tenants.create("Capped", tenant_id="capped", max_budget_minor=500)
    run = svc.create_run("incident", budget_minor=100_000, tenant_id="capped")
    # The tenant ceiling clamps the requested budget.
    assert run.intent.budget_minor == 500


def test_separate_ledgers_per_run_across_tenants():
    """Each run has its own ledger; tenant A's evidence is not in tenant B's."""
    svc = _svc_with_two_tenants()
    run_a = svc.create_run("incident a", tenant_id="tenant-a")
    run_b = svc.create_run("incident b", tenant_id="tenant-b")
    svc.advance(run_a.run_id, "tenant-a")
    ev_a = svc.evidence(run_a.run_id, "tenant-a")
    # B's ledger is independent and not advanced.
    ev_b = svc.evidence(run_b.run_id, "tenant-b")
    assert ev_a["run_id"] != ev_b["run_id"]
    assert ev_a["length"] != ev_b["length"]
    assert ev_a["verified"] and ev_b["verified"]


# ── API-level isolation (boundary must not leak existence) ────────────────────


def _client() -> TestClient:
    svc = RunService(earn_autonomy_to=2)
    svc.tenants.create("Tenant A", tenant_id="tenant-a")
    svc.tenants.create("Tenant B", tenant_id="tenant-b")
    return TestClient(create_app(svc))


def test_api_tenant_crud():
    c = _client()
    r = c.post("/tenants", json={"display_name": "New Org"})
    assert r.status_code == 200
    assert r.json()["tenant_id"] == "new-org"
    # Duplicate is a conflict.
    r2 = c.post("/tenants", json={"display_name": "New Org", "tenant_id": "new-org"})
    assert r2.status_code == 409
    # Listing includes default + the three created.
    listed = c.get("/tenants").json()["tenants"]
    ids = {t["tenant_id"] for t in listed}
    assert {"default", "tenant-a", "tenant-b", "new-org"} <= ids


def test_api_cross_tenant_access_returns_404_not_403():
    """A 403 would confirm the run exists in another tenant. We return 404 so the
    boundary does not even leak existence."""
    c = _client()
    created = c.post(
        "/runs", json={"intent": "investigate incident"}, headers={"X-Tenant-Id": "tenant-a"}
    )
    assert created.status_code == 200
    run_id = created.json()["run_id"]

    # Owner sees it.
    assert c.get(f"/runs/{run_id}", headers={"X-Tenant-Id": "tenant-a"}).status_code == 200
    # Other tenant gets an indistinguishable 404.
    other = c.get(f"/runs/{run_id}", headers={"X-Tenant-Id": "tenant-b"})
    truly_missing = c.get("/runs/deadbeef", headers={"X-Tenant-Id": "tenant-b"})
    assert other.status_code == 404
    assert truly_missing.status_code == 404
    assert other.json()["detail"] == truly_missing.json()["detail"]


def test_api_list_runs_scoped_by_header():
    c = _client()
    c.post("/runs", json={"intent": "a one"}, headers={"X-Tenant-Id": "tenant-a"})
    c.post("/runs", json={"intent": "b one"}, headers={"X-Tenant-Id": "tenant-b"})
    a = c.get("/runs", headers={"X-Tenant-Id": "tenant-a"}).json()
    b = c.get("/runs", headers={"X-Tenant-Id": "tenant-b"}).json()
    assert a["tenant_id"] == "tenant-a" and len(a["runs"]) == 1
    assert b["tenant_id"] == "tenant-b" and len(b["runs"]) == 1


def test_api_unknown_tenant_header_404():
    c = _client()
    r = c.get("/runs", headers={"X-Tenant-Id": "ghost"})
    assert r.status_code == 404
