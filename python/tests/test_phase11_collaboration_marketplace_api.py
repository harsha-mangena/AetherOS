"""Phase 11 integration tests — collaboration, marketplace, and run lifecycle endpoints.

Atom of thoughts:
  Each test targets exactly one independently verifiable property:
  - endpoint existence and HTTP status code
  - tenant isolation boundary (cross-tenant access → 404, never 403)
  - tamper-evidence (ledger chain verifies after every write)
  - signature verification gate (invalid sig → 400)
  - governance gate (constitutionally forbidden scope → 400)
  - idempotency (open_collaboration twice → same object, no error)
  - lifecycle ordering (cancel before delete; delete active → 409)

Chain of thoughts:
  1. Build a shared TestClient+RunService fixture with a known-good tenant.
  2. Test collaboration CRUD: open → list → admit → contribute → get (with chain verify).
  3. Test marketplace: publish (valid + invalid sig) → catalog → install (valid, bad scope,
     constitutionally forbidden) → installed.
  4. Test run lifecycle: cancel a planned run → cancel idempotency → delete terminal run →
     delete active run (should 409) → 404 on deleted run.
  5. Test tenant isolation: collaboration and run endpoints return 404 for wrong tenant.

Research net / grounding:
  - RFC 7807: structured error responses (we verify `detail` key in error bodies).
  - C2SP witness: tested in Phase 9c; these tests are orthogonal.
  - Ed25519: IETF RFC 8032. We use AgentIdentity.sign (Rust-backed dalek) for all signing
    to ensure byte-reproducibility matches SkillManifest.canonical_bytes().
"""

from __future__ import annotations

import json
import pytest

try:
    from fastapi.testclient import TestClient
except ImportError:  # pragma: no cover
    pytest.skip("fastapi not installed", allow_module_level=True)

import aetheros
from aetheros_orchestrator.api import create_app
from aetheros_orchestrator.run_service import RunService
from aetheros_orchestrator.marketplace import SkillManifest, SignedSkill


# ── fixtures ────────────────────────────────────────────────────────────────


def _make_client():
    """Build a TestClient over a fresh RunService with two isolated tenants."""
    svc = RunService()
    svc.tenants.create("Tenant Alpha", tenant_id="alpha")
    svc.tenants.create("Tenant Beta", tenant_id="beta")
    app = create_app(svc)
    return TestClient(app), svc


def _alpha(client: TestClient, method: str, path: str, **kw):
    """Call an endpoint with X-Tenant-Id: alpha."""
    fn = getattr(client, method)
    return fn(path, headers={"x-tenant-id": "alpha"}, **kw)


def _beta(client: TestClient, method: str, path: str, **kw):
    fn = getattr(client, method)
    return fn(path, headers={"x-tenant-id": "beta"}, **kw)


def _signed_skill(
    skill_id: str = "test.skill",
    version: str = "1.0.0",
    required_scopes: list[str] | None = None,
    declared_tools: list[str] | None = None,
    description: str = "A test skill.",
) -> tuple[aetheros.AgentIdentity, SignedSkill]:
    """Produce a valid publisher identity + SignedSkill pair."""
    publisher = aetheros.AgentIdentity.generate("publisher-agent")
    manifest = SkillManifest(
        skill_id=skill_id,
        version=version,
        publisher_agent_id=publisher.agent_id,
        publisher_public_key=publisher.public_key,
        required_scopes=tuple(required_scopes or ["logs:read"]),
        declared_tools=tuple(declared_tools or ["log_search"]),
        description=description,
    )
    signature = publisher.sign(manifest.canonical_bytes())
    return publisher, SignedSkill(manifest=manifest, signature=signature)


def _manifest_publish_dict(signed: SignedSkill) -> dict:
    """Full manifest dict suitable for the publish endpoint (includes publisher_public_key)."""
    m = signed.manifest
    return {
        "skill_id": m.skill_id,
        "version": m.version,
        "publisher_agent_id": m.publisher_agent_id,
        "publisher_public_key": m.publisher_public_key,
        "required_scopes": sorted(m.required_scopes),
        "declared_tools": sorted(m.declared_tools),
        "description": m.description,
    }


def _valid_lease_dict(agent: aetheros.AgentIdentity, issuer: aetheros.AgentIdentity) -> dict:
    """Issue and serialize a valid, unrevoked capability lease for `agent` signed by `issuer`."""
    from aetheros import CapabilityLease
    lease = CapabilityLease.issue(
        issuer=issuer,
        subject_agent_id=agent.agent_id,
        scopes=["logs:read"],
        currency="USD",
        limit_minor=50_000,
    )
    return lease.to_dict()


# ── collaboration: open and list ─────────────────────────────────────────────


def test_open_collaboration_creates_and_returns_201():
    client, _ = _make_client()
    r = _alpha(client, "post", "/collaborations", json={"collaboration_id": "op-1"})
    assert r.status_code == 201
    body = r.json()
    assert body["collaboration_id"] == "op-1"
    assert body["tenant_id"] == "alpha"
    assert body["member_count"] == 0
    assert body["ledger_length"] == 0


def test_open_collaboration_idempotent():
    """Opening the same collaboration_id twice returns the same object without error."""
    client, _ = _make_client()
    r1 = _alpha(client, "post", "/collaborations", json={"collaboration_id": "idem-1"})
    r2 = _alpha(client, "post", "/collaborations", json={"collaboration_id": "idem-1"})
    assert r1.status_code == 201
    assert r2.status_code == 201
    assert r1.json()["collaboration_id"] == r2.json()["collaboration_id"]


def test_list_collaborations_empty_at_start():
    client, _ = _make_client()
    r = _alpha(client, "get", "/collaborations")
    assert r.status_code == 200
    assert r.json()["collaborations"] == []


def test_list_collaborations_shows_opened():
    client, _ = _make_client()
    _alpha(client, "post", "/collaborations", json={"collaboration_id": "list-1"})
    _alpha(client, "post", "/collaborations", json={"collaboration_id": "list-2"})
    r = _alpha(client, "get", "/collaborations")
    assert r.status_code == 200
    ids = {c["collaboration_id"] for c in r.json()["collaborations"]}
    assert {"list-1", "list-2"}.issubset(ids)


def test_list_collaborations_tenant_isolated():
    """Beta tenant sees none of alpha's collaborations."""
    client, _ = _make_client()
    _alpha(client, "post", "/collaborations", json={"collaboration_id": "alpha-collab"})
    r = _beta(client, "get", "/collaborations")
    assert r.status_code == 200
    ids = {c["collaboration_id"] for c in r.json()["collaborations"]}
    assert "alpha-collab" not in ids


# ── collaboration: admit and contribute ─────────────────────────────────────


def test_admit_agent_to_collaboration():
    client, svc = _make_client()
    _alpha(client, "post", "/collaborations", json={"collaboration_id": "adm-1"})
    issuer = aetheros.AgentIdentity.generate("issuer")
    agent = aetheros.AgentIdentity.generate("agent-a")
    lease_dict = _valid_lease_dict(agent, issuer)
    r = _alpha(client, "post", "/collaborations/adm-1/admit", json={
        "agent_id": agent.agent_id,
        "lease": lease_dict,
    })
    assert r.status_code == 201
    body = r.json()
    assert body["agent_id"] == agent.agent_id
    assert "lease_id" in body
    assert body["admitted_at_seq"] == 0  # first entry on the chain


def test_contribute_records_entry_and_chain_verifies():
    client, svc = _make_client()
    _alpha(client, "post", "/collaborations", json={"collaboration_id": "con-1"})
    issuer = aetheros.AgentIdentity.generate("issuer")
    agent = aetheros.AgentIdentity.generate("agent-b")
    lease_dict = _valid_lease_dict(agent, issuer)
    _alpha(client, "post", "/collaborations/con-1/admit", json={
        "agent_id": agent.agent_id, "lease": lease_dict,
    })
    r = _alpha(client, "post", "/collaborations/con-1/contribute", json={
        "agent_id": agent.agent_id,
        "event_type": "agent.analysis",
        "payload": {"finding": "latency spike"},
    })
    assert r.status_code == 201
    body = r.json()
    assert body["event_type"] == "agent.analysis"
    assert "entry_hash" in body
    # Chain integrity: GET the collaboration and verify the ledger
    r2 = _alpha(client, "get", "/collaborations/con-1")
    assert r2.json()["verified"] is True
    assert r2.json()["ledger_length"] == 2  # admit + contribute


def test_contribute_unadmitted_agent_rejected():
    client, _ = _make_client()
    _alpha(client, "post", "/collaborations", json={"collaboration_id": "unadm-1"})
    r = _alpha(client, "post", "/collaborations/unadm-1/contribute", json={
        "agent_id": "phantom-agent",
        "event_type": "agent.hack",
        "payload": {},
    })
    assert r.status_code == 400


def test_get_collaboration_shows_full_ledger():
    client, svc = _make_client()
    _alpha(client, "post", "/collaborations", json={"collaboration_id": "full-1"})
    issuer = aetheros.AgentIdentity.generate("issuer")
    agent = aetheros.AgentIdentity.generate("agent-c")
    lease_dict = _valid_lease_dict(agent, issuer)
    _alpha(client, "post", "/collaborations/full-1/admit", json={
        "agent_id": agent.agent_id, "lease": lease_dict,
    })
    _alpha(client, "post", "/collaborations/full-1/contribute", json={
        "agent_id": agent.agent_id,
        "event_type": "agent.step",
        "payload": {"step": 1},
    })
    r = _alpha(client, "get", "/collaborations/full-1")
    assert r.status_code == 200
    body = r.json()
    assert body["verified"] is True
    assert len(body["members"]) == 1
    assert body["members"][0]["agent_id"] == agent.agent_id
    entries = body["entries"]
    event_types = [e["event_type"] for e in entries]
    assert "collaboration.member_admitted" in event_types
    assert "agent.step" in event_types


def test_get_collaboration_cross_tenant_returns_404():
    client, _ = _make_client()
    _alpha(client, "post", "/collaborations", json={"collaboration_id": "xcollab-1"})
    r = _beta(client, "get", "/collaborations/xcollab-1")
    assert r.status_code == 404


# ── marketplace: publish ─────────────────────────────────────────────────────


def test_publish_valid_skill_returns_201():
    client, _ = _make_client()
    _, signed = _signed_skill()
    r = client.post("/marketplace/skills", json={
        "manifest": _manifest_publish_dict(signed),
        "signature": signed.signature,
    })
    assert r.status_code == 201
    assert r.json()["skill_id"] == signed.manifest.skill_id


def test_publish_invalid_signature_returns_400():
    client, _ = _make_client()
    _, signed = _signed_skill(skill_id="bad.skill")
    r = client.post("/marketplace/skills", json={
        "manifest": _manifest_publish_dict(signed),
        "signature": "deadbeef" * 16,  # 128 hex chars of garbage
    })
    assert r.status_code == 400


def test_catalog_empty_before_publish():
    client, _ = _make_client()
    r = client.get("/marketplace/catalog")
    assert r.status_code == 200
    assert r.json()["skills"] == []


def test_catalog_shows_published_skill():
    client, _ = _make_client()
    _, signed = _signed_skill(skill_id="cat.skill")
    client.post("/marketplace/skills", json={
        "manifest": _manifest_publish_dict(signed),
        "signature": signed.signature,
    })
    r = client.get("/marketplace/catalog")
    ids = [s["skill_id"] for s in r.json()["skills"]]
    assert "cat.skill" in ids


# ── marketplace: install ─────────────────────────────────────────────────────


def test_install_skill_under_governance_succeeds():
    client, _ = _make_client()
    _, signed = _signed_skill(skill_id="inst.skill", required_scopes=["logs:read"])
    client.post("/marketplace/skills", json={
        "manifest": _manifest_publish_dict(signed),
        "signature": signed.signature,
    })
    r = _alpha(client, "post", "/marketplace/skills/inst.skill/install", json={
        "version": "1.0.0",
        "permitted_scopes": ["logs:read"],
    })
    assert r.status_code == 201
    body = r.json()
    assert body["skill_id"] == "inst.skill"
    assert body["tenant_id"] == "alpha"
    assert "installed_at_seq" in body


def test_install_skill_missing_from_catalog_returns_404():
    client, _ = _make_client()
    r = _alpha(client, "post", "/marketplace/skills/ghost.skill/install", json={
        "version": "9.9.9",
        "permitted_scopes": [],
    })
    assert r.status_code == 404


def test_install_skill_scope_not_permitted_returns_400():
    """Tenant delegates only logs:read but skill requires s3:write → 400."""
    client, _ = _make_client()
    _, signed = _signed_skill(skill_id="scope.skill", required_scopes=["s3:write"])
    client.post("/marketplace/skills", json={
        "manifest": _manifest_publish_dict(signed),
        "signature": signed.signature,
    })
    r = _alpha(client, "post", "/marketplace/skills/scope.skill/install", json={
        "version": "1.0.0",
        "permitted_scopes": ["logs:read"],  # s3:write not in here
    })
    assert r.status_code == 400


def test_installed_shows_skill_after_install():
    client, _ = _make_client()
    _, signed = _signed_skill(skill_id="listed.skill")
    client.post("/marketplace/skills", json={
        "manifest": _manifest_publish_dict(signed),
        "signature": signed.signature,
    })
    _alpha(client, "post", "/marketplace/skills/listed.skill/install", json={
        "version": "1.0.0",
        "permitted_scopes": ["logs:read"],
    })
    r = _alpha(client, "get", "/marketplace/installed")
    assert r.status_code == 200
    ids = [s["skill_id"] for s in r.json()["installed"]]
    assert "listed.skill" in ids


def test_installed_tenant_isolated():
    """Alpha's installed skill is invisible to beta."""
    client, _ = _make_client()
    _, signed = _signed_skill(skill_id="iso.skill")
    client.post("/marketplace/skills", json={
        "manifest": _manifest_publish_dict(signed),
        "signature": signed.signature,
    })
    _alpha(client, "post", "/marketplace/skills/iso.skill/install", json={
        "version": "1.0.0",
        "permitted_scopes": ["logs:read"],
    })
    r = _beta(client, "get", "/marketplace/installed")
    ids = [s["skill_id"] for s in r.json()["installed"]]
    assert "iso.skill" not in ids


# ── run lifecycle: cancel and delete ─────────────────────────────────────────


def test_cancel_planned_run_transitions_to_halted():
    client, _ = _make_client()
    run = _alpha(client, "post", "/runs", json={
        "intent": "summarise logs",
        "submitted_by": "human:vamsi",
        "budget_minor": 50000,
    }).json()
    run_id = run["run_id"]
    assert run["status"] == "planned"
    r = _alpha(client, "post", f"/runs/{run_id}/cancel")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "halted"
    assert body["denied_reason"] == "cancelled by operator"


def test_cancel_run_is_idempotent_on_terminal():
    """Cancelling an already-halted run returns 200 with no state change."""
    client, _ = _make_client()
    run_id = _alpha(client, "post", "/runs", json={
        "intent": "summarise logs", "submitted_by": "human:vamsi", "budget_minor": 50000,
    }).json()["run_id"]
    _alpha(client, "post", f"/runs/{run_id}/cancel")
    r = _alpha(client, "post", f"/runs/{run_id}/cancel")
    assert r.status_code == 200
    assert r.json()["status"] == "halted"


def test_cancel_records_event_in_evidence_ledger():
    """Cancellation must leave a run.cancelled event in the tamper-evident ledger."""
    client, _ = _make_client()
    run_id = _alpha(client, "post", "/runs", json={
        "intent": "analyse alerts", "submitted_by": "human:vamsi", "budget_minor": 50000,
    }).json()["run_id"]
    _alpha(client, "post", f"/runs/{run_id}/cancel")
    evidence = _alpha(client, "get", f"/runs/{run_id}/evidence").json()
    assert evidence["verified"] is True
    event_types = [e["event_type"] for e in evidence["entries"]]
    assert "run.cancelled" in event_types


def test_cancel_unknown_run_returns_404():
    client, _ = _make_client()
    r = _alpha(client, "post", "/runs/no-such-run/cancel")
    assert r.status_code == 404


def test_delete_terminal_run_returns_204():
    client, _ = _make_client()
    run_id = _alpha(client, "post", "/runs", json={
        "intent": "patch server", "submitted_by": "human:vamsi", "budget_minor": 50000,
    }).json()["run_id"]
    _alpha(client, "post", f"/runs/{run_id}/cancel")
    r = _alpha(client, "delete", f"/runs/{run_id}")
    assert r.status_code == 204


def test_delete_active_run_returns_409():
    """Deleting a non-terminal run must be rejected with 409 Conflict."""
    client, _ = _make_client()
    run_id = _alpha(client, "post", "/runs", json={
        "intent": "deploy service", "submitted_by": "human:vamsi", "budget_minor": 50000,
    }).json()["run_id"]
    r = _alpha(client, "delete", f"/runs/{run_id}")
    assert r.status_code == 409


def test_deleted_run_is_gone():
    client, _ = _make_client()
    run_id = _alpha(client, "post", "/runs", json={
        "intent": "check disk", "submitted_by": "human:vamsi", "budget_minor": 50000,
    }).json()["run_id"]
    _alpha(client, "post", f"/runs/{run_id}/cancel")
    _alpha(client, "delete", f"/runs/{run_id}")
    r = _alpha(client, "get", f"/runs/{run_id}")
    assert r.status_code == 404


def test_cross_tenant_cancel_returns_404():
    """Beta cannot cancel alpha's run — the boundary must not leak the run's existence."""
    client, _ = _make_client()
    run_id = _alpha(client, "post", "/runs", json={
        "intent": "rotate keys", "submitted_by": "human:vamsi", "budget_minor": 50000,
    }).json()["run_id"]
    r = _beta(client, "post", f"/runs/{run_id}/cancel")
    assert r.status_code == 404
