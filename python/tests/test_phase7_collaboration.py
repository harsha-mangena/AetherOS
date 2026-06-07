"""Phase 7c tests: cross-agent collaboration via a shared, attributable ledger.

Proves several agents can write to one tamper-evident chain with per-agent attribution,
that admission requires a valid unrevoked lease, that a revoked lease loses write access,
and that the Phase 6 tenant boundary holds — a collaboration is never reachable across
tenants.
"""

from __future__ import annotations

import pytest

from aetheros import AgentIdentity, CapabilityLease
from aetheros_orchestrator.collaboration import (
    CollaborationRegistry,
    MembershipRevoked,
    NotAMember,
)
from aetheros_orchestrator.tenancy import CrossTenantAccess


def _issuer() -> AgentIdentity:
    return AgentIdentity.generate("control-plane")


def _lease_for(issuer: AgentIdentity, agent_id: str) -> CapabilityLease:
    return CapabilityLease.issue(
        issuer,
        agent_id,
        scopes=["task:contribute"],
        currency="USD",
        limit_minor=100_000,
        ttl_seconds=3600.0,
    )


def test_two_agents_contribute_to_one_attributable_chain() -> None:
    issuer = _issuer()
    reg = CollaborationRegistry()
    collab = reg.open("incident-42", tenant_id="acme")

    a = AgentIdentity.generate("analyst")
    b = AgentIdentity.generate("remediator")
    collab.admit("acme", a.agent_id, _lease_for(issuer, a.agent_id))
    collab.admit("acme", b.agent_id, _lease_for(issuer, b.agent_id))

    collab.contribute("acme", a.agent_id, "finding.logged", {"detail": "root cause found"})
    collab.contribute("acme", b.agent_id, "remediation.applied", {"detail": "rolled back deploy"})

    # One ordered, intact chain.
    assert collab.verify("acme") is True
    # Attribution holds per agent.
    a_entries = collab.contributions_by("acme", a.agent_id)
    b_entries = collab.contributions_by("acme", b.agent_id)
    assert len(a_entries) == 1 and a_entries[0].event_type == "finding.logged"
    assert len(b_entries) == 1 and b_entries[0].event_type == "remediation.applied"
    assert a_entries[0].payload["_agent_id"] == a.agent_id


def test_non_member_cannot_contribute() -> None:
    issuer = _issuer()
    reg = CollaborationRegistry()
    collab = reg.open("c1", tenant_id="acme")
    stranger = AgentIdentity.generate("stranger")
    with pytest.raises(NotAMember):
        collab.contribute("acme", stranger.agent_id, "x", {"k": "v"})


def test_revoked_lease_loses_write_access() -> None:
    issuer = _issuer()
    reg = CollaborationRegistry()
    collab = reg.open("c2", tenant_id="acme")
    a = AgentIdentity.generate("analyst")
    lease = _lease_for(issuer, a.agent_id)
    collab.admit("acme", a.agent_id, lease)
    # First write works.
    collab.contribute("acme", a.agent_id, "ok", {"n": 1})
    # Revoke the admitting lease; subsequent writes are refused.
    lease.revoke()
    with pytest.raises(MembershipRevoked):
        collab.contribute("acme", a.agent_id, "blocked", {"n": 2})


def test_admission_requires_matching_subject() -> None:
    issuer = _issuer()
    reg = CollaborationRegistry()
    collab = reg.open("c3", tenant_id="acme")
    a = AgentIdentity.generate("analyst")
    # Lease issued for a *different* subject.
    wrong = _lease_for(issuer, "someone-else")
    with pytest.raises(Exception):
        collab.admit("acme", a.agent_id, wrong)


def test_tenant_boundary_blocks_cross_tenant_access() -> None:
    issuer = _issuer()
    reg = CollaborationRegistry()
    collab = reg.open("shared-id", tenant_id="acme")
    a = AgentIdentity.generate("analyst")
    collab.admit("acme", a.agent_id, _lease_for(issuer, a.agent_id))

    # Same collaboration_id under a different tenant must not resolve to acme's collab.
    with pytest.raises(CrossTenantAccess):
        reg.get("shared-id", tenant_id="globex")

    # Direct cross-tenant operations on the acme collab are refused.
    with pytest.raises(CrossTenantAccess):
        collab.contribute("globex", a.agent_id, "x", {"k": "v"})
    with pytest.raises(CrossTenantAccess):
        collab.members("globex")
    with pytest.raises(CrossTenantAccess):
        collab.verify("globex")


def test_registry_open_is_idempotent_per_tenant() -> None:
    reg = CollaborationRegistry()
    c1 = reg.open("dup", tenant_id="acme")
    c2 = reg.open("dup", tenant_id="acme")
    assert c1 is c2
    # But a different tenant gets a distinct, isolated collaboration object.
    c3 = reg.open("dup", tenant_id="globex")
    assert c3 is not c1
