"""Cross-agent collaboration via a shared, attributable evidence ledger (Phase 7c).

Multi-agent workflows need several agents to contribute to one task while preserving a
single, ordered, tamper-evident audit trail *and* per-agent attribution *and* the Phase 6
tenant boundary. This module provides that as a `SharedLedger`.

Design (atom of thoughts): a collaboration = an immutable (tenant_id, collaboration_id)
key + a roster of participating agents (each admitted with a verified, unrevoked
capability lease) + the one tamper-evident ledger they all write to. Every contribution is
stamped with the writing agent's id and its admitting lease id, so the single hash chain
stays ordered while every entry is independently attributable.

Isolation (revalidated against Phase 6): the collaboration is keyed by tenant. An agent
admitted under tenant A can never write to or read a collaboration owned by tenant B —
attempting it raises `CrossTenantAccess`, identical to every other cross-tenant denial, so
the boundary never leaks the existence of another tenant's collaboration.

Trust contract (reflection): admission is not a trust shortcut. An agent is only admitted
if it presents a lease that (1) verifies its issuer signature, (2) is not revoked, and
(3) names that agent as its subject. A write by a non-member, or by a member whose lease
has since been revoked, is refused and never reaches the chain.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

from aetheros import CapabilityLease, EvidenceLedger

from .tenancy import CrossTenantAccess, DEFAULT_TENANT_ID


class CollaborationError(Exception):
    """Base class for collaboration errors."""


class NotAMember(CollaborationError):
    """The writing agent has not been admitted to the collaboration."""


class MembershipRevoked(CollaborationError):
    """The agent's admitting lease has been revoked since admission."""


@dataclass(frozen=True)
class Membership:
    """An agent's admission to a collaboration, tied to its admitting lease."""

    agent_id: str
    lease_id: str
    admitted_at_seq: int


@dataclass
class SharedLedger:
    """A tenant-scoped, multi-agent, attributable evidence ledger.

    All participating agents append to one tamper-evident chain. Each entry carries the
    writing agent's id and its admitting lease id, so the chain is single and ordered
    while every contribution is attributable.
    """

    tenant_id: str
    collaboration_id: str
    ledger: EvidenceLedger = field(default_factory=EvidenceLedger)
    _members: dict[str, Membership] = field(default_factory=dict)
    _leases: dict[str, CapabilityLease] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    # ── tenant boundary ──────────────────────────────────────────────────────

    def _assert_tenant(self, tenant_id: str) -> None:
        """Refuse any access whose tenant does not own this collaboration."""
        if tenant_id != self.tenant_id:
            raise CrossTenantAccess(
                f"collaboration {self.collaboration_id} is not visible to tenant {tenant_id}"
            )

    # ── membership ───────────────────────────────────────────────────────────

    def admit(self, tenant_id: str, agent_id: str, lease: CapabilityLease) -> Membership:
        """Admit an agent, verifying it holds a valid, unrevoked lease as its subject.

        Admission is itself recorded as evidence, so the roster is reconstructable from
        the chain alone.
        """
        self._assert_tenant(tenant_id)
        if not lease.verify():
            raise CollaborationError(f"agent {agent_id}: lease signature invalid")
        if lease.revoked:
            raise CollaborationError(f"agent {agent_id}: lease is revoked")
        if lease.subject_agent_id != agent_id:
            raise CollaborationError(
                f"lease subject {lease.subject_agent_id} does not match agent {agent_id}"
            )
        with self._lock:
            seq, _hash = self.ledger.append(
                "control-plane",
                "collaboration.member_admitted",
                {
                    "collaboration_id": self.collaboration_id,
                    "tenant_id": self.tenant_id,
                    "agent_id": agent_id,
                    "lease_id": lease.lease_id,
                },
            )
            membership = Membership(agent_id=agent_id, lease_id=lease.lease_id, admitted_at_seq=seq)
            self._members[agent_id] = membership
            self._leases[agent_id] = lease
            return membership

    def is_member(self, agent_id: str) -> bool:
        with self._lock:
            return agent_id in self._members

    def members(self, tenant_id: str) -> list[Membership]:
        self._assert_tenant(tenant_id)
        with self._lock:
            return sorted(self._members.values(), key=lambda m: m.admitted_at_seq)

    # ── attributable contribution ────────────────────────────────────────────

    def contribute(
        self,
        tenant_id: str,
        agent_id: str,
        event_type: str,
        payload: dict,
    ) -> tuple[int, str]:
        """Append an attributed entry to the shared chain.

        Refused unless the agent is a current member whose admitting lease is still valid
        and unrevoked. The entry is stamped with the agent id and its admitting lease id.
        """
        self._assert_tenant(tenant_id)
        with self._lock:
            membership = self._members.get(agent_id)
            if membership is None:
                raise NotAMember(f"agent {agent_id} is not a member of {self.collaboration_id}")
            lease = self._leases[agent_id]
            if lease.revoked or not lease.verify():
                raise MembershipRevoked(
                    f"agent {agent_id}: admitting lease no longer valid"
                )
            stamped = dict(payload)
            stamped["_agent_id"] = agent_id
            stamped["_lease_id"] = membership.lease_id
            stamped["_collaboration_id"] = self.collaboration_id
            return self.ledger.append(agent_id, event_type, stamped)

    # ── read side ────────────────────────────────────────────────────────────

    def contributions_by(self, tenant_id: str, agent_id: str) -> list:
        """All entries attributed to one agent (tenant-checked)."""
        self._assert_tenant(tenant_id)
        return [
            e
            for e in self.ledger.entries()
            if isinstance(e.payload, dict) and e.payload.get("_agent_id") == agent_id
        ]

    def verify(self, tenant_id: str) -> bool:
        """Verify the shared chain is intact (tenant-checked)."""
        self._assert_tenant(tenant_id)
        return self.ledger.verify()


class CollaborationRegistry:
    """Thread-safe registry of shared collaborations, keyed by (tenant_id, collaboration_id)."""

    def __init__(self) -> None:
        self._collabs: dict[tuple[str, str], SharedLedger] = {}
        self._lock = threading.Lock()

    def open(self, collaboration_id: str, tenant_id: str = DEFAULT_TENANT_ID) -> SharedLedger:
        """Open (or create) a collaboration under a tenant."""
        key = (tenant_id, collaboration_id)
        with self._lock:
            existing = self._collabs.get(key)
            if existing is not None:
                return existing
            collab = SharedLedger(tenant_id=tenant_id, collaboration_id=collaboration_id)
            self._collabs[key] = collab
            return collab

    def get(self, collaboration_id: str, tenant_id: str = DEFAULT_TENANT_ID) -> SharedLedger:
        """Fetch a collaboration, enforcing the tenant boundary by construction.

        A lookup with the wrong tenant id raises CrossTenantAccess — it cannot return
        another tenant's collaboration even if the collaboration_id is known.
        """
        with self._lock:
            collab = self._collabs.get((tenant_id, collaboration_id))
        if collab is None:
            # Do not reveal whether it exists under another tenant.
            raise CrossTenantAccess(
                f"collaboration {collaboration_id} not found for tenant {tenant_id}"
            )
        return collab
