"""Multi-tenant workspace isolation (Phase 6).

A Tenant is a hard isolation boundary, not a data-partitioning convenience. The whole
AetherOS thesis is governance and isolation, so the tenant boundary is enforced by
construction: every run, capability lease, evidence ledger, policy lookup, and analytics
query is keyed by an immutable tenant id, and any cross-tenant access is denied.

Design (atom of thoughts): a Tenant = id + display name + creation time + per-tenant
config overrides (policy/autonomy/budget ceilings) + an isolation invariant that nothing
created under tenant A is ever reachable through tenant B.

The TenantRegistry owns tenants. The tenant-scoped RunService (see run_service.py) keys
all run state by (tenant_id, run_id) and refuses lookups that cross the boundary, raising
CrossTenantAccess — which the API maps to 403/404 so a caller can never confirm the
existence of another tenant's run.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone


class TenantError(Exception):
    """Base class for tenancy errors."""


class UnknownTenant(TenantError):
    """The requested tenant does not exist."""


class CrossTenantAccess(TenantError):
    """A caller tried to reach a resource owned by a different tenant.

    Raised whenever a (tenant_id, resource) pair does not match the resource's owning
    tenant. The API layer maps this to 404 (not 403) so the boundary does not even leak
    the existence of another tenant's resources.
    """


_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$")


def _slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")
    return slug or "tenant"


@dataclass(frozen=True)
class Tenant:
    """An immutable isolation boundary for one organization / workspace.

    Frozen so a tenant id can never be mutated after creation — the isolation key is
    stable for the lifetime of every resource created under it.
    """

    tenant_id: str
    display_name: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    # Optional per-tenant ceilings layered on top of the global config.
    max_budget_minor: int | None = None
    max_autonomy_tier: int | None = None

    def to_view(self) -> dict:
        return {
            "tenant_id": self.tenant_id,
            "display_name": self.display_name,
            "created_at": self.created_at,
            "max_budget_minor": self.max_budget_minor,
            "max_autonomy_tier": self.max_autonomy_tier,
        }


class TenantRegistry:
    """Thread-safe registry of tenants. The source of truth for the isolation boundary."""

    def __init__(self) -> None:
        self._tenants: dict[str, Tenant] = {}
        self._lock = threading.Lock()

    def create(
        self,
        display_name: str,
        tenant_id: str | None = None,
        max_budget_minor: int | None = None,
        max_autonomy_tier: int | None = None,
    ) -> Tenant:
        tid = tenant_id or _slugify(display_name)
        if not _SLUG_RE.match(tid):
            raise TenantError(
                f"invalid tenant id {tid!r}: must be 3-64 chars, lowercase alphanumeric/hyphen"
            )
        with self._lock:
            if tid in self._tenants:
                raise TenantError(f"tenant already exists: {tid}")
            tenant = Tenant(
                tenant_id=tid,
                display_name=display_name,
                max_budget_minor=max_budget_minor,
                max_autonomy_tier=max_autonomy_tier,
            )
            self._tenants[tid] = tenant
            return tenant

    def get(self, tenant_id: str) -> Tenant:
        with self._lock:
            t = self._tenants.get(tenant_id)
            if t is None:
                raise UnknownTenant(f"unknown tenant: {tenant_id}")
            return t

    def ensure(self, tenant_id: str, display_name: str | None = None) -> Tenant:
        """Get a tenant, creating it on first use (idempotent onboarding)."""
        try:
            return self.get(tenant_id)
        except UnknownTenant:
            return self.create(display_name or tenant_id, tenant_id=tenant_id)

    def list(self) -> list[Tenant]:
        with self._lock:
            return sorted(self._tenants.values(), key=lambda t: t.created_at)

    def exists(self, tenant_id: str) -> bool:
        with self._lock:
            return tenant_id in self._tenants


# A conventional default tenant so single-tenant callers (and the existing tests/demo)
# keep working unchanged: when no tenant is specified, everything lands here.
DEFAULT_TENANT_ID = "default"
