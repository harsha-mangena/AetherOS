"""Capability lease — Python wrapper over the native signed lease."""

from __future__ import annotations

import json
from typing import Sequence

from pydantic import BaseModel, Field

from . import _aether_native as _native
from .identity import AgentIdentity
from .time_utils import now_rfc3339, rfc3339_in


class Budget(BaseModel):
    """A monetary budget slice in integer minor currency units (e.g. cents)."""

    currency: str = Field(..., description="ISO 4217 currency code, e.g. USD.")
    limit_minor: int = Field(..., ge=0, description="Hard limit in minor units.")
    spent_minor: int = Field(0, ge=0, description="Amount already spent, minor units.")

    @property
    def remaining_minor(self) -> int:
        return max(0, self.limit_minor - self.spent_minor)


class LeaseDenied(Exception):
    """Raised when an authorization check on a lease fails."""


class CapabilityLease:
    """A signed, scoped, time-bounded grant of authority to an agent."""

    def __init__(self, native: "_native.CapabilityLease") -> None:
        self._native = native

    @classmethod
    def issue(
        cls,
        issuer: AgentIdentity,
        subject_agent_id: str,
        scopes: Sequence[str],
        currency: str,
        limit_minor: int,
        issued_at: str | None = None,
        expires_at: str | None = None,
        ttl_seconds: float = 3600.0,
    ) -> "CapabilityLease":
        """Issue and sign a new lease.

        If `expires_at` is omitted, the lease expires `ttl_seconds` from issuance.
        """
        issued = issued_at or now_rfc3339()
        expires = expires_at or rfc3339_in(ttl_seconds)
        native = _native.CapabilityLease.issue(
            issuer._native,
            subject_agent_id,
            list(scopes),
            currency,
            int(limit_minor),
            issued,
            expires,
        )
        return cls(native)

    @classmethod
    def from_json(cls, data: str) -> "CapabilityLease":
        return cls(_native.CapabilityLease.from_json(data))

    @property
    def lease_id(self) -> str:
        return self._native.lease_id

    @property
    def subject_agent_id(self) -> str:
        return self._native.subject_agent_id

    @property
    def scopes(self) -> list[str]:
        return list(self._native.scopes)

    @property
    def remaining_minor(self) -> int:
        return self._native.remaining_minor

    @property
    def spent_minor(self) -> int:
        return self._native.spent_minor

    @property
    def revoked(self) -> bool:
        return self._native.revoked

    def verify(self) -> bool:
        """Verify the issuer's signature over the lease body."""
        return bool(self._native.verify())

    def revoke(self) -> None:
        self._native.revoke()

    def grants_scope(self, scope: str) -> bool:
        return bool(self._native.grants_scope(scope))

    def authorize(self, scope: str, cost_minor: int, now: str | None = None) -> None:
        """Full authorization check. Raises `LeaseDenied` on failure."""
        try:
            self._native.authorize(scope, int(cost_minor), now or now_rfc3339())
        except Exception as exc:  # native raises ValueError/RuntimeError
            raise LeaseDenied(str(exc)) from exc

    def record_spend(self, amount_minor: int) -> None:
        """Record a spend against the budget. Must follow a successful authorize."""
        try:
            self._native.record_spend(int(amount_minor))
        except Exception as exc:
            raise LeaseDenied(str(exc)) from exc

    def to_json(self) -> str:
        return self._native.to_json()

    def to_dict(self) -> dict:
        return json.loads(self._native.to_json())

    def __repr__(self) -> str:
        return (
            f"CapabilityLease(lease_id={self.lease_id!r}, "
            f"subject={self.subject_agent_id!r}, scopes={self.scopes}, "
            f"remaining={self.remaining_minor})"
        )
