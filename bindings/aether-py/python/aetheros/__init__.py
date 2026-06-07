"""AetherOS core — Python API over the Rust security primitives.

This package wraps the native PyO3 extension (`_aether_native`) with ergonomic,
typed Python classes and Pydantic models. Application and orchestration code should
import from here rather than touching the native module directly.

Public surface:
    AgentIdentity      — cryptographic Ed25519 identity for an agent.
    CapabilityLease    — signed, scoped, time-bounded grant of authority.
    Budget             — monetary budget slice (minor currency units).
    EvidenceLedger     — append-only, hash-chained audit trail.
    AgentDescriptor    — Pydantic model: shareable public view of an identity.
    EvidenceEntry      — Pydantic model: one ledger entry.
    verify_signature   — standalone Ed25519 verification helper.
    now_rfc3339        — UTC timestamp helper used for issuance/expiry/events.
"""

from __future__ import annotations

from .identity import AgentDescriptor, AgentIdentity, verify_signature
from .lease import Budget, CapabilityLease
from .ledger import EvidenceEntry, EvidenceLedger
from .time_utils import now_rfc3339, rfc3339_in

try:  # pragma: no cover - version surfaced from the native module
    from ._aether_native import __core_version__ as core_version
except Exception:  # pragma: no cover
    core_version = "unknown"

__all__ = [
    "AgentIdentity",
    "AgentDescriptor",
    "CapabilityLease",
    "Budget",
    "EvidenceLedger",
    "EvidenceEntry",
    "verify_signature",
    "now_rfc3339",
    "rfc3339_in",
    "core_version",
]

__version__ = "0.1.0"
