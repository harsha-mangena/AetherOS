"""Durable, policy-mediated organizational memory (Phase 3).

The hybrid-memory model splits ephemeral per-run working memory (see EphemeralMemory)
from durable organizational memory that persists across runs and agents. Durable
memory is *governed*: every record carries a sensitivity scope, and every read or
write is mediated by the policy engine plus the acting lease's scopes, with an
evidence event emitted for each access.

Integrity: each record is content-addressed with the same canonical SHA-256 used by
the core ledger (via the native EvidenceLedger as a hashing oracle is avoided; we hash
a canonical JSON form directly with hashlib over sorted-key JSON to match the core's
canonical form). Tampering with a stored record is detectable by recomputing its id.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

from .policy import PolicyDecision, PolicyEngine


def _canonical_json(value: object) -> str:
    """Canonical JSON matching the core: sorted keys, compact separators."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _content_id(namespace: str, key: str, content: str, sensitivity: str) -> str:
    payload = _canonical_json(
        {
            "namespace": namespace,
            "key": key,
            "content": content,
            "sensitivity": sensitivity,
        }
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class DurableRecord:
    """A durable organizational memory record."""

    namespace: str
    key: str
    content: str
    sensitivity: str  # the scope required to read this, e.g. "memory:read:org"
    record_id: str = ""
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def __post_init__(self) -> None:
        expected = _content_id(self.namespace, self.key, self.content, self.sensitivity)
        if not self.record_id:
            self.record_id = expected

    def verify_integrity(self) -> bool:
        return self.record_id == _content_id(
            self.namespace, self.key, self.content, self.sensitivity
        )


class MemoryAccessDenied(RuntimeError):
    """Raised when policy or lease scope denies a memory access."""


# A scope-checker decides whether the acting lease grants a given scope.
ScopeChecker = Callable[[str], bool]
# An evidence emitter records a memory access event.
EvidenceEmitter = Callable[[str, dict], None]


class DurableMemory:
    """Policy-mediated durable organizational memory.

    Reads and writes are authorized two ways, both of which must pass:
      1. The acting lease must grant the record's sensitivity scope (least privilege).
      2. The policy engine must allow the corresponding memory tool action.
    Every access emits an evidence event.
    """

    def __init__(
        self,
        policy: PolicyEngine,
        scope_checker: ScopeChecker,
        autonomy_tier: int = 0,
        evidence_emitter: Optional[EvidenceEmitter] = None,
    ) -> None:
        self._policy = policy
        self._grants = scope_checker
        self._tier = autonomy_tier
        self._emit = evidence_emitter or (lambda _t, _p: None)
        self._store: dict[tuple[str, str], DurableRecord] = {}

    def _authorize(self, action: str, scope: str, tool: str) -> PolicyDecision:
        if not self._grants(scope):
            self._emit(
                "memory.access.denied",
                {"action": action, "scope": scope, "reason": "lease does not grant scope"},
            )
            raise MemoryAccessDenied(f"lease does not grant '{scope}'")
        decision = self._policy.evaluate(
            scope=scope, tool=tool, autonomy_tier=self._tier, cost_minor=0, high_impact=False
        )
        if not decision.allowed:
            self._emit(
                "memory.access.denied",
                {"action": action, "scope": scope, "reason": decision.reason},
            )
            raise MemoryAccessDenied(decision.reason)
        return decision

    def write(
        self, namespace: str, key: str, content: str, sensitivity: str = "memory:read:org"
    ) -> DurableRecord:
        write_scope = sensitivity.replace(":read:", ":write:", 1)
        self._authorize("write", write_scope, "memory_write")
        record = DurableRecord(
            namespace=namespace, key=key, content=content, sensitivity=sensitivity
        )
        self._store[(namespace, key)] = record
        self._emit(
            "memory.write",
            {"namespace": namespace, "key": key, "record_id": record.record_id},
        )
        return record

    def read(self, namespace: str, key: str) -> DurableRecord:
        record = self._store.get((namespace, key))
        if record is None:
            self._emit("memory.read.miss", {"namespace": namespace, "key": key})
            raise KeyError(f"no durable record for {namespace}/{key}")
        self._authorize("read", record.sensitivity, "memory_read")
        if not record.verify_integrity():
            self._emit(
                "memory.integrity.failure",
                {"namespace": namespace, "key": key, "record_id": record.record_id},
            )
            raise RuntimeError(f"durable record {record.record_id} failed integrity check")
        self._emit(
            "memory.read",
            {"namespace": namespace, "key": key, "record_id": record.record_id},
        )
        return record

    def __len__(self) -> int:
        return len(self._store)
