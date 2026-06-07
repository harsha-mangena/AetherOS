"""Evidence ledger — Python wrapper over the native hash-chained ledger."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field

from . import _aether_native as _native
from .time_utils import now_rfc3339


class EvidenceEntry(BaseModel):
    """One entry in the evidence ledger (validated view of native output)."""

    seq: int
    timestamp: str
    actor: str
    event_type: str
    payload: dict[str, Any] | list[Any] | str | int | float | bool | None
    prev_hash: str
    entry_hash: str


class LedgerIntegrityError(Exception):
    """Raised when the ledger hash chain fails verification."""


class EvidenceLedger:
    """An append-only, hash-chained, replayable audit trail."""

    def __init__(self, native: "_native.EvidenceLedger | None" = None) -> None:
        self._native = native or _native.EvidenceLedger()

    @classmethod
    def from_json(cls, data: str) -> "EvidenceLedger":
        """Load a ledger from JSON, verifying its integrity (raises on tamper)."""
        try:
            return cls(_native.EvidenceLedger.from_json(data))
        except Exception as exc:
            raise LedgerIntegrityError(str(exc)) from exc

    @property
    def length(self) -> int:
        return self._native.len

    @property
    def head_hash(self) -> str:
        return self._native.head_hash

    def append(
        self,
        actor: str,
        event_type: str,
        payload: Any,
        timestamp: str | None = None,
    ) -> tuple[int, str]:
        """Append an event, chaining it to the head. Returns (seq, entry_hash)."""
        ts = timestamp or now_rfc3339()
        payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        return self._native.append(ts, actor, event_type, payload_json)

    def verify(self) -> bool:
        """Verify the full hash chain. Returns True if intact."""
        return bool(self._native.verify())

    def require_intact(self) -> None:
        """Raise `LedgerIntegrityError` if the chain is broken."""
        if not self.verify():
            raise LedgerIntegrityError("evidence ledger hash chain is broken")

    def replay(self) -> list[tuple[int, str, str]]:
        """Return a chronological list of (seq, event_type, actor) after verifying."""
        try:
            return list(self._native.replay_summary())
        except Exception as exc:
            raise LedgerIntegrityError(str(exc)) from exc

    def entries(self) -> list[EvidenceEntry]:
        """Return all entries as validated Pydantic models."""
        raw = json.loads(self._native.to_json())
        return [EvidenceEntry.model_validate(e) for e in raw.get("entries", [])]

    def to_json(self) -> str:
        return self._native.to_json()

    def __len__(self) -> int:
        return self._native.len

    def __repr__(self) -> str:
        return f"EvidenceLedger(entries={self.length}, head={self.head_hash[:12]}…)"
