"""Basic ephemeral task memory (Phase 1 foundation).

Hybrid memory in AetherOS splits ephemeral per-task working memory (here, in Python)
from durable organizational memory (introduced in Phase 3, with the durable ledger
anchored in Rust). This module provides the ephemeral half: a bounded, append-only
working buffer scoped to a single task/run, with simple recency-based retrieval.
"""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field


class MemoryRecord(BaseModel):
    """A single ephemeral memory record."""

    role: str = Field(..., description="Who produced it: 'agent', 'tool', 'human', 'system'.")
    content: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    tags: list[str] = Field(default_factory=list)


class EphemeralMemory:
    """Bounded, append-only working memory for a single task/run.

    When the buffer exceeds `max_entries`, the oldest records are dropped. This keeps
    working memory tractable; durable retention is the job of the durable memory tier.
    """

    def __init__(self, max_entries: int = 200) -> None:
        self._max = max_entries
        self._records: list[MemoryRecord] = []

    def add(self, role: str, content: str, tags: list[str] | None = None) -> MemoryRecord:
        record = MemoryRecord(role=role, content=content, tags=tags or [])
        self._records.append(record)
        if len(self._records) > self._max:
            # Drop oldest overflow.
            self._records = self._records[-self._max :]
        return record

    def recent(self, limit: int = 20) -> list[MemoryRecord]:
        """Return the most recent `limit` records, oldest-first."""
        return self._records[-limit:]

    def search(self, term: str, limit: int = 20) -> list[MemoryRecord]:
        """Naive substring/tag search over content (replaced by RAG in Phase 3)."""
        term_l = term.lower()
        hits = [
            r
            for r in self._records
            if term_l in r.content.lower() or any(term_l in t.lower() for t in r.tags)
        ]
        return hits[-limit:]

    def all(self) -> list[MemoryRecord]:
        return list(self._records)

    def __len__(self) -> int:
        return len(self._records)
