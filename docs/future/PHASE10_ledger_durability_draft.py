"""Ledger persistence backends (Phase 9b).

The Rust EvidenceLedger is the canonical, verified in-memory ledger. For durability,
we optionally persist its state to SQLite after each append. The governance and
transparency layers depend on the in-memory Rust ledger and are unaffected by storage.

On service restart, the SQLite ledger is re-loaded into a fresh EvidenceLedger and
integrity-checked.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from aetheros import EvidenceEntry, EvidenceLedger


class LedgerStore(ABC):
    """Abstract interface for durable ledger storage."""

    @abstractmethod
    def persist_entries(self, entries: list[EvidenceEntry]) -> None:
        """Persist a full ledger snapshot."""

    @abstractmethod
    def load_entries(self) -> list[EvidenceEntry]:
        """Load entries from storage."""

    @abstractmethod
    def verify_persisted_chain(self) -> tuple[bool, Optional[str]]:
        """Verify the persisted ledger's hash chain."""


class NoStore(LedgerStore):
    """No-op store (in-memory only, current MVP behavior)."""

    def persist_entries(self, entries: list[EvidenceEntry]) -> None:
        pass

    def load_entries(self) -> list[EvidenceEntry]:
        return []

    def verify_persisted_chain(self) -> tuple[bool, Optional[str]]:
        return True, None


class SQLiteStore(LedgerStore):
    """Persistent SQLite store for ledger entries.

    Stores evidence entries keyed by (tenant_id, run_id). On load, verifies the
    hash chain to detect tampering.
    """

    def __init__(
        self, tenant_id: str, run_id: str, db_dir: Path | str = "./ledgers"
    ) -> None:
        self.tenant_id = tenant_id
        self.run_id = run_id
        self.db_dir = Path(db_dir)
        self.db_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.db_dir / f"{tenant_id}.db"
        self._lock = threading.RLock()
        self._init_db()

    def _init_db(self) -> None:
        """Initialize the database schema if it doesn't exist."""
        with self._lock:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS ledger_entries (
                        tenant_id TEXT NOT NULL,
                        run_id TEXT NOT NULL,
                        seq INTEGER NOT NULL,
                        timestamp TEXT NOT NULL,
                        actor TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        payload TEXT NOT NULL,
                        prev_hash TEXT NOT NULL,
                        entry_hash TEXT NOT NULL UNIQUE,
                        PRIMARY KEY (tenant_id, run_id, seq)
                    )
                    """
                )
                conn.commit()

    def persist_entries(self, entries: list[EvidenceEntry]) -> None:
        """Write all entries. Called after each append to keep storage in sync."""
        with self._lock:
            with sqlite3.connect(str(self.db_path)) as conn:
                # Delete any existing entries for this run (idempotent).
                conn.execute(
                    "DELETE FROM ledger_entries WHERE tenant_id = ? AND run_id = ?",
                    (self.tenant_id, self.run_id),
                )
                # Insert the current ledger state.
                for entry in entries:
                    try:
                        conn.execute(
                            """
                            INSERT INTO ledger_entries
                            (tenant_id, run_id, seq, timestamp, actor, event_type, payload, prev_hash, entry_hash)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                self.tenant_id,
                                self.run_id,
                                entry.seq,
                                entry.timestamp,
                                entry.actor,
                                entry.event_type,
                                json.dumps(entry.payload),
                                entry.prev_hash,
                                entry.entry_hash,
                            ),
                        )
                    except sqlite3.IntegrityError as e:
                        raise RuntimeError(f"Failed to persist ledger entry: {e}")
                conn.commit()

    def load_entries(self) -> list[EvidenceEntry]:
        """Load entries from storage for a specific run."""
        with self._lock:
            with sqlite3.connect(str(self.db_path)) as conn:
                rows = conn.execute(
                    """
                    SELECT seq, timestamp, actor, event_type, payload, prev_hash, entry_hash
                    FROM ledger_entries
                    WHERE tenant_id = ? AND run_id = ?
                    ORDER BY seq ASC
                    """,
                    (self.tenant_id, self.run_id),
                ).fetchall()
            entries = []
            for row in rows:
                seq, timestamp, actor, event_type, payload_json, prev_hash, entry_hash = row
                entry = EvidenceEntry(
                    seq=seq,
                    timestamp=timestamp,
                    actor=actor,
                    event_type=event_type,
                    payload=json.loads(payload_json),
                    prev_hash=prev_hash,
                    entry_hash=entry_hash,
                )
                entries.append(entry)
            return entries

    def verify_persisted_chain(self) -> tuple[bool, Optional[str]]:
        """Verify the hash chain of persisted entries."""
        entries = self.load_entries()
        if not entries:
            return True, None
        prev_hash = "0" * 64  # genesis
        for i, entry in enumerate(entries):
            if entry.prev_hash != prev_hash:
                return False, f"entry {i}: prev_hash mismatch (expected {prev_hash}, got {entry.prev_hash})"
            prev_hash = entry.entry_hash
        return True, None


class DurableLedger:
    """Wrapper around the Rust EvidenceLedger that optionally persists to storage.

    The Rust ledger is always the in-memory source of truth. On each append, the
    current state is optionally written to storage. On load from storage, a fresh
    Rust ledger is reconstructed and integrity-checked.
    """

    def __init__(
        self,
        store: LedgerStore | None = None,
    ) -> None:
        self._ledger = EvidenceLedger()
        self._store = store or NoStore()
        self._lock = threading.RLock()

    def append(self, actor: str, event_type: str, payload: Any) -> tuple[int, str]:
        """Append to the in-memory ledger and persist."""
        with self._lock:
            seq, entry_hash = self._ledger.append(actor, event_type, payload)
            # Persist the updated ledger state.
            self._store.persist_entries(self._ledger.entries())
            return seq, entry_hash

    def entries(self) -> list[EvidenceEntry]:
        """Return all entries from the in-memory ledger."""
        with self._lock:
            return self._ledger.entries()

    def verify(self) -> bool:
        """Verify the in-memory ledger."""
        with self._lock:
            return self._ledger.verify()

    def replay(self) -> list[tuple[int, str, str]]:
        """Replay the ledger as (seq, event_type, payload_str)."""
        with self._lock:
            return self._ledger.replay()

    def require_intact(self) -> None:
        """Raise if the ledger fails verification."""
        with self._lock:
            self._ledger.require_intact()

    def to_json(self) -> str:
        """Serialize the ledger to JSON."""
        with self._lock:
            return self._ledger.to_json()

    @staticmethod
    def from_storage(store: LedgerStore) -> DurableLedger:
        """Reconstruct a ledger from persistent storage.

        Loads all entries and rebuilds the Rust ledger, then verifies the chain.
        """
        entries = store.load_entries()
        is_valid, error = store.verify_persisted_chain()
        if not is_valid:
            raise RuntimeError(f"Ledger integrity check failed: {error}")
        # Reconstruct by importing the entries.
        ledger = EvidenceLedger()
        for entry in entries:
            ledger.append(entry.actor, entry.event_type, entry.payload, entry.timestamp)
        # Final verification.
        if not ledger.verify():
            raise RuntimeError("Reconstructed ledger failed integrity check")
        return DurableLedger(store=store)
