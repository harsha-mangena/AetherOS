"""Ledger durability backends and DurableLedger — Phase 10.

Design rationale
────────────────
The Rust ``EvidenceLedger`` is the canonical, cryptographically-verified in-memory
truth. Every append produces a hash-chained entry; ``verify()`` re-walks the full
chain from genesis. The governance, policy, and transparency layers all depend on
this in-memory ledger and are entirely unaffected by what storage backend is chosen.

Durability problem
──────────────────
The in-memory ledger is lost on process restart. Phase 10 adds optional persistence
so that a run's evidence survives a service crash or scheduled restart, enabling
long-running agentic tasks and post-mortem auditing without a human checkpoint.

Storage strategy: canonical JSON blob
──────────────────────────────────────
The single correct persistence strategy is to store the ledger's own canonical JSON
snapshot (produced by ``EvidenceLedger.to_json()``) as one row per run, and restore
it via ``EvidenceLedger.from_json()``. This is correct because:

1. ``from_json`` re-verifies the full hash chain on load — the tamper-detection gate
   is the Rust core, not a Python re-implementation. An attacker who mutates the DB
   row is caught immediately at load time.

2. There is no payload re-serialization on restore. The alternative (per-entry row +
   re-append-on-load) is fragile: if key ordering or unicode escaping differs between
   ``json.dumps`` calls across Python/Rust versions, the reconstructed ``entry_hash``
   diverges from the stored one silently. The blob strategy avoids this entirely.

3. Schema is minimal and stable: a single ``ledger_snapshots`` table keyed by
   ``(tenant_id, run_id)`` with one ``ledger_json`` text column. No migrations needed
   as the ledger format evolves — the JSON is opaque to SQLite.

Concurrency
───────────
SQLite is opened in WAL mode (writers do not block readers). A Python-level
``threading.RLock`` guards each ``SQLiteStore`` instance against concurrent Python
threads calling ``persist`` and ``load`` simultaneously.

References
──────────
* SQLite WAL mode: https://www.sqlite.org/wal.html
* RFC 6962 / AetherOS evidence ledger design: ``crates/aether-core/src/evidence.rs``
"""

from __future__ import annotations

import sqlite3
import threading
from abc import ABC, abstractmethod
from pathlib import Path

from aetheros import EvidenceLedger
from aetheros.ledger import LedgerIntegrityError


# ── Abstract interface ─────────────────────────────────────────────────────────


class LedgerStore(ABC):
    """Abstract persistence backend for a single run's evidence ledger."""

    @abstractmethod
    def persist(self, tenant_id: str, run_id: str, ledger_json: str) -> None:
        """Write (or overwrite) the canonical JSON snapshot for this run."""

    @abstractmethod
    def load(self, tenant_id: str, run_id: str) -> str | None:
        """Return the canonical JSON snapshot, or None if not persisted yet."""

    @abstractmethod
    def delete(self, tenant_id: str, run_id: str) -> None:
        """Remove the persisted snapshot (e.g. for test teardown or run expiry)."""


# ── No-op backend (default — in-memory only, backward-compatible) ─────────────


class NoStore(LedgerStore):
    """No-op store. Ledger lives in memory only (current MVP behaviour)."""

    def persist(self, tenant_id: str, run_id: str, ledger_json: str) -> None:
        pass

    def load(self, tenant_id: str, run_id: str) -> str | None:
        return None

    def delete(self, tenant_id: str, run_id: str) -> None:
        pass


# ── SQLite backend ─────────────────────────────────────────────────────────────


class SQLiteStore(LedgerStore):
    """Durable SQLite backend: one database file per tenant, WAL-mode.

    Schema: a single ``ledger_snapshots`` table keyed by ``(tenant_id, run_id)``.
    Each row holds the full canonical ledger JSON produced by
    ``EvidenceLedger.to_json()``.  On load, the JSON is passed to
    ``EvidenceLedger.from_json()`` which re-verifies the hash chain in Rust.
    """

    _SCHEMA = """
        CREATE TABLE IF NOT EXISTS ledger_snapshots (
            tenant_id   TEXT NOT NULL,
            run_id      TEXT NOT NULL,
            ledger_json TEXT NOT NULL,
            updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            PRIMARY KEY (tenant_id, run_id)
        )
    """

    def __init__(self, db_dir: Path | str = "./ledgers") -> None:
        self._db_dir = Path(db_dir)
        self._db_dir.mkdir(parents=True, exist_ok=True)
        # Per-tenant connections are created lazily; one RLock per store instance.
        self._lock = threading.RLock()

    def _db_path(self, tenant_id: str) -> Path:
        # Sanitise tenant_id to prevent path traversal — replace any non-alphanumeric
        # characters (other than '-' and '_') with '_'.
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in tenant_id)
        return self._db_dir / f"{safe}.db"

    def _connect(self, tenant_id: str) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path(tenant_id)), check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute(self._SCHEMA)
        conn.commit()
        return conn

    def persist(self, tenant_id: str, run_id: str, ledger_json: str) -> None:
        with self._lock:
            conn = self._connect(tenant_id)
            try:
                conn.execute(
                    """
                    INSERT INTO ledger_snapshots (tenant_id, run_id, ledger_json, updated_at)
                    VALUES (?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                    ON CONFLICT(tenant_id, run_id) DO UPDATE SET
                        ledger_json = excluded.ledger_json,
                        updated_at  = excluded.updated_at
                    """,
                    (tenant_id, run_id, ledger_json),
                )
                conn.commit()
            finally:
                conn.close()

    def load(self, tenant_id: str, run_id: str) -> str | None:
        with self._lock:
            db = self._db_path(tenant_id)
            if not db.exists():
                return None
            conn = self._connect(tenant_id)
            try:
                row = conn.execute(
                    "SELECT ledger_json FROM ledger_snapshots WHERE tenant_id=? AND run_id=?",
                    (tenant_id, run_id),
                ).fetchone()
            finally:
                conn.close()
            return row[0] if row else None

    def delete(self, tenant_id: str, run_id: str) -> None:
        with self._lock:
            db = self._db_path(tenant_id)
            if not db.exists():
                return
            conn = self._connect(tenant_id)
            try:
                conn.execute(
                    "DELETE FROM ledger_snapshots WHERE tenant_id=? AND run_id=?",
                    (tenant_id, run_id),
                )
                conn.commit()
            finally:
                conn.close()


# ── DurableLedger — thin wrapper with correct restoration semantics ────────────


class DurableLedger:
    """An ``EvidenceLedger`` that optionally persists after each append.

    The Rust ledger is always the in-memory source of truth and the only party that
    produces or verifies hashes.  ``DurableLedger`` is a thin wrapper that:

    1. Delegates every ledger operation to the inner ``EvidenceLedger``.
    2. After each successful ``append``, calls ``store.persist`` with the ledger's
       canonical JSON snapshot.
    3. On ``from_storage``, loads the JSON snapshot and passes it to
       ``EvidenceLedger.from_json()`` — which verifies the full hash chain in Rust
       before returning.  Tampered or truncated data raises ``LedgerIntegrityError``.

    All public methods mirror ``EvidenceLedger`` so that ``DurableLedger`` is a
    drop-in replacement wherever ``EvidenceLedger`` is expected (``run_service``,
    ``transparency``, ``compliance``, etc.).
    """

    def __init__(
        self,
        tenant_id: str,
        run_id: str,
        store: LedgerStore | None = None,
        *,
        _ledger: EvidenceLedger | None = None,
    ) -> None:
        self._tenant_id = tenant_id
        self._run_id = run_id
        self._store = store or NoStore()
        self._ledger = _ledger or EvidenceLedger()
        self._lock = threading.RLock()

    # ── Persistence ───────────────────────────────────────────────────────────

    def _persist(self) -> None:
        """Write the current canonical JSON snapshot to the store (under lock)."""
        self._store.persist(self._tenant_id, self._run_id, self._ledger.to_json())

    # ── EvidenceLedger interface ───────────────────────────────────────────────

    @property
    def length(self) -> int:
        return self._ledger.length

    @property
    def head_hash(self) -> str:
        return self._ledger.head_hash

    def append(self, actor: str, event_type: str, payload, timestamp: str | None = None):
        """Append an event and persist the new snapshot atomically."""
        with self._lock:
            result = self._ledger.append(actor, event_type, payload, timestamp)
            self._persist()
            return result

    def verify(self) -> bool:
        return self._ledger.verify()

    def require_intact(self) -> None:
        self._ledger.require_intact()

    def replay(self):
        return self._ledger.replay()

    def entries(self):
        return self._ledger.entries()

    def to_json(self) -> str:
        return self._ledger.to_json()

    def __len__(self) -> int:
        return self._ledger.length

    def __repr__(self) -> str:
        return (
            f"DurableLedger(tenant={self._tenant_id!r}, run={self._run_id!r}, "
            f"entries={self.length}, head={self.head_hash[:12]}…)"
        )

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def from_storage(
        cls,
        tenant_id: str,
        run_id: str,
        store: LedgerStore,
    ) -> "DurableLedger":
        """Restore a run's ledger from the durable store.

        Loads the canonical JSON snapshot and passes it to
        ``EvidenceLedger.from_json()``, which verifies the full Rust hash chain.
        On success, returns a ``DurableLedger`` whose inner ledger is identical to
        the one that was last persisted — byte-for-byte, hash-for-hash.

        Raises ``LedgerIntegrityError`` if:
          * No snapshot is found for (tenant_id, run_id) — the run was never
            persisted or was deleted. Callers must handle this as a fresh ledger.
          * The stored JSON cannot be parsed or has a broken hash chain.

        This is the only correct restoration path. Re-appending entries from a
        row-per-entry table would risk payload re-serialization drift and silent
        hash divergence — which is why the blob strategy was chosen.
        """
        json_data = store.load(tenant_id, run_id)
        if json_data is None:
            raise LedgerIntegrityError(
                f"No persisted ledger found for tenant={tenant_id!r}, run={run_id!r}"
            )
        # EvidenceLedger.from_json verifies the chain in Rust; raises on tamper.
        ledger = EvidenceLedger.from_json(json_data)
        return cls(tenant_id, run_id, store, _ledger=ledger)


# ── Factory function (used by RunService) ─────────────────────────────────────


def make_ledger(
    tenant_id: str,
    run_id: str,
    backend: str = "none",
    db_dir: str = "./ledgers",
) -> DurableLedger:
    """Construct the appropriate ``DurableLedger`` for a new run.

    When ``backend="none"`` (default), returns a ``DurableLedger`` backed by a
    ``NoStore`` — identical to the prior in-memory-only behaviour.
    When ``backend="sqlite"``, returns one backed by a ``SQLiteStore`` that will
    persist after every append.

    This function is the single injection point for the storage backend so that
    ``RunService`` never imports ``SQLiteStore`` directly and tests can inject any
    ``LedgerStore`` implementation.
    """
    if backend == "sqlite":
        store: LedgerStore = SQLiteStore(db_dir=db_dir)
    else:
        store = NoStore()
    return DurableLedger(tenant_id=tenant_id, run_id=run_id, store=store)
