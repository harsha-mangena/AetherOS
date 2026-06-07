"""Run-state durability — Phase 13.

Design rationale
────────────────
Phase 10 made the *evidence ledger* durable: a run's tamper-evident audit trail
survives a process restart because the Rust ``EvidenceLedger`` is snapshotted to
SQLite as canonical JSON and restored via ``EvidenceLedger.from_json()`` (which
re-verifies the hash chain in Rust). But the *run* itself — its position in the
plan, its status, its pending approval gate, its accumulated results, and its
governance state (the signed capability lease and the agent identities that hold
it) — lived only in ``RunService._runs``, a plain in-memory dict.

The consequence was an incoherent durability story: after a restart the
cryptographic evidence was intact, yet the service's headline promise — *resumable
governed runs that span a human approval gate across multiple client requests* —
silently broke. Every in-flight run, and every human approval gate it was waiting
on, was lost. Phase 13 closes that gap.

What must survive, and how
──────────────────────────
A governed run is faithfully reconstructable from three classes of state:

1. **Plain resumable scalars and structures** — ``run_id``, ``tenant_id``,
   ``status``, ``cursor``, ``pending_step_id``, ``total_cost_minor``,
   ``denied_reason``, ``created_at``, the ``Intent``, the compiled ``ExecutionPlan``,
   and the list of ``StepResult``. All are Pydantic models or primitives with a
   lossless JSON round-trip. The plan is persisted verbatim (NOT recompiled on
   restore) so a non-deterministic or evolving ``IntentCompiler`` can never make a
   restored run diverge from the one that was actually authorized and partially
   executed.

2. **Governance restoration triple** — the run's authority must come back exactly
   as it was, not freshly minted:
     * the control-plane ``AgentIdentity`` (issuer) — persisted as
       ``(agent_id, display_name, created_at, secret_seed_hex)`` and restored via
       ``AgentIdentity.from_seed_hex`` so the *same* Ed25519 keypair returns;
     * the execution ``AgentIdentity`` (subject) — same shape;
     * the signed ``CapabilityLease`` — persisted via ``lease.to_json()`` and
       restored via ``CapabilityLease.from_json()``. Critically this preserves
       ``spent_minor`` (budget already consumed) and the issuer signature, so a
       restored run cannot "forget" how much budget it burned and cannot have its
       authority silently re-minted. ``lease.verify()`` still passes because the
       restored issuer identity carries the same public key.
     * the ``AutonomyRecord`` for the executing agent — persisted via its JSON
       snapshot and restored via ``AutonomyRecord.from_json`` so the agent's earned
       tier (which drives ``requires_approval`` re-evaluation) is exactly preserved.

3. **The durable ledger** — already handled by Phase 10's ``LedgerStore``. On
   restore the run's ledger is loaded with ``DurableLedger.from_storage`` (Rust
   re-verifies the chain) and re-attached to the rebuilt ``GovernanceContext``.

Live, non-serializable objects (the ``SandboxController`` and the policy/constitution
engines) are **rebuilt deterministically from config**, never pickled — they carry no
per-run mutable state that isn't already in the ledger or the lease.

Storage strategy
────────────────
One ``run_states`` row per run, keyed by ``(tenant_id, run_id)``, holding a single
canonical-JSON ``state_json`` text column. Same minimal, migration-free schema shape
proven by ``ledger_store.SQLiteStore``. SQLite in WAL mode; a per-instance
``threading.RLock`` guards concurrent persist/load.

Security note
─────────────
``state_json`` contains exported secret seeds for the run's identities. The store
writes them to a local SQLite file under the operator-controlled ``db_dir`` (same
trust boundary as the ledger DB). This is acceptable for a local control plane; a
networked deployment would wrap ``RunStateStore`` with an at-rest encryption layer
or move the seeds into a secret manager keyed by ``run_id``. The serializer is the
single choke point for that upgrade.

References
──────────
* SQLite WAL mode: https://www.sqlite.org/wal.html
* Capability/identity persistence primitives: ``bindings/aether-py/src/lib.rs``
  (``AgentIdentity.from_seed_hex`` / ``secret_seed_hex``, ``CapabilityLease.to_json`` /
  ``from_json`` preserving ``spent_minor`` + signature, ``AutonomyRecord.from_json``).
* Phase 10 ledger durability: ``ledger_store.py``.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


# ── Abstract interface (mirrors ledger_store.LedgerStore) ──────────────────────


class RunStateStore(ABC):
    """Abstract persistence backend for a single governed run's resumable state."""

    @abstractmethod
    def persist(self, tenant_id: str, run_id: str, state_json: str) -> None:
        """Write (or overwrite) the canonical JSON state document for this run."""

    @abstractmethod
    def load(self, tenant_id: str, run_id: str) -> str | None:
        """Return the canonical JSON state document, or None if not persisted."""

    @abstractmethod
    def delete(self, tenant_id: str, run_id: str) -> None:
        """Remove the persisted state document (e.g. on run deletion)."""

    @abstractmethod
    def load_all(self, tenant_id: str | None = None) -> list[tuple[str, str, str]]:
        """Return all persisted ``(tenant_id, run_id, state_json)`` rows.

        When ``tenant_id`` is given, only that tenant's rows are returned. Used at
        service startup to repopulate ``RunService._runs`` from durable storage.
        """


# ── No-op backend (default — in-memory only, backward-compatible) ─────────────


class NoRunStateStore(RunStateStore):
    """No-op store. Run state lives in memory only (pre-Phase-13 behaviour)."""

    def persist(self, tenant_id: str, run_id: str, state_json: str) -> None:
        pass

    def load(self, tenant_id: str, run_id: str) -> str | None:
        return None

    def delete(self, tenant_id: str, run_id: str) -> None:
        pass

    def load_all(self, tenant_id: str | None = None) -> list[tuple[str, str, str]]:
        return []


# ── SQLite backend ─────────────────────────────────────────────────────────────


class SQLiteRunStateStore(RunStateStore):
    """Durable SQLite backend for run state: one DB file per tenant, WAL-mode.

    Schema: a single ``run_states`` table keyed by ``(tenant_id, run_id)`` holding
    the full canonical-JSON state document produced by ``RunStateSerializer.dump``.
    The document is opaque to SQLite, so the run-state format can evolve without a
    migration. Restoration validity is enforced in Python/Rust on load, not by the
    schema.
    """

    _SCHEMA = """
        CREATE TABLE IF NOT EXISTS run_states (
            tenant_id   TEXT NOT NULL,
            run_id      TEXT NOT NULL,
            state_json  TEXT NOT NULL,
            updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            PRIMARY KEY (tenant_id, run_id)
        )
    """

    def __init__(self, db_dir: Path | str = "./run_states") -> None:
        self._db_dir = Path(db_dir)
        self._db_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    def _db_path(self, tenant_id: str) -> Path:
        # Sanitise tenant_id to prevent path traversal — mirror ledger_store.
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in tenant_id)
        return self._db_dir / f"{safe}.db"

    def _connect(self, tenant_id: str) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path(tenant_id)), check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute(self._SCHEMA)
        conn.commit()
        return conn

    def persist(self, tenant_id: str, run_id: str, state_json: str) -> None:
        with self._lock:
            conn = self._connect(tenant_id)
            try:
                conn.execute(
                    """
                    INSERT INTO run_states (tenant_id, run_id, state_json, updated_at)
                    VALUES (?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                    ON CONFLICT(tenant_id, run_id) DO UPDATE SET
                        state_json = excluded.state_json,
                        updated_at = excluded.updated_at
                    """,
                    (tenant_id, run_id, state_json),
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
                    "SELECT state_json FROM run_states WHERE tenant_id=? AND run_id=?",
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
                    "DELETE FROM run_states WHERE tenant_id=? AND run_id=?",
                    (tenant_id, run_id),
                )
                conn.commit()
            finally:
                conn.close()

    def load_all(self, tenant_id: str | None = None) -> list[tuple[str, str, str]]:
        with self._lock:
            rows: list[tuple[str, str, str]] = []
            if tenant_id is not None:
                dbs = [self._db_path(tenant_id)]
            else:
                # One DB file per tenant; scan the directory.
                dbs = sorted(self._db_dir.glob("*.db"))
            for db in dbs:
                if not db.exists():
                    continue
                conn = sqlite3.connect(str(db), check_same_thread=False)
                try:
                    conn.execute(self._SCHEMA)
                    for t, r, s in conn.execute(
                        "SELECT tenant_id, run_id, state_json FROM run_states"
                    ).fetchall():
                        rows.append((t, r, s))
                finally:
                    conn.close()
            return rows


# ── Factory function (used by RunService) ─────────────────────────────────────


def make_run_state_store(
    backend: str = "none",
    db_dir: str = "./run_states",
) -> RunStateStore:
    """Construct the appropriate ``RunStateStore`` for a service.

    ``backend="none"`` (default) returns a ``NoRunStateStore`` — identical to the
    pre-Phase-13 in-memory-only behaviour, so every existing test passes unchanged.
    ``backend="sqlite"`` returns a ``SQLiteRunStateStore`` that persists each run's
    state after every state-machine transition and repopulates runs on startup.
    """
    if backend == "sqlite":
        return SQLiteRunStateStore(db_dir=db_dir)
    return NoRunStateStore()
