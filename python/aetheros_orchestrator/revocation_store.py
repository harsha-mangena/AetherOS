"""Durable JWT revocation store — Phase 15.

Design rationale
────────────────
Phase 12 introduced JWT revocation as a defence against a token that must be
killed *before* its natural expiry — a logout, a tenant rotation, or a detected
compromise. But the revocation set lived in a plain in-memory ``set[str]`` inside
``TokenStore``: it was lost on every process restart.

That left a concrete security correctness gap, one flagged at the close of
Phase 14: a token explicitly revoked at 10:00 would, after a restart at 10:05,
*silently validate again* for the remainder of its TTL. Revocation that does not
survive a restart is not revocation — it is a hint. An attacker who compromises a
token and waits out (or induces) a restart defeats it entirely. Phase 15 closes
the gap by persisting revocations to SQLite, mirroring the durability pattern
proven by Phase 10's ledger store and Phase 13's run-state store.

What is persisted, and why an expiry column
────────────────────────────────────────────
A revocation entry is the pair ``(jti, expires_at)``:

  * ``jti``        — the unique JWT ID (RFC 7519 §4.1.7) of the revoked token.
  * ``expires_at`` — the token's own ``exp`` claim (Unix seconds).

Storing ``expires_at`` is what makes the denylist *self-pruning*, the standard
practice for server-side JWT revocation lists (cf. OAuth 2.0 Token Revocation,
RFC 7009, and the JWT denylist pattern): a revoked token only needs to stay on
the list until it would have expired anyway. Once ``now > expires_at`` the
signature check alone rejects it, so the row is dead weight and can be swept.
Without the expiry the list would grow without bound. With it, the list is
bounded by the number of *unexpired* revoked tokens — naturally small.

A revocation with an unknown expiry (e.g. a malformed token whose ``exp`` could
not be read) is stored with ``expires_at = None`` and is kept indefinitely: we
fail safe toward *over*-revoking, never under-revoking.

Storage strategy
────────────────
One ``revoked_tokens`` table keyed by ``jti`` (globally unique — a uuid4 hex, so
no tenant scoping is required for correctness), holding ``expires_at``. SQLite in
WAL mode; a per-instance ``threading.RLock`` guards concurrent revoke/check, the
same minimal, migration-free shape as ``run_state_store.SQLiteRunStateStore``.

A single DB file (``revocations.db``) under the operator-controlled directory is
used rather than one-file-per-tenant: revocation is a global deny-list keyed by an
already-unique jti, and ``is_revoked`` must answer without knowing the tenant (the
validator checks revocation generically for both HS256 and EdDSA tokens).

Pruning runs opportunistically inside ``is_revoked`` and ``revoke`` under the same
lock — no background thread, no separate lifecycle to manage. Pruning is a pure
optimisation: correctness never depends on it, because an expired ``jti`` that is
still on the list is simply redundant with the signature/expiry check.

Backward compatibility
───────────────────────
``InMemoryRevocationStore`` reproduces the exact pre-Phase-15 semantics
(``set[str]``, lost on restart) and is the default the factory returns when no
directory is configured. Every Phase 12 and Phase 14 auth test passes unchanged,
and an HS256/EdDSA deployment with an empty ``revocation_store_dir`` touches no
filesystem.

References
──────────
* RFC 7519 — JSON Web Token; ``jti`` (§4.1.7), ``exp`` (§4.1.4).
* RFC 7009 — OAuth 2.0 Token Revocation (server-side revocation semantics).
* SQLite WAL mode: https://www.sqlite.org/wal.html
* Sibling durability stores: ``run_state_store.py``, ``ledger_store.py``.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from abc import ABC, abstractmethod
from pathlib import Path


# ── Abstract interface (mirrors run_state_store.RunStateStore) ─────────────────


class RevocationStore(ABC):
    """Abstract persistence backend for the JWT revocation deny-list.

    The contract is a deny-list keyed by ``jti``: a jti that was never revoked is
    not on the list (``is_revoked`` returns False). The cryptographic signature and
    ``exp`` checks remain the primary gate; this store only adds *early* invalidation.
    """

    @abstractmethod
    def revoke(self, jti: str, expires_at: int | None = None) -> None:
        """Mark ``jti`` revoked. Idempotent.

        ``expires_at`` is the token's ``exp`` claim (Unix seconds) when known, so the
        backend can self-prune the entry once it passes. ``None`` means "keep
        indefinitely" — used when the expiry could not be read (fail toward
        over-revoking).
        """

    @abstractmethod
    def is_revoked(self, jti: str) -> bool:
        """Return True iff ``jti`` is currently on the deny-list."""


# ── In-memory backend (default — backward-compatible, lost on restart) ─────────


class InMemoryRevocationStore(RevocationStore):
    """Thread-safe in-memory deny-list. Reproduces pre-Phase-15 ``TokenStore``.

    Tracks ``expires_at`` so it can self-prune just like the SQLite backend, keeping
    behaviour identical across backends; the only difference is durability.
    """

    def __init__(self) -> None:
        # jti -> expires_at (None = keep indefinitely)
        self._revoked: dict[str, int | None] = {}
        self._lock = threading.Lock()

    def _prune_locked(self, now: int) -> None:
        expired = [
            jti
            for jti, exp in self._revoked.items()
            if exp is not None and exp <= now
        ]
        for jti in expired:
            del self._revoked[jti]

    def revoke(self, jti: str, expires_at: int | None = None) -> None:
        with self._lock:
            now = int(time.time())
            self._prune_locked(now)
            self._revoked[jti] = expires_at

    def is_revoked(self, jti: str) -> bool:
        with self._lock:
            now = int(time.time())
            self._prune_locked(now)
            return jti in self._revoked


# ── SQLite backend (durable — survives restart) ────────────────────────────────


class SQLiteRevocationStore(RevocationStore):
    """Durable SQLite deny-list: one ``revocations.db`` file, WAL-mode.

    Schema: a single ``revoked_tokens`` table keyed by ``jti`` holding ``expires_at``
    (nullable Unix seconds). Expired rows are swept opportunistically under the same
    lock on every ``revoke``/``is_revoked`` call. The schema is migration-free; new
    columns can be added without breaking older rows.
    """

    _SCHEMA = """
        CREATE TABLE IF NOT EXISTS revoked_tokens (
            jti         TEXT PRIMARY KEY,
            expires_at  INTEGER,
            revoked_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        )
    """

    def __init__(self, db_dir: Path | str = "./revocations") -> None:
        self._db_dir = Path(db_dir)
        self._db_dir.mkdir(parents=True, exist_ok=True)
        self._db_path = self._db_dir / "revocations.db"
        self._lock = threading.RLock()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute(self._SCHEMA)
        conn.commit()
        return conn

    def _prune(self, conn: sqlite3.Connection, now: int) -> None:
        # Sweep entries whose token would have expired on its own anyway.
        conn.execute(
            "DELETE FROM revoked_tokens WHERE expires_at IS NOT NULL AND expires_at <= ?",
            (now,),
        )

    def revoke(self, jti: str, expires_at: int | None = None) -> None:
        with self._lock:
            conn = self._connect()
            try:
                now = int(time.time())
                self._prune(conn, now)
                conn.execute(
                    """
                    INSERT INTO revoked_tokens (jti, expires_at)
                    VALUES (?, ?)
                    ON CONFLICT(jti) DO UPDATE SET expires_at = excluded.expires_at
                    """,
                    (jti, expires_at),
                )
                conn.commit()
            finally:
                conn.close()

    def is_revoked(self, jti: str) -> bool:
        with self._lock:
            conn = self._connect()
            try:
                now = int(time.time())
                self._prune(conn, now)
                conn.commit()
                row = conn.execute(
                    "SELECT 1 FROM revoked_tokens WHERE jti=?",
                    (jti,),
                ).fetchone()
            finally:
                conn.close()
            return row is not None


# ── Factory (used by AuthService) ──────────────────────────────────────────────


def make_revocation_store(revocation_store_dir: str = "") -> RevocationStore:
    """Construct the appropriate ``RevocationStore`` from config.

    Empty ``revocation_store_dir`` (default) returns an ``InMemoryRevocationStore`` —
    identical to the pre-Phase-15 in-memory-only behaviour, so every existing auth
    test passes unchanged and no filesystem activity occurs. A non-empty path returns
    a ``SQLiteRevocationStore`` so revoked tokens stay revoked across restarts.
    """
    if revocation_store_dir.strip():
        return SQLiteRevocationStore(db_dir=revocation_store_dir.strip())
    return InMemoryRevocationStore()
