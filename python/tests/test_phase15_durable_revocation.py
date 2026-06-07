"""Phase 15 tests: durable JWT revocation.

Phase 12 introduced JWT revocation, but the deny-list lived in an in-memory set
that was lost on restart — a token revoked before a restart silently re-validated
afterward for the rest of its TTL. Phase 15 persists the deny-list to SQLite so a
revocation survives a restart, and self-prunes entries once the token's own ``exp``
has passed (the entry is then redundant with the signature/exp check).

Properties under test (atom of thoughts — smallest verifiable units):

  RevocationStore unit (backend-agnostic + SQLite-specific):
    1.  In-memory store: revoke then is_revoked is True; unknown jti is False.
    2.  In-memory store: an entry whose expires_at has passed is pruned (not revoked).
    3.  In-memory store: expires_at=None is kept indefinitely (never pruned).
    4.  SQLite store: revoke then is_revoked is True; unknown jti is False.
    5.  SQLite store DURABILITY: a brand-new store over the same dir still reports
        the jti revoked (survives "restart").
    6.  SQLite store self-prunes an expired entry on access.
    7.  SQLite store keeps an expires_at=None entry across a restart indefinitely.
    8.  Factory: empty dir -> InMemoryRevocationStore; non-empty -> SQLiteRevocationStore.

  AuthService integration:
    9.  Durable revocation across restart (HS256): revoke a token, build a NEW
        AuthService over the same revocation_store_dir, the token is still rejected.
    10. Durable revocation across restart (EdDSA): same, with a persistent keystore
        so the token remains otherwise valid after the "restart".
    11. revoke_token persists the token's exp so the durable entry self-prunes.
    12. Backward-compat: default (no revocation_store_dir) keeps in-memory semantics —
        a fresh AuthService does NOT see the prior instance's revocation, and no
        filesystem directory is created.
"""

from __future__ import annotations

import time
from pathlib import Path

import jwt as _jwt
import pytest

from aetheros_orchestrator.auth import AuthConfig, AuthService, InvalidToken, RevokedToken
from aetheros_orchestrator.revocation_store import (
    InMemoryRevocationStore,
    SQLiteRevocationStore,
    make_revocation_store,
)

_ADMIN_SECRET = "phase15-admin-secret-value!!"
_SIGNING_SECRET = "phase15-signing-secret-32+bytes-long!!"
_TTL = 3600


def _hs256_cfg(*, ttl: int = _TTL, revocation_store_dir: str = "") -> AuthConfig:
    return AuthConfig(
        enabled=True,
        algorithm="HS256",
        secret=_SIGNING_SECRET,
        admin_secret=_ADMIN_SECRET,
        token_ttl_seconds=ttl,
        revocation_store_dir=revocation_store_dir,
    )


def _eddsa_cfg(
    *, ttl: int = _TTL, keystore_dir: str = "", revocation_store_dir: str = ""
) -> AuthConfig:
    return AuthConfig(
        enabled=True,
        algorithm="EdDSA",
        secret=_SIGNING_SECRET,
        admin_secret=_ADMIN_SECRET,
        token_ttl_seconds=ttl,
        token_keystore_dir=keystore_dir,
        revocation_store_dir=revocation_store_dir,
    )


# ── 1-3. in-memory store unit ──────────────────────────────────────────────────


def test_inmemory_revoke_and_check():
    store = InMemoryRevocationStore()
    assert store.is_revoked("jti-a") is False
    store.revoke("jti-a", expires_at=int(time.time()) + 1000)
    assert store.is_revoked("jti-a") is True
    assert store.is_revoked("never-revoked") is False


def test_inmemory_prunes_expired_entry():
    store = InMemoryRevocationStore()
    # Already expired one second ago.
    store.revoke("jti-old", expires_at=int(time.time()) - 1)
    assert store.is_revoked("jti-old") is False


def test_inmemory_keeps_none_expiry_indefinitely():
    store = InMemoryRevocationStore()
    store.revoke("jti-forever", expires_at=None)
    assert store.is_revoked("jti-forever") is True


# ── 4-7. SQLite store unit ─────────────────────────────────────────────────────


def test_sqlite_revoke_and_check(tmp_path: Path):
    store = SQLiteRevocationStore(db_dir=str(tmp_path))
    assert store.is_revoked("jti-a") is False
    store.revoke("jti-a", expires_at=int(time.time()) + 1000)
    assert store.is_revoked("jti-a") is True
    assert store.is_revoked("unknown") is False


def test_sqlite_revocation_survives_restart(tmp_path: Path):
    d = str(tmp_path)
    store1 = SQLiteRevocationStore(db_dir=d)
    store1.revoke("jti-persist", expires_at=int(time.time()) + 1000)
    # Simulate a process restart: a brand-new store over the same directory.
    store2 = SQLiteRevocationStore(db_dir=d)
    assert store2.is_revoked("jti-persist") is True


def test_sqlite_prunes_expired_entry(tmp_path: Path):
    store = SQLiteRevocationStore(db_dir=str(tmp_path))
    store.revoke("jti-old", expires_at=int(time.time()) - 1)
    assert store.is_revoked("jti-old") is False


def test_sqlite_keeps_none_expiry_across_restart(tmp_path: Path):
    d = str(tmp_path)
    SQLiteRevocationStore(db_dir=d).revoke("jti-forever", expires_at=None)
    assert SQLiteRevocationStore(db_dir=d).is_revoked("jti-forever") is True


# ── 8. factory ─────────────────────────────────────────────────────────────────


def test_factory_selects_backend(tmp_path: Path):
    assert isinstance(make_revocation_store(""), InMemoryRevocationStore)
    assert isinstance(make_revocation_store("   "), InMemoryRevocationStore)
    assert isinstance(
        make_revocation_store(str(tmp_path)), SQLiteRevocationStore
    )


# ── 9-11. AuthService durable integration ──────────────────────────────────────


def test_hs256_revocation_survives_restart(tmp_path: Path):
    rdir = str(tmp_path / "rev")
    svc1 = AuthService(_hs256_cfg(revocation_store_dir=rdir))
    token = svc1.issue_token("alpha", _ADMIN_SECRET)
    # Sanity: valid before revocation.
    assert svc1.validate_token(token)["sub"] == "alpha"
    svc1.revoke_token(token)
    with pytest.raises(RevokedToken):
        svc1.validate_token(token)
    # Simulate restart: a NEW AuthService over the same revocation dir.
    svc2 = AuthService(_hs256_cfg(revocation_store_dir=rdir))
    with pytest.raises(RevokedToken):
        svc2.validate_token(token)


def test_eddsa_revocation_survives_restart(tmp_path: Path):
    kdir = str(tmp_path / "keys")
    rdir = str(tmp_path / "rev")
    svc1 = AuthService(_eddsa_cfg(keystore_dir=kdir, revocation_store_dir=rdir))
    token = svc1.issue_token("alpha", _ADMIN_SECRET)
    assert svc1.validate_token(token)["sub"] == "alpha"
    svc1.revoke_token(token)
    with pytest.raises(RevokedToken):
        svc1.validate_token(token)
    # Restart: new service over the SAME keystore (so the token still verifies
    # cryptographically) AND the same revocation dir (so it stays revoked).
    svc2 = AuthService(_eddsa_cfg(keystore_dir=kdir, revocation_store_dir=rdir))
    with pytest.raises(RevokedToken):
        svc2.validate_token(token)


def test_revoke_token_persists_exp_for_self_pruning(tmp_path: Path):
    rdir = str(tmp_path / "rev")
    # Token already expired: revoke_token must still extract jti+exp and persist,
    # and the durable store must then self-prune it (exp in the past).
    svc = AuthService(_hs256_cfg(ttl=-10, revocation_store_dir=rdir))
    token = svc.issue_token("alpha", _ADMIN_SECRET)
    jti = svc.revoke_token(token)
    assert isinstance(jti, str) and len(jti) == 32
    # The persisted entry has an expires_at in the past, so a fresh store prunes it.
    store = make_revocation_store(rdir)
    assert store.is_revoked(jti) is False


# ── 12. backward-compat: in-memory default is unchanged ────────────────────────


def test_default_revocation_is_inmemory_and_not_shared(tmp_path: Path, monkeypatch):
    # No revocation_store_dir → in-memory only. A revocation in one service must NOT
    # be visible to a freshly constructed service (pre-Phase-15 semantics), and no
    # directory is created on disk.
    monkeypatch.chdir(tmp_path)
    svc1 = AuthService(_hs256_cfg())
    token = svc1.issue_token("alpha", _ADMIN_SECRET)
    svc1.revoke_token(token)
    with pytest.raises(RevokedToken):
        svc1.validate_token(token)
    # Fresh service, no shared durable store → token is valid again (in-memory lost).
    svc2 = AuthService(_hs256_cfg())
    assert svc2.validate_token(token)["sub"] == "alpha"
    # No stray revocation directory was created by the default path.
    assert not any(p.is_dir() for p in tmp_path.iterdir()) or list(
        tmp_path.iterdir()
    ) == []
