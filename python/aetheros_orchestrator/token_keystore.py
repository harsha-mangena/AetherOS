"""Per-tenant Ed25519 token keystore — Phase 14 + Phase 18 (key rotation).

Why per-tenant asymmetric keys
───────────────────────────────
Phase 12 signed every tenant's control-plane JWT with a single shared HMAC-SHA256
secret (``auth.secret``). That secret is simultaneously the signing key *and* the
verification key for *all* tenants. Two structural weaknesses follow:

* **Blast radius.** Any component that must *verify* a token (a gateway, a sidecar,
  an external auditor) needs the one secret that can *forge* every tenant's token.
  There is no way to hand out verify-only capability.
* **No tenant cryptographic boundary.** A token is just ``sub = tenant_id`` signed
  by the shared secret; nothing cryptographically binds a token to the tenant it
  was minted for beyond an unprotected claim value.

Phase 14 adds an asymmetric path. Each tenant gets its own Ed25519 keypair. A token
for tenant *T* is signed with *T*'s **private** key and carries ``kid = T`` in its
JOSE header. Verification loads *T*'s **public** key by ``kid`` and additionally
requires ``sub == kid`` — so a token signed by tenant A's key can never validate as
tenant B. Public keys can be published (a JWKS document) for offline, verify-only
checking without ever exposing signing material.

Phase 18 — Key Rotation (NIST SP 800-57 cryptoperiod management)
─────────────────────────────────────────────────────────────────
A key generated once and never rotated violates NIST SP 800-57 Part 1 Rev 5 §5.3
(Cryptoperiod management). An operator who suspects compromise, or who follows a
periodic rotation schedule, needs a safe migration path.

Key lifecycle state machine (NIST SP 800-57 §5.3.5):
  ACTIVE    — the key currently signs new tokens; there is exactly one ACTIVE key
              per tenant at any time. ``issue_token`` stamps its versioned kid.
  RETIRING  — a formerly ACTIVE key whose rotation timestamp + overlap_ttl has not
              yet passed; still verifiable, never signs. Tokens issued before the
              rotation remain valid until their natural ``exp``.
  EXPIRED   — a RETIRING key whose overlap window has closed, or a key that was
              emergency-retired via ``retire_all``. Neither signs nor verifies.

Version naming: ``kid = "{tenant_id}#{v}"`` where *v* starts at 1 and increments
by 1 on each rotation. The unversioned ``kid = tenant_id`` (Phase 14 format) is
mapped to ``tenant_id#v1`` on first access for backward compatibility.

O(1) disk layout: each key version is stored as ``<safe(kid)>.pem`` (i.e.
``safe(tenant_id)_v{N}.pem``). The registry metadata (which version is ACTIVE,
which are RETIRING and their rotation timestamps) is stored as ``<safe(tenant_id)>
.json`` alongside the PEM files. This keeps the disk layout auditable without a
separate database.

Design (atom of thoughts — Phase 18)
──────────────────────────────────────
1. ``rotate(tenant_id, overlap_ttl_seconds)`` atomically generates a new Ed25519
   keypair, assigns it the next version, writes its PEM, updates the registry JSON
   (new key → ACTIVE, old key → RETIRING with rotation_ts), and returns the new kid.
2. ``public_pem(kid)`` accepts both versioned kids (``tenant#v2``) and the legacy
   unversioned form (``tenant_id``), resolving the latter to ``v1`` transparently.
3. ``prune(tenant_id, now, token_ttl_seconds)`` drops RETIRING keys whose overlap
   window has closed — called lazily on rotate() and retire_all() to avoid unbounded
   growth. The worst-case number of live keys per tenant is
   ``ceil(max_token_ttl / min_rotation_interval) + 1``, bounded by config.
4. ``retire_all(tenant_id)`` immediately moves every RETIRING key to EXPIRED — a
   break-glass emergency invalidation of all retiring keys (not individual tokens).
   A new ACTIVE key must already exist before retire_all makes sense; it does not
   generate one.
5. ``key_info(tenant_id)`` returns a JSON-serialisable summary of the current key
   registry for the ops inspection endpoint.
6. ``jwks()`` publishes ACTIVE + RETIRING (non-expired) public keys so that
   downstream verifiers can validate tokens issued with either. EXPIRED keys are
   omitted, so tokens signed with an expired key are correctly rejected.

Standards / research net
────────────────────────
* RFC 8032 — Edwards-Curve Digital Signature Algorithm (Ed25519).
* RFC 8037 — CFRG curves (Ed25519) for JOSE; the ``EdDSA`` ``alg`` and ``OKP`` ``kty``.
* RFC 7517 — JSON Web Key (JWK) and JWK Set.
* RFC 7518 §4.1 — ``kid`` is a hint matching a token to a verifier's key set.
* RFC 9068 §4 / RFC 8725 §3.10 — rotate signing keys periodically; keep old keys
  in JWKS until tokens signed with them are expired.
* NIST SP 800-57 Part 1 Rev 5 §5.3 — cryptoperiods; originator usage period
  (signing) vs recipient usage period (verification); transition period concept.
* NIST SP 800-57 Part 1 §5.3.5 — the ACTIVE → RETIRING → EXPIRED state machine
  mirrors NIST's "active", "transition" (verify only), and "expired" key states.
* Google Cloud KMS / AWS KMS — PRIMARY (signs) / ENABLED (verifies only) / DISABLED
  are the exact analogue of ACTIVE / RETIRING / EXPIRED.
"""

from __future__ import annotations

import base64
import json
import threading
import time
from enum import Enum
from pathlib import Path
from typing import NamedTuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    NoEncryption,
)


# ── helpers ──────────────────────────────────────────────────────────────────

def _b64url_no_pad(raw: bytes) -> str:
    """Base64url-encode without padding (JOSE convention, RFC 7515 §2)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


# ── key lifecycle ─────────────────────────────────────────────────────────────

class KeyState(str, Enum):
    """NIST SP 800-57 Part 1 §5.3.5 key state machine."""
    ACTIVE = "ACTIVE"      # currently signs; exactly one per tenant
    RETIRING = "RETIRING"  # verifies only; overlap window open
    EXPIRED = "EXPIRED"    # neither signs nor verifies; omitted from JWKS


class KeyRecord(NamedTuple):
    """Immutable metadata for one key version stored in the registry."""
    kid: str              # versioned kid, e.g. "alpha#v2"
    version: int          # 1-based integer
    state: KeyState
    created_at: float     # Unix timestamp
    rotated_at: float | None = None  # set when state → RETIRING


# ── registry persistence ──────────────────────────────────────────────────────

def _registry_to_dict(records: list[KeyRecord]) -> dict:
    return {
        "keys": [
            {
                "kid": r.kid,
                "version": r.version,
                "state": r.state.value,
                "created_at": r.created_at,
                "rotated_at": r.rotated_at,
            }
            for r in records
        ]
    }


def _registry_from_dict(data: dict) -> list[KeyRecord]:
    result = []
    for k in data.get("keys", []):
        result.append(KeyRecord(
            kid=k["kid"],
            version=k["version"],
            state=KeyState(k["state"]),
            created_at=float(k["created_at"]),
            rotated_at=float(k["rotated_at"]) if k.get("rotated_at") is not None else None,
        ))
    return result


# ── main keystore class ───────────────────────────────────────────────────────

class TenantKeyStore:
    """Per-tenant Ed25519 keypairs for EdDSA token signing with key rotation.

    Thread-safe. When ``db_dir`` is a non-empty path, each tenant's private keys are
    written there as PKCS#8 PEM files (``<safe_kid>.pem``) and the key registry is
    stored as ``<safe_tenant>.json``, so issued tokens remain verifiable across
    process restarts. When ``db_dir`` is empty, keys live only in memory.

    Key naming
    ──────────
    Phase 14 used ``kid = tenant_id`` (flat). Phase 18 uses versioned kids:
    ``kid = "{tenant_id}#{v}"`` where v is a 1-based integer. Unversioned Phase 14
    kids are accepted transparently in ``public_pem`` by mapping them to ``v1``.

    Path traversal in ``tenant_id`` is neutralised the same way the ledger and
    run-state stores sanitise tenant identifiers before touching the filesystem.
    ``#`` in tenant_id is replaced with ``_`` in the safe form.
    """

    def __init__(
        self,
        db_dir: str | Path = "",
        passphrase: str = "",
        default_overlap_ttl_seconds: int = 3600,
    ) -> None:
        self._db_dir = Path(db_dir) if db_dir else None
        if self._db_dir is not None:
            self._db_dir.mkdir(parents=True, exist_ok=True)
        # in-memory key cache: versioned kid → Ed25519PrivateKey
        self._cache: dict[str, Ed25519PrivateKey] = {}
        # in-memory registry: tenant_id → list[KeyRecord]
        self._registry: dict[str, list[KeyRecord]] = {}
        self._lock = threading.RLock()
        self._passphrase: bytes = passphrase.encode("utf-8") if passphrase else b""
        self._default_overlap_ttl_seconds = default_overlap_ttl_seconds

    # ── filesystem helpers ────────────────────────────────────────────────────

    @staticmethod
    def _safe(s: str) -> str:
        """Sanitise an arbitrary string for use as a path component."""
        return "".join(c if c.isalnum() or c in "-_" else "_" for c in s)

    def _pem_path(self, kid: str) -> Path | None:
        """Disk path for the PKCS#8 PEM file for a versioned kid."""
        if self._db_dir is None:
            return None
        return self._db_dir / f"{self._safe(kid)}.pem"

    def _registry_path(self, tenant_id: str) -> Path | None:
        """Disk path for the JSON registry file for a tenant."""
        if self._db_dir is None:
            return None
        return self._db_dir / f"{self._safe(tenant_id)}.json"

    def _load_key_from_disk(self, kid: str) -> Ed25519PrivateKey | None:
        path = self._pem_path(kid)
        if path is None or not path.exists():
            return None
        password = self._passphrase if self._passphrase else None
        key = serialization.load_pem_private_key(path.read_bytes(), password=password)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError(f"keystore file for kid {kid!r} is not Ed25519")
        return key

    def _persist_key_to_disk(self, kid: str, key: Ed25519PrivateKey) -> None:
        path = self._pem_path(kid)
        if path is None:
            return
        enc_alg = (
            BestAvailableEncryption(self._passphrase)
            if self._passphrase
            else NoEncryption()
        )
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc_alg,
        )
        tmp = path.with_suffix(".pem.tmp")
        tmp.write_bytes(pem)
        try:
            tmp.chmod(0o600)
        except OSError:  # pragma: no cover — best effort on exotic filesystems
            pass
        tmp.replace(path)

    def _load_registry_from_disk(self, tenant_id: str) -> list[KeyRecord]:
        path = self._registry_path(tenant_id)
        if path is None or not path.exists():
            return []
        try:
            data = json.loads(path.read_text("utf-8"))
            return _registry_from_dict(data)
        except Exception:  # pragma: no cover — corrupt registry; start fresh
            return []

    def _persist_registry_to_disk(self, tenant_id: str, records: list[KeyRecord]) -> None:
        path = self._registry_path(tenant_id)
        if path is None:
            return
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(_registry_to_dict(records), indent=2), encoding="utf-8")
        tmp.replace(path)

    # ── registry management ───────────────────────────────────────────────────

    def _get_registry(self, tenant_id: str) -> list[KeyRecord]:
        """Load the registry for a tenant from cache or disk (never creates one)."""
        if tenant_id in self._registry:
            return self._registry[tenant_id]
        records = self._load_registry_from_disk(tenant_id)
        self._registry[tenant_id] = records
        return records

    def _active_record(self, tenant_id: str) -> KeyRecord | None:
        """Return the current ACTIVE key record, or None if none exists."""
        for r in self._get_registry(tenant_id):
            if r.state == KeyState.ACTIVE:
                return r
        return None

    def _make_versioned_kid(self, tenant_id: str, version: int) -> str:
        return f"{tenant_id}#v{version}"

    def _next_version(self, tenant_id: str) -> int:
        records = self._get_registry(tenant_id)
        if not records:
            return 1
        return max(r.version for r in records) + 1

    # ── key access (internal) ─────────────────────────────────────────────────

    def _get_or_create_key(self, kid: str) -> Ed25519PrivateKey:
        """Return the key for a versioned kid, loading from disk or generating fresh."""
        cached = self._cache.get(kid)
        if cached is not None:
            return cached
        on_disk = self._load_key_from_disk(kid)
        if on_disk is not None:
            self._cache[kid] = on_disk
            return on_disk
        key = Ed25519PrivateKey.generate()
        self._persist_key_to_disk(kid, key)
        self._cache[kid] = key
        return key

    def _get_existing_key(self, kid: str) -> Ed25519PrivateKey | None:
        """Return the key for a versioned kid if it exists; None otherwise."""
        cached = self._cache.get(kid)
        if cached is not None:
            return cached
        on_disk = self._load_key_from_disk(kid)
        if on_disk is not None:
            self._cache[kid] = on_disk
        return on_disk

    # ── Phase 14 backward-compat: resolve unversioned kid → v1 ───────────────

    def _resolve_kid(self, kid: str) -> str:
        """Resolve a potentially-unversioned Phase-14 kid to its canonical versioned form.

        If ``kid`` already contains ``#v`` it is returned unchanged.
        Otherwise it is treated as a tenant_id and mapped to ``{tenant_id}#v1``.
        This preserves full backward-compatibility with tokens issued by Phase 14/15/16
        which carry ``kid = tenant_id`` in their JOSE header.
        """
        if "#v" in kid:
            return kid
        return self._make_versioned_kid(kid, 1)

    # ── public API ───────────────────────────────────────────────────────────

    def private_pem(self, tenant_id: str) -> str:
        """Return the ACTIVE signing key as a PKCS#8 PEM, creating v1 on first call.

        Raises ``KeyError`` if key rotation is required but no ACTIVE key exists
        (should not occur in normal operation — ``rotate()`` always leaves one).
        """
        with self._lock:
            active = self._active_record(tenant_id)
            if active is None:
                # First-ever access: generate v1 and register it as ACTIVE.
                kid = self._make_versioned_kid(tenant_id, 1)
                key = self._get_or_create_key(kid)
                record = KeyRecord(
                    kid=kid,
                    version=1,
                    state=KeyState.ACTIVE,
                    created_at=time.time(),
                )
                records = [record]
                self._registry[tenant_id] = records
                self._persist_registry_to_disk(tenant_id, records)
                active = record
            else:
                key = self._get_or_create_key(active.kid)
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("ascii")

    def active_kid(self, tenant_id: str) -> str:
        """Return the versioned kid of the current ACTIVE key for a tenant.

        Calls ``private_pem`` to ensure v1 is created if this is the first access.
        """
        with self._lock:
            # Ensure the registry is populated.
            _ = self.private_pem.__wrapped__ if hasattr(self.private_pem, "__wrapped__") else None
            active = self._active_record(tenant_id)
            if active is not None:
                return active.kid
        # Not yet initialised — trigger first-access creation.
        self.private_pem(tenant_id)
        with self._lock:
            active = self._active_record(tenant_id)
            assert active is not None
            return active.kid

    def public_pem(self, kid: str) -> str | None:
        """Return the public key PEM for a kid (versioned or legacy unversioned).

        Verification must fail closed for an unknown kid — hence None rather than
        lazily minting a key (minting on *verify* would let any caller conjure a
        valid-looking tenant).

        Accepts both versioned kids (``tenant#v2``) and Phase-14 unversioned form
        (``tenant_id`` → resolved to ``tenant_id#v1`` transparently). Expired keys
        return None so tokens signed with them are rejected.
        """
        with self._lock:
            versioned = self._resolve_kid(kid)
            # Derive tenant_id from the versioned kid.
            tenant_id = versioned.split("#v")[0]
            # Check the registry state for this kid.
            records = self._get_registry(tenant_id)
            state_for_kid: KeyState | None = None
            for r in records:
                if r.kid == versioned:
                    state_for_kid = r.state
                    break
            if state_for_kid == KeyState.EXPIRED:
                return None  # reject — key has been retired
            if state_for_kid is None and records:
                # kid not in registry at all — unknown
                return None
            key = self._get_existing_key(versioned)
            if key is None:
                return None
            return key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("ascii")

    # ── key rotation ─────────────────────────────────────────────────────────

    def rotate(
        self,
        tenant_id: str,
        overlap_ttl_seconds: int | None = None,
        now: float | None = None,
    ) -> str:
        """Rotate the ACTIVE key for a tenant and return the new versioned kid.

        Steps (atomic under the lock):
        1. Ensure v1 exists (first-access creation if needed).
        2. Move current ACTIVE → RETIRING (records rotation_ts).
        3. Generate a new Ed25519 keypair, assign next version, write PEM.
        4. Register the new key as ACTIVE.
        5. Prune any RETIRING keys whose overlap window has already closed.
        6. Persist the updated registry to disk.

        ``overlap_ttl_seconds`` controls how long the old key remains in RETIRING
        state. During this window tokens signed with the old key are still verifiable.
        Defaults to ``self._default_overlap_ttl_seconds`` (config-driven).

        Returns the new versioned kid (e.g. ``"alpha#v2"``).
        """
        ttl = overlap_ttl_seconds if overlap_ttl_seconds is not None else self._default_overlap_ttl_seconds
        ts = now if now is not None else time.time()
        with self._lock:
            # Ensure v1 exists.
            self.private_pem(tenant_id)
            records = self._get_registry(tenant_id)

            # Move current ACTIVE → RETIRING.
            new_records: list[KeyRecord] = []
            for r in records:
                if r.state == KeyState.ACTIVE:
                    new_records.append(KeyRecord(
                        kid=r.kid,
                        version=r.version,
                        state=KeyState.RETIRING,
                        created_at=r.created_at,
                        rotated_at=ts,
                    ))
                else:
                    new_records.append(r)

            # Generate new ACTIVE key.
            new_version = max((r.version for r in new_records), default=0) + 1
            new_kid = self._make_versioned_kid(tenant_id, new_version)
            new_key = Ed25519PrivateKey.generate()
            self._persist_key_to_disk(new_kid, new_key)
            self._cache[new_kid] = new_key
            new_records.append(KeyRecord(
                kid=new_kid,
                version=new_version,
                state=KeyState.ACTIVE,
                created_at=ts,
            ))

            # Prune expired RETIRING keys.
            new_records = self._prune_records(new_records, ts, ttl)

            self._registry[tenant_id] = new_records
            self._persist_registry_to_disk(tenant_id, new_records)
        return new_kid

    def _prune_records(
        self,
        records: list[KeyRecord],
        now: float,
        overlap_ttl_seconds: int,
    ) -> list[KeyRecord]:
        """Mark RETIRING keys whose overlap window has closed as EXPIRED.

        EXPIRED keys are retained in the registry (for auditability) but their
        PEM is no longer needed for verification; they are excluded from JWKS.
        We keep the record so the version counter never resets.
        """
        result = []
        for r in records:
            if (
                r.state == KeyState.RETIRING
                and r.rotated_at is not None
                and now - r.rotated_at >= overlap_ttl_seconds
            ):
                result.append(KeyRecord(
                    kid=r.kid,
                    version=r.version,
                    state=KeyState.EXPIRED,
                    created_at=r.created_at,
                    rotated_at=r.rotated_at,
                ))
            else:
                result.append(r)
        return result

    def prune(
        self,
        tenant_id: str,
        now: float | None = None,
        overlap_ttl_seconds: int | None = None,
    ) -> int:
        """Explicitly prune expired RETIRING keys. Returns count of keys expired."""
        ts = now if now is not None else time.time()
        ttl = overlap_ttl_seconds if overlap_ttl_seconds is not None else self._default_overlap_ttl_seconds
        with self._lock:
            records = self._get_registry(tenant_id)
            new_records = self._prune_records(records, ts, ttl)
            expired_count = sum(
                1 for old, new in zip(records, new_records)
                if old.state == KeyState.RETIRING and new.state == KeyState.EXPIRED
            )
            if expired_count:
                self._registry[tenant_id] = new_records
                self._persist_registry_to_disk(tenant_id, new_records)
        return expired_count

    def retire_all(self, tenant_id: str, now: float | None = None) -> int:
        """Emergency: immediately expire ALL RETIRING keys for a tenant.

        This is a break-glass operation. It does not generate a new key — the
        caller must ensure a new ACTIVE key exists (via rotate()) before calling
        retire_all(), or all future token issuance will fail.

        Returns the count of keys moved from RETIRING → EXPIRED.
        """
        ts = now if now is not None else time.time()
        with self._lock:
            records = self._get_registry(tenant_id)
            new_records = []
            count = 0
            for r in records:
                if r.state == KeyState.RETIRING:
                    new_records.append(KeyRecord(
                        kid=r.kid,
                        version=r.version,
                        state=KeyState.EXPIRED,
                        created_at=r.created_at,
                        rotated_at=r.rotated_at if r.rotated_at is not None else ts,
                    ))
                    count += 1
                else:
                    new_records.append(r)
            self._registry[tenant_id] = new_records
            self._persist_registry_to_disk(tenant_id, new_records)
        return count

    # ── ops inspection ────────────────────────────────────────────────────────

    def key_info(self, tenant_id: str) -> dict:
        """Return a JSON-serialisable summary of the key registry for a tenant.

        Suitable for the GET /auth/keys/{tenant_id} ops endpoint.
        """
        with self._lock:
            records = self._get_registry(tenant_id)
        return {
            "tenant_id": tenant_id,
            "keys": [
                {
                    "kid": r.kid,
                    "version": r.version,
                    "state": r.state.value,
                    "created_at": r.created_at,
                    "rotated_at": r.rotated_at,
                }
                for r in records
            ],
            "active_kid": next(
                (r.kid for r in records if r.state == KeyState.ACTIVE), None
            ),
        }

    def known_tenants(self) -> list[str]:
        """All tenants with at least one key (in cache, registry, or on disk)."""
        with self._lock:
            tenants: set[str] = set(self._registry)
            if self._db_dir is not None:
                for f in self._db_dir.glob("*.json"):
                    tenants.add(f.stem)  # safe(tenant_id)
                # Also pick up unregistered v1 PEMs from Phase 14 deployments.
                for f in self._db_dir.glob("*.pem"):
                    stem = f.stem
                    # Only include flat (unversioned) PEMs — versioned ones have "#v" (→ "_v")
                    if "_v" not in stem:
                        tenants.add(stem)
            return sorted(tenants)

    # ── JWKS export (RFC 7517 / RFC 8037) ─────────────────────────────────────

    @staticmethod
    def _jwk_for(kid: str, public_key: Ed25519PublicKey) -> dict:
        raw = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": _b64url_no_pad(raw),
            "kid": kid,
            "alg": "EdDSA",
            "use": "sig",
        }

    def jwks(self) -> dict:
        """Export ACTIVE and RETIRING (non-expired) public keys as an RFC 7517 JWK Set.

        Verify-only material: contains no private keys. EXPIRED keys are omitted so
        tokens signed with a retired key are correctly rejected by downstream verifiers.
        A downstream verifier selects the right key by matching the token's ``kid``
        header to a JWK ``kid``.

        During a rotation overlap window, both the new ACTIVE key and the old RETIRING
        key appear in the JWKS, allowing tokens issued before and after the rotation to
        be validated simultaneously (RFC 9068 §4 / RFC 8725 §3.10).
        """
        keys = []
        with self._lock:
            for tenant_id in self.known_tenants():
                records = self._get_registry(tenant_id)
                if not records:
                    # Phase 14 legacy: no registry yet; synthesise a v1 record.
                    kid = self._make_versioned_kid(tenant_id, 1)
                    key = self._get_existing_key(kid)
                    # Also try the unversioned disk PEM (Phase 14 format).
                    if key is None:
                        key = self._load_key_from_disk(tenant_id)
                        if key is not None:
                            self._cache[kid] = key
                    if key is not None:
                        keys.append(self._jwk_for(kid, key.public_key()))
                    continue
                for r in records:
                    if r.state == KeyState.EXPIRED:
                        continue
                    key = self._get_existing_key(r.kid)
                    if key is not None:
                        keys.append(self._jwk_for(r.kid, key.public_key()))
        return {"keys": keys}
