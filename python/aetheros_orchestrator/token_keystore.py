"""Per-tenant Ed25519 token keystore — Phase 14.

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

Design (atom of thoughts)
─────────────────────────
The smallest independently verifiable properties of this keystore:
1. ``private_pem(tenant_id)`` returns a stable Ed25519 private key for a tenant,
   generating + persisting one on first request (idempotent thereafter).
2. ``public_pem(tenant_id)`` returns the matching public key, or None if the tenant
   has no key yet (verification of an unknown tenant must fail closed).
3. Keys persist across restarts when a ``db_dir`` is configured; an empty dir gives
   an ephemeral in-memory keystore (keys regenerate each process — dev/test only).
4. ``jwks()`` exports every known tenant's public key as an RFC 7517 JWK set with
   ``kty = OKP``, ``crv = Ed25519`` (RFC 8037), and ``kid = tenant_id``.

Standards / research net
────────────────────────
* RFC 8032 — Edwards-Curve Digital Signature Algorithm (Ed25519).
* RFC 8037 — CFRG curves (Ed25519) for JOSE; the ``EdDSA`` ``alg`` and ``OKP`` ``kty``.
* RFC 7517 — JSON Web Key (JWK) and JWK Set.
* RFC 7638 — JWK Thumbprint (used to derive a stable ``kid`` is optional; we use
  ``tenant_id`` directly as ``kid`` since it is the natural routing key here).

The signing primitive is the ``cryptography`` library's Ed25519 (the same primitive
family the Rust kernel uses for ``AgentIdentity``), kept deliberately separate from
the kernel: control-plane tokens are a public JOSE boundary artifact, not an internal
kernel serialization, so they must not couple to kernel byte formats.
"""

from __future__ import annotations

import base64
import threading
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    NoEncryption,
)


def _b64url_no_pad(raw: bytes) -> str:
    """Base64url-encode without padding (JOSE convention, RFC 7515 §2)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class TenantKeyStore:
    """Per-tenant Ed25519 keypairs for EdDSA token signing.

    Thread-safe. When ``db_dir`` is a non-empty path, each tenant's private key is
    written there as a PKCS#8 PEM (``<safe_tenant>.pem``) on first generation, so
    issued tokens remain verifiable across process restarts. When ``db_dir`` is
    empty, keys live only in memory.

    Path traversal in ``tenant_id`` is neutralised the same way the ledger and
    run-state stores sanitise tenant identifiers before touching the filesystem.
    """

    def __init__(self, db_dir: str | Path = "", passphrase: str = "") -> None:
        self._db_dir = Path(db_dir) if db_dir else None
        if self._db_dir is not None:
            self._db_dir.mkdir(parents=True, exist_ok=True)
        self._cache: dict[str, Ed25519PrivateKey] = {}
        self._lock = threading.RLock()
        # Phase 16: when non-empty, PKCS#8 PEM files are encrypted with PBES2
        # (BestAvailableEncryption = PBKDF2-HMAC-SHA512 + AES-256-CBC, RFC 8018 §6.2).
        # Empty passphrase = plaintext PEM, byte-for-byte identical to Phase 14/15.
        self._passphrase: bytes = passphrase.encode("utf-8") if passphrase else b""

    # ── filesystem helpers ────────────────────────────────────────────────────

    @staticmethod
    def _safe(tenant_id: str) -> str:
        return "".join(c if c.isalnum() or c in "-_" else "_" for c in tenant_id)

    def _key_path(self, tenant_id: str) -> Path | None:
        if self._db_dir is None:
            return None
        return self._db_dir / f"{self._safe(tenant_id)}.pem"

    def _load_from_disk(self, tenant_id: str) -> Ed25519PrivateKey | None:
        path = self._key_path(tenant_id)
        if path is None or not path.exists():
            return None
        password = self._passphrase if self._passphrase else None
        key = serialization.load_pem_private_key(path.read_bytes(), password=password)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError(f"keystore file for tenant {tenant_id!r} is not Ed25519")
        return key

    def _persist_to_disk(self, tenant_id: str, key: Ed25519PrivateKey) -> None:
        path = self._key_path(tenant_id)
        if path is None:
            return
        # Phase 16: use PKCS#8 PBES2 encryption when a passphrase is configured
        # (RFC 8018 §6.2 — BestAvailableEncryption selects PBKDF2-HMAC-SHA512 +
        # AES-256-CBC, which is what the cryptography library emits for Ed25519
        # keys).  Plaintext mode (empty passphrase) is byte-for-byte identical to
        # all prior phases.
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
        # Write atomically and restrict permissions — this is secret signing material.
        tmp = path.with_suffix(".pem.tmp")
        tmp.write_bytes(pem)
        try:
            tmp.chmod(0o600)
        except OSError:  # pragma: no cover — best effort on exotic filesystems
            pass
        tmp.replace(path)

    # ── key access ────────────────────────────────────────────────────────────

    def _get_or_create(self, tenant_id: str) -> Ed25519PrivateKey:
        with self._lock:
            cached = self._cache.get(tenant_id)
            if cached is not None:
                return cached
            on_disk = self._load_from_disk(tenant_id)
            if on_disk is not None:
                self._cache[tenant_id] = on_disk
                return on_disk
            key = Ed25519PrivateKey.generate()
            self._persist_to_disk(tenant_id, key)
            self._cache[tenant_id] = key
            return key

    def _get_existing(self, tenant_id: str) -> Ed25519PrivateKey | None:
        with self._lock:
            cached = self._cache.get(tenant_id)
            if cached is not None:
                return cached
            on_disk = self._load_from_disk(tenant_id)
            if on_disk is not None:
                self._cache[tenant_id] = on_disk
            return on_disk

    def private_pem(self, tenant_id: str) -> str:
        """Return the tenant's signing key as a PKCS#8 PEM, creating it if absent."""
        key = self._get_or_create(tenant_id)
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("ascii")

    def public_pem(self, tenant_id: str) -> str | None:
        """Return the tenant's public key PEM, or None if the tenant has no key.

        Verification must fail closed for an unknown tenant — hence None rather than
        lazily minting a key (minting on *verify* would let any caller conjure a
        valid-looking tenant).
        """
        key = self._get_existing(tenant_id)
        if key is None:
            return None
        return key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def known_tenants(self) -> list[str]:
        """All tenants with a key (in cache or on disk)."""
        with self._lock:
            tenants = set(self._cache)
            if self._db_dir is not None:
                for pem in self._db_dir.glob("*.pem"):
                    tenants.add(pem.stem)
            return sorted(tenants)

    # ── JWKS export (RFC 7517 / RFC 8037) ─────────────────────────────────────

    @staticmethod
    def _jwk_for(tenant_id: str, public_key: Ed25519PublicKey) -> dict:
        raw = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": _b64url_no_pad(raw),
            "kid": tenant_id,
            "alg": "EdDSA",
            "use": "sig",
        }

    def jwks(self) -> dict:
        """Export all known tenant public keys as an RFC 7517 JWK Set.

        Verify-only material: contains no private keys. A downstream verifier can
        select the right key by matching the token's ``kid`` header to a JWK ``kid``.
        """
        keys = []
        for tenant_id in self.known_tenants():
            key = self._get_existing(tenant_id)
            if key is not None:
                keys.append(self._jwk_for(tenant_id, key.public_key()))
        return {"keys": keys}
