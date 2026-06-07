"""At-rest encryption primitive — Phase 16.

Provides a versioned, authenticated encryption envelope used by both secret sinks:
run-state SQLite (contains Ed25519 seed_hex) and per-tenant PKCS#8 keystore PEM files.

Design
──────
Algorithm:  AES-256-GCM (NIST SP 800-38D) — authenticated encryption so any
            tampering or wrong-passphrase attempt raises ``DecryptionError`` rather
            than silently returning garbage.
KDF:        scrypt (RFC 7914, Percival 2009) — memory-hard key derivation from the
            operator passphrase.  N=2¹⁷, r=8, p=1 (the RFC §4 recommended
            parameters) derive a 256-bit key; a fresh random 32-byte salt is
            generated per message so the same passphrase never produces the same
            key twice and a precomputed-table attack is infeasible.
Nonce:      12 bytes (96 bits), fresh random per message (SP 800-38D §8.2.2).
            AESGCM.encrypt appends the 16-byte GCM authentication tag to the
            ciphertext so a single ``encrypt`` call produces authenticated output.
Envelope:   VERSION(1) || SALT(32) || NONCE(12) || CIPHERTEXT+TAG(variable)
            The leading version byte allows future KDF/cipher migration: a decrypt
            call that finds an unknown version raises ``DecryptionError`` rather
            than silently misinterpreting the bytes.

Backward-compatibility
──────────────────────
When ``passphrase`` is empty or None, ``SecretBox`` is not constructed; callers use
the ``SecretBox.is_active(passphrase)`` helper to guard construction, and the
``optional_box`` factory returns None so existing code paths continue to write/read
plaintext, byte-for-byte identical to all prior phases.

Thread-safety: every ``SecretBox`` instance is stateless after construction —
``encrypt`` and ``decrypt`` create fresh KDF contexts per call so concurrent calls
do not race on shared mutable state.

References
──────────
* NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation — Galois/Counter Mode (GCM).
* RFC 7914: The scrypt Password-Based Key Derivation Function.
* RFC 8018: PKCS #5 v2.1 — Password-Based Cryptography Specification.
"""
from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Envelope layout constants
_VERSION = b"\x01"
_SALT_LEN = 32   # bytes — unique per message, prevents precomputed-table attacks
_NONCE_LEN = 12  # bytes — 96-bit GCM nonce, SP 800-38D §8.2.2 recommended size
_TAG_LEN = 16    # bytes — GCM authentication tag appended by AESGCM.encrypt

# scrypt cost parameters (RFC 7914 §4 recommended: N=2^17 for interactive login;
# we use 2^17 for at-rest where the cost is paid once per persist/load, giving
# ~128 MiB memory hardness against brute force on a stolen DB or PEM file).
_SCRYPT_N = 131072  # 2^17
_SCRYPT_R = 8
_SCRYPT_P = 1
_KEY_LEN = 32  # 256-bit AES key


class DecryptionError(Exception):
    """Raised when decryption fails: wrong passphrase, tampered ciphertext, or unknown version."""


class SecretBox:
    """Authenticated envelope encryptor backed by AES-256-GCM + scrypt.

    Construct with a non-empty passphrase.  For optional encryption (passphrase
    may be absent), use the module-level ``optional_box`` factory instead, which
    returns None when the passphrase is empty.
    """

    def __init__(self, passphrase: str) -> None:
        if not passphrase:
            raise ValueError("passphrase must be a non-empty string")
        self._passphrase = passphrase.encode("utf-8")

    # ── key derivation ─────────────────────────────────────────────────────────

    def _derive_key(self, salt: bytes) -> bytes:
        """Derive a 256-bit AES key from the passphrase + per-message salt via scrypt."""
        kdf = Scrypt(
            salt=salt,
            length=_KEY_LEN,
            n=_SCRYPT_N,
            r=_SCRYPT_R,
            p=_SCRYPT_P,
        )
        return kdf.derive(self._passphrase)

    # ── public API ────────────────────────────────────────────────────────────

    def encrypt(self, plaintext: bytes) -> bytes:
        """Return a versioned authenticated-encryption envelope of ``plaintext``.

        The returned bytes are safe to store in SQLite or on disk.  Every call
        produces different output even for identical plaintext (random salt + nonce).
        """
        salt = os.urandom(_SALT_LEN)
        nonce = os.urandom(_NONCE_LEN)
        key = self._derive_key(salt)
        ct_and_tag = AESGCM(key).encrypt(nonce, plaintext, None)
        return _VERSION + salt + nonce + ct_and_tag

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt and authenticate an envelope produced by ``encrypt``.

        Raises ``DecryptionError`` on wrong passphrase, tampered data, or unknown
        version byte — the caller must not proceed if this raises.
        """
        _HEADER = 1 + _SALT_LEN + _NONCE_LEN  # 45 bytes
        if len(data) < _HEADER + _TAG_LEN:
            raise DecryptionError("envelope too short")
        version = data[:1]
        if version != _VERSION:
            raise DecryptionError(f"unknown envelope version {version!r}")
        salt = data[1: 1 + _SALT_LEN]
        nonce = data[1 + _SALT_LEN: _HEADER]
        ct_and_tag = data[_HEADER:]
        key = self._derive_key(salt)
        try:
            return AESGCM(key).decrypt(nonce, ct_and_tag, None)
        except InvalidTag as exc:
            raise DecryptionError("decryption failed: wrong passphrase or tampered data") from exc


# ── convenience helpers ────────────────────────────────────────────────────────


def optional_box(passphrase: str | None) -> SecretBox | None:
    """Return a SecretBox when ``passphrase`` is non-empty, else None (plaintext mode)."""
    if passphrase:
        return SecretBox(passphrase)
    return None
