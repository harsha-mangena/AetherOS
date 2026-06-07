"""Phase 16 tests: at-rest encryption for secret sinks.

Properties under test (atom of thoughts — smallest verifiable units):

  SecretBox unit:
    1.  encrypt then decrypt round-trips identical bytes for arbitrary plaintext.
    2.  Two encrypt calls on the same plaintext produce different ciphertext (random salt+nonce).
    3.  decrypt with wrong passphrase raises DecryptionError.
    4.  decrypt with one-byte tampered ciphertext raises DecryptionError.
    5.  decrypt with truncated envelope raises DecryptionError.
    6.  optional_box returns None for empty/None passphrase, SecretBox for non-empty.

  EncryptedRunStateStore unit:
    7.  persist then load round-trips state_json unchanged.
    8.  The inner store sees only ciphertext (not plaintext JSON).
    9.  load of a non-existent run_id returns None.
    10. delete removes the entry; subsequent load returns None.
    11. load_all returns all rows with decrypted state_json.
    12. DURABILITY: a new EncryptedRunStateStore over the same db_dir and passphrase
        correctly decrypts data written by the first instance (simulates restart).
    13. Wrong passphrase on a populated store raises DecryptionError on load.

  TenantKeyStore encryption unit:
    14. With passphrase: a generated key round-trips through persist+load; the on-disk
        PEM bytes are *not* the plaintext PKCS#8 PEM (i.e. they are encrypted).
    15. With passphrase: a new TenantKeyStore over the same dir+passphrase recovers the
        identical public key (simulates restart — the private key survives encryption).
    16. Without passphrase: PEM file is plaintext (begins with "-----BEGIN PRIVATE KEY-----").
    17. Wrong passphrase on an encrypted PEM raises an exception on load.

  Config integration:
    18. StorageConfig default: encryption_passphrase is "".
    19. AuthConfig default: keystore_passphrase is "".
    20. make_run_state_store with backend="sqlite" + passphrase wraps with
        EncryptedRunStateStore; without passphrase returns SQLiteRunStateStore directly.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from aetheros_orchestrator.secret_box import DecryptionError, SecretBox, optional_box
from aetheros_orchestrator.run_state_store import (
    EncryptedRunStateStore,
    SQLiteRunStateStore,
    make_run_state_store,
)
from aetheros_orchestrator.token_keystore import TenantKeyStore
from aetheros_orchestrator.config import StorageConfig, AuthConfig


_PASSPHRASE = "test-phase16-passphrase-secure!!"
_STATE = '{"run_id": "r1", "status": "pending", "seed_hex": "deadbeef"}'
_TENANT = "tenant_enc"
_RUN = "run_enc_1"


# ── 1-6. SecretBox unit ────────────────────────────────────────────────────────


def test_secret_box_round_trip():
    box = SecretBox(_PASSPHRASE)
    plaintext = b"hello secret world"
    assert box.decrypt(box.encrypt(plaintext)) == plaintext


def test_secret_box_different_ciphertext_same_plaintext():
    box = SecretBox(_PASSPHRASE)
    p = b"same plaintext"
    assert box.encrypt(p) != box.encrypt(p)


def test_secret_box_wrong_passphrase():
    box = SecretBox(_PASSPHRASE)
    enc = box.encrypt(b"sensitive")
    wrong = SecretBox("wrong-passphrase!!")
    with pytest.raises(DecryptionError):
        wrong.decrypt(enc)


def test_secret_box_tampered_ciphertext():
    box = SecretBox(_PASSPHRASE)
    enc = bytearray(box.encrypt(b"sensitive"))
    enc[-1] ^= 0xFF  # flip last byte of GCM tag
    with pytest.raises(DecryptionError):
        box.decrypt(bytes(enc))


def test_secret_box_truncated_envelope():
    box = SecretBox(_PASSPHRASE)
    with pytest.raises(DecryptionError):
        box.decrypt(b"\x01" + b"\x00" * 5)


def test_optional_box():
    assert optional_box("") is None
    assert optional_box(None) is None
    box = optional_box(_PASSPHRASE)
    assert isinstance(box, SecretBox)


# ── 7-13. EncryptedRunStateStore unit ─────────────────────────────────────────


def _make_enc_store(db_dir: str, passphrase: str = _PASSPHRASE) -> EncryptedRunStateStore:
    inner = SQLiteRunStateStore(db_dir=db_dir)
    box = SecretBox(passphrase)
    return EncryptedRunStateStore(inner, box)


def test_encrypted_store_round_trip(tmp_path):
    store = _make_enc_store(str(tmp_path))
    store.persist(_TENANT, _RUN, _STATE)
    assert store.load(_TENANT, _RUN) == _STATE


def test_encrypted_store_inner_sees_ciphertext(tmp_path):
    store = _make_enc_store(str(tmp_path))
    store.persist(_TENANT, _RUN, _STATE)
    # Read directly from inner store — should be hex ciphertext, not plaintext JSON
    inner_raw = store._inner.load(_TENANT, _RUN)
    assert inner_raw is not None
    assert "seed_hex" not in inner_raw
    assert "deadbeef" not in inner_raw


def test_encrypted_store_load_missing(tmp_path):
    store = _make_enc_store(str(tmp_path))
    assert store.load(_TENANT, "no-such-run") is None


def test_encrypted_store_delete(tmp_path):
    store = _make_enc_store(str(tmp_path))
    store.persist(_TENANT, _RUN, _STATE)
    store.delete(_TENANT, _RUN)
    assert store.load(_TENANT, _RUN) is None


def test_encrypted_store_load_all(tmp_path):
    store = _make_enc_store(str(tmp_path))
    store.persist(_TENANT, "run1", '{"id": "run1"}')
    store.persist(_TENANT, "run2", '{"id": "run2"}')
    rows = store.load_all(_TENANT)
    assert len(rows) == 2
    jsons = {r[2] for r in rows}
    assert '{"id": "run1"}' in jsons
    assert '{"id": "run2"}' in jsons


def test_encrypted_store_durability(tmp_path):
    """New store over same dir+passphrase decrypts data written by first store."""
    store1 = _make_enc_store(str(tmp_path))
    store1.persist(_TENANT, _RUN, _STATE)
    # Simulate restart: new instance
    store2 = _make_enc_store(str(tmp_path))
    assert store2.load(_TENANT, _RUN) == _STATE


def test_encrypted_store_wrong_passphrase(tmp_path):
    store1 = _make_enc_store(str(tmp_path), passphrase=_PASSPHRASE)
    store1.persist(_TENANT, _RUN, _STATE)
    store2 = _make_enc_store(str(tmp_path), passphrase="wrong-passphrase!!")
    with pytest.raises(DecryptionError):
        store2.load(_TENANT, _RUN)


# ── 14-17. TenantKeyStore encryption unit ─────────────────────────────────────


def test_keystore_encrypted_round_trip(tmp_path):
    ks = TenantKeyStore(db_dir=str(tmp_path), passphrase=_PASSPHRASE)
    pub1 = ks.public_pem("tenant_A")
    # Reload from disk
    ks2 = TenantKeyStore(db_dir=str(tmp_path), passphrase=_PASSPHRASE)
    pub2 = ks2.public_pem("tenant_A")
    assert pub1 == pub2


def test_keystore_pem_is_encrypted_on_disk(tmp_path):
    ks = TenantKeyStore(db_dir=str(tmp_path), passphrase=_PASSPHRASE)
    ks.private_pem("tenant_B")  # triggers key generation + persist
    pem_file = next(tmp_path.glob("*.pem"))
    content = pem_file.read_bytes().decode("ascii")
    # Encrypted PKCS#8 PEM begins with ENCRYPTED PRIVATE KEY, not PRIVATE KEY
    assert "ENCRYPTED PRIVATE KEY" in content
    assert "-----BEGIN PRIVATE KEY-----" not in content


def test_keystore_plaintext_pem_without_passphrase(tmp_path):
    ks = TenantKeyStore(db_dir=str(tmp_path))  # no passphrase
    ks.private_pem("tenant_C")
    pem_file = next(tmp_path.glob("*.pem"))
    content = pem_file.read_bytes().decode("ascii")
    assert "-----BEGIN PRIVATE KEY-----" in content


def test_keystore_wrong_passphrase_on_load(tmp_path):
    ks = TenantKeyStore(db_dir=str(tmp_path), passphrase=_PASSPHRASE)
    ks.private_pem("tenant_D")
    ks_wrong = TenantKeyStore(db_dir=str(tmp_path), passphrase="wrong!!")
    with pytest.raises(Exception):
        ks_wrong.private_pem("tenant_D")


# ── 18-20. Config integration ─────────────────────────────────────────────────


def test_storage_config_defaults():
    cfg = StorageConfig()
    assert cfg.encryption_passphrase == ""


def test_auth_config_defaults():
    cfg = AuthConfig()
    assert cfg.keystore_passphrase == ""


def test_make_run_state_store_encrypted(tmp_path):
    store = make_run_state_store(
        backend="sqlite",
        db_dir=str(tmp_path),
        passphrase=_PASSPHRASE,
    )
    assert isinstance(store, EncryptedRunStateStore)


def test_make_run_state_store_plaintext(tmp_path):
    store = make_run_state_store(backend="sqlite", db_dir=str(tmp_path))
    assert isinstance(store, SQLiteRunStateStore)
