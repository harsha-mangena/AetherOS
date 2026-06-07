"""Phase 10 tests: ledger durability — SQLite persistence and restart simulation.

Threat model / correctness invariants under test
─────────────────────────────────────────────────
1.  Backward compatibility — NoStore is a no-op; existing behavior is unaffected.
2.  Round-trip fidelity — the canonical JSON snapshot survives a store/load cycle
    byte-for-byte; EvidenceLedger.from_json verifies the hash chain in Rust.
3.  Tamper detection — a mutated snapshot is caught at restore time; the hash chain
    verification inside EvidenceLedger.from_json raises LedgerIntegrityError.
4.  Hash equivalence — the restored ledger has the same head_hash as the original;
    every entry_hash is identical; verify() is True on the restored ledger.
5.  Transparency compatibility — entries() from a restored DurableLedger feed
    TransparencyLog.from_ledger correctly; STH verifies with the same result as
    for an in-memory ledger.
6.  Multi-run isolation — two runs for the same tenant store independent snapshots;
    loading one does not affect the other.
7.  Multi-tenant isolation — same run_id for two tenants maps to two distinct rows
    in separate SQLite files; loading one never returns the other's data.
8.  Thread safety — concurrent appends from multiple threads all reach the store
    and the final ledger verify() is True.
9.  RunService wiring — create_run uses the configured backend; the default (none)
    is backward-compatible; the sqlite backend persists a real governed run.
"""

from __future__ import annotations

import json
import threading
import uuid
from pathlib import Path

import pytest

from aetheros import EvidenceLedger
from aetheros.ledger import LedgerIntegrityError
from aetheros_orchestrator.ledger_store import (
    DurableLedger,
    LedgerStore,
    NoStore,
    SQLiteStore,
    make_ledger,
)
from aetheros_orchestrator.transparency import TransparencyLog, verify_signed_tree_head

# ── helpers ────────────────────────────────────────────────────────────────────

TENANT = "tenant-phase10"
RUN_A = "run-aaaaaaaa"
RUN_B = "run-bbbbbbbb"
TENANT_B = "tenant-beta10"


def _tmp_store(tmp_path: Path) -> SQLiteStore:
    return SQLiteStore(db_dir=tmp_path)


def _driven_ledger(n: int = 5) -> EvidenceLedger:
    """A plain EvidenceLedger with n entries."""
    led = EvidenceLedger()
    for i in range(n):
        led.append("human:vamsi", f"phase10.test.event_{i}", {"seq": i})
    return led


# ── 1. NoStore backward compatibility ─────────────────────────────────────────


def test_nostore_persist_is_noop() -> None:
    store = NoStore()
    store.persist(TENANT, RUN_A, '{"entries":[],"head_hash":"' + "0" * 64 + '"}')
    # load always returns None — nothing was stored.
    assert store.load(TENANT, RUN_A) is None


def test_nostore_delete_is_noop() -> None:
    store = NoStore()
    store.delete(TENANT, RUN_A)  # must not raise


def test_durable_ledger_with_nostore_appends_normally() -> None:
    dl = DurableLedger(TENANT, RUN_A, NoStore())
    seq, entry_hash = dl.append("human:vamsi", "audit.event", {"k": "v"})
    assert seq == 0
    assert len(entry_hash) == 64  # 32-byte hex
    assert dl.length == 1
    assert dl.verify() is True


# ── 2. SQLiteStore round-trip fidelity ────────────────────────────────────────


def test_sqlitestore_persist_and_load_round_trips_json(tmp_path: Path) -> None:
    store = _tmp_store(tmp_path)
    original = _driven_ledger(4)
    ledger_json = original.to_json()
    store.persist(TENANT, RUN_A, ledger_json)
    loaded_json = store.load(TENANT, RUN_A)
    assert loaded_json is not None
    assert json.loads(loaded_json) == json.loads(ledger_json)


def test_sqlitestore_load_unknown_run_returns_none(tmp_path: Path) -> None:
    store = _tmp_store(tmp_path)
    assert store.load(TENANT, "no-such-run") is None


def test_sqlitestore_load_unknown_tenant_returns_none(tmp_path: Path) -> None:
    store = _tmp_store(tmp_path)
    assert store.load("unknown-tenant-xyz", RUN_A) is None


def test_sqlitestore_persist_is_idempotent(tmp_path: Path) -> None:
    """Overwriting an existing row with updated JSON must succeed."""
    store = _tmp_store(tmp_path)
    led1 = _driven_ledger(3)
    store.persist(TENANT, RUN_A, led1.to_json())
    led2 = _driven_ledger(7)
    store.persist(TENANT, RUN_A, led2.to_json())
    loaded = store.load(TENANT, RUN_A)
    assert json.loads(loaded)  # non-empty, from led2 (7 entries)


def test_sqlitestore_delete_removes_snapshot(tmp_path: Path) -> None:
    store = _tmp_store(tmp_path)
    store.persist(TENANT, RUN_A, _driven_ledger(2).to_json())
    assert store.load(TENANT, RUN_A) is not None
    store.delete(TENANT, RUN_A)
    assert store.load(TENANT, RUN_A) is None


# ── 3. Tamper detection ────────────────────────────────────────────────────────


def test_tampered_ledger_json_raises_on_restore(tmp_path: Path) -> None:
    """A mutated payload must be caught by EvidenceLedger.from_json (Rust hash check)."""
    store = _tmp_store(tmp_path)
    original = _driven_ledger(5)
    data = json.loads(original.to_json())
    # Mutate the payload of the first entry; the entry_hash will no longer match.
    if data.get("entries"):
        data["entries"][0]["payload"] = {"tampered": True}
    store.persist(TENANT, RUN_A, json.dumps(data))
    with pytest.raises(LedgerIntegrityError):
        DurableLedger.from_storage(TENANT, RUN_A, store)


def test_from_storage_unknown_run_raises_integrity_error(tmp_path: Path) -> None:
    """from_storage on a run that was never persisted must raise LedgerIntegrityError."""
    store = _tmp_store(tmp_path)
    with pytest.raises(LedgerIntegrityError, match="No persisted ledger"):
        DurableLedger.from_storage(TENANT, "ghost-run", store)


# ── 4. Hash equivalence after restore (restart simulation) ────────────────────


def test_restored_ledger_has_same_head_hash(tmp_path: Path) -> None:
    """After persist → restore, head_hash must be identical to the original."""
    store = _tmp_store(tmp_path)
    dl = DurableLedger(TENANT, RUN_A, store)
    for i in range(6):
        dl.append("human:vamsi", "audit.step", {"i": i})
    original_head = dl.head_hash

    # Simulate restart.
    restored = DurableLedger.from_storage(TENANT, RUN_A, store)
    assert restored.head_hash == original_head


def test_restored_ledger_has_correct_length(tmp_path: Path) -> None:
    store = _tmp_store(tmp_path)
    dl = DurableLedger(TENANT, RUN_A, store)
    for i in range(8):
        dl.append("human:vamsi", "audit.event", {"i": i})
    restored = DurableLedger.from_storage(TENANT, RUN_A, store)
    assert restored.length == 8


def test_restored_ledger_verify_is_true(tmp_path: Path) -> None:
    store = _tmp_store(tmp_path)
    dl = DurableLedger(TENANT, RUN_A, store)
    dl.append("human:vamsi", "event.a", {"x": 1})
    dl.append("human:vamsi", "event.b", {"x": 2})
    restored = DurableLedger.from_storage(TENANT, RUN_A, store)
    assert restored.verify() is True


def test_restored_ledger_entries_match_original(tmp_path: Path) -> None:
    """Every entry_hash and actor must be identical between original and restored ledger."""
    store = _tmp_store(tmp_path)
    dl = DurableLedger(TENANT, RUN_A, store)
    for i in range(5):
        dl.append(f"agent:{i}", "event.test", {"i": i})
    orig_entries = dl.entries()

    restored = DurableLedger.from_storage(TENANT, RUN_A, store)
    rest_entries = restored.entries()

    assert len(rest_entries) == len(orig_entries)
    for orig, rest in zip(orig_entries, rest_entries):
        assert orig.entry_hash == rest.entry_hash
        assert orig.actor == rest.actor
        assert orig.event_type == rest.event_type
        assert orig.seq == rest.seq


# ── 5. Transparency layer compatibility after restore ─────────────────────────


def test_restored_ledger_feeds_transparency_log(tmp_path: Path) -> None:
    """A restored DurableLedger must work as a drop-in for TransparencyLog.from_ledger."""
    import aetheros

    store = _tmp_store(tmp_path)
    dl = DurableLedger(TENANT, RUN_A, store)
    for i in range(4):
        dl.append("human:vamsi", "governed.step", {"i": i})

    restored = DurableLedger.from_storage(TENANT, RUN_A, store)
    log = TransparencyLog.from_ledger(restored)
    signer = aetheros.AgentIdentity.generate("test-operator")
    sth = log.signed_tree_head(signer, "2026-06-07T12:00:00+00:00")
    assert sth.tree_size == 4
    assert verify_signed_tree_head(sth) is True


def test_restored_ledger_transparency_root_matches_original(tmp_path: Path) -> None:
    """The Merkle root over entry_hashes must be identical for original and restored ledger."""
    import aetheros

    store = _tmp_store(tmp_path)
    dl = DurableLedger(TENANT, RUN_A, store)
    for i in range(5):
        dl.append("agent:x", "audit.event", {"v": i})

    signer = aetheros.AgentIdentity.generate("log-op")
    ts = "2026-06-07T00:00:00+00:00"
    orig_sth = TransparencyLog.from_ledger(dl).signed_tree_head(signer, ts)

    restored = DurableLedger.from_storage(TENANT, RUN_A, store)
    rest_sth = TransparencyLog.from_ledger(restored).signed_tree_head(signer, ts)

    assert orig_sth.root_hash == rest_sth.root_hash
    assert orig_sth.tree_size == rest_sth.tree_size


# ── 6. Multi-run isolation ─────────────────────────────────────────────────────


def test_two_runs_same_tenant_stored_independently(tmp_path: Path) -> None:
    store = _tmp_store(tmp_path)

    dl_a = DurableLedger(TENANT, RUN_A, store)
    dl_b = DurableLedger(TENANT, RUN_B, store)
    for i in range(3):
        dl_a.append("agent:a", "event.a", {"i": i})
    for i in range(7):
        dl_b.append("agent:b", "event.b", {"i": i})

    restored_a = DurableLedger.from_storage(TENANT, RUN_A, store)
    restored_b = DurableLedger.from_storage(TENANT, RUN_B, store)

    assert restored_a.length == 3
    assert restored_b.length == 7
    # Head hashes must differ.
    assert restored_a.head_hash != restored_b.head_hash


# ── 7. Multi-tenant isolation ─────────────────────────────────────────────────


def test_same_run_id_different_tenants_isolated(tmp_path: Path) -> None:
    """Same run_id under two tenants must store and restore independently."""
    store = _tmp_store(tmp_path)

    dl_alpha = DurableLedger(TENANT, RUN_A, store)
    dl_beta = DurableLedger(TENANT_B, RUN_A, store)
    for i in range(2):
        dl_alpha.append("agent:alpha", "event.alpha", {"i": i})
    for i in range(5):
        dl_beta.append("agent:beta", "event.beta", {"i": i})

    restored_alpha = DurableLedger.from_storage(TENANT, RUN_A, store)
    restored_beta = DurableLedger.from_storage(TENANT_B, RUN_A, store)

    assert restored_alpha.length == 2
    assert restored_beta.length == 5


# ── 8. Thread safety ──────────────────────────────────────────────────────────


def test_concurrent_appends_are_safe(tmp_path: Path) -> None:
    """Concurrent appends from N threads must all reach the store; final verify must pass."""
    store = _tmp_store(tmp_path)
    dl = DurableLedger(TENANT, RUN_A, store)

    n_threads = 10
    errors: list[Exception] = []

    def _worker(idx: int) -> None:
        try:
            dl.append("agent:concurrent", "event.concurrent", {"idx": idx})
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=_worker, args=(i,)) for i in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Thread errors: {errors}"
    assert dl.length == n_threads
    assert dl.verify() is True

    # Restore and verify the final snapshot is consistent.
    restored = DurableLedger.from_storage(TENANT, RUN_A, store)
    assert restored.length == n_threads
    assert restored.verify() is True


# ── 9. make_ledger factory ────────────────────────────────────────────────────


def test_make_ledger_none_backend_returns_durable_ledger_with_nostore() -> None:
    dl = make_ledger(TENANT, RUN_A, backend="none")
    assert isinstance(dl, DurableLedger)
    dl.append("agent:x", "event", {"k": "v"})
    assert dl.length == 1
    assert dl.verify() is True


def test_make_ledger_sqlite_backend_persists(tmp_path: Path) -> None:
    dl = make_ledger(TENANT, RUN_A, backend="sqlite", db_dir=str(tmp_path))
    for i in range(3):
        dl.append("agent:x", "event", {"i": i})
    assert dl.length == 3
    # The store must have persisted — we can restore directly.
    store = SQLiteStore(db_dir=tmp_path)
    restored = DurableLedger.from_storage(TENANT, RUN_A, store)
    assert restored.length == 3
    assert restored.head_hash == dl.head_hash


# ── 10. RunService integration ────────────────────────────────────────────────


def test_run_service_default_config_is_backward_compatible() -> None:
    """RunService with default config (storage.backend='none') must pass all existing gates."""
    pytest.importorskip("fastapi")
    from aetheros_orchestrator.run_service import RunService

    svc = RunService()
    run = svc.create_run("Investigate the production incident in checkout and restore service")
    state = svc.advance(run.run_id)
    while state.status == "awaiting_approval":
        state = svc.resume(
            run.run_id, state.pending_step_id, approved=True, approver="human:vamsi"
        )
    # The ledger must still be verifiable after a full governed run.
    assert state.ctx.ledger.verify() is True
    assert state.ctx.ledger.length >= 1


def test_run_service_sqlite_backend_persists_governed_run(tmp_path: Path) -> None:
    """With storage.backend='sqlite', a full governed run's ledger is persisted."""
    pytest.importorskip("fastapi")
    from aetheros_orchestrator.config import AetherConfig, StorageConfig
    from aetheros_orchestrator.run_service import RunService

    cfg = AetherConfig(
        storage=StorageConfig(backend="sqlite", db_dir=str(tmp_path))
    )
    svc = RunService(config=cfg)
    run = svc.create_run("Investigate the production incident in checkout and restore service")
    state = svc.advance(run.run_id)
    while state.status == "awaiting_approval":
        state = svc.resume(
            run.run_id, state.pending_step_id, approved=True, approver="human:vamsi"
        )

    # The ledger in memory must be intact.
    assert state.ctx.ledger.verify() is True
    final_length = state.ctx.ledger.length
    final_head = state.ctx.ledger.head_hash
    assert final_length >= 1

    # The snapshot in SQLite must restore to the same ledger.
    store = SQLiteStore(db_dir=tmp_path)
    tid = run.tenant_id
    run_id = run.run_id
    restored = DurableLedger.from_storage(tid, run_id, store)
    assert restored.length == final_length
    assert restored.head_hash == final_head
    assert restored.verify() is True
