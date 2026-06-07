"""Phase 13 tests: run-state durability — resumable governed runs survive a restart.

Threat model / correctness invariants under test
─────────────────────────────────────────────────
Phase 10 made the evidence ledger durable. Phase 13 makes the *run* durable: the
resumable state machine (status, plan cursor, pending human-approval gate, results)
together with the governance authority that holds it (signed capability lease + the
agent identities + earned-autonomy tier). The invariants:

 1.  Backward compatibility — NoRunStateStore is a no-op; the default RunService
     (persist_runs=False) behaves exactly as before, and no run state touches disk.
 2.  Store round-trip — SQLiteRunStateStore persist/load/delete behave correctly,
     including load_all for startup repopulation.
 3.  Restart fidelity at a human gate — a run paused at AWAITING_APPROVAL is fully
     reconstructed by a brand-new service: same status, cursor, pending_step_id.
 4.  Budget integrity — the restored lease preserves spent_minor / remaining_minor
     exactly; a restart cannot make a run forget how much budget it consumed.
 5.  Authority integrity — the restored lease's issuer signature still verifies,
     because the control-plane identity is restored from its exact seed (not re-minted).
 6.  Evidence continuity — the restored run's durable ledger is the same hash chain,
     Rust-verified intact, same head_hash and length as before the restart.
 7.  Autonomy continuity — the executing agent's earned tier survives, so approval-gate
     re-evaluation after restart is identical.
 8.  Resume-after-restart — a restored paused run can be resumed to completion, and the
     post-restart ledger remains verifiable.
 9.  Tenant isolation — a restored run keeps its owning tenant; cross-tenant access is
     still refused, and per-tenant DB files keep runs separate.
10.  Deletion durability — deleting a terminal run purges its durable state so it is
     not resurrected on the next restart.
11.  Serial-version guard — an unknown serial_version is rejected at load time.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aetheros_orchestrator.config import load_config
from aetheros_orchestrator.run_state_store import (
    NoRunStateStore,
    RunStateStore,
    SQLiteRunStateStore,
    make_run_state_store,
)

pytest.importorskip("fastapi")

from aetheros_orchestrator.run_service import RunService, RunStateSerializer  # noqa: E402

# ── helpers ────────────────────────────────────────────────────────────────────

INCIDENT = "Investigate the production incident in checkout and restore service"


def _durable_config(tmp_path: Path):
    """A config with full run-state + ledger durability, isolated under tmp_path."""
    cfg = load_config().model_copy(deep=True)
    cfg.storage.persist_runs = True
    cfg.storage.backend = "sqlite"
    cfg.storage.db_dir = str(tmp_path / "ledgers")
    cfg.storage.run_state_db_dir = str(tmp_path / "runstates")
    return cfg


def _advance_to_gate(svc: RunService, run_id: str):
    """Advance a run until it pauses at its first human-approval gate."""
    state = svc.advance(run_id)
    assert state.status == "awaiting_approval", (
        f"expected an approval gate, got {state.status}"
    )
    return state


# ── 1. Backward compatibility ─────────────────────────────────────────────────


def test_default_service_does_not_persist_runs() -> None:
    """Default RunService uses a no-op store; persist flag is off."""
    svc = RunService()
    assert svc._persist_runs is False
    assert isinstance(svc._run_store, NoRunStateStore)


def test_default_run_completes_unchanged() -> None:
    """A full governed run with persist off still completes and verifies."""
    svc = RunService()
    run = svc.create_run(INCIDENT)
    state = svc.advance(run.run_id)
    while state.status == "awaiting_approval":
        state = svc.resume(
            run.run_id, state.pending_step_id, approved=True, approver="human:vamsi"
        )
    assert state.status in ("completed", "halted")
    assert state.ctx.ledger.verify() is True


def test_make_run_state_store_factory() -> None:
    assert isinstance(make_run_state_store("none"), NoRunStateStore)
    assert isinstance(make_run_state_store("sqlite", db_dir="./_x"), SQLiteRunStateStore)


# ── 2. Store round-trip ───────────────────────────────────────────────────────


def test_sqlite_store_persist_load_delete(tmp_path: Path) -> None:
    store = SQLiteRunStateStore(db_dir=tmp_path)
    assert store.load("t1", "r1") is None
    store.persist("t1", "r1", '{"k":1}')
    assert json.loads(store.load("t1", "r1")) == {"k": 1}
    # overwrite
    store.persist("t1", "r1", '{"k":2}')
    assert json.loads(store.load("t1", "r1")) == {"k": 2}
    store.delete("t1", "r1")
    assert store.load("t1", "r1") is None


def test_sqlite_store_load_all(tmp_path: Path) -> None:
    store = SQLiteRunStateStore(db_dir=tmp_path)
    store.persist("t1", "r1", '{"a":1}')
    store.persist("t1", "r2", '{"a":2}')
    store.persist("t2", "r3", '{"a":3}')
    all_rows = store.load_all()
    assert {(t, r) for t, r, _ in all_rows} == {("t1", "r1"), ("t1", "r2"), ("t2", "r3")}
    t1_rows = store.load_all(tenant_id="t1")
    assert {(t, r) for t, r, _ in t1_rows} == {("t1", "r1"), ("t1", "r2")}


def test_nostore_is_noop() -> None:
    store: RunStateStore = NoRunStateStore()
    store.persist("t", "r", "{}")
    assert store.load("t", "r") is None
    assert store.load_all() == []
    store.delete("t", "r")  # no raise


# ── 3-7. Restart fidelity at a human gate ─────────────────────────────────────


def test_paused_run_survives_restart_with_full_fidelity(tmp_path: Path) -> None:
    cfg = _durable_config(tmp_path)
    svc = RunService(config=cfg)
    run = svc.create_run(INCIDENT, budget_minor=50_000)
    rid = run.run_id
    before = _advance_to_gate(svc, rid)

    pre_status = before.status
    pre_cursor = before.cursor
    pre_pending = before.pending_step_id
    pre_spent = before.ctx.lease.spent_minor
    pre_remaining = before.ctx.lease.remaining_minor
    pre_head = before.ctx.ledger.head_hash
    pre_len = before.ctx.ledger.length
    pre_tier = before.ctx.autonomy_tier
    assert before.ctx.lease.verify() is True

    # Simulate a service restart: a brand-new service over the same durable config.
    svc2 = RunService(config=cfg)
    after = svc2.get(rid)

    # 3. status / cursor / pending gate reconstructed exactly
    assert after.status == pre_status == "awaiting_approval"
    assert after.cursor == pre_cursor
    assert after.pending_step_id == pre_pending
    # 4. budget integrity
    assert after.ctx.lease.spent_minor == pre_spent
    assert after.ctx.lease.remaining_minor == pre_remaining
    # 5. authority integrity — issuer signature still verifies
    assert after.ctx.lease.verify() is True
    # 6. evidence continuity — same chain, Rust-verified intact
    assert after.ctx.ledger.head_hash == pre_head
    assert after.ctx.ledger.length == pre_len
    assert after.ctx.ledger.verify() is True
    # 7. autonomy continuity
    assert after.ctx.autonomy_tier == pre_tier


# ── 8. Resume-after-restart ────────────────────────────────────────────────────


def test_restored_run_resumes_to_terminal(tmp_path: Path) -> None:
    cfg = _durable_config(tmp_path)
    svc = RunService(config=cfg)
    run = svc.create_run(INCIDENT, budget_minor=100_000)
    rid = run.run_id
    _advance_to_gate(svc, rid)

    # Restart, then drive the restored run through every gate to a terminal state.
    svc2 = RunService(config=cfg)
    state = svc2.get(rid)
    while state.status == "awaiting_approval":
        state = svc2.resume(
            rid, state.pending_step_id, approved=True, approver="human:vamsi"
        )
    assert state.status in ("completed", "halted")
    assert state.ctx.ledger.verify() is True

    # And a *second* restart sees the terminal run persisted, still intact.
    svc3 = RunService(config=cfg)
    final = svc3.get(rid)
    assert final.status == state.status
    assert final.ctx.ledger.verify() is True


def test_restored_run_denial_path(tmp_path: Path) -> None:
    """A restored paused run can also be denied; it halts and persists as halted."""
    cfg = _durable_config(tmp_path)
    svc = RunService(config=cfg)
    run = svc.create_run(INCIDENT, budget_minor=100_000)
    rid = run.run_id
    before = _advance_to_gate(svc, rid)

    svc2 = RunService(config=cfg)
    state = svc2.get(rid)
    state = svc2.resume(
        rid, state.pending_step_id, approved=False, approver="human:vamsi"
    )
    assert state.status == "halted"
    assert state.denied_reason is not None

    svc3 = RunService(config=cfg)
    assert svc3.get(rid).status == "halted"


# ── 9. Tenant isolation ───────────────────────────────────────────────────────


def test_restored_run_preserves_tenant_isolation(tmp_path: Path) -> None:
    cfg = _durable_config(tmp_path)
    svc = RunService(config=cfg)
    # Two tenants, each with an in-flight run.
    svc.tenants.ensure("tenant-alpha", "Alpha")
    svc.tenants.ensure("tenant-beta", "Beta")
    run_a = svc.create_run(INCIDENT, tenant_id="tenant-alpha")
    run_b = svc.create_run(INCIDENT, tenant_id="tenant-beta")
    _advance_to_gate(svc, run_a.run_id)
    _advance_to_gate(svc, run_b.run_id)

    svc2 = RunService(config=cfg)
    # Each restored run keeps its owning tenant.
    assert svc2.get(run_a.run_id).tenant_id == "tenant-alpha"
    assert svc2.get(run_b.run_id).tenant_id == "tenant-beta"
    # Cross-tenant access to a restored run is still refused.
    from aetheros_orchestrator.tenancy import CrossTenantAccess

    with pytest.raises(CrossTenantAccess):
        svc2.get(run_a.run_id, tenant_id="tenant-beta")


# ── 10. Deletion durability ───────────────────────────────────────────────────


def test_deleting_terminal_run_purges_durable_state(tmp_path: Path) -> None:
    cfg = _durable_config(tmp_path)
    svc = RunService(config=cfg)
    run = svc.create_run(INCIDENT, budget_minor=100_000)
    rid = run.run_id
    tid = run.tenant_id
    # Cancel to reach a terminal state, then delete.
    svc.cancel_run(rid)
    svc.delete_run(rid)

    # The durable row is gone …
    store = SQLiteRunStateStore(db_dir=cfg.storage.run_state_db_dir)
    assert store.load(tid, rid) is None
    # … and a restart does not resurrect it.
    svc2 = RunService(config=cfg)
    with pytest.raises(KeyError):
        svc2.get(rid)


def test_cancelled_run_persists_as_halted(tmp_path: Path) -> None:
    cfg = _durable_config(tmp_path)
    svc = RunService(config=cfg)
    run = svc.create_run(INCIDENT, budget_minor=100_000)
    rid = run.run_id
    svc.cancel_run(rid)

    svc2 = RunService(config=cfg)
    restored = svc2.get(rid)
    assert restored.status == "halted"
    assert restored.denied_reason == "cancelled by operator"
    # The cancellation evidence entry survived too.
    assert restored.ctx.ledger.verify() is True


# ── 11. Serial-version guard ──────────────────────────────────────────────────


def test_unknown_serial_version_is_rejected(tmp_path: Path) -> None:
    cfg = _durable_config(tmp_path)
    svc = RunService(config=cfg)
    run = svc.create_run(INCIDENT, budget_minor=50_000)
    _advance_to_gate(svc, run.run_id)

    # Tamper the persisted document's serial_version.
    store = SQLiteRunStateStore(db_dir=cfg.storage.run_state_db_dir)
    raw = store.load(run.tenant_id, run.run_id)
    doc = json.loads(raw)
    doc["serial_version"] = 999

    from aetheros import EvidenceLedger

    with pytest.raises(ValueError, match="serial_version"):
        RunStateSerializer.load(
            json.dumps(doc), cfg, EvidenceLedger(), svc._adapter
        )


# ── 12. Persist-without-sqlite-ledger mode ────────────────────────────────────


def test_persist_runs_without_sqlite_ledger_restores_scalars(tmp_path: Path) -> None:
    """persist_runs=True but ledger backend='none' restores run scalars + lease.

    The prior evidence chain is not available (ledger was never persisted), but the
    run's status, cursor, lease budget, and authority all come back — the documented
    degraded mode.
    """
    cfg = load_config().model_copy(deep=True)
    cfg.storage.persist_runs = True
    cfg.storage.backend = "none"
    cfg.storage.run_state_db_dir = str(tmp_path / "runstates")
    svc = RunService(config=cfg)
    run = svc.create_run(INCIDENT, budget_minor=50_000)
    rid = run.run_id
    before = _advance_to_gate(svc, rid)
    pre_spent = before.ctx.lease.spent_minor

    svc2 = RunService(config=cfg)
    after = svc2.get(rid)
    assert after.status == "awaiting_approval"
    assert after.pending_step_id == before.pending_step_id
    assert after.ctx.lease.spent_minor == pre_spent
    assert after.ctx.lease.verify() is True
