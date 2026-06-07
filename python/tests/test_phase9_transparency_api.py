"""Phase 9 API tests: transparency endpoints over the HTTP control plane.

These prove the RFC 6962 guarantees are reachable over the wire the way an external auditor
would actually consume them: fetch a signed tree head for a run, fetch an inclusion proof for
a single evidence entry, and — after the ledger grows — fetch a consistency proof that the
history was append-only. Verification is done with the same Rust-evaluated verifiers a
third party would use, against roots taken only from signed tree heads (never trusting the
server for a root it didn't sign).
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from aetheros_orchestrator.api import create_app
from aetheros_orchestrator.run_service import RunService
from aetheros_orchestrator.transparency import (
    verify_consistency,
    verify_inclusion,
    verify_signed_tree_head,
)

INTENT = "Investigate the production incident in checkout and restore service"


def _driven_client():
    svc = RunService()
    client = TestClient(create_app(svc))
    run = svc.create_run(INTENT)
    state = svc.advance(run.run_id)
    while state.status == "awaiting_approval":
        state = svc.resume(
            run.run_id, state.pending_step_id, approved=True, approver="human:vamsi"
        )
    return svc, client, run.run_id


def test_transparency_endpoint_returns_verifiable_sth() -> None:
    _, client, run_id = _driven_client()
    r = client.get(f"/runs/{run_id}/transparency")
    assert r.status_code == 200
    body = r.json()
    assert body["run_id"] == run_id
    assert body["ledger_verified"] is True
    sth = body["signed_tree_head"]
    assert sth["tree_size"] >= 1
    assert verify_signed_tree_head(sth) is True


def test_transparency_inclusion_proof_verifies_against_signed_root() -> None:
    _, client, run_id = _driven_client()
    r = client.get(f"/runs/{run_id}/transparency", params={"leaf": 0})
    assert r.status_code == 200
    body = r.json()
    sth = body["signed_tree_head"]
    proof = body["inclusion_proof"]
    assert proof["leaf_index"] == 0
    assert verify_inclusion(proof, proof["entry_hash"], sth["root_hash"]) is True
    # The proof does not verify against a root the log never signed.
    assert verify_inclusion(proof, proof["entry_hash"], f"{0xbad:064x}") is False


def test_transparency_out_of_range_leaf_is_400() -> None:
    _, client, run_id = _driven_client()
    size = client.get(f"/runs/{run_id}/transparency").json()["signed_tree_head"]["tree_size"]
    r = client.get(f"/runs/{run_id}/transparency", params={"leaf": size})
    assert r.status_code == 400


def test_transparency_unknown_run_is_404() -> None:
    client = TestClient(create_app(RunService()))
    r = client.get("/runs/does-not-exist/transparency")
    assert r.status_code == 404


def test_consistency_endpoint_proves_append_only_growth() -> None:
    """Retain an early STH, grow the ledger, then prove the history only appended.

    This is the gossip-style audit: the auditor holds a root it saw earlier and checks the
    consistency proof against *that* retained root — the server is never trusted for it.
    """
    svc, client, run_id = _driven_client()

    # Observe and retain an early signed tree head.
    early = client.get(f"/runs/{run_id}/transparency").json()["signed_tree_head"]
    early_size = early["tree_size"]
    early_root = early["root_hash"]

    # Grow the ledger by recording more governed evidence on the same run.
    ledger = svc.get(run_id).ctx.ledger
    before = ledger.length
    ledger.append("human:vamsi", "audit.note", {"k": "v1"})
    ledger.append("human:vamsi", "audit.note", {"k": "v2"})
    assert ledger.length == before + 2

    # Ask for a consistency proof from the retained size to the current ledger.
    r = client.get(
        f"/runs/{run_id}/transparency/consistency", params={"first_size": early_size}
    )
    assert r.status_code == 200
    body = r.json()
    assert body["first_size"] == early_size
    assert body["current_size"] == early_size + 2
    current_root = body["signed_tree_head"]["root_hash"]
    proof = body["consistency_proof"]

    # The proof connects the retained early root to the current signed root.
    assert verify_consistency(proof, early_root, current_root) is True
    # And fails against a root the auditor never actually saw.
    assert verify_consistency(proof, f"{0x1234:064x}", current_root) is False


def test_consistency_out_of_range_first_size_is_400() -> None:
    _, client, run_id = _driven_client()
    size = client.get(f"/runs/{run_id}/transparency").json()["signed_tree_head"]["tree_size"]
    r = client.get(
        f"/runs/{run_id}/transparency/consistency", params={"first_size": size + 5}
    )
    assert r.status_code == 400


def test_consistency_unknown_run_is_404() -> None:
    client = TestClient(create_app(RunService()))
    r = client.get(
        "/runs/does-not-exist/transparency/consistency", params={"first_size": 1}
    )
    assert r.status_code == 404
