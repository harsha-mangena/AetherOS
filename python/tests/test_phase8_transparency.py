"""Phase 8 transparency tests: RFC 6962 Merkle log over the evidence ledger.

These exercise the cross-language transparency surface end to end:

  * the orchestrator wrapper (`aetheros_orchestrator.transparency`) authoring a log over a
    ledger's entry hashes, signing a Signed Tree Head (STH) with an agent identity, and
    producing inclusion/consistency proofs;
  * the Rust-evaluated verifiers (`verify_inclusion`, `verify_consistency`,
    `verify_signed_tree_head`) accepting honest proofs and rejecting forged ones;
  * the `RunService.transparency` integration signing an STH with the control-plane identity
    over a real governed run's ledger, with an optional inclusion proof;
  * tamper-resistance: mutating the committed leaf set breaks every proof against the
    signed root, so the log can never attest to evidence the ledger does not contain.

The cryptography lives in `aether_core::transparency`; nothing here re-implements it. The
point of these tests is the composition contract — that the Python authoring layer marshals
the right bytes in and the verifiers hold the line on what those bytes commit to.
"""

from __future__ import annotations

import pytest

import aetheros
from aetheros_orchestrator.transparency import (
    InclusionProof,
    TransparencyLog,
    verify_consistency,
    verify_inclusion,
    verify_signed_tree_head,
)

TS = "2026-06-07T00:00:00+00:00"
TS2 = "2026-06-07T01:00:00+00:00"


def _hashes(n: int) -> list[str]:
    """n distinct, well-formed 32-byte hex leaf hashes."""
    return [f"{i:064x}" for i in range(1, n + 1)]


def _identity() -> "aetheros.AgentIdentity":
    return aetheros.AgentIdentity.generate("log-operator")


# ── log construction & roots ────────────────────────────────────────────────


def test_empty_log_has_zero_size() -> None:
    log = TransparencyLog([])
    assert log.size == 0


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 8, 13, 33])
def test_size_tracks_leaf_count(n: int) -> None:
    log = TransparencyLog(_hashes(n))
    assert log.size == n
    # The root of a non-empty tree is a 32-byte hex digest.
    assert len(log.root_hash) == 64
    int(log.root_hash, 16)  # parses as hex


def test_root_is_deterministic_for_same_leaves() -> None:
    leaves = _hashes(7)
    assert TransparencyLog(leaves).root_hash == TransparencyLog(leaves).root_hash


def test_root_changes_when_a_leaf_changes() -> None:
    leaves = _hashes(7)
    mutated = list(leaves)
    mutated[3] = f"{999:064x}"
    assert TransparencyLog(leaves).root_hash != TransparencyLog(mutated).root_hash


def test_root_changes_when_order_changes() -> None:
    leaves = _hashes(5)
    swapped = list(leaves)
    swapped[1], swapped[2] = swapped[2], swapped[1]
    assert TransparencyLog(leaves).root_hash != TransparencyLog(swapped).root_hash


# ── signed tree heads ───────────────────────────────────────────────────────


def test_signed_tree_head_verifies() -> None:
    log = TransparencyLog(_hashes(5))
    sth = log.signed_tree_head(_identity(), TS)
    assert sth.tree_size == 5
    assert sth.root_hash == log.root_hash
    assert sth.timestamp == TS
    assert verify_signed_tree_head(sth) is True


def test_signed_tree_head_dict_roundtrip_verifies() -> None:
    log = TransparencyLog(_hashes(4))
    sth = log.signed_tree_head(_identity(), TS)
    # A verifier that only ever saw the serialized STH must still be able to check it.
    assert verify_signed_tree_head(sth.to_dict()) is True


def test_signed_tree_head_rejects_tampered_root() -> None:
    log = TransparencyLog(_hashes(5))
    sth = log.signed_tree_head(_identity(), TS).to_dict()
    sth["root_hash"] = f"{0xdead:064x}"
    assert verify_signed_tree_head(sth) is False


def test_signed_tree_head_rejects_tampered_size() -> None:
    log = TransparencyLog(_hashes(5))
    sth = log.signed_tree_head(_identity(), TS).to_dict()
    sth["tree_size"] = 6
    assert verify_signed_tree_head(sth) is False


def test_signed_tree_head_rejects_tampered_timestamp() -> None:
    log = TransparencyLog(_hashes(5))
    sth = log.signed_tree_head(_identity(), TS).to_dict()
    sth["timestamp"] = TS2
    assert verify_signed_tree_head(sth) is False


def test_signed_tree_head_rejects_foreign_signer() -> None:
    log = TransparencyLog(_hashes(5))
    sth = log.signed_tree_head(_identity(), TS).to_dict()
    # Swap in a different key: the signature no longer matches the public key.
    sth["signer_public_key"] = _identity().public_key
    assert verify_signed_tree_head(sth) is False


# ── inclusion proofs ────────────────────────────────────────────────────────


@pytest.mark.parametrize("n", [1, 2, 3, 5, 8, 16, 33])
def test_inclusion_proof_verifies_for_every_leaf(n: int) -> None:
    leaves = _hashes(n)
    log = TransparencyLog(leaves)
    root = log.root_hash
    for i in range(n):
        proof = log.inclusion_proof(i)
        assert proof.leaf_index == i
        assert proof.tree_size == n
        assert proof.entry_hash == leaves[i]
        assert verify_inclusion(proof, leaves[i], root) is True


def test_inclusion_proof_rejects_forged_root() -> None:
    leaves = _hashes(8)
    log = TransparencyLog(leaves)
    proof = log.inclusion_proof(3)
    assert verify_inclusion(proof, leaves[3], f"{0xbad:064x}") is False


def test_inclusion_proof_rejects_wrong_leaf() -> None:
    leaves = _hashes(8)
    log = TransparencyLog(leaves)
    proof = log.inclusion_proof(3)
    # Same audit path, but claim a different leaf value at that position.
    assert verify_inclusion(proof, f"{0x9999:064x}", log.root_hash) is False


def test_inclusion_proof_rejects_index_substitution() -> None:
    leaves = _hashes(8)
    log = TransparencyLog(leaves)
    root = log.root_hash
    proof = log.inclusion_proof(3)
    # Take leaf 3's audit path but assert it proves leaf 4's value.
    forged = InclusionProof(
        leaf_index=proof.leaf_index,
        tree_size=proof.tree_size,
        audit_path=proof.audit_path,
        entry_hash=leaves[4],
    )
    assert verify_inclusion(forged, leaves[4], root) is False


def test_inclusion_proof_out_of_range_raises() -> None:
    log = TransparencyLog(_hashes(4))
    with pytest.raises(IndexError):
        log.inclusion_proof(4)
    with pytest.raises(IndexError):
        log.inclusion_proof(-1)


# ── consistency proofs (append-only) ────────────────────────────────────────


@pytest.mark.parametrize(
    "first,second",
    [(1, 2), (1, 5), (2, 3), (3, 8), (5, 7), (8, 16), (6, 24)],
)
def test_consistency_proof_verifies_for_append(first: int, second: int) -> None:
    leaves = _hashes(second)
    old_root = TransparencyLog(leaves[:first]).root_hash
    log = TransparencyLog(leaves)
    proof = log.consistency_proof(first)
    assert verify_consistency(proof, old_root, log.root_hash) is True


def test_consistency_proof_rejects_wrong_prior_root() -> None:
    leaves = _hashes(8)
    log = TransparencyLog(leaves)
    proof = log.consistency_proof(5)
    assert verify_consistency(proof, f"{0x1111:064x}", log.root_hash) is False


def test_consistency_proof_rejects_non_prefix_history() -> None:
    """A history that rewrote an earlier leaf is not a prefix; consistency must fail."""
    base = _hashes(8)
    # Same length, but leaf 1 was rewritten — not an append of the first-5 prefix.
    rewritten = list(base)
    rewritten[1] = f"{0x7777:064x}"
    honest_old_root = TransparencyLog(base[:5]).root_hash
    divergent = TransparencyLog(rewritten)
    proof = divergent.consistency_proof(5)
    assert verify_consistency(proof, honest_old_root, divergent.root_hash) is False


# ── tamper-resistance over the leaf set ─────────────────────────────────────


def test_tampering_the_committed_leaves_breaks_inclusion() -> None:
    """Signing an STH, then attesting inclusion against a mutated log, must fail.

    This is the core promise: the log can only attest to the leaves it actually committed
    under the signed root. Swap the leaf set out from under a signed root and the honest
    verifier rejects every inclusion proof.
    """
    leaves = _hashes(6)
    signed = TransparencyLog(leaves)
    sth = signed.signed_tree_head(_identity(), TS)

    tampered = list(leaves)
    tampered[2] = f"{0xfeed:064x}"
    tampered_log = TransparencyLog(tampered)
    proof = tampered_log.inclusion_proof(2)

    # The tampered entry does not verify against the originally signed root.
    assert verify_inclusion(proof, tampered[2], sth.root_hash) is False
    # And the tampered log's own root no longer matches what was signed.
    assert tampered_log.root_hash != sth.root_hash


# ── RunService integration ──────────────────────────────────────────────────

INTENT = "Investigate the production incident in checkout and restore service"


def _driven_run():
    from aetheros_orchestrator.run_service import RunService

    svc = RunService()
    run = svc.create_run(INTENT)
    state = svc.advance(run.run_id)
    while state.status == "awaiting_approval":
        state = svc.resume(
            run.run_id, state.pending_step_id, approved=True, approver="human:vamsi"
        )
    return svc, run.run_id


def test_run_transparency_signs_a_verifiable_sth() -> None:
    svc, run_id = _driven_run()
    out = svc.transparency(run_id)
    assert out["run_id"] == run_id
    assert out["ledger_verified"] is True
    sth = out["signed_tree_head"]
    assert sth["tree_size"] >= 1
    # The control-plane identity's signature over the run's evidence root verifies.
    assert verify_signed_tree_head(sth) is True


def test_run_transparency_inclusion_proof_matches_signed_root() -> None:
    svc, run_id = _driven_run()
    out = svc.transparency(run_id, leaf_index=0)
    sth = out["signed_tree_head"]
    proof = out["inclusion_proof"]
    assert proof["leaf_index"] == 0
    # The proof returned by the service verifies against the STH it was issued with.
    assert verify_inclusion(proof, proof["entry_hash"], sth["root_hash"]) is True


def test_run_transparency_rejects_out_of_range_leaf() -> None:
    svc, run_id = _driven_run()
    size = svc.transparency(run_id)["signed_tree_head"]["tree_size"]
    with pytest.raises(IndexError):
        svc.transparency(run_id, leaf_index=size)
