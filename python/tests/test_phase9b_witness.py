"""Phase 9b — Witness cosigning: split-view (equivocation) defense.

Threat model
────────────
RFC 6962 §7.2 gossip / IETF C2SP tlog-witness / Sigsum design:

A single auditor verifying STH + inclusion proofs *cannot* detect a split view —
a log that presents two different, each-internally-consistent histories to two
different auditors.  Independent witnesses defeat this by each retaining the last
tree head they endorsed.  To cosign a new head, a witness demands a consistency
proof from *its own* retained root, not the server's claimed old root.  If the log
has equivocated, one root from one history will not be consistent with the new head
from the other; the honest witness refuses, exposing the fork.

These tests exercise every gate the Witness and WitnessRegistry enforce:

  1.  First-sighting — any valid STH is cosigned, pointer is set.
  2.  Honest growth — valid STH + valid consistency proof advances the pointer.
  3.  Idempotent re-endorsement — presenting the same STH again returns a fresh
      cosignature without changing the retained root.
  4.  Rollback refusal — a shrunken tree must be rejected.
  5.  Equivocation refusal — same size, different root must be rejected.
  6.  Missing-consistency-proof refusal — growth without a proof must be rejected.
  7.  Inconsistent-proof refusal — a consistency proof that does not link the
      witness's *retained* root to the new root must be rejected.
  8.  Forged-cosignature rejection — a cosignature not produced by the claimed key
      must fail verify_cosignature.
  9.  Cosignature binding check — a cosignature for one STH must not verify for a
      different STH (even with the same witness key).
  10. Registry deduplication — two Witness objects sharing the same key pair are
      counted as one; they cannot manufacture independent endorsements.
  11. Foreign-witness rejection — is_trustworthy discards cosignatures from keys
      not in the panel.
  12. Threshold quorum — the panel signals trustworthy only when ≥ threshold
      distinct, valid cosignatures are collected.
  13. Serialization round-trip — Cosignature and CosignedTreeHead round-trip
      through to_dict without losing verifiability.
  14. Parametrized growth (multiple size pairs) — the common path holds across
      different tree sizes.
  15. Multi-log independence — a witness's last-seen state for log A is not
      affected by cosigning for log B.
"""

from __future__ import annotations

import json
import pytest

import aetheros
from aetheros_orchestrator.transparency import (
    TransparencyLog,
    verify_consistency,
    verify_signed_tree_head,
)
from aetheros_orchestrator.witness import (
    Cosignature,
    CosignedTreeHead,
    Witness,
    WitnessRefusal,
    WitnessRegistry,
    _canonical_tree_head_bytes,
    verify_cosignature,
)

# ── shared helpers ────────────────────────────────────────────────────────────

TS = "2026-06-07T00:00:00+00:00"
TS2 = "2026-06-07T01:00:00+00:00"
LOG_A = "log:aetheros:primary"
LOG_B = "log:aetheros:secondary"


def _hashes(n: int) -> list[str]:
    """n distinct, well-formed 32-byte hex leaf hashes."""
    return [f"{i:064x}" for i in range(1, n + 1)]


def _log_op() -> aetheros.AgentIdentity:
    """A fresh log-operator identity for signing STHs."""
    return aetheros.AgentIdentity.generate("log-operator")


def _witness_id() -> aetheros.AgentIdentity:
    """A fresh witness identity."""
    return aetheros.AgentIdentity.generate("witness")


def _sth(leaves: list[str], op: aetheros.AgentIdentity, ts: str = TS):
    """Build a real SignedTreeHead from the given leaf set."""
    return TransparencyLog(leaves).signed_tree_head(op, ts)


def _consistency(leaves: list[str], first_size: int) -> dict:
    """Consistency proof from first_size to len(leaves)."""
    return TransparencyLog(leaves).consistency_proof(first_size)


def _root(leaves: list[str]) -> str:
    return TransparencyLog(leaves).root_hash


# ── 1. First-sighting ─────────────────────────────────────────────────────────


def test_first_sighting_cosigns_without_proof() -> None:
    """A witness with no prior state cosigns any valid STH unconditionally."""
    op = _log_op()
    leaves = _hashes(5)
    sth = _sth(leaves, op)

    w = Witness(_witness_id())
    cosig = w.cosign(LOG_A, sth)

    assert cosig.tree_size == 5
    assert cosig.root_hash == sth.root_hash
    assert verify_cosignature(cosig, sth) is True


def test_first_sighting_sets_last_seen() -> None:
    leaves = _hashes(4)
    op = _log_op()
    sth = _sth(leaves, op)

    w = Witness(_witness_id())
    assert w.last_seen(LOG_A) is None
    w.cosign(LOG_A, sth)
    size, root = w.last_seen(LOG_A)
    assert size == 4
    assert root == sth.root_hash


def test_first_sighting_rejects_invalid_sth() -> None:
    """Even on first sighting, the log-operator signature must be valid."""
    op = _log_op()
    sth = _sth(_hashes(3), op).to_dict()
    sth["root_hash"] = f"{0xdead:064x}"  # tamper

    w = Witness(_witness_id())
    with pytest.raises(WitnessRefusal) as exc:
        w.cosign(LOG_A, sth)
    assert exc.value.reason == "invalid_sth_signature"


# ── 2. Honest growth ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "first,second",
    [(1, 2), (1, 5), (2, 3), (3, 8), (5, 7), (8, 16), (6, 24)],
)
def test_honest_growth_advances_pointer(first: int, second: int) -> None:
    """Growth from first to second with a valid consistency proof is accepted."""
    op = _log_op()
    all_leaves = _hashes(second)

    # Initial sighting
    sth_old = _sth(all_leaves[:first], op, TS)
    w = Witness(_witness_id())
    w.cosign(LOG_A, sth_old)

    # Honest growth
    sth_new = _sth(all_leaves, op, TS2)
    proof = _consistency(all_leaves, first)
    cosig = w.cosign(LOG_A, sth_new, consistency_proof=proof)

    assert cosig.tree_size == second
    assert cosig.root_hash == sth_new.root_hash
    assert verify_cosignature(cosig, sth_new) is True
    size, root = w.last_seen(LOG_A)
    assert size == second
    assert root == sth_new.root_hash


def test_honest_growth_cosignature_binds_to_new_sth() -> None:
    """The cosignature produced after growth signs the *new* STH, not the old one."""
    op = _log_op()
    all_leaves = _hashes(8)

    sth_old = _sth(all_leaves[:5], op, TS)
    sth_new = _sth(all_leaves, op, TS2)
    proof = _consistency(all_leaves, 5)

    w = Witness(_witness_id())
    w.cosign(LOG_A, sth_old)
    cosig = w.cosign(LOG_A, sth_new, proof)

    # Verifies against the new STH
    assert verify_cosignature(cosig, sth_new) is True
    # Does *not* verify against the old STH
    assert verify_cosignature(cosig, sth_old) is False


# ── 3. Idempotent re-endorsement ──────────────────────────────────────────────


def test_idempotent_endorsement_same_root() -> None:
    """Re-presenting the same STH returns a valid cosignature without error."""
    op = _log_op()
    sth = _sth(_hashes(5), op)

    w = Witness(_witness_id())
    cosig1 = w.cosign(LOG_A, sth)
    cosig2 = w.cosign(LOG_A, sth)  # same STH, no consistency proof needed

    assert cosig2.tree_size == 5
    assert cosig2.root_hash == sth.root_hash
    assert verify_cosignature(cosig2, sth) is True
    # Last-seen pointer unchanged
    assert w.last_seen(LOG_A) == (5, sth.root_hash)
    _ = cosig1  # consumed


def test_idempotent_endorsement_does_not_require_proof() -> None:
    """Idempotent re-endorsement without a consistency proof must not raise."""
    op = _log_op()
    sth = _sth(_hashes(3), op)
    w = Witness(_witness_id())
    w.cosign(LOG_A, sth)
    # Passing no proof for identical re-presentation is explicitly allowed.
    w.cosign(LOG_A, sth, consistency_proof=None)


# ── 4. Rollback refusal ───────────────────────────────────────────────────────


def test_rollback_refused() -> None:
    """A shrunken tree must be refused; any accepted STH must advance the log."""
    op = _log_op()
    all_leaves = _hashes(8)

    sth_big = _sth(all_leaves, op, TS2)
    sth_small = _sth(all_leaves[:3], op, TS)

    w = Witness(_witness_id())
    w.cosign(LOG_A, sth_big)

    with pytest.raises(WitnessRefusal) as exc:
        w.cosign(LOG_A, sth_small)
    assert exc.value.reason == "rollback"


def test_rollback_preserved_after_refusal() -> None:
    """After refusing a rollback the witness's retained pointer is unchanged."""
    op = _log_op()
    all_leaves = _hashes(6)

    sth8 = _sth(all_leaves, op, TS)
    sth3 = _sth(all_leaves[:3], op, TS)

    w = Witness(_witness_id())
    w.cosign(LOG_A, sth8)
    prior = w.last_seen(LOG_A)
    with pytest.raises(WitnessRefusal):
        w.cosign(LOG_A, sth3)
    assert w.last_seen(LOG_A) == prior


# ── 5. Equivocation refusal ───────────────────────────────────────────────────


def test_equivocation_refused_same_size_different_root() -> None:
    """A different root at the same tree size is equivocation; must be refused."""
    op = _log_op()
    all_leaves = _hashes(5)
    # Two same-size logs with different leaf 0
    honest_leaves = all_leaves
    fork_leaves = [f"{0xaaaa:064x}"] + all_leaves[1:]

    op_honest = _log_op()
    sth_honest = _sth(honest_leaves, op_honest, TS)
    # The fork is signed by a different (valid) log operator key.
    op_fork = _log_op()
    sth_fork = _sth(fork_leaves, op_fork, TS)

    w = Witness(_witness_id())
    w.cosign(LOG_A, sth_honest)

    with pytest.raises(WitnessRefusal) as exc:
        w.cosign(LOG_A, sth_fork)
    assert exc.value.reason == "equivocation"


def test_equivocation_pointer_unchanged_after_refusal() -> None:
    op_a = _log_op()
    op_b = _log_op()
    leaves_a = _hashes(5)
    leaves_b = [f"{0xbbbb:064x}"] + _hashes(5)[1:]

    sth_a = _sth(leaves_a, op_a, TS)
    sth_b = _sth(leaves_b, op_b, TS)

    w = Witness(_witness_id())
    w.cosign(LOG_A, sth_a)
    prior = w.last_seen(LOG_A)
    with pytest.raises(WitnessRefusal):
        w.cosign(LOG_A, sth_b)
    assert w.last_seen(LOG_A) == prior


# ── 6. Missing consistency proof ──────────────────────────────────────────────


def test_growth_without_proof_refused() -> None:
    """Growth from a prior state without a consistency proof must be refused."""
    op = _log_op()
    all_leaves = _hashes(8)

    sth_old = _sth(all_leaves[:4], op, TS)
    sth_new = _sth(all_leaves, op, TS2)

    w = Witness(_witness_id())
    w.cosign(LOG_A, sth_old)

    with pytest.raises(WitnessRefusal) as exc:
        w.cosign(LOG_A, sth_new, consistency_proof=None)
    assert exc.value.reason == "missing_consistency_proof"


# ── 7. Inconsistent proof ────────────────────────────────────────────────────


def test_forged_history_consistency_proof_fails() -> None:
    """A consistency proof from a rewritten history does not link the witness's retained root.

    This is the core split-view scenario: the log gave witness W a history up to
    root_A (based on leaves A), then later presents root_B with a consistency
    proof B→new that is valid internally but does not connect from root_A.  The
    witness checks against its *retained* root_A, not the server-supplied old root,
    so the forged proof fails.
    """
    op_honest = _log_op()
    op_fork = _log_op()

    honest_leaves = _hashes(8)
    fork_leaves = [f"{0xcccc:064x}"] + _hashes(8)[1:]  # rewritten leaf 0

    # Witness retains the honest 5-leaf root.
    sth_honest_5 = _sth(honest_leaves[:5], op_honest, TS)
    w = Witness(_witness_id())
    w.cosign(LOG_A, sth_honest_5)

    # The fork presents a new 8-leaf root with a consistency proof from *its own* 5-leaf root.
    sth_fork_8 = _sth(fork_leaves, op_fork, TS2)
    # Consistency proof from the fork's own 5-leaf root to the fork's 8-leaf root.
    fork_proof = TransparencyLog(fork_leaves).consistency_proof(5)

    with pytest.raises(WitnessRefusal) as exc:
        w.cosign(LOG_A, sth_fork_8, consistency_proof=fork_proof)
    # Either inconsistency or invalid_sth_signature — the log signed with a different key
    # so verify_signed_tree_head also has a chance to catch it, but the consistency check
    # is the split-view defense. Accept either reason.
    assert exc.value.reason in ("inconsistent", "invalid_sth_signature")


def test_wrong_proof_for_correct_endpoints_refused() -> None:
    """A consistency proof whose path nodes were tampered (correct endpoints, wrong nodes)."""
    op = _log_op()
    all_leaves = _hashes(8)

    sth_old = _sth(all_leaves[:5], op, TS)
    sth_new = _sth(all_leaves, op, TS2)
    proof = _consistency(all_leaves, 5)

    # Corrupt the 'proof' array (the actual Merkle path nodes) with garbage hashes.
    corrupted = dict(proof)
    corrupted["proof"] = [f"{0xbaad:064x}" * 1 for _ in corrupted.get("proof", ["x"])]

    w = Witness(_witness_id())
    w.cosign(LOG_A, sth_old)

    with pytest.raises(WitnessRefusal) as exc:
        w.cosign(LOG_A, sth_new, consistency_proof=corrupted)
    assert exc.value.reason == "inconsistent"


# ── 8. Forged cosignature ────────────────────────────────────────────────────


def test_forged_cosignature_does_not_verify() -> None:
    """A cosignature with a made-up signature hex must fail verify_cosignature."""
    op = _log_op()
    sth = _sth(_hashes(5), op)
    witness_id = _witness_id()

    forged = Cosignature(
        witness_id=witness_id.agent_id,
        witness_public_key=witness_id.public_key,
        tree_size=sth.tree_size,
        root_hash=sth.root_hash,
        signature="00" * 64,  # 64 bytes of zeros — not a valid Ed25519 signature
    )
    assert verify_cosignature(forged, sth) is False


def test_replayed_cosignature_wrong_sth_does_not_verify() -> None:
    """A real cosignature for STH_A does not verify when presented for STH_B."""
    op = _log_op()
    all_leaves = _hashes(8)
    sth_a = _sth(all_leaves[:5], op, TS)
    sth_b = _sth(all_leaves, op, TS2)

    w = Witness(_witness_id())
    cosig_a = w.cosign(LOG_A, sth_a)

    # Present cosig_a against sth_b — size/root mismatch causes verify to return False.
    assert verify_cosignature(cosig_a, sth_b) is False


def test_cosignature_wrong_root_hash_field_does_not_verify() -> None:
    """Mutating the root_hash in a Cosignature causes the binding check to fail."""
    op = _log_op()
    sth = _sth(_hashes(5), op)
    w = Witness(_witness_id())
    cosig = w.cosign(LOG_A, sth)

    tampered = Cosignature(
        witness_id=cosig.witness_id,
        witness_public_key=cosig.witness_public_key,
        tree_size=cosig.tree_size,
        root_hash=f"{0xdead:064x}",  # different root
        signature=cosig.signature,
    )
    assert verify_cosignature(tampered, sth) is False


# ── 9. Canonical bytes consistency ───────────────────────────────────────────


def test_canonical_bytes_matches_verify_signed_tree_head_content() -> None:
    """The witness re-signs the same canonical bytes that verify_signed_tree_head checks.

    This property is what makes a cosignature an independent endorsement of the
    exact same commitment: both the log operator and the witness sign
    json({"root_hash":…,"timestamp":…,"tree_size":…}) with sorted keys.
    """
    op = _log_op()
    sth = _sth(_hashes(5), op)

    canonical = _canonical_tree_head_bytes(sth)
    # Reconstruct manually, mirroring transparency.verify_signed_tree_head
    content = {
        "root_hash": sth.root_hash,
        "timestamp": sth.timestamp,
        "tree_size": sth.tree_size,
    }
    expected = json.dumps(content, separators=(",", ":"), sort_keys=True).encode("utf-8")
    assert canonical == expected


# ── 10. Registry deduplication ───────────────────────────────────────────────


def test_duplicate_witness_key_deduplicated() -> None:
    """Two Witness objects sharing the same underlying key pair count as one."""
    shared_id = _witness_id()
    w1 = Witness(shared_id)
    w2 = Witness(shared_id)  # same identity object → same public key

    reg = WitnessRegistry([w1, w2], threshold=1)
    assert reg.size == 1


def test_duplicate_key_cannot_reach_threshold_of_two() -> None:
    shared_id = _witness_id()
    w1 = Witness(shared_id)
    w2 = Witness(shared_id)

    # Registry deduplicates to size 1; threshold 2 is invalid.
    with pytest.raises(ValueError, match="threshold"):
        WitnessRegistry([w1, w2], threshold=2)


def test_three_witnesses_two_duplicate_only_two_unique() -> None:
    id1 = _witness_id()
    id2 = _witness_id()
    w1a = Witness(id1)
    w1b = Witness(id1)
    w2 = Witness(id2)

    reg = WitnessRegistry([w1a, w1b, w2], threshold=1)
    assert reg.size == 2  # deduplicated to 2


# ── 11. Foreign-witness rejection in is_trustworthy ──────────────────────────


def test_foreign_cosignature_not_counted() -> None:
    """A cosignature from a key not in the panel does not count toward threshold."""
    op = _log_op()
    sth = _sth(_hashes(5), op)

    member = Witness(_witness_id())
    stranger = Witness(_witness_id())

    reg = WitnessRegistry([member], threshold=1)

    # Build a CosignedTreeHead that contains only the stranger's cosignature.
    stranger_cosig = stranger.cosign(LOG_A, sth)
    cth = CosignedTreeHead(
        signed_tree_head=sth.to_dict(),
        cosignatures=[stranger_cosig],
    )
    assert reg.is_trustworthy(cth) is False


def test_foreign_cosignature_mixed_with_member_still_one_valid() -> None:
    """Mixed panel: stranger cosig + member cosig → only member counts."""
    op = _log_op()
    sth = _sth(_hashes(5), op)

    member = Witness(_witness_id())
    stranger = Witness(_witness_id())

    reg = WitnessRegistry([member], threshold=1)

    cosig_member = member.cosign(LOG_A, sth)
    cosig_stranger = stranger.cosign(LOG_A, sth)

    cth = CosignedTreeHead(
        signed_tree_head=sth.to_dict(),
        cosignatures=[cosig_member, cosig_stranger],
    )
    # Threshold=1 and member is valid → trustworthy
    assert reg.is_trustworthy(cth) is True


# ── 12. Threshold quorum ──────────────────────────────────────────────────────


@pytest.mark.parametrize("n,threshold", [(3, 2), (5, 3), (5, 5), (7, 4)])
def test_quorum_reached_with_all_honest_witnesses(n: int, threshold: int) -> None:
    op = _log_op()
    sth = _sth(_hashes(5), op)

    witnesses = [Witness(_witness_id()) for _ in range(n)]
    reg = WitnessRegistry(witnesses, threshold=threshold)
    cth = reg.cosign(LOG_A, sth)

    assert len(cth.cosignatures) == n  # all cosigned (no refusals)
    assert reg.is_trustworthy(cth) is True


def test_quorum_not_reached_below_threshold() -> None:
    """A CosignedTreeHead with fewer cosignatures than threshold is not trustworthy."""
    op = _log_op()
    sth = _sth(_hashes(5), op)

    witnesses = [Witness(_witness_id()) for _ in range(5)]
    reg = WitnessRegistry(witnesses, threshold=4)

    # Simulate only 2 witnesses cosigning — below threshold of 4.
    cosigs = [w.cosign(LOG_A, sth) for w in witnesses[:2]]
    cth = CosignedTreeHead(signed_tree_head=sth.to_dict(), cosignatures=cosigs)

    assert reg.is_trustworthy(cth) is False


def test_quorum_forged_cosigs_do_not_inflate_count() -> None:
    """Forged cosignatures from panel members do not count toward quorum."""
    op = _log_op()
    sth = _sth(_hashes(5), op)

    witnesses = [Witness(_witness_id()) for _ in range(3)]
    reg = WitnessRegistry(witnesses, threshold=2)

    # Forge cosignatures for all three panel members.
    forged_cosigs = [
        Cosignature(
            witness_id=w.witness_id,
            witness_public_key=w.public_key,
            tree_size=sth.tree_size,
            root_hash=sth.root_hash,
            signature="00" * 64,
        )
        for w in witnesses
    ]
    cth = CosignedTreeHead(signed_tree_head=sth.to_dict(), cosignatures=forged_cosigs)
    assert reg.is_trustworthy(cth) is False


def test_threshold_default_is_strict_majority() -> None:
    """Default threshold for n witnesses is n//2 + 1 (strict majority)."""
    witnesses = [Witness(_witness_id()) for _ in range(5)]
    reg = WitnessRegistry(witnesses)
    assert reg.threshold == 3  # 5//2 + 1 = 3


@pytest.mark.parametrize("threshold", [0, -1])
def test_invalid_threshold_below_one_raises(threshold: int) -> None:
    witnesses = [Witness(_witness_id()) for _ in range(3)]
    with pytest.raises(ValueError):
        WitnessRegistry(witnesses, threshold=threshold)


def test_invalid_threshold_above_panel_size_raises() -> None:
    witnesses = [Witness(_witness_id()) for _ in range(3)]
    with pytest.raises(ValueError):
        WitnessRegistry(witnesses, threshold=4)


def test_empty_witness_list_raises() -> None:
    with pytest.raises(ValueError):
        WitnessRegistry([])


# ── 13. Serialization round-trip ─────────────────────────────────────────────


def test_cosignature_to_dict_round_trips_verification() -> None:
    """A Cosignature serialized via to_dict still verifies with verify_cosignature."""
    op = _log_op()
    sth = _sth(_hashes(5), op)

    w = Witness(_witness_id())
    cosig = w.cosign(LOG_A, sth)

    cosig_dict = cosig.to_dict()
    assert verify_cosignature(cosig_dict, sth.to_dict()) is True


def test_cosigned_tree_head_to_dict_preserves_trustworthiness() -> None:
    """CosignedTreeHead serialized via to_dict reconstructs a trustworthy object."""
    op = _log_op()
    sth = _sth(_hashes(6), op)

    witnesses = [Witness(_witness_id()) for _ in range(3)]
    reg = WitnessRegistry(witnesses, threshold=2)
    cth = reg.cosign(LOG_A, sth)

    d = cth.to_dict()
    # Re-hydrate from the dict representation.
    cth2 = CosignedTreeHead(
        signed_tree_head=d["signed_tree_head"],
        cosignatures=[
            Cosignature(
                witness_id=c["witness_id"],
                witness_public_key=c["witness_public_key"],
                tree_size=c["tree_size"],
                root_hash=c["root_hash"],
                signature=c["signature"],
            )
            for c in d["cosignatures"]
        ],
    )
    assert reg.is_trustworthy(cth2) is True


def test_cosigned_tree_head_json_serializable() -> None:
    """CosignedTreeHead.to_dict() must be JSON-serializable (no custom types)."""
    op = _log_op()
    sth = _sth(_hashes(4), op)
    w = Witness(_witness_id())
    cosig = w.cosign(LOG_A, sth)
    cth = CosignedTreeHead(signed_tree_head=sth.to_dict(), cosignatures=[cosig])
    json_str = json.dumps(cth.to_dict())
    assert isinstance(json_str, str)


# ── 14. Multi-log independence ────────────────────────────────────────────────


def test_witness_tracks_two_logs_independently() -> None:
    """A witness's last-seen for LOG_A is completely independent from LOG_B."""
    op_a = _log_op()
    op_b = _log_op()
    leaves_a = _hashes(5)
    leaves_b = _hashes(10)

    sth_a = _sth(leaves_a, op_a, TS)
    sth_b = _sth(leaves_b, op_b, TS)

    w = Witness(_witness_id())
    w.cosign(LOG_A, sth_a)
    w.cosign(LOG_B, sth_b)

    size_a, root_a = w.last_seen(LOG_A)
    size_b, root_b = w.last_seen(LOG_B)
    assert size_a == 5
    assert size_b == 10
    assert root_a == sth_a.root_hash
    assert root_b == sth_b.root_hash


def test_log_b_rollback_does_not_affect_log_a_pointer() -> None:
    """A rollback refusal for LOG_B does not change the retained state for LOG_A."""
    op = _log_op()
    leaves = _hashes(8)

    sth_a8 = _sth(leaves, op, TS)
    sth_b8 = _sth(leaves, op, TS2)
    sth_b3 = _sth(leaves[:3], op, TS)

    w = Witness(_witness_id())
    w.cosign(LOG_A, sth_a8)
    w.cosign(LOG_B, sth_b8)
    prior_a = w.last_seen(LOG_A)

    with pytest.raises(WitnessRefusal) as exc:
        w.cosign(LOG_B, sth_b3)
    assert exc.value.reason == "rollback"
    # LOG_A pointer untouched.
    assert w.last_seen(LOG_A) == prior_a


# ── 15. Registry gossip-style batch cosigning ────────────────────────────────


def test_registry_cosign_collects_all_honest_cosigs() -> None:
    """Registry.cosign returns a CosignedTreeHead with one entry per honest witness."""
    op = _log_op()
    sth = _sth(_hashes(6), op)
    witnesses = [Witness(_witness_id()) for _ in range(4)]
    reg = WitnessRegistry(witnesses, threshold=3)
    cth = reg.cosign(LOG_A, sth)

    assert len(cth.cosignatures) == 4
    assert cth.signed_tree_head["tree_size"] == 6


def test_registry_cosign_with_one_equivocating_witness_still_reaches_quorum() -> None:
    """One witness pre-poisoned with a different root refuses; the remaining three form quorum."""
    op_honest = _log_op()
    op_fork = _log_op()
    all_leaves = _hashes(5)
    fork_leaves = [f"{0xffff:064x}"] + all_leaves[1:]

    sth_honest = _sth(all_leaves, op_honest, TS)
    # Pre-poison witness[0] with the fork's root.
    sth_fork = _sth(fork_leaves, op_fork, TS)

    witnesses = [Witness(_witness_id()) for _ in range(4)]
    # Witness 0 has seen a different root at size 5.
    witnesses[0].cosign(LOG_A, sth_fork)

    reg = WitnessRegistry(witnesses, threshold=3)
    cth = reg.cosign(LOG_A, sth_honest)

    # Witness 0 refuses (equivocation); witnesses 1–3 cosign.
    assert len(cth.cosignatures) == 3
    assert reg.is_trustworthy(cth) is True  # 3 of 4, threshold=3


def test_registry_cosign_majority_refusing_does_not_reach_quorum() -> None:
    """If a majority of witnesses have seen a different history, quorum fails."""
    op_a = _log_op()
    op_b = _log_op()
    all_leaves = _hashes(5)
    alt_leaves = [f"{0x1234:064x}"] + all_leaves[1:]

    sth_honest = _sth(all_leaves, op_a, TS)
    sth_alt = _sth(alt_leaves, op_b, TS)

    witnesses = [Witness(_witness_id()) for _ in range(5)]
    # Witnesses 0, 1, 2 have seen an alternative root at size 5.
    for w in witnesses[:3]:
        w.cosign(LOG_A, sth_alt)

    reg = WitnessRegistry(witnesses, threshold=3)
    cth = reg.cosign(LOG_A, sth_honest)

    # Witnesses 0-2 refuse; only witnesses 3-4 cosign → 2 < threshold 3.
    assert len(cth.cosignatures) == 2
    assert reg.is_trustworthy(cth) is False
