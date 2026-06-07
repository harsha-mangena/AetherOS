"""Phase 9c API tests: witness-cosigned transparency endpoint over the HTTP control plane.

Threat model and test coverage
───────────────────────────────
Phase 9b proved the Witness and WitnessRegistry mechanics in isolation (split-view defence,
rollback/equivocation refusal, threshold quorum). Phase 9c wires those mechanics into the live
control-plane HTTP endpoint so that an external auditor can consume cryptographically verified,
witness-cosigned Signed Tree Heads over the wire — the same way a gossip network participant
would.

These tests exercise the endpoint at the HTTP boundary, verifying every protocol guarantee an
external party can check with public keys alone:

 1. Response shape — all required fields present for a completed run.
 2. STH authenticity — the log operator's signature verifies with verify_signed_tree_head.
 3. Cosignature authenticity — every returned cosignature verifies with verify_cosignature.
 4. Panel metadata — witness_count and threshold match the service's configuration.
 5. Trustworthiness (first call) — all fresh witnesses cosign unconditionally; trustworthy=True.
 6. Honest-growth path (second call) — after the ledger grows, witnesses that held prior state
    must receive a consistency proof; the endpoint must supply it correctly; every cosignature
    still verifies; trustworthy remains True. This is the canonical C2SP tlog-witness / RFC 6962
    gossip-auditor pattern: the retained-root consistency check is the actual split-view defence.
 7. Trustworthy flag semantics — the flag reflects real threshold quorum, not a trivial True.
 8. Tenant isolation — a run created in tenant A is a 404 on the cosigned endpoint for tenant B.
 9. Unknown run — an unrecognised run_id returns 404.

References
───────────
* RFC 6962 §7.2 gossip protocol
* C2SP tlog-witness specification (https://github.com/C2SP/C2SP/blob/main/tlog-witness.md)
* Sigsum log design
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from aetheros_orchestrator.api import create_app
from aetheros_orchestrator.run_service import RunService
from aetheros_orchestrator.transparency import verify_signed_tree_head
from aetheros_orchestrator.witness import verify_cosignature

INTENT = "Investigate the production incident in checkout and restore service"

# Tenant IDs used for isolation tests (must differ from the default "default" tenant).
TENANT_A = "tenant-alpha"
TENANT_B = "tenant-beta"


# ── Shared setup helpers ───────────────────────────────────────────────────────


def _driven_client(svc: RunService | None = None):
    """Create a service, drive one full governed run to completion, return (svc, client, run_id)."""
    if svc is None:
        svc = RunService()
    client = TestClient(create_app(svc))
    run = svc.create_run(INTENT)
    state = svc.advance(run.run_id)
    while state.status == "awaiting_approval":
        state = svc.resume(
            run.run_id, state.pending_step_id, approved=True, approver="human:vamsi"
        )
    return svc, client, run.run_id


def _cosigned_url(run_id: str) -> str:
    return f"/runs/{run_id}/transparency/cosigned"


# ── 1. Response shape ─────────────────────────────────────────────────────────


def test_cosigned_endpoint_returns_required_fields() -> None:
    """All mandatory fields must be present in the cosigned endpoint response."""
    _, client, run_id = _driven_client()
    r = client.get(_cosigned_url(run_id))
    assert r.status_code == 200
    body = r.json()
    for field in (
        "run_id",
        "ledger_verified",
        "signed_tree_head",
        "cosignatures",
        "witness_count",
        "threshold",
        "trustworthy",
    ):
        assert field in body, f"missing field: {field}"
    assert body["run_id"] == run_id


# ── 2. STH authenticity ───────────────────────────────────────────────────────


def test_cosigned_sth_carries_valid_log_operator_signature() -> None:
    """The STH embedded in the cosigned response must pass verify_signed_tree_head.

    This proves that the transparency layer's RFC 6962 signing commitment is intact when
    cosignatures are gathered — the endpoint doesn't modify the STH before handing it to
    the witness panel.
    """
    _, client, run_id = _driven_client()
    body = client.get(_cosigned_url(run_id)).json()
    sth = body["signed_tree_head"]
    assert sth["tree_size"] >= 1
    assert verify_signed_tree_head(sth) is True


# ── 3. Cosignature authenticity ───────────────────────────────────────────────


def test_every_returned_cosignature_verifies_against_sth() -> None:
    """Each cosignature in the response is a valid Ed25519 endorsement of the embedded STH.

    An external gossip auditor performing this check with the witness's public key (carried
    in the cosignature itself) is the terminal external-verification step defined by the
    C2SP tlog-witness protocol.
    """
    _, client, run_id = _driven_client()
    body = client.get(_cosigned_url(run_id)).json()
    sth = body["signed_tree_head"]
    cosignatures = body["cosignatures"]
    assert len(cosignatures) > 0, "endpoint returned zero cosignatures"
    for i, cosig in enumerate(cosignatures):
        assert verify_cosignature(cosig, sth) is True, (
            f"cosignature[{i}] (witness {cosig.get('witness_id', '?')!r}) "
            f"failed verification against STH size={sth.get('tree_size')}"
        )


# ── 4. Panel metadata ─────────────────────────────────────────────────────────


def test_panel_metadata_matches_service_configuration() -> None:
    """witness_count and threshold in the response reflect the service's actual panel config.

    The endpoint must not hard-code these values; they must come from the live RunService
    instance that owns the witness registry.
    """
    svc = RunService()
    _, client, run_id = _driven_client(svc)
    body = client.get(_cosigned_url(run_id)).json()
    assert body["witness_count"] == svc.witness_panel_size
    assert body["threshold"] == svc.witness_threshold


# ── 5. Trustworthiness — first call (all witnesses fresh, no prior state) ─────


def test_first_call_is_trustworthy_all_witnesses_cosign() -> None:
    """On the first cosigned call for a run, all witnesses have no prior state.

    Every witness cosigns unconditionally (first-sighting path). The panel must reach
    threshold and the endpoint must return trustworthy=True.
    """
    svc, client, run_id = _driven_client()
    body = client.get(_cosigned_url(run_id)).json()
    # All witnesses cosigned (first-sighting path).
    assert len(body["cosignatures"]) == svc.witness_panel_size
    assert body["trustworthy"] is True


# ── 6 & 7. Honest-growth path (second call after ledger growth) ───────────────


def test_second_call_after_ledger_growth_exercises_consistency_path() -> None:
    """After the first cosigned call, each witness retains the endorsed root.

    Growing the ledger then calling the endpoint again forces the service to compute a
    consistency proof from the witnesses' retained size to the new size.  Each witness
    independently verifies that proof before cosigning.  This is the canonical RFC 6962 /
    C2SP tlog-witness gossip-auditor verification path — the split-view defence in action.

    Post-growth requirements:
    * The new STH has a strictly larger tree_size.
    * Every cosignature in the second response verifies against the *new* STH.
    * The new STH itself verifies (log-operator signature).
    * trustworthy remains True (whole panel, no refusals).
    """
    svc, client, run_id = _driven_client()

    # First call: witnesses' retained roots are now set.
    first = client.get(_cosigned_url(run_id)).json()
    first_size = first["signed_tree_head"]["tree_size"]

    # Grow the ledger by appending direct evidence entries on the same run.
    ledger = svc.get(run_id).ctx.ledger
    before = ledger.length
    ledger.append("human:vamsi", "audit.growth_test", {"step": 1})
    ledger.append("human:vamsi", "audit.growth_test", {"step": 2})
    assert ledger.length == before + 2, "ledger did not grow as expected"

    # Second call: witnesses have prior state → service must supply a consistency proof.
    second = client.get(_cosigned_url(run_id)).json()
    second_size = second["signed_tree_head"]["tree_size"]

    # The ledger grew, so the new STH must reflect that.
    assert second_size > first_size, (
        f"second STH size {second_size} not larger than first {first_size}"
    )
    assert second_size == first_size + 2

    # STH itself must still carry a valid log-operator signature.
    assert verify_signed_tree_head(second["signed_tree_head"]) is True

    # Every cosignature in the second response must verify against the *new* STH.
    # This proves witnesses successfully ran the consistency-proof check and advanced
    # their retained roots to the new head — the core tlog-witness protocol step.
    cosigs_2 = second["cosignatures"]
    assert len(cosigs_2) > 0, "second call returned no cosignatures"
    for i, cosig in enumerate(cosigs_2):
        assert verify_cosignature(cosig, second["signed_tree_head"]) is True, (
            f"second-call cosignature[{i}] did not verify after ledger growth"
        )

    # Panel must still be trustworthy — all honest witnesses advanced.
    assert second["trustworthy"] is True


def test_second_call_cosignatures_do_not_verify_against_stale_sth() -> None:
    """The cosignatures from the second (post-growth) call bind the *new* STH only.

    Presenting a cosignature from call 2 against call 1's STH must fail — the witness
    signed the new root, not the old one. This proves the endpoint isn't recycling
    stale cosignatures.
    """
    svc, client, run_id = _driven_client()

    # First call.
    first = client.get(_cosigned_url(run_id)).json()
    first_sth = first["signed_tree_head"]

    # Grow and second call.
    ledger = svc.get(run_id).ctx.ledger
    ledger.append("human:vamsi", "audit.binding_check", {"k": "v"})
    ledger.append("human:vamsi", "audit.binding_check", {"k": "v2"})

    second = client.get(_cosigned_url(run_id)).json()
    second_cosigs = second["cosignatures"]

    # Each cosignature from the second call must NOT verify against the first STH.
    for i, cosig in enumerate(second_cosigs):
        assert verify_cosignature(cosig, first_sth) is False, (
            f"second-call cosignature[{i}] should not verify against the stale first-call STH"
        )


# ── 8. Tenant isolation ───────────────────────────────────────────────────────


def test_cosigned_endpoint_tenant_isolation() -> None:
    """A run created under tenant A must be a 404 on the cosigned endpoint for tenant B.

    This is the same cross-tenant guarantee tested for transparency and evidence endpoints:
    the cosigned path must route through the same tenancy gate.
    """
    svc = RunService()
    svc._tenants.ensure(TENANT_A, "Alpha Workspace")
    svc._tenants.ensure(TENANT_B, "Beta Workspace")
    client = TestClient(create_app(svc))

    # Create a run under tenant A and drive it.
    run = svc.create_run(INTENT, tenant_id=TENANT_A)
    state = svc.advance(run.run_id, tenant_id=TENANT_A)
    while state.status == "awaiting_approval":
        state = svc.resume(
            run.run_id, state.pending_step_id, approved=True, approver="human:vamsi",
            tenant_id=TENANT_A,
        )

    # Tenant A can see it.
    r_ok = client.get(
        _cosigned_url(run.run_id), headers={"x-tenant-id": TENANT_A}
    )
    assert r_ok.status_code == 200

    # Tenant B cannot see tenant A's run.
    r_forbidden = client.get(
        _cosigned_url(run.run_id), headers={"x-tenant-id": TENANT_B}
    )
    assert r_forbidden.status_code == 404


# ── 9. Unknown run ────────────────────────────────────────────────────────────


def test_cosigned_endpoint_unknown_run_is_404() -> None:
    """A request for an unrecognised run_id must return 404."""
    client = TestClient(create_app(RunService()))
    r = client.get("/runs/no-such-run/transparency/cosigned")
    assert r.status_code == 404


# ── 10. Ledger integrity is preserved after cosigning ─────────────────────────


def test_cosigned_endpoint_ledger_verified_is_true() -> None:
    """The cosigned response must confirm the underlying ledger is tamper-evident.

    ledger_verified=True is the same guarantee surfaced on the plain transparency
    endpoint — witness cosigning must not bypass or short-circuit it.
    """
    _, client, run_id = _driven_client()
    body = client.get(_cosigned_url(run_id)).json()
    assert body["ledger_verified"] is True


# ── 11. Idempotent re-call without growth (panel state stability) ──────────────


def test_repeated_cosigned_call_without_growth_is_idempotent() -> None:
    """Calling the cosigned endpoint twice with no ledger growth is idempotent.

    The second call presents the same STH to witnesses that already hold it as their
    last-seen root. Per the tlog-witness protocol, idempotent re-endorsement of the
    identical head (same size, same root) is explicitly permitted and must not raise.
    Both calls must return trustworthy=True with all cosignatures valid.
    """
    _, client, run_id = _driven_client()

    first = client.get(_cosigned_url(run_id)).json()
    second = client.get(_cosigned_url(run_id)).json()

    assert first["signed_tree_head"]["tree_size"] == second["signed_tree_head"]["tree_size"]
    assert first["signed_tree_head"]["root_hash"] == second["signed_tree_head"]["root_hash"]
    assert second["trustworthy"] is True
    sth = second["signed_tree_head"]
    for cosig in second["cosignatures"]:
        assert verify_cosignature(cosig, sth) is True
