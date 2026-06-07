"""Roundtrip and behavior tests for the AetherOS Python bindings.

These exercise the full PyO3 boundary: identity signing/verification, lease
issuance and authorization, and the tamper-evident evidence ledger — confirming
the Phase 1 success criteria that Rust primitives are usable from Python and that
the evidence ledger records and verifies entries.
"""

from __future__ import annotations

import pytest

from aetheros import (
    AgentIdentity,
    CapabilityLease,
    EvidenceLedger,
    core_version,
    now_rfc3339,
    rfc3339_in,
    verify_signature,
)
from aetheros.lease import LeaseDenied
from aetheros.ledger import LedgerIntegrityError


def test_core_version_present():
    assert core_version != "unknown"


# ── Identity ────────────────────────────────────────────────────────────────

def test_identity_generate_fields():
    ident = AgentIdentity.generate("investigator")
    assert ident.display_name == "investigator"
    assert len(ident.public_key) == 64
    assert len(ident.fingerprint) == 32
    assert ident.agent_id


def test_identity_sign_verify_roundtrip():
    ident = AgentIdentity.generate("signer")
    msg = b"governed action: read s3"
    sig = ident.sign(msg)
    assert verify_signature(ident.public_key, msg, sig)
    assert not verify_signature(ident.public_key, b"tampered", sig)


def test_identity_seed_roundtrip():
    ident = AgentIdentity.generate("seedy")
    seed = ident.secret_seed_hex()
    restored = AgentIdentity.from_seed_hex(
        ident.agent_id, ident.display_name, ident.created_at, seed
    )
    assert restored.public_key == ident.public_key
    sig = restored.sign(b"hello")
    assert verify_signature(ident.public_key, b"hello", sig)


def test_identity_descriptor_is_pydantic():
    ident = AgentIdentity.generate("desc")
    d = ident.descriptor()
    assert d.agent_id == ident.agent_id
    assert d.public_key == ident.public_key
    assert d.fingerprint == ident.fingerprint


# ── Capability lease ────────────────────────────────────────────────────────

def _issuer() -> AgentIdentity:
    return AgentIdentity.generate("control-plane")


def test_lease_issue_and_verify():
    issuer = _issuer()
    lease = CapabilityLease.issue(
        issuer, "subject", ["tool:slack.post", "s3:read:logs"], "USD", 10_000
    )
    assert lease.verify()
    assert lease.grants_scope("tool:slack.post")
    assert not lease.grants_scope("admin:all")
    assert lease.remaining_minor == 10_000


def test_lease_authorize_happy_path():
    issuer = _issuer()
    lease = CapabilityLease.issue(issuer, "subject", ["s3:read:logs"], "USD", 10_000)
    lease.authorize("s3:read:logs", 500)  # should not raise
    lease.record_spend(500)
    assert lease.spent_minor == 500
    assert lease.remaining_minor == 9_500


def test_lease_denies_missing_scope():
    issuer = _issuer()
    lease = CapabilityLease.issue(issuer, "subject", ["s3:read:logs"], "USD", 10_000)
    with pytest.raises(LeaseDenied):
        lease.authorize("admin:delete", 0)


def test_lease_denies_over_budget():
    issuer = _issuer()
    lease = CapabilityLease.issue(issuer, "subject", ["s3:read:logs"], "USD", 1_000)
    with pytest.raises(LeaseDenied):
        lease.authorize("s3:read:logs", 5_000)


def test_lease_denies_expired():
    issuer = _issuer()
    lease = CapabilityLease.issue(
        issuer,
        "subject",
        ["s3:read:logs"],
        "USD",
        10_000,
        issued_at="2020-01-01T00:00:00Z",
        expires_at="2020-01-02T00:00:00Z",
    )
    with pytest.raises(LeaseDenied):
        lease.authorize("s3:read:logs", 0)


def test_lease_denies_revoked():
    issuer = _issuer()
    lease = CapabilityLease.issue(issuer, "subject", ["s3:read:logs"], "USD", 10_000)
    lease.revoke()
    assert lease.revoked
    with pytest.raises(LeaseDenied):
        lease.authorize("s3:read:logs", 0)


def test_lease_json_roundtrip_preserves_signature():
    issuer = _issuer()
    lease = CapabilityLease.issue(issuer, "subject", ["s3:read:logs"], "USD", 10_000)
    data = lease.to_json()
    restored = CapabilityLease.from_json(data)
    assert restored.verify()
    assert restored.lease_id == lease.lease_id


# ── Evidence ledger ─────────────────────────────────────────────────────────

def test_ledger_append_and_verify():
    ledger = EvidenceLedger()
    seq0, h0 = ledger.append("human:vamsi", "intent.submitted", {"intent": "incident 4821"})
    seq1, h1 = ledger.append("control-plane", "lease.issued", {"scope": "s3:read"})
    assert seq0 == 0 and seq1 == 1
    assert h0 != h1
    assert len(ledger) == 2
    assert ledger.verify()


def test_ledger_replay_is_chronological():
    ledger = EvidenceLedger()
    ledger.append("human:vamsi", "intent.submitted", {"x": 1})
    ledger.append("agent:inv", "tool.invoked", {"tool": "log_search"})
    replay = ledger.replay()
    assert [e[1] for e in replay] == ["intent.submitted", "tool.invoked"]


def test_ledger_entries_as_pydantic():
    ledger = EvidenceLedger()
    ledger.append("human:vamsi", "intent.submitted", {"intent": "x"})
    entries = ledger.entries()
    assert entries[0].seq == 0
    assert entries[0].event_type == "intent.submitted"
    assert entries[0].prev_hash == "0" * 64


def test_ledger_json_roundtrip_verifies():
    ledger = EvidenceLedger()
    ledger.append("a", "e1", {"k": 1})
    ledger.append("b", "e2", {"k": 2})
    data = ledger.to_json()
    restored = EvidenceLedger.from_json(data)
    assert len(restored) == 2
    assert restored.verify()


def test_ledger_rejects_tampered_json():
    ledger = EvidenceLedger()
    ledger.append("a", "e1", {"k": 1})
    data = ledger.to_json()
    tampered = data.replace('"k":1', '"k":999')
    with pytest.raises(LedgerIntegrityError):
        EvidenceLedger.from_json(tampered)


def test_time_helpers_format():
    assert now_rfc3339().endswith("Z")
    assert rfc3339_in(60).endswith("Z")
    assert len(now_rfc3339()) == 20
