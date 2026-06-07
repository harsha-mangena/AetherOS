"""Tests for the Phase 1 orchestrator foundations: config and ephemeral memory,
plus an integration test wiring identity + lease + evidence ledger together.
"""

from __future__ import annotations

import os

from aetheros import AgentIdentity, CapabilityLease, EvidenceLedger
from aetheros_orchestrator import EphemeralMemory, load_config


def test_load_config_defaults():
    cfg = load_config()
    assert cfg.core.default_currency == "USD"
    assert cfg.governance.default_budget_minor == 10_000
    assert cfg.governance.require_human_approval is True
    assert "tool:*.write" in cfg.governance.high_impact_scopes


def test_config_env_override(monkeypatch):
    monkeypatch.setenv("AETHER__GOVERNANCE__DEFAULT_BUDGET_MINOR", "50000")
    monkeypatch.setenv("AETHER__GOVERNANCE__REQUIRE_HUMAN_APPROVAL", "false")
    cfg = load_config()
    assert cfg.governance.default_budget_minor == 50_000
    assert cfg.governance.require_human_approval is False


def test_ephemeral_memory_bounded():
    mem = EphemeralMemory(max_entries=3)
    for i in range(5):
        mem.add("agent", f"step {i}")
    assert len(mem) == 3
    contents = [r.content for r in mem.all()]
    assert contents == ["step 2", "step 3", "step 4"]


def test_ephemeral_memory_search():
    mem = EphemeralMemory()
    mem.add("tool", "fetched logs from s3", tags=["s3", "logs"])
    mem.add("agent", "analyzing error rate")
    hits = mem.search("logs")
    assert len(hits) == 1
    assert "logs" in hits[0].content


def test_phase1_integration_governed_action_recorded():
    """A minimal governed action: issue a lease, authorize an action, charge the
    budget, and record tamper-evident evidence at each step. This is the seed of the
    end-to-end governed flow that Phase 2 will orchestrate."""
    cfg = load_config()

    control_plane = AgentIdentity.generate("control-plane")
    agent = AgentIdentity.generate("incident-investigator")
    ledger = EvidenceLedger()

    ledger.append("human:vamsi", "intent.submitted", {"intent": "investigate incident 4821"})

    lease = CapabilityLease.issue(
        control_plane,
        agent.agent_id,
        scopes=["s3:read:incident-logs"],
        currency=cfg.core.default_currency,
        limit_minor=cfg.governance.default_budget_minor,
    )
    assert lease.verify()
    ledger.append(
        "control-plane",
        "lease.issued",
        {"lease_id": lease.lease_id, "subject": agent.agent_id, "scopes": lease.scopes},
    )

    # Agent attempts a governed action.
    cost = 12
    lease.authorize("s3:read:incident-logs", cost)
    lease.record_spend(cost)
    ledger.append(
        agent.agent_id,
        "tool.invoked",
        {"tool": "log_search", "cost_minor": cost, "remaining": lease.remaining_minor},
    )

    # The full audit trail is intact and replayable.
    assert ledger.verify()
    replay = ledger.replay()
    assert [e[1] for e in replay] == [
        "intent.submitted",
        "lease.issued",
        "tool.invoked",
    ]
    assert lease.remaining_minor == cfg.governance.default_budget_minor - cost
