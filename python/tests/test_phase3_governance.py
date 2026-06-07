"""Phase 3 tests: hybrid policy engine (Rust-evaluated), earned autonomy, and
policy-mediated durable memory, plus the governance integration that ties them
into step authorization.
"""

from __future__ import annotations

import pytest

from aetheros import EvidenceLedger
from aetheros_orchestrator import (
    AutonomyTracker,
    DurableMemory,
    GovernanceContext,
    Intent,
    IntentCompiler,
    MemoryAccessDenied,
    PolicyEngine,
    load_config,
)
from aetheros_orchestrator.config import (
    AetherConfig,
    AutonomyConfig,
    PolicyConfig,
    PolicyRuleConfig,
)


# ── Policy engine (Rust-evaluated, deny-overrides) ──────────────────────────

def _engine(rules, default_allow=False):
    return PolicyEngine(
        PolicyConfig(
            default_allow=default_allow,
            rules=[PolicyRuleConfig(**r) for r in rules],
        )
    )


def test_default_deny_when_no_rule_matches():
    eng = _engine([{"id": "allow-reads", "effect": "allow", "scope": "*:read:*"}])
    d = eng.evaluate("db:write:prod", "writer", autonomy_tier=3, cost_minor=0, high_impact=False)
    assert d.allowed is False
    assert d.deciding_rule_id is None


def test_allow_rule_permits():
    eng = _engine([{"id": "allow-reads", "effect": "allow", "scope": "*:read:*"}])
    d = eng.evaluate("s3:read:logs", "log_search", autonomy_tier=0, cost_minor=5, high_impact=False)
    assert d.allowed is True
    assert d.deciding_rule_id == "allow-reads"


def test_deny_overrides_allow_regardless_of_priority():
    eng = _engine(
        [
            {"id": "allow-all", "effect": "allow", "scope": "*", "priority": 100},
            {"id": "deny-prod-delete", "effect": "deny", "scope": "*:delete:prod*", "priority": 1},
        ]
    )
    d = eng.evaluate("db:delete:prod-main", "dropper", autonomy_tier=3, cost_minor=0, high_impact=True)
    assert d.allowed is False
    assert d.deciding_rule_id == "deny-prod-delete"


def test_autonomy_tier_gates_rule():
    eng = _engine(
        [{"id": "allow-infra", "effect": "allow", "scope": "infra:*", "min_autonomy_tier": 1}]
    )
    assert not eng.evaluate("infra:restart:web", "svc", 0, 5, True).allowed
    assert eng.evaluate("infra:restart:web", "svc", 1, 5, True).allowed


def test_high_impact_requires_approval_even_when_allowed():
    eng = _engine([{"id": "allow-all", "effect": "allow", "scope": "*"}])
    d = eng.evaluate("infra:restart:web", "svc", 3, 5, True)
    assert d.allowed and d.requires_approval


def test_default_config_policy_loads_and_evaluates():
    cfg = load_config()
    eng = PolicyEngine.from_config(cfg)
    assert eng.rule_count >= 4
    # Reads are allowed for tier 0.
    assert eng.evaluate("s3:read:logs", "log_search", 0, 1, False).allowed
    # Infra restart denied at tier 0, allowed at tier 1.
    assert not eng.evaluate("infra:restart:checkout", "service_restart", 0, 20, True).allowed
    assert eng.evaluate("infra:restart:checkout", "service_restart", 1, 20, True).allowed
    # Prod delete always denied.
    assert not eng.evaluate("db:delete:prod", "dropper", 3, 0, True).allowed


# ── Earned autonomy ─────────────────────────────────────────────────────────

def test_autonomy_promotes_after_threshold_and_demotes_on_violation():
    tracker = AutonomyTracker(AutonomyConfig(promotion_threshold=3, max_tier=3))
    aid = "agent-1"
    assert tracker.tier(aid) == 0
    assert not tracker.record_success(aid)
    assert not tracker.record_success(aid)
    assert tracker.record_success(aid)  # third success -> promote
    assert tracker.tier(aid) == 1
    # Violation demotes a full tier.
    assert tracker.record_violation(aid)
    assert tracker.tier(aid) == 0


def test_autonomy_snapshot_roundtrips():
    tracker = AutonomyTracker(AutonomyConfig(promotion_threshold=2, max_tier=2))
    tracker.record_success("a")
    tracker.record_success("a")
    snap = tracker.snapshot("a")
    assert snap["tier"] == 1
    assert snap["total_successes"] == 2


# ── Policy-mediated durable memory ──────────────────────────────────────────

def _grants_all(_scope: str) -> bool:
    return True


def test_durable_memory_write_then_read_with_grants():
    cfg = load_config()
    policy = PolicyEngine.from_config(cfg)
    events = []
    mem = DurableMemory(
        policy,
        scope_checker=_grants_all,
        autonomy_tier=1,
        evidence_emitter=lambda t, p: events.append((t, p)),
    )
    rec = mem.write("org", "runbook:checkout", "Restart then verify health.", "memory:read:org")
    assert rec.verify_integrity()
    got = mem.read("org", "runbook:checkout")
    assert got.content == "Restart then verify health."
    kinds = [e[0] for e in events]
    assert "memory.write" in kinds and "memory.read" in kinds


def test_durable_memory_denies_read_without_scope():
    cfg = load_config()
    policy = PolicyEngine.from_config(cfg)
    # Lease grants write but not the secret read scope.
    granted = {"memory:write:secret", "memory:write:org", "memory:read:org"}
    mem = DurableMemory(
        policy,
        scope_checker=lambda s: s in granted,
        autonomy_tier=1,
    )
    mem.write("org", "api-key", "s3cr3t", "memory:read:secret")
    with pytest.raises(MemoryAccessDenied):
        mem.read("org", "api-key")


def test_durable_memory_detects_tampering():
    cfg = load_config()
    policy = PolicyEngine.from_config(cfg)
    mem = DurableMemory(policy, scope_checker=_grants_all, autonomy_tier=1)
    rec = mem.write("org", "k", "original", "memory:read:org")
    # Tamper with stored content directly.
    rec.content = "tampered"
    with pytest.raises(RuntimeError):
        mem.read("org", "k")


# ── Governance integration: policy + autonomy in step authorization ─────────

def _intent():
    return Intent(
        text="Investigate the production incident in checkout",
        submitted_by="human:vamsi",
        budget_minor=100_000,
    )


def test_fresh_agent_denied_infra_restart_until_autonomy_earned():
    cfg = load_config()
    intent = _intent()
    ledger = EvidenceLedger()
    plan = IntentCompiler(cfg).compile(intent, ledger)
    scopes = [s.scope for s in plan.steps]
    ctx = GovernanceContext.for_run(cfg, intent, scopes, ledger=ledger)

    restart_step = next(s for s in plan.steps if s.scope == "infra:restart:checkout")

    # Tier 0: policy denies the restart and counts a violation.
    decision = ctx.authorize_step(restart_step)
    assert decision.allowed is False
    assert "policy.denied" in [e[1] for e in ledger.replay()]

    # Earn autonomy to tier 1, then the same step is policy-allowed (still gated).
    for _ in range(cfg.autonomy.promotion_threshold):
        ctx.autonomy.record_success(ctx.agent.agent_id)
    assert ctx.autonomy_tier >= 1
    decision = ctx.authorize_step(restart_step)
    assert decision.allowed is True
    assert decision.requires_approval is True


def test_prod_delete_is_never_authorized():
    cfg = load_config()
    intent = _intent()
    ledger = EvidenceLedger()
    # Build a context and a lease that even grants the dangerous scope.
    ctx = GovernanceContext.for_run(
        cfg, intent, ["db:delete:prod"], ledger=ledger
    )
    for _ in range(20):  # max out autonomy
        ctx.autonomy.record_success(ctx.agent.agent_id)

    from aetheros_orchestrator.models import PlanStep

    step = PlanStep(
        step_id="step-x",
        description="drop prod table",
        tool="dropper",
        scope="db:delete:prod",
        arguments={},
        estimated_cost_minor=0,
        high_impact=True,
    )
    decision = ctx.authorize_step(step)
    assert decision.allowed is False
    assert decision.deciding_rule_id == "deny-prod-delete"
