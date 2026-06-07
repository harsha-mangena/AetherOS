"""Phase 2 tests: intent compilation, governed execution engine, and the
LangGraph human-in-the-loop orchestration of the Production Incident workflow.
"""

from __future__ import annotations

import pytest

from aetheros import EvidenceLedger
from aetheros_orchestrator import (
    GovernanceContext,
    GovernedEngine,
    IntentCompiler,
    Intent,
    LLMPlanner,
    RuleBasedPlanner,
    auto_deny,
    load_config,
)
from aetheros_orchestrator.intent_compiler import IntentCompilationError
from aetheros_orchestrator.models import StepStatus


def _intent(text="Investigate the production incident in checkout", budget=100_000):
    return Intent(text=text, submitted_by="human:vamsi", budget_minor=budget)


def _earn_tier1(ctx, runs: int = 5):
    """Simulate an agent that has earned autonomy tier 1 through prior governed runs.

    Phase 3 gates infra mutations behind earned autonomy: a brand-new agent (tier 0)
    cannot restart production infrastructure. These end-to-end tests model an agent
    that has already built a track record, so we record enough successes to reach
    tier 1 before executing the incident plan.
    """
    for _ in range(runs):
        ctx.autonomy.record_success(ctx.agent.agent_id)
    assert ctx.autonomy_tier >= 1
    return ctx


# ── Intent compilation ──────────────────────────────────────────────────────

def test_compiler_produces_incident_plan():
    cfg = load_config()
    compiler = IntentCompiler(cfg)
    ledger = EvidenceLedger()
    plan = compiler.compile(_intent(), ledger)
    assert len(plan.steps) == 5
    assert plan.steps[0].tool == "log_search"
    # The restart and slack-post steps must be flagged high-impact by config policy.
    high = [s.step_id for s in plan.steps if s.high_impact]
    assert "step-4" in high and "step-5" in high
    # intent.submitted evidence anchored the run.
    assert ledger.verify()
    assert ledger.replay()[0][1] == "intent.submitted"


def test_compiler_enforces_max_plan_steps():
    cfg = load_config()
    cfg.orchestration.max_plan_steps = 2
    compiler = IntentCompiler(cfg)
    with pytest.raises(IntentCompilationError):
        compiler.compile(_intent())


def test_config_high_impact_overrides_planner():
    """Even if a planner marks a write scope as low-impact, config policy wins."""
    cfg = load_config()

    class NaivePlanner(RuleBasedPlanner):
        def plan(self, intent_text):
            steps = super()._generic_readonly_plan(intent_text)
            from aetheros_orchestrator.models import PlanStep

            steps.append(
                PlanStep(
                    step_id="step-3",
                    description="write a file",
                    tool="writer",
                    scope="tool:fs.write",
                    estimated_cost_minor=1,
                    high_impact=False,  # planner is wrong
                )
            )
            return steps

    compiler = IntentCompiler(cfg, planner=NaivePlanner())
    plan = compiler.compile(_intent("do a thing"))
    write_step = [s for s in plan.steps if s.tool == "writer"][0]
    assert write_step.high_impact is True


# ── LLM planner structured-output validation ────────────────────────────────

def test_llm_planner_parses_valid_json():
    def fake_complete(prompt):
        return (
            '[{"description":"read logs","tool":"log_search",'
            '"scope":"s3:read:logs","arguments":{},"estimated_cost_minor":5}]'
        )

    planner = LLMPlanner(fake_complete)
    steps = planner.plan("look at logs")
    assert len(steps) == 1
    assert steps[0].tool == "log_search"


def test_llm_planner_rejects_invalid_json():
    planner = LLMPlanner(lambda p: "not json at all")
    with pytest.raises(ValueError):
        planner.plan("x")


def test_llm_planner_tolerates_code_fence():
    def fake(prompt):
        return '```json\n[{"description":"d","tool":"search","scope":"data:read","arguments":{},"estimated_cost_minor":1}]\n```'

    steps = LLMPlanner(fake).plan("x")
    assert steps[0].scope == "data:read"


# ── Governed execution engine (framework-agnostic) ──────────────────────────

def test_engine_full_incident_run_with_auto_approval():
    cfg = load_config()
    intent = _intent()
    compiler = IntentCompiler(cfg)
    ledger = EvidenceLedger()
    plan = compiler.compile(intent, ledger)

    scopes = [s.scope for s in plan.steps]
    ctx = GovernanceContext.for_run(cfg, intent, scopes, ledger=ledger)
    _earn_tier1(ctx)
    engine = GovernedEngine(ctx)
    outcome = engine.run(plan)

    assert outcome.completed is True
    assert all(r.status == StepStatus.EXECUTED for r in outcome.results)
    assert outcome.total_cost_minor == plan.total_estimated_cost_minor
    # Ledger is intact and contains approvals for the two high-impact steps.
    assert ledger.verify()
    event_types = [e[1] for e in ledger.replay()]
    assert event_types.count("approval.granted") == 2
    assert event_types[-1] == "run.completed"
    # Budget was charged in the Rust lease.
    assert ctx.lease.spent_minor == plan.total_estimated_cost_minor


def test_engine_halts_on_human_denial():
    cfg = load_config()
    intent = _intent()
    compiler = IntentCompiler(cfg)
    ledger = EvidenceLedger()
    plan = compiler.compile(intent, ledger)
    scopes = [s.scope for s in plan.steps]
    ctx = GovernanceContext.for_run(cfg, intent, scopes, ledger=ledger)
    _earn_tier1(ctx)

    engine = GovernedEngine(ctx, approval=auto_deny)
    outcome = engine.run(plan)

    assert outcome.completed is False
    assert outcome.denied_reason is not None
    # The read-only steps before the first high-impact step executed.
    executed = [r for r in outcome.results if r.status == StepStatus.EXECUTED]
    assert len(executed) == 3
    assert ledger.verify()
    assert ledger.replay()[-1][1] == "run.halted"


def test_engine_denies_when_scope_not_leased():
    """If the lease lacks a step's scope, the Rust authorize call denies it."""
    cfg = load_config()
    intent = _intent()
    compiler = IntentCompiler(cfg)
    ledger = EvidenceLedger()
    plan = compiler.compile(intent, ledger)
    # Issue a lease missing the restart scope entirely.
    limited_scopes = [s.scope for s in plan.steps if "restart" not in s.scope]
    ctx = GovernanceContext.for_run(cfg, intent, limited_scopes, ledger=ledger)

    outcome = GovernedEngine(ctx).run(plan)
    assert outcome.completed is False
    # policy.denied recorded for the un-leased scope.
    assert any(e[1] == "policy.denied" for e in ledger.replay())


def test_engine_denies_when_budget_exhausted():
    cfg = load_config()
    intent = _intent(budget=20)  # tiny budget; run cannot finish
    compiler = IntentCompiler(cfg)
    ledger = EvidenceLedger()
    plan = compiler.compile(intent, ledger)
    scopes = [s.scope for s in plan.steps]
    ctx = GovernanceContext.for_run(cfg, intent, scopes, ledger=ledger)
    outcome = GovernedEngine(ctx).run(plan)
    assert outcome.completed is False
