"""Phase 2 LangGraph integration: real human-in-the-loop interrupt/resume.

Verifies that the LangGraph StateGraph pauses at a high-impact approval gate via
`interrupt`, checkpoints state, and resumes correctly when a human verdict is
supplied with `Command(resume=...)` — driving the full Production Incident workflow
to completion with a tamper-evident, replayable ledger.
"""

from __future__ import annotations

import pytest

pytest.importorskip("langgraph")

from langgraph.types import Command  # noqa: E402

from aetheros import EvidenceLedger  # noqa: E402
from aetheros_orchestrator import (  # noqa: E402
    GovernanceContext,
    IntentCompiler,
    Intent,
    load_config,
)
from aetheros_orchestrator.graph import build_graph  # noqa: E402


def _setup():
    cfg = load_config()
    intent = Intent(
        text="Investigate the production incident in checkout",
        submitted_by="human:vamsi",
        budget_minor=100_000,
    )
    ledger = EvidenceLedger()
    plan = IntentCompiler(cfg).compile(intent, ledger)
    scopes = [s.scope for s in plan.steps]
    ctx = GovernanceContext.for_run(cfg, intent, scopes, ledger=ledger)
    # Phase 3: infra mutations require earned autonomy. Model an agent with a track
    # record so the incident plan's restart step is policy-permitted (still gated by
    # human approval).
    for _ in range(5):
        ctx.autonomy.record_success(ctx.agent.agent_id)
    return cfg, intent, ledger, plan, ctx


def test_graph_interrupts_at_high_impact_then_resumes():
    _cfg, _intent, ledger, plan, ctx = _setup()
    graph, config = build_graph(ctx, plan)

    state = {"plan": plan.model_dump(), "cursor": 0, "results": []}
    result = graph.invoke(state, config)

    # The graph should have paused at the first high-impact step (the restart).
    assert "__interrupt__" in result
    interrupt_payload = result["__interrupt__"][0].value
    assert interrupt_payload["kind"] == "approval_request"
    assert interrupt_payload["step_id"] == "step-4"

    # Three read-only steps already executed and were recorded.
    assert ctx.lease.spent_minor == sum(
        s.estimated_cost_minor for s in plan.steps[:3]
    )

    # Human approves; resume.
    result = graph.invoke(
        Command(resume={"granted": True, "approver": "human:vamsi"}), config
    )

    # Next high-impact step (slack post) interrupts again.
    assert "__interrupt__" in result
    assert result["__interrupt__"][0].value["step_id"] == "step-5"

    # Approve the final step too.
    result = graph.invoke(
        Command(resume={"granted": True, "approver": "human:vamsi"}), config
    )

    assert result.get("completed") is True
    assert ledger.verify()
    events = [e[1] for e in ledger.replay()]
    assert events.count("approval.granted") == 2
    assert events[-1] == "run.completed"
    assert ctx.lease.spent_minor == plan.total_estimated_cost_minor


def test_graph_halts_when_human_denies():
    _cfg, _intent, ledger, plan, ctx = _setup()
    graph, config = build_graph(ctx, plan)

    graph.invoke({"plan": plan.model_dump(), "cursor": 0, "results": []}, config)
    # Deny the restart.
    result = graph.invoke(
        Command(resume={"granted": False, "approver": "human:vamsi"}), config
    )
    assert result.get("completed") is False
    assert result.get("denied_reason")
    assert ledger.verify()
    events = [e[1] for e in ledger.replay()]
    assert "approval.denied" in events
    assert events[-1] == "run.halted"
