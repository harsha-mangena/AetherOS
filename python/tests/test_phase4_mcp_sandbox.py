"""Phase 4 tests: MCP adapter, egress proxy gateway, Rust-controlled sandbox with
provenance, and the full governed incident run executed through the sandbox stack.
"""

from __future__ import annotations

import time

import pytest

from aetheros import EvidenceLedger
from aetheros_orchestrator import (
    EgressDenied,
    GatewayConfig,
    GovernanceContext,
    GovernedEngine,
    Intent,
    IntentCompiler,
    LocalSandbox,
    MockMCPAdapter,
    ProxyGateway,
    SandboxExecutionError,
    ToolSpec,
    build_local_sandbox,
    default_incident_adapter,
    load_config,
)
from aetheros_orchestrator.models import StepStatus


# ── MCP adapter ─────────────────────────────────────────────────────────────

def test_mock_adapter_lists_and_calls_tools():
    adapter = default_incident_adapter()
    names = {t.name for t in adapter.list_tools()}
    assert {"log_search", "service_restart", "slack_post"} <= names
    out = adapter.call_tool("log_search", {"window": "last_2h"})
    assert out["window"] == "last_2h"


def test_mock_adapter_unknown_tool_raises():
    adapter = MockMCPAdapter()
    with pytest.raises(KeyError):
        adapter.call_tool("nope", {})


# ── Proxy gateway egress ────────────────────────────────────────────────────

def _gateway():
    return ProxyGateway(
        GatewayConfig(
            allow_destinations=["slack.com", "*.internal"],
            external_tools=["service_restart", "slack_post"],
            deny_by_default=True,
        )
    )


def test_gateway_allows_internal_tools_without_destination():
    gw = _gateway()
    gw.check("log_search", None)  # internal tool, no egress check


def test_gateway_allows_allowlisted_destination():
    gw = _gateway()
    gw.check("slack_post", "slack.com")
    gw.check("service_restart", "infra.internal")


def test_gateway_denies_unlisted_destination():
    gw = _gateway()
    with pytest.raises(EgressDenied):
        gw.check("slack_post", "evil.example.com")


def test_gateway_denies_external_without_destination():
    gw = _gateway()
    with pytest.raises(EgressDenied):
        gw.check("service_restart", None)


# ── Sandbox execution + provenance ──────────────────────────────────────────

def test_sandbox_executes_and_produces_verifiable_provenance():
    cfg = load_config()
    sandbox, dests = build_local_sandbox(cfg, default_incident_adapter())
    result = sandbox.execute("service_restart", {"service": "checkout"}, dests["service_restart"])
    assert result.output["restarted"] is True
    assert result.provenance.verify()
    # Tampering with the recorded output breaks provenance verification.
    result.provenance.output = {"restarted": False}
    assert not result.provenance.verify()


def test_sandbox_blocks_denied_egress():
    cfg = load_config()
    sandbox, _ = build_local_sandbox(cfg, default_incident_adapter())
    # slack_post is external; an unlisted destination must be blocked.
    with pytest.raises(SandboxExecutionError):
        sandbox.execute("slack_post", {}, "evil.example.com")


def test_sandbox_enforces_timeout():
    adapter = MockMCPAdapter()
    adapter.register(ToolSpec("slow"), lambda a: time.sleep(2) or {"ok": True})
    gw = ProxyGateway(GatewayConfig(external_tools=[], deny_by_default=False))
    sandbox = LocalSandbox(adapter, gw, timeout_seconds=0.2)
    with pytest.raises(SandboxExecutionError):
        sandbox.execute("slow", {})


# ── Full governed run through the sandbox stack ─────────────────────────────

def _seed_tier1(ctx, cfg):
    for _ in range(cfg.autonomy.promotion_threshold):
        ctx.autonomy.record_success(ctx.agent.agent_id)


def test_full_incident_run_through_sandbox_records_provenance():
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
    _seed_tier1(ctx, cfg)

    sandbox, dests = build_local_sandbox(cfg, default_incident_adapter())
    engine = GovernedEngine(ctx, sandbox=sandbox, destinations=dests)
    outcome = engine.run(plan)

    assert outcome.completed is True
    assert all(r.status == StepStatus.EXECUTED for r in outcome.results)
    assert ledger.verify()
    # Every tool.invoked evidence entry carries a sandbox provenance id.
    invoked = [e for e in ledger.entries() if e.event_type == "tool.invoked"]
    assert len(invoked) == len(plan.steps)
    for entry in invoked:
        assert "provenance_id" in entry.payload
        assert len(entry.payload["provenance_id"]) == 64


def test_run_halts_when_external_egress_denied():
    """If a high-impact external step targets a non-allowlisted destination, the
    sandbox blocks it and the run halts with a recorded tool.failed event."""
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
    _seed_tier1(ctx, cfg)

    sandbox, _dests = build_local_sandbox(cfg, default_incident_adapter())
    # Force slack_post to an unlisted destination via the destinations map.
    bad_dests = {"service_restart": "infra.internal", "slack_post": "evil.example.com"}
    engine = GovernedEngine(ctx, sandbox=sandbox, destinations=bad_dests)
    outcome = engine.run(plan)

    assert outcome.completed is False
    events = [e[1] for e in ledger.replay()]
    assert "tool.failed" in events
    assert events[-1] == "run.halted"
