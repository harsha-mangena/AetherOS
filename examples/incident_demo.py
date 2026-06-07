#!/usr/bin/env python3
"""End-to-end demo: Production Incident Investigation and Response under AetherOS.

Run:  python examples/incident_demo.py

Shows the full governed flow:
  intent -> compiled plan -> least-privilege lease -> governed execution with a
  human-approval gate on high-impact steps -> tamper-evident, replayable evidence.

This uses the framework-agnostic GovernedEngine with an interactive approval prompt
(falls back to auto-approve when stdin is not a TTY, e.g. in CI).
"""

from __future__ import annotations

import sys

from aetheros import EvidenceLedger
from aetheros_orchestrator import (
    GovernanceContext,
    GovernedEngine,
    Intent,
    IntentCompiler,
    load_config,
)
from aetheros_orchestrator.models import PlanStep


def approval(step: PlanStep):
    prompt = (
        f"\n  APPROVAL REQUIRED for {step.step_id}: {step.description}\n"
        f"    scope={step.scope}  cost={step.estimated_cost_minor} minor\n"
        f"  Approve? [y/N] "
    )
    if not sys.stdin.isatty():
        print(prompt + "y  (auto, non-interactive)")
        return True, "human:auto"
    answer = input(prompt).strip().lower()
    return (answer == "y"), "human:operator"


def main() -> int:
    config = load_config()
    intent = Intent(
        text="Investigate the production incident in checkout and restore service",
        submitted_by="human:vamsi",
        budget_minor=100_000,
    )

    ledger = EvidenceLedger()
    plan = IntentCompiler(config).compile(intent, ledger)

    print("=" * 68)
    print("AetherOS — Production Incident Investigation & Response")
    print("=" * 68)
    print(f"Intent: {intent.text}")
    print(f"Plan {plan.plan_id} ({len(plan.steps)} steps, "
          f"est. {plan.total_estimated_cost_minor} minor):")
    for s in plan.steps:
        flag = "  [HIGH-IMPACT — gated]" if s.high_impact else ""
        print(f"  {s.step_id}: {s.description}{flag}")

    scopes = [s.scope for s in plan.steps]
    ctx = GovernanceContext.for_run(config, intent, scopes, ledger=ledger)
    # Phase 3: restarting production infra requires earned autonomy. Model an agent
    # that has already built a track record of successful governed runs (tier >= 1).
    for _ in range(config.autonomy.promotion_threshold):
        ctx.autonomy.record_success(ctx.agent.agent_id)
    print(f"\nIssued lease {ctx.lease.lease_id} to agent {ctx.agent.agent_id[:8]}…")
    print(f"  scopes: {len(ctx.lease.scopes)}  budget: {intent.budget_minor} minor")
    print(f"  earned autonomy tier: {ctx.autonomy_tier}\n")

    outcome = GovernedEngine(ctx, approval=approval).run(plan)

    print("\n" + "-" * 68)
    print(f"Run completed: {outcome.completed}  "
          f"spent: {outcome.total_cost_minor} minor  "
          f"remaining: {ctx.lease.remaining_minor} minor")
    if outcome.denied_reason:
        print(f"Halted: {outcome.denied_reason}")

    print(f"\nEvidence ledger: {ledger.length} entries, "
          f"integrity verified: {ledger.verify()}")
    print("Replay:")
    for seq, event_type, actor in ledger.replay():
        print(f"  #{seq:<2} {event_type:<20} by {actor}")

    return 0 if outcome.completed else 1


if __name__ == "__main__":
    raise SystemExit(main())
