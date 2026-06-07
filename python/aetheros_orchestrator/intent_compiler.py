"""Intent compiler.

Compiles a natural-language Intent into a validated, governed ExecutionPlan. The
compiler is where high-level intent becomes an auditable, structured plan: it runs a
planner, validates structured output, enforces plan-size and high-impact policy from
config, and records an `intent.submitted` evidence event so the run is anchored in
the ledger from its very first moment.
"""

from __future__ import annotations

import fnmatch
import uuid

from aetheros import EvidenceLedger

from .config import AetherConfig
from .models import ExecutionPlan, Intent, PlanStep
from .planner import Planner, RuleBasedPlanner


class IntentCompilationError(Exception):
    """Raised when an intent cannot be compiled into a valid plan."""


class IntentCompiler:
    """Turns Intents into validated ExecutionPlans under config-driven policy."""

    def __init__(self, config: AetherConfig, planner: Planner | None = None) -> None:
        self._config = config
        self._planner = planner or RuleBasedPlanner()

    def _scope_is_high_impact(self, scope: str) -> bool:
        return any(
            fnmatch.fnmatch(scope, pattern)
            for pattern in self._config.governance.high_impact_scopes
        )

    def compile(self, intent: Intent, ledger: EvidenceLedger | None = None) -> ExecutionPlan:
        steps = self._planner.plan(intent.text)

        if not steps:
            raise IntentCompilationError("planner produced no steps")
        max_steps = self._config.orchestration.max_plan_steps
        if len(steps) > max_steps:
            raise IntentCompilationError(
                f"plan has {len(steps)} steps, exceeds max_plan_steps={max_steps}"
            )

        # Reconcile high-impact: a step is high-impact if the planner said so OR the
        # configured high-impact scope patterns match. This makes governance policy
        # authoritative over planner optimism.
        normalized: list[PlanStep] = []
        for step in steps:
            high = step.high_impact or self._scope_is_high_impact(step.scope)
            normalized.append(step.model_copy(update={"high_impact": high}))

        plan = ExecutionPlan(
            plan_id=f"plan-{uuid.uuid4().hex[:12]}",
            intent_text=intent.text,
            submitted_by=intent.submitted_by,
            steps=normalized,
        )

        if ledger is not None:
            ledger.append(
                intent.submitted_by,
                "intent.submitted",
                {
                    "plan_id": plan.plan_id,
                    "intent": intent.text,
                    "steps": len(plan.steps),
                    "estimated_cost_minor": plan.total_estimated_cost_minor,
                    "high_impact_steps": [s.step_id for s in plan.steps if s.high_impact],
                },
            )

        return plan
