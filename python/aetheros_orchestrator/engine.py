"""Framework-agnostic governed execution engine.

This engine executes a compiled ExecutionPlan under governance, independent of any
orchestration framework. It is the canonical definition of AetherOS's governed
execution semantics:

    for each step:
        if step needs human approval -> ask approver; deny -> skip/stop
        authorize via the Rust capability lease (scope + budget + expiry + signature)
        if denied -> record policy.denied and stop
        execute the tool
        charge the Rust-tracked budget and append tamper-evident evidence

The LangGraph graph (graph.py) delegates to these same governance primitives, so the
behavior proven by the engine's tests is the behavior the graph exhibits. Keeping
this layer framework-free is a deliberate decision: the governed-execution moat must
not depend on a third-party runtime.
"""

from __future__ import annotations

from typing import Callable

from .governance import GovernanceContext
from .models import ExecutionOutcome, ExecutionPlan, PlanStep, StepResult, StepStatus
from .sandbox import SandboxController, SandboxExecutionError
from .tools import ToolRegistry, default_registry

# An approval callback receives the step awaiting approval and returns (granted, approver).
ApprovalCallback = Callable[[PlanStep], "tuple[bool, str]"]


def auto_approve(step: PlanStep) -> tuple[bool, str]:
    """Default approval policy: approve everything as 'human:auto'. Tests override."""
    return True, "human:auto"


def auto_deny(step: PlanStep) -> tuple[bool, str]:
    """Approval policy that denies everything (for testing the denial path)."""
    return False, "human:auto"


class GovernedEngine:
    """Executes a plan step by step under a GovernanceContext."""

    def __init__(
        self,
        ctx: GovernanceContext,
        registry: ToolRegistry | None = None,
        approval: ApprovalCallback = auto_approve,
        sandbox: SandboxController | None = None,
        destinations: dict[str, str] | None = None,
    ) -> None:
        self._ctx = ctx
        self._registry = registry or default_registry()
        self._approval = approval
        # Phase 4: when a sandbox is provided, tool calls execute inside it (with
        # egress control + provenance) instead of via the raw registry.
        self._sandbox = sandbox
        # Optional tool -> external destination map used for egress checks.
        self._destinations = destinations or {}

    def run(self, plan: ExecutionPlan, stop_on_denial: bool = True) -> ExecutionOutcome:
        results: list[StepResult] = []
        total_cost = 0
        denied_reason: str | None = None
        completed = True

        for step in plan.steps:
            # 1. Human approval gate for high-impact steps.
            if self._ctx.requires_approval(step):
                granted, approver = self._approval(step)
                self._ctx.record_approval(step, approver, granted)
                if not granted:
                    results.append(
                        StepResult(
                            step_id=step.step_id,
                            status=StepStatus.DENIED,
                            detail=f"human approval denied by {approver}",
                        )
                    )
                    denied_reason = f"approval denied for {step.step_id}"
                    completed = False
                    if stop_on_denial:
                        break
                    continue

            # 2. Capability authorization via the Rust lease.
            decision = self._ctx.authorize_step(step)
            if not decision:
                results.append(
                    StepResult(
                        step_id=step.step_id,
                        status=StepStatus.DENIED,
                        detail=decision.reason,
                    )
                )
                denied_reason = decision.reason
                completed = False
                if stop_on_denial:
                    break
                continue

            # 3. Execute the tool — inside the sandbox if one is configured (Phase 4),
            #    otherwise directly via the registry. Either way, governance (policy +
            #    lease) already authorized this step above.
            provenance_id: str | None = None
            try:
                if self._sandbox is not None:
                    destination = step.arguments.get("destination") or self._destinations.get(step.tool)
                    sb_result = self._sandbox.execute(step.tool, step.arguments, destination)
                    output = sb_result.output
                    provenance_id = sb_result.provenance.record_id
                else:
                    output = self._registry.invoke(step.tool, step.arguments)
            except (SandboxExecutionError, Exception) as exc:  # tool/sandbox failure
                results.append(
                    StepResult(
                        step_id=step.step_id,
                        status=StepStatus.FAILED,
                        detail=str(exc),
                    )
                )
                self._ctx.ledger.append(
                    "control-plane",
                    "tool.failed",
                    {"step_id": step.step_id, "tool": step.tool, "reason": str(exc)},
                )
                completed = False
                if stop_on_denial:
                    break
                continue

            # 4. Charge budget and record evidence (tying in sandbox provenance).
            cost = step.estimated_cost_minor
            seq = self._ctx.charge_and_record(step, cost, output, provenance_id=provenance_id)
            total_cost += cost
            results.append(
                StepResult(
                    step_id=step.step_id,
                    status=StepStatus.EXECUTED,
                    output=output,
                    cost_minor=cost,
                    evidence_seq=seq,
                )
            )

        # Terminal evidence.
        self._ctx.ledger.append(
            "control-plane",
            "run.completed" if completed else "run.halted",
            {"plan_id": plan.plan_id, "total_cost_minor": total_cost, "completed": completed},
        )

        return ExecutionOutcome(
            plan_id=plan.plan_id,
            completed=completed,
            results=results,
            total_cost_minor=total_cost,
            evidence_head=self._ctx.ledger.head_hash,
            denied_reason=denied_reason,
        )
