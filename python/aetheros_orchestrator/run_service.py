"""Resumable governed-run service (Phase 5 backend).

The UI (or any client) drives governed runs through a small, stable surface:

    svc = RunService()
    run = svc.create_run(intent_text, submitted_by, budget_minor)   # compiles a plan
    state = svc.advance(run.run_id)                                  # runs until a gate
    # ...if state.status == "awaiting_approval": show the gate to a human...
    state = svc.resume(run.run_id, step_id, approved=True, approver="human:vamsi")
    # ...repeat advance/resume until terminal...
    evidence = svc.evidence(run.run_id)                             # verify + replay

This is a UI-agnostic state machine layered over the framework-agnostic GovernedEngine
primitives (authorize -> execute -> charge -> record). It exists so the desktop app
never re-implements governance: every decision still flows through the Rust policy
engine + capability lease and the tamper-evident ledger. Runs are held in memory keyed
by run_id; a persistent store can drop in behind the same interface later.

Why a resumable machine and not a synchronous run: a human approval gate spans
multiple client requests. The service executes a plan step by step, and when it reaches
a high-impact step it pauses (persisting the paused position) and returns
`awaiting_approval` so the client can collect a human decision and call `resume`.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from aetheros import EvidenceLedger

from .config import AetherConfig, load_config
from .governance import GovernanceContext
from .intent_compiler import IntentCompiler
from .mcp_adapter import MCPAdapter, default_incident_adapter
from .models import ExecutionPlan, Intent, PlanStep, StepResult, StepStatus
from .sandbox import SandboxController, SandboxExecutionError, build_local_sandbox


class RunStatus:
    PLANNED = "planned"
    RUNNING = "running"
    AWAITING_APPROVAL = "awaiting_approval"
    COMPLETED = "completed"
    HALTED = "halted"


@dataclass
class RunState:
    """Mutable state for one governed run, owned by the RunService."""

    run_id: str
    intent: Intent
    plan: ExecutionPlan
    ctx: GovernanceContext
    sandbox: SandboxController
    destinations: dict[str, str]
    status: str = RunStatus.PLANNED
    cursor: int = 0  # index of the next step to process
    results: list[StepResult] = field(default_factory=list)
    total_cost_minor: int = 0
    denied_reason: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    # The step currently awaiting a human approval decision, if any.
    pending_step_id: str | None = None

    def to_view(self) -> dict[str, Any]:
        """A JSON-serializable snapshot for the UI."""
        return {
            "run_id": self.run_id,
            "status": self.status,
            "intent": {
                "text": self.intent.text,
                "submitted_by": self.intent.submitted_by,
                "budget_minor": self.intent.budget_minor,
            },
            "agent_id": self.ctx.agent.agent_id,
            "autonomy_tier": self.ctx.autonomy_tier,
            "lease_id": self.ctx.lease.lease_id if self.ctx.lease else None,
            "remaining_minor": self.ctx.lease.remaining_minor if self.ctx.lease else None,
            "total_cost_minor": self.total_cost_minor,
            "pending_step_id": self.pending_step_id,
            "denied_reason": self.denied_reason,
            "plan": [
                {
                    "step_id": s.step_id,
                    "description": s.description,
                    "tool": s.tool,
                    "scope": s.scope,
                    "estimated_cost_minor": s.estimated_cost_minor,
                    "high_impact": s.high_impact,
                    "status": self._step_status(s),
                }
                for s in self.plan.steps
            ],
            "results": [
                {
                    "step_id": r.step_id,
                    "status": r.status.value,
                    "output": r.output,
                    "cost_minor": r.cost_minor,
                    "evidence_seq": r.evidence_seq,
                    "detail": r.detail,
                }
                for r in self.results
            ],
            "evidence_head": self.ctx.ledger.head_hash,
            "evidence_length": self.ctx.ledger.length,
            "created_at": self.created_at,
        }

    def _step_status(self, step: PlanStep) -> str:
        for r in self.results:
            if r.step_id == step.step_id:
                return r.status.value
        if step.step_id == self.pending_step_id:
            return StepStatus.AWAITING_APPROVAL.value
        return StepStatus.PENDING.value


class RunService:
    """Creates and drives resumable governed runs for the UI / API layer."""

    def __init__(
        self,
        config: AetherConfig | None = None,
        adapter: MCPAdapter | None = None,
        earn_autonomy_to: int = 1,
    ) -> None:
        self._config = config or load_config()
        self._adapter = adapter or default_incident_adapter()
        self._runs: dict[str, RunState] = {}
        self._lock = threading.Lock()
        # For the MVP demo, model an agent that has already earned a track record so
        # infra mutations are policy-allowed (still gated by human approval). Real
        # deployments would load persisted autonomy per agent.
        self._earn_autonomy_to = earn_autonomy_to

    # ── lifecycle ───────────────────────────────────────────────────────────

    def create_run(
        self, intent_text: str, submitted_by: str = "human:operator", budget_minor: int = 100_000
    ) -> RunState:
        intent = Intent(text=intent_text, submitted_by=submitted_by, budget_minor=budget_minor)
        ledger = EvidenceLedger()
        plan = IntentCompiler(self._config).compile(intent, ledger)
        scopes = [s.scope for s in plan.steps]
        ctx = GovernanceContext.for_run(self._config, intent, scopes, ledger=ledger)
        # Seed earned autonomy for the demo agent.
        for _ in range(self._earn_autonomy_to * self._config.autonomy.promotion_threshold):
            ctx.autonomy.record_success(ctx.agent.agent_id)
        sandbox, destinations = build_local_sandbox(self._config, self._adapter)

        run = RunState(
            run_id=uuid.uuid4().hex,
            intent=intent,
            plan=plan,
            ctx=ctx,
            sandbox=sandbox,
            destinations=destinations,
        )
        with self._lock:
            self._runs[run.run_id] = run
        return run

    def get(self, run_id: str) -> RunState:
        with self._lock:
            if run_id not in self._runs:
                raise KeyError(f"unknown run: {run_id}")
            return self._runs[run_id]

    def list_runs(self) -> list[dict[str, Any]]:
        with self._lock:
            return [r.to_view() for r in self._runs.values()]

    # ── execution state machine ──────────────────────────────────────────────

    def advance(self, run_id: str) -> RunState:
        """Execute steps until the run completes, halts, or hits an approval gate."""
        run = self.get(run_id)
        if run.status in (RunStatus.COMPLETED, RunStatus.HALTED):
            return run
        run.status = RunStatus.RUNNING

        while run.cursor < len(run.plan.steps):
            step = run.plan.steps[run.cursor]

            # Pause for human approval before processing a gated step.
            if run.ctx.requires_approval(step):
                run.status = RunStatus.AWAITING_APPROVAL
                run.pending_step_id = step.step_id
                return run

            if not self._execute_step(run, step):
                return run  # halted inside execution
            run.cursor += 1

        return self._finalize(run, completed=True)

    def resume(self, run_id: str, step_id: str, approved: bool, approver: str) -> RunState:
        """Apply a human approval decision to the pending gated step, then continue."""
        run = self.get(run_id)
        if run.status != RunStatus.AWAITING_APPROVAL or run.pending_step_id != step_id:
            raise ValueError(f"run {run_id} is not awaiting approval for {step_id}")

        step = run.plan.steps[run.cursor]
        run.ctx.record_approval(step, approver, approved)
        run.pending_step_id = None

        if not approved:
            run.results.append(
                StepResult(
                    step_id=step.step_id,
                    status=StepStatus.DENIED,
                    detail=f"human approval denied by {approver}",
                )
            )
            run.denied_reason = f"approval denied for {step.step_id}"
            return self._finalize(run, completed=False)

        # Approved: execute the step, then continue advancing.
        if not self._execute_step(run, step):
            return run
        run.cursor += 1
        return self.advance(run_id)

    # ── internals ─────────────────────────────────────────────────────────────

    def _execute_step(self, run: RunState, step: PlanStep) -> bool:
        """Authorize, execute in the sandbox, charge, and record one step.

        Returns True on success (caller advances the cursor), False if the run halted.
        """
        decision = run.ctx.authorize_step(step)
        if not decision:
            run.results.append(
                StepResult(step_id=step.step_id, status=StepStatus.DENIED, detail=decision.reason)
            )
            run.denied_reason = decision.reason
            self._finalize(run, completed=False)
            return False

        try:
            destination = step.arguments.get("destination") or run.destinations.get(step.tool)
            sb_result = run.sandbox.execute(step.tool, step.arguments, destination)
            output = sb_result.output
            provenance_id = sb_result.provenance.record_id
        except (SandboxExecutionError, Exception) as exc:
            run.results.append(
                StepResult(step_id=step.step_id, status=StepStatus.FAILED, detail=str(exc))
            )
            run.ctx.ledger.append(
                "control-plane",
                "tool.failed",
                {"step_id": step.step_id, "tool": step.tool, "reason": str(exc)},
            )
            run.denied_reason = str(exc)
            self._finalize(run, completed=False)
            return False

        cost = step.estimated_cost_minor
        seq = run.ctx.charge_and_record(step, cost, output, provenance_id=provenance_id)
        run.total_cost_minor += cost
        run.results.append(
            StepResult(
                step_id=step.step_id,
                status=StepStatus.EXECUTED,
                output=output,
                cost_minor=cost,
                evidence_seq=seq,
            )
        )
        return True

    def _finalize(self, run: RunState, completed: bool) -> RunState:
        if run.status in (RunStatus.COMPLETED, RunStatus.HALTED):
            return run
        run.status = RunStatus.COMPLETED if completed else RunStatus.HALTED
        run.ctx.ledger.append(
            "control-plane",
            "run.completed" if completed else "run.halted",
            {
                "plan_id": run.plan.plan_id,
                "total_cost_minor": run.total_cost_minor,
                "completed": completed,
            },
        )
        if completed:
            run.ctx.autonomy.record_success(run.ctx.agent.agent_id)
        return run

    # ── evidence ──────────────────────────────────────────────────────────────

    def evidence(self, run_id: str) -> dict[str, Any]:
        run = self.get(run_id)
        ledger = run.ctx.ledger
        return {
            "run_id": run_id,
            "verified": ledger.verify(),
            "head_hash": ledger.head_hash,
            "length": ledger.length,
            "entries": [
                {
                    "seq": e.seq,
                    "event_type": e.event_type,
                    "actor": e.actor,
                    "timestamp": e.timestamp,
                    "payload": e.payload,
                    "entry_hash": e.entry_hash,
                    "prev_hash": e.prev_hash,
                }
                for e in ledger.entries()
            ],
        }
