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
from .tenancy import (
    DEFAULT_TENANT_ID,
    CrossTenantAccess,
    TenantRegistry,
)


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
    tenant_id: str = DEFAULT_TENANT_ID
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
            "tenant_id": self.tenant_id,
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
        registry: TenantRegistry | None = None,
    ) -> None:
        self._config = config or load_config()
        self._adapter = adapter or default_incident_adapter()
        self._runs: dict[str, RunState] = {}
        self._lock = threading.Lock()
        # For the MVP demo, model an agent that has already earned a track record so
        # infra mutations are policy-allowed (still gated by human approval). Real
        # deployments would load persisted autonomy per agent.
        self._earn_autonomy_to = earn_autonomy_to
        # Tenancy: a registry of isolation boundaries. The default tenant always exists
        # so single-tenant callers (and the existing tests/demo) work unchanged.
        self._tenants = registry or TenantRegistry()
        self._tenants.ensure(DEFAULT_TENANT_ID, "Default Workspace")

    # ── tenancy ──────────────────────────────────────────────────────────────

    @property
    def tenants(self) -> TenantRegistry:
        return self._tenants

    def _resolve_tenant(self, tenant_id: str | None) -> str:
        """Validate a tenant id, creating the default on demand. Returns the id."""
        tid = tenant_id or DEFAULT_TENANT_ID
        # ensure() is idempotent; unknown non-default tenants must be created explicitly
        # via the registry, so a typo can't silently spawn an isolated workspace.
        if tid == DEFAULT_TENANT_ID:
            self._tenants.ensure(DEFAULT_TENANT_ID, "Default Workspace")
        else:
            self._tenants.get(tid)  # raises UnknownTenant if it doesn't exist
        return tid

    # ── lifecycle ───────────────────────────────────────────────────────────

    def create_run(
        self,
        intent_text: str,
        submitted_by: str = "human:operator",
        budget_minor: int = 100_000,
        tenant_id: str | None = None,
    ) -> RunState:
        tid = self._resolve_tenant(tenant_id)
        tenant = self._tenants.get(tid)
        # Per-tenant budget ceiling: a tenant can cap spend below the requested budget.
        if tenant.max_budget_minor is not None:
            budget_minor = min(budget_minor, tenant.max_budget_minor)
        intent = Intent(text=intent_text, submitted_by=submitted_by, budget_minor=budget_minor)
        ledger = EvidenceLedger()
        plan = IntentCompiler(self._config).compile(intent, ledger)
        scopes = [s.scope for s in plan.steps]
        ctx = GovernanceContext.for_run(self._config, intent, scopes, ledger=ledger)
        # Seed earned autonomy for the demo agent, respecting any per-tenant tier ceiling.
        target_tier = self._earn_autonomy_to
        if tenant.max_autonomy_tier is not None:
            target_tier = min(target_tier, tenant.max_autonomy_tier)
        for _ in range(target_tier * self._config.autonomy.promotion_threshold):
            ctx.autonomy.record_success(ctx.agent.agent_id)
        sandbox, destinations = build_local_sandbox(self._config, self._adapter)

        run = RunState(
            run_id=uuid.uuid4().hex,
            intent=intent,
            plan=plan,
            ctx=ctx,
            sandbox=sandbox,
            destinations=destinations,
            tenant_id=tid,
        )
        with self._lock:
            self._runs[run.run_id] = run
        return run

    def get(self, run_id: str, tenant_id: str | None = None) -> RunState:
        """Fetch a run, enforcing the tenant isolation boundary.

        If tenant_id is given and does not match the run's owning tenant, raise
        CrossTenantAccess — never return another tenant's run, and (at the API layer)
        never even confirm that it exists.
        """
        with self._lock:
            if run_id not in self._runs:
                raise KeyError(f"unknown run: {run_id}")
            run = self._runs[run_id]
        if tenant_id is not None and run.tenant_id != tenant_id:
            raise CrossTenantAccess(
                f"run {run_id} is not accessible from tenant {tenant_id}"
            )
        return run

    def list_runs(self, tenant_id: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            runs = list(self._runs.values())
        if tenant_id is not None:
            runs = [r for r in runs if r.tenant_id == tenant_id]
        return [r.to_view() for r in runs]

    # ── execution state machine ──────────────────────────────────────────────

    def advance(self, run_id: str, tenant_id: str | None = None) -> RunState:
        """Execute steps until the run completes, halts, or hits an approval gate."""
        run = self.get(run_id, tenant_id)
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

    def resume(
        self,
        run_id: str,
        step_id: str,
        approved: bool,
        approver: str,
        tenant_id: str | None = None,
    ) -> RunState:
        """Apply a human approval decision to the pending gated step, then continue."""
        run = self.get(run_id, tenant_id)
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
        return self.advance(run_id, tenant_id)

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

    # ── analytics ──────────────────────────────────────────────────────────────

    def analytics(self, tenant_id: str | None = None) -> dict[str, Any]:
        """Per-tenant metrics as a pure projection over that tenant's run ledgers.

        Isolation-preserving: only this tenant's runs are folded, and each contributes
        its own evidence report. If the tenant is unknown, raises UnknownTenant.
        """
        from .analytics import compute_tenant_analytics

        tid = self._resolve_tenant(tenant_id)
        with self._lock:
            run_ids = [rid for rid, r in self._runs.items() if r.tenant_id == tid]
        reports = [self.evidence(rid, tid) for rid in run_ids]
        return compute_tenant_analytics(tid, reports).to_view()

    # ── evidence ──────────────────────────────────────────────────────────────

    def evidence(self, run_id: str, tenant_id: str | None = None) -> dict[str, Any]:
        run = self.get(run_id, tenant_id)
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

    # ── transparency (Phase 8) ──────────────────────────────────────────────

    def transparency(
        self,
        run_id: str,
        tenant_id: str | None = None,
        leaf_index: int | None = None,
    ) -> dict[str, Any]:
        """Signed Tree Head over a run's evidence ledger, with an optional inclusion proof.

        The control-plane identity that issued the run's authority also signs the tree head,
        so the same key material that governs the run vouches for its evidence commitment.
        When `leaf_index` is given, an inclusion proof for that evidence entry is returned;
        a verifier can check it against the STH root without holding the whole ledger.
        """
        from .transparency import TransparencyLog

        run = self.get(run_id, tenant_id)
        ledger = run.ctx.ledger
        now = datetime.now(timezone.utc).isoformat()
        log = TransparencyLog.from_ledger(ledger)
        sth = log.signed_tree_head(run.ctx.control_plane, now)
        result: dict[str, Any] = {
            "run_id": run_id,
            "ledger_verified": ledger.verify(),
            "signed_tree_head": sth.to_dict(),
        }
        if leaf_index is not None:
            if leaf_index < 0 or leaf_index >= log.size:
                raise IndexError(
                    f"leaf index {leaf_index} out of range for tree of size {log.size}"
                )
            proof = log.inclusion_proof(leaf_index)
            result["inclusion_proof"] = proof.to_dict()
        return result

    def transparency_consistency(
        self,
        run_id: str,
        first_size: int,
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        """Append-only consistency proof from an earlier tree size to the current ledger.

        An auditor who retained a prior Signed Tree Head (at `first_size`) can ask the log to
        prove the ledger only grew since — never rewrote history. The server returns the proof
        and a freshly signed current STH; the auditor checks
        ``verify_consistency(proof, retained_old_root, current_sth.root_hash)`` against the
        root it already holds. The server never needs to be trusted for the old root: a
        non-prefix history cannot produce a passing proof against the retained root.
        """
        from .transparency import TransparencyLog

        run = self.get(run_id, tenant_id)
        ledger = run.ctx.ledger
        log = TransparencyLog.from_ledger(ledger)
        if first_size < 1 or first_size > log.size:
            raise IndexError(
                f"first_size {first_size} out of range for tree of size {log.size}"
            )
        now = datetime.now(timezone.utc).isoformat()
        sth = log.signed_tree_head(run.ctx.control_plane, now)
        return {
            "run_id": run_id,
            "first_size": first_size,
            "current_size": log.size,
            "consistency_proof": log.consistency_proof(first_size),
            "signed_tree_head": sth.to_dict(),
        }

    def compliance(self, tenant_id: str | None = None) -> dict[str, Any]:
        """Tenant-wide SOC2/GDPR compliance rollup, projected from the run ledgers.

        Isolation-preserving: only this tenant's runs are evaluated. Each run ledger is an
        independently verifiable trail; the tenant is attestable only if every run ledger
        verifies, and compliant only if no control fails in any run.
        """
        from .compliance import ComplianceExporter

        tid = self._resolve_tenant(tenant_id)
        with self._lock:
            runs = [(rid, r) for rid, r in self._runs.items() if r.tenant_id == tid]
        exporter = ComplianceExporter()
        reports = []
        for rid, run in runs:
            report = exporter.generate(run.ctx.ledger, tenant_id=tid)
            view = report.to_view()
            view["run_id"] = rid
            reports.append(view)
        attestable = all(r["attestable"] for r in reports) if reports else True
        compliant = all(r["compliant"] for r in reports) if reports else True
        return {
            "tenant_id": tid,
            "run_count": len(reports),
            "attestable": attestable,
            "compliant": compliant,
            "reports": reports,
        }
