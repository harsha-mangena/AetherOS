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

import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from aetheros import EvidenceLedger
from aetheros.identity import AgentIdentity
from aetheros.lease import CapabilityLease

from .config import AetherConfig, load_config
from .governance import GovernanceContext
from .intent_compiler import IntentCompiler
from .ledger_store import make_ledger, DurableLedger, SQLiteStore, NoStore
from .mcp_adapter import MCPAdapter, default_incident_adapter
from .models import ExecutionPlan, Intent, PlanStep, StepResult, StepStatus
from .run_state_store import RunStateStore, make_run_state_store
from .sandbox import SandboxController, SandboxExecutionError, build_local_sandbox
from .tenancy import (
    DEFAULT_TENANT_ID,
    CrossTenantAccess,
    TenantRegistry,
)
from .collaboration import CollaborationRegistry, CollaborationError, NotAMember, MembershipRevoked
from .marketplace import SkillMarketplace, SignedSkill, SkillManifest, MarketplaceError
from .constitution import ConstitutionEngine
from . import tracing as _tracing
from . import trace_log as _trace_log


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


class RunStateSerializer:
    """Serialize/restore a ``RunState`` for durability (Phase 13).

    The serializer is the single choke point that decides exactly what survives a
    restart and how it is reconstructed. It captures three classes of state:

    * plain resumable structure (status, cursor, results, intent, plan, …),
    * the governance restoration triple (control-plane + agent identities as
      seed-hex, and the signed lease JSON which preserves spent budget + signature),
    * the executing agent's earned-autonomy snapshot.

    The durable evidence ledger is persisted/restored separately by the Phase-10
    ``LedgerStore`` and re-attached during restore. Live objects (sandbox, policy,
    constitution) are rebuilt from config, never pickled.

    ``SERIAL_VERSION`` lets a future format change be detected at load time.
    """

    SERIAL_VERSION = 1

    @staticmethod
    def dump(run: "RunState") -> str:
        """Produce the canonical-JSON state document for a run."""
        ctx = run.ctx
        assert ctx.lease is not None, "cannot persist a run whose lease was never issued"
        doc: dict[str, Any] = {
            "serial_version": RunStateSerializer.SERIAL_VERSION,
            "run_id": run.run_id,
            "tenant_id": run.tenant_id,
            "status": run.status,
            "cursor": run.cursor,
            "pending_step_id": run.pending_step_id,
            "total_cost_minor": run.total_cost_minor,
            "denied_reason": run.denied_reason,
            "created_at": run.created_at,
            "intent": run.intent.model_dump(),
            # Persist the plan verbatim — never recompile on restore, so a
            # non-deterministic/evolving IntentCompiler cannot make a restored run
            # diverge from the one that was authorized and partially executed.
            "plan": run.plan.model_dump(),
            "results": [r.model_dump() for r in run.results],
            "destinations": dict(run.destinations),
            # ── governance restoration triple ──────────────────────────────────
            "control_plane": {
                "agent_id": ctx.control_plane.agent_id,
                "display_name": ctx.control_plane.display_name,
                "created_at": ctx.control_plane.created_at,
                "seed_hex": ctx.control_plane.secret_seed_hex(),
            },
            "agent": {
                "agent_id": ctx.agent.agent_id,
                "display_name": ctx.agent.display_name,
                "created_at": ctx.agent.created_at,
                "seed_hex": ctx.agent.secret_seed_hex(),
            },
            # Lease JSON preserves spent_minor (consumed budget) + issuer signature.
            "lease_json": ctx.lease.to_json(),
            # Earned-autonomy snapshot for the executing agent (drives approval gates).
            "autonomy_json": json.dumps(ctx.autonomy.snapshot(ctx.agent.agent_id)),
        }
        return json.dumps(doc, separators=(",", ":"), sort_keys=True)

    @staticmethod
    def load(
        state_json: str,
        config: AetherConfig,
        ledger: EvidenceLedger,
        adapter: MCPAdapter,
    ) -> "RunState":
        """Reconstruct a fully live ``RunState`` from its persisted document.

        ``ledger`` must be the run's restored durable ledger (loaded by the caller
        via the Phase-10 store). ``adapter`` + ``config`` rebuild the sandbox and the
        policy/constitution engines deterministically. The lease and identities are
        restored exactly, so the run resumes with the authority and consumed budget
        it had before the restart.
        """
        doc = json.loads(state_json)
        version = doc.get("serial_version")
        if version != RunStateSerializer.SERIAL_VERSION:
            raise ValueError(
                f"unsupported run-state serial_version {version!r} "
                f"(expected {RunStateSerializer.SERIAL_VERSION})"
            )

        intent = Intent.model_validate(doc["intent"])
        plan = ExecutionPlan.model_validate(doc["plan"])
        results = [StepResult.model_validate(r) for r in doc["results"]]

        cp = doc["control_plane"]
        control_plane = AgentIdentity.from_seed_hex(
            cp["agent_id"], cp["display_name"], cp["created_at"], cp["seed_hex"]
        )
        ag = doc["agent"]
        agent = AgentIdentity.from_seed_hex(
            ag["agent_id"], ag["display_name"], ag["created_at"], ag["seed_hex"]
        )
        lease = CapabilityLease.from_json(doc["lease_json"])

        from .autonomy import AutonomyTracker

        autonomy = AutonomyTracker.from_config(config)
        autonomy.restore(agent.agent_id, doc["autonomy_json"])

        ctx = GovernanceContext.restore(
            config,
            control_plane=control_plane,
            agent=agent,
            ledger=ledger,
            lease=lease,
            autonomy=autonomy,
        )

        sandbox, _destinations = build_local_sandbox(config, adapter)
        destinations = dict(doc.get("destinations") or _destinations)

        run = RunState(
            run_id=doc["run_id"],
            intent=intent,
            plan=plan,
            ctx=ctx,
            sandbox=sandbox,
            destinations=destinations,
            tenant_id=doc["tenant_id"],
            status=doc["status"],
            cursor=doc["cursor"],
            results=results,
            total_cost_minor=doc["total_cost_minor"],
            denied_reason=doc["denied_reason"],
            created_at=doc["created_at"],
            pending_step_id=doc["pending_step_id"],
        )
        return run


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
        # Phase 23: graceful drain. When drain() is called (e.g. on SIGTERM),
        # _draining is set to True. advance() checks this flag before each step
        # and halts the run with reason "service draining" instead of executing it.
        # This guarantees a terminal ledger entry for every in-flight run before exit.
        self._draining: bool = False
        self._drain_complete = threading.Event()
        # For the MVP demo, model an agent that has already earned a track record so
        # infra mutations are policy-allowed (still gated by human approval). Real
        # deployments would load persisted autonomy per agent.
        self._earn_autonomy_to = earn_autonomy_to
        # Tenancy: a registry of isolation boundaries. The default tenant always exists
        # so single-tenant callers (and the existing tests/demo) work unchanged.
        self._tenants = registry or TenantRegistry()
        self._tenants.ensure(DEFAULT_TENANT_ID, "Default Workspace")
        # Witness panel (Phase 9b/9c): a persistent set of independent witnesses that
        # cosign this control plane's signed tree heads, defeating split-view attacks.
        # Built once and reused across calls so each witness retains the last root it
        # endorsed per log (run) — which is what makes the consistency check meaningful.
        self._witness_registry = self._build_witness_registry()
        # Phase 11: multi-agent collaboration registry (tenant-isolated shared ledgers).
        self._collaborations = CollaborationRegistry()
        # Phase 11: governed skill marketplace (Ed25519 origin + constitution gate).
        self._marketplace = SkillMarketplace(
            constitution=ConstitutionEngine.from_config(self._config)
        )
        # Phase 13: run-state durability. When storage.persist_runs is true, every
        # state-machine transition is snapshotted to SQLite and in-flight runs are
        # repopulated from disk at startup — so a run paused at a human approval gate
        # survives a service restart. Default NoRunStateStore → in-memory only.
        scfg = self._config.storage
        self._persist_runs = scfg.persist_runs
        self._run_store: RunStateStore = make_run_state_store(
            backend="sqlite" if scfg.persist_runs else "none",
            db_dir=scfg.run_state_db_dir,
            passphrase=getattr(scfg, "encryption_passphrase", ""),
        )
        if self._persist_runs:
            self._restore_runs_from_storage()

    def _build_witness_registry(self):
        """Construct the config-driven witness panel (lazy import; zero-hardcoding)."""
        import aetheros
        from .witness import Witness, WitnessRegistry

        tcfg = self._config.transparency
        count = max(1, tcfg.witness_count)
        witnesses = [
            Witness(aetheros.AgentIdentity.generate(f"witness-{i}"))
            for i in range(count)
        ]
        threshold = tcfg.witness_threshold if tcfg.witness_threshold > 0 else None
        return WitnessRegistry(witnesses, threshold=threshold)

    @property
    def witness_panel_size(self) -> int:
        return self._witness_registry.size

    @property
    def witness_threshold(self) -> int:
        return self._witness_registry.threshold

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

    # ── run-state durability (Phase 13) ───────────────────────────────────────

    def _persist_run(self, run: RunState) -> None:
        """Snapshot a run's resumable state to the durable store (no-op if disabled).

        Called after every state-machine transition. The evidence ledger persists
        itself independently after each append (Phase 10 DurableLedger); this writes
        the run scalars + governance restoration triple so the two together fully
        reconstruct the run.
        """
        if not self._persist_runs:
            return
        self._run_store.persist(run.tenant_id, run.run_id, RunStateSerializer.dump(run))

    def _restore_runs_from_storage(self) -> None:
        """Repopulate ``self._runs`` from durable storage at service startup.

        For each persisted run: restore its evidence ledger from the Phase-10 ledger
        store (Rust re-verifies the hash chain), then rebuild the live RunState via
        the serializer. A run whose ledger snapshot is missing or fails verification
        is skipped (logged via the ledger raising) so one corrupt run can't block the
        whole service from coming back up.
        """
        scfg = self._config.storage
        for tenant_id, run_id, state_json in self._run_store.load_all():
            try:
                ledger = self._restore_ledger(tenant_id, run_id)
                run = RunStateSerializer.load(
                    state_json, self._config, ledger, self._adapter
                )
            except Exception:
                # Skip unrecoverable runs; the durable evidence remains on disk for
                # forensic inspection. Do not let one bad row abort startup.
                continue
            self._runs[run.run_id] = run

    def _restore_ledger(self, tenant_id: str, run_id: str):
        """Load a run's durable evidence ledger for restoration.

        When the ledger backend is SQLite, restore via DurableLedger.from_storage
        (Rust re-verifies the chain). Otherwise the ledger was never persisted, so
        the restored run gets a fresh in-memory ledger wrapper — the run scalars and
        lease still restore, but prior evidence is not available (this is the
        documented persist_runs-without-sqlite mode).
        """
        scfg = self._config.storage
        if scfg.backend == "sqlite":
            store = SQLiteStore(db_dir=scfg.db_dir)
            return DurableLedger.from_storage(tenant_id, run_id, store)
        return DurableLedger(tenant_id, run_id, NoStore())

    def create_run(
        self,
        intent_text: str,
        submitted_by: str = "human:operator",
        budget_minor: int = 100_000,
        tenant_id: str | None = None,
    ) -> RunState:
        if self._draining:
            raise RuntimeError("service is draining — no new runs accepted")
        tid = self._resolve_tenant(tenant_id)
        tenant = self._tenants.get(tid)
        # Per-tenant budget ceiling: a tenant can cap spend below the requested budget.
        if tenant.max_budget_minor is not None:
            budget_minor = min(budget_minor, tenant.max_budget_minor)
        intent = Intent(text=intent_text, submitted_by=submitted_by, budget_minor=budget_minor)
        run_id = uuid.uuid4().hex
        # Phase 10: use the config-driven ledger backend (NoStore by default → identical
        # to prior in-memory behavior; SQLiteStore when storage.backend="sqlite").
        scfg = self._config.storage
        ledger = make_ledger(tid, run_id, backend=scfg.backend, db_dir=scfg.db_dir)
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
            run_id=run_id,
            intent=intent,
            plan=plan,
            ctx=ctx,
            sandbox=sandbox,
            destinations=destinations,
            tenant_id=tid,
        )
        with self._lock:
            self._runs[run.run_id] = run
        self._persist_run(run)
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

        # Refuse to start new work if the service is draining.
        if self._draining:
            return self._drain_halt(run)

        tracer = _tracing.get_tracer()
        with tracer.start_as_current_span(
            "aetheros.run.advance",
            attributes={
                "aetheros.tenant_id": run.tenant_id,
                "aetheros.run_id": run_id,
                "aetheros.plan_id": run.plan.plan_id,
            },
        ):
            run.status = RunStatus.RUNNING

            while run.cursor < len(run.plan.steps):
                step = run.plan.steps[run.cursor]

                # Check drain flag before each step — allows current step to complete.
                if self._draining:
                    return self._drain_halt(run)

                # Pause for human approval before processing a gated step.
                if run.ctx.requires_approval(step):
                    run.status = RunStatus.AWAITING_APPROVAL
                    run.pending_step_id = step.step_id
                    self._persist_run(run)  # the paused gate must survive a restart
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
        tracer = _tracing.get_tracer()
        step_attrs = {
            "aetheros.tenant_id": run.tenant_id,
            "aetheros.run_id": run.run_id,
            "aetheros.step_id": step.step_id,
            "aetheros.tool": step.tool,
            "aetheros.scope": step.scope,
            "aetheros.high_impact": step.high_impact,
        }

        # Authorize.
        with tracer.start_as_current_span("aetheros.governance.authorize", attributes=step_attrs):
            decision = run.ctx.authorize_step(step)
        if not decision:
            run.results.append(
                StepResult(step_id=step.step_id, status=StepStatus.DENIED, detail=decision.reason)
            )
            run.denied_reason = decision.reason
            self._finalize(run, completed=False)
            return False

        # Execute.
        try:
            with tracer.start_as_current_span("aetheros.tool.invoke", attributes=step_attrs):
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

        # Charge and record.
        trace_ctx = _trace_log.get_trace_context()
        with tracer.start_as_current_span("aetheros.ledger.append", attributes=step_attrs):
            cost = step.estimated_cost_minor
            extra: dict | None = None
            if trace_ctx.get("trace_id"):
                extra = {"_trace_id": trace_ctx["trace_id"], "_span_id": trace_ctx["span_id"]}
            seq = run.ctx.charge_and_record(step, cost, output, provenance_id=provenance_id, extra_payload=extra)

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

    # ── run lifecycle (Phase 11) ─────────────────────────────────────────────

    def cancel_run(self, run_id: str, tenant_id: str | None = None) -> RunState:
        """Cancel a run that has not yet reached a terminal state.

        A cancelled run transitions to HALTED with a cancellation note in the evidence
        ledger so the audit trail records who/when/why the run was terminated early.
        Already-COMPLETED or already-HALTED runs are returned unchanged (idempotent).
        """
        run = self.get(run_id, tenant_id)
        if run.status in (RunStatus.COMPLETED, RunStatus.HALTED):
            return run
        run.ctx.ledger.append(
            "control-plane",
            "run.cancelled",
            {"run_id": run_id, "prior_status": run.status},
        )
        run.status = RunStatus.HALTED
        run.denied_reason = "cancelled by operator"
        self._persist_run(run)
        return run

    def delete_run(self, run_id: str, tenant_id: str | None = None) -> None:
        """Remove a run from the service registry.

        Only terminal (COMPLETED or HALTED) runs may be deleted; active runs must
        be cancelled first. Raises ValueError for non-terminal runs to prevent
        accidental loss of in-flight evidence.
        """
        run = self.get(run_id, tenant_id)
        if run.status not in (RunStatus.COMPLETED, RunStatus.HALTED):
            raise ValueError(
                f"run {run_id} is in state '{run.status}' — cancel it before deleting"
            )
        with self._lock:
            self._runs.pop(run_id, None)
        # Purge durable run state so a deleted run is not resurrected on restart.
        if self._persist_runs:
            self._run_store.delete(run.tenant_id, run_id)

    # ── collaboration (Phase 11) ─────────────────────────────────────────────

    def open_collaboration(self, collaboration_id: str, tenant_id: str | None = None) -> dict[str, Any]:
        """Open (or retrieve) a tenant-scoped shared ledger for multi-agent collaboration."""
        tid = self._resolve_tenant(tenant_id)
        collab = self._collaborations.open(collaboration_id, tid)
        return {
            "collaboration_id": collab.collaboration_id,
            "tenant_id": collab.tenant_id,
            "member_count": len(collab._members),  # noqa: SLF001 — same package
            "ledger_length": collab.ledger.length,
        }

    def list_collaborations(self, tenant_id: str | None = None) -> list[dict[str, Any]]:
        """List all collaborations visible to a tenant."""
        tid = self._resolve_tenant(tenant_id)
        with self._collaborations._lock:  # noqa: SLF001 — same package
            pairs = [
                (cid, collab)
                for (t, cid), collab in self._collaborations._collabs.items()  # noqa: SLF001
                if t == tid
            ]
        return [
            {
                "collaboration_id": cid,
                "tenant_id": tid,
                "member_count": len(collab._members),  # noqa: SLF001
                "ledger_length": collab.ledger.length,
            }
            for cid, collab in pairs
        ]

    def admit_to_collaboration(
        self,
        collaboration_id: str,
        agent_id: str,
        lease_dict: dict[str, Any],
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        """Admit an agent to a collaboration, verifying its capability lease.

        `lease_dict` is the JSON representation of a CapabilityLease (as produced by
        `lease.to_dict()`). The lease signature is verified inside `SharedLedger.admit`.
        """
        import aetheros
        tid = self._resolve_tenant(tenant_id)
        try:
            collab = self._collaborations.get(collaboration_id, tid)
        except Exception:
            collab = self._collaborations.open(collaboration_id, tid)
        import json as _json
        lease = aetheros.CapabilityLease.from_json(_json.dumps(lease_dict))
        membership = collab.admit(tid, agent_id, lease)
        return {
            "collaboration_id": collaboration_id,
            "agent_id": membership.agent_id,
            "lease_id": membership.lease_id,
            "admitted_at_seq": membership.admitted_at_seq,
        }

    def contribute_to_collaboration(
        self,
        collaboration_id: str,
        agent_id: str,
        event_type: str,
        payload: dict[str, Any],
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        """Append an attributed entry to a collaboration's shared ledger."""
        tid = self._resolve_tenant(tenant_id)
        collab = self._collaborations.get(collaboration_id, tid)
        seq, entry_hash = collab.contribute(tid, agent_id, event_type, payload)
        return {
            "collaboration_id": collaboration_id,
            "seq": seq,
            "entry_hash": entry_hash,
            "agent_id": agent_id,
            "event_type": event_type,
        }

    def get_collaboration(self, collaboration_id: str, tenant_id: str | None = None) -> dict[str, Any]:
        """Fetch a collaboration's state and its full tamper-evident ledger."""
        tid = self._resolve_tenant(tenant_id)
        collab = self._collaborations.get(collaboration_id, tid)
        return {
            "collaboration_id": collab.collaboration_id,
            "tenant_id": collab.tenant_id,
            "verified": collab.verify(tid),
            "members": [
                {"agent_id": m.agent_id, "lease_id": m.lease_id, "admitted_at_seq": m.admitted_at_seq}
                for m in collab.members(tid)
            ],
            "ledger_length": collab.ledger.length,
            "entries": [
                {
                    "seq": e.seq,
                    "actor": e.actor,
                    "event_type": e.event_type,
                    "payload": e.payload,
                    "entry_hash": e.entry_hash,
                }
                for e in collab.ledger.entries()
            ],
        }

    # ── marketplace (Phase 11) ────────────────────────────────────────────────

    def marketplace_publish(self, manifest_dict: dict[str, Any], signature: str) -> dict[str, Any]:
        """Publish a signed skill to the governed marketplace catalog.

        The manifest dict must contain: skill_id, version, publisher_agent_id,
        publisher_public_key, required_scopes (list), declared_tools (list),
        description (optional). Raises MarketplaceError if the signature is invalid.
        """
        manifest = SkillManifest(
            skill_id=manifest_dict["skill_id"],
            version=manifest_dict["version"],
            publisher_agent_id=manifest_dict["publisher_agent_id"],
            publisher_public_key=manifest_dict["publisher_public_key"],
            required_scopes=tuple(manifest_dict.get("required_scopes", [])),
            declared_tools=tuple(manifest_dict.get("declared_tools", [])),
            description=manifest_dict.get("description", ""),
        )
        signed = SignedSkill(manifest=manifest, signature=signature)
        self._marketplace.publish(signed)
        return manifest.to_view()

    def marketplace_catalog(self) -> list[dict[str, Any]]:
        """Return all skills listed in the governed marketplace catalog."""
        return [m.to_view() for m in self._marketplace.catalog()]

    def marketplace_install(
        self,
        skill_id: str,
        version: str,
        tenant_id: str | None = None,
        permitted_scopes: list[str] | None = None,
    ) -> dict[str, Any]:
        """Install a catalog skill under the full governance gate for a tenant.

        Verifies Ed25519 origin, checks least-privilege scope delegation, and
        evaluates constitutional supremacy before admitting the skill.
        """
        tid = self._resolve_tenant(tenant_id)
        # Look up the signed skill from the catalog by id@version key.
        key = f"{skill_id}@{version}"
        with self._marketplace._lock:  # noqa: SLF001 — same package
            signed = self._marketplace._catalog.get(key)  # noqa: SLF001
        if signed is None:
            raise KeyError(f"skill {key!r} not found in catalog")
        scopes = set(permitted_scopes or [])
        installed = self._marketplace.install(signed, tid, scopes)
        return {
            "skill_id": installed.manifest.skill_id,
            "version": installed.manifest.version,
            "tenant_id": tid,
            "installed_at_seq": installed.installed_at_seq,
            "required_scopes": sorted(installed.manifest.required_scopes),
            "declared_tools": sorted(installed.manifest.declared_tools),
        }

    def marketplace_installed(self, tenant_id: str | None = None) -> list[dict[str, Any]]:
        """List all skills installed under a tenant."""
        tid = self._resolve_tenant(tenant_id)
        return [
            {
                "skill_id": s.manifest.skill_id,
                "version": s.manifest.version,
                "installed_at_seq": s.installed_at_seq,
                "required_scopes": sorted(s.manifest.required_scopes),
                "declared_tools": sorted(s.manifest.declared_tools),
            }
            for s in self._marketplace.installed(tid)
        ]

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
        self._persist_run(run)
        return run

    def _drain_halt(self, run: "RunState") -> "RunState":
        """Record a graceful-drain halt entry in the ledger and finalize the run."""
        if run.status in (RunStatus.COMPLETED, RunStatus.HALTED):
            return run
        run.denied_reason = "service draining — run halted gracefully"
        run.ctx.ledger.append(
            "control-plane",
            "run.drain_halted",
            {
                "plan_id": run.plan.plan_id,
                "cursor": run.cursor,
                "total_cost_minor": run.total_cost_minor,
                "reason": "service draining",
            },
        )
        return self._finalize(run, completed=False)

    def drain(self, timeout_seconds: int = 30) -> int:
        """Gracefully halt all in-flight runs and wait for them to reach terminal state.

        Sets the drain flag so advance() halts any new step execution. Then waits
        up to timeout_seconds for all runs currently in RUNNING status to reach a
        terminal state. Returns the number of runs that were drained (halted during
        the drain window).

        This is called by the FastAPI lifespan shutdown handler (via asyncio.to_thread)
        so it does not block the event loop.

        Standards: Kubernetes Graceful Termination (k8s docs v1.29 §Pod Lifecycle)
        recommends draining in-flight work within terminationGracePeriodSeconds (default 30s).
        """
        self._draining = True
        deadline = time.monotonic() + timeout_seconds
        drained = 0

        while time.monotonic() < deadline:
            with self._lock:
                running = [r for r in self._runs.values() if r.status == RunStatus.RUNNING]
            if not running:
                break
            # Drain each running run.
            for run in running:
                if run.status == RunStatus.RUNNING:
                    self._drain_halt(run)
                    drained += 1
            time.sleep(0.05)  # 50ms poll — allows advance() to see the flag

        return drained

    @property
    def is_draining(self) -> bool:
        """True if the service is in drain mode (no new steps will be executed)."""
        return self._draining

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

    def transparency_cosigned(
        self,
        run_id: str,
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        """Signed Tree Head plus independent witness cosignatures (Phase 9c).

        Gossips the current STH to the persistent witness panel. Each witness retains
        the last root it endorsed for *this run's log* and only cosigns a new head it
        can prove grew append-only from the root it itself holds — so a control plane
        that tried to show two divergent histories for the same run would have at least
        one honest witness refuse, exposing the fork. The head is publicly trustworthy
        once ``threshold`` distinct witnesses cosign it.

        Calling this repeatedly as the ledger grows exercises the real consistency path:
        the second call must carry a consistency proof from the witness's retained root,
        which the witness verifies before advancing.
        """
        from .transparency import TransparencyLog

        run = self.get(run_id, tenant_id)
        ledger = run.ctx.ledger
        log = TransparencyLog.from_ledger(ledger)
        now = datetime.now(timezone.utc).isoformat()
        sth = log.signed_tree_head(run.ctx.control_plane, now)

        # If any witness has already endorsed an earlier head for this run, supply a
        # consistency proof from that retained size to now so honest growth is cosignable.
        proof: dict[str, Any] | None = None
        retained = self._min_retained_size(run_id)
        if retained is not None and retained < log.size:
            proof = log.consistency_proof(retained)

        cosigned = self._witness_registry.cosign(run_id, sth, consistency_proof=proof)
        return {
            "run_id": run_id,
            "ledger_verified": ledger.verify(),
            "signed_tree_head": sth.to_dict(),
            "cosignatures": [c.to_dict() for c in cosigned.cosignatures],
            "witness_count": self._witness_registry.size,
            "threshold": self._witness_registry.threshold,
            "trustworthy": self._witness_registry.is_trustworthy(cosigned),
        }

    def _min_retained_size(self, log_id: str) -> int | None:
        """The smallest tree size any panel witness has retained for ``log_id``.

        A consistency proof from this size satisfies every witness that has advanced at
        least this far; witnesses on their first sighting need no proof and cosign anyway.
        Returns None if no witness has yet endorsed a head for the log.
        """
        sizes = [
            seen[0]
            for w in self._witness_registry._witnesses  # noqa: SLF001 — same package
            if (seen := w.last_seen(log_id)) is not None
        ]
        return min(sizes) if sizes else None

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

    def audit_runs(self, tenant_id: str | None = None) -> list[tuple[str, str, Any]]:
        """Return [(run_id, tenant_id, ledger), ...] for all runs owned by this tenant.

        Helper for both audit_events() and audit_summary() — centralises the
        per-tenant run lookup so both endpoints share one consistent data source.
        Isolation-preserving: only this tenant's runs are returned.
        """
        tid = self._resolve_tenant(tenant_id)
        with self._lock:
            return [
                (rid, tid, r.ctx.ledger)
                for rid, r in self._runs.items()
                if r.tenant_id == tid
            ]

    def audit_events(
        self,
        tenant_id: str | None = None,
        event_type: str | None = None,
        since: str | None = None,
        until: str | None = None,
        actor: str | None = None,
        offset: int = 0,
        limit: int = 100,
        max_limit: int = 1000,
    ):
        """Return a paginated, filtered AuditPage from all runs for this tenant.

        Delegates to AuditExporter.export() with the full set of runs belonging
        to the tenant. Returns an AuditPage dataclass (serialisable via .to_dict()).
        """
        from .audit_exporter import AuditExporter

        runs = self.audit_runs(tenant_id)
        exporter = AuditExporter()
        return exporter.export(
            runs,
            event_type=event_type,
            since=since,
            until=until,
            actor=actor,
            offset=offset,
            limit=limit,
            max_limit=max_limit,
        )

    def audit_summary(self, tenant_id: str | None = None) -> dict:
        """Return an event-count summary across all runs for this tenant.

        Lighter than a full event export — useful for dashboard widgets and
        SIEM health checks. Delegates to AuditExporter.summary().
        """
        from .audit_exporter import AuditExporter

        runs = self.audit_runs(tenant_id)
        return AuditExporter.summary(runs)
