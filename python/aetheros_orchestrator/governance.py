"""Governance bridge between Python orchestration and the Rust core.

This is the seam where orchestration calls into the Rust security primitives via
PyO3. A GovernanceContext owns:

- the control-plane AgentIdentity (the issuer of authority),
- the run's CapabilityLease (issued to the executing agent),
- the EvidenceLedger (the tamper-evident audit trail).

Every governed step passes through `authorize_step` (which calls the Rust lease's
authorize: signature + revocation + expiry + scope + budget) and, on success,
`charge_and_record` (which charges the Rust-tracked budget and appends evidence).
The Python layer never makes an authorization decision itself — it asks the Rust
core and records the outcome.
"""

from __future__ import annotations

from aetheros import AgentIdentity, CapabilityLease, EvidenceLedger
from aetheros.lease import LeaseDenied

from .config import AetherConfig
from .models import Intent, PlanStep


class GovernanceDecision:
    """Outcome of an authorization check for a step."""

    def __init__(self, allowed: bool, reason: str | None = None) -> None:
        self.allowed = allowed
        self.reason = reason

    def __bool__(self) -> bool:
        return self.allowed


class GovernanceContext:
    """Holds identities, the run lease, and the ledger for one governed run."""

    def __init__(
        self,
        config: AetherConfig,
        control_plane: AgentIdentity,
        agent: AgentIdentity,
        ledger: EvidenceLedger,
    ) -> None:
        self._config = config
        self.control_plane = control_plane
        self.agent = agent
        self.ledger = ledger
        self.lease: CapabilityLease | None = None

    @classmethod
    def for_run(
        cls,
        config: AetherConfig,
        intent: Intent,
        required_scopes: list[str],
        ledger: EvidenceLedger | None = None,
        control_plane: AgentIdentity | None = None,
        agent: AgentIdentity | None = None,
    ) -> "GovernanceContext":
        """Bootstrap a governance context: identities, ledger, and a signed lease
        scoped to exactly the capabilities the plan requires (least privilege)."""
        ledger = ledger or EvidenceLedger()
        control_plane = control_plane or AgentIdentity.generate("control-plane")
        agent = agent or AgentIdentity.generate("execution-agent")
        ctx = cls(config, control_plane, agent, ledger)
        ctx.issue_lease(intent, required_scopes)
        return ctx

    def issue_lease(self, intent: Intent, scopes: list[str]) -> CapabilityLease:
        """Issue a signed lease to the agent for exactly `scopes`, recording it."""
        lease = CapabilityLease.issue(
            self.control_plane,
            self.agent.agent_id,
            scopes=sorted(set(scopes)),
            currency=intent.currency,
            limit_minor=intent.budget_minor,
            ttl_seconds=self._config.governance.default_lease_ttl_seconds,
        )
        self.lease = lease
        self.ledger.append(
            "control-plane",
            "lease.issued",
            {
                "lease_id": lease.lease_id,
                "subject": self.agent.agent_id,
                "scopes": lease.scopes,
                "budget_minor": intent.budget_minor,
                "currency": intent.currency,
            },
        )
        return lease

    def requires_approval(self, step: PlanStep) -> bool:
        """Whether a step requires a human approval gate before execution."""
        return bool(self._config.governance.require_human_approval and step.high_impact)

    def authorize_step(self, step: PlanStep) -> GovernanceDecision:
        """Ask the Rust lease whether this step is permitted right now."""
        assert self.lease is not None, "lease not issued"
        try:
            self.lease.authorize(step.scope, step.estimated_cost_minor)
            return GovernanceDecision(True)
        except LeaseDenied as exc:
            self.ledger.append(
                "control-plane",
                "policy.denied",
                {"step_id": step.step_id, "scope": step.scope, "reason": str(exc)},
            )
            return GovernanceDecision(False, str(exc))

    def record_approval(self, step: PlanStep, approver: str, granted: bool) -> None:
        """Record a human approval decision in the ledger."""
        self.ledger.append(
            approver,
            "approval.granted" if granted else "approval.denied",
            {"step_id": step.step_id, "scope": step.scope},
        )

    def charge_and_record(self, step: PlanStep, actual_cost_minor: int, output_summary) -> int:
        """Charge the Rust-tracked budget for a successful step and record evidence.

        Returns the evidence sequence number of the tool.invoked entry.
        """
        assert self.lease is not None
        self.lease.record_spend(actual_cost_minor)
        seq, _hash = self.ledger.append(
            self.agent.agent_id,
            "tool.invoked",
            {
                "step_id": step.step_id,
                "tool": step.tool,
                "scope": step.scope,
                "cost_minor": actual_cost_minor,
                "remaining_minor": self.lease.remaining_minor,
                "output": output_summary,
            },
        )
        return seq
