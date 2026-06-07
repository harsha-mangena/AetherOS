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

from .autonomy import AutonomyTracker
from .config import AetherConfig
from .constitution import ConstitutionEngine
from .models import Intent, PlanStep
from .policy import PolicyEngine


class GovernanceDecision:
    """Outcome of an authorization check for a step."""

    def __init__(
        self,
        allowed: bool,
        reason: str | None = None,
        requires_approval: bool = False,
        deciding_rule_id: str | None = None,
        constitutional_article_id: str | None = None,
    ) -> None:
        self.allowed = allowed
        self.reason = reason
        self.requires_approval = requires_approval
        self.deciding_rule_id = deciding_rule_id
        self.constitutional_article_id = constitutional_article_id

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
        policy: PolicyEngine | None = None,
        autonomy: AutonomyTracker | None = None,
        constitution: ConstitutionEngine | None = None,
    ) -> None:
        self._config = config
        self.control_plane = control_plane
        self.agent = agent
        self.ledger = ledger
        self.lease: CapabilityLease | None = None
        self.policy = policy or PolicyEngine.from_config(config)
        self.autonomy = autonomy or AutonomyTracker.from_config(config)
        self.constitution = constitution or ConstitutionEngine.from_config(config)

    @property
    def autonomy_tier(self) -> int:
        """Current earned-autonomy tier of the executing agent."""
        return self.autonomy.tier(self.agent.agent_id)

    @classmethod
    def for_run(
        cls,
        config: AetherConfig,
        intent: Intent,
        required_scopes: list[str],
        ledger: EvidenceLedger | None = None,
        control_plane: AgentIdentity | None = None,
        agent: AgentIdentity | None = None,
        policy: PolicyEngine | None = None,
        autonomy: AutonomyTracker | None = None,
        constitution: ConstitutionEngine | None = None,
    ) -> "GovernanceContext":
        """Bootstrap a governance context: identities, ledger, and a signed lease
        scoped to exactly the capabilities the plan requires (least privilege)."""
        ledger = ledger or EvidenceLedger()
        control_plane = control_plane or AgentIdentity.generate("control-plane")
        agent = agent or AgentIdentity.generate("execution-agent")
        ctx = cls(
            config,
            control_plane,
            agent,
            ledger,
            policy=policy,
            autonomy=autonomy,
            constitution=constitution,
        )
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
        """Whether a step requires a human approval gate before execution.

        A step is gated if config marks it high-impact-by-policy OR the Rust policy
        engine's decision for the step demands approval at the agent's current tier.
        """
        if self._config.governance.require_human_approval and step.high_impact:
            return True
        # The constitution can demand a human gate before policy is even consulted.
        verdict = self.constitution.judge(
            scope=step.scope,
            tool=step.tool,
            autonomy_tier=self.autonomy_tier,
            cost_minor=step.estimated_cost_minor,
            high_impact=step.high_impact,
        )
        if verdict.permitted and verdict.requires_approval:
            return True
        decision = self.policy.evaluate(
            scope=step.scope,
            tool=step.tool,
            autonomy_tier=self.autonomy_tier,
            cost_minor=step.estimated_cost_minor,
            high_impact=step.high_impact,
        )
        return bool(decision.allowed and decision.requires_approval)

    def authorize_step(self, step: PlanStep) -> GovernanceDecision:
        """Authorize a step: the Rust policy engine AND the Rust lease must both allow.

        Order: policy first (is this class of action permitted for this agent's tier?),
        then the lease (does this specific agent hold the scope, budget, and a valid,
        unexpired, unrevoked grant?). Either denial halts the step and records evidence,
        and a policy denial is also counted as an autonomy violation.
        """
        assert self.lease is not None, "lease not issued"

        # Supreme layer: the constitution is consulted before policy. A constitutional
        # forbid is absolute and short-circuits the entire pipeline; no policy allow and
        # no autonomy tier can override it. It is also counted as an autonomy violation.
        verdict = self.constitution.judge(
            scope=step.scope,
            tool=step.tool,
            autonomy_tier=self.autonomy_tier,
            cost_minor=step.estimated_cost_minor,
            high_impact=step.high_impact,
        )
        if not verdict.permitted:
            self.autonomy.record_violation(self.agent.agent_id)
            self.ledger.append(
                "control-plane",
                "constitution.violation",
                {
                    "step_id": step.step_id,
                    "scope": step.scope,
                    "article_id": verdict.article_id,
                    "principle": verdict.principle,
                    "reason": verdict.reason,
                },
            )
            return GovernanceDecision(
                False,
                verdict.reason,
                constitutional_article_id=verdict.article_id,
            )

        decision = self.policy.evaluate(
            scope=step.scope,
            tool=step.tool,
            autonomy_tier=self.autonomy_tier,
            cost_minor=step.estimated_cost_minor,
            high_impact=step.high_impact,
        )
        if not decision.allowed:
            self.autonomy.record_violation(self.agent.agent_id)
            self.ledger.append(
                "control-plane",
                "policy.denied",
                {
                    "step_id": step.step_id,
                    "scope": step.scope,
                    "reason": decision.reason,
                    "deciding_rule_id": decision.deciding_rule_id,
                },
            )
            return GovernanceDecision(
                False, decision.reason, deciding_rule_id=decision.deciding_rule_id
            )

        try:
            self.lease.authorize(step.scope, step.estimated_cost_minor)
            return GovernanceDecision(
                True,
                requires_approval=decision.requires_approval,
                deciding_rule_id=decision.deciding_rule_id,
            )
        except LeaseDenied as exc:
            self.ledger.append(
                "control-plane",
                "policy.denied",
                {"step_id": step.step_id, "scope": step.scope, "reason": str(exc)},
            )
            return GovernanceDecision(False, str(exc))

    def record_run_success(self) -> bool:
        """Record a fully successful run as an autonomy success. Returns True if the
        agent was promoted to a higher autonomy tier."""
        promoted = self.autonomy.record_success(self.agent.agent_id)
        if promoted:
            self.ledger.append(
                "control-plane",
                "autonomy.promoted",
                {"agent": self.agent.agent_id, "tier": self.autonomy_tier},
            )
        return promoted

    def record_approval(self, step: PlanStep, approver: str, granted: bool) -> None:
        """Record a human approval decision in the ledger."""
        self.ledger.append(
            approver,
            "approval.granted" if granted else "approval.denied",
            {"step_id": step.step_id, "scope": step.scope},
        )

    def charge_and_record(
        self, step: PlanStep, actual_cost_minor: int, output_summary, provenance_id: str | None = None
    ) -> int:
        """Charge the Rust-tracked budget for a successful step and record evidence.

        Returns the evidence sequence number of the tool.invoked entry. When the step
        executed inside a sandbox, `provenance_id` ties the ledger entry to the
        verifiable sandbox provenance record (Phase 4).
        """
        assert self.lease is not None
        self.lease.record_spend(actual_cost_minor)
        payload = {
            "step_id": step.step_id,
            "tool": step.tool,
            "scope": step.scope,
            "cost_minor": actual_cost_minor,
            "remaining_minor": self.lease.remaining_minor,
            "output": output_summary,
        }
        if provenance_id is not None:
            payload["provenance_id"] = provenance_id
        seq, _hash = self.ledger.append(
            self.agent.agent_id,
            "tool.invoked",
            payload,
        )
        return seq
