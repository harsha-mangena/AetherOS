"""Analytics: per-tenant usage, autonomy, and governance metrics (Phase 6).

A core design choice: analytics is a *pure projection over the evidence ledger*, not a
separate mutable store. The tamper-evident ledger is already the source of truth for
everything that happened (every tool.invoked, policy.denied, approval.granted/denied,
autonomy.promoted, run.completed/halted entry). Deriving metrics by folding over those
entries means the dashboard can never drift from the audit trail — if the ledger
verifies, the numbers are trustworthy by construction, and any metric can be traced back
to the exact entries that produced it.

Scope: metrics are always computed per tenant by aggregating that tenant's runs' ledgers
(the RunService already enforces tenant isolation on which runs are visible). Cross-tenant
aggregation is never possible through this module because it only ever receives one
tenant's runs.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterable


# Event vocabulary emitted by the governance/run layers (see governance.py, run_service.py).
EV_LEASE_ISSUED = "lease.issued"
EV_TOOL_INVOKED = "tool.invoked"
EV_TOOL_FAILED = "tool.failed"
EV_POLICY_DENIED = "policy.denied"
EV_APPROVAL_GRANTED = "approval.granted"
EV_APPROVAL_DENIED = "approval.denied"
EV_AUTONOMY_PROMOTED = "autonomy.promoted"
EV_RUN_COMPLETED = "run.completed"
EV_RUN_HALTED = "run.halted"


@dataclass
class TenantAnalytics:
    """Aggregated metrics for one tenant, derived from its runs' ledgers."""

    tenant_id: str
    runs_total: int = 0
    runs_completed: int = 0
    runs_halted: int = 0
    tool_invocations: int = 0
    tool_failures: int = 0
    policy_violations: int = 0
    approvals_granted: int = 0
    approvals_denied: int = 0
    autonomy_promotions: int = 0
    total_spend_minor: int = 0
    # Spend and invocation counts broken down by tool, for the dashboard.
    spend_by_tool: dict[str, int] = field(default_factory=dict)
    invocations_by_tool: dict[str, int] = field(default_factory=dict)
    # Every metric is backed by the evidence: total entries folded.
    evidence_entries_scanned: int = 0
    all_ledgers_verified: bool = True

    @property
    def completion_rate(self) -> float:
        return (self.runs_completed / self.runs_total) if self.runs_total else 0.0

    @property
    def approval_rate(self) -> float:
        total = self.approvals_granted + self.approvals_denied
        return (self.approvals_granted / total) if total else 0.0

    def to_view(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "runs": {
                "total": self.runs_total,
                "completed": self.runs_completed,
                "halted": self.runs_halted,
                "completion_rate": round(self.completion_rate, 4),
            },
            "tools": {
                "invocations": self.tool_invocations,
                "failures": self.tool_failures,
                "by_tool": self.invocations_by_tool,
            },
            "governance": {
                "policy_violations": self.policy_violations,
                "approvals_granted": self.approvals_granted,
                "approvals_denied": self.approvals_denied,
                "approval_rate": round(self.approval_rate, 4),
                "autonomy_promotions": self.autonomy_promotions,
            },
            "spend": {
                "total_minor": self.total_spend_minor,
                "by_tool": self.spend_by_tool,
            },
            "integrity": {
                "evidence_entries_scanned": self.evidence_entries_scanned,
                "all_ledgers_verified": self.all_ledgers_verified,
            },
        }


def compute_tenant_analytics(tenant_id: str, evidence_reports: Iterable[dict[str, Any]]) -> TenantAnalytics:
    """Fold a tenant's run evidence reports (from RunService.evidence) into metrics.

    Each report is the dict returned by RunService.evidence(): {verified, entries:[...]}.
    This function never sees other tenants' data — the caller passes only this tenant's
    reports — so isolation is preserved by construction.
    """
    a = TenantAnalytics(tenant_id=tenant_id)
    spend_by_tool: Counter[str] = Counter()
    inv_by_tool: Counter[str] = Counter()

    for report in evidence_reports:
        a.runs_total += 1
        if not report.get("verified", False):
            a.all_ledgers_verified = False
        run_completed = False
        run_halted = False
        for entry in report.get("entries", []):
            a.evidence_entries_scanned += 1
            etype = entry.get("event_type")
            payload = entry.get("payload", {}) or {}
            if etype == EV_TOOL_INVOKED:
                a.tool_invocations += 1
                tool = payload.get("tool", "unknown")
                cost = int(payload.get("cost_minor", 0) or 0)
                a.total_spend_minor += cost
                spend_by_tool[tool] += cost
                inv_by_tool[tool] += 1
            elif etype == EV_TOOL_FAILED:
                a.tool_failures += 1
            elif etype == EV_POLICY_DENIED:
                a.policy_violations += 1
            elif etype == EV_APPROVAL_GRANTED:
                a.approvals_granted += 1
            elif etype == EV_APPROVAL_DENIED:
                a.approvals_denied += 1
            elif etype == EV_AUTONOMY_PROMOTED:
                a.autonomy_promotions += 1
            elif etype == EV_RUN_COMPLETED:
                run_completed = True
            elif etype == EV_RUN_HALTED:
                run_halted = True
        if run_completed:
            a.runs_completed += 1
        elif run_halted:
            a.runs_halted += 1

    a.spend_by_tool = dict(spend_by_tool)
    a.invocations_by_tool = dict(inv_by_tool)
    return a
