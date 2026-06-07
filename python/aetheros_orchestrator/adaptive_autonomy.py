"""Adaptive autonomy: evidence-driven tier promotion/demotion advice (Phase 6).

The Rust core owns the *mechanism* of autonomy state transitions (promotion/demotion
thresholds, tier ceiling) — that state must be unforgeable, so it stays in Rust. This
module adds the *policy* layer above it: given an agent's recent behavioural evidence,
decide whether the next signal should be a success (toward promotion), a violation
(toward demotion), or a hold. The advisor never mutates tier state directly; it returns
a recommendation that the caller applies through the existing Rust-backed
AutonomyTracker.record_success/record_violation. So even an ML scorer can only *advise* —
it can never forge a tier.

Pluggability (tree of thoughts). The roadmap calls for "tier promotion/demotion based on
ML models." Shipping a fake trained model with no data would be dishonest and untestable.
Instead the scoring function is a swappable `AutonomyScorer`:
  - HeuristicScorer (default): deterministic, explainable rules over a behaviour window.
  - A future MLScorer drops in behind the same protocol once real telemetry exists, with
    zero changes to the advisor or the governance wiring.

Self-healing: when an agent trends badly (failures/violations over its recent window),
the advisor recommends demotion, which tightens what the agent may do autonomously — the
system heals by reducing blast radius, all recorded as evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol


class AutonomyAction(str, Enum):
    PROMOTE_SIGNAL = "promote_signal"  # record a success toward promotion
    DEMOTE_SIGNAL = "demote_signal"  # record a violation toward demotion
    HOLD = "hold"  # no change recommended


@dataclass(frozen=True)
class BehaviorWindow:
    """A summary of an agent's recent behaviour, fed to the scorer.

    Derived from evidence (analytics / ledger), never from agent-supplied input.
    """

    successes: int = 0
    failures: int = 0
    violations: int = 0
    approvals_granted: int = 0
    approvals_denied: int = 0

    @property
    def total(self) -> int:
        return self.successes + self.failures + self.violations

    @property
    def failure_rate(self) -> float:
        return ((self.failures + self.violations) / self.total) if self.total else 0.0


@dataclass(frozen=True)
class AutonomyRecommendation:
    action: AutonomyAction
    confidence: float
    rationale: str

    def to_view(self) -> dict:
        return {
            "action": self.action.value,
            "confidence": round(self.confidence, 4),
            "rationale": self.rationale,
        }


class AutonomyScorer(Protocol):
    """Maps a behaviour window to a recommendation. Swap for an ML model later."""

    def score(self, window: BehaviorWindow) -> AutonomyRecommendation: ...


@dataclass
class HeuristicScorer:
    """Deterministic, explainable default scorer.

    Demote when the recent failure+violation rate crosses `demote_threshold`; promote when
    a clean streak of at least `promote_min_successes` with zero violations is observed;
    otherwise hold. Every recommendation carries a human-readable rationale so an operator
    (and the evidence trail) can see exactly why a tier change was advised.
    """

    demote_threshold: float = 0.34
    promote_min_successes: int = 3

    def score(self, window: BehaviorWindow) -> AutonomyRecommendation:
        # Any violation in the window is a hard demote signal — governance is conservative.
        if window.violations > 0 and window.failure_rate >= self.demote_threshold:
            return AutonomyRecommendation(
                AutonomyAction.DEMOTE_SIGNAL,
                confidence=min(1.0, 0.5 + window.failure_rate),
                rationale=(
                    f"failure_rate={window.failure_rate:.2f} with {window.violations} "
                    f"violation(s) >= demote_threshold={self.demote_threshold}"
                ),
            )
        if (
            window.violations == 0
            and window.failures == 0
            and window.successes >= self.promote_min_successes
        ):
            return AutonomyRecommendation(
                AutonomyAction.PROMOTE_SIGNAL,
                confidence=min(1.0, window.successes / (self.promote_min_successes * 2)),
                rationale=(
                    f"{window.successes} clean successes (>= {self.promote_min_successes}) "
                    "with no failures or violations"
                ),
            )
        return AutonomyRecommendation(
            AutonomyAction.HOLD,
            confidence=0.5,
            rationale="behaviour within normal band; no tier change advised",
        )


class AutonomyAdvisor:
    """Turns evidence into autonomy recommendations and (optionally) applies them.

    Applying a recommendation always goes through the Rust-backed tracker, so the Rust
    core remains the sole authority over actual tier state. `evaluate` is pure advice;
    `apply` enacts it and reports whether the Rust core changed the tier.
    """

    def __init__(self, scorer: AutonomyScorer | None = None) -> None:
        self._scorer = scorer or HeuristicScorer()

    def evaluate(self, window: BehaviorWindow) -> AutonomyRecommendation:
        return self._scorer.score(window)

    def apply(self, tracker, agent_id: str, window: BehaviorWindow) -> dict:
        """Evaluate and enact a recommendation via the Rust-backed tracker.

        Returns a record of what was advised and whether the tier actually changed.
        """
        rec = self.evaluate(window)
        tier_before = tracker.tier(agent_id)
        changed = False
        if rec.action is AutonomyAction.PROMOTE_SIGNAL:
            changed = tracker.record_success(agent_id)
        elif rec.action is AutonomyAction.DEMOTE_SIGNAL:
            changed = tracker.record_violation(agent_id)
        return {
            "recommendation": rec.to_view(),
            "tier_before": tier_before,
            "tier_after": tracker.tier(agent_id),
            "tier_changed": changed,
        }


def window_from_analytics(analytics_view: dict) -> BehaviorWindow:
    """Build a BehaviorWindow from a TenantAnalytics view (evidence-derived)."""
    runs = analytics_view.get("runs", {})
    tools = analytics_view.get("tools", {})
    gov = analytics_view.get("governance", {})
    return BehaviorWindow(
        successes=int(runs.get("completed", 0)),
        failures=int(tools.get("failures", 0)),
        violations=int(gov.get("policy_violations", 0)),
        approvals_granted=int(gov.get("approvals_granted", 0)),
        approvals_denied=int(gov.get("approvals_denied", 0)),
    )
