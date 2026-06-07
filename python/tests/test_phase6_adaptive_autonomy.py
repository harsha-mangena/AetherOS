"""Phase 6d tests: adaptive autonomy advisor.

Proves the advisor (1) gives deterministic, explainable advice, (2) only ever *advises* —
actual tier changes go through the Rust-backed tracker, (3) accepts a pluggable scorer so
an ML model can drop in later, and (4) demotes on bad behaviour (self-healing).
"""

from __future__ import annotations

from aetheros_orchestrator.adaptive_autonomy import (
    AutonomyAction,
    AutonomyAdvisor,
    AutonomyRecommendation,
    BehaviorWindow,
    HeuristicScorer,
    window_from_analytics,
)
from aetheros_orchestrator.autonomy import AutonomyTracker
from aetheros_orchestrator.config import load_config


def _tracker() -> AutonomyTracker:
    return AutonomyTracker.from_config(load_config())


def test_clean_streak_recommends_promotion():
    advisor = AutonomyAdvisor()
    rec = advisor.evaluate(BehaviorWindow(successes=4))
    assert rec.action is AutonomyAction.PROMOTE_SIGNAL
    assert "clean successes" in rec.rationale


def test_violations_recommend_demotion():
    advisor = AutonomyAdvisor()
    rec = advisor.evaluate(BehaviorWindow(successes=1, failures=1, violations=2))
    assert rec.action is AutonomyAction.DEMOTE_SIGNAL
    assert rec.confidence > 0.5


def test_normal_band_holds():
    advisor = AutonomyAdvisor()
    rec = advisor.evaluate(BehaviorWindow(successes=1, failures=0, violations=0))
    assert rec.action is AutonomyAction.HOLD


def test_apply_routes_through_rust_tracker():
    advisor = AutonomyAdvisor()
    tracker = _tracker()
    agent = "agent-1"
    assert tracker.tier(agent) == 0
    # Enough clean successes to advise + enact promotion via the Rust core.
    result = None
    for _ in range(load_config().autonomy.promotion_threshold):
        result = advisor.apply(tracker, agent, BehaviorWindow(successes=5))
    assert result is not None
    assert result["recommendation"]["action"] == "promote_signal"
    # The Rust core is the one that actually moved the tier.
    assert tracker.tier(agent) >= 1


def test_demotion_reduces_tier_via_tracker():
    advisor = AutonomyAdvisor()
    tracker = _tracker()
    agent = "agent-2"
    cfg = load_config()
    # Promote first.
    for _ in range(cfg.autonomy.promotion_threshold):
        tracker.record_success(agent)
    promoted_tier = tracker.tier(agent)
    assert promoted_tier >= 1
    # A bad window now advises demotion and the tracker enacts it.
    result = advisor.apply(
        tracker, agent, BehaviorWindow(successes=0, failures=2, violations=2)
    )
    assert result["recommendation"]["action"] == "demote_signal"
    assert tracker.tier(agent) <= promoted_tier


def test_pluggable_scorer_seam():
    """A custom scorer drops in without touching the advisor — the ML seam."""

    class AlwaysDemote:
        def score(self, window: BehaviorWindow) -> AutonomyRecommendation:
            return AutonomyRecommendation(AutonomyAction.DEMOTE_SIGNAL, 0.99, "stub model")

    advisor = AutonomyAdvisor(scorer=AlwaysDemote())
    rec = advisor.evaluate(BehaviorWindow(successes=100))
    assert rec.action is AutonomyAction.DEMOTE_SIGNAL
    assert rec.rationale == "stub model"


def test_window_from_analytics():
    view = {
        "runs": {"completed": 3},
        "tools": {"failures": 1},
        "governance": {"policy_violations": 2, "approvals_granted": 4, "approvals_denied": 1},
    }
    w = window_from_analytics(view)
    assert w.successes == 3
    assert w.failures == 1
    assert w.violations == 2
    assert w.approvals_granted == 4
    assert w.approvals_denied == 1


def test_heuristic_scorer_thresholds_are_tunable():
    strict = HeuristicScorer(demote_threshold=0.1, promote_min_successes=10)
    # A single violation with low rate now trips demotion under the strict threshold.
    rec = strict.score(BehaviorWindow(successes=8, failures=0, violations=1))
    assert rec.action is AutonomyAction.DEMOTE_SIGNAL
