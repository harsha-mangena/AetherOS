"""Phase 7a/7b tests: agent constitution and its supremacy in the governance gate.

Proves the constitution is (1) evaluated in the Rust core, (2) supreme over policy — a
forbid blocks even when policy would allow and even at max autonomy tier, (3) able to
force a human gate, and (4) recorded as tamper-evident evidence with the article cited.
"""

from __future__ import annotations

from aetheros_orchestrator.config import (
    ArticleConfig,
    ConstitutionConfig,
    PolicyConfig,
    PolicyRuleConfig,
    load_config,
)
from aetheros_orchestrator.constitution import ConstitutionEngine
from aetheros_orchestrator.governance import GovernanceContext
from aetheros_orchestrator.models import Intent, PlanStep


def _engine(articles: list[ArticleConfig], version: str = "vtest") -> ConstitutionEngine:
    return ConstitutionEngine(ConstitutionConfig(version=version, articles=articles))


def test_forbid_is_absolute_even_at_max_tier() -> None:
    eng = _engine(
        [
            ArticleConfig(
                id="no-prod-delete",
                principle="Never delete production data autonomously.",
                verdict="forbid",
                scope="db:delete:prod",
            )
        ]
    )
    j = eng.judge("db:delete:prod", "dropper", autonomy_tier=3, cost_minor=0, high_impact=True)
    assert j.permitted is False
    assert j.article_id == "no-prod-delete"
    assert bool(j) is False


def test_require_approval_permits_behind_gate() -> None:
    eng = _engine(
        [
            ArticleConfig(
                id="approve-high-impact",
                principle="High-impact needs a human.",
                verdict="require_approval",
                high_impact=True,
            )
        ]
    )
    j = eng.judge("infra:restart:web", "restart", autonomy_tier=2, cost_minor=5, high_impact=True)
    assert j.permitted is True
    assert j.requires_approval is True
    assert j.article_id == "approve-high-impact"


def test_silent_pass_for_benign_action() -> None:
    eng = _engine(
        [
            ArticleConfig(
                id="no-prod-delete",
                principle="x",
                verdict="forbid",
                scope="db:delete:prod",
            )
        ]
    )
    j = eng.judge("s3:read:logs", "search", autonomy_tier=0, cost_minor=1, high_impact=False)
    assert j.permitted is True
    assert j.requires_approval is False
    assert j.article_id is None


def test_cost_floor_gates_article() -> None:
    eng = _engine(
        [
            ArticleConfig(
                id="approve-expensive",
                principle="Large spend needs a human.",
                verdict="require_approval",
                min_cost_minor=1000,
            )
        ]
    )
    assert eng.judge("x", "y", 1, 500, False).requires_approval is False
    assert eng.judge("x", "y", 1, 1000, False).requires_approval is True


def test_default_config_loads_a_constitution() -> None:
    cfg = load_config()
    eng = ConstitutionEngine.from_config(cfg)
    # The shipped default constitution has the prod-deletion and credential articles.
    assert eng.article_count >= 2
    j = eng.judge("db:delete:prod-orders", "dropper", 3, 0, True)
    assert j.permitted is False


# ── supremacy inside the governance gate ─────────────────────────────────────


def _gov_with_constitution(article: ArticleConfig, allow_everything: bool = True) -> GovernanceContext:
    """A governance context whose *policy* allows everything but whose *constitution*
    carries the given article — so any blocking is attributable to the constitution."""
    cfg = load_config()
    # Override policy to allow-all, and constitution to exactly the one article.
    cfg.policy = PolicyConfig(
        default_allow=allow_everything,
        require_approval_for_high_impact=False,
        rules=[
            PolicyRuleConfig(id="allow-all", effect="allow", scope="*", priority=100)
        ],
    )
    cfg.constitution = ConstitutionConfig(version="vtest", articles=[article])
    intent = Intent(
        text="test",
        submitted_by="human:test",
        currency="USD",
        budget_minor=1_000_000,
    )
    return GovernanceContext.for_run(cfg, intent, required_scopes=["db:delete:prod", "s3:read:logs"])


def test_constitution_blocks_step_that_policy_would_allow() -> None:
    ctx = _gov_with_constitution(
        ArticleConfig(
            id="no-prod-delete",
            principle="Never delete production data autonomously.",
            verdict="forbid",
            scope="db:delete:prod*",
        )
    )
    step = PlanStep(
        step_id="s-1",
        description="delete prod table",
        tool="dropper",
        scope="db:delete:prod",
        estimated_cost_minor=0,
        high_impact=True,
    )
    decision = ctx.authorize_step(step)
    assert bool(decision) is False
    assert decision.constitutional_article_id == "no-prod-delete"
    # The violation is recorded as tamper-evident evidence citing the article.
    events = [e.event_type for e in ctx.ledger.entries()]
    assert "constitution.violation" in events
    assert ctx.ledger.verify() is True


def test_constitution_allows_benign_step_through_to_policy() -> None:
    ctx = _gov_with_constitution(
        ArticleConfig(
            id="no-prod-delete",
            principle="x",
            verdict="forbid",
            scope="db:delete:prod*",
        )
    )
    step = PlanStep(
        step_id="s-2",
        description="read logs",
        tool="search",
        scope="s3:read:logs",
        estimated_cost_minor=1,
        high_impact=False,
    )
    decision = ctx.authorize_step(step)
    assert bool(decision) is True
    assert decision.constitutional_article_id is None
