"""Constitution engine — Python authoring over the supreme Rust governance core.

Phase 7. A constitution sits *above* policy in the governance hierarchy. Article
authoring and config loading happen here; the supremacy semantics — a `forbid` is
absolute, evaluated before policy, and no autonomy tier can buy past it — are computed
by the Rust core via the native ConstitutionEngine, where orchestration code cannot
weaken them.

Composition contract (revalidated against defense-in-depth authorization): the engine
can only ever *tighten* behaviour. A constitutional judgment is consulted first; a
`forbid` short-circuits the whole pipeline, and a `require_approval` forces a human gate
even if downstream policy would have allowed silently. The constitution never grants
authority it can only withhold or escalate it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from aetheros import _aether_native as _native  # type: ignore

from .config import AetherConfig, ConstitutionConfig


@dataclass
class Judgment:
    """A structured constitutional judgment returned to orchestration code."""

    permitted: bool
    requires_approval: bool
    article_id: str | None
    principle: str | None
    reason: str

    def __bool__(self) -> bool:
        return self.permitted


class ConstitutionEngine:
    """Config-authored, Rust-evaluated constitution engine."""

    def __init__(self, constitution_config: ConstitutionConfig) -> None:
        document = {
            "version": constitution_config.version,
            "articles": [
                {k: v for k, v in article.model_dump().items() if v is not None}
                for article in constitution_config.articles
            ],
        }
        self._engine = _native.ConstitutionEngine.from_json(json.dumps(document))

    @classmethod
    def from_config(cls, config: AetherConfig) -> "ConstitutionEngine":
        return cls(config.constitution)

    @property
    def version(self) -> str:
        return self._engine.version

    @property
    def article_count(self) -> int:
        return self._engine.article_count

    def judge(
        self,
        scope: str,
        tool: str,
        autonomy_tier: int,
        cost_minor: int,
        high_impact: bool,
    ) -> Judgment:
        action = {
            "scope": scope,
            "tool": tool,
            "autonomy_tier": autonomy_tier,
            "cost_minor": cost_minor,
            "high_impact": high_impact,
        }
        raw = self._engine.judge(json.dumps(action))
        data = json.loads(raw)
        return Judgment(
            permitted=data["permitted"],
            requires_approval=data["requires_approval"],
            article_id=data.get("article_id"),
            principle=data.get("principle"),
            reason=data["reason"],
        )
