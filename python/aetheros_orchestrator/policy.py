"""Policy engine — Python authoring over the Rust evaluation core.

Rule authoring and loading from config happen here; the actual allow/deny decision
(deny-overrides, default-deny) is computed by the Rust core via the native
PolicyEngine, where it cannot be bypassed by orchestration code. This is the Phase 3
"critical parts in Rust" split.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from aetheros import _aether_native as _native  # type: ignore

from .config import AetherConfig, PolicyConfig


@dataclass
class PolicyDecision:
    """A structured policy decision returned to orchestration code."""

    allowed: bool
    requires_approval: bool
    deciding_rule_id: str | None
    reason: str

    def __bool__(self) -> bool:
        return self.allowed


class PolicyEngine:
    """Config-authored, Rust-evaluated policy engine."""

    def __init__(self, policy_config: PolicyConfig) -> None:
        document = {
            "default_allow": policy_config.default_allow,
            "require_approval_for_high_impact": policy_config.require_approval_for_high_impact,
            "rules": [
                {
                    k: v
                    for k, v in rule.model_dump().items()
                    if v is not None
                }
                for rule in policy_config.rules
            ],
        }
        self._engine = _native.PolicyEngine.from_json(json.dumps(document))

    @classmethod
    def from_config(cls, config: AetherConfig) -> "PolicyEngine":
        return cls(config.policy)

    @property
    def rule_count(self) -> int:
        return self._engine.rule_count

    def evaluate(
        self,
        scope: str,
        tool: str,
        autonomy_tier: int,
        cost_minor: int,
        high_impact: bool,
    ) -> PolicyDecision:
        request = {
            "scope": scope,
            "tool": tool,
            "autonomy_tier": autonomy_tier,
            "cost_minor": cost_minor,
            "high_impact": high_impact,
        }
        raw = self._engine.evaluate(json.dumps(request))
        data = json.loads(raw)
        return PolicyDecision(
            allowed=data["allowed"],
            requires_approval=data["requires_approval"],
            deciding_rule_id=data.get("deciding_rule_id"),
            reason=data["reason"],
        )
