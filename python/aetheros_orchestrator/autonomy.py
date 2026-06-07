"""Earned-autonomy tracking — Python wrapper over the Rust autonomy record.

The promotion/demotion logic lives in the Rust core (governance state that must not be
forgeable). This wrapper provides an ergonomic API and config-driven construction, and
an in-memory registry for tracking many agents during a session. Durable persistence
of autonomy records uses each record's JSON form.
"""

from __future__ import annotations

from aetheros import _aether_native as _native  # type: ignore

from .config import AetherConfig, AutonomyConfig


class AutonomyTracker:
    """Tracks earned-autonomy records for agents, backed by the Rust core."""

    def __init__(self, config: AutonomyConfig) -> None:
        self._config = config
        self._records: dict[str, object] = {}

    @classmethod
    def from_config(cls, config: AetherConfig) -> "AutonomyTracker":
        return cls(config.autonomy)

    def _record(self, agent_id: str):
        rec = self._records.get(agent_id)
        if rec is None:
            rec = _native.AutonomyRecord(
                agent_id, self._config.promotion_threshold, self._config.max_tier
            )
            self._records[agent_id] = rec
        return rec

    def tier(self, agent_id: str) -> int:
        """Current autonomy tier for an agent (0 if unseen)."""
        return self._record(agent_id).tier

    def record_success(self, agent_id: str) -> bool:
        """Record a successful run; returns True if the agent was promoted."""
        return self._record(agent_id).record_success()

    def record_violation(self, agent_id: str) -> bool:
        """Record a violation; returns True if the agent was demoted."""
        return self._record(agent_id).record_violation()

    def snapshot(self, agent_id: str) -> dict:
        """Return a JSON-decoded snapshot of the agent's record."""
        import json

        return json.loads(self._record(agent_id).to_json())
