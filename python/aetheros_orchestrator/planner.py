"""Planners turn a natural-language Intent into an ordered list of governed steps.

Two implementations ship:

- RuleBasedPlanner: deterministic, offline, dependency-free. It recognizes the
  Production Incident Investigation & Response workflow (the MVP demo) and a few
  generic patterns. Used by all tests and as a safe default.
- LLMPlanner: wraps an injectable `complete(prompt) -> str` callable that must
  return JSON matching the plan-step schema. The runtime supplies the model; the
  orchestrator stays model-agnostic. Output is strictly validated before use.

This separation keeps the governed-execution core testable without network or LLM
access while remaining ready for real model-driven planning.
"""

from __future__ import annotations

import json
import re
from typing import Callable, Protocol

from .models import PlanStep


class Planner(Protocol):
    """A planner produces an ordered list of PlanStep for an intent."""

    def plan(self, intent_text: str) -> list[PlanStep]:  # pragma: no cover - protocol
        ...


# Scopes considered high-impact (must align with config high_impact_scopes patterns).
_HIGH_IMPACT_HINTS = ("write", "delete", "restart", "deploy", "post", "patch", "rollback")


def _is_high_impact(scope: str) -> bool:
    s = scope.lower()
    return any(h in s for h in _HIGH_IMPACT_HINTS)


class RuleBasedPlanner:
    """Deterministic planner for offline use and the incident-response demo."""

    def plan(self, intent_text: str) -> list[PlanStep]:
        text = intent_text.lower()
        if "incident" in text or "investigate" in text or "outage" in text:
            return self._incident_response_plan()
        return self._generic_readonly_plan(intent_text)

    def _incident_response_plan(self) -> list[PlanStep]:
        """The Production Incident Investigation & Response workflow.

        Read-only investigation steps run autonomously; the remediation step is
        high-impact and therefore gated behind human approval.
        """
        return [
            PlanStep(
                step_id="step-1",
                description="Search recent production logs for error signatures",
                tool="log_search",
                scope="s3:read:incident-logs",
                arguments={"window": "last_1h", "level": "error"},
                estimated_cost_minor=15,
                high_impact=False,
            ),
            PlanStep(
                step_id="step-2",
                description="Inspect service health and recent deploys",
                tool="metrics_query",
                scope="metrics:read:service-health",
                arguments={"services": ["checkout", "payments"]},
                estimated_cost_minor=10,
                high_impact=False,
            ),
            PlanStep(
                step_id="step-3",
                description="Correlate findings and draft a root-cause hypothesis",
                tool="analysis",
                scope="analysis:run",
                arguments={},
                estimated_cost_minor=5,
                high_impact=False,
            ),
            PlanStep(
                step_id="step-4",
                description="Restart the unhealthy service to restore availability",
                tool="service_restart",
                scope="infra:restart:checkout",
                arguments={"service": "checkout"},
                estimated_cost_minor=20,
                high_impact=True,
            ),
            PlanStep(
                step_id="step-5",
                description="Post an incident summary to the response channel",
                tool="slack_post",
                scope="tool:slack.post",
                arguments={"channel": "#incidents"},
                estimated_cost_minor=2,
                high_impact=True,
            ),
        ]

    def _generic_readonly_plan(self, intent_text: str) -> list[PlanStep]:
        return [
            PlanStep(
                step_id="step-1",
                description=f"Gather read-only context for: {intent_text}",
                tool="search",
                scope="data:read",
                arguments={"query": intent_text},
                estimated_cost_minor=5,
                high_impact=False,
            ),
            PlanStep(
                step_id="step-2",
                description="Summarize findings",
                tool="analysis",
                scope="analysis:run",
                arguments={},
                estimated_cost_minor=3,
                high_impact=False,
            ),
        ]


class LLMPlanner:
    """Planner backed by an injectable completion function returning JSON.

    The completion callable receives a prompt and must return a JSON array of objects
    with keys: description, tool, scope, arguments (object), estimated_cost_minor
    (int). step_id and high_impact are assigned/derived here. Any malformed output
    raises ValueError — we never execute an unvalidated plan.
    """

    def __init__(self, complete: Callable[[str], str]) -> None:
        self._complete = complete

    PROMPT_TEMPLATE = (
        "You are the AetherOS intent compiler. Convert the user's intent into a "
        "minimal ordered list of governed tool steps. Return ONLY a JSON array. Each "
        "element must have: description (string), tool (string), scope (string like "
        "'s3:read:logs' or 'infra:restart:svc'), arguments (object), "
        "estimated_cost_minor (integer cents). Do not include prose.\n\nIntent: {intent}"
    )

    def plan(self, intent_text: str) -> list[PlanStep]:
        raw = self._complete(self.PROMPT_TEMPLATE.format(intent=intent_text))
        data = self._extract_json_array(raw)
        steps: list[PlanStep] = []
        for i, item in enumerate(data, start=1):
            if not isinstance(item, dict):
                raise ValueError("plan element is not an object")
            scope = str(item["scope"])
            steps.append(
                PlanStep(
                    step_id=f"step-{i}",
                    description=str(item["description"]),
                    tool=str(item["tool"]),
                    scope=scope,
                    arguments=dict(item.get("arguments", {})),
                    estimated_cost_minor=int(item.get("estimated_cost_minor", 0)),
                    high_impact=bool(item.get("high_impact", _is_high_impact(scope))),
                )
            )
        return steps

    @staticmethod
    def _extract_json_array(raw: str):
        raw = raw.strip()
        # Tolerate fenced code blocks.
        fence = re.search(r"```(?:json)?\s*(\[.*?\])\s*```", raw, re.DOTALL)
        candidate = fence.group(1) if fence else raw
        try:
            data = json.loads(candidate)
        except json.JSONDecodeError as exc:
            raise ValueError(f"planner returned invalid JSON: {exc}") from exc
        if not isinstance(data, list):
            raise ValueError("planner must return a JSON array")
        return data
