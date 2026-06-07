"""Pydantic models for the AetherOS orchestration layer.

These structures are the typed contract between the intent compiler, the planner,
the governance layer, and the execution graph. Everything that crosses a node
boundary in the StateGraph is one of these models (or a plain dict view of one),
so execution is auditable and replayable end to end.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Intent(BaseModel):
    """A natural-language goal submitted by a human, plus governance envelope."""

    text: str = Field(..., description="The natural-language intent / goal.")
    submitted_by: str = Field(..., description="Human principal id, e.g. 'human:vamsi'.")
    currency: str = Field("USD", description="Budget currency for the run.")
    budget_minor: int = Field(10_000, ge=0, description="Total budget for the run, minor units.")
    autonomy_tier: int = Field(
        1, ge=0, le=3, description="Requested autonomy tier (0=manual .. 3=high)."
    )


class StepStatus(str, Enum):
    PENDING = "pending"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    DENIED = "denied"
    EXECUTED = "executed"
    FAILED = "failed"
    SKIPPED = "skipped"


class PlanStep(BaseModel):
    """One governed step in an execution plan."""

    step_id: str = Field(..., description="Stable identifier, e.g. 'step-1'.")
    description: str = Field(..., description="Human-readable description of the step.")
    tool: str = Field(..., description="Tool to invoke, e.g. 'log_search'.")
    scope: str = Field(..., description="Capability scope required, e.g. 's3:read:logs'.")
    arguments: dict[str, Any] = Field(default_factory=dict)
    estimated_cost_minor: int = Field(0, ge=0, description="Estimated cost, minor units.")
    high_impact: bool = Field(
        False, description="Whether the step mutates/affects systems and needs approval."
    )
    status: StepStatus = StepStatus.PENDING


class ExecutionPlan(BaseModel):
    """A validated, ordered plan of governed steps compiled from an intent."""

    plan_id: str
    intent_text: str
    submitted_by: str
    steps: list[PlanStep]

    @property
    def total_estimated_cost_minor(self) -> int:
        return sum(s.estimated_cost_minor for s in self.steps)


class StepResult(BaseModel):
    """The result of executing (or attempting) a single step."""

    step_id: str
    status: StepStatus
    output: Any = None
    cost_minor: int = 0
    evidence_seq: int | None = None
    detail: str | None = None


class ExecutionOutcome(BaseModel):
    """The terminal outcome of a governed run."""

    plan_id: str
    completed: bool
    results: list[StepResult] = Field(default_factory=list)
    total_cost_minor: int = 0
    evidence_head: str | None = None
    denied_reason: str | None = None
