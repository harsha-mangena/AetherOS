"""LangGraph-backed governed orchestration with human-in-the-loop checkpoints.

This module wraps the framework-agnostic governance primitives in a LangGraph
StateGraph so runs are stateful, checkpointed, and pausable at human-approval gates.
The graph is intentionally thin: all authorization and budget decisions are made by
the same GovernanceContext used by `engine.GovernedEngine`, and every node emits
evidence. LangGraph provides durable execution state and the `interrupt` mechanism
for human-in-the-loop approval; it does not make governance decisions.

If LangGraph is not installed, importing this module raises ImportError lazily only
when `build_graph` is called, so the rest of the orchestrator works without it.

Graph shape:

    START -> govern_step --(needs approval and not yet approved)--> [interrupt]
          -> govern_step -> (loop over steps) -> finalize -> END

State carries the plan, a cursor, accumulated results, and the approval verdict
supplied when the run is resumed after an interrupt.
"""

from __future__ import annotations

from typing import Any, TypedDict

from .governance import GovernanceContext
from .models import ExecutionPlan, StepResult, StepStatus
from .tools import ToolRegistry, default_registry


class RunState(TypedDict, total=False):
    """Mutable state threaded through the graph."""

    plan: dict  # ExecutionPlan dumped to dict (LangGraph state must be plain data)
    cursor: int
    results: list[dict]
    total_cost_minor: int
    completed: bool
    denied_reason: str | None
    pending_approval_step: str | None


def build_graph(
    ctx: GovernanceContext,
    plan: ExecutionPlan,
    registry: ToolRegistry | None = None,
):
    """Build and compile a LangGraph StateGraph for a governed run.

    Returns a tuple `(compiled_graph, config)` where `config` carries the thread id
    for checkpointing. High-impact steps trigger a LangGraph `interrupt`; resume the
    run by invoking the graph again with a Command(resume={"granted": bool,
    "approver": str}).
    """
    try:
        from langgraph.checkpoint.memory import MemorySaver
        from langgraph.graph import END, START, StateGraph
        from langgraph.types import interrupt
    except ImportError as exc:  # pragma: no cover - exercised only without langgraph
        raise ImportError(
            "langgraph is required for build_graph; install with "
            "'pip install aetheros-orchestrator[orchestration]'"
        ) from exc

    registry = registry or default_registry()
    steps = plan.steps

    def govern_step(state: RunState) -> dict[str, Any]:
        cursor = state.get("cursor", 0)
        results = list(state.get("results", []))
        total = state.get("total_cost_minor", 0)
        if cursor >= len(steps):
            return {"completed": True}

        step = steps[cursor]

        # Human approval gate via LangGraph interrupt (pauses & checkpoints).
        if ctx.requires_approval(step):
            verdict = interrupt(
                {
                    "kind": "approval_request",
                    "step_id": step.step_id,
                    "description": step.description,
                    "scope": step.scope,
                    "estimated_cost_minor": step.estimated_cost_minor,
                }
            )
            granted = bool(verdict.get("granted", False)) if isinstance(verdict, dict) else False
            approver = verdict.get("approver", "human:unknown") if isinstance(verdict, dict) else "human:unknown"
            ctx.record_approval(step, approver, granted)
            if not granted:
                results.append(
                    StepResult(
                        step_id=step.step_id,
                        status=StepStatus.DENIED,
                        detail=f"human approval denied by {approver}",
                    ).model_dump()
                )
                return {
                    "results": results,
                    "completed": False,
                    "denied_reason": f"approval denied for {step.step_id}",
                }

        # Capability authorization via the Rust lease.
        decision = ctx.authorize_step(step)
        if not decision:
            results.append(
                StepResult(
                    step_id=step.step_id, status=StepStatus.DENIED, detail=decision.reason
                ).model_dump()
            )
            return {"results": results, "completed": False, "denied_reason": decision.reason}

        # Execute and charge.
        output = registry.invoke(step.tool, step.arguments)
        cost = step.estimated_cost_minor
        seq = ctx.charge_and_record(step, cost, output)
        results.append(
            StepResult(
                step_id=step.step_id,
                status=StepStatus.EXECUTED,
                output=output,
                cost_minor=cost,
                evidence_seq=seq,
            ).model_dump()
        )
        return {
            "results": results,
            "cursor": cursor + 1,
            "total_cost_minor": total + cost,
        }

    def should_continue(state: RunState) -> str:
        if state.get("completed") or state.get("denied_reason"):
            return "finalize"
        if state.get("cursor", 0) >= len(steps):
            return "finalize"
        return "govern_step"

    def finalize(state: RunState) -> dict[str, Any]:
        completed = not state.get("denied_reason") and state.get("cursor", 0) >= len(steps)
        ctx.ledger.append(
            "control-plane",
            "run.completed" if completed else "run.halted",
            {
                "plan_id": plan.plan_id,
                "total_cost_minor": state.get("total_cost_minor", 0),
                "completed": completed,
            },
        )
        return {"completed": completed}

    builder = StateGraph(RunState)
    builder.add_node("govern_step", govern_step)
    builder.add_node("finalize", finalize)
    builder.add_edge(START, "govern_step")
    builder.add_conditional_edges(
        "govern_step", should_continue, {"govern_step": "govern_step", "finalize": "finalize"}
    )
    builder.add_edge("finalize", END)

    compiled = builder.compile(checkpointer=MemorySaver())
    config = {"configurable": {"thread_id": plan.plan_id}}
    return compiled, config
