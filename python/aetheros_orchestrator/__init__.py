"""AetherOS orchestration layer.

Builds on `aetheros` (the Rust-backed core) to provide intent compilation, governed
task-graph execution, governance enforcement, and hybrid memory.

Phase 1: configuration + ephemeral memory foundations.
Phase 2: intent compiler, planner, governance bridge to the Rust core, a
framework-agnostic governed execution engine, and a LangGraph StateGraph with
human-in-the-loop approval checkpoints and per-node evidence emission.
"""

from __future__ import annotations

from .config import AetherConfig, load_config
from .engine import GovernedEngine, auto_approve, auto_deny
from .governance import GovernanceContext, GovernanceDecision
from .intent_compiler import IntentCompilationError, IntentCompiler
from .memory import EphemeralMemory, MemoryRecord
from .models import (
    ExecutionOutcome,
    ExecutionPlan,
    Intent,
    PlanStep,
    StepResult,
    StepStatus,
)
from .planner import LLMPlanner, Planner, RuleBasedPlanner
from .tools import ToolRegistry, default_registry

__all__ = [
    # config / memory
    "AetherConfig",
    "load_config",
    "EphemeralMemory",
    "MemoryRecord",
    # models
    "Intent",
    "PlanStep",
    "ExecutionPlan",
    "StepResult",
    "StepStatus",
    "ExecutionOutcome",
    # planning / compilation
    "Planner",
    "RuleBasedPlanner",
    "LLMPlanner",
    "IntentCompiler",
    "IntentCompilationError",
    # governance / execution
    "GovernanceContext",
    "GovernanceDecision",
    "GovernedEngine",
    "auto_approve",
    "auto_deny",
    "ToolRegistry",
    "default_registry",
]

__version__ = "0.2.0"
