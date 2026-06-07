"""AetherOS orchestration layer.

Builds on `aetheros` (the Rust-backed core) to provide intent compilation, governed
task-graph execution, governance enforcement, and hybrid memory.

Phase 1: configuration + ephemeral memory foundations.
Phase 2: intent compiler, planner, governance bridge to the Rust core, a
framework-agnostic governed execution engine, and a LangGraph StateGraph with
human-in-the-loop approval checkpoints and per-node evidence emission.
"""

from __future__ import annotations

from .autonomy import AutonomyTracker
from .config import AetherConfig, load_config
from .durable_memory import DurableMemory, DurableRecord, MemoryAccessDenied
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
from .policy import PolicyDecision, PolicyEngine
from .gateway import EgressDenied, GatewayConfig, ProxyGateway
from .mcp_adapter import (
    MCPAdapter,
    MockMCPAdapter,
    StdioMCPServerConfig,
    ToolSpec,
    default_incident_adapter,
)
from .sandbox import (
    LocalSandbox,
    ProvenanceRecord,
    SandboxController,
    SandboxExecutionError,
    SandboxResult,
    build_local_sandbox,
)
from .tools import ToolRegistry, default_registry

__all__ = [
    # config / memory
    "AetherConfig",
    "load_config",
    "EphemeralMemory",
    "MemoryRecord",
    "DurableMemory",
    "DurableRecord",
    "MemoryAccessDenied",
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
    # policy / autonomy (Phase 3)
    "PolicyEngine",
    "PolicyDecision",
    "AutonomyTracker",
    # MCP + sandbox (Phase 4)
    "MCPAdapter",
    "MockMCPAdapter",
    "StdioMCPServerConfig",
    "ToolSpec",
    "default_incident_adapter",
    "ProxyGateway",
    "GatewayConfig",
    "EgressDenied",
    "LocalSandbox",
    "SandboxController",
    "SandboxResult",
    "SandboxExecutionError",
    "ProvenanceRecord",
    "build_local_sandbox",
]

__version__ = "0.4.0"
