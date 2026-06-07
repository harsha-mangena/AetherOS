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
from .run_service import RunService, RunState, RunStatus
from .tenancy import (
    DEFAULT_TENANT_ID,
    CrossTenantAccess,
    Tenant,
    TenantError,
    TenantRegistry,
    UnknownTenant,
)
from .identity_provider import (
    ClaimMappingRule,
    IdentityProvider,
    MockOIDCProvider,
    OnboardingDenied,
    OnboardingResult,
    OnboardingService,
    TokenVerificationError,
    VerifiedClaims,
)
from .analytics import TenantAnalytics, compute_tenant_analytics
from .adaptive_autonomy import (
    AutonomyAction,
    AutonomyAdvisor,
    AutonomyRecommendation,
    AutonomyScorer,
    BehaviorWindow,
    HeuristicScorer,
    window_from_analytics,
)
from .sandbox_backends import (
    ExecutionBackend,
    FirecrackerStubBackend,
    InProcessBackend,
    IsolationLevel,
    SandboxBackendError,
    WasmStubBackend,
    available_backends,
    build_backend,
)

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
    # control plane (Phase 5)
    "RunService",
    "RunState",
    "RunStatus",
    # multi-tenancy (Phase 6)
    "Tenant",
    "TenantRegistry",
    "TenantError",
    "UnknownTenant",
    "CrossTenantAccess",
    "DEFAULT_TENANT_ID",
    # enterprise identity (Phase 6)
    "IdentityProvider",
    "MockOIDCProvider",
    "VerifiedClaims",
    "ClaimMappingRule",
    "OnboardingService",
    "OnboardingResult",
    "OnboardingDenied",
    "TokenVerificationError",
    # analytics (Phase 6)
    "TenantAnalytics",
    "compute_tenant_analytics",
    # adaptive autonomy (Phase 6)
    "AutonomyAdvisor",
    "AutonomyScorer",
    "HeuristicScorer",
    "AutonomyAction",
    "AutonomyRecommendation",
    "BehaviorWindow",
    "window_from_analytics",
    # sandbox backends (Phase 6)
    "ExecutionBackend",
    "InProcessBackend",
    "WasmStubBackend",
    "FirecrackerStubBackend",
    "IsolationLevel",
    "SandboxBackendError",
    "build_backend",
    "available_backends",
]

__version__ = "0.6.0"
