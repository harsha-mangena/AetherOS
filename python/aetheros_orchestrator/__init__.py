"""AetherOS orchestration layer.

Builds on `aetheros` (the Rust-backed core) to provide intent compilation, governed
task-graph execution, governance enforcement, and hybrid memory. Phase 1 ships the
configuration and basic memory foundations; later phases add the LangGraph
orchestration, policy engine, MCP adapters, and sandbox control.
"""

from __future__ import annotations

from .config import AetherConfig, load_config
from .memory import EphemeralMemory, MemoryRecord

__all__ = [
    "AetherConfig",
    "load_config",
    "EphemeralMemory",
    "MemoryRecord",
]

__version__ = "0.1.0"
