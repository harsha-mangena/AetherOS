"""MCP client and config-driven adapters (Phase 4).

AetherOS is MCP-native: it governs Model Context Protocol tool calls rather than
replacing them. This module defines a small adapter abstraction so the governed engine
can invoke tools that live behind MCP servers, while staying hermetic and testable.

- MCPAdapter: the interface the rest of the system depends on. `list_tools()` and
  `call_tool(name, arguments)`.
- MockMCPAdapter: deterministic, in-process adapter used by tests and the offline
  demo. It exposes the incident-response toolset.
- StdioMCPServerConfig / build_stdio_adapter: config to launch a real MCP server over
  stdio using the official `mcp` SDK. Construction is lazy so importing this module
  never requires a live server.

The governance invariant is enforced upstream (the engine authorizes every step via
the Rust policy engine + lease before any adapter is called), so adapters never make
authorization decisions — they only execute already-governed calls.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Protocol, runtime_checkable


@dataclass
class ToolSpec:
    """A tool exposed by an MCP adapter."""

    name: str
    description: str = ""
    # JSON-schema-ish description of arguments; informational for governance/UI.
    input_schema: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class MCPAdapter(Protocol):
    """Interface for an MCP-backed (or MCP-shaped) tool provider."""

    def list_tools(self) -> list[ToolSpec]:
        ...

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        ...


class MockMCPAdapter:
    """Deterministic in-process adapter exposing the incident-response toolset.

    Mirrors what a real MCP server would return, but runs offline so tests and the
    demo are hermetic. Each callable returns a JSON-serializable dict used as evidence.
    """

    def __init__(self, tools: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] | None = None,
                 specs: dict[str, ToolSpec] | None = None) -> None:
        self._tools = tools or {}
        self._specs = specs or {}

    def register(self, spec: ToolSpec, fn: Callable[[dict[str, Any]], dict[str, Any]]) -> None:
        self._tools[spec.name] = fn
        self._specs[spec.name] = spec

    def list_tools(self) -> list[ToolSpec]:
        return list(self._specs.values())

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name not in self._tools:
            raise KeyError(f"unknown MCP tool: {name}")
        return self._tools[name](dict(arguments))


@dataclass
class StdioMCPServerConfig:
    """Config to launch a real MCP server over stdio (resolved at runtime)."""

    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    # Tool names this server is permitted to expose (allowlist; empty = all).
    allow_tools: list[str] = field(default_factory=list)


def default_incident_adapter() -> MockMCPAdapter:
    """The MCP adapter used by the incident demo and tests."""
    adapter = MockMCPAdapter()

    adapter.register(
        ToolSpec("log_search", "Search service logs", {"window": "str", "level": "str"}),
        lambda a: {
            "matches": 3,
            "top_error": "ConnectionPool timeout in checkout-service",
            "window": a.get("window", "last_1h"),
        },
    )
    adapter.register(
        ToolSpec("metrics_query", "Query service health metrics", {"services": "list"}),
        lambda a: {
            "unhealthy": ["checkout"],
            "recent_deploy": "checkout v2.4.1 deployed 22m ago",
            "error_rate": 0.18,
        },
    )
    adapter.register(
        ToolSpec("analysis", "Run local correlation analysis"),
        lambda a: {
            "hypothesis": "checkout v2.4.1 introduced a connection-pool regression",
            "confidence": 0.82,
        },
    )
    adapter.register(
        ToolSpec("service_restart", "Restart a service (external side effect)", {"service": "str"}),
        lambda a: {"service": a.get("service", "checkout"), "restarted": True},
    )
    adapter.register(
        ToolSpec("slack_post", "Post to a Slack channel (external side effect)", {"channel": "str"}),
        lambda a: {"channel": a.get("channel", "#incidents"), "posted": True},
    )
    adapter.register(
        ToolSpec("search", "Generic search"),
        lambda a: {"query": a.get("query", ""), "results": 5},
    )
    return adapter
