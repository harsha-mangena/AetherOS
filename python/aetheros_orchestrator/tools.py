"""Tool registry and mock governed tools.

In Phase 4 these become real MCP-backed adapters routed through the Rust governance
layer. For Phases 2–3 they are deterministic mocks that let us exercise the full
governed-execution path (authorize -> execute -> charge -> record) without external
systems. Each tool returns a small JSON-serializable summary used as evidence.
"""

from __future__ import annotations

from typing import Any, Callable

ToolFn = Callable[[dict[str, Any]], dict[str, Any]]


class ToolRegistry:
    """A registry mapping tool names to callables."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolFn] = {}

    def register(self, name: str, fn: ToolFn) -> None:
        self._tools[name] = fn

    def has(self, name: str) -> bool:
        return name in self._tools

    def invoke(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name not in self._tools:
            raise KeyError(f"unknown tool: {name}")
        return self._tools[name](arguments)


def default_registry() -> ToolRegistry:
    """A registry pre-populated with the mock tools used by the incident demo."""
    reg = ToolRegistry()

    def log_search(args: dict[str, Any]) -> dict[str, Any]:
        return {
            "matches": 3,
            "top_error": "ConnectionPool timeout in checkout-service",
            "window": args.get("window", "last_1h"),
        }

    def metrics_query(args: dict[str, Any]) -> dict[str, Any]:
        return {
            "unhealthy": ["checkout"],
            "recent_deploy": "checkout v2.4.1 deployed 22m ago",
            "error_rate": 0.18,
        }

    def analysis(args: dict[str, Any]) -> dict[str, Any]:
        return {
            "hypothesis": "checkout v2.4.1 introduced a connection-pool regression",
            "confidence": 0.82,
        }

    def service_restart(args: dict[str, Any]) -> dict[str, Any]:
        return {"service": args.get("service", "checkout"), "restarted": True}

    def slack_post(args: dict[str, Any]) -> dict[str, Any]:
        return {"channel": args.get("channel", "#incidents"), "posted": True}

    def search(args: dict[str, Any]) -> dict[str, Any]:
        return {"query": args.get("query", ""), "results": 5}

    reg.register("log_search", log_search)
    reg.register("metrics_query", metrics_query)
    reg.register("analysis", analysis)
    reg.register("service_restart", service_restart)
    reg.register("slack_post", slack_post)
    reg.register("search", search)
    return reg
