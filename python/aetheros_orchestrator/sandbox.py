"""Sandbox controller (Phase 4).

Every governed tool call executes inside a sandbox boundary that captures provenance,
enforces a wall-clock timeout, routes external calls through the egress gateway, and
produces a content-addressed provenance record. The governance gate (policy + lease)
runs upstream in the engine BEFORE the sandbox is ever entered, so the sandbox only
ever runs already-authorized calls — it adds isolation and provenance, not
authorization.

Backends are pluggable behind the SandboxController protocol:
- LocalSandbox: in-process, deterministic, with a timeout guard and provenance. Used
  for hermetic tests and the offline demo.
- A native-process or E2B backend implements the same protocol and drops in via config
  without touching the engine.

Provenance records are hashed with the same canonical SHA-256 as the evidence ledger,
so a tool result recorded in the ledger can be tied back to a verifiable execution
record.
"""

from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable, TYPE_CHECKING

from .gateway import EgressDenied, ProxyGateway
from .mcp_adapter import MCPAdapter

if TYPE_CHECKING:
    from .sandbox_backends import ExecutionBackend


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class SandboxExecutionError(RuntimeError):
    """A tool call failed or was blocked inside the sandbox."""


@dataclass
class ProvenanceRecord:
    """A verifiable record of one sandboxed tool execution."""

    tool: str
    arguments: dict[str, Any]
    output: dict[str, Any]
    started_at: str
    finished_at: str
    backend: str
    record_id: str = ""

    def __post_init__(self) -> None:
        if not self.record_id:
            self.record_id = self.compute_id()

    def compute_id(self) -> str:
        payload = _canonical_json(
            {
                "tool": self.tool,
                "arguments": self.arguments,
                "output": self.output,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "backend": self.backend,
            }
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def verify(self) -> bool:
        return self.record_id == self.compute_id()


@dataclass
class SandboxResult:
    output: dict[str, Any]
    provenance: ProvenanceRecord


@runtime_checkable
class SandboxController(Protocol):
    def execute(
        self, tool: str, arguments: dict[str, Any], destination: str | None = None
    ) -> SandboxResult:
        ...


class LocalSandbox:
    """In-process sandbox with a timeout guard, egress control, and provenance."""

    def __init__(
        self,
        adapter: MCPAdapter,
        gateway: ProxyGateway,
        timeout_seconds: float = 10.0,
        backend: "ExecutionBackend | None" = None,
    ) -> None:
        from .sandbox_backends import InProcessBackend

        self._adapter = adapter
        self._gateway = gateway
        self._timeout = timeout_seconds
        self._pool = ThreadPoolExecutor(max_workers=4)
        self._backend = backend or InProcessBackend()

    @property
    def backend_name(self) -> str:  # type: ignore[override]
        return self._backend.name

    def execute(
        self, tool: str, arguments: dict[str, Any], destination: str | None = None
    ) -> SandboxResult:
        started = datetime.now(timezone.utc).isoformat()

        # Egress control for external/side-effecting tools.
        try:
            self._gateway.check(tool, destination)
        except EgressDenied as exc:
            raise SandboxExecutionError(str(exc)) from exc

        # Execute with a wall-clock timeout guard, via the pluggable backend.
        future = self._pool.submit(self._backend.run, self._adapter.call_tool, tool, arguments)
        try:
            output = future.result(timeout=self._timeout)
        except FuturesTimeout as exc:
            future.cancel()
            raise SandboxExecutionError(
                f"tool '{tool}' exceeded {self._timeout}s sandbox timeout"
            ) from exc
        except Exception as exc:  # tool raised
            raise SandboxExecutionError(f"tool '{tool}' failed: {exc}") from exc

        if not isinstance(output, dict):
            raise SandboxExecutionError(
                f"tool '{tool}' returned non-dict output: {type(output).__name__}"
            )

        finished = datetime.now(timezone.utc).isoformat()
        prov = ProvenanceRecord(
            tool=tool,
            arguments=dict(arguments),
            output=output,
            started_at=started,
            finished_at=finished,
            backend=self.backend_name,
        )
        return SandboxResult(output=output, provenance=prov)

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False)


def build_local_sandbox(config, adapter: MCPAdapter) -> tuple["LocalSandbox", dict[str, str]]:
    """Build a LocalSandbox + tool->destination map from an AetherConfig.

    Returns the sandbox and the destination map the engine uses for egress checks.
    Keeping construction here means callers (engine, demo, UI) wire the governed
    execution stack from config alone — zero hardcoding.
    """
    from .gateway import GatewayConfig, ProxyGateway
    from .sandbox_backends import build_backend

    sb = config.sandbox
    gateway = ProxyGateway(
        GatewayConfig(
            allow_destinations=list(sb.gateway.allow_destinations),
            external_tools=list(sb.gateway.external_tools),
            deny_by_default=sb.gateway.deny_by_default,
        )
    )
    backend = build_backend(getattr(sb, "backend", "local"))
    sandbox = LocalSandbox(
        adapter, gateway, timeout_seconds=sb.timeout_seconds, backend=backend
    )
    return sandbox, dict(sb.tool_destinations)
