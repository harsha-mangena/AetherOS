"""Expanded sandbox execution backends (Phase 6).

Phase 4 gave us LocalSandbox: a wrapper that enforces a wall-clock timeout, egress
control, and content-addressed provenance around an in-process tool call. Phase 6
factors out the *execution strategy* — the part that actually runs the tool body — behind
an `ExecutionBackend` protocol, so stronger isolation (WASM, Firecracker microVM, native
process jail) drops in without touching the governance wrapper, the engine, or the
provenance/ledger plumbing.

Honesty about isolation (research net / revalidate). Real WASM (e.g. wasmtime) and
Firecracker isolation are host- and dependency-specific: Firecracker needs a Linux host
with KVM and cannot run hermetically in this dev/test environment, and a real WASM
sandbox needs a compiled runtime and a wasm build of each tool. Shipping a backend that
*claims* isolation it does not provide would be a governance lie — worse than none, since
operators would over-trust it. So each backend declares an honest `isolation_level` and
`provides_isolation` flag. The default `InProcessBackend` is explicit that it does NOT
isolate (it relies on the upstream policy/lease gate + timeout + egress for safety). The
`WasmStubBackend` and `FirecrackerStubBackend` are clearly-labelled placeholders that
carry the capability contract and config wiring a real implementation will satisfy; they
raise if asked to actually execute, so they can never be silently trusted in production.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Protocol, runtime_checkable


class IsolationLevel(str, Enum):
    NONE = "none"  # same process; safety comes from policy/lease + timeout + egress
    PROCESS = "process"  # separate OS process / jail
    WASM = "wasm"  # WebAssembly sandbox (memory-isolated, capability-gated)
    MICROVM = "microvm"  # Firecracker / microVM (hardware-virtualized)


class SandboxBackendError(RuntimeError):
    """A backend could not execute (e.g. an unconfigured isolation backend)."""


@runtime_checkable
class ExecutionBackend(Protocol):
    """Runs an already-authorized tool body. The governance gate ran upstream."""

    name: str
    isolation_level: IsolationLevel
    provides_isolation: bool

    def run(self, call, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Execute `call(tool, arguments)` under this backend, returning its dict output."""
        ...


class InProcessBackend:
    """Default backend: runs the tool in-process.

    It explicitly does NOT provide isolation. Safety for this backend comes from the
    upstream policy + lease authorization, the sandbox timeout, and egress control. This
    is the right default for trusted first-party tools and for hermetic tests/demos.
    """

    name = "in-process"
    isolation_level = IsolationLevel.NONE
    provides_isolation = False

    def run(self, call, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return call(tool, arguments)


class _UnconfiguredIsolationBackend:
    """Base for isolation backends that are not yet wired to a real runtime.

    Declares the honest capability contract but refuses to execute, so it can never be
    mistaken for working isolation. A real implementation overrides `run`.
    """

    name = "unconfigured"
    isolation_level = IsolationLevel.NONE
    provides_isolation = False
    _runtime_hint = "no runtime configured"

    def run(self, call, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        raise SandboxBackendError(
            f"{self.name} backend is not configured ({self._runtime_hint}); "
            "configure a real runtime or use the in-process backend"
        )


class WasmStubBackend(_UnconfiguredIsolationBackend):
    """Placeholder for a WASM (e.g. wasmtime) backend.

    Carries the WASM capability contract: a real implementation compiles tools to wasm,
    instantiates them in a memory-isolated, capability-gated runtime, and returns their
    output. Until that runtime + wasm artifacts exist, it refuses to run.
    """

    name = "wasm"
    isolation_level = IsolationLevel.WASM
    provides_isolation = True  # the *level* it targets; gated by configuration below
    _runtime_hint = "wasmtime runtime + wasm tool artifacts not present"


class FirecrackerStubBackend(_UnconfiguredIsolationBackend):
    """Placeholder for a Firecracker microVM backend (Linux + KVM only)."""

    name = "firecracker"
    isolation_level = IsolationLevel.MICROVM
    provides_isolation = True
    _runtime_hint = "Firecracker requires a Linux host with KVM"


# Registry mapping config names to backend factories.
_BACKENDS: dict[str, type] = {
    "in-process": InProcessBackend,
    "local": InProcessBackend,  # alias: the local sandbox's default execution strategy
    "wasm": WasmStubBackend,
    "firecracker": FirecrackerStubBackend,
}


def build_backend(name: str) -> ExecutionBackend:
    """Construct an execution backend by config name (zero hardcoding at call sites)."""
    factory = _BACKENDS.get(name)
    if factory is None:
        raise SandboxBackendError(
            f"unknown sandbox backend '{name}'; known: {sorted(_BACKENDS)}"
        )
    return factory()


def available_backends() -> dict[str, dict[str, Any]]:
    """Describe each registered backend's honest isolation capabilities."""
    out: dict[str, dict[str, Any]] = {}
    for key, factory in _BACKENDS.items():
        b = factory()
        out[key] = {
            "name": b.name,
            "isolation_level": b.isolation_level.value,
            "provides_isolation": b.provides_isolation,
        }
    return out
