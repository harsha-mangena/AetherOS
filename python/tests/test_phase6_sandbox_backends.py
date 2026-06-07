"""Phase 6e tests: pluggable sandbox execution backends.

Proves the execution strategy is swappable behind the SandboxController wrapper, that the
default stays in-process and honest about isolation, and that unconfigured isolation
backends refuse to run (never silently trusted) while still flowing provenance correctly.
"""

from __future__ import annotations

import pytest

from aetheros_orchestrator.config import load_config
from aetheros_orchestrator.gateway import GatewayConfig, ProxyGateway
from aetheros_orchestrator.mcp_adapter import default_incident_adapter
from aetheros_orchestrator.sandbox import LocalSandbox, build_local_sandbox
from aetheros_orchestrator.sandbox_backends import (
    FirecrackerStubBackend,
    InProcessBackend,
    IsolationLevel,
    SandboxBackendError,
    WasmStubBackend,
    available_backends,
    build_backend,
)


def _gateway() -> ProxyGateway:
    return ProxyGateway(GatewayConfig(deny_by_default=False))


def test_default_backend_is_in_process_and_honest():
    b = InProcessBackend()
    assert b.isolation_level is IsolationLevel.NONE
    assert b.provides_isolation is False


def test_build_backend_known_and_unknown():
    assert isinstance(build_backend("in-process"), InProcessBackend)
    assert isinstance(build_backend("local"), InProcessBackend)
    assert isinstance(build_backend("wasm"), WasmStubBackend)
    assert isinstance(build_backend("firecracker"), FirecrackerStubBackend)
    with pytest.raises(SandboxBackendError):
        build_backend("does-not-exist")


def test_available_backends_describe_capabilities():
    desc = available_backends()
    assert desc["wasm"]["isolation_level"] == "wasm"
    assert desc["firecracker"]["isolation_level"] == "microvm"
    assert desc["in-process"]["provides_isolation"] is False


def test_unconfigured_isolation_backends_refuse_to_run():
    """Critical: a stub isolation backend must never silently execute as if isolated."""
    for backend in (WasmStubBackend(), FirecrackerStubBackend()):
        with pytest.raises(SandboxBackendError):
            backend.run(lambda t, a: {"ok": True}, "noop", {})


def test_localsandbox_uses_injected_backend_in_provenance():
    adapter = default_incident_adapter()
    sandbox = LocalSandbox(adapter, _gateway(), backend=InProcessBackend())
    # Use a real tool from the incident adapter.
    tool = adapter.list_tools()[0].name
    result = sandbox.execute(tool, {})
    assert result.provenance.backend == "in-process"
    assert result.provenance.verify()
    assert sandbox.backend_name == "in-process"


def test_localsandbox_default_backend_still_works():
    adapter = default_incident_adapter()
    sandbox = LocalSandbox(adapter, _gateway())
    tool = adapter.list_tools()[0].name
    result = sandbox.execute(tool, {})
    assert result.provenance.backend == "in-process"


def test_build_local_sandbox_honors_config_backend():
    cfg = load_config()
    cfg.sandbox.backend = "in-process"
    adapter = default_incident_adapter()
    sandbox, destinations = build_local_sandbox(cfg, adapter)
    assert sandbox.backend_name == "in-process"
    assert isinstance(destinations, dict)
