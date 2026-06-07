"""Phase 21: Structured log-trace correlation + production health API — tests.

Atom of thoughts (each test validates exactly one independently verifiable property)
─────────────────────────────────────────────────────────────────────────────────────
Health endpoint tests:
  1.  test_live_always_200 — GET /health/live returns 200 with status=pass
  2.  test_live_body_schema — response has "status" and "service" keys
  3.  test_ready_200_default_config — default config returns 200
  4.  test_ready_schema — response has "status" and "checks" keys
  5.  test_ready_storage_pass_when_no_sqlite — storage check absent/pass when backend=none
  6.  test_ready_storage_warn_when_dir_missing — SQLite enabled but dir missing → warn
  7.  test_ready_storage_pass_when_dir_exists — SQLite + existing tmpdir → pass
  8.  test_ready_tracing_warn_when_enabled_no_otlp — tracing enabled exporter=none → pass/warn
  9.  test_ready_overall_fail_when_one_check_fails — force fail → HTTP 503
  10. test_deep_200 — GET /health/deep returns 200
  11. test_deep_rust_core_pass — rust_core check is present and passes
  12. test_deep_schema — response checks dict includes rust_core key
  13. test_deep_503_when_rust_core_unavailable — mocked EvidenceLedger raises → 503

Log-trace correlation tests:
  14. test_otel_filter_adds_trace_id_when_span_active
  15. test_otel_filter_empty_strings_when_no_span
  16. test_otel_filter_never_drops_records
  17. test_get_trace_context_returns_dict
  18. test_get_trace_context_empty_when_no_span
  19. test_get_trace_context_populated_when_span_active
  20. test_install_log_filter_idempotent
  21. test_log_filter_installed_after_configure_for_test

Ledger trace context injection tests:
  22. test_ledger_entry_has_trace_id_when_tracing_enabled
  23. test_ledger_entry_no_trace_fields_when_tracing_disabled
  24. test_trace_id_matches_span_trace_id

Integration tests:
  25. test_health_and_tracing_together
  26. test_live_under_load
  27. test_ready_component_time_is_iso8601
  28. test_deep_all_components_present
  29. test_health_config_disabled_returns_minimal
"""

from __future__ import annotations

import logging
import re
import unittest.mock
from datetime import datetime

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("opentelemetry")

from fastapi.testclient import TestClient

from aetheros_orchestrator.api import create_app
from aetheros_orchestrator.config import AetherConfig, HealthConfig, StorageConfig, TracingConfig
from aetheros_orchestrator.health import make_health_router
from aetheros_orchestrator.run_service import RunService
from aetheros_orchestrator import tracing as _tracing
from aetheros_orchestrator.tracing import configure_for_test, disable
from aetheros_orchestrator.trace_log import OtelLoggingFilter, install_log_filter, get_trace_context


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_client(config: AetherConfig | None = None) -> TestClient:
    """Build a TestClient backed by a default RunService and the given config."""
    svc = RunService()
    svc.tenants.create("Test Tenant", tenant_id="alpha")
    if config is not None:
        # Patch create_app to use the provided config.
        app = _make_app_with_config(config)
    else:
        app = create_app(service=svc)
    return TestClient(app, raise_server_exceptions=True)


def _make_app_with_config(config: AetherConfig):
    """Build a FastAPI app with the given AetherConfig for health endpoint control."""
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from aetheros_orchestrator.health import make_health_router

    app = FastAPI(title="AetherOS Test App")
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
    app.include_router(make_health_router(config))
    return app


_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX16 = re.compile(r"^[0-9a-f]{16}$")
_ISO8601 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")


def _advance_run(svc: RunService, tenant_id: str = "alpha") -> str:
    run = svc.create_run("investigate the incident", "human:vamsi", 500, tenant_id)
    svc.advance(run.run_id, tenant_id)
    return run.run_id


# ── Health endpoint tests ─────────────────────────────────────────────────────

def test_live_always_200():
    """GET /health/live returns 200 with status=pass."""
    client = _make_client()
    r = client.get("/health/live")
    assert r.status_code == 200
    assert r.json()["status"] == "pass"


def test_live_body_schema():
    """Response to GET /health/live has 'status' and 'service' keys."""
    client = _make_client()
    r = client.get("/health/live")
    body = r.json()
    assert "status" in body
    assert "service" in body


def test_ready_200_default_config():
    """Default config (no sqlite, no tracing) returns HTTP 200."""
    config = AetherConfig()
    client = TestClient(_make_app_with_config(config))
    r = client.get("/health/ready")
    assert r.status_code == 200


def test_ready_schema():
    """Response to GET /health/ready has 'status' and 'checks' keys."""
    config = AetherConfig()
    client = TestClient(_make_app_with_config(config))
    r = client.get("/health/ready")
    body = r.json()
    assert "status" in body
    assert "checks" in body


def test_ready_storage_pass_when_no_sqlite():
    """When storage.backend='none', no storage check or pass (not fail)."""
    config = AetherConfig()
    assert config.storage.backend == "none"
    client = TestClient(_make_app_with_config(config))
    r = client.get("/health/ready")
    body = r.json()
    assert r.status_code == 200
    # storage check should either be absent or not 'fail'
    storage = body["checks"].get("storage")
    assert storage is None or storage["status"] != "fail"


def test_ready_storage_warn_when_dir_missing(tmp_path):
    """SQLite enabled but db_dir doesn't exist → storage check status=warn."""
    non_existent = str(tmp_path / "nonexistent_dir_xyz")
    config = AetherConfig(
        storage=StorageConfig(backend="sqlite", db_dir=non_existent)
    )
    client = TestClient(_make_app_with_config(config))
    r = client.get("/health/ready")
    body = r.json()
    assert "storage" in body["checks"]
    assert body["checks"]["storage"]["status"] == "warn"


def test_ready_storage_pass_when_dir_exists(tmp_path):
    """SQLite enabled and db_dir exists → storage check status=pass."""
    config = AetherConfig(
        storage=StorageConfig(backend="sqlite", db_dir=str(tmp_path))
    )
    client = TestClient(_make_app_with_config(config))
    r = client.get("/health/ready")
    body = r.json()
    assert "storage" in body["checks"]
    assert body["checks"]["storage"]["status"] == "pass"


def test_ready_tracing_warn_when_enabled_no_otlp():
    """Tracing enabled with exporter=none: check is pass or warn (SDK present)."""
    config = AetherConfig(
        tracing=TracingConfig(enabled=True, exporter_type="none")
    )
    client = TestClient(_make_app_with_config(config))
    r = client.get("/health/ready")
    body = r.json()
    # When SDK is present, it should be pass; if not installed, warn.
    assert "tracing" in body["checks"]
    assert body["checks"]["tracing"]["status"] in ("pass", "warn")


def test_ready_overall_fail_when_one_check_fails(tmp_path, monkeypatch):
    """Force a storage check to fail → overall status=fail, HTTP 503."""
    config = AetherConfig(
        storage=StorageConfig(backend="sqlite", db_dir=str(tmp_path))
    )
    # Monkeypatch Path.touch to raise OSError, simulating unwritable dir.
    from pathlib import Path
    original_touch = Path.touch

    def _bad_touch(self, *args, **kwargs):
        if "aetheros_health_probe" in str(self):
            raise OSError("permission denied")
        return original_touch(self, *args, **kwargs)

    monkeypatch.setattr(Path, "touch", _bad_touch)
    client = TestClient(_make_app_with_config(config))
    r = client.get("/health/ready")
    assert r.status_code == 503
    assert r.json()["status"] == "fail"


def test_deep_200():
    """GET /health/deep returns HTTP 200 under default config."""
    config = AetherConfig()
    client = TestClient(_make_app_with_config(config))
    r = client.get("/health/deep")
    assert r.status_code == 200


def test_deep_rust_core_pass():
    """The rust_core check in /health/deep passes (EvidenceLedger works)."""
    config = AetherConfig()
    client = TestClient(_make_app_with_config(config))
    r = client.get("/health/deep")
    body = r.json()
    assert "rust_core" in body["checks"]
    assert body["checks"]["rust_core"]["status"] == "pass"


def test_deep_schema():
    """Response to GET /health/deep has rust_core in the checks dict."""
    config = AetherConfig()
    client = TestClient(_make_app_with_config(config))
    r = client.get("/health/deep")
    body = r.json()
    assert "status" in body
    assert "checks" in body
    assert "rust_core" in body["checks"]


def test_deep_503_when_rust_core_unavailable():
    """When EvidenceLedger raises, rust_core=fail and HTTP 503."""
    config = AetherConfig()
    import aetheros_orchestrator.health as _health_mod

    original = _health_mod._check_rust_core

    def _failing():
        return _health_mod._check_result("rust_core", "component", "fail", "mocked failure")

    _health_mod._check_rust_core = _failing
    try:
        client = TestClient(_make_app_with_config(config))
        r = client.get("/health/deep")
        assert r.status_code == 503
        assert r.json()["status"] == "fail"
        assert r.json()["checks"]["rust_core"]["status"] == "fail"
    finally:
        _health_mod._check_rust_core = original


# ── Log-trace correlation tests ───────────────────────────────────────────────

def test_otel_filter_adds_trace_id_when_span_active():
    """OtelLoggingFilter injects 32-hex trace_id and 16-hex span_id when span is active."""
    fixture = configure_for_test()
    try:
        from opentelemetry import trace as otel_trace
        tracer = _tracing.get_tracer("test")
        with tracer.start_as_current_span("test.span"):
            filt = OtelLoggingFilter()
            record = logging.LogRecord("test", logging.INFO, "", 0, "msg", (), None)
            filt.filter(record)
            assert _HEX32.match(record.trace_id), f"Expected 32-hex trace_id, got: {record.trace_id!r}"
            assert _HEX16.match(record.span_id), f"Expected 16-hex span_id, got: {record.span_id!r}"
    finally:
        disable()


def test_otel_filter_empty_strings_when_no_span():
    """OtelLoggingFilter injects empty strings when no span is active."""
    filt = OtelLoggingFilter()
    record = logging.LogRecord("test", logging.INFO, "", 0, "msg", (), None)
    filt.filter(record)
    assert record.trace_id == ""
    assert record.span_id == ""


def test_otel_filter_never_drops_records():
    """OtelLoggingFilter.filter() always returns True."""
    filt = OtelLoggingFilter()
    record = logging.LogRecord("test", logging.DEBUG, "", 0, "hello", (), None)
    assert filt.filter(record) is True


def test_get_trace_context_returns_dict():
    """get_trace_context() always returns a dict with trace_id and span_id keys."""
    ctx = get_trace_context()
    assert isinstance(ctx, dict)
    assert "trace_id" in ctx
    assert "span_id" in ctx


def test_get_trace_context_empty_when_no_span():
    """get_trace_context() returns empty strings when no span is active."""
    ctx = get_trace_context()
    assert ctx["trace_id"] == ""
    assert ctx["span_id"] == ""


def test_get_trace_context_populated_when_span_active():
    """get_trace_context() returns non-empty 32-hex trace_id when span is active."""
    fixture = configure_for_test()
    try:
        tracer = _tracing.get_tracer("test")
        with tracer.start_as_current_span("test.span.ctx"):
            ctx = get_trace_context()
            assert _HEX32.match(ctx["trace_id"]), f"Expected 32-hex, got: {ctx['trace_id']!r}"
            assert _HEX16.match(ctx["span_id"]), f"Expected 16-hex, got: {ctx['span_id']!r}"
    finally:
        disable()


def test_install_log_filter_idempotent():
    """Calling install_log_filter twice doesn't add duplicate filters."""
    logger = logging.getLogger("aetheros_orchestrator_test_idempotent_xyz")
    # Clear existing filters first.
    logger.filters.clear()

    install_log_filter("aetheros_orchestrator_test_idempotent_xyz")
    install_log_filter("aetheros_orchestrator_test_idempotent_xyz")
    install_log_filter("aetheros_orchestrator_test_idempotent_xyz")

    otel_filters = [f for f in logger.filters if isinstance(f, OtelLoggingFilter)]
    assert len(otel_filters) == 1

    # Cleanup.
    logger.filters.clear()


def test_log_filter_installed_after_configure_for_test():
    """After configure_for_test(), the aetheros_orchestrator logger has an OtelLoggingFilter."""
    fixture = configure_for_test()
    try:
        logger = logging.getLogger("aetheros_orchestrator")
        otel_filters = [f for f in logger.filters if isinstance(f, OtelLoggingFilter)]
        assert len(otel_filters) >= 1
    finally:
        disable()


# ── Ledger trace context injection tests ──────────────────────────────────────

def test_ledger_entry_has_trace_id_when_tracing_enabled():
    """Ledger 'tool.invoked' entries include _trace_id when tracing is enabled."""
    fixture = configure_for_test()
    try:
        svc = RunService()
        svc.tenants.create("Alpha", tenant_id="alpha")
        run_id = _advance_run(svc, "alpha")
        ev = svc.evidence(run_id, "alpha")
        invoked = [e for e in ev["entries"] if e["event_type"] == "tool.invoked"]
        # At least one entry should have _trace_id (steps run inside advance span).
        assert any("_trace_id" in e["payload"] for e in invoked), (
            "Expected at least one tool.invoked entry with _trace_id; "
            f"payloads: {[e['payload'] for e in invoked]}"
        )
    finally:
        disable()


def test_ledger_entry_no_trace_fields_when_tracing_disabled():
    """Ledger entries do NOT include _trace_id when tracing is disabled (default)."""
    # Ensure tracing is disabled.
    disable()
    svc = RunService()
    svc.tenants.create("Beta", tenant_id="beta")
    run_id = _advance_run(svc, "beta")
    ev = svc.evidence(run_id, "beta")
    invoked = [e for e in ev["entries"] if e["event_type"] == "tool.invoked"]
    for entry in invoked:
        assert "_trace_id" not in entry["payload"], (
            f"Expected no _trace_id in payload when tracing is disabled; got: {entry['payload']}"
        )


def test_trace_id_matches_span_trace_id():
    """The _trace_id in ledger entries matches the root span's trace_id."""
    fixture = configure_for_test()
    try:
        svc = RunService()
        svc.tenants.create("Gamma", tenant_id="gamma")

        tracer = _tracing.get_tracer("test")
        with tracer.start_as_current_span("aetheros.run.advance") as root_span:
            run_id = _advance_run(svc, "gamma")
            root_ctx = root_span.get_span_context()
            expected_trace_id = format(root_ctx.trace_id, "032x")

        ev = svc.evidence(run_id, "gamma")
        invoked = [e for e in ev["entries"] if e["event_type"] == "tool.invoked"]
        entries_with_trace = [e for e in invoked if "_trace_id" in e["payload"]]
        assert entries_with_trace, "Expected at least one tool.invoked entry with _trace_id"
        # All entries with _trace_id should share the root span's trace_id.
        for entry in entries_with_trace:
            assert entry["payload"]["_trace_id"] == expected_trace_id, (
                f"trace_id mismatch: expected {expected_trace_id}, "
                f"got {entry['payload']['_trace_id']}"
            )
    finally:
        disable()


# ── Integration tests ─────────────────────────────────────────────────────────

def test_health_and_tracing_together():
    """With tracing enabled, /health/ready returns 200 and tracing check passes."""
    config = AetherConfig(
        tracing=TracingConfig(enabled=True, exporter_type="none")
    )
    client = TestClient(_make_app_with_config(config))
    r = client.get("/health/ready")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] in ("pass", "warn")
    assert "tracing" in body["checks"]
    assert body["checks"]["tracing"]["status"] in ("pass", "warn")


def test_live_under_load():
    """GET /health/live returns 200 for 10 consecutive requests."""
    client = _make_client()
    for _ in range(10):
        r = client.get("/health/live")
        assert r.status_code == 200
        assert r.json()["status"] == "pass"


def test_ready_component_time_is_iso8601(tmp_path):
    """Each check result in /health/ready has a valid ISO 8601 'time' field."""
    config = AetherConfig(
        storage=StorageConfig(backend="sqlite", db_dir=str(tmp_path)),
        tracing=TracingConfig(enabled=True, exporter_type="none"),
    )
    client = TestClient(_make_app_with_config(config))
    r = client.get("/health/ready")
    body = r.json()
    for component_id, check in body["checks"].items():
        assert "time" in check, f"Missing 'time' in check for {component_id}"
        assert _ISO8601.match(check["time"]), (
            f"Invalid ISO 8601 time for {component_id}: {check['time']!r}"
        )


def test_deep_all_components_present(tmp_path):
    """Deep check includes storage, tracing, and rust_core keys."""
    config = AetherConfig(
        storage=StorageConfig(backend="sqlite", db_dir=str(tmp_path)),
        tracing=TracingConfig(enabled=True, exporter_type="none"),
    )
    client = TestClient(_make_app_with_config(config))
    r = client.get("/health/deep")
    body = r.json()
    assert "storage" in body["checks"], "Missing storage check in /health/deep"
    assert "tracing" in body["checks"], "Missing tracing check in /health/deep"
    assert "rust_core" in body["checks"], "Missing rust_core check in /health/deep"


def test_health_config_disabled_returns_minimal():
    """HealthConfig(enabled=False) → /health/ready returns pass with empty checks."""
    config = AetherConfig(health=HealthConfig(enabled=False))
    client = TestClient(_make_app_with_config(config))
    r = client.get("/health/ready")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "pass"
    assert body["checks"] == {}
