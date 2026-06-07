"""Phase 23 tests: graceful shutdown drain logic + Prometheus alerting rules.

Covers:
  - RunService drain flag, _drain_halt, drain(), is_draining property
  - create_run rejection when draining
  - advance() behavior when draining
  - Ledger entries for drain-halted runs
  - FastAPI lifespan context manager wiring
  - config/alerting/rules.yml existence, validity, structure
  - GET /config/alerting endpoint
  - Integration: drain idempotency
"""

from __future__ import annotations

import threading
from pathlib import Path

import pytest
import yaml

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from aetheros_orchestrator.api import create_app
from aetheros_orchestrator.run_service import RunService, RunStatus

REPO_ROOT = Path(__file__).parent.parent.parent
RULES_PATH = REPO_ROOT / "config" / "alerting" / "rules.yml"

INTENT = "Investigate the production incident in checkout and restore service"


# ── Drain logic unit tests ─────────────────────────────────────────────────────


def test_run_service_has_drain_method():
    svc = RunService()
    assert hasattr(svc, "drain"), "RunService must have a drain() method"
    assert callable(svc.drain)


def test_run_service_has_is_draining_property():
    svc = RunService()
    assert hasattr(svc, "is_draining"), "RunService must have an is_draining property"
    assert svc.is_draining is False, "is_draining should start as False"


def test_drain_sets_draining_flag():
    svc = RunService()
    assert svc.is_draining is False
    svc.drain(timeout_seconds=0)
    assert svc.is_draining is True


def test_drain_returns_int():
    svc = RunService()
    result = svc.drain(timeout_seconds=0)
    assert isinstance(result, int), "drain() must return an int"


def test_drain_returns_zero_with_no_runs():
    svc = RunService()
    result = svc.drain(timeout_seconds=0)
    assert result == 0, "drain() with no runs should return 0"


def test_create_run_raises_when_draining():
    svc = RunService()
    svc.drain(timeout_seconds=0)
    with pytest.raises(RuntimeError, match="draining"):
        svc.create_run(INTENT)


def test_advance_returns_halted_when_draining():
    svc = RunService()
    run = svc.create_run(INTENT)
    # Manually set draining flag without going through drain() so we can
    # still have a run to advance.
    svc._draining = True
    result = svc.advance(run.run_id)
    assert result.status == RunStatus.HALTED


def test_advance_records_drain_halt_ledger_entry():
    svc = RunService()
    run = svc.create_run(INTENT)
    svc._draining = True
    svc.advance(run.run_id)
    ev = svc.evidence(run.run_id)
    drain_entries = [
        e for e in ev["entries"] if e["event_type"] == "run.drain_halted"
    ]
    assert len(drain_entries) >= 1, "Ledger must contain a run.drain_halted entry"


def test_drain_halt_sets_denied_reason():
    svc = RunService()
    run = svc.create_run(INTENT)
    svc._draining = True
    result = svc.advance(run.run_id)
    assert result.denied_reason is not None
    assert "draining" in result.denied_reason.lower()


def test_drain_halts_running_runs():
    """Start a run, set it to RUNNING status, then drain — it should be halted."""
    svc = RunService()
    run = svc.create_run(INTENT)
    # Force RUNNING status so drain() sees it.
    run.status = RunStatus.RUNNING
    result = svc.drain(timeout_seconds=1)
    assert result >= 1, "drain() should report at least 1 drained run"
    assert run.status == RunStatus.HALTED


# ── Lifespan / API shutdown tests ─────────────────────────────────────────────


def test_create_app_has_lifespan():
    """The created app should have a lifespan context configured."""
    app = create_app()
    # FastAPI stores the lifespan on router.lifespan_context
    assert app.router.lifespan_context is not None


def test_app_starts_with_running_service():
    """TestClient context manager should handle startup/shutdown lifecycle."""
    svc = RunService()
    app = create_app(service=svc)
    with TestClient(app) as client:
        resp = client.get("/health")
        assert resp.status_code == 200


def test_app_rejects_runs_after_service_drain():
    """Injecting a pre-drained service; POST /runs should return 503."""
    svc = RunService()
    svc.drain(timeout_seconds=0)
    app = create_app(service=svc)
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.post("/runs", json={"intent": INTENT, "submitted_by": "test-user"})
    assert resp.status_code == 503


def test_lifespan_drain_timeout_is_configurable():
    """create_app should accept a drain_timeout_seconds parameter."""
    svc = RunService()
    # Should not raise
    app = create_app(service=svc, drain_timeout_seconds=5)
    assert app is not None


# ── Alerting rules file tests ──────────────────────────────────────────────────


def test_alerting_rules_file_exists():
    assert RULES_PATH.exists(), f"config/alerting/rules.yml not found at {RULES_PATH}"


def test_alerting_rules_is_valid_yaml():
    content = RULES_PATH.read_text()
    parsed = yaml.safe_load(content)
    assert parsed is not None, "rules.yml must parse as non-empty YAML"


def test_alerting_rules_has_groups():
    parsed = yaml.safe_load(RULES_PATH.read_text())
    assert "groups" in parsed, "rules.yml must have a top-level 'groups' key"


def test_alerting_rules_has_recording_group():
    parsed = yaml.safe_load(RULES_PATH.read_text())
    group_names = [g["name"] for g in parsed["groups"]]
    assert "aetheros.recording" in group_names


def test_alerting_rules_has_alerts_group():
    parsed = yaml.safe_load(RULES_PATH.read_text())
    group_names = [g["name"] for g in parsed["groups"]]
    assert "aetheros.alerts" in group_names


def test_alerting_rules_recording_count():
    parsed = yaml.safe_load(RULES_PATH.read_text())
    recording_group = next(
        g for g in parsed["groups"] if g["name"] == "aetheros.recording"
    )
    rules = recording_group.get("rules", [])
    assert len(rules) >= 5, f"Expected at least 5 recording rules, got {len(rules)}"


def test_alerting_rules_alert_count():
    parsed = yaml.safe_load(RULES_PATH.read_text())
    alerts_group = next(
        g for g in parsed["groups"] if g["name"] == "aetheros.alerts"
    )
    rules = alerts_group.get("rules", [])
    assert len(rules) >= 5, f"Expected at least 5 alerting rules, got {len(rules)}"


def test_alerting_rules_deny_rate_alert_present():
    parsed = yaml.safe_load(RULES_PATH.read_text())
    alerts_group = next(
        g for g in parsed["groups"] if g["name"] == "aetheros.alerts"
    )
    alert_names = [r.get("alert") for r in alerts_group["rules"]]
    assert "AetherOSHighPolicyDenyRate" in alert_names


def test_alerting_rules_severity_labels():
    parsed = yaml.safe_load(RULES_PATH.read_text())
    alerts_group = next(
        g for g in parsed["groups"] if g["name"] == "aetheros.alerts"
    )
    for rule in alerts_group["rules"]:
        labels = rule.get("labels", {})
        assert "severity" in labels, f"Alert {rule.get('alert')} missing severity label"


def test_alerting_rules_runbook_urls():
    parsed = yaml.safe_load(RULES_PATH.read_text())
    alerts_group = next(
        g for g in parsed["groups"] if g["name"] == "aetheros.alerts"
    )
    for rule in alerts_group["rules"]:
        annotations = rule.get("annotations", {})
        assert "runbook_url" in annotations, (
            f"Alert {rule.get('alert')} missing runbook_url annotation"
        )


def test_alerting_rules_four_golden_signals_covered():
    """Recording rules should cover latency, traffic, errors, and saturation."""
    parsed = yaml.safe_load(RULES_PATH.read_text())
    recording_group = next(
        g for g in parsed["groups"] if g["name"] == "aetheros.recording"
    )
    all_exprs = " ".join(r.get("expr", "") for r in recording_group["rules"])

    # Latency — duration histogram
    assert "aetheros_runs_duration_ms_bucket" in all_exprs or "duration_ms" in all_exprs
    # Traffic — run starts
    assert "aetheros_runs_started_total" in all_exprs
    # Errors — policy denials
    assert "aetheros_policy_denied_total" in all_exprs
    # Saturation — budget throughput
    assert "aetheros_budget_spent_minor_total" in all_exprs


# ── GET /config/alerting endpoint tests ───────────────────────────────────────


def _alerting_client() -> TestClient:
    return TestClient(create_app(RunService()))


def test_get_alerting_endpoint_200():
    c = _alerting_client()
    resp = c.get("/config/alerting")
    assert resp.status_code == 200


def test_get_alerting_content_type_yaml():
    c = _alerting_client()
    resp = c.get("/config/alerting")
    assert "yaml" in resp.headers.get("content-type", "").lower()


def test_get_alerting_contains_groups():
    c = _alerting_client()
    resp = c.get("/config/alerting")
    assert "groups:" in resp.text


def test_get_alerting_contains_recording_rules():
    c = _alerting_client()
    resp = c.get("/config/alerting")
    assert "aetheros:policy_deny_rate:5m" in resp.text


def test_get_alerting_contains_alert_rules():
    c = _alerting_client()
    resp = c.get("/config/alerting")
    assert "AetherOSHighPolicyDenyRate" in resp.text


def test_get_alerting_is_valid_yaml():
    c = _alerting_client()
    resp = c.get("/config/alerting")
    parsed = yaml.safe_load(resp.text)
    assert parsed is not None
    assert "groups" in parsed


# ── Integration test ───────────────────────────────────────────────────────────


def test_drain_then_advance_is_idempotent():
    """Calling advance on an already-halted run after drain should be a no-op."""
    svc = RunService()
    run = svc.create_run(INTENT)
    svc._draining = True
    # First advance halts the run.
    result1 = svc.advance(run.run_id)
    assert result1.status == RunStatus.HALTED

    # Second advance on the halted run must return the same run unchanged.
    result2 = svc.advance(run.run_id)
    assert result2.status == RunStatus.HALTED
    assert result2.run_id == result1.run_id

    # Evidence should only have one drain_halted entry (not two).
    ev = svc.evidence(run.run_id)
    drain_entries = [e for e in ev["entries"] if e["event_type"] == "run.drain_halted"]
    assert len(drain_entries) == 1, "Should not double-record drain_halted entries"
