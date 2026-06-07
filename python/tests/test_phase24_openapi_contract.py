"""Phase 24 — OpenAPI 1.0 contract tests.

Covers:
  - OpenAPI schema structure (version, title, paths)
  - Committed docs/openapi.json existence, validity, and drift detection
  - generate_openapi.py script existence
  - HTTP method contract for known GET endpoints
"""
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aetheros_orchestrator.api import create_app

REPO_ROOT = Path(__file__).parent.parent.parent


@pytest.fixture(scope="module")
def app():
    return create_app()


@pytest.fixture(scope="module")
def schema(app):
    return app.openapi()


@pytest.fixture(scope="module")
def client(app):
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# OpenAPI schema structure tests
# ---------------------------------------------------------------------------

def test_openapi_has_info(schema):
    assert "info" in schema


def test_openapi_version_is_1_0_0(schema):
    assert schema["info"]["version"] == "1.0.0"


def test_openapi_title_is_correct(schema):
    assert schema["info"]["title"] == "AetherOS Control Plane API"


def test_openapi_has_paths(schema):
    assert "paths" in schema
    assert len(schema["paths"]) >= 20


def test_openapi_health_live_path_present(schema):
    assert "/health/live" in schema["paths"]


def test_openapi_health_ready_path_present(schema):
    assert "/health/ready" in schema["paths"]


def test_openapi_health_deep_path_present(schema):
    assert "/health/deep" in schema["paths"]


def test_openapi_admin_runs_path_present(schema):
    assert "/admin/runs" in schema["paths"]


def test_openapi_admin_budget_path_present(schema):
    # FastAPI registers with the actual parameter name used in the route
    budget_paths = [p for p in schema["paths"] if "budget" in p]
    assert budget_paths, "No budget path found in schema"


def test_openapi_admin_deny_rate_path_present(schema):
    assert "/admin/policy/deny-rate" in schema["paths"]


def test_openapi_admin_summary_path_present(schema):
    assert "/admin/summary" in schema["paths"]


def test_openapi_metrics_path_present(schema):
    assert "/metrics" in schema["paths"]


def test_openapi_config_alerting_path_present(schema):
    assert "/config/alerting" in schema["paths"]


def test_openapi_auth_token_path_present(schema):
    assert "/auth/token" in schema["paths"]


def test_openapi_runs_path_present(schema):
    assert "/runs" in schema["paths"]


def test_openapi_openapi_version(schema):
    assert schema["openapi"].startswith("3.")


# ---------------------------------------------------------------------------
# Committed spec file tests
# ---------------------------------------------------------------------------

def test_openapi_json_file_exists():
    assert (REPO_ROOT / "docs" / "openapi.json").exists(), (
        "docs/openapi.json does not exist. Run: python scripts/generate_openapi.py"
    )


def test_openapi_json_is_valid_json():
    path = REPO_ROOT / "docs" / "openapi.json"
    assert path.exists()
    parsed = json.loads(path.read_text())
    assert isinstance(parsed, dict)


def test_openapi_json_matches_live_app(app):
    """Drift-detection: committed spec must exactly match what the live app produces."""
    path = REPO_ROOT / "docs" / "openapi.json"
    assert path.exists(), "docs/openapi.json missing — run: python scripts/generate_openapi.py"

    committed = json.dumps(json.loads(path.read_text()), indent=2, sort_keys=True)
    live = json.dumps(app.openapi(), indent=2, sort_keys=True)

    assert committed == live, (
        "docs/openapi.json is stale — run: python scripts/generate_openapi.py && git add docs/openapi.json"
    )


def test_generate_script_exists():
    assert (REPO_ROOT / "scripts" / "generate_openapi.py").exists()


# ---------------------------------------------------------------------------
# Endpoint HTTP contract tests
# ---------------------------------------------------------------------------

def test_all_get_endpoints_return_not_405(client):
    """A selection of known GET endpoints must not return 405 Method Not Allowed."""
    get_paths = [
        "/health/live",
        "/health/ready",
        "/health/deep",
        "/admin/runs",
        "/admin/policy/deny-rate",
        "/admin/summary",
        "/metrics",
        "/runs",
        "/auth/jwks",
        "/config/alerting",
        "/config/policy",
        "/analytics",
    ]
    for path in get_paths:
        resp = client.get(path)
        assert resp.status_code != 405, (
            f"GET {path} returned 405 Method Not Allowed — route may be missing"
        )
