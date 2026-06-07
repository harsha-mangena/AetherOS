"""Production health and readiness endpoints for AetherOS — Phase 21.

Three probes following Kubernetes and IETF Health Check Response Format conventions:

  GET /health/live   — liveness: process is alive (always 200 if handler responds)
  GET /health/ready  — readiness: all critical dependencies are reachable
  GET /health/deep   — deep: full dependency + data-integrity check

Response schema follows draft-inadarei-api-health-check-06 (IETF 2022):
  status: "pass" | "warn" | "fail"
  checks: { componentId: { status, componentType, observedValue, time } }

Standards:
- Kubernetes Liveness/Readiness/Startup probe conventions (k8s docs v1.29)
- Google SRE Book (2016): liveness ≠ readiness
- IETF Health Check Response Format for HTTP APIs (draft-inadarei-api-health-check-06, 2022)
- Spring Boot Actuator / ASP.NET health check schema conventions
"""

from __future__ import annotations

import datetime
import os
from pathlib import Path
from typing import Any

try:
    from fastapi import APIRouter
    from fastapi.responses import JSONResponse
    _FASTAPI_AVAILABLE = True
except ImportError:  # pragma: no cover
    _FASTAPI_AVAILABLE = False

from .config import AetherConfig


# ── Status helpers ─────────────────────────────────────────────────────────────

_STATUS_ORDER = {"pass": 0, "warn": 1, "fail": 2}


def _worst(statuses: list[str]) -> str:
    """Return the most severe status from a list."""
    return max(statuses, key=lambda s: _STATUS_ORDER.get(s, 0), default="pass")


def _now_iso() -> str:
    """Return the current UTC time as an ISO 8601 string."""
    return datetime.datetime.utcnow().isoformat() + "Z"


def _check_result(
    component_id: str,
    component_type: str,
    status: str,
    observed_value: str,
) -> dict[str, Any]:
    return {
        "status": status,
        "componentId": component_id,
        "componentType": component_type,
        "observedValue": observed_value,
        "time": _now_iso(),
    }


# ── Individual checks ─────────────────────────────────────────────────────────

def _check_storage(config: AetherConfig) -> dict[str, Any] | None:
    """Check whether the configured storage backend is reachable."""
    if config.storage.backend != "sqlite":
        return None
    try:
        import sqlite3  # noqa: F401 — availability check
        db_dir = Path(config.storage.db_dir)
        if not db_dir.exists():
            return _check_result(
                "storage",
                "datastore",
                "warn",
                f"db_dir '{db_dir}' does not exist yet; will be created on first use",
            )
        # Verify we can write into the directory.
        test_path = db_dir / ".aetheros_health_probe"
        try:
            test_path.touch()
            test_path.unlink()
        except OSError as exc:
            return _check_result(
                "storage",
                "datastore",
                "fail",
                f"db_dir '{db_dir}' is not writable: {exc}",
            )
        return _check_result("storage", "datastore", "pass", f"sqlite db_dir '{db_dir}' is writable")
    except Exception as exc:
        return _check_result("storage", "datastore", "fail", f"storage check error: {exc}")


def _check_tracing(config: AetherConfig) -> dict[str, Any] | None:
    """Check whether the OpenTelemetry SDK is importable when tracing is enabled."""
    if not config.tracing.enabled:
        return None
    try:
        import opentelemetry  # noqa: F401 — availability check
        return _check_result(
            "tracing",
            "system",
            "pass",
            f"opentelemetry SDK available (exporter={config.tracing.exporter_type})",
        )
    except ImportError:
        return _check_result(
            "tracing",
            "system",
            "warn",
            "opentelemetry SDK not installed; tracing will be a no-op",
        )
    except Exception as exc:
        return _check_result("tracing", "system", "warn", f"tracing check warning: {exc}")


def _check_rust_core() -> dict[str, Any]:
    """Verify the Rust core (aetheros extension) is loaded and functional."""
    try:
        from aetheros import EvidenceLedger
        ledger = EvidenceLedger()
        ok = ledger.verify()
        if ok:
            return _check_result("rust_core", "component", "pass", "EvidenceLedger().verify() returned True")
        else:
            return _check_result("rust_core", "component", "fail", "EvidenceLedger().verify() returned False")
    except Exception as exc:
        return _check_result("rust_core", "component", "fail", f"rust core check failed: {exc}")


def _check_key_store(config: AetherConfig) -> dict[str, Any] | None:
    """Check that the auth key store directory exists or can be created."""
    ks_dir = getattr(config.auth, "token_keystore_dir", "")
    if not ks_dir:
        return None
    try:
        ks_path = Path(ks_dir)
        if not ks_path.exists():
            ks_path.mkdir(parents=True, exist_ok=True)
        return _check_result("key_store", "datastore", "pass", f"key_store dir '{ks_path}' exists/created")
    except Exception as exc:
        return _check_result("key_store", "datastore", "fail", f"key_store dir error: {exc}")


# ── Router factory ────────────────────────────────────────────────────────────

def make_health_router(config: AetherConfig) -> "APIRouter":
    """Build and return a FastAPI APIRouter with /health/live, /health/ready, /health/deep.

    Parameters
    ----------
    config:
        The active AetherConfig instance. Checks are gated on config.health.enabled;
        when False the ready/deep probes return pass with an empty checks dict so no
        internal topology is leaked.
    """
    router = APIRouter(prefix="/health", tags=["health"])

    @router.get("/live")
    def liveness() -> dict[str, Any]:
        """Liveness probe — always returns 200 if the process is alive."""
        return {"status": "pass", "service": "aetheros-control-plane"}

    @router.get("")
    @router.get("/")
    def liveness_legacy() -> dict[str, Any]:
        """Legacy liveness probe — backward-compatible alias for /health/live.

        Returns status="ok" to maintain backward compatibility with Phase 5-20
        tests that call GET /health and expect {"status": "ok", ...}.
        """
        return {"status": "ok", "service": "aetheros-control-plane"}

    @router.get("/ready")
    def readiness():
        """Readiness probe — checks critical dependencies."""
        if not config.health.enabled:
            return JSONResponse(status_code=200, content={"status": "pass", "checks": {}})

        checks: dict[str, Any] = {}

        storage_result = _check_storage(config)
        if storage_result is not None:
            checks["storage"] = storage_result

        tracing_result = _check_tracing(config)
        if tracing_result is not None:
            checks["tracing"] = tracing_result

        all_statuses = [c["status"] for c in checks.values()] if checks else ["pass"]
        overall = _worst(all_statuses)
        http_status = 503 if overall == "fail" else 200

        return JSONResponse(
            status_code=http_status,
            content={"status": overall, "checks": checks},
        )

    @router.get("/deep")
    def deep():
        """Deep probe — full dependency + data-integrity check."""
        if not config.health.enabled:
            return JSONResponse(status_code=200, content={"status": "pass", "checks": {}})

        checks: dict[str, Any] = {}

        storage_result = _check_storage(config)
        if storage_result is not None:
            checks["storage"] = storage_result

        tracing_result = _check_tracing(config)
        if tracing_result is not None:
            checks["tracing"] = tracing_result

        if config.health.deep_checks:
            checks["rust_core"] = _check_rust_core()

        key_store_result = _check_key_store(config)
        if key_store_result is not None:
            checks["key_store"] = key_store_result

        all_statuses = [c["status"] for c in checks.values()] if checks else ["pass"]
        overall = _worst(all_statuses)
        http_status = 503 if overall == "fail" else 200

        return JSONResponse(
            status_code=http_status,
            content={"status": overall, "checks": checks},
        )

    return router
