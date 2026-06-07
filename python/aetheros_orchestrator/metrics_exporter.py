"""Prometheus metrics bridge for AetherOS — Phase 22.

Bridges the OpenTelemetry Metrics SDK to Prometheus text exposition format via
the PrometheusMetricReader, enabling Grafana, Alertmanager, and any
Prometheus-compatible scraper to consume AetherOS governed-execution metrics.

Standards / research net
────────────────────────
* OpenMetrics specification v1.0.0 (CNCF 2022): text exposition format, counter
  _total suffix, histogram _bucket/_sum/_count suffix conventions, # HELP / # TYPE
  comment lines, label set identification.
* OpenTelemetry Metrics SDK Python v1.24.0: PrometheusMetricReader bridge
  pattern — attaches to SdkMeterProvider metric_readers list, converts OTEL
  data model to Prometheus exposition on each scrape (pull model).
* Prometheus Data Model (prometheus.io 2023): metric name + label set is the
  identity of a time series; label cardinality is bounded by attribute count.
* OTEL Semantic Conventions v1.25.0: aetheros.* namespace custom metrics,
  attribute naming follows {namespace}.{attribute} convention.

Zero-hardcoding: Prometheus exporter is opt-in. When prometheus.enabled = False
(default) GET /metrics returns HTTP 404. When enabled, the PrometheusMetricReader
replaces the tracing module's MeterProvider reader, so all aetheros.* instruments
are scraped alongside standard Python process metrics.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

# ── optional Prometheus imports ────────────────────────────────────────────────
try:
    from prometheus_client import CollectorRegistry, generate_latest
    _PROMETHEUS_AVAILABLE = True
except ImportError:
    _PROMETHEUS_AVAILABLE = False
    CollectorRegistry = None  # type: ignore[assignment,misc]
    generate_latest = None  # type: ignore[assignment]

try:
    from opentelemetry.exporter.prometheus import PrometheusMetricReader
    _PROM_READER_AVAILABLE = True
except ImportError:
    _PROM_READER_AVAILABLE = False
    PrometheusMetricReader = None  # type: ignore[assignment,misc]

try:
    from opentelemetry.sdk.metrics import MeterProvider as SdkMeterProvider
    _SDK_AVAILABLE = True
except ImportError:
    _SDK_AVAILABLE = False
    SdkMeterProvider = None  # type: ignore[assignment,misc]

try:
    from fastapi import APIRouter
    from fastapi.responses import JSONResponse, Response
    _FASTAPI_AVAILABLE = True
except ImportError:
    _FASTAPI_AVAILABLE = False

# ── module-level state ─────────────────────────────────────────────────────────

_reader: "PrometheusMetricReader | None" = None
_registry: "CollectorRegistry | None" = None
_lock = threading.Lock()


def configure_prometheus(prefix: str = "") -> "PrometheusMetricReader":
    """Install a PrometheusMetricReader into the tracing MeterProvider.

    Creates an isolated CollectorRegistry (test-safe — no global state pollution),
    wraps it in a PrometheusMetricReader, rebuilds the tracing._meter_provider with
    that reader, and stores the reader at module level for generate_metrics().

    Parameters
    ----------
    prefix:
        Optional metric name prefix for all instruments (e.g. "aetheros_"). Empty
        string (default) = no prefix; instruments use their natural OTEL names.

    Returns
    -------
    PrometheusMetricReader
        The installed reader. Callers can inspect reader._registry for test assertions.
    """
    global _reader, _registry

    if not _PROMETHEUS_AVAILABLE:
        raise RuntimeError(
            "prometheus_client is not installed; "
            "pip install prometheus-client opentelemetry-exporter-prometheus"
        )
    if not _PROM_READER_AVAILABLE:
        raise RuntimeError(
            "opentelemetry-exporter-prometheus is not installed; "
            "pip install opentelemetry-exporter-prometheus"
        )
    if not _SDK_AVAILABLE:
        raise RuntimeError(
            "opentelemetry-sdk is not installed; pip install opentelemetry-sdk"
        )

    from . import tracing as _tracing

    registry = CollectorRegistry()
    reader = PrometheusMetricReader(
        registry=registry,
        disable_target_info=True,
        prefix=prefix,
    )
    meter_provider = SdkMeterProvider(metric_readers=[reader])

    with _tracing._lock:
        _tracing._meter_provider = meter_provider
        _tracing._enabled = True

    with _lock:
        _reader = reader
        _registry = registry

    return reader


def generate_metrics() -> bytes:
    """Return the current Prometheus text-format scrape payload.

    Calls generate_latest() on the reader's isolated CollectorRegistry. Returns
    b"" if configure_prometheus() has not been called.
    """
    if not _PROMETHEUS_AVAILABLE or _reader is None:
        return b""
    try:
        reg = _reader._registry  # type: ignore[union-attr]
        return generate_latest(reg)  # type: ignore[operator]
    except Exception:
        return b""


def configure_for_test() -> "tuple[PrometheusMetricReader, CollectorRegistry]":
    """Create an isolated PrometheusMetricReader and CollectorRegistry for tests.

    Configures the tracing module to use the new reader. Returns (reader, registry)
    so tests can call generate_latest(registry) and assert on the output.

    This is distinct from tracing.configure_for_test() which uses InMemoryMetricReader.
    """
    reader = configure_prometheus(prefix="")
    with _lock:
        reg = _registry
    return reader, reg  # type: ignore[return-value]


def make_metrics_router(config: "object") -> "APIRouter":
    """Return a FastAPI APIRouter that exposes GET /metrics (Phase 22).

    When config.prometheus.enabled is True and prometheus_client is installed,
    GET /metrics serves the Prometheus text exposition payload (OpenMetrics v1.0.0).
    When disabled, returns HTTP 404. When prometheus_client is missing, HTTP 503.

    Parameters
    ----------
    config:
        AetherConfig instance (or any object with a .prometheus.enabled attribute).
    """
    if not _FASTAPI_AVAILABLE:
        raise RuntimeError("fastapi is required; pip install fastapi")

    router = APIRouter()

    @router.get("/metrics")
    def metrics() -> Response:
        """Prometheus text-format scrape endpoint (OpenMetrics v1.0.0).

        Returns all aetheros.* OTEL instruments plus standard Python process
        and GC metrics. Responds with Content-Type text/plain; version=0.0.4.

        HTTP 404 when prometheus.enabled = False (default).
        HTTP 503 when prometheus_client is not installed.
        """
        prom_cfg = getattr(config, "prometheus", None)
        enabled = getattr(prom_cfg, "enabled", False) if prom_cfg is not None else False

        if not _PROMETHEUS_AVAILABLE:
            return JSONResponse(
                status_code=503,
                content={"detail": "prometheus_client not installed"},
            )

        if not enabled:
            return JSONResponse(
                status_code=404,
                content={"detail": "Prometheus metrics not enabled"},
            )

        payload = generate_metrics()
        return Response(
            content=payload,
            status_code=200,
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    return router
